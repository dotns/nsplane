//! The running engine: one owner task drives the core, I/O tasks feed it through bounded
//! queues.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use nsplane_core::x25519::StaticSecret;
use nsplane_core::{ConfigChange, Core, CoreConfig, CryptoJob, Event, Input, Output, PeerStats};
use nsplane_packet::{MAX_BATCH, PacketBatch, PacketBuf, Path, PeerId, TransportId};
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::{Semaphore, broadcast, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep, sleep_until};

use crate::events::{
    DROP_NO_TRANSPORT, DROP_SINK_CLOSED, DROP_SINK_FULL, DROP_TRANSMIT_FULL, DROP_TRANSPORT_CLOSED,
    DROP_TRANSPORT_REMOVED, DROP_TRANSPORT_SEND_ERROR,
};
use crate::fragment::{Action, FragmentStats, Fragmenter};
use crate::handle::{
    Command, EngineHandle, EngineStatus, Injection, PeerMtus, QueueDepth, QueueStats,
    TransportError, TransportStats,
};
use crate::io::{PacketSink, PacketSource};
use crate::path_mtu::{PathMtu, Verdict};
use crate::transport::{PathMtuReport, Transport};

/// Capacity of the command queue from the handles to the owner task.
const COMMAND_CAPACITY: usize = 64;
/// Size of the receive buffer: the largest UDP payload.
const MAX_DATAGRAM: usize = 65535;
/// Capacity of the queue of path MTU reports from the transports to the owner task.
const PATH_MTU_REPORTS: usize = 16;

/// A running engine.
///
/// One owner task owns the [`Core`] and loops: it waits for a handle command, a local packet,
/// a received datagram or the core's next timeout, feeds the core and drains its outputs.
/// When it wakes for a local packet or a received datagram, it also takes the ones already
/// queued behind it (up to [`MAX_BATCH`]) and feeds them to the core as one batch
/// ([`Core::handle_locals`], [`Core::handle_datagrams`]); it never waits for a batch to fill,
/// so a lone packet goes through at once. Without crypto workers, the source and receive
/// tasks hand over what one read returned as one message (up to [`MAX_BATCH`] items, as
/// many as the queue has room for); either way the input queues are bounded in items.
/// I/O tasks surround it, each connected through a bounded queue: the source task
/// ([`PacketSource::recv`]), the sink task ([`PacketSink::send`]) and, for every transport,
/// a receive task ([`Transport::recv`]) and a transmit task ([`Transport::send`]). The core
/// is never shared. Without crypto workers the data path takes no lock: each peer owns its
/// tunnel. With crypto workers each peer's tunnel is shared with its jobs behind a mutex,
/// uncontended except while a job of that peer runs.
///
/// Transports: the engine runs any number of transports, keyed by [`Transport::id`]. Every
/// transport's received datagrams feed the core through one queue, so a peer's
/// authenticated traffic may arrive on any of them (the [`PathPolicy`] decides whether its
/// path follows). A datagram to transmit goes to the transport named by its
/// [`Path::transport`]; when none is installed under that id, it is dropped and counted
/// under [`crate::DROP_NO_TRANSPORT`]. Each transport's tasks are spawned for its concrete
/// type when it is added, so no datagram goes through a boxed future (unless the transport
/// is a boxed [`DynTransport`]).
///
/// Backpressure: a full sink queue drops the decrypted packet and counts it under
/// [`crate::DROP_SINK_FULL`]. Each transport has its own transmit queue and its own backlog
/// in the owner task: when the queue is full, that transport's datagrams wait in the
/// backlog, in order, while datagrams to other transports keep going to their own queues,
/// so they never queue behind a slow transport. Each backlog is bounded by the queue
/// capacity: a datagram caused by a local packet, a received datagram or a timer (including
/// the timers run by [`EngineHandle::resume`]) that finds its transport's backlog at the
/// bound is dropped and counted under [`crate::DROP_TRANSMIT_FULL`]. Datagrams caused by
/// handle calls always wait and may take a backlog past the bound. Local packets are read
/// only while some installed transport can take them without a deep backlog: its transmit
/// queue has room or its backlog is below the local threshold ([`MAX_BATCH`], at most the
/// queue capacity). The owner stops reading local packets while at least one transport is
/// installed and every installed transport's transmit queue is full with its backlog at the
/// threshold (which transport a local packet leads to is only known once the core has
/// handled it), and takes no more at once than the most room any transport has, counting
/// one datagram per packet; this in turn holds back the source, so a saturated transport
/// does not build a backlog of local traffic ahead of new packets. So an engine with one
/// transport holds back its local packets instead of dropping them, while with several
/// transports a stalled one never holds back local packets for the others: those for the
/// stalled one fill its backlog to the bound and are dropped from then on. With no
/// transport installed, local reads never pause. Received datagrams, timers and handle calls are served
/// meanwhile. A transport that never drains keeps its backlog until it closes (the backlog
/// is then dropped under [`crate::DROP_TRANSPORT_CLOSED`]) or is removed with
/// [`EngineHandle::remove_transport`], which counts every datagram still queued for it
/// (being sent, in its transmit queue or in its backlog) under
/// [`crate::DROP_TRANSPORT_REMOVED`]. [`EngineHandle::replace_transport`] moves all of them,
/// in order, to the new transport instead.
///
/// Inline output: without crypto workers, the owner task sends the datagrams of one drain
/// of the core itself ([`Transport::try_send_batch`]) when nothing of their transport is
/// waiting in its backlog, queued or being sent by its transmit task, and hands the
/// packets of the drain to the sink itself ([`PacketSink::try_send_batch`]) when nothing
/// is queued for or being delivered by the sink task, so on an idle path neither task is
/// woken. What the transport or sink does not take at once (it would block, or it takes
/// part of the batch) goes to the transmit queue and backlog, or the deliver queue, in
/// order and under the rules above; later datagrams and packets queue behind it until the
/// task has drained, so each transport and the sink keep the order of the core's outputs.
/// It sends itself only for a drain after which no local packet or received datagram is
/// waiting (it would wait next): under load it hands the datagrams to the transmit tasks,
/// which send them while it seals the next batch. A
/// transport or sink that took nothing (one that keeps the default, or is full) is skipped
/// for 1, 2, 4, ... up to 1024 drains, until it takes something again. While suspended
/// the owner task never sends or delivers itself. Failed and closed
/// transports and sinks count as with their tasks; datagrams and packets the owner hands
/// over itself never enter a queue, so the queues' high-water marks stay lower.
///
/// Buffers: datagrams are received into one reusable 64 KiB buffer and copied into an
/// exactly sized [`PacketBuf`], so queued datagrams do not each pin 64 KiB. The core takes
/// each datagram by value: it delivers a decrypted packet in the datagram's own buffer and
/// puts the buffers of all other datagrams into its pool itself. Buffers rejected by a full
/// sink and transmitted buffers (returned by the transmit task over a bounded queue, dropped
/// when it is full, or by the owner task at once when it sent them itself) go back to the
/// core's pool with [`Core::recycle`]. Delivered packets are
/// owned by the sink.
///
/// Suspension: [`EngineHandle::suspend`] pauses the engine without tearing it down. While
/// suspended, every I/O task waits before its next read or write (one already in progress
/// may complete), so datagrams that arrive stay in the socket's buffer, and the owner task
/// polls neither its queues nor the core's timer: no I/O runs and no timer fires. Handle
/// calls are still served; the datagrams they cause wait in the transmit queues and the
/// waiting datagrams (within their bounds) until [`EngineHandle::resume`], which runs the
/// core's timers once with the current time, so sessions that expired meanwhile expire and
/// due handshakes start, before normal operation continues. Peers and sessions are kept
/// across a suspension, and transports added or replaced while suspended start suspended.
///
/// MTU: the engine takes [`PacketSource::mtu`] when it starts and a small task, gated by
/// the suspension like the I/O tasks, forwards every change of that watch to the owner task.
/// The owner keeps the last value it saw ([`EngineHandle::mtu`]) and publishes
/// `Event::MtuChanged` when a forwarded value differs from it, so a value sent again does not
/// publish. Changes made while suspended collapse into the latest value, published once
/// after [`EngineHandle::resume`] if it differs. Once the source drops its sender, the
/// engine stops watching and keeps the last value.
///
/// Path MTU: the inner MTU of each peer follows the path its data leaves on, lowered from
/// the source MTU by the ceiling of its transport ([`EngineBuilder::transport_max_datagram`])
/// and the MTU learned for the path ([`EngineHandle::report_path_mtu`],
/// [`Transport::path_mtu_reports`]); [`EngineHandle::peer_mtus`] publishes it. It reaches
/// the local side through the fragmentation stage, which holds packets to the
/// destination's peer's MTU, or through ICMP the caller generates; without a fragmenter it
/// is visible only through [`EngineHandle::peer_mtus`]. The source MTU above keeps its
/// meaning. The owner keeps this state only once a ceiling is set or a report arrives, and
/// a transport's reports are forwarded by a task (gated by the suspension) only when it
/// has any; until then nothing of it costs anything.
///
/// Crypto workers: with [`EngineBuilder::crypto_workers`] set to 2 or more, the owner task
/// hands the encryption of local packets and the decryption of received transport data to a
/// pool of worker tasks ([`Core::handle_datagrams_deferred`], [`Core::handle_locals_deferred`])
/// and finishes each packet when its worker hands it back ([`Core::complete_job`]);
/// everything else (routing, filters, handshakes, timers, counters, events) stays on the
/// owner, which then never sends or delivers inline. The pool is sharded by peer:
/// all packets of a peer, in both directions, go to the same worker (in batches, handed over
/// when one is full or the owner has nothing else to do), which runs them in arrival order, so each peer's packets leave in the order they came while different peers
/// are encrypted in parallel (on a multi-threaded runtime). At most queue capacity packets
/// are with the workers at a time; while that many are, the owner stops reading local
/// packets and received datagrams. Before every handle call that reads or changes peers,
/// counters or sessions, the owner waits for the packets with the workers, so the call sees
/// (and acts after) every packet read before it, as without workers.
///
/// When an I/O side reports [`io::ErrorKind::BrokenPipe`], its task stops and the engine
/// keeps running without it; other I/O errors are logged and the task continues. A datagram
/// the transport fails to send (any error, [`io::ErrorKind::BrokenPipe`] included) is
/// dropped and counted under [`crate::DROP_TRANSPORT_SEND_ERROR`]: the transmit task counts
/// it in a counter shared with the owner task and wakes the owner, which publishes the
/// drops, so a successful send costs nothing extra. A failed batched send counts exactly the
/// datagrams the [`Transport::send_batch`] call reports failed (at least one): for
/// [`crate::UdpTransport`], the datagrams of the failed segmented run.
///
/// The engine runs until [`EngineHandle::shutdown`]. Dropping the `Engine` aborts every task
/// at once, so keep it alive (typically by awaiting [`Engine::wait`]) for as long as the
/// engine should run; handles alone do not keep it running.
///
/// [`PathPolicy`]: nsplane_core::PathPolicy
/// [`DynTransport`]: crate::DynTransport
/// [`EngineBuilder::crypto_workers`]: crate::EngineBuilder::crypto_workers
/// [`EngineBuilder::transport_max_datagram`]: crate::EngineBuilder::transport_max_datagram
pub struct Engine {
    handle: EngineHandle,
    owner: Option<JoinHandle<()>>,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// A new handle to this engine.
    pub fn handle(&self) -> EngineHandle {
        self.handle.clone()
    }

    /// Resolves once the engine has shut down after [`EngineHandle::shutdown`].
    ///
    /// Returns an error if the owner task failed (panicked).
    pub async fn wait(mut self) -> io::Result<()> {
        match self.owner.take() {
            Some(owner) => owner.await.map_err(io::Error::other),
            None => Ok(()),
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.abort();
        }
    }
}

/// Everything [`spawn`] needs, collected by the builder.
pub(crate) struct Parts<Src, Snk> {
    pub(crate) core: CoreConfig,
    pub(crate) private_key: Option<StaticSecret>,
    pub(crate) source: Src,
    pub(crate) sink: Snk,
    /// At least one, with unique ids.
    pub(crate) transports: Vec<NewTransport>,
    pub(crate) queue_capacity: usize,
    pub(crate) event_capacity: usize,
    pub(crate) fragmenter: Option<Fragmenter>,
    /// Crypto worker tasks; fewer than 2 runs the cryptography on the owner task.
    pub(crate) crypto_workers: usize,
    /// The largest datagram of each transport given to the builder.
    pub(crate) transport_max: BTreeMap<TransportId, u16>,
    /// How long a learned path MTU lasts.
    pub(crate) path_mtu_expiry: Duration,
}

/// Spawns the owner task and the I/O tasks.
pub(crate) fn spawn<Src: PacketSource, Snk: PacketSink>(parts: Parts<Src, Snk>) -> Engine {
    let capacity = parts.queue_capacity;
    let (command_tx, commands) = mpsc::channel(COMMAND_CAPACITY);
    // Without crypto workers the source and receive tasks hand over whole batches.
    let fast_path = parts.crypto_workers < 2;
    let handoff = if fast_path { MAX_BATCH } else { 1 };
    let (local_tx, local) = batch_queue(capacity, handoff);
    let (datagram_tx, datagrams) = batch_queue(capacity, handoff);
    let (recycle_tx, recycled) = mpsc::channel(capacity);
    let (signal, send_error_signal) = mpsc::channel(1);
    let (deliver, deliver_rx) = mpsc::channel(capacity);
    let sink = Arc::new(parts.sink);
    let sink_outstanding = Arc::new(AtomicUsize::new(0));
    let (events, _) = broadcast::channel(parts.event_capacity);
    let (suspended, _) = watch::channel(false);
    let (mtu_tx, mtu_changes) = mpsc::channel(1);
    let mut mtu_watch = parts.source.mtu();
    let mtu = *mtu_watch.borrow_and_update();

    let mut core = Core::new(parts.core);
    // Starts the core's timer schedule, so the timers run from the start.
    core.handle_timeout(now());
    let deadline = core
        .poll_timeout()
        .map_or_else(Instant::now, Instant::from_std);

    let workers =
        (parts.crypto_workers >= 2).then(|| Workers::spawn(parts.crypto_workers, capacity));
    // The done queue holds as many batches as jobs may be in flight.
    let crypto_capacity = workers.as_ref().map_or(0, |workers| workers.bound);
    let mut owner = Owner {
        core,
        private_key: parts.private_key,
        commands,
        local: Some(local),
        datagrams,
        datagram_tx,
        recycled,
        recycle_tx,
        send_errors: SendErrors {
            count: Arc::default(),
            signal,
        },
        send_error_signal,
        deliver,
        transports: BTreeMap::new(),
        timer: Box::pin(sleep_until(deadline)),
        events,
        drops: BTreeMap::new(),
        mtu,
        mtu_changes: Some(mtu_changes),
        fragmenter: parts.fragmenter,
        path_mtus: PathMtus::new(mtu, parts.transport_max, parts.path_mtu_expiry),
        tasks: vec![
            Task::spawn(watch_mtu(mtu_watch, mtu_tx, suspended.subscribe())),
            Task::spawn(read_source(parts.source, local_tx, suspended.subscribe())),
            Task::spawn(write_sink(
                Arc::clone(&sink),
                deliver_rx,
                Arc::clone(&sink_outstanding),
                suspended.subscribe(),
            )),
        ],
        queue_capacity: capacity,
        high_water: QueueStats {
            command: QueueDepth::new(COMMAND_CAPACITY),
            local: QueueDepth::new(capacity),
            datagrams: QueueDepth::new(capacity),
            deliver: QueueDepth::new(capacity),
            recycle: QueueDepth::new(capacity),
            transmit: QueueDepth::new(capacity),
            backlog: QueueDepth::new(capacity),
            events: QueueDepth::new(parts.event_capacity),
            crypto: QueueDepth::new(crypto_capacity),
            crypto_done: QueueDepth::new(crypto_capacity),
        },
        local_first: false,
        suspended,
        fast_path,
        inline: Inline {
            allowed: fast_path,
            send: false,
            queued: false,
            drains: 0,
        },
        sink: InlineSink {
            try_deliver: Box::new(move |packets| sink.try_send_batch(packets)),
            outstanding: sink_outstanding,
            closed: false,
            backoff: Backoff::default(),
            delivered: VecDeque::with_capacity(MAX_BATCH),
        },
        workers,
        datagram_batch: Vec::with_capacity(MAX_BATCH),
        local_batch: Vec::with_capacity(MAX_BATCH),
        jobs: Vec::with_capacity(MAX_BATCH),
    };
    for transport in parts.transports {
        let slot = owner.start_transport(transport.start, VecDeque::new(), None);
        owner.transports.insert(transport.id, slot);
    }

    Engine {
        handle: EngineHandle::new(command_tx),
        owner: Some(tokio::spawn(owner.run())),
    }
}

/// The current time on tokio's clock, so a paused runtime clock drives the core too.
fn now() -> std::time::Instant {
    Instant::now().into_std()
}

/// A spawned task, aborted when dropped.
struct Task(JoinHandle<()>);

impl Task {
    fn spawn(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(tokio::spawn(future))
    }

    /// Aborts the task and waits until it is gone.
    async fn stop(mut self) {
        self.0.abort();
        // The task was aborted on purpose; its cancellation error carries no information.
        let _ = (&mut self.0).await;
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A queue bounded in items whose senders hand over batches: one message and one semaphore
/// operation per batch rather than per item.
fn batch_queue<T>(capacity: usize, handoff: usize) -> (BatchSender<T>, BatchQueue<T>) {
    let (batches, rx) = mpsc::unbounded_channel();
    let permits = Arc::new(Semaphore::new(capacity));
    (
        BatchSender {
            batches,
            permits: Arc::clone(&permits),
            most: handoff.clamp(1, capacity),
        },
        BatchQueue {
            batches: rx,
            held: VecDeque::new(),
            permits,
            capacity,
            taken: 0,
        },
    )
}

/// One message of a [`batch_queue`]: a lone item travels without an allocation.
enum Handoff<T> {
    One(T),
    Many(Vec<T>),
}

/// The sending side of a [`batch_queue`]; a permit of its semaphore stands for a free item
/// slot.
struct BatchSender<T> {
    batches: mpsc::UnboundedSender<Handoff<T>>,
    permits: Arc<Semaphore>,
    /// The most items one message carries, at most the capacity.
    most: usize,
}

impl<T> Clone for BatchSender<T> {
    fn clone(&self) -> Self {
        Self {
            batches: self.batches.clone(),
            permits: Arc::clone(&self.permits),
            most: self.most,
        }
    }
}

impl<T> BatchSender<T> {
    /// Hands over every item of `items`, in order, waiting for room: in messages of up to
    /// `most` items, each as large as the free slots allow (at least one). Fails once the
    /// queue is gone.
    async fn send(&self, items: &mut VecDeque<T>) -> Result<(), ()> {
        while !items.is_empty() {
            let n = items
                .len()
                .min(self.most)
                .min(self.permits.available_permits().max(1));
            // `n` is at most `most`, which is at most the capacity.
            let permits = u32::try_from(n).map_err(drop)?;
            self.permits
                .acquire_many(permits)
                .await
                .map_err(drop)?
                .forget();
            let handoff = match items.pop_front() {
                Some(item) if n == 1 => Handoff::One(item),
                Some(item) => {
                    let mut batch = Vec::with_capacity(n);
                    batch.push(item);
                    batch.extend(items.drain(..n - 1));
                    Handoff::Many(batch)
                }
                None => return Ok(()),
            };
            self.batches.send(handoff).map_err(drop)?;
        }
        Ok(())
    }
}

/// The receiving side of a [`batch_queue`], in the owner task. Items of a batch it has not
/// taken yet stay held here, in order, and keep their slots.
struct BatchQueue<T> {
    batches: mpsc::UnboundedReceiver<Handoff<T>>,
    /// Received items not taken yet, oldest first.
    held: VecDeque<T>,
    permits: Arc<Semaphore>,
    capacity: usize,
    /// Items taken whose slots are not freed yet ([`BatchQueue::release`]).
    taken: usize,
}

impl<T> BatchQueue<T> {
    /// The next item; `None` once every sender is gone and every item was taken.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        if self.held.is_empty() {
            return match self.batches.poll_recv(cx) {
                Poll::Ready(Some(handoff)) => Poll::Ready(self.unpack(handoff)),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            };
        }
        Poll::Ready(self.take())
    }

    /// The next item if one is queued.
    fn try_recv(&mut self) -> Option<T> {
        if self.held.is_empty() {
            let handoff = self.batches.try_recv().ok()?;
            return self.unpack(handoff);
        }
        self.take()
    }

    /// Takes the first item of a message received with nothing held, holding the rest.
    fn unpack(&mut self, handoff: Handoff<T>) -> Option<T> {
        match handoff {
            Handoff::One(item) => {
                self.taken += 1;
                Some(item)
            }
            Handoff::Many(batch) => {
                self.held.extend(batch);
                self.take()
            }
        }
    }

    fn take(&mut self) -> Option<T> {
        let item = self.held.pop_front()?;
        self.taken += 1;
        Some(item)
    }

    /// Whether no item is held or queued.
    fn is_empty(&self) -> bool {
        self.held.is_empty() && self.batches.is_empty()
    }

    /// Frees the slots of the items taken, at once.
    fn release(&mut self) {
        if self.taken > 0 {
            self.permits.add_permits(std::mem::take(&mut self.taken));
        }
    }

    /// Items in the queue, not counting those taken.
    fn len(&self) -> usize {
        self.capacity - self.permits.available_permits() - self.taken
    }
}

impl<T> Drop for BatchQueue<T> {
    fn drop(&mut self) {
        // Wakes the senders waiting for room.
        self.permits.close();
    }
}

/// What a stopped transmit task hands back: its queue and the datagrams of the batch it was
/// sending that were not sent, oldest first.
type Unsent = (mpsc::Receiver<Datagram>, Vec<Datagram>);

/// A transport's transmit task, stopped through a signal so that it hands back the datagrams
/// it did not send; aborted when dropped.
struct Transmitter {
    /// `None` once the stop was signalled.
    stop: Option<oneshot::Sender<()>>,
    /// Resolves to `None` when the task ended on its own (the transport or the engine is
    /// gone), having dropped its queue.
    task: JoinHandle<Option<Unsent>>,
}

impl Transmitter {
    /// Stops the task and returns the datagrams it did not send, oldest first.
    async fn stop(mut self) -> VecDeque<Datagram> {
        if let Some(stop) = self.stop.take() {
            // The task may have ended already.
            let _ = stop.send(());
        }
        let mut unsent = VecDeque::new();
        // Nothing comes back from a task that ended on its own or failed.
        if let Ok(Some((mut queue, sending))) = (&mut self.task).await {
            unsent.extend(sending);
            while let Ok(datagram) = queue.try_recv() {
                unsent.push_back(datagram);
            }
        }
        unsent
    }
}

impl Drop for Transmitter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A datagram and the path to send it on.
type Datagram = (Path, PacketBuf);
/// Waits for room in the transmit queue.
type Reserve = Pin<Box<dyn Future<Output = Result<OwnedPermit<Datagram>, SendError<()>>> + Send>>;

/// Hands datagrams to a transport without waiting ([`Transport::try_send_batch`]).
type TrySend = Box<dyn Fn(&[Datagram], &mut usize, &mut usize) -> io::Result<()> + Send>;
/// Hands packets to the sink without waiting ([`PacketSink::try_send_batch`]).
type TryDeliver = Box<dyn Fn(&mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> + Send>;

/// Spawns a transport's receive and transmit tasks, given the queue receiving its datagrams,
/// its transmit queue (both ends), the queue returning transmitted buffers, the transport's
/// traffic counters (which report failed sends) and the suspension state; also returns how
/// to send on it without waiting and its path MTU reports, if it has any.
type Start = Box<
    dyn FnOnce(
            BatchSender<Datagram>,
            mpsc::WeakSender<Datagram>,
            mpsc::Receiver<Datagram>,
            mpsc::Sender<PacketBuf>,
            Arc<Traffic>,
            watch::Receiver<bool>,
        ) -> (
            Task,
            Transmitter,
            TrySend,
            Option<mpsc::Receiver<PathMtuReport>>,
        ) + Send,
>;

/// A transport on its way to the owner task, erased to its id and the spawning of its tasks,
/// which stay generic over its type.
pub(crate) struct NewTransport {
    pub(crate) id: TransportId,
    start: Start,
}

impl NewTransport {
    pub(crate) fn new<T: Transport>(transport: T) -> Self {
        Self {
            id: transport.id(),
            start: Box::new(
                move |datagrams, slots, queue, recycle, traffic, suspended| {
                    let reports = transport.path_mtu_reports();
                    let transport = Arc::new(transport);
                    let (stop, stopped) = oneshot::channel();
                    let sender = Arc::clone(&transport);
                    (
                        Task::spawn(receive(
                            Arc::clone(&transport),
                            datagrams,
                            Arc::clone(&traffic),
                            suspended.clone(),
                        )),
                        Transmitter {
                            stop: Some(stop),
                            task: tokio::spawn(transmit(
                                transport, slots, queue, recycle, traffic, suspended, stopped,
                            )),
                        },
                        Box::new(move |datagrams, sent, failed| {
                            sender.try_send_batch(datagrams, sent, failed)
                        }),
                        reports,
                    )
                },
            ),
        }
    }
}

/// Where transmit tasks report failed sends: a count the owner task takes, and a signal
/// that wakes it.
#[derive(Clone)]
struct SendErrors {
    count: Arc<AtomicUsize>,
    /// The owner keeps a sender, so the signal never closes; a full signal is already
    /// pending.
    signal: mpsc::Sender<()>,
}

impl SendErrors {
    /// Reports `failed` datagrams.
    fn report(&self, failed: usize) {
        // The signal orders the count before the owner's take.
        self.count.fetch_add(failed, Ordering::Relaxed);
        let _ = self.signal.try_send(());
    }

    /// The failed sends since the last take.
    fn take(&self) -> usize {
        self.count.swap(0, Ordering::Relaxed)
    }
}

/// The traffic counters of a transport, updated once per batch by its tasks or the owner
/// task, and where its failed sends are reported.
struct Traffic {
    rx_datagrams: AtomicU64,
    rx_bytes: AtomicU64,
    tx_datagrams: AtomicU64,
    tx_bytes: AtomicU64,
    tx_failed: AtomicU64,
    /// Datagrams in the transmit queue or in the batch the transmit task is sending: raised
    /// by the owner per queued datagram, lowered by the transmit task once it is done with
    /// its batch.
    outstanding: AtomicUsize,
    errors: SendErrors,
}

impl Traffic {
    const fn new(errors: SendErrors) -> Self {
        Self {
            rx_datagrams: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_datagrams: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_failed: AtomicU64::new(0),
            outstanding: AtomicUsize::new(0),
            errors,
        }
    }

    /// Counts `failed` datagrams and reports them to the owner.
    fn failed(&self, failed: usize) {
        self.tx_failed.fetch_add(failed as u64, Ordering::Relaxed);
        self.errors.report(failed);
    }

    /// Counts the datagrams of `done` as sent (handed off or failed).
    fn sent(&self, done: &[Datagram]) {
        if done.is_empty() {
            return;
        }
        let bytes = done.iter().map(|(_, data)| data.len() as u64).sum();
        self.tx_datagrams
            .fetch_add(done.len() as u64, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn stats(&self, id: TransportId) -> TransportStats {
        TransportStats {
            id,
            rx_datagrams: self.rx_datagrams.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_datagrams: self.tx_datagrams.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_failed: self.tx_failed.load(Ordering::Relaxed),
        }
    }
}

/// An installed transport: its transmit queue, the datagrams waiting for room in it, its
/// two tasks and its traffic counters.
struct TransportSlot {
    queue: mpsc::Sender<Datagram>,
    /// Datagrams waiting for room in the transmit queue, oldest first.
    pending: VecDeque<Datagram>,
    /// Armed while `pending` is not empty.
    flush: Option<Reserve>,
    receive: Task,
    transmit: Transmitter,
    /// Forwards the transport's path MTU reports, if it has any.
    reports: Option<Task>,
    traffic: Arc<Traffic>,
    try_send: TrySend,
    /// Datagrams the owner task sends itself at the end of the current drain, oldest
    /// first ([`Owner::send_inline`]).
    inline: Vec<Datagram>,
    /// The transport reported [`io::ErrorKind::BrokenPipe`] to the owner task.
    closed: bool,
    backoff: Backoff,
}

impl TransportSlot {
    /// Queues `datagram`, or adds it to the waiting datagrams when the queue is full or
    /// others are waiting. With `droppable`, a datagram that finds `bound` datagrams waiting
    /// is rejected; a closed queue rejects every datagram. Returns the rejected buffer and
    /// the reason.
    fn transmit(
        &mut self,
        datagram: Datagram,
        droppable: bool,
        bound: usize,
    ) -> Result<(), (PacketBuf, &'static str)> {
        if self.closed {
            return Err((datagram.1, DROP_TRANSPORT_CLOSED));
        }
        let datagram = if self.pending.is_empty() {
            self.traffic.outstanding.fetch_add(1, Ordering::Relaxed);
            match self.queue.try_send(datagram) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    self.traffic.outstanding.fetch_sub(1, Ordering::Relaxed);
                    match error {
                        TrySendError::Full(datagram) => datagram,
                        TrySendError::Closed((_, data)) => {
                            return Err((data, DROP_TRANSPORT_CLOSED));
                        }
                    }
                }
            }
        } else {
            datagram
        };
        if droppable && self.pending.len() >= bound {
            return Err((datagram.1, DROP_TRANSMIT_FULL));
        }
        self.pending.push_back(datagram);
        Ok(())
    }

    /// Whether nothing of the transport is waiting, queued or being sent, so the owner task
    /// may send on it itself without passing any of it.
    fn idle(&self) -> bool {
        self.pending.is_empty()
            && !self.closed
            && !self.queue.is_closed()
            && self.traffic.outstanding.load(Ordering::Acquire) == 0
    }

    /// Sends `batch` on the transport without waiting, counting the datagrams it is done
    /// with and the failed ones as the transmit task does; returns how many it is done
    /// with. [`io::ErrorKind::BrokenPipe`] marks the transport closed.
    fn send_now(&mut self, batch: &[Datagram]) -> usize {
        let mut sent = 0;
        while sent < batch.len() {
            let before = sent;
            let mut failed = 0;
            let Err(e) = (self.try_send)(batch, &mut sent, &mut failed) else {
                sent = batch.len();
                break;
            };
            if e.kind() == io::ErrorKind::WouldBlock {
                sent = sent.clamp(before, batch.len());
                if failed > 0 {
                    self.traffic.failed(failed.min(sent - before));
                }
                break;
            }
            // As in the transmit task: the failed datagram is dropped, and at least one and
            // at most the datagrams the call was done with count as failed.
            sent = sent.max(before + 1).min(batch.len());
            self.traffic.failed(failed.clamp(1, sent - before));
            if e.kind() == io::ErrorKind::BrokenPipe {
                tracing::debug!("Transport closed for sending");
                self.closed = true;
                break;
            }
            tracing::debug!(message = "Transport send error", error = ?e);
        }
        self.traffic.sent(&batch[..sent]);
        sent
    }

    /// Stops both tasks and returns every datagram still queued for the transport, oldest
    /// first: the one being sent, the transmit queue's, then the waiting ones.
    async fn stop(mut self) -> VecDeque<Datagram> {
        self.flush = None;
        if let Some(reports) = self.reports.take() {
            reports.stop().await;
        }
        self.receive.stop().await;
        let mut unsent = self.transmit.stop().await;
        unsent.append(&mut self.pending);
        unsent.extend(self.inline.drain(..));
        unsent
    }

    /// Datagrams in the transmit queue, counting a reserved slot.
    fn queued(&self) -> usize {
        self.queue.max_capacity() - self.queue.capacity()
    }
}

/// The crypto worker tasks and their queues.
///
/// Jobs go to the workers in batches: each worker's batch is handed over once it is full, or
/// with every other batch once one is full or the owner has nothing else to do, so a busy
/// owner wakes each worker once per batch rather than once per packet.
struct Workers {
    /// One job queue per worker; a peer's jobs go to worker `peer % n`.
    queues: Vec<mpsc::Sender<Vec<CryptoJob>>>,
    /// The jobs of each worker not handed over yet, oldest first.
    batches: Vec<Vec<CryptoJob>>,
    /// Batches the workers ran, in the order each worker ran them.
    done: mpsc::Receiver<Vec<CryptoJob>>,
    /// Jobs batched or with the workers and not completed yet; at most `bound`.
    in_flight: usize,
    /// The most jobs in flight since [`Owner::queue_stats`] last took it.
    peak: usize,
    bound: usize,
    tasks: Vec<Task>,
}

impl Workers {
    /// Spawns `n` workers, with at most `bound` jobs in flight.
    fn spawn(n: usize, bound: usize) -> Self {
        // Every queue holds a batch of each job in flight, so handing one over never waits.
        let (done_tx, done) = mpsc::channel(bound);
        let (queues, tasks) = (0..n)
            .map(|_| {
                let (queue, jobs) = mpsc::channel(bound);
                (queue, Task::spawn(crypto_worker(jobs, done_tx.clone())))
            })
            .unzip();
        Self {
            queues,
            batches: (0..n).map(|_| Vec::new()).collect(),
            done,
            in_flight: 0,
            peak: 0,
            bound,
            tasks,
        }
    }

    /// Adds `job` to its peer's worker's batch; `true` once that batch is full.
    fn dispatch(&mut self, job: CryptoJob) -> bool {
        let worker = job.peer().get() as usize % self.queues.len();
        let batch = &mut self.batches[worker];
        batch.push(job);
        self.in_flight += 1;
        self.peak = self.peak.max(self.in_flight);
        batch.len() >= MAX_BATCH
    }

    /// Hands every batch of jobs to its worker; completes the jobs of a worker that is gone
    /// (it panicked) on `core`.
    fn flush(&mut self, core: &mut Core) {
        for (queue, batch) in self.queues.iter().zip(&mut self.batches) {
            if batch.is_empty() {
                continue;
            }
            // Never full: a queue holds a batch of each job in flight.
            if let Err(TrySendError::Full(jobs) | TrySendError::Closed(jobs)) =
                queue.try_send(std::mem::take(batch))
            {
                self.in_flight -= jobs.len();
                for job in jobs {
                    core.complete_job(job);
                }
            }
        }
    }

    /// Whether the bound of jobs in flight is reached.
    const fn full(&self) -> bool {
        self.in_flight >= self.bound
    }
}

/// The sink as the owner task sees it.
struct InlineSink {
    try_deliver: TryDeliver,
    /// Packets in the deliver queue or in the batch the sink task is delivering: raised by
    /// the owner per queued packet, lowered by the sink task once it is done with its batch.
    outstanding: Arc<AtomicUsize>,
    /// The sink reported [`io::ErrorKind::BrokenPipe`] to the owner task.
    closed: bool,
    backoff: Backoff,
    /// Packets the owner task delivers itself at the end of the current drain, oldest
    /// first ([`Owner::deliver_inline`]).
    delivered: VecDeque<(PeerId, PacketBuf)>,
}

/// When the owner task sends and delivers itself.
struct Inline {
    /// No crypto workers and not suspended: the owner task may deliver itself.
    allowed: bool,
    /// For the current drain: allowed, and no local packet or received datagram is waiting,
    /// so the owner task would wait next and may also send itself. Under load it hands the
    /// datagrams to the transmit tasks, which send them while it seals the next batch.
    send: bool,
    /// Some transport has datagrams in [`TransportSlot::inline`].
    queued: bool,
    /// Drains so far, the clock of [`Backoff`].
    drains: u64,
}

/// The longest a transport or sink that took nothing is skipped, in drains.
const MAX_BACKOFF: u64 = 1024;

/// Skips inline sending to a transport or sink that took nothing (one that does not
/// support it, or is full) for a number of drains that doubles with every such try, up to
/// [`MAX_BACKOFF`], and restarts once it takes something.
#[derive(Debug, Default)]
struct Backoff {
    /// The first drain to try again in.
    retry_at: u64,
    /// The last wait, in drains.
    wait: u64,
}

impl Backoff {
    const fn ready(&self, drain: u64) -> bool {
        drain >= self.retry_at
    }

    /// Records a try in `drain`; `took` whether anything was taken.
    fn record(&mut self, drain: u64, took: bool) {
        if took {
            self.wait = 0;
        } else {
            self.wait = (self.wait * 2).clamp(1, MAX_BACKOFF);
            self.retry_at = drain + self.wait;
        }
    }
}

/// The per-path MTU state of the owner task.
struct PathMtus {
    /// The ceilings; `None` until a ceiling is set or a report arrives.
    table: Option<Box<PathMtu>>,
    /// How long a learned path MTU lasts.
    expiry: Duration,
    /// The queue the transports' report forwarders feed; `None` until a transport has
    /// reports.
    reports: Option<(mpsc::Sender<PathMtuReport>, mpsc::Receiver<PathMtuReport>)>,
    /// Publishes the peers' inner MTUs.
    published: watch::Sender<PeerMtus>,
}

impl PathMtus {
    /// No table unless the builder set transport ceilings.
    fn new(mtu: u16, transport_max: BTreeMap<TransportId, u16>, expiry: Duration) -> Self {
        let table = (!transport_max.is_empty()).then(|| {
            let mut table = PathMtu::new(expiry);
            for (id, max) in transport_max {
                table.set_transport_max(id, Some(max));
            }
            Box::new(table)
        });
        Self {
            table,
            expiry,
            reports: None,
            published: watch::Sender::new(PeerMtus::unconstrained(mtu)),
        }
    }

    /// The table, created on first use.
    fn table(&mut self) -> &mut PathMtu {
        let expiry = self.expiry;
        self.table
            .get_or_insert_with(|| Box::new(PathMtu::new(expiry)))
    }
}

/// What woke the owner task.
enum Wake {
    Command(Option<Command>),
    Datagram(Option<Datagram>),
    Local(Option<PacketBuf>),
    Mtu(Option<u16>),
    /// A transport reported a path MTU.
    PathMtu(Option<PathMtuReport>),
    /// A transmit task reported failed sends.
    SendErrors,
    /// Room in the transmit queue of a transport with waiting datagrams.
    Flush(TransportId, Option<OwnedPermit<Datagram>>),
    /// A crypto worker ran a job.
    Crypto(Option<Vec<CryptoJob>>),
    Timer,
}

/// The state of the owner task.
struct Owner {
    core: Core,
    /// The last private key given to the engine.
    private_key: Option<StaticSecret>,
    commands: mpsc::Receiver<Command>,
    /// Local packets; `None` once the source task has stopped.
    local: Option<BatchQueue<PacketBuf>>,
    datagrams: BatchQueue<Datagram>,
    /// Cloned into every transport receive task.
    datagram_tx: BatchSender<Datagram>,
    /// Buffers returned by the transmit task.
    recycled: mpsc::Receiver<PacketBuf>,
    /// Cloned into every transmit task.
    recycle_tx: mpsc::Sender<PacketBuf>,
    /// Cloned into every transmit task.
    send_errors: SendErrors,
    /// Signalled by [`SendErrors::report`].
    send_error_signal: mpsc::Receiver<()>,
    deliver: mpsc::Sender<(PeerId, PacketBuf)>,
    transports: BTreeMap<TransportId, TransportSlot>,
    timer: Pin<Box<Sleep>>,
    events: broadcast::Sender<Event>,
    drops: BTreeMap<&'static str, u64>,
    /// The last MTU of the source.
    mtu: u16,
    /// MTU changes of the source; `None` once the source dropped its watch's sender.
    mtu_changes: Option<mpsc::Receiver<u16>>,
    /// Keeps local packets within `mtu` (or a peer's lower MTU), if installed.
    fragmenter: Option<Fragmenter>,
    path_mtus: PathMtus,
    /// The MTU watcher, source and sink tasks.
    tasks: Vec<Task>,
    queue_capacity: usize,
    /// Capacities and high-water marks of the queues, without the current occupancies.
    high_water: QueueStats,
    /// Alternates which of local packets and datagrams is polled first.
    local_first: bool,
    /// Whether the engine is suspended; every I/O task watches it.
    suspended: watch::Sender<bool>,
    /// No crypto workers: the owner task may send datagrams and deliver packets itself.
    fast_path: bool,
    inline: Inline,
    /// How the owner task delivers packets itself.
    sink: InlineSink,
    /// The crypto worker pool, if enabled.
    workers: Option<Workers>,
    /// Reused for each batch of received datagrams.
    datagram_batch: Vec<Datagram>,
    /// Reused for each batch of local packets.
    local_batch: Vec<PacketBuf>,
    /// Reused for the crypto jobs of each batch.
    jobs: Vec<CryptoJob>,
}

impl Owner {
    async fn run(mut self) {
        loop {
            self.arm_timer();
            let wake = poll_fn(|cx| {
                let wake = self.poll_wake(cx);
                // Nothing else to do: the batched jobs go to the workers now.
                if wake.is_pending() {
                    self.flush_jobs();
                }
                wake
            })
            .await;
            // Datagrams caused by local packets, the network or a timer may overflow the
            // waiting datagrams.
            let droppable = matches!(
                wake,
                Wake::Local(_) | Wake::Datagram(_) | Wake::Crypto(_) | Wake::Timer
            );
            match wake {
                Wake::Command(None) => break,
                Wake::Command(Some(command)) => {
                    if settles(&command) {
                        self.settle().await;
                    }
                    if let ControlFlow::Break(reply) = self.command(command).await {
                        self.stop().await;
                        // The caller may have stopped waiting.
                        let _ = reply.send(());
                        return;
                    }
                }
                Wake::Datagram(Some(datagram)) => self.input_datagrams(datagram),
                // The owner keeps a sender of both queues, so they never close.
                Wake::Datagram(None) | Wake::PathMtu(None) => {}
                Wake::Local(Some(packet)) => self.input_locals(packet),
                Wake::Local(None) => self.local = None,
                Wake::Mtu(Some(mtu)) => {
                    if mtu != self.mtu {
                        self.mtu = mtu;
                        self.event(Event::MtuChanged { mtu });
                        self.recompute_peer_mtus();
                    }
                }
                Wake::PathMtu(Some(report)) => {
                    self.report_path_mtu(&report);
                }
                Wake::Mtu(None) => self.mtu_changes = None,
                Wake::SendErrors => self.send_errors(),
                Wake::Flush(id, permit) => {
                    // No permit: the transmit queue closed, and moving drops the datagrams.
                    if let Some(permit) = permit
                        && let Some(slot) = self.transports.get_mut(&id)
                        && let Some(datagram) = slot.pending.pop_front()
                    {
                        slot.traffic.outstanding.fetch_add(1, Ordering::Relaxed);
                        permit.send(datagram);
                        self.high_water.transmit.record(slot.queued());
                    }
                    self.move_pending(id);
                }
                Wake::Crypto(Some(jobs)) => self.complete_jobs(jobs),
                // The workers are gone (one panicked): the jobs they held are lost.
                Wake::Crypto(None) => self.workers = None,
                Wake::Timer => {
                    let now = now();
                    self.core.handle_timeout(now);
                    if let Some(table) = &mut self.path_mtus.table
                        && table.expire(now)
                    {
                        self.recompute_peer_mtus();
                    }
                }
            }
            self.drain(droppable);
        }
        self.stop().await;
    }

    fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<Wake> {
        if let Poll::Ready(command) = self.commands.poll_recv(cx) {
            return Poll::Ready(Wake::Command(command));
        }
        // Only handle commands run while suspended.
        if *self.suspended.borrow() {
            return Poll::Pending;
        }
        for (id, slot) in &mut self.transports {
            if let Some(flush) = &mut slot.flush
                && let Poll::Ready(permit) = flush.as_mut().poll(cx)
            {
                slot.flush = None;
                return Poll::Ready(Wake::Flush(*id, permit.ok()));
            }
        }
        if let Some(workers) = &mut self.workers {
            if let Poll::Ready(job) = workers.done.poll_recv(cx) {
                return Poll::Ready(Wake::Crypto(job));
            }
            // Nothing more goes to the workers until they hand jobs back.
            if workers.full() {
                return self.poll_rest(cx);
            }
        }
        self.local_first = !self.local_first;
        if self.local_first {
            if let Poll::Ready(wake) = self.poll_local(cx) {
                return Poll::Ready(wake);
            }
            if let Poll::Ready(datagram) = self.datagrams.poll_recv(cx) {
                return Poll::Ready(Wake::Datagram(datagram));
            }
        } else {
            if let Poll::Ready(datagram) = self.datagrams.poll_recv(cx) {
                return Poll::Ready(Wake::Datagram(datagram));
            }
            if let Poll::Ready(wake) = self.poll_local(cx) {
                return Poll::Ready(wake);
            }
        }
        self.poll_rest(cx)
    }

    /// Polls the MTU changes and the timer.
    fn poll_rest(&mut self, cx: &mut Context<'_>) -> Poll<Wake> {
        if let Some(changes) = &mut self.mtu_changes
            && let Poll::Ready(mtu) = changes.poll_recv(cx)
        {
            return Poll::Ready(Wake::Mtu(mtu));
        }
        if let Some((_, reports)) = &mut self.path_mtus.reports
            && let Poll::Ready(report) = reports.poll_recv(cx)
        {
            return Poll::Ready(Wake::PathMtu(report));
        }
        if self.send_error_signal.poll_recv(cx).is_ready() {
            return Poll::Ready(Wake::SendErrors);
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Wake::Timer);
        }
        Poll::Pending
    }

    /// Polls the source queue, unless there is no room for local packets
    /// ([`Owner::local_room`]).
    fn poll_local(&mut self, cx: &mut Context<'_>) -> Poll<Wake> {
        let full = self.local_room() == 0;
        match &mut self.local {
            Some(local) if !full => local.poll_recv(cx).map(Wake::Local),
            _ => Poll::Pending,
        }
    }

    /// Arms the timer for the core's next timeout or, if earlier, the next expiry of a
    /// learned path MTU.
    fn arm_timer(&mut self) {
        let mut deadline = self.core.poll_timeout();
        if let Some(expiry) = self
            .path_mtus
            .table
            .as_ref()
            .and_then(|table| table.next_expiry())
        {
            deadline = Some(deadline.map_or(expiry, |deadline| deadline.min(expiry)));
        }
        if let Some(deadline) = deadline {
            let deadline = Instant::from_std(deadline);
            if self.timer.deadline() != deadline {
                self.timer.as_mut().reset(deadline);
            }
        }
    }

    /// Feeds `first` and the datagrams queued behind it to the core as one batch, or their
    /// cryptography to the crypto workers.
    ///
    /// Takes only what is already queued, never waiting for more: at most [`MAX_BATCH`]
    /// datagrams, no more than the crypto workers have room for and, since each may deliver a
    /// packet, no more than the sink queue has room for (but always `first`).
    fn input_datagrams(&mut self, first: Datagram) {
        self.high_water
            .datagrams
            .record_received(self.datagrams.len());
        let room = self.batch_room().min(self.deliver.capacity());
        let batch = &mut self.datagram_batch;
        batch.push(first);
        while batch.len() < room
            && let Some(datagram) = self.datagrams.try_recv()
        {
            batch.push(datagram);
        }
        self.datagrams.release();
        let now = now();
        if self.workers.is_some() {
            self.core
                .handle_datagrams_deferred(batch.drain(..), now, &mut self.jobs);
            self.dispatch_jobs();
        } else {
            self.core.handle_datagrams(batch.drain(..), now);
        }
    }

    /// Feeds `first` and the local packets queued behind it, each through the fragmentation
    /// stage if installed, to the core as one batch, or their cryptography to the crypto
    /// workers; ICMP errors from the fragmentation stage go back to the local side.
    ///
    /// Takes only what is already queued, never waiting for more: at most [`MAX_BATCH`]
    /// packets, no more than the crypto workers have room for and no more than the room for
    /// local packets ([`Owner::local_room`]), counting one datagram per packet (but always
    /// `first`). A packet that leads to several datagrams (fragments, a handshake) may take
    /// the waiting datagrams past the local threshold, up to their bound; those that find
    /// the bound reached are dropped as usual.
    fn input_locals(&mut self, first: PacketBuf) {
        let Some(local) = &self.local else {
            return;
        };
        self.high_water.local.record_received(local.len());
        let room = self.batch_room().min(self.local_room());
        let now = now();
        let source = self.mtu;
        let floor = self
            .path_mtus
            .table
            .as_ref()
            .map_or(source, |table| table.floor(source));
        let mut next = Some(first);
        let mut taken = 0;
        while let Some(packet) = next {
            taken += 1;
            match &mut self.fragmenter {
                None => self.local_batch.push(packet),
                Some(fragmenter) => {
                    let core = &self.core;
                    let table = &mut self.path_mtus.table;
                    // Above the floor: the destination's peer and its MTU, following the
                    // path its data leaves on now (a policy may have moved it).
                    let lookup = |dst| {
                        let peer = core.route(dst);
                        let mtu = match (peer, table.as_deref_mut()) {
                            (Some(peer), Some(table)) => {
                                table.peer(peer, core.data_path(peer), source)
                            }
                            _ => source,
                        };
                        (peer, mtu)
                    };
                    match fragmenter.process(packet, floor, now, lookup) {
                        Action::Send(packet) => self.local_batch.push(packet),
                        Action::Fragments(fragments) => self.local_batch.extend(fragments),
                        Action::Reply(peer, packet) => self.core.inject_inbound(peer, packet),
                        Action::Drop(reason) => self.dropped(None, reason),
                    }
                }
            }
            next = match &mut self.local {
                Some(local) if taken < room => local.try_recv(),
                _ => None,
            };
        }
        if let Some(local) = &mut self.local {
            local.release();
        }
        if self
            .path_mtus
            .table
            .as_ref()
            .is_some_and(|table| table.changed())
        {
            self.publish_peer_mtus();
        }
        let batch = &mut self.local_batch;
        if self.workers.is_some() {
            self.core
                .handle_locals_deferred(batch.drain(..), now, &mut self.jobs);
            self.dispatch_jobs();
        } else {
            self.core.handle_locals(batch.drain(..), now);
        }
    }

    /// The most items to take from a packet queue at once: [`MAX_BATCH`], and no more than
    /// the crypto workers have room for, each item leading to at most one job.
    fn batch_room(&self) -> usize {
        self.workers.as_ref().map_or(MAX_BATCH, |workers| {
            MAX_BATCH.min(workers.bound.saturating_sub(workers.in_flight))
        })
    }

    /// The local packets to take before every installed transport's transmit queue is full
    /// and its waiting datagrams are at the local threshold ([`MAX_BATCH`], at most the queue
    /// capacity), counting one datagram per packet: the most room over the transports, since
    /// which transport a packet leads to is only known once the core has handled it.
    /// Unbounded without transports.
    fn local_room(&self) -> usize {
        let threshold = self.queue_capacity.min(MAX_BATCH);
        self.transports
            .values()
            .map(|slot| {
                // Waiting datagrams take the queue's free slots first.
                let free = if slot.pending.is_empty() {
                    slot.queue.capacity()
                } else {
                    0
                };
                free + threshold.saturating_sub(slot.pending.len())
            })
            .max()
            .unwrap_or(usize::MAX)
    }

    /// Adds every job of the current batch to its worker's batch, handing the batches over
    /// whenever one is full.
    fn dispatch_jobs(&mut self) {
        let Some(workers) = &mut self.workers else {
            return;
        };
        for job in self.jobs.drain(..) {
            if workers.dispatch(job) {
                workers.flush(&mut self.core);
            }
        }
    }

    /// Hands every batch of jobs to its worker.
    fn flush_jobs(&mut self) {
        if let Some(workers) = &mut self.workers {
            workers.flush(&mut self.core);
        }
    }

    /// Completes a batch the workers handed back.
    fn complete_jobs(&mut self, jobs: Vec<CryptoJob>) {
        let Some(workers) = &mut self.workers else {
            return;
        };
        self.high_water
            .crypto_done
            .record_received(workers.done.len());
        workers.in_flight -= jobs.len();
        for job in jobs {
            self.core.complete_job(job);
        }
    }

    /// Waits for every job with the crypto workers and completes it.
    async fn settle(&mut self) {
        self.flush_jobs();
        while let Some(workers) = &mut self.workers
            && workers.in_flight > 0
        {
            match workers.done.recv().await {
                Some(jobs) => self.complete_jobs(jobs),
                None => self.workers = None,
            }
            self.drain(true);
        }
        self.drain(true);
    }

    /// Handles a command; breaks with the reply channel on shutdown.
    async fn command(&mut self, command: Command) -> ControlFlow<oneshot::Sender<()>> {
        if !matches!(command, Command::QueueStats(..)) {
            self.high_water.command.record_received(self.commands.len());
        }
        // Replies are best effort: the caller may have stopped waiting.
        match command {
            Command::Config(change, reply) => {
                if let ConfigChange::SetPrivateKey(key) = &change {
                    self.private_key = Some(key.clone());
                }
                self.core.handle_input(Input::Config(change), now());
                self.drain(false);
                if self.path_mtus.table.is_some() {
                    self.recompute_peer_mtus();
                }
                let _ = reply.send(());
            }
            Command::PeerId(key, reply) => {
                let _ = reply.send(self.core.peer_id(&key));
            }
            Command::PeerStats(peer, reply) => {
                let _ = reply.send(self.core.peer_stats(peer));
            }
            Command::Peers(reply) => {
                let _ = reply.send(self.peers());
            }
            Command::PublicKey(reply) => {
                let _ = reply.send(self.core.public_key());
            }
            Command::PrivateKey(reply) => {
                let _ = reply.send(self.private_key.clone());
            }
            Command::Inject(injection, reply) => {
                self.inject(injection);
                let _ = reply.send(());
            }
            Command::AddTransport(transport, reply) => {
                let _ = reply.send(self.add_transport(transport));
            }
            Command::RemoveTransport(id, reply) => {
                let _ = reply.send(self.remove_transport(id).await);
            }
            Command::ReplaceTransport(transport, reply) => {
                let result = match self.transports.remove(&transport.id) {
                    Some(old) => {
                        // The datagrams queued for the old transport go out on the new one,
                        // and its counters keep running.
                        let traffic = Arc::clone(&old.traffic);
                        let pending = old.stop().await;
                        // The old transmit task is gone with what it held.
                        traffic.outstanding.store(0, Ordering::Relaxed);
                        let slot = self.start_transport(transport.start, pending, Some(traffic));
                        self.transports.insert(transport.id, slot);
                        self.drain(false);
                        Ok(())
                    }
                    None => Err(TransportError::Unknown(transport.id)),
                };
                let _ = reply.send(result);
            }
            Command::Suspend(reply) => {
                self.suspend();
                let _ = reply.send(());
            }
            Command::Resume(reply) => {
                self.resume();
                let _ = reply.send(());
            }
            Command::Mtu(reply) => {
                let _ = reply.send(self.mtu);
            }
            Command::Subscribe(reply) => {
                let _ = reply.send(self.events.subscribe());
            }
            Command::DropCounters(reply) => {
                // Includes failed sends whose signal is not served yet.
                self.send_errors();
                let _ = reply.send(self.drops.clone());
            }
            Command::QueueStats(take, reply) => {
                let _ = reply.send(self.queue_stats(take));
            }
            Command::FragmentStats(reply) => self.fragment_stats(reply),
            Command::TransportStats(reply) => {
                let _ = reply.send(self.transport_stats());
            }
            Command::Status(reply) => {
                let _ = reply.send(self.status());
            }
            command @ (Command::SetTransportMaxDatagram(..)
            | Command::ReportPathMtu(..)
            | Command::PeerMtu(..)
            | Command::PeerMtus(..)
            | Command::PathMtuStats(..)) => self.path_mtu_command(command),
            Command::Shutdown(reply) => return ControlFlow::Break(reply),
        }
        ControlFlow::Continue(())
    }

    /// The high-water marks including the current occupancies; with `take`, the marks
    /// restart at 0 afterwards.
    fn queue_stats(&mut self, take: bool) -> QueueStats {
        let marks = &mut self.high_water;
        // The command being served is not counted.
        marks.command.record(self.commands.len());
        if let Some(local) = &self.local {
            marks.local.record(local.len());
        }
        marks.datagrams.record(self.datagrams.len());
        marks
            .deliver
            .record(self.deliver.max_capacity() - self.deliver.capacity());
        marks.recycle.record(self.recycled.len());
        for slot in self.transports.values() {
            marks.transmit.record(slot.queued());
            marks.backlog.record(slot.pending.len());
        }
        marks
            .events
            .record(self.events.len().min(marks.events.capacity));
        if let Some(workers) = &mut self.workers {
            marks
                .crypto
                .record(std::mem::take(&mut workers.peak).max(workers.in_flight));
            marks.crypto_done.record(workers.done.len());
        }
        let stats = *marks;
        if take {
            for depth in [
                &mut marks.command,
                &mut marks.local,
                &mut marks.datagrams,
                &mut marks.deliver,
                &mut marks.recycle,
                &mut marks.transmit,
                &mut marks.backlog,
                &mut marks.events,
                &mut marks.crypto,
                &mut marks.crypto_done,
            ] {
                depth.high_water = 0;
            }
        }
        stats
    }

    /// Every peer's statistics.
    fn peers(&self) -> Vec<PeerStats> {
        self.core
            .peers()
            .filter_map(|peer| self.core.peer_stats(peer))
            .collect()
    }

    /// A snapshot of the engine, counting the failed sends reported so far.
    fn status(&mut self) -> EngineStatus {
        self.send_errors();
        let queues = self.queue_stats(false);
        EngineStatus {
            public_key: self.core.public_key(),
            mtu: self.mtu,
            suspended: *self.suspended.borrow(),
            peers: self.peers(),
            transports: self.transport_stats(),
            drops: self.drops.clone(),
            queues,
            fragments: self
                .fragmenter
                .as_ref()
                .map(Fragmenter::stats)
                .unwrap_or_default(),
            peer_mtus: self.path_mtus.published.borrow().clone(),
            path_mtu: self
                .path_mtus
                .table
                .as_ref()
                .map(|table| table.stats())
                .unwrap_or_default(),
        }
    }

    /// Handles a command about the path MTUs.
    fn path_mtu_command(&mut self, command: Command) {
        match command {
            Command::SetTransportMaxDatagram(id, max, reply) => {
                self.set_transport_max(id, max);
                let _ = reply.send(());
            }
            Command::ReportPathMtu(report, reply) => {
                let _ = reply.send(self.report_path_mtu(&report));
            }
            Command::PeerMtu(peer, reply) => {
                let _ = reply.send(self.peer_mtu(peer));
            }
            Command::PeerMtus(reply) => {
                let _ = reply.send(self.path_mtus.published.subscribe());
            }
            Command::PathMtuStats(reply) => {
                let stats = self.path_mtus.table.as_ref().map(|table| table.stats());
                let _ = reply.send(stats.unwrap_or_default());
            }
            _ => {}
        }
    }

    /// Sets or clears the largest datagram of transport `id`.
    fn set_transport_max(&mut self, id: TransportId, max: Option<u16>) {
        if max.is_none() && self.path_mtus.table.is_none() {
            return;
        }
        if self.path_mtus.table().set_transport_max(id, max) {
            self.recompute_peer_mtus();
        }
    }

    /// Validates and applies a path MTU report; whether it was accepted.
    fn report_path_mtu(&mut self, report: &PathMtuReport) -> bool {
        let now = now();
        let verdict = self.path_mtus.table().report(report, now, &self.core);
        if verdict == Verdict::Lowered {
            self.recompute_peer_mtus();
        }
        verdict != Verdict::Ignored
    }

    /// The inner MTU of `peer`; `None` for an unknown peer.
    fn peer_mtu(&mut self, peer: PeerId) -> Option<u16> {
        self.core.peer_stats(peer)?;
        let Some(table) = &mut self.path_mtus.table else {
            return Some(self.mtu);
        };
        let mtu = table.peer(peer, self.core.data_path(peer), self.mtu);
        if table.changed() {
            self.publish_peer_mtus();
        }
        Some(mtu)
    }

    /// Recomputes every peer's inner MTU and publishes the result if it changed.
    fn recompute_peer_mtus(&mut self) {
        if let Some(table) = &mut self.path_mtus.table {
            table.recompute(&self.core, self.mtu);
        }
        self.publish_peer_mtus();
    }

    /// Publishes the peers' inner MTUs, if they differ from the published ones.
    fn publish_peer_mtus(&mut self) {
        let mtus = match &mut self.path_mtus.table {
            Some(table) => {
                table.take_changed();
                table.peer_mtus(self.mtu)
            }
            None => PeerMtus::unconstrained(self.mtu),
        };
        self.path_mtus.published.send_if_modified(|current| {
            let modified = *current != mtus;
            if modified {
                *current = mtus;
            }
            modified
        });
    }

    /// The traffic counters of every transport, ordered by id.
    fn transport_stats(&self) -> Vec<TransportStats> {
        self.transports
            .iter()
            .map(|(id, slot)| slot.traffic.stats(*id))
            .collect()
    }

    /// Replies with the counters of the fragmentation stage; all zeros without one.
    fn fragment_stats(&self, reply: oneshot::Sender<FragmentStats>) {
        let stats = self.fragmenter.as_ref().map(Fragmenter::stats);
        let _ = reply.send(stats.unwrap_or_default());
    }

    /// Starts and installs `transport` unless its id is taken.
    fn add_transport(&mut self, transport: NewTransport) -> Result<(), TransportError> {
        if self.transports.contains_key(&transport.id) {
            return Err(TransportError::Duplicate(transport.id));
        }
        let slot = self.start_transport(transport.start, VecDeque::new(), None);
        self.transports.insert(transport.id, slot);
        Ok(())
    }

    /// Hands an injected packet or handshake to the core and sends what it produced.
    fn inject(&mut self, injection: Injection) {
        let now = now();
        match injection {
            Injection::Inbound(peer, packet) => self.core.inject_inbound(peer, packet),
            Injection::Outbound(packet) => self.core.inject_outbound(packet, now),
            Injection::OutboundOn(peer, path, packet) => {
                self.core.inject_outbound_on(peer, path, packet, now);
            }
            Injection::Handshake(peer, path) => self.core.force_handshake(peer, path, now),
            Injection::HandshakeOn(peer, path) => self.core.force_handshake_on(peer, path, now),
        }
        self.drain(false);
    }

    /// Stops and removes transport `id`; the datagrams still queued for it are dropped.
    async fn remove_transport(&mut self, id: TransportId) -> Result<(), TransportError> {
        let old = self
            .transports
            .remove(&id)
            .ok_or(TransportError::Unknown(id))?;
        for (_, data) in old.stop().await {
            self.core.recycle(data);
            self.dropped(None, DROP_TRANSPORT_REMOVED);
        }
        Ok(())
    }

    /// Suspends every I/O task and the owner's own polling, unless already suspended.
    fn suspend(&mut self) {
        self.inline.allowed = false;
        if !self.suspended.send_replace(true) {
            self.event(Event::Suspended);
        }
    }

    /// Resumes after [`Owner::suspend`] and runs the timers that did not fire meanwhile.
    fn resume(&mut self) {
        if self.suspended.send_replace(false) {
            self.inline.allowed = self.fast_path;
            self.event(Event::Resumed);
            self.core.handle_timeout(now());
            self.drain(true);
        }
    }

    /// Spawns the receive and transmit tasks of a transport, with `pending` datagrams
    /// waiting for its transmit queue, counting into `traffic` (new counters if `None`).
    fn start_transport(
        &mut self,
        start: Start,
        pending: VecDeque<Datagram>,
        traffic: Option<Arc<Traffic>>,
    ) -> TransportSlot {
        let traffic = traffic.unwrap_or_else(|| Arc::new(Traffic::new(self.send_errors.clone())));
        let (queue, transmit_rx) = mpsc::channel(self.queue_capacity);
        let (receive, transmit, try_send, reports) = start(
            self.datagram_tx.clone(),
            queue.downgrade(),
            transmit_rx,
            self.recycle_tx.clone(),
            Arc::clone(&traffic),
            self.suspended.subscribe(),
        );
        let reports = reports.map(|reports| {
            let (owner, _) = self
                .path_mtus
                .reports
                .get_or_insert_with(|| mpsc::channel(PATH_MTU_REPORTS));
            Task::spawn(forward_path_mtu(
                reports,
                owner.clone(),
                self.suspended.subscribe(),
            ))
        });
        TransportSlot {
            queue,
            pending,
            flush: None,
            receive,
            transmit,
            reports,
            traffic,
            try_send,
            inline: Vec::new(),
            closed: false,
            backoff: Backoff::default(),
        }
    }

    /// Stops every I/O task and the crypto workers and waits until they are gone.
    async fn stop(&mut self) {
        if let Some(workers) = self.workers.take() {
            for task in workers.tasks {
                task.stop().await;
            }
        }
        for (_, transport) in std::mem::take(&mut self.transports) {
            transport.stop().await;
        }
        for task in self.tasks.drain(..) {
            task.stop().await;
        }
    }

    /// Routes the core's outputs, returns transmitted buffers to the core and arms the
    /// flush of waiting datagrams. With `droppable`, datagrams to transmit may overflow the
    /// waiting datagrams.
    fn drain(&mut self, droppable: bool) {
        self.inline.drains += 1;
        self.inline.send = self.inline.allowed
            && self.datagrams.is_empty()
            && self.local.as_ref().is_none_or(BatchQueue::is_empty);
        while let Some(output) = self.core.poll_output() {
            match output {
                Output::Transmit { path, data } => self.transmit(path, data, droppable),
                Output::Deliver { from, packet } => self.deliver(from, packet),
                Output::Event(event) => self.event(event),
            }
        }
        if std::mem::take(&mut self.inline.queued) {
            while let Some(id) = self
                .transports
                .iter()
                .find(|(_, slot)| !slot.inline.is_empty())
                .map(|(id, _)| *id)
            {
                self.send_inline(id, droppable);
            }
        }
        if !self.sink.delivered.is_empty() {
            self.deliver_inline();
        }
        self.high_water.recycle.record(self.recycled.len());
        while let Ok(buf) = self.recycled.try_recv() {
            self.core.recycle(buf);
        }
        for slot in self.transports.values_mut() {
            if slot.flush.is_none() && !slot.pending.is_empty() {
                slot.flush = Some(Box::pin(slot.queue.clone().reserve_owned()));
            }
        }
    }

    /// Sends a datagram on the transport its path names: without crypto workers, the owner
    /// task sends it itself at the end of the drain when no input is waiting and nothing
    /// of that transport is waiting, queued or being sent, and otherwise queues it.
    fn transmit(&mut self, path: Path, data: PacketBuf, droppable: bool) {
        if self.inline.send
            && let Some(slot) = self.transports.get_mut(&path.transport)
            && (!slot.inline.is_empty() || (slot.backoff.ready(self.inline.drains) && slot.idle()))
        {
            slot.inline.push((path, data));
            self.inline.queued = true;
            if slot.inline.len() >= MAX_BATCH {
                self.send_inline(path.transport, droppable);
            }
            return;
        }
        self.queue_datagram(path, data, droppable);
    }

    /// Hands the datagrams collected for transport `id` to it without waiting; returns the
    /// buffers of those it is done with to the core and queues the rest, in order.
    fn send_inline(&mut self, id: TransportId, droppable: bool) {
        let Some(slot) = self.transports.get_mut(&id) else {
            return;
        };
        let mut batch = std::mem::take(&mut slot.inline);
        let sent = slot.send_now(&batch);
        slot.backoff.record(self.inline.drains, sent > 0);
        for (path, data) in batch.drain(sent..) {
            self.queue_datagram(path, data, droppable);
        }
        while let Some((_, data)) = batch.pop() {
            self.core.recycle(data);
        }
        if let Some(slot) = self.transports.get_mut(&id) {
            slot.inline = batch;
        }
    }

    /// Queues a datagram for the transport its path names.
    fn queue_datagram(&mut self, path: Path, data: PacketBuf, droppable: bool) {
        let result = match self.transports.get_mut(&path.transport) {
            Some(slot) => {
                let result = slot.transmit((path, data), droppable, self.queue_capacity);
                self.high_water.transmit.record(slot.queued());
                self.high_water.backlog.record(slot.pending.len());
                result
            }
            None => Err((data, DROP_NO_TRANSPORT)),
        };
        if let Err((data, reason)) = result {
            self.core.recycle(data);
            self.dropped(None, reason);
        }
    }

    /// Moves the waiting datagrams of transport `id` to its transmit queue until it is full,
    /// in order.
    fn move_pending(&mut self, id: TransportId) {
        let Some(slot) = self.transports.get_mut(&id) else {
            return;
        };
        for (path, data) in std::mem::take(&mut slot.pending) {
            self.transmit(path, data, false);
        }
    }

    /// Delivers a packet: without crypto workers, the owner task hands it to the sink itself
    /// at the end of the drain when no packet is queued for or being delivered by the sink
    /// task, and otherwise queues it.
    fn deliver(&mut self, from: PeerId, packet: PacketBuf) {
        let sink = &mut self.sink;
        if self.inline.allowed
            && !sink.closed
            && (!sink.delivered.is_empty()
                || (sink.backoff.ready(self.inline.drains)
                    && sink.outstanding.load(Ordering::Acquire) == 0))
        {
            sink.delivered.push_back((from, packet));
            if sink.delivered.len() >= MAX_BATCH {
                self.deliver_inline();
            }
            return;
        }
        self.queue_delivery(from, packet);
    }

    /// Hands the packets collected for the sink to it without waiting and queues the rest,
    /// in order.
    fn deliver_inline(&mut self) {
        let mut packets = std::mem::take(&mut self.sink.delivered);
        let offered = packets.len();
        while !packets.is_empty() {
            match (self.sink.try_deliver)(&mut packets) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    tracing::debug!("Packet sink closed");
                    self.sink.closed = true;
                    break;
                }
                Err(e) => tracing::warn!(message = "Packet sink error", error = ?e),
            }
        }
        self.sink
            .backoff
            .record(self.inline.drains, packets.len() < offered);
        while let Some((from, packet)) = packets.pop_front() {
            self.queue_delivery(from, packet);
        }
        self.sink.delivered = packets;
    }

    /// Queues a packet for the sink task.
    fn queue_delivery(&mut self, from: PeerId, packet: PacketBuf) {
        if self.sink.closed {
            self.core.recycle(packet);
            self.dropped(Some(from), DROP_SINK_CLOSED);
            return;
        }
        self.sink.outstanding.fetch_add(1, Ordering::Relaxed);
        let result = self.deliver.try_send((from, packet));
        if result.is_err() {
            self.sink.outstanding.fetch_sub(1, Ordering::Relaxed);
        }
        let reason = match result {
            Ok(()) => {
                let queued = self.deliver.max_capacity() - self.deliver.capacity();
                self.high_water.deliver.record(queued);
                return;
            }
            Err(TrySendError::Full((_, packet))) => {
                self.high_water
                    .deliver
                    .record(self.high_water.deliver.capacity);
                self.core.recycle(packet);
                DROP_SINK_FULL
            }
            Err(TrySendError::Closed((_, packet))) => {
                self.core.recycle(packet);
                DROP_SINK_CLOSED
            }
        };
        self.dropped(Some(from), reason);
    }

    fn dropped(&mut self, peer: Option<PeerId>, reason: &'static str) {
        self.event(Event::Dropped { peer, reason });
    }

    /// Counts and publishes the failed sends the transmit tasks reported.
    fn send_errors(&mut self) {
        for _ in 0..self.send_errors.take() {
            self.dropped(None, DROP_TRANSPORT_SEND_ERROR);
        }
    }

    /// Counts drops and publishes the event; never blocks.
    fn event(&mut self, event: Event) {
        if let Event::PathAdopted { peer, .. } = event
            && let Some(table) = &mut self.path_mtus.table
        {
            table.peer(peer, self.core.data_path(peer), self.mtu);
            if table.changed() {
                self.publish_peer_mtus();
            }
        }
        let dropped = if let Event::Dropped { reason, .. } = event {
            *self.drops.entry(reason).or_default() += 1;
            true
        } else {
            false
        };
        // No subscribers is not an error.
        let _ = self.events.send(event);
        // Reading the occupancy takes the channel's locks: not on the per-packet drop path.
        if !dropped {
            let depth = &mut self.high_water.events;
            depth.record(self.events.len().min(depth.capacity));
        }
    }
}

/// Whether `command` reads or changes peers, counters or sessions, so that it waits for the
/// jobs with the crypto workers to act after every packet read before it.
const fn settles(command: &Command) -> bool {
    matches!(
        command,
        Command::Config(..)
            | Command::PeerStats(..)
            | Command::Peers(..)
            | Command::Inject(..)
            | Command::DropCounters(..)
            | Command::Status(..)
    )
}

/// Runs the batches of jobs from the owner, in order, and hands them back until the owner is
/// gone.
async fn crypto_worker(
    mut jobs: mpsc::Receiver<Vec<CryptoJob>>,
    done: mpsc::Sender<Vec<CryptoJob>>,
) {
    while let Some(mut batch) = jobs.recv().await {
        batch.iter_mut().for_each(CryptoJob::run);
        // The queue holds a batch of each job in flight, so this does not wait.
        if done.send(batch).await.is_err() {
            return;
        }
    }
}

/// Waits while the engine is suspended; `false` once the engine is gone.
async fn running(suspended: &mut watch::Receiver<bool>) -> bool {
    suspended.wait_for(|suspended| !suspended).await.is_ok()
}

/// Forwards every change of the source's MTU watch to the owner until the sender is dropped.
/// Changes while suspended collapse into the latest value, forwarded after resuming.
async fn watch_mtu(
    mut mtu: watch::Receiver<u16>,
    changes: mpsc::Sender<u16>,
    mut suspended: watch::Receiver<bool>,
) {
    while mtu.changed().await.is_ok() {
        if !running(&mut suspended).await {
            return;
        }
        let value = *mtu.borrow_and_update();
        if changes.send(value).await.is_err() {
            return;
        }
    }
}

/// Forwards a transport's path MTU reports to the owner until either side is gone. Reports
/// that arrive while suspended wait until the engine resumes.
async fn forward_path_mtu(
    mut reports: mpsc::Receiver<PathMtuReport>,
    owner: mpsc::Sender<PathMtuReport>,
    mut suspended: watch::Receiver<bool>,
) {
    while let Some(report) = reports.recv().await {
        if !running(&mut suspended).await || owner.send(report).await.is_err() {
            return;
        }
    }
}

/// Reads batches of local packets into the owner's queue until the source closes.
async fn read_source<Src: PacketSource>(
    mut source: Src,
    local: BatchSender<PacketBuf>,
    mut suspended: watch::Receiver<bool>,
) {
    let mut batch = PacketBatch::new();
    let mut packets = VecDeque::with_capacity(MAX_BATCH);
    while running(&mut suspended).await {
        let result = source.recv_batch(&mut batch).await;
        packets.extend(batch.drain());
        if local.send(&mut packets).await.is_err() {
            return;
        }
        match result {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                tracing::debug!("Packet source closed");
                return;
            }
            Err(e) => tracing::warn!(message = "Packet source error", error = ?e),
        }
    }
}

/// Delivers decrypted packets to the sink in batches of what is queued, until it closes.
async fn write_sink<Snk: PacketSink>(
    sink: Arc<Snk>,
    mut deliver: mpsc::Receiver<(PeerId, PacketBuf)>,
    outstanding: Arc<AtomicUsize>,
    mut suspended: watch::Receiver<bool>,
) {
    let mut packets = VecDeque::with_capacity(MAX_BATCH);
    while let Some(first) = deliver.recv().await {
        packets.push_back(first);
        while packets.len() < MAX_BATCH {
            let Ok(next) = deliver.try_recv() else { break };
            packets.push_back(next);
        }
        let taken = packets.len();
        if !running(&mut suspended).await {
            return;
        }
        while !packets.is_empty() {
            match sink.send_batch(&mut packets).await {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    tracing::debug!("Packet sink closed");
                    return;
                }
                Err(e) => tracing::warn!(message = "Packet sink error", error = ?e),
            }
        }
        // Done with the batch: the owner may deliver itself once nothing else is queued.
        outstanding.fetch_sub(taken, Ordering::Release);
    }
}

/// Receives batches of datagrams into the owner's queue until the transport closes, counting
/// them in `traffic`.
async fn receive<T: Transport>(
    transport: Arc<T>,
    datagrams: BatchSender<Datagram>,
    traffic: Arc<Traffic>,
    mut suspended: watch::Receiver<bool>,
) {
    let mut buf = PacketBuf::with_capacity(MAX_DATAGRAM);
    let mut received = VecDeque::with_capacity(MAX_BATCH);
    while running(&mut suspended).await {
        let result = transport.recv_batch(&mut buf, &mut received).await;
        if !received.is_empty() {
            let bytes = received.iter().map(|(_, data)| data.len() as u64).sum();
            traffic
                .rx_datagrams
                .fetch_add(received.len() as u64, Ordering::Relaxed);
            traffic.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
        if datagrams.send(&mut received).await.is_err() {
            return;
        }
        match result {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                tracing::debug!("Transport closed for receiving");
                return;
            }
            Err(e) => tracing::debug!(message = "Transport receive error", error = ?e),
        }
    }
}

/// Runs `future` unless `stop` fires first; `None` when stopped.
async fn unless_stopped<F: Future>(
    stop: &mut oneshot::Receiver<()>,
    future: F,
) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    poll_fn(|cx| {
        if Pin::new(&mut *stop).poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        future.as_mut().poll(cx).map(Some)
    })
    .await
}

/// Sends queued datagrams in batches of up to [`MAX_BATCH`] until the transport closes;
/// returns the buffers for reuse and counts the datagrams it is done with, and every failed
/// one, in `traffic`. Once `stop` fires, hands back its queue and the
/// datagrams of the batch it was sending that were not sent.
///
/// Every datagram of a batch after the first keeps its slot in the queue reserved (through
/// `slots`, the queue's sender) until the batch is done, so a batch holds no more of the
/// transport's datagrams than sending them one by one would; one more only when the owner
/// takes a freed slot first, which ends the batch.
async fn transmit<T: Transport>(
    transport: Arc<T>,
    slots: mpsc::WeakSender<Datagram>,
    mut queue: mpsc::Receiver<Datagram>,
    recycle: mpsc::Sender<PacketBuf>,
    traffic: Arc<Traffic>,
    mut suspended: watch::Receiver<bool>,
    mut stop: oneshot::Receiver<()>,
) -> Option<Unsent> {
    let mut batch = Vec::with_capacity(MAX_BATCH);
    let mut reserved = Vec::with_capacity(MAX_BATCH);
    loop {
        let Some(next) = unless_stopped(&mut stop, queue.recv()).await else {
            return Some((queue, batch));
        };
        batch.push(next?);
        // Every datagram after the first holds a reserved slot.
        while reserved.len() + 1 < MAX_BATCH {
            let Ok(next) = queue.try_recv() else { break };
            batch.push(next);
            // The owner may take the freed slot first; the batch then ends here.
            match slots.upgrade().map(mpsc::Sender::try_reserve_owned) {
                Some(Ok(slot)) => reserved.push(slot),
                _ => break,
            }
        }
        let mut sent = 0;
        let outcome = unless_stopped(&mut stop, async {
            // `false` once the engine is gone or the transport is closed.
            if !running(&mut suspended).await {
                return false;
            }
            loop {
                let before = sent;
                let mut failed = 0;
                let Err(e) = transport.send_batch(&batch, &mut sent, &mut failed).await else {
                    sent = batch.len();
                    return true;
                };
                // The failed datagram is dropped, even if the transport did not count it or
                // advance past it. Only the datagrams the call reports failed are counted
                // (a failed segmented send loses its run, not the runs handed off before
                // it), at least one and never more than the call was done with.
                sent = sent.max(before + 1).min(batch.len());
                traffic.failed(failed.clamp(1, sent - before));
                if e.kind() == io::ErrorKind::BrokenPipe {
                    tracing::debug!("Transport closed for sending");
                    return false;
                }
                tracing::debug!(message = "Transport send error", error = ?e);
                if sent == batch.len() {
                    return true;
                }
            }
        })
        .await;
        reserved.clear();
        let done = sent.min(batch.len());
        traffic.sent(&batch[..done]);
        if outcome == Some(false) {
            return None;
        }
        for (_, data) in batch.drain(..done) {
            // A full recycle queue just drops the buffer.
            let _ = recycle.try_send(data);
        }
        if outcome.is_none() {
            // Stopped: the datagrams not sent go back with the queue, in order.
            return Some((queue, batch));
        }
        // Done with the batch: the owner may send itself once nothing else is queued.
        traffic.outstanding.fetch_sub(done, Ordering::Release);
    }
}
