//! The running engine: one owner task drives the core, I/O tasks feed it through bounded
//! queues.

mod command;
mod input;
mod output;
mod path_mtu;
mod queue;
mod run;
mod tasks;
mod transport;
mod workers;

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use nsplane_core::x25519::StaticSecret;
use nsplane_core::{Core, CoreConfig, CryptoJob, Event};
#[cfg(doc)]
use nsplane_packet::Path;
use nsplane_packet::{MAX_BATCH, PacketBuf, PeerId, TransportId};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep, sleep_until};

use self::input::{Barriers, PlaintextQueue};
use self::output::{Inline, InlineSink};
use self::path_mtu::PathMtus;
use self::queue::{BatchQueue, BatchSender, batch_queue};
pub(crate) use self::tasks::SourceTaken;
use self::tasks::{read_source, watch_mtu, write_sink};
pub(crate) use self::transport::NewTransport;
use self::transport::{Datagram, DeliverRoom, Recycle, SendErrors, TransportSlot};
use self::workers::Workers;
use crate::fragment::Fragmenter;
use crate::handle::{Command, EngineHandle, Plaintext, QueueDepth, QueueStats};
use crate::io::{PacketSink, PacketSource};
#[cfg(doc)]
use crate::transport::Transport;

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
/// a receive task ([`Transport::recv`]) and a transmit task ([`Transport::send`]). The owner
/// hands the datagrams one drain of the core queues for a transport to its transmit task as
/// one message (up to [`MAX_BATCH`]; the transmit queue stays bounded in datagrams), and the
/// transmit task sends what is queued in batches of up to [`MAX_BATCH`]. The core
/// is never shared. Each peer owns its tunnel; receive replay validation takes a lock
/// even without crypto workers. With workers each tunnel stays behind a mutex, but only
/// the owner locks it: the owner reserves a local packet's counter or checks a received message's
/// session and replay window, and hands the job a seal or open ticket (session key and
/// counter), so a job never touches the tunnel; the owner commits each open, in order,
/// when it completes the job. The mutex is therefore uncontended.
///
/// Transports: the engine runs any number of transports, keyed by [`Transport::id`]. Every
/// transport's received datagrams feed the core through one queue, so a peer's
/// authenticated traffic may arrive on any transport permitted by its local identity
/// (the [`PathPolicy`] decides whether its path follows). A datagram to transmit goes
/// to the transport named by its
/// [`Path::transport`]; when none is installed under that id, it is dropped and counted
/// under [`crate::DROP_NO_TRANSPORT`]. Each transport's tasks are spawned for its concrete
/// type when it is added, so no datagram goes through a boxed future (unless the transport
/// is a boxed [`DynTransport`]).
///
/// Backpressure: since each received datagram may deliver a packet, the owner reads received
/// datagrams only while the deliver queue has room for them (beyond those with the crypto
/// workers), as many at once, so a sink slower than the network holds the datagrams back in
/// the transport (for UDP, the socket's buffer) instead of dropping decrypted packets. A
/// stalled sink so also delays the handshakes and keepalives that arrive behind them; once
/// the sink is closed, nothing is held back. A packet that still finds the deliver queue full
/// (one injected with a handle call, say) is dropped and counted under
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
/// woken. What the transport or sink does
/// not take at once (it would block, or it takes part of the batch) goes to the transmit
/// queue and backlog, or the deliver queue, in order and under the rules above; later datagrams and packets queue behind it until the
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
/// sink go back to the core's pool with [`Core::recycle`]. Transmitted buffers go back to
/// the source task, one message per batch sent (by the transmit task, or by the owner task
/// when it sent them itself), which hands them to [`PacketSource::recycle`] before its next
/// read, so the source can read into them again. That queue is bounded in buffers and
/// lossy: a full queue drops them (the owner task puts its own into the core's pool
/// instead), so returning a buffer never waits, and a stopped or suspended source task
/// takes none. A source that takes none of the first buffers it is given (it keeps the
/// default) is given none again: the transmitted buffers then go back to the owner task
/// over a bounded queue (dropped when it is full) and into the core's pool. Delivered
/// packets are owned by the sink.
///
/// Suspension: [`EngineHandle::suspend`] pauses the engine without tearing it down. While
/// suspended, every I/O task waits before its next read or write (one already in progress
/// may complete), so datagrams that arrive stay in the socket's buffer, and the owner task
/// polls neither its packet queues nor the core's timer. Independently owned transport
/// tasks, such as link dialing and pings, are not paused by this gate. Handle
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
/// owner, which then never sends or delivers inline. The owner reserves each local packet's
/// counter (nonce) in order and checks each received datagram against the replay window
/// when it hands the job out; the jobs go to the workers in turn, whatever their peer (in
/// batches, handed over when one is full or the owner has nothing else to do), so one peer's
/// packets are encrypted on every worker in parallel (on a multi-threaded runtime). The owner
/// completes the jobs in the order it handed them out, marking each received datagram's
/// counter as received only then, so each peer's packets leave in the order they came and a
/// duplicate opened on two workers at once is still rejected. Queue capacity limits input
/// admission to the workers; fragmentation can expand an admitted packet into several
/// jobs and exceed that budget. While the budget is reached, the owner stops reading local
/// packets and received datagrams, and the received datagrams with the workers count
/// against the deliver queue's room (see Backpressure). Likewise, the local packets with
/// the workers count against the room for local packets, so a slow transport holds back
/// the source instead of dropping their datagrams under [`crate::DROP_TRANSMIT_FULL`].
/// Before `ConfigChange` commands, peer statistics/session/list queries, injections, drop
/// counter and status queries, unanswered-handshake queries, and identity removal/list
/// queries, the owner waits for outstanding jobs. Key/ID and transport-counter queries
/// do not wait for workers.
///
/// Local barrier: [`EngineHandle::local_barrier`] waits until every local packet the source
/// task took before the call has been routed and filtered or dropped; the source task counts
/// each read in a counter the handles share, the owner counts what it took through the core.
///
/// Plaintext ingress: with [`EngineBuilder::plaintext_ingress`] the owner also polls a
/// bounded queue of plaintext packets attributed to peers, next to the received datagrams and
/// under the same deliver-queue backpressure, and runs each through
/// [`Core::receive_plaintext`].
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
/// [`EngineBuilder::plaintext_ingress`]: crate::EngineBuilder::plaintext_ingress
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
    /// The queue of [`crate::PlaintextIngress`], if built.
    pub(crate) plaintext: Option<mpsc::Receiver<Plaintext>>,
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
    let (recycle, source_recycled, recycled) = Recycle::new(capacity);
    let (signal, send_error_signal) = mpsc::channel(1);
    let (deliver, deliver_rx) = mpsc::channel(capacity);
    let sink = Arc::new(parts.sink);
    let sink_outstanding = Arc::new(AtomicUsize::new(0));
    let (events, _) = broadcast::channel(parts.event_capacity);
    let (suspended, _) = watch::channel(false);
    let (mtu_tx, mtu_changes) = mpsc::channel(1);
    let mut mtu_watch = parts.source.mtu();
    let mtu = *mtu_watch.borrow_and_update();
    let source_taken = Arc::new(SourceTaken::default());

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
        recycle_bufs: Vec::new(),
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
            Task::spawn(read_source(
                parts.source,
                local_tx,
                source_recycled,
                Arc::clone(&recycle.declined),
                Arc::clone(&source_taken),
                suspended.subscribe(),
            )),
            Task::spawn(write_sink(
                Arc::clone(&sink),
                deliver_rx,
                Arc::clone(&sink_outstanding),
                suspended.subscribe(),
            )),
        ],
        recycle,
        queue_capacity: capacity,
        high_water: queue_marks(capacity, parts.event_capacity, crypto_capacity),
        local_first: false,
        suspended,
        fast_path,
        inline: Inline {
            allowed: fast_path,
            send: false,
            queued: false,
            drains: 0,
        },
        staged: false,
        deliver_room: None,
        sink: InlineSink::new(sink, sink_outstanding, fast_path),
        workers,
        datagram_batch: Vec::with_capacity(MAX_BATCH),
        local_batch: Vec::with_capacity(MAX_BATCH),
        jobs: Vec::with_capacity(MAX_BATCH),
        barriers: Barriers::default(),
        plaintext: parts.plaintext.map(|packets| PlaintextQueue {
            packets,
            first: false,
        }),
    };
    for transport in parts.transports {
        let slot = owner.start_transport(transport.start, VecDeque::new(), None);
        owner.transports.insert(transport.id, slot);
    }

    Engine {
        handle: EngineHandle::new(command_tx, source_taken),
        owner: Some(tokio::spawn(owner.run())),
    }
}

/// The queue capacities, with no high-water marks yet.
const fn queue_marks(capacity: usize, events: usize, crypto: usize) -> QueueStats {
    QueueStats {
        command: QueueDepth::new(COMMAND_CAPACITY),
        local: QueueDepth::new(capacity),
        datagrams: QueueDepth::new(capacity),
        deliver: QueueDepth::new(capacity),
        recycle: QueueDepth::new(capacity),
        transmit: QueueDepth::new(capacity),
        backlog: QueueDepth::new(capacity),
        events: QueueDepth::new(events),
        crypto: QueueDepth::new(crypto),
        crypto_done: QueueDepth::new(crypto),
    }
}

/// The current time on tokio's clock, so a paused runtime clock drives the core too.
fn now() -> std::time::Instant {
    Instant::now().into_std()
}

/// A spawned task, aborted when dropped.
struct Task(JoinHandle<()>);

impl Task {
    pub(super) fn spawn(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(tokio::spawn(future))
    }

    /// Aborts the task and waits until it is gone.
    pub(super) async fn stop(mut self) {
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
    /// Transmitted buffers returned to the owner task, while the source takes none.
    recycled: BatchQueue<PacketBuf>,
    /// Reused for the buffers taken from `recycled`.
    recycle_bufs: Vec<PacketBuf>,
    /// Where transmitted buffers go back; cloned into every transmit task.
    recycle: Recycle,
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
    /// Armed while the deliver queue has no room and no job that may deliver is with the
    /// crypto workers, so only the sink task can make room.
    deliver_room: Option<DeliverRoom>,
    /// Capacities and high-water marks of the queues, without the current occupancies.
    high_water: QueueStats,
    /// Alternates which of local packets and datagrams is polled first.
    local_first: bool,
    /// Whether the engine is suspended; every I/O task watches it.
    suspended: watch::Sender<bool>,
    /// No crypto workers: the owner task may send datagrams and deliver packets itself.
    fast_path: bool,
    inline: Inline,
    /// Some transport has datagrams in [`TransportSlot::staged`].
    staged: bool,
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
    barriers: Barriers,
    /// The plaintext ingress queue; `None` without one or once every entry is gone.
    plaintext: Option<PlaintextQueue>,
}
