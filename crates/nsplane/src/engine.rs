//! The running engine: one owner task drives the core, I/O tasks feed it through bounded
//! queues.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use nsplane_core::x25519::StaticSecret;
use nsplane_core::{ConfigChange, Core, CoreConfig, Event, Input, Output};
use nsplane_packet::{PacketBuf, Path, PeerId, TransportId};
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep, sleep_until};

use crate::events::{
    DROP_NO_TRANSPORT, DROP_SINK_CLOSED, DROP_SINK_FULL, DROP_TRANSMIT_FULL, DROP_TRANSPORT_CLOSED,
    DROP_TRANSPORT_REMOVED, DROP_TRANSPORT_SEND_ERROR,
};
use crate::handle::{Command, EngineHandle, QueueDepth, QueueStats, TransportError};
use crate::io::{PacketSink, PacketSource};
use crate::transport::Transport;

/// Capacity of the command queue from the handles to the owner task.
const COMMAND_CAPACITY: usize = 64;
/// Size of the receive buffer: the largest UDP payload.
const MAX_DATAGRAM: usize = 65535;

/// A running engine.
///
/// One owner task owns the [`Core`] and loops: it waits for a handle command, a local packet,
/// a received datagram or the core's next timeout, feeds the core and drains its outputs.
/// I/O tasks surround it, each connected through a bounded queue: the source task
/// ([`PacketSource::recv`]), the sink task ([`PacketSink::send`]) and, for every transport,
/// a receive task ([`Transport::recv`]) and a transmit task ([`Transport::send`]). The core
/// is never shared, so there are no locks on the data path.
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
/// handle calls always wait and may take a backlog past the bound. The owner stops reading
/// local packets only while at least one transport is installed and every installed
/// transport's backlog is at the bound (which transport a local packet leads to is only
/// known once the core has handled it), which in turn holds back the source. So an engine
/// with one transport holds back its local packets instead of dropping them, while with
/// several transports a stalled one never holds back local packets for the others: those
/// for the stalled one are dropped once its backlog is full. With no transport installed,
/// local reads never pause. Received datagrams, timers and handle calls are served
/// meanwhile. A transport that never drains keeps its backlog until it closes (the backlog
/// is then dropped under [`crate::DROP_TRANSPORT_CLOSED`]) or is removed with
/// [`EngineHandle::remove_transport`], which counts every datagram still queued for it
/// (being sent, in its transmit queue or in its backlog) under
/// [`crate::DROP_TRANSPORT_REMOVED`]. [`EngineHandle::replace_transport`] moves all of them,
/// in order, to the new transport instead.
///
/// Buffers: datagrams are received into one reusable 64 KiB buffer and copied into an
/// exactly sized [`PacketBuf`], so queued datagrams do not each pin 64 KiB. The core takes
/// each datagram by value: it delivers a decrypted packet in the datagram's own buffer and
/// puts the buffers of all other datagrams into its pool itself. Buffers rejected by a full
/// sink and transmitted buffers (returned by the transmit task over a bounded queue, dropped
/// when it is full) go back to the core's pool with [`Core::recycle`]. Delivered packets are
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
/// When an I/O side reports [`io::ErrorKind::BrokenPipe`], its task stops and the engine
/// keeps running without it; other I/O errors are logged and the task continues. A datagram
/// the transport fails to send (any error, [`io::ErrorKind::BrokenPipe`] included) is
/// dropped and counted under [`crate::DROP_TRANSPORT_SEND_ERROR`]: the transmit task counts
/// it in a counter shared with the owner task and wakes the owner, which publishes the
/// drops, so a successful send costs nothing extra.
///
/// The engine runs until [`EngineHandle::shutdown`]. Dropping the `Engine` aborts every task
/// at once, so keep it alive (typically by awaiting [`Engine::wait`]) for as long as the
/// engine should run; handles alone do not keep it running.
///
/// [`PathPolicy`]: nsplane_core::PathPolicy
/// [`DynTransport`]: crate::DynTransport
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
}

/// Spawns the owner task and the I/O tasks.
pub(crate) fn spawn<Src: PacketSource, Snk: PacketSink>(parts: Parts<Src, Snk>) -> Engine {
    let capacity = parts.queue_capacity;
    let (command_tx, commands) = mpsc::channel(COMMAND_CAPACITY);
    let (local_tx, local) = mpsc::channel(capacity);
    let (datagram_tx, datagrams) = mpsc::channel(capacity);
    let (recycle_tx, recycled) = mpsc::channel(capacity);
    let (signal, send_error_signal) = mpsc::channel(1);
    let (deliver, deliver_rx) = mpsc::channel(capacity);
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
        tasks: vec![
            Task::spawn(watch_mtu(mtu_watch, mtu_tx, suspended.subscribe())),
            Task::spawn(read_source(parts.source, local_tx, suspended.subscribe())),
            Task::spawn(write_sink(parts.sink, deliver_rx, suspended.subscribe())),
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
        },
        local_first: false,
        suspended,
    };
    for transport in parts.transports {
        let slot = owner.start_transport(transport.start, VecDeque::new());
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

/// What a stopped transmit task hands back: its queue and the datagram it was sending.
type Unsent = (mpsc::Receiver<Datagram>, Option<Datagram>);

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

/// Spawns a transport's receive and transmit tasks, given the queue receiving its datagrams,
/// its transmit queue, the queue returning transmitted buffers, where to report failed
/// sends and the suspension state.
type Start = Box<
    dyn FnOnce(
            mpsc::Sender<Datagram>,
            mpsc::Receiver<Datagram>,
            mpsc::Sender<PacketBuf>,
            SendErrors,
            watch::Receiver<bool>,
        ) -> (Task, Transmitter)
        + Send,
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
            start: Box::new(move |datagrams, queue, recycle, errors, suspended| {
                let transport = Arc::new(transport);
                let (stop, stopped) = oneshot::channel();
                (
                    Task::spawn(receive(
                        Arc::clone(&transport),
                        datagrams,
                        suspended.clone(),
                    )),
                    Transmitter {
                        stop: Some(stop),
                        task: tokio::spawn(transmit(
                            transport, queue, recycle, errors, suspended, stopped,
                        )),
                    },
                )
            }),
        }
    }
}

/// Where transmit tasks report failed sends: a count the owner task takes, and a signal
/// that wakes it.
#[derive(Clone)]
struct SendErrors {
    count: Arc<AtomicU64>,
    /// The owner keeps a sender, so the signal never closes; a full signal is already
    /// pending.
    signal: mpsc::Sender<()>,
}

impl SendErrors {
    fn report(&self) {
        // The signal orders the count before the owner's take.
        self.count.fetch_add(1, Ordering::Relaxed);
        let _ = self.signal.try_send(());
    }

    /// The failed sends since the last take.
    fn take(&self) -> u64 {
        self.count.swap(0, Ordering::Relaxed)
    }
}

/// An installed transport: its transmit queue, the datagrams waiting for room in it and its
/// two tasks.
struct TransportSlot {
    queue: mpsc::Sender<Datagram>,
    /// Datagrams waiting for room in the transmit queue, oldest first.
    pending: VecDeque<Datagram>,
    /// Armed while `pending` is not empty.
    flush: Option<Reserve>,
    receive: Task,
    transmit: Transmitter,
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
        let datagram = if self.pending.is_empty() {
            match self.queue.try_send(datagram) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(datagram)) => datagram,
                Err(TrySendError::Closed((_, data))) => return Err((data, DROP_TRANSPORT_CLOSED)),
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

    /// Stops both tasks and returns every datagram still queued for the transport, oldest
    /// first: the one being sent, the transmit queue's, then the waiting ones.
    async fn stop(mut self) -> VecDeque<Datagram> {
        self.flush = None;
        self.receive.stop().await;
        let mut unsent = self.transmit.stop().await;
        unsent.append(&mut self.pending);
        unsent
    }

    /// Datagrams in the transmit queue, counting a reserved slot.
    fn queued(&self) -> usize {
        self.queue.max_capacity() - self.queue.capacity()
    }
}

/// What woke the owner task.
enum Wake {
    Command(Option<Command>),
    Datagram(Option<Datagram>),
    Local(Option<PacketBuf>),
    Mtu(Option<u16>),
    /// A transmit task reported failed sends.
    SendErrors,
    /// Room in the transmit queue of a transport with waiting datagrams.
    Flush(TransportId, Option<OwnedPermit<Datagram>>),
    Timer,
}

/// The state of the owner task.
struct Owner {
    core: Core,
    /// The last private key given to the engine.
    private_key: Option<StaticSecret>,
    commands: mpsc::Receiver<Command>,
    /// Local packets; `None` once the source task has stopped.
    local: Option<mpsc::Receiver<PacketBuf>>,
    datagrams: mpsc::Receiver<Datagram>,
    /// Cloned into every transport receive task.
    datagram_tx: mpsc::Sender<Datagram>,
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
    /// The MTU watcher, source and sink tasks.
    tasks: Vec<Task>,
    queue_capacity: usize,
    /// Capacities and high-water marks of the queues, without the current occupancies.
    high_water: QueueStats,
    /// Alternates which of local packets and datagrams is polled first.
    local_first: bool,
    /// Whether the engine is suspended; every I/O task watches it.
    suspended: watch::Sender<bool>,
}

impl Owner {
    async fn run(mut self) {
        loop {
            self.arm_timer();
            let wake = poll_fn(|cx| self.poll_wake(cx)).await;
            // Datagrams caused by local packets, the network or a timer may overflow the
            // waiting datagrams.
            let droppable = matches!(wake, Wake::Local(_) | Wake::Datagram(_) | Wake::Timer);
            match wake {
                Wake::Command(None) => break,
                Wake::Command(Some(command)) => {
                    if let ControlFlow::Break(reply) = self.command(command).await {
                        self.stop().await;
                        // The caller may have stopped waiting.
                        let _ = reply.send(());
                        return;
                    }
                }
                Wake::Datagram(Some((path, data))) => {
                    self.high_water
                        .datagrams
                        .record_received(self.datagrams.len());
                    self.core
                        .handle_input(Input::Datagram { path, data }, now());
                }
                // The owner keeps a sender, so the queue never closes.
                Wake::Datagram(None) => {}
                Wake::Local(Some(packet)) => {
                    if let Some(local) = &self.local {
                        self.high_water.local.record_received(local.len());
                    }
                    self.core.handle_input(Input::Local { packet }, now());
                }
                Wake::Local(None) => self.local = None,
                Wake::Mtu(Some(mtu)) => {
                    if mtu != self.mtu {
                        self.mtu = mtu;
                        self.event(Event::MtuChanged { mtu });
                    }
                }
                Wake::Mtu(None) => self.mtu_changes = None,
                Wake::SendErrors => self.send_errors(),
                Wake::Flush(id, permit) => {
                    // No permit: the transmit queue closed, and moving drops the datagrams.
                    if let Some(permit) = permit
                        && let Some(slot) = self.transports.get_mut(&id)
                        && let Some(datagram) = slot.pending.pop_front()
                    {
                        permit.send(datagram);
                        self.high_water.transmit.record(slot.queued());
                    }
                    self.move_pending(id);
                }
                Wake::Timer => self.core.handle_timeout(now()),
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
        if let Some(changes) = &mut self.mtu_changes
            && let Poll::Ready(mtu) = changes.poll_recv(cx)
        {
            return Poll::Ready(Wake::Mtu(mtu));
        }
        if self.send_error_signal.poll_recv(cx).is_ready() {
            return Poll::Ready(Wake::SendErrors);
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Wake::Timer);
        }
        Poll::Pending
    }

    /// Polls the source queue, unless every installed transport's waiting datagrams are at
    /// the bound.
    fn poll_local(&mut self, cx: &mut Context<'_>) -> Poll<Wake> {
        let bound = self.queue_capacity;
        let full = !self.transports.is_empty()
            && self
                .transports
                .values()
                .all(|slot| slot.pending.len() >= bound);
        match &mut self.local {
            Some(local) if !full => local.poll_recv(cx).map(Wake::Local),
            _ => Poll::Pending,
        }
    }

    fn arm_timer(&mut self) {
        if let Some(deadline) = self.core.poll_timeout() {
            let deadline = Instant::from_std(deadline);
            if self.timer.deadline() != deadline {
                self.timer.as_mut().reset(deadline);
            }
        }
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
                let _ = reply.send(());
            }
            Command::PeerId(key, reply) => {
                let _ = reply.send(self.core.peer_id(&key));
            }
            Command::PeerStats(peer, reply) => {
                let _ = reply.send(self.core.peer_stats(peer));
            }
            Command::Peers(reply) => {
                let peers = self
                    .core
                    .peers()
                    .filter_map(|peer| self.core.peer_stats(peer))
                    .collect();
                let _ = reply.send(peers);
            }
            Command::PublicKey(reply) => {
                let _ = reply.send(self.core.public_key());
            }
            Command::PrivateKey(reply) => {
                let _ = reply.send(self.private_key.clone());
            }
            Command::InjectInbound(peer, packet, reply) => {
                self.core.inject_inbound(peer, packet);
                self.drain(false);
                let _ = reply.send(());
            }
            Command::InjectOutbound(packet, reply) => {
                self.core.inject_outbound(packet, now());
                self.drain(false);
                let _ = reply.send(());
            }
            Command::ForceHandshake(peer, path, reply) => {
                self.core.force_handshake(peer, path, now());
                self.drain(false);
                let _ = reply.send(());
            }
            Command::AddTransport(transport, reply) => {
                let result = if self.transports.contains_key(&transport.id) {
                    Err(TransportError::Duplicate(transport.id))
                } else {
                    let slot = self.start_transport(transport.start, VecDeque::new());
                    self.transports.insert(transport.id, slot);
                    Ok(())
                };
                let _ = reply.send(result);
            }
            Command::RemoveTransport(id, reply) => {
                let _ = reply.send(self.remove_transport(id).await);
            }
            Command::ReplaceTransport(transport, reply) => {
                let result = match self.transports.remove(&transport.id) {
                    Some(old) => {
                        // The datagrams queued for the old transport go out on the new one.
                        let pending = old.stop().await;
                        let slot = self.start_transport(transport.start, pending);
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
            ] {
                depth.high_water = 0;
            }
        }
        stats
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
        if !self.suspended.send_replace(true) {
            self.event(Event::Suspended);
        }
    }

    /// Resumes after [`Owner::suspend`] and runs the timers that did not fire meanwhile.
    fn resume(&mut self) {
        if self.suspended.send_replace(false) {
            self.event(Event::Resumed);
            self.core.handle_timeout(now());
            self.drain(true);
        }
    }

    /// Spawns the receive and transmit tasks of a transport, with `pending` datagrams
    /// waiting for its transmit queue.
    fn start_transport(&self, start: Start, pending: VecDeque<Datagram>) -> TransportSlot {
        let (queue, transmit_rx) = mpsc::channel(self.queue_capacity);
        let (receive, transmit) = start(
            self.datagram_tx.clone(),
            transmit_rx,
            self.recycle_tx.clone(),
            self.send_errors.clone(),
            self.suspended.subscribe(),
        );
        TransportSlot {
            queue,
            pending,
            flush: None,
            receive,
            transmit,
        }
    }

    /// Stops every I/O task and waits until they are gone.
    async fn stop(&mut self) {
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
        while let Some(output) = self.core.poll_output() {
            match output {
                Output::Transmit { path, data } => self.transmit(path, data, droppable),
                Output::Deliver { from, packet } => self.deliver(from, packet),
                Output::Event(event) => self.event(event),
            }
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

    /// Sends a datagram on the transport its path names.
    fn transmit(&mut self, path: Path, data: PacketBuf, droppable: bool) {
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

    fn deliver(&mut self, from: PeerId, packet: PacketBuf) {
        let reason = match self.deliver.try_send((from, packet)) {
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

/// Reads local packets into the owner's queue until the source closes.
async fn read_source<Src: PacketSource>(
    mut source: Src,
    local: mpsc::Sender<PacketBuf>,
    mut suspended: watch::Receiver<bool>,
) {
    while running(&mut suspended).await {
        match source.recv().await {
            Ok(packet) => {
                if local.send(packet).await.is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                tracing::debug!("Packet source closed");
                return;
            }
            Err(e) => tracing::warn!(message = "Packet source error", error = ?e),
        }
    }
}

/// Delivers decrypted packets to the sink until it closes.
async fn write_sink<Snk: PacketSink>(
    sink: Snk,
    mut deliver: mpsc::Receiver<(PeerId, PacketBuf)>,
    mut suspended: watch::Receiver<bool>,
) {
    while let Some((from, packet)) = deliver.recv().await {
        if !running(&mut suspended).await {
            return;
        }
        match sink.send(packet, from).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                tracing::debug!("Packet sink closed");
                return;
            }
            Err(e) => tracing::warn!(message = "Packet sink error", error = ?e),
        }
    }
}

/// Receives datagrams into the owner's queue until the transport closes.
async fn receive<T: Transport>(
    transport: Arc<T>,
    datagrams: mpsc::Sender<Datagram>,
    mut suspended: watch::Receiver<bool>,
) {
    let mut buf = PacketBuf::with_capacity(MAX_DATAGRAM);
    while running(&mut suspended).await {
        match transport.recv(&mut buf).await {
            Ok((len, path)) => {
                let data = PacketBuf::from_packet(&buf.as_packet()[..len]);
                if datagrams.send((path, data)).await.is_err() {
                    return;
                }
            }
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

/// Sends queued datagrams until the transport closes; returns the buffers for reuse and
/// reports every failed send to `errors`. Once `stop` fires, hands back its queue and the
/// datagram it was sending, if any.
async fn transmit<T: Transport>(
    transport: Arc<T>,
    mut queue: mpsc::Receiver<Datagram>,
    recycle: mpsc::Sender<PacketBuf>,
    errors: SendErrors,
    mut suspended: watch::Receiver<bool>,
    mut stop: oneshot::Receiver<()>,
) -> Option<Unsent> {
    loop {
        let Some(next) = unless_stopped(&mut stop, queue.recv()).await else {
            return Some((queue, None));
        };
        let (path, data) = next?;
        let sent = unless_stopped(&mut stop, async {
            // `None` once the engine is gone.
            if running(&mut suspended).await {
                Some(transport.send(data.as_packet(), &path).await)
            } else {
                None
            }
        })
        .await;
        match sent {
            None => return Some((queue, Some((path, data)))),
            Some(None) => return None,
            Some(Some(Ok(()))) => {}
            Some(Some(Err(e))) if e.kind() == io::ErrorKind::BrokenPipe => {
                tracing::debug!("Transport closed for sending");
                errors.report();
                let _ = recycle.try_send(data);
                return None;
            }
            Some(Some(Err(e))) => {
                tracing::debug!(message = "Transport send error", error = ?e);
                errors.report();
            }
        }
        // A full recycle queue just drops the buffer.
        let _ = recycle.try_send(data);
    }
}
