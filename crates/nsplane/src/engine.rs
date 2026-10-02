//! The running engine: one owner task drives the core, I/O tasks feed it through bounded
//! queues.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use nsplane_core::x25519::StaticSecret;
use nsplane_core::{ConfigChange, Core, CoreConfig, Event, Input, Output};
use nsplane_packet::{PacketBuf, Path, PeerId, TransportId};
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep, sleep_until};

use crate::events::{
    DROP_NO_TRANSPORT, DROP_SINK_CLOSED, DROP_SINK_FULL, DROP_TRANSMIT_FULL, DROP_TRANSPORT_CLOSED,
};
use crate::handle::{Command, EngineHandle, TransportError};
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
/// type when it is added, so no datagram goes through a boxed future.
///
/// Backpressure: a full sink queue drops the decrypted packet and counts it under
/// [`crate::DROP_SINK_FULL`]. Each transport has its own transmit queue; when it is full,
/// that transport's datagrams wait in the owner task, in order, while datagrams to other
/// transports keep going to their own queues, so a slow transport never delays another
/// transport's datagrams. The waiting datagrams of a transport are bounded by the queue
/// capacity: a datagram caused by a received datagram or a timer that finds them at the
/// bound is dropped and counted under [`crate::DROP_TRANSMIT_FULL`]. Datagrams caused by
/// local packets or handle calls always wait, so local packets are held back, never dropped:
/// the owner stops reading local packets while any transport has waiting datagrams (which
/// transport a local packet leads to is only known once the core has handled it), which in
/// turn holds back the source. Received datagrams, timers and handle calls are still served
/// meanwhile. A transport that never drains therefore holds back local packets until it
/// closes (its waiting datagrams are then dropped under [`crate::DROP_TRANSPORT_CLOSED`]) or
/// is removed with [`EngineHandle::remove_transport`].
///
/// Buffers: datagrams are received into one reusable 64 KiB buffer and copied into an
/// exactly sized [`PacketBuf`], so queued datagrams do not each pin 64 KiB. Datagram buffers
/// the core is done with, buffers rejected by a full sink and transmitted buffers (returned
/// by the transmit task over a bounded queue, dropped when it is full) go back to the core's
/// pool with [`Core::recycle`]. Delivered packets are owned by the sink.
///
/// When an I/O side reports [`io::ErrorKind::BrokenPipe`], its task stops and the engine
/// keeps running without it; other I/O errors are logged and the task continues.
///
/// The engine runs until [`EngineHandle::shutdown`]. Dropping the `Engine` aborts every task
/// at once, so keep it alive (typically by awaiting [`Engine::wait`]) for as long as the
/// engine should run; handles alone do not keep it running.
///
/// [`PathPolicy`]: nsplane_core::PathPolicy
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
    let (deliver, deliver_rx) = mpsc::channel(capacity);
    let (events, _) = broadcast::channel(parts.event_capacity);

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
        deliver,
        transports: BTreeMap::new(),
        timer: Box::pin(sleep_until(deadline)),
        events,
        drops: BTreeMap::new(),
        tasks: vec![
            Task::spawn(read_source(parts.source, local_tx)),
            Task::spawn(write_sink(parts.sink, deliver_rx)),
        ],
        queue_capacity: capacity,
        local_first: false,
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

/// A datagram and the path to send it on.
type Datagram = (Path, PacketBuf);
/// Waits for room in the transmit queue.
type Reserve = Pin<Box<dyn Future<Output = Result<OwnedPermit<Datagram>, SendError<()>>> + Send>>;

/// Spawns a transport's receive and transmit tasks, given the queue receiving its datagrams,
/// its transmit queue and the queue returning transmitted buffers.
type Start = Box<
    dyn FnOnce(
            mpsc::Sender<Datagram>,
            mpsc::Receiver<Datagram>,
            mpsc::Sender<PacketBuf>,
        ) -> (Task, Task)
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
            start: Box::new(move |datagrams, queue, recycle| {
                let transport = Arc::new(transport);
                (
                    Task::spawn(receive(Arc::clone(&transport), datagrams)),
                    Task::spawn(transmit(transport, queue, recycle)),
                )
            }),
        }
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
    transmit: Task,
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

    /// Stops both tasks and returns the waiting datagrams.
    async fn stop(self) -> VecDeque<Datagram> {
        self.receive.stop().await;
        self.transmit.stop().await;
        self.pending
    }
}

/// What woke the owner task.
enum Wake {
    Command(Option<Command>),
    Datagram(Option<Datagram>),
    Local(Option<PacketBuf>),
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
    deliver: mpsc::Sender<(PeerId, PacketBuf)>,
    transports: BTreeMap<TransportId, TransportSlot>,
    timer: Pin<Box<Sleep>>,
    events: broadcast::Sender<Event>,
    drops: BTreeMap<&'static str, u64>,
    /// The source and sink tasks.
    tasks: Vec<Task>,
    queue_capacity: usize,
    /// Alternates which of local packets and datagrams is polled first.
    local_first: bool,
}

impl Owner {
    async fn run(mut self) {
        loop {
            self.arm_timer();
            let wake = poll_fn(|cx| self.poll_wake(cx)).await;
            // Datagrams caused by the network or a timer may overflow the waiting datagrams.
            let droppable = matches!(wake, Wake::Datagram(_) | Wake::Timer);
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
                Wake::Datagram(Some((path, mut data))) => {
                    self.core.handle_input(
                        Input::Datagram {
                            path,
                            data: &mut data,
                        },
                        now(),
                    );
                    self.core.recycle(data);
                }
                // The owner keeps a sender, so the queue never closes.
                Wake::Datagram(None) => {}
                Wake::Local(Some(packet)) => self.core.handle_input(Input::Local { packet }, now()),
                Wake::Local(None) => self.local = None,
                Wake::Flush(id, permit) => {
                    // No permit: the transmit queue closed, and moving drops the datagrams.
                    if let Some(permit) = permit
                        && let Some(datagram) = self
                            .transports
                            .get_mut(&id)
                            .and_then(|slot| slot.pending.pop_front())
                    {
                        permit.send(datagram);
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
        if self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Wake::Timer);
        }
        Poll::Pending
    }

    /// Polls the source queue, unless datagrams are waiting for a transmit queue.
    fn poll_local(&mut self, cx: &mut Context<'_>) -> Poll<Wake> {
        let waiting = self
            .transports
            .values()
            .any(|slot| !slot.pending.is_empty());
        match &mut self.local {
            Some(local) if !waiting => local.poll_recv(cx).map(Wake::Local),
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
                let result = match self.transports.remove(&id) {
                    Some(old) => {
                        for (_, data) in old.stop().await {
                            self.core.recycle(data);
                            self.dropped(None, DROP_NO_TRANSPORT);
                        }
                        Ok(())
                    }
                    None => Err(TransportError::Unknown(id)),
                };
                let _ = reply.send(result);
            }
            Command::ReplaceTransport(transport, reply) => {
                let result = match self.transports.remove(&transport.id) {
                    Some(old) => {
                        // The waiting datagrams go out on the new transport.
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
            Command::Subscribe(reply) => {
                let _ = reply.send(self.events.subscribe());
            }
            Command::DropCounters(reply) => {
                let _ = reply.send(self.drops.clone());
            }
            Command::Shutdown(reply) => return ControlFlow::Break(reply),
        }
        ControlFlow::Continue(())
    }

    /// Spawns the receive and transmit tasks of a transport, with `pending` datagrams
    /// waiting for its transmit queue.
    fn start_transport(&self, start: Start, pending: VecDeque<Datagram>) -> TransportSlot {
        let (queue, transmit_rx) = mpsc::channel(self.queue_capacity);
        let (receive, transmit) = start(
            self.datagram_tx.clone(),
            transmit_rx,
            self.recycle_tx.clone(),
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
            Some(slot) => slot.transmit((path, data), droppable, self.queue_capacity),
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
            Ok(()) => return,
            Err(TrySendError::Full((_, packet))) => {
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

    /// Counts drops and publishes the event; never blocks.
    fn event(&mut self, event: Event) {
        if let Event::Dropped { reason, .. } = event {
            *self.drops.entry(reason).or_default() += 1;
        }
        // No subscribers is not an error.
        let _ = self.events.send(event);
    }
}

/// Reads local packets into the owner's queue until the source closes.
async fn read_source<Src: PacketSource>(mut source: Src, local: mpsc::Sender<PacketBuf>) {
    loop {
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
async fn write_sink<Snk: PacketSink>(sink: Snk, mut deliver: mpsc::Receiver<(PeerId, PacketBuf)>) {
    while let Some((from, packet)) = deliver.recv().await {
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
async fn receive<T: Transport>(transport: Arc<T>, datagrams: mpsc::Sender<Datagram>) {
    let mut buf = PacketBuf::with_capacity(MAX_DATAGRAM);
    loop {
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

/// Sends queued datagrams until the transport closes; returns the buffers for reuse.
async fn transmit<T: Transport>(
    transport: Arc<T>,
    mut queue: mpsc::Receiver<Datagram>,
    recycle: mpsc::Sender<PacketBuf>,
) {
    while let Some((path, data)) = queue.recv().await {
        match transport.send(data.as_packet(), &path).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                tracing::debug!("Transport closed for sending");
                return;
            }
            Err(e) => tracing::debug!(message = "Transport send error", error = ?e),
        }
        // A full recycle queue just drops the buffer.
        let _ = recycle.try_send(data);
    }
}
