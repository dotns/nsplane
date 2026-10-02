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

use nstun_core::x25519::StaticSecret;
use nstun_core::{ConfigChange, Core, CoreConfig, Event, Input, Output};
use nstun_packet::{PacketBuf, Path, PeerId};
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep, sleep_until};

use crate::events::{
    DROP_NO_TRANSPORT, DROP_SINK_CLOSED, DROP_SINK_FULL, DROP_TRANSMIT_FULL, DROP_TRANSPORT_CLOSED,
};
use crate::handle::{Command, EngineHandle};
use crate::io::{PacketSink, PacketSource};
use crate::transport::Transport;
use crate::udp::UdpTransport;

/// Capacity of the command queue from the handles to the owner task.
const COMMAND_CAPACITY: usize = 64;
/// Size of the receive buffer: the largest UDP payload.
const MAX_DATAGRAM: usize = 65535;

/// A running engine.
///
/// One owner task owns the [`Core`] and loops: it waits for a handle command, a local packet,
/// a received datagram or the core's next timeout, feeds the core and drains its outputs.
/// Four I/O tasks surround it, each connected through a bounded queue: the source task
/// ([`PacketSource::recv`]), the transport receive task ([`Transport::recv`]), the transmit
/// task ([`Transport::send`]) and the sink task ([`PacketSink::send`]). The core is never
/// shared, so there are no locks on the data path.
///
/// Backpressure: a full sink queue drops the decrypted packet and counts it under
/// [`crate::DROP_SINK_FULL`]. When the transmit queue is full, datagrams wait in the owner
/// task and the owner stops reading local packets until every waiting datagram has moved to
/// the queue, which in turn holds back the source. The waiting datagrams are bounded by the
/// queue capacity: a datagram caused by a received datagram or a timer that finds them at
/// the bound is dropped and counted under [`crate::DROP_TRANSMIT_FULL`]. Datagrams caused by
/// local packets or handle calls always wait, so local packets are held back, never dropped.
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
pub struct Engine<T: Transport = UdpTransport> {
    handle: EngineHandle<T>,
    owner: Option<JoinHandle<()>>,
}

impl<T: Transport> fmt::Debug for Engine<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl<T: Transport> Engine<T> {
    /// A new handle to this engine.
    pub fn handle(&self) -> EngineHandle<T> {
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

impl<T: Transport> Drop for Engine<T> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.abort();
        }
    }
}

/// Everything [`spawn`] needs, collected by the builder.
pub(crate) struct Parts<Src, Snk, T> {
    pub(crate) core: CoreConfig,
    pub(crate) private_key: Option<StaticSecret>,
    pub(crate) source: Src,
    pub(crate) sink: Snk,
    pub(crate) transport: Option<T>,
    pub(crate) queue_capacity: usize,
    pub(crate) event_capacity: usize,
}

/// Spawns the owner task and the I/O tasks.
pub(crate) fn spawn<Src: PacketSource, Snk: PacketSink, T: Transport>(
    parts: Parts<Src, Snk, T>,
) -> Engine<T> {
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
        transport: None,
        pending: VecDeque::new(),
        flush: None,
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
    owner.transport = parts.transport.map(|t| owner.start_transport(t));

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

/// The installed transport: its transmit queue and its two tasks.
struct TransportSlot {
    queue: mpsc::Sender<Datagram>,
    receive: Task,
    transmit: Task,
}

impl TransportSlot {
    async fn stop(self) {
        self.receive.stop().await;
        self.transmit.stop().await;
    }
}

/// What woke the owner task.
enum Wake<T> {
    Command(Option<Command<T>>),
    Datagram(Option<Datagram>),
    Local(Option<PacketBuf>),
    Flush(Option<OwnedPermit<Datagram>>),
    Timer,
}

/// The state of the owner task.
struct Owner<T> {
    core: Core,
    /// The last private key given to the engine.
    private_key: Option<StaticSecret>,
    commands: mpsc::Receiver<Command<T>>,
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
    transport: Option<TransportSlot>,
    /// Datagrams waiting for room in the transmit queue, oldest first.
    pending: VecDeque<Datagram>,
    /// Armed while `pending` is not empty.
    flush: Option<Reserve>,
    timer: Pin<Box<Sleep>>,
    events: broadcast::Sender<Event>,
    drops: BTreeMap<&'static str, u64>,
    /// The source and sink tasks.
    tasks: Vec<Task>,
    queue_capacity: usize,
    /// Alternates which of local packets and datagrams is polled first.
    local_first: bool,
}

impl<T: Transport> Owner<T> {
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
                Wake::Flush(permit) => {
                    // No permit: the transmit queue closed, and moving drops the datagrams.
                    if let Some(permit) = permit
                        && let Some(datagram) = self.pending.pop_front()
                    {
                        permit.send(datagram);
                    }
                    self.move_pending();
                }
                Wake::Timer => self.core.handle_timeout(now()),
            }
            self.drain(droppable);
        }
        self.stop().await;
    }

    fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<Wake<T>> {
        if let Poll::Ready(command) = self.commands.poll_recv(cx) {
            return Poll::Ready(Wake::Command(command));
        }
        if let Some(flush) = &mut self.flush
            && let Poll::Ready(permit) = flush.as_mut().poll(cx)
        {
            self.flush = None;
            return Poll::Ready(Wake::Flush(permit.ok()));
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

    /// Polls the source queue, unless datagrams are waiting for the transmit queue.
    fn poll_local(&mut self, cx: &mut Context<'_>) -> Poll<Wake<T>> {
        match &mut self.local {
            Some(local) if self.pending.is_empty() => local.poll_recv(cx).map(Wake::Local),
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
    async fn command(&mut self, command: Command<T>) -> ControlFlow<oneshot::Sender<()>> {
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
            Command::SetTransport(transport, reply) => {
                // The armed flush waits on the old transmit queue.
                self.flush = None;
                if let Some(old) = self.transport.take() {
                    old.stop().await;
                }
                self.transport = Some(self.start_transport(transport));
                self.drain(false);
                let _ = reply.send(());
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

    /// Spawns the receive and transmit tasks of `transport`.
    fn start_transport(&self, transport: T) -> TransportSlot {
        let transport = Arc::new(transport);
        let (queue, transmit_rx) = mpsc::channel(self.queue_capacity);
        TransportSlot {
            queue,
            receive: Task::spawn(receive(Arc::clone(&transport), self.datagram_tx.clone())),
            transmit: Task::spawn(transmit(transport, transmit_rx, self.recycle_tx.clone())),
        }
    }

    /// Stops every I/O task and waits until they are gone.
    async fn stop(&mut self) {
        if let Some(transport) = self.transport.take() {
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
        if self.flush.is_none()
            && !self.pending.is_empty()
            && let Some(transport) = &self.transport
        {
            self.flush = Some(Box::pin(transport.queue.clone().reserve_owned()));
        }
    }

    fn transmit(&mut self, path: Path, data: PacketBuf, droppable: bool) {
        let Some(transport) = &self.transport else {
            self.core.recycle(data);
            return self.dropped(None, DROP_NO_TRANSPORT);
        };
        if !self.pending.is_empty() {
            return self.wait((path, data), droppable);
        }
        match transport.queue.try_send((path, data)) {
            Ok(()) => {}
            Err(TrySendError::Full(datagram)) => self.wait(datagram, droppable),
            Err(TrySendError::Closed((_, data))) => {
                self.core.recycle(data);
                self.dropped(None, DROP_TRANSPORT_CLOSED);
            }
        }
    }

    /// Adds a datagram to the waiting datagrams; with `droppable`, drops it when they are at
    /// the queue capacity.
    fn wait(&mut self, datagram: Datagram, droppable: bool) {
        if droppable && self.pending.len() >= self.queue_capacity {
            self.core.recycle(datagram.1);
            return self.dropped(None, DROP_TRANSMIT_FULL);
        }
        self.pending.push_back(datagram);
    }

    /// Moves waiting datagrams to the transmit queue until it is full, in order.
    fn move_pending(&mut self) {
        for (path, data) in std::mem::take(&mut self.pending) {
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
