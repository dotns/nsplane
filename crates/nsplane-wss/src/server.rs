//! [`WssStreamServer`]: the terminate leg of the stream carrier. It dials the relay like a
//! [`WssStreamClient`](crate::WssStreamClient) and serves the `WsFrame` protocol of the
//! [`frame`](crate::frame) module on the session, relaying each opened stream to a backend
//! the embedder's [`WssResolver`] picks.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{BoxFuture, LinkState};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::config::WssConfig;
use crate::connect::{Connector, DialCounters, add, bump, get, invalid, lock};
use crate::frame::{self, FrameCommand, Protocol, WsFrame};
use crate::stream::{CLOSE_WAIT, FRAME_OVERHEAD};
use crate::{MAX_DATA_PAYLOAD, MAX_DATAGRAM};

/// The bounds of a [`WssStreamServer`] session; the defaults are ns `tunnel-ws`'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WssServerLimits {
    /// The most received bytes one stream queues (and is writing) toward its backend; a
    /// frame beyond it closes the stream. 4 MiB by default.
    pub stream_buffer: usize,
    /// The most received bytes all streams of the session queue together; a frame beyond
    /// it closes its stream. 32 MiB by default.
    pub session_buffer: usize,
    /// The most frames one stream queues toward its backend; a frame beyond it closes the
    /// stream. 64 by default.
    pub stream_queue: usize,
    /// The bounded queue of `CLOSE_ACK` and refusing or resetting CLOSE frames (and pings)
    /// toward the socket, written before data. 64 messages by default.
    pub control_queue: usize,
    /// The bounded queue of DATA frames and the CLOSE after a backend's end toward the
    /// socket. 256 messages by default.
    pub data_queue: usize,
    /// The most live streams on the session; an OPEN beyond it is answered with CLOSE.
    /// 1024 by default.
    pub max_streams: usize,
}

impl Default for WssServerLimits {
    fn default() -> Self {
        Self {
            stream_buffer: 4 * 1024 * 1024,
            session_buffer: 32 * 1024 * 1024,
            stream_queue: 64,
            control_queue: 64,
            data_queue: 256,
            max_streams: 1024,
        }
    }
}

impl WssServerLimits {
    /// Sets [`stream_buffer`](Self::stream_buffer).
    #[must_use]
    pub const fn stream_buffer(mut self, bytes: usize) -> Self {
        self.stream_buffer = bytes;
        self
    }

    /// Sets [`session_buffer`](Self::session_buffer).
    #[must_use]
    pub const fn session_buffer(mut self, bytes: usize) -> Self {
        self.session_buffer = bytes;
        self
    }

    /// Sets [`stream_queue`](Self::stream_queue).
    #[must_use]
    pub const fn stream_queue(mut self, frames: usize) -> Self {
        self.stream_queue = frames;
        self
    }

    /// Sets [`control_queue`](Self::control_queue).
    #[must_use]
    pub const fn control_queue(mut self, messages: usize) -> Self {
        self.control_queue = messages;
        self
    }

    /// Sets [`data_queue`](Self::data_queue).
    #[must_use]
    pub const fn data_queue(mut self, messages: usize) -> Self {
        self.data_queue = messages;
        self
    }

    /// Sets [`max_streams`](Self::max_streams).
    #[must_use]
    pub const fn max_streams(mut self, streams: usize) -> Self {
        self.max_streams = streams;
        self
    }
}

/// An OPEN a [`WssResolver`] decides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WssOpen {
    /// The number of the session (counting from 1) the OPEN arrived on.
    pub session: u64,
    /// The stream id on that session.
    pub stream_id: u32,
    /// The target the peer asked for.
    pub target: SocketAddr,
    /// The protocol of the stream.
    pub protocol: Protocol,
}

/// A [`WssResolver`]'s refusal of an OPEN: the stream is answered with CLOSE.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Error)]
#[error("wss stream open denied")]
pub struct Denied;

/// The embedder's policy of a [`WssStreamServer`]: maps each OPEN to the backend the
/// server connects to, or denies it.
pub trait WssResolver: Send + Sync + 'static {
    /// The backend of `open` (a TCP connection or a connected UDP socket to it carries the
    /// stream), or [`Denied`]. Called once per OPEN, on the stream's own task: a slow
    /// answer delays only that stream, whose received data queues meanwhile.
    fn resolve(&self, open: WssOpen) -> BoxFuture<'_, Result<SocketAddr, Denied>>;
}

/// Why a relayed stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WssCloseReason {
    /// The peer closed it (CLOSE, after its data was written to the backend) or
    /// acknowledged a close.
    PeerClosed,
    /// The backend ended its side (EOF); a CLOSE went out behind the stream's data.
    BackendClosed,
    /// The backend could not be connected; a CLOSE went out.
    ConnectFailed,
    /// Reading from or writing to the backend failed; a CLOSE went out.
    BackendError,
    /// A received frame was over a [`WssServerLimits`] bound; a CLOSE went out.
    Overflow,
    /// The session ended.
    SessionEnded,
}

/// What a [`WssStreamEvent`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WssStreamEventKind {
    /// The OPEN was resolved; the server connects to the backend and relays.
    Open,
    /// The relay ended.
    Close {
        /// Why.
        reason: WssCloseReason,
        /// Payload bytes written to the backend.
        to_backend: u64,
        /// Payload bytes read from the backend and sent to the peer.
        from_backend: u64,
    },
}

/// A stream lifecycle event of a [`WssStreamServer`]; see
/// [`with_events`](WssStreamServer::with_events).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WssStreamEvent {
    /// The number of the session (counting from 1).
    pub session: u64,
    /// The stream id on that session.
    pub stream_id: u32,
    /// The protocol of the stream.
    pub protocol: Protocol,
    /// The target the peer asked for.
    pub target: SocketAddr,
    /// The backend the resolver picked.
    pub backend: SocketAddr,
    /// What happened.
    pub kind: WssStreamEventKind,
}

/// The counters of a [`WssStreamServer`].
#[derive(Debug, Default)]
pub struct WssServerStats {
    sessions: AtomicU64,
    active_sessions: AtomicUsize,
    dial: DialCounters,
    streams_opened: AtomicU64,
    streams_denied: AtomicU64,
    streams_refused: AtomicU64,
    streams_closed: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    ignored: AtomicU64,
    invalid: AtomicU64,
    overflows: AtomicU64,
    event_drops: AtomicU64,
    /// What the queues of all streams cost now (the session budget in use).
    buffered: AtomicUsize,
}

impl WssServerStats {
    /// Whether a session is up.
    pub fn connected(&self) -> bool {
        self.active_sessions.load(Ordering::Relaxed) > 0
    }

    /// Sessions that came up.
    pub fn sessions(&self) -> u64 {
        get(&self.sessions)
    }

    /// Failed dials, rejections included.
    pub fn connect_failures(&self) -> u64 {
        get(&self.dial.connect_failures)
    }

    /// Dials rejected with 401 Unauthorized.
    pub fn rejected_unauthorized(&self) -> u64 {
        get(&self.dial.rejected_unauthorized)
    }

    /// Dials rejected with 403 Forbidden.
    pub fn rejected_forbidden(&self) -> u64 {
        get(&self.dial.rejected_forbidden)
    }

    /// OPENs the resolver accepted: streams relayed to a backend.
    pub fn streams_opened(&self) -> u64 {
        get(&self.streams_opened)
    }

    /// OPENs the resolver denied.
    pub fn streams_denied(&self) -> u64 {
        get(&self.streams_denied)
    }

    /// OPENs refused for a stream id in use or over [`WssServerLimits::max_streams`].
    pub fn streams_refused(&self) -> u64 {
        get(&self.streams_refused)
    }

    /// Relayed streams that ended.
    pub fn streams_closed(&self) -> u64 {
        get(&self.streams_closed)
    }

    /// Payload bytes sent to the peer.
    pub fn tx_bytes(&self) -> u64 {
        get(&self.tx_bytes)
    }

    /// Payload bytes received from the peer and queued.
    pub fn rx_bytes(&self) -> u64 {
        get(&self.rx_bytes)
    }

    /// DATA frames for unknown or closed stream ids, ignored.
    pub fn ignored(&self) -> u64 {
        get(&self.ignored)
    }

    /// Messages that are not a frame (text, malformed), ignored.
    pub fn invalid(&self) -> u64 {
        get(&self.invalid)
    }

    /// Received frames over a [`WssServerLimits`] bound, each closing its stream.
    pub fn overflows(&self) -> u64 {
        get(&self.overflows)
    }

    /// Events dropped because the event channel was full or closed.
    pub fn event_drops(&self) -> u64 {
        get(&self.event_drops)
    }

    /// Received bytes queued toward backends now, as charged on
    /// [`WssServerLimits::session_buffer`].
    pub fn buffered(&self) -> usize {
        self.buffered.load(Ordering::Relaxed)
    }
}

/// One stream of a session, shared by its table entry, its queued frames and its relay.
#[derive(Debug)]
struct Stream {
    id: u32,
    /// What its queued (and in-write) frames cost.
    charged: AtomicUsize,
    /// Ends the relay at once: an overflow or the peer's `CLOSE_ACK`.
    reset: Notify,
    /// The reset was an overflow.
    overflowed: AtomicBool,
    /// The backend, once resolved.
    backend: OnceLock<SocketAddr>,
}

/// A received payload on its way to the backend; dropping it releases its cost.
struct Queued {
    payload: Bytes,
    cost: usize,
    stream: Arc<Stream>,
    stats: Arc<WssServerStats>,
}

impl Drop for Queued {
    fn drop(&mut self) {
        self.stream.charged.fetch_sub(self.cost, Ordering::Relaxed);
        self.stats.buffered.fetch_sub(self.cost, Ordering::Relaxed);
    }
}

/// A live stream in the session table. Dropping it (on the peer's CLOSE) ends the queue:
/// the relay writes what is queued, ends the backend's input and stops.
struct Entry {
    stream: Arc<Stream>,
    tx: mpsc::Sender<Queued>,
}

/// The payload bytes a relay moved.
#[derive(Debug, Default)]
struct Moved {
    to_backend: AtomicU64,
    from_backend: AtomicU64,
}

/// One WSS connection to the relay.
struct Session {
    number: u64,
    limits: WssServerLimits,
    stats: Arc<WssServerStats>,
    resolver: Arc<dyn WssResolver>,
    events: Option<mpsc::Sender<WssStreamEvent>>,
    table: StdMutex<HashMap<u32, Entry>>,
    control: mpsc::Sender<Message>,
    data: mpsc::Sender<Message>,
    /// Set when the session ends: every relay stops.
    down: watch::Sender<bool>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("number", &self.number)
            .field("streams", &lock(&self.table).len())
            .finish_non_exhaustive()
    }
}

/// The receiving ends of a session's write queues.
struct Queues {
    control: mpsc::Receiver<Message>,
    data: mpsc::Receiver<Message>,
}

impl Session {
    fn new(
        number: u64,
        limits: WssServerLimits,
        stats: Arc<WssServerStats>,
        resolver: Arc<dyn WssResolver>,
        events: Option<mpsc::Sender<WssStreamEvent>>,
    ) -> (Arc<Self>, Queues) {
        let (control, control_rx) = mpsc::channel(limits.control_queue);
        let (data, data_rx) = mpsc::channel(limits.data_queue);
        let session = Arc::new(Self {
            number,
            limits,
            stats,
            resolver,
            events,
            table: StdMutex::new(HashMap::new()),
            control,
            data,
            down: watch::Sender::new(false),
        });
        let queues = Queues {
            control: control_rx,
            data: data_rx,
        };
        (session, queues)
    }

    /// Queues a control frame without waiting; dropped (and logged) when the queue is full.
    fn send_control(&self, frame: &WsFrame) {
        if self
            .control
            .try_send(Message::Binary(frame.encode()))
            .is_err()
        {
            tracing::warn!(session = self.number, stream_id = frame.stream_id, command = ?frame.command, "wss control queue full; frame dropped");
        }
    }

    /// Takes the stream `id` out of the table if it is still `stream`.
    fn remove(&self, id: u32, stream: &Arc<Stream>) {
        let mut table = lock(&self.table);
        if table
            .get(&id)
            .is_some_and(|entry| Arc::ptr_eq(&entry.stream, stream))
        {
            table.remove(&id);
        }
    }

    fn emit(&self, event: WssStreamEvent) {
        if let Some(events) = &self.events
            && events.try_send(event).is_err()
        {
            bump(&self.stats.event_drops);
        }
    }

    /// Handles one received binary message; OPENs spawn their relay on `tasks`.
    fn dispatch(self: &Arc<Self>, message: &Bytes, tasks: &mut JoinSet<()>) {
        let frame = match WsFrame::decode(message) {
            Ok(frame) => frame,
            Err(error) => {
                bump(&self.stats.invalid);
                tracing::debug!(session = self.number, %error, "wss frame dropped");
                return;
            }
        };
        let id = frame.stream_id;
        match frame.command {
            FrameCommand::Open { target, protocol } => self.open(id, target, protocol, tasks),
            FrameCommand::Data => self.deliver(id, frame.payload),
            FrameCommand::Close => {
                // Acknowledged whether known or not. The entry goes; its relay writes what
                // is queued and ends the backend's input.
                self.send_control(&WsFrame::close_ack(id));
                let entry = lock(&self.table).remove(&id);
                drop(entry);
            }
            FrameCommand::CloseAck => {
                let entry = lock(&self.table).remove(&id);
                if let Some(entry) = entry {
                    entry.stream.reset.notify_one();
                }
            }
        }
    }

    /// Registers the stream `id` and spawns its relay, or answers CLOSE for an id in use
    /// (keeping that stream) or over the stream maximum.
    fn open(
        self: &Arc<Self>,
        id: u32,
        target: SocketAddr,
        protocol: Protocol,
        tasks: &mut JoinSet<()>,
    ) {
        let (tx, rx) = mpsc::channel(self.limits.stream_queue);
        let stream = Arc::new(Stream {
            id,
            charged: AtomicUsize::new(0),
            reset: Notify::new(),
            overflowed: AtomicBool::new(false),
            backend: OnceLock::new(),
        });
        let refusal = {
            let mut table = lock(&self.table);
            if table.contains_key(&id) {
                Some("duplicate stream id")
            } else if table.len() >= self.limits.max_streams {
                Some("stream limit reached")
            } else {
                let entry = Entry {
                    stream: Arc::clone(&stream),
                    tx,
                };
                table.insert(id, entry);
                None
            }
        };
        if let Some(refusal) = refusal {
            bump(&self.stats.streams_refused);
            tracing::warn!(session = self.number, stream_id = id, %target, limit = self.limits.max_streams, "wss open refused: {refusal}; sending CLOSE");
            self.send_control(&WsFrame::close(id));
            return;
        }
        tasks.spawn(Arc::clone(self).relay(stream, target, protocol, rx));
    }

    /// Queues `payload` for the stream `id` within its bounds; over a bound the stream is
    /// closed (only that stream), as ns does.
    fn deliver(&self, id: u32, payload: Bytes) {
        let table = lock(&self.table);
        let Some(entry) = table.get(&id) else {
            bump(&self.stats.ignored);
            tracing::debug!(
                session = self.number,
                stream_id = id,
                "wss data for an unknown stream"
            );
            return;
        };
        let len = payload.len();
        let cost = len + FRAME_OVERHEAD;
        // Only the session task adds to the budgets, so the check holds until the add.
        let fits = entry.stream.charged.load(Ordering::Relaxed) + cost <= self.limits.stream_buffer
            && self.stats.buffered.load(Ordering::Relaxed) + cost <= self.limits.session_buffer;
        let queued = fits && {
            entry.stream.charged.fetch_add(cost, Ordering::Relaxed);
            self.stats.buffered.fetch_add(cost, Ordering::Relaxed);
            let queued = Queued {
                payload,
                cost,
                stream: Arc::clone(&entry.stream),
                stats: Arc::clone(&self.stats),
            };
            entry.tx.try_send(queued).is_ok()
        };
        if queued {
            add(&self.stats.rx_bytes, len);
            return;
        }
        let stream = Arc::clone(&entry.stream);
        drop(table);
        bump(&self.stats.overflows);
        tracing::warn!(
            session = self.number,
            stream_id = id,
            "wss stream buffer full; closing only that stream"
        );
        self.remove(id, &stream);
        stream.overflowed.store(true, Ordering::Relaxed);
        stream.reset.notify_one();
        self.send_control(&WsFrame::close(id));
    }

    /// Resolves, connects and relays one stream until it or the session ends.
    async fn relay(
        self: Arc<Self>,
        stream: Arc<Stream>,
        target: SocketAddr,
        protocol: Protocol,
        rx: mpsc::Receiver<Queued>,
    ) {
        let mut down = self.down.subscribe();
        let moved = Moved::default();
        let open = WssOpen {
            session: self.number,
            stream_id: stream.id,
            target,
            protocol,
        };
        let reason = tokio::select! {
            biased;
            _ = down.wait_for(|down| *down) => WssCloseReason::SessionEnded,
            () = stream.reset.notified() => {
                if stream.overflowed.load(Ordering::Relaxed) {
                    WssCloseReason::Overflow
                } else {
                    WssCloseReason::PeerClosed
                }
            }
            reason = self.serve(&stream, open, rx, &moved) => reason,
        };
        self.remove(stream.id, &stream);
        // Denied (or ended before resolving): no stream was opened.
        let Some(&backend) = stream.backend.get() else {
            return;
        };
        bump(&self.stats.streams_closed);
        let (to_backend, from_backend) = (
            moved.to_backend.load(Ordering::Relaxed),
            moved.from_backend.load(Ordering::Relaxed),
        );
        tracing::debug!(session = self.number, stream_id = stream.id, %target, %backend, ?reason, to_backend, from_backend, "wss stream closed");
        self.emit(WssStreamEvent {
            session: self.number,
            stream_id: stream.id,
            protocol,
            target,
            backend,
            kind: WssStreamEventKind::Close {
                reason,
                to_backend,
                from_backend,
            },
        });
    }

    async fn serve(
        &self,
        stream: &Arc<Stream>,
        open: WssOpen,
        rx: mpsc::Receiver<Queued>,
        moved: &Moved,
    ) -> WssCloseReason {
        let Ok(backend) = self.resolver.resolve(open).await else {
            bump(&self.stats.streams_denied);
            tracing::warn!(session = self.number, stream_id = open.stream_id, target = %open.target, protocol = ?open.protocol, "wss open denied; sending CLOSE");
            self.remove(stream.id, stream);
            self.send_control(&WsFrame::close(stream.id));
            // Not reported: no stream was opened.
            return WssCloseReason::PeerClosed;
        };
        let _ = stream.backend.set(backend);
        bump(&self.stats.streams_opened);
        self.emit(WssStreamEvent {
            session: self.number,
            stream_id: open.stream_id,
            protocol: open.protocol,
            target: open.target,
            backend,
            kind: WssStreamEventKind::Open,
        });
        let relayed = match open.protocol {
            Protocol::Tcp => self.relay_tcp(stream.id, backend, rx, moved).await,
            Protocol::Udp => self.relay_udp(stream.id, backend, rx, moved).await,
        };
        match relayed {
            Ok(reason) => reason,
            Err((reason, error)) => {
                tracing::debug!(session = self.number, stream_id = stream.id, %backend, %error, ?reason, "wss relay failed; sending CLOSE");
                self.send_control(&WsFrame::close(stream.id));
                reason
            }
        }
    }

    /// Sends a backend's bytes to the peer as one DATA frame; `false` once the session is
    /// gone.
    async fn send_data(&self, id: u32, payload: &[u8], moved: &Moved) -> bool {
        let Ok(permit) = self.data.reserve().await else {
            return false;
        };
        permit.send(Message::Binary(frame::encode_data(id, payload)));
        add(&self.stats.tx_bytes, payload.len());
        moved
            .from_backend
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        true
    }

    /// Relays a TCP stream, both directions at once (a backend that echoes only reads
    /// while its writes drain). An error is answered with CLOSE by the caller.
    async fn relay_tcp(
        &self,
        id: u32,
        backend: SocketAddr,
        mut rx: mpsc::Receiver<Queued>,
        moved: &Moved,
    ) -> Result<WssCloseReason, (WssCloseReason, io::Error)> {
        let tcp = TcpStream::connect(backend)
            .await
            .map_err(|e| (WssCloseReason::ConnectFailed, e))?;
        let _ = tcp.set_nodelay(true);
        let (mut read, mut write) = tcp.into_split();
        let to_backend = async {
            while let Some(queued) = rx.recv().await {
                write.write_all(&queued.payload).await?;
                moved
                    .to_backend
                    .fetch_add(queued.payload.len() as u64, Ordering::Relaxed);
            }
            // The peer's CLOSE: the backend's input ends after what came before it.
            write.shutdown().await
        };
        let from_backend = async {
            let mut buf = vec![0; MAX_DATA_PAYLOAD];
            loop {
                let n = read.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<_, io::Error>(true);
                }
                if !self.send_data(id, &buf[..n], moved).await {
                    return Ok(false);
                }
            }
        };
        tokio::select! {
            written = to_backend => match written {
                Ok(()) => Ok(WssCloseReason::PeerClosed),
                Err(error) => Err((WssCloseReason::BackendError, error)),
            },
            read = from_backend => match read {
                Ok(true) => {
                    // The backend's EOF: CLOSE behind the data already queued.
                    if let Ok(permit) = self.data.reserve().await {
                        permit.send(Message::Binary(WsFrame::close(id).encode()));
                    }
                    Ok(WssCloseReason::BackendClosed)
                }
                Ok(false) => Ok(WssCloseReason::SessionEnded),
                Err(error) => Err((WssCloseReason::BackendError, error)),
            },
        }
    }

    /// Relays a UDP flow through a socket connected to `backend`: one datagram per DATA
    /// frame, both directions at once.
    async fn relay_udp(
        &self,
        id: u32,
        backend: SocketAddr,
        mut rx: mpsc::Receiver<Queued>,
        moved: &Moved,
    ) -> Result<WssCloseReason, (WssCloseReason, io::Error)> {
        let local = if backend.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let socket = UdpSocket::bind(local)
            .await
            .map_err(|e| (WssCloseReason::ConnectFailed, e))?;
        socket
            .connect(backend)
            .await
            .map_err(|e| (WssCloseReason::ConnectFailed, e))?;
        let to_backend = async {
            while let Some(queued) = rx.recv().await {
                match socket.send(&queued.payload).await {
                    Ok(_) => {
                        moved
                            .to_backend
                            .fetch_add(queued.payload.len() as u64, Ordering::Relaxed);
                    }
                    // As ns: a datagram that cannot be sent is dropped; the flow stays.
                    Err(error) => {
                        tracing::debug!(session = self.number, stream_id = id, %error, "wss udp send failed");
                    }
                }
            }
        };
        let from_backend = async {
            let mut buf = vec![0; MAX_DATAGRAM];
            loop {
                let n = socket.recv(&mut buf).await?;
                if !self.send_data(id, &buf[..n], moved).await {
                    return Ok::<_, io::Error>(());
                }
            }
        };
        tokio::select! {
            () = to_backend => Ok(WssCloseReason::PeerClosed),
            read = from_backend => match read {
                Ok(()) => Ok(WssCloseReason::SessionEnded),
                Err(error) => Err((WssCloseReason::BackendError, error)),
            },
        }
    }

    /// Runs the session on `ws`: writes the queues (control first) and keepalive pings,
    /// dispatches received frames, and ends on a socket error, a close, a read idle or
    /// `shutdown`, which it returns whether it was. Every stream still open is closed.
    async fn run<S, F>(
        self: Arc<Self>,
        ws: WebSocketStream<S>,
        queues: Queues,
        config: &WssConfig,
        shutdown: &mut Pin<&mut F>,
    ) -> bool
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        F: Future<Output = ()> + Send,
    {
        let Queues {
            control: mut control_rx,
            data: mut data_rx,
        } = queues;
        let (ping_interval, read_idle) = (config.ping_interval, config.read_idle);
        let mut tasks = JoinSet::new();
        let (mut sink, mut stream) = ws.split();
        let writer = async {
            let mut pings = tokio::time::interval(ping_interval);
            pings.tick().await;
            loop {
                let message = tokio::select! {
                    biased;
                    Some(message) = control_rx.recv() => message,
                    _ = pings.tick() => Message::Ping(Bytes::new()),
                    Some(message) = data_rx.recv() => message,
                };
                if let Err(error) = sink.send(message).await {
                    return format!("write failed: {error}");
                }
            }
        };
        let reader = async {
            let mut idle = pin!(tokio::time::sleep(read_idle));
            loop {
                tokio::select! {
                    message = stream.next() => {
                        idle.as_mut().reset(Instant::now() + read_idle);
                        match message {
                            Some(Ok(Message::Binary(data))) => self.dispatch(&data, &mut tasks),
                            Some(Ok(Message::Text(_))) => bump(&self.stats.invalid),
                            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                            Some(Ok(Message::Close(_))) | None => return "closed by the peer".to_owned(),
                            Some(Err(error)) => return format!("read failed: {error}"),
                        }
                    }
                    () = &mut idle => return "silent".to_owned(),
                    Some(_) = tasks.join_next() => {}
                }
            }
        };
        let (reason, shut_down) = tokio::select! {
            reason = writer => (reason, false),
            reason = reader => (reason, false),
            () = shutdown.as_mut() => ("shut down".to_owned(), true),
        };
        // Relays stop first, so that none mistakes the dropped queues for the peer's CLOSE.
        self.down.send_replace(true);
        let entries: Vec<Entry> = lock(&self.table).drain().map(|(_, entry)| entry).collect();
        drop(entries);
        while tasks.join_next().await.is_some() {}
        tracing::info!(session = self.number, url = %config.url, %reason, "wss session ended");
        let _ = tokio::time::timeout(CLOSE_WAIT, sink.close()).await;
        shut_down
    }
}

/// Marks the server disconnected when its session ends, or its run is dropped.
struct Up<'a>(&'a WssStreamServer);

impl Drop for Up<'_> {
    fn drop(&mut self) {
        self.0.stats.active_sessions.store(0, Ordering::Relaxed);
        self.0.connector.set_state(LinkState::Disconnected);
    }
}

/// The terminate leg of the stream carrier: dials the relay and serves the `WsFrame`
/// protocol of the [`frame`](crate::frame) module on the session, the peer of a
/// [`WssStreamClient`](crate::WssStreamClient) (ns `WsTunnel`'s role).
///
/// - **Session**: dialed like [`WssDialer`](crate::WssDialer) links (URL, TLS, headers,
///   bearer, 401/403 as [`LinkState::Rejected`], the doubling backoff, pings and the read
///   idle of the [`WssConfig`]). One session at a time carries every stream; when it ends
///   (socket error, close, read idle) its streams are closed and the next is dialed after
///   the backoff.
/// - **OPEN**: an OPEN registers the stream (an id in use, or one over
///   [`max_streams`](WssServerLimits::max_streams), is answered with CLOSE) and asks the
///   [`WssResolver`] for its backend; a denial is answered with CLOSE. The server connects
///   to the backend (TCP, or a connected UDP socket) and relays both ways: TCP bytes in
///   DATA frames of at most [`MAX_DATA_PAYLOAD`] bytes, one datagram per DATA frame for
///   UDP.
/// - **CLOSE**: always answered with `CLOSE_ACK` (on the control queue), known or not;
///   the stream's queued data is still written, then the backend's input ends. A
///   backend's EOF sends CLOSE behind the stream's data; a failed connect or backend
///   error sends CLOSE at once.
/// - **Bounds**: see [`WssServerLimits`]. Received payloads cost their length plus 64
///   bytes each until written to the backend; a frame over the stream or session bound
///   closes its stream only.
///
/// [`run`](Self::run) drives it until a shutdown; [`stats`](Self::stats),
/// [`state`](Self::state) and [`with_events`](Self::with_events) observe it.
pub struct WssStreamServer {
    connector: Connector,
    limits: WssServerLimits,
    resolver: Arc<dyn WssResolver>,
    events: Option<mpsc::Sender<WssStreamEvent>>,
    stats: Arc<WssServerStats>,
}

impl fmt::Debug for WssStreamServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WssStreamServer")
            .field("connector", &self.connector)
            .field("limits", &self.limits)
            .field("events", &self.events.is_some())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl WssStreamServer {
    /// A server for `config` within `limits`, resolving OPENs with `resolver`; it dials
    /// nothing until [`run`](Self::run).
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] where
    /// [`WssDialer::new`](crate::WssDialer::new) does, and on a zero queue length or
    /// stream maximum.
    pub fn new(
        config: WssConfig,
        limits: WssServerLimits,
        resolver: Arc<dyn WssResolver>,
    ) -> io::Result<Self> {
        if limits.stream_queue == 0 || limits.control_queue == 0 || limits.data_queue == 0 {
            return Err(invalid("wss stream queues must hold a message".to_owned()));
        }
        if limits.max_streams == 0 {
            return Err(invalid("a wss session must carry a stream".to_owned()));
        }
        Ok(Self {
            connector: Connector::new(config)?,
            limits,
            resolver,
            events: None,
            stats: Arc::new(WssServerStats::default()),
        })
    }

    /// Reports stream opens and closes on `events`. Sending never waits: an event that
    /// does not fit is dropped and counted in [`WssServerStats::event_drops`].
    #[must_use]
    pub fn with_events(mut self, events: mpsc::Sender<WssStreamEvent>) -> Self {
        self.events = Some(events);
        self
    }

    /// The counters.
    pub fn stats(&self) -> Arc<WssServerStats> {
        Arc::clone(&self.stats)
    }

    /// Watches the session state: [`LinkState::Disconnected`] at first and while no
    /// session is up, [`LinkState::Connected`] while one is, [`LinkState::Rejected`] after
    /// a dial was refused with 401 or 403 (until a session comes up).
    pub fn state(&self) -> watch::Receiver<LinkState> {
        self.connector.state()
    }

    /// Dials and serves sessions, one after another, until `shutdown` completes; then
    /// closes the open streams and the session and returns.
    ///
    /// Cancellation-safe: dropping the future instead ends the session and every relay at
    /// once.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) {
        let mut shutdown = pin!(shutdown);
        loop {
            let dialed = tokio::select! {
                () = shutdown.as_mut() => return,
                dialed = self.connector.connect(&self.stats.dial) => dialed,
            };
            // A failed dial already set the backoff of the next one.
            let Ok(ws) = dialed else {
                continue;
            };
            let number = self.stats.sessions.fetch_add(1, Ordering::Relaxed) + 1;
            let (session, queues) = Session::new(
                number,
                self.limits,
                Arc::clone(&self.stats),
                Arc::clone(&self.resolver),
                self.events.clone(),
            );
            let up = Up(&self);
            self.stats.active_sessions.store(1, Ordering::Relaxed);
            self.connector.set_state(LinkState::Connected);
            let config = self.connector.config();
            tracing::info!(session = number, url = %config.url, "wss session up");
            let shut_down = session.run(ws, queues, config, &mut shutdown).await;
            drop(up);
            if shut_down {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests;
