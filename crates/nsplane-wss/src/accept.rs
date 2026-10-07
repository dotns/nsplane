//! [`WssServerTransport`]: a [`Transport`] over the WebSocket sessions the embedder accepts.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{Ecn, PacketBuf, Path, Transport, TransportId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::config::Pings;
use crate::connect::{add, bump, get, lock, ws_config};
use crate::{MAX_DATAGRAM, MAX_MESSAGE};

/// How long a closing session waits to send its close frame.
const CLOSE_WAIT: Duration = Duration::from_secs(1);

/// Settings of a [`WssServerTransport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WssServerConfig {
    /// How many datagrams wait for each session's writer; once full,
    /// [`Transport::send`] to that session fails at once. 256 by default; 0 is taken as 1.
    pub queue: usize,
    /// How many received datagrams, of all sessions, wait for
    /// [`recv`](Transport::recv); once full, the sessions' readers wait, so a slow engine
    /// pushes back on each session's TCP connection. 1024 by default; 0 is taken as 1.
    pub inbound_queue: usize,
    /// The interval of each session's keepalive pings; `None` (or zero) sends no pings
    /// ([`read_idle`](Self::read_idle) still applies). 10 s by default.
    pub ping_interval: Option<Duration>,
    /// Closes a session when no frame at all (pongs included) arrived on it for this long.
    /// 35 s by default.
    pub read_idle: Duration,
    /// The most sessions open at once; [`WssAcceptor::accept`] refuses more. 4096 by
    /// default.
    ///
    /// The limit bounds memory: each session buffers up to [`queue`](Self::queue)
    /// outbound datagrams of up to [`MAX_DATAGRAM`] bytes each, and the sessions share
    /// [`inbound_queue`](Self::inbound_queue) received ones. The worst case is
    /// `max_sessions` x `queue` x [`MAX_DATAGRAM`] plus `inbound_queue` x
    /// [`MAX_DATAGRAM`]: with the defaults 4096 x 256 x 64 KiB = 64 GiB plus
    /// 1024 x 64 KiB = 64 MiB. Datagrams take only their own length, so with WireGuard
    /// datagrams of at most about 1.5 KiB the defaults stay near 1.5 GiB; lower the limit
    /// or the queue for a smaller bound.
    pub max_sessions: usize,
}

impl WssServerConfig {
    /// The default settings.
    pub const fn new() -> Self {
        Self {
            queue: 256,
            inbound_queue: 1024,
            ping_interval: Some(Duration::from_secs(10)),
            read_idle: Duration::from_secs(35),
            max_sessions: 4096,
        }
    }

    /// Sets [`queue`](Self::queue).
    #[must_use]
    pub const fn queue(mut self, queue: usize) -> Self {
        self.queue = queue;
        self
    }

    /// Sets [`inbound_queue`](Self::inbound_queue).
    #[must_use]
    pub const fn inbound_queue(mut self, queue: usize) -> Self {
        self.inbound_queue = queue;
        self
    }

    /// Sets [`ping_interval`](Self::ping_interval).
    #[must_use]
    pub const fn ping_interval(mut self, interval: Option<Duration>) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Sets [`read_idle`](Self::read_idle).
    #[must_use]
    pub const fn read_idle(mut self, idle: Duration) -> Self {
        self.read_idle = idle;
        self
    }

    /// Sets [`max_sessions`](Self::max_sessions).
    #[must_use]
    pub const fn max_sessions(mut self, max: usize) -> Self {
        self.max_sessions = max;
        self
    }
}

impl Default for WssServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// The counters of a [`WssServerTransport`] and all its sessions.
#[derive(Debug, Default)]
pub struct WssServerTransportStats {
    active: AtomicU64,
    accepted: AtomicU64,
    refused_limit: AtomicU64,
    refused_closed: AtomicU64,
    closed_idle: AtomicU64,
    closed_error: AtomicU64,
    closed_peer: AtomicU64,
    closed_local: AtomicU64,
    sent_to_closed: AtomicU64,
    traffic: WssSessionStats,
}

impl WssServerTransportStats {
    /// Sessions open now.
    pub fn active(&self) -> u64 {
        get(&self.active)
    }

    /// Sessions accepted.
    pub fn accepted(&self) -> u64 {
        get(&self.accepted)
    }

    /// Sessions refused at [`WssServerConfig::max_sessions`].
    pub fn refused_limit(&self) -> u64 {
        get(&self.refused_limit)
    }

    /// Sessions refused because the transport was dropped.
    pub fn refused_closed(&self) -> u64 {
        get(&self.refused_closed)
    }

    /// Sessions closed after [`WssServerConfig::read_idle`] without a frame.
    pub fn closed_idle(&self) -> u64 {
        get(&self.closed_idle)
    }

    /// Sessions closed by a read or write error.
    pub fn closed_error(&self) -> u64 {
        get(&self.closed_error)
    }

    /// Sessions the peer closed: a close frame or the end of the stream.
    pub fn closed_peer(&self) -> u64 {
        get(&self.closed_peer)
    }

    /// Sessions closed by [`WssSession::close`] or by dropping the transport.
    pub fn closed_local(&self) -> u64 {
        get(&self.closed_local)
    }

    /// Datagrams sent to an address without a live session, and failed with
    /// [`io::ErrorKind::NotConnected`].
    pub fn sent_to_closed(&self) -> u64 {
        get(&self.sent_to_closed)
    }

    /// Datagrams received, of all sessions.
    pub fn rx(&self) -> u64 {
        self.traffic.rx()
    }

    /// Bytes of the datagrams received, of all sessions.
    pub fn rx_bytes(&self) -> u64 {
        self.traffic.rx_bytes()
    }

    /// Datagrams written to a session, of all sessions.
    pub fn tx(&self) -> u64 {
        self.traffic.tx()
    }

    /// Bytes of the datagrams written to a session, of all sessions.
    pub fn tx_bytes(&self) -> u64 {
        self.traffic.tx_bytes()
    }

    /// Text messages received and dropped, of all sessions.
    pub fn dropped_text(&self) -> u64 {
        self.traffic.dropped_text()
    }

    /// Datagrams longer than [`MAX_DATAGRAM`], sent or received, dropped, of all sessions.
    pub fn dropped_oversized(&self) -> u64 {
        self.traffic.dropped_oversized()
    }

    /// Datagrams whose send failed on a full session queue, of all sessions.
    pub fn dropped_queue_full(&self) -> u64 {
        self.traffic.dropped_queue_full()
    }
}

/// The counters of one session of a [`WssServerTransport`].
#[derive(Debug, Default)]
pub struct WssSessionStats {
    rx: AtomicU64,
    rx_bytes: AtomicU64,
    tx: AtomicU64,
    tx_bytes: AtomicU64,
    dropped_text: AtomicU64,
    dropped_oversized: AtomicU64,
    dropped_queue_full: AtomicU64,
}

impl WssSessionStats {
    /// Datagrams received.
    pub fn rx(&self) -> u64 {
        get(&self.rx)
    }

    /// Bytes of the datagrams received.
    pub fn rx_bytes(&self) -> u64 {
        get(&self.rx_bytes)
    }

    /// Datagrams written to the session.
    pub fn tx(&self) -> u64 {
        get(&self.tx)
    }

    /// Bytes of the datagrams written to the session.
    pub fn tx_bytes(&self) -> u64 {
        get(&self.tx_bytes)
    }

    /// Text messages received and dropped.
    pub fn dropped_text(&self) -> u64 {
        get(&self.dropped_text)
    }

    /// Datagrams longer than [`MAX_DATAGRAM`], sent or received, dropped.
    pub fn dropped_oversized(&self) -> u64 {
        get(&self.dropped_oversized)
    }

    /// Datagrams whose send failed on the full session queue.
    pub fn dropped_queue_full(&self) -> u64 {
        get(&self.dropped_queue_full)
    }
}

/// One session as the transport keeps it.
struct Session {
    addr: SocketAddr,
    outgoing: mpsc::Sender<Bytes>,
    close: Notify,
    stats: Arc<WssSessionStats>,
}

/// The open sessions by address; `closed` once the transport is dropped.
#[derive(Default)]
struct Sessions {
    closed: bool,
    /// The interface id of the last session's address.
    last: u64,
    open: HashMap<SocketAddr, Arc<Session>>,
}

/// What the transport, its acceptors and the session tasks share.
struct Shared {
    config: WssServerConfig,
    stats: Arc<WssServerTransportStats>,
    sessions: StdMutex<Sessions>,
    incoming: mpsc::Sender<(SocketAddr, Bytes)>,
}

impl Shared {
    /// Counts `f` on the transport's and the session's traffic counters.
    fn count(&self, session: &Session, f: impl Fn(&WssSessionStats)) {
        f(&self.stats.traffic);
        f(&session.stats);
    }
}

/// The address of the session with interface id `n`: `100::n` (in the RFC 6666
/// discard-only prefix `100::/64`), port 0.
fn session_addr(n: u64) -> SocketAddr {
    let ip = Ipv6Addr::from((0x0100_u128 << 112) | u128::from(n));
    SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, 0))
}

/// A [`Transport`] over the WebSocket sessions the embedder accepts: the server side of
/// [`WssDialer`](crate::WssDialer).
///
/// The embedder runs the listener: it accepts the connection, terminates TLS, checks the
/// request (path, token) and does the WebSocket upgrade, then hands the session to
/// [`WssAcceptor::accept`]. This crate does no authentication. Each session carries one
/// datagram per binary message, raw bytes as with [`WssDialer`](crate::WssDialer).
///
/// - **Endpoints**: each session gets its own address, never reused while the transport
///   lives: an IPv6 address in `100::/64` (the RFC 6666 discard-only prefix) whose interface
///   id counts the sessions accepted, port 0. Received datagrams come from
///   `Path { transport: id, addr: session address, ecn: NotEct }`. A WSS peer's endpoint
///   (in the engine's status and in UAPI) shows such an address: it identifies a session,
///   not a host.
/// - **Replies** go to the address the engine sends to: a peer's path roams on its
///   authenticated messages, so replies go to the session the peer last authenticated on.
///   Sending to an address without a live session fails at once with
///   [`io::ErrorKind::NotConnected`] (the engine counts
///   [`DROP_TRANSPORT_SEND_ERROR`](nsplane::DROP_TRANSPORT_SEND_ERROR); counted in
///   [`sent_to_closed`](WssServerTransportStats::sent_to_closed)). Between a session
///   closing and the peer dialing again, datagrams to that peer are lost by design,
///   counted as send errors: WireGuard retransmits its handshakes, and the peer's next
///   authenticated datagram on the new session moves its path there.
/// - **Backpressure**: each session has a queue of [`WssServerConfig::queue`] datagrams,
///   drained by its writer. `send` never waits on a slow session: on a full queue it fails
///   with [`io::ErrorKind::WouldBlock`] (counted in
///   [`dropped_queue_full`](WssServerTransportStats::dropped_queue_full)). Received
///   datagrams of all sessions share a queue of [`WssServerConfig::inbound_queue`];
///   while it is full the sessions' readers wait, pushing back on their TCP connections.
/// - **Messages**: text messages and binary ones longer than [`MAX_DATAGRAM`] are dropped
///   and counted, as is a datagram longer than [`MAX_DATAGRAM`] sent (the send succeeds).
///   A close frame, the end of the stream, an error, or no frame for
///   [`WssServerConfig::read_idle`] closes the session; it sends pings every
///   [`WssServerConfig::ping_interval`].
/// - **Lifecycle**: a session lives until it closes as above or by
///   [`WssSession::close`]; dropping its [`WssSession`] handle does not close it. Dropping
///   the transport closes every session, and [`WssAcceptor::accept`] fails afterwards.
///
/// Created (and its sessions accepted) inside a tokio runtime; each session runs in a task
/// of its own.
pub struct WssServerTransport {
    id: TransportId,
    shared: Arc<Shared>,
    incoming: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
}

impl WssServerTransport {
    /// The transport, and the acceptor that hands it sessions.
    pub fn new(id: TransportId, config: WssServerConfig) -> (Self, WssAcceptor) {
        let (incoming_tx, incoming) = mpsc::channel(config.inbound_queue.max(1));
        let shared = Arc::new(Shared {
            config,
            stats: Arc::new(WssServerTransportStats::default()),
            sessions: StdMutex::new(Sessions::default()),
            incoming: incoming_tx,
        });
        let acceptor = WssAcceptor {
            shared: Arc::clone(&shared),
        };
        let transport = Self {
            id,
            shared,
            incoming: Mutex::new(incoming),
        };
        (transport, acceptor)
    }

    /// The counters.
    pub fn stats(&self) -> Arc<WssServerTransportStats> {
        Arc::clone(&self.shared.stats)
    }
}

impl fmt::Debug for WssServerTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WssServerTransport")
            .field("id", &self.id)
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

impl Drop for WssServerTransport {
    fn drop(&mut self) {
        let open = {
            let mut sessions = lock(&self.shared.sessions);
            sessions.closed = true;
            std::mem::take(&mut sessions.open)
        };
        for session in open.values() {
            session.close.notify_one();
        }
    }
}

impl Transport for WssServerTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        let (addr, message) = self
            .incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "wss server closed"))?;
        let len = message.len().min(buf.capacity());
        buf.set_len(buf.capacity());
        buf.as_packet_mut()[..len].copy_from_slice(&message[..len]);
        buf.set_len(len);
        let path = Path {
            transport: self.id,
            addr,
            ecn: Ecn::NotEct,
        };
        Ok((len, path))
    }

    fn send(&self, datagram: &[u8], to: &Path) -> impl Future<Output = io::Result<()>> + Send {
        std::future::ready(self.try_send(datagram, to.addr))
    }
}

impl WssServerTransport {
    /// Queues `datagram` for the session at `addr`.
    fn try_send(&self, datagram: &[u8], addr: SocketAddr) -> io::Result<()> {
        let shared = &*self.shared;
        let session = lock(&shared.sessions).open.get(&addr).cloned();
        let Some(session) = session else {
            bump(&shared.stats.sent_to_closed);
            return Err(not_connected());
        };
        if datagram.len() > MAX_DATAGRAM {
            shared.count(&session, |s| bump(&s.dropped_oversized));
            return Ok(());
        }
        match session.outgoing.try_send(Bytes::copy_from_slice(datagram)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                shared.count(&session, |s| bump(&s.dropped_queue_full));
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "wss session send queue full",
                ))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                bump(&shared.stats.sent_to_closed);
                Err(not_connected())
            }
        }
    }
}

/// The error of a send to an address without a live session.
fn not_connected() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "no wss session at this address",
    )
}

/// Hands accepted WebSocket sessions to its [`WssServerTransport`].
#[derive(Clone)]
pub struct WssAcceptor {
    shared: Arc<Shared>,
}

impl fmt::Debug for WssAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WssAcceptor")
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

impl WssAcceptor {
    /// The WebSocket settings to upgrade with: messages and frames of at most
    /// [`MAX_MESSAGE`] bytes, the bound [`accept`](Self::accept) requires.
    pub fn ws_config() -> WebSocketConfig {
        ws_config()
    }

    /// Runs `ws`, a WebSocket the caller accepted and upgraded (after its own
    /// authentication), as a session of the transport, in a task of its own.
    ///
    /// Fails, dropping `ws` without starting anything, with
    /// [`io::ErrorKind::InvalidInput`] when `ws` reads messages or frames longer than
    /// [`MAX_MESSAGE`] (upgrade with [`ws_config`](Self::ws_config)),
    /// [`io::ErrorKind::BrokenPipe`] once the transport is dropped, and
    /// [`io::ErrorKind::ConnectionRefused`] when [`WssServerConfig::max_sessions`] are
    /// open.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime.
    pub fn accept<S>(&self, ws: WebSocketStream<S>) -> io::Result<WssSession>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let bounded = |limit: Option<usize>| limit.is_some_and(|limit| limit <= MAX_MESSAGE);
        let limits = ws.get_config();
        if !bounded(limits.max_message_size) || !bounded(limits.max_frame_size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("wss session reads messages longer than {MAX_MESSAGE} bytes"),
            ));
        }
        let shared = &self.shared;
        let (outgoing, outgoing_rx) = mpsc::channel(shared.config.queue.max(1));
        let session = {
            let mut sessions = lock(&shared.sessions);
            if sessions.closed {
                bump(&shared.stats.refused_closed);
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "wss server closed",
                ));
            }
            if sessions.open.len() >= shared.config.max_sessions {
                bump(&shared.stats.refused_limit);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "wss session limit reached",
                ));
            }
            sessions.last += 1;
            let session = Arc::new(Session {
                addr: session_addr(sessions.last),
                outgoing,
                close: Notify::new(),
                stats: Arc::new(WssSessionStats::default()),
            });
            sessions.open.insert(session.addr, Arc::clone(&session));
            session
        };
        bump(&shared.stats.accepted);
        bump(&shared.stats.active);
        tracing::debug!(addr = %session.addr, "wss session accepted");
        tokio::spawn(run(
            Arc::clone(shared),
            Arc::clone(&session),
            ws,
            outgoing_rx,
        ));
        Ok(WssSession { session })
    }
}

/// An accepted session of a [`WssServerTransport`].
///
/// Dropping the handle does not close the session; [`close`](Self::close) does.
pub struct WssSession {
    session: Arc<Session>,
}

impl fmt::Debug for WssSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WssSession")
            .field("addr", &self.session.addr)
            .field("stats", &self.session.stats)
            .finish()
    }
}

impl WssSession {
    /// The session's address: the source of its datagrams and the destination that
    /// reaches it.
    pub fn addr(&self) -> SocketAddr {
        self.session.addr
    }

    /// Closes the session (with a close frame, if it can be sent within a second); sends
    /// to its address fail from then on. Does nothing on a closed session.
    pub fn close(&self) {
        self.session.close.notify_one();
    }

    /// The session's counters.
    pub fn stats(&self) -> Arc<WssSessionStats> {
        Arc::clone(&self.session.stats)
    }
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Idle,
    Error,
    Peer,
    Local,
}

/// The session task: reads and writes until the session ends, then closes it.
async fn run<S>(
    shared: Arc<Shared>,
    session: Arc<Session>,
    ws: WebSocketStream<S>,
    outgoing: mpsc::Receiver<Bytes>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sink, stream) = ws.split();
    let end = tokio::select! {
        end = read(&shared, &session, stream) => end,
        end = write(&shared, &session, &mut sink, outgoing) => end,
        () = session.close.notified() => End::Local,
    };
    lock(&shared.sessions).open.remove(&session.addr);
    let stats = &shared.stats;
    stats.active.fetch_sub(1, Ordering::Relaxed);
    bump(match end {
        End::Idle => &stats.closed_idle,
        End::Error => &stats.closed_error,
        End::Peer => &stats.closed_peer,
        End::Local => &stats.closed_local,
    });
    tracing::debug!(addr = %session.addr, ?end, "wss session closed");
    if end != End::Error {
        let _ = tokio::time::timeout(CLOSE_WAIT, sink.close()).await;
    }
}

/// Hands the session's datagrams to the transport until it ends.
async fn read<S>(
    shared: &Shared,
    session: &Session,
    mut stream: SplitStream<WebSocketStream<S>>,
) -> End
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let Ok(message) = tokio::time::timeout(shared.config.read_idle, stream.next()).await else {
            return End::Idle;
        };
        match message {
            Some(Ok(Message::Binary(data))) => {
                if data.len() > MAX_DATAGRAM {
                    shared.count(session, |s| bump(&s.dropped_oversized));
                    continue;
                }
                let len = data.len();
                if shared.incoming.send((session.addr, data)).await.is_err() {
                    return End::Local;
                }
                shared.count(session, |s| {
                    bump(&s.rx);
                    add(&s.rx_bytes, len);
                });
            }
            Some(Ok(Message::Text(_))) => shared.count(session, |s| bump(&s.dropped_text)),
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
            Some(Ok(Message::Close(_))) | None => return End::Peer,
            Some(Err(e)) => {
                tracing::debug!(addr = %session.addr, error = %e, "wss session read failed");
                return End::Error;
            }
        }
    }
}

/// Writes the queued datagrams and the keepalive pings until a write fails.
async fn write<S>(
    shared: &Shared,
    session: &Session,
    sink: &mut SplitSink<WebSocketStream<S>, Message>,
    mut outgoing: mpsc::Receiver<Bytes>,
) -> End
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pings = Pings::new(shared.config.ping_interval.unwrap_or_default());
    loop {
        let message = tokio::select! {
            datagram = outgoing.recv() => {
                let Some(datagram) = datagram else {
                    return End::Local;
                };
                let len = datagram.len();
                if let Err(e) = sink.send(Message::Binary(datagram)).await {
                    tracing::debug!(addr = %session.addr, error = %e, "wss session write failed");
                    return End::Error;
                }
                shared.count(session, |s| {
                    bump(&s.tx);
                    add(&s.tx_bytes, len);
                });
                continue;
            }
            () = pings.tick() => Message::Ping(Bytes::new()),
        };
        if let Err(e) = sink.send(message).await {
            tracing::debug!(addr = %session.addr, error = %e, "wss session ping failed");
            return End::Error;
        }
    }
}

#[cfg(test)]
mod tests;
