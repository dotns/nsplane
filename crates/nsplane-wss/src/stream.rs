//! [`WssStreamClient`]: TCP streams and UDP flows multiplexed over WSS sessions with the
//! `WsFrame` protocol of the [`frame`](crate::frame) module.

#![expect(deprecated, reason = "the deprecated stream client and its tests")]

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use bytes::{Buf as _, Bytes};
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::LinkState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::AbortHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::MAX_DATAGRAM;
use crate::config::WssConfig;
use crate::connect::{
    Connector, DialCounters, Ws, WssDialError, WssDialEvent, add, bump, get, invalid, lock,
};
use crate::frame::{self, FrameCommand, HEADER_LEN, Protocol, WsFrame};

/// The most stream bytes one DATA frame carries: a frame is at most 65536 bytes, the most
/// a peer reads.
#[deprecated(
    since = "0.11.0",
    note = "the WebSocket stream carrier has no remaining consumer and will be removed once its users have switched; use a WireGuard peer over WssDialer instead"
)]
pub const MAX_DATA_PAYLOAD: usize = 65_536 - HEADER_LEN;

/// What each queued received frame costs on top of its payload, so that empty or tiny
/// frames cannot queue without bound.
pub(crate) const FRAME_OVERHEAD: usize = 64;

/// How long a session closing on its own waits for the WebSocket close handshake.
pub(crate) const CLOSE_WAIT: Duration = Duration::from_secs(1);

/// The bounds of a [`WssStreamClient`].
#[deprecated(
    since = "0.11.0",
    note = "the WebSocket stream carrier has no remaining consumer and will be removed once its users have switched; use a WireGuard peer over WssDialer instead"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WssStreamLimits {
    /// The most received bytes one stream queues before it is read. 4 MiB by default.
    pub stream_buffer: usize,
    /// The most received bytes all streams of one session queue together. 32 MiB by
    /// default.
    pub session_buffer: usize,
    /// The bounded queue of OPEN, `CLOSE_ACK` and reset CLOSE frames (and pings) toward the
    /// socket, written before data. 64 messages by default.
    pub control_queue: usize,
    /// The bounded queue of DATA frames and orderly CLOSE frames toward the socket. 256
    /// messages by default.
    pub data_queue: usize,
    /// The most live streams (TCP streams and UDP flows) on one session; an open beyond it
    /// goes to another session, dialed when none has room. 1024 by default.
    ///
    /// A server may reject OPENs beyond its own per-session stream cap (commonly 1024),
    /// so keep this at most the server's cap. A server may also write all streams of a
    /// session through one shared writer queue.
    pub max_streams_per_session: usize,
    /// How long [`connect`](WssStreamClient::connect), [`open_tcp`](WssStreamClient::open_tcp)
    /// and [`open_udp`](WssStreamClient::open_udp) wait for a session. Past it they fail
    /// with the error of the last session dial (its kind, message and [`WssDialError`]),
    /// or with [`io::ErrorKind::TimedOut`] when none failed since the last session came up;
    /// the dial goes on, with its backoff, and serves later opens. `None` (the default)
    /// waits as long as the dial does: its backoff, the token wait after a 401
    /// ([`WssConfig::token_wait`]) and the dial itself.
    pub open_timeout: Option<Duration>,
}

impl Default for WssStreamLimits {
    fn default() -> Self {
        Self {
            stream_buffer: 4 * 1024 * 1024,
            session_buffer: 32 * 1024 * 1024,
            control_queue: 64,
            data_queue: 256,
            max_streams_per_session: 1024,
            open_timeout: None,
        }
    }
}

impl WssStreamLimits {
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

    /// Sets [`max_streams_per_session`](Self::max_streams_per_session); see there for the
    /// server caveats.
    #[must_use]
    pub const fn max_streams_per_session(mut self, streams: usize) -> Self {
        self.max_streams_per_session = streams;
        self
    }

    /// Sets [`open_timeout`](Self::open_timeout).
    #[must_use]
    pub const fn open_timeout(mut self, timeout: Duration) -> Self {
        self.open_timeout = Some(timeout);
        self
    }
}

/// The counters of a [`WssStreamClient`] and its sessions.
#[deprecated(
    since = "0.11.0",
    note = "the WebSocket stream carrier has no remaining consumer and will be removed once its users have switched; use a WireGuard peer over WssDialer instead"
)]
#[derive(Debug, Default)]
pub struct WssStreamStats {
    sessions: AtomicU64,
    active_sessions: AtomicUsize,
    dial: DialCounters,
    streams_opened: AtomicU64,
    streams_closed: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    ignored: AtomicU64,
    invalid: AtomicU64,
    overflows: AtomicU64,
}

impl WssStreamStats {
    /// Whether a session is up.
    pub fn connected(&self) -> bool {
        self.active_sessions() > 0
    }

    /// Sessions that came up.
    pub fn sessions(&self) -> u64 {
        get(&self.sessions)
    }

    /// Sessions up now.
    pub fn active_sessions(&self) -> usize {
        self.active_sessions.load(Ordering::Relaxed)
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

    /// Streams and flows opened.
    pub fn streams_opened(&self) -> u64 {
        get(&self.streams_opened)
    }

    /// Streams and flows gone from their session: closed by the peer, acknowledged, or
    /// with their session.
    pub fn streams_closed(&self) -> u64 {
        get(&self.streams_closed)
    }

    /// Payload bytes sent.
    pub fn tx_bytes(&self) -> u64 {
        get(&self.tx_bytes)
    }

    /// Payload bytes received and queued.
    pub fn rx_bytes(&self) -> u64 {
        get(&self.rx_bytes)
    }

    /// Frames for unknown or closed stream ids, ignored.
    pub fn ignored(&self) -> u64 {
        get(&self.ignored)
    }

    /// Messages that are not a frame the client takes (text, malformed, an OPEN), ignored.
    pub fn invalid(&self) -> u64 {
        get(&self.invalid)
    }

    /// Received frames over a receive bound: each resets its TCP stream, or is a UDP
    /// datagram dropped.
    pub fn overflows(&self) -> u64 {
        get(&self.overflows)
    }
}

/// How a flow ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The peer closed it, or acknowledged our close: reads end, writes fail.
    Closed,
    /// A receive bound overflowed (TCP): reads and writes fail with a reset.
    Reset,
    /// Its session ended: reads fail with a reset, writes with a broken pipe.
    Lost,
}

#[derive(Debug, Default)]
struct FlowState {
    /// Received payloads, oldest first; a TCP stream's front may be partly read.
    queue: VecDeque<Bytes>,
    /// What the queue costs on the stream and session budgets.
    charged: usize,
    waker: Option<Waker>,
    end: Option<End>,
    /// A CLOSE was sent: no more writes.
    closing: bool,
    /// The handle is gone: received data is ignored.
    detached: bool,
}

/// One stream or flow of a session.
#[derive(Debug)]
struct Flow {
    id: u32,
    protocol: Protocol,
    state: StdMutex<FlowState>,
}

impl Flow {
    fn ended(&self, end: End) {
        let mut state = lock(&self.state);
        state.end.get_or_insert(end);
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

/// The streams of a session.
#[derive(Debug)]
struct Table {
    flows: HashMap<u32, Arc<Flow>>,
    next_id: u32,
    closed: bool,
}

impl Table {
    fn new() -> Self {
        Self {
            flows: HashMap::new(),
            next_id: 1,
            closed: false,
        }
    }

    /// A new flow with the next free id, or `None` when the session ended or holds `max`
    /// flows. Ids count up from 1, wrap past 0 and skip ids still in use.
    fn insert(&mut self, protocol: Protocol, max: usize) -> Option<Arc<Flow>> {
        if self.closed || self.flows.len() >= max {
            return None;
        }
        let id = loop {
            let id = self.next_id;
            self.next_id = self.next_id.checked_add(1).unwrap_or(1);
            if !self.flows.contains_key(&id) {
                break id;
            }
        };
        let flow = Arc::new(Flow {
            id,
            protocol,
            state: StdMutex::new(FlowState::default()),
        });
        self.flows.insert(id, Arc::clone(&flow));
        Some(flow)
    }
}

/// One WSS connection carrying many flows.
struct Session {
    number: u64,
    limits: WssStreamLimits,
    stats: Arc<WssStreamStats>,
    connector: Arc<Connector>,
    table: StdMutex<Table>,
    /// What the queues of all flows cost.
    buffered: AtomicUsize,
    control: mpsc::Sender<Message>,
    data: mpsc::Sender<Message>,
    shutdown: watch::Sender<bool>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("number", &self.number)
            .field("buffered", &self.buffered)
            .finish_non_exhaustive()
    }
}

/// The receiving ends of a session's queues, taken by its task.
struct Queues {
    control: mpsc::Receiver<Message>,
    data: mpsc::Receiver<Message>,
    shutdown: watch::Receiver<bool>,
}

impl Session {
    fn new(
        number: u64,
        limits: WssStreamLimits,
        stats: Arc<WssStreamStats>,
        connector: Arc<Connector>,
    ) -> (Arc<Self>, Queues) {
        let (control, control_rx) = mpsc::channel(limits.control_queue);
        let (data, data_rx) = mpsc::channel(limits.data_queue);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let session = Arc::new(Self {
            number,
            limits,
            stats,
            connector,
            table: StdMutex::new(Table::new()),
            buffered: AtomicUsize::new(0),
            control,
            data,
            shutdown,
        });
        let queues = Queues {
            control: control_rx,
            data: data_rx,
            shutdown: shutdown_rx,
        };
        (session, queues)
    }

    fn is_closed(&self) -> bool {
        lock(&self.table).closed
    }

    fn reserve(&self, protocol: Protocol) -> Option<Arc<Flow>> {
        let flow = lock(&self.table).insert(protocol, self.limits.max_streams_per_session)?;
        bump(&self.stats.streams_opened);
        Some(flow)
    }

    /// Queues a control frame without waiting; `false` when the queue is full or gone.
    fn send_control(&self, frame: &WsFrame) -> bool {
        let sent = self
            .control
            .try_send(Message::Binary(frame.encode()))
            .is_ok();
        if !sent {
            tracing::warn!(session = self.number, stream_id = frame.stream_id, command = ?frame.command, "wss control queue full; frame dropped");
        }
        sent
    }

    /// Releases `bytes` of queued data from the session budget.
    fn release(&self, bytes: usize) {
        self.buffered.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Handles one received binary message.
    fn dispatch(&self, message: &Bytes) {
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
            FrameCommand::Data => {
                let flow = lock(&self.table).flows.get(&id).cloned();
                match flow {
                    Some(flow) => self.deliver(&flow, frame.payload),
                    None => bump(&self.stats.ignored),
                }
            }
            FrameCommand::Close => {
                // Acknowledged whether known or not, as the server side does.
                self.send_control(&WsFrame::close_ack(id));
                self.finish(id);
            }
            FrameCommand::CloseAck => self.finish(id),
            FrameCommand::Open { .. } => bump(&self.stats.invalid),
        }
    }

    /// Ends the flow `id` after the peer's CLOSE or `CLOSE_ACK`; its id is free again.
    fn finish(&self, id: u32) {
        let flow = lock(&self.table).flows.remove(&id);
        match flow {
            Some(flow) => {
                bump(&self.stats.streams_closed);
                flow.ended(End::Closed);
            }
            None => bump(&self.stats.ignored),
        }
    }

    /// Queues `payload` for `flow` within the stream and session bounds.
    ///
    /// Over a bound, a TCP stream is reset (only that stream: a CLOSE goes out and its
    /// reads fail once the queued bytes are read), as the server side closes a stream it
    /// cannot buffer for; a UDP datagram is dropped and the flow stays.
    fn deliver(&self, flow: &Flow, payload: Bytes) {
        let mut state = lock(&flow.state);
        if state.detached || state.end.is_some() {
            bump(&self.stats.ignored);
            return;
        }
        if payload.is_empty() && flow.protocol == Protocol::Tcp {
            // Nothing to read; an empty read would mean the end of the stream.
            return;
        }
        let len = payload.len();
        let cost = len + FRAME_OVERHEAD;
        // Only the session task adds to the session budget, so the check holds until the
        // add below.
        let fits = state.charged + cost <= self.limits.stream_buffer
            && self.buffered.load(Ordering::Relaxed) + cost <= self.limits.session_buffer;
        if !fits {
            bump(&self.stats.overflows);
            if flow.protocol == Protocol::Tcp {
                tracing::debug!(
                    session = self.number,
                    stream_id = flow.id,
                    "wss stream buffer full; resetting the stream"
                );
                state.end = Some(End::Reset);
                state.closing = true;
                if let Some(waker) = state.waker.take() {
                    waker.wake();
                }
                drop(state);
                self.send_control(&WsFrame::close(flow.id));
            }
            return;
        }
        state.charged += cost;
        self.buffered.fetch_add(cost, Ordering::Relaxed);
        state.queue.push_back(payload);
        add(&self.stats.rx_bytes, len);
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }

    /// Ends the session: every flow still on it is lost.
    fn end(&self) {
        let flows: Vec<Arc<Flow>> = {
            let mut table = lock(&self.table);
            table.closed = true;
            table.flows.drain().map(|(_, flow)| flow).collect()
        };
        add(&self.stats.streams_closed, flows.len());
        for flow in flows {
            flow.ended(End::Lost);
        }
        self.connector.lost();
        self.connector.emit(WssDialEvent::Lost);
        if self.stats.active_sessions.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.connector.set_state(LinkState::Disconnected);
        }
    }

    /// Runs the session on `ws`: writes the queues (control first) and keepalive pings,
    /// dispatches received frames, and ends the session on a socket error, a close, a read
    /// idle or a shutdown.
    async fn run(self: Arc<Self>, ws: Ws, queues: Queues) {
        let Queues {
            control: mut control_rx,
            data: mut data_rx,
            mut shutdown,
        } = queues;
        let config = self.connector.config();
        let read_idle = config.read_idle;
        let (mut sink, mut stream) = ws.split();
        let writer = async {
            let mut pings = config.pings();
            loop {
                let message = tokio::select! {
                    biased;
                    Some(message) = control_rx.recv() => message,
                    () = pings.tick() => Message::Ping(Bytes::new()),
                    Some(message) = data_rx.recv() => message,
                };
                if let Err(error) = sink.send(message).await {
                    return format!("write failed: {error}");
                }
            }
        };
        let reader = async {
            loop {
                let Ok(message) = tokio::time::timeout(read_idle, stream.next()).await else {
                    return "silent".to_owned();
                };
                match message {
                    Some(Ok(Message::Binary(data))) => self.dispatch(&data),
                    Some(Ok(Message::Text(_))) => bump(&self.stats.invalid),
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_))) | None => return "closed by the peer".to_owned(),
                    Some(Err(error)) => return format!("read failed: {error}"),
                }
            }
        };
        let reason = tokio::select! {
            reason = writer => reason,
            reason = reader => reason,
            _ = shutdown.wait_for(|down| *down) => "shut down".to_owned(),
        };
        self.end();
        tracing::info!(session = self.number, url = %config.url, %reason, "wss session ended");
        let _ = tokio::time::timeout(CLOSE_WAIT, sink.close()).await;
    }
}

/// A copy of a dial error: its kind and message, and its [`WssDialError`] if it has one.
fn copy_error(error: &io::Error) -> io::Error {
    let kind = error.kind();
    error
        .get_ref()
        .and_then(|e| e.downcast_ref::<WssDialError>())
        .map_or_else(
            || io::Error::new(kind, error.to_string()),
            |detail| io::Error::new(kind, detail.clone()),
        )
}

/// A session dial in flight, run by its own task.
struct Dial {
    /// Closed when the dial finished and its outcome is recorded.
    done: watch::Receiver<()>,
    task: AbortHandle,
}

/// The client state shared by its clones.
struct Inner {
    connector: Arc<Connector>,
    limits: WssStreamLimits,
    stats: Arc<WssStreamStats>,
    sessions: StdMutex<Vec<Arc<Session>>>,
    /// The dial in flight: one at a time. Its outcome is recorded under this lock.
    dialing: StdMutex<Option<Dial>>,
    /// Finished dials.
    dials: AtomicU64,
    /// The error of the last dial, if it failed.
    last_failure: StdMutex<Option<io::Error>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let dial = lock(&self.dialing).take();
        if let Some(dial) = dial {
            dial.task.abort();
        }
        for session in lock(&self.sessions).iter() {
            session.shutdown.send_replace(true);
        }
    }
}

impl Inner {
    /// [`with_session`](Self::with_session) within the open timeout, if one is set.
    async fn within_open_timeout<T>(
        self: &Arc<Self>,
        take: impl FnMut(&Arc<Session>) -> Option<T> + Send,
    ) -> io::Result<T> {
        let Some(limit) = self.limits.open_timeout else {
            return self.with_session(take).await;
        };
        if let Ok(result) = tokio::time::timeout(limit, self.with_session(take)).await {
            return result;
        }
        Err(lock(&self.last_failure).as_ref().map_or_else(
            || io::Error::new(io::ErrorKind::TimedOut, "wss open timed out"),
            copy_error,
        ))
    }

    /// The first of `take` over the live sessions that is `Some`, dialing a new session
    /// while there is none. Waiters behind a failed dial get its error rather than dialing
    /// once each.
    ///
    /// The dial runs in its own task, so a waiter dropped (or timed out) neither stops it
    /// nor loses its backoff or token wait.
    async fn with_session<T>(
        self: &Arc<Self>,
        mut take: impl FnMut(&Arc<Session>) -> Option<T> + Send,
    ) -> io::Result<T> {
        loop {
            if let Some(found) = self.find(&mut take) {
                return Ok(found);
            }
            let seen = self.dials.load(Ordering::Acquire);
            let mut done = {
                let mut dialing = lock(&self.dialing);
                if let Some(found) = self.find(&mut take) {
                    return Ok(found);
                }
                if self.dials.load(Ordering::Acquire) != seen
                    && let Some(failure) = lock(&self.last_failure).as_ref()
                {
                    return Err(copy_error(failure));
                }
                dialing.get_or_insert_with(|| self.dial()).done.clone()
            };
            // Closed once the dial's outcome is recorded.
            let _ = done.changed().await;
            if let Some(found) = self.find(&mut take) {
                return Ok(found);
            }
            if let Some(failure) = lock(&self.last_failure).as_ref() {
                return Err(copy_error(failure));
            }
        }
    }

    fn find<T>(&self, take: &mut impl FnMut(&Arc<Session>) -> Option<T>) -> Option<T> {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|session| !session.is_closed());
        sessions.iter().find_map(take)
    }

    /// Starts a dial in its own task; called with [`dialing`](Self::dialing) locked.
    fn dial(self: &Arc<Self>) -> Dial {
        let (finished, done) = watch::channel(());
        let inner = Arc::downgrade(self);
        let connector = Arc::clone(&self.connector);
        let stats = Arc::clone(&self.stats);
        let task = tokio::spawn(async move {
            let result = connector.connect(&stats.dial).await;
            if let Some(inner) = inner.upgrade() {
                inner.dialed(result);
            }
            drop(finished);
        });
        Dial {
            done,
            task: task.abort_handle(),
        }
    }

    /// Records the outcome of the dial in flight: a session, or the failure.
    fn dialed(&self, result: io::Result<Ws>) {
        let mut dialing = lock(&self.dialing);
        *dialing = None;
        self.dials.fetch_add(1, Ordering::Release);
        let ws = match result {
            Ok(ws) => ws,
            Err(error) => {
                *lock(&self.last_failure) = Some(error);
                return;
            }
        };
        *lock(&self.last_failure) = None;
        // A further session is dialed for capacity, without the backoff after a loss.
        self.connector.retry_now();
        let number = self.stats.sessions.fetch_add(1, Ordering::Relaxed) + 1;
        let (session, queues) = Session::new(
            number,
            self.limits,
            Arc::clone(&self.stats),
            Arc::clone(&self.connector),
        );
        self.stats.active_sessions.fetch_add(1, Ordering::Relaxed);
        self.connector.set_state(LinkState::Connected);
        self.connector.emit(WssDialEvent::Connected);
        tracing::info!(session = number, url = %self.connector.config().url, "wss session up");
        tokio::spawn(Arc::clone(&session).run(ws, queues));
        lock(&self.sessions).push(session);
    }

    /// Reserves a flow on a session with room and sends its OPEN.
    async fn open(self: &Arc<Self>, target: SocketAddr, protocol: Protocol) -> io::Result<Handle> {
        let (session, flow) = self
            .within_open_timeout(|session| {
                session
                    .reserve(protocol)
                    .map(|flow| (Arc::clone(session), flow))
            })
            .await?;
        let open = WsFrame::open(flow.id, target, protocol);
        let handle = Handle {
            session,
            flow,
            target,
        };
        // OPEN goes on the control queue, written before any DATA queued after it.
        if handle
            .session
            .control
            .send(Message::Binary(open.encode()))
            .await
            .is_err()
        {
            return Err(lost());
        }
        Ok(handle)
    }
}

fn lost() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "wss session lost")
}

/// One open flow of a session: what [`WssTcpStream`] and [`WssUdpFlow`] share.
#[derive(Debug)]
struct Handle {
    session: Arc<Session>,
    flow: Arc<Flow>,
    target: SocketAddr,
}

impl Handle {
    /// Whether the flow may still send.
    fn writable(&self) -> io::Result<()> {
        let state = lock(&self.flow.state);
        match state.end {
            Some(End::Reset) => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "wss stream reset",
            )),
            Some(End::Lost) => Err(lost()),
            Some(End::Closed) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wss stream closed by the peer",
            )),
            None if state.closing => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wss stream shut down",
            )),
            None => Ok(()),
        }
    }

    /// Takes queued bytes into `buf` (TCP) or the next datagram (UDP), or tells how the
    /// flow ended once its queue is empty.
    fn poll_take(
        &self,
        cx: &Context<'_>,
        buf: Option<&mut ReadBuf<'_>>,
    ) -> Poll<io::Result<Option<Bytes>>> {
        let mut state = lock(&self.flow.state);
        if let Some(front) = state.queue.front_mut() {
            let (taken, released) = if let Some(buf) = buf {
                let n = front.len().min(buf.remaining());
                buf.put_slice(&front[..n]);
                front.advance(n);
                if front.is_empty() {
                    state.queue.pop_front();
                    (None, n + FRAME_OVERHEAD)
                } else {
                    (None, n)
                }
            } else {
                let datagram = state.queue.pop_front().unwrap_or_default();
                let released = datagram.len() + FRAME_OVERHEAD;
                (Some(datagram), released)
            };
            state.charged -= released;
            self.session.release(released);
            return Poll::Ready(Ok(taken));
        }
        match state.end {
            Some(End::Closed) => Poll::Ready(Ok(None)),
            Some(End::Reset) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "wss stream reset: receive buffer full",
            ))),
            Some(End::Lost) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "wss session lost",
            ))),
            None => {
                state.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Marks the flow closing; `false` when it already is or ended.
    fn start_close(&self) -> bool {
        let mut state = lock(&self.flow.state);
        if state.closing || state.end.is_some() {
            return false;
        }
        state.closing = true;
        true
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let mut state = lock(&self.flow.state);
        state.detached = true;
        state.queue.clear();
        self.session.release(std::mem::take(&mut state.charged));
        drop(state);
        if !self.start_close() {
            return;
        }
        // Behind the flow's queued data if there is room, else at least on the control
        // queue; with neither the peer keeps the stream, but its id is not held here.
        let id = self.flow.id;
        let close = Message::Binary(WsFrame::close(id).encode());
        let sent = match self.session.data.try_send(close) {
            Ok(()) => true,
            Err(error) => self.session.control.try_send(error.into_inner()).is_ok(),
        };
        if !sent {
            tracing::warn!(
                session = self.session.number,
                stream_id = id,
                "wss queues full; CLOSE dropped"
            );
            if lock(&self.session.table).flows.remove(&id).is_some() {
                bump(&self.session.stats.streams_closed);
            }
        }
    }
}

/// A pending wait for room on a session's data queue.
type Reserve = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Message>, mpsc::error::SendError<()>>> + Send>,
>;

/// A TCP stream over a WSS session, opened by [`WssStreamClient::open_tcp`].
///
/// Writes go out as DATA frames of at most [`MAX_DATA_PAYLOAD`] bytes, waiting for room on
/// the session's data queue. [`poll_shutdown`](AsyncWrite::poll_shutdown) sends CLOSE
/// behind the data already written: the wire has no other half-close, and the server
/// side may tear the stream down on it, so the stream keeps reading until the peer's
/// CLOSE or `CLOSE_ACK` and then reads EOF. A CLOSE from the peer reads as EOF (after the
/// bytes before it) and is answered with `CLOSE_ACK`. Dropping the stream without a
/// shutdown sends CLOSE too.
///
/// Reads fail with [`io::ErrorKind::ConnectionReset`] when the session is lost, or when
/// the peer sent more than the stream's receive buffer holds; writes then fail with
/// [`io::ErrorKind::BrokenPipe`] (or the reset), as they do after a shutdown or the
/// peer's CLOSE.
#[deprecated(
    since = "0.11.0",
    note = "the WebSocket stream carrier has no remaining consumer and will be removed once its users have switched; use a WireGuard peer over WssDialer instead"
)]
pub struct WssTcpStream {
    handle: Handle,
    reserve: Option<Reserve>,
}

impl fmt::Debug for WssTcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WssTcpStream")
            .field("stream_id", &self.handle.flow.id)
            .field("target", &self.handle.target)
            .finish_non_exhaustive()
    }
}

impl WssTcpStream {
    /// The stream id on its session.
    pub fn stream_id(&self) -> u32 {
        self.handle.flow.id
    }

    /// The target the stream was opened to.
    pub const fn target(&self) -> SocketAddr {
        self.handle.target
    }

    /// Waits for room on the data queue.
    fn poll_reserve(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<mpsc::OwnedPermit<Message>>> {
        if self.reserve.is_none() {
            match self.handle.session.data.clone().try_reserve_owned() {
                Ok(permit) => return Poll::Ready(Ok(permit)),
                Err(mpsc::error::TrySendError::Closed(_)) => return Poll::Ready(Err(lost())),
                Err(mpsc::error::TrySendError::Full(data)) => {
                    self.reserve = Some(Box::pin(data.reserve_owned()));
                }
            }
        }
        let Some(reserve) = self.reserve.as_mut() else {
            return Poll::Ready(Err(lost()));
        };
        let permit = ready!(reserve.as_mut().poll(cx));
        self.reserve = None;
        Poll::Ready(permit.map_err(|_| lost()))
    }
}

impl AsyncRead for WssTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.handle.poll_take(cx, Some(buf)))?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for WssTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.handle.writable()?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let permit = ready!(self.poll_reserve(cx))?;
        self.handle.writable()?;
        let n = buf.len().min(MAX_DATA_PAYLOAD);
        permit.send(Message::Binary(frame::encode_data(
            self.handle.flow.id,
            &buf[..n],
        )));
        add(&self.handle.session.stats.tx_bytes, n);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let state = lock(&self.handle.flow.state);
            if state.closing || state.end.is_some() {
                return Poll::Ready(Ok(()));
            }
        }
        let permit = ready!(self.poll_reserve(cx))?;
        if self.handle.start_close() {
            permit.send(Message::Binary(
                WsFrame::close(self.handle.flow.id).encode(),
            ));
        }
        Poll::Ready(Ok(()))
    }
}

/// A UDP flow over a WSS session, opened by [`WssStreamClient::open_udp`]: each datagram
/// is one DATA frame. Dropping the flow sends CLOSE.
///
/// A datagram arriving while the flow's receive buffer is full is dropped (and counted in
/// [`WssStreamStats::overflows`]); the flow stays open.
#[deprecated(
    since = "0.11.0",
    note = "the WebSocket stream carrier has no remaining consumer and will be removed once its users have switched; use a WireGuard peer over WssDialer instead"
)]
pub struct WssUdpFlow {
    handle: Handle,
}

impl fmt::Debug for WssUdpFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WssUdpFlow")
            .field("stream_id", &self.handle.flow.id)
            .field("target", &self.handle.target)
            .finish_non_exhaustive()
    }
}

impl WssUdpFlow {
    /// The stream id on its session.
    pub fn stream_id(&self) -> u32 {
        self.handle.flow.id
    }

    /// The target the flow was opened to.
    pub const fn target(&self) -> SocketAddr {
        self.handle.target
    }

    /// Sends one datagram, waiting for room on the session's data queue.
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] on a datagram longer than
    /// [`MAX_DATAGRAM`], and with [`io::ErrorKind::BrokenPipe`] once the flow or its
    /// session ended.
    pub async fn send(&self, datagram: &[u8]) -> io::Result<()> {
        if datagram.len() > MAX_DATAGRAM {
            return Err(invalid(format!(
                "datagram of {} bytes is longer than {MAX_DATAGRAM}",
                datagram.len()
            )));
        }
        self.handle.writable()?;
        let permit = self
            .handle
            .session
            .data
            .reserve()
            .await
            .map_err(|_| lost())?;
        self.handle.writable()?;
        permit.send(Message::Binary(frame::encode_data(
            self.handle.flow.id,
            datagram,
        )));
        add(&self.handle.session.stats.tx_bytes, datagram.len());
        Ok(())
    }

    /// The next datagram; `None` once the peer closed the flow. Fails with
    /// [`io::ErrorKind::ConnectionReset`] when the session is lost.
    pub async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Polls for the next datagram, as [`recv`](Self::recv).
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        self.handle.poll_take(cx, None)
    }
}

/// Opens TCP streams and UDP flows to targets behind a WSS server (such as a
/// [`WssStreamServer`](crate::WssStreamServer)), multiplexed over WSS sessions with the
/// `WsFrame` protocol.
///
/// - **Sessions**: dialed like [`WssDialer`](crate::WssDialer) links (URL, TLS, headers,
///   bearer, 401/403 as [`LinkState::Rejected`], the doubling backoff, pings and the read
///   idle of the [`WssConfig`]), lazily on the first open or by [`connect`](Self::connect).
///   [`events`](Self::events) reports each dial and session.
///   Every stream and flow shares one session until it holds
///   [`max_streams_per_session`](WssStreamLimits::max_streams_per_session) live ones;
///   only then is another session dialed. One dial runs at a time, in its own task; opens
///   waiting for it share its result. A dial after a session was lost waits
///   [`reconnect_delay`](WssConfig::reconnect_delay), or the backoff. With
///   [`open_timeout`](WssStreamLimits::open_timeout), opens fail fast with the last dial
///   error instead of waiting out the backoff or the token wait; the dial goes on.
/// - **Stream ids**: per session, counting up from 1, never 0, skipping ids still in use.
///   An id stays in use until the peer's CLOSE or `CLOSE_ACK`.
/// - **Loss**: when a session ends (socket error, close, read idle), every stream and flow
///   on it fails; the next open dials again.
/// - **Bounds**: see [`WssStreamLimits`]. Frames for unknown or closed stream ids are
///   ignored and counted.
///
/// Clones share the sessions. Dropping the last clone ends them, failing the streams
/// still open.
#[deprecated(
    since = "0.11.0",
    note = "the WebSocket stream carrier has no remaining consumer and will be removed once its users have switched; use a WireGuard peer over WssDialer instead"
)]
#[derive(Clone)]
pub struct WssStreamClient {
    inner: Arc<Inner>,
}

impl fmt::Debug for WssStreamClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WssStreamClient")
            .field("connector", &self.inner.connector)
            .field("limits", &self.inner.limits)
            .field("stats", &self.inner.stats)
            .finish_non_exhaustive()
    }
}

impl WssStreamClient {
    /// A client for `config` within `limits`; it dials nothing yet.
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] where [`WssDialer::new`] does, and on a
    /// zero queue length or stream maximum.
    ///
    /// [`WssDialer::new`]: crate::WssDialer::new
    pub fn new(config: WssConfig, limits: WssStreamLimits) -> io::Result<Self> {
        if limits.control_queue == 0 || limits.data_queue == 0 {
            return Err(invalid("wss stream queues must hold a message".to_owned()));
        }
        if limits.max_streams_per_session == 0 {
            return Err(invalid("a wss session must carry a stream".to_owned()));
        }
        let inner = Inner {
            connector: Arc::new(Connector::new(config)?),
            limits,
            stats: Arc::new(WssStreamStats::default()),
            sessions: StdMutex::new(Vec::new()),
            dialing: StdMutex::new(None),
            dials: AtomicU64::new(0),
            last_failure: StdMutex::new(None),
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The counters.
    pub fn stats(&self) -> Arc<WssStreamStats> {
        Arc::clone(&self.inner.stats)
    }

    /// Watches the session state: [`LinkState::Disconnected`] at first and while no
    /// session is up, [`LinkState::Connected`] while one is, [`LinkState::Rejected`] after
    /// a dial was refused with 401 or 403 (until a session comes up).
    pub fn state(&self) -> watch::Receiver<LinkState> {
        self.inner.connector.state()
    }

    /// Receives the [`WssDialEvent`]s from now on: one per failed, timed out or rejected
    /// session dial, [`Connected`](WssDialEvent::Connected) per session that came up and
    /// [`Lost`](WssDialEvent::Lost) per session that ended, after its `Connected`.
    pub fn events(&self) -> broadcast::Receiver<WssDialEvent> {
        self.inner.connector.events()
    }

    /// Dials a session unless one is up.
    pub async fn connect(&self) -> io::Result<()> {
        self.inner.within_open_timeout(|_| Some(())).await
    }

    /// Opens a TCP stream to `target` (an OPEN with protocol TCP).
    ///
    /// Returns once the OPEN is queued: the protocol has no open reply, and a server
    /// refusing the target answers with CLOSE, which reads as EOF.
    pub async fn open_tcp(&self, target: SocketAddr) -> io::Result<WssTcpStream> {
        let handle = self.inner.open(target, Protocol::Tcp).await?;
        Ok(WssTcpStream {
            handle,
            reserve: None,
        })
    }

    /// Opens a UDP flow to `target` (an OPEN with protocol UDP), as
    /// [`open_tcp`](Self::open_tcp).
    pub async fn open_udp(&self, target: SocketAddr) -> io::Result<WssUdpFlow> {
        let handle = self.inner.open(target, Protocol::Udp).await?;
        Ok(WssUdpFlow { handle })
    }
}

#[cfg(test)]
mod tests;
