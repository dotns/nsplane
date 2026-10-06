//! The session tests of ns `tunnel-ws` (dispatch, lifecycle, and the behavior its logging
//! test exercises), ported to the server with a test resolver for ns's policy.

use super::*;
use crate::WssTls;
use rustls::RootCertStore;
use tokio::net::TcpListener;
use tokio::time::timeout;

const WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Resolves the targets it maps; denies the rest. The map may change between OPENs.
#[derive(Debug, Default)]
struct Allow(StdMutex<HashMap<SocketAddr, SocketAddr>>);

impl Allow {
    fn with(pairs: &[(SocketAddr, SocketAddr)]) -> Arc<Self> {
        let allow = Self::default();
        lock(&allow.0).extend(pairs.iter().copied());
        Arc::new(allow)
    }
}

impl WssResolver for Allow {
    fn resolve(&self, open: WssOpen) -> BoxFuture<'_, Result<SocketAddr, Denied>> {
        let backend = lock(&self.0).get(&open.target).copied().ok_or(Denied);
        Box::pin(std::future::ready(backend))
    }
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn config() -> WssConfig {
    WssConfig::new("wss://relay.test/", WssTls::Roots(RootCertStore::empty()))
}

/// A session without a socket: the test plays its task, reading the queues.
fn new_session(limits: WssServerLimits, resolver: Arc<Allow>) -> (Arc<Session>, Queues) {
    Session::new(
        1,
        limits,
        Arc::new(WssServerStats::default()),
        resolver,
        None,
    )
}

fn with_events(
    limits: WssServerLimits,
    resolver: Arc<Allow>,
) -> (Arc<Session>, Queues, mpsc::Receiver<WssStreamEvent>) {
    let (events, events_rx) = mpsc::channel(16);
    let (session, queues) = Session::new(
        1,
        limits,
        Arc::new(WssServerStats::default()),
        resolver,
        Some(events),
    );
    (session, queues, events_rx)
}

/// Registers stream `id` without a relay; the test reads its queue.
fn register(session: &Session, id: u32) -> mpsc::Receiver<Queued> {
    let (tx, rx) = mpsc::channel(session.limits.stream_queue);
    let stream = Arc::new(Stream {
        id,
        charged: AtomicUsize::new(0),
        reset: Notify::new(),
        overflowed: AtomicBool::new(false),
        backend: OnceLock::new(),
    });
    lock(&session.table).insert(id, Entry { stream, tx });
    rx
}

fn data(id: u32, payload: &[u8]) -> Bytes {
    frame::encode_data(id, payload)
}

fn open(id: u32, target: SocketAddr, protocol: Protocol) -> Bytes {
    WsFrame::open(id, target, protocol).encode()
}

fn decode(message: Message) -> WsFrame {
    match message {
        Message::Binary(bytes) => WsFrame::decode(&bytes).unwrap(),
        other => panic!("unexpected {other:?}"),
    }
}

/// The next frame on a queue, if one is there.
fn next(queue: &mut mpsc::Receiver<Message>) -> Option<WsFrame> {
    queue.try_recv().ok().map(decode)
}

/// The next frame on a queue, within [`WAIT`].
async fn next_within(queue: &mut mpsc::Receiver<Message>) -> WsFrame {
    decode(timeout(WAIT, queue.recv()).await.unwrap().unwrap())
}

async fn event(events: &mut mpsc::Receiver<WssStreamEvent>) -> WssStreamEvent {
    timeout(WAIT, events.recv()).await.unwrap().unwrap()
}

/// Waits for every relay of `tasks` to end.
async fn join(tasks: &mut JoinSet<()>) {
    while let Some(joined) = timeout(WAIT, tasks.join_next()).await.unwrap() {
        joined.unwrap();
    }
}

#[test]
fn limits_defaults_and_setters() {
    let limits = WssServerLimits::default();
    assert_eq!(limits.stream_buffer, 4 * 1024 * 1024);
    assert_eq!(limits.session_buffer, 32 * 1024 * 1024);
    assert_eq!(limits.stream_queue, 64);
    assert_eq!(limits.control_queue, 64);
    assert_eq!(limits.data_queue, 256);
    assert_eq!(limits.max_streams, 1024);
    let limits = limits
        .stream_buffer(1)
        .session_buffer(2)
        .stream_queue(3)
        .control_queue(4)
        .data_queue(5)
        .max_streams(6);
    assert_eq!(
        limits,
        WssServerLimits {
            stream_buffer: 1,
            session_buffer: 2,
            stream_queue: 3,
            control_queue: 4,
            data_queue: 5,
            max_streams: 6,
        }
    );
}

#[test]
fn zero_queues_and_stream_maximum_are_refused() {
    for limits in [
        WssServerLimits::default().stream_queue(0),
        WssServerLimits::default().control_queue(0),
        WssServerLimits::default().data_queue(0),
        WssServerLimits::default().max_streams(0),
    ] {
        let err = WssStreamServer::new(config(), limits, Allow::with(&[])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
    let err = WssStreamServer::new(
        WssConfig::new("ws://relay.test/", WssTls::Roots(RootCertStore::empty())),
        WssServerLimits::default(),
        Allow::with(&[]),
    )
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let server =
        WssStreamServer::new(config(), WssServerLimits::default(), Allow::with(&[])).unwrap();
    assert_eq!(*server.state().borrow(), LinkState::Disconnected);
    assert!(!server.stats().connected());
}

/// ns `payload_queue_enforces_and_releases_byte_budgets`: a frame over the stream or the
/// session budget closes its stream and charges nothing; a queued frame costs its payload
/// plus the frame overhead on both budgets until it is taken.
#[test]
fn payload_queue_enforces_and_releases_byte_budgets() {
    let limits = WssServerLimits::default().stream_buffer(FRAME_OVERHEAD + 3);
    let (session, mut queues) = new_session(limits, Allow::with(&[]));
    let _rx = register(&session, 1);
    session.deliver(1, Bytes::from_static(&[0; 4]));
    assert_eq!(next(&mut queues.control), Some(WsFrame::close(1)));
    assert!(lock(&session.table).is_empty());
    assert_eq!(session.stats.buffered(), 0);
    assert_eq!(session.stats.overflows(), 1);

    let limits = WssServerLimits::default().session_buffer(FRAME_OVERHEAD + 3);
    let (session, mut queues) = new_session(limits, Allow::with(&[]));
    let _rx = register(&session, 2);
    session.deliver(2, Bytes::from_static(&[0; 4]));
    assert_eq!(next(&mut queues.control), Some(WsFrame::close(2)));
    assert_eq!(session.stats.buffered(), 0);

    let limits = WssServerLimits::default().stream_buffer(2 * (FRAME_OVERHEAD + 4));
    let (session, mut queues) = new_session(limits, Allow::with(&[]));
    let mut rx = register(&session, 3);
    session.deliver(3, Bytes::from_static(&[0; 4]));
    session.deliver(3, Bytes::from_static(&[1; 4]));
    let stream = Arc::clone(&lock(&session.table)[&3].stream);
    assert_eq!(
        stream.charged.load(Ordering::Relaxed),
        2 * (FRAME_OVERHEAD + 4)
    );
    assert_eq!(session.stats.buffered(), 2 * (FRAME_OVERHEAD + 4));
    assert_eq!(session.stats.rx_bytes(), 8);
    drop(rx.try_recv().unwrap());
    assert_eq!(stream.charged.load(Ordering::Relaxed), FRAME_OVERHEAD + 4);
    assert_eq!(session.stats.buffered(), FRAME_OVERHEAD + 4);
    // Taking the stream's queue away releases the rest.
    drop(rx);
    assert_eq!(session.stats.buffered(), 0);
    assert_eq!(next(&mut queues.control), None);
}

/// The per-stream frame cap holds even for empty frames.
#[test]
fn stream_queue_caps_frames_including_empty_ones() {
    let limits = WssServerLimits::default().stream_queue(2);
    let (session, mut queues) = new_session(limits, Allow::with(&[]));
    let _rx = register(&session, 5);
    for _ in 0..3 {
        session.deliver(5, Bytes::new());
    }
    assert_eq!(session.stats.overflows(), 1);
    assert_eq!(next(&mut queues.control), Some(WsFrame::close(5)));
    assert_eq!(session.stats.buffered(), 2 * FRAME_OVERHEAD);
}

/// ns `saturated_stream_closes_without_blocking_another_stream`.
#[tokio::test]
async fn saturated_stream_closes_without_blocking_another_stream() {
    let limits = WssServerLimits::default().session_buffer(FRAME_OVERHEAD + 3);
    let (session, mut queues) = new_session(limits, Allow::with(&[]));
    let mut tasks = JoinSet::new();
    let _saturated = register(&session, 1);
    let mut healthy = register(&session, 2);
    session.dispatch(&data(1, &[0; 4]), &mut tasks);
    assert!(!lock(&session.table).contains_key(&1));
    assert!(lock(&session.table).contains_key(&2));
    assert_eq!(next(&mut queues.control), Some(WsFrame::close(1)));

    session.dispatch(&data(2, b"ok"), &mut tasks);
    assert_eq!(healthy.recv().await.unwrap().payload, &b"ok"[..]);
}

/// ns `open_denied_by_services_sends_close_frame`: the resolver's denial is answered with
/// CLOSE and leaves no stream; no event reports it.
#[tokio::test]
async fn open_denied_sends_close_frame() {
    let (session, mut queues, mut events) = with_events(
        WssServerLimits::default(),
        Allow::with(&[(addr("192.168.1.10:80"), addr("127.0.0.1:9"))]),
    );
    let mut tasks = JoinSet::new();
    session.dispatch(&open(42, addr("10.0.0.1:22"), Protocol::Tcp), &mut tasks);
    join(&mut tasks).await;
    assert_eq!(next(&mut queues.control), Some(WsFrame::close(42)));
    assert!(lock(&session.table).is_empty());
    assert_eq!(session.stats.streams_denied(), 1);
    assert_eq!(session.stats.streams_opened(), 0);
    assert_eq!(session.stats.streams_closed(), 0);
    assert!(events.try_recv().is_err());
}

/// ns `duplicate_open_sends_close_without_replacing_stream`.
#[tokio::test]
async fn duplicate_open_sends_close_without_replacing_stream() {
    let (session, mut queues) = new_session(WssServerLimits::default(), Allow::with(&[]));
    let mut tasks = JoinSet::new();
    let mut original = register(&session, 9);
    session.dispatch(&open(9, addr("192.168.1.10:80"), Protocol::Tcp), &mut tasks);
    assert!(tasks.is_empty());
    assert_eq!(next(&mut queues.control), Some(WsFrame::close(9)));
    assert_eq!(session.stats.streams_refused(), 1);

    session.dispatch(&data(9, b"still-original"), &mut tasks);
    assert_eq!(
        original.recv().await.unwrap().payload,
        &b"still-original"[..]
    );
}

/// ns `stream_limit_sends_close_without_registering_stream`.
#[tokio::test]
async fn stream_limit_sends_close_without_registering_stream() {
    let limits = WssServerLimits::default().max_streams(3);
    let (session, mut queues) = new_session(limits, Allow::with(&[]));
    let mut tasks = JoinSet::new();
    let _rx: Vec<_> = (0..3).map(|id| register(&session, id)).collect();
    session.dispatch(
        &open(50_000, addr("192.168.1.10:80"), Protocol::Tcp),
        &mut tasks,
    );
    assert_eq!(next(&mut queues.control), Some(WsFrame::close(50_000)));
    assert!(!lock(&session.table).contains_key(&50_000));
    assert_eq!(lock(&session.table).len(), 3);
    assert_eq!(session.stats.streams_refused(), 1);
}

/// ns `open_allowed_by_services_does_not_send_close` and
/// `later_open_reads_the_latest_shared_services_snapshot`: an allowed OPEN sends no CLOSE
/// on its own, and each OPEN asks the resolver as it is then.
#[tokio::test]
async fn allowed_open_relays_and_later_opens_see_the_latest_policy() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let allow = Allow::with(&[]);
    let (session, mut queues, mut events) =
        with_events(WssServerLimits::default(), Arc::clone(&allow));
    let mut tasks = JoinSet::new();
    let target = addr("192.168.1.10:22");
    session.dispatch(&open(98, target, Protocol::Tcp), &mut tasks);
    join(&mut tasks).await;
    assert_eq!(next(&mut queues.control), Some(WsFrame::close(98)));

    lock(&allow.0).insert(target, backend.local_addr().unwrap());
    session.dispatch(&open(99, target, Protocol::Tcp), &mut tasks);
    assert!(lock(&session.table).contains_key(&99));
    let opened = event(&mut events).await;
    assert_eq!(
        opened,
        WssStreamEvent {
            session: 1,
            stream_id: 99,
            protocol: Protocol::Tcp,
            target,
            backend: backend.local_addr().unwrap(),
            kind: WssStreamEventKind::Open,
        }
    );
    let _accepted = timeout(WAIT, backend.accept()).await.unwrap().unwrap();
    assert_eq!(next(&mut queues.control), None);
    assert_eq!(session.stats.streams_opened(), 1);
}

/// Every CLOSE is acknowledged, known or not; a `CLOSE_ACK` or DATA for an unknown id
/// changes nothing (ns logging test: DATA for an unknown stream registers nothing).
#[test]
fn unknown_ids_and_invalid_frames() {
    let (session, mut queues) = new_session(WssServerLimits::default(), Allow::with(&[]));
    let mut tasks = JoinSet::new();
    session.dispatch(&WsFrame::close(77).encode(), &mut tasks);
    assert_eq!(next(&mut queues.control), Some(WsFrame::close_ack(77)));
    session.dispatch(&WsFrame::close_ack(77).encode(), &mut tasks);
    session.dispatch(&data(99, &[1]), &mut tasks);
    assert_eq!(session.stats.ignored(), 1);
    assert!(lock(&session.table).is_empty());
    assert!(tasks.is_empty());
    assert_eq!(next(&mut queues.control), None);

    session.dispatch(&Bytes::from_static(&[0, 0, 0]), &mut tasks);
    session.dispatch(&Bytes::from_static(&[0, 0, 0, 1, 0x7F]), &mut tasks);
    assert_eq!(session.stats.invalid(), 2);
}

/// The peer's CLOSE is acknowledged at once; the data before it still reaches the
/// backend, whose input then ends.
#[tokio::test]
async fn peer_close_writes_the_queued_data_then_ends_the_backend_input() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = addr("10.0.0.2:80");
    let (session, mut queues, mut events) = with_events(
        WssServerLimits::default(),
        Allow::with(&[(target, backend.local_addr().unwrap())]),
    );
    let mut tasks = JoinSet::new();
    session.dispatch(&open(1, target, Protocol::Tcp), &mut tasks);
    session.dispatch(&data(1, b"hello "), &mut tasks);
    session.dispatch(&data(1, b"world"), &mut tasks);
    session.dispatch(&WsFrame::close(1).encode(), &mut tasks);
    assert_eq!(next(&mut queues.control), Some(WsFrame::close_ack(1)));
    assert!(lock(&session.table).is_empty());

    let (mut tcp, _) = timeout(WAIT, backend.accept()).await.unwrap().unwrap();
    let mut received = Vec::new();
    timeout(WAIT, tcp.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, b"hello world");
    join(&mut tasks).await;
    assert_eq!(event(&mut events).await.kind, WssStreamEventKind::Open);
    assert_eq!(
        event(&mut events).await.kind,
        WssStreamEventKind::Close {
            reason: WssCloseReason::PeerClosed,
            to_backend: 11,
            from_backend: 0,
        }
    );
    assert_eq!(session.stats.buffered(), 0);
    assert_eq!(session.stats.streams_closed(), 1);
    assert_eq!(next(&mut queues.control), None);
}

/// The backend's bytes go out as DATA; its EOF as CLOSE behind them, on the data queue.
#[tokio::test]
async fn backend_eof_sends_close_behind_its_data() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = addr("10.0.0.2:80");
    let (session, mut queues, mut events) = with_events(
        WssServerLimits::default(),
        Allow::with(&[(target, backend.local_addr().unwrap())]),
    );
    let mut tasks = JoinSet::new();
    session.dispatch(&open(4, target, Protocol::Tcp), &mut tasks);
    let (mut tcp, _) = timeout(WAIT, backend.accept()).await.unwrap().unwrap();
    tcp.write_all(b"bye").await.unwrap();
    drop(tcp);
    assert_eq!(
        next_within(&mut queues.data).await,
        WsFrame::data(4, Bytes::from_static(b"bye"))
    );
    assert_eq!(next_within(&mut queues.data).await, WsFrame::close(4));
    join(&mut tasks).await;
    assert!(lock(&session.table).is_empty());
    assert_eq!(next(&mut queues.control), None);
    assert_eq!(event(&mut events).await.kind, WssStreamEventKind::Open);
    assert_eq!(
        event(&mut events).await.kind,
        WssStreamEventKind::Close {
            reason: WssCloseReason::BackendClosed,
            to_backend: 0,
            from_backend: 3,
        }
    );
    assert_eq!(session.stats.tx_bytes(), 3);
}

/// A backend that refuses the connection: CLOSE at once on the control queue.
#[tokio::test]
async fn connect_failure_sends_close() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let refused = closed.local_addr().unwrap();
    drop(closed);
    let target = addr("10.0.0.2:81");
    let (session, mut queues, mut events) = with_events(
        WssServerLimits::default(),
        Allow::with(&[(target, refused)]),
    );
    let mut tasks = JoinSet::new();
    session.dispatch(&open(6, target, Protocol::Tcp), &mut tasks);
    join(&mut tasks).await;
    assert_eq!(next(&mut queues.control), Some(WsFrame::close(6)));
    assert!(lock(&session.table).is_empty());
    assert_eq!(event(&mut events).await.kind, WssStreamEventKind::Open);
    assert!(matches!(
        event(&mut events).await.kind,
        WssStreamEventKind::Close {
            reason: WssCloseReason::ConnectFailed,
            ..
        }
    ));
}

/// The peer's `CLOSE_ACK` of a live stream ends its relay without another CLOSE.
#[tokio::test]
async fn close_ack_ends_the_relay() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = addr("10.0.0.2:80");
    let (session, mut queues, mut events) = with_events(
        WssServerLimits::default(),
        Allow::with(&[(target, backend.local_addr().unwrap())]),
    );
    let mut tasks = JoinSet::new();
    session.dispatch(&open(3, target, Protocol::Tcp), &mut tasks);
    let _accepted = timeout(WAIT, backend.accept()).await.unwrap().unwrap();
    session.dispatch(&WsFrame::close_ack(3).encode(), &mut tasks);
    join(&mut tasks).await;
    assert_eq!(event(&mut events).await.kind, WssStreamEventKind::Open);
    assert!(matches!(
        event(&mut events).await.kind,
        WssStreamEventKind::Close {
            reason: WssCloseReason::PeerClosed,
            ..
        }
    ));
    assert_eq!(next(&mut queues.control), None);
    assert_eq!(next(&mut queues.data), None);
}

/// A UDP flow carries one datagram per DATA frame, both ways.
#[tokio::test]
async fn udp_relays_one_datagram_per_frame() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = addr("10.0.0.2:53");
    let (session, mut queues) = new_session(
        WssServerLimits::default(),
        Allow::with(&[(target, backend.local_addr().unwrap())]),
    );
    let mut tasks = JoinSet::new();
    session.dispatch(&open(8, target, Protocol::Udp), &mut tasks);
    session.dispatch(&data(8, b"query"), &mut tasks);
    session.dispatch(&data(8, b"two"), &mut tasks);
    let mut buf = [0; 64];
    let (n, from) = timeout(WAIT, backend.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"query");
    let (n, _) = timeout(WAIT, backend.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"two");
    backend.send_to(b"answer", from).await.unwrap();
    backend.send_to(b"more", from).await.unwrap();
    assert_eq!(
        next_within(&mut queues.data).await,
        WsFrame::data(8, Bytes::from_static(b"answer"))
    );
    assert_eq!(
        next_within(&mut queues.data).await,
        WsFrame::data(8, Bytes::from_static(b"more"))
    );
}

/// A full event channel drops the event and counts it; the stream is unaffected.
#[tokio::test]
async fn full_event_channel_drops_and_counts() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = addr("10.0.0.2:80");
    let (events, mut events_rx) = mpsc::channel(1);
    let (session, mut queues) = Session::new(
        1,
        WssServerLimits::default(),
        Arc::new(WssServerStats::default()),
        Allow::with(&[(target, backend.local_addr().unwrap())]),
        Some(events),
    );
    let mut tasks = JoinSet::new();
    session.dispatch(&open(1, target, Protocol::Tcp), &mut tasks);
    session.dispatch(&WsFrame::close(1).encode(), &mut tasks);
    join(&mut tasks).await;
    assert_eq!(session.stats.event_drops(), 1);
    assert_eq!(event(&mut events_rx).await.kind, WssStreamEventKind::Open);
    assert_eq!(next(&mut queues.control), Some(WsFrame::close_ack(1)));
}

// ── Lifecycle: the session task on a plain WebSocket ───────────────────────

/// Our session's socket (the dialing side) and the peer's.
async fn ws_pair() -> (WebSocketStream<TcpStream>, WebSocketStream<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tokio_tungstenite::accept_async(tcp).await.unwrap()
    });
    let tcp = TcpStream::connect(url.trim_start_matches("ws://").trim_end_matches('/'))
        .await
        .unwrap();
    let (ours, _) = tokio_tungstenite::client_async(url, tcp).await.unwrap();
    (ours, peer.await.unwrap())
}

/// Runs `session` on `ws` until `shutdown`; the task yields whether it was shut down.
fn spawn_session(
    session: Arc<Session>,
    queues: Queues,
    ws: WebSocketStream<TcpStream>,
    config: WssConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move {
        let mut shutdown = pin!(shutdown);
        session.run(ws, queues, &config, &mut shutdown).await
    })
}

/// ns `session_peer_close_runs_cleanup`.
#[tokio::test]
async fn peer_close_ends_the_session() {
    let (ours, mut peer) = ws_pair().await;
    let (session, queues) = new_session(WssServerLimits::default(), Allow::with(&[]));
    let run = spawn_session(session, queues, ours, config(), std::future::pending());
    peer.send(Message::Close(None)).await.unwrap();
    assert!(!timeout(WAIT, run).await.unwrap().unwrap());
}

/// ns `session_eof_runs_cleanup`.
#[tokio::test]
async fn eof_ends_the_session() {
    let (ours, mut peer) = ws_pair().await;
    let (session, queues) = new_session(WssServerLimits::default(), Allow::with(&[]));
    let run = spawn_session(session, queues, ours, config(), std::future::pending());
    peer.get_mut().shutdown().await.unwrap();
    assert!(!timeout(WAIT, run).await.unwrap().unwrap());
}

/// ns `session_silent_half_open_triggers_idle_timeout`: a peer that never answers ends
/// the session after the read idle.
#[tokio::test]
async fn silent_peer_ends_the_session_after_the_read_idle() {
    let (ours, _peer) = ws_pair().await;
    let (session, queues) = new_session(WssServerLimits::default(), Allow::with(&[]));
    let config = config().keepalive(
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(300),
    );
    let started = Instant::now();
    let run = spawn_session(session, queues, ours, config, std::future::pending());
    assert!(!timeout(WAIT, run).await.unwrap().unwrap());
    assert!(started.elapsed() >= std::time::Duration::from_millis(300));
}

/// With pings off the session sends no ping over many would-be intervals, and a silent
/// peer still ends it after the read idle.
#[tokio::test]
async fn pings_off_sends_no_ping_and_keeps_the_read_idle() {
    let (ours, mut peer) = ws_pair().await;
    let (session, queues) = new_session(WssServerLimits::default(), Allow::with(&[]));
    // Six would-be 50 ms intervals before the read idle.
    let config = config()
        .keepalive(
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(300),
        )
        .ping_interval(None);
    let started = Instant::now();
    let run = spawn_session(session, queues, ours, config, std::future::pending());
    // The peer reads (without writing) until the session closes the socket.
    let mut received = Vec::new();
    while let Some(Ok(message)) = timeout(WAIT, peer.next()).await.unwrap() {
        received.push(message);
    }
    assert!(!timeout(WAIT, run).await.unwrap().unwrap());
    assert!(started.elapsed() >= std::time::Duration::from_millis(300));
    assert!(
        !received.iter().any(|m| matches!(m, Message::Ping(_))),
        "{received:?}"
    );
}

/// ns `session_stays_up_while_peer_pongs`.
#[tokio::test]
async fn session_stays_up_while_the_peer_pongs() {
    let (ours, mut peer) = ws_pair().await;
    let (session, queues) = new_session(WssServerLimits::default(), Allow::with(&[]));
    let config = config().keepalive(
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(300),
    );
    let run = spawn_session(session, queues, ours, config, std::future::pending());
    let pump = tokio::spawn(async move { while let Some(Ok(_)) = peer.next().await {} });
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert!(
        !run.is_finished(),
        "a live peer must not trip the read idle"
    );
    run.abort();
    pump.abort();
}

/// ns `session_shutdown_clears_registry_and_drains_idle_relay` and its UDP twin: a
/// shutdown ends the relays (each reported closed), empties the table and closes the
/// socket.
#[tokio::test]
async fn shutdown_closes_every_stream_and_the_session() {
    let tcp_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp_backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (tcp_target, udp_target) = (addr("10.0.0.2:80"), addr("10.0.0.2:53"));
    let (ours, mut peer) = ws_pair().await;
    let (session, queues, mut events) = with_events(
        WssServerLimits::default(),
        Allow::with(&[
            (tcp_target, tcp_backend.local_addr().unwrap()),
            (udp_target, udp_backend.local_addr().unwrap()),
        ]),
    );
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = spawn_session(Arc::clone(&session), queues, ours, config(), async move {
        let _ = stopped.await;
    });
    peer.send(Message::Binary(open(7, tcp_target, Protocol::Tcp)))
        .await
        .unwrap();
    peer.send(Message::Binary(open(8, udp_target, Protocol::Udp)))
        .await
        .unwrap();
    peer.send(Message::Binary(data(7, b"pending")))
        .await
        .unwrap();
    for _ in 0..2 {
        assert_eq!(event(&mut events).await.kind, WssStreamEventKind::Open);
    }
    let _accepted = timeout(WAIT, tcp_backend.accept()).await.unwrap().unwrap();

    stop.send(()).unwrap();
    assert!(timeout(WAIT, run).await.unwrap().unwrap());
    let mut closed = Vec::new();
    for _ in 0..2 {
        let closing = event(&mut events).await;
        assert!(matches!(
            closing.kind,
            WssStreamEventKind::Close {
                reason: WssCloseReason::SessionEnded,
                ..
            }
        ));
        closed.push(closing.stream_id);
    }
    closed.sort_unstable();
    assert_eq!(closed, [7, 8]);
    assert!(lock(&session.table).is_empty());
    assert_eq!(session.stats.buffered(), 0);
    assert_eq!(session.stats.streams_closed(), 2);
    // The peer sees the close.
    let ended = timeout(WAIT, async {
        while let Some(Ok(message)) = peer.next().await {
            if message.is_close() {
                return true;
            }
        }
        true
    })
    .await
    .unwrap();
    assert!(ended);
}

/// ns logging test: a shutdown that is already done ends the run at once.
#[tokio::test]
async fn completed_shutdown_ends_the_run_at_once() {
    let (ours, _peer) = ws_pair().await;
    let (session, queues) = new_session(WssServerLimits::default(), Allow::with(&[]));
    let run = spawn_session(session, queues, ours, config(), std::future::ready(()));
    assert!(timeout(WAIT, run).await.unwrap().unwrap());
}
