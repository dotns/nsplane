use super::*;
use crate::WssTls;
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const TARGET: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 7);

fn config() -> WssConfig {
    WssConfig::new("wss://relay.test/", WssTls::Roots(RootCertStore::empty()))
}

/// A session without a socket: the test plays its task, reading the queues.
fn session(limits: WssStreamLimits) -> (Arc<Session>, Queues) {
    let connector = Arc::new(Connector::new(config()).unwrap());
    let stats = Arc::new(WssStreamStats::default());
    stats.active_sessions.fetch_add(1, Ordering::Relaxed);
    Session::new(1, limits, stats, connector)
}

fn handle(session: &Arc<Session>, protocol: Protocol) -> Handle {
    Handle {
        session: Arc::clone(session),
        flow: session.reserve(protocol).unwrap(),
        target: TARGET,
    }
}

fn tcp(session: &Arc<Session>) -> WssTcpStream {
    WssTcpStream {
        handle: handle(session, Protocol::Tcp),
        reserve: None,
    }
}

fn udp(session: &Arc<Session>) -> WssUdpFlow {
    WssUdpFlow {
        handle: handle(session, Protocol::Udp),
    }
}

fn data(id: u32, payload: &[u8]) -> Bytes {
    frame::encode_data(id, payload)
}

/// The next frame on a queue, decoded.
fn next(queue: &mut mpsc::Receiver<Message>) -> Option<WsFrame> {
    match queue.try_recv().ok()? {
        Message::Binary(bytes) => Some(WsFrame::decode(&bytes).unwrap()),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn ids_start_at_one_never_zero_and_skip_live_ids() {
    let mut table = Table::new();
    let ids: Vec<u32> = (0..3)
        .map(|_| table.insert(Protocol::Tcp, 10).unwrap().id)
        .collect();
    assert_eq!(ids, [1, 2, 3]);
    table.flows.remove(&2);
    table.next_id = u32::MAX;
    // u32::MAX, then past 0 and the live 1 to the free 2, then past the live 3.
    let ids: Vec<u32> = (0..3)
        .map(|_| table.insert(Protocol::Udp, 10).unwrap().id)
        .collect();
    assert_eq!(ids, [u32::MAX, 2, 4]);

    // At the limit, and once closed, no more flows.
    assert_eq!(table.flows.len(), 5);
    assert!(table.insert(Protocol::Tcp, 5).is_none());
    assert!(table.insert(Protocol::Tcp, 6).is_some());
    table.closed = true;
    assert!(table.insert(Protocol::Tcp, 100).is_none());
}

#[test]
fn limits_defaults_and_setters() {
    let limits = WssStreamLimits::default();
    assert_eq!(limits.stream_buffer, 4 * 1024 * 1024);
    assert_eq!(limits.session_buffer, 32 * 1024 * 1024);
    assert_eq!(limits.control_queue, 64);
    assert_eq!(limits.data_queue, 256);
    assert_eq!(limits.max_streams_per_session, 1024);
    assert_eq!(limits.open_timeout, None);
    assert!(format!("{limits:?}").contains("open_timeout: None"));
    let limits = limits
        .stream_buffer(1)
        .session_buffer(2)
        .control_queue(3)
        .data_queue(4)
        .max_streams_per_session(5)
        .open_timeout(Duration::from_millis(6));
    assert_eq!(
        (
            limits.stream_buffer,
            limits.session_buffer,
            limits.control_queue,
            limits.data_queue,
            limits.max_streams_per_session
        ),
        (1, 2, 3, 4, 5)
    );
    assert_eq!(limits.open_timeout, Some(Duration::from_millis(6)));
    assert!(format!("{limits:?}").contains("open_timeout: Some(6ms)"));
    assert_eq!(MAX_DATA_PAYLOAD + HEADER_LEN, 65_536);
}

#[test]
fn zero_queues_and_stream_maximum_are_refused() {
    for limits in [
        WssStreamLimits::default().control_queue(0),
        WssStreamLimits::default().data_queue(0),
        WssStreamLimits::default().max_streams_per_session(0),
    ] {
        let err = WssStreamClient::new(config(), limits).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
    let err = WssStreamClient::new(
        WssConfig::new("ws://relay.test/", WssTls::Roots(RootCertStore::empty())),
        WssStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn received_data_reads_in_order_and_releases_the_budgets() {
    let (session, _queues) = session(WssStreamLimits::default());
    let mut stream = tcp(&session);
    let id = stream.stream_id();
    session.dispatch(&data(id, b"hello "));
    session.dispatch(&data(id, b""));
    session.dispatch(&data(id, b"world"));
    assert_eq!(
        session.buffered.load(Ordering::Relaxed),
        11 + 2 * FRAME_OVERHEAD
    );

    let mut buf = [0; 8];
    assert_eq!(stream.read(&mut buf).await.unwrap(), 6);
    assert_eq!(&buf[..6], b"hello ");
    let mut buf = [0; 3];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"wor");
    assert_eq!(session.buffered.load(Ordering::Relaxed), 2 + FRAME_OVERHEAD);
    stream.read_exact(&mut buf[..2]).await.unwrap();
    assert_eq!(session.buffered.load(Ordering::Relaxed), 0);
    assert_eq!(lock(&stream.handle.flow.state).charged, 0);
    assert_eq!(session.stats.rx_bytes(), 11);
}

/// A stream over its buffer is reset alone, as the ns terminate closes only the affected
/// stream: CLOSE goes out on the control queue, its queued bytes still read, then the
/// reset; the other stream keeps receiving.
#[tokio::test]
async fn stream_overflow_resets_only_that_stream() {
    let limits = WssStreamLimits::default().stream_buffer(2 * (FRAME_OVERHEAD + 10));
    let (session, mut queues) = session(limits);
    let mut full = tcp(&session);
    let mut other = tcp(&session);
    for _ in 0..3 {
        session.dispatch(&data(full.stream_id(), &[1; 10]));
    }
    session.dispatch(&data(other.stream_id(), b"ok"));
    assert_eq!(session.stats.overflows(), 1);
    assert_eq!(
        next(&mut queues.control),
        Some(WsFrame::close(full.stream_id()))
    );
    // Further data for the reset stream is ignored.
    session.dispatch(&data(full.stream_id(), b"late"));
    assert_eq!(session.stats.ignored(), 1);

    let mut read = [0; 20];
    full.read_exact(&mut read).await.unwrap();
    assert_eq!(read, [1; 20]);
    let err = full.read(&mut read).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    let err = full.write_all(b"x").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);

    let mut buf = [0; 2];
    other.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");
    // The reset stream keeps its id until the peer acknowledges.
    assert!(lock(&session.table).flows.contains_key(&full.stream_id()));
    session.dispatch(&WsFrame::close_ack(full.stream_id()).encode());
    assert!(!lock(&session.table).flows.contains_key(&full.stream_id()));
    // Its drop sends no second CLOSE.
    drop(full);
    assert_eq!(next(&mut queues.control), None);
    assert_eq!(next(&mut queues.data), None);
}

#[tokio::test]
async fn session_budget_bounds_all_streams() {
    let limits = WssStreamLimits::default().session_buffer(FRAME_OVERHEAD + 100);
    let (session, mut queues) = session(limits);
    let mut first = tcp(&session);
    let second = tcp(&session);
    session.dispatch(&data(first.stream_id(), &[0; 100]));
    session.dispatch(&data(second.stream_id(), &[0; 1]));
    assert_eq!(session.stats.overflows(), 1);
    assert_eq!(
        next(&mut queues.control),
        Some(WsFrame::close(second.stream_id()))
    );
    // Reading the first stream frees the budget for the others.
    let mut buf = [0; 100];
    first.read_exact(&mut buf).await.unwrap();
    let third = tcp(&session);
    session.dispatch(&data(third.stream_id(), &[0; 100]));
    assert_eq!(session.stats.overflows(), 1);
}

/// A full UDP flow drops the datagram and stays open; empty datagrams are datagrams.
#[tokio::test]
async fn udp_overflow_drops_the_datagram() {
    let limits = WssStreamLimits::default().stream_buffer(2 * FRAME_OVERHEAD + 3);
    let (session, mut queues) = session(limits);
    let mut flow = udp(&session);
    let id = flow.stream_id();
    session.dispatch(&data(id, b"abc"));
    session.dispatch(&data(id, b""));
    session.dispatch(&data(id, b"x"));
    assert_eq!(session.stats.overflows(), 1);
    assert_eq!(next(&mut queues.control), None);
    assert_eq!(flow.recv().await.unwrap().unwrap(), &b"abc"[..]);
    assert_eq!(flow.recv().await.unwrap().unwrap(), &b""[..]);
    session.dispatch(&data(id, b"x"));
    assert_eq!(flow.recv().await.unwrap().unwrap(), &b"x"[..]);

    flow.send(b"out").await.unwrap();
    assert_eq!(
        next(&mut queues.data),
        Some(WsFrame::data(id, Bytes::from_static(b"out")))
    );
    let err = flow.send(&vec![0; MAX_DATAGRAM + 1]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    // The peer's CLOSE ends the flow.
    session.dispatch(&WsFrame::close(id).encode());
    assert_eq!(flow.recv().await.unwrap(), None);
    assert_eq!(next(&mut queues.control), Some(WsFrame::close_ack(id)));
    drop(flow);
    assert_eq!(next(&mut queues.data), None);
}

/// A peer CLOSE reads as EOF after the bytes before it, is acknowledged and frees the id;
/// writes then fail and the drop sends nothing.
#[tokio::test]
async fn peer_close_is_eof_and_acknowledged() {
    let (session, mut queues) = session(WssStreamLimits::default());
    let mut stream = tcp(&session);
    let id = stream.stream_id();
    session.dispatch(&data(id, b"last"));
    session.dispatch(&WsFrame::close(id).encode());
    assert_eq!(next(&mut queues.control), Some(WsFrame::close_ack(id)));
    assert_eq!(session.stats.streams_closed(), 1);
    assert!(lock(&session.table).flows.is_empty());

    let mut read = Vec::new();
    stream.read_to_end(&mut read).await.unwrap();
    assert_eq!(read, b"last");
    let err = stream.write_all(b"x").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    stream.shutdown().await.unwrap();
    drop(stream);
    assert_eq!(next(&mut queues.data), None);
    assert_eq!(next(&mut queues.control), None);
}

#[test]
fn unknown_and_invalid_frames_are_counted() {
    let (session, mut queues) = session(WssStreamLimits::default());
    session.dispatch(&data(77, b"x"));
    session.dispatch(&WsFrame::close_ack(77).encode());
    session.dispatch(&WsFrame::close(78).encode());
    assert_eq!(session.stats.ignored(), 3);
    // An unknown CLOSE is acknowledged all the same.
    assert_eq!(next(&mut queues.control), Some(WsFrame::close_ack(78)));

    session.dispatch(&Bytes::from_static(&[0, 0, 0]));
    session.dispatch(&Bytes::from_static(&[0, 0, 0, 1, 0x7F]));
    session.dispatch(&WsFrame::open(1, TARGET, Protocol::Tcp).encode());
    assert_eq!(session.stats.invalid(), 3);
    assert_eq!(session.stats.ignored(), 3);
}

/// A shutdown sends CLOSE behind the data written before it; the stream reads on until
/// the `CLOSE_ACK`.
#[tokio::test]
async fn shutdown_closes_behind_the_data_and_reads_until_the_ack() {
    let (session, mut queues) = session(WssStreamLimits::default());
    let mut stream = tcp(&session);
    let id = stream.stream_id();
    let big = vec![7; MAX_DATA_PAYLOAD + 10];
    stream.write_all(&big).await.unwrap();
    stream.shutdown().await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        next(&mut queues.data),
        Some(WsFrame::data(id, Bytes::from(vec![7; MAX_DATA_PAYLOAD])))
    );
    assert_eq!(
        next(&mut queues.data),
        Some(WsFrame::data(id, Bytes::from(vec![7; 10])))
    );
    assert_eq!(next(&mut queues.data), Some(WsFrame::close(id)));
    assert_eq!(next(&mut queues.data), None);
    assert_eq!(session.stats.tx_bytes(), big.len() as u64);
    let err = stream.write_all(b"x").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

    session.dispatch(&data(id, b"reply"));
    session.dispatch(&WsFrame::close_ack(id).encode());
    let mut read = Vec::new();
    stream.read_to_end(&mut read).await.unwrap();
    assert_eq!(read, b"reply");
    drop(stream);
    assert_eq!(next(&mut queues.data), None);
    assert_eq!(next(&mut queues.control), None);
}

/// A write waits for room on the data queue instead of failing.
#[tokio::test]
async fn writes_wait_for_room_on_the_data_queue() {
    let (session, mut queues) = session(WssStreamLimits::default().data_queue(1));
    let mut stream = tcp(&session);
    stream.write_all(b"a").await.unwrap();
    let writer = tokio::spawn(async move {
        stream.write_all(b"b").await.unwrap();
        stream
    });
    tokio::task::yield_now().await;
    assert!(!writer.is_finished());
    assert!(next(&mut queues.data).is_some());
    let _stream = writer.await.unwrap();
    assert!(next(&mut queues.data).is_some());
}

#[test]
fn drop_without_shutdown_sends_close() {
    let (session, mut queues) = session(WssStreamLimits::default());
    let stream = tcp(&session);
    let id = stream.stream_id();
    session.dispatch(&data(id, b"unread"));
    drop(stream);
    assert_eq!(next(&mut queues.data), Some(WsFrame::close(id)));
    assert_eq!(session.buffered.load(Ordering::Relaxed), 0);
    // Data until the acknowledgement is ignored; the id stays in use until then.
    session.dispatch(&data(id, b"late"));
    assert_eq!(session.stats.ignored(), 1);
    assert!(
        session
            .reserve(Protocol::Tcp)
            .is_some_and(|flow| flow.id != id)
    );
    session.dispatch(&WsFrame::close_ack(id).encode());
    assert!(!lock(&session.table).flows.contains_key(&id));

    // With both queues full the CLOSE is dropped and the id freed.
    let (session, _queues) = session_with_full_queues();
    let stream = tcp(&session);
    let id = stream.stream_id();
    drop(stream);
    assert!(!lock(&session.table).flows.contains_key(&id));
}

fn session_with_full_queues() -> (Arc<Session>, Queues) {
    let (session, queues) = session(WssStreamLimits::default().control_queue(1).data_queue(1));
    session
        .control
        .try_send(Message::Ping(Bytes::new()))
        .unwrap();
    session.data.try_send(Message::Ping(Bytes::new())).unwrap();
    (session, queues)
}

#[tokio::test]
async fn session_loss_fails_every_flow() {
    let (session, queues) = session(WssStreamLimits::default());
    let mut stream = tcp(&session);
    let mut flow = udp(&session);
    session.dispatch(&data(stream.stream_id(), b"before"));
    session.end();
    drop(queues);
    assert!(session.is_closed());
    assert!(session.reserve(Protocol::Tcp).is_none());
    assert_eq!(session.stats.streams_closed(), 2);
    assert!(!session.stats.connected());
    assert_eq!(*session.connector.state().borrow(), LinkState::Disconnected);

    let mut read = [0; 6];
    stream.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, b"before");
    let err = stream.read(&mut read).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    let err = stream.write_all(b"x").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(
        flow.recv().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(
        flow.send(b"x").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}
