//! The server transport's tests: sessions over in-memory streams, and the dialer's wire.

use super::*;
use crate::{WssConfig, WssDialer, WssTls};
use nsplane::LinkConfig;
use rustls::RootCertStore;
use tokio::io::DuplexStream;
use tokio::net::TcpListener;
use tokio::time::{Instant, timeout};
use tokio_tungstenite::tungstenite::protocol::Role;

const WAIT: Duration = Duration::from_secs(5);

/// The far end of a session: the client side of its WebSocket.
type Client = WebSocketStream<DuplexStream>;

fn path(addr: SocketAddr) -> Path {
    Path {
        transport: TransportId::new(7),
        addr,
        ecn: Ecn::NotEct,
    }
}

fn server(config: WssServerConfig) -> (WssServerTransport, WssAcceptor) {
    WssServerTransport::new(TransportId::new(7), config)
}

/// A WebSocket pair over an in-memory stream of `buffer` bytes each way: the server side,
/// upgraded with the acceptor's settings, and the client side.
async fn ws_pair(buffer: usize) -> (WebSocketStream<DuplexStream>, Client) {
    let (server, client) = tokio::io::duplex(buffer);
    let server =
        WebSocketStream::from_raw_socket(server, Role::Server, Some(WssAcceptor::ws_config()))
            .await;
    let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    (server, client)
}

/// An accepted session and its client.
async fn session(acceptor: &WssAcceptor) -> (WssSession, Client) {
    let (server, client) = ws_pair(1 << 20).await;
    (acceptor.accept(server).unwrap(), client)
}

/// The next datagram the transport received, with its sender.
async fn recv(transport: &WssServerTransport) -> (SocketAddr, Vec<u8>) {
    let mut buf = PacketBuf::with_capacity(MAX_DATAGRAM);
    let (len, path) = timeout(WAIT, transport.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (path.transport, path.ecn),
        (TransportId::new(7), Ecn::NotEct)
    );
    (path.addr, buf.as_packet()[..len].to_vec())
}

/// The next message the client received.
async fn next(client: &mut Client) -> Option<Message> {
    timeout(WAIT, client.next())
        .await
        .unwrap()
        .map(Result::unwrap)
}

/// Waits until `done` holds.
async fn until(done: impl Fn() -> bool + Send + Sync) {
    timeout(WAIT, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn config_defaults() {
    let config = WssServerConfig::default();
    assert_eq!(config.queue, 256);
    assert_eq!(config.inbound_queue, 1024);
    assert_eq!(config.ping_interval, Some(Duration::from_secs(10)));
    assert_eq!(config.read_idle, Duration::from_secs(35));
    assert_eq!(config.max_sessions, 4096);
    let ms = Duration::from_millis;
    let config = config
        .queue(1)
        .inbound_queue(2)
        .ping_interval(None)
        .read_idle(ms(3))
        .max_sessions(4);
    assert_eq!(
        config,
        WssServerConfig {
            queue: 1,
            inbound_queue: 2,
            ping_interval: None,
            read_idle: ms(3),
            max_sessions: 4,
        }
    );
}

#[test]
fn session_addresses_are_in_the_discard_prefix() {
    assert_eq!(session_addr(1), "[100::1]:0".parse().unwrap());
    assert_eq!(
        session_addr(u64::MAX),
        "[100::ffff:ffff:ffff:ffff]:0".parse().unwrap()
    );
}

/// A [`WssDialer`] link and the server transport carry each other's datagrams unchanged.
#[tokio::test]
async fn wire_compatible_with_the_dialer() {
    let (transport, acceptor) = server(WssServerConfig::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepting = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async_with_config(tcp, Some(WssAcceptor::ws_config()))
            .await
            .unwrap();
        acceptor.accept(ws).unwrap()
    });
    let config = WssConfig::new(
        format!("ws://{addr}/"),
        WssTls::Roots(RootCertStore::empty()),
    )
    .allow_plaintext(true);
    let peer: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let link = WssDialer::new(config).unwrap().into_transport(
        TransportId::new(2),
        peer,
        LinkConfig::default(),
    );
    let session = timeout(WAIT, accepting).await.unwrap().unwrap();

    let datagram: Vec<u8> = (0..=255).cycle().take(1400).collect();
    let to_peer = Path {
        transport: TransportId::new(2),
        addr: peer,
        ecn: Ecn::NotEct,
    };
    link.send(&datagram, &to_peer).await.unwrap();
    assert_eq!(recv(&transport).await, (session.addr(), datagram.clone()));

    let reply: Vec<u8> = datagram.iter().rev().copied().collect();
    transport.send(&reply, &path(session.addr())).await.unwrap();
    let mut buf = PacketBuf::with_capacity(MAX_DATAGRAM);
    let (len, from) = timeout(WAIT, link.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!((from.addr, &buf.as_packet()[..len]), (peer, &reply[..]));

    let stats = transport.stats();
    assert_eq!((stats.rx(), stats.rx_bytes()), (1, 1400));
    assert_eq!((stats.tx(), stats.tx_bytes()), (1, 1400));
    let session_stats = session.stats();
    assert_eq!((session_stats.rx(), session_stats.tx()), (1, 1));
}

/// Each session has its own address: datagrams come from it, and sends to it reach only
/// that session.
#[tokio::test]
async fn sessions_have_their_own_addresses() {
    let (transport, acceptor) = server(WssServerConfig::default());
    let (a, mut client_a) = session(&acceptor).await;
    let (b, mut client_b) = session(&acceptor).await;
    let prefix = |addr: SocketAddr| match addr {
        SocketAddr::V6(addr) => addr.ip().segments()[..4] == [0x100, 0, 0, 0] && addr.port() == 0,
        SocketAddr::V4(_) => false,
    };
    assert!(prefix(a.addr()) && prefix(b.addr()));
    assert_ne!(a.addr(), b.addr());

    client_a
        .send(Message::binary(&b"from a"[..]))
        .await
        .unwrap();
    assert_eq!(recv(&transport).await, (a.addr(), b"from a".to_vec()));
    client_b
        .send(Message::binary(&b"from b"[..]))
        .await
        .unwrap();
    assert_eq!(recv(&transport).await, (b.addr(), b"from b".to_vec()));

    transport.send(b"to b", &path(b.addr())).await.unwrap();
    transport.send(b"to a", &path(a.addr())).await.unwrap();
    assert_eq!(
        next(&mut client_a).await,
        Some(Message::binary(&b"to a"[..]))
    );
    assert_eq!(
        next(&mut client_b).await,
        Some(Message::binary(&b"to b"[..]))
    );
    assert_eq!((a.stats().tx(), b.stats().tx()), (1, 1));
    assert_eq!(transport.stats().active(), 2);
}

/// A close frame closes the session as a peer close; sends to its address then fail, and
/// the next session gets a new address.
#[tokio::test]
async fn sends_to_a_closed_session_fail() {
    let (transport, acceptor) = server(WssServerConfig::default());
    let stats = transport.stats();
    let (first, mut client) = session(&acceptor).await;
    client.close(None).await.unwrap();
    until(|| stats.closed_peer() == 1).await;
    assert_eq!(stats.active(), 0);

    let err = transport
        .send(b"late", &path(first.addr()))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    assert_eq!(stats.sent_to_closed(), 1);

    let (second, _client) = session(&acceptor).await;
    assert_ne!(second.addr(), first.addr());
    let err = transport
        .send(b"late", &path(first.addr()))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    assert_eq!(stats.sent_to_closed(), 2);
    assert_eq!(stats.accepted(), 2);
}

/// [`WssSession::close`] sends a close frame; dropping the handle closes nothing.
#[tokio::test]
async fn close_closes_and_drop_does_not() {
    let (transport, acceptor) = server(WssServerConfig::default());
    let stats = transport.stats();
    let (kept, mut kept_client) = session(&acceptor).await;
    let (dropped, mut dropped_client) = session(&acceptor).await;
    let dropped_addr = dropped.addr();
    drop(dropped);

    kept.close();
    assert!(matches!(
        next(&mut kept_client).await,
        Some(Message::Close(_))
    ));
    until(|| stats.closed_local() == 1).await;
    assert_eq!(stats.active(), 1);

    transport.send(b"still", &path(dropped_addr)).await.unwrap();
    assert_eq!(
        next(&mut dropped_client).await,
        Some(Message::binary(&b"still"[..]))
    );
}

/// A session whose writer is stalled fills its queue: sends to it fail at once, sends to
/// the others go on.
#[tokio::test]
async fn full_queue_fails_at_once() {
    let config = WssServerConfig::default().queue(2).ping_interval(None);
    let (transport, acceptor) = server(config);
    // The client never reads, and its stream holds less than one datagram.
    let (server_ws, _stalled_client) = ws_pair(64).await;
    let stalled = acceptor.accept(server_ws).unwrap();
    let (other, mut other_client) = session(&acceptor).await;

    let datagram = [0u8; 1000];
    let mut failed = None;
    for _ in 0..10 {
        match transport.send(&datagram, &path(stalled.addr())).await {
            Ok(()) => tokio::time::sleep(Duration::from_millis(10)).await,
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    assert_eq!(failed.unwrap().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(stalled.stats().dropped_queue_full(), 1);
    assert_eq!(transport.stats().dropped_queue_full(), 1);

    transport.send(b"other", &path(other.addr())).await.unwrap();
    assert_eq!(
        next(&mut other_client).await,
        Some(Message::binary(&b"other"[..]))
    );
    assert_eq!(other.stats().dropped_queue_full(), 0);
}

/// A silent session closes after the read idle; with pings off it gets no ping.
#[tokio::test]
async fn read_idle_closes_a_silent_session() {
    let config = WssServerConfig::default()
        .ping_interval(None)
        .read_idle(Duration::from_millis(200));
    let (transport, acceptor) = server(config);
    let stats = transport.stats();
    let started = Instant::now();
    let (_session, mut client) = session(&acceptor).await;
    let mut received = Vec::new();
    while let Some(message) = next(&mut client).await {
        let close = matches!(message, Message::Close(_));
        received.push(message);
        if close {
            break;
        }
    }
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert!(
        !received.iter().any(|m| matches!(m, Message::Ping(_))),
        "{received:?}"
    );
    until(|| stats.closed_idle() == 1).await;
    assert_eq!(stats.active(), 0);
}

/// Pings keep a session that only answers them open past the read idle.
#[tokio::test]
async fn pongs_keep_a_session_open() {
    let config = WssServerConfig::default()
        .ping_interval(Some(Duration::from_millis(50)))
        .read_idle(Duration::from_millis(200));
    let (transport, acceptor) = server(config);
    let (_session, mut client) = session(&acceptor).await;
    // Reading answers the pings.
    let mut pings = 0;
    let deadline = Instant::now() + Duration::from_millis(500);
    while let Ok(message) = tokio::time::timeout_at(deadline, client.next()).await {
        assert!(matches!(message, Some(Ok(Message::Ping(_)))), "{message:?}");
        pings += 1;
    }
    assert!(pings >= 5, "{pings}");
    let stats = transport.stats();
    assert_eq!((stats.active(), stats.closed_idle()), (1, 0));
}

/// Text messages and oversized datagrams are dropped and counted, the session kept.
#[tokio::test]
async fn text_and_oversized_messages_are_dropped() {
    let (transport, acceptor) = server(WssServerConfig::default());
    let (session, mut client) = session(&acceptor).await;
    client.send(Message::text("hello")).await.unwrap();
    client
        .send(Message::binary(vec![0u8; MAX_DATAGRAM + 1]))
        .await
        .unwrap();
    client.send(Message::binary(&b"ok"[..])).await.unwrap();
    assert_eq!(recv(&transport).await, (session.addr(), b"ok".to_vec()));

    // A datagram too long to send is dropped too; the send succeeds.
    transport
        .send(&vec![0u8; MAX_DATAGRAM + 1], &path(session.addr()))
        .await
        .unwrap();
    let stats = transport.stats();
    assert_eq!((stats.dropped_text(), stats.dropped_oversized()), (1, 2));
    let session_stats = session.stats();
    assert_eq!(
        (
            session_stats.dropped_text(),
            session_stats.dropped_oversized()
        ),
        (1, 2)
    );
    assert_eq!((stats.rx(), stats.active()), (1, 1));
}

/// Sessions beyond the limit are refused without a task; dropping the transport closes
/// the open ones and refuses later sessions.
#[tokio::test]
async fn limit_and_drop() {
    let (transport, acceptor) = server(WssServerConfig::default().max_sessions(1));
    let stats = transport.stats();
    let (_session, mut client) = session(&acceptor).await;

    let (server_ws, mut refused_client) = ws_pair(1 << 20).await;
    let err = acceptor.accept(server_ws).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(
        (stats.refused_limit(), stats.active(), stats.accepted()),
        (1, 1, 1)
    );
    // The refused WebSocket was dropped: its client sees the stream end.
    assert!(
        timeout(WAIT, refused_client.next())
            .await
            .unwrap()
            .is_none_or(|m| m.is_err())
    );

    drop(transport);
    assert!(matches!(next(&mut client).await, Some(Message::Close(_))));
    until(|| stats.closed_local() == 1).await;
    assert_eq!(stats.active(), 0);

    let (server_ws, _client) = ws_pair(1 << 20).await;
    let err = acceptor.accept(server_ws).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(stats.refused_closed(), 1);
}

/// A WebSocket that reads messages longer than [`MAX_MESSAGE`] is refused.
#[tokio::test]
async fn unbounded_websockets_are_refused() {
    let (_transport, acceptor) = server(WssServerConfig::default());
    let (server_ws, _client) = tokio::io::duplex(64);
    let ws = WebSocketStream::from_raw_socket(server_ws, Role::Server, None).await;
    let err = acceptor.accept(ws).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}
