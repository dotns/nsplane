//! Netstack options ns account mode asks for: accept backpressure (SYNs wait while the
//! accept queue is full instead of connections being closed), `connect_tcp_from` with a
//! caller-chosen local port, and a random start of the ephemeral port range per stack.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_core::Stream;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, ChannelTransport, Ecn, Engine, EngineBuilder, Path, Peer, TransportId};
use nsplane_e2e::TestResult;
use nsplane_netstack::{NetStack, NetStackConfig, NetStackHandle, TcpConnection};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

/// How long a connection may take, SYN retransmissions included.
const CONNECT: Duration = Duration::from_secs(15);

/// One engine with a netstack at `10.0.0.<seed>`.
struct Side {
    engine: Engine,
    stack: NetStackHandle,
    ip: Ipv4Addr,
    public: PublicKey,
    path: Path,
}

fn side(
    seed: u8,
    transport: ChannelTransport,
    path: Path,
    configure: impl FnOnce(&mut NetStackConfig),
) -> TestResult<Side> {
    let ip = Ipv4Addr::new(10, 0, 0, seed);
    let mut config = NetStackConfig::new(vec![(IpAddr::V4(ip), 32)], 1420);
    configure(&mut config);
    let (stack, handle) = NetStack::new(config);
    let (source, sink) = stack.split();
    let secret = StaticSecret::from([seed; 32]);
    let public = PublicKey::from(&secret);
    let engine = EngineBuilder::new(source, sink)
        .private_key(secret)
        .transport(transport)
        .build()?;
    Ok(Side {
        engine,
        stack: handle,
        ip,
        public,
        path,
    })
}

/// A client (seed 1) and a server (seed 2) whose stack is set up by `server`, peers of each
/// other.
async fn pair(server: impl FnOnce(&mut NetStackConfig)) -> TestResult<(Side, Side)> {
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, a, b);
    let at = |(transport, addr): (TransportId, SocketAddr)| Path {
        transport,
        addr,
        ecn: Ecn::NotEct,
    };
    let client = side(1, link_a, at(a), |_| {})?;
    let server = side(2, link_b, at(b), server)?;
    for (from, to) in [(&client, &server), (&server, &client)] {
        let peer = Peer {
            allowed_ips: vec![AllowedIp {
                addr: IpAddr::V4(to.ip),
                cidr: 32,
            }],
            path: Some(Path {
                transport: from.path.transport,
                ..to.path
            }),
            ..Peer::new(to.public)
        };
        from.engine.handle().add_or_update_peer(peer).await?;
    }
    Ok((client, server))
}

/// The next item of `stream`.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_next(cx)).await
}

/// Writes `byte` on `conn` and reads it back from `peer`.
async fn passes(conn: &mut TcpConnection, peer: &mut TcpConnection, byte: u8) -> TestResult {
    conn.write_all(&[byte]).await?;
    let mut buf = [0; 1];
    timeout(CONNECT, peer.read_exact(&mut buf)).await??;
    assert_eq!(buf, [byte]);
    Ok(())
}

#[tokio::test]
async fn with_accept_backpressure_connections_wait_for_the_application() -> TestResult {
    let (client, server) = pair(|config| {
        config.accept_capacity = 1;
        config.accept_backpressure = true;
    })
    .await?;
    let target = SocketAddr::new(IpAddr::V4(server.ip), 7);
    // Three connections at once while the server accepts none: one fills the queue, the
    // others complete their handshakes and wait in the stack. A fourth one later finds the
    // queue full: its SYN goes unanswered until the application makes room.
    let connect = |stack: NetStackHandle| {
        tokio::spawn(async move { timeout(CONNECT, stack.connect_tcp(target)).await })
    };
    let mut connects: Vec<_> = (0..3).map(|_| connect(client.stack.clone())).collect();
    sleep(Duration::from_millis(300)).await;
    connects.push(connect(client.stack.clone()));
    let deadline = tokio::time::Instant::now() + CONNECT;
    while server.stack.stats().syn_deferred == 0 {
        if tokio::time::Instant::now() > deadline {
            return Err(format!("no SYN deferred: {:?}", server.stack.stats()).into());
        }
        sleep(Duration::from_millis(10)).await;
    }

    let mut incoming = server.stack.incoming_tcp();
    let mut accepted = Vec::new();
    for _ in 0..4 {
        accepted.push(
            timeout(CONNECT, next(&mut incoming))
                .await?
                .ok_or("incoming ended")?,
        );
    }
    let mut opened = Vec::new();
    for connect in connects {
        opened.push(connect.await???);
    }
    for (i, conn) in opened.iter_mut().enumerate() {
        let local = conn.local_addr();
        let peer = accepted
            .iter_mut()
            .find(|a| a.peer_addr() == local)
            .ok_or("no accepted end")?;
        passes(conn, peer, u8::try_from(i)?).await?;
    }
    let stats = server.stack.stats();
    assert_eq!(stats.tcp_not_accepted, 0, "{stats:?}");
    Ok(())
}

#[tokio::test]
async fn without_accept_backpressure_a_full_queue_closes_connections() -> TestResult {
    let (client, server) = pair(|config| config.accept_capacity = 1).await?;
    let target = SocketAddr::new(IpAddr::V4(server.ip), 7);
    // Kept open: the server closes the two it cannot queue.
    let mut opened = Vec::new();
    for _ in 0..3 {
        opened.push(timeout(CONNECT, client.stack.connect_tcp(target)).await??);
    }
    let deadline = tokio::time::Instant::now() + CONNECT;
    while server.stack.stats().tcp_not_accepted < 2 {
        if tokio::time::Instant::now() > deadline {
            return Err(format!("{:?}", server.stack.stats()).into());
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.stack.stats().syn_deferred, 0);
    assert_eq!(opened.len(), 3);
    Ok(())
}

#[tokio::test]
async fn connect_tcp_from_uses_the_given_local_port() -> TestResult {
    let (client, server) = pair(|_| {}).await?;
    let target = SocketAddr::new(IpAddr::V4(server.ip), 7);
    let mut incoming = server.stack.incoming_tcp();
    let mut conn = timeout(CONNECT, client.stack.connect_tcp_from(40_000, target)).await??;
    assert_eq!(
        conn.local_addr(),
        SocketAddr::new(IpAddr::V4(client.ip), 40_000)
    );
    let mut peer = timeout(CONNECT, next(&mut incoming))
        .await?
        .ok_or("incoming ended")?;
    assert_eq!(peer.peer_addr().port(), 40_000);
    passes(&mut conn, &mut peer, 1).await?;

    let again = client.stack.connect_tcp_from(40_000, target).await;
    assert_eq!(
        again.err().map(|e| e.kind()),
        Some(io::ErrorKind::AddrInUse)
    );
    Ok(())
}

#[tokio::test]
async fn ephemeral_ports_start_at_a_random_point_per_stack() -> TestResult {
    let mut first = Vec::new();
    for _ in 0..4 {
        let (client, server) = pair(|_| {}).await?;
        let target = SocketAddr::new(IpAddr::V4(server.ip), 7);
        let conn = timeout(CONNECT, client.stack.connect_tcp(target)).await??;
        let port = conn.local_addr().port();
        assert!(port >= 49_152, "{port}");
        first.push(port);
    }
    // Four stacks starting at the same port: about one chance in 2^42 if random.
    assert!(first.windows(2).any(|w| w[0] != w[1]), "{first:?}");
    Ok(())
}
