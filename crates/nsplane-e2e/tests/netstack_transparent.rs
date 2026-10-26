//! A transparent netstack behind an engine: the client side routes every destination
//! (`0.0.0.0/0`, `::/0`) to the stack's node, whose stack is the endpoint for TCP and UDP to
//! any address in its prefixes. Accepted connections and flows keep the dialed address as
//! their local address and reply from it; under `Admission::Decide` a rejected connection
//! is reset and a rejected flow answered with a port unreachable from the dialed address.
//! Without transparent mode the same packets are dropped as `no_address`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures_core::Stream;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelTransport, Ecn, Engine, EngineBuilder, PacketBuf, Path, Peer,
    PeerId, Splitter, TransportId,
};
use nsplane_e2e::{QUIET, TestResult, WAIT, verify_checksums};
use nsplane_netstack::{
    Admission, DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, NetStackStats,
    PendingProtocol, TransparentConfig,
};
use nsplane_packet::{IpPacket, protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};

/// Capacity of the transport and the ICMP collector.
const CAPACITY: usize = 1024;
/// The client stack's addresses.
const CLIENT4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const CLIENT6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
/// The transparent stack's own addresses.
const STACK4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const STACK6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
/// Dialed destinations inside the stack's prefixes.
const TCP4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
const TCP6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)),
    443,
);
const UDP4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 53);
/// Dialed destinations the deciding application rejects.
const REJECT_TCP4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 443);
const REJECT_TCP6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x11)),
    443,
);
const REJECT_UDP4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)), 53);
const REJECT_UDP6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x12)),
    53,
);
/// A destination outside the stack's prefixes.
const OUTSIDE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 53);

/// The prefixes of the transparent stack.
fn prefixes() -> Vec<(IpAddr, u8)> {
    vec![
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24),
        (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24),
        (
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            32,
        ),
    ]
}

/// The client node: a plain stack whose engine routes everything to the server, with the
/// ICMP and `ICMPv6` packets it receives split off to `icmp` instead of its stack.
struct Client {
    _engine: Engine,
    stack: NetStackHandle,
    icmp: mpsc::Receiver<(PeerId, PacketBuf)>,
}

/// The server node: an engine whose whole local side is the stack under test.
struct Server {
    _engine: Engine,
    stack: NetStackHandle,
}

/// A client and a server whose stack runs with `transparent`, peers of each other.
async fn pair(
    transparent: Option<TransparentConfig>,
    admission: Admission,
) -> TestResult<(Client, Server)> {
    let client_path = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let server_path = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_c, link_s) = ChannelTransport::pair(CAPACITY, client_path, server_path);

    let (client_stack, client_handle) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(CLIENT4), 32), (IpAddr::V6(CLIENT6), 128)],
        DEFAULT_MTU,
    ));
    let (client_source, client_sink) = client_stack.split();
    let (collector, icmp) = ChannelSink::new(CAPACITY);
    let splitter = Splitter::new(|_peer, packet| {
        match IpPacket::parse(packet.as_packet()).map(|ip| ip.protocol()) {
            Ok(protocol::ICMP | protocol::ICMPV6) => 0,
            _ => 1,
        }
    })
    .sink(collector)
    .sink(client_sink);
    let client_secret = StaticSecret::from([1; 32]);
    let client_engine = EngineBuilder::new(client_source, splitter)
        .private_key(client_secret.clone())
        .transport(link_c)
        .build()?;

    let mut config = NetStackConfig::new(
        vec![(IpAddr::V4(STACK4), 32), (IpAddr::V6(STACK6), 128)],
        DEFAULT_MTU,
    );
    config.transparent = transparent;
    config.admission = admission;
    let (server_stack, server_handle) = NetStack::new(config);
    let (server_source, server_sink) = server_stack.split();
    let server_secret = StaticSecret::from([2; 32]);
    let server_engine = EngineBuilder::new(server_source, server_sink)
        .private_key(server_secret.clone())
        .transport(link_s)
        .build()?;

    let peer = |secret: &StaticSecret, via: TransportId, addr, allowed: &[(IpAddr, u8)]| Peer {
        allowed_ips: allowed
            .iter()
            .map(|&(addr, cidr)| AllowedIp { addr, cidr })
            .collect(),
        path: Some(Path {
            transport: via,
            addr,
            ecn: Ecn::NotEct,
        }),
        ..Peer::new(PublicKey::from(secret))
    };
    client_engine
        .handle()
        .add_or_update_peer(peer(
            &server_secret,
            client_path.0,
            server_path.1,
            &[
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            ],
        ))
        .await?;
    server_engine
        .handle()
        .add_or_update_peer(peer(
            &client_secret,
            server_path.0,
            client_path.1,
            &[(IpAddr::V4(CLIENT4), 32), (IpAddr::V6(CLIENT6), 128)],
        ))
        .await?;
    Ok((
        Client {
            _engine: client_engine,
            stack: client_handle,
            icmp,
        },
        Server {
            _engine: server_engine,
            stack: server_handle,
        },
    ))
}

/// The next item of `stream`.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_next(cx)).await
}

/// Accepts every TCP connection and UDP flow of `stack`, reports each as
/// `(protocol, peer_addr, local_addr)` and echoes its bytes or datagrams.
fn serve_echo(stack: &NetStackHandle) -> mpsc::UnboundedReceiver<(u8, SocketAddr, SocketAddr)> {
    let (report, reports) = mpsc::unbounded_channel();
    let mut tcp = stack.incoming_tcp();
    let tcp_report = report.clone();
    tokio::spawn(async move {
        while let Some(conn) = next(&mut tcp).await {
            // The test may have stopped listening; the echo still runs.
            let _ = tcp_report.send((protocol::TCP, conn.peer_addr(), conn.local_addr()));
            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(conn);
                tokio::io::copy(&mut reader, &mut writer).await?;
                writer.shutdown().await
            });
        }
    });
    let mut udp = stack.incoming_udp();
    tokio::spawn(async move {
        while let Some(mut flow) = next(&mut udp).await {
            let _ = report.send((protocol::UDP, flow.peer_addr(), flow.local_addr()));
            tokio::spawn(async move {
                let reply = flow.reply_handle();
                while let Some(datagram) = flow.recv().await {
                    reply.send(&datagram).await?;
                }
                io::Result::Ok(())
            });
        }
    });
    reports
}

/// Connects from `client` to `target` and checks the echo; returns the client's local
/// address.
async fn tcp_echo(client: &NetStackHandle, target: SocketAddr) -> TestResult<SocketAddr> {
    let mut conn = timeout(WAIT, client.connect_tcp(target)).await??;
    assert_eq!(conn.peer_addr(), target);
    let message = format!("hello {target}");
    conn.write_all(message.as_bytes()).await?;
    let mut echoed = vec![0; message.len()];
    timeout(WAIT, conn.read_exact(&mut echoed)).await??;
    assert_eq!(echoed, message.as_bytes());
    Ok(conn.local_addr())
}

/// Sends one datagram from a socket bound on `client` to `target` and checks that the echo
/// comes back from `target`; returns the client's source address.
async fn udp_echo(client: &NetStackHandle, target: SocketAddr) -> TestResult<SocketAddr> {
    let source = client_addr(target);
    let mut socket = client.bind_udp(source).await?;
    let message = format!("hello {target}");
    socket.send_to(message.as_bytes(), target).await?;
    let (echo, from) = timeout(WAIT, socket.recv_from()).await??;
    assert_eq!(from, target);
    assert_eq!(&echo[..], message.as_bytes());
    Ok(SocketAddr::new(source.ip(), socket.local_addr().port()))
}

/// The client's address of `target`'s family, port 0.
const fn client_addr(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(CLIENT4), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(CLIENT6), 0),
    }
}

/// Checks that the server reported `expected` next, as `(protocol, peer, local)`.
async fn expect_report(
    reports: &mut mpsc::UnboundedReceiver<(u8, SocketAddr, SocketAddr)>,
    expected: (u8, SocketAddr, SocketAddr),
) -> TestResult {
    let report = timeout(WAIT, reports.recv())
        .await?
        .ok_or("echo server stopped")?;
    assert_eq!(report, expected);
    Ok(())
}

/// Waits until `done` holds for `stack`'s stats and returns them.
async fn stats_until(
    stack: &NetStackHandle,
    done: impl Fn(&NetStackStats) -> bool,
) -> TestResult<NetStackStats> {
    let deadline = Instant::now() + WAIT;
    loop {
        let stats = stack.stats();
        if done(&stats) {
            return Ok(stats);
        }
        if Instant::now() > deadline {
            return Err(format!("stats did not settle: {stats:?}").into());
        }
        sleep(Duration::from_millis(10)).await;
    }
}

/// Sends a datagram from `client` to `target` and checks that the client receives an ICMP
/// (IPv4) or `ICMPv6` (IPv6) port unreachable from `target`'s address quoting it.
async fn expect_port_unreachable(client: &mut Client, target: SocketAddr) -> TestResult {
    let socket = client.stack.bind_udp(client_addr(target)).await?;
    socket.send_to(b"rejected", target).await?;
    let (_, packet) = timeout(WAIT, client.icmp.recv())
        .await?
        .ok_or("collector closed")?;
    verify_checksums(packet.as_packet())?;
    let ip = IpPacket::parse(packet.as_packet())?;
    assert_eq!(ip.src(), target.ip());
    assert_eq!(ip.dst(), client_addr(target).ip());
    let message = ip.payload();
    // Destination / port unreachable: type and code.
    let unreachable: [u8; 2] = match target {
        SocketAddr::V4(_) => [3, 3],
        SocketAddr::V6(_) => [1, 4],
    };
    assert_eq!(message.get(..2), Some(&unreachable[..]));
    let quoted = IpPacket::parse(message.get(8..).ok_or("short ICMP message")?)?;
    assert_eq!(quoted.protocol(), protocol::UDP);
    assert_eq!(quoted.dst(), target.ip());
    assert_eq!(
        quoted.payload().get(2..4),
        Some(&target.port().to_be_bytes()[..])
    );
    Ok(())
}

#[tokio::test]
async fn immediate_admission_answers_for_the_dialed_address() -> TestResult {
    let (client, server) = pair(
        Some(TransparentConfig {
            prefixes: prefixes(),
            ..Default::default()
        }),
        Admission::Immediate,
    )
    .await?;
    let mut reports = serve_echo(&server.stack);

    for target in [TCP4, TCP6] {
        let local = tcp_echo(&client.stack, target).await?;
        assert_eq!(local.ip(), client_addr(target).ip());
        expect_report(&mut reports, (protocol::TCP, local, target)).await?;
    }
    let source = udp_echo(&client.stack, UDP4).await?;
    expect_report(&mut reports, (protocol::UDP, source, UDP4)).await?;

    // Outside the prefixes: dropped, counted in both `rejected_prefix` and `no_address`.
    let socket = client.stack.bind_udp(client_addr(OUTSIDE)).await?;
    socket.send_to(b"outside", OUTSIDE).await?;
    let stats = stats_until(&server.stack, |s| s.rejected_prefix > 0).await?;
    let mut expected = NetStackStats::default();
    expected.accepted = 3;
    expected.rejected_prefix = 1;
    expected.no_address = 1;
    assert_eq!(stats, expected);
    assert!(reports.try_recv().is_err(), "nothing else was accepted");
    Ok(())
}

#[tokio::test]
async fn decide_admission_accepts_and_rejects() -> TestResult {
    let (mut client, server) = pair(
        Some(TransparentConfig {
            prefixes: prefixes(),
            ..Default::default()
        }),
        Admission::Decide {
            timeout: WAIT,
            max_pending: 16,
        },
    )
    .await?;
    let mut reports = serve_echo(&server.stack);
    let (offered_tx, mut offered) = mpsc::unbounded_channel();
    let mut pending = server.stack.incoming_pending();
    tokio::spawn(async move {
        while let Some(item) = next(&mut pending).await {
            let _ = offered_tx.send((item.protocol(), item.peer_addr(), item.local_addr()));
            if [TCP4, TCP6, UDP4].contains(&item.local_addr()) {
                item.accept();
            } else {
                item.reject();
            }
        }
    });

    for target in [TCP4, TCP6] {
        let local = tcp_echo(&client.stack, target).await?;
        let item = timeout(WAIT, offered.recv()).await?.ok_or("decider")?;
        assert_eq!(item, (PendingProtocol::Tcp, local, target));
        expect_report(&mut reports, (protocol::TCP, local, target)).await?;
    }
    let source = udp_echo(&client.stack, UDP4).await?;
    let item = timeout(WAIT, offered.recv()).await?.ok_or("decider")?;
    assert_eq!(item, (PendingProtocol::Udp, source, UDP4));
    expect_report(&mut reports, (protocol::UDP, source, UDP4)).await?;

    for target in [REJECT_TCP4, REJECT_TCP6] {
        let refused = timeout(WAIT, client.stack.connect_tcp(target)).await?;
        assert_eq!(
            refused.err().map(|e| e.kind()),
            Some(io::ErrorKind::ConnectionRefused),
            "{target}"
        );
        let item = timeout(WAIT, offered.recv()).await?.ok_or("decider")?;
        assert_eq!((item.0, item.2), (PendingProtocol::Tcp, target));
    }
    for target in [REJECT_UDP4, REJECT_UDP6] {
        expect_port_unreachable(&mut client, target).await?;
        let item = timeout(WAIT, offered.recv()).await?.ok_or("decider")?;
        assert_eq!((item.0, item.2), (PendingProtocol::Udp, target));
    }

    let stats = stats_until(&server.stack, |s| s.rejected_hook >= 4).await?;
    let mut expected = NetStackStats::default();
    expected.accepted = 3;
    expected.rejected_hook = 4;
    assert_eq!(stats, expected);
    assert!(reports.try_recv().is_err(), "no rejected flow was accepted");
    Ok(())
}

#[tokio::test]
async fn without_transparent_mode_the_packets_have_no_address() -> TestResult {
    let (client, server) = pair(None, Admission::Immediate).await?;
    let mut reports = serve_echo(&server.stack);

    let connects: Vec<_> = [TCP4, TCP6]
        .into_iter()
        .map(|target| {
            let stack = client.stack.clone();
            tokio::spawn(async move { stack.connect_tcp(target).await })
        })
        .collect();
    let socket = client.stack.bind_udp(client_addr(UDP4)).await?;
    socket.send_to(b"no address", UDP4).await?;

    // Two SYNs and a datagram at least; SYN retransmissions may add more.
    let stats = stats_until(&server.stack, |s| s.no_address >= 3).await?;
    let mut expected = NetStackStats::default();
    expected.no_address = stats.no_address;
    assert_eq!(stats, expected);
    sleep(QUIET).await;
    for connect in &connects {
        assert!(!connect.is_finished(), "a SYN was answered");
    }
    for connect in connects {
        connect.abort();
    }
    assert!(reports.try_recv().is_err(), "nothing was accepted");
    Ok(())
}
