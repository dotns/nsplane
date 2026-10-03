//! `NetStackHandle::owns` as the routing policy of a hybrid local side: node A's `Splitter`
//! hands what its netstack owns to the stack and everything else to another consumer (a
//! channel collector). TCP from peer B to A's stack opens (a SYN, `Listener`) and runs
//! (its segments, `Flow`) through the stack, while B's packets to a host behind A, TCP SYN
//! and UDP alike, reach the other consumer.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelTransport, Ecn, EngineBuilder, Path, Peer, Splitter, TransportId,
};
use nsplane_e2e::{Family, QUIET, StackNode, TRANSFER, TestResult, WAIT, serve_tcp_echo};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, Ownership};
use nsplane_packet::{IpPacket, protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Capacity of the transport and the collector.
const CAPACITY: usize = 1024;
/// A's netstack addresses.
const A_STACK4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const A_STACK6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
/// A host behind A's other consumer.
const A_HOST4: Ipv4Addr = Ipv4Addr::new(10, 1, 0, 5);
/// TCP port of A's echo server.
const TCP_PORT: u16 = 7;
/// Bytes echoed per TCP round trip.
const BULK: usize = 256 << 10;

/// Node A as B's peer, reached over B's transport `via` at `addr`: A's netstack addresses
/// and the range behind its other consumer are allowed.
fn a_as_peer(secret: &StaticSecret, via: TransportId, addr: SocketAddr) -> Peer {
    let allowed = [
        (IpAddr::V4(A_STACK4), 32),
        (IpAddr::V6(A_STACK6), 128),
        (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16),
    ];
    Peer {
        allowed_ips: allowed
            .into_iter()
            .map(|(addr, cidr)| AllowedIp { addr, cidr })
            .collect(),
        path: Some(Path {
            transport: via,
            addr,
            ecn: Ecn::NotEct,
        }),
        ..Peer::new(PublicKey::from(secret))
    }
}

/// Connects from `client` to `target`, sends [`BULK`] bytes, half-closes and checks that
/// the same bytes come back, followed by EOF.
async fn tcp_round_trip(client: &NetStackHandle, target: SocketAddr) -> TestResult {
    let conn = timeout(TRANSFER, client.connect_tcp(target)).await??;
    let sent: Vec<u8> = (0..BULK).map(|i| (i % 251).to_le_bytes()[0]).collect();
    let (mut reader, mut writer) = tokio::io::split(conn);
    let write = async {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    };
    let read = async {
        let mut echoed = Vec::with_capacity(BULK);
        reader.read_to_end(&mut echoed).await?;
        Ok::<_, io::Error>(echoed)
    };
    let ((), echoed) = timeout(TRANSFER, async { tokio::try_join!(write, read) }).await??;
    if echoed != sent {
        return Err(format!("echo from {target} changed the data").into());
    }
    Ok(())
}

/// Packets the splitter routed to the stack, per ownership class.
#[derive(Default)]
struct Routed {
    flow: AtomicU64,
    listener: AtomicU64,
}

#[tokio::test]
async fn splitter_routes_by_stack_ownership() -> TestResult {
    let a_path = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b_path = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(CAPACITY, a_path, b_path);

    // Node A: the netstack owns what it holds or accepts; the collector gets the rest.
    let (stack, a_stack) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(A_STACK4), 32), (IpAddr::V6(A_STACK6), 128)],
        DEFAULT_MTU,
    ));
    let (stack_source, stack_sink) = stack.split();
    let (collector, mut collected) = ChannelSink::new(CAPACITY);
    let routed = Arc::new(Routed::default());
    let splitter = Splitter::new({
        let owner = a_stack.clone();
        let routed = Arc::clone(&routed);
        move |_peer, packet| match owner.owns(packet.as_packet()) {
            Ownership::Flow => {
                routed.flow.fetch_add(1, Ordering::Relaxed);
                1
            }
            Ownership::Listener => {
                routed.listener.fetch_add(1, Ordering::Relaxed);
                1
            }
            _ => 0,
        }
    })
    .sink(collector)
    .sink(stack_sink);
    let a_secret = StaticSecret::from([1; 32]);
    let a = EngineBuilder::new(stack_source, splitter)
        .private_key(a_secret.clone())
        .transport(link_a)
        .build()?;
    let b = StackNode::new(2, b_path.0, b_path.1, link_b, DEFAULT_MTU)?;
    a.handle().add_or_update_peer(b.as_peer(a_path.0)).await?;
    b.handle
        .add_or_update_peer(a_as_peer(&a_secret, b_path.0, a_path.1))
        .await?;

    // TCP to A's stack: each SYN opens through `Listener`, every later segment of the
    // connection is a `Flow`, and the echo completes only if all of them reach the stack.
    serve_tcp_echo(&a_stack);
    tcp_round_trip(&b.stack, SocketAddr::new(IpAddr::V4(A_STACK4), TCP_PORT)).await?;
    tcp_round_trip(&b.stack, SocketAddr::new(IpAddr::V6(A_STACK6), TCP_PORT)).await?;
    let listener = routed.listener.load(Ordering::Relaxed);
    let flow = routed.flow.load(Ordering::Relaxed);
    assert!(listener >= 2, "one SYN per connection, got {listener}");
    assert!(
        flow > 2 * (BULK as u64) / u64::from(DEFAULT_MTU),
        "the connections' segments are flows, got {flow}"
    );

    // Unrelated packets: a SYN and a datagram to a host behind A go to the collector.
    let host_tcp = SocketAddr::new(IpAddr::V4(A_HOST4), 80);
    let connect = tokio::spawn({
        let stack = b.stack.clone();
        async move { stack.connect_tcp(host_tcp).await }
    });
    let (_, syn) = timeout(WAIT, collected.recv())
        .await?
        .ok_or("collector closed")?;
    let ip = IpPacket::parse(syn.as_packet())?;
    assert_eq!(ip.protocol(), protocol::TCP);
    assert_eq!(ip.dst(), IpAddr::V4(A_HOST4));
    connect.abort();

    let host_udp = SocketAddr::new(IpAddr::V4(A_HOST4), 4000);
    let socket = b.stack.bind_udp(b.socket_addr(Family::V4, 5000)).await?;
    socket.send_to(b"to the host", host_udp).await?;
    let datagram = timeout(WAIT, async {
        loop {
            let (_, packet) = collected.recv().await.ok_or("collector closed")?;
            let ip = IpPacket::parse(packet.as_packet())?;
            // Skip the SYN's retransmissions.
            if ip.protocol() == protocol::UDP {
                return TestResult::Ok(packet);
            }
        }
    })
    .await??;
    let ip = IpPacket::parse(datagram.as_packet())?;
    assert_eq!(ip.dst(), IpAddr::V4(A_HOST4));

    // Nothing addressed to A's stack reached the collector.
    tokio::time::sleep(QUIET).await;
    while let Ok((_, packet)) = collected.try_recv() {
        let ip = IpPacket::parse(packet.as_packet())?;
        assert_eq!(ip.dst(), IpAddr::V4(A_HOST4), "only the host's packets");
    }
    Ok(())
}
