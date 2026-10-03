//! Netstack reassembly between engines over an in-memory channel transport: IPv4 fragments
//! and IPv6 Fragment-header packets a raw node sends out of order reach a bound
//! `UdpSocket` and an incoming `UdpFlow` intact with `NetStackConfig::reassembly`, the
//! limits and the timeout are counted in `NetStackStats`, the default keeps dropping
//! fragments, and an oversize IPv4 reply split by the sender's engine fragmenter
//! (`udp_allow_fragmentation`) arrives whole at a reassembling stack.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use nsplane::x25519::StaticSecret;
use nsplane::{ChannelTransport, EngineBuilder, FragmentConfig};
use nsplane_e2e::{MTU, Node, Options, QUIET, StackNode, TestResult, WAIT, next_within, udp};
use nsplane_netstack::{NetStack, NetStackConfig, NetStackStats, ReassemblyConfig};
use nsplane_packet::checksum::ipv4_header_checksum;
use nsplane_packet::{Ecn, Path, TransportId};
use tokio::time::{sleep, timeout};

/// Next header value of the IPv6 Fragment header.
const IPV6_FRAGMENT: u8 = 44;
/// UDP port the raw node sends from.
const SRC_PORT: u16 = 40000;
/// UDP port of the stack's bound socket.
const BOUND_PORT: u16 = 5353;
/// UDP port with no socket on the stack: datagrams to it open a flow.
const FLOW_PORT: u16 = 9;

/// `len` bytes with a pattern of period 251.
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
}

/// A stack node with key seed `seed` on `transport` at `at`, its stack configured by
/// `configure`, with a fragmenter on its engine.
fn stack_node(
    seed: u8,
    at: (TransportId, SocketAddr),
    transport: ChannelTransport,
    configure: impl FnOnce(NetStackConfig) -> NetStackConfig,
) -> TestResult<StackNode> {
    let ip4 = Ipv4Addr::new(10, 0, 0, seed);
    let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed));
    let (stack, handle) = NetStack::new(configure(NetStackConfig::new(
        vec![(IpAddr::V4(ip4), 32), (IpAddr::V6(ip6), 128)],
        MTU,
    )));
    let (source, sink) = stack.split();
    let engine = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([seed; 32]))
        .transport(transport)
        .fragmenter(FragmentConfig::default())
        .build()?;
    Ok(StackNode {
        handle: engine.handle(),
        engine,
        stack: handle,
        secret: StaticSecret::from([seed; 32]),
        ip4,
        ip6,
        path: Path {
            transport: at.0,
            addr: at.1,
            ecn: Ecn::NotEct,
        },
    })
}

/// The two ends of a channel transport pair.
fn ends() -> [(TransportId, SocketAddr); 2] {
    [
        (
            TransportId::new(1),
            SocketAddr::from(([192, 0, 2, 1], 1000)),
        ),
        (
            TransportId::new(2),
            SocketAddr::from(([192, 0, 2, 2], 2000)),
        ),
    ]
}

/// A stack node (seed 1, `reassembly` on its stack) and a raw node (seed 2) linked by a
/// channel transport and introduced.
async fn stack_and_raw(
    reassembly: Option<ReassemblyConfig>,
) -> TestResult<(StackNode, Node<ChannelTransport>)> {
    let [a, b] = ends();
    let (link_a, link_b) = ChannelTransport::pair(1024, a, b);
    let node = stack_node(1, a, link_a, |config| NetStackConfig {
        reassembly,
        ..config
    })?;
    let raw = Node::new(2, b.0, b.1, link_b, Options::default());
    node.handle
        .add_or_update_peer(raw.as_peer(node.path.transport))
        .await?;
    raw.handle
        .add_or_update_peer(node.as_peer(raw.path.transport))
        .await?;
    Ok((node, raw))
}

/// `packet` (IPv4, 20-byte header) split into fragments of `chunk` payload bytes (a
/// multiple of 8) with identification `id`, in order.
fn fragments_v4(packet: &[u8], chunk: usize, id: u16) -> TestResult<Vec<Vec<u8>>> {
    let (header, payload) = packet.split_at(20);
    let count = payload.len().div_ceil(chunk);
    let mut fragments = Vec::new();
    for (i, part) in payload.chunks(chunk).enumerate() {
        let mut fragment = header.to_vec();
        fragment[2..4].copy_from_slice(&u16::try_from(20 + part.len())?.to_be_bytes());
        fragment[4..6].copy_from_slice(&id.to_be_bytes());
        let more = if i + 1 < count { 0x2000 } else { 0 };
        let offset = u16::try_from(i * chunk / 8)?;
        fragment[6..8].copy_from_slice(&(more | offset).to_be_bytes());
        fragment[10..12].fill(0);
        let checksum = ipv4_header_checksum(&fragment);
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        fragment.extend_from_slice(part);
        fragments.push(fragment);
    }
    Ok(fragments)
}

/// `packet` (IPv6, no extension headers) split into Fragment-header packets of `chunk`
/// payload bytes (a multiple of 8) with identification `id`, in order.
fn fragments_v6(packet: &[u8], chunk: usize, id: u32) -> TestResult<Vec<Vec<u8>>> {
    let (header, payload) = packet.split_at(40);
    let count = payload.len().div_ceil(chunk);
    let mut fragments = Vec::new();
    for (i, part) in payload.chunks(chunk).enumerate() {
        let mut fragment = header.to_vec();
        fragment[4..6].copy_from_slice(&u16::try_from(8 + part.len())?.to_be_bytes());
        fragment[6] = IPV6_FRAGMENT;
        let offset = u16::try_from(i * chunk)? | u16::from(i + 1 < count);
        fragment.extend_from_slice(&[header[6], 0]);
        fragment.extend_from_slice(&offset.to_be_bytes());
        fragment.extend_from_slice(&id.to_be_bytes());
        fragment.extend_from_slice(part);
        fragments.push(fragment);
    }
    Ok(fragments)
}

async fn send_all(raw: &Node<ChannelTransport>, packets: &[Vec<u8>]) -> TestResult {
    for packet in packets {
        raw.send(packet).await?;
    }
    Ok(())
}

/// Waits until the stack's counters satisfy `ready`.
async fn until_stats(node: &StackNode, ready: impl Fn(&NetStackStats) -> bool) -> TestResult {
    timeout(WAIT, async {
        while !ready(&node.stack.stats()) {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| format!("counters never matched: {:?}", node.stack.stats()).into())
}

#[tokio::test]
async fn out_of_order_fragments_reach_a_socket_and_a_flow() -> TestResult {
    let (node, raw) = stack_and_raw(Some(ReassemblyConfig::default())).await?;
    let mut incoming = node.stack.incoming_udp();

    for v6 in [false, true] {
        let (local, remote, local_flow, id) = if v6 {
            (
                IpAddr::V6(node.ip6),
                IpAddr::V6(raw.ip6),
                SocketAddr::new(IpAddr::V6(node.ip6), FLOW_PORT),
                2,
            )
        } else {
            (
                IpAddr::V4(node.ip4),
                IpAddr::V4(raw.ip4),
                SocketAddr::new(IpAddr::V4(node.ip4), FLOW_PORT),
                1,
            )
        };
        let bound = SocketAddr::new(local, BOUND_PORT);
        let from = SocketAddr::new(remote, SRC_PORT);
        let mut socket = node.stack.bind_udp(bound).await?;
        let split = |packet: &[u8], id: u16| {
            if v6 {
                fragments_v6(packet, 1232, u32::from(id))
            } else {
                fragments_v4(packet, 1360, id)
            }
        };

        // To the bound socket, last fragment first.
        let payload = data(3000);
        let mut fragments = split(&udp(from, bound, &payload), id)?;
        assert!(fragments.len() > 2);
        fragments.reverse();
        send_all(&raw, &fragments).await?;
        let (got, sender) = timeout(WAIT, socket.recv_from()).await??;
        assert_eq!(sender, from);
        assert_eq!(got.as_ref(), payload.as_slice());

        // To a new flow, the first fragment last.
        let payload = data(2000);
        let mut fragments = split(&udp(from, local_flow, &payload), id + 10)?;
        fragments.rotate_left(1);
        send_all(&raw, &fragments).await?;
        let mut flow = next_within(&mut incoming, WAIT).await?;
        assert_eq!((flow.peer_addr(), flow.local_addr()), (from, local_flow));
        let got = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
        assert_eq!(got.as_ref(), payload.as_slice());
    }
    let stats = node.stack.stats();
    assert_eq!(stats.reassembled, 4);
    assert_eq!(
        (
            stats.unsupported,
            stats.reassembly_timeout,
            stats.reassembly_overflow
        ),
        (0, 0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn limits_and_timeout_are_counted() -> TestResult {
    let reassembly = ReassemblyConfig {
        max_datagrams: 1,
        timeout: Duration::from_millis(200),
        max_bytes: 2000,
    };
    let (node, raw) = stack_and_raw(Some(reassembly)).await?;
    let bound = SocketAddr::new(IpAddr::V4(node.ip4), BOUND_PORT);
    let from = SocketAddr::new(IpAddr::V4(raw.ip4), SRC_PORT);
    let mut socket = node.stack.bind_udp(bound).await?;
    let packet = udp(from, bound, &data(1500));

    // One datagram is held; the first fragment of a second one exceeds `max_datagrams`.
    let held = fragments_v4(&packet, 1000, 1)?;
    let refused = fragments_v4(&packet, 1000, 2)?;
    send_all(&raw, &[held[0].clone(), refused[0].clone()]).await?;
    until_stats(&node, |stats| stats.reassembly_overflow == 1).await?;
    // The held one expires on the stack's own timer.
    until_stats(&node, |stats| stats.reassembly_timeout == 1).await?;
    // Its last fragment, now alone, expires in turn.
    send_all(&raw, &held[1..]).await?;
    until_stats(&node, |stats| stats.reassembly_timeout == 2).await?;

    // A datagram beyond `max_bytes` (fragments of 1000, 1000, 1000 and 8 bytes): every
    // fragment after the first exceeds it.
    let big = udp(from, bound, &data(3000));
    send_all(&raw, &fragments_v4(&big, 1000, 3)?).await?;
    until_stats(&node, |stats| stats.reassembly_overflow == 4).await?;
    assert!(timeout(QUIET, socket.recv_from()).await.is_err());

    // Within the bounds, a datagram still completes.
    send_all(&raw, &fragments_v4(&packet, 1000, 4)?).await?;
    let (got, _) = timeout(WAIT, socket.recv_from()).await??;
    assert_eq!(got.len(), 1500);
    assert_eq!(node.stack.stats().reassembled, 1);
    Ok(())
}

#[tokio::test]
async fn without_reassembly_fragments_are_dropped() -> TestResult {
    let (node, raw) = stack_and_raw(None).await?;
    let bound = SocketAddr::new(IpAddr::V4(node.ip4), BOUND_PORT);
    let bound6 = SocketAddr::new(IpAddr::V6(node.ip6), BOUND_PORT);
    let mut socket = node.stack.bind_udp(bound).await?;
    let mut socket6 = node.stack.bind_udp(bound6).await?;
    let from = SocketAddr::new(IpAddr::V4(raw.ip4), SRC_PORT);
    let from6 = SocketAddr::new(IpAddr::V6(raw.ip6), SRC_PORT);
    let mut fragments = fragments_v4(&udp(from, bound, &data(2000)), 1000, 1)?;
    fragments.extend(fragments_v6(&udp(from6, bound6, &data(2000)), 1000, 1)?);
    send_all(&raw, &fragments).await?;
    until_stats(&node, |stats| stats.unsupported == 6).await?;
    assert!(timeout(QUIET, socket.recv_from()).await.is_err());
    assert!(timeout(QUIET, socket6.recv_from()).await.is_err());
    let stats = node.stack.stats();
    assert_eq!(
        (
            stats.reassembled,
            stats.reassembly_timeout,
            stats.reassembly_overflow
        ),
        (0, 0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn oversize_reply_from_the_engine_fragmenter_reassembles() -> TestResult {
    let [a, b] = ends();
    let (link_a, link_b) = ChannelTransport::pair(1024, a, b);
    let sender = stack_node(1, a, link_a, |config| NetStackConfig {
        udp_allow_fragmentation: true,
        ..config
    })?;
    let receiver = stack_node(2, b, link_b, |config| NetStackConfig {
        reassembly: Some(ReassemblyConfig::default()),
        ..config
    })?;
    sender
        .handle
        .add_or_update_peer(receiver.as_peer(sender.path.transport))
        .await?;
    receiver
        .handle
        .add_or_update_peer(sender.as_peer(receiver.path.transport))
        .await?;
    let payload = data(3000);

    // A reply on the sender's incoming flow reaches the receiver's bound socket.
    let mut incoming = sender.stack.incoming_udp();
    let bound = SocketAddr::new(IpAddr::V4(receiver.ip4), BOUND_PORT);
    let mut socket = receiver.stack.bind_udp(bound).await?;
    let target = SocketAddr::new(IpAddr::V4(sender.ip4), FLOW_PORT);
    socket.send_to(b"hello", target).await?;
    let flow = next_within(&mut incoming, WAIT).await?;
    flow.send(&payload).await?;
    let (got, from) = timeout(WAIT, socket.recv_from()).await??;
    assert_eq!(from, target);
    assert_eq!(got.as_ref(), payload.as_slice());

    // A reply on the sender's bound socket reaches the receiver's incoming flow.
    let mut incoming = receiver.stack.incoming_udp();
    let replier = sender
        .stack
        .bind_udp(SocketAddr::new(IpAddr::V4(sender.ip4), BOUND_PORT))
        .await?;
    let flow_local = SocketAddr::new(IpAddr::V4(receiver.ip4), FLOW_PORT);
    replier.send_to(b"hello", flow_local).await?;
    let mut flow = next_within(&mut incoming, WAIT).await?;
    let got = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
    assert_eq!(got.as_ref(), b"hello");
    replier.send_to(&payload, flow_local).await?;
    let got = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
    assert_eq!(got.as_ref(), payload.as_slice());

    let stats = receiver.stack.stats();
    assert_eq!(stats.reassembled, 2);
    assert_eq!(stats.unsupported, 0);
    Ok(())
}
