//! Netstack fragment admission between engines over an in-memory channel transport: once
//! `NetStackHandle::discard_fragments` revokes a datagram whose first fragment the stack
//! already holds, its remaining fragments from a raw node never join a later datagram on
//! the same tuple, for IPv4 and IPv6, and `NetStackHandle::owns` remembers a first
//! fragment's `Flow` verdict for the later fragments of its datagram until the discard.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nsplane::x25519::StaticSecret;
use nsplane::{ChannelTransport, EngineBuilder};
use nsplane_e2e::{MTU, Node, Options, StackNode, TestResult, WAIT, udp};
use nsplane_netstack::{NetStack, NetStackConfig, Ownership, ReassemblyConfig, UdpSocket};
use nsplane_packet::checksum::ipv4_header_checksum;
use nsplane_packet::{Ecn, Path, TransportId, protocol};
use tokio::time::timeout;

/// Next header value of the IPv6 Fragment header.
const IPV6_FRAGMENT: u8 = 44;
/// UDP port the raw node sends from.
const SRC_PORT: u16 = 40000;
/// UDP port of the stack's bound socket.
const BOUND_PORT: u16 = 5353;
/// Payload bytes per fragment (a multiple of 8).
const CHUNK: usize = 512;

/// `len` bytes with a pattern of period 251, offset by `seed`.
fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251).to_le_bytes()[0].wrapping_add(seed))
        .collect()
}

/// A stack node (seed 1, reassembling) and a raw node (seed 2) linked by a channel
/// transport and introduced.
async fn stack_and_raw() -> TestResult<(StackNode, Node<ChannelTransport>)> {
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, a, b);
    let ip4 = Ipv4Addr::new(10, 0, 0, 1);
    let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let (stack, handle) = NetStack::new(NetStackConfig {
        reassembly: Some(ReassemblyConfig::default()),
        ..NetStackConfig::new(vec![(IpAddr::V4(ip4), 32), (IpAddr::V6(ip6), 128)], MTU)
    });
    let (source, sink) = stack.split();
    let engine = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([1; 32]))
        .transport(link_a)
        .build()?;
    let node = StackNode {
        handle: engine.handle(),
        engine,
        stack: handle,
        secret: StaticSecret::from([1; 32]),
        ip4,
        ip6,
        path: Path {
            transport: a.0,
            addr: a.1,
            ecn: Ecn::NotEct,
        },
    };
    let raw = Node::new(2, b.0, b.1, link_b, Options::default());
    node.handle
        .add_or_update_peer(raw.as_peer(node.path.transport))
        .await?;
    raw.handle
        .add_or_update_peer(node.as_peer(raw.path.transport))
        .await?;
    Ok((node, raw))
}

/// `packet` split into fragments of [`CHUNK`] payload bytes with identification `id`, in
/// order: IPv4 fragments for a 20-byte IPv4 header, Fragment-header packets for an IPv6
/// header without extension headers.
fn fragments(packet: &[u8], id: u16) -> TestResult<Vec<Vec<u8>>> {
    let v6 = packet[0] >> 4 == 6;
    let (header, payload) = packet.split_at(if v6 { 40 } else { 20 });
    let count = payload.len().div_ceil(CHUNK);
    let mut fragments = Vec::new();
    for (i, part) in payload.chunks(CHUNK).enumerate() {
        let more = i + 1 < count;
        let mut fragment = header.to_vec();
        if v6 {
            fragment[4..6].copy_from_slice(&u16::try_from(8 + part.len())?.to_be_bytes());
            fragment[6] = IPV6_FRAGMENT;
            let offset = u16::try_from(i * CHUNK)? | u16::from(more);
            fragment.extend_from_slice(&[header[6], 0]);
            fragment.extend_from_slice(&offset.to_be_bytes());
            fragment.extend_from_slice(&u32::from(id).to_be_bytes());
        } else {
            fragment[2..4].copy_from_slice(&u16::try_from(20 + part.len())?.to_be_bytes());
            fragment[4..6].copy_from_slice(&id.to_be_bytes());
            let offset = u16::try_from(i * CHUNK / 8)? | if more { 0x2000 } else { 0 };
            fragment[6..8].copy_from_slice(&offset.to_be_bytes());
            fragment[10..12].fill(0);
            let checksum = ipv4_header_checksum(&fragment);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
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

/// Sends a small whole datagram from `from` to `bound` and waits for it on `socket`, so
/// everything the raw node sent before it went through the stack first.
async fn barrier(
    raw: &Node<ChannelTransport>,
    socket: &mut UdpSocket,
    from: SocketAddr,
    bound: SocketAddr,
) -> TestResult {
    raw.send(&udp(from, bound, b"barrier")).await?;
    let (got, _) = timeout(WAIT, socket.recv_from()).await??;
    assert_eq!(got.as_ref(), b"barrier");
    Ok(())
}

/// The bound address and the raw node's source of one family.
fn tuple(node: &StackNode, raw: &Node<ChannelTransport>, v6: bool) -> (SocketAddr, SocketAddr) {
    if v6 {
        (
            SocketAddr::new(IpAddr::V6(node.ip6), BOUND_PORT),
            SocketAddr::new(IpAddr::V6(raw.ip6), SRC_PORT),
        )
    } else {
        (
            SocketAddr::new(IpAddr::V4(node.ip4), BOUND_PORT),
            SocketAddr::new(IpAddr::V4(raw.ip4), SRC_PORT),
        )
    }
}

#[tokio::test]
async fn a_revoked_flows_fragments_never_join_a_later_flow_on_the_same_tuple() -> TestResult {
    let (node, raw) = stack_and_raw().await?;
    let mut dropped = 0;
    for v6 in [false, true] {
        let (bound, from) = tuple(&node, &raw, v6);
        let mut socket = node.stack.bind_udp(bound).await?;

        // The first fragment of datagram 7 is held when its admission is revoked.
        let revoked = fragments(&udp(from, bound, &data(1500, 1)), 7)?;
        send_all(&raw, &revoked[..1]).await?;
        barrier(&raw, &mut socket, from, bound).await?;
        node.stack
            .discard_fragments(from.ip(), bound.ip(), protocol::UDP, 7);

        // The rest of datagram 7 and a new datagram on the same tuple: only the new one
        // arrives.
        let payload = data(1400, 2);
        send_all(&raw, &revoked[1..]).await?;
        send_all(&raw, &fragments(&udp(from, bound, &payload), 8)?).await?;
        dropped += revoked.len() as u64 - 1;
        let (got, sender) = timeout(WAIT, socket.recv_from()).await??;
        assert_eq!((got.as_ref(), sender), (payload.as_slice(), from));
        barrier(&raw, &mut socket, from, bound).await?;
    }
    let stats = node.stack.stats();
    assert_eq!((stats.reassembled, stats.reassembly_overflow), (2, dropped));
    Ok(())
}

#[tokio::test]
async fn owns_remembers_a_first_fragments_flow_until_the_discard() -> TestResult {
    let (node, raw) = stack_and_raw().await?;
    for v6 in [false, true] {
        let (bound, from) = tuple(&node, &raw, v6);
        let _socket = node.stack.bind_udp(bound).await?;
        let packet = udp(from, bound, &data(1500, 1));
        let datagram = fragments(&packet, 7)?;
        let other = fragments(&packet, 8)?;

        assert_eq!(node.stack.owns(&datagram[1]), Ownership::Listener, "early");
        assert_eq!(node.stack.owns(&datagram[0]), Ownership::Flow, "first");
        assert_eq!(node.stack.owns(&datagram[1]), Ownership::Flow, "later");
        assert_eq!(node.stack.owns(&datagram[2]), Ownership::Flow, "last");
        assert_eq!(node.stack.owns(&other[1]), Ownership::Listener, "other id");

        node.stack
            .discard_fragments(from.ip(), bound.ip(), protocol::UDP, 7);
        assert_eq!(
            node.stack.owns(&datagram[1]),
            Ownership::Listener,
            "discarded"
        );
        assert_eq!(
            node.stack.owns(&datagram[0]),
            Ownership::Flow,
            "first again"
        );
        assert_eq!(
            node.stack.owns(&datagram[2]),
            Ownership::Listener,
            "still discarded"
        );
    }
    Ok(())
}
