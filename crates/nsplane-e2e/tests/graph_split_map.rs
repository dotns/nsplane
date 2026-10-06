//! A rewriting `Splitter` as an engine's local side: the TUN ingress demux of a hybrid
//! local side, which runs a Redirect and then routes on the result.
//!
//! Engine A serves peer X over a `ChannelTransport`. A's sink is a `Splitter::new_map` that
//! redirects packets to a virtual address onto the netstack's service address (fixing the
//! IPv4 header and UDP checksums) and routes them to a netstack-like channel, sends
//! everything else untouched to a TUN-like channel, and routes a blocked class to an index
//! without a sink, where the splitter counts it as misrouted.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, DROP_SINK_CLOSED, Ecn, Engine,
    EngineBuilder, PacketBuf, PacketSink, Path, Peer, PeerId, Splitter, TransportId,
};
use nsplane_e2e::{Family, Node, Options, TestResult, WAIT, udp, verify_checksums};
use nsplane_packet::checksum::{
    ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{IpPacket, protocol};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Capacity of the channels and the link.
const CAPACITY: usize = 1024;
/// MTU of A's local side.
const MTU: u16 = 1420;
/// Key seeds: peer X, engine A. The nodes' tunnel addresses are `10.0.0.<seed>` and
/// `fd00::<seed>`.
const X_SEED: u8 = 1;
const A_SEED: u8 = 2;
/// The virtual address X reaches the netstack service on, redirected to [`SERVICE4`].
const VIRT4: Ipv4Addr = Ipv4Addr::new(10, 0, 4, 4);
const VIRT6: Ipv6Addr = Ipv6Addr::new(0xfd00, 4, 0, 0, 0, 0, 0, 4);
/// The netstack's service address.
const SERVICE4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const SERVICE6: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x64, 0, 0, 0, 0, 0, 1);
/// An address the demux routes to an index without a sink.
const BLOCKED4: Ipv4Addr = Ipv4Addr::new(10, 0, 4, 9);
const BLOCKED6: Ipv6Addr = Ipv6Addr::new(0xfd00, 4, 0, 0, 0, 0, 0, 9);
/// A host behind A's TUN side.
const OTHER4: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
const OTHER6: Ipv6Addr = Ipv6Addr::new(0xfd09, 0, 0, 0, 0, 0, 0, 1);
/// UDP port of every packet.
const PORT: u16 = 5000;
/// Packets per burst.
const BURST: usize = 32;
/// The splitter's sink indexes; [`NOWHERE`] has no sink.
const NETSTACK: usize = 0;
const TUN: usize = 1;
const NOWHERE: usize = 2;

/// Transport ids and addresses of X and A on their link.
const X_PATH: (TransportId, SocketAddr) = (
    TransportId::new(1),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1000),
);
const A_PATH: (TransportId, SocketAddr) = (
    TransportId::new(2),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 2000),
);

/// A node's tunnel address of `family`.
fn tunnel(seed: u8, family: Family) -> IpAddr {
    match family {
        Family::V4 => IpAddr::V4(Ipv4Addr::new(10, 0, 0, seed)),
        Family::V6 => IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed))),
    }
}

/// The virtual, service, blocked and other addresses of `family`.
const fn targets(family: Family) -> (IpAddr, IpAddr, IpAddr, IpAddr) {
    match family {
        Family::V4 => (
            IpAddr::V4(VIRT4),
            IpAddr::V4(SERVICE4),
            IpAddr::V4(BLOCKED4),
            IpAddr::V4(OTHER4),
        ),
        Family::V6 => (
            IpAddr::V6(VIRT6),
            IpAddr::V6(SERVICE6),
            IpAddr::V6(BLOCKED6),
            IpAddr::V6(OTHER6),
        ),
    }
}

/// A UDP packet from `src` to `dst`, both on [`PORT`], with valid checksums.
fn packet(src: IpAddr, dst: IpAddr, payload: &str) -> Vec<u8> {
    udp(
        SocketAddr::new(src, PORT),
        SocketAddr::new(dst, PORT),
        payload.as_bytes(),
    )
}

/// Replaces the destination of a UDP packet without IP options or extension headers with
/// `to` if it is `from`, and recomputes the checksums, as a Redirect does. Returns whether it
/// rewrote the packet.
fn rewrite_dst(packet: &mut [u8], from: IpAddr, to: IpAddr) -> bool {
    let (from, to) = match (from, to) {
        (IpAddr::V4(from), IpAddr::V4(to)) => (from.octets().to_vec(), to.octets().to_vec()),
        (IpAddr::V6(from), IpAddr::V6(to)) => (from.octets().to_vec(), to.octets().to_vec()),
        _ => return false,
    };
    let (header, at) = match packet.first().map(|byte| byte >> 4) {
        Some(4) => (20, 16),
        Some(6) => (40, 24),
        _ => return false,
    };
    if packet.get(at..at + from.len()) != Some(&from[..]) || packet.len() < header + 8 {
        return false;
    }
    packet[at..at + to.len()].copy_from_slice(&to);
    let checksum = header + 6..header + 8;
    packet[checksum.clone()].fill(0);
    let Ok(ip) = IpPacket::parse(packet) else {
        return false;
    };
    let sum = match (ip.src(), ip.dst()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            transport_checksum_v4(src, dst, protocol::UDP, ip.payload())
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            transport_checksum_v6(src, dst, protocol::UDP, ip.payload())
        }
        _ => return false,
    };
    let sum = if sum == 0 { 0xFFFF } else { sum };
    packet[checksum].copy_from_slice(&sum.to_be_bytes());
    if header == 20 {
        packet[10..12].fill(0);
        let sum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    true
}

/// The TUN ingress demux: redirects the virtual address to the service address and routes
/// the result to the netstack, the blocked addresses nowhere and the rest to the TUN side.
fn demux(_from: PeerId, packet: &mut PacketBuf) -> usize {
    let redirected = [Family::V4, Family::V6].into_iter().any(|family| {
        let (virt, service, _, _) = targets(family);
        rewrite_dst(packet.as_packet_mut(), virt, service)
    });
    if redirected {
        return NETSTACK;
    }
    let blocked = IpPacket::parse(packet.as_packet())
        .is_ok_and(|ip| ip.dst() == IpAddr::V4(BLOCKED4) || ip.dst() == IpAddr::V6(BLOCKED6));
    if blocked { NOWHERE } else { TUN }
}

/// A sink shared between an engine and the test, so the test reads the counters of a sink
/// the engine owns.
struct Shared<S>(Arc<S>);

impl<S: PacketSink> PacketSink for Shared<S> {
    async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
        self.0.send(packet, from).await
    }

    async fn send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        self.0.send_batch(packets).await
    }
}

fn public(seed: u8) -> PublicKey {
    PublicKey::from(&StaticSecret::from([seed; 32]))
}

/// Peer X and engine A on one link, introduced to each other; A's local side is a TUN-like
/// source nobody writes to and `sink`.
async fn x_and_a(sink: impl PacketSink) -> TestResult<(Node<ChannelTransport>, Engine)> {
    let (source, _tx, _mtu) = ChannelSource::new(CAPACITY, MTU);
    let (link_x, link_a) = ChannelTransport::pair(CAPACITY, X_PATH, A_PATH);
    let x = Node::new(X_SEED, X_PATH.0, X_PATH.1, link_x, Options::default());
    let a = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([A_SEED; 32]))
        .transport(link_a)
        .build()?;
    a.handle().add_or_update_peer(x.as_peer(A_PATH.0)).await?;
    x.handle
        .add_or_update_peer(Peer {
            allowed_ips: [
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ]
            .into_iter()
            .map(|addr| AllowedIp { addr, cidr: 0 })
            .collect(),
            path: Some(Path {
                transport: X_PATH.0,
                addr: A_PATH.1,
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(public(A_SEED))
        })
        .await?;
    Ok((x, a))
}

/// The next packet on `rx`, checked to come from `peer`, to be `expected` and to carry
/// valid checksums.
async fn expect(
    rx: &mut mpsc::Receiver<(PeerId, PacketBuf)>,
    peer: PeerId,
    expected: &[u8],
) -> TestResult {
    let (from, delivered) = timeout(WAIT, rx.recv()).await?.ok_or("sink closed")?;
    assert_eq!((from, delivered.as_packet()), (peer, expected));
    verify_checksums(delivered.as_packet())
}

/// X -> A -> `Splitter::new_map`: redirected packets reach the netstack rewritten with valid
/// checksums, the others reach the TUN side untouched, both in order, and the blocked ones
/// are counted as misrouted while the engine keeps delivering, for IPv4 and IPv6.
#[tokio::test]
async fn rewriting_demux_on_engine_delivery() -> TestResult {
    let (netstack, mut netstack_out) = ChannelSink::new(CAPACITY);
    let (tun, mut tun_out) = ChannelSink::new(CAPACITY);
    let splitter = Arc::new(Splitter::new_map(demux).sink(netstack).sink(tun));
    let (x, a) = x_and_a(Shared(Arc::clone(&splitter))).await?;
    let x_at_a = a
        .handle()
        .peer_id(x.public())
        .await?
        .ok_or("unknown peer")?;

    let mut misrouted = 0;
    for family in [Family::V4, Family::V6] {
        let (virt, service, blocked, other) = targets(family);
        let x_ip = tunnel(X_SEED, family);

        // Interleaved: to the virtual address, to a blocked address, to the TUN side.
        for i in 0..BURST {
            x.send(&packet(x_ip, virt, &format!("to the netstack {i}")))
                .await?;
            x.send(&packet(x_ip, blocked, &format!("blocked {i}")))
                .await?;
            x.send(&packet(x_ip, other, &format!("to the TUN side {i}")))
                .await?;
        }
        for i in 0..BURST {
            let redirected = packet(x_ip, service, &format!("to the netstack {i}"));
            expect(&mut netstack_out, x_at_a, &redirected).await?;
        }
        for i in 0..BURST {
            let untouched = packet(x_ip, other, &format!("to the TUN side {i}"));
            expect(&mut tun_out, x_at_a, &untouched).await?;
        }
        misrouted += BURST as u64;
        // Each blocked packet was sent before a delivered one, so it is counted by now.
        assert_eq!(splitter.stats().misrouted, misrouted);
    }

    let stats = splitter.stats();
    assert_eq!((stats.misrouted, stats.failed), (2 * BURST as u64, 0));
    // The misrouted packets did not take the local side for gone: the engine still delivers
    // and dropped nothing as sink-closed.
    let x_ip = tunnel(X_SEED, Family::V4);
    x.send(&packet(x_ip, IpAddr::V4(VIRT4), "after")).await?;
    expect(
        &mut netstack_out,
        x_at_a,
        &packet(x_ip, IpAddr::V4(SERVICE4), "after"),
    )
    .await?;
    let drops = a.handle().drop_counters().await?;
    assert_eq!(drops.get(DROP_SINK_CLOSED).copied().unwrap_or(0), 0);
    assert!(netstack_out.try_recv().is_err() && tun_out.try_recv().is_err());
    Ok(())
}
