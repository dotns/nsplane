//! Engines over loopback [`UdpTransport`]s with segmentation offload on, off, and on at one
//! peer only: interleaved TCP-like and UDP flows of IPv4 and IPv6 packets from the channel
//! source arrive at the peer's channel sink intact and in order per flow, in both
//! directions at once, with every packet MTU - 1 bytes, MTU bytes, or of mixed sizes
//! around the MTU.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nsplane::{TransportId, UdpTransport};
use nsplane_e2e::{Family, MTU, Node, Options, TestResult, WAIT, introduce, transfer, udp};
use nsplane_packet::{PacketBuf, PeerId, protocol};
use tokio::time::timeout;

/// Packets per direction and size profile, spread round robin over [`FLOWS`].
const PACKETS: usize = 1024;
/// Packets per direction in flight at once, well within the socket buffers.
const WINDOW: usize = 128;
/// Length of the TCP header the TCP-like packets carry (no options).
const TCP_HEADER: usize = 20;
/// Length of a UDP header.
const UDP_HEADER: usize = 8;
/// Bytes at the start of each payload: the flow number and the packet's sequence number.
const TAG: usize = 9;

/// A flow: IP version, transport protocol and source port (the destination port is fixed).
#[derive(Debug, Clone, Copy)]
struct Flow {
    family: Family,
    tcp: bool,
    port: u16,
}

/// Eight interleaved flows: two each of TCP and UDP over IPv4 and IPv6.
const FLOWS: [Flow; 8] = [
    Flow {
        family: Family::V4,
        tcp: true,
        port: 40001,
    },
    Flow {
        family: Family::V6,
        tcp: false,
        port: 40002,
    },
    Flow {
        family: Family::V4,
        tcp: false,
        port: 40003,
    },
    Flow {
        family: Family::V6,
        tcp: true,
        port: 40004,
    },
    Flow {
        family: Family::V4,
        tcp: true,
        port: 40005,
    },
    Flow {
        family: Family::V6,
        tcp: false,
        port: 40006,
    },
    Flow {
        family: Family::V4,
        tcp: false,
        port: 40007,
    },
    Flow {
        family: Family::V6,
        tcp: true,
        port: 40008,
    },
];

/// Destination port of every flow.
const DST_PORT: u16 = 5201;

/// The sizes of the packets of one run.
#[derive(Debug, Clone, Copy)]
enum Sizes {
    /// Every packet is MTU - 1 bytes.
    MtuMinusOne,
    /// Every packet fills the MTU.
    Mtu,
    /// MTU, MTU - 1, MTU - 2, small and mid-sized packets in turn.
    Mixed,
}

impl Sizes {
    /// The IP packet length of packet `seq`.
    fn len(self, seq: usize) -> usize {
        let mtu = usize::from(MTU);
        match self {
            Self::MtuMinusOne => mtu - 1,
            Self::Mtu => mtu,
            Self::Mixed => [mtu, mtu - 1, mtu, mtu - 2, 120, mtu, 700][seq % 7],
        }
    }
}

/// The Internet checksum of the concatenated `chunks` (each of even length but the last).
fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for chunk in chunks {
        for pair in chunk.chunks(2) {
            let word = u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
            sum += u32::from(word);
        }
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// A TCP-like packet (an ACK|PSH segment with sequence number `seq`) carrying `payload`
/// from `src` to `dst`, with valid IP header and TCP checksums.
fn tcp(src: SocketAddr, dst: SocketAddr, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(TCP_HEADER + payload.len());
    segment.extend_from_slice(&src.port().to_be_bytes());
    segment.extend_from_slice(&dst.port().to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&1u32.to_be_bytes());
    segment.extend_from_slice(&[0x50, 0x18, 0xFF, 0xFF, 0, 0, 0, 0]);
    segment.extend_from_slice(payload);
    let len = u16::try_from(segment.len()).unwrap_or(u16::MAX);
    let mut packet = Vec::new();
    let pseudo = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = len.saturating_add(20);
            packet.extend_from_slice(&[0x45, 0]);
            packet.extend_from_slice(&total.to_be_bytes());
            packet.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol::TCP, 0, 0]);
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());
            let sum = checksum(&[&packet]);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
            [
                &s.octets()[..],
                &d.octets()[..],
                &[0, protocol::TCP],
                &len.to_be_bytes(),
            ]
            .concat()
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            packet.extend_from_slice(&[0x60, 0, 0, 0]);
            packet.extend_from_slice(&len.to_be_bytes());
            packet.extend_from_slice(&[protocol::TCP, 64]);
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());
            [
                &s.octets()[..],
                &d.octets()[..],
                &u32::from(len).to_be_bytes(),
                &[0, 0, 0, protocol::TCP],
            ]
            .concat()
        }
        _ => unreachable!("one IP version per flow"),
    };
    let sum = checksum(&[&pseudo, &segment]);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(&segment);
    packet
}

/// Packet `seq` from `from` to `to` of `sizes`: its flow and the packet. The payload starts
/// with the flow number and `seq`.
fn packet(
    from: &Node<UdpTransport>,
    to: &Node<UdpTransport>,
    sizes: Sizes,
    seq: usize,
) -> (usize, Vec<u8>) {
    let index = seq % FLOWS.len();
    let flow = FLOWS[index];
    let (src, dst, ip_header) = match flow.family {
        Family::V4 => (IpAddr::V4(from.ip4), IpAddr::V4(to.ip4), 20),
        Family::V6 => (IpAddr::V6(from.ip6), IpAddr::V6(to.ip6), 40),
    };
    let header = ip_header + if flow.tcp { TCP_HEADER } else { UDP_HEADER };
    let mut data: Vec<u8> = (0..sizes.len(seq) - header)
        .map(|at| u8::try_from((at + seq) % 251).unwrap_or(0))
        .collect();
    data[0] = u8::try_from(index).unwrap_or(u8::MAX);
    data[1..TAG].copy_from_slice(&(seq as u64).to_be_bytes());
    let (src, dst) = (
        SocketAddr::new(src, flow.port),
        SocketAddr::new(dst, DST_PORT),
    );
    let packet = if flow.tcp {
        tcp(src, dst, u32::try_from(seq).unwrap_or(u32::MAX), &data)
    } else {
        udp(src, dst, &data)
    };
    assert_eq!(packet.len(), sizes.len(seq));
    (index, packet)
}

/// The flow number of a delivered packet: the first payload byte.
fn flow_of(packet: &[u8]) -> Option<usize> {
    let (ip_header, proto) = match packet.first()? >> 4 {
        4 => (20, *packet.get(9)?),
        6 => (40, *packet.get(6)?),
        _ => return None,
    };
    let header = ip_header
        + if proto == protocol::TCP {
            TCP_HEADER
        } else {
            UDP_HEADER
        };
    packet.get(header).map(|&flow| usize::from(flow))
}

/// Receives `count` packets at `node`, all from `peer`, and appends them to their flows.
async fn collect(
    node: &mut Node<UdpTransport>,
    peer: PeerId,
    count: usize,
    flows: &mut [Vec<Vec<u8>>],
) -> TestResult {
    for _ in 0..count {
        let (from, packet) = match timeout(WAIT, node.delivered.recv()).await {
            Ok(Some((from, packet))) => (from, packet.as_packet().to_vec()),
            Ok(None) => return Err("sink closed".into()),
            Err(_) => return Err(format!("packet missing after {WAIT:?}").into()),
        };
        if from != peer {
            return Err(format!("packet attributed to {from:?}").into());
        }
        let flow = flow_of(&packet).ok_or("delivered packet without a flow")?;
        flows
            .get_mut(flow)
            .ok_or_else(|| format!("unknown flow {flow}"))?
            .push(packet);
    }
    Ok(())
}

/// Checks that every flow of `sent` arrived as `received`: complete, intact and in order.
fn check_flows(
    sizes: Sizes,
    dir: &str,
    sent: &[(usize, Vec<u8>)],
    received: &[Vec<Vec<u8>>],
) -> TestResult {
    for (flow, got) in received.iter().enumerate() {
        let expected: Vec<&Vec<u8>> = sent
            .iter()
            .filter(|(index, _)| *index == flow)
            .map(|(_, packet)| packet)
            .collect();
        if got.len() != expected.len() {
            return Err(format!(
                "{sizes:?} {dir} flow {flow}: {} of {} packets",
                got.len(),
                expected.len()
            )
            .into());
        }
        if let Some(at) = (0..got.len()).find(|&at| got[at] != *expected[at]) {
            return Err(format!(
                "{sizes:?} {dir} flow {flow}: packet {at} changed, lost or out of order"
            )
            .into());
        }
    }
    Ok(())
}

/// A node with key seed `seed` on a UDP transport on the IPv4 loopback, with segmentation
/// offload `offload`.
fn node(seed: u8, offload: bool) -> TestResult<Node<UdpTransport>> {
    let id = TransportId::new(u16::from(seed));
    let transport = UdpTransport::bind(id, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    transport.set_offload(offload)?;
    assert_eq!(transport.offload(), offload);
    let addr = transport.local_addr();
    Ok(Node::new(seed, id, addr, transport, Options::default()))
}

/// Two peers with offload `a_offload` and `b_offload` move [`PACKETS`] packets each way at
/// once, [`WINDOW`] at a time, for every size profile.
async fn flows(a_offload: bool, b_offload: bool) -> TestResult {
    let (mut a, mut b) = (node(1, a_offload)?, node(2, b_offload)?);
    introduce(&a, &b, None).await?;
    // The handshake first, so no packet waits for it.
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V6, 64).await?;
    let (a_b, b_a) = (a.peer_of(&b).await?, b.peer_of(&a).await?);
    for sizes in [Sizes::MtuMinusOne, Sizes::Mtu, Sizes::Mixed] {
        let to_b: Vec<_> = (0..PACKETS).map(|seq| packet(&a, &b, sizes, seq)).collect();
        let to_a: Vec<_> = (0..PACKETS).map(|seq| packet(&b, &a, sizes, seq)).collect();
        let mut at_b = vec![Vec::new(); FLOWS.len()];
        let mut at_a = vec![Vec::new(); FLOWS.len()];
        for start in (0..PACKETS).step_by(WINDOW) {
            let end = (start + WINDOW).min(PACKETS);
            for seq in start..end {
                a.local.send(PacketBuf::from_packet(&to_b[seq].1)).await?;
                b.local.send(PacketBuf::from_packet(&to_a[seq].1)).await?;
            }
            collect(&mut b, b_a, end - start, &mut at_b).await?;
            collect(&mut a, a_b, end - start, &mut at_a).await?;
        }
        check_flows(sizes, "a->b", &to_b, &at_b)?;
        check_flows(sizes, "b->a", &to_a, &at_a)?;
    }
    for node in [&a, &b] {
        let counters = node.handle.drop_counters().await?;
        let dropped: Vec<_> = counters.iter().filter(|(_, count)| **count > 0).collect();
        if !dropped.is_empty() {
            return Err(format!("drops counted: {dropped:?}").into());
        }
    }
    Ok(())
}

#[tokio::test]
async fn flows_around_mtu_offload_on() -> TestResult {
    flows(true, true).await
}

#[tokio::test]
async fn flows_around_mtu_offload_off() -> TestResult {
    flows(false, false).await
}

#[tokio::test]
async fn flows_around_mtu_offload_on_and_off_peers() -> TestResult {
    flows(true, false).await
}
