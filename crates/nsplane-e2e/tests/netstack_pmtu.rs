//! The netstack's own TCP over a path with a smaller MTU (ns MB-x7): two stacks at the
//! default MTU (1420) joined by a hop whose MTU is 1376, as on a relay path. The hop drops
//! every larger packet and answers it with an ICMP Fragmentation Needed or an `ICMPv6`
//! Packet Too Big. A bulk transfer completes intact over IPv4 and IPv6, in segments that
//! fit the hop; a stack that ignores those messages resends every lost segment at its full
//! size, and the connection stalls for good.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use nsplane::{PacketSink, PacketSource};
use nsplane_e2e::{TRANSFER, TestResult, next_within};
use nsplane_netstack::{
    DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, NetStackSink, NetStackSource,
};
use nsplane_packet::checksum::{internet_checksum, ipv4_header_checksum, transport_checksum_v6};
use nsplane_packet::{IpPacket, PacketBuf, PeerId, protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// The MTU of the hop between the stacks.
const HOP_MTU: usize = 1376;
/// Bytes sent per transfer.
const BULK: usize = 8 << 20;
/// TCP port of the receiving stack.
const PORT: u16 = 9000;
/// The hop's addresses, the source of its ICMP messages.
const ROUTER_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 9, 254);
const ROUTER_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 9, 0, 0, 0, 0xfe);

/// What the hop did, in both directions.
#[derive(Default)]
struct HopStats {
    /// Packets above [`HOP_MTU`], dropped and answered.
    dropped: AtomicU64,
    /// The largest packet passed on.
    largest: AtomicUsize,
}

/// `len` bytes whose pattern (period 251) does not line up with any segment size.
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
}

/// The ICMP Fragmentation Needed or `ICMPv6` Packet Too Big a router at the hop sends to
/// the source of `packet`: the IP header and 8 bytes quoted over IPv4 (RFC 792), as much
/// as fits a 1280-byte message over IPv6 (RFC 4443).
fn too_big(packet: &[u8]) -> Option<PacketBuf> {
    let mtu = u16::try_from(HOP_MTU).ok()?;
    match IpPacket::parse(packet).ok()?.src() {
        IpAddr::V4(dst) => {
            let ihl = usize::from(packet.first()? & 0xf) * 4;
            let [hi, lo] = mtu.to_be_bytes();
            let mut icmp = vec![3, 4, 0, 0, 0, 0, hi, lo];
            icmp.extend_from_slice(packet.get(..ihl + 8)?);
            let sum = internet_checksum(&icmp);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            let mut out = vec![0x45, 0];
            out.extend_from_slice(&u16::try_from(20 + icmp.len()).ok()?.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0, 64, protocol::ICMP, 0, 0]);
            out.extend_from_slice(&ROUTER_V4.octets());
            out.extend_from_slice(&dst.octets());
            let sum = ipv4_header_checksum(&out);
            out[10..12].copy_from_slice(&sum.to_be_bytes());
            out.extend_from_slice(&icmp);
            Some(PacketBuf::from_packet(&out))
        }
        IpAddr::V6(dst) => {
            let mut icmp = vec![2, 0, 0, 0];
            icmp.extend_from_slice(&u32::from(mtu).to_be_bytes());
            icmp.extend_from_slice(packet.get(..packet.len().min(1280 - 48))?);
            let sum = transport_checksum_v6(ROUTER_V6, dst, protocol::ICMPV6, &icmp);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            let mut out = vec![0x60, 0, 0, 0];
            out.extend_from_slice(&u16::try_from(icmp.len()).ok()?.to_be_bytes());
            out.extend_from_slice(&[protocol::ICMPV6, 64]);
            out.extend_from_slice(&ROUTER_V6.octets());
            out.extend_from_slice(&dst.octets());
            out.extend_from_slice(&icmp);
            Some(PacketBuf::from_packet(&out))
        }
    }
}

/// Forwards `from`'s packets to `to` through the hop: a packet above [`HOP_MTU`] is dropped
/// and answered into `back`, the sink of the stack that sent it.
async fn hop(
    mut from: NetStackSource,
    to: Arc<NetStackSink>,
    back: Arc<NetStackSink>,
    stats: Arc<HopStats>,
) {
    while let Ok(packet) = from.recv().await {
        let len = packet.as_packet().len();
        let sent = if len > HOP_MTU {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            match too_big(packet.as_packet()) {
                Some(reply) => back.send(reply, PeerId::new(1)).await,
                None => Ok(()),
            }
        } else {
            stats.largest.fetch_max(len, Ordering::Relaxed);
            to.send(packet, PeerId::new(1)).await
        };
        if sent.is_err() {
            break;
        }
    }
}

/// Stack `a` (`10.0.0.1`, `fd00::1`) and stack `b` (`10.0.0.2`, `fd00::2`) at the default
/// MTU, joined by the hop.
fn pair() -> TestResult<(NetStackHandle, NetStackHandle, Arc<HopStats>)> {
    let config = |v4: [u8; 4], v6: &str| -> TestResult<NetStackConfig> {
        Ok(NetStackConfig::new(
            vec![(IpAddr::from(v4), 24), (v6.parse()?, 64)],
            DEFAULT_MTU,
        ))
    };
    let (a_stack, a) = NetStack::new(config([10, 0, 0, 1], "fd00::1")?);
    let (b_stack, b) = NetStack::new(config([10, 0, 0, 2], "fd00::2")?);
    let (a_source, a_sink) = a_stack.split();
    let (b_source, b_sink) = b_stack.split();
    let (a_sink, b_sink) = (Arc::new(a_sink), Arc::new(b_sink));
    let stats = Arc::new(HopStats::default());
    tokio::spawn(hop(
        a_source,
        Arc::clone(&b_sink),
        Arc::clone(&a_sink),
        Arc::clone(&stats),
    ));
    tokio::spawn(hop(b_source, a_sink, b_sink, Arc::clone(&stats)));
    Ok((a, b, stats))
}

/// `a` sends [`BULK`] bytes to `b` at `target` over the hop and half-closes; `b` must read
/// exactly those bytes within [`TRANSFER`].
async fn bulk_over_the_hop(target: IpAddr) -> TestResult {
    let (a, b, stats) = pair()?;
    let mut incoming = b.incoming_tcp();
    let receiver = tokio::spawn(async move {
        let mut conn = next_within(&mut incoming, TRANSFER).await?;
        let mut received = Vec::with_capacity(BULK);
        conn.read_to_end(&mut received).await?;
        TestResult::Ok(received)
    });
    let mut conn = timeout(TRANSFER, a.connect_tcp(SocketAddr::new(target, PORT))).await??;
    let sent = data(BULK);
    let transfer = async {
        conn.write_all(&sent).await?;
        conn.shutdown().await?;
        receiver.await?
    };
    let received = timeout(TRANSFER, transfer).await.map_err(|_| {
        format!(
            "stalled: not done after {TRANSFER:?}, {} packets dropped at the hop",
            stats.dropped.load(Ordering::Relaxed)
        )
    })??;
    assert_eq!(received.len(), BULK);
    assert!(received == sent, "the transfer changed the data");
    assert!(
        stats.dropped.load(Ordering::Relaxed) > 0,
        "full-size segments reached the hop"
    );
    assert!(stats.largest.load(Ordering::Relaxed) <= HOP_MTU);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_over_ipv4_follows_fragmentation_needed() -> TestResult {
    bulk_over_the_hop(IpAddr::from([10, 0, 0, 2])).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_over_ipv6_follows_packet_too_big() -> TestResult {
    bulk_over_the_hop("fd00::2".parse()?).await
}
