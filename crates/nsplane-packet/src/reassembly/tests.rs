use super::*;
use crate::checksum::{internet_checksum, transport_checksum_v4, transport_checksum_v6};
use crate::{IpPacket, UdpHeader, protocol};

const V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const V4_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
/// Hop-by-Hop header carrying UDP, padded with a `PadN` option.
const HOP_BY_HOP_UDP: [u8; 8] = [protocol::UDP, 0, 1, 4, 0, 0, 0, 0];

/// A UDP segment with `len` payload bytes and its checksum field zeroed.
fn udp_segment(len: usize) -> Vec<u8> {
    let total = u16::try_from(8 + len).unwrap();
    let mut segment = vec![0xca, 0x6c, 0x00, 0x35];
    segment.extend_from_slice(&total.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend((0..len).map(|i| u8::try_from(i % 251).unwrap()));
    segment
}

/// A valid IPv4 UDP packet with `len` payload bytes and identification `id`.
fn udp_v4(len: usize, id: u16) -> Vec<u8> {
    let mut segment = udp_segment(len);
    let sum = transport_checksum_v4(V4_SRC, V4_DST, protocol::UDP, &segment);
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
    let total = u16::try_from(20 + segment.len()).unwrap();
    let mut packet = vec![0x45, 0x02];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 64, protocol::UDP, 0, 0]);
    packet.extend_from_slice(&V4_SRC.octets());
    packet.extend_from_slice(&V4_DST.octets());
    let checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&segment);
    packet
}

/// Splits an unfragmented IPv4 `packet` (20-byte header) into fragments of `chunk`
/// payload bytes.
fn fragment_v4(packet: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let (header, data) = packet.split_at(20);
    let count = data.len().div_ceil(chunk);
    data.chunks(chunk)
        .enumerate()
        .map(|(i, part)| {
            let mut fragment = header.to_vec();
            let total = u16::try_from(20 + part.len()).unwrap();
            fragment[2..4].copy_from_slice(&total.to_be_bytes());
            let mut flags = u16::try_from(i * chunk / 8).unwrap();
            if i + 1 < count {
                flags |= 0x2000;
            }
            fragment[6..8].copy_from_slice(&flags.to_be_bytes());
            let checksum = ipv4_header_checksum(&fragment);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
            fragment.extend_from_slice(part);
            fragment
        })
        .collect()
}

/// A valid IPv6 UDP packet with `len` payload bytes, behind a Hop-by-Hop header when
/// `hop_by_hop` is set.
fn udp_v6(len: usize, hop_by_hop: bool) -> Vec<u8> {
    let mut segment = udp_segment(len);
    let sum = transport_checksum_v6(V6_SRC, V6_DST, protocol::UDP, &segment);
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
    let extension: &[u8] = if hop_by_hop { &HOP_BY_HOP_UDP } else { &[] };
    let payload_len = u16::try_from(extension.len() + segment.len()).unwrap();
    let next = if hop_by_hop {
        HOP_BY_HOP
    } else {
        protocol::UDP
    };
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.extend_from_slice(&[next, 64]);
    packet.extend_from_slice(&V6_SRC.octets());
    packet.extend_from_slice(&V6_DST.octets());
    packet.extend_from_slice(extension);
    packet.extend_from_slice(&segment);
    packet
}

/// Splits an unfragmented IPv6 `packet` whose unfragmentable part is `unfragmentable`
/// bytes and whose last next-header field is at `next_at` into fragments of `chunk`
/// bytes, inserting a Fragment header with identification `id`.
fn fragment_v6(
    packet: &[u8],
    unfragmentable: usize,
    next_at: usize,
    chunk: usize,
    id: u32,
) -> Vec<Vec<u8>> {
    let (header, data) = packet.split_at(unfragmentable);
    let inner = packet[next_at];
    let count = data.len().div_ceil(chunk);
    data.chunks(chunk)
        .enumerate()
        .map(|(i, part)| {
            let mut fragment = header.to_vec();
            fragment[next_at] = FRAGMENT;
            let payload_len = u16::try_from(unfragmentable - 40 + 8 + part.len()).unwrap();
            fragment[4..6].copy_from_slice(&payload_len.to_be_bytes());
            let mut offset = u16::try_from(i * chunk).unwrap();
            if i + 1 < count {
                offset |= 1;
            }
            fragment.extend_from_slice(&[inner, 0]);
            fragment.extend_from_slice(&offset.to_be_bytes());
            fragment.extend_from_slice(&id.to_be_bytes());
            fragment.extend_from_slice(part);
            fragment
        })
        .collect()
}

/// Deterministic permutations of `0..n`: in order, reversed, and a few shuffles.
fn orders(n: usize) -> Vec<Vec<usize>> {
    let mut orders = vec![(0..n).collect::<Vec<_>>(), (0..n).rev().collect()];
    let mut state = 0x2545_f491_u64;
    for _ in 0..8 {
        let mut order: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let j = usize::try_from(state >> 33).unwrap() % (i + 1);
            order.swap(i, j);
        }
        orders.push(order);
    }
    orders
}

/// Pushes `fragments` in `order`, expecting every one but the last to be held, and
/// returns the completed packet.
fn reassemble(reassembler: &mut Reassembler, fragments: &[Vec<u8>], order: &[usize]) -> Vec<u8> {
    let now = Instant::now();
    let (last, held) = order.split_last().unwrap();
    for &i in held {
        assert_eq!(reassembler.push(&fragments[i], now), Outcome::Held);
    }
    match reassembler.push(&fragments[*last], now) {
        Outcome::Complete(packet) => packet,
        other => panic!("expected a complete datagram, got {other:?}"),
    }
}

/// Checks the IPv4 header checksum and the UDP checksum of `packet`.
fn assert_v4_valid(packet: &[u8]) {
    let parsed = IpPacket::parse(packet).unwrap();
    let IpPacket::V4 { header, payload } = &parsed else {
        panic!("not IPv4");
    };
    assert!(parsed.fragment().is_none());
    assert_eq!(usize::from(header.total_len()), packet.len());
    assert_eq!(internet_checksum(&packet[..header.header_len()]), 0);
    let (udp, _) = UdpHeader::parse(payload).unwrap();
    assert_eq!(usize::from(udp.len()), payload.len());
    assert_eq!(
        transport_checksum_v4(header.src(), header.dst(), protocol::UDP, payload),
        0
    );
}

/// Checks the IPv6 payload length and the UDP checksum of `packet`, whose UDP header
/// starts at `udp_at`.
fn assert_v6_valid(packet: &[u8], udp_at: usize) {
    let IpPacket::V6 { header, payload } = IpPacket::parse(packet).unwrap() else {
        panic!("not IPv6");
    };
    assert_eq!(usize::from(header.payload_len()) + 40, packet.len());
    let segment = &payload[udp_at - 40..];
    let (udp, _) = UdpHeader::parse(segment).unwrap();
    assert_eq!(usize::from(udp.len()), segment.len());
    assert_eq!(
        transport_checksum_v6(header.src(), header.dst(), protocol::UDP, segment),
        0
    );
}

#[test]
fn config_defaults() {
    let config = ReassemblyConfig::default();
    assert_eq!(config.max_datagrams, 64);
    assert_eq!(config.timeout, Duration::from_secs(30));
    assert_eq!(config.max_bytes, 65_535);
}

#[test]
fn ipv4_any_order() {
    let original = udp_v4(1000, 0x4242);
    let fragments = fragment_v4(&original, 160);
    assert_eq!(fragments.len(), 7);
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    for (n, order) in orders(fragments.len()).iter().enumerate() {
        let packet = reassemble(&mut reassembler, &fragments, order);
        assert_eq!(packet, original, "order {order:?}");
        assert_v4_valid(&packet);
        assert_eq!(reassembler.pending(), 0);
        assert_eq!(
            reassembler.stats().reassembled,
            u64::try_from(n + 1).unwrap()
        );
    }
}

#[test]
fn ipv4_keeps_first_fragment_header_and_df() {
    let original = udp_v4(100, 7);
    let mut fragments = fragment_v4(&original, 64);
    // A later fragment with another TTL; the first fragment's header wins.
    fragments[1][8] = 3;
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    let packet = reassemble(&mut reassembler, &fragments, &[1, 0]);
    assert_eq!(packet, original);
    // DF set on the first fragment survives, MF and the offset do not.
    let mut first = fragments[0].clone();
    first[6] |= 0x40;
    first[10..12].fill(0);
    let checksum = ipv4_header_checksum(&first);
    first[10..12].copy_from_slice(&checksum.to_be_bytes());
    let packet = reassemble(&mut reassembler, &[first, fragments[1].clone()], &[0, 1]);
    assert_eq!(&packet[6..8], &[0x40, 0]);
    assert_v4_valid(&packet);
}

#[test]
fn ipv6_any_order() {
    let original = udp_v6(1000, false);
    let fragments = fragment_v6(&original, 40, 6, 160, 0xdead_beef);
    assert_eq!(fragments.len(), 7);
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    for order in orders(fragments.len()) {
        let packet = reassemble(&mut reassembler, &fragments, &order);
        assert_eq!(packet, original, "order {order:?}");
        assert_v6_valid(&packet, 40);
    }
}

#[test]
fn ipv6_after_hop_by_hop_any_order() {
    let original = udp_v6(700, true);
    let fragments = fragment_v6(&original, 48, 40, 200, 9);
    assert_eq!(fragments.len(), 4);
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    for order in orders(fragments.len()) {
        let packet = reassemble(&mut reassembler, &fragments, &order);
        assert_eq!(packet, original, "order {order:?}");
        assert_eq!(packet[6], HOP_BY_HOP);
        assert_eq!(packet[40], protocol::UDP);
        assert_v6_valid(&packet, 48);
    }
}

#[test]
fn ipv6_atomic_fragment_completes_at_once() {
    let original = udp_v6(50, false);
    let fragments = fragment_v6(&original, 40, 6, 1024, 1);
    assert_eq!(fragments.len(), 1);
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    assert_eq!(
        reassembler.push(&fragments[0], Instant::now()),
        Outcome::Complete(original)
    );
}

#[test]
fn datagrams_are_keyed_separately() {
    let a = udp_v4(300, 1);
    let b = udp_v4(300, 2);
    let (fa, fb) = (fragment_v4(&a, 160), fragment_v4(&b, 160));
    let mut v6 = fragment_v6(&udp_v6(300, false), 40, 6, 160, 1);
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    assert_eq!(reassembler.push(&fa[0], now), Outcome::Held);
    assert_eq!(reassembler.push(&fb[1], now), Outcome::Held);
    assert_eq!(reassembler.push(&v6[0], now), Outcome::Held);
    assert_eq!(reassembler.pending(), 3);
    assert_eq!(reassembler.push(&fa[1], now), Outcome::Complete(a));
    assert_eq!(reassembler.push(&fb[0], now), Outcome::Complete(b));
    assert!(matches!(
        reassembler.push(&v6.remove(1), now),
        Outcome::Complete(_)
    ));
    assert_eq!(reassembler.pending(), 0);
}

#[test]
fn duplicates_are_tolerated() {
    let original = udp_v4(500, 3);
    let fragments = fragment_v4(&original, 160);
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    for i in [1, 1, 0, 1, 0, 3, 3] {
        assert_eq!(reassembler.push(&fragments[i], now), Outcome::Held);
    }
    assert_eq!(
        reassembler.push(&fragments[2], now),
        Outcome::Complete(original)
    );
    let stats = reassembler.stats();
    assert_eq!(
        (stats.reassembled, stats.overlap, stats.malformed),
        (1, 0, 0)
    );
}

#[test]
fn overlap_drops_the_datagram() {
    let original = udp_v4(500, 4);
    let fragments = fragment_v4(&original, 160);
    let overlapping = fragment_v4(&original, 80);
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    assert_eq!(reassembler.push(&fragments[0], now), Outcome::Held);
    // Bytes 80..160 again, but with different coverage than the held 0..160.
    assert_eq!(reassembler.push(&overlapping[1], now), Outcome::Dropped);
    assert_eq!(reassembler.stats().overlap, 1);
    assert_eq!(reassembler.pending(), 0);
    // The rest of the datagram opens a new entry that never completes.
    assert_eq!(reassembler.push(&fragments[1], now), Outcome::Held);

    let original = udp_v6(500, false);
    let fragments = fragment_v6(&original, 40, 6, 160, 5);
    let overlapping = fragment_v6(&original, 40, 6, 240, 5);
    assert_eq!(reassembler.push(&fragments[1], now), Outcome::Held);
    assert_eq!(reassembler.push(&overlapping[0], now), Outcome::Dropped);
    assert_eq!(reassembler.stats().overlap, 2);
    assert_eq!(reassembler.stats().reassembled, 0);
}

#[test]
fn conflicting_lengths_are_malformed() {
    let fragments = fragment_v4(&udp_v4(500, 6), 160);
    let shorter = fragment_v4(&udp_v4(200, 6), 160);
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    assert_eq!(reassembler.push(&fragments[2], now), Outcome::Held);
    // A last fragment ending before held data.
    assert_eq!(reassembler.push(&shorter[1], now), Outcome::Dropped);
    assert_eq!(reassembler.stats().malformed, 1);
    assert_eq!(reassembler.pending(), 0);
}

#[test]
fn invalid_fragments_are_malformed() {
    let mut fragment = fragment_v4(&udp_v4(500, 7), 160).remove(0);
    // A non-last fragment whose length is not a multiple of 8.
    fragment.pop();
    let total = u16::try_from(fragment.len()).unwrap();
    fragment[2..4].copy_from_slice(&total.to_be_bytes());
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    assert_eq!(
        reassembler.push(&fragment, Instant::now()),
        Outcome::Dropped
    );
    let stats = reassembler.stats();
    assert_eq!(stats.malformed, 1);
    assert_eq!(reassembler.pending(), 0);
}

#[test]
fn max_datagrams_overflow_is_counted() {
    let config = ReassemblyConfig {
        max_datagrams: 2,
        ..ReassemblyConfig::default()
    };
    let packets: Vec<_> = (1..=3).map(|id| udp_v4(300, id)).collect();
    let fragments: Vec<_> = packets.iter().map(|p| fragment_v4(p, 160)).collect();
    let now = Instant::now();
    let mut reassembler = Reassembler::new(config);
    assert_eq!(reassembler.push(&fragments[0][0], now), Outcome::Held);
    assert_eq!(reassembler.push(&fragments[1][0], now), Outcome::Held);
    assert_eq!(reassembler.push(&fragments[2][0], now), Outcome::Dropped);
    assert_eq!(reassembler.stats().overflow, 1);
    assert_eq!(reassembler.pending(), 2);
    // Held datagrams are not evicted and still complete.
    assert_eq!(
        reassembler.push(&fragments[0][1], now),
        Outcome::Complete(packets[0].clone())
    );
    assert_eq!(reassembler.push(&fragments[2][0], now), Outcome::Held);
}

#[test]
fn max_bytes_overflow_is_counted() {
    let config = ReassemblyConfig {
        max_bytes: 400,
        ..ReassemblyConfig::default()
    };
    let now = Instant::now();
    let mut reassembler = Reassembler::new(config);

    // A fragment reaching beyond the bound drops the held datagram.
    let fragments = fragment_v4(&udp_v4(500, 8), 160);
    assert_eq!(reassembler.push(&fragments[0], now), Outcome::Held);
    assert_eq!(reassembler.push(&fragments[2], now), Outcome::Dropped);
    assert_eq!(reassembler.stats().overflow, 1);
    assert_eq!(reassembler.pending(), 0);

    // A datagram exactly at the bound completes.
    let original = udp_v4(400 - 28, 9);
    let fragments = fragment_v4(&original, 160);
    let packet = reassemble(&mut reassembler, &fragments, &[2, 1, 0]);
    assert_eq!(packet, original);

    // IPv6 counts the unfragmentable part too.
    let fragments = fragment_v6(&udp_v6(400, true), 48, 40, 160, 10);
    assert_eq!(reassembler.push(&fragments[0], now), Outcome::Held);
    assert_eq!(reassembler.push(&fragments[2], now), Outcome::Dropped);
    assert_eq!(reassembler.stats().overflow, 2);
}

#[test]
fn timeout_expires_incomplete_datagrams() {
    let fragments = fragment_v4(&udp_v4(300, 11), 160);
    let other = fragment_v4(&udp_v4(300, 12), 160);
    let start = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    assert_eq!(reassembler.push(&fragments[0], start), Outcome::Held);
    // Age counts from the first fragment, not the latest one.
    let later = start + Duration::from_secs(20);
    assert_eq!(reassembler.push(&other[0], later), Outcome::Held);
    assert_eq!(reassembler.expire(start + Duration::from_secs(29)), 0);
    assert_eq!(reassembler.expire(start + Duration::from_secs(30)), 1);
    assert_eq!(reassembler.stats().timeout, 1);
    assert_eq!(reassembler.pending(), 1);

    // Expiry also runs when a fragment arrives; the late fragment opens a new entry.
    let late = later + Duration::from_secs(31);
    assert_eq!(reassembler.push(&fragments[1], late), Outcome::Held);
    assert_eq!(reassembler.stats().timeout, 2);
    assert_eq!(reassembler.pending(), 1);
    assert_eq!(reassembler.stats().reassembled, 0);
}

#[test]
fn non_fragments_pass() {
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyConfig::default());
    let mut df = udp_v4(100, 13);
    df[6] = 0x40;
    for packet in [
        udp_v4(100, 13),
        df,
        udp_v6(100, false),
        udp_v6(100, true),
        Vec::new(),
        vec![0x45, 0, 0],
        vec![0x60; 10],
        vec![0x12; 40],
    ] {
        assert_eq!(reassembler.push(&packet, now), Outcome::Pass, "{packet:?}");
    }
    assert_eq!(reassembler.stats(), ReassemblyStats::default());
    assert_eq!(reassembler.pending(), 0);
}
