//! Per-packet cost of the `Translator` on the `alias4` path.
//!
//! - `alias4_out/{tcp,udp}/{64B,1400B|1420B}/{1,1000}`: `outbound` of an IPv4
//!   packet from `self4` to a peer's `alias4`, translated to IPv6 from the
//!   self `node4` to the peer's `node4`; the TCP payload is 1400 B and the
//!   UDP payload 1420 B, so both stay within a 1500 B MTU once translated.
//!   The last segment is the number of peers in the table (lookup cost).
//! - `alias4_in/...`: `inbound` of the IPv6 reply from the peer's `node4` to
//!   the self `node4`, translated back to IPv4 from the `alias4` to `self4`.
//!
//! Every packet is rebuilt per iteration (in a buffer with the engine's
//! headroom and room for the 20 bytes the translation adds), so each
//! iteration verifies and rewrites real checksums.

use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_nat::{PeerMapping, SelfMapping, TranslationTable, Translator};
use nsplane_packet::checksum::{
    ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{PacketBuf, PeerId};

const SELF4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const SELF_NODE4: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xffff, 1);
/// The peer the packets go to; the other peers only fill the table.
const PEER: PeerId = PeerId::new(1);

/// The mapping of peer `n` (1-based): `alias4` 100.65.x.y, `node4`
/// `fd00::n:1`, `node6` `fd00::n:0`.
const fn mapping(n: u16) -> PeerMapping {
    let [hi, lo] = n.to_be_bytes();
    PeerMapping {
        node6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, n, 0),
        node4: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, n, 1),
        alias6: None,
        alias4: Some(Ipv4Addr::new(100, 65, hi, lo)),
    }
}

fn table(peers: u16) -> TranslationTable {
    let table = (1..=peers)
        .fold(TranslationTable::builder(), |builder, n| {
            builder.peer(PeerId::new(u32::from(n)), mapping(n))
        })
        .self_mapping(SelfMapping {
            self4: SELF4,
            node4: SELF_NODE4,
        })
        .build();
    assert!(table.is_ok(), "invalid table");
    table.unwrap_or_default()
}

/// A TCP (20-byte header) or UDP segment with `payload` bytes; the checksum
/// field is left zero.
fn segment(protocol: u8, payload: usize) -> Vec<u8> {
    let header = if protocol == 6 { 20 } else { 8 };
    let mut segment: Vec<u8> = (0..=u8::MAX).cycle().take(header + payload).collect();
    segment[0..4].copy_from_slice(&[0xc3, 0x50, 0x14, 0x51]);
    if protocol == 6 {
        segment[12] = 0x50;
        segment[16..18].fill(0);
    } else {
        let len = u16::try_from(segment.len()).unwrap_or(u16::MAX);
        segment[4..6].copy_from_slice(&len.to_be_bytes());
        segment[6..8].fill(0);
    }
    segment
}

/// Writes a checksum into `segment` (TCP at 16, UDP at 6; UDP never zero).
fn seal(protocol: u8, segment: &mut [u8], checksum: u16) {
    let (at, checksum) = if protocol == 6 {
        (16, checksum)
    } else {
        (6, if checksum == 0 { 0xffff } else { checksum })
    };
    segment[at..at + 2].copy_from_slice(&checksum.to_be_bytes());
}

/// An IPv4 packet from `self4` to the peer's `alias4`.
fn ipv4(protocol: u8, payload: usize) -> Vec<u8> {
    let dst = Ipv4Addr::new(100, 65, 0, 1);
    let mut segment = segment(protocol, payload);
    let checksum = transport_checksum_v4(SELF4, dst, protocol, &segment);
    seal(protocol, &mut segment, checksum);
    let total = u16::try_from(20 + segment.len()).unwrap_or(u16::MAX);
    let mut bytes = vec![0x45, 0];
    bytes.extend_from_slice(&total.to_be_bytes());
    bytes.extend_from_slice(&[0x12, 0x34, 0x40, 0, 64, protocol, 0, 0]);
    bytes.extend_from_slice(&SELF4.octets());
    bytes.extend_from_slice(&dst.octets());
    let checksum = ipv4_header_checksum(&bytes);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes.extend_from_slice(&segment);
    bytes
}

/// The IPv6 reply from the peer's `node4` to the self `node4`.
fn ipv6(protocol: u8, payload: usize) -> Vec<u8> {
    let src = mapping(1).node4;
    let mut segment = segment(protocol, payload);
    let checksum = transport_checksum_v6(src, SELF_NODE4, protocol, &segment);
    seal(protocol, &mut segment, checksum);
    let len = u16::try_from(segment.len()).unwrap_or(u16::MAX);
    let mut bytes = vec![0x60, 0, 0, 0];
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(&[protocol, 64]);
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&SELF_NODE4.octets());
    bytes.extend_from_slice(&segment);
    bytes
}

/// A packet buffer holding `bytes`, with room for the translation to grow it.
fn buffer(bytes: &[u8]) -> PacketBuf {
    let mut packet = PacketBuf::with_capacity(bytes.len() + 28);
    packet.extend_from_slice(bytes);
    packet
}

/// The (protocol, name, payload) cases.
const CASES: [(u8, &str, usize); 4] = [
    (6, "tcp", 64),
    (6, "tcp", 1400),
    (17, "udp", 64),
    (17, "udp", 1420),
];

fn alias4(c: &mut Criterion) {
    for (name, outbound) in [("alias4_out", true), ("alias4_in", false)] {
        let mut group = c.benchmark_group(name);
        for peers in [1, 1000] {
            let translator = Translator::new(table(peers));
            for (protocol, proto_name, payload) in CASES {
                let bytes = if outbound {
                    ipv4(protocol, payload)
                } else {
                    ipv6(protocol, payload)
                };
                let filter = |packet: &mut PacketBuf| {
                    if outbound {
                        translator.outbound(PEER, packet)
                    } else {
                        translator.inbound(PEER, packet)
                    }
                };
                assert_eq!(filter(&mut buffer(&bytes)), Verdict::Accept);
                group.bench_function(format!("{proto_name}/{payload}B/{peers}"), |b| {
                    b.iter_batched_ref(
                        || buffer(&bytes),
                        |packet| filter(black_box(packet)),
                        BatchSize::SmallInput,
                    );
                });
            }
            let stats = translator.stats();
            assert_eq!(stats.dropped_out + stats.dropped_in, 0);
            assert_eq!(stats.grown_copies, 0);
        }
        group.finish();
    }
}

criterion_group!(benches, alias4);
criterion_main!(benches);
