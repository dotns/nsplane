//! Per-packet cost of the `Translator` on the `eam4` and LAN prefix paths.
//!
//! - `eam4_out/{tcp,udp}/{64B,1400B|1420B}/{1,1000}`: `outbound` of an IPv4
//!   packet from the self `eam4` to a peer's `eam4`, translated to IPv6 from the
//!   self `eam6` to the peer's `eam6`; the TCP payload is 1400 B and the
//!   UDP payload 1420 B, so both stay within a 1500 B MTU once translated.
//!   The last segment is the number of peers in the table (lookup cost).
//! - `eam4_in/...`: `inbound` of the IPv6 reply from the peer's `eam6` to
//!   the self `eam6`, translated back to IPv4 from the peer's `eam4` to the self `eam4`.
//! - `lan_out/...`, `lan_in/...`: the same from the self `eam4` to a host of
//!   the /96 LAN prefix behind the peer and back; the table has one LAN
//!   prefix per peer.
//! - `lan_remap_out/...`, `lan_remap_in/...`: the same with /120 LAN
//!   prefixes that embed 192.168.1.0/24 instead of the `lan4` network.
//!
//! Every packet is rebuilt per iteration (in a buffer with the engine's
//! headroom and room for the 20 bytes the translation adds), so each
//! iteration verifies and rewrites real checksums.

use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_nat::{LanPrefix, PeerMapping, SelfMapping, TranslationTable, Translator};
use nsplane_packet::checksum::{
    ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{PacketBuf, PeerId};

const SELF_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const SELF_EAM6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xffff, 1);
/// The peer the packets go to; the other peers only fill the table.
const PEER: PeerId = PeerId::new(1);

/// The mapping of peer `n` (1-based): `eam4` 100.65.x.y, `eam6`
/// `fd00::n:1`, `peer6` `fd00::n:0`.
const fn mapping(n: u16) -> PeerMapping {
    let [hi, lo] = n.to_be_bytes();
    PeerMapping {
        peer6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, n, 0),
        eam6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, n, 1),
        local6: None,
        eam4: Some(Ipv4Addr::new(100, 65, hi, lo)),
    }
}

/// The /96 LAN prefix behind peer `n` (1-based): `lan4` 10.x.y.0/24 and
/// `lan6` `fd64::n:0:0`.
fn lan(n: u16) -> LanPrefix {
    let [hi, lo] = n.to_be_bytes();
    LanPrefix {
        lan4: (Ipv4Addr::new(10, hi, lo, 0), 24),
        lan6: (Ipv6Addr::new(0xfd64, 0, 0, 0, 0, n, 0, 0), 96),
        peer: Some(PeerId::new(u32::from(n))),
    }
}

/// [`lan`] with the /120 `lan6` `fd64::n:c0a8:100`, which embeds
/// 192.168.1.0/24.
fn lan_remap(n: u16) -> LanPrefix {
    LanPrefix {
        lan6: (Ipv6Addr::new(0xfd64, 0, 0, 0, 0, n, 0xc0a8, 0x0100), 120),
        ..lan(n)
    }
}

/// A host of the LAN behind `PEER`, and its IPv6 address through [`lan`].
const LAN_HOST4: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 5);
const LAN_HOST6: Ipv6Addr = Ipv6Addr::new(0xfd64, 0, 0, 0, 0, 1, 0x0a00, 0x0105);
/// The IPv6 address of [`LAN_HOST4`] through [`lan_remap`].
const LAN_REMAP_HOST6: Ipv6Addr = Ipv6Addr::new(0xfd64, 0, 0, 0, 0, 1, 0xc0a8, 0x0105);

/// A table of `peers` peers, each with the LAN prefix `lan` gives it, if any.
fn table(peers: u16, lan: impl Fn(u16) -> Option<LanPrefix>) -> TranslationTable {
    let table = (1..=peers)
        .fold(TranslationTable::builder(), |builder, n| {
            let builder = builder.peer(PeerId::new(u32::from(n)), mapping(n));
            match lan(n) {
                Some(prefix) => builder.lan(prefix),
                None => builder,
            }
        })
        .self_mapping(SelfMapping {
            eam4: SELF_EAM4,
            eam6: SELF_EAM6,
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

/// An IPv4 packet from the self `eam4` to `dst`.
fn ipv4(dst: Ipv4Addr, protocol: u8, payload: usize) -> Vec<u8> {
    let mut segment = segment(protocol, payload);
    let checksum = transport_checksum_v4(SELF_EAM4, dst, protocol, &segment);
    seal(protocol, &mut segment, checksum);
    let total = u16::try_from(20 + segment.len()).unwrap_or(u16::MAX);
    let mut bytes = vec![0x45, 0];
    bytes.extend_from_slice(&total.to_be_bytes());
    bytes.extend_from_slice(&[0x12, 0x34, 0x40, 0, 64, protocol, 0, 0]);
    bytes.extend_from_slice(&SELF_EAM4.octets());
    bytes.extend_from_slice(&dst.octets());
    let checksum = ipv4_header_checksum(&bytes);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes.extend_from_slice(&segment);
    bytes
}

/// The IPv6 reply from `src` to the self `eam6`.
fn ipv6(src: Ipv6Addr, protocol: u8, payload: usize) -> Vec<u8> {
    let mut segment = segment(protocol, payload);
    let checksum = transport_checksum_v6(src, SELF_EAM6, protocol, &segment);
    seal(protocol, &mut segment, checksum);
    let len = u16::try_from(segment.len()).unwrap_or(u16::MAX);
    let mut bytes = vec![0x60, 0, 0, 0];
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(&[protocol, 64]);
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&SELF_EAM6.octets());
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

/// The `{prefix}_out` and `{prefix}_in` groups: `outbound` of IPv4 packets
/// from the self `eam4` to `dst4`, and `inbound` of the IPv6 replies from
/// `src6`, with the LAN prefixes `lan` gives each peer.
fn translate(
    c: &mut Criterion,
    prefix: &str,
    lan: impl Fn(u16) -> Option<LanPrefix> + Copy,
    dst4: Ipv4Addr,
    src6: Ipv6Addr,
) {
    for (direction, outbound) in [("out", true), ("in", false)] {
        let mut group = c.benchmark_group(format!("{prefix}_{direction}"));
        for peers in [1, 1000] {
            let translator = Translator::new(table(peers, lan));
            for (protocol, proto_name, payload) in CASES {
                let bytes = if outbound {
                    ipv4(dst4, protocol, payload)
                } else {
                    ipv6(src6, protocol, payload)
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

fn eam4(c: &mut Criterion) {
    let peer = mapping(1);
    let dst4 = peer.eam4.unwrap_or(Ipv4Addr::UNSPECIFIED);
    translate(c, "eam4", |_| None, dst4, peer.eam6);
}

fn lan96(c: &mut Criterion) {
    translate(c, "lan", |n| Some(lan(n)), LAN_HOST4, LAN_HOST6);
}

fn lan_remapped(c: &mut Criterion) {
    translate(
        c,
        "lan_remap",
        |n| Some(lan_remap(n)),
        LAN_HOST4,
        LAN_REMAP_HOST6,
    );
}

criterion_group!(benches, eam4, lan96, lan_remapped);
criterion_main!(benches);
