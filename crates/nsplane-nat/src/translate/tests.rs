//! Translator tests: filter behaviour per mapping kind, and (in `vectors`)
//! the ported ns translation tests and RFC 7915 vectors. Every translated
//! packet's checksums are verified by a full recompute.

mod vectors;

use std::net::{Ipv4Addr, Ipv6Addr};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, PeerId, protocol};

use super::{Translator, TranslatorStats, reasons};
use crate::checksum::{internet_checksum, transport_checksum_v4, transport_checksum_v6};
use crate::{LanPrefix, PeerMapping, SelfMapping, TranslationTable};

pub(super) const PEER: PeerId = PeerId::new(1);
pub(super) const OTHER: PeerId = PeerId::new(2);

pub(super) fn ip4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

pub(super) fn ip6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

pub(super) const SELF4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 100);
pub(super) const ALIAS4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
pub(super) const OTHER_ALIAS4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

pub(super) fn self_node4() -> Ipv6Addr {
    ip6("fd00::ff:1")
}

pub(super) fn peer_mapping() -> PeerMapping {
    PeerMapping {
        node6: ip6("fd00::1:0"),
        node4: ip6("fd00::1:1"),
        alias6: Some(ip6("fd99::1")),
        alias4: Some(ALIAS4),
    }
}

pub(super) fn other_mapping() -> PeerMapping {
    PeerMapping {
        node6: ip6("fd00::2:0"),
        node4: ip6("fd00::2:1"),
        alias6: None,
        alias4: Some(OTHER_ALIAS4),
    }
}

fn lan(lan4: &str, len4: u8, lan6: &str, peer: Option<PeerId>) -> LanPrefix {
    LanPrefix {
        lan4: (ip4(lan4), len4),
        lan6: (ip6(lan6), 96),
        peer,
    }
}

/// The local LAN `192.168.1.0/24 <-> fd64:1::/96`, `PEER`'s LAN
/// `10.0.0.0/8 <-> fd64:2::/96` and `OTHER`'s LAN `172.16.0.0/16 <-> fd64:3::/96`.
pub(super) fn table() -> TranslationTable {
    TranslationTable::builder()
        .peer(PEER, peer_mapping())
        .peer(OTHER, other_mapping())
        .self_mapping(SelfMapping {
            self4: SELF4,
            node4: self_node4(),
        })
        .lan(lan("192.168.1.0", 24, "fd64:1::", None))
        .lan(lan("10.0.0.0", 8, "fd64:2::", Some(PEER)))
        .lan(lan("172.16.0.0", 16, "fd64:3::", Some(OTHER)))
        .build()
        .unwrap()
}

pub(super) fn translator() -> Translator {
    Translator::new(table())
}

// --- Packet builders (ported from the ns test helpers) ---

/// The IPv4 header fields the tests vary.
#[derive(Debug, Clone, Copy)]
pub(super) struct Hdr4<'a> {
    pub(super) ttl: u8,
    pub(super) tos: u8,
    pub(super) id: u16,
    /// Flags and fragment offset.
    pub(super) fragment: u16,
    pub(super) options: &'a [u8],
}

impl Default for Hdr4<'_> {
    fn default() -> Self {
        Self {
            ttl: 64,
            tos: 0,
            id: 1,
            fragment: 0x4000,
            options: &[],
        }
    }
}

pub(super) fn ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    hdr: Hdr4<'_>,
    payload: &[u8],
) -> Vec<u8> {
    assert_eq!(hdr.options.len() % 4, 0);
    let ihl = 20 + hdr.options.len();
    let mut packet = vec![0_u8; ihl];
    packet[0] = 0x40 | u8::try_from(ihl / 4).unwrap();
    packet[1] = hdr.tos;
    packet[2..4].copy_from_slice(&u16::try_from(ihl + payload.len()).unwrap().to_be_bytes());
    packet[4..6].copy_from_slice(&hdr.id.to_be_bytes());
    packet[6..8].copy_from_slice(&hdr.fragment.to_be_bytes());
    packet[8] = hdr.ttl;
    packet[9] = proto;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..ihl].copy_from_slice(hdr.options);
    let checksum = internet_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// An unfragmented IPv4 packet with DF, TTL 64 and TOS 0.
pub(super) fn ipv4_simple(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    ipv4(src, dst, proto, Hdr4::default(), payload)
}

/// An IPv6 packet; `extensions[0]` is the first next header, the rest the
/// extension header bytes.
pub(super) fn ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    proto: u8,
    hop: u8,
    tc: u8,
    extensions: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0_u8; 40];
    packet[0] = 0x60 | (tc >> 4);
    packet[1] = tc << 4;
    let len = extensions.len().saturating_sub(1) + payload.len();
    packet[4..6].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    packet[6] = extensions.first().copied().unwrap_or(proto);
    packet[7] = hop;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    if let Some(rest) = extensions.get(1..) {
        packet.extend_from_slice(rest);
    }
    packet.extend_from_slice(payload);
    packet
}

pub(super) fn ipv6_simple(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    ipv6(src, dst, proto, 64, 0, &[], payload)
}

fn transport(header: usize, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0_u8; header];
    segment.extend_from_slice(payload);
    segment
}

fn tcp_segment(payload: &[u8]) -> Vec<u8> {
    let mut segment = transport(20, payload);
    segment[0..2].copy_from_slice(&40000_u16.to_be_bytes());
    segment[2..4].copy_from_slice(&22_u16.to_be_bytes());
    segment[12] = 0x50;
    segment[13] = 0x18;
    segment[14..16].copy_from_slice(&4096_u16.to_be_bytes());
    segment
}

fn udp_segment(payload: &[u8]) -> Vec<u8> {
    let mut segment = transport(8, payload);
    segment[0..2].copy_from_slice(&40000_u16.to_be_bytes());
    segment[2..4].copy_from_slice(&53_u16.to_be_bytes());
    let len = u16::try_from(segment.len()).unwrap();
    segment[4..6].copy_from_slice(&len.to_be_bytes());
    segment
}

pub(super) fn tcp4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut segment = tcp_segment(payload);
    let checksum = transport_checksum_v4(src, dst, protocol::TCP, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

pub(super) fn tcp6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut segment = tcp_segment(payload);
    let checksum = transport_checksum_v6(src, dst, protocol::TCP, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// A UDP datagram; `zero` leaves the checksum out.
pub(super) fn udp4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8], zero: bool) -> Vec<u8> {
    let mut segment = udp_segment(payload);
    if !zero {
        let checksum = transport_checksum_v4(src, dst, protocol::UDP, &segment);
        let wire = if checksum == 0 { 0xffff } else { checksum };
        segment[6..8].copy_from_slice(&wire.to_be_bytes());
    }
    segment
}

pub(super) fn udp6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut segment = udp_segment(payload);
    let checksum = transport_checksum_v6(src, dst, protocol::UDP, &segment);
    let wire = if checksum == 0 { 0xffff } else { checksum };
    segment[6..8].copy_from_slice(&wire.to_be_bytes());
    segment
}

pub(super) fn echo4(reply: bool, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![if reply { 0 } else { 8 }, 0, 0, 0, 0x12, 0x34, 0, 1];
    body.extend_from_slice(payload);
    let checksum = internet_checksum(&body);
    body[2..4].copy_from_slice(&checksum.to_be_bytes());
    body
}

pub(super) fn echo6(src: Ipv6Addr, dst: Ipv6Addr, reply: bool, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![if reply { 129 } else { 128 }, 0, 0, 0, 0x12, 0x34, 0, 1];
    body.extend_from_slice(payload);
    let checksum = transport_checksum_v6(src, dst, protocol::ICMPV6, &body);
    body[2..4].copy_from_slice(&checksum.to_be_bytes());
    body
}

pub(super) fn icmp4_error(kind: u8, code: u8, rest: [u8; 4], quote: &[u8]) -> Vec<u8> {
    let mut body = vec![kind, code, 0, 0];
    body.extend_from_slice(&rest);
    body.extend_from_slice(quote);
    let checksum = internet_checksum(&body);
    body[2..4].copy_from_slice(&checksum.to_be_bytes());
    body
}

pub(super) fn icmp6_error(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    kind: u8,
    code: u8,
    rest: [u8; 4],
    quote: &[u8],
) -> Vec<u8> {
    let mut body = vec![kind, code, 0, 0];
    body.extend_from_slice(&rest);
    body.extend_from_slice(quote);
    let checksum = transport_checksum_v6(src, dst, protocol::ICMPV6, &body);
    body[2..4].copy_from_slice(&checksum.to_be_bytes());
    body
}

// --- Running and checking ---

/// A buffer holding `bytes` with room to grow.
pub(super) fn buf(bytes: &[u8]) -> PacketBuf {
    let mut packet = PacketBuf::with_capacity(bytes.len() + 64);
    packet.set_len(bytes.len());
    packet.as_packet_mut().copy_from_slice(bytes);
    packet
}

pub(super) fn outbound(translator: &Translator, peer: PeerId, bytes: &[u8]) -> (Verdict, Vec<u8>) {
    let mut packet = buf(bytes);
    let verdict = translator.outbound(peer, &mut packet);
    (verdict, packet.as_packet().to_vec())
}

pub(super) fn inbound(translator: &Translator, peer: PeerId, bytes: &[u8]) -> (Verdict, Vec<u8>) {
    let mut packet = buf(bytes);
    let verdict = translator.inbound(peer, &mut packet);
    (verdict, packet.as_packet().to_vec())
}

/// Translates outbound and expects acceptance.
pub(super) fn out_ok(bytes: &[u8]) -> Vec<u8> {
    let (verdict, packet) = outbound(&translator(), PEER, bytes);
    assert_eq!(verdict, Verdict::Accept);
    packet
}

/// Translates inbound and expects acceptance.
pub(super) fn in_ok(bytes: &[u8]) -> Vec<u8> {
    let (verdict, packet) = inbound(&translator(), PEER, bytes);
    assert_eq!(verdict, Verdict::Accept);
    packet
}

pub(super) fn out_drop(bytes: &[u8]) -> &'static str {
    match outbound(&translator(), PEER, bytes).0 {
        Verdict::Drop { reason } => reason,
        other => panic!("expected a drop, got {other:?}"),
    }
}

pub(super) fn in_drop(bytes: &[u8]) -> &'static str {
    match inbound(&translator(), PEER, bytes).0 {
        Verdict::Drop { reason } => reason,
        other => panic!("expected a drop, got {other:?}"),
    }
}

pub(super) fn src6(packet: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap())
}

pub(super) fn dst6(packet: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap())
}

pub(super) fn src4(packet: &[u8]) -> Ipv4Addr {
    Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap())
}

pub(super) fn dst4(packet: &[u8]) -> Ipv4Addr {
    Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap())
}

/// Checks the IPv6 header lengths and, for an unfragmented packet or a first
/// fragment carrying the whole segment, the TCP/UDP/`ICMPv6` checksum.
/// Returns the upper-layer offset.
pub(super) fn check_v6(packet: &[u8]) -> usize {
    assert_eq!(packet[0] >> 4, 6);
    assert_eq!(packet[1] & 0x0f, 0, "flow label");
    assert_eq!(&packet[2..4], &[0, 0], "flow label");
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40,
        packet.len()
    );
    let (proto, start, fragmented) = if packet[6] == 44 {
        (packet[40], 48, true)
    } else {
        (packet[6], 40, false)
    };
    if !fragmented && matches!(proto, protocol::TCP | protocol::UDP | protocol::ICMPV6) {
        assert_eq!(
            transport_checksum_v6(src6(packet), dst6(packet), proto, &packet[start..]),
            0,
            "IPv6 upper-layer checksum"
        );
    }
    start
}

/// Checks the IPv4 header checksum and lengths and, for an unfragmented
/// packet, the TCP/UDP/ICMP checksum.
pub(super) fn check_v4(packet: &[u8]) {
    assert_eq!(packet[0], 0x45);
    assert_eq!(internet_checksum(&packet[..20]), 0, "IPv4 header checksum");
    assert_eq!(
        usize::from(u16::from_be_bytes([packet[2], packet[3]])),
        packet.len()
    );
    let fragmented = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
    if fragmented {
        return;
    }
    let segment = &packet[20..];
    match packet[9] {
        protocol::TCP | protocol::UDP => assert_eq!(
            transport_checksum_v4(src4(packet), dst4(packet), packet[9], segment),
            0,
            "IPv4 transport checksum"
        ),
        protocol::ICMP => assert_eq!(internet_checksum(segment), 0, "ICMP checksum"),
        _ => {}
    }
}

fn traffic_class(packet: &[u8]) -> u8 {
    ((packet[0] & 0x0f) << 4) | (packet[1] >> 4)
}

// --- Outbound ---

#[test]
fn outbound_alias4_from_self4_becomes_ipv6_to_node4() {
    for proto in [protocol::TCP, protocol::UDP] {
        let body = if proto == protocol::TCP {
            tcp4(SELF4, ALIAS4, b"odd")
        } else {
            udp4(SELF4, ALIAS4, b"odd", false)
        };
        let hdr = Hdr4 {
            tos: 0xeb,
            id: 7,
            ..Hdr4::default()
        };
        let packet = ipv4(SELF4, ALIAS4, proto, hdr, &body);
        let v6 = out_ok(&packet);
        assert_eq!(v6.len(), packet.len() + 20);
        check_v6(&v6);
        assert_eq!((src6(&v6), dst6(&v6)), (self_node4(), peer_mapping().node4));
        assert_eq!((v6[6], v6[7], traffic_class(&v6)), (proto, 63, 0xeb));
        assert_eq!(&v6[40..], {
            let mut expected = body.clone();
            let at = if proto == protocol::TCP { 16 } else { 6 };
            expected[at..at + 2].copy_from_slice(&v6[40 + at..42 + at]);
            expected
        });
    }
}

#[test]
fn outbound_lan4_becomes_lan6_on_both_sides() {
    let (src, dst) = (ip4("192.168.1.20"), ip4("10.1.2.3"));
    let packet = ipv4_simple(src, dst, protocol::UDP, &udp4(src, dst, b"lan", false));
    let v6 = out_ok(&packet);
    check_v6(&v6);
    assert_eq!(src6(&v6), ip6("fd64:1::c0a8:114"));
    assert_eq!(dst6(&v6), ip6("fd64:2::a01:203"));

    // A LAN source towards a peer alias.
    let packet = ipv4_simple(src, ALIAS4, protocol::UDP, &udp4(src, ALIAS4, b"x", false));
    let v6 = out_ok(&packet);
    check_v6(&v6);
    assert_eq!(
        (src6(&v6), dst6(&v6)),
        (ip6("fd64:1::c0a8:114"), peer_mapping().node4)
    );
}

#[test]
fn outbound_mapping_of_another_peer_is_dropped() {
    let udp = |dst| ipv4_simple(SELF4, dst, protocol::UDP, &udp4(SELF4, dst, b"x", false));
    assert_eq!(out_drop(&udp(OTHER_ALIAS4)), reasons::PEER_MISMATCH);
    assert_eq!(out_drop(&udp(ip4("172.16.0.9"))), reasons::PEER_MISMATCH);
    let alias6 = peer_mapping().alias6.unwrap();
    let packet = ipv6_simple(
        ip6("fd00::ff:0"),
        alias6,
        protocol::UDP,
        &udp6(ip6("fd00::ff:0"), alias6, b"x"),
    );
    let (verdict, _) = outbound(&translator(), OTHER, &packet);
    assert_eq!(
        verdict,
        Verdict::Drop {
            reason: reasons::PEER_MISMATCH
        }
    );
}

#[test]
fn outbound_unmapped_source_is_dropped() {
    for src in [ip4("198.51.100.7"), ALIAS4, ip4("10.0.0.5")] {
        let packet = ipv4_simple(src, ALIAS4, protocol::UDP, &udp4(src, ALIAS4, b"x", false));
        assert_eq!(out_drop(&packet), reasons::UNMAPPED, "{src}");
    }
}

#[test]
fn native_packets_pass_unchanged() {
    let translator = translator();
    let dst = ip4("198.51.100.1");
    let native4 = ipv4_simple(SELF4, dst, protocol::UDP, &udp4(SELF4, dst, b"x", false));
    let (dst6, own6) = (ip6("2001:db8::1"), ip6("fd00::ff:0"));
    let native6 = ipv6_simple(own6, dst6, protocol::UDP, &udp6(own6, dst6, b"x"));
    // A local LAN destination is not a translated one either.
    let local_lan = ipv4_simple(
        SELF4,
        ip4("192.168.1.9"),
        protocol::ICMP,
        &echo4(false, b""),
    );
    for packet in [
        native4,
        native6,
        local_lan,
        vec![0x45; 10],
        vec![0x60; 20],
        vec![],
    ] {
        assert_eq!(
            outbound(&translator, PEER, &packet),
            (Verdict::Accept, packet.clone())
        );
        assert_eq!(
            inbound(&translator, PEER, &packet),
            (Verdict::Accept, packet)
        );
    }
    // Native IPv6 between the peer's node6 and ours, and to a node4 that is
    // not ours, passes inbound.
    let node6 = other_mapping().node6;
    let packet = ipv6_simple(node6, own6, protocol::UDP, &udp6(node6, own6, b"x"));
    assert_eq!(
        inbound(&translator, OTHER, &packet),
        (Verdict::Accept, packet)
    );
    assert_eq!(translator.stats(), TranslatorStats::default());
}

#[test]
fn outbound_alias6_is_rewritten_to_node6() {
    let (src, alias6, node6) = (
        ip6("fd00::ff:0"),
        peer_mapping().alias6.unwrap(),
        peer_mapping().node6,
    );
    for (proto, body) in [
        (protocol::TCP, tcp6(src, alias6, b"tcp")),
        (protocol::UDP, udp6(src, alias6, b"udp")),
        (protocol::ICMPV6, echo6(src, alias6, false, b"ping")),
    ] {
        let packet = ipv6_simple(src, alias6, proto, &body);
        let rewritten = out_ok(&packet);
        assert_eq!(rewritten.len(), packet.len());
        assert_eq!((src6(&rewritten), dst6(&rewritten)), (src, node6));
        assert_eq!(rewritten[7], 64, "6 -> 6 keeps the hop limit");
        check_v6(&rewritten);
    }
}

// --- Inbound ---

#[test]
fn inbound_node4_to_self_becomes_ipv4_from_alias4() {
    let (src, dst) = (peer_mapping().node4, self_node4());
    for (proto, body) in [
        (protocol::TCP, tcp6(src, dst, b"odd")),
        (protocol::UDP, udp6(src, dst, b"odd")),
        (protocol::ICMPV6, echo6(src, dst, true, b"pong")),
    ] {
        let packet = ipv6(src, dst, proto, 9, 0x2e, &[], &body);
        let v4 = in_ok(&packet);
        assert_eq!(v4.len(), packet.len() - 20);
        check_v4(&v4);
        assert_eq!((src4(&v4), dst4(&v4)), (ALIAS4, SELF4));
        let proto4 = if proto == protocol::ICMPV6 {
            protocol::ICMP
        } else {
            proto
        };
        assert_eq!((v4[1], v4[8], v4[9]), (0x2e, 8, proto4));
    }
}

#[test]
fn inbound_lan6_becomes_lan4_on_both_sides() {
    let (src, dst) = (ip6("fd64:2::a01:203"), ip6("fd64:1::c0a8:114"));
    let packet = ipv6_simple(src, dst, protocol::UDP, &udp6(src, dst, b"lan"));
    let v4 = in_ok(&packet);
    check_v4(&v4);
    assert_eq!(
        (src4(&v4), dst4(&v4)),
        (ip4("10.1.2.3"), ip4("192.168.1.20"))
    );

    // The peer's node4 towards a local LAN host.
    let src = peer_mapping().node4;
    let packet = ipv6_simple(src, dst, protocol::UDP, &udp6(src, dst, b"x"));
    let v4 = in_ok(&packet);
    check_v4(&v4);
    assert_eq!((src4(&v4), dst4(&v4)), (ALIAS4, ip4("192.168.1.20")));
}

#[test]
fn inbound_source_must_belong_to_the_peer() {
    let dst = self_node4();
    let udp = |src| ipv6_simple(src, dst, protocol::UDP, &udp6(src, dst, b"x"));
    assert_eq!(in_drop(&udp(other_mapping().node4)), reasons::PEER_MISMATCH);
    assert_eq!(in_drop(&udp(ip6("fd64:3::ac10:1"))), reasons::PEER_MISMATCH);
    assert_eq!(
        in_drop(&udp(ip6("fd64:1::c0a8:101"))),
        reasons::SPOOFED_SOURCE
    );
    assert_eq!(in_drop(&udp(peer_mapping().node6)), reasons::UNMAPPED);
    assert_eq!(in_drop(&udp(ip6("2001:db8::1"))), reasons::UNMAPPED);
}

#[test]
fn inbound_node6_is_rewritten_to_alias6() {
    let (node6, dst) = (peer_mapping().node6, ip6("fd00::ff:0"));
    let packet = ipv6_simple(node6, dst, protocol::TCP, &tcp6(node6, dst, b"hello"));
    let rewritten = in_ok(&packet);
    check_v6(&rewritten);
    assert_eq!(
        (src6(&rewritten), dst6(&rewritten)),
        (peer_mapping().alias6.unwrap(), dst)
    );

    // A peer without an alias6 keeps its node6.
    let node6 = other_mapping().node6;
    let packet = ipv6_simple(node6, dst, protocol::UDP, &udp6(node6, dst, b"x"));
    assert_eq!(
        inbound(&translator(), OTHER, &packet),
        (Verdict::Accept, packet)
    );
}

#[test]
fn inbound_spoofed_local_view_sources_are_dropped() {
    for src in [ALIAS4, OTHER_ALIAS4, ip4("10.0.0.1"), ip4("192.168.1.1")] {
        let packet = ipv4_simple(src, SELF4, protocol::UDP, &udp4(src, SELF4, b"x", false));
        assert_eq!(in_drop(&packet), reasons::SPOOFED_SOURCE, "{src}");
    }
    let (alias6, dst) = (peer_mapping().alias6.unwrap(), ip6("fd00::ff:0"));
    let packet = ipv6_simple(alias6, dst, protocol::UDP, &udp6(alias6, dst, b"x"));
    assert_eq!(in_drop(&packet), reasons::SPOOFED_SOURCE);
}

// --- Table swap, predicate, buffers, counters ---

#[test]
fn store_swaps_the_table_atomically() {
    let translator = translator();
    let packet = ipv4_simple(
        SELF4,
        ALIAS4,
        protocol::UDP,
        &udp4(SELF4, ALIAS4, b"x", false),
    );
    assert_eq!(
        dst6(&outbound(&translator, PEER, &packet).1),
        peer_mapping().node4
    );

    let moved = PeerMapping {
        node6: ip6("fd00::9:0"),
        node4: ip6("fd00::9:1"),
        ..peer_mapping()
    };
    let next = TranslationTable::builder()
        .peer(PEER, moved)
        .self_mapping(SelfMapping {
            self4: SELF4,
            node4: self_node4(),
        })
        .build()
        .unwrap();
    let before = translator.table();
    translator.store(next);
    assert!(
        before.peer(OTHER).is_some(),
        "the old snapshot stays intact"
    );
    assert!(translator.table().peer(OTHER).is_none());
    let (verdict, v6) = outbound(&translator, PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    assert_eq!(dst6(&v6), moved.node4);
    check_v6(&v6);
}

#[test]
fn predicate_follows_the_current_table() {
    let translator = translator();
    let translated = translator.ipv4_translated_predicate();
    for (addr, expected) in [
        (ALIAS4, true),
        (OTHER_ALIAS4, true),
        (ip4("10.200.0.1"), true),
        (ip4("172.16.255.255"), true),
        (ip4("192.168.1.1"), false),
        (SELF4, false),
        (ip4("198.51.100.1"), false),
    ] {
        assert_eq!(translated(addr), expected, "{addr}");
    }
    translator.store(TranslationTable::default());
    assert!(!translated(ALIAS4));
    assert!(!translated(ip4("10.200.0.1")));
    translator.store(table());
    assert!(translated(ALIAS4));
}

#[test]
fn packets_that_cannot_grow_are_dropped() {
    let packet = ipv4_simple(
        SELF4,
        ALIAS4,
        protocol::UDP,
        &udp4(SELF4, ALIAS4, b"x", false),
    );
    let mut tight = PacketBuf::with_capacity(packet.len() + 19);
    tight.set_len(packet.len());
    tight.as_packet_mut().copy_from_slice(&packet);
    if tight.capacity() < packet.len() + 20 {
        assert_eq!(
            translator().outbound(PEER, &mut tight),
            Verdict::Drop {
                reason: reasons::NO_ROOM
            }
        );
    }
    let mut exact = PacketBuf::with_capacity(packet.len() + 20);
    exact.set_len(packet.len());
    exact.as_packet_mut().copy_from_slice(&packet);
    assert_eq!(translator().outbound(PEER, &mut exact), Verdict::Accept);
    check_v6(exact.as_packet());
}

#[test]
fn stats_count_each_outcome() {
    let translator = translator();
    let out = ipv4_simple(
        SELF4,
        ALIAS4,
        protocol::UDP,
        &udp4(SELF4, ALIAS4, b"x", false),
    );
    let mismatch = ipv4_simple(
        SELF4,
        OTHER_ALIAS4,
        protocol::UDP,
        &udp4(SELF4, OTHER_ALIAS4, b"x", false),
    );
    let (node4, own) = (peer_mapping().node4, self_node4());
    let back = ipv6_simple(node4, own, protocol::UDP, &udp6(node4, own, b"x"));
    let (node6, dst) = (peer_mapping().node6, ip6("fd00::ff:0"));
    let rewrite = ipv6_simple(node6, dst, protocol::UDP, &udp6(node6, dst, b"x"));
    let spoof = ipv4_simple(
        ALIAS4,
        SELF4,
        protocol::UDP,
        &udp4(ALIAS4, SELF4, b"x", false),
    );
    outbound(&translator, PEER, &out);
    outbound(&translator, PEER, &out);
    outbound(&translator, PEER, &mismatch);
    inbound(&translator, PEER, &back);
    inbound(&translator, PEER, &rewrite);
    inbound(&translator, PEER, &spoof);
    assert_eq!(
        translator.stats(),
        TranslatorStats {
            translated_out: 2,
            translated_in: 1,
            rewritten_out: 0,
            rewritten_in: 1,
            dropped_out: 1,
            dropped_in: 1,
            reassembled: 0,
        }
    );
}

// --- Fragments through the filter ---

fn fragment4(id: u16, offset_units: u16, more: bool, ttl: u8, bytes: &[u8]) -> Vec<u8> {
    let flags = offset_units | if more { 0x2000 } else { 0 };
    let hdr = Hdr4 {
        ttl,
        tos: 0x03,
        id,
        fragment: flags,
        options: &[],
    };
    ipv4(SELF4, ALIAS4, protocol::UDP, hdr, bytes)
}

#[test]
fn zero_checksum_udp_fragments_are_reassembled_in_order() {
    let translator = translator();
    let udp = udp4(SELF4, ALIAS4, b"abcdefghijklmnopqrstuvwx", true);
    let first = fragment4(77, 0, true, 2, &udp[..16]);
    let middle = fragment4(77, 2, true, 64, &udp[16..24]);
    let last = fragment4(77, 3, false, 64, &udp[24..]);
    assert_eq!(outbound(&translator, PEER, &first).0, Verdict::Handled);
    assert_eq!(outbound(&translator, PEER, &middle).0, Verdict::Handled);
    let (verdict, v6) = outbound(&translator, PEER, &last);
    assert_eq!(verdict, Verdict::Accept);
    assert_eq!((v6[6], v6[7], v6.len()), (protocol::UDP, 1, 72));
    check_v6(&v6);
    assert_eq!(&v6[48..], b"abcdefghijklmnopqrstuvwx");
    assert_eq!(translator.stats().reassembled, 1);
    assert_eq!(translator.stats().translated_out, 1);
}

#[test]
fn zero_checksum_tail_before_its_first_fragment_is_translated_alone() {
    let translator = translator();
    let udp = udp4(SELF4, ALIAS4, b"abcdefghijklmnopqrstuvwx", true);
    let tail = fragment4(78, 2, false, 64, &udp[16..]);
    let (verdict, v6) = outbound(&translator, PEER, &tail);
    assert_eq!(verdict, Verdict::Accept);
    assert_eq!((v6[6], v6[40]), (44, protocol::UDP));
    // The first fragment opens an entry that can no longer complete.
    let first = fragment4(78, 0, true, 64, &udp[..16]);
    assert_eq!(outbound(&translator, PEER, &first).0, Verdict::Handled);
    assert_eq!(translator.stats().reassembled, 0);
}

#[test]
fn checksummed_udp_fragments_are_translated_one_by_one() {
    let translator = translator();
    let udp = udp4(SELF4, ALIAS4, b"abcdefghijklmnopqrstuvwx", false);
    let pieces = [
        fragment4(100, 0, true, 2, &udp[..16]),
        fragment4(100, 2, true, 64, &udp[16..24]),
        fragment4(100, 3, false, 255, &udp[24..]),
    ];
    let mut joined = Vec::new();
    for (index, piece) in pieces.iter().enumerate() {
        let (verdict, v6) = outbound(&translator, PEER, piece);
        assert_eq!(verdict, Verdict::Accept);
        assert_eq!(v6.len(), piece.len() + 28);
        assert_eq!(check_v6(&v6), 48);
        let bits = u16::from_be_bytes([v6[42], v6[43]]);
        assert_eq!(usize::from(bits >> 3), [0, 2, 3][index]);
        assert_eq!(bits & 1 == 1, index < 2);
        assert_eq!(&v6[44..48], &100_u32.to_be_bytes());
        assert_eq!(v6[7], [1, 63, 254][index]);
        joined.extend_from_slice(&v6[48..]);
    }
    assert_eq!(
        transport_checksum_v6(self_node4(), peer_mapping().node4, protocol::UDP, &joined),
        0
    );
}

#[test]
fn ipv6_fragments_become_ipv4_fragments_inbound() {
    let (src, dst) = (peer_mapping().node4, self_node4());
    let udp = udp6(src, dst, b"abcdefghijklmnopqrstuvwx");
    let mut joined = Vec::new();
    for (offset, more, bytes) in [(0_u16, true, &udp[..16]), (2, false, &udp[16..])] {
        let bits = (offset << 3) | u16::from(more);
        let mut extension = vec![44, protocol::UDP, 0];
        extension.extend_from_slice(&bits.to_be_bytes());
        extension.extend_from_slice(&0x0102_abcd_u32.to_be_bytes());
        let packet = ipv6(src, dst, protocol::UDP, 64, 0, &extension, bytes);
        let v4 = in_ok(&packet);
        check_v4(&v4);
        assert_eq!(v4.len(), packet.len() - 28);
        assert_eq!(&v4[4..6], &0xabcd_u16.to_be_bytes());
        let flags = u16::from_be_bytes([v4[6], v4[7]]);
        assert_eq!(flags, offset | if more { 0x2000 } else { 0 });
        joined.extend_from_slice(&v4[20..]);
    }
    assert_eq!(
        transport_checksum_v4(ALIAS4, SELF4, protocol::UDP, &joined),
        0
    );
}
