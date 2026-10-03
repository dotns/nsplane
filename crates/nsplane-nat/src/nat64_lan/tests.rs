//! Tests of the NAT64-to-LAN translator, adapted from ns
//! `subnet_route/tests.rs` to in-place translation on `PacketBuf`, plus the
//! flow lifetime (port reservation, expiry, eviction, removal) and route
//! replacement.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use nsplane::{PacketSink, PacketSource};
use nsplane_packet::{PacketBatch, PacketBuf, PeerId, protocol};

use super::*;
use crate::checksum::{
    internet_checksum, ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6, valid,
};

const CLIENT: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
/// `192.168.7.1` inside the mapped /96.
const HOST6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 7, 0xc0a8, 0x0701);
const HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 7, 1);
const SNAT: Ipv4Addr = Ipv4Addr::new(192, 168, 7, 254);
const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 7, 253);
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;

fn mapped(host: Ipv4Addr) -> Ipv6Addr {
    let [a, b, c, d] = host.octets();
    let prefix = Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 7, 0, 0).octets();
    let mut octets = prefix;
    octets[12..].copy_from_slice(&[a, b, c, d]);
    Ipv6Addr::from(octets)
}

fn route() -> LanRoute {
    LanRoute::new(
        (Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 7, 0, 0), 96),
        (Ipv4Addr::new(192, 168, 7, 0), 24),
        SNAT,
    )
    .unwrap()
}

fn routes(routes: Vec<LanRoute>) -> Arc<ArcSwap<Vec<LanRoute>>> {
    Arc::new(ArcSwap::from_pointee(routes))
}

fn lan() -> Nat64Lan {
    Nat64Lan::new(routes(vec![route()]), Nat64LanConfig::default())
}

fn config(max_tcp_mss: Option<u16>) -> Nat64LanConfig {
    Nat64LanConfig {
        max_tcp_mss,
        ..Nat64LanConfig::default()
    }
}

// -- Packet builders: every packet carries valid checksums. --

fn udp(src_port: u16, dst_port: u16, data: &[u8]) -> Vec<u8> {
    let mut segment = vec![0; 8];
    segment[0..2].copy_from_slice(&src_port.to_be_bytes());
    segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
    segment[4..6].copy_from_slice(&u16::try_from(8 + data.len()).unwrap().to_be_bytes());
    segment.extend_from_slice(data);
    segment
}

fn tcp(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8, options: &[u8]) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let mut segment = vec![0; 20];
    segment[0..2].copy_from_slice(&src_port.to_be_bytes());
    segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
    segment[4..8].copy_from_slice(&seq.to_be_bytes());
    segment[8..12].copy_from_slice(&ack.to_be_bytes());
    segment[12] = u8::try_from(((20 + options.len()) / 4) << 4).unwrap();
    segment[13] = flags;
    segment[14..16].copy_from_slice(&65535_u16.to_be_bytes());
    segment.extend_from_slice(options);
    segment
}

/// An MSS option.
fn mss(value: u16) -> [u8; 4] {
    let [hi, lo] = value.to_be_bytes();
    [2, 4, hi, lo]
}

fn echo(kind: u8, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![kind, 0, 0, 0];
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(data);
    message
}

/// The offset of the checksum in a transport header.
const fn checksum_at(protocol: u8) -> usize {
    match protocol {
        protocol::TCP => 16,
        protocol::UDP => 6,
        _ => 2,
    }
}

fn ipv6_bytes(next: u8, src: Ipv6Addr, dst: Ipv6Addr, mut segment: Vec<u8>) -> Vec<u8> {
    let at = checksum_at(next);
    if matches!(next, protocol::TCP | protocol::UDP | protocol::ICMPV6) && segment.len() >= at + 2 {
        segment[at..at + 2].fill(0);
        let checksum = transport_checksum_v6(src, dst, next, &segment);
        segment[at..at + 2].copy_from_slice(&checksum.to_be_bytes());
    }
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    packet[6] = next;
    packet[7] = 63;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    packet.extend_from_slice(&segment);
    packet
}

fn ipv6(next: u8, segment: Vec<u8>) -> PacketBuf {
    PacketBuf::from_packet(&ipv6_bytes(next, CLIENT, HOST6, segment))
}

fn ipv4_bytes(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, mut segment: Vec<u8>) -> Vec<u8> {
    let at = checksum_at(protocol);
    segment[at..at + 2].fill(0);
    let checksum = if protocol == protocol::ICMP {
        internet_checksum(&segment)
    } else {
        transport_checksum_v4(src, dst, protocol, &segment)
    };
    segment[at..at + 2].copy_from_slice(&checksum.to_be_bytes());
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(20 + segment.len()).unwrap().to_be_bytes());
    packet[8] = 50;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&segment);
    packet
}

/// A LAN reply from `HOST` to the SNAT address.
fn reply(protocol: u8, segment: Vec<u8>) -> PacketBuf {
    PacketBuf::from_packet(&ipv4_bytes(protocol, HOST, SNAT, segment))
}

/// An ICMP Fragmentation Needed from the LAN router quoting `quoted`.
fn fragmentation_needed(mtu: u16, quoted: &[u8]) -> PacketBuf {
    let mut message = vec![3, 4, 0, 0, 0, 0];
    message.extend_from_slice(&mtu.to_be_bytes());
    message.extend_from_slice(&quoted[..28]);
    PacketBuf::from_packet(&ipv4_bytes(protocol::ICMP, ROUTER, SNAT, message))
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// Asserts that an IPv4 packet's header and transport checksums are valid.
fn assert_valid4(packet: &[u8]) {
    assert_eq!(packet[0], 0x45);
    assert_eq!(usize::from(be16(packet, 2)), packet.len());
    assert!(valid(&packet[..20]), "IPv4 header checksum");
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let segment = &packet[20..];
    if packet[9] == protocol::ICMP {
        assert!(valid(segment), "ICMP checksum");
    } else {
        assert_eq!(transport_checksum_v4(src, dst, packet[9], segment), 0);
    }
}

/// Asserts that an IPv6 packet's transport checksum is valid.
fn assert_valid6(packet: &[u8]) {
    assert_eq!(packet[0] >> 4, 6);
    assert_eq!(usize::from(be16(packet, 4)) + 40, packet.len());
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
    assert_eq!(transport_checksum_v6(src, dst, packet[6], &packet[40..]), 0);
}

/// Forwards a UDP request from `CLIENT:4321` to `HOST6:53` and returns the
/// translated packet.
fn forward_udp(lan: &Nat64Lan) -> Vec<u8> {
    let mut packet = ipv6(protocol::UDP, udp(4321, 53, b"query"));
    assert_eq!(lan.forward(&mut packet), Nat64Verdict::Translated);
    packet.as_packet().to_vec()
}

/// Asserts that `call` leaves `packet` alone.
fn assert_not_ours(packet: &mut PacketBuf, call: impl Fn(&mut PacketBuf) -> Nat64Verdict) {
    let before = packet.as_packet().to_vec();
    assert_eq!(call(packet), Nat64Verdict::NotOurs);
    assert_eq!(packet.as_packet(), before.as_slice());
}

// -- Routes (ns `SubnetRoute`). --

#[test]
fn resolves_only_the_configured_virtual_prefix() {
    let route = route();
    assert_eq!(route.resolve(HOST6), Some(HOST));
    assert_eq!(
        route.resolve(Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 8, 0xc0a8, 0x0701)),
        None
    );
    assert_eq!(route.resolve(mapped(Ipv4Addr::new(192, 168, 8, 1))), None);
}

#[test]
fn rejects_invalid_shape_and_dangerous_ipv4_targets() {
    let prefix = Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 7, 0, 0);
    let lan4 = (Ipv4Addr::new(192, 168, 7, 0), 24);
    assert_eq!(
        LanRoute::new((prefix, 120), lan4, SNAT),
        Err(Nat64LanError::MappedPrefix)
    );
    assert_eq!(
        LanRoute::new((HOST6, 96), lan4, SNAT),
        Err(Nat64LanError::MappedPrefix)
    );
    assert_eq!(
        LanRoute::new((prefix, 96), (HOST, 24), SNAT),
        Err(Nat64LanError::RealPrefix)
    );
    assert_eq!(
        LanRoute::new((prefix, 96), (Ipv4Addr::UNSPECIFIED, 33), SNAT),
        Err(Nat64LanError::RealPrefix)
    );

    let loopback = LanRoute::new((prefix, 96), (Ipv4Addr::new(127, 0, 0, 0), 8), SNAT).unwrap();
    assert_eq!(loopback.resolve(mapped(Ipv4Addr::LOCALHOST)), None);
    let any = LanRoute::new((prefix, 96), (Ipv4Addr::UNSPECIFIED, 0), SNAT).unwrap();
    for unsafe_target in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(169, 254, 1, 1),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::BROADCAST,
    ] {
        assert_eq!(any.resolve(mapped(unsafe_target)), None, "{unsafe_target}");
    }
    assert_eq!(any.resolve(mapped(HOST)), Some(HOST));
    assert_eq!(
        route().resolve(mapped(Ipv4Addr::new(192, 168, 7, 255))),
        None,
        "directed broadcast must not become a LAN target"
    );
    // A /31 has no broadcast address.
    let point = LanRoute::new((prefix, 96), (Ipv4Addr::new(10, 0, 0, 0), 31), SNAT).unwrap();
    assert_eq!(
        point.resolve(mapped(Ipv4Addr::new(10, 0, 0, 1))),
        Some(Ipv4Addr::new(10, 0, 0, 1))
    );
}

// -- Forward translation. --

#[test]
fn rewrites_authorized_ipv6_udp_to_snatted_ipv4() {
    let lan = lan();
    let translated = forward_udp(&lan);
    assert_eq!(translated.len(), 48 + 5 - 20);
    assert_eq!(translated[0] >> 4, 4);
    assert_eq!(translated[8], 63);
    assert_eq!(translated[9], protocol::UDP);
    assert_eq!(&translated[12..16], &SNAT.octets());
    assert_eq!(&translated[16..20], &HOST.octets());
    assert!(be16(&translated, 20) >= 32768);
    assert_eq!(be16(&translated, 22), 53);
    assert_eq!(&translated[28..], b"query");
    assert_valid4(&translated);
    assert_eq!(lan.stats().forwarded, 1);
    assert_eq!(lan.stats().conntrack.entries, 1);
}

#[test]
fn forward_moves_the_start_inside_the_buffer() {
    let lan = lan();
    let mut packet = ipv6(protocol::UDP, udp(4321, 53, b"query"));
    let headroom = packet.headroom();
    let end = packet.as_packet().as_ptr_range().end;
    assert_eq!(lan.forward(&mut packet), Nat64Verdict::Translated);
    assert_eq!(packet.headroom(), headroom + 20);
    assert_eq!(packet.as_packet().as_ptr_range().end, end);
}

#[test]
fn rejects_extensions_and_unauthorized_ipv6_packets() {
    let lan = lan();
    // A fragment header (and any other extension header) is not ours.
    let mut fragment = ipv6(44, vec![protocol::UDP, 0, 0, 0, 0, 0, 0, 1]);
    assert_not_ours(&mut fragment, |p| lan.forward(p));
    // Another /96.
    let other = Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 8, 0xc0a8, 0x0701);
    let mut elsewhere =
        PacketBuf::from_packet(&ipv6_bytes(protocol::UDP, CLIENT, other, udp(1, 53, b"")));
    assert_not_ours(&mut elsewhere, |p| lan.forward(p));
    // Other protocols, and IPv4.
    let mut gre = ipv6(47, vec![0; 8]);
    assert_not_ours(&mut gre, |p| lan.forward(p));
    let mut v4 = reply(protocol::UDP, udp(53, 1, b""));
    assert_not_ours(&mut v4, |p| lan.forward(p));
    assert_eq!(lan.stats().not_ours, 4);
    assert_eq!(lan.stats().conntrack.entries, 0);
}

#[test]
fn unsafe_targets_inside_the_mapped_prefix_are_dropped_and_counted() {
    let lan = lan();
    for target in [
        Ipv4Addr::new(192, 168, 7, 255),
        Ipv4Addr::new(192, 168, 8, 1),
        Ipv4Addr::LOCALHOST,
    ] {
        let mut packet = PacketBuf::from_packet(&ipv6_bytes(
            protocol::UDP,
            CLIENT,
            mapped(target),
            udp(1, 53, b""),
        ));
        assert_eq!(
            lan.forward(&mut packet),
            Nat64Verdict::Drop(reasons::UNSAFE_TARGET)
        );
    }
    let stats = lan.stats();
    assert_eq!((stats.unsafe_target, stats.forwarded), (3, 0));
    assert_eq!(stats.conntrack.inserted, 0);
}

#[test]
fn translates_only_icmpv6_echo_requests_and_rejects_other_icmp() {
    let lan = lan();
    let mut packet = ipv6(protocol::ICMPV6, echo(128, 7, 1, b"ping"));
    assert_eq!(lan.forward(&mut packet), Nat64Verdict::Translated);
    let translated = packet.as_packet();
    assert_eq!(translated[9], protocol::ICMP);
    assert_eq!(translated[20], 8);
    assert_eq!(translated[21], 0);
    assert!(be16(translated, 24) >= 32768, "the identifier is SNATed");
    assert_eq!(be16(translated, 26), 1);
    assert_eq!(&translated[28..], b"ping");
    assert_valid4(translated);

    let mut unreachable = ipv6(protocol::ICMPV6, echo(1, 7, 1, b""));
    assert_not_ours(&mut unreachable, |p| lan.forward(p));
    let mut code = ipv6_bytes(protocol::ICMPV6, CLIENT, HOST6, echo(128, 7, 1, b""));
    code[41] = 1;
    assert_not_ours(&mut PacketBuf::from_packet(&code), |p| lan.forward(p));
    let mut echo_reply = ipv6(protocol::ICMPV6, echo(129, 7, 1, b""));
    assert_not_ours(&mut echo_reply, |p| lan.forward(p));
}

#[test]
fn rejects_malformed_and_ipv4_unrepresentable_payloads() {
    let lan = lan();
    // IPv6 permits this payload length, but adding the IPv4 header would
    // overflow IPv4's 16-bit total length.
    let mut segment = udp(1234, 53, &[]);
    segment.resize(usize::from(u16::MAX), 0);
    segment[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    let mut oversized = ipv6(protocol::UDP, segment);
    assert_eq!(
        lan.forward(&mut oversized),
        Nat64Verdict::Drop(reasons::MALFORMED)
    );
    // A payload length that disagrees with the packet.
    let mut bytes = ipv6_bytes(protocol::UDP, CLIENT, HOST6, udp(1, 53, b"x"));
    bytes.push(0);
    assert_eq!(
        lan.forward(&mut PacketBuf::from_packet(&bytes)),
        Nat64Verdict::Drop(reasons::MALFORMED)
    );
    // A truncated TCP header.
    let mut short = ipv6(protocol::TCP, vec![0; 12]);
    assert_eq!(
        lan.forward(&mut short),
        Nat64Verdict::Drop(reasons::MALFORMED)
    );
    let stats = lan.stats();
    assert_eq!((stats.other_drops, stats.conntrack.inserted), (3, 0));
}

#[test]
fn an_existing_flow_reuses_its_port() {
    let lan = lan();
    let first = forward_udp(&lan);
    let second = forward_udp(&lan);
    assert_eq!(first, second);
    let mut other = ipv6(protocol::UDP, udp(4322, 53, b"query"));
    assert_eq!(lan.forward(&mut other), Nat64Verdict::Translated);
    assert_ne!(be16(other.as_packet(), 20), be16(&first, 20));
    let stats = lan.stats().conntrack;
    assert_eq!((stats.entries, stats.inserted), (2, 2));
}

// -- Reverse translation. --

#[test]
fn conntrack_restores_lan_reply_to_the_original_ipv6_flow() {
    let lan = lan();
    let forwarded = forward_udp(&lan);
    let snat_port = be16(&forwarded, 20);
    let mut packet = reply(protocol::UDP, udp(53, snat_port, b"answer"));
    assert_eq!(lan.reverse(&mut packet), Nat64Verdict::Translated);
    let restored = packet.as_packet();
    assert_eq!(restored[0] >> 4, 6);
    assert_eq!(restored[6], protocol::UDP);
    assert_eq!(restored[7], 50);
    assert_eq!(&restored[8..24], &HOST6.octets());
    assert_eq!(&restored[24..40], &CLIENT.octets());
    assert_eq!(be16(restored, 40), 53);
    assert_eq!(be16(restored, 42), 4321);
    assert_eq!(&restored[48..], b"answer");
    assert_valid6(restored);
    assert_eq!(lan.stats().reversed, 1);

    let target = SocketAddrV4::new(HOST, 53);
    let snat = SocketAddrV4::new(SNAT, snat_port);
    assert!(lan.remove_flow(protocol::UDP, snat, target));
    let mut again = reply(protocol::UDP, udp(53, snat_port, b"answer"));
    assert_not_ours(&mut again, |p| lan.reverse(p));
    assert!(!lan.remove_flow(protocol::UDP, snat, target));
    assert!(!lan.remove_flow(47, snat, target));
}

#[test]
fn reverse_grows_into_headroom_or_copies_once() {
    let lan = lan();
    let snat_port = be16(&forward_udp(&lan), 20);
    let mut packet = reply(protocol::UDP, udp(53, snat_port, b"answer"));
    let end = packet.as_packet().as_ptr_range().end;
    assert_eq!(lan.reverse(&mut packet), Nat64Verdict::Translated);
    assert_eq!(packet.as_packet().as_ptr_range().end, end, "in place");

    // No headroom at all: one copy into a buffer with the standard headroom.
    let bytes = ipv4_bytes(protocol::UDP, HOST, SNAT, udp(53, snat_port, b"answer"));
    let len = bytes.len();
    let mut packet = PacketBuf::with_capacity(len);
    packet.reserve_front(packet.headroom()).unwrap();
    packet.set_len(len);
    packet.as_packet_mut().copy_from_slice(&bytes);
    assert_eq!(packet.headroom(), 0);
    assert_eq!(lan.reverse(&mut packet), Nat64Verdict::Translated);
    assert_eq!(packet.len(), len + 20);
    assert_valid6(packet.as_packet());
}

#[test]
fn conntrack_restores_tcp_sequence_and_checksum_without_corruption() {
    let lan = lan();
    let mut request = ipv6(protocol::TCP, tcp(4321, 18084, 0x1234_5678, 0, SYN, &[]));
    assert_eq!(lan.forward(&mut request), Nat64Verdict::Translated);
    let forwarded = request.as_packet();
    assert_valid4(forwarded);
    let snat_port = be16(forwarded, 20);
    assert_eq!(be32(forwarded, 24), 0x1234_5678);

    let mut packet = reply(
        protocol::TCP,
        tcp(18084, snat_port, 0xe6fe_9612, 0x1234_5679, SYN_ACK, &[]),
    );
    assert_eq!(lan.reverse(&mut packet), Nat64Verdict::Translated);
    let restored = packet.as_packet();
    assert_eq!(be32(restored, 44), 0xe6fe_9612);
    assert_eq!(be32(restored, 48), 0x1234_5679);
    assert_eq!(be16(restored, 42), 4321);
    assert_valid6(restored);
}

#[test]
fn clamps_only_tcp_syn_mss_in_both_directions() {
    let lan = Nat64Lan::new(routes(vec![route()]), config(Some(1360)));
    // NOP, NOP, MSS 1460: the option is found after other options.
    let options = [1, 1, 0, 0, 0, 0, 0, 0];
    let mut syn_options = options;
    syn_options[2..6].copy_from_slice(&mss(1460));
    let mut syn = ipv6(protocol::TCP, tcp(4321, 80, 1, 0, SYN, &syn_options));
    assert_eq!(lan.forward(&mut syn), Nat64Verdict::Translated);
    let forwarded = syn.as_packet();
    assert_eq!(be16(forwarded, 44), 1360);
    assert_valid4(forwarded);
    let snat_port = be16(forwarded, 20);

    let mut syn_ack = reply(protocol::TCP, tcp(80, snat_port, 9, 2, SYN_ACK, &mss(1460)));
    assert_eq!(lan.reverse(&mut syn_ack), Nat64Verdict::Translated);
    assert_eq!(be16(syn_ack.as_packet(), 62), 1360);
    assert_valid6(syn_ack.as_packet());

    // A smaller MSS and segments without SYN are left alone.
    let mut small = reply(protocol::TCP, tcp(80, snat_port, 9, 2, SYN_ACK, &mss(1200)));
    assert_eq!(lan.reverse(&mut small), Nat64Verdict::Translated);
    assert_eq!(be16(small.as_packet(), 62), 1200);
    let mut ack = ipv6(protocol::TCP, tcp(4321, 80, 2, 10, ACK, &mss(1460)));
    assert_eq!(lan.forward(&mut ack), Nat64Verdict::Translated);
    assert_eq!(be16(ack.as_packet(), 42), 1460);
    assert_valid4(ack.as_packet());

    // Without a limit nothing is clamped.
    let plain = lan_without_clamp_forward(&mss(1460));
    assert_eq!(be16(&plain, 42), 1460);
}

fn lan_without_clamp_forward(options: &[u8]) -> Vec<u8> {
    let lan = lan();
    let mut syn = ipv6(protocol::TCP, tcp(4321, 80, 1, 0, SYN, options));
    assert_eq!(lan.forward(&mut syn), Nat64Verdict::Translated);
    syn.as_packet().to_vec()
}

#[test]
fn conntrack_restores_matching_ipv4_fragmentation_needed_as_packet_too_big() {
    let lan = lan();
    let forwarded = forward_udp(&lan);

    let mut error = fragmentation_needed(1400, &forwarded);
    assert_eq!(lan.reverse(&mut error), Nat64Verdict::Translated);
    let restored = error.as_packet();
    assert_eq!(restored.len(), 96);
    assert_eq!(restored[6], protocol::ICMPV6);
    assert_eq!(restored[7], 50);
    assert_eq!(&restored[8..24], &HOST6.octets());
    assert_eq!(&restored[24..40], &CLIENT.octets());
    assert_eq!(restored[40], 2);
    assert_eq!(restored[41], 0);
    assert_eq!(be32(restored, 44), 1420);
    assert_eq!(restored[48] >> 4, 6);
    assert_eq!(restored[54], protocol::UDP);
    assert_eq!(&restored[56..72], &CLIENT.octets());
    assert_eq!(&restored[72..88], &HOST6.octets());
    assert_eq!(be16(restored, 88), 4321);
    assert_eq!(be16(restored, 90), 53);
    assert_valid6(restored);
    assert_eq!(lan.stats().packet_too_big, 1);

    // Other codes, a zero MTU and unknown flows are not ours.
    let mut port_unreachable = fragmentation_needed(1400, &forwarded);
    let bytes = port_unreachable.as_packet_mut();
    bytes[21] = 3;
    assert_not_ours(&mut port_unreachable, |p| lan.reverse(p));
    let mut zero = fragmentation_needed(0, &forwarded);
    assert_not_ours(&mut zero, |p| lan.reverse(p));
    let mut unknown = forwarded;
    unknown[20..22].copy_from_slice(&1_u16.to_be_bytes());
    let mut unknown = fragmentation_needed(1400, &unknown);
    assert_not_ours(&mut unknown, |p| lan.reverse(p));
    assert_eq!(lan.stats().packet_too_big, 1);
}

#[test]
fn conntrack_restores_only_matching_icmp_echo_reply() {
    let lan = lan();
    let mut request = ipv6(protocol::ICMPV6, echo(128, 4321, 9, b"ping"));
    assert_eq!(lan.forward(&mut request), Nat64Verdict::Translated);
    let forwarded = request.as_packet().to_vec();
    let identifier = be16(&forwarded, 24);
    assert_ne!(identifier, 4321);

    // Fragmentation Needed quoting the echo request, below the IPv6 minimum.
    let mut too_big = fragmentation_needed(1200, &forwarded);
    assert_eq!(lan.reverse(&mut too_big), Nat64Verdict::Translated);
    let packet_too_big = too_big.as_packet();
    assert_eq!(packet_too_big[40], 2);
    assert_eq!(be32(packet_too_big, 44), 1280);
    assert_eq!(packet_too_big[88], 128);
    assert_eq!(be16(packet_too_big, 92), 4321);
    assert_eq!(be16(packet_too_big, 94), 9);
    assert_valid6(packet_too_big);

    let mut packet = reply(protocol::ICMP, echo(0, identifier, 9, b"ping"));
    assert_eq!(lan.reverse(&mut packet), Nat64Verdict::Translated);
    let restored = packet.as_packet();
    assert_eq!(restored[6], protocol::ICMPV6);
    assert_eq!(restored[40], 129);
    assert_eq!(restored[41], 0);
    assert_eq!(be16(restored, 44), 4321);
    assert_eq!(&restored[46..], &[0, 9, b'p', b'i', b'n', b'g']);
    assert_valid6(restored);

    let mut echo_request = reply(protocol::ICMP, echo(8, identifier, 9, b"ping"));
    assert_not_ours(&mut echo_request, |p| lan.reverse(p));

    assert!(lan.remove_flow(
        protocol::ICMP,
        SocketAddrV4::new(SNAT, identifier),
        SocketAddrV4::new(HOST, 0),
    ));
}

#[test]
fn replies_of_unknown_flows_and_other_packets_are_not_ours() {
    let lan = lan();
    let snat_port = be16(&forward_udp(&lan), 20);
    let mut wrong_port = reply(protocol::UDP, udp(54, snat_port, b""));
    assert_not_ours(&mut wrong_port, |p| lan.reverse(p));
    let mut wrong_host = PacketBuf::from_packet(&ipv4_bytes(
        protocol::UDP,
        ROUTER,
        SNAT,
        udp(53, snat_port, b""),
    ));
    assert_not_ours(&mut wrong_host, |p| lan.reverse(p));
    let mut ipv6_packet = ipv6(protocol::UDP, udp(4321, 53, b""));
    assert_not_ours(&mut ipv6_packet, |p| lan.reverse(p));
    let mut fragment = ipv4_bytes(protocol::UDP, HOST, SNAT, udp(53, snat_port, b""));
    fragment[6] = 0x20;
    assert_not_ours(&mut PacketBuf::from_packet(&fragment), |p| lan.reverse(p));
}

// -- Routes replaced through the ArcSwap. --

#[test]
fn routes_are_replaced_atomically() {
    let shared = routes(Vec::new());
    let lan = Nat64Lan::new(Arc::clone(&shared), Nat64LanConfig::default());
    let mut packet = ipv6(protocol::UDP, udp(4321, 53, b""));
    assert_not_ours(&mut packet, |p| lan.forward(p));

    // Same `mapped` prefix, but HOST is outside `real`: only route() resolves.
    let elsewhere = LanRoute::new(
        (Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 7, 0, 0), 96),
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        Ipv4Addr::new(10, 9, 9, 9),
    )
    .unwrap();
    shared.store(Arc::new(vec![elsewhere, route()]));
    assert_eq!(lan.forward(&mut packet), Nat64Verdict::Translated);
    assert_eq!(&packet.as_packet()[12..16], &SNAT.octets());
    assert_eq!(lan.stats().ambiguous_route, 0);

    shared.store(Arc::new(Vec::new()));
    let mut packet = ipv6(protocol::UDP, udp(4321, 53, b""));
    assert_not_ours(&mut packet, |p| lan.forward(p));
}

#[test]
fn a_destination_several_routes_resolve_is_dropped_and_counted() {
    let mut second = route();
    second.snat_source = Ipv4Addr::new(10, 9, 9, 9);
    let shared = routes(vec![route(), second]);
    let lan = Nat64Lan::new(Arc::clone(&shared), Nat64LanConfig::default());
    let mut packet = ipv6(protocol::UDP, udp(4321, 53, b""));
    let before = packet.as_packet().to_vec();
    assert_eq!(
        lan.forward(&mut packet),
        Nat64Verdict::Drop(reasons::AMBIGUOUS_ROUTE)
    );
    assert_eq!(packet.as_packet(), before.as_slice());
    let stats = lan.stats();
    assert_eq!(stats.ambiguous_route, 1);
    assert_eq!(stats.forwarded, 0);
    assert_eq!(stats.conntrack.entries, 0);

    // A tracked flow is gated too once its destination becomes ambiguous.
    shared.store(Arc::new(vec![route()]));
    forward_udp(&lan);
    shared.store(Arc::new(vec![route(), second]));
    let mut packet = ipv6(protocol::UDP, udp(4321, 53, b"query"));
    assert_eq!(
        lan.forward(&mut packet),
        Nat64Verdict::Drop(reasons::AMBIGUOUS_ROUTE)
    );
    assert_eq!(lan.stats().ambiguous_route, 2);
}

// -- DF. --

/// The DF bit of a UDP packet with `len` bytes of data, forwarded with
/// `set_df`.
fn forwarded_df(set_df: bool, len: usize) -> bool {
    let config = Nat64LanConfig {
        set_df,
        ..Nat64LanConfig::default()
    };
    let lan = Nat64Lan::new(routes(vec![route()]), config);
    let mut packet = ipv6(protocol::UDP, udp(4321, 53, &vec![0; len]));
    assert_eq!(lan.forward(&mut packet), Nat64Verdict::Translated);
    let bytes = packet.as_packet();
    assert_valid4(bytes);
    be16(bytes, 6) & 0x4000 != 0
}

#[test]
fn df_is_clear_by_default() {
    assert!(!Nat64LanConfig::default().set_df);
    // 20 + 8 + 1300 bytes of IPv4: above the 1260-byte threshold.
    assert!(!forwarded_df(false, 1300));
    assert!(!forwarded_df(false, 5));
}

#[test]
fn set_df_marks_only_packets_above_1260_bytes() {
    assert!(forwarded_df(true, 1300));
    // 20 + 8 + 1232 = 1260 bytes: at the threshold, not above.
    assert!(!forwarded_df(true, 1232));
    assert!(!forwarded_df(true, 5));
}

// -- SNAT ports. --

/// A [`SnatPorts`] that records releases, optionally refusing every
/// reservation or offering the ports of `candidates` by `seq`.
#[derive(Default)]
struct Recorder {
    inner: DefaultSnatPorts,
    refuse: bool,
    candidates: Option<fn(u32) -> u16>,
    reserved: Mutex<Vec<SocketAddrV4>>,
    released: Mutex<Vec<SocketAddrV4>>,
}

impl SnatPorts for Recorder {
    fn reserve(&self, protocol: u8, snat: SocketAddrV4) -> bool {
        self.reserved.lock().unwrap().push(snat);
        !self.refuse && (self.candidates.is_some() || self.inner.reserve(protocol, snat))
    }

    fn release(&self, protocol: u8, snat: SocketAddrV4) {
        self.released.lock().unwrap().push(snat);
        self.inner.release(protocol, snat);
    }

    fn candidate(&self, protocol: u8, snat_source: Ipv4Addr, seq: u32) -> u16 {
        self.candidates.map_or_else(
            || self.inner.candidate(protocol, snat_source, seq),
            |candidates| candidates(seq),
        )
    }
}

fn recorded(recorder: Recorder, config: Nat64LanConfig) -> (Nat64Lan, Arc<Recorder>) {
    let recorder = Arc::new(recorder);
    let ports: Arc<dyn SnatPorts> = recorder.clone();
    (
        Nat64Lan::with_snat_ports(routes(vec![route()]), config, ports),
        recorder,
    )
}

#[test]
fn default_candidates_round_robin_over_the_upper_port_range() {
    let ports = DefaultSnatPorts::new();
    assert_eq!(ports.candidate(protocol::UDP, SNAT, 0), 32768);
    assert_eq!(ports.candidate(protocol::UDP, SNAT, 32767), 65535);
    assert_eq!(ports.candidate(protocol::UDP, SNAT, 32768), 32768);
    assert!(ports.reserve(protocol::UDP, SocketAddrV4::new(SNAT, 32768)));
    // Shared by all protocols, as ns `reserved_snat_ports`.
    assert!(!ports.reserve(protocol::TCP, SocketAddrV4::new(SNAT, 32768)));
    assert!(ports.reserve(protocol::TCP, SocketAddrV4::new(HOST, 32768)));
    ports.release(protocol::UDP, SocketAddrV4::new(SNAT, 32768));
    assert_eq!(ports.len(), 1);
}

#[test]
fn port_exhaustion_tries_port_tries_candidates_and_drops() {
    let config = Nat64LanConfig {
        port_tries: 5,
        ..Nat64LanConfig::default()
    };
    let (lan, recorder) = recorded(
        Recorder {
            refuse: true,
            ..Recorder::default()
        },
        config,
    );
    let mut packet = ipv6(protocol::UDP, udp(4321, 53, b""));
    assert_eq!(
        lan.forward(&mut packet),
        Nat64Verdict::Drop(reasons::PORT_EXHAUSTED)
    );
    assert_eq!(recorder.reserved.lock().unwrap().len(), 5);
    assert!(recorder.released.lock().unwrap().is_empty());
    let stats = lan.stats();
    assert_eq!((stats.port_exhausted, stats.conntrack.entries), (1, 0));
}

#[test]
fn a_conflicting_candidate_is_released_and_the_next_one_taken() {
    // A caller that does not keep reservations exclusive: the second flow to
    // the same LAN service is first offered the port of the first one.
    let (lan, recorder) = recorded(
        Recorder {
            candidates: Some(|seq| if seq < 2 { 40000 } else { 40001 }),
            ..Recorder::default()
        },
        Nat64LanConfig::default(),
    );
    let first = forward_udp(&lan);
    assert_eq!(be16(&first, 20), 40000);
    let mut second = ipv6(protocol::UDP, udp(4322, 53, b""));
    assert_eq!(lan.forward(&mut second), Nat64Verdict::Translated);
    assert_eq!(be16(second.as_packet(), 20), 40001);
    assert_eq!(
        *recorder.released.lock().unwrap(),
        [SocketAddrV4::new(SNAT, 40000)]
    );
}

#[test]
fn zero_max_entries_drops_new_flows_and_releases_the_port() {
    let config = Nat64LanConfig {
        conntrack: ConntrackConfig {
            max_entries: 0,
            ..ConntrackConfig::default()
        },
        ..Nat64LanConfig::default()
    };
    let (lan, recorder) = recorded(Recorder::default(), config);
    let mut packet = ipv6(protocol::UDP, udp(4321, 53, b""));
    assert_eq!(
        lan.forward(&mut packet),
        Nat64Verdict::Drop(reasons::CONNTRACK_FULL)
    );
    assert_eq!(recorder.released.lock().unwrap().len(), 1);
    assert!(recorder.inner.is_empty());
}

#[test]
fn remove_flow_releases_the_port() {
    let (lan, recorder) = recorded(Recorder::default(), Nat64LanConfig::default());
    let snat = SocketAddrV4::new(SNAT, be16(&forward_udp(&lan), 20));
    assert_eq!(recorder.inner.len(), 1);
    assert!(lan.remove_flow(protocol::UDP, snat, SocketAddrV4::new(HOST, 53)));
    assert_eq!(*recorder.released.lock().unwrap(), [snat]);
    assert!(recorder.inner.is_empty());
    assert_eq!(lan.stats().conntrack.removed, 1);
}

/// A translator over the default route whose flow table follows a clock
/// moved by hand, with the clock handle.
fn clocked(
    recorder: Recorder,
    conntrack: ConntrackConfig,
) -> (Nat64Lan, Arc<Recorder>, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let handle = Arc::clone(&clock);
    let recorder = Arc::new(recorder);
    let ports: Arc<dyn SnatPorts> = recorder.clone();
    let config = Nat64LanConfig {
        conntrack,
        ..Nat64LanConfig::default()
    };
    let table = Conntrack::with_clock(conntrack, move || *handle.lock().unwrap());
    let lan = Nat64Lan::with_conntrack(routes(vec![route()]), config, ports, table);
    (lan, recorder, clock)
}

fn advance(clock: &Mutex<Instant>, secs: u64) {
    *clock.lock().unwrap() += Duration::from_secs(secs);
}

#[test]
fn expiry_releases_the_port_and_the_next_packet_takes_a_new_one() {
    let (lan, recorder, clock) = clocked(Recorder::default(), ConntrackConfig::default());
    let first = forward_udp(&lan);
    let snat = SocketAddrV4::new(SNAT, be16(&first, 20));
    advance(&clock, 30);
    let mut late = reply(protocol::UDP, udp(53, snat.port(), b""));
    assert_not_ours(&mut late, |p| lan.reverse(p));
    assert_eq!(*recorder.released.lock().unwrap(), [snat]);
    assert!(recorder.inner.is_empty());

    let second = forward_udp(&lan);
    assert_ne!(be16(&second, 20), snat.port());
    let stats = lan.stats().conntrack;
    assert_eq!((stats.entries, stats.expired), (1, 1));
}

#[test]
fn eviction_releases_the_port() {
    let (lan, recorder, clock) = clocked(
        Recorder::default(),
        ConntrackConfig {
            max_entries: 1,
            ..ConntrackConfig::default()
        },
    );
    let first = SocketAddrV4::new(SNAT, be16(&forward_udp(&lan), 20));
    advance(&clock, 1);
    let mut other = ipv6(protocol::UDP, udp(4322, 53, b""));
    assert_eq!(lan.forward(&mut other), Nat64Verdict::Translated);
    assert_eq!(*recorder.released.lock().unwrap(), [first]);
    assert_eq!(recorder.inner.len(), 1);
    assert_eq!(lan.stats().conntrack.evicted, 1);
}

#[test]
fn nat64_lan_is_shareable() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Nat64Lan>();
    assert_eq!(Nat64LanConfig::default().port_tries, 32);
    assert!(format!("{:?}", lan()).starts_with("Nat64Lan"));
}

// -- The local-side wrappers. --

#[tokio::test]
async fn sink_forwards_in_order_and_discards_drops() {
    let nat = Arc::new(lan());
    let (sink, mut delivered) = nsplane::ChannelSink::new(8);
    let sink = Nat64LanSink::new(sink, Arc::clone(&nat));
    let unsafe_target = ipv6_bytes(
        protocol::UDP,
        CLIENT,
        mapped(Ipv4Addr::LOCALHOST),
        udp(1, 53, b""),
    );
    let not_ours = reply(protocol::UDP, udp(53, 1, b""));
    let mut packets = VecDeque::from([
        (PeerId::new(1), ipv6(protocol::UDP, udp(4321, 53, b"query"))),
        (PeerId::new(1), PacketBuf::from_packet(&unsafe_target)),
        (PeerId::new(2), PacketBuf::from_packet(not_ours.as_packet())),
    ]);
    sink.send_batch(&mut packets).await.unwrap();
    assert!(packets.is_empty());
    let (peer, first) = delivered.recv().await.unwrap();
    assert_eq!(peer, PeerId::new(1));
    assert_valid4(first.as_packet());
    assert_eq!(first.as_packet()[16..20], HOST.octets());
    let (peer, second) = delivered.recv().await.unwrap();
    assert_eq!(
        (peer, second.as_packet()),
        (PeerId::new(2), not_ours.as_packet())
    );

    sink.send(PacketBuf::from_packet(&unsafe_target), PeerId::new(1))
        .await
        .unwrap();
    assert!(delivered.try_recv().is_err());
    let stats = nat.stats();
    assert_eq!(
        (stats.forwarded, stats.unsafe_target, stats.not_ours),
        (1, 2, 1)
    );
}

#[tokio::test]
async fn source_reverses_in_order_and_keeps_the_mtu() {
    let nat = Arc::new(lan());
    let snat_port = be16(&forward_udp(&nat), 20);
    let (source, local, mtu) = nsplane::ChannelSource::new(8, 1400);
    let mut source = Nat64LanSource::new(source, Arc::clone(&nat));
    let not_ours = reply(protocol::UDP, udp(53, 1, b""));
    local
        .send(reply(protocol::UDP, udp(53, snat_port, b"answer")))
        .await
        .unwrap();
    local
        .send(PacketBuf::from_packet(not_ours.as_packet()))
        .await
        .unwrap();

    let mut batch = PacketBatch::new();
    while batch.len() < 2 {
        source.recv_batch(&mut batch).await.unwrap();
    }
    let packets: Vec<_> = batch.drain().collect();
    assert_valid6(packets[0].as_packet());
    assert_eq!(packets[0].as_packet()[24..40], CLIENT.octets());
    assert_eq!(packets[1].as_packet(), not_ours.as_packet());

    assert_eq!(*source.mtu().borrow(), 1400);
    mtu.send(1280).unwrap();
    assert_eq!(*source.mtu().borrow(), 1280);
    let stats = nat.stats();
    assert_eq!((stats.reversed, stats.not_ours), (1, 1));
}
