use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::checksum::transport_checksum_v4;

const V4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const V4_TARGET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const V6_CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const V6_TARGET: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
const IDENTIFIER: u16 = 0x1234;
const SEQUENCE: u16 = 0x0007;
const PAYLOAD: &[u8] = b"abcdefghijklmnopqrstuvwabcdefghi";

/// An ICMP message with a valid checksum; `checksum` sums the message with
/// its checksum field zeroed.
fn icmp_message(
    icmp_type: u8,
    code: u8,
    payload: &[u8],
    checksum: impl Fn(&[u8]) -> u16,
) -> Vec<u8> {
    let mut message = vec![icmp_type, code, 0, 0];
    message.extend_from_slice(&IDENTIFIER.to_be_bytes());
    message.extend_from_slice(&SEQUENCE.to_be_bytes());
    message.extend_from_slice(payload);
    let sum = checksum(&message);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

/// A valid IPv4 packet (TTL 64, identification 0xbeef) carrying `message`
/// as `proto`, with `options` and the flags/fragment field `flags_fragment`.
fn ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    flags_fragment: u16,
    options: &[u8],
    message: &[u8],
) -> Vec<u8> {
    let header_len = 20 + options.len();
    let ihl = u8::try_from(header_len / 4).unwrap();
    let total = u16::try_from(header_len + message.len()).unwrap();
    let mut packet = vec![0x40 | ihl, 0x00];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&0xbeef_u16.to_be_bytes());
    packet.extend_from_slice(&flags_fragment.to_be_bytes());
    packet.extend_from_slice(&[64, proto, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(options);
    let sum = internet_checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(message);
    packet
}

/// A valid IPv6 packet (hop limit 64, flow label 0x12345) carrying `payload`
/// after a fixed header with next header `next_header`.
fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0x01, 0x23, 0x45];
    packet.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(&[next_header, 64]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(payload);
    packet
}

/// An IPv4 ICMP message from `src` to `dst`, everything valid.
fn icmp_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    icmp_type: u8,
    code: u8,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let message = icmp_message(icmp_type, code, payload, internet_checksum);
    ipv4(src, dst, protocol::ICMP, 0, options, &message)
}

/// An IPv6 `ICMPv6` message from `src` to `dst`, everything valid.
fn icmp_v6(src: Ipv6Addr, dst: Ipv6Addr, icmp_type: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let message = icmp_message(icmp_type, code, payload, |m| {
        transport_checksum_v6(src, dst, protocol::ICMPV6, m)
    });
    ipv6(src, dst, protocol::ICMPV6, &message)
}

/// Asserts that `packet` is not answered and stays byte-for-byte unchanged.
#[track_caller]
fn assert_untouched(mut packet: Vec<u8>) {
    let copy = packet.clone();
    assert!(!echo_reply_in_place(&mut packet));
    assert_eq!(packet, copy);
}

/// Asserts that the IPv4 `packet` is a valid reply: both checksums verify to
/// zero, and it matches the reply built from scratch.
#[track_caller]
fn assert_v4_reply(packet: &[u8], options: &[u8], payload: &[u8]) {
    let header_len = 20 + options.len();
    assert_eq!(internet_checksum(&packet[..header_len]), 0);
    assert_eq!(internet_checksum(&packet[header_len..]), 0);
    assert_eq!(
        packet,
        icmp_v4(V4_TARGET, V4_CLIENT, 0, 0, options, payload)
    );
}

/// Asserts that the IPv6 `packet` is a valid reply: the `ICMPv6` checksum
/// verifies to zero, and it matches the reply built from scratch.
#[track_caller]
fn assert_v6_reply(packet: &[u8], payload: &[u8]) {
    assert_eq!(
        transport_checksum_v6(V6_TARGET, V6_CLIENT, protocol::ICMPV6, &packet[40..]),
        0
    );
    assert_eq!(packet, icmp_v6(V6_TARGET, V6_CLIENT, 129, 0, payload));
}

#[test]
fn v4_echo_request_becomes_reply() {
    let mut packet = icmp_v4(V4_CLIENT, V4_TARGET, 8, 0, &[], PAYLOAD);
    assert!(echo_reply_in_place(&mut packet));
    assert_v4_reply(&packet, &[], PAYLOAD);
    let (header, message) = Ipv4Header::parse(&packet).unwrap();
    assert_eq!((header.src(), header.dst()), (V4_TARGET, V4_CLIENT));
    assert_eq!(header.ttl(), 64);
    assert_eq!(header.identification(), 0xbeef);
    let (icmp, payload) = IcmpHeader::parse(message).unwrap();
    assert_eq!((icmp.icmp_type(), icmp.code()), (0, 0));
    assert_eq!((icmp.identifier(), icmp.sequence()), (IDENTIFIER, SEQUENCE));
    assert_eq!(payload, PAYLOAD);
}

#[test]
fn v6_echo_request_becomes_reply() {
    let mut packet = icmp_v6(V6_CLIENT, V6_TARGET, 128, 0, PAYLOAD);
    assert!(echo_reply_in_place(&mut packet));
    assert_v6_reply(&packet, PAYLOAD);
    let (header, message) = Ipv6Header::parse(&packet).unwrap();
    assert_eq!((header.src(), header.dst()), (V6_TARGET, V6_CLIENT));
    assert_eq!(header.hop_limit(), 64);
    assert_eq!(header.flow_label(), 0x12345);
    let (icmp, payload) = IcmpHeader::parse(message).unwrap();
    assert_eq!((icmp.icmp_type(), icmp.code()), (129, 0));
    assert_eq!((icmp.identifier(), icmp.sequence()), (IDENTIFIER, SEQUENCE));
    assert_eq!(payload, PAYLOAD);
}

#[test]
fn ns_parity_v4_cases() {
    // ns `subnet_icmp_echo_reply`: the minimum 28-byte request, an odd-length
    // payload (zero-padded in the checksum), IPv4 options kept as they are and
    // the don't-fragment flag of a whole datagram.
    let options = [0x94, 0x04, 0x00, 0x00]; // Router Alert
    for (options, payload) in [
        (&[][..], &[][..]),
        (&[][..], &b"odd"[..]),
        (&options[..], PAYLOAD),
    ] {
        let mut packet = icmp_v4(V4_CLIENT, V4_TARGET, 8, 0, options, payload);
        assert!(echo_reply_in_place(&mut packet));
        assert_v4_reply(&packet, options, payload);
    }
    let message = icmp_message(8, 0, PAYLOAD, internet_checksum);
    let mut packet = ipv4(V4_CLIENT, V4_TARGET, protocol::ICMP, 0x4000, &[], &message);
    assert!(echo_reply_in_place(&mut packet));
    let reply = icmp_message(0, 0, PAYLOAD, internet_checksum);
    assert_eq!(
        packet,
        ipv4(V4_TARGET, V4_CLIENT, protocol::ICMP, 0x4000, &[], &reply)
    );
}

#[test]
fn ns_parity_v6_cases() {
    // ns `is_icmpv6_echo_request`: the minimum 48-byte request and an
    // odd-length payload.
    for payload in [&[][..], &b"odd"[..]] {
        let mut packet = icmp_v6(V6_CLIENT, V6_TARGET, 128, 0, payload);
        assert_eq!(packet.len(), 48 + payload.len());
        assert!(echo_reply_in_place(&mut packet));
        assert_v6_reply(&packet, payload);
    }
}

#[test]
fn replying_twice_is_not_answered() {
    let mut packet = icmp_v4(V4_CLIENT, V4_TARGET, 8, 0, &[], PAYLOAD);
    assert!(echo_reply_in_place(&mut packet));
    assert_untouched(packet);
    let mut packet = icmp_v6(V6_CLIENT, V6_TARGET, 128, 0, PAYLOAD);
    assert!(echo_reply_in_place(&mut packet));
    assert_untouched(packet);
}

#[test]
fn other_icmp_types_and_codes_are_untouched() {
    for (icmp_type, code) in [(0, 0), (8, 1), (3, 3), (11, 0), (13, 0), (128, 0)] {
        assert_untouched(icmp_v4(V4_CLIENT, V4_TARGET, icmp_type, code, &[], PAYLOAD));
    }
    for (icmp_type, code) in [(129, 0), (128, 1), (1, 4), (135, 0), (8, 0)] {
        assert_untouched(icmp_v6(V6_CLIENT, V6_TARGET, icmp_type, code, PAYLOAD));
    }
}

#[test]
fn other_protocols_are_untouched() {
    let message = icmp_message(8, 0, PAYLOAD, internet_checksum);
    for proto in [protocol::TCP, protocol::UDP, protocol::ICMPV6] {
        assert_untouched(ipv4(V4_CLIENT, V4_TARGET, proto, 0, &[], &message));
    }
    let message = icmp_message(128, 0, PAYLOAD, |m| {
        transport_checksum_v4(V4_CLIENT, V4_TARGET, protocol::ICMP, m)
    });
    for next_header in [protocol::TCP, protocol::UDP, protocol::ICMP] {
        assert_untouched(ipv6(V6_CLIENT, V6_TARGET, next_header, &message));
    }
}

#[test]
fn truncated_packets_are_untouched() {
    let v4 = icmp_v4(V4_CLIENT, V4_TARGET, 8, 0, &[], &[]);
    for len in 0..v4.len() {
        assert_untouched(v4[..len].to_vec());
    }
    let v6 = icmp_v6(V6_CLIENT, V6_TARGET, 128, 0, &[]);
    for len in 0..v6.len() {
        assert_untouched(v6[..len].to_vec());
    }
    // Headers that declare an ICMP message shorter than the 8-byte header.
    let message = icmp_message(8, 0, &[], internet_checksum);
    assert_untouched(ipv4(
        V4_CLIENT,
        V4_TARGET,
        protocol::ICMP,
        0,
        &[],
        &message[..7],
    ));
    assert_untouched(ipv6(
        V6_CLIENT,
        V6_TARGET,
        protocol::ICMPV6,
        &[128, 0, 0, 0],
    ));
}

#[test]
fn bad_ipv4_headers_are_untouched() {
    let request = icmp_v4(V4_CLIENT, V4_TARGET, 8, 0, &[], PAYLOAD);
    // Version 5, IHL 4, and an IHL longer than the packet.
    for first in [0x55, 0x44, 0x4f] {
        let mut packet = request.clone();
        packet[0] = first;
        assert_untouched(packet);
    }
    // Total length below the header length.
    let mut packet = request.clone();
    packet[2..4].copy_from_slice(&19_u16.to_be_bytes());
    assert_untouched(packet);
    // Other version nibbles.
    for first in [0x00, 0x15, 0x75, 0xf5] {
        let mut packet = request.clone();
        packet[0] = first;
        assert_untouched(packet);
    }
}

#[test]
fn ipv4_fragments_are_untouched() {
    let message = icmp_message(8, 0, PAYLOAD, internet_checksum);
    // More fragments (first fragment), a middle and a last fragment.
    for flags_fragment in [0x2000, 0x2003, 0x0003] {
        assert_untouched(ipv4(
            V4_CLIENT,
            V4_TARGET,
            protocol::ICMP,
            flags_fragment,
            &[],
            &message,
        ));
    }
}

#[test]
fn ipv6_extension_headers_are_untouched() {
    let message = icmp_message(128, 0, PAYLOAD, |m| {
        transport_checksum_v6(V6_CLIENT, V6_TARGET, protocol::ICMPV6, m)
    });
    // Hop-by-Hop, Destination Options and Routing headers carrying ICMPv6,
    // padded with a PadN option.
    for next_header in [0, 60, 43] {
        let mut payload = vec![protocol::ICMPV6, 0, 1, 4, 0, 0, 0, 0];
        payload.extend_from_slice(&message);
        assert_untouched(ipv6(V6_CLIENT, V6_TARGET, next_header, &payload));
    }
    // A Fragment header carrying ICMPv6.
    let mut payload = vec![protocol::ICMPV6, 0, 0, 0, 0, 0, 0, 1];
    payload.extend_from_slice(&message);
    assert_untouched(ipv6(V6_CLIENT, V6_TARGET, 44, &payload));
}

#[test]
fn length_mismatches_are_untouched() {
    let request = icmp_v4(V4_CLIENT, V4_TARGET, 8, 0, &[], PAYLOAD);
    // Trailing bytes beyond the total length, and a total length beyond the buffer.
    let mut packet = request.clone();
    packet.push(0);
    assert_untouched(packet);
    let mut packet = request.clone();
    packet.truncate(request.len() - 1);
    assert_untouched(packet);
    // Total length one short of / one past the buffer, checksum kept valid.
    for total in [request.len() - 1, request.len() + 1] {
        let mut packet = request.clone();
        packet[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
        packet[10..12].fill(0);
        let sum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_untouched(packet);
    }

    let request = icmp_v6(V6_CLIENT, V6_TARGET, 128, 0, PAYLOAD);
    let mut packet = request.clone();
    packet.push(0);
    assert_untouched(packet);
    let mut packet = request.clone();
    packet.truncate(request.len() - 1);
    assert_untouched(packet);
    for payload_len in [request.len() - 41, request.len() - 39] {
        let mut packet = request.clone();
        packet[4..6].copy_from_slice(&u16::try_from(payload_len).unwrap().to_be_bytes());
        assert_untouched(packet);
    }
}
