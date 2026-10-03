//! Parsing and in-place rewriting of the packets [`Nat64Lan`](super::Nat64Lan)
//! translates (ns `subnet_route` packet helpers).
//!
//! Checksums are recomputed in full, as ns does, after the ports and the TCP
//! MSS are rewritten; the payload is never copied except for the one-time
//! reallocation of a reply whose buffer lacks 20 bytes of headroom.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nsplane_packet::{FiveTuple, PacketBuf, protocol};

use crate::checksum::{
    internet_checksum, ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6, udp_wire,
};

const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV4_DESTINATION_UNREACHABLE: u8 = 3;
const ICMPV4_FRAGMENTATION_NEEDED: u8 = 4;
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV6_PACKET_TOO_BIG: u8 = 2;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const TCP_SYN: u8 = 0x02;

/// The header size difference between IPv6 and IPv4.
const HEADER_DELTA: usize = 20;
/// With `set_df`, IPv4 packets above this total length get DF (RFC 7915:
/// 1280 minus the header difference).
const DF_THRESHOLD: usize = 1260;
/// The IPv6 minimum link MTU.
const IPV6_MINIMUM_MTU: u32 = 1280;
/// A Packet Too Big: IPv6 header, `ICMPv6` header, quoted IPv6 header and
/// 8 bytes of its transport header (ns `restore_packet_too_big`).
const PACKET_TOO_BIG_LEN: usize = 40 + 8 + 48;

const fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

const fn addr4(bytes: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3])
}

fn addr6(bytes: &[u8], at: usize) -> Ipv6Addr {
    let mut octets = [0; 16];
    octets.copy_from_slice(&bytes[at..at + 16]);
    Ipv6Addr::from(octets)
}

/// The IPv4 protocol of a translated IPv6 next header.
const fn ipv4_protocol(next_header: u8) -> Option<u8> {
    match next_header {
        protocol::TCP | protocol::UDP => Some(next_header),
        protocol::ICMPV6 => Some(protocol::ICMP),
        _ => None,
    }
}

/// The IPv6 next header of a restored IPv4 protocol.
const fn ipv6_protocol(protocol: u8) -> u8 {
    if protocol == protocol::ICMP {
        protocol::ICMPV6
    } else {
        protocol
    }
}

/// An IPv6 packet [`forward`](super::Nat64Lan::forward) may translate.
#[derive(Debug, Clone, Copy)]
pub(super) struct Request {
    /// The IPv4 protocol of the translated packet.
    pub(super) protocol: u8,
    pub(super) dst: Ipv6Addr,
}

/// The shape check of a request: an IPv6 TCP or UDP packet or an `ICMPv6`
/// echo request without extension headers. Everything else is not ours.
pub(super) fn request(bytes: &[u8]) -> Option<Request> {
    if bytes.len() < 40 || bytes[0] >> 4 != 6 {
        return None;
    }
    let protocol = ipv4_protocol(bytes[6])?;
    if protocol == protocol::ICMP
        && (bytes.len() < 42 || bytes[40] != ICMPV6_ECHO_REQUEST || bytes[41] != 0)
    {
        return None;
    }
    Some(Request {
        protocol,
        dst: addr6(bytes, 24),
    })
}

/// The flow tuple of a request after its destination resolved, keyed by the
/// IPv4 protocol (an echo flow carries its identifier as both ports), and its
/// TCP flags; `None` for a malformed packet: a payload length that disagrees
/// with the packet, a truncated transport header, or a payload too large for
/// IPv4.
pub(super) fn request_tuple(bytes: &[u8], request: Request) -> Option<(FiveTuple, u8)> {
    let payload = bytes.len() - 40;
    let minimum = if request.protocol == protocol::TCP {
        20
    } else {
        8
    };
    if usize::from(be16(bytes, 4)) != payload
        || payload < minimum
        || payload + HEADER_DELTA > usize::from(u16::MAX)
    {
        return None;
    }
    let (src_port, dst_port) = if request.protocol == protocol::ICMP {
        (be16(bytes, 44), be16(bytes, 44))
    } else {
        (be16(bytes, 40), be16(bytes, 42))
    };
    let flags = if request.protocol == protocol::TCP {
        bytes[53]
    } else {
        0
    };
    let tuple = FiveTuple {
        src: IpAddr::V6(addr6(bytes, 8)),
        dst: IpAddr::V6(request.dst),
        protocol: request.protocol,
        src_port,
        dst_port,
    };
    Some((tuple, flags))
}

/// Translates a checked request to IPv4 from `translated.src` to
/// `translated.dst` with the source port (or echo identifier)
/// `translated.src_port`, in place: the IPv4 header is written over the end
/// of the IPv6 header and the packet start moves forward by 20 bytes. DF is
/// set only with `set_df` and above [`DF_THRESHOLD`].
pub(super) fn to_ipv4(
    packet: &mut PacketBuf,
    translated: &FiveTuple,
    max_tcp_mss: Option<u16>,
    set_df: bool,
) {
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (translated.src, translated.dst) else {
        return;
    };
    let bytes = packet.as_packet_mut();
    let traffic_class = (bytes[0] << 4) | (bytes[1] >> 4);
    let hop_limit = bytes[7];
    let protocol = translated.protocol;
    let segment = &mut bytes[40..];
    if protocol == protocol::ICMP {
        segment[0] = ICMPV4_ECHO_REQUEST;
        put16(segment, 4, translated.src_port);
    } else {
        put16(segment, 0, translated.src_port);
    }
    if let Some(maximum) = max_tcp_mss
        && protocol == protocol::TCP
    {
        clamp_tcp_mss(segment, maximum);
    }
    let total = bytes.len() - HEADER_DELTA;
    let header = &mut bytes[HEADER_DELTA..40];
    header.fill(0);
    header[0] = 0x45;
    header[1] = traffic_class;
    put16(header, 2, u16::try_from(total).unwrap_or(u16::MAX));
    if set_df && total > DF_THRESHOLD {
        put16(header, 6, 0x4000);
    }
    header[8] = hop_limit;
    header[9] = protocol;
    header[12..16].copy_from_slice(&src.octets());
    header[16..20].copy_from_slice(&dst.octets());
    let checksum = ipv4_header_checksum(header);
    put16(header, 10, checksum);
    let segment = &mut bytes[40..];
    match protocol {
        protocol::ICMP => {
            put16(segment, 2, 0);
            let checksum = internet_checksum(segment);
            put16(segment, 2, checksum);
        }
        protocol::TCP => {
            put16(segment, 16, 0);
            let checksum = transport_checksum_v4(src, dst, protocol, segment);
            put16(segment, 16, checksum);
        }
        _ => {
            put16(segment, 6, 0);
            let checksum = transport_checksum_v4(src, dst, protocol, segment);
            put16(segment, 6, udp_wire(checksum));
        }
    }
    // The packet holds 40 bytes or more; this cannot fail.
    let _ = packet.advance(HEADER_DELTA);
}

/// An unfragmented IPv4 header without options whose total length matches
/// the packet (ns `exact_unfragmented_ipv4` and the length check of
/// `parse_ipv4_reply_flow`).
fn plain_ipv4(bytes: &[u8]) -> bool {
    bytes.len() >= 20
        && bytes[0] == 0x45
        && usize::from(be16(bytes, 2)) == bytes.len()
        && unfragmented(be16(bytes, 6))
}

/// Whether IPv4 flags and fragment offset have MF clear and a zero offset
/// (the low 14 bits).
const fn unfragmented(flags_offset: u16) -> bool {
    flags_offset.trailing_zeros() >= 14
}

/// The tuple and TCP flags of an IPv4 TCP or UDP packet or ICMP echo reply
/// that may answer a flow (ns `parse_ipv4_reply_flow`).
pub(super) fn reply_tuple(bytes: &[u8]) -> Option<(FiveTuple, u8)> {
    if bytes.len() < 28 || !plain_ipv4(bytes) {
        return None;
    }
    let protocol = bytes[9];
    let (src_port, dst_port, flags) = match protocol {
        protocol::ICMP if bytes[20] == ICMPV4_ECHO_REPLY && bytes[21] == 0 => {
            (be16(bytes, 24), be16(bytes, 24), 0)
        }
        protocol::TCP if bytes.len() >= 40 => (be16(bytes, 20), be16(bytes, 22), bytes[33]),
        protocol::UDP => (be16(bytes, 20), be16(bytes, 22), 0),
        _ => return None,
    };
    let tuple = FiveTuple {
        src: IpAddr::V4(addr4(bytes, 12)),
        dst: IpAddr::V4(addr4(bytes, 16)),
        protocol,
        src_port,
        dst_port,
    };
    Some((tuple, flags))
}

/// Restores a reply of the flow whose first packet was `original` to IPv6,
/// in place: the packet grows by 20 bytes into its headroom, or is copied
/// once into a buffer with the standard headroom when it has less.
pub(super) fn to_ipv6(packet: &mut PacketBuf, original: &FiveTuple, max_tcp_mss: Option<u16>) {
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (original.dst, original.src) else {
        return;
    };
    if packet.headroom() < HEADER_DELTA {
        *packet = PacketBuf::from_packet(packet.as_packet());
    }
    let bytes = packet.as_packet();
    let traffic_class = bytes[1];
    let hop_limit = bytes[8];
    let payload = bytes.len() - 20;
    // The standard headroom holds 32 bytes; this cannot fail.
    let _ = packet.reserve_front(HEADER_DELTA);
    let protocol = ipv6_protocol(original.protocol);
    let bytes = packet.as_packet_mut();
    let header = &mut bytes[..40];
    header[0] = 0x60 | (traffic_class >> 4);
    header[1] = traffic_class << 4;
    header[2..4].fill(0);
    put16(header, 4, u16::try_from(payload).unwrap_or(u16::MAX));
    header[6] = protocol;
    header[7] = hop_limit;
    header[8..24].copy_from_slice(&src.octets());
    header[24..40].copy_from_slice(&dst.octets());
    let segment = &mut bytes[40..];
    let at = match protocol {
        protocol::ICMPV6 => {
            segment[0] = ICMPV6_ECHO_REPLY;
            put16(segment, 4, original.src_port);
            2
        }
        protocol::TCP => {
            put16(segment, 2, original.src_port);
            if let Some(maximum) = max_tcp_mss {
                clamp_tcp_mss(segment, maximum);
            }
            16
        }
        _ => {
            put16(segment, 2, original.src_port);
            6
        }
    };
    put16(segment, at, 0);
    let checksum = transport_checksum_v6(src, dst, protocol, segment);
    put16(segment, at, finish(protocol, checksum));
}

/// An ICMP Fragmentation Needed quoting a translated packet: the reply tuple
/// of the quoted flow, the hop limit and the next-hop MTU of the error, and
/// the 4 bytes after the quoted ports or echo identifier (ns
/// `parse_ipv4_fragmentation_needed`).
pub(super) struct FragmentationNeeded {
    pub(super) reply: FiveTuple,
    pub(super) hop_limit: u8,
    pub(super) mtu: u16,
    pub(super) quoted_ttl: u8,
    pub(super) quoted_tail: [u8; 4],
}

/// Parses an ICMP Fragmentation Needed with a non-zero MTU quoting an
/// unfragmented TCP, UDP or echo request packet.
pub(super) fn fragmentation_needed(bytes: &[u8]) -> Option<FragmentationNeeded> {
    if bytes.len() < 20 + 8 + 28
        || !plain_ipv4(bytes)
        || bytes[9] != protocol::ICMP
        || bytes[20] != ICMPV4_DESTINATION_UNREACHABLE
        || bytes[21] != ICMPV4_FRAGMENTATION_NEEDED
    {
        return None;
    }
    let mtu = be16(bytes, 26);
    let quoted = &bytes[28..];
    if mtu == 0 || quoted[0] != 0x45 || !unfragmented(be16(quoted, 6)) {
        return None;
    }
    let protocol = quoted[9];
    let (src_port, dst_port, tail) = match protocol {
        protocol::ICMP if quoted[20] == ICMPV4_ECHO_REQUEST && quoted[21] == 0 => {
            (be16(quoted, 24), be16(quoted, 24), 26)
        }
        protocol::TCP | protocol::UDP => (be16(quoted, 20), be16(quoted, 22), 24),
        _ => return None,
    };
    let mut quoted_tail = [0; 4];
    let available = quoted.len().min(28) - tail;
    quoted_tail[..available].copy_from_slice(&quoted[tail..tail + available]);
    Some(FragmentationNeeded {
        reply: FiveTuple {
            src: IpAddr::V4(addr4(quoted, 16)),
            dst: IpAddr::V4(addr4(quoted, 12)),
            protocol,
            src_port: dst_port,
            dst_port: src_port,
        },
        hop_limit: bytes[8],
        mtu,
        quoted_ttl: quoted[8],
        quoted_tail,
    })
}

/// Replaces `packet` with the `ICMPv6` Packet Too Big that tells the sender
/// of `original` about `error` (ns `restore_packet_too_big` and
/// `original_ipv6_quote`): from the mapped LAN host to the original source,
/// with the MTU raised by the header difference (at least 1280) and a quote
/// of the original IPv6 header and 8 bytes of its transport header.
pub(super) fn packet_too_big(
    packet: &mut PacketBuf,
    original: &FiveTuple,
    error: &FragmentationNeeded,
) {
    let (IpAddr::V6(client), IpAddr::V6(host)) = (original.src, original.dst) else {
        return;
    };
    let mtu = (u32::from(error.mtu) + 20).max(IPV6_MINIMUM_MTU);
    let protocol = ipv6_protocol(original.protocol);
    let mut out = [0; PACKET_TOO_BIG_LEN];
    out[0] = 0x60;
    put16(&mut out, 4, 56);
    out[6] = protocol::ICMPV6;
    out[7] = error.hop_limit;
    out[8..24].copy_from_slice(&host.octets());
    out[24..40].copy_from_slice(&client.octets());
    out[40] = ICMPV6_PACKET_TOO_BIG;
    out[44..48].copy_from_slice(&mtu.to_be_bytes());
    let quote = &mut out[48..];
    quote[0] = 0x60;
    put16(quote, 4, 8);
    quote[6] = protocol;
    quote[7] = error.quoted_ttl;
    quote[8..24].copy_from_slice(&client.octets());
    quote[24..40].copy_from_slice(&host.octets());
    if protocol == protocol::ICMPV6 {
        quote[40] = ICMPV6_ECHO_REQUEST;
        put16(quote, 44, original.src_port);
        quote[46..48].copy_from_slice(&error.quoted_tail[..2]);
    } else {
        put16(quote, 40, original.src_port);
        put16(quote, 42, original.dst_port);
        quote[44..48].copy_from_slice(&error.quoted_tail);
    }
    let checksum = transport_checksum_v6(host, client, protocol::ICMPV6, &out[40..]);
    put16(&mut out, 42, checksum);
    packet.set_len(PACKET_TOO_BIG_LEN);
    packet.as_packet_mut().copy_from_slice(&out);
}

/// The on-wire form of a computed checksum: UDP never sends zero.
const fn finish(protocol: u8, checksum: u16) -> u16 {
    if protocol == protocol::UDP {
        udp_wire(checksum)
    } else {
        checksum
    }
}

/// Lowers the MSS option of a TCP SYN (or SYN-ACK) `segment` to `maximum`
/// (ns `clamp_tcp_mss`). The caller recomputes the checksum.
fn clamp_tcp_mss(segment: &mut [u8], maximum: u16) {
    if segment.len() < 20 || segment[13] & TCP_SYN == 0 {
        return;
    }
    let end = usize::from(segment[12] >> 4) * 4;
    if end < 20 || segment.len() < end {
        return;
    }
    let mut option = 20;
    while option < end {
        match segment[option] {
            0 => return,
            1 => option += 1,
            2 if option + 4 <= end && segment[option + 1] == 4 => {
                if be16(segment, option + 2) > maximum {
                    put16(segment, option + 2, maximum);
                }
                return;
            }
            _ => {
                let Some(&length) = segment.get(option + 1) else {
                    return;
                };
                let length = usize::from(length);
                if length < 2 || option + length > end {
                    return;
                }
                option += length;
            }
        }
    }
}
