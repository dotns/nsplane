//! ICMP Echo request classification and in-place Echo reply synthesis for
//! addresses answered locally.
//!
//! [`is_echo_request`] tells whether a packet is an ICMP or `ICMPv6` Echo
//! request without touching it, so a caller can pick the pings it answers
//! before handing them to [`echo_reply_in_place`]. It accepts the requests
//! [`echo_reply_in_place`] rewrites, as well as a few it refuses (it only
//! classifies, so it stays permissive):
//!
//! - **IPv4**: protocol 1, ICMP type 8, code 0, with the IPv4 header parsing
//!   and the 8-byte ICMP header present within the total length. A non-first
//!   fragment (offset other than 0) never starts with an ICMP header and is
//!   `false`; a first fragment (offset 0, more-fragments set) whose ICMP
//!   header is complete is `true`.
//! - **IPv6**: next header 58 (`ICMPv6`) in the fixed header, type 128,
//!   code 0, with the 8-byte header present within the payload length; IPv6
//!   extension headers are not walked, so a request behind one is `false`.
//! - Bytes beyond the length the IP header declares are ignored; a buffer
//!   shorter than that length is `false`. Checksums are not verified.
//!
//! [`echo_reply_in_place`] turns an ICMP Echo request into its Echo reply in
//! the same buffer, so a caller that answers pings for an address it owns can
//! send the request's bytes straight back:
//!
//! - **IPv4**: an ICMP Echo request (type 8, code 0) gets its source and
//!   destination swapped and type 0 (Echo reply); the ICMP checksum is
//!   recomputed over the ICMP message and the header checksum over the IPv4
//!   header (options included, kept as they are).
//! - **IPv6**: an `ICMPv6` Echo request (type 128, code 0) directly after the
//!   fixed header gets its source and destination swapped and type 129 (Echo
//!   reply); the `ICMPv6` checksum is recomputed with the IPv6 pseudo-header.
//! - The TTL / hop limit is unchanged, and so are the identifier, the
//!   sequence number and the payload.
//!
//! Anything else returns `false` and leaves the buffer byte-for-byte
//! untouched: other ICMP types and codes, other protocols, IPv6 extension
//! headers (only the next header of the fixed header is looked at), IPv4
//! fragments other than a whole datagram (a fragment's checksum cannot be
//! recomputed), malformed or truncated packets, and packets whose length
//! differs from the one their IP header declares (trailing bytes would
//! otherwise be summed into the ICMP checksum). The packet is fully validated
//! before anything is written. Incoming checksums are not verified.
//!
//! Only the packet transform lives here: probing the real destination (for
//! instance with a host ICMP socket) before answering is up to the caller.

use crate::checksum::{internet_checksum, ipv4_header_checksum, transport_checksum_v6};
use crate::ip::{IcmpHeader, Ipv4Header, Ipv6Header};
use crate::protocol;

/// ICMP Echo request / reply types (RFC 792).
const ECHO_REQUEST_V4: u8 = 8;
const ECHO_REPLY_V4: u8 = 0;
/// `ICMPv6` Echo request / reply types (RFC 4443).
const ECHO_REQUEST_V6: u8 = 128;
const ECHO_REPLY_V6: u8 = 129;
/// Byte range of the source and destination addresses in each IP header.
const IPV4_ADDRESSES: std::ops::Range<usize> = 12..20;
const IPV6_ADDRESSES: std::ops::Range<usize> = 8..40;
/// Byte range of the checksum field in the IPv4 header and the ICMP header.
const IPV4_CHECKSUM: std::ops::Range<usize> = 10..12;
const ICMP_CHECKSUM: std::ops::Range<usize> = 2..4;
/// Length of the IPv6 fixed header.
const IPV6_HEADER_LEN: usize = 40;

/// Whether `packet` is an IPv4 ICMP or IPv6 `ICMPv6` Echo request; never
/// modifies it. See the [module docs](self).
pub fn is_echo_request(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Ipv4Header::parse(packet).is_ok_and(|(header, message)| {
            header.protocol() == protocol::ICMP
                && header.fragment_offset() == 0
                && is_echo_message(message, ECHO_REQUEST_V4)
        }),
        Some(6) => Ipv6Header::parse(packet).is_ok_and(|(header, message)| {
            header.next_header() == protocol::ICMPV6 && is_echo_message(message, ECHO_REQUEST_V6)
        }),
        _ => false,
    }
}

/// Rewrites the IPv4 ICMP or IPv6 `ICMPv6` Echo request in `packet` into its
/// Echo reply and returns `true`; returns `false` and leaves `packet`
/// untouched for anything else. See the [module docs](self).
pub fn echo_reply_in_place(packet: &mut [u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => reply_v4(packet),
        Some(6) => reply_v6(packet),
        _ => false,
    }
}

/// Whether `message` is an ICMP or `ICMPv6` Echo request of type `request`
/// (code 0, at least the 8-byte header).
fn is_echo_message(message: &[u8], request: u8) -> bool {
    IcmpHeader::parse(message)
        .is_ok_and(|(header, _)| header.icmp_type() == request && header.code() == 0)
}

fn reply_v4(packet: &mut [u8]) -> bool {
    let header_len = {
        let Ok((header, message)) = Ipv4Header::parse(packet) else {
            return false;
        };
        let whole = !header.more_fragments() && header.fragment_offset() == 0;
        if usize::from(header.total_len()) != packet.len()
            || header.protocol() != protocol::ICMP
            || !whole
            || !is_echo_message(message, ECHO_REQUEST_V4)
        {
            return false;
        }
        header.header_len()
    };
    let (src, dst) = packet[IPV4_ADDRESSES].split_at_mut(4);
    src.swap_with_slice(dst);
    let message = &mut packet[header_len..];
    message[0] = ECHO_REPLY_V4;
    message[ICMP_CHECKSUM].fill(0);
    let sum = internet_checksum(message);
    message[ICMP_CHECKSUM].copy_from_slice(&sum.to_be_bytes());
    let sum = ipv4_header_checksum(&packet[..header_len]);
    packet[IPV4_CHECKSUM].copy_from_slice(&sum.to_be_bytes());
    true
}

fn reply_v6(packet: &mut [u8]) -> bool {
    let (src, dst) = {
        let Ok((header, message)) = Ipv6Header::parse(packet) else {
            return false;
        };
        if IPV6_HEADER_LEN + usize::from(header.payload_len()) != packet.len()
            || header.next_header() != protocol::ICMPV6
            || !is_echo_message(message, ECHO_REQUEST_V6)
        {
            return false;
        }
        (header.dst(), header.src())
    };
    let (old_src, old_dst) = packet[IPV6_ADDRESSES].split_at_mut(16);
    old_src.swap_with_slice(old_dst);
    let message = &mut packet[IPV6_HEADER_LEN..];
    message[0] = ECHO_REPLY_V6;
    message[ICMP_CHECKSUM].fill(0);
    let sum = transport_checksum_v6(src, dst, protocol::ICMPV6, message);
    message[ICMP_CHECKSUM].copy_from_slice(&sum.to_be_bytes());
    true
}

#[cfg(test)]
mod tests;
