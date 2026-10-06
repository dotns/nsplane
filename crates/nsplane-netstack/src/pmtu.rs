//! Path MTU discovery for the stack's own TCP connections (RFC 1191, RFC 8201).
//!
//! An ICMP Destination Unreachable / Fragmentation Needed (type 3, code 4) or an `ICMPv6`
//! Packet Too Big (type 2) that quotes a TCP segment the stack sent lowers that
//! connection's MSS. This module only reads the message; the driver checks it against
//! the stack's addresses, MTU and live connections.

use std::net::SocketAddr;

use nsplane_packet::{IcmpHeader, IpPacket, protocol};

use crate::ownership::{ICMP_HEADER, quoted_tuple};

/// ICMP Destination Unreachable, and its Fragmentation Needed code (RFC 792, RFC 1191).
const DESTINATION_UNREACHABLE: u8 = 3;
const FRAGMENTATION_NEEDED: u8 = 4;
/// `ICMPv6` Packet Too Big (RFC 4443).
const PACKET_TOO_BIG: u8 = 2;
/// The lowest path MTU taken from an IPv4 message: the datagram size every host accepts
/// (RFC 791), and the stack's own `MIN_MTU`.
const MIN_PATH_MTU_V4: u32 = 576;
/// The lowest path MTU taken from an IPv6 message, the IPv6 minimum link MTU (RFC 8200).
const MIN_PATH_MTU_V6: u32 = 1280;
/// Quoted TCP header bytes needed: the ports and the sequence number.
const QUOTED_TCP: usize = 8;

/// What an ICMP or `ICMPv6` packet to the stack is.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Message {
    /// Not a Fragmentation Needed or Packet Too Big.
    Other,
    /// A Fragmentation Needed or Packet Too Big the stack does not act on: its quote is
    /// not a TCP segment from an address of the message's family, or its MTU is 0 or
    /// below the family's minimum.
    Ignored,
    /// A Fragmentation Needed or Packet Too Big for a TCP segment.
    TooBig(TooBig),
}

/// A path MTU reported for a TCP segment.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TooBig {
    /// The segment's source, from the stack's side.
    pub(crate) local: SocketAddr,
    /// The segment's destination.
    pub(crate) remote: SocketAddr,
    /// The segment's sequence number.
    pub(crate) seq: u32,
    /// The reported path MTU, at least the family's minimum.
    pub(crate) mtu: u32,
}

impl TooBig {
    /// The MSS that fits the path MTU, by the rule the stack advertises with: `mtu - 40`
    /// over IPv4, `mtu - 60` over IPv6.
    pub(crate) fn mss(&self) -> usize {
        let headers = if self.local.is_ipv4() { 40 } else { 60 };
        usize::try_from(self.mtu - headers).unwrap_or(usize::MAX)
    }
}

/// Reads an ICMP or `ICMPv6` packet to the stack. Checksums are not verified, as elsewhere
/// in the stack.
pub(crate) fn parse(packet: &[u8]) -> Message {
    let Ok(ip) = IpPacket::parse(packet) else {
        return Message::Other;
    };
    let icmp = ip.payload();
    let Ok((header, _)) = IcmpHeader::parse(icmp) else {
        return Message::Other;
    };
    let v4 = ip.src().is_ipv4();
    let (mtu, min) = match (v4, ip.protocol(), header.icmp_type(), header.code()) {
        (true, protocol::ICMP, DESTINATION_UNREACHABLE, FRAGMENTATION_NEEDED) => {
            // RFC 1191: the next-hop MTU is the low 16 bits of the rest of the header. An
            // old router sends 0; the stack does not guess a plateau for it.
            (u32::from(header.sequence()), MIN_PATH_MTU_V4)
        }
        (false, protocol::ICMPV6, PACKET_TOO_BIG, _) => (
            (u32::from(header.identifier()) << 16) | u32::from(header.sequence()),
            MIN_PATH_MTU_V6,
        ),
        _ => return Message::Other,
    };
    if mtu < min {
        return Message::Ignored;
    }
    let Some((protocol::TCP, local, remote, tcp)) = icmp.get(ICMP_HEADER..).and_then(quoted_tuple)
    else {
        return Message::Ignored;
    };
    let Some(&[_, _, _, _, s0, s1, s2, s3]) = tcp.get(..QUOTED_TCP) else {
        return Message::Ignored;
    };
    if local.is_ipv4() != v4 {
        return Message::Ignored;
    }
    Message::TooBig(TooBig {
        local,
        remote,
        seq: u32::from_be_bytes([s0, s1, s2, s3]),
        mtu,
    })
}
