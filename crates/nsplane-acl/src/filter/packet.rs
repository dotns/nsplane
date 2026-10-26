//! Raw header and flow helpers.

use std::net::{IpAddr, Ipv4Addr};

use nsplane_packet::{FiveTuple, IcmpHeader, IpPacket, protocol};

use super::table::AllowedKey;
use crate::net::{IpNet, Protocol};
use crate::rules::{Flow, Transport};

/// The fragment fields of a raw IPv4 header (at least 20 bytes, version 4):
/// the key, whether the offset is non-zero, and whether it is the first
/// fragment of several.
pub(super) const fn ipv4_fragment(bytes: &[u8]) -> Option<(AllowedKey, bool, bool)> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
    let key = AllowedKey {
        src: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        dst: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        protocol: bytes[9],
        id: u16::from_be_bytes([bytes[4], bytes[5]]),
    };
    let offset = flags & 0x1fff;
    Some((key, offset > 0, offset == 0 && flags & 0x2000 != 0))
}

/// Whether a raw IPv4 packet is addressed to `local`.
pub(super) fn is_to_local(bytes: &[u8], local: Ipv4Addr) -> bool {
    bytes.len() >= 20 && bytes[0] >> 4 == 4 && bytes[16..20] == local.octets()
}

/// Whether the source address of an IPv4 or IPv6 packet, read from the raw
/// header, lies in one of `prefixes`; `false` when the buffer is too short to
/// hold it or the version is neither 4 nor 6.
pub(super) fn source_in(bytes: &[u8], prefixes: &[IpNet]) -> bool {
    let source = match bytes.first().map(|b| b >> 4) {
        Some(4) => bytes
            .get(12..16)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(IpAddr::from),
        Some(6) => bytes
            .get(8..24)
            .and_then(|s| <[u8; 16]>::try_from(s).ok())
            .map(IpAddr::from),
        _ => None,
    };
    source.is_some_and(|source| prefixes.iter().any(|net| net.contains(&source)))
}

/// Whether a packet is an IPv4 ICMP echo reply, read from the raw header
/// whatever its fragment offset.
pub(super) fn is_icmp_echo_reply(bytes: &[u8]) -> bool {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return false;
    }
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    if ihl < 20 || bytes.len() < ihl + 8 || bytes[9] != protocol::ICMP {
        return false;
    }
    bytes[ihl] == 0
}

/// The flow of a TCP or UDP five-tuple.
pub(super) const fn tcp_udp_flow(tuple: &FiveTuple, protocol: Protocol) -> Flow {
    let (src_port, dst_port) = (tuple.src_port, tuple.dst_port);
    Flow {
        src: tuple.src,
        dst: tuple.dst,
        transport: match protocol {
            Protocol::Tcp => Transport::Tcp { src_port, dst_port },
            Protocol::Udp => Transport::Udp { src_port, dst_port },
        },
    }
}

/// The transport of a packet that is neither TCP nor UDP: ICMP on IPv4 and
/// `ICMPv6` on IPv6 by message type, any other protocol by number.
pub(super) fn other_transport(packet: &IpPacket<'_>, protocol: u8) -> Option<Transport> {
    match (packet.src(), protocol) {
        (IpAddr::V4(_), protocol::ICMP) | (IpAddr::V6(_), protocol::ICMPV6) => {
            let (icmp, _) = IcmpHeader::parse(packet.payload()).ok()?;
            Some(Transport::Icmp {
                icmp_type: icmp.icmp_type(),
            })
        }
        (_, number) => Some(Transport::Ip(number)),
    }
}

pub(super) const fn is_icmp(protocol: u8) -> bool {
    matches!(protocol, protocol::ICMP | protocol::ICMPV6)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EchoType {
    Request,
    Reply,
}

/// The echo type of an ICMP or `ICMPv6` packet, `None` for other messages.
pub(super) fn echo_type(packet: &IpPacket<'_>) -> Option<EchoType> {
    let (icmp, _) = IcmpHeader::parse(packet.payload()).ok()?;
    match (packet.protocol(), icmp.icmp_type()) {
        (protocol::ICMP, 8) | (protocol::ICMPV6, 128) => Some(EchoType::Request),
        (protocol::ICMP, 0) | (protocol::ICMPV6, 129) => Some(EchoType::Reply),
        _ => None,
    }
}
