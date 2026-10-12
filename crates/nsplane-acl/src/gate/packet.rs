//! IPv4 and IPv6 header parsing and flow/fragment keys.

use std::net::{Ipv4Addr, Ipv6Addr};

use nsplane_packet::PeerId;

use super::PacketDirection;
use super::addr::{GateAddr, address_at};
use super::policy::Slot;
use super::state::{FlowKey, FragmentKey};
use crate::rules::Transport;

/// At most this many IPv6 extension headers precede the upper layer.
const MAX_EXTENSION_HEADERS: usize = 8;

#[derive(Debug, Clone, Copy)]
pub(super) struct PacketMeta<A: GateAddr> {
    pub(super) source: A,
    pub(super) destination: A,
    /// The upper-layer protocol (for IPv6, behind the extension headers).
    pub(super) protocol: u8,
    pub(super) src_port: Option<u16>,
    pub(super) dst_port: Option<u16>,
    pub(super) tcp_flags: u8,
    pub(super) icmp_type: Option<u8>,
    pub(super) icmp_identifier: Option<u16>,
    pub(super) identification: A::FragmentId,
    pub(super) fragment_offset: u16,
    pub(super) more_fragments: bool,
}

/// The transport fields of an upper-layer header: ports, TCP flags, ICMP
/// type and identifier.
type Upper = (Option<u16>, Option<u16>, u8, Option<u8>, Option<u16>);

/// The transport fields of the upper-layer `payload` of `protocol`; `None`
/// when a TCP, UDP or ICMP (`icmp`) header is truncated.
#[inline]
const fn upper_layer(protocol: u8, icmp: u8, payload: &[u8]) -> Option<Upper> {
    Some(match protocol {
        6 if payload.len() >= 20 => (
            Some(u16::from_be_bytes([payload[0], payload[1]])),
            Some(u16::from_be_bytes([payload[2], payload[3]])),
            payload[13],
            None,
            None,
        ),
        17 if payload.len() >= 8 => (
            Some(u16::from_be_bytes([payload[0], payload[1]])),
            Some(u16::from_be_bytes([payload[2], payload[3]])),
            0,
            None,
            None,
        ),
        _ if protocol == icmp && payload.len() >= 8 => (
            None,
            None,
            0,
            Some(payload[0]),
            Some(u16::from_be_bytes([payload[4], payload[5]])),
        ),
        6 | 17 => return None,
        _ if protocol == icmp => return None,
        _ => (None, None, 0, None, None),
    })
}

impl PacketMeta<Ipv4Addr> {
    pub(super) fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return None;
        }
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        if ihl < 20 || packet.len() < ihl {
            return None;
        }
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if total_len < ihl || packet.len() < total_len {
            return None;
        }
        let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
        let fragment_offset = flags_offset & 0x1fff;
        let more_fragments = flags_offset & 0x2000 != 0;
        let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let protocol = packet[9];
        let identification = u16::from_be_bytes([packet[4], packet[5]]);
        if fragment_offset != 0 {
            return Some(Self {
                source,
                destination,
                protocol,
                src_port: None,
                dst_port: None,
                tcp_flags: 0,
                icmp_type: None,
                icmp_identifier: None,
                identification,
                fragment_offset,
                more_fragments,
            });
        }
        let (src_port, dst_port, tcp_flags, icmp_type, icmp_identifier) =
            upper_layer(protocol, 1, &packet[ihl..total_len])?;
        Some(Self {
            source,
            destination,
            protocol,
            src_port,
            dst_port,
            tcp_flags,
            icmp_type,
            icmp_identifier,
            identification,
            fragment_offset,
            more_fragments,
        })
    }
}

/// The upper layer of an IPv6 packet, behind its extension headers.
#[derive(Debug, Clone, Copy)]
struct Chain {
    /// The upper-layer protocol: the last next-header value.
    protocol: u8,
    /// Where the upper-layer header (or a later fragment's data) starts.
    offset: usize,
    /// The Fragment header's identification, offset (in 8-byte units) and
    /// more-fragments flag.
    fragment: Option<(u32, u16, bool)>,
}

/// Walk the extension headers of the IPv6 packet `packet` (40 bytes of
/// fixed header, then its payload; every header must lie within it):
/// Hop-by-Hop, Routing and Destination Options by their length, AH by its
/// own length, and one Fragment header, after which a later fragment holds
/// no more headers. `None` for a truncated chain, more than
/// [`MAX_EXTENSION_HEADERS`] headers or a second Fragment header.
fn walk_v6(packet: &[u8]) -> Option<Chain> {
    let mut protocol = *packet.get(6)?;
    let mut offset = 40;
    let mut fragment = None;
    for _ in 0..=MAX_EXTENSION_HEADERS {
        let length = match protocol {
            0 | 43 | 60 => (usize::from(*packet.get(offset + 1)?) + 1) * 8,
            51 => (usize::from(*packet.get(offset + 1)?) + 2) * 4,
            44 if fragment.is_none() => 8,
            _ => {
                return (protocol != 44).then_some(Chain {
                    protocol,
                    offset,
                    fragment,
                });
            }
        };
        let header = packet.get(offset..offset + length)?;
        if protocol == 44 {
            let field = u16::from_be_bytes([header[2], header[3]]);
            let identification = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            fragment = Some((identification, field >> 3, field & 1 != 0));
        }
        protocol = header[0];
        offset += length;
        if fragment.is_some_and(|(_, units, _)| units != 0) {
            return Some(Chain {
                protocol,
                offset,
                fragment,
            });
        }
    }
    None
}

/// Parse an IPv6 packet.
pub(super) fn parse_v6(packet: &[u8]) -> Option<PacketMeta<Ipv6Addr>> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let end = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let packet = packet.get(..end)?;
    let chain = walk_v6(packet)?;
    let (identification, fragment_offset, more_fragments) = chain.fragment.unwrap_or((0, 0, false));
    let source = address_at(packet, 8);
    let destination = address_at(packet, 24);
    let protocol = chain.protocol;
    if fragment_offset != 0 {
        return Some(PacketMeta {
            source,
            destination,
            protocol,
            src_port: None,
            dst_port: None,
            tcp_flags: 0,
            icmp_type: None,
            icmp_identifier: None,
            identification,
            fragment_offset,
            more_fragments,
        });
    }
    let (src_port, dst_port, tcp_flags, icmp_type, icmp_identifier) =
        upper_layer(protocol, 58, &packet[chain.offset..])?;
    Some(PacketMeta {
        source,
        destination,
        protocol,
        src_port,
        dst_port,
        tcp_flags,
        icmp_type,
        icmp_identifier,
        identification,
        fragment_offset,
        more_fragments,
    })
}

impl<A: GateAddr> PacketMeta<A> {
    pub(super) fn is_reverse_only(self) -> bool {
        match self.protocol {
            6 => self.tcp_flags & 0x02 == 0 || self.tcp_flags & 0x10 != 0,
            protocol if protocol == A::ICMP => self.icmp_type.is_some_and(A::is_reverse_only_icmp),
            _ => false,
        }
    }

    pub(super) const fn tcp_terminal(self) -> bool {
        self.protocol == 6 && self.tcp_flags & (0x01 | 0x04) != 0
    }

    pub(super) const fn tcp_initial_syn(self) -> bool {
        self.protocol == 6 && self.tcp_flags & 0x02 != 0 && self.tcp_flags & 0x10 == 0
    }

    pub(super) fn is_icmp_error(self) -> bool {
        self.protocol == A::ICMP && self.icmp_type.is_some_and(A::is_icmp_error)
    }

    /// The packet's `(remote, local)` addresses.
    pub(super) const fn endpoints(self, direction: PacketDirection) -> (A, A) {
        match direction {
            PacketDirection::Inbound => (self.source, self.destination),
            PacketDirection::Outbound => (self.destination, self.source),
        }
    }

    /// The transport a grant or rule matches; `None` for a later fragment.
    pub(super) const fn transport(self) -> Option<Transport> {
        if self.fragment_offset != 0 {
            return None;
        }
        Some(
            match (self.protocol, self.src_port, self.dst_port, self.icmp_type) {
                (6, Some(src_port), Some(dst_port), _) => Transport::Tcp { src_port, dst_port },
                (17, Some(src_port), Some(dst_port), _) => Transport::Udp { src_port, dst_port },
                (protocol, _, _, Some(icmp_type)) if protocol == A::ICMP => {
                    Transport::Icmp { icmp_type }
                }
                (protocol, ..) => Transport::Ip(protocol),
            },
        )
    }

    pub(super) const fn fragment_key(
        self,
        slot: Slot,
        direction: PacketDirection,
        peer: PeerId,
    ) -> FragmentKey<A> {
        FragmentKey {
            slot,
            direction,
            peer,
            source: self.source,
            destination: self.destination,
            protocol: self.protocol,
            identification: self.identification,
        }
    }
}

pub(super) fn flow_key<A: GateAddr>(
    slot: Slot,
    direction: PacketDirection,
    peer: PeerId,
    packet: &PacketMeta<A>,
) -> Option<FlowKey<A>> {
    let (remote_ip, local_ip, remote_port, local_port) = match direction {
        PacketDirection::Inbound => (
            packet.source,
            packet.destination,
            packet.src_port.or(packet.icmp_identifier).unwrap_or(0),
            packet.dst_port.or(packet.icmp_identifier).unwrap_or(0),
        ),
        PacketDirection::Outbound => (
            packet.destination,
            packet.source,
            packet.dst_port.or(packet.icmp_identifier).unwrap_or(0),
            packet.src_port.or(packet.icmp_identifier).unwrap_or(0),
        ),
    };
    if matches!(packet.protocol, 6 | 17) && (remote_port == 0 || local_port == 0) {
        return None;
    }
    Some(FlowKey {
        slot,
        peer,
        remote_ip,
        local_ip,
        protocol: packet.protocol,
        remote_port,
        local_port,
    })
}

/// The addresses of an ICMP error and of the packet it quotes, with the
/// quoted protocol and ports (the identifier of a quoted ICMP packet).
#[derive(Debug, Clone, Copy)]
pub(super) struct Quote<A> {
    outer_source: A,
    outer_destination: A,
    inner_source: A,
    inner_destination: A,
    protocol: u8,
    inner_src_port: u16,
    inner_dst_port: u16,
}

/// The ports of a quoted upper-layer header of at least 8 bytes.
const fn quoted_ports(protocol: u8, icmp: u8, payload: &[u8]) -> (u16, u16) {
    match protocol {
        6 | 17 => (
            u16::from_be_bytes([payload[0], payload[1]]),
            u16::from_be_bytes([payload[2], payload[3]]),
        ),
        _ if protocol == icmp => {
            let identifier = u16::from_be_bytes([payload[4], payload[5]]);
            (identifier, identifier)
        }
        _ => (0, 0),
    }
}

/// The quote of an `ICMPv4` error: the quoted IPv4 header and 8 bytes of
/// its upper layer.
pub(super) fn quote_v4(packet: &[u8]) -> Option<Quote<Ipv4Addr>> {
    let outer_ihl = usize::from(*packet.first()? & 0x0f) * 4;
    let outer_source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let outer_destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let inner = packet.get(outer_ihl.checked_add(8)?..)?;
    if inner.len() < 20 || inner[0] >> 4 != 4 {
        return None;
    }
    let inner_ihl = usize::from(inner[0] & 0x0f) * 4;
    if inner_ihl < 20 || inner.len() < inner_ihl + 8 {
        return None;
    }
    let protocol = inner[9];
    let (inner_src_port, inner_dst_port) = quoted_ports(protocol, 1, &inner[inner_ihl..]);
    Some(Quote {
        outer_source,
        outer_destination,
        inner_source: Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]),
        inner_destination: Ipv4Addr::new(inner[16], inner[17], inner[18], inner[19]),
        protocol,
        inner_src_port,
        inner_dst_port,
    })
}

/// The quote of an `ICMPv6` error: the quoted IPv6 header, its extension
/// headers (walked within the quote) and 8 bytes of its upper layer.
pub(super) fn quote_v6(packet: &[u8]) -> Option<Quote<Ipv6Addr>> {
    let end = 40 + usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
    let packet = packet.get(..end)?;
    let outer = walk_v6(packet)?;
    let inner = packet.get(outer.offset.checked_add(8)?..)?;
    if inner.len() < 40 || inner[0] >> 4 != 6 {
        return None;
    }
    let chain = walk_v6(inner)?;
    if chain.fragment.is_some_and(|(_, offset, _)| offset != 0) {
        return None;
    }
    let payload = inner.get(chain.offset..chain.offset + 8)?;
    let (inner_src_port, inner_dst_port) = quoted_ports(chain.protocol, 58, payload);
    Some(Quote {
        outer_source: address_at(packet, 8),
        outer_destination: address_at(packet, 24),
        inner_source: address_at(inner, 8),
        inner_destination: address_at(inner, 24),
        protocol: chain.protocol,
        inner_src_port,
        inner_dst_port,
    })
}

/// Resolve the original flow quoted by an ICMP error. The quoted packet is
/// checked against the opposite direction and never creates state of its own.
pub(super) fn related_flow_key<A: GateAddr>(
    slot: Slot,
    direction: PacketDirection,
    peer: PeerId,
    packet: &[u8],
) -> Option<FlowKey<A>> {
    let Quote {
        outer_source,
        outer_destination,
        inner_source,
        inner_destination,
        protocol,
        inner_src_port,
        inner_dst_port,
    } = A::quote(packet)?;
    let (remote_ip, local_ip, remote_port, local_port) = match direction {
        PacketDirection::Inbound => {
            if inner_source != outer_destination || outer_source != inner_destination {
                return None;
            }
            (
                inner_destination,
                inner_source,
                inner_dst_port,
                inner_src_port,
            )
        }
        PacketDirection::Outbound => {
            if inner_destination != outer_source || outer_destination != inner_source {
                return None;
            }
            (
                inner_source,
                inner_destination,
                inner_src_port,
                inner_dst_port,
            )
        }
    };
    Some(FlowKey {
        slot,
        peer,
        remote_ip,
        local_ip,
        protocol,
        remote_port,
        local_port,
    })
}
