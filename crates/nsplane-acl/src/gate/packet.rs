//! IPv4 header parsing and flow/fragment keys.

use std::net::Ipv4Addr;

use nsplane_packet::PeerId;

use super::PacketDirection;
use super::policy::Slot;
use super::state::{FlowKey, FragmentKey};
use crate::rules::Transport;

#[derive(Debug, Clone, Copy)]
pub(super) struct PacketMeta {
    pub(super) source: Ipv4Addr,
    pub(super) destination: Ipv4Addr,
    pub(super) protocol: u8,
    pub(super) src_port: Option<u16>,
    pub(super) dst_port: Option<u16>,
    pub(super) tcp_flags: u8,
    pub(super) icmp_type: Option<u8>,
    pub(super) icmp_identifier: Option<u16>,
    pub(super) identification: u16,
    pub(super) fragment_offset: u16,
    pub(super) more_fragments: bool,
}

impl PacketMeta {
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
        let payload = &packet[ihl..total_len];
        let (src_port, dst_port, tcp_flags, icmp_type, icmp_identifier) = match protocol {
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
            1 if payload.len() >= 8 => (
                None,
                None,
                0,
                Some(payload[0]),
                Some(u16::from_be_bytes([payload[4], payload[5]])),
            ),
            6 | 17 | 1 => return None,
            _ => (None, None, 0, None, None),
        };
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

    pub(super) const fn is_reverse_only(self) -> bool {
        match self.protocol {
            6 => self.tcp_flags & 0x02 == 0 || self.tcp_flags & 0x10 != 0,
            1 => matches!(self.icmp_type, Some(0 | 3 | 4 | 5 | 11 | 12)),
            _ => false,
        }
    }

    pub(super) const fn tcp_terminal(self) -> bool {
        self.protocol == 6 && self.tcp_flags & (0x01 | 0x04) != 0
    }

    pub(super) const fn tcp_initial_syn(self) -> bool {
        self.protocol == 6 && self.tcp_flags & 0x02 != 0 && self.tcp_flags & 0x10 == 0
    }

    pub(super) const fn is_icmp_error(self) -> bool {
        self.protocol == 1 && matches!(self.icmp_type, Some(3 | 4 | 11 | 12))
    }

    /// The packet's `(remote, local)` addresses.
    pub(super) const fn endpoints(self, direction: PacketDirection) -> (Ipv4Addr, Ipv4Addr) {
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
                (1, _, _, Some(icmp_type)) => Transport::Icmp { icmp_type },
                (protocol, ..) => Transport::Ip(protocol),
            },
        )
    }

    pub(super) const fn fragment_key(
        self,
        slot: Slot,
        direction: PacketDirection,
        peer: PeerId,
    ) -> FragmentKey {
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

pub(super) const fn packet_ipv4_endpoints(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some((
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    ))
}

pub(super) fn flow_key(
    slot: Slot,
    direction: PacketDirection,
    peer: PeerId,
    packet: &PacketMeta,
) -> Option<FlowKey> {
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

/// Resolve the original flow quoted by an `ICMPv4` error. The quoted packet is
/// checked against the opposite direction and never creates state of its own.
pub(super) fn related_flow_key(
    slot: Slot,
    direction: PacketDirection,
    peer: PeerId,
    packet: &[u8],
) -> Option<FlowKey> {
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
    let inner_source = Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]);
    let inner_destination = Ipv4Addr::new(inner[16], inner[17], inner[18], inner[19]);
    let protocol = inner[9];
    let payload = &inner[inner_ihl..];
    let (inner_src_port, inner_dst_port) = match protocol {
        6 | 17 => (
            u16::from_be_bytes([payload[0], payload[1]]),
            u16::from_be_bytes([payload[2], payload[3]]),
        ),
        1 => {
            let identifier = u16::from_be_bytes([payload[4], payload[5]]);
            (identifier, identifier)
        }
        _ => (0, 0),
    };
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
