//! Raw TCP header helpers.

use std::net::{IpAddr, SocketAddr};

use nsplane_packet::{IpPacket, PacketBuf, checksum, protocol};
use smoltcp::wire::IpEndpoint;

use crate::device::TAILROOM;
use crate::pending::{self};

/// Locates a TCP segment before reserving listener capacity.
pub(crate) fn tcp_segment(pkt: &[u8]) -> Option<&[u8]> {
    if pkt.first().is_some_and(|byte| byte >> 4 == 6) {
        let packet = smoltcp::wire::Ipv6Packet::new_checked(pkt).ok()?;
        let mut next = packet.next_header();
        let mut offset = 40;
        // Match smoltcp's receiver: one Hop-by-Hop header may precede TCP.
        if next == smoltcp::wire::IpProtocol::HopByHop {
            let extension = smoltcp::wire::Ipv6ExtHeader::new_checked(packet.payload()).ok()?;
            next = extension.next_header();
            offset += (usize::from(extension.header_len()) + 1) * 8;
        }
        if next != smoltcp::wire::IpProtocol::Tcp {
            return None;
        }
        return pkt.get(offset..40 + usize::from(packet.payload_len()));
    }
    let (&first, rest) = pkt.split_first()?;
    if pkt.len() < 20 || first >> 4 != 4 || rest.get(8) != Some(&protocol::TCP) {
        return None;
    }
    let ihl = usize::from(first & 0xf) * 4;
    if pkt.len() < ihl + 4 {
        return None;
    }
    pkt.get(ihl..)
}

/// The `(src, dst)` of a TCP packet.
pub(crate) fn tcp_tuple(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let segment = tcp_segment(pkt)?;
    let (src_port, dst_port) = (
        u16::from_be_bytes([*segment.first()?, *segment.get(1)?]),
        u16::from_be_bytes([*segment.get(2)?, *segment.get(3)?]),
    );
    let ip = IpPacket::parse(pkt).ok()?;
    Some((
        SocketAddr::new(ip.src(), src_port),
        SocketAddr::new(ip.dst(), dst_port),
    ))
}

/// What a packet dropped from the backlog leaves behind: an empty packet, which keeps the
/// later packets' egress positions and which the source discards.
pub(super) fn placeholder() -> PacketBuf {
    PacketBuf::with_capacity(0)
}

/// The RST answering the bare SYN `syn`, from its destination (RFC 9293 section 3.10.7.1:
/// sequence number 0, acknowledging the SYN and its data).
pub(crate) fn tcp_reset(syn: &[u8]) -> Option<PacketBuf> {
    const RST_ACK: u8 = 0x14;
    const FIN: u8 = 0x01;
    let segment = tcp_segment(syn)?;
    let (&[src_hi, src_lo, dst_hi, dst_lo, s0, s1, s2, s3], rest) =
        segment.split_first_chunk::<8>()?;
    let offset = usize::from(rest.get(4)? >> 4) * 4;
    let flags = *rest.get(5)?;
    let data = segment.len().checked_sub(offset)?;
    let length = u32::try_from(data).ok()? + 1 + u32::from(flags & FIN);
    let ack = u32::from_be_bytes([s0, s1, s2, s3]).wrapping_add(length);
    let mut reply = [0u8; 20];
    reply[0..2].copy_from_slice(&[dst_hi, dst_lo]);
    reply[2..4].copy_from_slice(&[src_hi, src_lo]);
    reply[8..12].copy_from_slice(&ack.to_be_bytes());
    reply[12] = 5 << 4;
    reply[13] = RST_ACK;
    let ip = IpPacket::parse(syn).ok()?;
    let (src, dst) = (ip.dst(), ip.src());
    let (header, total) = match src {
        IpAddr::V4(_) => (20, 40),
        IpAddr::V6(_) => (40, 60),
    };
    let mut packet = PacketBuf::with_capacity(total + TAILROOM);
    packet.set_len(total);
    let bytes = packet.as_packet_mut();
    let (head, tcp) = bytes.split_at_mut(header);
    tcp.copy_from_slice(&reply);
    let sum = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            head[0] = 0x45;
            head[2..4].copy_from_slice(&40u16.to_be_bytes());
            head[6] = 0x40;
            head[8] = 64;
            head[9] = protocol::TCP;
            head[12..16].copy_from_slice(&src.octets());
            head[16..20].copy_from_slice(&dst.octets());
            let header_checksum = checksum::ipv4_header_checksum(head);
            head[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            pending::pseudo_header_checksum(src.into(), dst.into(), protocol::TCP, tcp)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            head[0] = 0x60;
            head[4..6].copy_from_slice(&20u16.to_be_bytes());
            head[6] = protocol::TCP;
            head[7] = 64;
            head[8..24].copy_from_slice(&src.octets());
            head[24..40].copy_from_slice(&dst.octets());
            pending::pseudo_header_checksum(src.into(), dst.into(), protocol::TCP, tcp)
        }
        _ => return None,
    };
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    Some(packet)
}

pub(super) fn tcp_dst_port(pkt: &[u8]) -> Option<u16> {
    let segment = tcp_segment(pkt)?;
    Some(u16::from_be_bytes([*segment.get(2)?, *segment.get(3)?]))
}

/// Whether a raw IP packet is a bare TCP SYN (a connection attempt, not the SYN-ACK of
/// one the stack opened).
pub(super) fn tcp_is_syn(pkt: &[u8]) -> bool {
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    let Some(&flags) = tcp_segment(pkt).and_then(|segment| segment.get(13)) else {
        return false;
    };
    flags & SYN != 0 && flags & ACK == 0
}

/// Converts a smoltcp endpoint to a std socket address.
pub(super) fn endpoint_to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.addr.into(), endpoint.port)
}
