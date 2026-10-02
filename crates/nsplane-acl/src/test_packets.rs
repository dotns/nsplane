//! Hand-built IP packets for the filter tests.

use std::net::IpAddr;

use nsplane_packet::{PacketBuf, protocol};

#[derive(Clone, Copy)]
/// IPv4 fragment fields: identification, offset in 8-byte units, more fragments.
pub(crate) struct Frag {
    pub(crate) id: u16,
    pub(crate) offset_units: u16,
    pub(crate) more: bool,
}

/// An IP packet carrying `transport` (a full transport header plus payload).
pub(crate) fn ip(src: IpAddr, dst: IpAddr, proto: u8, transport: &[u8]) -> PacketBuf {
    ip_frag(src, dst, proto, transport, None)
}

/// An IPv4 or IPv6 packet; `frag` applies to IPv4 only.
pub(crate) fn ip_frag(
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    transport: &[u8],
    frag: Option<Frag>,
) -> PacketBuf {
    let mut bytes = Vec::new();
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = u16::try_from(20 + transport.len()).unwrap();
            let flags = frag.map_or(0, |f| f.offset_units | if f.more { 0x2000 } else { 0 });
            let id = frag.map_or(0, |f| f.id);
            bytes.extend_from_slice(&[0x45, 0]);
            bytes.extend_from_slice(&total.to_be_bytes());
            bytes.extend_from_slice(&id.to_be_bytes());
            bytes.extend_from_slice(&flags.to_be_bytes());
            bytes.extend_from_slice(&[64, proto, 0, 0]);
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let len = u16::try_from(transport.len()).unwrap();
            bytes.extend_from_slice(&[0x60, 0, 0, 0]);
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(&[proto, 64]);
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
        }
        _ => panic!("mixed address families"),
    }
    bytes.extend_from_slice(transport);
    PacketBuf::from_packet(&bytes)
}

/// A TCP header (no options) followed by `payload`.
pub(crate) fn tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&src_port.to_be_bytes());
    t.extend_from_slice(&dst_port.to_be_bytes());
    t.extend_from_slice(&[0; 8]);
    t.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(payload);
    t
}

/// A UDP header followed by `payload`.
pub(crate) fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(8 + payload.len()).unwrap();
    let mut u = Vec::new();
    u.extend_from_slice(&src_port.to_be_bytes());
    u.extend_from_slice(&dst_port.to_be_bytes());
    u.extend_from_slice(&len.to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    u
}

/// An ICMP echo header of type `icmp_type` with identifier `id`.
pub(crate) fn icmp_echo(icmp_type: u8, id: u16) -> Vec<u8> {
    let mut i = vec![icmp_type, 0, 0, 0];
    i.extend_from_slice(&id.to_be_bytes());
    i.extend_from_slice(&[0, 1]);
    i
}

/// A TCP packet.
pub(crate) fn tcp_packet(src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> PacketBuf {
    ip(src, dst, protocol::TCP, &tcp(sport, dport, b"data"))
}

/// A UDP packet.
pub(crate) fn udp_packet(src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> PacketBuf {
    ip(src, dst, protocol::UDP, &udp(sport, dport, b"data"))
}
