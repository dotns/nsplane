//! Virtio-net offload headers and segmentation of GSO packets; pure, no I/O.
//!
//! A Linux TUN or TAP device with `IFF_VNET_HDR`, or a packet socket with
//! `PACKET_VNET_HDR`, puts a [`VirtioNetHdr`] in front of every packet. A packet read that
//! way may be one TCP or UDP super-packet (GSO) with a partial checksum; [`segment`] splits
//! it into IP packets of `gso_size` payload bytes with complete headers and checksums.

use crate::checksum::{fold, sum_words};
use crate::{PacketBatch, PacketBuf, PacketPool, TAILROOM};

/// Length of an IPv4 header without options.
const IPV4_HDR: usize = 20;
/// Length of the fixed IPv6 header.
const IPV6_HDR: usize = 40;
/// Length of a TCP header without options.
const TCP_HDR: usize = 20;
/// Length of a UDP header.
const UDP_HDR: usize = 8;
/// IP protocol number of TCP.
const TCP: u8 = 6;
/// IP protocol number of UDP.
const UDP: u8 = 17;
/// TCP flag bits.
const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const TCP_CWR: u8 = 0x80;
/// Offset of the checksum field inside the TCP header.
const TCP_CSUM_OFFSET: usize = 16;
/// Offset of the checksum field inside the UDP header.
const UDP_CSUM_OFFSET: usize = 6;
/// Largest IP packet a segment may be.
const MAX_IP_LEN: usize = 65535;

/// `struct virtio_net_hdr` as the legacy virtio-net header carries it: 10 bytes, every
/// 16-bit field in host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtioNetHdr {
    /// [`Self::F_NEEDS_CSUM`] or 0.
    pub flags: u8,
    /// One of the `GSO_*` types, optionally or-ed with [`Self::GSO_ECN`].
    pub gso_type: u8,
    /// Length of the IP and transport headers of a super-packet.
    pub hdr_len: u16,
    /// Transport payload bytes per segment.
    pub gso_size: u16,
    /// Offset of the transport header, where checksumming starts.
    pub csum_start: u16,
    /// Offset of the checksum field from `csum_start`.
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    /// Encoded length in bytes.
    pub const LEN: usize = 10;
    /// The checksum at `csum_start + csum_offset` holds the pseudo-header sum only and
    /// must be completed over the bytes from `csum_start` to the end.
    pub const F_NEEDS_CSUM: u8 = 1;
    /// Not a super-packet.
    pub const GSO_NONE: u8 = 0;
    /// TCP over IPv4 super-packet.
    pub const GSO_TCPV4: u8 = 1;
    /// TCP over IPv6 super-packet.
    pub const GSO_TCPV6: u8 = 4;
    /// UDP super-packet (USO), IPv4 or IPv6.
    pub const GSO_UDP_L4: u8 = 5;
    /// Flag bit: the TCP super-packet has CWR set (on its first segment only).
    pub const GSO_ECN: u8 = 0x80;

    /// Parses the first [`Self::LEN`] bytes of `bytes`.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, OffloadError> {
        let b = bytes
            .first_chunk::<{ Self::LEN }>()
            .ok_or(OffloadError::Truncated)?;
        Ok(Self {
            flags: b[0],
            gso_type: b[1],
            hdr_len: u16::from_ne_bytes([b[2], b[3]]),
            gso_size: u16::from_ne_bytes([b[4], b[5]]),
            csum_start: u16::from_ne_bytes([b[6], b[7]]),
            csum_offset: u16::from_ne_bytes([b[8], b[9]]),
        })
    }

    /// The header as written in front of a packet.
    #[inline]
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0; Self::LEN];
        b[0] = self.flags;
        b[1] = self.gso_type;
        b[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        b[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        b[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        b[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
        b
    }
}

/// Why a header or packet was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OffloadError {
    /// The input is shorter than the headers it must hold (including `hdr_len`).
    Truncated,
    /// The `gso_type` is unknown or unsupported (e.g. UFO, or ECN on UDP).
    UnsupportedGso,
    /// A GSO type with `gso_size` 0.
    ZeroGsoSize,
    /// The IP or transport header does not match the GSO type: wrong version or
    /// protocol, bad IHL or data offset, IPv6 extension headers, or a fragment.
    BadHeaders,
    /// `csum_start + csum_offset` leaves no room for a 16-bit checksum.
    BadChecksumOffset,
    /// A segment would exceed 65535 bytes.
    TooLong,
}

/// Splits one IP packet read behind the virtio-net header `hdr` into IP packets.
///
/// `GSO_NONE` yields the packet itself (with its checksum completed if
/// [`VirtioNetHdr::F_NEEDS_CSUM`] is set). TCP and UDP super-packets yield one packet per
/// `gso_size` bytes of payload (the last may be shorter), each with its own lengths,
/// IPv4 identification (+1 per segment) and header checksum, TCP sequence number and
/// flags (FIN and PSH only on the last segment, CWR only on the first) and a full
/// transport checksum. The header length is taken from the packet (IP header plus TCP
/// data offset or UDP header), not from `hdr_len` or `csum_start`; IPv6 extension
/// headers are not supported.
///
/// Every packet is taken from `pool` with the standard headroom and a capacity of at
/// least `capacity` (or its length plus [`TAILROOM`], if larger, so it is sealed in
/// place), and appended to `out`, starting at segment index `first`. Segments that do not
/// fit into `out` (at most [`MAX_BATCH`](crate::MAX_BATCH) packets) are not produced: the call then returns
/// `Ok(Some(next))` and the caller continues with `first = next` and a batch with room.
/// `Ok(None)` means all segments were produced. A malformed header or packet is an error
/// and produces nothing.
pub fn segment(
    hdr: &VirtioNetHdr,
    packet: &[u8],
    first: usize,
    capacity: usize,
    pool: &mut PacketPool,
    out: &mut PacketBatch,
) -> Result<Option<usize>, OffloadError> {
    let gso = hdr.gso_type & !VirtioNetHdr::GSO_ECN;
    if gso == VirtioNetHdr::GSO_NONE {
        if hdr.gso_type != gso {
            return Err(OffloadError::UnsupportedGso);
        }
        let csum = if hdr.flags & VirtioNetHdr::F_NEEDS_CSUM == 0 {
            None
        } else {
            let start = usize::from(hdr.csum_start);
            let field = start + usize::from(hdr.csum_offset);
            if field + 2 > packet.len() {
                return Err(OffloadError::BadChecksumOffset);
            }
            Some((start, field))
        };
        if first > 0 {
            return Ok(None);
        }
        let mut buf = pool.get((packet.len() + TAILROOM).max(capacity));
        buf.extend_from_slice(packet);
        let seg = buf.as_packet_mut();
        if let Some((start, field)) = csum {
            let mut csum = !fold(sum_words(0, &seg[start..]));
            if csum == 0 && l4_protocol(seg) == Some(UDP) {
                csum = 0xFFFF;
            }
            seg[field..field + 2].copy_from_slice(&csum.to_be_bytes());
        }
        return Ok(push(out, pool, buf, 0));
    }

    let (version, proto) = match gso {
        VirtioNetHdr::GSO_TCPV4 => (4, TCP),
        VirtioNetHdr::GSO_TCPV6 => (6, TCP),
        VirtioNetHdr::GSO_UDP_L4 if hdr.gso_type == gso => {
            (packet.first().ok_or(OffloadError::Truncated)? >> 4, UDP)
        }
        _ => return Err(OffloadError::UnsupportedGso),
    };
    if hdr.gso_size == 0 {
        return Err(OffloadError::ZeroGsoSize);
    }
    if usize::from(hdr.hdr_len) > packet.len() {
        return Err(OffloadError::Truncated);
    }
    let ip_len = ip_header_len(packet, version, proto)?;
    let hlen = ip_len + transport_header_len(&packet[ip_len..], proto)?;
    let payload = &packet[hlen..];
    let gso_size = usize::from(hdr.gso_size);
    if hlen + gso_size.min(payload.len()) > MAX_IP_LEN {
        return Err(OffloadError::TooLong);
    }
    let count = payload.len().div_ceil(gso_size).max(1);
    for i in first..count {
        if out.is_full() {
            return Ok(Some(i));
        }
        let chunk = &payload[i * gso_size..payload.len().min((i + 1) * gso_size)];
        let mut buf = pool.get((hlen + chunk.len() + TAILROOM).max(capacity));
        buf.extend_from_slice(&packet[..hlen]);
        buf.extend_from_slice(chunk);
        fix_segment(
            buf.as_packet_mut(),
            version == 6,
            ip_len,
            proto,
            i,
            count,
            i * gso_size,
        );
        if let Some(next) = push(out, pool, buf, i) {
            return Ok(Some(next));
        }
    }
    Ok(None)
}

/// Appends `buf` (segment `i`) to `out`; if `out` is full, returns `buf` to `pool` and
/// yields `Some(i)`.
fn push(out: &mut PacketBatch, pool: &mut PacketPool, buf: PacketBuf, i: usize) -> Option<usize> {
    out.push(buf).err().map(|buf| {
        pool.put(buf);
        i
    })
}

/// Rewrites the copied headers of segment `i` of `count`, whose payload starts `offset`
/// bytes into the super-packet's payload.
fn fix_segment(
    seg: &mut [u8],
    v6: bool,
    ip_len: usize,
    proto: u8,
    i: usize,
    count: usize,
    offset: usize,
) {
    let len = seg.len();
    if v6 {
        put16(seg, 4, len - IPV6_HDR);
    } else {
        put16(seg, 2, len);
        let id = u16::from_be_bytes([seg[4], seg[5]]).wrapping_add(low16(i));
        seg[4..6].copy_from_slice(&id.to_be_bytes());
        seg[10..12].fill(0);
        let csum = !fold(sum_words(0, &seg[..ip_len]));
        seg[10..12].copy_from_slice(&csum.to_be_bytes());
    }
    let field = if proto == TCP {
        let tcp = ip_len;
        let seq = u32::from_be_bytes([seg[tcp + 4], seg[tcp + 5], seg[tcp + 6], seg[tcp + 7]]);
        seg[tcp + 4..tcp + 8].copy_from_slice(&seq.wrapping_add(low32(offset)).to_be_bytes());
        if i + 1 != count {
            seg[tcp + 13] &= !(TCP_FIN | TCP_PSH);
        }
        if i != 0 {
            seg[tcp + 13] &= !TCP_CWR;
        }
        tcp + TCP_CSUM_OFFSET
    } else {
        put16(seg, ip_len + 4, len - ip_len);
        ip_len + UDP_CSUM_OFFSET
    };
    seg[field..field + 2].fill(0);
    let mut csum = !fold(sum_words(
        pseudo_sum(seg, v6, proto, len - ip_len),
        &seg[ip_len..],
    ));
    if csum == 0 && proto == UDP {
        csum = 0xFFFF;
    }
    seg[field..field + 2].copy_from_slice(&csum.to_be_bytes());
}

/// Validates the IP header of a super-packet against `version` and `proto` and returns
/// its length.
fn ip_header_len(packet: &[u8], version: u8, proto: u8) -> Result<usize, OffloadError> {
    let first = *packet.first().ok_or(OffloadError::Truncated)?;
    if first >> 4 != version {
        return Err(OffloadError::BadHeaders);
    }
    if version == 6 {
        if packet.len() < IPV6_HDR {
            return Err(OffloadError::Truncated);
        }
        if packet[6] != proto {
            return Err(OffloadError::BadHeaders);
        }
        return Ok(IPV6_HDR);
    }
    let ihl = usize::from(first & 0x0F) * 4;
    if packet.len() < IPV4_HDR.max(ihl) {
        return Err(OffloadError::Truncated);
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3FFF;
    if ihl < IPV4_HDR || packet[9] != proto || fragment != 0 {
        return Err(OffloadError::BadHeaders);
    }
    Ok(ihl)
}

/// Validates the transport header at the start of `l4` and returns its length.
fn transport_header_len(l4: &[u8], proto: u8) -> Result<usize, OffloadError> {
    let len = if proto == TCP {
        let offset = l4.get(12).ok_or(OffloadError::Truncated)?;
        let len = usize::from(offset >> 4) * 4;
        if len < TCP_HDR {
            return Err(OffloadError::BadHeaders);
        }
        len
    } else {
        UDP_HDR
    };
    if l4.len() < len {
        return Err(OffloadError::Truncated);
    }
    Ok(len)
}

/// The transport protocol of an IP packet without IPv6 extension headers.
fn l4_protocol(packet: &[u8]) -> Option<u8> {
    match packet.first()? >> 4 {
        4 => packet.get(9).copied(),
        6 => packet.get(6).copied(),
        _ => None,
    }
}

/// Unfolded sum of the pseudo-header of `packet` for a transport length `l4_len`.
fn pseudo_sum(packet: &[u8], v6: bool, proto: u8, l4_len: usize) -> u64 {
    let addrs = if v6 { &packet[8..40] } else { &packet[12..20] };
    sum_words(u64::from(proto) + l4_len as u64, addrs)
}

/// Writes the low 16 bits of `value` big-endian at `at`.
fn put16(packet: &mut [u8], at: usize, value: usize) {
    packet[at..at + 2].copy_from_slice(&low16(value).to_be_bytes());
}

/// The low 16 bits of `value`.
const fn low16(value: usize) -> u16 {
    let [lo, hi, ..] = value.to_le_bytes();
    u16::from_le_bytes([lo, hi])
}

/// The low 32 bits of `value`.
const fn low32(value: usize) -> u32 {
    let [a, b, c, d, ..] = value.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::checksum::{internet_checksum, transport_checksum_v4, transport_checksum_v6};
    use crate::{HEADROOM, MAX_BATCH};

    const TCP_ACK: u8 = 0x10;

    const SRC4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DST4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const SRC6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const DST6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

    /// Header fields of a test packet.
    #[derive(Clone)]
    struct Spec {
        v6: bool,
        proto: u8,
        sport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        tos: u8,
        ttl: u8,
        id: u16,
        df: bool,
        flow: u32,
        tcp_options: Vec<u8>,
        ip_options: Vec<u8>,
    }

    fn spec(v6: bool, proto: u8) -> Spec {
        Spec {
            v6,
            proto,
            sport: 40000,
            seq: 0xFFFF_FF00,
            ack: 77,
            flags: TCP_ACK,
            window: 512,
            tos: 0,
            ttl: 64,
            id: 0xFFF0,
            df: true,
            flow: 0x12345,
            tcp_options: Vec::new(),
            ip_options: Vec::new(),
        }
    }

    impl Spec {
        fn ip_len(&self) -> usize {
            if self.v6 {
                IPV6_HDR
            } else {
                IPV4_HDR + self.ip_options.len()
            }
        }

        fn hlen(&self) -> usize {
            self.ip_len()
                + if self.proto == TCP {
                    TCP_HDR + self.tcp_options.len()
                } else {
                    UDP_HDR
                }
        }

        /// The spec of the `i`-th packet of a flow whose earlier packets carried
        /// `offset` payload bytes.
        fn nth(&self, i: usize, offset: usize) -> Self {
            let mut s = self.clone();
            s.seq = s.seq.wrapping_add(u32::try_from(offset).unwrap());
            s.id = s.id.wrapping_add(u16::try_from(i).unwrap());
            s
        }
    }

    /// `len` payload bytes as found at `offset` of a flow's byte stream.
    fn payload(offset: usize, len: usize) -> Vec<u8> {
        (offset..offset + len)
            .map(|k| u8::try_from(k % 251).unwrap())
            .collect()
    }

    /// Transport checksum computed with nsplane-packet's helpers.
    fn l4_checksum(v6: bool, proto: u8, l4: &[u8]) -> u16 {
        if v6 {
            transport_checksum_v6(SRC6, DST6, proto, l4)
        } else {
            transport_checksum_v4(SRC4, DST4, proto, l4)
        }
    }

    /// A valid packet built with nsplane-packet's checksum helpers.
    fn build(s: &Spec, data: &[u8]) -> Vec<u8> {
        let ip_len = s.ip_len();
        let hlen = s.hlen();
        let len = hlen + data.len();
        let mut p = vec![0; len];
        if s.v6 {
            let word = (6 << 28) | (u32::from(s.tos) << 20) | s.flow;
            p[..4].copy_from_slice(&word.to_be_bytes());
            put16(&mut p, 4, len - IPV6_HDR);
            p[6] = s.proto;
            p[7] = s.ttl;
            p[8..24].copy_from_slice(&SRC6.octets());
            p[24..40].copy_from_slice(&DST6.octets());
        } else {
            p[0] = 0x40 | u8::try_from(ip_len / 4).unwrap();
            p[1] = s.tos;
            put16(&mut p, 2, len);
            p[4..6].copy_from_slice(&s.id.to_be_bytes());
            p[6] = if s.df { 0x40 } else { 0 };
            p[8] = s.ttl;
            p[9] = s.proto;
            p[12..16].copy_from_slice(&SRC4.octets());
            p[16..20].copy_from_slice(&DST4.octets());
            p[IPV4_HDR..ip_len].copy_from_slice(&s.ip_options);
            let csum = internet_checksum(&p[..ip_len]);
            p[10..12].copy_from_slice(&csum.to_be_bytes());
        }
        let l4 = ip_len;
        p[l4..l4 + 2].copy_from_slice(&s.sport.to_be_bytes());
        p[l4 + 2..l4 + 4].copy_from_slice(&443u16.to_be_bytes());
        let field = if s.proto == TCP {
            p[l4 + 4..l4 + 8].copy_from_slice(&s.seq.to_be_bytes());
            p[l4 + 8..l4 + 12].copy_from_slice(&s.ack.to_be_bytes());
            p[l4 + 12] = u8::try_from((hlen - ip_len) / 4).unwrap() << 4;
            p[l4 + 13] = s.flags;
            p[l4 + 14..l4 + 16].copy_from_slice(&s.window.to_be_bytes());
            p[l4 + TCP_HDR..hlen].copy_from_slice(&s.tcp_options);
            l4 + TCP_CSUM_OFFSET
        } else {
            put16(&mut p, l4 + 4, len - ip_len);
            l4 + UDP_CSUM_OFFSET
        };
        p[hlen..].copy_from_slice(data);
        let mut csum = l4_checksum(s.v6, s.proto, &p[ip_len..]);
        if csum == 0 && s.proto == UDP {
            csum = 0xFFFF;
        }
        p[field..field + 2].copy_from_slice(&csum.to_be_bytes());
        p
    }

    /// The partial (pseudo-header only) checksum the kernel leaves in `packet` for
    /// `l4_len` transport bytes.
    fn partial(packet: &[u8], proto: u8, l4_len: usize) -> u16 {
        let zeros = vec![0; l4_len];
        if packet[0] >> 4 == 6 {
            let src: [u8; 16] = packet[8..24].try_into().unwrap();
            let dst: [u8; 16] = packet[24..40].try_into().unwrap();
            !transport_checksum_v6(src.into(), dst.into(), proto, &zeros)
        } else {
            let src: [u8; 4] = packet[12..16].try_into().unwrap();
            let dst: [u8; 4] = packet[16..20].try_into().unwrap();
            !transport_checksum_v4(src.into(), dst.into(), proto, &zeros)
        }
    }

    /// Asserts lengths and checksums of `p` with nsplane-packet's helpers.
    fn assert_valid(p: &[u8]) {
        let v6 = p[0] >> 4 == 6;
        let (ip_len, proto) = if v6 {
            assert_eq!(
                usize::from(u16::from_be_bytes([p[4], p[5]])) + IPV6_HDR,
                p.len()
            );
            (IPV6_HDR, p[6])
        } else {
            let ihl = usize::from(p[0] & 0x0F) * 4;
            assert_eq!(usize::from(u16::from_be_bytes([p[2], p[3]])), p.len());
            assert_eq!(internet_checksum(&p[..ihl]), 0, "IPv4 header checksum");
            (ihl, p[9])
        };
        if proto == UDP {
            let udp_len = u16::from_be_bytes([p[ip_len + 4], p[ip_len + 5]]);
            assert_eq!(usize::from(udp_len), p.len() - ip_len);
        }
        assert_eq!(
            l4_checksum(v6, proto, &p[ip_len..]),
            0,
            "transport checksum"
        );
    }

    /// A super-packet of `len` payload bytes as the kernel hands it over, with the
    /// partial checksum and a vnet header for `gso_size`.
    fn super_packet(s: &Spec, len: usize, gso_size: usize) -> (VirtioNetHdr, Vec<u8>) {
        let mut p = build(s, &payload(0, len));
        let (ip_len, hlen) = (s.ip_len(), s.hlen());
        let offset = if s.proto == TCP {
            TCP_CSUM_OFFSET
        } else {
            UDP_CSUM_OFFSET
        };
        let csum = partial(&p, s.proto, p.len() - ip_len);
        p[ip_len + offset..ip_len + offset + 2].copy_from_slice(&csum.to_be_bytes());
        let gso_type = match (s.proto, s.v6) {
            (TCP, false) => VirtioNetHdr::GSO_TCPV4 | VirtioNetHdr::GSO_ECN,
            (TCP, true) => VirtioNetHdr::GSO_TCPV6 | VirtioNetHdr::GSO_ECN,
            _ => VirtioNetHdr::GSO_UDP_L4,
        };
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdr::F_NEEDS_CSUM,
            gso_type,
            hdr_len: u16::try_from(hlen).unwrap(),
            gso_size: u16::try_from(gso_size).unwrap(),
            csum_start: u16::try_from(ip_len).unwrap(),
            csum_offset: u16::try_from(offset).unwrap(),
        };
        (hdr, p)
    }

    /// Segments `packet` completely, one batch after another.
    fn run(hdr: &VirtioNetHdr, packet: &[u8]) -> Result<Vec<Vec<u8>>, OffloadError> {
        let mut pool = PacketPool::new(MAX_BATCH);
        let mut segments = Vec::new();
        let mut first = 0;
        loop {
            let mut out = PacketBatch::new();
            let next = segment(hdr, packet, first, 0, &mut pool, &mut out)?;
            segments.extend(out.iter().map(|p| p.as_packet().to_vec()));
            match next {
                Some(next) => first = next,
                None => return Ok(segments),
            }
        }
    }

    #[test]
    fn header_round_trip() {
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdr::F_NEEDS_CSUM,
            gso_type: VirtioNetHdr::GSO_TCPV6 | VirtioNetHdr::GSO_ECN,
            hdr_len: 0x0102,
            gso_size: 1380,
            csum_start: 40,
            csum_offset: 16,
        };
        let bytes = hdr.encode();
        assert_eq!(bytes.len(), VirtioNetHdr::LEN);
        assert_eq!(bytes[..2], [1, 0x84]);
        assert_eq!(bytes[2..4], 0x0102u16.to_ne_bytes());
        assert_eq!(bytes[4..6], 1380u16.to_ne_bytes());
        assert_eq!(VirtioNetHdr::parse(&bytes), Ok(hdr));
        let mut longer = bytes.to_vec();
        longer.extend_from_slice(&[0x45, 0]);
        assert_eq!(VirtioNetHdr::parse(&longer), Ok(hdr));
        assert_eq!(
            VirtioNetHdr::parse(&bytes[..9]),
            Err(OffloadError::Truncated)
        );
        assert_eq!(VirtioNetHdr::parse(&[]), Err(OffloadError::Truncated));
        assert_eq!(VirtioNetHdr::parse(&[0; 10]), Ok(VirtioNetHdr::default()));
    }

    /// Segments super-packets of every interesting size for `v6`/`proto` and compares
    /// each segment with the packet a sender would have built.
    fn check_segmentation(v6: bool, proto: u8) {
        let mut s = spec(v6, proto);
        if proto == TCP {
            s.flags = TCP_ACK | TCP_PSH | TCP_FIN | TCP_CWR;
        }
        let overhead = s.hlen();
        for mtu in [1280, 1420, 1500] {
            let g = mtu - overhead;
            for len in [1, g - 1, g, g + 1, 3 * g, 3 * g + 1, MAX_IP_LEN - overhead] {
                let (hdr, packet) = super_packet(&s, len, g);
                let segments = run(&hdr, &packet).unwrap();
                assert_eq!(segments.len(), len.div_ceil(g), "mtu {mtu} len {len}");
                for (i, seg) in segments.iter().enumerate() {
                    assert_valid(seg);
                    let mut si = s.nth(i, i * g);
                    if i + 1 != segments.len() {
                        si.flags &= !(TCP_FIN | TCP_PSH);
                    }
                    if i != 0 {
                        si.flags &= !TCP_CWR;
                    }
                    let data = payload(i * g, g.min(len - i * g));
                    assert_eq!(*seg, build(&si, &data), "mtu {mtu} len {len} segment {i}");
                }
            }
        }
    }

    #[test]
    fn segments_tcpv4() {
        check_segmentation(false, TCP);
    }

    #[test]
    fn segments_tcpv6() {
        check_segmentation(true, TCP);
    }

    #[test]
    fn segments_udpv4() {
        check_segmentation(false, UDP);
    }

    #[test]
    fn segments_udpv6() {
        check_segmentation(true, UDP);
    }

    #[test]
    fn segments_tcp_with_options() {
        let mut s = spec(false, TCP);
        s.tcp_options = vec![1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2];
        let (hdr, packet) = super_packet(&s, 2500, 1000);
        let segments = run(&hdr, &packet).unwrap();
        assert_eq!(segments.len(), 3);
        for (i, seg) in segments.iter().enumerate() {
            assert_valid(seg);
            let data = payload(i * 1000, 1000.min(2500 - i * 1000));
            assert_eq!(*seg, build(&s.nth(i, i * 1000), &data));
        }
    }

    #[test]
    fn segments_ipv4_with_twenty_option_bytes() {
        for proto in [TCP, UDP] {
            let mut s = spec(false, proto);
            // 19 NOPs and End of Options List: IHL 10, the length of an IPv6 header.
            s.ip_options = vec![1; 19];
            s.ip_options.push(0);
            assert_eq!(s.ip_len(), 40);
            let (hdr, packet) = super_packet(&s, 2500, 1000);
            let segments = run(&hdr, &packet).unwrap();
            assert_eq!(segments.len(), 3);
            for (i, seg) in segments.iter().enumerate() {
                assert_valid(seg);
                let data = payload(i * 1000, 1000.min(2500 - i * 1000));
                assert_eq!(
                    *seg,
                    build(&s.nth(i, i * 1000), &data),
                    "proto {proto} segment {i}"
                );
            }
        }
    }

    #[test]
    fn segmentation_continues_across_batches() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 100 * 70 + 5, 100);
        let mut pool = PacketPool::new(0);
        let mut out = PacketBatch::new();
        assert_eq!(
            segment(&hdr, &packet, 0, 0, &mut pool, &mut out),
            Ok(Some(MAX_BATCH))
        );
        assert!(out.is_full());
        let mut segments: Vec<Vec<u8>> = out.drain().map(|p| p.as_packet().to_vec()).collect();
        assert_eq!(
            segment(&hdr, &packet, MAX_BATCH, 0, &mut pool, &mut out),
            Ok(None)
        );
        assert_eq!(out.len(), 71 - MAX_BATCH);
        segments.extend(out.drain().map(|p| p.as_packet().to_vec()));
        assert_eq!(segments, run(&hdr, &packet).unwrap());
        for (i, seg) in segments.iter().enumerate() {
            assert_eq!(
                *seg,
                build(
                    &s.nth(i, i * 100),
                    &payload(i * 100, 100.min(7005 - i * 100))
                )
            );
        }

        // A partly filled batch takes what fits; a full one takes nothing.
        let mut out = PacketBatch::new();
        for _ in 0..MAX_BATCH - 4 {
            out.push(PacketBuf::with_capacity(0)).unwrap();
        }
        assert_eq!(
            segment(&hdr, &packet, 0, 0, &mut pool, &mut out),
            Ok(Some(4))
        );
        assert_eq!(
            segment(&hdr, &packet, 4, 0, &mut pool, &mut out),
            Ok(Some(4))
        );
        let none = VirtioNetHdr::default();
        assert_eq!(
            segment(&none, &packet, 0, 0, &mut pool, &mut out),
            Ok(Some(0))
        );
        assert_eq!(segment(&none, &packet, 1, 0, &mut pool, &mut out), Ok(None));
    }

    #[test]
    fn completes_needs_csum() {
        for (v6, proto) in [(false, TCP), (true, TCP), (false, UDP), (true, UDP)] {
            let s = spec(v6, proto);
            let expected = build(&s, &payload(0, 333));
            let (mut hdr, packet) = super_packet(&s, 333, 1000);
            assert_ne!(packet, expected);
            hdr.gso_type = VirtioNetHdr::GSO_NONE;
            hdr.gso_size = 0;
            hdr.hdr_len = 0;
            let segments = run(&hdr, &packet).unwrap();
            assert_eq!(segments, [expected]);
            assert_valid(&segments[0]);
        }
    }

    #[test]
    fn gso_none_passes_packet_through() {
        let hdr = VirtioNetHdr::default();
        let bytes = [0xAB; 77];
        assert_eq!(run(&hdr, &bytes).unwrap(), [bytes.to_vec()]);
        assert_eq!(run(&hdr, &[]).unwrap(), [Vec::<u8>::new()]);
        let mut pool = PacketPool::new(1);
        let mut out = PacketBatch::new();
        segment(&hdr, &bytes, 0, 0, &mut pool, &mut out).unwrap();
        let buf = out.iter_mut().next().unwrap();
        assert_eq!(buf.with_headroom_mut().len(), HEADROOM + 77);
    }

    #[test]
    fn packets_get_at_least_the_requested_capacity() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 3000, 1000);
        let none = VirtioNetHdr::default();
        let mut pool = PacketPool::new(0);
        for capacity in [0, 1528, 1040] {
            let mut out = PacketBatch::new();
            assert_eq!(
                segment(&hdr, &packet, 0, capacity, &mut pool, &mut out),
                Ok(None)
            );
            assert_eq!(out.len(), 3);
            assert_eq!(
                segment(&none, &packet[..77], 0, capacity, &mut pool, &mut out),
                Ok(None)
            );
            for p in out.iter() {
                assert!(p.capacity() >= capacity.max(p.len() + TAILROOM));
                assert_eq!(p.headroom(), HEADROOM);
            }
        }
    }

    #[test]
    fn segments_reuse_pooled_buffers_without_growth() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 3000, 1000);
        let mut pool = PacketPool::new(8);
        // Buffers that held larger packets before: reused, overwritten, not grown.
        for _ in 0..3 {
            let mut old = pool.get(1600);
            old.extend_from_slice(&[0xEE; 1600]);
            pool.put(old);
        }
        let mut fresh = PacketBatch::new();
        segment(&hdr, &packet, 0, 0, &mut PacketPool::new(0), &mut fresh).unwrap();
        let mut out = PacketBatch::new();
        segment(&hdr, &packet, 0, 1500 + TAILROOM, &mut pool, &mut out).unwrap();
        assert_eq!(pool.free_len(), 0);
        let got: Vec<&[u8]> = out.iter().map(PacketBuf::as_packet).collect();
        let want: Vec<&[u8]> = fresh.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, want);
        for p in out.iter() {
            assert!(p.capacity() >= 1500 + TAILROOM);
        }
    }

    #[test]
    fn rejects_malformed_input() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 3000, 1000);
        let err = |hdr: &VirtioNetHdr, packet: &[u8]| run(hdr, packet).unwrap_err();

        assert_eq!(
            err(&VirtioNetHdr { gso_size: 0, ..hdr }, &packet),
            OffloadError::ZeroGsoSize
        );
        for gso_type in [
            2,
            3,
            6,
            0x7F,
            VirtioNetHdr::GSO_UDP_L4 | VirtioNetHdr::GSO_ECN,
            0x80,
        ] {
            assert_eq!(
                err(&VirtioNetHdr { gso_type, ..hdr }, &packet),
                OffloadError::UnsupportedGso
            );
        }
        let hdr_len = u16::try_from(packet.len() + 1).unwrap();
        assert_eq!(
            err(&VirtioNetHdr { hdr_len, ..hdr }, &packet),
            OffloadError::Truncated
        );
        let v6 = VirtioNetHdr {
            gso_type: VirtioNetHdr::GSO_TCPV6,
            ..hdr
        };
        assert_eq!(err(&v6, &packet), OffloadError::BadHeaders);
        let udp = VirtioNetHdr {
            gso_type: VirtioNetHdr::GSO_UDP_L4,
            ..hdr
        };
        assert_eq!(err(&udp, &packet), OffloadError::BadHeaders);
        assert_eq!(err(&hdr, &[]), OffloadError::Truncated);
        assert_eq!(err(&udp, &[]), OffloadError::Truncated);

        let mut bad = packet.clone();
        bad[0] = 0x44;
        assert_eq!(err(&hdr, &bad), OffloadError::BadHeaders);
        let mut bad = packet.clone();
        bad[0] = 0x4F;
        assert_eq!(
            err(&VirtioNetHdr { hdr_len: 0, ..hdr }, &bad[..50]),
            OffloadError::Truncated
        );
        let mut bad = packet.clone();
        bad[6] |= 0x20;
        assert_eq!(err(&hdr, &bad), OffloadError::BadHeaders);
        let mut bad = packet.clone();
        bad[32] = 0x40;
        assert_eq!(err(&hdr, &bad), OffloadError::BadHeaders);
        let mut bad = packet.clone();
        bad[32] = 0xF0;
        assert_eq!(
            err(&VirtioNetHdr { hdr_len: 0, ..hdr }, &bad[..70]),
            OffloadError::Truncated
        );
        let mut v6_ext = build(&spec(true, TCP), &[1; 10]);
        v6_ext[6] = 0;
        assert_eq!(err(&v6, &v6_ext), OffloadError::BadHeaders);

        let too_long = VirtioNetHdr {
            gso_size: u16::MAX,
            ..hdr
        };
        let mut big = packet.clone();
        big.resize(70_000, 0);
        assert_eq!(err(&too_long, &big), OffloadError::TooLong);

        let csum = VirtioNetHdr {
            csum_start: 3030,
            csum_offset: 16,
            ..VirtioNetHdr::default()
        };
        let csum = VirtioNetHdr {
            flags: VirtioNetHdr::F_NEEDS_CSUM,
            ..csum
        };
        assert_eq!(err(&csum, &packet), OffloadError::BadChecksumOffset);
        let max = VirtioNetHdr {
            csum_start: u16::MAX,
            csum_offset: u16::MAX,
            ..csum
        };
        assert_eq!(err(&max, &packet), OffloadError::BadChecksumOffset);
        let ecn_none = VirtioNetHdr {
            gso_type: VirtioNetHdr::GSO_ECN,
            ..csum
        };
        assert_eq!(err(&ecn_none, &packet), OffloadError::UnsupportedGso);
    }

    #[test]
    fn truncated_and_random_input_never_panics() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 3000, 1000);
        for cut in 0..packet.len() {
            let hdr = VirtioNetHdr { hdr_len: 0, ..hdr };
            let result = run(&hdr, &packet[..cut]);
            if cut < s.hlen() {
                assert_eq!(result, Err(OffloadError::Truncated), "cut {cut}");
            }
        }
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let mut raw = next().to_le_bytes();
            raw[0] &= 1;
            raw[1] %= 6;
            raw[5] &= 3;
            raw[7] &= 63;
            let hdr = VirtioNetHdr::parse(&[raw.as_slice(), &[0, 0]].concat()).unwrap();
            let cut = usize::from(u16::from_le_bytes([raw[2], raw[3]])) % (packet.len() + 1);
            let mut packet = packet[..cut].to_vec();
            for _ in 0..4 {
                let r = next();
                if let Some(byte) = packet.get_mut(usize::try_from(r % 64).unwrap()) {
                    *byte = r.to_le_bytes()[7];
                }
            }
            let _ = run(&hdr, &packet);
        }
    }
}
