//! UDP datagram builder for packets an application injects into the tunnel.
//!
//! [`write_udp`] writes a whole IPv4 or IPv6 UDP datagram from (source, destination,
//! payload) into a [`PacketBuf`], and [`udp_packet`] returns a fresh buffer sized for it,
//! ready for `EngineHandle::inject_outbound` or `inject_outbound_on`, for both IP versions
//! and any ports:
//!
//! - **IPv6** (RFC 8200): version 6, traffic class 0, flow label 0, next header 17, hop
//!   limit 64, no extension headers; the UDP checksum is always computed.
//! - **IPv4**: IHL 5 (no options), TOS 0, identification 0, DF set, TTL 64, protocol 17
//!   and the header checksum; the UDP checksum is computed as well.
//! - A UDP checksum that computes to `0` is sent as `0xFFFF` (RFC 768) for both versions.
//!
//! The IP version follows the socket addresses: an IPv4-mapped IPv6 address
//! (`::ffff:a.b.c.d`) in a [`SocketAddr::V6`] is taken as IPv6 and builds an IPv6
//! datagram. Mixed versions and payloads that do not fit the 16-bit length fields (65 507
//! bytes over IPv4, 65 527 over IPv6) are a [`UdpBuildError`].
//!
//! ```
//! use std::net::{Ipv6Addr, SocketAddr};
//!
//! use nsplane_packet::{IpPacket, UdpHeader, build::udp_packet, protocol};
//!
//! let src = SocketAddr::from(("fd00::1".parse::<Ipv6Addr>()?, 47900));
//! let dst = SocketAddr::from(("fd00::2".parse::<Ipv6Addr>()?, 47900));
//! let packet = udp_packet(src, dst, b"control message")?;
//!
//! let ip = IpPacket::parse(packet.as_packet())?;
//! assert_eq!(ip.protocol(), protocol::UDP);
//! assert_eq!(ip.dst(), dst.ip());
//! let (udp, payload) = UdpHeader::parse(ip.payload())?;
//! assert_eq!(udp.dst_port(), 47900);
//! assert_eq!(payload, b"control message");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;

use crate::buf::PacketBuf;
use crate::checksum::{ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6};
use crate::protocol;

/// Header lengths: IPv4 without options, the IPv6 fixed header, UDP.
const IPV4_HEADER_LEN: u16 = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
/// TTL / hop limit of every built datagram.
const HOP_LIMIT: u8 = 64;
/// Byte range of the checksum field in the IPv4 header and the UDP header.
const IPV4_CHECKSUM: Range<usize> = 10..12;
const UDP_CHECKSUM: Range<usize> = 6..8;

/// A UDP datagram cannot be built from the given addresses and payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UdpBuildError {
    /// The source and destination are of different IP versions.
    MixedFamilies,
    /// The payload does not fit the 16-bit UDP or IP length fields.
    TooLarge,
}

impl fmt::Display for UdpBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MixedFamilies => "source and destination of different IP versions",
            Self::TooLarge => "payload too large for a UDP datagram",
        })
    }
}

impl std::error::Error for UdpBuildError {}

/// The addresses of a datagram, one IP version.
#[derive(Clone, Copy)]
enum Addresses {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

impl Addresses {
    fn header_len(self) -> usize {
        match self {
            Self::V4(..) => usize::from(IPV4_HEADER_LEN),
            Self::V6(..) => IPV6_HEADER_LEN,
        }
    }
}

/// The addresses and the UDP length of a datagram carrying `payload_len` bytes.
fn layout(
    src: SocketAddr,
    dst: SocketAddr,
    payload_len: usize,
) -> Result<(Addresses, u16), UdpBuildError> {
    let addresses = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => Addresses::V4(s, d),
        (IpAddr::V6(s), IpAddr::V6(d)) => Addresses::V6(s, d),
        _ => return Err(UdpBuildError::MixedFamilies),
    };
    // IPv4 counts its header in the total length; the IPv6 payload length is the UDP length.
    let limit = match addresses {
        Addresses::V4(..) => u16::MAX - IPV4_HEADER_LEN,
        Addresses::V6(..) => u16::MAX,
    };
    let udp_len = payload_len
        .checked_add(UDP_HEADER_LEN)
        .and_then(|len| u16::try_from(len).ok())
        .filter(|&len| len <= limit)
        .ok_or(UdpBuildError::TooLarge)?;
    Ok((addresses, udp_len))
}

/// Length of the whole IP packet [`write_udp`] writes for these arguments.
fn packet_len(addresses: Addresses, udp_len: u16) -> usize {
    addresses.header_len() + usize::from(udp_len)
}

/// Writes a UDP datagram from `src` to `dst` carrying `payload` into `buf`, replacing its
/// packet bytes and keeping its headroom. See the [module docs](self).
///
/// # Errors
///
/// Returns [`UdpBuildError::MixedFamilies`] if `src` and `dst` are of different IP versions
/// and [`UdpBuildError::TooLarge`] if `payload` does not fit the length fields; `buf` is left
/// unchanged.
pub fn write_udp(
    buf: &mut PacketBuf,
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Result<(), UdpBuildError> {
    let (addresses, udp_len) = layout(src, dst, payload.len())?;
    buf.set_len(packet_len(addresses, udp_len));
    let (header, segment) = buf.as_packet_mut().split_at_mut(addresses.header_len());

    segment[..2].copy_from_slice(&src.port().to_be_bytes());
    segment[2..4].copy_from_slice(&dst.port().to_be_bytes());
    segment[4..6].copy_from_slice(&udp_len.to_be_bytes());
    segment[UDP_CHECKSUM].fill(0);
    segment[UDP_HEADER_LEN..].copy_from_slice(payload);
    let sum = match addresses {
        Addresses::V4(s, d) => transport_checksum_v4(s, d, protocol::UDP, segment),
        Addresses::V6(s, d) => transport_checksum_v6(s, d, protocol::UDP, segment),
    };
    let sum = if sum == 0 { 0xFFFF } else { sum };
    segment[UDP_CHECKSUM].copy_from_slice(&sum.to_be_bytes());

    match addresses {
        Addresses::V4(s, d) => {
            let total = udp_len + IPV4_HEADER_LEN;
            header[..2].copy_from_slice(&[0x45, 0]);
            header[2..4].copy_from_slice(&total.to_be_bytes());
            header[4..12].copy_from_slice(&[0, 0, 0x40, 0, HOP_LIMIT, protocol::UDP, 0, 0]);
            header[12..16].copy_from_slice(&s.octets());
            header[16..20].copy_from_slice(&d.octets());
            let sum = ipv4_header_checksum(header);
            header[IPV4_CHECKSUM].copy_from_slice(&sum.to_be_bytes());
        }
        Addresses::V6(s, d) => {
            header[..4].copy_from_slice(&[0x60, 0, 0, 0]);
            header[4..6].copy_from_slice(&udp_len.to_be_bytes());
            header[6..8].copy_from_slice(&[protocol::UDP, HOP_LIMIT]);
            header[8..24].copy_from_slice(&s.octets());
            header[24..40].copy_from_slice(&d.octets());
        }
    }
    Ok(())
}

/// A UDP datagram from `src` to `dst` carrying `payload`, in a fresh [`PacketBuf`] sized
/// for it. See [`write_udp`] and the [module docs](self).
///
/// # Errors
///
/// As [`write_udp`].
pub fn udp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Result<PacketBuf, UdpBuildError> {
    let (addresses, udp_len) = layout(src, dst, payload.len())?;
    let mut buf = PacketBuf::with_capacity(packet_len(addresses, udp_len));
    write_udp(&mut buf, src, dst, payload)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buf::{HEADROOM, PacketPool};
    use crate::checksum::internet_checksum;
    use crate::ip::{IpPacket, UdpHeader};

    fn v4(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, last], port))
    }

    fn v6(last: u16, port: u16) -> SocketAddr {
        SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last), port))
    }

    /// The UDP checksum over the pseudo-header of `packet`, `0` when it verifies.
    fn udp_sum(packet: &[u8]) -> u16 {
        let ip = IpPacket::parse(packet).unwrap();
        match (ip.src(), ip.dst()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                transport_checksum_v4(s, d, protocol::UDP, ip.payload())
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                transport_checksum_v6(s, d, protocol::UDP, ip.payload())
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn ipv4_round_trips() {
        let packet = udp_packet(v4(1, 40000), v4(2, 47900), b"hello").unwrap();
        let bytes = packet.as_packet();
        assert_eq!(bytes.len(), 20 + 8 + 5);
        let IpPacket::V4 { header, payload } = IpPacket::parse(bytes).unwrap() else {
            panic!("not IPv4");
        };
        assert_eq!(header.ihl(), 5);
        assert_eq!(header.dscp(), 0);
        assert_eq!(usize::from(header.total_len()), bytes.len());
        assert_eq!(header.identification(), 0);
        assert!(header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.ttl(), 64);
        assert_eq!(header.protocol(), protocol::UDP);
        assert_eq!(header.src(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(header.dst(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(internet_checksum(&bytes[..20]), 0);

        let (udp, data) = UdpHeader::parse(payload).unwrap();
        assert_eq!((udp.src_port(), udp.dst_port()), (40000, 47900));
        assert_eq!(usize::from(udp.len()), payload.len());
        assert_ne!(udp.checksum(), 0);
        assert_eq!(data, b"hello");
        assert_eq!(udp_sum(bytes), 0);
    }

    #[test]
    fn ipv6_round_trips() {
        let packet = udp_packet(v6(1, 47900), v6(2, 47900), b"control").unwrap();
        let bytes = packet.as_packet();
        assert_eq!(bytes.len(), 40 + 8 + 7);
        let IpPacket::V6 { header, payload } = IpPacket::parse(bytes).unwrap() else {
            panic!("not IPv6");
        };
        assert_eq!(header.traffic_class(), 0);
        assert_eq!(header.flow_label(), 0);
        assert_eq!(usize::from(header.payload_len()), 8 + 7);
        assert_eq!(header.next_header(), protocol::UDP);
        assert_eq!(header.hop_limit(), 64);
        assert_eq!(IpAddr::V6(header.src()), v6(1, 0).ip());
        assert_eq!(IpAddr::V6(header.dst()), v6(2, 0).ip());

        let (udp, data) = UdpHeader::parse(payload).unwrap();
        assert_eq!((udp.src_port(), udp.dst_port()), (47900, 47900));
        assert_eq!(usize::from(udp.len()), payload.len());
        assert_ne!(udp.checksum(), 0);
        assert_eq!(data, b"control");
        assert_eq!(udp_sum(bytes), 0);
    }

    /// A payload whose UDP checksum computes to zero: the checksum with a zero payload word,
    /// then that word set to the complement of the sum.
    fn zero_sum_payload(src: SocketAddr, dst: SocketAddr) -> [u8; 2] {
        let packet = udp_packet(src, dst, &[0, 0]).unwrap();
        let ip = IpPacket::parse(packet.as_packet()).unwrap();
        // The one's complement sum without the word is `!checksum`; adding `checksum` as the
        // word makes it 0xFFFF, so the checksum computes to 0.
        [ip.payload()[6], ip.payload()[7]]
    }

    #[test]
    fn zero_checksum_is_sent_as_all_ones() {
        for (src, dst) in [(v4(1, 1), v4(2, 2)), (v6(1, 1), v6(2, 2))] {
            let payload = zero_sum_payload(src, dst);
            let packet = udp_packet(src, dst, &payload).unwrap();
            let ip = IpPacket::parse(packet.as_packet()).unwrap();
            assert_eq!(ip.payload()[UDP_CHECKSUM], [0xFF, 0xFF], "{src}");
            assert_eq!(udp_sum(packet.as_packet()), 0);
        }
    }

    #[test]
    fn empty_payload() {
        for (src, dst, len) in [(v4(1, 5), v4(2, 6), 28), (v6(1, 5), v6(2, 6), 48)] {
            let packet = udp_packet(src, dst, &[]).unwrap();
            assert_eq!(packet.len(), len);
            let ip = IpPacket::parse(packet.as_packet()).unwrap();
            let (udp, data) = UdpHeader::parse(ip.payload()).unwrap();
            assert_eq!(udp.len(), 8);
            assert_eq!(data, []);
            assert_eq!(udp_sum(packet.as_packet()), 0);
        }
    }

    #[test]
    fn maximum_payload() {
        for (src, dst, max) in [(v4(1, 5), v4(2, 6), 65_507), (v6(1, 5), v6(2, 6), 65_527)] {
            let payload = vec![0xA5; max];
            let packet = udp_packet(src, dst, &payload).unwrap();
            let ip = IpPacket::parse(packet.as_packet()).unwrap();
            assert_eq!(&ip.payload()[8..], payload);
            assert_eq!(udp_sum(packet.as_packet()), 0);

            let payload = vec![0xA5; max + 1];
            assert_eq!(
                udp_packet(src, dst, &payload).unwrap_err(),
                UdpBuildError::TooLarge
            );
        }
    }

    #[test]
    fn mixed_families_fail_and_mapped_is_ipv6() {
        assert_eq!(
            udp_packet(v4(1, 5), v6(2, 6), b"x").unwrap_err(),
            UdpBuildError::MixedFamilies
        );
        assert_eq!(
            udp_packet(v6(1, 5), v4(2, 6), b"x").unwrap_err(),
            UdpBuildError::MixedFamilies
        );
        let mapped = |last| SocketAddr::from((Ipv4Addr::new(10, 0, 0, last).to_ipv6_mapped(), 7));
        assert_eq!(
            udp_packet(v4(1, 5), mapped(2), b"x").unwrap_err(),
            UdpBuildError::MixedFamilies
        );
        let packet = udp_packet(mapped(1), mapped(2), b"x").unwrap();
        assert_eq!(packet.as_packet()[0] >> 4, 6);
        assert_eq!(udp_sum(packet.as_packet()), 0);
        assert_eq!(
            UdpBuildError::MixedFamilies.to_string(),
            "source and destination of different IP versions"
        );
        assert_eq!(
            UdpBuildError::TooLarge.to_string(),
            "payload too large for a UDP datagram"
        );
    }

    #[test]
    fn errors_leave_the_buffer_unchanged() {
        let mut buf = PacketBuf::from_packet(&[1, 2, 3]);
        let payload = vec![0; 70_000];
        assert!(write_udp(&mut buf, v6(1, 5), v6(2, 6), &payload).is_err());
        assert!(write_udp(&mut buf, v4(1, 5), v6(2, 6), b"x").is_err());
        assert_eq!(buf.as_packet(), [1, 2, 3]);
    }

    #[test]
    fn writing_into_a_pooled_buffer_keeps_its_headroom() {
        let mut pool = PacketPool::new(1);
        let mut buf = pool.get_len(1500);
        buf.as_packet_mut().fill(0xEE);
        write_udp(&mut buf, v6(1, 47900), v6(2, 47900), b"probe").unwrap();
        assert_eq!(buf.headroom(), HEADROOM);
        assert_eq!(buf.len(), 40 + 8 + 5);
        assert_eq!(
            buf.as_packet(),
            udp_packet(v6(1, 47900), v6(2, 47900), b"probe")
                .unwrap()
                .as_packet()
        );

        // Shrinking and growing again in place: a shorter datagram, then a longer one.
        write_udp(&mut buf, v4(1, 1), v4(2, 2), &[]).unwrap();
        assert_eq!(buf.len(), 28);
        write_udp(&mut buf, v4(1, 1), v4(2, 2), &[7; 1000]).unwrap();
        assert_eq!(buf.headroom(), HEADROOM);
        assert_eq!(udp_sum(buf.as_packet()), 0);
        assert_eq!(buf.with_headroom_mut()[..HEADROOM], [0; HEADROOM]);
    }
}
