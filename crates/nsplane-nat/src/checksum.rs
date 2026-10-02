//! Internet checksum helpers for rewritten packets.
//!
//! Full checksums come from [`nsplane_packet::checksum`] and are re-exported
//! here. The `update_*` helpers apply RFC 1624 (equation 3) incremental
//! updates: given the checksum field of a packet and the data that changed,
//! they return the checksum a full recompute would produce, without touching
//! the rest of the packet.
//!
//! Checksums are the final, complemented values in host order, as read from
//! or written big-endian into a header. Replaced data must start at an even
//! offset of the checksummed range.

use std::net::{Ipv4Addr, Ipv6Addr};

pub use nsplane_packet::checksum::{
    internet_checksum, ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};

/// Adds two 16-bit one's complement values (end-around carry).
fn add(a: u16, b: u16) -> u16 {
    let (sum, carry) = a.overflowing_add(b);
    sum + u16::from(carry)
}

/// Returns the folded one's complement sum of `data` (not complemented); an odd
/// trailing byte is padded with zero.
pub fn sum(data: &[u8]) -> u16 {
    !internet_checksum(data)
}

/// Returns whether `data`, including its checksum field, sums to a valid checksum.
pub fn valid(data: &[u8]) -> bool {
    internet_checksum(data) == 0
}

/// Updates `checksum` for one 16-bit word replaced from `old` to `new`.
///
/// More generally `old` and `new` may be the [`sum`]s of any removed and added
/// data; `update_u16(checksum, 0, added)` adds data that was not covered before.
pub fn update_u16(checksum: u16, old: u16, new: u16) -> u16 {
    !add(add(!checksum, !old), new)
}

/// Updates `checksum` for one 32-bit word replaced from `old` to `new`.
pub fn update_u32(checksum: u16, old: u32, new: u32) -> u16 {
    update_bytes(checksum, &old.to_be_bytes(), &new.to_be_bytes())
}

/// Updates `checksum` for an IPv4 address replaced from `old` to `new`.
pub fn update_ipv4(checksum: u16, old: Ipv4Addr, new: Ipv4Addr) -> u16 {
    update_u32(checksum, old.to_bits(), new.to_bits())
}

/// Updates `checksum` for an IPv6 address replaced from `old` to `new`.
pub fn update_ipv6(checksum: u16, old: Ipv6Addr, new: Ipv6Addr) -> u16 {
    update_bytes(checksum, &old.octets(), &new.octets())
}

/// Updates `checksum` for the bytes `old` replaced by `new` (the same length,
/// or a change of which data is covered).
pub fn update_bytes(checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    update_u16(checksum, sum(old), sum(new))
}

/// A TCP/UDP/ICMPv6 pseudo-header (RFC 793, RFC 768, RFC 8200 section 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoHeader {
    /// IPv4 pseudo-header.
    V4 {
        /// Source address.
        src: Ipv4Addr,
        /// Destination address.
        dst: Ipv4Addr,
        /// IP protocol number.
        protocol: u8,
        /// Transport segment length in bytes.
        len: u16,
    },
    /// IPv6 pseudo-header.
    V6 {
        /// Source address.
        src: Ipv6Addr,
        /// Destination address.
        dst: Ipv6Addr,
        /// Upper-layer protocol number (next header).
        protocol: u8,
        /// Upper-layer packet length in bytes.
        len: u32,
    },
}

impl PseudoHeader {
    /// Returns the one's complement [`sum`] of the pseudo-header.
    pub fn sum(self) -> u16 {
        match self {
            Self::V4 {
                src,
                dst,
                protocol,
                len,
            } => [sum(&src.octets()), sum(&dst.octets()), len]
                .into_iter()
                .fold(u16::from(protocol), add),
            Self::V6 {
                src,
                dst,
                protocol,
                len,
            } => [
                sum(&src.octets()),
                sum(&dst.octets()),
                sum(&len.to_be_bytes()),
            ]
            .into_iter()
            .fold(u16::from(protocol), add),
        }
    }
}

/// Updates a transport `checksum` for its pseudo-header replaced from `old` to
/// `new`, including an address-family change (IPv4 to IPv6 and back).
///
/// For ICMP, which has no pseudo-header, use [`update_u16`] with a zero old or
/// new sum to add or remove the `ICMPv6` pseudo-header.
pub fn update_pseudo_header(checksum: u16, old: PseudoHeader, new: PseudoHeader) -> u16 {
    update_u16(checksum, old.sum(), new.sum())
}

/// Returns the on-wire form of a computed UDP checksum: a computed `0x0000` is
/// sent as `0xFFFF`, since a zero field means "no checksum" (RFC 768).
pub const fn udp_wire(checksum: u16) -> u16 {
    if checksum == 0 { 0xFFFF } else { checksum }
}

/// Applies `update` to a UDP checksum `field` and returns the new field.
///
/// A zero field over IPv4 means the sender computed no checksum; it is left at
/// zero. Otherwise the updated checksum goes through [`udp_wire`]. A packet
/// translated to IPv6 needs a checksum, so a zero field must be replaced by a
/// full computation instead.
pub fn update_udp(field: u16, update: impl FnOnce(u16) -> u16) -> u16 {
    if field == 0 {
        0
    } else {
        udp_wire(update(field))
    }
}

#[cfg(test)]
mod tests {
    use nsplane_packet::protocol;

    use super::*;

    /// Deterministic xorshift64 generator for the property tests.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }

        fn u16(&mut self) -> u16 {
            let [.., hi, lo] = self.next().to_be_bytes();
            u16::from_be_bytes([hi, lo])
        }

        fn u32(&mut self) -> u32 {
            let [.., a, b, c, d] = self.next().to_be_bytes();
            u32::from_be_bytes([a, b, c, d])
        }

        fn v4(&mut self) -> Ipv4Addr {
            Ipv4Addr::from_bits(self.u32())
        }

        fn v6(&mut self) -> Ipv6Addr {
            Ipv6Addr::from_bits((u128::from(self.next()) << 64) | u128::from(self.next()))
        }

        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next().to_be_bytes()[7]).collect()
        }

        /// A random even offset where `width` bytes fit in `len`.
        fn offset(&mut self, len: usize, width: usize) -> usize {
            self.below((len - width) / 2 + 1) * 2
        }
    }

    const ROUNDS: usize = 2000;

    /// Random TCP or UDP segment with the checksum field (at `field`) zeroed.
    fn segment(rng: &mut Rng) -> (u8, usize, Vec<u8>) {
        let (proto, at, header) = if rng.next().is_multiple_of(2) {
            (protocol::TCP, 16, 20)
        } else {
            (protocol::UDP, 6, 8)
        };
        let len = header + rng.below(64);
        let mut bytes = rng.bytes(len);
        bytes[at..at + 2].fill(0);
        (proto, at, bytes)
    }

    fn field(bytes: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([bytes[at], bytes[at + 1]])
    }

    #[test]
    fn rfc1624_vector() {
        // RFC 1624 section 4: HC = 0xDD2F, m = 0x5555 -> m' = 0x3285 gives 0x0000.
        assert_eq!(update_u16(0xDD2F, 0x5555, 0x3285), 0x0000);
    }

    #[test]
    fn sum_and_valid() {
        assert_eq!(sum(&[]), 0);
        assert_eq!(
            sum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0xddf2
        );
        assert_eq!(sum(&[0xff, 0xff, 0x00, 0x01]), 0x0001);
        assert!(valid(&[0x12, 0x34, 0xed, 0xcb]));
        assert!(!valid(&[0x12, 0x34, 0xed, 0xca]));
    }

    #[test]
    fn pseudo_header_sum_matches_full_checksum() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 7);
        let header = PseudoHeader::V4 {
            src,
            dst,
            protocol: protocol::UDP,
            len: 0,
        };
        assert_eq!(
            !header.sum(),
            transport_checksum_v4(src, dst, protocol::UDP, &[])
        );
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let header = PseudoHeader::V6 {
            src,
            dst,
            protocol: protocol::TCP,
            len: 0,
        };
        assert_eq!(
            !header.sum(),
            transport_checksum_v6(src, dst, protocol::TCP, &[])
        );
    }

    #[test]
    fn udp_zero_rule() {
        assert_eq!(udp_wire(0), 0xFFFF);
        assert_eq!(udp_wire(0x1234), 0x1234);
        // No checksum stays no checksum.
        assert_eq!(update_udp(0, |_| 0x1234), 0);
        // A computed zero is sent as 0xFFFF.
        assert_eq!(
            update_udp(0xDD2F, |c| update_u16(c, 0x5555, 0x3285)),
            0xFFFF
        );
        assert_eq!(update_udp(0x1234, |c| c + 1), 0x1235);
    }

    #[test]
    fn prop_update_u16_and_u32() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..ROUNDS {
            let len = 4 + rng.below(60);
            let mut data = rng.bytes(len);
            let before = internet_checksum(&data);

            let at = rng.offset(len, 2);
            let old = field(&data, at);
            let new = rng.u16();
            data[at..at + 2].copy_from_slice(&new.to_be_bytes());
            let before16 = update_u16(before, old, new);
            assert_eq!(before16, internet_checksum(&data));

            let at = rng.offset(len, 4);
            let old = u32::from_be_bytes(data[at..at + 4].try_into().unwrap());
            let new = rng.u32();
            data[at..at + 4].copy_from_slice(&new.to_be_bytes());
            assert_eq!(update_u32(before16, old, new), internet_checksum(&data));
        }
    }

    #[test]
    fn prop_update_bytes() {
        let mut rng = Rng(0x0123_4567_89AB_CDEF);
        for _ in 0..ROUNDS {
            let len = 2 + rng.below(80);
            let mut data = rng.bytes(len);
            let before = internet_checksum(&data);
            let width = 2 * (1 + rng.below(len / 2));
            let at = rng.offset(len, width);
            let old = data[at..at + width].to_vec();
            let new = rng.bytes(width);
            data[at..at + width].copy_from_slice(&new);
            assert_eq!(update_bytes(before, &old, &new), internet_checksum(&data));
        }
    }

    #[test]
    fn prop_update_ipv4_header_and_transport() {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        for _ in 0..ROUNDS {
            // IPv4 header checksum after a source or destination rewrite.
            let mut header = rng.bytes(20);
            header[0] = 0x45;
            let check = ipv4_header_checksum(&header);
            header[10..12].copy_from_slice(&check.to_be_bytes());
            let at = if rng.next().is_multiple_of(2) { 12 } else { 16 };
            let old = Ipv4Addr::from(<[u8; 4]>::try_from(&header[at..at + 4]).unwrap());
            let new = rng.v4();
            header[at..at + 4].copy_from_slice(&new.octets());
            assert_eq!(update_ipv4(check, old, new), ipv4_header_checksum(&header));

            // Transport checksum after the same rewrite in the pseudo-header.
            let (proto, _, segment) = segment(&mut rng);
            let (src, dst, new) = (rng.v4(), rng.v4(), rng.v4());
            let check = transport_checksum_v4(src, dst, proto, &segment);
            assert_eq!(
                update_ipv4(check, src, new),
                transport_checksum_v4(new, dst, proto, &segment)
            );
            assert_eq!(
                update_ipv4(check, dst, new),
                transport_checksum_v4(src, new, proto, &segment)
            );
        }
    }

    #[test]
    fn prop_update_ipv6_transport() {
        let mut rng = Rng(0x5151_7272_A3A3_0F0F);
        for _ in 0..ROUNDS {
            let (proto, _, segment) = segment(&mut rng);
            let (src, dst, new) = (rng.v6(), rng.v6(), rng.v6());
            let check = transport_checksum_v6(src, dst, proto, &segment);
            assert_eq!(
                update_ipv6(check, src, new),
                transport_checksum_v6(new, dst, proto, &segment)
            );
            assert_eq!(
                update_ipv6(check, dst, new),
                transport_checksum_v6(src, new, proto, &segment)
            );
        }
    }

    #[test]
    fn prop_address_family_change() {
        let mut rng = Rng(0x1357_9BDF_2468_ACE0);
        for _ in 0..ROUNDS {
            let (proto, at, mut segment) = segment(&mut rng);
            let (src4, dst4, src6, dst6) = (rng.v4(), rng.v4(), rng.v6(), rng.v6());
            let len = segment.len();
            let v4 = PseudoHeader::V4 {
                src: src4,
                dst: dst4,
                protocol: proto,
                len: u16::try_from(len).unwrap(),
            };
            let v6 = PseudoHeader::V6 {
                src: src6,
                dst: dst6,
                protocol: proto,
                len: u32::try_from(len).unwrap(),
            };

            // 4 -> 6, with the result stored in the segment and verified.
            let check4 = transport_checksum_v4(src4, dst4, proto, &segment);
            let check6 = update_pseudo_header(check4, v4, v6);
            assert_eq!(check6, transport_checksum_v6(src6, dst6, proto, &segment));
            segment[at..at + 2].copy_from_slice(&check6.to_be_bytes());
            assert_eq!(transport_checksum_v6(src6, dst6, proto, &segment), 0);
            segment[at..at + 2].fill(0);

            // 6 -> 4.
            assert_eq!(update_pseudo_header(check6, v6, v4), check4);

            // ICMPv4 (no pseudo-header) <-> ICMPv6 (pseudo-header, protocol 58).
            let icmp6 = PseudoHeader::V6 {
                src: src6,
                dst: dst6,
                protocol: protocol::ICMPV6,
                len: u32::try_from(len).unwrap(),
            };
            let icmp4 = internet_checksum(&segment);
            let with = update_u16(icmp4, 0, icmp6.sum());
            assert_eq!(
                with,
                transport_checksum_v6(src6, dst6, protocol::ICMPV6, &segment)
            );
            assert_eq!(update_u16(with, icmp6.sum(), 0), icmp4);
        }
    }

    #[test]
    fn prop_udp_update_matches_wire_recompute() {
        let mut rng = Rng(0xA5A5_5A5A_1234_8765);
        for _ in 0..ROUNDS {
            let len = 8 + rng.below(32);
            let mut segment = rng.bytes(len);
            segment[6..8].fill(0);
            let (src, dst, new) = (rng.v4(), rng.v4(), rng.v4());
            let field = udp_wire(transport_checksum_v4(src, dst, protocol::UDP, &segment));
            let updated = update_udp(field, |c| update_ipv4(c, src, new));
            let full = udp_wire(transport_checksum_v4(new, dst, protocol::UDP, &segment));
            assert_eq!(updated, full);
            assert_eq!(update_udp(0, |c| update_ipv4(c, src, new)), 0);
        }
    }
}
