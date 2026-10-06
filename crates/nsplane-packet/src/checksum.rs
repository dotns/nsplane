//! RFC 1071 Internet checksum helpers.
//!
//! All functions return the final, complemented checksum in host order, ready to be
//! written big-endian into a header.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Byte range of the checksum field inside an IPv4 header.
const IPV4_CHECKSUM: std::ops::Range<usize> = 10..12;

/// Adds `data` as big-endian 16-bit words to `acc`; an odd trailing byte is padded with zero.
///
/// The bulk is summed as big-endian 32-bit words: since `2^16 ≡ 1` modulo `2^16 - 1`, that
/// folds to the same one's-complement sum (RFC 1071 §2(B)), and the u64 cannot overflow
/// below `2^32` words.
fn add_words(acc: u64, data: &[u8]) -> u64 {
    let (words, tail) = data.as_chunks::<4>();
    let tail = match *tail {
        [a, b, c] => u64::from(u16::from_be_bytes([a, b])) + u64::from(u16::from_be_bytes([c, 0])),
        [a, b] => u64::from(u16::from_be_bytes([a, b])),
        [a] => u64::from(u16::from_be_bytes([a, 0])),
        _ => 0,
    };
    words.iter().fold(acc + tail, |acc, word| {
        acc + u64::from(u32::from_be_bytes(*word))
    })
}

/// Folds the carries of `acc` into 16 bits and returns the one's complement.
const fn finish(mut acc: u64) -> u16 {
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    let [.., hi, lo] = acc.to_be_bytes();
    !u16::from_be_bytes([hi, lo])
}

/// Returns the Internet checksum of `data` (odd length is padded with a zero byte).
pub fn internet_checksum(data: &[u8]) -> u16 {
    finish(add_words(0, data))
}

/// Returns the checksum of an IPv4 header, treating its checksum field (bytes 10..12)
/// as zero so the result can be written straight into the header.
///
/// A header shorter than 20 bytes is summed as given.
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let before = header.get(..IPV4_CHECKSUM.start).unwrap_or(header);
    let after = header.get(IPV4_CHECKSUM.end..).unwrap_or(&[]);
    finish(add_words(add_words(0, before), after))
}

/// Returns the TCP/UDP/ICMPv6-style checksum of `segment` over an IPv4 pseudo-header.
///
/// The caller must zero the segment's own checksum field first. A UDP result of
/// `0x0000` is not mapped to `0xFFFF` here (RFC 768); that is the caller's job.
pub fn transport_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, segment: &[u8]) -> u16 {
    let mut acc = add_words(0, &src.octets());
    acc = add_words(acc, &dst.octets());
    acc += u64::from(protocol) + segment.len() as u64;
    finish(add_words(acc, segment))
}

/// Returns the TCP/UDP/ICMPv6 checksum of `segment` over an IPv6 pseudo-header.
///
/// The caller must zero the segment's own checksum field first. A UDP result of
/// `0x0000` is not mapped to `0xFFFF` here; that is the caller's job.
pub fn transport_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, segment: &[u8]) -> u16 {
    let mut acc = add_words(0, &src.octets());
    acc = add_words(acc, &dst.octets());
    acc += u64::from(protocol) + segment.len() as u64;
    finish(add_words(acc, segment))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(!internet_checksum(&data), 0xddf2);
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn odd_length_pads_with_zero() {
        assert_eq!(internet_checksum(&[0x12, 0x34, 0x56]), !0x6834);
        assert_eq!(internet_checksum(&[]), 0xFFFF);
    }

    #[test]
    fn ipv4_header_known_vector() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ipv4_header_checksum(&header), 0xb861);
        // Same result with the field zeroed, and a valid header sums to zero.
        let mut zeroed = header;
        zeroed[10..12].fill(0);
        assert_eq!(ipv4_header_checksum(&zeroed), 0xb861);
        assert_eq!(internet_checksum(&header), 0);
    }

    #[test]
    fn ipv4_header_short_input_does_not_panic() {
        for len in 0..20 {
            let header = [0x45u8; 20];
            let _ = ipv4_header_checksum(&header[..len]);
        }
        assert_eq!(ipv4_header_checksum(&[0x45, 0x00]), !0x4500);
    }

    #[test]
    fn udp_over_ipv4_verifies() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 7);
        // src port 51820, dst port 53, len 13, checksum 0, payload "hello".
        let mut segment = vec![0xca, 0x6c, 0x00, 0x35, 0x00, 0x0d, 0x00, 0x00];
        segment.extend_from_slice(b"hello");
        let sum = transport_checksum_v4(src, dst, 17, &segment);
        assert_ne!(sum, 0);
        segment[6..8].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(transport_checksum_v4(src, dst, 17, &segment), 0);
    }

    #[test]
    fn tcp_over_ipv6_verifies() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut segment = vec![
            0x01, 0xbb, 0xc0, 0x00, // ports 443 -> 49152
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0xff, 0xff, // data offset 5, SYN, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent pointer
        ];
        segment.push(0x2a);
        let sum = transport_checksum_v6(src, dst, 6, &segment);
        segment[16..18].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(transport_checksum_v6(src, dst, 6, &segment), 0);
    }

    /// The previous 16-bit word loop, kept as the reference for [`add_words`].
    fn add_words_16(acc: u64, data: &[u8]) -> u64 {
        let (words, tail) = data.as_chunks::<2>();
        let tail = match tail {
            [last] => u64::from(u16::from_be_bytes([*last, 0])),
            _ => 0,
        };
        words.iter().fold(acc + tail, |acc, word| {
            acc + u64::from(u16::from_be_bytes(*word))
        })
    }

    /// Deterministic xorshift64 PRNG for the equivalence test.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % n as u64).unwrap()
        }
    }

    #[test]
    fn matches_16_bit_reference() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        let mut buf = [0u8; 2048 + 8];
        for _ in 0..4096 {
            buf.fill_with(|| rng.next().to_le_bytes()[0]);
            // Half the cases short, where the tail handling dominates.
            let len = if rng.next() & 1 == 0 {
                rng.below(65)
            } else {
                rng.below(2049)
            };
            // Up to 2^48: room for any realistic chain of further sums.
            let acc = rng.next() >> 16;
            let src = Ipv4Addr::from_bits(u32::try_from(rng.next() >> 32).unwrap());
            let dst = Ipv4Addr::from_bits(u32::try_from(rng.next() >> 32).unwrap());
            let src6 = Ipv6Addr::from_bits(u128::from(rng.next()) << 64 | u128::from(rng.next()));
            let dst6 = Ipv6Addr::from_bits(u128::from(rng.next()) << 64 | u128::from(rng.next()));
            let protocol = rng.next().to_le_bytes()[0];
            for offset in 0..8 {
                let data = &buf[offset..offset + len];
                assert_eq!(
                    finish(add_words(acc, data)),
                    finish(add_words_16(acc, data)),
                    "add_words len {len} offset {offset}"
                );
                assert_eq!(internet_checksum(data), finish(add_words_16(0, data)));

                let before = data.get(..IPV4_CHECKSUM.start).unwrap_or(data);
                let after = data.get(IPV4_CHECKSUM.end..).unwrap_or(&[]);
                assert_eq!(
                    ipv4_header_checksum(data),
                    finish(add_words_16(add_words_16(0, before), after))
                );

                let mut v4 = add_words_16(add_words_16(0, &src.octets()), &dst.octets());
                v4 += u64::from(protocol) + data.len() as u64;
                assert_eq!(
                    transport_checksum_v4(src, dst, protocol, data),
                    finish(add_words_16(v4, data))
                );

                let mut v6 = add_words_16(add_words_16(0, &src6.octets()), &dst6.octets());
                v6 += u64::from(protocol) + data.len() as u64;
                assert_eq!(
                    transport_checksum_v6(src6, dst6, protocol, data),
                    finish(add_words_16(v6, data))
                );
            }
        }
    }

    #[test]
    fn pseudo_header_matches_explicit_layout() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let segment = [0x11, 0x22, 0x33];
        let mut explicit = Vec::new();
        explicit.extend_from_slice(&src.octets());
        explicit.extend_from_slice(&dst.octets());
        explicit.extend_from_slice(&[0, 17, 0, 3]);
        explicit.extend_from_slice(&segment);
        assert_eq!(
            transport_checksum_v4(src, dst, 17, &segment),
            internet_checksum(&explicit)
        );
    }
}
