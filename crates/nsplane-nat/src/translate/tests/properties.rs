//! Randomized properties of the strict parsers and of the translator on packets a
//! remote party controls.
//!
//! The inputs come from a seeded generator: packets of every mapping kind and protocol,
//! most of them with a few fields flipped, truncated or extended and, half of the time,
//! their checksums computed again so the change gets past the checksum checks.

use nsplane_packet::IpPacket;
use nsplane_packet::reassembly::{Outcome, Reassembler, ReassemblyConfig};

use super::super::parse::{Ipv4, Ipv6};
use super::*;

/// `SplitMix64`.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n`.
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    const fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    const fn u16(&mut self) -> u16 {
        let [a, b, ..] = self.next().to_le_bytes();
        u16::from_le_bytes([a, b])
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}

/// A host inside the IPv4 prefix `base`/`len`.
fn host4(rng: &mut Rng, base: &str, len: u32) -> Ipv4Addr {
    let host = u32::from(rng.u16()) % (1 << (32 - len)).max(1);
    Ipv4Addr::from_bits(ip4(base).to_bits() | host.max(1))
}

/// The address of `host` inside the /96 `base`.
fn host6(base: &str, host: Ipv4Addr) -> Ipv6Addr {
    Ipv6Addr::from_bits(ip6(base).to_bits() | u128::from(host.to_bits()))
}

/// A local-side IPv4 address: mapped ones of every kind, and others.
fn local4(rng: &mut Rng) -> Ipv4Addr {
    match rng.below(8) {
        0 | 1 => SELF_EAM4,
        2 => host4(rng, "192.168.1.0", 24),
        3 | 4 => EAM4,
        5 => host4(rng, "10.0.0.0", 8),
        6 => rng.pick(&[OTHER_EAM4, ip4("172.16.3.4")]),
        _ => rng.pick(&[
            ip4("8.8.8.8"),
            ip4("127.0.0.1"),
            ip4("224.0.0.1"),
            ip4("0.0.0.0"),
        ]),
    }
}

/// A tunnel-side IPv6 address: mapped ones of every kind, and others.
fn tunnel6(rng: &mut Rng) -> Ipv6Addr {
    match rng.below(9) {
        0 | 1 => self_eam6(),
        2 => host6("fd64:1::", host4(rng, "192.168.1.0", 24)),
        3 | 4 => peer_mapping().eam6,
        5 => peer_mapping().peer6,
        6 => host6("fd64:2::", host4(rng, "10.0.0.0", 8)),
        7 => rng.pick(&[
            other_mapping().eam6,
            ip6("fd99::1"),
            ip6("fd64:3::ac10:304"),
        ]),
        _ => rng.pick(&[ip6("2001:db8::1"), ip6("::1"), ip6("ff02::1"), ip6("::")]),
    }
}

/// A valid IPv4 packet from `src` to `dst` quoted in an ICMP error, or one cut short
/// behind the first `keep` bytes of its transport header.
fn quote4(rng: &mut Rng, src: Ipv4Addr, dst: Ipv4Addr, keep: usize) -> Vec<u8> {
    let len = rng.below(24) + 1;
    let data = rng.bytes(len);
    let (proto, body) = match rng.below(4) {
        0 => (protocol::TCP, tcp4(src, dst, &data)),
        1 => (protocol::ICMP, echo4(rng.chance(50), &data)),
        2 => (protocol::UDP, udp4(src, dst, &data, true)),
        _ => (protocol::UDP, udp4(src, dst, &data, false)),
    };
    let hdr = Hdr4 {
        ttl: rng.byte(),
        ..Hdr4::default()
    };
    let mut quote = ipv4(src, dst, proto, hdr, &body);
    if rng.chance(30) {
        quote.truncate(20 + keep + rng.below(quote.len() - 19 - keep));
    }
    quote
}

/// The IPv6 counterpart of [`quote4`].
fn quote6(rng: &mut Rng, src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let len = rng.below(24) + 1;
    let data = rng.bytes(len);
    let (proto, body) = match rng.below(3) {
        0 => (protocol::TCP, tcp6(src, dst, &data)),
        1 => (protocol::ICMPV6, echo6(src, dst, rng.chance(50), &data)),
        _ => (protocol::UDP, udp6(src, dst, &data)),
    };
    let mut quote = ipv6(src, dst, proto, rng.byte(), 0, &[], &body);
    if rng.chance(30) {
        quote.truncate(40 + rng.below(quote.len() - 39));
    }
    quote
}

/// The second word of an ICMP error: zero, an MTU, a pointer or a length attribute.
fn error_rest(rng: &mut Rng) -> [u8; 4] {
    match rng.below(4) {
        0 => [0; 4],
        1 => [0, 0, 5, rng.byte()],
        2 => [rng.pick(&[0, 1, 2, 8, 9, 12, 16, 20, 40]), 0, 0, 0],
        _ => [rng.byte() % 16, rng.byte() % 16, 0, rng.byte() % 48],
    }
}

/// A valid IPv4 packet between two local-side addresses, mostly a pair the translator
/// maps for `PEER`.
fn valid4(rng: &mut Rng) -> Vec<u8> {
    let (src, dst) = if rng.chance(60) {
        let lan = (host4(rng, "192.168.1.0", 24), host4(rng, "10.0.0.0", 8));
        (rng.pick(&[SELF_EAM4, lan.0]), rng.pick(&[EAM4, lan.1]))
    } else {
        (local4(rng), local4(rng))
    };
    let len = rng.below(64);
    let data = rng.bytes(len);
    let (proto, body) = match rng.below(8) {
        0 | 1 => (protocol::TCP, tcp4(src, dst, &data)),
        2 => (protocol::UDP, udp4(src, dst, &data, true)),
        3 => (protocol::UDP, udp4(src, dst, &data, false)),
        4 => (protocol::ICMP, echo4(rng.chance(50), &data)),
        5 | 6 => {
            let kind = rng.pick(&[3, 3, 3, 11, 12, 4, 5]);
            let code = rng.pick(&[0, 1, 2, 3, 4, 9, 13, 14]);
            let mut error = icmp4_error(kind, code, error_rest(rng), &quote4(rng, dst, src, 0));
            if rng.chance(20) {
                // Bytes behind the quote, as an RFC 4884 extension would be.
                error.extend(rng.bytes(8));
                error[2..4].fill(0);
                let checksum = internet_checksum(&error);
                error[2..4].copy_from_slice(&checksum.to_be_bytes());
            }
            (protocol::ICMP, error)
        }
        _ => (47, data),
    };
    let options = [1, 1, 1, 0];
    let hdr = Hdr4 {
        ttl: rng.pick(&[0, 1, 2, 64, 64, 64, 255]),
        tos: rng.byte(),
        id: rng.u16(),
        fragment: rng.pick(&[0, 0, 0, 0x4000, 0x4000, 0x2000, 0x2001, 3]),
        options: if rng.chance(15) { &options } else { &[] },
    };
    ipv4(src, dst, proto, hdr, &body)
}

/// A valid IPv6 packet between two tunnel-side addresses, mostly a pair the translator
/// maps or rewrites for `PEER`, behind none or a few extension headers.
fn valid6(rng: &mut Rng) -> Vec<u8> {
    let (src, dst) = match rng.below(10) {
        0..=5 => {
            let lan = (
                host6("fd64:2::", host4(rng, "10.0.0.0", 8)),
                host6("fd64:1::", host4(rng, "192.168.1.0", 24)),
            );
            (
                rng.pick(&[peer_mapping().eam6, lan.0]),
                rng.pick(&[self_eam6(), lan.1]),
            )
        }
        6 => (peer_mapping().peer6, ip6("2001:db8::1")),
        7 => (ip6("2001:db8::1"), ip6("fd99::1")),
        _ => (tunnel6(rng), tunnel6(rng)),
    };
    let len = rng.below(64);
    let data = rng.bytes(len);
    let (proto, body) = match rng.below(7) {
        0 | 1 => (protocol::TCP, tcp6(src, dst, &data)),
        2 | 3 => (protocol::UDP, udp6(src, dst, &data)),
        4 => (protocol::ICMPV6, echo6(src, dst, rng.chance(50), &data)),
        5 => {
            let kind = rng.pick(&[1, 1, 2, 3, 4, 100]);
            let code = rng.pick(&[0, 1, 2, 3, 4, 5]);
            let quote = quote6(rng, dst, src);
            let error = icmp6_error(src, dst, kind, code, error_rest(rng), &quote);
            (protocol::ICMPV6, error)
        }
        _ => (47, data),
    };
    // The first next header, then the extension headers.
    let mut extensions = Vec::new();
    if rng.chance(15) {
        extensions.extend([0, proto, 0, 1, 4, 0, 0, 0, 0]);
    }
    if rng.chance(15) {
        let more = u8::from(rng.chance(50));
        let offset = rng.pick(&[0, 0, 8]);
        let first = if extensions.is_empty() {
            &[44][..]
        } else {
            &[]
        };
        if let Some(next) = extensions.get_mut(1) {
            *next = 44;
        }
        extensions.extend(first);
        extensions.extend([proto, 0, 0, offset | more, 0, 0, 0, rng.byte()]);
    }
    let hop = rng.pick(&[0, 1, 2, 64, 64, 64, 255]);
    ipv6(src, dst, proto, hop, rng.byte(), &extensions, &body)
}

/// Changes a few fields of `packet`: bit flips, boundary values in bytes and 16-bit
/// fields, truncation and trailing bytes. Half of the changes land in the outer headers.
fn mutate(rng: &mut Rng, packet: &mut Vec<u8>) {
    for _ in 0..=rng.below(2) {
        if packet.is_empty() {
            packet.push(rng.byte());
        }
        let len = packet.len();
        let at = if rng.chance(50) {
            rng.below(len.min(48))
        } else {
            rng.below(len)
        };
        match rng.below(7) {
            0 => packet[at] ^= 1 << rng.below(8),
            1 => packet[at] = rng.pick(&[0, 1, 0x0f, 0x45, 0x60, 0x7f, 0x80, 0xff]),
            2 if at + 1 < len => {
                let value = rng.pick(&[0, 1, 8, 20, 40, 0x7fff, 0xffff, len, len + 1, len - 1]);
                let [.., hi, lo] = value.to_be_bytes();
                packet[at..at + 2].copy_from_slice(&[hi, lo]);
            }
            3 => packet.truncate(rng.below(len + 1)),
            4 => {
                let extra = 1 + rng.below(24);
                packet.extend(rng.bytes(extra));
            }
            // A protocol or next-header value the parsers treat specially.
            5 if at < 48 => packet[at] = rng.pick(&[0, 1, 6, 17, 43, 44, 50, 51, 58, 59, 60]),
            _ => packet[at] = rng.byte(),
        }
    }
}

/// Makes the checksums of a changed packet valid again, as far as its layout allows:
/// the IPv4 header checksum, and the transport checksum of an unfragmented TCP, UDP,
/// ICMP or `ICMPv6` message directly behind the IP header.
fn repair(packet: &mut [u8]) {
    let Ok(parsed) = IpPacket::parse(packet) else {
        return;
    };
    let (proto, len, fragment) = (parsed.protocol(), parsed.payload().len(), parsed.fragment());
    let (src, dst) = (parsed.src(), parsed.dst());
    let start = if packet[0] >> 4 == 4 {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        packet[10..12].fill(0);
        let checksum = internet_checksum(&packet[..header_len]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        header_len
    } else {
        40
    };
    let at = match proto {
        protocol::TCP => 16,
        protocol::UDP => 6,
        protocol::ICMP | protocol::ICMPV6 => 2,
        _ => return,
    };
    if fragment.is_some() || len < at + 2 {
        return;
    }
    let segment = &mut packet[start..start + len];
    segment[at..at + 2].fill(0);
    let checksum = match (src, dst, proto) {
        (_, _, protocol::ICMP) => internet_checksum(segment),
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst), _) => {
            transport_checksum_v4(src, dst, proto, segment)
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst), _) => {
            transport_checksum_v6(src, dst, proto, segment)
        }
        _ => return,
    };
    segment[at..at + 2].copy_from_slice(&checksum.to_be_bytes());
}

/// Valid, changed and random packets of both versions.
fn untrusted(rng: &mut Rng) -> Vec<u8> {
    let mut packet = if rng.chance(50) {
        valid4(rng)
    } else {
        valid6(rng)
    };
    match rng.below(10) {
        0 => {
            let len = rng.below(100);
            packet = rng.bytes(len);
            if let Some(first) = packet.first_mut() {
                *first = rng.pick(&[0x45, 0x46, 0x60]);
            }
        }
        1..=3 => {}
        _ => {
            mutate(rng, &mut packet);
            if rng.chance(50) {
                repair(&mut packet);
            }
        }
    }
    packet
}

/// Whether the transport checksum of a strictly parsed packet verifies; `None` for a
/// fragment and for protocols without one.
fn transport_ok(packet: &[u8]) -> Option<bool> {
    if packet[0] >> 4 == 4 {
        let v4 = Ipv4::parse(packet, false).unwrap();
        let segment = &packet[v4.payload.clone()];
        match v4.protocol {
            _ if v4.fragmented() => None,
            protocol::TCP | protocol::UDP => {
                Some(transport_checksum_v4(v4.src, v4.dst, v4.protocol, segment) == 0)
            }
            protocol::ICMP => Some(internet_checksum(segment) == 0),
            _ => None,
        }
    } else {
        let v6 = Ipv6::parse(packet, false).unwrap();
        let segment = &packet[v6.payload.clone()];
        match v6.protocol {
            _ if v6.fragment.is_some() => None,
            protocol::UDP if segment.len() >= 8 && segment[6..8] == [0, 0] => Some(false),
            protocol::TCP | protocol::UDP | protocol::ICMPV6 => {
                Some(transport_checksum_v6(v6.src, v6.dst, v6.protocol, segment) == 0)
            }
            _ => None,
        }
    }
}

#[test]
fn strict_parsers_accept_only_consistent_packets() {
    let mut rng = Rng(0x3001);
    let (mut accepted4, mut accepted6) = (0, 0);
    for case in 0..30_000 {
        let bytes = untrusted(&mut rng);
        let lenient = IpPacket::parse(&bytes);
        for quoted in [false, true] {
            if let Ok(v4) = Ipv4::parse(&bytes, quoted) {
                accepted4 += 1;
                let context = format!("case {case} quoted {quoted}: {bytes:02x?}");
                assert_eq!(bytes[0] >> 4, 4, "{context}");
                assert!((20..=60).contains(&v4.header_len), "{context}");
                assert!(v4.header_len <= v4.total_len, "{context}");
                assert!(v4.header_len <= bytes.len(), "{context}");
                assert_eq!(internet_checksum(&bytes[..v4.header_len]), 0, "{context}");
                assert_eq!(
                    v4.payload,
                    v4.header_len..v4.total_len.min(bytes.len()),
                    "{context}"
                );
                assert_eq!(bytes[6] & 0x80, 0, "{context}");
                assert_eq!((v4.src, v4.dst), (src4(&bytes), dst4(&bytes)), "{context}");
                if !quoted {
                    assert_eq!(v4.total_len, bytes.len(), "{context}");
                    // A packet the strict parser takes, the data plane's parser takes too.
                    let lenient = lenient.as_ref().unwrap();
                    assert_eq!(lenient.payload(), &bytes[v4.payload.clone()], "{context}");
                    assert_eq!(lenient.protocol(), v4.protocol, "{context}");
                    assert_eq!(lenient.fragment().is_some(), v4.fragmented(), "{context}");
                    for addr in [v4.src, v4.dst] {
                        assert!(
                            !addr.is_unspecified() && !addr.is_loopback() && !addr.is_multicast(),
                            "{context}"
                        );
                    }
                    // What is a packet on its own is a quotable packet too.
                    assert!(Ipv4::parse(&bytes, true).is_ok(), "{context}");
                }
            }
            if let Ok(v6) = Ipv6::parse(&bytes, quoted) {
                accepted6 += 1;
                let context = format!("case {case} quoted {quoted}: {bytes:02x?}");
                assert_eq!(bytes[0] >> 4, 6, "{context}");
                assert_eq!(
                    v6.total_len,
                    40 + usize::from(u16::from_be_bytes([bytes[4], bytes[5]])),
                    "{context}"
                );
                assert!(v6.payload.start >= 40, "{context}");
                assert!(v6.payload.start <= v6.payload.end, "{context}");
                assert_eq!(v6.payload.end, v6.total_len.min(bytes.len()), "{context}");
                // The protocol is not a header the walk steps over or refuses. Behind a
                // fragment header, which ends the chain, ESP and "no next header" are
                // carried as the payload they are.
                assert!(!matches!(v6.protocol, 0 | 43 | 44 | 51 | 60), "{context}");
                assert!(
                    v6.fragment.is_some() || !matches!(v6.protocol, 50 | 59),
                    "{context}"
                );
                assert_eq!((v6.src, v6.dst), (src6(&bytes), dst6(&bytes)), "{context}");
                if let Some(fragment) = v6.fragment {
                    // The fragment header is the last one, right in front of the payload.
                    let header = &bytes[v6.payload.start - 8..v6.payload.start];
                    assert_eq!(header[0], v6.protocol, "{context}");
                    let bits = u16::from_be_bytes([header[2], header[3]]);
                    assert_eq!(
                        (fragment.offset, fragment.more),
                        (bits >> 3, bits & 1 == 1),
                        "{context}"
                    );
                    assert_eq!(
                        fragment.identification.to_be_bytes(),
                        header[4..8],
                        "{context}"
                    );
                } else if v6.payload.start == 40 {
                    assert_eq!(v6.protocol, bytes[6], "{context}");
                }
                if !quoted {
                    assert_eq!(v6.total_len, bytes.len(), "{context}");
                    assert!(lenient.is_ok(), "{context}");
                    assert!(Ipv6::parse(&bytes, true).is_ok(), "{context}");
                }
            }
        }
    }
    assert!(accepted4 > 5_000, "only {accepted4} IPv4 packets accepted");
    assert!(accepted6 > 5_000, "only {accepted6} IPv6 packets accepted");
}

#[test]
fn a_quoted_packet_parses_at_every_cut_behind_its_headers() {
    let mut rng = Rng(0x3002);
    for case in 0..2_000 {
        let (src, dst) = (rng.pick(&[SELF_EAM4, EAM4]), ip4("10.1.2.3"));
        let v4 = quote4(&mut rng, src, dst, 0);
        let whole = Ipv4::parse(&v4, true).unwrap();
        for cut in 20..=v4.len() {
            let cut_short = Ipv4::parse(&v4[..cut], true).unwrap();
            assert_eq!(
                cut_short.payload,
                20..cut.min(whole.total_len),
                "case {case}"
            );
            assert_eq!(
                (cut_short.protocol, cut_short.total_len),
                (whole.protocol, whole.total_len),
                "case {case}"
            );
        }
        // Bytes behind the packet are not part of it.
        let mut padded = v4.clone();
        padded.extend(rng.bytes(12));
        if whole.total_len == v4.len() {
            assert_eq!(Ipv4::parse(&padded, true).unwrap().payload, whole.payload);
        }

        let v6 = quote6(&mut rng, self_eam6(), peer_mapping().eam6);
        let whole = Ipv6::parse(&v6, true).unwrap();
        for cut in 40..=v6.len() {
            let cut_short = Ipv6::parse(&v6[..cut], true).unwrap();
            assert_eq!(
                cut_short.payload,
                40..cut.min(whole.total_len),
                "case {case}"
            );
            assert_eq!(cut_short.protocol, whole.protocol, "case {case}");
        }
    }
}

/// Checks a packet the translator accepted and changed, and returns whether it is IPv6.
fn check_translated(input: &[u8], output: &[u8], context: &str) -> bool {
    // Exact length fields, in the data plane's parser and in the strict one.
    let lenient = IpPacket::parse(output).unwrap_or_else(|error| panic!("{error}: {context}"));
    let v6 = output[0] >> 4 == 6;
    let header_len = if v6 { 40 } else { 20 };
    assert_eq!(
        header_len + lenient.payload().len(),
        output.len(),
        "{context}"
    );
    if v6 {
        assert!(Ipv6::parse(output, false).is_ok(), "{context}");
    } else {
        assert_eq!(output[0], 0x45, "{context}");
        assert!(Ipv4::parse(output, false).is_ok(), "{context}");
    }
    if v6 == (input[0] >> 4 == 6) {
        // An address rewrite keeps the transport checksum as good as it was.
        assert_eq!(transport_ok(output), transport_ok(input), "{context}");
        assert_eq!(output.len(), input.len(), "{context}");
        return v6;
    }
    // A translation only lets valid checksums through.
    assert_ne!(transport_ok(output), Some(false), "{context}");
    if v6 {
        assert_eq!(
            (output[1] & 0x0f, output[2], output[3]),
            (0, 0, 0),
            "{context}"
        );
    }
    // The packet quoted in a translated error is of the new version too.
    let (proto, body) = (lenient.protocol(), lenient.payload());
    let error = match proto {
        protocol::ICMP => matches!(body[0], 3 | 11 | 12),
        protocol::ICMPV6 => body[0] < 128,
        _ => false,
    };
    if error {
        let quote = &body[8..];
        // A quoted echo is of the new version as well, as far as its header is there. The
        // type is its first byte, so one byte of the header is enough: this check used to
        // be left out, because a header cut below four bytes kept the type of the other
        // version until the translator mapped it.
        if v6 {
            assert!(quote.len() >= 40 && quote[0] >> 4 == 6, "{context}");
            if quote[6] == protocol::ICMPV6 {
                assert!(!matches!(quote.get(40), Some(0 | 8)), "{context}");
            }
        } else {
            assert!(quote.len() >= 20 && quote[0] == 0x45, "{context}");
            assert_eq!(internet_checksum(&quote[..20]), 0, "{context}");
            let offset = u16::from_be_bytes([quote[6], quote[7]]) << 3;
            if quote[9] == protocol::ICMP && offset == 0 {
                assert!(!matches!(quote.get(20), Some(128 | 129)), "{context}");
            }
        }
    }
    v6
}

#[test]
fn translated_packets_parse_and_carry_valid_checksums() {
    let mut rng = Rng(0x3003);
    let translator = translator();
    let (mut translated, mut rewritten, mut dropped) = (0, 0, 0);
    for case in 0..40_000 {
        let packet = untrusted(&mut rng);
        let peer = rng.pick(&[PEER, PEER, PEER, OTHER]);
        // Mostly the direction in which a packet of this version is translated.
        let out = rng.chance(if packet.first().is_some_and(|b| b >> 4 == 4) {
            80
        } else {
            25
        });
        let before = translator.stats();
        let (verdict, output) = if out {
            outbound(&translator, peer, &packet)
        } else {
            inbound(&translator, peer, &packet)
        };
        let after = translator.stats();
        let context = format!("case {case} out {out} {peer:?}: {packet:02x?} -> {output:02x?}");
        // What the counters of this direction say happened.
        let counted = if out {
            (
                after.translated_out - before.translated_out,
                after.rewritten_out - before.rewritten_out,
                after.dropped_out - before.dropped_out,
            )
        } else {
            (
                after.translated_in - before.translated_in,
                after.rewritten_in - before.rewritten_in,
                after.dropped_in - before.dropped_in,
            )
        };
        match verdict {
            Verdict::Drop { reason } => {
                dropped += 1;
                assert!(!reason.is_empty(), "{context}");
                assert_eq!(counted, (0, 0, 1), "{context}");
            }
            Verdict::Handled => {
                // Only an outbound IPv4 UDP fragment is ever held.
                assert!(out && packet[0] >> 4 == 4 && packet[9] == 17, "{context}");
                assert_eq!(counted, (0, 0, 0), "{context}");
            }
            Verdict::Accept if output == packet => {
                assert_eq!(counted, (0, 0, 0), "{context}");
            }
            Verdict::Accept => {
                let v6 = check_translated(&packet, &output, &context);
                if v6 == (packet[0] >> 4 == 6) {
                    rewritten += 1;
                    assert_eq!(counted, (0, 1, 0), "{context}");
                } else {
                    translated += 1;
                    // Outbound IPv4 becomes IPv6 and inbound IPv6 becomes IPv4, never
                    // the other way.
                    assert_eq!(v6, out, "{context}");
                    assert_eq!(counted, (1, 0, 0), "{context}");
                }
            }
        }
    }
    assert!(translated > 1_500, "only {translated} packets translated");
    assert!(rewritten > 150, "only {rewritten} packets rewritten");
    assert!(dropped > 5_000, "only {dropped} packets dropped");
}

const US: PeerId = PeerId::new(7);

/// The table of `PEER`, where this node is the peer `US`: the same IPv6 addresses and
/// LAN prefixes as [`table`], seen from the other end.
fn remote_table() -> TranslationTable {
    TranslationTable::builder()
        .peer(
            US,
            PeerMapping {
                peer6: ip6("fd00::ff:0"),
                eam6: self_eam6(),
                local6: None,
                eam4: Some(ip4("100.64.9.1")),
            },
        )
        .self_mapping(SelfMapping {
            eam4: ip4("100.64.9.2"),
            eam6: peer_mapping().eam6,
        })
        .lan(lan("192.168.1.0", 24, "fd64:1::", Some(US)))
        .lan(lan("10.0.0.0", 8, "fd64:2::", None))
        .build()
        .unwrap()
}

#[test]
fn a_packet_translated_at_both_ends_arrives_with_its_segment() {
    let mut rng = Rng(0x3004);
    let (near, far) = (translator(), Translator::new(remote_table()));
    for case in 0..4_000 {
        // Between the two EAM addresses, or between the two LANs.
        let lan = rng.chance(50);
        let (src, dst) = if lan {
            (
                host4(&mut rng, "192.168.1.0", 24),
                host4(&mut rng, "10.0.0.0", 8),
            )
        } else {
            (SELF_EAM4, EAM4)
        };
        let len = rng.below(1_400);
        let data = rng.bytes(len);
        let (proto, body) = match rng.below(5) {
            0 => (protocol::TCP, tcp4(src, dst, &data)),
            1 => (protocol::UDP, udp4(src, dst, &data, false)),
            2 => (protocol::UDP, udp4(src, dst, &data, true)),
            3 => (protocol::ICMP, echo4(rng.chance(50), &data)),
            _ => {
                // With the 8 transport bytes RFC 792 asks for, and a UDP checksum: the
                // far end refuses an error that quotes IPv6 UDP without one, and no
                // packet that crossed the tunnel is quoted like that.
                let quote = loop {
                    let quote = quote4(&mut rng, dst, src, 8);
                    if quote[9] != protocol::UDP || quote[26..28] != [0, 0] {
                        break quote;
                    }
                };
                let kind = rng.pick(&[(3, 1), (3, 3), (11, 0), (11, 1)]);
                (protocol::ICMP, icmp4_error(kind.0, kind.1, [0; 4], &quote))
            }
        };
        let hdr = Hdr4 {
            ttl: 3 + rng.byte() % 250,
            tos: rng.byte(),
            id: rng.u16(),
            fragment: rng.pick(&[0, 0x4000]),
            options: &[],
        };
        let sent = ipv4(src, dst, proto, hdr, &body);
        let (verdict, v6) = outbound(&near, PEER, &sent);
        assert_eq!(verdict, Verdict::Accept, "case {case}: {sent:02x?}");
        check_v6(&v6);
        let (verdict, received) = inbound(&far, US, &v6);
        assert_eq!(verdict, Verdict::Accept, "case {case}: {sent:02x?}");
        check_v4(&received);

        let (far_src, far_dst) = if lan {
            (src, dst)
        } else {
            (ip4("100.64.9.1"), ip4("100.64.9.2"))
        };
        assert_eq!((src4(&received), dst4(&received)), (far_src, far_dst));
        assert_eq!(
            (received[1], received[8], received[9]),
            (hdr.tos, hdr.ttl - 2, proto),
            "case {case}"
        );
        let (segment, arrived) = (&sent[20..], &received[20..]);
        if proto == protocol::ICMP && matches!(body[0], 3 | 11) {
            // An error: the same type and code, quoting the same packet as the far end
            // sees it.
            assert_eq!(arrived[..2], segment[..2], "case {case}");
            let (quote, far_quote) = (&segment[8..], &arrived[8..]);
            assert_eq!(far_quote.len(), quote.len(), "case {case}");
            assert_eq!((src4(far_quote), dst4(far_quote)), (far_dst, far_src));
            assert_eq!((far_quote[8], far_quote[9]), (quote[8], quote[9]));
            if quote[9] != protocol::ICMP && lan {
                assert_eq!(far_quote[20..], quote[20..], "case {case}");
            }
            continue;
        }
        // The segment as sent, but for its checksum (verified above).
        let at = match proto {
            protocol::TCP => 16,
            protocol::UDP => 6,
            _ => 2,
        };
        assert_eq!(arrived[..at], segment[..at], "case {case}");
        assert_eq!(arrived[at + 2..], segment[at + 2..], "case {case}");
    }
}

/// A UDP datagram cut into IPv4 fragments at random 8-byte boundaries.
fn fragments4(rng: &mut Rng, id: u16, udp: &[u8]) -> Vec<Vec<u8>> {
    let units = udp.len().div_ceil(8);
    let mut cuts: Vec<usize> = (0..=rng.below(4))
        .map(|_| (1 + rng.below(units - 1)) * 8)
        .collect();
    cuts.extend([0, udp.len()]);
    cuts.sort_unstable();
    cuts.dedup();
    cuts.windows(2)
        .map(|cut| {
            let offset = u16::try_from(cut[0] / 8).unwrap();
            fragment4(id, offset, cut[1] != udp.len(), 64, &udp[cut[0]..cut[1]])
        })
        .collect()
}

#[test]
fn fragmented_udp_arrives_whole_whatever_the_order() {
    let mut rng = Rng(0x3005);
    let translator = translator();
    let (mut reassembled, mut one_by_one) = (0, 0);
    for case in 0..1_500 {
        let len = 9 + rng.below(1_100);
        let data = rng.bytes(len);
        let zero = rng.chance(50);
        let udp = udp4(SELF_EAM4, EAM4, &data, zero);
        let id = u16::try_from(case).unwrap();
        let mut pieces = fragments4(&mut rng, id, &udp);
        rng.shuffle(&mut pieces);

        // What the translator lets through, put together by an IPv6 reassembler.
        let mut receiver = Reassembler::new(ReassemblyConfig::default());
        let now = std::time::Instant::now();
        let mut whole = None;
        let mut accepted = 0;
        for piece in &pieces {
            let (verdict, v6) = outbound(&translator, PEER, piece);
            match verdict {
                Verdict::Handled => continue,
                Verdict::Accept => accepted += 1,
                Verdict::Drop { reason } => panic!("case {case}: dropped as {reason}"),
            }
            assert!(whole.is_none(), "case {case}: output after the datagram");
            match receiver.push(&v6, now) {
                Outcome::Pass => whole = Some(v6),
                Outcome::Complete(packet) => whole = Some(packet),
                Outcome::Held => {}
                Outcome::Dropped => panic!("case {case}: an invalid IPv6 fragment"),
            }
        }
        let whole = whole.unwrap_or_else(|| panic!("case {case}: nothing arrived"));
        if accepted == 1 {
            reassembled += 1;
        } else {
            one_by_one += 1;
            assert_eq!(accepted, pieces.len(), "case {case}");
            assert!(!zero, "case {case}: no checksum, yet not reassembled");
        }
        assert_eq!(check_v6(&whole), 40, "case {case}");
        assert_eq!((whole[6], whole[7]), (protocol::UDP, 63), "case {case}");
        assert_eq!(
            (src6(&whole), dst6(&whole)),
            (self_eam6(), peer_mapping().eam6)
        );
        assert_eq!(whole[40..46], udp[..6], "case {case}");
        assert_eq!(&whole[48..], data.as_slice(), "case {case}");
    }
    assert!(
        reassembled > 700,
        "only {reassembled} datagrams reassembled"
    );
    assert!(
        one_by_one > 100,
        "only {one_by_one} datagrams sent in fragments"
    );
}
