//! Randomized properties of the code that parses bytes a remote party controls: the IP
//! header views, the echo responder, the reassembly table, the checksum helpers and the
//! virtio-net segmentation.
//!
//! The inputs come from a seeded generator, so every run tests the same cases. Most of
//! them are valid packets with a few fields flipped, truncated or extended: uniform random
//! bytes rarely get past the first length check.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use nsplane_packet::checksum::{
    fold, internet_checksum, ipv4_header_checksum, sum_words, transport_checksum_v4,
    transport_checksum_v6,
};
use nsplane_packet::icmp::{echo_reply_in_place, is_echo_request};
use nsplane_packet::reassembly::{Outcome, Reassembler, ReassemblyConfig, ReassemblyStats};
use nsplane_packet::vnet::{VirtioNetHdr, segment};
use nsplane_packet::{
    IcmpHeader, IpPacket, Malformed, PacketBatch, PacketPool, TcpHeader, UdpHeader, protocol,
    udp_packet,
};

/// IPv6 next-header value of the Fragment header.
const FRAGMENT: u8 = 44;

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

    fn v4(&mut self) -> Ipv4Addr {
        Ipv4Addr::from(<[u8; 4]>::try_from(self.bytes(4)).unwrap())
    }

    fn v6(&mut self) -> Ipv6Addr {
        Ipv6Addr::from(<[u8; 16]>::try_from(self.bytes(16)).unwrap())
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}

fn be16(value: usize) -> [u8; 2] {
    u16::try_from(value).unwrap().to_be_bytes()
}

const fn read16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// A structurally valid transport segment for `protocol`; checksum fields are random.
fn transport(rng: &mut Rng, protocol: u8) -> Vec<u8> {
    let data_len = rng.below(48);
    match protocol {
        protocol::TCP => {
            let options = rng.below(4) * 4;
            let mut segment = rng.bytes(20);
            segment[12] = u8::try_from((20 + options) / 4).unwrap() << 4;
            segment.extend(rng.bytes(options + data_len));
            segment
        }
        protocol::UDP => {
            let mut segment = rng.bytes(8 + data_len);
            segment[4..6].copy_from_slice(&be16(8 + data_len));
            segment
        }
        protocol::ICMP | protocol::ICMPV6 => {
            let mut segment = rng.bytes(8 + data_len);
            segment[0] = if protocol == protocol::ICMP {
                rng.pick(&[0, 3, 8, 8, 8, 11])
            } else {
                rng.pick(&[1, 3, 128, 128, 128, 129])
            };
            segment[1] = if rng.chance(90) { 0 } else { rng.byte() };
            segment
        }
        _ => rng.bytes(data_len),
    }
}

/// An IPv4 packet with a valid header checksum.
fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
    let header_len = 20 + options.len();
    let mut packet = vec![0x40 | u8::try_from(header_len / 4).unwrap(), 0];
    packet.extend_from_slice(&be16(header_len + payload.len()));
    packet.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(options);
    let checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&be16(payload.len()));
    packet.extend_from_slice(&[next_header, 64]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(payload);
    packet
}

/// What [`valid`] built.
struct Built {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    payload: Vec<u8>,
    packet: Vec<u8>,
}

/// A valid IPv4 or IPv6 packet carrying TCP, UDP, ICMP or another protocol.
fn valid(rng: &mut Rng) -> Built {
    let protocol = rng.pick(&[
        protocol::TCP,
        protocol::UDP,
        protocol::ICMP,
        protocol::ICMPV6,
        47,
    ]);
    let payload = transport(rng, protocol);
    if rng.chance(50) {
        let (src, dst) = (rng.v4(), rng.v4());
        let options_len = if rng.chance(70) { 0 } else { rng.below(11) * 4 };
        let options = rng.bytes(options_len);
        let packet = ipv4(src, dst, protocol, &options, &payload);
        Built {
            src: src.into(),
            dst: dst.into(),
            protocol,
            payload,
            packet,
        }
    } else {
        let (src, dst) = (rng.v6(), rng.v6());
        let packet = ipv6(src, dst, protocol, &payload);
        Built {
            src: src.into(),
            dst: dst.into(),
            protocol,
            payload,
            packet,
        }
    }
}

/// Changes a few fields of `packet`: bit flips, boundary values in bytes and 16-bit
/// fields, truncation and trailing bytes. Half of the changes land in the headers.
fn mutate(rng: &mut Rng, packet: &mut Vec<u8>) {
    for _ in 0..=rng.below(3) {
        if packet.is_empty() {
            packet.push(rng.byte());
        }
        let len = packet.len();
        let at = if rng.chance(50) {
            rng.below(len.min(48))
        } else {
            rng.below(len)
        };
        match rng.below(6) {
            0 => packet[at] ^= 1 << rng.below(8),
            1 => packet[at] = rng.pick(&[0, 1, 0x0f, 0x7f, 0x80, 0xf0, 0xff]),
            2 if at + 1 < len => {
                let value = rng.pick(&[0, 1, 7, 8, 20, 40, 0x7fff, 0xffff, len, len + 1, len - 1]);
                packet[at..at + 2].copy_from_slice(&value.to_le_bytes()[..2]);
                packet[at..at + 2].reverse();
            }
            3 => packet.truncate(rng.below(len + 1)),
            4 => {
                let extra = 1 + rng.below(40);
                packet.extend(rng.bytes(extra));
            }
            _ => packet[at] = rng.byte(),
        }
    }
}

/// Valid, mutated-valid and random packets.
fn untrusted(rng: &mut Rng) -> Vec<u8> {
    match rng.below(10) {
        0 => {
            let len = rng.below(80);
            let mut bytes = rng.bytes(len);
            if let Some(first) = bytes.first_mut()
                && rng.chance(80)
            {
                *first = rng.pick(&[0x45, 0x46, 0x4f, 0x60]);
            }
            bytes
        }
        1 | 2 => valid(rng).packet,
        _ => {
            let mut packet = valid(rng).packet;
            mutate(rng, &mut packet);
            packet
        }
    }
}

/// The payload range [`IpPacket::parse`] must find in `bytes`, written from RFC 791 and
/// RFC 8200 independently of the implementation.
fn expected_payload(bytes: &[u8]) -> Result<std::ops::Range<usize>, Malformed> {
    let Some(&first) = bytes.first() else {
        return Err(Malformed::Truncated);
    };
    match first >> 4 {
        4 => {
            if bytes.len() < 20 {
                return Err(Malformed::Truncated);
            }
            let header_len = usize::from(first & 0x0f) * 4;
            let total_len = usize::from(read16(bytes, 2));
            if header_len < 20 {
                Err(Malformed::BadHeaderLength)
            } else if header_len > bytes.len() {
                Err(Malformed::Truncated)
            } else if total_len < header_len {
                Err(Malformed::BadTotalLength)
            } else if total_len > bytes.len() {
                Err(Malformed::Truncated)
            } else {
                Ok(header_len..total_len)
            }
        }
        6 => {
            if bytes.len() < 40 {
                return Err(Malformed::Truncated);
            }
            let end = 40 + usize::from(read16(bytes, 4));
            if end > bytes.len() {
                Err(Malformed::Truncated)
            } else {
                Ok(40..end)
            }
        }
        _ => Err(Malformed::BadVersion),
    }
}

/// The ports [`IpPacket::five_tuple`] must report for a transport `payload`.
fn expected_ports(protocol: u8, payload: &[u8]) -> Option<(u16, u16)> {
    match protocol {
        protocol::TCP => {
            let header_len = usize::from(payload.get(12)? >> 4) * 4;
            (payload.len() >= 20 && header_len >= 20 && header_len <= payload.len())
                .then(|| (read16(payload, 0), read16(payload, 2)))
        }
        protocol::UDP => (payload.len() >= 8).then(|| (read16(payload, 0), read16(payload, 2))),
        protocol::ICMP | protocol::ICMPV6 => {
            let echo: &[u8] = if protocol == protocol::ICMP {
                &[0, 8]
            } else {
                &[128, 129]
            };
            (payload.len() >= 8).then(|| {
                let id = if echo.contains(&payload[0]) {
                    read16(payload, 4)
                } else {
                    0
                };
                (id, id)
            })
        }
        _ => Some((0, 0)),
    }
}

#[test]
fn parse_agrees_with_the_header_layout_on_untrusted_bytes() {
    let mut rng = Rng(0x1001);
    let mut parsed = 0;
    for case in 0..30_000 {
        let bytes = untrusted(&mut rng);
        let expected = expected_payload(&bytes);
        let packet = match IpPacket::parse(&bytes) {
            Ok(packet) => packet,
            Err(error) => {
                assert_eq!(Err(error), expected, "case {case}: {bytes:02x?}");
                continue;
            }
        };
        parsed += 1;
        let range = expected
            .clone()
            .unwrap_or_else(|error| panic!("case {case}: parsed, expected {error}: {bytes:02x?}"));
        assert_eq!(packet.payload(), &bytes[range], "case {case}: {bytes:02x?}");
        let (src, dst, protocol, offset): (IpAddr, IpAddr, u8, u16) = if bytes[0] >> 4 == 4 {
            (
                <[u8; 4]>::try_from(&bytes[12..16]).unwrap().into(),
                <[u8; 4]>::try_from(&bytes[16..20]).unwrap().into(),
                bytes[9],
                read16(&bytes, 6) & 0x1fff,
            )
        } else {
            (
                <[u8; 16]>::try_from(&bytes[8..24]).unwrap().into(),
                <[u8; 16]>::try_from(&bytes[24..40]).unwrap().into(),
                bytes[6],
                0,
            )
        };
        assert_eq!(
            (packet.src(), packet.dst(), packet.protocol()),
            (src, dst, protocol),
            "case {case}: {bytes:02x?}"
        );
        let more = bytes[0] >> 4 == 4 && bytes[6] & 0x20 != 0;
        let fragment = packet.fragment();
        assert_eq!(
            fragment.map(|f| (f.id, f.offset, f.more)),
            (more || offset != 0).then(|| (read16(&bytes, 4), offset * 8, more)),
            "case {case}: {bytes:02x?}"
        );
        let ports = if offset == 0 {
            expected_ports(protocol, packet.payload())
        } else {
            None
        };
        let tuple = packet.five_tuple();
        assert_eq!(
            tuple.map(|t| (t.src, t.dst, t.protocol, t.src_port, t.dst_port)),
            ports.map(|(src_port, dst_port)| (src, dst, protocol, src_port, dst_port)),
            "case {case}: {bytes:02x?}"
        );
        // The transport views accept exactly what the flow key was read from.
        let transport = match protocol {
            protocol::TCP => TcpHeader::parse(packet.payload()).is_ok(),
            protocol::UDP => UdpHeader::parse(packet.payload()).is_ok(),
            _ => IcmpHeader::parse(packet.payload()).is_ok(),
        };
        if matches!(
            protocol,
            protocol::TCP | protocol::UDP | protocol::ICMP | protocol::ICMPV6
        ) {
            assert_eq!(
                transport,
                expected_ports(protocol, packet.payload()).is_some(),
                "case {case}: {bytes:02x?}"
            );
        }
        let _ = packet.ecn();
    }
    // The generator must not be rejected at the first check most of the time.
    assert!(parsed > 10_000, "only {parsed} cases parsed");
}

#[test]
fn built_packets_parse_back_to_their_fields() {
    let mut rng = Rng(0x1002);
    for case in 0..5_000 {
        let built = valid(&mut rng);
        let packet = IpPacket::parse(&built.packet).unwrap();
        assert_eq!(
            (packet.src(), packet.dst(), packet.protocol()),
            (built.src, built.dst, built.protocol),
            "case {case}"
        );
        assert_eq!(packet.payload(), built.payload, "case {case}");
        assert_eq!(packet.fragment(), None, "case {case}");
        assert!(packet.five_tuple().is_some(), "case {case}");
        // Trailing bytes behind the declared length are not part of the packet.
        let mut padded = built.packet.clone();
        let extra = 1 + rng.below(8);
        padded.extend(rng.bytes(extra));
        assert_eq!(
            IpPacket::parse(&padded).unwrap().payload(),
            built.payload,
            "case {case}"
        );
    }
}

/// Whether the transport checksum of the UDP, TCP or `ICMPv6` segment in `packet` verifies.
fn transport_checksum_verifies(packet: &IpPacket<'_>) -> bool {
    let sum = match (packet.src(), packet.dst()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            transport_checksum_v4(src, dst, packet.protocol(), packet.payload())
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            transport_checksum_v6(src, dst, packet.protocol(), packet.payload())
        }
        _ => return false,
    };
    sum == 0
}

/// Whether the IPv4 header checksum of `packet` verifies.
fn header_checksum_verifies(packet: &[u8]) -> bool {
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    internet_checksum(&packet[..header_len]) == 0
}

#[test]
fn built_udp_datagrams_round_trip_with_valid_checksums() {
    let mut rng = Rng(0x1003);
    for case in 0..3_000 {
        let (src, dst): (IpAddr, IpAddr) = if rng.chance(50) {
            (rng.v4().into(), rng.v4().into())
        } else {
            (rng.v6().into(), rng.v6().into())
        };
        let (src, dst) = (
            SocketAddr::new(src, rng.u16()),
            SocketAddr::new(dst, rng.u16()),
        );
        let len = if rng.chance(2) {
            60_000 + rng.below(5_000)
        } else {
            rng.below(300)
        };
        let payload = rng.bytes(len);
        let built = udp_packet(src, dst, &payload).unwrap();
        let bytes = built.as_packet();
        let packet = IpPacket::parse(bytes).unwrap();
        assert_eq!(packet.payload().len(), 8 + payload.len(), "case {case}");
        let tuple = packet.five_tuple().unwrap();
        assert_eq!(
            (tuple.src, tuple.src_port, tuple.dst, tuple.dst_port),
            (src.ip(), src.port(), dst.ip(), dst.port()),
            "case {case}"
        );
        let (udp, data) = UdpHeader::parse(packet.payload()).unwrap();
        assert_eq!(usize::from(udp.len()), 8 + payload.len(), "case {case}");
        assert_eq!(data, payload, "case {case}");
        assert_ne!(udp.checksum(), 0, "case {case}");
        assert!(transport_checksum_verifies(&packet), "case {case}");
        if src.is_ipv4() {
            assert!(header_checksum_verifies(bytes), "case {case}");
        }
    }
}

#[test]
fn a_written_checksum_verifies_wherever_the_field_is() {
    let mut rng = Rng(0x1004);
    for case in 0..5_000 {
        let len = 2 + rng.below(200);
        let mut data = rng.bytes(len);
        let field = rng.below(len / 2) * 2;
        data[field..field + 2].fill(0);
        let sum = internet_checksum(&data);
        data[field..field + 2].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(internet_checksum(&data), 0, "case {case}: {data:02x?}");
        // A sum may be chained across any even split.
        let split = rng.below(len / 2 + 1) * 2;
        let (head, tail) = data.split_at(split);
        assert_eq!(
            fold(sum_words(sum_words(0, head), tail)),
            fold(sum_words(0, &data)),
            "case {case}: {data:02x?} at {split}"
        );
        // One changed byte never leaves the checksum valid.
        let at = rng.below(len);
        let old = data[at];
        data[at] = old.wrapping_add(1 + rng.byte() % 254);
        assert_ne!(internet_checksum(&data), 0, "case {case}: {data:02x?}");
    }
}

#[test]
fn echo_replies_only_to_whole_echo_requests_and_stays_valid() {
    let mut rng = Rng(0x1005);
    let mut replies = 0;
    for case in 0..20_000 {
        let request = untrusted(&mut rng);
        let mut reply = request.clone();
        let replied = echo_reply_in_place(&mut reply);
        if !replied {
            assert_eq!(reply, request, "case {case}: {request:02x?}");
            continue;
        }
        replies += 1;
        assert!(is_echo_request(&request), "case {case}: {request:02x?}");
        assert!(!is_echo_request(&reply), "case {case}: {request:02x?}");
        assert_eq!(reply.len(), request.len(), "case {case}: {request:02x?}");
        let (before, after) = (
            IpPacket::parse(&request).unwrap(),
            IpPacket::parse(&reply).unwrap(),
        );
        // Whole packets only: nothing behind the declared length, and no fragment.
        assert_eq!(
            expected_payload(&request).unwrap().end,
            request.len(),
            "case {case}: {request:02x?}"
        );
        assert_eq!(before.fragment(), None, "case {case}: {request:02x?}");
        assert_eq!(
            (after.src(), after.dst(), after.protocol()),
            (before.dst(), before.src(), before.protocol()),
            "case {case}: {request:02x?}"
        );
        let (old, new) = (before.payload(), after.payload());
        assert_eq!(old[1], 0, "case {case}: {request:02x?}");
        assert_eq!(&new[4..], &old[4..], "case {case}: {request:02x?}");
        if request[0] >> 4 == 4 {
            assert_eq!((old[0], new[0]), (8, 0), "case {case}: {request:02x?}");
            assert!(header_checksum_verifies(&reply), "case {case}");
            assert_eq!(internet_checksum(new), 0, "case {case}: {request:02x?}");
        } else {
            assert_eq!((old[0], new[0]), (128, 129), "case {case}: {request:02x?}");
            assert!(transport_checksum_verifies(&after), "case {case}");
        }
    }
    assert!(replies > 500, "only {replies} replies");
}

/// One datagram and the fragments it was cut into.
struct Fragmented {
    /// The packet reassembly must return.
    whole: Vec<u8>,
    fragments: Vec<Vec<u8>>,
}

/// Cut points of `len` bytes into `pieces` fragments, every one but the last a multiple
/// of 8 bytes long and none empty.
fn cuts(rng: &mut Rng, len: usize, pieces: usize) -> Vec<usize> {
    let units = (len - 1) / 8;
    let mut cuts: Vec<usize> = (0..pieces - 1)
        .map(|_| (1 + rng.below(units.max(1))) * 8)
        .filter(|&cut| cut < len)
        .collect();
    cuts.sort_unstable();
    cuts.dedup();
    cuts.insert(0, 0);
    cuts.push(len);
    cuts
}

/// A random IPv4 datagram (options included, DF as drawn) cut into at least two
/// fragments.
fn fragmented_v4(rng: &mut Rng, src: Ipv4Addr, id: u16, len: usize) -> Fragmented {
    let options_len = if rng.chance(60) { 0 } else { rng.below(11) * 4 };
    let options = rng.bytes(options_len);
    let payload = rng.bytes(len);
    let dst = rng.v4();
    let dont_fragment = if rng.chance(20) { 0x40 } else { 0 };
    let header_len = 20 + options.len();
    let stamp = |packet: &mut [u8], flags_offset: u16| {
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        packet[6] |= dont_fragment;
        let checksum = ipv4_header_checksum(&packet[..header_len]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    };
    let mut whole = ipv4(src, dst, protocol::UDP, &options, &payload);
    stamp(&mut whole, 0);
    let pieces = 2 + rng.below(11);
    let cuts = cuts(rng, len, pieces);
    let fragments = cuts
        .windows(2)
        .map(|cut| {
            let mut fragment = ipv4(src, dst, protocol::UDP, &options, &payload[cut[0]..cut[1]]);
            let more = if cut[1] == len { 0 } else { 0x2000 };
            stamp(&mut fragment, more | u16::try_from(cut[0] / 8).unwrap());
            fragment
        })
        .collect();
    Fragmented { whole, fragments }
}

/// A random IPv6 datagram, behind none, one or two extension headers, cut into one
/// fragment (an atomic fragment) or more.
fn fragmented_v6(rng: &mut Rng, src: Ipv6Addr, id: u32, len: usize) -> Fragmented {
    let dst = rng.v6();
    let data = rng.bytes(len);
    // Unfragmentable extension headers: (type, bytes after the two fixed ones).
    let mut extensions: Vec<(u8, Vec<u8>)> = Vec::new();
    if rng.chance(30) {
        let body = 6 + rng.below(2) * 8;
        extensions.push((0, rng.bytes(body)));
    }
    if rng.chance(30) {
        extensions.push((43, rng.bytes(6)));
    }
    // The chain as (next header of the fixed header, extension bytes) for a packet whose
    // last unfragmentable header names `last`.
    let chain = |last: u8| {
        let mut bytes = Vec::new();
        let types: Vec<u8> = extensions.iter().map(|(kind, _)| *kind).collect();
        for (i, (_, body)) in extensions.iter().enumerate() {
            bytes.push(types.get(i + 1).copied().unwrap_or(last));
            bytes.push(u8::try_from((body.len() + 2) / 8 - 1).unwrap());
            bytes.extend_from_slice(body);
        }
        (types.first().copied().unwrap_or(last), bytes)
    };
    let (first, unfragmentable) = chain(protocol::UDP);
    let whole = ipv6(src, dst, first, &[&unfragmentable[..], &data].concat());
    let (first, unfragmentable) = chain(FRAGMENT);
    let pieces = 1 + rng.below(12);
    let cuts = cuts(rng, len, pieces);
    let fragments = cuts
        .windows(2)
        .map(|cut| {
            let more = u16::from(cut[1] != len);
            let mut payload = unfragmentable.clone();
            payload.extend_from_slice(&[protocol::UDP, rng.byte()]);
            payload.extend_from_slice(&(u16::try_from(cut[0]).unwrap() | more).to_be_bytes());
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&data[cut[0]..cut[1]]);
            ipv6(src, dst, first, &payload)
        })
        .collect();
    Fragmented { whole, fragments }
}

/// The fragments of `datagrams` in one delivery order: each datagram's fragments
/// shuffled, some repeated before its last one arrives, the datagrams interleaved.
/// Yields (datagram, fragment, whether it completes the datagram).
fn delivery(rng: &mut Rng, datagrams: &[Fragmented]) -> Vec<(usize, usize, bool)> {
    let mut queues: Vec<Vec<(usize, bool)>> = datagrams
        .iter()
        .map(|datagram| {
            let mut order: Vec<usize> = (0..datagram.fragments.len()).collect();
            rng.shuffle(&mut order);
            let mut queue: Vec<(usize, bool)> = order.iter().map(|&i| (i, false)).collect();
            queue.last_mut().unwrap().1 = true;
            for _ in 0..rng.below(4) {
                if queue.len() < 2 {
                    break;
                }
                // Repeat an earlier fragment anywhere after it and before the last one.
                let from = rng.below(queue.len() - 1);
                let to = from + 1 + rng.below(queue.len() - 1 - from);
                queue.insert(to, (queue[from].0, false));
            }
            queue.reverse();
            queue
        })
        .collect();
    let mut order = Vec::new();
    while queues.iter().any(|queue| !queue.is_empty()) {
        let datagram = rng.below(queues.len());
        if let Some((fragment, last)) = queues[datagram].pop() {
            order.push((datagram, fragment, last));
        }
    }
    order
}

#[test]
fn any_fragmentation_and_delivery_order_reassembles_the_datagram() {
    let mut rng = Rng(0x1006);
    let now = Instant::now();
    let mut fragments = 0_u64;
    for case in 0..1_500 {
        let count = 1 + rng.below(3);
        let datagrams: Vec<Fragmented> = (0..count)
            .map(|index| {
                // Mostly small; some near the largest packet an IP header can describe.
                let large = rng.chance(3);
                let id = u16::try_from(case * 4 + index).unwrap();
                if rng.chance(50) {
                    let len = if large {
                        65_000 + rng.below(475)
                    } else {
                        9 + rng.below(3_000)
                    };
                    fragmented_v4(&mut rng, Ipv4Addr::new(192, 0, 2, 1), id, len)
                } else {
                    let len = if large {
                        65_000 + rng.below(500)
                    } else {
                        1 + rng.below(3_000)
                    };
                    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
                    fragmented_v6(&mut rng, src, u32::from(id) << 8, len)
                }
            })
            .collect();
        let mut reassembler = Reassembler::new(ReassemblyConfig {
            max_bytes: 65_535 + 40,
            ..ReassemblyConfig::default()
        });
        let order = delivery(&mut rng, &datagrams);
        for &(datagram, fragment, last) in &order {
            fragments += 1;
            let outcome = reassembler.push(&datagrams[datagram].fragments[fragment], now);
            if last {
                let Outcome::Complete(packet) = outcome else {
                    panic!("case {case}: {outcome:?} for the last fragment, order {order:?}");
                };
                assert!(
                    packet == datagrams[datagram].whole,
                    "case {case}: datagram {datagram} differs, order {order:?}"
                );
            } else {
                assert_eq!(outcome, Outcome::Held, "case {case}: order {order:?}");
            }
        }
        assert_eq!(reassembler.pending(), 0, "case {case}");
        let mut expected = ReassemblyStats::default();
        expected.reassembled = count as u64;
        assert_eq!(reassembler.stats(), expected, "case {case}");
    }
    assert!(fragments > 15_000, "only {fragments} fragments");
}

/// Outcome counts of one run, to compare with [`ReassemblyStats`].
#[derive(Default)]
struct Tally {
    complete: u64,
    dropped: u64,
}

/// Feeds `packet` and checks what must hold after any push.
fn push_checked(
    reassembler: &mut Reassembler,
    tally: &mut Tally,
    packet: &[u8],
    now: Instant,
) -> Outcome {
    let (before, pending) = (reassembler.stats(), reassembler.pending());
    let outcome = reassembler.push(packet, now);
    let stats = reassembler.stats();
    match &outcome {
        Outcome::Pass => {
            // Nothing is learned from a packet that is not a fragment.
            assert_eq!(stats, before, "{packet:02x?}");
            assert_eq!(reassembler.pending(), pending, "{packet:02x?}");
        }
        Outcome::Held => {}
        Outcome::Dropped => tally.dropped += 1,
        Outcome::Complete(whole) => {
            tally.complete += 1;
            assert!(
                whole.len() <= reassembler.config().max_bytes,
                "{packet:02x?}"
            );
            // The result is a whole packet with exact length fields.
            assert_eq!(
                expected_payload(whole).map(|range| range.end),
                Ok(whole.len()),
                "{packet:02x?} gave {whole:02x?}"
            );
            let parsed = IpPacket::parse(whole).unwrap();
            assert_eq!(parsed.fragment(), None, "{packet:02x?}");
            if whole[0] >> 4 == 4 {
                assert!(header_checksum_verifies(whole), "{packet:02x?}");
            }
        }
    }
    if let Ok(parsed) = IpPacket::parse(packet)
        && packet[0] >> 4 == 4
    {
        // IPv4 fragments are recognised by MF and the offset alone.
        assert_eq!(
            outcome == Outcome::Pass,
            parsed.fragment().is_none(),
            "{packet:02x?}"
        );
    }
    assert!(
        reassembler.pending() <= reassembler.config().max_datagrams,
        "{packet:02x?}"
    );
    assert_eq!(stats.reassembled, tally.complete, "{packet:02x?}");
    // Every drop is counted once, and so is every eviction.
    assert_eq!(
        stats.malformed + stats.overflow + stats.overlap,
        tally.dropped + stats.evicted,
        "{packet:02x?}"
    );
    assert!(stats.timeout >= before.timeout && stats.evicted >= before.evicted);
    outcome
}

/// The byte every fragment of `stream` carries at `offset` of its datagram; never zero,
/// which is what a hole would read as.
fn stream_byte(stream: usize, offset: usize) -> u8 {
    u8::try_from((stream * 31 + offset * 7 + offset / 251) % 255 + 1).unwrap()
}

/// A fragment of `stream` with an arbitrary offset, length and MF flag. The streams
/// share a few sources and identifications; the payload bytes depend only on the stream
/// and their place in the datagram.
fn stream_fragment(rng: &mut Rng, stream: usize) -> Vec<u8> {
    let units = match rng.below(20) {
        0 => 8_191,
        1 => 8_000 + rng.below(191),
        2..=5 => rng.below(12),
        _ => rng.below(4),
    };
    let start = units * 8;
    let len = match rng.below(20) {
        0..=2 => rng.below(40),
        3..=7 => rng.below(5) * 8,
        _ => 8,
    };
    let more = rng.chance(75);
    let data: Vec<u8> = (start..start + len)
        .map(|offset| stream_byte(stream, offset))
        .collect();
    let last = u8::try_from(stream).unwrap();
    if stream.is_multiple_of(2) {
        let (src, dst) = (Ipv4Addr::new(192, 0, 2, last), Ipv4Addr::new(192, 0, 2, 99));
        let mut packet = ipv4(src, dst, protocol::UDP, &[], &data);
        packet[4..6].copy_from_slice(&[0x10, last]);
        let flags = u16::try_from(units).unwrap() | if more { 0x2000 } else { 0 };
        packet[6..8].copy_from_slice(&flags.to_be_bytes());
        let checksum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    } else {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(last));
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99);
        let mut payload = vec![protocol::UDP, 0];
        payload.extend_from_slice(&(u16::try_from(start).unwrap() | u16::from(more)).to_be_bytes());
        payload.extend_from_slice(&[0, 0, 0x10, last]);
        payload.extend_from_slice(&data);
        ipv6(src, dst, FRAGMENT, &payload)
    }
}

#[test]
fn arbitrary_fragment_sequences_never_yield_holes_or_misplaced_bytes() {
    let mut rng = Rng(0x1007);
    let mut completed = 0;
    for case in 0..300 {
        let config = ReassemblyConfig {
            max_datagrams: rng.below(5),
            timeout: Duration::from_secs(10),
            max_bytes: rng.pick(&[64, 120, 600, 65_535, 70_000]),
        };
        let streams = 1 + rng.below(6);
        let mut reassembler = Reassembler::new(config);
        let mut tally = Tally::default();
        let mut now = Instant::now();
        for _ in 0..200 {
            let stream = rng.below(streams);
            let packet = stream_fragment(&mut rng, stream);
            now += Duration::from_millis(u64::try_from(rng.below(400)).unwrap());
            let Outcome::Complete(whole) = push_checked(&mut reassembler, &mut tally, &packet, now)
            else {
                continue;
            };
            let parsed = IpPacket::parse(&whole).unwrap();
            assert_eq!(parsed.protocol(), protocol::UDP, "case {case}");
            let source = match parsed.src() {
                IpAddr::V4(src) => src.octets()[3],
                IpAddr::V6(src) => src.octets()[15],
            };
            assert_eq!(usize::from(source), stream, "case {case}");
            // Count the datagrams that took more than one fragment.
            completed += usize::from(parsed.payload().len() > 8);
            for (offset, &byte) in parsed.payload().iter().enumerate() {
                assert_eq!(
                    byte,
                    stream_byte(stream, offset),
                    "case {case}: offset {offset} of {whole:02x?}"
                );
            }
        }
        // Expiry alone empties the table, and counts what it discards.
        let (pending, before) = (reassembler.pending(), reassembler.stats().timeout);
        assert_eq!(reassembler.expire(now + Duration::from_secs(10)), pending);
        assert_eq!(reassembler.pending(), 0, "case {case}");
        assert_eq!(reassembler.stats().timeout - before, pending as u64);
    }
    assert!(completed > 300, "only {completed} datagrams completed");
}

#[test]
fn untrusted_packets_keep_the_reassembly_counters_consistent() {
    let mut rng = Rng(0x1008);
    let mut fragments = 0;
    for _ in 0..200 {
        let mut reassembler = Reassembler::new(ReassemblyConfig {
            max_datagrams: rng.below(4),
            timeout: Duration::from_secs(10),
            max_bytes: rng.pick(&[100, 2_000, 65_535]),
        });
        let mut tally = Tally::default();
        let mut now = Instant::now();
        for _ in 0..100 {
            let mut packet = if rng.chance(30) {
                untrusted(&mut rng)
            } else {
                let stream = rng.below(4);
                stream_fragment(&mut rng, stream)
            };
            if rng.chance(50) {
                mutate(&mut rng, &mut packet);
            }
            now += Duration::from_millis(u64::try_from(rng.below(300)).unwrap());
            if push_checked(&mut reassembler, &mut tally, &packet, now) != Outcome::Pass {
                fragments += 1;
            }
        }
    }
    assert!(fragments > 5_000, "only {fragments} fragments");
}

/// The IP and transport header lengths of a TCP or UDP `packet`.
fn header_lens(packet: &[u8]) -> (usize, usize) {
    let (ip_len, protocol) = if packet[0] >> 4 == 4 {
        (usize::from(packet[0] & 0x0f) * 4, packet[9])
    } else {
        (40, packet[6])
    };
    let transport_len = if protocol == protocol::TCP {
        usize::from(packet[ip_len + 12] >> 4) * 4
    } else {
        8
    };
    (ip_len, transport_len)
}

/// Runs [`segment`] to the end over as many batches as it asks for; the segments, or
/// `None` for an error (which must leave every batch empty).
fn segment_all(hdr: &VirtioNetHdr, packet: &[u8], pool: &mut PacketPool) -> Option<Vec<Vec<u8>>> {
    let mut segments = Vec::new();
    let mut first = 0;
    loop {
        let mut out = PacketBatch::new();
        let result = segment(hdr, packet, first, 0, pool, &mut out);
        let produced = out.len();
        segments.extend(out.drain().map(|buf| buf.as_packet().to_vec()));
        match result {
            Ok(None) => return Some(segments),
            Ok(Some(next)) => {
                assert_eq!(next, first + produced, "{hdr:?} {packet:02x?}");
                assert!(produced > 0, "{hdr:?} {packet:02x?}");
                first = next;
            }
            Err(_) => {
                assert_eq!(produced, 0, "{hdr:?} {packet:02x?}");
                assert!(segments.is_empty(), "{hdr:?} {packet:02x?}");
                return None;
            }
        }
    }
}

#[test]
fn segmentation_of_untrusted_super_packets_conserves_the_payload() {
    let mut rng = Rng(0x1009);
    let mut pool = PacketPool::new(8);
    let mut segmented = 0;
    for case in 0..6_000 {
        let mut built = valid(&mut rng);
        if rng.chance(60) {
            // Segmentable: TCP or UDP with more payload than one segment takes.
            let protocol = rng.pick(&[protocol::TCP, protocol::UDP]);
            let mut payload = transport(&mut rng, protocol);
            let extra = rng.below(600);
            payload.extend(rng.bytes(extra));
            built.packet = if rng.chance(50) {
                ipv4(rng.v4(), rng.v4(), protocol, &[], &payload)
            } else {
                ipv6(rng.v6(), rng.v6(), protocol, &payload)
            };
        }
        let mut packet = built.packet;
        if rng.chance(30) {
            mutate(&mut rng, &mut packet);
        }
        let small = (rng.u16() % 128, rng.u16() % 64);
        let hdr = VirtioNetHdr {
            flags: rng.pick(&[0, 0, 1, 0xff]),
            gso_type: rng.pick(&[0, 0, 1, 1, 4, 4, 5, 5, 3, 0x80, 0x81, 0x84, 0x85]),
            hdr_len: rng.pick(&[0, 40, 60, 0xffff]),
            gso_size: if rng.chance(90) {
                u16::try_from(rng.below(200)).unwrap()
            } else {
                rng.u16()
            },
            csum_start: rng.pick(&[0, 20, 40, 0xffff, small.0]),
            csum_offset: rng.pick(&[6, 16, 0, 0xffff, small.1]),
        };
        assert_eq!(VirtioNetHdr::parse(&hdr.encode()), Ok(hdr), "case {case}");
        let Some(segments) = segment_all(&hdr, &packet, &mut pool) else {
            continue;
        };
        if hdr.gso_type & !VirtioNetHdr::GSO_ECN == VirtioNetHdr::GSO_NONE {
            // The packet itself, changed at most in the checksum field.
            assert_eq!(segments.len(), 1, "case {case}");
            assert_eq!(segments[0].len(), packet.len(), "case {case}");
            let differing = segments[0]
                .iter()
                .zip(&packet)
                .filter(|(a, b)| a != b)
                .count();
            assert!(differing <= 2, "case {case}: {hdr:?} {packet:02x?}");
            continue;
        }
        segmented += 1;
        let (ip_len, transport_len) = header_lens(&packet);
        let payload = &packet[ip_len + transport_len..];
        let gso_size = usize::from(hdr.gso_size);
        assert_eq!(
            segments.len(),
            payload.len().div_ceil(gso_size).max(1),
            "case {case}: {hdr:?} {packet:02x?}"
        );
        let mut carried = Vec::new();
        for (index, bytes) in segments.iter().enumerate() {
            let context = format!("case {case} segment {index}: {hdr:?} {packet:02x?}");
            assert_eq!(
                expected_payload(bytes).map(|range| range.end),
                Ok(bytes.len()),
                "{context}"
            );
            assert_eq!(header_lens(bytes), (ip_len, transport_len), "{context}");
            let parsed = IpPacket::parse(bytes).unwrap();
            if bytes[0] >> 4 == 4 {
                assert!(header_checksum_verifies(bytes), "{context}");
            }
            let l4 = parsed.payload();
            assert!(l4.len() - transport_len <= gso_size, "{context}");
            if parsed.protocol() == protocol::UDP {
                assert_eq!(usize::from(read16(l4, 4)), l4.len(), "{context}");
                assert_ne!(read16(l4, 6), 0, "{context}");
            } else {
                let sent = u32::try_from(carried.len()).unwrap();
                let sequence = |bytes: &[u8]| {
                    u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[ip_len + 4..ip_len + 8]).unwrap())
                };
                assert_eq!(
                    sequence(bytes),
                    sequence(&packet).wrapping_add(sent),
                    "{context}"
                );
            }
            assert!(transport_checksum_verifies(&parsed), "{context}");
            carried.extend_from_slice(&l4[transport_len..]);
        }
        assert_eq!(carried, payload, "case {case}: {hdr:?} {packet:02x?}");
    }
    assert!(segmented > 400, "only {segmented} super-packets segmented");
}
