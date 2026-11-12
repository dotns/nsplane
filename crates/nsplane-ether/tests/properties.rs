//! Property tests of the parsers that take the guest's frames: the ethernet header, ARP,
//! neighbor discovery, DHCP, and the adapter that dispatches between them.
//!
//! The cases come from a seeded generator, so every run tests the same inputs. Packets are
//! built and decoded a second time by the code of this file, written from the wire formats,
//! and the parsers must agree with it on valid, changed and arbitrary input alike.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use nsplane_ether::arp::{self, PACKET_LEN};
use nsplane_ether::frame::{self, HEADER_LEN};
use nsplane_ether::ndp::{self, ALL_NODES};
use nsplane_ether::{
    ArpOp, ArpPacket, DhcpConfig, DhcpMessage, DhcpServer, EtherAdapter, EtherConfig, EtherType,
    Frame, FrameError, MacAddr, MessageType, Ndp, NdpMessage, RaConfig,
};
use nsplane_packet::checksum::{internet_checksum, transport_checksum_v4};
use nsplane_packet::udp_packet;

const GW_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
const GUEST_MAC: MacAddr = MacAddr([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
const OTHER_MAC: MacAddr = MacAddr([0x52, 0x54, 0, 0xab, 0xcd, 0xef]);
const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const PREFIX: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 0);
const GW_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1);
const GUEST_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 0x15);
const ICMPV6: u8 = 58;

/// `SplitMix64`.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

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
        let b = self.next().to_le_bytes();
        u16::from_le_bytes([b[0], b[1]])
    }

    const fn u32(&mut self) -> u32 {
        let b = self.next().to_le_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.byte())
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// Changes a few bytes of `bytes`, or its length.
fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>) {
    for _ in 0..=rng.below(2) {
        match rng.below(5) {
            0 | 1 if !bytes.is_empty() => {
                let at = rng.below(bytes.len());
                bytes[at] ^= 1 << rng.below(8);
            }
            2 if !bytes.is_empty() => {
                let at = rng.below(bytes.len());
                bytes[at] = rng.pick(&[0, 1, 2, 6, 8, 255]);
            }
            3 => bytes.truncate(rng.below(bytes.len() + 1)),
            _ => {
                let len = 1 + rng.below(8);
                let tail = rng.bytes(len);
                bytes.extend_from_slice(&tail);
            }
        }
    }
}

fn mac(rng: &mut Rng) -> MacAddr {
    match rng.below(10) {
        0 => MacAddr::BROADCAST,
        1 => MacAddr([0x33, 0x33, 0, 0, 0, rng.byte()]),
        2 => MacAddr([0; 6]),
        _ => MacAddr(rng.array()),
    }
}

fn ipv4(rng: &mut Rng) -> Ipv4Addr {
    match rng.below(10) {
        0 => Ipv4Addr::UNSPECIFIED,
        1 => Ipv4Addr::BROADCAST,
        2 => GW_IP,
        3 => GUEST_IP,
        4 => Ipv4Addr::new(224, 0, 0, rng.byte()),
        5 => Ipv4Addr::new(169, 254, 1, rng.byte()),
        _ => Ipv4Addr::new(10, 0, rng.pick(&[2, 3]), rng.pick(&[1, 2, 15, 20, 21, 22])),
    }
}

fn eth(dst: MacAddr, src: MacAddr, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&dst.0);
    out.extend_from_slice(&src.0);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn mac_at(bytes: &[u8], at: usize) -> MacAddr {
    MacAddr(bytes[at..at + 6].try_into().unwrap())
}

fn ipv4_at(bytes: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[at..at + 4]).unwrap())
}

fn ipv6_at(bytes: &[u8], at: usize) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[at..at + 16]).unwrap())
}

const fn read16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

#[test]
fn the_frame_parser_agrees_with_the_header_layout() {
    let mut rng = Rng(0x5eed_e701);
    let mut seen = [0_u32; 4];
    for _ in 0..30_000 {
        let ethertype = match rng.below(4) {
            0 => rng.pick(&[0x0800, 0x0806, 0x86dd]),
            1 => rng.pick(&[0x8100, 0x88a8, 0x9100]),
            2 => rng.pick(&[0, 0x002e, 0x05dc, 0x05ff, 0x0600]),
            _ => rng.u16(),
        };
        let len = rng.below(40);
        let mut bytes = eth(mac(&mut rng), mac(&mut rng), ethertype, &rng.bytes(len));
        if rng.chance(15) {
            bytes.truncate(rng.below(HEADER_LEN + 2));
        }
        let parsed = Frame::parse(&bytes);
        if bytes.len() < HEADER_LEN {
            assert_eq!(parsed, Err(FrameError::Truncated));
            seen[0] += 1;
            continue;
        }
        match read16(&bytes, 12) {
            0x8100 | 0x88a8 | 0x9100 => {
                assert_eq!(parsed, Err(FrameError::VlanTagged));
                seen[1] += 1;
            }
            0..0x0600 => {
                assert_eq!(parsed, Err(FrameError::NotEthernetII));
                seen[2] += 1;
            }
            ethertype => {
                let frame = parsed.unwrap();
                assert_eq!(frame.dst, mac_at(&bytes, 0));
                assert_eq!(frame.src, mac_at(&bytes, 6));
                assert_eq!(frame.ethertype, EtherType(ethertype));
                assert_eq!(frame.payload, &bytes[HEADER_LEN..]);
                let mut header = [0; HEADER_LEN];
                frame::write_header(&mut header, frame.dst, frame.src, frame.ethertype).unwrap();
                assert_eq!(header, bytes[..HEADER_LEN]);
                seen[3] += 1;
            }
        }
    }
    assert!(seen.iter().all(|&count| count > 2_000), "{seen:?}");
}

fn arp_packet(rng: &mut Rng) -> ArpPacket {
    let sender_ip = ipv4(rng);
    ArpPacket {
        op: rng.pick(&[ArpOp::Request, ArpOp::Request, ArpOp::Reply]),
        sender_mac: mac(rng),
        sender_ip,
        target_mac: mac(rng),
        target_ip: if rng.chance(15) { sender_ip } else { ipv4(rng) },
    }
}

#[test]
fn arp_packets_round_trip_and_a_reply_answers_its_request() {
    let mut rng = Rng(0x5eed_e702);
    let (mut answered, mut refused) = (0, 0);
    for _ in 0..30_000 {
        let packet = arp_packet(&mut rng);
        let mut bytes = Vec::new();
        packet.write(&mut bytes);
        assert_eq!(bytes.len(), PACKET_LEN);
        // Frame padding behind the packet is not part of it.
        let padding = rng.below(20);
        bytes.extend_from_slice(&rng.bytes(padding));
        assert_eq!(ArpPacket::parse(&bytes), Ok(packet));

        let reply = arp::reply(&packet, GW_MAC, GW_IP);
        let asks_us = packet.op == ArpOp::Request
            && packet.target_ip == GW_IP
            && packet.sender_ip != GW_IP
            && packet.sender_mac.0[0] & 1 == 0;
        assert_eq!(reply.is_some(), asks_us, "{packet:?}");
        if let Some(reply) = reply {
            let frame = Frame::parse(&reply).unwrap();
            assert_eq!(
                (frame.dst, frame.src, frame.ethertype),
                (packet.sender_mac, GW_MAC, EtherType::ARP)
            );
            let expected = ArpPacket {
                op: ArpOp::Reply,
                sender_mac: GW_MAC,
                sender_ip: GW_IP,
                target_mac: packet.sender_mac,
                target_ip: packet.sender_ip,
            };
            assert_eq!(ArpPacket::parse(frame.payload), Ok(expected));
            answered += 1;
        }

        // Changed bytes: accepted exactly when the fixed fields still say ethernet and
        // IPv4, request or reply, and then read back as written.
        mutate(&mut rng, &mut bytes);
        let supported = bytes.len() >= PACKET_LEN
            && bytes[..6] == [0, 1, 8, 0, 6, 4]
            && matches!(read16(&bytes, 6), 1 | 2);
        if let Ok(parsed) = ArpPacket::parse(&bytes) {
            assert!(supported, "{bytes:02x?}");
            let mut written = Vec::new();
            parsed.write(&mut written);
            assert_eq!(written, bytes[..PACKET_LEN]);
        } else {
            assert!(!supported, "{bytes:02x?}");
            refused += 1;
        }
    }
    assert!(answered > 500 && refused > 3_000, "{answered} {refused}");
}

/// The Internet checksum of an `ICMPv6` message between `src` and `dst`.
fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut data = Vec::with_capacity(40 + icmp.len() + 1);
    data.extend_from_slice(&src.octets());
    data.extend_from_slice(&dst.octets());
    data.extend_from_slice(&u32::try_from(icmp.len()).unwrap().to_be_bytes());
    data.extend_from_slice(&[0, 0, 0, ICMPV6]);
    data.extend_from_slice(icmp);
    if data.len() % 2 == 1 {
        data.push(0);
    }
    let mut sum: u32 = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes(*pair)))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap()
}

/// An IPv6 packet with `payload` behind the fixed header.
fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, next: u8, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60, 0, 0, 0];
    out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&[next, hop_limit]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(payload);
    out
}

/// Writes the checksum of the `ICMPv6` message of `packet`, when it has room for one.
fn repair_icmpv6(packet: &mut [u8]) {
    if packet.len() < 44 {
        return;
    }
    let end = (40 + usize::from(read16(packet, 4))).min(packet.len());
    if end < 44 {
        return;
    }
    packet[42..44].fill(0);
    let sum = icmpv6_checksum(ipv6_at(packet, 8), ipv6_at(packet, 24), &packet[40..end]);
    packet[42..44].copy_from_slice(&sum.to_be_bytes());
}

fn solicited_node(target: Ipv6Addr) -> Ipv6Addr {
    let o = target.octets();
    Ipv6Addr::from([
        0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, o[13], o[14], o[15],
    ])
}

fn ipv6(rng: &mut Rng) -> Ipv6Addr {
    match rng.below(8) {
        0 => GW_IPV6,
        1 => GW_MAC.link_local(),
        2 => GUEST_IPV6,
        3 => Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, rng.u16()),
        4 => Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.u16()),
        _ => Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, rng.pick(&[0x15, 0x16, 0x20])),
    }
}

/// Neighbor discovery options: a link-layer address option of type `kind` when `link` is
/// set, among options of other types.
fn nd_options(rng: &mut Rng, kind: u8, link: Option<MacAddr>) -> Vec<u8> {
    let mut options: Vec<Vec<u8>> = (0..rng.below(3))
        .map(|_| {
            let units = 1 + rng.below(3);
            let mut option = vec![rng.pick(&[3, 5, 14, 25, 200]), u8::try_from(units).unwrap()];
            option.extend_from_slice(&rng.bytes(units * 8 - 2));
            option
        })
        .collect();
    if let Some(link) = link {
        let mut option = vec![kind, 1];
        option.extend_from_slice(&link.0);
        let at = rng.below(options.len() + 1);
        options.insert(at, option);
    }
    options.concat()
}

/// A neighbor discovery packet the parser must accept, and what it must read from it.
fn nd_packet(rng: &mut Rng) -> (Vec<u8>, Ndp) {
    let unspecified = rng.chance(20);
    let src = if unspecified {
        Ipv6Addr::UNSPECIFIED
    } else {
        ipv6(rng)
    };
    let link = (!unspecified && rng.chance(60)).then(|| mac(rng));
    let target = ipv6(rng);
    let (dst, icmp, message) = match rng.below(3) {
        0 => {
            let mut icmp = vec![133, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&nd_options(rng, 1, link));
            let message = NdpMessage::RouterSolicitation { source_mac: link };
            (Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2), icmp, message)
        }
        1 => {
            let mut icmp = vec![135, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&target.octets());
            icmp.extend_from_slice(&nd_options(rng, 1, link));
            let dst = if unspecified || rng.chance(50) {
                solicited_node(target)
            } else {
                target
            };
            let message = NdpMessage::NeighborSolicitation {
                target,
                source_mac: link,
            };
            (dst, icmp, message)
        }
        _ => {
            let flags = rng.byte();
            let link = rng.chance(60).then(|| mac(rng));
            let mut icmp = vec![136, 0, 0, 0, flags, 0, 0, 0];
            icmp.extend_from_slice(&target.octets());
            icmp.extend_from_slice(&nd_options(rng, 2, link));
            let dst = if flags & 0x40 != 0 || rng.chance(50) {
                ipv6(rng)
            } else {
                ALL_NODES
            };
            let message = NdpMessage::NeighborAdvertisement {
                target,
                target_mac: link,
                router: flags & 0x80 != 0,
                solicited: flags & 0x40 != 0,
                override_entry: flags & 0x20 != 0,
            };
            (dst, icmp, message)
        }
    };
    let mut packet = ipv6_packet(src, dst, ICMPV6, 255, &icmp);
    repair_icmpv6(&mut packet);
    (packet, Ndp { src, dst, message })
}

/// The first option of type `wanted` in a neighbor discovery option area; `Err` when the
/// options do not fill the area or one has length zero.
fn nd_link_option(mut options: &[u8], wanted: u8) -> Result<Option<MacAddr>, ()> {
    let mut found = None;
    while !options.is_empty() {
        if options.len() < 2 || options[1] == 0 {
            return Err(());
        }
        let len = usize::from(options[1]) * 8;
        if options.len() < len {
            return Err(());
        }
        if options[0] == wanted && found.is_none() {
            found = Some(mac_at(options, 2));
        }
        options = &options[len..];
    }
    Ok(found)
}

/// RFC 4861 sections 6.1.1, 7.1.1 and 7.1.2 for a packet: the message the gateway acts on,
/// `Ok(None)` for another packet, `Err` for one that fails validation.
fn nd_expected(packet: &[u8]) -> Result<Option<Ndp>, ()> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Err(());
    }
    let end = 40 + usize::from(read16(packet, 4));
    let icmp = packet.get(40..end).ok_or(())?;
    if packet[6] != ICMPV6 || !matches!(icmp.first(), Some(133 | 135 | 136)) {
        return Ok(None);
    }
    let (src, dst) = (ipv6_at(packet, 8), ipv6_at(packet, 24));
    let fixed = if icmp[0] == 133 { 8 } else { 24 };
    if packet[7] != 255
        || icmp.len() < fixed
        || icmpv6_checksum(src, dst, icmp) != 0
        || icmp[1] != 0
    {
        return Err(());
    }
    let options = &icmp[fixed..];
    let message = match icmp[0] {
        133 => {
            let source_mac = nd_link_option(options, 1)?;
            if src.is_unspecified() && source_mac.is_some() {
                return Err(());
            }
            NdpMessage::RouterSolicitation { source_mac }
        }
        135 => {
            let target = ipv6_at(icmp, 8);
            let source_mac = nd_link_option(options, 1)?;
            let solicited_node =
                dst.octets()[..13] == [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff];
            if target.is_multicast()
                || (src.is_unspecified() && (source_mac.is_some() || !solicited_node))
            {
                return Err(());
            }
            NdpMessage::NeighborSolicitation { target, source_mac }
        }
        _ => {
            let target = ipv6_at(icmp, 8);
            let target_mac = nd_link_option(options, 2)?;
            let solicited = icmp[4] & 0x40 != 0;
            if target.is_multicast() || (solicited && dst.is_multicast()) {
                return Err(());
            }
            NdpMessage::NeighborAdvertisement {
                target,
                target_mac,
                router: icmp[4] & 0x80 != 0,
                solicited,
                override_entry: icmp[4] & 0x20 != 0,
            }
        }
    };
    Ok(Some(Ndp { src, dst, message }))
}

#[test]
fn the_neighbor_discovery_parser_applies_the_validity_rules() {
    let mut rng = Rng(0x5eed_e703);
    let (mut accepted, mut ignored, mut refused) = (0, 0, 0);
    for _ in 0..30_000 {
        let (mut packet, expected) = nd_packet(&mut rng);
        assert_eq!(nd_expected(&packet), Ok(Some(expected)), "{packet:02x?}");
        if rng.chance(40) {
            // Frame padding is cut off by the caller; here the packet is as generated.
            assert_eq!(Ndp::parse(&packet), Ok(Some(expected)), "{packet:02x?}");
            accepted += 1;
            continue;
        }
        mutate(&mut rng, &mut packet);
        if rng.chance(10) && packet.len() > 7 {
            packet[7] = rng.byte();
        }
        if rng.chance(75) {
            repair_icmpv6(&mut packet);
        }
        let parsed = Ndp::parse(&packet);
        assert_eq!(parsed.ok(), nd_expected(&packet).ok(), "{packet:02x?}");
        match parsed {
            Ok(Some(_)) => accepted += 1,
            Ok(None) => ignored += 1,
            Err(_) => refused += 1,
        }
    }
    assert!(
        accepted > 15_000 && ignored > 200 && refused > 4_000,
        "{accepted} {ignored} {refused}"
    );
}

/// Asserts that `frame` is a neighbor discovery frame the gateway may send: from its MAC,
/// hop limit 255, a valid checksum and options that fill the message. Returns the packet.
fn assert_nd_frame(frame: &[u8]) -> &[u8] {
    let parsed = Frame::parse(frame).unwrap();
    assert_eq!((parsed.src, parsed.ethertype), (GW_MAC, EtherType::IPV6));
    let packet = parsed.payload;
    assert_eq!((packet[0] >> 4, packet[6], packet[7]), (6, ICMPV6, 255));
    assert_eq!(usize::from(read16(packet, 4)), packet.len() - 40);
    let icmp = &packet[40..];
    let (src, dst) = (ipv6_at(packet, 8), ipv6_at(packet, 24));
    assert_eq!(icmpv6_checksum(src, dst, icmp), 0, "{frame:02x?}");
    let fixed = if icmp[0] == 134 { 16 } else { 24 };
    assert!(nd_link_option(&icmp[fixed..], 0).is_ok(), "{frame:02x?}");
    packet
}

#[test]
fn neighbor_discovery_answers_parse_as_what_they_say() {
    let mut rng = Rng(0x5eed_e704);
    let (mut advertised, mut routed) = (0, 0);
    for _ in 0..20_000 {
        let (packet, request) = nd_packet(&mut rng);
        let ours = [GW_MAC.link_local(), GW_IPV6];
        let answer = ndp::answer_neighbor_solicitation(&request, GUEST_MAC, GW_MAC, &ours);
        let asked = match request.message {
            NdpMessage::NeighborSolicitation { target, source_mac } if ours.contains(&target) => {
                Some((target, source_mac))
            }
            _ => None,
        };
        assert_eq!(answer.is_some(), asked.is_some(), "{packet:02x?}");
        if let (Some(answer), Some((target, source_mac))) = (answer, asked) {
            let direct = !request.src.is_unspecified();
            let reply = Ndp::parse(assert_nd_frame(&answer)).unwrap().unwrap();
            let expected = Ndp {
                src: target,
                dst: if direct { request.src } else { ALL_NODES },
                message: NdpMessage::NeighborAdvertisement {
                    target,
                    target_mac: Some(GW_MAC),
                    router: true,
                    solicited: direct,
                    override_entry: true,
                },
            };
            assert_eq!(reply, expected);
            let dst_mac = if direct {
                source_mac.unwrap_or(GUEST_MAC)
            } else {
                MacAddr([0x33, 0x33, 0, 0, 0, 1])
            };
            assert_eq!(mac_at(&answer, 0), dst_mac);
            advertised += 1;
        }

        let config = RaConfig {
            router_lifetime: rng.u16(),
            mtu: rng.u32(),
            prefix: rng.chance(60).then_some(PREFIX),
            dns: (0..rng.pick(&[0, 0, 1, 2, 127, 128, 200]))
                .map(|_| ipv6(&mut rng))
                .collect(),
            ..RaConfig::default()
        };
        let answer = ndp::answer_router_solicitation(&request, GUEST_MAC, GW_MAC, &config);
        let solicited = matches!(request.message, NdpMessage::RouterSolicitation { .. });
        assert_eq!(answer.is_some(), solicited);
        if let Some(answer) = answer {
            let packet = assert_nd_frame(&answer);
            let icmp = &packet[40..];
            assert_eq!((icmp[0], icmp[1]), (134, 0));
            assert_eq!(read16(icmp, 6), config.router_lifetime);
            assert_eq!(ipv6_at(packet, 8), GW_MAC.link_local());
            // Options in order: source link-layer address, MTU, prefix, DNS servers.
            let dns = config.dns.len().min(127);
            let mut expected = 16 + 8 + 8;
            assert_eq!(icmp[16..24], [1, 1, 2, 0, 0, 0, 0, 1]);
            assert_eq!(icmp[24..28], [5, 1, 0, 0]);
            assert_eq!(icmp[28..32], config.mtu.to_be_bytes());
            if config.prefix.is_some() {
                assert_eq!(icmp[expected..expected + 4], [3, 4, 64, 0xc0]);
                assert_eq!(ipv6_at(icmp, expected + 16), PREFIX);
                expected += 32;
            }
            if dns > 0 {
                assert_eq!(icmp[expected], 25);
                assert_eq!(usize::from(icmp[expected + 1]), 1 + 2 * dns);
                for (i, server) in config.dns.iter().take(dns).enumerate() {
                    assert_eq!(ipv6_at(icmp, expected + 8 + 16 * i), *server);
                }
                expected += 8 + 16 * dns;
            }
            assert_eq!(icmp.len(), expected);
            routed += 1;
        }
    }
    assert!(
        advertised > 1_000 && routed > 3_000,
        "{advertised} {routed}"
    );
}

const DHCP_FIXED: usize = 240;
const COOKIE: [u8; 4] = [99, 130, 83, 99];

/// A DHCP message of type `kind` from `chaddr`, with the options in a random order among
/// padding and options the server does not read.
fn dhcp_message(
    rng: &mut Rng,
    kind: u8,
    chaddr: MacAddr,
    requested: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut out = vec![rng.pick(&[1, 1, 1, 1, 2]), 1, 6, 0];
    out.extend_from_slice(&rng.array::<4>());
    out.extend_from_slice(&rng.array::<2>());
    out.extend_from_slice(&rng.pick(&[[0, 0], [0x80, 0]]));
    let ciaddr = rng.pick(&[Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, GUEST_IP]);
    out.extend_from_slice(&ciaddr.octets());
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&chaddr.0);
    out.extend_from_slice(&[0; 10 + 192]);
    out.extend_from_slice(&COOKIE);

    let mut options = vec![vec![53, 1, kind]];
    if let Some(addr) = requested {
        options.push([&[50, 4][..], &addr.octets()].concat());
    }
    if let Some(addr) = server_id {
        options.push([&[54, 4][..], &addr.octets()].concat());
    }
    for _ in 0..rng.below(4) {
        let option = if rng.chance(30) {
            vec![0]
        } else {
            let len = rng.below(6);
            // A second option of a code the server reads only behind the first one.
            let code = match rng.pick(&[12, 55, 57, 61, 50, 54]) {
                50 if requested.is_none() => 12,
                54 if server_id.is_none() => 55,
                code => code,
            };
            let mut option = vec![code, u8::try_from(len).unwrap()];
            option.extend_from_slice(&rng.bytes(len));
            option
        };
        // Behind the options the server reads, so that those stay the first of their code.
        options.push(option);
    }
    let fixed = 1 + usize::from(requested.is_some()) + usize::from(server_id.is_some());
    for i in (1..fixed).rev() {
        options.swap(i, rng.below(i + 1));
    }
    out.extend_from_slice(&options.concat());
    if rng.chance(90) {
        out.push(255);
        let len = rng.below(8);
        out.extend_from_slice(&rng.bytes(len));
    }
    out
}

/// The data of the first option `code` of a DHCP option area; `Err` when an option runs
/// past the end.
fn dhcp_option(mut options: &[u8], code: u8) -> Result<Option<&[u8]>, ()> {
    let mut found = None;
    while let Some((&kind, rest)) = options.split_first() {
        options = rest;
        match kind {
            0 => {}
            255 => break,
            _ => {
                let (&len, rest) = options.split_first().ok_or(())?;
                let data = rest.get(..usize::from(len)).ok_or(())?;
                options = &rest[usize::from(len)..];
                if kind == code && found.is_none() {
                    found = Some(data);
                }
            }
        }
    }
    Ok(found)
}

/// Whether `bytes` is a DHCP message over ethernet: RFC 2131 section 2 with a message type
/// of RFC 2132 section 9.6.
fn dhcp_valid(bytes: &[u8]) -> bool {
    bytes.len() >= DHCP_FIXED
        && bytes[1..3] == [1, 6]
        && bytes[236..240] == COOKIE
        && matches!(dhcp_option(&bytes[DHCP_FIXED..], 53), Ok(Some(&[1..=8])))
}

#[test]
fn the_dhcp_parser_reads_the_fields_and_the_first_option_of_a_code() {
    let mut rng = Rng(0x5eed_e705);
    let (mut accepted, mut refused) = (0, 0);
    for _ in 0..30_000 {
        let kind = rng.pick(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let chaddr = mac(&mut rng);
        let requested = rng.chance(50).then(|| ipv4(&mut rng));
        let server_id = rng.chance(50).then(|| ipv4(&mut rng));
        let mut bytes = dhcp_message(&mut rng, kind, chaddr, requested, server_id);
        if rng.chance(50) {
            mutate(&mut rng, &mut bytes);
        } else {
            let message = DhcpMessage::parse(&bytes).unwrap();
            assert_eq!(message.message_type.to_u8(), kind);
            assert_eq!(message.chaddr, chaddr);
            assert_eq!(message.requested_ip(), requested);
            assert_eq!(message.server_id(), server_id);
        }
        let Ok(message) = DhcpMessage::parse(&bytes) else {
            assert!(!dhcp_valid(&bytes), "{bytes:02x?}");
            refused += 1;
            continue;
        };
        assert!(dhcp_valid(&bytes), "{bytes:02x?}");
        assert_eq!(message.op, bytes[0]);
        assert_eq!(message.xid.to_be_bytes(), bytes[4..8]);
        assert_eq!(message.secs, read16(&bytes, 8));
        assert_eq!(message.flags, read16(&bytes, 10));
        assert_eq!(message.broadcast(), bytes[10] & 0x80 != 0);
        assert_eq!(message.ciaddr, ipv4_at(&bytes, 12));
        assert_eq!(message.yiaddr, ipv4_at(&bytes, 16));
        assert_eq!(message.siaddr, ipv4_at(&bytes, 20));
        assert_eq!(message.giaddr, ipv4_at(&bytes, 24));
        assert_eq!(message.chaddr, mac_at(&bytes, 28));
        let options = &bytes[DHCP_FIXED..];
        assert_eq!(
            Some(&[message.message_type.to_u8()][..]),
            dhcp_option(options, 53).unwrap()
        );
        for code in [50, 54, 55, 61, rng.byte()] {
            assert_eq!(message.option(code), dhcp_option(options, code).unwrap());
        }
        accepted += 1;
    }
    assert!(accepted > 18_000 && refused > 3_000, "{accepted} {refused}");
}

/// Asserts that `frame` carries the DHCP `reply` from the server to the client port, with
/// valid lengths and checksums, and returns its destination MAC and address.
fn assert_dhcp_frame(frame: &[u8], reply: &[u8]) -> (MacAddr, Ipv4Addr) {
    let parsed = Frame::parse(frame).unwrap();
    assert_eq!((parsed.src, parsed.ethertype), (GW_MAC, EtherType::IPV4));
    let packet = parsed.payload;
    assert_eq!((packet[0], packet[9]), (0x45, 17));
    assert_eq!(usize::from(read16(packet, 2)), packet.len());
    assert_eq!(internet_checksum(&packet[..20]), 0);
    let (src, dst) = (ipv4_at(packet, 12), ipv4_at(packet, 16));
    assert_eq!(src, GW_IP);
    let udp = &packet[20..];
    assert_eq!((read16(udp, 0), read16(udp, 2)), (67, 68));
    assert_eq!(usize::from(read16(udp, 4)), udp.len());
    assert_eq!(transport_checksum_v4(src, dst, 17, udp), 0);
    assert_eq!(&udp[8..], reply);
    (parsed.dst, dst)
}

/// Asserts that `frame` carries `reply` to where a client without an address hears it:
/// broadcast for a NAK, on request and without a client address, else to the client.
fn assert_dhcp_reply_addressed(frame: &[u8], reply: &[u8], message: &DhcpMessage<'_>) {
    let (dst_mac, dst) = assert_dhcp_frame(frame, reply);
    let broadcast = message.message_type == MessageType::Nak
        || message.broadcast()
        || message.ciaddr.is_unspecified();
    if broadcast {
        assert_eq!((dst_mac, dst), (MacAddr::BROADCAST, Ipv4Addr::BROADCAST));
    } else {
        assert_eq!((dst_mac, dst), (message.chaddr, message.ciaddr));
    }
}

#[test]
fn the_dhcp_server_promises_its_address_to_one_client_at_a_time() {
    let mut rng = Rng(0x5eed_e706);
    let (mut acks, mut naks, mut offers, mut freed) = (0, 0, 0, 0);
    for _ in 0..200 {
        let mut config = DhcpConfig::new(GW_IP, GUEST_IP, rng.pick(&[0, 8, 24, 32, 40]));
        config.router = rng.chance(50).then_some(GW_IP);
        config.dns = (0..rng.pick(&[0, 1, 2, 63, 70]))
            .map(|_| ipv4(&mut rng))
            .collect();
        config.mtu = rng.chance(50).then(|| rng.u16());
        config.lease_secs = rng.pick(&[0, 60, 86_400, u32::MAX]);
        let mut server = DhcpServer::new(config.clone());
        for _ in 0..150 {
            let client = rng.pick(&[GUEST_MAC, GUEST_MAC, OTHER_MAC]);
            let kind = rng.pick(&[1, 1, 3, 3, 3, 4, 7, 7, 8, 2, 5]);
            let requested = rng
                .chance(70)
                .then(|| rng.pick(&[GUEST_IP, GUEST_IP, Ipv4Addr::new(10, 0, 2, 99)]));
            let server_id = rng.chance(40).then(|| rng.pick(&[GW_IP, GW_IP, GUEST_IP]));
            let mut request = dhcp_message(&mut rng, kind, client, requested, server_id);
            if rng.chance(15) {
                mutate(&mut rng, &mut request);
            }
            let before = server.bound();
            let reply = server.handle(&request, client);
            let after = server.bound();

            // The lease moves only to the client that asked, and only from free; it is
            // given up only by its holder.
            if after.is_none() && before.is_some() {
                assert_eq!(before, Some(client));
                freed += 1;
            } else if after != before {
                assert_eq!((before, after), (None, Some(client)));
            }
            let Some(reply) = reply else {
                assert!(
                    after.is_none() || before.is_some(),
                    "bound without an answer"
                );
                continue;
            };
            let asked = DhcpMessage::parse(&request).unwrap();
            let message = DhcpMessage::parse(&reply).unwrap();
            assert_eq!(asked.op, 1);
            assert_eq!(
                (
                    message.op,
                    message.xid,
                    message.flags,
                    message.chaddr,
                    message.giaddr
                ),
                (2, asked.xid, asked.flags, asked.chaddr, asked.giaddr)
            );
            assert!(reply.len() >= 300);
            assert_eq!(message.server_id(), Some(GW_IP));
            let other_holds = before.is_some_and(|holder| holder != client);
            match message.message_type {
                MessageType::Offer => {
                    assert_eq!(asked.message_type, MessageType::Discover);
                    assert_eq!(message.yiaddr, GUEST_IP);
                    assert!(!other_holds);
                    offers += 1;
                }
                MessageType::Ack if asked.message_type == MessageType::Inform => {
                    assert_eq!(message.yiaddr, Ipv4Addr::UNSPECIFIED);
                    assert_eq!(message.option(51), None);
                }
                MessageType::Ack => {
                    assert_eq!(asked.message_type, MessageType::Request);
                    assert_eq!(message.yiaddr, GUEST_IP);
                    assert_eq!(after, Some(client));
                    assert!(!other_holds);
                    assert_eq!(
                        message.option(51),
                        Some(&config.lease_secs.to_be_bytes()[..])
                    );
                    acks += 1;
                }
                MessageType::Nak => {
                    assert_eq!(asked.message_type, MessageType::Request);
                    assert_eq!(message.yiaddr, Ipv4Addr::UNSPECIFIED);
                    assert_eq!(message.option(1), None);
                    naks += 1;
                }
                other => panic!("a server does not send {other:?}"),
            }
            if message.message_type != MessageType::Nak {
                assert_eq!(message.option(1), Some(&config.netmask().octets()[..]));
                assert_eq!(message.option(3).is_some(), config.router.is_some());
                let dns = config.dns.len().min(63);
                assert_eq!(message.option(6).map_or(0, <[u8]>::len), 4 * dns);
            }

            let frame = server.reply_frame(&reply, GW_MAC).unwrap();
            assert_dhcp_reply_addressed(&frame, &reply, &message);
        }
    }
    assert!(acks > 500 && naks > 500 && offers > 500 && freed > 100);
}

/// What a frame from the generator is, when nothing in it was changed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Sent {
    /// An IP packet for the IP side.
    Ip(Vec<u8>),
    Other,
}

fn udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    udp_packet(src, dst, payload).unwrap().as_packet().to_vec()
}

/// A frame as a guest may send it, with padding behind some.
fn guest_frame(rng: &mut Rng) -> (Vec<u8>, Sent) {
    let src = rng.pick(&[
        GUEST_MAC,
        GUEST_MAC,
        GUEST_MAC,
        GUEST_MAC,
        OTHER_MAC,
        MacAddr::BROADCAST,
    ]);
    let dst = rng.pick(&[GW_MAC, GW_MAC, GW_MAC, MacAddr::BROADCAST, OTHER_MAC]);
    let for_us = src.0[0] & 1 == 0 && dst != OTHER_MAC;
    let padding = if rng.chance(30) { rng.below(30) } else { 0 };
    let (ethertype, mut payload, sent) = match rng.below(8) {
        0 | 1 => {
            let mut payload = Vec::new();
            arp_packet(rng).write(&mut payload);
            (0x0806, payload, Sent::Other)
        }
        2 => {
            let kind = rng.pick(&[1, 3, 3, 7, 8]);
            let requested = rng.chance(70).then_some(GUEST_IP);
            let message = dhcp_message(rng, kind, src, requested, None);
            let to = rng.pick(&[Ipv4Addr::BROADCAST, GW_IP]);
            let packet = udp(
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 68)),
                SocketAddr::from((to, 67)),
                &message,
            );
            (0x0800, packet, Sent::Other)
        }
        3 => {
            let len = rng.below(60);
            let packet = udp(
                SocketAddr::from((GUEST_IP, 40000)),
                SocketAddr::from((ipv4(rng), rng.pick(&[53, 68, 443]))),
                &rng.bytes(len),
            );
            (0x0800, packet.clone(), Sent::Ip(packet))
        }
        4 | 5 => (0x86dd, nd_packet(rng).0, Sent::Other),
        6 => {
            let len = rng.below(60);
            let packet = udp(
                SocketAddr::from((GUEST_IPV6, 40000)),
                SocketAddr::from((ipv6(rng), 53)),
                &rng.bytes(len),
            );
            (0x86dd, packet.clone(), Sent::Ip(packet))
        }
        _ => {
            let len = rng.below(40);
            (
                rng.pick(&[0x8100, 0x0100, 0x88cc, 0x0800, 0x86dd]),
                rng.bytes(len),
                Sent::Other,
            )
        }
    };
    payload.extend_from_slice(&rng.bytes(padding));
    let mut frame = eth(dst, src, ethertype, &payload);
    if rng.chance(25) {
        mutate(rng, &mut frame);
        return (frame, Sent::Other);
    }
    (frame, if for_us { sent } else { Sent::Other })
}

/// Asserts that `reply` is a frame the gateway may send to the guest.
fn assert_reply(reply: &[u8], lease: bool) {
    let frame = Frame::parse(reply).unwrap();
    assert_eq!(frame.src, GW_MAC);
    match frame.ethertype {
        EtherType::ARP => {
            assert_eq!(reply.len(), HEADER_LEN + PACKET_LEN);
            let packet = ArpPacket::parse(frame.payload).unwrap();
            assert_eq!((packet.op, packet.sender_mac), (ArpOp::Reply, GW_MAC));
            assert_eq!(packet.target_mac, frame.dst);
            // The lease address is the guest's: the gateway never claims it.
            assert!(!lease || packet.sender_ip != GUEST_IP);
        }
        EtherType::IPV6 => {
            assert_nd_frame(reply);
        }
        EtherType::IPV4 => {
            let packet = frame.payload;
            assert_dhcp_frame(reply, &packet[28..]);
            assert_eq!(DhcpMessage::parse(&packet[28..]).unwrap().op, 2);
        }
        other => panic!("the gateway does not send {other:?}"),
    }
}

#[test]
fn the_adapter_accounts_for_every_frame_and_passes_only_whole_ip_packets() {
    let mut rng = Rng(0x5eed_e707);
    let (mut passed, mut answered, mut answered_dhcp) = (0, 0, 0);
    for round in 0..40 {
        let prefix = (round % 2 == 0).then_some(PREFIX);
        let config = EtherConfig {
            gateway_ipv4: (round % 5 != 0).then_some(GW_IP),
            gateway_ipv6: prefix.map(|_| GW_IPV6),
            ipv6_prefix: prefix,
            dhcp: (round % 3 != 0).then(|| DhcpConfig::new(GW_IP, GUEST_IP, 24)),
            proxy_neighbors: round % 4 != 0,
            ..EtherConfig::new(GW_MAC)
        };
        let mut adapter = EtherAdapter::new(config.clone());
        let mut guest = None;
        let mut sent_replies = 0;
        let frames = 500;
        for _ in 0..frames {
            let (bytes, sent) = guest_frame(&mut rng);
            let mut replies = Vec::new();
            let packet = adapter.from_guest(&bytes, &mut replies);

            let unknown = guest.is_none();
            if let Ok(frame) = Frame::parse(&bytes)
                && frame.src.0[0] & 1 == 0
            {
                guest = Some(frame.src);
            }
            assert_eq!(adapter.guest_mac(), guest);
            if let Some(packet) = packet {
                // The packet is the frame's payload up to the length its header declares.
                let frame = Frame::parse(&bytes).unwrap();
                assert!(frame.dst == GW_MAC || frame.dst.0[0] & 1 == 1);
                assert_eq!(packet, &bytes[HEADER_LEN..HEADER_LEN + packet.len()]);
                let (version, len) = match frame.ethertype {
                    EtherType::IPV4 => (4, usize::from(read16(packet, 2))),
                    EtherType::IPV6 => (6, 40 + usize::from(read16(packet, 4))),
                    other => panic!("{other:?} is not for the IP side"),
                };
                assert_eq!((packet[0] >> 4, packet.len()), (version, len));
                // Nothing is answered, but the first frame of a guest brings the
                // unsolicited router advertisement with it.
                assert_eq!(replies.len(), usize::from(unknown && prefix.is_some()));
                passed += 1;
            }
            if let Sent::Ip(expected) = &sent {
                let dhcp = config.dhcp.is_some()
                    && expected[0] >> 4 == 4
                    && read16(expected, 22) == 67
                    && matches!(ipv4_at(expected, 16), Ipv4Addr::BROADCAST | GW_IP);
                if !dhcp {
                    assert_eq!(packet, Some(&expected[..]), "{bytes:02x?}");
                }
            }
            for reply in &replies {
                assert_reply(reply, config.dhcp.is_some());
                // The model used to let any datagram to port 67 be answered. The adapter
                // is the receiving host of a DHCP datagram, so a reply now also says the
                // request had a correct IPv4 header checksum and a UDP length that ends
                // inside the packet, with a whole DHCP message before that end.
                if Frame::parse(reply).unwrap().ethertype == EtherType::IPV4 {
                    let request = &bytes[HEADER_LEN..];
                    let header_len = usize::from(request[0] & 0x0f) * 4;
                    assert_eq!(internet_checksum(&request[..header_len]), 0);
                    let datagram = &request[header_len..usize::from(read16(request, 2))];
                    let message = &datagram[8..usize::from(read16(datagram, 4))];
                    assert!(dhcp_valid(message), "{bytes:02x?}");
                    answered_dhcp += 1;
                }
            }
            sent_replies += u64::try_from(replies.len()).unwrap();
            answered += replies.len();
        }

        let stats = adapter.stats();
        let unsolicited = u64::from(prefix.is_some() && guest.is_some());
        assert_eq!(stats.frames_in, frames);
        assert_eq!(
            stats.frames_in,
            stats.ip_in
                + stats.arp_replies
                + stats.dhcp_replies
                + (stats.nd_replies - unsolicited)
                + stats.drop_malformed
                + stats.drop_not_for_gateway
                + stats.drop_unsupported
                + stats.drop_unanswered,
            "{stats:?}"
        );
        assert_eq!(stats.frames_out, sent_replies);
        assert_eq!(
            stats.frames_out,
            stats.arp_replies + stats.dhcp_replies + stats.nd_replies
        );
        assert!(stats.arp_proxied <= stats.arp_replies && stats.nd_proxied <= stats.nd_replies);
        if !config.proxy_neighbors {
            assert_eq!((stats.arp_proxied, stats.nd_proxied), (0, 0));
        }
        if config.dhcp.is_none() {
            assert_eq!(stats.dhcp_replies, 0);
        }
    }
    assert!(passed > 1_500 && answered > 1_500, "{passed} {answered}");
    assert!(answered_dhcp > 200, "{answered_dhcp}");
}
