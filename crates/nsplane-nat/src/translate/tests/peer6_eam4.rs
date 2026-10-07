//! IPv4 EAMs to `peer6`: an IPv4 address translated to and from a peer's
//! `peer6` (`TranslationTableBuilder::peer_with_peer6_eam4`), next to the
//! peer's `eam4` and `local6`.
//!
//! Outbound packets go from this node (`SELF_EAM4`) to `PEER`'s `peer6_eam4`;
//! inbound packets come from `PEER`'s `peer6` to the self `eam6`.

use super::*;

const PEER6_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 50);
const OTHER_PEER6_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 51);

fn peer6() -> Ipv6Addr {
    peer_mapping().peer6
}

/// [`table`] with `peer6_eam4` addresses for `PEER` and `OTHER`.
fn peer6_eam4_table() -> TranslationTable {
    TranslationTable::builder()
        .peer_with_peer6_eam4(PEER, peer_mapping(), PEER6_EAM4)
        .peer_with_peer6_eam4(OTHER, other_mapping(), OTHER_PEER6_EAM4)
        .self_mapping(SelfMapping {
            eam4: SELF_EAM4,
            eam6: self_eam6(),
        })
        .lan(lan("192.168.1.0", 24, "fd64:1::", None))
        .lan(lan("10.0.0.0", 8, "fd64:2::", Some(PEER)))
        .build()
        .unwrap()
}

fn peer6_eam4_translator() -> Translator {
    Translator::new(peer6_eam4_table())
}

fn out_peer6_eam4(peer: PeerId, bytes: &[u8]) -> (Verdict, Vec<u8>) {
    outbound(&peer6_eam4_translator(), peer, bytes)
}

fn in_peer6_eam4(peer: PeerId, bytes: &[u8]) -> (Verdict, Vec<u8>) {
    inbound(&peer6_eam4_translator(), peer, bytes)
}

fn dropped(reason: &'static str) -> Verdict {
    Verdict::Drop { reason }
}

#[test]
fn outbound_peer6_eam4_becomes_ipv6_to_peer6() {
    for (proto, body) in [
        (protocol::TCP, tcp4(SELF_EAM4, PEER6_EAM4, b"tcp")),
        (protocol::UDP, udp4(SELF_EAM4, PEER6_EAM4, b"udp", false)),
        (protocol::ICMP, echo4(false, b"ping")),
    ] {
        let hdr = Hdr4 {
            tos: 0xb8,
            ..Hdr4::default()
        };
        let packet = ipv4(SELF_EAM4, PEER6_EAM4, proto, hdr, &body);
        let (verdict, v6) = out_peer6_eam4(PEER, &packet);
        assert_eq!(verdict, Verdict::Accept, "{proto}");
        assert_eq!(v6.len(), packet.len() + 20);
        check_v6(&v6);
        assert_eq!((src6(&v6), dst6(&v6)), (self_eam6(), peer6()));
        let proto6 = if proto == protocol::ICMP {
            protocol::ICMPV6
        } else {
            proto
        };
        assert_eq!((v6[6], v6[7], traffic_class(&v6)), (proto6, 63, 0xb8));
    }
    // A local LAN source becomes its lan6 address.
    let src = ip4("192.168.1.20");
    let packet = ipv4_simple(
        src,
        PEER6_EAM4,
        protocol::UDP,
        &udp4(src, PEER6_EAM4, b"x", false),
    );
    let (verdict, v6) = out_peer6_eam4(PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v6(&v6);
    assert_eq!((src6(&v6), dst6(&v6)), (ip6("fd64:1::c0a8:114"), peer6()));
}

#[test]
fn inbound_peer6_to_self_eam6_becomes_ipv4_from_the_peer6_eam4() {
    let (src, dst) = (peer6(), self_eam6());
    for (proto, body) in [
        (protocol::TCP, tcp6(src, dst, b"tcp")),
        (protocol::UDP, udp6(src, dst, b"udp")),
        (protocol::ICMPV6, echo6(src, dst, true, b"pong")),
    ] {
        let packet = ipv6(src, dst, proto, 9, 0x2e, &[], &body);
        let (verdict, v4) = in_peer6_eam4(PEER, &packet);
        assert_eq!(verdict, Verdict::Accept, "{proto}");
        assert_eq!(v4.len(), packet.len() - 20);
        check_v4(&v4);
        assert_eq!((src4(&v4), dst4(&v4)), (PEER6_EAM4, SELF_EAM4));
        let proto4 = if proto == protocol::ICMPV6 {
            protocol::ICMP
        } else {
            proto
        };
        assert_eq!((v4[1], v4[8], v4[9]), (0x2e, 8, proto4));
    }
    // Towards a local LAN host.
    let dst = ip6("fd64:1::c0a8:114");
    let packet = ipv6_simple(src, dst, protocol::UDP, &udp6(src, dst, b"x"));
    let (verdict, v4) = in_peer6_eam4(PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v4(&v4);
    assert_eq!((src4(&v4), dst4(&v4)), (PEER6_EAM4, ip4("192.168.1.20")));
}

#[test]
fn icmp_errors_quoting_peer6_eam4_packets_are_translated() {
    // Outbound: this node reports an error for a packet from the `peer6_eam4`.
    let body = udp4(PEER6_EAM4, SELF_EAM4, b"quoted", false);
    let hdr = Hdr4 {
        ttl: 37,
        ..Hdr4::default()
    };
    let quoted = ipv4(PEER6_EAM4, SELF_EAM4, protocol::UDP, hdr, &body);
    let error = icmp4_error(3, 3, [0; 4], &quoted);
    let packet = ipv4_simple(SELF_EAM4, PEER6_EAM4, protocol::ICMP, &error);
    let (verdict, v6) = out_peer6_eam4(PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v6(&v6);
    assert_eq!((v6[40], v6[41]), (1, 4), "port unreachable");
    let quote = &v6[48..];
    assert_eq!((src6(quote), dst6(quote)), (peer6(), self_eam6()));
    assert_eq!(quote[7], 37, "the quoted hop limit is not decremented");
    assert_eq!(
        transport_checksum_v6(peer6(), self_eam6(), protocol::UDP, &quote[40..]),
        0
    );

    // Inbound: the peer reports an error for a packet this node sent to the
    // `peer6_eam4`.
    let body = udp6(self_eam6(), peer6(), b"quoted");
    let quoted = ipv6(self_eam6(), peer6(), protocol::UDP, 37, 0, &[], &body);
    let error = icmp6_error(peer6(), self_eam6(), 1, 4, [0; 4], &quoted);
    let packet = ipv6_simple(peer6(), self_eam6(), protocol::ICMPV6, &error);
    let (verdict, v4) = in_peer6_eam4(PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v4(&v4);
    assert_eq!((src4(&v4), dst4(&v4)), (PEER6_EAM4, SELF_EAM4));
    assert_eq!((v4[20], v4[21]), (3, 3), "port unreachable");
    let quote = &v4[28..];
    assert_eq!((src4(quote), dst4(quote)), (SELF_EAM4, PEER6_EAM4));
    assert_eq!(quote[8], 37, "the quoted TTL is not decremented");
    assert_eq!(internet_checksum(&quote[..20]), 0);
    assert_eq!(
        transport_checksum_v4(SELF_EAM4, PEER6_EAM4, protocol::UDP, &quote[20..]),
        0
    );
}

#[test]
fn peer6_eam4_fragments_are_translated_both_ways() {
    // Outbound: a checksummed UDP datagram in three IPv4 fragments.
    let translator = peer6_eam4_translator();
    let udp = udp4(SELF_EAM4, PEER6_EAM4, b"abcdefghijklmnopqrstuvwx", false);
    let mut joined = Vec::new();
    for (index, (offset, more, bytes)) in [
        (0_u16, true, &udp[..16]),
        (2, true, &udp[16..24]),
        (3, false, &udp[24..]),
    ]
    .into_iter()
    .enumerate()
    {
        let hdr = Hdr4 {
            id: 300,
            fragment: offset | if more { 0x2000 } else { 0 },
            ..Hdr4::default()
        };
        let piece = ipv4(SELF_EAM4, PEER6_EAM4, protocol::UDP, hdr, bytes);
        let (verdict, v6) = outbound(&translator, PEER, &piece);
        assert_eq!(verdict, Verdict::Accept, "fragment {index}");
        assert_eq!(check_v6(&v6), 48);
        assert_eq!((src6(&v6), dst6(&v6)), (self_eam6(), peer6()));
        assert_eq!(&v6[44..48], &300_u32.to_be_bytes());
        joined.extend_from_slice(&v6[48..]);
    }
    assert_eq!(
        transport_checksum_v6(self_eam6(), peer6(), protocol::UDP, &joined),
        0
    );

    // Inbound: a UDP datagram in two IPv6 fragments.
    let (src, dst) = (peer6(), self_eam6());
    let udp = udp6(src, dst, b"abcdefghijklmnopqrstuvwx");
    let mut joined = Vec::new();
    for (offset, more, bytes) in [(0_u16, true, &udp[..16]), (2, false, &udp[16..])] {
        let bits = (offset << 3) | u16::from(more);
        let mut extension = vec![44, protocol::UDP, 0];
        extension.extend_from_slice(&bits.to_be_bytes());
        extension.extend_from_slice(&0x0102_abcd_u32.to_be_bytes());
        let packet = ipv6(src, dst, protocol::UDP, 64, 0, &extension, bytes);
        let (verdict, v4) = in_peer6_eam4(PEER, &packet);
        assert_eq!(verdict, Verdict::Accept);
        check_v4(&v4);
        assert_eq!((src4(&v4), dst4(&v4)), (PEER6_EAM4, SELF_EAM4));
        assert_eq!(&v4[4..6], &0xabcd_u16.to_be_bytes());
        joined.extend_from_slice(&v4[20..]);
    }
    assert_eq!(
        transport_checksum_v4(PEER6_EAM4, SELF_EAM4, protocol::UDP, &joined),
        0
    );
}

#[test]
fn a_peer6_eam4_source_is_a_spoof() {
    for src in [PEER6_EAM4, OTHER_PEER6_EAM4] {
        let packet = ipv4_simple(
            src,
            SELF_EAM4,
            protocol::UDP,
            &udp4(src, SELF_EAM4, b"x", false),
        );
        assert_eq!(
            in_peer6_eam4(PEER, &packet).0,
            dropped(reasons::SPOOFED_SOURCE),
            "{src}"
        );
    }
}

#[test]
fn a_peer6_eam4_of_another_peer_is_dropped() {
    // Outbound: routed to PEER, addressed to OTHER's `peer6_eam4`.
    let packet = ipv4_simple(
        SELF_EAM4,
        OTHER_PEER6_EAM4,
        protocol::UDP,
        &udp4(SELF_EAM4, OTHER_PEER6_EAM4, b"x", false),
    );
    assert_eq!(
        out_peer6_eam4(PEER, &packet).0,
        dropped(reasons::PEER_MISMATCH)
    );
    // Inbound: PEER's peer6 arriving from OTHER.
    let (src, dst) = (peer6(), self_eam6());
    let packet = ipv6_simple(src, dst, protocol::UDP, &udp6(src, dst, b"x"));
    assert_eq!(
        in_peer6_eam4(OTHER, &packet).0,
        dropped(reasons::PEER_MISMATCH)
    );
    // An unmapped source is still refused.
    let packet = ipv4_simple(
        ip4("198.51.100.7"),
        PEER6_EAM4,
        protocol::UDP,
        &udp4(ip4("198.51.100.7"), PEER6_EAM4, b"x", false),
    );
    assert_eq!(out_peer6_eam4(PEER, &packet).0, dropped(reasons::UNMAPPED));
}

#[test]
fn peer6_eam4_coexists_with_eam4_and_local6() {
    let translator = peer6_eam4_translator();
    let mapping = peer_mapping();
    let local6 = mapping.local6.unwrap();
    let own6 = ip6("fd00::ff:0");

    // eam4 still goes to eam6, the `peer6_eam4` to peer6.
    for (dst, expected) in [(EAM4, mapping.eam6), (PEER6_EAM4, mapping.peer6)] {
        let packet = ipv4_simple(
            SELF_EAM4,
            dst,
            protocol::UDP,
            &udp4(SELF_EAM4, dst, b"x", false),
        );
        let (verdict, v6) = outbound(&translator, PEER, &packet);
        assert_eq!(verdict, Verdict::Accept, "{dst}");
        check_v6(&v6);
        assert_eq!(dst6(&v6), expected);
    }
    // IPv6 to local6 is still rewritten to peer6 and stays IPv6.
    let packet = ipv6_simple(own6, local6, protocol::UDP, &udp6(own6, local6, b"x"));
    let (verdict, v6) = outbound(&translator, PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v6(&v6);
    assert_eq!(
        (src6(&v6), dst6(&v6), v6.len()),
        (own6, mapping.peer6, packet.len())
    );

    // Inbound: eam6 -> self eam6 comes from eam4, peer6 -> self eam6
    // from the `peer6_eam4`, peer6 -> this node's own IPv6 address is rewritten to local6.
    for (src, expected) in [(mapping.eam6, EAM4), (mapping.peer6, PEER6_EAM4)] {
        let packet = ipv6_simple(
            src,
            self_eam6(),
            protocol::UDP,
            &udp6(src, self_eam6(), b"x"),
        );
        let (verdict, v4) = inbound(&translator, PEER, &packet);
        assert_eq!(verdict, Verdict::Accept, "{src}");
        check_v4(&v4);
        assert_eq!((src4(&v4), dst4(&v4)), (expected, SELF_EAM4));
    }
    let src = mapping.peer6;
    let packet = ipv6_simple(src, own6, protocol::TCP, &tcp6(src, own6, b"x"));
    let (verdict, v6) = inbound(&translator, PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v6(&v6);
    assert_eq!((src6(&v6), dst6(&v6)), (local6, own6));

    let stats = translator.stats();
    assert_eq!((stats.translated_out, stats.rewritten_out), (2, 1));
    assert_eq!((stats.translated_in, stats.rewritten_in), (2, 1));
}

#[test]
fn the_predicate_covers_peer6_eam4s() {
    let translator = peer6_eam4_translator();
    let translated = translator.ipv4_translated_predicate();
    for addr in [PEER6_EAM4, OTHER_PEER6_EAM4, EAM4] {
        assert!(translated(addr), "{addr}");
    }
    assert!(!translated(SELF_EAM4));
    translator.store(table());
    assert!(!translated(PEER6_EAM4));
}
