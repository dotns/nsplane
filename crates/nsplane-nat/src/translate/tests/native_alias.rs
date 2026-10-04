//! Native IPv4 aliases: an IPv4 address translated to and from a peer's
//! `node6` (`TranslationTableBuilder::peer_with_native_alias4`), next to the
//! peer's `alias4` and `alias6`.
//!
//! Outbound packets go from this node (`SELF4`) to `PEER`'s native alias;
//! inbound packets come from `PEER`'s `node6` to the self `node4`.

use super::*;

const NATIVE4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 50);
const OTHER_NATIVE4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 51);

fn node6() -> Ipv6Addr {
    peer_mapping().node6
}

/// [`table`] with native aliases for `PEER` and `OTHER`.
fn native_table() -> TranslationTable {
    TranslationTable::builder()
        .peer_with_native_alias4(PEER, peer_mapping(), NATIVE4)
        .peer_with_native_alias4(OTHER, other_mapping(), OTHER_NATIVE4)
        .self_mapping(SelfMapping {
            self4: SELF4,
            node4: self_node4(),
        })
        .lan(lan("192.168.1.0", 24, "fd64:1::", None))
        .lan(lan("10.0.0.0", 8, "fd64:2::", Some(PEER)))
        .build()
        .unwrap()
}

fn native_translator() -> Translator {
    Translator::new(native_table())
}

fn out_native(peer: PeerId, bytes: &[u8]) -> (Verdict, Vec<u8>) {
    outbound(&native_translator(), peer, bytes)
}

fn in_native(peer: PeerId, bytes: &[u8]) -> (Verdict, Vec<u8>) {
    inbound(&native_translator(), peer, bytes)
}

fn dropped(reason: &'static str) -> Verdict {
    Verdict::Drop { reason }
}

#[test]
fn outbound_native_alias_becomes_ipv6_to_node6() {
    for (proto, body) in [
        (protocol::TCP, tcp4(SELF4, NATIVE4, b"tcp")),
        (protocol::UDP, udp4(SELF4, NATIVE4, b"udp", false)),
        (protocol::ICMP, echo4(false, b"ping")),
    ] {
        let hdr = Hdr4 {
            tos: 0xb8,
            ..Hdr4::default()
        };
        let packet = ipv4(SELF4, NATIVE4, proto, hdr, &body);
        let (verdict, v6) = out_native(PEER, &packet);
        assert_eq!(verdict, Verdict::Accept, "{proto}");
        assert_eq!(v6.len(), packet.len() + 20);
        check_v6(&v6);
        assert_eq!((src6(&v6), dst6(&v6)), (self_node4(), node6()));
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
        NATIVE4,
        protocol::UDP,
        &udp4(src, NATIVE4, b"x", false),
    );
    let (verdict, v6) = out_native(PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v6(&v6);
    assert_eq!((src6(&v6), dst6(&v6)), (ip6("fd64:1::c0a8:114"), node6()));
}

#[test]
fn inbound_node6_to_self_node4_becomes_ipv4_from_the_native_alias() {
    let (src, dst) = (node6(), self_node4());
    for (proto, body) in [
        (protocol::TCP, tcp6(src, dst, b"tcp")),
        (protocol::UDP, udp6(src, dst, b"udp")),
        (protocol::ICMPV6, echo6(src, dst, true, b"pong")),
    ] {
        let packet = ipv6(src, dst, proto, 9, 0x2e, &[], &body);
        let (verdict, v4) = in_native(PEER, &packet);
        assert_eq!(verdict, Verdict::Accept, "{proto}");
        assert_eq!(v4.len(), packet.len() - 20);
        check_v4(&v4);
        assert_eq!((src4(&v4), dst4(&v4)), (NATIVE4, SELF4));
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
    let (verdict, v4) = in_native(PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v4(&v4);
    assert_eq!((src4(&v4), dst4(&v4)), (NATIVE4, ip4("192.168.1.20")));
}

#[test]
fn icmp_errors_quoting_native_alias_packets_are_translated() {
    // Outbound: this node reports an error for a packet from the native alias.
    let body = udp4(NATIVE4, SELF4, b"quoted", false);
    let hdr = Hdr4 {
        ttl: 37,
        ..Hdr4::default()
    };
    let quoted = ipv4(NATIVE4, SELF4, protocol::UDP, hdr, &body);
    let error = icmp4_error(3, 3, [0; 4], &quoted);
    let packet = ipv4_simple(SELF4, NATIVE4, protocol::ICMP, &error);
    let (verdict, v6) = out_native(PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v6(&v6);
    assert_eq!((v6[40], v6[41]), (1, 4), "port unreachable");
    let quote = &v6[48..];
    assert_eq!((src6(quote), dst6(quote)), (node6(), self_node4()));
    assert_eq!(quote[7], 37, "the quoted hop limit is not decremented");
    assert_eq!(
        transport_checksum_v6(node6(), self_node4(), protocol::UDP, &quote[40..]),
        0
    );

    // Inbound: the peer reports an error for a packet this node sent to the
    // native alias.
    let body = udp6(self_node4(), node6(), b"quoted");
    let quoted = ipv6(self_node4(), node6(), protocol::UDP, 37, 0, &[], &body);
    let error = icmp6_error(node6(), self_node4(), 1, 4, [0; 4], &quoted);
    let packet = ipv6_simple(node6(), self_node4(), protocol::ICMPV6, &error);
    let (verdict, v4) = in_native(PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v4(&v4);
    assert_eq!((src4(&v4), dst4(&v4)), (NATIVE4, SELF4));
    assert_eq!((v4[20], v4[21]), (3, 3), "port unreachable");
    let quote = &v4[28..];
    assert_eq!((src4(quote), dst4(quote)), (SELF4, NATIVE4));
    assert_eq!(quote[8], 37, "the quoted TTL is not decremented");
    assert_eq!(internet_checksum(&quote[..20]), 0);
    assert_eq!(
        transport_checksum_v4(SELF4, NATIVE4, protocol::UDP, &quote[20..]),
        0
    );
}

#[test]
fn native_alias_fragments_are_translated_both_ways() {
    // Outbound: a checksummed UDP datagram in three IPv4 fragments.
    let translator = native_translator();
    let udp = udp4(SELF4, NATIVE4, b"abcdefghijklmnopqrstuvwx", false);
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
        let piece = ipv4(SELF4, NATIVE4, protocol::UDP, hdr, bytes);
        let (verdict, v6) = outbound(&translator, PEER, &piece);
        assert_eq!(verdict, Verdict::Accept, "fragment {index}");
        assert_eq!(check_v6(&v6), 48);
        assert_eq!((src6(&v6), dst6(&v6)), (self_node4(), node6()));
        assert_eq!(&v6[44..48], &300_u32.to_be_bytes());
        joined.extend_from_slice(&v6[48..]);
    }
    assert_eq!(
        transport_checksum_v6(self_node4(), node6(), protocol::UDP, &joined),
        0
    );

    // Inbound: a UDP datagram in two IPv6 fragments.
    let (src, dst) = (node6(), self_node4());
    let udp = udp6(src, dst, b"abcdefghijklmnopqrstuvwx");
    let mut joined = Vec::new();
    for (offset, more, bytes) in [(0_u16, true, &udp[..16]), (2, false, &udp[16..])] {
        let bits = (offset << 3) | u16::from(more);
        let mut extension = vec![44, protocol::UDP, 0];
        extension.extend_from_slice(&bits.to_be_bytes());
        extension.extend_from_slice(&0x0102_abcd_u32.to_be_bytes());
        let packet = ipv6(src, dst, protocol::UDP, 64, 0, &extension, bytes);
        let (verdict, v4) = in_native(PEER, &packet);
        assert_eq!(verdict, Verdict::Accept);
        check_v4(&v4);
        assert_eq!((src4(&v4), dst4(&v4)), (NATIVE4, SELF4));
        assert_eq!(&v4[4..6], &0xabcd_u16.to_be_bytes());
        joined.extend_from_slice(&v4[20..]);
    }
    assert_eq!(
        transport_checksum_v4(NATIVE4, SELF4, protocol::UDP, &joined),
        0
    );
}

#[test]
fn a_native_alias_source_is_a_spoof() {
    for src in [NATIVE4, OTHER_NATIVE4] {
        let packet = ipv4_simple(src, SELF4, protocol::UDP, &udp4(src, SELF4, b"x", false));
        assert_eq!(
            in_native(PEER, &packet).0,
            dropped(reasons::SPOOFED_SOURCE),
            "{src}"
        );
    }
}

#[test]
fn a_native_alias_of_another_peer_is_dropped() {
    // Outbound: routed to PEER, addressed to OTHER's native alias.
    let packet = ipv4_simple(
        SELF4,
        OTHER_NATIVE4,
        protocol::UDP,
        &udp4(SELF4, OTHER_NATIVE4, b"x", false),
    );
    assert_eq!(out_native(PEER, &packet).0, dropped(reasons::PEER_MISMATCH));
    // Inbound: PEER's node6 arriving from OTHER.
    let (src, dst) = (node6(), self_node4());
    let packet = ipv6_simple(src, dst, protocol::UDP, &udp6(src, dst, b"x"));
    assert_eq!(in_native(OTHER, &packet).0, dropped(reasons::PEER_MISMATCH));
    // An unmapped source is still refused.
    let packet = ipv4_simple(
        ip4("198.51.100.7"),
        NATIVE4,
        protocol::UDP,
        &udp4(ip4("198.51.100.7"), NATIVE4, b"x", false),
    );
    assert_eq!(out_native(PEER, &packet).0, dropped(reasons::UNMAPPED));
}

#[test]
fn native_alias_coexists_with_alias4_and_alias6() {
    let translator = native_translator();
    let mapping = peer_mapping();
    let alias6 = mapping.alias6.unwrap();
    let own6 = ip6("fd00::ff:0");

    // alias4 still goes to node4, the native alias to node6.
    for (dst, expected) in [(ALIAS4, mapping.node4), (NATIVE4, mapping.node6)] {
        let packet = ipv4_simple(SELF4, dst, protocol::UDP, &udp4(SELF4, dst, b"x", false));
        let (verdict, v6) = outbound(&translator, PEER, &packet);
        assert_eq!(verdict, Verdict::Accept, "{dst}");
        check_v6(&v6);
        assert_eq!(dst6(&v6), expected);
    }
    // IPv6 to alias6 is still rewritten to node6 and stays IPv6.
    let packet = ipv6_simple(own6, alias6, protocol::UDP, &udp6(own6, alias6, b"x"));
    let (verdict, v6) = outbound(&translator, PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v6(&v6);
    assert_eq!(
        (src6(&v6), dst6(&v6), v6.len()),
        (own6, mapping.node6, packet.len())
    );

    // Inbound: node4 -> self node4 comes from alias4, node6 -> self node4
    // from the native alias, node6 -> self node6 is rewritten to alias6.
    for (src, expected) in [(mapping.node4, ALIAS4), (mapping.node6, NATIVE4)] {
        let packet = ipv6_simple(
            src,
            self_node4(),
            protocol::UDP,
            &udp6(src, self_node4(), b"x"),
        );
        let (verdict, v4) = inbound(&translator, PEER, &packet);
        assert_eq!(verdict, Verdict::Accept, "{src}");
        check_v4(&v4);
        assert_eq!((src4(&v4), dst4(&v4)), (expected, SELF4));
    }
    let src = mapping.node6;
    let packet = ipv6_simple(src, own6, protocol::TCP, &tcp6(src, own6, b"x"));
    let (verdict, v6) = inbound(&translator, PEER, &packet);
    assert_eq!(verdict, Verdict::Accept);
    check_v6(&v6);
    assert_eq!((src6(&v6), dst6(&v6)), (alias6, own6));

    let stats = translator.stats();
    assert_eq!((stats.translated_out, stats.rewritten_out), (2, 1));
    assert_eq!((stats.translated_in, stats.rewritten_in), (2, 1));
}

#[test]
fn the_predicate_covers_native_aliases() {
    let translator = native_translator();
    let translated = translator.ipv4_translated_predicate();
    for addr in [NATIVE4, OTHER_NATIVE4, ALIAS4] {
        assert!(translated(addr), "{addr}");
    }
    assert!(!translated(SELF4));
    translator.store(table());
    assert!(!translated(NATIVE4));
}
