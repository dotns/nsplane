//! Ported ns translation tests and RFC 7915 vectors, run through the filter.
//!
//! Outbound packets go from this node (`SELF4`) to `PEER` (`ALIAS4`); inbound
//! packets come from `PEER`'s `node4` to the self `node4`. ICMP errors quote
//! a packet of the reverse direction.

use super::*;

fn peer_node4() -> Ipv6Addr {
    peer_mapping().node4
}

/// An inbound IPv6 packet from `PEER`'s `node4` to the self `node4`.
fn inbound6(proto: u8, hop: u8, tc: u8, extensions: &[u8], body: &[u8]) -> Vec<u8> {
    ipv6(peer_node4(), self_node4(), proto, hop, tc, extensions, body)
}

fn udp_out(payload: &[u8]) -> Vec<u8> {
    udp4(SELF4, ALIAS4, payload, false)
}

fn udp_in(payload: &[u8]) -> Vec<u8> {
    udp6(peer_node4(), self_node4(), payload)
}

#[test]
fn tcp_vector_v4_to_v6() {
    // ns `translates_tcp_v4_to_v6_with_exact_mapping`.
    let hdr = Hdr4 {
        tos: 0x03,
        id: 0x1234,
        ..Hdr4::default()
    };
    let packet = ipv4(
        SELF4,
        ALIAS4,
        protocol::TCP,
        hdr,
        &tcp4(SELF4, ALIAS4, b"odd!"),
    );
    let v6 = out_ok(&packet);
    assert_eq!(v6.len(), 64);
    check_v6(&v6);
    assert_eq!(v6[0] >> 4, 6);
    assert_eq!(v6[1] & 0x30, 0x30);
    assert_eq!((v6[6], v6[7]), (protocol::TCP, 63));
    assert_eq!(&v6[60..], b"odd!");
}

#[test]
fn tcp_and_udp_round_trip_with_valid_checksums() {
    for proto in [protocol::TCP, protocol::UDP] {
        let body = if proto == protocol::TCP {
            tcp4(SELF4, ALIAS4, b"odd")
        } else {
            udp_out(b"odd")
        };
        let hdr = Hdr4 {
            ttl: 255,
            tos: 0xeb,
            id: 7,
            ..Hdr4::default()
        };
        let v6 = out_ok(&ipv4(SELF4, ALIAS4, proto, hdr, &body));
        assert_eq!(v6[7], 254);
        check_v6(&v6);

        let back = if proto == protocol::TCP {
            tcp6(peer_node4(), self_node4(), b"odd")
        } else {
            udp_in(b"odd")
        };
        let v4 = in_ok(&inbound6(proto, 64, 0, &[], &back));
        assert_eq!((src4(&v4), dst4(&v4)), (ALIAS4, SELF4));
        check_v4(&v4);
    }
}

#[test]
fn echo_both_directions_preserves_odd_payload() {
    let hdr = Hdr4 {
        ttl: 3,
        tos: 3,
        id: 9,
        ..Hdr4::default()
    };
    let v6 = out_ok(&ipv4(
        SELF4,
        ALIAS4,
        protocol::ICMP,
        hdr,
        &echo4(false, b"abc"),
    ));
    assert_eq!((v6[6], v6[7], v6[40]), (protocol::ICMPV6, 2, 128));
    check_v6(&v6);
    assert_eq!(&v6[48..], b"abc");

    for (reply, kind) in [(false, 8), (true, 0)] {
        let echo = echo6(peer_node4(), self_node4(), reply, b"abc");
        let v4 = in_ok(&inbound6(protocol::ICMPV6, 64, 0, &[], &echo));
        assert_eq!((v4[9], v4[20]), (protocol::ICMP, kind));
        check_v4(&v4);
        assert_eq!(&v4[28..], b"abc");
    }
    let reply = out_ok(&ipv4_simple(
        SELF4,
        ALIAS4,
        protocol::ICMP,
        &echo4(true, b""),
    ));
    assert_eq!(reply[40], 129);
    check_v6(&reply);
}

#[test]
fn ipv4_options_are_dropped_and_traffic_class_kept() {
    let udp = udp_out(b"z");
    let hdr = Hdr4 {
        tos: 0xa7,
        options: &[1, 1, 0, 0],
        ..Hdr4::default()
    };
    let packet = ipv4(SELF4, ALIAS4, protocol::UDP, hdr, &udp);
    let v6 = out_ok(&packet);
    assert_eq!(v6.len(), packet.len() - 24 + 40);
    assert_eq!((traffic_class(&v6), v6[7]), (0xa7, 63));
    check_v6(&v6);
}

#[test]
fn ipv6_extension_headers_are_skipped() {
    let extensions = [0_u8, 60, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0];
    let packet = inbound6(protocol::UDP, 64, 0xa7, &extensions, &udp_in(b"z"));
    let v4 = in_ok(&packet);
    assert_eq!((v4[1], v4[8], v4[9]), (0xa7, 63, protocol::UDP));
    assert_eq!(v4.len(), packet.len() - 40 - 16 + 20);
    check_v4(&v4);
}

#[test]
fn fails_closed_on_hops_lengths_checksums_protocols_and_source_routes() {
    let udp = udp_out(b"abc");
    for ttl in [0, 1] {
        let hdr = Hdr4 {
            ttl,
            ..Hdr4::default()
        };
        let packet = ipv4(SELF4, ALIAS4, protocol::UDP, hdr, &udp);
        assert_eq!(out_drop(&packet), reasons::HOP_LIMIT_EXCEEDED);
    }
    for hop in [0, 1] {
        let packet = inbound6(protocol::UDP, hop, 0, &[], &udp_in(b"abc"));
        assert_eq!(in_drop(&packet), reasons::HOP_LIMIT_EXCEEDED);
    }
    let mut trailing = ipv4_simple(SELF4, ALIAS4, protocol::UDP, &udp);
    trailing.push(0);
    assert_eq!(out_drop(&trailing), reasons::LENGTH_MISMATCH);

    let mut tampered = ipv4_simple(SELF4, ALIAS4, protocol::UDP, &udp);
    tampered[28] ^= 1;
    assert_eq!(out_drop(&tampered), reasons::INVALID_CHECKSUM);

    let mut header = ipv4_simple(SELF4, ALIAS4, protocol::UDP, &udp);
    header[1] ^= 1;
    assert_eq!(out_drop(&header), reasons::INVALID_CHECKSUM);

    let unsupported = ipv4_simple(SELF4, ALIAS4, 99, b"x");
    assert_eq!(out_drop(&unsupported), reasons::UNSUPPORTED_PROTOCOL);
    let unsupported = inbound6(99, 64, 0, &[], b"x");
    assert_eq!(in_drop(&unsupported), reasons::UNSUPPORTED_PROTOCOL);

    let routed = Hdr4 {
        options: &[131, 7, 4, 1, 2, 3, 4, 0],
        ..Hdr4::default()
    };
    let packet = ipv4(SELF4, ALIAS4, protocol::UDP, routed, &udp);
    assert_eq!(out_drop(&packet), reasons::SOURCE_ROUTE);
    let exhausted = Hdr4 {
        options: &[131, 7, 8, 1, 2, 3, 4, 0],
        ..Hdr4::default()
    };
    out_ok(&ipv4(SELF4, ALIAS4, protocol::UDP, exhausted, &udp));

    let mut reserved = ipv4_simple(SELF4, ALIAS4, protocol::UDP, &udp);
    reserved[6] |= 0x80;
    let checksum = internet_checksum(&{
        let mut header = reserved[..20].to_vec();
        header[10..12].fill(0);
        header
    });
    reserved[10..12].copy_from_slice(&checksum.to_be_bytes());
    assert_eq!(out_drop(&reserved), reasons::MALFORMED);
}

#[test]
fn illegal_addresses_are_refused() {
    let table = TranslationTable::builder()
        .peer(PEER, peer_mapping())
        .lan(LanPrefix {
            lan4: (Ipv4Addr::new(127, 0, 0, 0), 8),
            lan6: (ip6("fd64:7f::"), 96),
            peer: None,
        })
        .build()
        .unwrap();
    let src = Ipv4Addr::LOCALHOST;
    let packet = ipv4_simple(src, ALIAS4, protocol::UDP, &udp4(src, ALIAS4, b"x", false));
    let (verdict, _) = outbound(&Translator::new(table), PEER, &packet);
    assert_eq!(
        verdict,
        Verdict::Drop {
            reason: reasons::ILLEGAL_ADDRESS
        }
    );
}

#[test]
fn ipv6_to_ipv4_sets_df_only_above_1260_bytes() {
    for (payload_len, df) in [(1232_usize, 0_u16), (1233, 0x4000)] {
        let packet = inbound6(protocol::UDP, 64, 0, &[], &udp_in(&vec![0x3c; payload_len]));
        let v4 = in_ok(&packet);
        check_v4(&v4);
        assert_eq!(u16::from_be_bytes([v4[6], v4[7]]) & 0x4000, df);
    }
}

#[test]
fn rejects_ipv6_zero_udp_checksum_active_routing_and_trailing_bytes() {
    let mut zero = udp_in(b"x");
    zero[6..8].fill(0);
    assert_eq!(
        in_drop(&inbound6(protocol::UDP, 64, 0, &[], &zero)),
        reasons::INVALID_CHECKSUM
    );
    let routing = [43_u8, 17, 0, 0, 1, 0, 0, 0, 0];
    assert_eq!(
        in_drop(&inbound6(protocol::UDP, 64, 0, &routing, &udp_in(b"x"))),
        reasons::ACTIVE_ROUTING_HEADER
    );
    let exhausted = [43_u8, 17, 0, 0, 0, 0, 0, 0, 0];
    in_ok(&inbound6(protocol::UDP, 64, 0, &exhausted, &udp_in(b"x")));
    let mut trailing = inbound6(protocol::UDP, 64, 0, &[], &udp_in(b"x"));
    trailing.push(0);
    assert_eq!(in_drop(&trailing), reasons::LENGTH_MISMATCH);
    let mut tampered = inbound6(protocol::UDP, 64, 0, &[], &udp_in(b"x"));
    tampered[48] ^= 1;
    assert_eq!(in_drop(&tampered), reasons::INVALID_CHECKSUM);
    let esp = inbound6(50, 64, 0, &[], &[0; 16]);
    assert_eq!(in_drop(&esp), reasons::UNSUPPORTED_PROTOCOL);
}

#[test]
fn udp_zero_result_is_sent_as_all_ones() {
    let segment = (0_u16..=u16::MAX)
        .map(|word| udp_out(&word.to_be_bytes()))
        .find(|segment| {
            let mut zeroed = segment.clone();
            zeroed[6..8].fill(0);
            transport_checksum_v6(self_node4(), peer_node4(), protocol::UDP, &zeroed) == 0
        })
        .unwrap();
    let packet = ipv4_simple(SELF4, ALIAS4, protocol::UDP, &segment);
    let v6 = out_ok(&packet);
    assert_eq!(&v6[46..48], &[0xff, 0xff]);
    check_v6(&v6);

    let mut tampered = packet;
    tampered[20] ^= 1;
    assert_eq!(out_drop(&tampered), reasons::INVALID_CHECKSUM);
}

#[test]
fn unfragmented_udp_without_checksum_gets_one() {
    let packet = ipv4_simple(
        SELF4,
        ALIAS4,
        protocol::UDP,
        &udp4(SELF4, ALIAS4, b"no checksum", true),
    );
    let v6 = out_ok(&packet);
    assert_ne!(&v6[46..48], &[0, 0]);
    check_v6(&v6);
}

/// A UDP packet from `PEER` (as seen locally) to this node, quoted in an
/// outbound ICMP error.
fn quoted_v4(ttl: u8) -> Vec<u8> {
    let hdr = Hdr4 {
        ttl,
        id: 7,
        ..Hdr4::default()
    };
    ipv4(
        ALIAS4,
        SELF4,
        protocol::UDP,
        hdr,
        &udp4(ALIAS4, SELF4, b"quote", false),
    )
}

/// A UDP packet from this node to `PEER`, quoted in an inbound `ICMPv6` error.
fn quoted_v6(hop: u8) -> Vec<u8> {
    let udp = udp6(self_node4(), peer_node4(), b"quote");
    ipv6(self_node4(), peer_node4(), protocol::UDP, hop, 0, &[], &udp)
}

#[test]
fn every_supported_icmpv4_error_and_its_quote() {
    let cases = [
        (3, 0, 1, 0),
        (3, 1, 1, 0),
        (3, 2, 4, 1),
        (3, 3, 1, 4),
        (3, 4, 2, 0),
        (3, 5, 1, 0),
        (3, 6, 1, 0),
        (3, 7, 1, 0),
        (3, 8, 1, 0),
        (3, 9, 1, 1),
        (3, 10, 1, 1),
        (3, 11, 1, 0),
        (3, 12, 1, 0),
        (3, 13, 1, 1),
        (3, 15, 1, 1),
        (11, 0, 3, 0),
        (11, 1, 3, 1),
        (12, 0, 4, 0),
        (12, 2, 4, 0),
    ];
    for (kind, code, kind6, code6) in cases {
        let rest = match (kind, code) {
            (3, 4) => [0, 0, 5, 120],
            (12, _) => [8, 0, 0, 0],
            _ => [0; 4],
        };
        let error = icmp4_error(kind, code, rest, &quoted_v4(37));
        let packet = ipv4_simple(SELF4, ALIAS4, protocol::ICMP, &error);
        let v6 = out_ok(&packet);
        check_v6(&v6);
        assert_eq!((v6[6], v6[40], v6[41]), (protocol::ICMPV6, kind6, code6));
        assert_eq!(v6.len(), packet.len() + 40, "outer and quoted header grow");
        let quote = &v6[48..];
        assert_eq!(quote[7], 37, "the quoted hop limit is not decremented");
        assert_eq!((src6(quote), dst6(quote)), (peer_node4(), self_node4()));
        assert_eq!(
            usize::from(u16::from_be_bytes([quote[4], quote[5]])),
            quote.len() - 40
        );
        assert_eq!(
            transport_checksum_v6(peer_node4(), self_node4(), protocol::UDP, &quote[40..]),
            0
        );
        let rest6 = u32::from_be_bytes([v6[44], v6[45], v6[46], v6[47]]);
        match (kind, code) {
            (3, 4) => assert_eq!(rest6, 1420, "MTU grows by 20"),
            (3, 2) => assert_eq!(rest6, 6, "points at the next header"),
            (12, _) => assert_eq!(rest6, 7, "TTL pointer maps to the hop limit"),
            _ => {}
        }
    }
}

#[test]
fn every_supported_icmpv6_error_and_its_quote() {
    let cases = [
        (1, 0, [0; 4], 3, 1),
        (1, 1, [0; 4], 3, 10),
        (1, 2, [0; 4], 3, 1),
        (1, 3, [0; 4], 3, 1),
        (1, 4, [0; 4], 3, 3),
        (2, 0, 1300_u32.to_be_bytes(), 3, 4),
        (3, 0, [0; 4], 11, 0),
        (3, 1, [0; 4], 11, 1),
        (4, 1, [0; 4], 3, 2),
        (4, 0, 7_u32.to_be_bytes(), 12, 0),
    ];
    for (kind, code, rest, kind4, code4) in cases {
        let error = icmp6_error(peer_node4(), self_node4(), kind, code, rest, &quoted_v6(37));
        let packet = inbound6(protocol::ICMPV6, 64, 0, &[], &error);
        let v4 = in_ok(&packet);
        check_v4(&v4);
        assert_eq!((v4[9], v4[20], v4[21]), (protocol::ICMP, kind4, code4));
        assert_eq!(v4.len(), packet.len() - 40);
        let quote = &v4[28..];
        assert_eq!(quote[8], 37, "the quoted TTL is not decremented");
        assert_eq!((src4(quote), dst4(quote)), (SELF4, ALIAS4));
        assert_eq!(internet_checksum(&quote[..20]), 0);
        assert_eq!(
            transport_checksum_v4(SELF4, ALIAS4, protocol::UDP, &quote[20..]),
            0
        );
        match kind {
            2 => assert_eq!(
                u16::from_be_bytes([v4[26], v4[27]]),
                1280,
                "MTU shrinks by 20"
            ),
            4 if code == 0 => assert_eq!(v4[24], 8, "hop limit pointer maps to the TTL"),
            _ => {}
        }
    }
}

#[test]
fn icmp_errors_quoting_echo_translate_the_quoted_echo() {
    // Time exceeded about a ping the peer sent (as traceroute sees it).
    let echo = ipv4_simple(ALIAS4, SELF4, protocol::ICMP, &echo4(false, b"probe"));
    let error = icmp4_error(11, 0, [0; 4], &echo);
    let v6 = out_ok(&ipv4_simple(SELF4, ALIAS4, protocol::ICMP, &error));
    check_v6(&v6);
    let quote = &v6[48..];
    assert_eq!((quote[6], quote[40]), (protocol::ICMPV6, 128));
    assert_eq!(
        transport_checksum_v6(peer_node4(), self_node4(), protocol::ICMPV6, &quote[40..]),
        0
    );

    let echo6 = echo6(self_node4(), peer_node4(), false, b"probe");
    let quoted = ipv6_simple(self_node4(), peer_node4(), protocol::ICMPV6, &echo6);
    let error = icmp6_error(peer_node4(), self_node4(), 3, 0, [0; 4], &quoted);
    let v4 = in_ok(&inbound6(protocol::ICMPV6, 64, 0, &[], &error));
    check_v4(&v4);
    let quote = &v4[28..];
    assert_eq!((quote[9], quote[20]), (protocol::ICMP, 8));
    assert_eq!(internet_checksum(&quote[20..]), 0);
}

#[test]
fn icmp_error_failures() {
    // A quote whose addresses are not in the table.
    let stranger = Ipv4Addr::new(100, 64, 9, 9);
    let hdr = Hdr4::default();
    let quote = ipv4(
        stranger,
        SELF4,
        protocol::UDP,
        hdr,
        &udp4(stranger, SELF4, b"x", false),
    );
    let error = icmp4_error(3, 3, [0; 4], &quote);
    assert_eq!(
        out_drop(&ipv4_simple(SELF4, ALIAS4, protocol::ICMP, &error)),
        reasons::UNMAPPED
    );
    // A truncated quote.
    let error = icmp4_error(3, 3, [0; 4], &[0; 12]);
    assert_eq!(
        out_drop(&ipv4_simple(SELF4, ALIAS4, protocol::ICMP, &error)),
        reasons::MALFORMED
    );
    // Redirect has no translation.
    let error = icmp4_error(5, 0, [0; 4], &[]);
    assert_eq!(
        out_drop(&ipv4_simple(SELF4, ALIAS4, protocol::ICMP, &error)),
        reasons::UNSUPPORTED_ICMP
    );
    // An error about an error.
    let inner = ipv4_simple(
        ALIAS4,
        SELF4,
        protocol::ICMP,
        &icmp4_error(3, 3, [0; 4], &[]),
    );
    let error = icmp4_error(3, 3, [0; 4], &inner);
    assert_eq!(
        out_drop(&ipv4_simple(SELF4, ALIAS4, protocol::ICMP, &error)),
        reasons::UNSUPPORTED_ICMP
    );
    // A bad ICMP checksum.
    let mut tampered = ipv4_simple(
        SELF4,
        ALIAS4,
        protocol::ICMP,
        &icmp4_error(3, 3, [0; 4], &quoted_v4(64)),
    );
    tampered[28] ^= 1;
    assert_eq!(out_drop(&tampered), reasons::INVALID_CHECKSUM);
    // An unknown ICMPv6 type and a bad ICMPv6 checksum.
    let unknown = icmp6_error(peer_node4(), self_node4(), 137, 0, [0; 4], &[]);
    assert_eq!(
        in_drop(&inbound6(protocol::ICMPV6, 64, 0, &[], &unknown)),
        reasons::UNSUPPORTED_ICMP
    );
    let mut bad = inbound6(
        protocol::ICMPV6,
        64,
        0,
        &[],
        &echo6(peer_node4(), self_node4(), false, b"x"),
    );
    bad[44] ^= 1;
    assert_eq!(in_drop(&bad), reasons::INVALID_CHECKSUM);
}

#[test]
fn fragment_fields_convert_in_both_directions() {
    // ns `converts_fragment_offset_more_flag_and_identification_in_both_directions`.
    let tcp = tcp4(SELF4, ALIAS4, b"12345678");
    let hdr = Hdr4 {
        id: 0xabcd,
        fragment: 0x2000,
        ..Hdr4::default()
    };
    let v6 = out_ok(&ipv4(SELF4, ALIAS4, protocol::TCP, hdr, &tcp[..24]));
    assert_eq!(check_v6(&v6), 48);
    assert_eq!(
        (v6[6], v6[40], u16::from_be_bytes([v6[42], v6[43]])),
        (44, protocol::TCP, 1)
    );
    assert_eq!(u32::from_be_bytes([v6[44], v6[45], v6[46], v6[47]]), 0xabcd);

    let tcp6 = tcp6(peer_node4(), self_node4(), b"12345678");
    let mut extension = vec![44, protocol::TCP, 0, 0, 1];
    extension.extend_from_slice(&0xabcd_u32.to_be_bytes());
    let v4 = in_ok(&inbound6(protocol::TCP, 64, 0, &extension, &tcp6[..24]));
    check_v4(&v4);
    assert_eq!(u16::from_be_bytes([v4[4], v4[5]]), 0xabcd);
    assert_eq!(u16::from_be_bytes([v4[6], v4[7]]), 0x2000);
}

#[test]
fn fragmented_icmp_and_bad_fragments_are_dropped() {
    let hdr = Hdr4 {
        fragment: 0x2000,
        ..Hdr4::default()
    };
    let fragmented = ipv4(
        SELF4,
        ALIAS4,
        protocol::ICMP,
        hdr,
        &echo4(false, b"12345678"),
    );
    assert_eq!(out_drop(&fragmented), reasons::FRAGMENTED_ICMP);
    let mut extension = vec![44, protocol::ICMPV6, 0, 0, 1];
    extension.extend_from_slice(&1_u32.to_be_bytes());
    let echo = echo6(peer_node4(), self_node4(), false, b"12345678");
    assert_eq!(
        in_drop(&inbound6(protocol::ICMPV6, 64, 0, &extension, &echo)),
        reasons::FRAGMENTED_ICMP
    );

    let tiny = ipv4(SELF4, ALIAS4, protocol::UDP, hdr, &[0; 4]);
    assert_eq!(out_drop(&tiny), reasons::TINY_FRAGMENT);

    // A non-final fragment that is not a multiple of 8 bytes, while reassembling.
    let translator = translator();
    let udp = udp4(SELF4, ALIAS4, b"abcdefghijklmnop", true);
    let first = ipv4(SELF4, ALIAS4, protocol::UDP, hdr, &udp[..16]);
    assert_eq!(outbound(&translator, PEER, &first).0, Verdict::Handled);
    let odd = Hdr4 {
        fragment: 0x2002,
        ..hdr
    };
    let middle = ipv4(SELF4, ALIAS4, protocol::UDP, odd, &udp[16..23]);
    assert_eq!(
        outbound(&translator, PEER, &middle).0,
        Verdict::Drop {
            reason: reasons::MALFORMED_FRAGMENT
        }
    );
}

#[test]
fn icmpv6_errors_through_alias6_rewrite_their_quote() {
    let (own, alias6, node6) = (
        ip6("fd00::ff:0"),
        peer_mapping().alias6.unwrap(),
        peer_mapping().node6,
    );
    // Outbound: port unreachable about a datagram the peer sent to us.
    let quote = ipv6_simple(alias6, own, protocol::UDP, &udp6(alias6, own, b"quote"));
    let error = icmp6_error(own, alias6, 1, 4, [0; 4], &quote);
    let v6 = out_ok(&ipv6_simple(own, alias6, protocol::ICMPV6, &error));
    check_v6(&v6);
    assert_eq!(dst6(&v6), node6);
    let inner = &v6[48..];
    assert_eq!((src6(inner), dst6(inner)), (node6, own));
    assert_eq!(
        transport_checksum_v6(node6, own, protocol::UDP, &inner[40..]),
        0
    );

    // Inbound: the peer reports an error about a datagram we sent to it.
    let quote = ipv6_simple(own, node6, protocol::UDP, &udp6(own, node6, b"quote"));
    let error = icmp6_error(node6, own, 3, 0, [0; 4], &quote);
    let v6 = in_ok(&ipv6_simple(node6, own, protocol::ICMPV6, &error));
    check_v6(&v6);
    assert_eq!(src6(&v6), alias6);
    let inner = &v6[48..];
    assert_eq!((src6(inner), dst6(inner)), (own, alias6));
    assert_eq!(
        transport_checksum_v6(own, alias6, protocol::UDP, &inner[40..]),
        0
    );
}

#[test]
fn malformed_matrix_never_panics_and_keeps_lengths_consistent() {
    // ns `deterministic_malformed_matrix_never_panics_or_emits_inconsistent_lengths`.
    let valid4 = ipv4_simple(SELF4, ALIAS4, protocol::UDP, &udp_out(b"matrix"));
    let valid6 = inbound6(protocol::UDP, 64, 0, &[], &udp_in(b"matrix"));
    let mutations = |valid: &[u8]| {
        let mut cases: Vec<Vec<u8>> = (0..=valid.len()).map(|len| valid[..len].to_vec()).collect();
        for index in 0..valid.len() {
            for mask in [0x01, 0x5a, 0xa5, 0xff] {
                let mut changed = valid.to_vec();
                changed[index] ^= mask;
                cases.push(changed);
            }
        }
        cases
    };
    let translator = translator();
    for packet in mutations(&valid4) {
        let (verdict, out) = outbound(&translator, PEER, &packet);
        if verdict == Verdict::Accept && out != packet {
            check_v6(&out);
        }
    }
    for packet in mutations(&valid6) {
        let (verdict, out) = inbound(&translator, PEER, &packet);
        if verdict == Verdict::Accept && out != packet && out.first() == Some(&0x45) {
            check_v4(&out);
        }
    }
}
