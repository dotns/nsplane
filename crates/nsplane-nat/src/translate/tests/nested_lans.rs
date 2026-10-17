//! Nested LAN prefixes (`TranslationTableBuilder::nested_lans`) through
//! every translator site that looks a LAN address up.
//!
//! The strict input has `PEER`'s LAN `10.1.0.0/16 <-> fd64:2::/96` and the
//! local LAN `192.168.1.0/24 <-> fd64:1::/96`, with `PEER`'s `peer6_eam4`.
//! The nested input adds `OTHER`'s `0.0.0.0/0 <-> fd64:9::/96`, which holds
//! every other address (the exact addresses included), and `PEER`'s
//! `192.168.1.128/25 <-> fd64:4::/96` inside the local LAN. Each case runs
//! on the nested table and, where the strict input gives the same answer,
//! on the strict table and on the strict input with nesting on.

use super::*;

const PEER6_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 50);

fn strict_builder() -> crate::TranslationTableBuilder {
    TranslationTable::builder()
        .peer_with_peer6_eam4(PEER, peer_mapping(), PEER6_EAM4)
        .peer(OTHER, other_mapping())
        .self_mapping(SelfMapping {
            eam4: SELF_EAM4,
            eam6: self_eam6(),
        })
        .lan(lan("10.1.0.0", 16, "fd64:2::", Some(PEER)))
        .lan(lan("192.168.1.0", 24, "fd64:1::", None))
}

fn nested() -> Translator {
    let table = strict_builder()
        .nested_lans()
        .lan(lan("0.0.0.0", 0, "fd64:9::", Some(OTHER)))
        .lan(lan("192.168.1.128", 25, "fd64:4::", Some(PEER)))
        .build()
        .unwrap();
    Translator::new(table)
}

/// The strict table and the strict input with nesting on.
fn stricts() -> [Translator; 2] {
    [
        Translator::new(strict_builder().build().unwrap()),
        Translator::new(strict_builder().nested_lans().build().unwrap()),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Pass,
    Drop(&'static str),
    V6(Ipv6Addr, Ipv6Addr),
    V4(Ipv4Addr, Ipv4Addr),
}

use Outcome::{Drop, Pass, V4, V6};

#[derive(Debug, Clone, Copy)]
enum Dir {
    Out,
    In,
}

/// Runs `bytes` through `translator`; returns the outcome and the packet.
fn run(translator: &Translator, dir: Dir, peer: PeerId, bytes: &[u8]) -> (Outcome, Vec<u8>) {
    let (verdict, packet) = match dir {
        Dir::Out => outbound(translator, peer, bytes),
        Dir::In => inbound(translator, peer, bytes),
    };
    let outcome = match verdict {
        Verdict::Drop { reason } => Drop(reason),
        Verdict::Accept if packet == bytes => Pass,
        Verdict::Accept if packet[0] >> 4 == 6 => {
            check_v6(&packet);
            V6(src6(&packet), dst6(&packet))
        }
        Verdict::Accept => {
            check_v4(&packet);
            V4(src4(&packet), dst4(&packet))
        }
        Verdict::Handled => panic!("unexpected {verdict:?}"),
    };
    (outcome, packet)
}

/// Checks `bytes` on the nested table and, with `strict`, on both strict
/// translators; returns the nested and (if any) strict packets.
fn case(
    dir: Dir,
    peer: PeerId,
    bytes: &[u8],
    nested_expected: Outcome,
    strict: Option<Outcome>,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let (outcome, packet) = run(&nested(), dir, peer, bytes);
    assert_eq!(outcome, nested_expected, "nested");
    let mut stricts_out = Vec::new();
    if let Some(expected) = strict {
        for (index, translator) in stricts().iter().enumerate() {
            let (outcome, packet) = run(translator, dir, peer, bytes);
            assert_eq!(outcome, expected, "strict {index}");
            stricts_out.push(packet);
        }
    }
    (packet, stricts_out)
}

fn udp_v4(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    ipv4_simple(src, dst, protocol::UDP, &udp4(src, dst, b"x", false))
}

fn udp_v6(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    ipv6_simple(src, dst, protocol::UDP, &udp6(src, dst, b"x"))
}

fn eam6() -> Ipv6Addr {
    peer_mapping().eam6
}

#[test]
fn a_outbound_destination_takes_the_longest_prefix_after_the_exact_addresses() {
    let own = self_eam6();
    let cases = [
        // (peer, dst, nested, strict).
        (
            PEER,
            ip4("10.1.0.5"),
            V6(own, ip6("fd64:2::a01:5")),
            V6(own, ip6("fd64:2::a01:5")),
        ),
        (
            OTHER,
            ip4("10.1.0.5"),
            Drop(reasons::PEER_MISMATCH),
            Drop(reasons::PEER_MISMATCH),
        ),
        (PEER, EAM4, V6(own, eam6()), V6(own, eam6())),
        (
            PEER,
            PEER6_EAM4,
            V6(own, peer_mapping().peer6),
            V6(own, peer_mapping().peer6),
        ),
        (
            OTHER,
            OTHER_EAM4,
            V6(own, other_mapping().eam6),
            V6(own, other_mapping().eam6),
        ),
        // The self `eam4` and the local LAN inside the /0 are not OTHER's.
        (OTHER, SELF_EAM4, Pass, Pass),
        (OTHER, ip4("192.168.1.20"), Pass, Pass),
    ];
    for (peer, dst, nested, strict) in cases {
        case(
            Dir::Out,
            peer,
            &udp_v4(SELF_EAM4, dst),
            nested,
            Some(strict),
        );
    }
    // Only in the nested table.
    let cases = [
        (OTHER, ip4("8.8.8.8"), V6(own, ip6("fd64:9::808:808"))),
        (PEER, ip4("8.8.8.8"), Drop(reasons::PEER_MISMATCH)),
        (PEER, ip4("192.168.1.130"), V6(own, ip6("fd64:4::c0a8:182"))),
        (OTHER, ip4("192.168.1.130"), Drop(reasons::PEER_MISMATCH)),
    ];
    for (peer, dst, nested) in cases {
        case(Dir::Out, peer, &udp_v4(SELF_EAM4, dst), nested, None);
    }
    for strict in stricts() {
        for dst in ["8.8.8.8", "192.168.1.130"] {
            let bytes = udp_v4(SELF_EAM4, ip4(dst));
            assert_eq!(run(&strict, Dir::Out, PEER, &bytes).0, Pass, "{dst}");
        }
    }
}

#[test]
fn b_inbound_ipv4_sources_inside_a_prefix_are_spoofs() {
    let spoof = Drop(reasons::SPOOFED_SOURCE);
    for (src, strict) in [
        (ip4("10.1.0.5"), spoof),
        (ip4("192.168.1.20"), spoof),
        (EAM4, spoof),
        (PEER6_EAM4, spoof),
        (SELF_EAM4, Pass),
    ] {
        case(Dir::In, PEER, &udp_v4(src, SELF_EAM4), strict, Some(strict));
    }
    case(
        Dir::In,
        PEER,
        &udp_v4(ip4("8.8.8.8"), SELF_EAM4),
        spoof,
        Some(Pass),
    );
}

#[test]
fn c_the_predicate_follows_the_longest_prefix() {
    let nested = nested();
    let stricts = stricts();
    let translated = nested.ipv4_translated_predicate();
    for (addr, in_nested, in_strict) in [
        (ip4("10.1.0.5"), true, true),
        (ip4("8.8.8.8"), true, false),
        (ip4("192.168.1.20"), false, false),
        (ip4("192.168.1.130"), true, false),
        (SELF_EAM4, false, false),
        (EAM4, true, true),
        (PEER6_EAM4, true, true),
        (OTHER_EAM4, true, true),
    ] {
        assert_eq!(translated(addr), in_nested, "{addr}");
        for strict in &stricts {
            assert_eq!(
                strict.ipv4_translated_predicate()(addr),
                in_strict,
                "{addr}"
            );
        }
    }
}

#[test]
fn d_outbound_sources_map_only_from_the_local_lan_and_the_self_eam4() {
    let dst4 = ip4("10.1.0.5");
    let dst = ip6("fd64:2::a01:5");
    for (src, strict) in [
        (ip4("192.168.1.20"), V6(ip6("fd64:1::c0a8:114"), dst)),
        (SELF_EAM4, V6(self_eam6(), dst)),
        (ip4("8.8.8.8"), Drop(reasons::UNMAPPED)),
        (EAM4, Drop(reasons::UNMAPPED)),
    ] {
        case(Dir::Out, PEER, &udp_v4(src, dst4), strict, Some(strict));
    }
    // The /25 inside the local LAN is PEER's.
    let src = ip4("192.168.1.130");
    case(
        Dir::Out,
        PEER,
        &udp_v4(src, dst4),
        Drop(reasons::UNMAPPED),
        None,
    );
    for strict in stricts() {
        let outcome = run(&strict, Dir::Out, PEER, &udp_v4(src, dst4)).0;
        assert_eq!(outcome, V6(ip6("fd64:1::c0a8:182"), dst));
    }
}

/// The source and destination of the packet quoted in a translated error.
fn quoted6(packet: &[u8]) -> (Ipv6Addr, Ipv6Addr) {
    let quote = &packet[48..];
    (src6(quote), dst6(quote))
}

fn quoted4(packet: &[u8]) -> (Ipv4Addr, Ipv4Addr) {
    let quote = &packet[28..];
    (src4(quote), dst4(quote))
}

/// An ICMP port unreachable from `src` to `dst` quoting a UDP packet from
/// `dst` to `src`.
fn icmp4_unreachable(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let quoted = udp_v4(dst, src);
    ipv4_simple(
        src,
        dst,
        protocol::ICMP,
        &icmp4_error(3, 3, [0; 4], &quoted),
    )
}

fn icmp6_unreachable(src: Ipv6Addr, dst: Ipv6Addr, quoted: (Ipv6Addr, Ipv6Addr)) -> Vec<u8> {
    let quoted = udp_v6(quoted.0, quoted.1);
    let error = icmp6_error(src, dst, 1, 4, [0; 4], &quoted);
    ipv6_simple(src, dst, protocol::ICMPV6, &error)
}

#[test]
fn e_quoted_ipv4_packets_map_like_the_outer_ones() {
    let own = self_eam6();
    let peer6 = peer_mapping().peer6;
    // The quoted source is the exact `peer6_eam4` inside OTHER's /0.
    let bytes = icmp4_unreachable(SELF_EAM4, PEER6_EAM4);
    let outer = V6(own, peer6);
    let (packet, stricts) = case(Dir::Out, PEER, &bytes, outer, Some(outer));
    for packet in stricts.iter().chain([&packet]) {
        assert_eq!(quoted6(packet), (peer6, own));
    }
    let (local, remote) = (ip4("192.168.1.20"), ip4("10.1.0.5"));
    let (local6, remote6) = (ip6("fd64:1::c0a8:114"), ip6("fd64:2::a01:5"));
    let bytes = icmp4_unreachable(local, remote);
    let outer = V6(local6, remote6);
    let (packet, stricts) = case(Dir::Out, PEER, &bytes, outer, Some(outer));
    for packet in stricts.iter().chain([&packet]) {
        assert_eq!(quoted6(packet), (remote6, local6));
    }
    // Only in the nested table: a quoted /0 address.
    let remote6 = ip6("fd64:9::808:808");
    let bytes = icmp4_unreachable(SELF_EAM4, ip4("8.8.8.8"));
    let (packet, _) = case(Dir::Out, OTHER, &bytes, V6(own, remote6), None);
    assert_eq!(quoted6(&packet), (remote6, own));
}

#[test]
fn f_inbound_destinations_map_back_only_to_their_own_prefix() {
    for (dst, strict) in [
        (ip6("fd64:1::c0a8:114"), V4(EAM4, ip4("192.168.1.20"))),
        (self_eam6(), V4(EAM4, SELF_EAM4)),
        // The local LAN or the exact addresses claimed under OTHER's /0.
        (ip6("fd64:9::c0a8:114"), Pass),
        (ip6("fd64:9::6440:64"), Pass),
        (ip6("fd64:9::6440:32"), Pass),
        // Outside the local LAN.
        (ip6("fd64:1::6440:64"), Pass),
    ] {
        case(Dir::In, PEER, &udp_v6(eam6(), dst), strict, Some(strict));
    }
    // PEER's /25 claimed under the local LAN's base.
    let bytes = udp_v6(eam6(), ip6("fd64:1::c0a8:182"));
    case(Dir::In, PEER, &bytes, Pass, None);
    for strict in stricts() {
        let outcome = run(&strict, Dir::In, PEER, &bytes).0;
        assert_eq!(outcome, V4(EAM4, ip4("192.168.1.130")));
    }
}

#[test]
fn g_spoofed_replies_under_a_shorter_prefix_are_unmapped() {
    let own = self_eam6();
    let unmapped = Drop(reasons::UNMAPPED);
    // A /16 address and the exact addresses under OTHER's /0.
    let spoofs = [
        ip6("fd64:9::a01:5"),
        ip6("fd64:9::6440:32"),
        ip6("fd64:9::6440:1"),
        ip6("fd64:9::6440:64"),
    ];
    for src in spoofs {
        case(Dir::In, OTHER, &udp_v6(src, own), unmapped, Some(unmapped));
    }
    let translator = nested();
    for src in spoofs {
        assert_eq!(
            run(&translator, Dir::In, OTHER, &udp_v6(src, own)).0,
            unmapped
        );
    }
    let stats = translator.stats();
    assert_eq!((stats.dropped_in, stats.translated_in), (4, 0));

    let remote = ip6("fd64:2::a01:5");
    let outcome = V4(ip4("10.1.0.5"), SELF_EAM4);
    case(Dir::In, PEER, &udp_v6(remote, own), outcome, Some(outcome));
    // Only in the nested table.
    let cases = [
        (OTHER, "fd64:9::808:808", V4(ip4("8.8.8.8"), SELF_EAM4)),
        (PEER, "fd64:9::808:808", Drop(reasons::PEER_MISMATCH)),
        (
            PEER,
            "fd64:4::c0a8:182",
            V4(ip4("192.168.1.130"), SELF_EAM4),
        ),
        // PEER's /25 claimed under the local LAN's base.
        (PEER, "fd64:1::c0a8:182", unmapped),
    ];
    for (peer, src, nested) in cases {
        case(Dir::In, peer, &udp_v6(ip6(src), own), nested, None);
    }
    for strict in stricts() {
        let run = |peer, src| run(&strict, Dir::In, peer, &udp_v6(ip6(src), own)).0;
        assert_eq!(run(OTHER, "fd64:9::808:808"), unmapped);
        assert_eq!(run(PEER, "fd64:4::c0a8:182"), unmapped);
        assert_eq!(run(PEER, "fd64:1::c0a8:182"), Drop(reasons::SPOOFED_SOURCE));
    }
}

#[test]
fn h_quoted_ipv6_packets_map_back_only_to_their_own_prefix() {
    let own = self_eam6();
    let remote = ip6("fd64:2::a01:5");
    let bytes = icmp6_unreachable(eam6(), own, (own, remote));
    let outer = V4(EAM4, SELF_EAM4);
    let (packet, stricts) = case(Dir::In, PEER, &bytes, outer, Some(outer));
    for packet in stricts.iter().chain([&packet]) {
        assert_eq!(quoted4(packet), (SELF_EAM4, ip4("10.1.0.5")));
    }
    // A quoted /16 address claimed under OTHER's /0.
    let bytes = icmp6_unreachable(eam6(), own, (own, ip6("fd64:9::a01:5")));
    let unmapped = Drop(reasons::UNMAPPED);
    case(Dir::In, PEER, &bytes, unmapped, Some(unmapped));
    // Only in the nested table: a quoted /0 address.
    let remote = ip6("fd64:9::808:808");
    let bytes = icmp6_unreachable(remote, own, (own, remote));
    let (packet, _) = case(Dir::In, OTHER, &bytes, V4(ip4("8.8.8.8"), SELF_EAM4), None);
    assert_eq!(quoted4(&packet), (SELF_EAM4, ip4("8.8.8.8")));
}
