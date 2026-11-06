//! Zero is an ordinary TCP/ICMP checksum; only UDP reserves it.

use super::*;

fn zero_tcp4(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let seed = tcp4(src, dst, &[0, 0]);
    let segment = tcp4(src, dst, &seed[16..18]);
    assert_eq!(&segment[16..18], &[0, 0]);
    segment
}

fn zero_tcp6(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let seed = tcp6(src, dst, &[0, 0]);
    let segment = tcp6(src, dst, &seed[16..18]);
    assert_eq!(&segment[16..18], &[0, 0]);
    segment
}

fn remote_translator() -> Translator {
    Translator::new(
        TranslationTable::builder()
            .self_mapping(SelfMapping {
                eam4: EAM4,
                eam6: peer_mapping().eam6,
            })
            .peer(
                PEER,
                PeerMapping {
                    peer6: ip6("fd00::ff:0"),
                    eam6: self_eam6(),
                    local6: None,
                    eam4: Some(SELF_EAM4),
                },
            )
            .build()
            .unwrap(),
    )
}

#[test]
fn zero_tcp_checksum_translates_both_directions_and_corruption_drops() {
    let mut v4 = ipv4_simple(SELF_EAM4, EAM4, protocol::TCP, &zero_tcp4(SELF_EAM4, EAM4));
    check_v4(&v4);
    check_v6(&out_ok(&v4));
    v4[40] ^= 1;
    assert_eq!(out_drop(&v4), reasons::INVALID_CHECKSUM);

    let (src, dst) = (peer_mapping().eam6, self_eam6());
    let mut v6 = ipv6_simple(src, dst, protocol::TCP, &zero_tcp6(src, dst));
    check_v6(&v6);
    check_v4(&in_ok(&v6));
    v6[60] ^= 1;
    assert_eq!(in_drop(&v6), reasons::INVALID_CHECKSUM);
}

#[test]
fn zero_tcp_checksum_from_incremental_update_is_accepted_at_next_hop() {
    let seed = zero_tcp6(self_eam6(), peer_mapping().eam6);
    let original = tcp4(SELF_EAM4, EAM4, &seed[20..]);
    assert_ne!(&original[16..18], &[0, 0]);
    let v6 = out_ok(&ipv4_simple(SELF_EAM4, EAM4, protocol::TCP, &original));
    assert_eq!(&v6[56..58], &[0, 0]);
    check_v6(&v6);
    let (verdict, v4) = inbound(&remote_translator(), PEER, &v6);
    assert_eq!(verdict, Verdict::Accept);
    check_v4(&v4);
    assert_eq!(&v4[20..], original);

    let seed = zero_tcp4(EAM4, SELF_EAM4);
    let original = tcp6(peer_mapping().eam6, self_eam6(), &seed[20..]);
    assert_ne!(&original[16..18], &[0, 0]);
    let v4 = in_ok(&ipv6_simple(
        peer_mapping().eam6,
        self_eam6(),
        protocol::TCP,
        &original,
    ));
    assert_eq!(&v4[36..38], &[0, 0]);
    check_v4(&v4);
    let (verdict, v6) = outbound(&remote_translator(), PEER, &v4);
    assert_eq!(verdict, Verdict::Accept);
    check_v6(&v6);
    assert_eq!(&v6[40..], original);
}

#[test]
fn zero_tcp_checksum_in_icmp_quotes_translates_both_directions() {
    let quote = ipv4_simple(EAM4, SELF_EAM4, protocol::TCP, &zero_tcp4(EAM4, SELF_EAM4));
    let error = icmp4_error(3, 3, [0; 4], &quote);
    let v6 = out_ok(&ipv4_simple(SELF_EAM4, EAM4, protocol::ICMP, &error));
    check_v6(&v6);
    check_v6(&v6[48..]);

    let (src, dst) = (self_eam6(), peer_mapping().eam6);
    let quote = ipv6_simple(src, dst, protocol::TCP, &zero_tcp6(src, dst));
    let error = icmp6_error(dst, src, 1, 4, [0; 4], &quote);
    let v4 = in_ok(&ipv6_simple(dst, src, protocol::ICMPV6, &error));
    check_v4(&v4);
    check_v4(&v4[28..]);
}

#[test]
fn zero_udp_checksum_retains_family_specific_rules() {
    let seed = udp6(self_eam6(), peer_mapping().eam6, &[0, 0]);
    let segment = udp4(SELF_EAM4, EAM4, &seed[6..8], true);
    let v6 = out_ok(&ipv4_simple(SELF_EAM4, EAM4, protocol::UDP, &segment));
    assert_eq!(&v6[46..48], &[0xff, 0xff]);
    check_v6(&v6);

    let seed = udp4(EAM4, SELF_EAM4, &[0, 0], false);
    let segment = udp6(peer_mapping().eam6, self_eam6(), &seed[6..8]);
    let v6 = ipv6_simple(peer_mapping().eam6, self_eam6(), protocol::UDP, &segment);
    let v4 = in_ok(&v6);
    assert_eq!(&v4[26..28], &[0xff, 0xff]);
    check_v4(&v4);

    // Even a zero field whose sum verifies is forbidden for UDP over IPv6.
    let (src, dst) = (peer_mapping().eam6, self_eam6());
    let seed = udp6(src, dst, &[0, 0]);
    let mut segment = udp6(src, dst, &seed[6..8]);
    segment[6..8].fill(0);
    assert_eq!(transport_checksum_v6(src, dst, protocol::UDP, &segment), 0);
    assert_eq!(
        in_drop(&ipv6_simple(src, dst, protocol::UDP, &segment)),
        reasons::INVALID_CHECKSUM
    );
}

#[test]
fn zero_udp_checksum_in_icmp_quotes_keeps_family_specific_rules() {
    let quote = ipv4_simple(
        EAM4,
        SELF_EAM4,
        protocol::UDP,
        &udp4(EAM4, SELF_EAM4, b"quote", true),
    );
    let error = icmp4_error(3, 3, [0; 4], &quote);
    let v6 = out_ok(&ipv4_simple(SELF_EAM4, EAM4, protocol::ICMP, &error));
    check_v6(&v6);
    assert_eq!(&v6[48 + 46..48 + 48], &[0, 0]);

    let (src, dst) = (self_eam6(), peer_mapping().eam6);
    let mut segment = udp6(src, dst, b"quote");
    segment[6..8].fill(0);
    let quote = ipv6_simple(src, dst, protocol::UDP, &segment);
    let error = icmp6_error(dst, src, 1, 4, [0; 4], &quote);
    assert_eq!(
        in_drop(&ipv6_simple(dst, src, protocol::ICMPV6, &error)),
        reasons::INVALID_CHECKSUM
    );
}
