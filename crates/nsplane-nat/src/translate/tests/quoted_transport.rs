//! The upper layer of a packet quoted in an ICMP error: an echo header cut
//! short, and protocols the translator does not translate on their own.

use super::*;

fn peer_eam6() -> Ipv6Addr {
    peer_mapping().eam6
}

/// Translates an outbound port unreachable error around `quote` and returns
/// the quoted IPv6 packet.
fn out_quote(quote: &[u8]) -> Vec<u8> {
    let error = icmp4_error(3, 3, [0; 4], quote);
    let v6 = out_ok(&ipv4_simple(SELF_EAM4, EAM4, protocol::ICMP, &error));
    check_v6(&v6);
    v6[48..].to_vec()
}

/// An inbound port unreachable error around `quote`.
fn in_error(quote: &[u8]) -> Vec<u8> {
    let error = icmp6_error(peer_eam6(), self_eam6(), 1, 4, [0; 4], quote);
    ipv6_simple(peer_eam6(), self_eam6(), protocol::ICMPV6, &error)
}

/// Translates [`in_error`] and returns the quoted IPv4 packet.
fn in_quote(quote: &[u8]) -> Vec<u8> {
    let v4 = in_ok(&in_error(quote));
    check_v4(&v4);
    v4[28..].to_vec()
}

#[test]
fn a_quoted_echo_header_cut_before_its_checksum_gets_its_type_translated() {
    // The echo `PEER` sent to this node, as an outbound error quotes it.
    for (reply, expected) in [(false, 128), (true, 129)] {
        let whole = ipv4_simple(EAM4, SELF_EAM4, protocol::ICMP, &echo4(reply, b"ping"));
        for kept in 1..4 {
            let quote = out_quote(&whole[..20 + kept]);
            assert_eq!(quote.len(), 40 + kept);
            assert_eq!(quote[6], protocol::ICMPV6);
            assert_eq!(quote[40], expected, "{kept} bytes of the header");
            // The code and what is there of the checksum stay as quoted.
            assert_eq!(quote[41..], whole[21..20 + kept]);
        }
        // Without a byte of the header there is nothing to translate.
        assert_eq!(out_quote(&whole[..20]).len(), 40);
    }
    // The echo this node sent to `PEER`, as an inbound error quotes it.
    let (src, dst) = (self_eam6(), peer_eam6());
    for (reply, expected) in [(false, 8), (true, 0)] {
        let whole = ipv6_simple(src, dst, protocol::ICMPV6, &echo6(src, dst, reply, b"ping"));
        for kept in 1..4 {
            let quote = in_quote(&whole[..40 + kept]);
            assert_eq!(quote.len(), 20 + kept);
            assert_eq!(quote[9], protocol::ICMP);
            assert_eq!(quote[20], expected, "{kept} bytes of the header");
            assert_eq!(quote[21..], whole[41..40 + kept]);
        }
        assert_eq!(in_quote(&whole[..40]).len(), 20);
    }
}

#[test]
fn the_reported_cut_echo_quote_is_translated() {
    // Found by the property tests: destination unreachable from a LAN host,
    // quoting two bytes of the echo reply it was sent.
    let packet = [
        0x45, 0x07, 0x00, 0x32, 0xf8, 0x51, 0x00, 0x00, 0x23, 0x01, 0x4f, 0xc6, 0xc0, 0xa8, 0x01,
        0xc9, 0x0a, 0x00, 0x83, 0x3b, 0x03, 0x03, 0xfc, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00,
        0x00, 0x1f, 0x00, 0x01, 0x40, 0x00, 0x00, 0x01, 0x2b, 0x31, 0x0a, 0x00, 0x83, 0x3b, 0xc0,
        0xa8, 0x01, 0xc9, 0x00, 0x00,
    ];
    let v6 = out_ok(&packet);
    check_v6(&v6);
    assert_eq!(
        (v6[48 + 6], &v6[48 + 40..]),
        (protocol::ICMPV6, &[129, 0][..])
    );
}

/// A Fragment header (`field` is the offset and M flag) in front of `next`.
fn fragment_extension(next: u8, field: u16) -> Vec<u8> {
    let mut extension = vec![44, next, 0];
    extension.extend_from_slice(&field.to_be_bytes());
    extension.extend_from_slice(&[0, 0, 0, 7]);
    extension
}

#[test]
fn esp_and_no_next_header_are_not_translated_behind_a_fragment_header_either() {
    // The parser takes them as the fragmented protocol; the translation then
    // refuses them with the reason an unfragmented packet gets.
    let (src, dst) = (peer_eam6(), self_eam6());
    for next in [50, 59] {
        let whole = ipv6_simple(src, dst, next, &[0; 16]);
        assert_eq!(in_drop(&whole), reasons::UNSUPPORTED_PROTOCOL, "{next}");
        for field in [1, 8, (2 << 3) | 1] {
            let fragment = ipv6(
                src,
                dst,
                next,
                64,
                0,
                &fragment_extension(next, field),
                &[0; 16],
            );
            assert_eq!(
                in_drop(&fragment),
                reasons::UNSUPPORTED_PROTOCOL,
                "{next}, fragment field {field}"
            );
        }
    }
    // An address rewrite translates no upper layer: it carries a fragment of
    // any protocol, and refuses only what the chain walk refuses.
    let (src, local6) = (ip6("fd00::ff:0"), peer_mapping().local6.unwrap());
    let fragment = ipv6(src, local6, 50, 64, 0, &fragment_extension(50, 1), &[0; 16]);
    assert_eq!(dst6(&out_ok(&fragment)), peer_mapping().peer6);
    let whole = ipv6_simple(src, local6, 50, &[0; 16]);
    assert_eq!(out_drop(&whole), reasons::UNSUPPORTED_PROTOCOL);
}

#[test]
fn a_quote_of_another_protocol_is_carried_with_its_addresses_translated() {
    // GRE, ESP: nothing in them depends on the addresses, and the host that
    // gets the error only matches the quote against what it sent.
    for proto in [47, 50] {
        let whole = ipv4_simple(EAM4, SELF_EAM4, proto, b"0123456789abcdef");
        let quote = out_quote(&whole);
        assert_eq!(quote[6], proto);
        assert_eq!((src6(&quote), dst6(&quote)), (peer_eam6(), self_eam6()));
        assert_eq!(quote[40..], whole[20..]);
    }
    let (src, dst) = (self_eam6(), peer_eam6());
    let gre = ipv6_simple(src, dst, 47, b"0123456789abcdef");
    let quote = in_quote(&gre);
    assert_eq!(quote[9], 47);
    assert_eq!((src4(&quote), dst4(&quote)), (SELF_EAM4, EAM4));
    assert_eq!(quote[20..], gre[40..]);
    // A quoted fragment of ESP is carried the same way.
    let fragment = ipv6(src, dst, 50, 64, 0, &fragment_extension(50, 1), &[7; 16]);
    let quote = in_quote(&fragment);
    assert_eq!(quote[9], 50);
    assert_eq!(quote[20..], [7; 16]);
    // A quoted IPv6 packet with ESP or No Next Header right in its chain is
    // refused by the chain walk, as the packet itself would be.
    for next in [50, 59] {
        let quoted = ipv6_simple(src, dst, next, &[0; 16]);
        assert_eq!(
            in_drop(&in_error(&quoted)),
            reasons::UNSUPPORTED_PROTOCOL,
            "{next}"
        );
    }
}
