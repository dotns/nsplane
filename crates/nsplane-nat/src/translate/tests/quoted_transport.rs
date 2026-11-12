//! The upper layer of a packet quoted in an ICMP error: an echo header cut
//! short.

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
