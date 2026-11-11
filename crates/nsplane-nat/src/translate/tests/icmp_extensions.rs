//! ICMP errors whose quoted packet is followed by more bytes: an RFC 4884
//! extension structure after the padded original datagram, or plain padding.
//! The quote is translated by its own length and the trailing bytes are left
//! out.

use super::*;

fn peer_eam6() -> Ipv6Addr {
    peer_mapping().eam6
}

/// An RFC 4884 extension structure holding one MPLS label stack object
/// (RFC 4950: class 1, C-Type 1) with one label stack entry.
fn mpls_extension() -> Vec<u8> {
    let mut extension = vec![0x20, 0, 0, 0];
    // Object header: length 8, class 1, C-Type 1; label 16 000, S, TTL 1.
    extension.extend_from_slice(&[0, 8, 1, 1, 0x03, 0xe8, 0x01, 0x01]);
    let checksum = internet_checksum(&extension);
    extension[2..4].copy_from_slice(&checksum.to_be_bytes());
    extension
}

/// A UDP packet `PEER` sent to this node with `payload`, as an outbound ICMP
/// error quotes it.
fn quoted_v4(payload: &[u8]) -> Vec<u8> {
    let hdr = Hdr4 {
        ttl: 37,
        id: 7,
        ..Hdr4::default()
    };
    let udp = udp4(EAM4, SELF_EAM4, payload, false);
    ipv4(EAM4, SELF_EAM4, protocol::UDP, hdr, &udp)
}

/// A UDP packet this node sent to `PEER` with `payload`, as an inbound
/// `ICMPv6` error quotes it.
fn quoted_v6(payload: &[u8]) -> Vec<u8> {
    let udp = udp6(self_eam6(), peer_eam6(), payload);
    ipv6(self_eam6(), peer_eam6(), protocol::UDP, 37, 0, &[], &udp)
}

/// Translates the outbound ICMP error and returns the quoted IPv6 packet.
fn out_quote(kind: u8, rest: [u8; 4], field: &[u8]) -> Vec<u8> {
    let error = icmp4_error(kind, 0, rest, field);
    let v6 = out_ok(&ipv4_simple(SELF_EAM4, EAM4, protocol::ICMP, &error));
    check_v6(&v6);
    assert_eq!((v6[6], v6[40]), (protocol::ICMPV6, 3));
    v6[48..].to_vec()
}

/// Translates the inbound `ICMPv6` error and returns the quoted IPv4 packet.
fn in_quote(rest: [u8; 4], field: &[u8]) -> Vec<u8> {
    let error = icmp6_error(peer_eam6(), self_eam6(), 3, 0, rest, field);
    let packet = ipv6(
        peer_eam6(),
        self_eam6(),
        protocol::ICMPV6,
        64,
        0,
        &[],
        &error,
    );
    let v4 = in_ok(&packet);
    check_v4(&v4);
    assert_eq!((v4[9], v4[20]), (protocol::ICMP, 11));
    v4[28..].to_vec()
}

/// The translation of `quote` alone, without anything after it.
fn plain_out_quote(quote: &[u8]) -> Vec<u8> {
    out_quote(11, [0; 4], quote)
}

#[test]
fn icmpv4_error_with_an_mpls_extension_translates_its_quote() {
    // Time exceeded from an MPLS router: the original datagram zero padded
    // to 128 bytes (32 words in the length attribute), then the extension.
    let quote = quoted_v4(b"traceroute probe");
    let mut field = quote.clone();
    field.resize(128, 0);
    field.extend_from_slice(&mpls_extension());
    let translated = out_quote(11, [0, 32, 0, 0], &field);
    assert_eq!(translated, plain_out_quote(&quote));
    assert_eq!(translated.len(), quote.len() + 20);
    assert_eq!(
        (src6(&translated), dst6(&translated)),
        (peer_eam6(), self_eam6())
    );
    assert_eq!(
        transport_checksum_v6(peer_eam6(), self_eam6(), protocol::UDP, &translated[40..]),
        0
    );
}

#[test]
fn icmpv4_error_with_an_extension_after_a_truncated_quote() {
    // The original datagram is longer than the 128 bytes quoted of it: the
    // quote ends where the length attribute says, not at the extension.
    let quote = quoted_v4(&[0x5a; 600]);
    let mut field = quote[..128].to_vec();
    field.extend_from_slice(&mpls_extension());
    let translated = out_quote(11, [0, 32, 0, 0], &field);
    assert_eq!(translated, plain_out_quote(&quote[..128]));
    assert_eq!(translated.len(), 128 + 20);
    assert_eq!(
        usize::from(u16::from_be_bytes([translated[4], translated[5]])),
        quote.len() - 20,
        "the quoted payload length is the original datagram's"
    );
}

#[test]
fn icmpv4_error_with_padding_after_its_quote() {
    let quote = quoted_v4(b"padded");
    let mut field = quote.clone();
    field.extend_from_slice(&[0; 6]);
    // Without a length attribute, and for destination unreachable too.
    assert_eq!(out_quote(11, [0; 4], &field), plain_out_quote(&quote));
    let error = icmp4_error(3, 3, [0; 4], &field);
    let v6 = out_ok(&ipv4_simple(SELF_EAM4, EAM4, protocol::ICMP, &error));
    check_v6(&v6);
    assert_eq!(&v6[48..], plain_out_quote(&quote));
}

#[test]
fn icmpv6_error_with_an_mpls_extension_translates_its_quote() {
    // The original datagram zero padded to 64-bit words, then the extension.
    let quote = quoted_v6(b"traceroute probe!");
    let mut field = quote.clone();
    field.resize(quote.len().next_multiple_of(8), 0);
    assert_ne!(field.len(), quote.len());
    let words = u8::try_from(field.len() / 8).unwrap();
    field.extend_from_slice(&mpls_extension());
    let translated = in_quote([words, 0, 0, 0], &field);
    assert_eq!(translated, in_quote([0; 4], &quote));
    assert_eq!(translated.len(), quote.len() - 20);
    assert_eq!((src4(&translated), dst4(&translated)), (SELF_EAM4, EAM4));
    assert_eq!(
        transport_checksum_v4(SELF_EAM4, EAM4, protocol::UDP, &translated[20..]),
        0
    );

    // A truncated quote ends at the length attribute.
    let long = quoted_v6(&[0x5a; 600]);
    let mut field = long[..128].to_vec();
    field.extend_from_slice(&mpls_extension());
    let translated = in_quote([16, 0, 0, 0], &field);
    assert_eq!(translated, in_quote([0; 4], &long[..128]));
    assert_eq!(translated.len(), 128 - 20);
}

#[test]
fn icmpv6_error_with_padding_after_its_quote() {
    let quote = quoted_v6(b"padded");
    let mut field = quote.clone();
    field.extend_from_slice(&[0; 6]);
    assert_eq!(in_quote([0; 4], &field), in_quote([0; 4], &quote));
}

#[test]
fn a_length_attribute_past_the_message_is_ignored() {
    let quote = quoted_v4(b"short");
    assert_eq!(
        out_quote(11, [0, 32, 0, 0], &quote),
        plain_out_quote(&quote)
    );
}

#[test]
fn rewritten_icmpv6_error_keeps_the_bytes_after_its_quote() {
    let (own, local6, peer6) = (
        ip6("fd00::ff:0"),
        peer_mapping().local6.unwrap(),
        peer_mapping().peer6,
    );
    // Inbound: the peer reports an error about a datagram we sent to it.
    let quote = ipv6_simple(own, peer6, protocol::UDP, &udp6(own, peer6, b"quoted!"));
    let mut field = quote.clone();
    field.resize(quote.len().next_multiple_of(8), 0);
    let words = u8::try_from(field.len() / 8).unwrap();
    let extension = mpls_extension();
    field.extend_from_slice(&extension);
    let error = icmp6_error(peer6, own, 3, 0, [words, 0, 0, 0], &field);
    let v6 = in_ok(&ipv6_simple(peer6, own, protocol::ICMPV6, &error));
    check_v6(&v6);
    assert_eq!(v6.len(), 48 + field.len());
    let inner = &v6[48..48 + quote.len()];
    assert_eq!((src6(inner), dst6(inner)), (own, local6));
    assert_eq!(
        transport_checksum_v6(own, local6, protocol::UDP, &inner[40..]),
        0
    );
    assert_eq!(&v6[v6.len() - extension.len()..], extension);
}
