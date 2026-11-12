//! The IPv6 extension header chain as the strict parser reads it: what is
//! skipped, what ends the chain and which reason refuses a packet.

use super::super::parse::Ipv6;
use super::*;

/// An extension header: its kind and its bytes (the first byte, the next
/// header, is filled in by [`chained`]).
type Extension = (u8, Vec<u8>);

/// A Hop-by-Hop (0), Routing (43) or Destination Options (60) header of
/// `units` 8-byte units.
fn options(kind: u8, units: u8) -> Extension {
    let mut header = vec![0_u8; usize::from(units) * 8];
    header[1] = units - 1;
    (kind, header)
}

/// A Fragment header; `field` holds the offset, the reserved bits and M.
fn fragment(field: u16, id: u32) -> Extension {
    let mut header = vec![0_u8; 8];
    header[2..4].copy_from_slice(&field.to_be_bytes());
    header[4..8].copy_from_slice(&id.to_be_bytes());
    (44, header)
}

/// An IPv6 packet between legal addresses whose `extensions` precede
/// `body` of `protocol`.
fn chained(extensions: &[Extension], protocol: u8, body: &[u8]) -> Vec<u8> {
    // The first next header, then the header bytes.
    let mut bytes = vec![extensions.first().map_or(protocol, |(kind, _)| *kind)];
    for (index, (_, header)) in extensions.iter().enumerate() {
        bytes.push(
            extensions
                .get(index + 1)
                .map_or(protocol, |(kind, _)| *kind),
        );
        bytes.extend_from_slice(&header[1..]);
    }
    ipv6(
        peer_mapping().eam6,
        self_eam6(),
        protocol,
        64,
        0,
        &bytes,
        body,
    )
}

fn refused(packet: &[u8], quoted: bool) -> &'static str {
    match Ipv6::parse(packet, quoted) {
        Err(reason) => reason,
        Ok(parsed) => panic!("expected a refusal, got {parsed:?}"),
    }
}

#[test]
fn options_and_exhausted_routing_headers_are_skipped() {
    for (name, extensions, start) in [
        ("none", vec![], 40),
        ("Hop-by-Hop", vec![options(0, 1)], 48),
        ("Destination Options", vec![options(60, 2)], 56),
        ("Routing", vec![options(43, 3)], 64),
        (
            "the longest header",
            vec![
                options(60, 255),
                (0, {
                    let mut header = vec![0_u8; 2048];
                    header[1] = 255;
                    header
                }),
            ],
            40 + 2040 + 2048,
        ),
        (
            "every kind",
            vec![
                options(0, 1),
                options(60, 1),
                options(43, 2),
                options(60, 1),
            ],
            80,
        ),
    ] {
        let packet = chained(&extensions, protocol::UDP, b"12345678");
        let parsed = Ipv6::parse(&packet, false).unwrap();
        assert_eq!(parsed.protocol, protocol::UDP, "{name}");
        assert_eq!(parsed.payload, start..start + 8, "{name}");
        assert_eq!(parsed.fragment, None, "{name}");
        assert_eq!(parsed.total_len, packet.len(), "{name}");
    }
}

#[test]
fn an_unknown_next_header_is_the_upper_layer() {
    for extensions in [vec![], vec![options(60, 1)]] {
        let start = 40 + extensions.len() * 8;
        let packet = chained(&extensions, 253, &[0, 9, 0, 0]);
        let parsed = Ipv6::parse(&packet, false).unwrap();
        assert_eq!((parsed.protocol, parsed.payload), (253, start..start + 4));
        // The upper layer may be empty.
        let packet = chained(&extensions, 253, &[]);
        let parsed = Ipv6::parse(&packet, false).unwrap();
        assert_eq!((parsed.protocol, parsed.payload), (253, start..start));
    }
}

#[test]
fn at_most_fifteen_extension_headers_are_walked() {
    let packet = chained(&vec![options(60, 1); 15], protocol::UDP, b"12345678");
    let parsed = Ipv6::parse(&packet, false).unwrap();
    assert_eq!(parsed.payload, 160..168);
    let packet = chained(&vec![options(60, 1); 16], protocol::UDP, b"12345678");
    assert_eq!(refused(&packet, false), reasons::UNSUPPORTED_EXTENSION);
    // The Fragment header counts.
    let mut chain = vec![options(60, 1); 15];
    chain.push(fragment(1, 7));
    let packet = chained(&chain, protocol::UDP, b"12345678");
    let parsed = Ipv6::parse(&packet, false).unwrap();
    assert_eq!(parsed.payload, 168..176);
    chain.insert(0, options(0, 1));
    let packet = chained(&chain, protocol::UDP, b"12345678");
    assert_eq!(refused(&packet, false), reasons::UNSUPPORTED_EXTENSION);
}

#[test]
fn ah_esp_and_no_next_header_are_refused_wherever_the_chain_reaches_them() {
    for next in [51, 50, 59] {
        for extensions in [vec![], vec![options(0, 1), options(60, 1)]] {
            let packet = chained(&extensions, next, &[0; 16]);
            assert_eq!(
                refused(&packet, false),
                reasons::UNSUPPORTED_PROTOCOL,
                "next header {next}"
            );
        }
    }
    // Refused without reading it: no byte of the header is present.
    let packet = chained(&[], 51, &[]);
    assert_eq!(refused(&packet, false), reasons::UNSUPPORTED_PROTOCOL);
}

#[test]
fn a_routing_header_with_segments_left_is_refused() {
    let mut active = options(43, 2);
    active.1[3] = 1;
    let packet = chained(&[options(0, 1), active.clone()], protocol::UDP, b"12345678");
    assert_eq!(refused(&packet, false), reasons::ACTIVE_ROUTING_HEADER);
    // Whole in the buffer but past the end of a quoted packet: still the
    // routing header's reason.
    let mut packet = chained(&[active], protocol::UDP, b"12345678");
    packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
    assert_eq!(refused(&packet, true), reasons::ACTIVE_ROUTING_HEADER);
}

#[test]
fn a_fragment_header_ends_the_chain() {
    for (name, field, offset, more) in [
        ("atomic", 0, 0, false),
        ("first", 1, 0, true),
        ("middle", (5 << 3) | 1, 5, true),
        ("last", 0x1fff << 3, 0x1fff, false),
    ] {
        let packet = chained(
            &[options(0, 1), fragment(field, 0x0102_0304)],
            protocol::UDP,
            b"12345678",
        );
        let parsed = Ipv6::parse(&packet, false).unwrap();
        assert_eq!(parsed.protocol, protocol::UDP, "{name}");
        assert_eq!(parsed.payload, 56..64, "{name}");
        let found = parsed.fragment.unwrap();
        assert_eq!(
            (found.offset, found.more, found.identification),
            (offset, more, 0x0102_0304),
            "{name}"
        );
        assert_eq!(parsed.has_transport_header(), offset == 0, "{name}");
    }
    // No data behind the header.
    let packet = chained(&[fragment(8, 1)], protocol::UDP, &[]);
    let parsed = Ipv6::parse(&packet, false).unwrap();
    assert_eq!(parsed.payload, 48..48);
}

#[test]
fn nothing_is_walked_behind_a_fragment_header() {
    // An extension header behind the Fragment header is refused, in a first
    // fragment and in a later one, whether or not its bytes are present.
    for next in [0, 43, 44, 51, 60] {
        for field in [0, 1, 8] {
            for body in [&[0_u8; 16][..], &[]] {
                let packet = chained(&[fragment(field, 1)], next, body);
                assert_eq!(
                    refused(&packet, false),
                    reasons::UNSUPPORTED_EXTENSION,
                    "next header {next}, field {field}"
                );
            }
        }
    }
    // ESP and No Next Header behind it are the fragmented protocol.
    for next in [50, 59] {
        let packet = chained(&[fragment(1, 1)], next, &[0; 16]);
        let parsed = Ipv6::parse(&packet, false).unwrap();
        assert_eq!((parsed.protocol, parsed.payload), (next, 48..64));
    }
}

#[test]
fn reserved_fragment_bits_are_malformed() {
    for field in [0b010, 0b100, 0b111, (3 << 3) | 0b010] {
        let packet = chained(&[fragment(field, 1)], protocol::UDP, b"12345678");
        assert_eq!(refused(&packet, false), reasons::MALFORMED, "{field:#b}");
    }
    // The refused next header is reported first.
    let packet = chained(&[fragment(0b010, 1)], 60, b"12345678");
    assert_eq!(refused(&packet, false), reasons::UNSUPPORTED_EXTENSION);
}

#[test]
fn a_chain_cut_inside_a_header_is_truncated() {
    // The packet ends after `kept` bytes of its last extension header.
    for (name, extensions, kept) in [
        ("options header, no bytes", vec![options(0, 1)], 0),
        ("options length byte", vec![options(60, 1)], 1),
        ("options header", vec![options(43, 2)], 15),
        (
            "second options header",
            vec![options(0, 1), options(60, 1)],
            7,
        ),
        ("Fragment header, no bytes", vec![fragment(0, 1)], 0),
        ("Fragment header", vec![fragment(0, 1)], 7),
        ("later fragment's header", vec![fragment(8, 1)], 7),
        (
            "Fragment header behind options",
            vec![options(0, 1), fragment(1, 1)],
            4,
        ),
    ] {
        let whole = chained(&extensions, protocol::UDP, &[]);
        let last = extensions.last().map_or(0, |(_, header)| header.len());
        let end = whole.len() - last + kept;
        let mut packet = whole[..end].to_vec();
        packet[4..6].copy_from_slice(&u16::try_from(end - 40).unwrap().to_be_bytes());
        assert_eq!(refused(&packet, false), reasons::TRUNCATED, "{name}");
        // A quoted packet cut at the same place, its length field intact.
        assert_eq!(
            refused(&whole[..end], true),
            reasons::TRUNCATED,
            "{name}, quoted"
        );
    }
    // A length field reaching past the packet.
    let mut overlong = chained(&[options(60, 1)], protocol::UDP, b"12345678");
    overlong[41] = 2;
    assert_eq!(refused(&overlong, false), reasons::TRUNCATED);
}

#[test]
fn a_quoted_chain_ends_at_the_payload_length() {
    // The buffer goes on behind the quoted packet (padding, an RFC 4884
    // structure): a header past the payload length is not part of it.
    let whole = chained(&[options(0, 1), options(60, 1)], protocol::UDP, b"12345678");
    for (payload_len, expected) in [(15_u16, None), (16, Some(56..56)), (20, Some(56..60))] {
        let mut quoted = whole.clone();
        quoted[4..6].copy_from_slice(&payload_len.to_be_bytes());
        match (Ipv6::parse(&quoted, true), expected) {
            (Ok(parsed), Some(payload)) => assert_eq!(parsed.payload, payload),
            (Err(reason), None) => assert_eq!(reason, reasons::TRUNCATED),
            (result, expected) => panic!("{payload_len}: {result:?}, expected {expected:?}"),
        }
    }
    let mut fragmented = chained(&[fragment(1, 1)], protocol::UDP, b"12345678");
    fragmented[4..6].copy_from_slice(&7_u16.to_be_bytes());
    assert_eq!(refused(&fragmented, true), reasons::TRUNCATED);
    // The refusal of what follows the Fragment header comes first.
    fragmented[40] = 60;
    assert_eq!(refused(&fragmented, true), reasons::UNSUPPORTED_EXTENSION);
    // A quote cut inside the upper layer keeps what is there.
    let parsed = Ipv6::parse(&whole[..60], true).unwrap();
    assert_eq!(
        (parsed.protocol, parsed.payload, parsed.total_len),
        (protocol::UDP, 56..60, 64)
    );
}
