//! The packet tag and the receipt marker through the translator: a packet copied into a
//! grown buffer keeps both, and a reassembled datagram keeps its fragments' tag only if they
//! all carried the same one.

use std::num::NonZeroU64;

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, protocol};

use super::{EAM4, PEER, SELF_EAM4, check_v6, fragment4, ipv4_simple, translator, udp4};
use crate::translate::reasons;

const fn tag(value: u64) -> Option<NonZeroU64> {
    NonZeroU64::new(value)
}

/// `bytes` in an exact-size buffer, with `value` as its tag (0 for none) and the receipt
/// marker set.
fn tagged(bytes: &[u8], value: u64) -> PacketBuf {
    let mut packet = PacketBuf::from_packet(bytes);
    packet.set_tag(tag(value));
    packet.set_tracked(true);
    packet
}

#[test]
fn a_grown_copy_keeps_the_tag_and_the_marker() {
    let packet = ipv4_simple(
        SELF_EAM4,
        EAM4,
        protocol::UDP,
        &udp4(SELF_EAM4, EAM4, b"x", false),
    );
    let translator = translator();
    // An exact-size buffer has no room for the 20 bytes the translation adds.
    let mut exact = tagged(&packet, 6);
    assert_eq!(translator.outbound(PEER, &mut exact), Verdict::Accept);
    check_v6(exact.as_packet());
    assert_eq!(translator.stats().grown_copies, 1);
    assert_eq!((exact.tag(), exact.is_tracked()), (tag(6), true));
}

/// Sends the fragments of a zero-checksum UDP datagram outbound with `tags`; returns the
/// last verdict and packet.
fn reassemble(id: u16, tags: [u64; 3]) -> (Verdict, PacketBuf, crate::TranslatorStats) {
    let translator = translator();
    let udp = udp4(SELF_EAM4, EAM4, b"abcdefghijklmnopqrstuvwx", true);
    let pieces = [
        fragment4(id, 0, true, 64, &udp[..16]),
        fragment4(id, 2, true, 64, &udp[16..24]),
        fragment4(id, 3, false, 64, &udp[24..]),
    ];
    let mut last = None;
    for (piece, value) in pieces.iter().zip(tags) {
        let mut packet = tagged(piece, value);
        let verdict = translator.outbound(PEER, &mut packet);
        last = Some((verdict, packet));
    }
    let (verdict, packet) = last.unwrap();
    (verdict, packet, translator.stats())
}

#[test]
fn a_reassembled_datagram_keeps_the_tag_its_fragments_share() {
    for value in [0, 9] {
        let (verdict, packet, stats) = reassemble(90, [value; 3]);
        assert_eq!(verdict, Verdict::Accept);
        check_v6(packet.as_packet());
        assert_eq!(packet.tag(), tag(value));
        assert_eq!((stats.reassembled, stats.dropped_out), (1, 0));
    }
}

#[test]
fn fragments_with_different_tags_are_dropped_and_counted() {
    for tags in [[1, 2, 1], [1, 0, 1], [0, 0, 3]] {
        let (verdict, _, stats) = reassemble(91, tags);
        assert_eq!(
            verdict,
            Verdict::Drop {
                reason: reasons::FRAGMENT_MIXED_TAGS
            },
            "{tags:?}"
        );
        assert_eq!(
            (stats.reassembled, stats.translated_out, stats.dropped_out),
            (1, 0, 1)
        );
    }
}
