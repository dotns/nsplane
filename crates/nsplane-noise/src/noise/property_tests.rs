// SPDX-License-Identifier: BSD-3-Clause

//! Randomized properties of the datagram parser and of tunnels fed datagrams nobody sent.
//!
//! The inputs come from a seeded generator. Most are authentic messages with a few bytes
//! changed, and, for handshake messages, mac1 computed again: whoever knows a public key
//! can do that, and without it nothing gets past the first check.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;

use super::handshake::{LABEL_MAC1, b2s_hash, b2s_keyed_mac_16, parse_handshake_anon};
use super::rate_limiter::RateLimiter;
use super::*;

/// Offset of mac1 from the end of a handshake message, and of mac2.
const MACS_SZ: usize = 32;
const MAC2_SZ: usize = 16;
/// The bytes of a handshake initiation the handshake authenticates: the ephemeral key, the
/// encrypted static key and the encrypted timestamp. The sender index in front of them is
/// covered by mac1 only.
const INIT_AUTHENTICATED: Range<usize> = 8..116;
/// The same for a handshake response: the receiver index (compared with the handshake it
/// answers), the ephemeral key and the encrypted empty payload.
const RESP_AUTHENTICATED: Range<usize> = 8..60;
/// The bytes of a handshake initiation that identify the initiator.
const INIT_IDENTITY: Range<usize> = 8..88;

/// `SplitMix64`.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n`.
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    const fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}

/// Two tunnels for each other, with fixed static keys.
struct Pair {
    initiator: Tunn,
    responder: Tunn,
    initiator_public: x25519::PublicKey,
    responder_public: x25519::PublicKey,
}

/// A pair whose tunnels allow `limit` handshakes before asking for cookies.
fn pair(limit: u64) -> Pair {
    let initiator = x25519::StaticSecret::from([0x11; 32]);
    let responder = x25519::StaticSecret::from([0x22; 32]);
    let initiator_public = x25519::PublicKey::from(&initiator);
    let responder_public = x25519::PublicKey::from(&responder);
    let limiter = |public: &x25519::PublicKey| Some(Arc::new(RateLimiter::new(public, limit)));
    Pair {
        initiator: Tunn::new(
            initiator,
            responder_public,
            None,
            None,
            1,
            limiter(&initiator_public),
        ),
        responder: Tunn::new(
            responder,
            initiator_public,
            None,
            None,
            2,
            limiter(&responder_public),
        ),
        initiator_public,
        responder_public,
    }
}

/// What a tunnel made of a datagram.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// `TunnResult::Done`.
    Done,
    /// `TunnResult::Err`, with the error's name.
    Rejected(String),
    Network(Vec<u8>),
    V4(Vec<u8>, Ipv4Addr),
    V6(Vec<u8>, Ipv6Addr),
}

impl Outcome {
    fn of(result: TunnResult<'_>) -> Self {
        match result {
            TunnResult::Done => Self::Done,
            TunnResult::Err(error) => Self::Rejected(format!("{error:?}")),
            TunnResult::WriteToNetwork(datagram) => Self::Network(datagram.to_vec()),
            TunnResult::WriteToTunnelV4(packet, src) => Self::V4(packet.to_vec(), src),
            TunnResult::WriteToTunnelV6(packet, src) => Self::V6(packet.to_vec(), src),
        }
    }

    /// The datagram to send, which the tunnel must have asked for.
    fn network(self) -> Vec<u8> {
        let Self::Network(datagram) = self else {
            panic!("expected a datagram to send, got {self:?}");
        };
        datagram
    }
}

/// Feeds `datagram` from `src` to `tun` through one of its three entry points: the copying
/// one, the in-place one, or (for what parses as transport data) the open ticket.
fn deliver(tun: &mut Tunn, rng: &mut Rng, src: Option<SocketAddr>, datagram: &[u8]) -> Outcome {
    let mut buf = datagram.to_vec();
    buf.resize(datagram.len().max(HANDSHAKE_INIT_SZ) + 16, 0);
    match rng.below(3) {
        0 => Outcome::of(tun.decapsulate(src, datagram, &mut buf)),
        1 => Outcome::of(tun.decapsulate_in_place(src, &mut buf, datagram.len())),
        _ => {
            let ticket = match tun.open_ticket(datagram) {
                Ok(ticket) => ticket,
                // Not transport data: the ticket path does not apply.
                Err(WireGuardError::InvalidPacket) => {
                    return Outcome::of(tun.decapsulate(src, datagram, &mut buf));
                }
                Err(error) => return Outcome::Rejected(format!("{error:?}")),
            };
            let mut opened = datagram.to_vec();
            match ticket.open(&mut opened) {
                Ok(plain_len) => Outcome::of(tun.commit_open(&ticket, &mut opened, plain_len)),
                Err(error) => Outcome::Rejected(format!("{error:?}")),
            }
        }
    }
}

/// The (sent, received) data bytes of `tun`.
fn bytes(tun: &Tunn) -> (usize, usize) {
    let (_, sent, received, ..) = tun.stats();
    (sent, received)
}

/// Feeds `datagram` and expects the tunnel to refuse it without counting anything.
fn assert_rejected(tun: &mut Tunn, rng: &mut Rng, datagram: &[u8], what: &str) {
    let before = bytes(tun);
    let outcome = deliver(tun, rng, None, datagram);
    assert!(
        matches!(outcome, Outcome::Rejected(_)),
        "{what}: {outcome:?} for {datagram:02x?}"
    );
    assert_eq!(bytes(tun), before, "{what}: {datagram:02x?}");
}

/// Writes the mac1 a handshake message for the owner of `receiver` must carry.
fn sign(receiver: &x25519::PublicKey, datagram: &mut [u8]) {
    let key = b2s_hash(LABEL_MAC1, receiver.as_bytes());
    let at = datagram.len() - MACS_SZ;
    let mac1 = b2s_keyed_mac_16(&key, &datagram[..at]);
    datagram[at..at + MAC2_SZ].copy_from_slice(&mac1);
}

/// `message` with at least one byte in `changed` different, or its key at `ephemeral`
/// replaced by a point of small order.
fn changed_within(
    rng: &mut Rng,
    message: &[u8],
    changed: Range<usize>,
    ephemeral: usize,
) -> Vec<u8> {
    let mut mutant = message.to_vec();
    for _ in 0..=rng.below(2) {
        let at = changed.start + rng.below(changed.len());
        match rng.below(8) {
            0 => {
                let mut point = [0; 32];
                point[0] = rng.pick(&[0, 1]);
                mutant[ephemeral..ephemeral + 32].copy_from_slice(&point);
            }
            1..=3 => mutant[at] ^= 1 << rng.below(8),
            _ => mutant[at] = mutant[at].wrapping_add(1 + rng.byte() % 255),
        }
    }
    if mutant == message {
        mutant[changed.start] ^= 1;
    }
    mutant
}

/// `message` with a bit flipped anywhere, or cut short, or with bytes behind it. Never
/// empty: an empty datagram is how a caller asks [`Tunn::decapsulate`] for its queue.
fn changed_anywhere(rng: &mut Rng, message: &[u8]) -> Vec<u8> {
    let mut mutant = message.to_vec();
    match rng.below(6) {
        0 => mutant.truncate(1 + rng.below(message.len() - 1)),
        1 => {
            let extra = 1 + rng.below(32);
            mutant.extend(rng.bytes(extra));
        }
        _ => {
            for _ in 0..=rng.below(2) {
                let at = rng.below(message.len());
                mutant[at] = mutant[at].wrapping_add(1 + rng.byte() % 255);
            }
            if mutant == message {
                mutant[0] ^= 1;
            }
        }
    }
    mutant
}

/// What [`Tunn::parse_incoming_packet`] must make of `datagram`: the message type, if
/// the type word and the length are those of one of the four messages.
fn expected_type(datagram: &[u8]) -> Option<u32> {
    let message_type = u32::from_le_bytes(*datagram.first_chunk()?);
    match (message_type, datagram.len()) {
        (1, 148) | (2, 92) | (3, 64) => Some(message_type),
        (4, len) if len >= 32 => Some(message_type),
        _ => None,
    }
}

fn le32(datagram: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(*datagram[at..].first_chunk().unwrap())
}

#[test]
fn parse_accepts_exactly_the_four_message_layouts() {
    let mut rng = Rng(0x2001);
    let limiter = RateLimiter::new(&pair(u64::MAX).responder_public, u64::MAX);
    let mut parsed = 0;
    for case in 0..30_000 {
        let len = match rng.below(10) {
            0 => rng.below(200),
            1 => 32 + rng.below(1500),
            _ => rng.pick(&[0, 3, 4, 31, 32, 33, 63, 64, 65, 91, 92, 93, 147, 148, 149]),
        };
        let mut datagram = rng.bytes(len);
        if let Some(word) = datagram.first_chunk_mut::<4>() {
            // The type with its three reserved zero bytes, which are sometimes not zero.
            let fitting = match len {
                148 => 1,
                92 => 2,
                64 => 3,
                _ => 4,
            };
            *word = [
                rng.pick(&[0, 1, 2, 3, 4, 5, 0x81, fitting, fitting]),
                0,
                0,
                0,
            ];
            if rng.chance(10) {
                word[1 + rng.below(3)] = 1 << rng.below(8);
            }
        }
        let expected = expected_type(&datagram);
        // Without the key's mac1 no datagram is a handshake for it.
        assert!(!limiter.mac1_matches(&datagram), "case {case}");
        let packet = match Tunn::parse_incoming_packet(&datagram) {
            Ok(packet) => packet,
            Err(error) => {
                assert!(
                    matches!(error, WireGuardError::InvalidPacket) && expected.is_none(),
                    "case {case}: {error:?} for {datagram:02x?}"
                );
                continue;
            }
        };
        parsed += 1;
        let (message_type, fields_match) = match packet {
            Packet::HandshakeInit(p) => (
                1,
                p.sender_idx == le32(&datagram, 4)
                    && p.unencrypted_ephemeral[..] == datagram[8..40]
                    && p.encrypted_static == &datagram[40..88]
                    && p.encrypted_timestamp == &datagram[88..116],
            ),
            Packet::HandshakeResponse(p) => (
                2,
                p.sender_idx == le32(&datagram, 4)
                    && p.receiver_idx == le32(&datagram, 8)
                    && p.unencrypted_ephemeral[..] == datagram[12..44]
                    && p.encrypted_nothing == &datagram[44..60],
            ),
            Packet::PacketCookieReply(p) => (
                3,
                p.receiver_idx == le32(&datagram, 4)
                    && p.nonce == &datagram[8..32]
                    && p.encrypted_cookie == &datagram[32..64],
            ),
            Packet::PacketData(p) => (
                4,
                p.receiver_idx == le32(&datagram, 4)
                    && p.counter == u64::from_le_bytes(*datagram[8..].first_chunk().unwrap())
                    && p.encrypted_encapsulated_packet == &datagram[16..],
            ),
        };
        assert_eq!(Some(message_type), expected, "case {case}: {datagram:02x?}");
        assert!(fields_match, "case {case}: {datagram:02x?}");
    }
    assert!(parsed > 5_000, "only {parsed} datagrams parsed");
}

#[test]
fn tunnels_without_a_handshake_refuse_every_datagram() {
    let mut rng = Rng(0x2002);
    let mut pair = pair(u64::MAX);
    let mut refused_after_mac1 = 0;
    for _ in 0..5_000 {
        let message_type = rng.pick(&[1, 2, 3, 4]);
        let len = match message_type {
            1 => 148,
            2 => 92,
            3 => 64,
            _ => 32 + rng.below(200),
        };
        let mut datagram = rng.bytes(len);
        datagram[..4].copy_from_slice(&[message_type, 0, 0, 0]);
        if message_type < 3 && rng.chance(50) {
            sign(&pair.responder_public, &mut datagram);
            refused_after_mac1 += 1;
        }
        if rng.chance(30) {
            datagram = changed_anywhere(&mut rng, &datagram);
        }
        assert_rejected(&mut pair.responder, &mut rng, &datagram, "random datagram");
        assert!(!pair.responder.has_session());
        let _ = Tunn::dst_address(&datagram);
    }
    assert!(refused_after_mac1 > 800);
}

/// A plaintext a peer may put into a transport data message: a valid IP packet, one with
/// its version or length fields changed, or anything.
fn plaintext(rng: &mut Rng) -> Vec<u8> {
    let mut packet = if rng.chance(50) {
        let header_len = if rng.chance(70) {
            20
        } else {
            20 + rng.below(11) * 4
        };
        let len = header_len + rng.below(600);
        let mut packet = rng.bytes(len);
        packet[0] = 0x40 | u8::try_from(header_len / 4).unwrap();
        packet[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        packet
    } else {
        let len = 40 + rng.below(600);
        let mut packet = rng.bytes(len);
        packet[0] = 0x60 | (packet[0] & 0x0f);
        packet[4..6].copy_from_slice(&u16::try_from(len - 40).unwrap().to_be_bytes());
        packet
    };
    match rng.below(12) {
        0 => packet.clear(),
        1 => {
            let len = 1 + rng.below(80);
            packet = rng.bytes(len);
        }
        2 => packet[0] = rng.byte(),
        3 => packet[0] = (packet[0] & 0xf0) | rng.pick(&[0, 1, 4, 5, 6, 15]),
        4 | 5 => {
            // The length field of either version, off by a little or by a lot.
            let at = if packet[0] >> 4 == 4 { 2 } else { 4 };
            let len = u16::from_be_bytes([packet[at], packet[at + 1]]);
            let len = rng.pick(&[0, 19, 20, 0xffff, len + 1, len + 15, len + 16, len / 2]);
            packet[at..at + 2].copy_from_slice(&len.to_be_bytes());
        }
        6 => packet.truncate(rng.below(packet.len())),
        7 => {
            let extra = 1 + rng.below(40);
            packet.extend(rng.bytes(extra));
        }
        _ => {}
    }
    packet
}

/// What the receiving tunnel must make of an authentic message carrying `plaintext`
/// (RFC 791 and RFC 8200 length rules over the plaintext as padded to 16 bytes).
fn expected_delivery(plaintext: &[u8]) -> Outcome {
    let invalid = Outcome::Rejected("InvalidPacket".into());
    let mut padded = plaintext.to_vec();
    padded.resize(plaintext.len().next_multiple_of(16), 0);
    let Some(&first) = padded.first() else {
        return Outcome::Done;
    };
    match first >> 4 {
        4 if padded.len() >= 20 => {
            let header_len = usize::from(first & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([padded[2], padded[3]]));
            if header_len < 20 || total_len < header_len || total_len > padded.len() {
                return invalid;
            }
            let src = <[u8; 4]>::try_from(&padded[12..16]).unwrap();
            Outcome::V4(padded[..total_len].to_vec(), src.into())
        }
        6 if padded.len() >= 40 => {
            let len = 40 + usize::from(u16::from_be_bytes([padded[4], padded[5]]));
            if len > padded.len() {
                return invalid;
            }
            let src = <[u8; 16]>::try_from(&padded[8..24]).unwrap();
            Outcome::V6(padded[..len].to_vec(), src.into())
        }
        _ => invalid,
    }
}

/// One handshake between the pair, with changed copies of both messages thrown at their
/// receivers before the authentic ones arrive.
fn handshake_among_forgeries(pair: &mut Pair, rng: &mut Rng, forgeries: usize) {
    let mut buf = [0; 256];
    let init = Outcome::of(pair.initiator.format_handshake_initiation(&mut buf, true)).network();
    assert_eq!(expected_type(&init), Some(1));
    let sender = parse_handshake_anon(
        &x25519::StaticSecret::from([0x22; 32]),
        &pair.responder_public,
        &match Tunn::parse_incoming_packet(&init).unwrap() {
            Packet::HandshakeInit(init) => init,
            other => panic!("{other:?}"),
        },
    )
    .unwrap();
    assert_eq!(sender.peer_static_public, *pair.initiator_public.as_bytes());
    assert_eq!(sender.peer_index, le32(&init, 4));

    for _ in 0..forgeries {
        let mut forged = changed_within(rng, &init, INIT_AUTHENTICATED, 8);
        if rng.chance(80) {
            sign(&pair.responder_public, &mut forged);
        }
        // Nobody else is taken for the initiator.
        if let Ok(Packet::HandshakeInit(parsed)) = Tunn::parse_incoming_packet(&forged) {
            let anon = parse_handshake_anon(
                &x25519::StaticSecret::from([0x22; 32]),
                &pair.responder_public,
                &parsed,
            );
            let identity_kept = forged[INIT_IDENTITY] == init[INIT_IDENTITY];
            assert_eq!(anon.is_ok(), identity_kept, "{forged:02x?}");
        }
        assert_rejected(&mut pair.responder, rng, &forged, "forged initiation");
    }
    let response = deliver(&mut pair.responder, rng, None, &init).network();
    assert_eq!(expected_type(&response), Some(2));
    assert_eq!(le32(&response, 8), le32(&init, 4));
    assert_rejected(&mut pair.responder, rng, &init, "replayed initiation");

    for _ in 0..forgeries {
        let mut forged = changed_within(rng, &response, RESP_AUTHENTICATED, 12);
        if rng.chance(80) {
            sign(&pair.initiator_public, &mut forged);
        }
        assert_rejected(&mut pair.initiator, rng, &forged, "forged response");
    }
    // The forgeries did not use up the handshake: the authentic response completes it.
    let keepalive = deliver(&mut pair.initiator, rng, None, &response).network();
    assert_eq!(expected_type(&keepalive), Some(4));
    assert_eq!(keepalive.len(), DATA_OVERHEAD_SZ);
    assert_rejected(&mut pair.initiator, rng, &response, "replayed response");
    assert_eq!(
        deliver(&mut pair.responder, rng, None, &keepalive),
        Outcome::Done
    );
}

#[test]
fn forged_handshake_messages_are_refused_and_leave_the_handshake_intact() {
    let mut rng = Rng(0x2003);
    let mut pair = pair(u64::MAX);
    for _ in 0..60 {
        handshake_among_forgeries(&mut pair, &mut rng, 8);
        assert!(pair.initiator.has_session() && pair.responder.has_session());
        assert_eq!(
            (bytes(&pair.initiator), bytes(&pair.responder)),
            ((0, 0), (0, 0))
        );
    }
}

#[test]
fn transport_data_arrives_once_as_sent_and_never_when_changed() {
    let mut rng = Rng(0x2004);
    let mut pair = pair(u64::MAX);
    let (mut delivered, mut invalid) = (0, 0);
    for round in 0..300 {
        if round % 20 == 0 {
            handshake_among_forgeries(&mut pair, &mut rng, 0);
        }
        let (sender, receiver) = if round % 2 == 0 {
            (&mut pair.initiator, &mut pair.responder)
        } else {
            (&mut pair.responder, &mut pair.initiator)
        };
        // A burst inside the replay window, delivered in any order.
        let mut burst: Vec<(Vec<u8>, Vec<u8>)> = (0..=rng.below(11))
            .map(|_| {
                let plaintext = plaintext(&mut rng);
                let mut buf = vec![0; plaintext.len() + 256];
                let datagram = Outcome::of(sender.encapsulate(&plaintext, &mut buf)).network();
                assert_eq!(expected_type(&datagram), Some(4));
                (plaintext, datagram)
            })
            .collect();
        rng.shuffle(&mut burst);
        for (plaintext, datagram) in &burst {
            for _ in 0..rng.below(3) {
                let forged = changed_anywhere(&mut rng, datagram);
                assert_rejected(receiver, &mut rng, &forged, "changed data");
            }
            let expected = expected_delivery(plaintext);
            let before = bytes(receiver);
            let outcome = deliver(receiver, &mut rng, None, datagram);
            assert_eq!(outcome, expected, "plaintext {plaintext:02x?}");
            let counted = match &outcome {
                Outcome::V4(packet, _) | Outcome::V6(packet, _) => {
                    delivered += 1;
                    packet.len()
                }
                _ => {
                    invalid += 1;
                    0
                }
            };
            assert_eq!(bytes(receiver), (before.0, before.1 + counted));
            assert_rejected(receiver, &mut rng, datagram, "replayed data");
        }
    }
    assert!(delivered > 800, "only {delivered} packets delivered");
    assert!(invalid > 300, "only {invalid} plaintexts refused");
}

#[test]
fn under_load_the_only_answer_to_a_handshake_is_a_cookie_reply() {
    let mut rng = Rng(0x2005);
    // No handshake is allowed without a cookie.
    let mut pair = pair(0);
    let mut buf = [0; 256];
    for round in 0..60 {
        let src = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1 + round)),
            51_820,
        ));
        let init =
            Outcome::of(pair.initiator.format_handshake_initiation(&mut buf, true)).network();
        for _ in 0..6 {
            let mut forged = changed_within(&mut rng, &init, 4..116, 8);
            let signed = rng.chance(60);
            if signed {
                sign(&pair.responder_public, &mut forged);
            }
            match deliver(&mut pair.responder, &mut rng, src, &forged) {
                Outcome::Rejected(_) if !signed => {}
                Outcome::Network(reply) if signed => {
                    assert_eq!(expected_type(&reply), Some(3));
                    assert_eq!(le32(&reply, 4), le32(&forged, 4));
                }
                outcome => panic!("{outcome:?} for {forged:02x?} (signed: {signed})"),
            }
        }
        let reply = deliver(&mut pair.responder, &mut rng, src, &init).network();
        assert_eq!(expected_type(&reply), Some(3));
        assert_eq!(le32(&reply, 4), le32(&init, 4));

        for _ in 0..6 {
            let forged = changed_anywhere(&mut rng, &reply);
            assert_rejected(
                &mut pair.initiator,
                &mut rng,
                &forged,
                "changed cookie reply",
            );
        }
        // The authentic cookie still counts, and the next initiation proves the address.
        assert_eq!(
            deliver(&mut pair.initiator, &mut rng, src, &reply),
            Outcome::Done
        );
        let init =
            Outcome::of(pair.initiator.format_handshake_initiation(&mut buf, true)).network();
        let other = Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 51_820));
        let refused = deliver(&mut pair.responder, &mut rng, other, &init).network();
        assert_eq!(
            expected_type(&refused),
            Some(3),
            "cookie of another address"
        );
        let response = deliver(&mut pair.responder, &mut rng, src, &init).network();
        assert_eq!(expected_type(&response), Some(2));
    }
}
