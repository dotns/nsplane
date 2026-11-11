// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::wire::{HANDSHAKE_INIT, HANDSHAKE_RESP, HandshakeInitMsg, HandshakeRespMsg};
use super::{
    HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ, HandshakeInit, HandshakeResponse, PacketCookieReply,
};
use crate::noise::errors::WireGuardError;
use crate::noise::session::Session;
use crate::sleepyinstant::Instant;
use crate::x25519;
use aead::AeadInPlace;
use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use blake2::digest::{FixedOutput, KeyInit};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::XChaCha20Poly1305;
use rand_core::OsRng;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;
use zerocopy::FromBytes;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const LABEL_MAC1: &[u8; 8] = b"mac1----";
pub(crate) const LABEL_COOKIE: &[u8; 8] = b"cookie--";
const KEY_LEN: usize = 32;
const TIMESTAMP_LEN: usize = 12;
const COOKIE_LEN: usize = 16;
const COOKIE_TAG_LEN: usize = 16;
/// What a handshake without a preshared key mixes in its place
const NO_PRESHARED_KEY: [u8; KEY_LEN] = [0; KEY_LEN];

// initiator.chaining_key = HASH(CONSTRUCTION)
const INITIAL_CHAIN_KEY: [u8; KEY_LEN] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];

// initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER)
const INITIAL_CHAIN_HASH: [u8; KEY_LEN] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

#[inline]
pub(crate) fn b2s_hash(data1: &[u8], data2: &[u8]) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    hash.update(data1);
    hash.update(data2);
    hash.finalize().into()
}

type HmacBlake2s = hmac::SimpleHmac<Blake2s256>;

#[inline]
fn hmac_blake2s(key: &[u8; KEY_LEN]) -> HmacBlake2s {
    #[allow(
        clippy::expect_used,
        reason = "INVARIANT: HMAC accepts keys of any length"
    )]
    HmacBlake2s::new_from_slice(key).expect("INVARIANT: HMAC accepts keys of any length")
}

#[inline]
fn keyed_blake2s<const N: usize, O>(key: &[u8; N]) -> Blake2sMac<O>
where
    O: blake2::digest::typenum::Unsigned
        + blake2::digest::typenum::IsLessOrEqual<blake2::digest::consts::U32>
        + blake2::digest::generic_array::ArrayLength<u8>,
    blake2::digest::typenum::LeEq<O, blake2::digest::consts::U32>: blake2::digest::typenum::NonZero,
{
    const { assert!(N > 0 && N <= KEY_LEN, "keyed BLAKE2s keys are 1..=32 bytes") };
    #[allow(
        clippy::expect_used,
        reason = "INVARIANT: key length is checked at compile time"
    )]
    Blake2sMac::new_from_slice(key).expect("INVARIANT: key length is checked at compile time")
}

#[inline]
/// RFC 2401 HMAC+Blake2s, not to be confused with *keyed* Blake2s
pub(crate) fn b2s_hmac(key: &[u8; KEY_LEN], data1: &[u8]) -> Zeroizing<[u8; 32]> {
    use blake2::digest::Update;
    let mut hmac = hmac_blake2s(key);
    hmac.update(data1);
    Zeroizing::new(hmac.finalize_fixed().into())
}

#[inline]
/// Like `b2s_hmac`, but chain data1 and data2 together
pub(crate) fn b2s_hmac2(key: &[u8; KEY_LEN], data1: &[u8], data2: &[u8]) -> Zeroizing<[u8; 32]> {
    use blake2::digest::Update;
    let mut hmac = hmac_blake2s(key);
    hmac.update(data1);
    hmac.update(data2);
    Zeroizing::new(hmac.finalize_fixed().into())
}

#[inline]
pub(crate) fn b2s_keyed_mac_16<const N: usize>(key: &[u8; N], data1: &[u8]) -> [u8; 16] {
    let mut hmac = keyed_blake2s::<N, blake2::digest::consts::U16>(key);
    blake2::digest::Update::update(&mut hmac, data1);
    hmac.finalize_fixed().into()
}

#[inline]
pub(crate) fn b2s_keyed_mac_16_2<const N: usize>(
    key: &[u8; N],
    data1: &[u8],
    data2: &[u8],
) -> [u8; 16] {
    let mut hmac = keyed_blake2s::<N, blake2::digest::consts::U16>(key);
    blake2::digest::Update::update(&mut hmac, data1);
    blake2::digest::Update::update(&mut hmac, data2);
    hmac.finalize_fixed().into()
}

pub(crate) fn b2s_mac_24<const N: usize>(key: &[u8; N], data1: &[u8]) -> [u8; 24] {
    let mut hmac = keyed_blake2s::<N, blake2::digest::consts::U24>(key);
    blake2::digest::Update::update(&mut hmac, data1);
    hmac.finalize_fixed().into()
}

#[inline]
pub(super) fn chacha20_poly1305_key(key: &[u8; KEY_LEN]) -> LessSafeKey {
    #[allow(
        clippy::expect_used,
        reason = "INVARIANT: ChaCha20-Poly1305 keys are 32 bytes"
    )]
    LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key)
            .expect("INVARIANT: ChaCha20-Poly1305 keys are 32 bytes"),
    )
}

#[inline]
/// This wrapper involves an extra copy and MAY BE SLOWER
fn aead_chacha20_seal(
    ciphertext: &mut [u8],
    key: &[u8; KEY_LEN],
    counter: u64,
    data: &[u8],
    aad: &[u8],
) {
    let mut nonce: [u8; 12] = [0; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());

    aead_chacha20_seal_inner(ciphertext, key, nonce, data, aad);
}

#[inline]
fn aead_chacha20_seal_inner(
    ciphertext: &mut [u8],
    key: &[u8; KEY_LEN],
    nonce: [u8; 12],
    data: &[u8],
    aad: &[u8],
) {
    let key = chacha20_poly1305_key(key);

    ciphertext[..data.len()].copy_from_slice(data);

    #[allow(clippy::expect_used, reason = "INVARIANT: handshake fields are tiny")]
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext[..data.len()],
        )
        .expect("INVARIANT: sealing only fails for inputs larger than 256 GiB");

    ciphertext[data.len()..].copy_from_slice(tag.as_ref());
}

#[inline]
/// This wrapper involves an extra copy and MAY BE SLOWER
fn aead_chacha20_open(
    buffer: &mut [u8],
    key: &[u8; KEY_LEN],
    counter: u64,
    data: &[u8],
    aad: &[u8],
) -> Result<(), WireGuardError> {
    let mut nonce: [u8; 12] = [0; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());

    aead_chacha20_open_inner(buffer, key, nonce, data, aad)
        .map_err(|_| WireGuardError::InvalidAeadTag)?;
    Ok(())
}

#[inline]
fn aead_chacha20_open_inner(
    buffer: &mut [u8],
    key: &[u8; KEY_LEN],
    nonce: [u8; 12],
    data: &[u8],
    aad: &[u8],
) -> Result<(), aws_lc_rs::error::Unspecified> {
    let key = chacha20_poly1305_key(key);

    let mut inner_buffer = data.to_owned();

    let plaintext = key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut inner_buffer,
    )?;

    buffer.copy_from_slice(plaintext);

    Ok(())
}

/// Rejects the all-zero X25519 result a public key of small order produces, in constant time.
fn contributory(shared: x25519::SharedSecret) -> Option<x25519::SharedSecret> {
    shared.was_contributory().then_some(shared)
}

#[derive(Debug)]
/// This struct represents a 12 byte [Tai64N](https://cr.yp.to/libtai/tai64.html) timestamp
struct Tai64N {
    secs: u64,
    nano: u32,
}

#[derive(Debug)]
/// This struct computes a [Tai64N](https://cr.yp.to/libtai/tai64.html) timestamp from current system time
struct TimeStamper {
    duration_at_start: Duration,
    instant_at_start: Instant,
}

impl TimeStamper {
    /// Create a new `TimeStamper`
    pub(crate) fn new() -> Self {
        Self {
            // A clock before 1970 only weakens replay protection of our own initiations.
            duration_at_start: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default(),
            instant_at_start: Instant::now(),
        }
    }

    /// Take time reading and generate a 12 byte timestamp
    pub(crate) fn stamp(&self) -> [u8; 12] {
        const TAI64_BASE: u64 = (1u64 << 62) + 37;
        let mut ext_stamp = [0u8; 12];
        let stamp = Instant::now().duration_since(self.instant_at_start) + self.duration_at_start;
        ext_stamp[0..8].copy_from_slice(&(stamp.as_secs() + TAI64_BASE).to_be_bytes());
        ext_stamp[8..12].copy_from_slice(&stamp.subsec_nanos().to_be_bytes());
        ext_stamp
    }
}

impl Tai64N {
    /// A zeroed out timestamp
    const fn zero() -> Self {
        Self { secs: 0, nano: 0 }
    }

    /// Parse a timestamp from a 12 byte u8 slice
    fn parse(buf: &[u8; 12]) -> Self {
        let mut sec_bytes = [0u8; 8];
        let mut nano_bytes = [0u8; 4];
        sec_bytes.copy_from_slice(&buf[..8]);
        nano_bytes.copy_from_slice(&buf[8..]);
        let secs = u64::from_be_bytes(sec_bytes);
        let nano = u32::from_be_bytes(nano_bytes);

        // WireGuard does not actually expect tai64n timestamp, just monotonically increasing one
        //if secs < (1u64 << 62) || secs >= (1u64 << 63) {
        //    return Err(WireGuardError::InvalidTai64nTimestamp);
        //};
        //if nano >= 1_000_000_000 {
        //   return Err(WireGuardError::InvalidTai64nTimestamp);
        //}

        Self { secs, nano }
    }

    /// Check if this timestamp represents a time that is chronologically after the time represented
    /// by the other timestamp
    pub(crate) const fn after(&self, other: &Self) -> bool {
        (self.secs > other.secs) || ((self.secs == other.secs) && (self.nano > other.nano))
    }
}

/// Parameters used by the noise protocol
struct NoiseParams {
    /// Our static public key
    static_public: x25519::PublicKey,
    /// Our static private key
    static_private: x25519::StaticSecret,
    /// Static public key of the other party
    peer_static_public: x25519::PublicKey,
    /// A shared key = `DH(static_private`, `peer_static_public`); `None` if the peer's key has
    /// small order, which makes it all zero: no handshake with that peer succeeds
    static_shared: Option<x25519::SharedSecret>,
    /// A pre-computation of HASH("mac1----", `peer_static_public`) for this peer
    sending_mac1_key: [u8; KEY_LEN],
    /// The preshared key; all zero without one, which is what such a handshake mixes in. A
    /// plain array, so that replacing the key overwrites the old one in place.
    preshared_key: [u8; KEY_LEN],
}

impl std::fmt::Debug for NoiseParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseParams")
            .field("static_public", &self.static_public)
            .field("static_private", &"<redacted>")
            .field("peer_static_public", &self.peer_static_public)
            .field("static_shared", &"<redacted>")
            .field("sending_mac1_key", &self.sending_mac1_key)
            .field(
                "preshared_key",
                &(!bool::from(self.preshared_key.ct_eq(&NO_PRESHARED_KEY))).then_some("<redacted>"),
            )
            .finish()
    }
}

struct HandshakeInitSentState {
    local_index: u32,
    hash: [u8; KEY_LEN],
    chaining_key: Zeroizing<[u8; KEY_LEN]>,
    ephemeral_private: x25519::ReusableSecret,
    time_sent: Instant,
}

impl std::fmt::Debug for HandshakeInitSentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitSentState")
            .field("local_index", &self.local_index)
            .field("hash", &self.hash)
            .field("chaining_key", &"<redacted>")
            .field("ephemeral_private", &"<redacted>")
            .field("time_sent", &self.time_sent)
            .finish()
    }
}

enum HandshakeState {
    /// No handshake in process
    None,
    /// We initiated the handshake
    InitSent(HandshakeInitSentState),
    /// Handshake initiated by peer
    InitReceived {
        hash: [u8; KEY_LEN],
        chaining_key: Zeroizing<[u8; KEY_LEN]>,
        peer_ephemeral_public: x25519::PublicKey,
        peer_index: u32,
    },
    /// Handshake was established too long ago (implies no handshake is in progress)
    Expired,
}

impl std::fmt::Debug for HandshakeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::InitSent(state) => f.debug_tuple("InitSent").field(state).finish(),
            Self::InitReceived {
                hash,
                chaining_key: _,
                peer_ephemeral_public,
                peer_index,
            } => f
                .debug_struct("InitReceived")
                .field("hash", hash)
                .field("chaining_key", &"<redacted>")
                .field("peer_ephemeral_public", peer_ephemeral_public)
                .field("peer_index", peer_index)
                .finish(),
            Self::Expired => f.write_str("Expired"),
        }
    }
}

#[derive(Debug)]
/// Handshake state of one peer.
pub struct Handshake {
    params: NoiseParams,
    /// Index of the next session
    next_index: u32,
    /// Allow to have two outgoing handshakes in flight, because sometimes we may receive a delayed response to a handshake with bad networks
    previous: HandshakeState,
    /// Current handshake state
    state: HandshakeState,
    cookies: Cookies,
    /// The timestamp of the last handshake we received
    last_handshake_timestamp: Tai64N,
    // TODO: make TimeStamper a singleton
    stamper: TimeStamper,
    pub(super) last_rtt: Option<u32>,
}

#[derive(Default)]
struct Cookies {
    last_mac1: Option<[u8; 16]>,
    index: u32,
    write_cookie: Option<Zeroizing<[u8; COOKIE_LEN]>>,
}

impl std::fmt::Debug for Cookies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cookies")
            .field("last_mac1", &self.last_mac1)
            .field("index", &self.index)
            .field(
                "write_cookie",
                &self.write_cookie.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug)]
/// The parts of a handshake initiation that identify the initiator.
pub struct HalfHandshake {
    /// The initiator's session index.
    pub peer_index: u32,
    /// The initiator's static public key.
    pub peer_static_public: [u8; 32],
}

/// Decrypts the initiator's static key without any per-peer state, to find the peer.
pub fn parse_handshake_anon(
    static_private: &x25519::StaticSecret,
    static_public: &x25519::PublicKey,
    packet: &HandshakeInit<'_>,
) -> Result<HalfHandshake, WireGuardError> {
    let peer_index = packet.sender_idx;
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = Zeroizing::new(INITIAL_CHAIN_KEY);
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = b2s_hash(&hash, static_public.as_bytes());
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let peer_ephemeral_public = x25519::PublicKey::from(*packet.unencrypted_ephemeral);
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(
        &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
        &[0x01],
    );
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let ephemeral_shared = contributory(static_private.diffie_hellman(&peer_ephemeral_public))
        .ok_or(WireGuardError::InvalidPacket)?;
    let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);

    let mut peer_static_public = [0u8; KEY_LEN];
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    aead_chacha20_open(
        &mut peer_static_public,
        &key,
        0,
        packet.encrypted_static,
        &hash,
    )?;

    Ok(HalfHandshake {
        peer_index,
        peer_static_public,
    })
}

impl Drop for NoiseParams {
    fn drop(&mut self) {
        // The x25519 secrets wipe themselves.
        self.preshared_key.zeroize();
    }
}

impl NoiseParams {
    /// New noise params struct from our secret key, peers public key, and optional preshared key
    fn new(
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        let static_shared = contributory(static_private.diffie_hellman(&peer_static_public));

        let initial_sending_mac_key = b2s_hash(LABEL_MAC1, peer_static_public.as_bytes());

        Self {
            static_public,
            static_private,
            peer_static_public,
            static_shared,
            sending_mac1_key: initial_sending_mac_key,
            preshared_key: preshared_key.unwrap_or(NO_PRESHARED_KEY),
        }
    }

    /// Set a new private key; returns its public key
    fn set_static_private(&mut self, static_private: x25519::StaticSecret) -> x25519::PublicKey {
        self.static_public = x25519::PublicKey::from(&static_private);
        self.static_private = static_private;

        self.static_shared =
            contributory(self.static_private.diffie_hellman(&self.peer_static_public));
        self.static_public
    }

    /// The shared key of the static keys, unless the peer's key has small order
    fn static_shared(&self) -> Result<&x25519::SharedSecret, WireGuardError> {
        self.static_shared.as_ref().ok_or(WireGuardError::WrongKey)
    }
}

impl Handshake {
    pub(crate) fn new(
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        peer_static_public: x25519::PublicKey,
        global_idx: u32,
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        let params = NoiseParams::new(
            static_private,
            static_public,
            peer_static_public,
            preshared_key,
        );

        Self {
            params,
            next_index: global_idx,
            previous: HandshakeState::None,
            state: HandshakeState::None,
            last_handshake_timestamp: Tai64N::zero(),
            stamper: TimeStamper::new(),
            cookies: Cookies::default(),
            last_rtt: None,
        }
    }

    pub(crate) const fn is_in_progress(&self) -> bool {
        !matches!(self.state, HandshakeState::None | HandshakeState::Expired)
    }

    /// Whether a handshake initiation is waiting for its response.
    pub(crate) const fn is_init_sent(&self) -> bool {
        matches!(self.state, HandshakeState::InitSent(_))
    }

    pub(crate) fn set_expired(&mut self) {
        self.previous = HandshakeState::Expired;
        self.state = HandshakeState::Expired;
    }

    pub(crate) const fn is_expired(&self) -> bool {
        matches!(self.state, HandshakeState::Expired)
    }

    pub(crate) const fn has_cookie(&self) -> bool {
        self.cookies.write_cookie.is_some()
    }

    pub(crate) fn clear_cookie(&mut self) {
        self.cookies.write_cookie = None;
    }

    // The index used is 24 bits for peer index, allowing for 16M active peers per server and 8 bits for cyclic session index
    fn inc_index(&mut self) -> u32 {
        let index = self.next_index;
        let idx8 = index.to_le_bytes()[0];
        self.next_index = (index & !0xff) | u32::from(idx8.wrapping_add(1));
        self.next_index
    }

    /// Sets a new private key; returns its public key.
    pub(crate) fn set_static_private(
        &mut self,
        private_key: x25519::StaticSecret,
    ) -> x25519::PublicKey {
        self.params.set_static_private(private_key)
    }

    /// Replaces the preshared key used when producing or accepting a handshake response,
    /// including responses to initiations already in flight. Established sessions keep
    /// their derived keys. The new key, or the zeros of no key, overwrite the old key.
    pub(crate) const fn set_preshared_key(&mut self, preshared_key: Option<[u8; KEY_LEN]>) {
        self.params.preshared_key = match preshared_key {
            Some(key) => key,
            None => NO_PRESHARED_KEY,
        };
    }

    pub(super) fn receive_handshake_initialization<'a>(
        &mut self,
        packet: &HandshakeInit<'_>,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = Zeroizing::new(INITIAL_CHAIN_KEY);
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = b2s_hash(&hash, self.params.static_public.as_bytes());
        // msg.sender_index = little_endian(initiator.sender_index)
        let peer_index = packet.sender_idx;
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        let peer_ephemeral_public = x25519::PublicKey::from(*packet.unencrypted_ephemeral);
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(
            &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
            &[0x01],
        );
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let ephemeral_shared = contributory(
            self.params
                .static_private
                .diffie_hellman(&peer_ephemeral_public),
        )
        .ok_or(WireGuardError::InvalidPacket)?;
        let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);

        let mut peer_static_public_decrypted = [0u8; KEY_LEN];
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        aead_chacha20_open(
            &mut peer_static_public_decrypted,
            &key,
            0,
            packet.encrypted_static,
            &hash,
        )?;

        if !bool::from(
            self.params
                .peer_static_public
                .as_bytes()
                .ct_eq(&peer_static_public_decrypted),
        ) {
            return Err(WireGuardError::WrongKey);
        }

        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = b2s_hash(&hash, packet.encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = b2s_hmac(&chaining_key, self.params.static_shared()?.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        aead_chacha20_open(&mut timestamp, &key, 0, packet.encrypted_timestamp, &hash)?;

        let timestamp = Tai64N::parse(&timestamp);
        if !timestamp.after(&self.last_handshake_timestamp) {
            // Possibly a replay
            return Err(WireGuardError::WrongTai64nTimestamp);
        }
        self.last_handshake_timestamp = timestamp;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = b2s_hash(&hash, packet.encrypted_timestamp);

        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitReceived {
                chaining_key,
                hash,
                peer_ephemeral_public,
                peer_index,
            },
        );

        self.format_handshake_response(dst)
    }

    pub(super) fn receive_handshake_response(
        &mut self,
        packet: &HandshakeResponse<'_>,
    ) -> Result<Session, WireGuardError> {
        // Check if there is a handshake awaiting a response and return the correct one
        let (state, is_previous) = match (&self.state, &self.previous) {
            (HandshakeState::InitSent(s), _) if s.local_index == packet.receiver_idx => (s, false),
            (_, HandshakeState::InitSent(s)) if s.local_index == packet.receiver_idx => (s, true),
            _ => return Err(WireGuardError::UnexpectedPacket),
        };

        let peer_index = packet.sender_idx;
        let local_index = state.local_index;

        let unencrypted_ephemeral = x25519::PublicKey::from(*packet.unencrypted_ephemeral);
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        let mut hash = b2s_hash(&state.hash, unencrypted_ephemeral.as_bytes());
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = b2s_hmac(&state.chaining_key, unencrypted_ephemeral.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        let mut chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = contributory(
            state
                .ephemeral_private
                .diffie_hellman(&unencrypted_ephemeral),
        )
        .ok_or(WireGuardError::InvalidPacket)?;
        let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let static_shared = contributory(
            self.params
                .static_private
                .diffie_hellman(&unencrypted_ephemeral),
        )
        .ok_or(WireGuardError::InvalidPacket)?;
        let temp = b2s_hmac(&chaining_key, static_shared.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = b2s_hmac(&chaining_key, &self.params.preshared_key);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = b2s_hmac2(&temp, &temp2[..], &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = b2s_hash(&hash, &temp2[..]);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_chacha20_open(&mut [], &key, 0, packet.encrypted_nothing, &hash)?;

        // responder.hash = HASH(responder.hash || msg.encrypted_nothing)
        // hash = b2s_hash(hash, buf[ENC_NOTHING_OFF..ENC_NOTHING_OFF + ENC_NOTHING_SZ]);

        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = b2s_hmac(&chaining_key, &[]);
        let temp2 = b2s_hmac(&temp1, &[0x01]);
        let temp3 = b2s_hmac2(&temp1, &temp2[..], &[0x02]);

        let rtt_time = Instant::now().duration_since(state.time_sent);
        self.last_rtt = Some(u32::try_from(rtt_time.as_millis()).unwrap_or(u32::MAX));

        if is_previous {
            self.previous = HandshakeState::None;
        } else {
            self.state = HandshakeState::None;
        }
        Ok(Session::new(local_index, peer_index, &temp3, &temp2))
    }

    pub(super) fn receive_cookie_reply(
        &mut self,
        packet: &PacketCookieReply<'_>,
    ) -> Result<(), WireGuardError> {
        let Some(mac1) = self.cookies.last_mac1 else {
            return Err(WireGuardError::UnexpectedPacket);
        };

        let local_index = self.cookies.index;
        if packet.receiver_idx != local_index {
            return Err(WireGuardError::WrongIndex);
        }
        // msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        let key = b2s_hash(LABEL_COOKIE, self.params.peer_static_public.as_bytes()); // TODO: pre-compute

        let Some((ciphertext, tag)) = packet
            .encrypted_cookie
            .split_first_chunk::<COOKIE_LEN>()
            .filter(|(_, tag)| tag.len() == COOKIE_TAG_LEN)
        else {
            return Err(WireGuardError::InvalidPacket);
        };
        // Decrypted in place, in a buffer that is wiped when the cookie is dropped.
        let mut cookie = Zeroizing::new(*ciphertext);
        XChaCha20Poly1305::new(&key.into())
            .decrypt_in_place_detached(packet.nonce.into(), &mac1, &mut cookie[..], tag.into())
            .map_err(|_| WireGuardError::InvalidAeadTag)?;

        self.cookies.write_cookie = Some(cookie);
        Ok(())
    }

    // Compute and append mac1 and mac2 to a handshake message
    fn append_mac1_and_mac2<'a>(&mut self, local_index: u32, dst: &'a mut [u8]) -> &'a mut [u8] {
        let mac1_off = dst.len() - 32;
        let mac2_off = dst.len() - 16;

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let msg_mac1 = b2s_keyed_mac_16(&self.params.sending_mac1_key, &dst[..mac1_off]);

        dst[mac1_off..mac2_off].copy_from_slice(&msg_mac1[..]);

        //msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        let msg_mac2: [u8; 16] = self
            .cookies
            .write_cookie
            .as_deref()
            .map_or([0u8; 16], |cookie| {
                b2s_keyed_mac_16(cookie, &dst[..mac2_off])
            });

        dst[mac2_off..].copy_from_slice(&msg_mac2[..]);

        self.cookies.index = local_index;
        self.cookies.last_mac1 = Some(msg_mac1);
        dst
    }

    pub(super) fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let Ok((msg, _)) = HandshakeInitMsg::mut_from_prefix(&mut *dst) else {
            return Err(WireGuardError::DestinationBufferTooSmall);
        };
        // Fails before any state changes if the peer's static key has small order.
        self.params.static_shared()?;
        let HandshakeInitMsg {
            message_type,
            sender_index,
            unencrypted_ephemeral,
            encrypted_static,
            encrypted_timestamp,
            macs: _,
        } = msg;

        let local_index = self.inc_index();

        // initiator.chaining_key = HASH(CONSTRUCTION)
        let mut chaining_key = Zeroizing::new(INITIAL_CHAIN_KEY);
        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        let mut hash = INITIAL_CHAIN_HASH;
        hash = b2s_hash(&hash, self.params.peer_static_public.as_bytes());
        // initiator.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519::ReusableSecret::random_from_rng(OsRng);
        // msg.message_type = 1
        // msg.reserved_zero = { 0, 0, 0 }
        *message_type = HANDSHAKE_INIT.into();
        // msg.sender_index = little_endian(initiator.sender_index)
        *sender_index = local_index.into();
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral
            .copy_from_slice(x25519::PublicKey::from(&ephemeral_private).as_bytes());
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, unencrypted_ephemeral);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&b2s_hmac(&chaining_key, unencrypted_ephemeral), &[0x01]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let ephemeral_shared =
            contributory(ephemeral_private.diffie_hellman(&self.params.peer_static_public))
                .ok_or(WireGuardError::WrongKey)?;
        let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        aead_chacha20_seal(
            encrypted_static,
            &key,
            0,
            self.params.static_public.as_bytes(),
            &hash,
        );
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = b2s_hash(&hash, encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = b2s_hmac(&chaining_key, self.params.static_shared()?.as_bytes());
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let timestamp = self.stamper.stamp();
        aead_chacha20_seal(encrypted_timestamp, &key, 0, &timestamp, &hash);
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = b2s_hash(&hash, encrypted_timestamp);

        let time_now = Instant::now();
        self.previous = std::mem::replace(
            &mut self.state,
            HandshakeState::InitSent(HandshakeInitSentState {
                local_index,
                chaining_key,
                hash,
                ephemeral_private,
                time_sent: time_now,
            }),
        );

        Ok(self.append_mac1_and_mac2(local_index, &mut dst[..HANDSHAKE_INIT_SZ]))
    }

    fn format_handshake_response<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<(&'a mut [u8], Session), WireGuardError> {
        if dst.len() < HANDSHAKE_RESP_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let state = std::mem::replace(&mut self.state, HandshakeState::None);
        let HandshakeState::InitReceived {
            mut chaining_key,
            mut hash,
            peer_ephemeral_public,
            peer_index,
        } = state
        else {
            self.state = state;
            return Err(WireGuardError::UnexpectedPacket);
        };

        let Ok((msg, _)) = HandshakeRespMsg::mut_from_prefix(&mut *dst) else {
            return Err(WireGuardError::DestinationBufferTooSmall);
        };
        let HandshakeRespMsg {
            message_type,
            sender_index,
            receiver_index,
            unencrypted_ephemeral,
            encrypted_nothing,
            macs: _,
        } = msg;

        // responder.ephemeral_private = DH_GENERATE()
        let ephemeral_private = x25519::ReusableSecret::random_from_rng(OsRng);
        let local_index = self.inc_index();
        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        *message_type = HANDSHAKE_RESP.into();
        // msg.sender_index = little_endian(responder.sender_index)
        *sender_index = local_index.into();
        // msg.receiver_index = little_endian(initiator.sender_index)
        *receiver_index = peer_index.into();
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        unencrypted_ephemeral
            .copy_from_slice(x25519::PublicKey::from(&ephemeral_private).as_bytes());
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, unencrypted_ephemeral);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = b2s_hmac(&chaining_key, unencrypted_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared =
            contributory(ephemeral_private.diffie_hellman(&peer_ephemeral_public))
                .ok_or(WireGuardError::InvalidPacket)?;
        let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let static_shared =
            contributory(ephemeral_private.diffie_hellman(&self.params.peer_static_public))
                .ok_or(WireGuardError::WrongKey)?;
        let temp = b2s_hmac(&chaining_key, static_shared.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = b2s_hmac(&chaining_key, &self.params.preshared_key);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = b2s_hmac2(&temp, &temp2[..], &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = b2s_hash(&hash, &temp2[..]);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_chacha20_seal(encrypted_nothing, &key, 0, &[], &hash);

        // Derive keys
        // temp1 = HMAC(initiator.chaining_key, [empty])
        // temp2 = HMAC(temp1, 0x1)
        // temp3 = HMAC(temp1, temp2 || 0x2)
        // initiator.sending_key = temp2
        // initiator.receiving_key = temp3
        // initiator.sending_key_counter = 0
        // initiator.receiving_key_counter = 0
        let temp1 = b2s_hmac(&chaining_key, &[]);
        let temp2 = b2s_hmac(&temp1, &[0x01]);
        let temp3 = b2s_hmac2(&temp1, &temp2[..], &[0x02]);

        let dst = self.append_mac1_and_mac2(local_index, &mut dst[..HANDSHAKE_RESP_SZ]);

        Ok((dst, Session::new(local_index, peer_index, &temp2, &temp3)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_of_a_received_initiation_hides_the_chaining_key() {
        let state = HandshakeState::InitReceived {
            hash: [0x11; KEY_LEN],
            chaining_key: Zeroizing::new([0xAB; KEY_LEN]),
            peer_ephemeral_public: x25519::PublicKey::from([9; KEY_LEN]),
            peer_index: 7,
        };
        let debug = format!("{state:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        // 0xAB prints as 171.
        assert!(!debug.contains("171"), "{debug}");
    }
    #[test]
    fn chacha20_seal_rfc7530_test_vector() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let expected_ciphertext: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let mut buffer = vec![0; plaintext.len() + 16];
        aead_chacha20_seal_inner(&mut buffer, &key, nonce, plaintext, &aad);

        assert_eq!(buffer[..plaintext.len()], expected_ciphertext);
        assert_eq!(buffer[plaintext.len()..], expected_tag);
    }

    /// Public keys of small order: X25519 with any private key gives the all-zero result.
    const LOW_ORDER_POINTS: [[u8; KEY_LEN]; 2] = [[0; KEY_LEN], {
        let mut one = [0; KEY_LEN];
        one[0] = 1;
        one
    }];

    struct ForgedInitiation {
        ephemeral: [u8; KEY_LEN],
        encrypted_static: [u8; KEY_LEN + 16],
        encrypted_timestamp: [u8; TIMESTAMP_LEN + 16],
    }

    impl ForgedInitiation {
        fn packet(&self) -> HandshakeInit<'_> {
            HandshakeInit {
                sender_idx: 7,
                unencrypted_ephemeral: &self.ephemeral,
                encrypted_static: &self.encrypted_static,
                encrypted_timestamp: &self.encrypted_timestamp,
            }
        }
    }

    /// Builds a handshake initiation by hand from the Diffie-Hellman results, so the sender
    /// can claim public keys it has no private key for.
    fn forge_initiation(
        responder_public: &x25519::PublicKey,
        ephemeral: [u8; KEY_LEN],
        ephemeral_shared: &[u8; KEY_LEN],
        static_public: &[u8; KEY_LEN],
        static_shared: &[u8; KEY_LEN],
    ) -> ForgedInitiation {
        let mut forged = ForgedInitiation {
            ephemeral,
            encrypted_static: [0; KEY_LEN + 16],
            encrypted_timestamp: [0; TIMESTAMP_LEN + 16],
        };
        let mut hash = b2s_hash(&INITIAL_CHAIN_HASH, responder_public.as_bytes());
        hash = b2s_hash(&hash, &ephemeral);
        let mut chaining_key = b2s_hmac(&b2s_hmac(&INITIAL_CHAIN_KEY, &ephemeral), &[0x01]);
        let temp = b2s_hmac(&chaining_key, ephemeral_shared);
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let key = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);
        aead_chacha20_seal(&mut forged.encrypted_static, &key, 0, static_public, &hash);
        hash = b2s_hash(&hash, &forged.encrypted_static);
        let temp = b2s_hmac(&chaining_key, static_shared);
        chaining_key = b2s_hmac(&temp, &[0x01]);
        let key = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);
        let timestamp = TimeStamper::new().stamp();
        aead_chacha20_seal(&mut forged.encrypted_timestamp, &key, 0, &timestamp, &hash);
        forged
    }

    fn key_pair() -> (x25519::StaticSecret, x25519::PublicKey) {
        let private = x25519::StaticSecret::random_from_rng(OsRng);
        let public = x25519::PublicKey::from(&private);
        (private, public)
    }

    #[test]
    fn initiation_with_a_low_order_ephemeral_is_rejected() {
        let (initiator_private, initiator_public) = key_pair();
        let (responder_private, responder_public) = key_pair();
        let static_shared = initiator_private.diffie_hellman(&responder_public);

        for ephemeral in LOW_ORDER_POINTS {
            let forged = forge_initiation(
                &responder_public,
                ephemeral,
                &[0; KEY_LEN],
                initiator_public.as_bytes(),
                static_shared.as_bytes(),
            );
            let mut responder = Handshake::new(
                responder_private.clone(),
                responder_public,
                initiator_public,
                0,
                None,
            );

            assert!(matches!(
                parse_handshake_anon(&responder_private, &responder_public, &forged.packet()),
                Err(WireGuardError::InvalidPacket)
            ));
            let mut dst = [0u8; HANDSHAKE_RESP_SZ];
            assert!(matches!(
                responder.receive_handshake_initialization(&forged.packet(), &mut dst),
                Err(WireGuardError::InvalidPacket)
            ));
            assert!(!responder.is_in_progress());
        }
    }

    #[test]
    fn response_with_a_low_order_ephemeral_is_rejected() {
        let (initiator_private, initiator_public) = key_pair();
        let (_, responder_public) = key_pair();

        for ephemeral in LOW_ORDER_POINTS {
            let mut initiator = Handshake::new(
                initiator_private.clone(),
                initiator_public,
                responder_public,
                0,
                None,
            );
            let mut dst = [0u8; HANDSHAKE_INIT_SZ];
            initiator
                .format_handshake_initiation(&mut dst)
                .expect("an initiation is formatted");
            let HandshakeState::InitSent(sent) = &initiator.state else {
                panic!("an initiation was sent");
            };

            // The responder's side of the key schedule, with both ephemeral Diffie-Hellman
            // results all zero.
            let mut hash = b2s_hash(&sent.hash, &ephemeral);
            let mut chaining_key = b2s_hmac(&b2s_hmac(&sent.chaining_key, &ephemeral), &[0x01]);
            for _ in 0..2 {
                chaining_key = b2s_hmac(&b2s_hmac(&chaining_key, &[0; KEY_LEN]), &[0x01]);
            }
            let temp = b2s_hmac(&chaining_key, &[0; KEY_LEN]);
            chaining_key = b2s_hmac(&temp, &[0x01]);
            let temp2 = b2s_hmac2(&temp, &chaining_key[..], &[0x02]);
            let key = b2s_hmac2(&temp, &temp2[..], &[0x03]);
            hash = b2s_hash(&hash, &temp2[..]);
            let mut encrypted_nothing = [0u8; 16];
            aead_chacha20_seal(&mut encrypted_nothing, &key, 0, &[], &hash);

            let response = HandshakeResponse {
                sender_idx: 7,
                receiver_idx: sent.local_index,
                unencrypted_ephemeral: &ephemeral,
                encrypted_nothing: &encrypted_nothing,
            };
            assert!(matches!(
                initiator.receive_handshake_response(&response),
                Err(WireGuardError::InvalidPacket)
            ));
            assert!(initiator.is_init_sent());
        }
    }

    #[test]
    fn peer_with_a_low_order_static_key_cannot_handshake() {
        let (responder_private, responder_public) = key_pair();

        for peer_static in LOW_ORDER_POINTS {
            let mut handshake = Handshake::new(
                responder_private.clone(),
                responder_public,
                x25519::PublicKey::from(peer_static),
                0,
                None,
            );

            let mut dst = [0u8; HANDSHAKE_INIT_SZ];
            assert!(matches!(
                handshake.format_handshake_initiation(&mut dst),
                Err(WireGuardError::WrongKey)
            ));
            assert!(!handshake.is_in_progress());

            // Anyone can compute the static-static secret of such a peer: it is all zero.
            let ephemeral_private = x25519::ReusableSecret::random_from_rng(OsRng);
            let forged = forge_initiation(
                &responder_public,
                x25519::PublicKey::from(&ephemeral_private).to_bytes(),
                ephemeral_private
                    .diffie_hellman(&responder_public)
                    .as_bytes(),
                &peer_static,
                &[0; KEY_LEN],
            );
            let mut dst = [0u8; HANDSHAKE_RESP_SZ];
            assert!(matches!(
                handshake.receive_handshake_initialization(&forged.packet(), &mut dst),
                Err(WireGuardError::WrongKey)
            ));
            assert!(!handshake.is_in_progress());

            // A new private key does not change that.
            let (private, _) = key_pair();
            handshake.set_static_private(private);
            let mut dst = [0u8; HANDSHAKE_INIT_SZ];
            assert!(matches!(
                handshake.format_handshake_initiation(&mut dst),
                Err(WireGuardError::WrongKey)
            ));
        }
    }

    #[test]
    fn symmetric_chacha20_seal_open() {
        let aad: [u8; 32] = Default::default();
        let key: [u8; 32] = Default::default();
        let counter = 0;

        let mut encrypted_nothing: [u8; 16] = Default::default();

        aead_chacha20_seal(&mut encrypted_nothing, &key, counter, &[], &aad);

        eprintln!("encrypted_nothing: {encrypted_nothing:?}");

        aead_chacha20_open(&mut [], &key, counter, &encrypted_nothing, &aad)
            .expect("Should open what we just sealed");
    }
}
