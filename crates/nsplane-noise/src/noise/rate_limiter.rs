use super::handshake::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24};
use super::wire::{COOKIE_REPLY, CookieReplyMsg, HANDSHAKE_INIT, HANDSHAKE_RESP};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{
    COOKIE_REPLY_SZ, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ, HandshakeInit, HandshakeResponse,
    Packet, Tunn, TunnResult, WireGuardError,
};
use zerocopy::FromBytes;

use portable_atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::sleepyinstant::Instant;

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often should reset count in seconds
const RESET_PERIOD: u64 = 1;

/// The device-wide handshake budget is this many times the per-source limit. It is a backstop
/// against floods spread over many source addresses.
const GLOBAL_LIMIT_FACTOR: u64 = 10;

/// Upper bound on the number of sources tracked per reset period. Sources beyond it are
/// treated as being under load.
const MAX_TRACKED_SOURCES: usize = 4096;

type Cookie = [u8; COOKIE_SIZE];

/// Handshake counters that decide when handshakes must carry a valid cookie.
///
/// A budget allows `limit` handshakes per second and source address, and ten times that from
/// all sources together. One budget can be shared by several [`RateLimiter`]s, one per local
/// key, through [`RateLimiter::with_budget`]: the limits then hold across all those keys, so
/// adding keys does not multiply the handshakes a sender gets processed.
pub struct HandshakeBudget {
    /// Handshakes per second and source address before cookies are required
    limit: u64,
    /// Handshakes since last reset, from all sources
    count: AtomicU64,
    /// Handshakes since last reset, per source address
    per_source: Mutex<HashMap<IpAddr, u64>>,
    /// The time last reset was performed on this budget, on the clock of the caller of
    /// `reset_count_at`; `None` until its first call
    last_reset: Mutex<Option<std::time::Instant>>,
}

impl std::fmt::Debug for HandshakeBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeBudget")
            .field("limit", &self.limit)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl HandshakeBudget {
    /// Creates a budget that allows `limit` handshakes per second and source address.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            count: AtomicU64::new(0),
            per_source: Mutex::new(HashMap::new()),
            last_reset: Mutex::new(None),
        }
    }

    /// See [`RateLimiter::reset_count_at`].
    fn reset_count_at(&self, now: std::time::Instant) {
        // The rate limiter is not very accurate, but at the scale we care about it doesn't matter much
        let mut last_reset_time = self.last_reset.lock();
        if last_reset_time
            .is_none_or(|last| now.saturating_duration_since(last).as_secs() >= RESET_PERIOD)
        {
            self.count.store(0, Ordering::SeqCst);
            self.per_source.lock().clear();
            *last_reset_time = Some(now);
        }
    }

    /// Counts a handshake from `src` and returns whether it must carry a valid cookie.
    ///
    /// Only sources that exceed their own budget are asked for cookies, so one flooding source
    /// does not push every other peer into cookie mode. The device-wide count is a backstop for
    /// floods from many sources; without a source address only the device-wide `limit` applies.
    fn is_under_load(&self, src: Option<IpAddr>) -> bool {
        let total = self.count.fetch_add(1, Ordering::SeqCst);
        let Some(ip) = src else {
            return total >= self.limit;
        };
        if total >= self.limit.saturating_mul(GLOBAL_LIMIT_FACTOR) {
            return true;
        }

        let mut per_source = self.per_source.lock();
        if !per_source.contains_key(&ip) && per_source.len() >= MAX_TRACKED_SOURCES {
            return true;
        }
        let count = per_source.entry(ip).or_insert(0);
        let previous = *count;
        *count += 1;
        previous >= self.limit
    }
}

/// There are two places where WireGuard requires "randomness" for cookies
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
///
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any `DoS` prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
///
/// The keys, the cookie secret and the nonce counter belong to one local key; the handshake
/// counters live in a [`HandshakeBudget`] that several limiters may share.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    /// The handshake counters, possibly shared with the limiters of other local keys
    budget: Arc<HandshakeBudget>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limit", &self.budget.limit)
            .field("count", &self.budget.count)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Creates a rate limiter for our `public_key` that allows `limit` handshakes per second.
    pub fn new(public_key: &crate::x25519::PublicKey, limit: u64) -> Self {
        Self::with_budget(public_key, Arc::new(HandshakeBudget::new(limit)))
    }

    /// Creates a rate limiter for our `public_key` that counts handshakes against `budget`.
    ///
    /// Limiters for several local keys can share one budget: the mac1 key, the cookie key, the
    /// cookie secret and the nonce stay per limiter, so the cookies for one source differ
    /// between keys, while the per-source and global limits hold across all of them.
    pub fn with_budget(
        public_key: &crate::x25519::PublicKey,
        budget: Arc<HandshakeBudget>,
    ) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        Self {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            budget,
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Reset packet count (ideally should be called with a period of 1 second), on the crate
    /// clock (`std::time::Instant::now()`); see [`RateLimiter::reset_count_at`].
    ///
    /// Resets the shared [`HandshakeBudget`], so for every limiter that uses it.
    pub fn reset_count(&self) {
        self.reset_count_at(std::time::Instant::now());
    }

    /// Reset packet count if a reset period passed since the last reset at `now` (ideally
    /// should be called with a period of 1 second).
    ///
    /// The first call always resets. Callers must pass instants from one clock: mixing this
    /// method with [`RateLimiter::reset_count`] is only sound if `now` comes from the crate
    /// clock. A `now` before the last reset resets nothing.
    ///
    /// Resets the shared [`HandshakeBudget`], so for every limiter that uses it: call it on
    /// one of them per period.
    pub fn reset_count_at(&self, now: std::time::Instant) {
        self.budget.reset_count_at(now);
    }

    /// Compute the correct cookie value based on the current secret value and the source
    /// address, IP and port, as the whitepaper requires.
    fn current_cookie(&self, addr: SocketAddr) -> Cookie {
        let mut addr_bytes = [0u8; 18];

        let ip_len = match addr.ip() {
            IpAddr::V4(a) => {
                addr_bytes[..4].copy_from_slice(&a.octets());
                4
            }
            IpAddr::V6(a) => {
                addr_bytes[..16].copy_from_slice(&a.octets());
                16
            }
        };
        addr_bytes[ip_len..ip_len + 2].copy_from_slice(&addr.port().to_be_bytes());

        // The current cookie for a given address is
        // MAC(responder.changing_secret_every_two_minutes, initiator.ip_address || initiator.port)
        // First we derive the secret from the current time, the value of cur_counter would change with time.
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        b2s_keyed_mac_16_2(
            &self.secret_key,
            &cur_counter.to_le_bytes(),
            &addr_bytes[..ip_len + 2],
        )
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
    }

    /// Returns whether `datagram` is a handshake initiation or response whose mac1 is keyed
    /// by this limiter's public key.
    ///
    /// Counts nothing against the budget and allocates nothing; any other or truncated input
    /// gives `false`. Use it to find which local key a handshake is addressed to before
    /// [`RateLimiter::verify_packet`] on that key's limiter.
    pub fn mac1_matches(&self, datagram: &[u8]) -> bool {
        let Some(packet_type) = datagram.first_chunk::<4>().map(|b| u32::from_le_bytes(*b)) else {
            return false;
        };
        if !matches!(
            (packet_type, datagram.len()),
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) | (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ)
        ) {
            return false;
        }
        let (msg, macs) = datagram.split_at(datagram.len() - 32);
        let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
        bool::from(computed_mac1[..].ct_eq(&macs[..16]))
    }

    pub(crate) fn format_cookie_reply<'a>(
        &self,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let Ok((msg, _)) = CookieReplyMsg::mut_from_prefix(&mut *dst) else {
            return Err(WireGuardError::DestinationBufferTooSmall);
        };

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        msg.message_type = COOKIE_REPLY.into();
        // msg.receiver_index = little_endian(initiator.sender_index)
        msg.receiver_index = idx.into();
        msg.nonce = self.nonce();

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(&msg.nonce);

        msg.encrypted_cookie[..16].copy_from_slice(&cookie);
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut msg.encrypted_cookie[..16])
            .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;

        msg.encrypted_cookie[16..].copy_from_slice(&tag);

        Ok(&mut dst[..COOKIE_REPLY_SZ])
    }

    /// Verify the MAC fields on the datagram, and apply rate limiting if needed
    pub fn verify_packet<'a, 'b>(
        &self,
        src_addr: Option<SocketAddr>,
        src: &'a [u8],
        dst: &'b mut [u8],
    ) -> Result<Packet<'a>, TunnResult<'b>> {
        let packet = Tunn::parse_incoming_packet(src)?;

        // Verify and rate limit handshake messages only
        if let Packet::HandshakeInit(HandshakeInit { sender_idx, .. })
        | Packet::HandshakeResponse(HandshakeResponse { sender_idx, .. }) = packet
        {
            let (msg, macs) = src.split_at(src.len() - 32);
            let (mac1, mac2) = macs.split_at(16);

            let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
            if !bool::from(computed_mac1[..].ct_eq(mac1)) {
                return Err(TunnResult::Err(WireGuardError::InvalidMac));
            }

            if self.budget.is_under_load(src_addr.map(|a| a.ip())) {
                let Some(addr) = src_addr else {
                    return Err(TunnResult::Err(WireGuardError::UnderLoad));
                };

                // Only given an address can we validate mac2
                let cookie = self.current_cookie(addr);
                let computed_mac2 = b2s_keyed_mac_16_2(&cookie, msg, mac1);

                if !bool::from(computed_mac2[..].ct_eq(mac2)) {
                    let cookie_packet = self
                        .format_cookie_reply(sender_idx, cookie, mac1, dst)
                        .map_err(TunnResult::Err)?;
                    return Err(TunnResult::WriteToNetwork(cookie_packet));
                }
            }
        }

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x25519::{PublicKey, StaticSecret};

    struct Initiator {
        tunn: Tunn,
    }

    impl Initiator {
        fn new(responder: &PublicKey) -> Self {
            let tunn = Tunn::new(
                StaticSecret::random_from_rng(OsRng),
                *responder,
                None,
                None,
                OsRng.next_u32() >> 8,
                None,
            );
            Self { tunn }
        }

        fn handshake_init(&mut self) -> Vec<u8> {
            let mut dst = [0u8; 256];
            match self.tunn.format_handshake_initiation(&mut dst, true) {
                TunnResult::WriteToNetwork(p) => p.to_vec(),
                other => panic!("expected a handshake initiation, got {other:?}"),
            }
        }
    }

    fn responder(limit: u64) -> (RateLimiter, PublicKey) {
        let public = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        (RateLimiter::new(&public, limit), public)
    }

    fn is_cookie_reply(result: &Result<Packet<'_>, TunnResult<'_>>) -> bool {
        matches!(result, Err(TunnResult::WriteToNetwork(_)))
    }

    #[test]
    fn cookie_is_bound_to_source_port() {
        let (limiter, public) = responder(0);
        let mut initiator = Initiator::new(&public);
        let mut dst = [0u8; 256];
        let addr = SocketAddr::from(([192, 0, 2, 1], 1000));
        let same_ip_other_port = SocketAddr::from(([192, 0, 2, 1], 2000));

        // Under load: the first initiation is answered with a cookie.
        let init = initiator.handshake_init();
        let Err(TunnResult::WriteToNetwork(cookie_reply)) =
            limiter.verify_packet(Some(addr), &init, &mut dst)
        else {
            panic!("expected a cookie reply");
        };
        let cookie_reply = cookie_reply.to_vec();
        let mut scratch = [0u8; 256];
        assert!(matches!(
            initiator
                .tunn
                .decapsulate(None, &cookie_reply, &mut scratch),
            TunnResult::Done
        ));

        // The initiation now carries a valid mac2 for `addr` only.
        let init = initiator.handshake_init();
        assert!(limiter.verify_packet(Some(addr), &init, &mut dst).is_ok());
        assert!(is_cookie_reply(&limiter.verify_packet(
            Some(same_ip_other_port),
            &init,
            &mut dst
        )));
    }

    #[test]
    fn flooding_source_does_not_put_other_sources_into_cookie_mode() {
        let (limiter, public) = responder(2);
        let mut flooder = Initiator::new(&public);
        let mut honest = Initiator::new(&public);
        let mut dst = [0u8; 256];
        let flooder_ip = SocketAddr::from(([192, 0, 2, 1], 1000));
        let honest_ip = SocketAddr::from(([192, 0, 2, 2], 1000));

        for _ in 0..2 {
            let init = flooder.handshake_init();
            assert!(
                limiter
                    .verify_packet(Some(flooder_ip), &init, &mut dst)
                    .is_ok()
            );
        }
        let init = flooder.handshake_init();
        assert!(is_cookie_reply(&limiter.verify_packet(
            Some(flooder_ip),
            &init,
            &mut dst
        )));

        let init = honest.handshake_init();
        assert!(
            limiter
                .verify_packet(Some(honest_ip), &init, &mut dst)
                .is_ok()
        );
    }

    fn shared_responders(limit: u64) -> [(RateLimiter, PublicKey); 2] {
        let budget = Arc::new(HandshakeBudget::new(limit));
        [(); 2].map(|()| {
            let public = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
            (
                RateLimiter::with_budget(&public, Arc::clone(&budget)),
                public,
            )
        })
    }

    #[test]
    fn shared_budget_limits_a_source_across_keys() {
        let [(first, first_public), (second, second_public)] = shared_responders(2);
        let mut to_first = Initiator::new(&first_public);
        let mut to_second = Initiator::new(&second_public);
        let mut dst = [0u8; 256];
        let flooder = SocketAddr::from(([192, 0, 2, 1], 1000));
        let other = SocketAddr::from(([192, 0, 2, 2], 1000));

        for _ in 0..2 {
            let init = to_first.handshake_init();
            assert!(first.verify_packet(Some(flooder), &init, &mut dst).is_ok());
        }
        // The flood to the first key put the source into cookie mode for the second key too.
        let init = to_second.handshake_init();
        assert!(is_cookie_reply(&second.verify_packet(
            Some(flooder),
            &init,
            &mut dst
        )));
        assert!(second.verify_packet(Some(other), &init, &mut dst).is_ok());

        // One reset on the first limiter clears the budget for both.
        first.reset_count();
        assert!(second.verify_packet(Some(flooder), &init, &mut dst).is_ok());
    }

    #[test]
    fn shared_budget_global_limit_spans_keys() {
        let [(first, first_public), (second, second_public)] = shared_responders(1);
        let mut to_first = Initiator::new(&first_public);
        let mut to_second = Initiator::new(&second_public);
        let mut dst = [0u8; 256];

        // Ten sources use up the global budget (ten times the per-source limit) on the first key.
        for host in 1..=10 {
            let init = to_first.handshake_init();
            let src = SocketAddr::from(([192, 0, 2, host], 1000));
            assert!(first.verify_packet(Some(src), &init, &mut dst).is_ok());
        }
        // A fresh source to the second key is under load.
        let init = to_second.handshake_init();
        let fresh = SocketAddr::from(([192, 0, 2, 11], 1000));
        assert!(is_cookie_reply(&second.verify_packet(
            Some(fresh),
            &init,
            &mut dst
        )));
    }

    #[test]
    fn limiters_sharing_a_budget_give_different_cookies() {
        let [(first, _), (second, _)] = shared_responders(0);
        let addr = SocketAddr::from(([192, 0, 2, 1], 1000));
        assert_ne!(first.current_cookie(addr), second.current_cookie(addr));
    }

    #[test]
    fn mac1_matches_only_its_own_key() {
        let [(first, first_public), (second, _)] = shared_responders(0);
        let mut initiator = Initiator::new(&first_public);
        let init = initiator.handshake_init();

        assert!(first.mac1_matches(&init));
        assert!(!second.mac1_matches(&init));
        assert!(!first.mac1_matches(&init[..init.len() - 1]));
        assert!(!first.mac1_matches(&[]));
        assert!(!first.mac1_matches(&[1, 0, 0]));
        let mut other_type = init;
        other_type[0] = 4;
        assert!(!first.mac1_matches(&other_type));

        // Matching counts nothing: after any number of matches, a limit of one still lets the
        // first verified initiation through without a cookie.
        let [(fresh, fresh_public), _] = shared_responders(1);
        let init = Initiator::new(&fresh_public).handshake_init();
        for _ in 0..10 {
            assert!(fresh.mac1_matches(&init));
        }
        let mut dst = [0u8; 256];
        let src = SocketAddr::from(([192, 0, 2, 1], 1000));
        assert!(fresh.verify_packet(Some(src), &init, &mut dst).is_ok());
    }

    #[test]
    fn mac1_matches_a_handshake_response_for_the_initiator_key() {
        let initiator_secret = StaticSecret::random_from_rng(OsRng);
        let initiator_public = PublicKey::from(&initiator_secret);
        let responder_secret = StaticSecret::random_from_rng(OsRng);
        let responder_public = PublicKey::from(&responder_secret);
        let mut initiator = Tunn::new(initiator_secret, responder_public, None, None, 1, None);
        let mut responder = Tunn::new(responder_secret, initiator_public, None, None, 2, None);

        let mut dst = [0u8; 256];
        let TunnResult::WriteToNetwork(init) =
            initiator.format_handshake_initiation(&mut dst, true)
        else {
            panic!("expected a handshake initiation");
        };
        let init = init.to_vec();
        let TunnResult::WriteToNetwork(response) = responder.decapsulate(None, &init, &mut dst)
        else {
            panic!("expected a handshake response");
        };

        let initiator_limiter = RateLimiter::new(&initiator_public, 0);
        let responder_limiter = RateLimiter::new(&responder_public, 0);
        assert!(initiator_limiter.mac1_matches(response));
        assert!(!responder_limiter.mac1_matches(response));
    }

    /// Golden values computed on the 0.11 single-key limiter: the mac1 it accepts, the mac2 it
    /// accepts under load and the cookie reply it sends, for fixed keys, a fixed initiation body
    /// and a fixed source. The cookie secret and the nonce key are random in production; the test
    /// pins them so the values are reproducible.
    mod golden {
        use super::*;

        const SECRET_KEY: [u8; 16] = [9; 16];
        const NONCE_KEY: [u8; 32] = [5; 32];
        const SENDER_INDEX: u32 = 0x1122_3344;

        const MAC1: [u8; 16] = [
            63, 220, 229, 120, 62, 28, 59, 209, 110, 195, 144, 168, 166, 61, 170, 89,
        ];
        const MAC2: [u8; 16] = [
            91, 99, 241, 93, 72, 229, 183, 206, 225, 148, 187, 234, 231, 205, 43, 16,
        ];
        const COOKIE_REPLY_BYTES: [u8; 64] = [
            3, 0, 0, 0, 68, 51, 34, 17, 43, 111, 33, 127, 148, 23, 108, 21, 101, 196, 196, 179, 72,
            55, 146, 129, 114, 156, 250, 130, 137, 68, 230, 41, 124, 113, 218, 76, 19, 238, 29,
            233, 217, 237, 255, 124, 42, 231, 227, 90, 36, 85, 180, 97, 157, 183, 6, 150, 65, 83,
            244, 76, 210, 92, 42, 2,
        ];

        fn responder_public() -> PublicKey {
            PublicKey::from(&StaticSecret::from([7; 32]))
        }

        fn limiter(limit: u64) -> RateLimiter {
            let mut limiter = RateLimiter::new(&responder_public(), limit);
            limiter.secret_key = SECRET_KEY;
            limiter.nonce_key = NONCE_KEY;
            limiter
        }

        fn source() -> SocketAddr {
            SocketAddr::from(([192, 0, 2, 1], 51820))
        }

        /// The first 116 bytes of a handshake initiation: type 1, a fixed sender index and a
        /// fixed pattern for the ephemeral, the encrypted static and the encrypted timestamp.
        fn body() -> [u8; 116] {
            let mut body = [0u8; 116];
            body[..4].copy_from_slice(&1u32.to_le_bytes());
            body[4..8].copy_from_slice(&SENDER_INDEX.to_le_bytes());
            for (i, b) in body[8..].iter_mut().enumerate() {
                *b = u8::try_from(i).unwrap_or(0);
            }
            body
        }

        fn datagram(mac1: [u8; 16], mac2: [u8; 16]) -> [u8; 148] {
            let mut datagram = [0u8; 148];
            datagram[..116].copy_from_slice(&body());
            datagram[116..132].copy_from_slice(&mac1);
            datagram[132..].copy_from_slice(&mac2);
            datagram
        }

        #[test]
        fn mac1_is_the_0_11_value() {
            let limiter = limiter(u64::MAX);
            let mut dst = [0u8; 256];
            assert!(
                limiter
                    .verify_packet(Some(source()), &datagram(MAC1, [0; 16]), &mut dst)
                    .is_ok()
            );
            let mut wrong = MAC1;
            wrong[0] ^= 1;
            assert!(matches!(
                limiter.verify_packet(Some(source()), &datagram(wrong, [0; 16]), &mut dst),
                Err(TunnResult::Err(WireGuardError::InvalidMac))
            ));
        }

        #[test]
        fn mac2_under_load_is_the_0_11_value() {
            let limiter = limiter(0);
            let mut dst = [0u8; 256];
            assert!(
                limiter
                    .verify_packet(Some(source()), &datagram(MAC1, MAC2), &mut dst)
                    .is_ok()
            );
            assert!(is_cookie_reply(&limiter.verify_packet(
                Some(source()),
                &datagram(MAC1, [0; 16]),
                &mut dst
            )));
        }

        #[test]
        fn cookie_reply_is_the_0_11_layout() {
            let limiter = limiter(0);
            let mut dst = [0u8; 256];
            let Err(TunnResult::WriteToNetwork(reply)) =
                limiter.verify_packet(Some(source()), &datagram(MAC1, [0; 16]), &mut dst)
            else {
                panic!("expected a cookie reply");
            };
            let reply = reply.to_vec();
            assert_eq!(reply, COOKIE_REPLY_BYTES);

            assert_eq!(reply.len(), 64);
            assert_eq!(reply[..4], [3, 0, 0, 0]);
            assert_eq!(reply[4..8], SENDER_INDEX.to_le_bytes());

            // The initiator decrypts the cookie under HASH(LABEL_COOKIE || responder public)
            // with its mac1 as associated data, and the cookie keys the expected mac2.
            let key = b2s_hash(LABEL_COOKIE, responder_public().as_bytes());
            let mut cookie = [0u8; 16];
            cookie.copy_from_slice(&reply[32..48]);
            XChaCha20Poly1305::new(&key.into())
                .decrypt_in_place_detached(
                    GenericArray::from_slice(&reply[8..32]),
                    &MAC1,
                    &mut cookie,
                    GenericArray::from_slice(&reply[48..64]),
                )
                .expect("the cookie reply decrypts");
            assert_eq!(b2s_keyed_mac_16_2(&cookie, &body(), &MAC1), MAC2);
        }
    }
}
