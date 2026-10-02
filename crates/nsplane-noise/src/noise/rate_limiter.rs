use super::handshake::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24};
use super::wire::{COOKIE_REPLY, CookieReplyMsg};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{
    COOKIE_REPLY_SZ, HandshakeInit, HandshakeResponse, Packet, Tunn, TunnResult, WireGuardError,
};
use zerocopy::FromBytes;

use portable_atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

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

/// There are two places where WireGuard requires "randomness" for cookies
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
///
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any `DoS` prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
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
    /// Handshakes per second and source address before cookies are required
    limit: u64,
    /// Handshakes since last reset, from all sources
    count: AtomicU64,
    /// Handshakes since last reset, per source address
    per_source: Mutex<HashMap<IpAddr, u64>>,
    /// The time last reset was performed on this rate limiter, on the clock of the caller of
    /// `reset_count_at`; `None` until its first call
    last_reset: Mutex<Option<std::time::Instant>>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limit", &self.limit)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Creates a rate limiter for our `public_key` that allows `limit` handshakes per second.
    pub fn new(public_key: &crate::x25519::PublicKey, limit: u64) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        Self {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            count: AtomicU64::new(0),
            per_source: Mutex::new(HashMap::new()),
            last_reset: Mutex::new(None),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Reset packet count (ideally should be called with a period of 1 second), on the crate
    /// clock (`std::time::Instant::now()`); see [`RateLimiter::reset_count_at`].
    pub fn reset_count(&self) {
        self.reset_count_at(std::time::Instant::now());
    }

    /// Reset packet count if a reset period passed since the last reset at `now` (ideally
    /// should be called with a period of 1 second).
    ///
    /// The first call always resets. Callers must pass instants from one clock: mixing this
    /// method with [`RateLimiter::reset_count`] is only sound if `now` comes from the crate
    /// clock. A `now` before the last reset resets nothing.
    pub fn reset_count_at(&self, now: std::time::Instant) {
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

            if self.is_under_load(src_addr.map(|a| a.ip())) {
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
}
