// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The peers of a device, indexed by public key, session index and allowed IP.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};

use super::allowed_ips::AllowedIps;
use super::peer::{AllowedIP, Peer};
use crate::noise::Tunn;
use crate::noise::rate_limiter::RateLimiter;
use crate::x25519::{PublicKey, StaticSecret};

/// A shared, lockable peer.
pub(crate) type SharedPeer = Arc<Mutex<Peer>>;

/// One peer section of a UAPI `set` request.
#[derive(Debug, Clone)]
pub(crate) struct PeerUpdate {
    pub(crate) public_key: PublicKey,
    pub(crate) remove: bool,
    pub(crate) replace_allowed_ips: bool,
    pub(crate) endpoint: Option<SocketAddr>,
    pub(crate) allowed_ips: Vec<AllowedIP>,
    /// `Some(0)` disables the persistent keepalive.
    pub(crate) persistent_keepalive: Option<u16>,
    /// `Some([0; 32])` removes the preshared key.
    pub(crate) preshared_key: Option<[u8; 32]>,
}

impl PeerUpdate {
    /// An update that changes nothing about `public_key` (or adds it without settings).
    pub(crate) const fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            remove: false,
            replace_allowed_ips: false,
            endpoint: None,
            allowed_ips: Vec::new(),
            persistent_keepalive: None,
            preshared_key: None,
        }
    }
}

/// Why a [`PeerUpdate`] could not be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerTableError {
    /// All 2^24 session indices are in use.
    IndicesExhausted,
}

/// The peers of a device.
///
/// Peers are reachable by public key, by the session index in received messages, and by
/// allowed IP (cryptokey routing). Allowed IPs exist only in the routing table, so a range that
/// a newer peer claims is moved away from its previous owner.
#[derive(Default)]
pub(crate) struct PeerTable {
    by_key: HashMap<PublicKey, SharedPeer>,
    by_idx: HashMap<u32, SharedPeer>,
    by_ip: AllowedIps<SharedPeer>,
    next_index: IndexLfsr,
}

impl std::fmt::Debug for PeerTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerTable")
            .field("peers", &self.len())
            .finish_non_exhaustive()
    }
}

impl PeerTable {
    /// Applies one UAPI peer section: removes, adds, or updates the peer in place.
    pub(crate) fn apply(
        &mut self,
        update: PeerUpdate,
        private_key: &StaticSecret,
        rate_limiter: Option<&Arc<RateLimiter>>,
    ) -> Result<(), PeerTableError> {
        if update.remove {
            self.remove(&update.public_key);
            return Ok(());
        }

        // An all-zero key means "no preshared key" in the UAPI.
        let preshared_key = update.preshared_key.map(|k| (k != [0; 32]).then_some(k));

        let peer = if let Some(peer) = self.by_key.get(&update.public_key) {
            let mut p = peer.lock();
            if let Some(endpoint) = update.endpoint {
                p.set_endpoint(endpoint);
            }
            if let Some(interval) = update.persistent_keepalive {
                p.set_persistent_keepalive(interval);
            }
            if let Some(preshared_key) = preshared_key {
                p.set_preshared_key(preshared_key);
            }
            drop(p);
            Arc::clone(peer)
        } else {
            let index = self
                .next_index
                .next()
                .ok_or(PeerTableError::IndicesExhausted)?;
            let preshared_key = preshared_key.flatten();
            let tunnel = Tunn::new(
                private_key.clone(),
                update.public_key,
                preshared_key,
                update.persistent_keepalive.filter(|&k| k > 0),
                index,
                rate_limiter.cloned(),
            );
            let peer = Arc::new(Mutex::new(Peer::new(
                tunnel,
                index,
                update.endpoint,
                preshared_key,
            )));
            self.by_key.insert(update.public_key, Arc::clone(&peer));
            self.by_idx.insert(index, Arc::clone(&peer));
            tracing::info!("Peer added");
            peer
        };

        if update.replace_allowed_ips {
            self.by_ip.remove(&|p: &SharedPeer| Arc::ptr_eq(p, &peer));
        }
        for AllowedIP { addr, cidr } in update.allowed_ips {
            self.by_ip.insert(addr, cidr, Arc::clone(&peer));
        }
        Ok(())
    }

    /// Removes a peer and closes its connected socket.
    pub(crate) fn remove(&mut self, public_key: &PublicKey) {
        if let Some(peer) = self.by_key.remove(public_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.lock();
                p.shutdown_endpoint(); // close open udp socket and free the closure
                self.by_idx.remove(&p.index());
            }
            self.by_ip.remove(&|p: &SharedPeer| Arc::ptr_eq(&peer, p));

            tracing::info!("Peer removed");
        }
    }

    /// Removes all peers.
    pub(crate) fn clear(&mut self) {
        for peer in self.by_key.values() {
            peer.lock().shutdown_endpoint();
        }
        self.by_key.clear();
        self.by_idx.clear();
        self.by_ip.clear();
    }

    /// The peer with this public key.
    pub(crate) fn get(&self, public_key: &PublicKey) -> Option<&SharedPeer> {
        self.by_key.get(public_key)
    }

    /// The peer that owns the session index in a received message (`receiver_idx`).
    pub(crate) fn by_index(&self, receiver_idx: u32) -> Option<&SharedPeer> {
        self.by_idx.get(&(receiver_idx >> 8))
    }

    /// The peer to send a packet for `dst` to (cryptokey routing).
    pub(crate) fn by_destination(&self, dst: IpAddr) -> Option<&SharedPeer> {
        self.by_ip.find(dst)
    }

    /// Whether `peer` may send packets from `src`: the longest allowed-IP match of `src`
    /// across all peers must be `peer` itself.
    pub(crate) fn routes_to(&self, src: IpAddr, peer: &SharedPeer) -> bool {
        self.by_ip.find(src).is_some_and(|p| Arc::ptr_eq(p, peer))
    }

    /// The allowed IPs of `peer` as `(network address, prefix length)`.
    pub(crate) fn allowed_ips(&self, peer: &SharedPeer) -> Vec<(IpAddr, u8)> {
        self.by_ip
            .iter()
            .filter(|(p, _, _)| Arc::ptr_eq(p, peer))
            .map(|(_, ip, cidr)| (ip, cidr))
            .collect()
    }

    /// All peers with their public keys.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&PublicKey, &SharedPeer)> {
        self.by_key.iter()
    }

    /// All peers.
    pub(crate) fn peers(&self) -> impl Iterator<Item = &SharedPeer> {
        self.by_key.values()
    }

    /// Number of peers.
    pub(crate) fn len(&self) -> usize {
        self.by_key.len()
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
#[derive(Debug)]
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0x00ff_ffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence, or `None` once the sequence
    /// is exhausted.
    const fn next(&mut self) -> Option<u32> {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0x00d8_0000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        let next = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        if next == self.initial {
            return None;
        }
        self.lfsr = next;
        Some(value ^ self.mask)
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        Self {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x25519::{PublicKey, StaticSecret};
    use rand_core::OsRng;
    use std::net::{IpAddr, SocketAddr};

    fn key() -> PublicKey {
        PublicKey::from(&StaticSecret::random_from_rng(OsRng))
    }

    fn net(s: &str) -> AllowedIP {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn add(table: &mut PeerTable, own: &StaticSecret, peer: PublicKey, ips: &[&str]) {
        let mut update = PeerUpdate::new(peer);
        update.allowed_ips = ips.iter().copied().map(net).collect();
        table.apply(update, own, None).unwrap();
    }

    #[test]
    fn adds_and_indexes_a_peer() {
        let own = StaticSecret::random_from_rng(OsRng);
        let mut table = PeerTable::default();
        let a = key();
        add(&mut table, &own, a, &["10.0.0.0/16"]);

        let peer = table.get(&a).unwrap();
        let index = peer.lock().index();
        assert!(Arc::ptr_eq(table.by_index(index << 8).unwrap(), peer));
        assert!(Arc::ptr_eq(
            table.by_destination(ip("10.0.3.4")).unwrap(),
            peer
        ));
        assert_eq!(table.allowed_ips(peer), vec![(ip("10.0.0.0"), 16)]);
    }

    #[test]
    fn source_check_uses_the_longest_match_across_peers() {
        let own = StaticSecret::random_from_rng(OsRng);
        let mut table = PeerTable::default();
        let (a, b) = (key(), key());
        add(&mut table, &own, a, &["10.0.0.0/16"]);
        add(&mut table, &own, b, &["10.0.1.0/24"]);
        let (peer_a, peer_b) = (table.get(&a).unwrap(), table.get(&b).unwrap());

        // 10.0.1.5 belongs to B even though it is also inside A's /16.
        assert!(!table.routes_to(ip("10.0.1.5"), peer_a));
        assert!(table.routes_to(ip("10.0.1.5"), peer_b));
        assert!(table.routes_to(ip("10.0.2.5"), peer_a));
        assert!(!table.routes_to(ip("192.0.2.1"), peer_a));
    }

    #[test]
    fn updates_an_existing_peer_in_place() {
        let own = StaticSecret::random_from_rng(OsRng);
        let mut table = PeerTable::default();
        let a = key();
        add(&mut table, &own, a, &["10.0.0.0/24"]);
        let index = table.get(&a).unwrap().lock().index();

        let endpoint: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let mut update = PeerUpdate::new(a);
        update.endpoint = Some(endpoint);
        update.persistent_keepalive = Some(25);
        update.preshared_key = Some([7; 32]);
        update.allowed_ips = vec![net("10.0.1.0/24")];
        table.apply(update, &own, None).unwrap();

        let peer = table.get(&a).unwrap();
        let p = peer.lock();
        assert_eq!(p.index(), index, "the peer keeps its sessions");
        assert_eq!(p.endpoint().addr, Some(endpoint));
        assert_eq!(p.persistent_keepalive(), Some(25));
        assert_eq!(p.preshared_key(), Some(&[7; 32]));
        drop(p);
        // Without replace_allowed_ips the new range is added.
        assert_eq!(
            table.allowed_ips(peer),
            vec![(ip("10.0.0.0"), 24), (ip("10.0.1.0"), 24)]
        );
    }

    #[test]
    fn replace_allowed_ips_drops_the_old_ranges() {
        let own = StaticSecret::random_from_rng(OsRng);
        let mut table = PeerTable::default();
        let a = key();
        add(&mut table, &own, a, &["10.0.0.0/24", "10.0.1.0/24"]);

        let mut update = PeerUpdate::new(a);
        update.replace_allowed_ips = true;
        update.allowed_ips = vec![net("10.0.2.0/24")];
        table.apply(update, &own, None).unwrap();

        let peer = table.get(&a).unwrap();
        assert_eq!(table.allowed_ips(peer), vec![(ip("10.0.2.0"), 24)]);
        assert!(table.by_destination(ip("10.0.0.1")).is_none());
    }

    #[test]
    fn an_allowed_ip_moves_to_the_peer_that_claims_it_last() {
        let own = StaticSecret::random_from_rng(OsRng);
        let mut table = PeerTable::default();
        let (a, b) = (key(), key());
        add(&mut table, &own, a, &["10.0.0.0/24"]);
        add(&mut table, &own, b, &["10.0.0.0/24"]);

        assert_eq!(table.allowed_ips(table.get(&a).unwrap()), Vec::new());
        assert!(table.routes_to(ip("10.0.0.1"), table.get(&b).unwrap()));
    }

    #[test]
    fn zero_preshared_key_clears_it() {
        let own = StaticSecret::random_from_rng(OsRng);
        let mut table = PeerTable::default();
        let a = key();
        let mut update = PeerUpdate::new(a);
        update.preshared_key = Some([7; 32]);
        table.apply(update, &own, None).unwrap();

        let mut update = PeerUpdate::new(a);
        update.preshared_key = Some([0; 32]);
        table.apply(update, &own, None).unwrap();
        assert_eq!(table.get(&a).unwrap().lock().preshared_key(), None);
    }

    #[test]
    fn remove_drops_every_index() {
        let own = StaticSecret::random_from_rng(OsRng);
        let mut table = PeerTable::default();
        let a = key();
        add(&mut table, &own, a, &["10.0.0.0/24"]);
        let index = table.get(&a).unwrap().lock().index();

        let mut update = PeerUpdate::new(a);
        update.remove = true;
        table.apply(update, &own, None).unwrap();

        assert!(table.get(&a).is_none());
        assert!(table.by_index(index << 8).is_none());
        assert!(table.by_destination(ip("10.0.0.1")).is_none());
        assert_eq!(table.len(), 0);
    }
}
