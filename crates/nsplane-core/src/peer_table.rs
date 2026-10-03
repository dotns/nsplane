// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The peers of the core, indexed by peer id, public key, session index and allowed IP.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use nsplane_noise::noise::rate_limiter::RateLimiter;
use nsplane_noise::noise::{Tunn, TunnResult};
use nsplane_noise::x25519::{PublicKey, StaticSecret};
use nsplane_packet::PeerId;
use rand_core::{OsRng, RngCore};

use crate::allowed_ips::AllowedIps;
use crate::peer::Peer;
use crate::types::{AllowedIp, PeerConfig};

/// Why a [`PeerConfig`] could not be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerTableError {
    /// No private key is set, so no tunnel can be created.
    NoPrivateKey,
    /// All 2^24 session indices are in use.
    IndicesExhausted,
    /// All peer ids have been handed out.
    IdsExhausted,
}

/// The own key pair and the handshake gate derived from it.
struct OwnKey {
    private: StaticSecret,
    public: PublicKey,
    /// Verifies handshakes before they are demultiplexed to a peer. Every peer's `Tunn` shares
    /// it, so the cookie it hands out also passes the tunnel's own verification.
    gate: Arc<RateLimiter>,
}

/// Hashes a session index with one multiplication. Session indices are random and chosen by the
/// table itself, so they need no keyed hash; the multiplication spreads them over all bits.
#[derive(Debug, Default, Clone, Copy)]
struct IndexHasher(u64);

impl Hasher for IndexHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 << 8 | u64::from(b)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }

    fn write_u32(&mut self, i: u32) {
        self.0 = u64::from(i).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// The peers of the core.
///
/// Peers are reachable by id, by public key, by the session index in received messages, and by
/// allowed IP (cryptokey routing). Allowed IPs exist only in the routing table, so a range that
/// a newer peer claims is moved away from its previous owner. Peer ids are never reused. A
/// peer's inbound destinations are kept apart from the routing table, by slot.
pub(crate) struct PeerTable {
    /// Ids of the peers, ascending: ids are handed out in order, so a new peer goes last.
    ids: Vec<PeerId>,
    /// The peers, at the position of their id in `ids`.
    peers: Vec<Peer>,
    /// The inbound destinations of the peers, at the position of their id in `ids`; `None`
    /// for an unchecked peer.
    destinations: Vec<Option<AllowedIps<()>>>,
    by_key: HashMap<PublicKey, PeerId>,
    by_index: HashMap<u32, PeerId, BuildHasherDefault<IndexHasher>>,
    by_ip: AllowedIps<PeerId>,
    next_index: IndexLfsr,
    next_id: u32,
    handshake_rate_limit: u64,
    /// Whether peers share their tunnels with crypto jobs.
    shared_tunnels: bool,
    key: Option<OwnKey>,
}

impl std::fmt::Debug for PeerTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerTable")
            .field("peers", &self.len())
            .finish_non_exhaustive()
    }
}

impl PeerTable {
    /// Creates an empty table without a private key. `handshake_rate_limit` is the number of
    /// handshakes per second the gate tolerates before replying with cookies. With
    /// `shared_tunnels` every peer keeps its tunnel behind a lock, to share it with crypto
    /// jobs; otherwise it owns the tunnel.
    pub(crate) fn new(handshake_rate_limit: u64, shared_tunnels: bool) -> Self {
        Self {
            ids: Vec::new(),
            peers: Vec::new(),
            destinations: Vec::new(),
            by_key: HashMap::new(),
            by_index: HashMap::default(),
            by_ip: AllowedIps::new(),
            next_index: IndexLfsr::default(),
            next_id: 1,
            handshake_rate_limit,
            shared_tunnels,
            key: None,
        }
    }

    /// Sets the own private key, re-keys every peer (clearing its sessions) and replaces the
    /// handshake gate. Setting the current key again changes nothing.
    pub(crate) fn set_private_key(&mut self, private_key: StaticSecret) {
        let public_key = PublicKey::from(&private_key);

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if self.key.as_ref().is_some_and(|k| k.public == public_key) {
            return;
        }

        let gate = Arc::new(RateLimiter::new(&public_key, self.handshake_rate_limit));
        for peer in &mut self.peers {
            peer.tunnel_mut().set_static_private(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&gate)),
            );
        }

        self.key = Some(OwnKey {
            gate,
            private: private_key,
            public: public_key,
        });
    }

    /// Whether peers share their tunnels with crypto jobs.
    pub(crate) const fn shared_tunnels(&self) -> bool {
        self.shared_tunnels
    }

    /// The own key pair, if set.
    pub(crate) fn key_pair(&self) -> Option<(&StaticSecret, &PublicKey)> {
        self.key.as_ref().map(|k| (&k.private, &k.public))
    }

    /// The handshake gate for the own key, if set.
    pub(crate) fn rate_limiter(&self) -> Option<&RateLimiter> {
        self.key.as_ref().map(|k| &*k.gate)
    }

    /// Adds the peer, or updates it in place if its public key is known. A new peer's tunnel
    /// runs its timers on the clock of `now`.
    pub(crate) fn apply(
        &mut self,
        config: &PeerConfig,
        now: Instant,
    ) -> Result<PeerId, PeerTableError> {
        // An all-zero key means "no preshared key" in the UAPI.
        let preshared_key = config.preshared_key.map(|k| (k != [0; 32]).then_some(k));

        let id = if let Some(&id) = self.by_key.get(&config.public_key) {
            if let Some(p) = self.peer_mut(id) {
                if let Some(path) = config.path {
                    p.set_path(path);
                }
                if let Some(interval) = config.persistent_keepalive {
                    p.set_persistent_keepalive(interval);
                }
                if let Some(preshared_key) = preshared_key {
                    p.set_preshared_key(preshared_key);
                }
            }
            if let Some(destinations) = &config.inbound_destinations {
                self.set_inbound_destinations(id, Some(destinations));
            }
            id
        } else {
            let own = self.key.as_ref().ok_or(PeerTableError::NoPrivateKey)?;
            let id = PeerId::new(self.next_id);
            let next_id = self
                .next_id
                .checked_add(1)
                .ok_or(PeerTableError::IdsExhausted)?;
            let index = self
                .next_index
                .next()
                .ok_or(PeerTableError::IndicesExhausted)?;
            let preshared_key = preshared_key.flatten();
            let mut tunnel = Tunn::new(
                own.private.clone(),
                config.public_key,
                preshared_key,
                None,
                index,
                Some(Arc::clone(&own.gate)),
            );
            // Start the timers at `now`, so whatever the tunnel does before its first timer
            // tick is timed on the core's clock. A fresh tunnel without a persistent
            // keepalive has nothing due; the keepalive is enabled afterwards.
            let started = tunnel.update_timers_at(now, &mut []);
            debug_assert!(matches!(started, TunnResult::Done), "{started:?}");
            tunnel.set_persistent_keepalive(config.persistent_keepalive.filter(|&k| k > 0));
            let peer = Peer::new(
                tunnel,
                self.shared_tunnels,
                config.public_key,
                index,
                config.path,
                preshared_key,
            );
            self.next_id = next_id;
            self.ids.push(id);
            self.peers.push(peer);
            self.destinations
                .push(config.inbound_destinations.as_deref().map(destination_set));
            self.by_key.insert(config.public_key, id);
            self.by_index.insert(index, id);
            tracing::info!("Peer added");
            id
        };

        if config.replace_allowed_ips {
            self.by_ip.remove(&|p: &PeerId| *p == id);
        }
        for &AllowedIp { addr, cidr } in &config.allowed_ips {
            self.by_ip.insert(addr, cidr, id);
        }
        Ok(id)
    }

    /// Removes a peer and returns its id.
    pub(crate) fn remove(&mut self, public_key: &PublicKey) -> Option<PeerId> {
        let id = self.by_key.remove(public_key)?;
        // Found a peer to remove, now purge all references to it:
        if let Ok(i) = self.ids.binary_search(&id) {
            self.ids.remove(i);
            let peer = self.peers.remove(i);
            self.destinations.remove(i);
            self.by_index.remove(&peer.index());
        }
        self.by_ip.remove(&|p: &PeerId| *p == id);

        tracing::info!("Peer removed");
        Some(id)
    }

    /// Removes all peers.
    pub(crate) fn clear(&mut self) {
        self.ids.clear();
        self.peers.clear();
        self.destinations.clear();
        self.by_key.clear();
        self.by_index.clear();
        self.by_ip.clear();
    }

    /// The peer with this public key.
    pub(crate) fn get(&self, public_key: &PublicKey) -> Option<PeerId> {
        self.by_key.get(public_key).copied()
    }

    /// The peer with this id.
    pub(crate) fn peer(&self, id: PeerId) -> Option<&Peer> {
        let i = self.ids.binary_search(&id).ok()?;
        self.peers.get(i)
    }

    /// The peer with this id, mutably.
    pub(crate) fn peer_mut(&mut self, id: PeerId) -> Option<&mut Peer> {
        let i = self.slot(id)?;
        self.peers.get_mut(i)
    }

    /// The position of the peer with this id; it stays valid until a peer is added or
    /// removed.
    pub(crate) fn slot(&self, id: PeerId) -> Option<usize> {
        self.ids.binary_search(&id).ok()
    }

    /// The peer at `slot`.
    pub(crate) fn at(&self, slot: usize) -> Option<&Peer> {
        self.peers.get(slot)
    }

    /// The peer at `slot`, mutably.
    pub(crate) fn at_mut(&mut self, slot: usize) -> Option<&mut Peer> {
        self.peers.get_mut(slot)
    }

    /// The peer that owns the session index in a received message (`receiver_idx`).
    pub(crate) fn by_index(&self, receiver_idx: u32) -> Option<PeerId> {
        self.by_index.get(&(receiver_idx >> 8)).copied()
    }

    /// The peer to send a packet for `dst` to (cryptokey routing).
    pub(crate) fn by_destination(&self, dst: IpAddr) -> Option<PeerId> {
        self.by_ip.find(dst).copied()
    }

    /// Whether `peer` may send packets from `src`: the longest allowed-IP match of `src`
    /// across all peers must be `peer` itself.
    pub(crate) fn routes_to(&self, src: IpAddr, peer: PeerId) -> bool {
        self.by_ip.find(src) == Some(&peer)
    }

    /// The allowed IPs of `peer`.
    pub(crate) fn allowed_ips(&self, peer: PeerId) -> Vec<AllowedIp> {
        self.by_ip
            .iter()
            .filter(|(p, _, _)| **p == peer)
            .map(|(_, addr, cidr)| AllowedIp { addr, cidr })
            .collect()
    }

    /// Sets the inbound destinations of `peer`, or with `None` removes them.
    pub(crate) fn set_inbound_destinations(
        &mut self,
        peer: PeerId,
        destinations: Option<&[AllowedIp]>,
    ) {
        if let Some(slot) = self.slot(peer)
            && let Some(set) = self.destinations.get_mut(slot)
        {
            *set = destinations.map(destination_set);
        }
    }

    /// The inbound destinations of the peer at `slot`; `None` if it is unchecked.
    pub(crate) fn inbound_destinations(&self, slot: usize) -> Option<&AllowedIps<()>> {
        self.destinations.get(slot)?.as_ref()
    }

    /// All peers with their ids, in id order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (PeerId, &Peer)> {
        self.ids.iter().copied().zip(&self.peers)
    }

    /// All peers with their ids, mutably, in id order.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (PeerId, &mut Peer)> {
        self.ids.iter().copied().zip(&mut self.peers)
    }

    /// Number of peers.
    pub(crate) const fn len(&self) -> usize {
        self.peers.len()
    }
}

/// The networks of `destinations` as a lookup table.
fn destination_set(destinations: &[AllowedIp]) -> AllowedIps<()> {
    let mut set = AllowedIps::new();
    for &AllowedIp { addr, cidr } in destinations {
        set.insert(addr, cidr, ());
    }
    set
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
    use nsplane_packet::{Ecn, Path, TransportId};

    fn key() -> PublicKey {
        PublicKey::from(&StaticSecret::random_from_rng(OsRng))
    }

    fn net(s: &str) -> AllowedIp {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn table() -> PeerTable {
        let mut table = PeerTable::new(100, false);
        table.set_private_key(StaticSecret::random_from_rng(OsRng));
        table
    }

    fn add(table: &mut PeerTable, peer: PublicKey, ips: &[&str]) -> PeerId {
        let mut config = PeerConfig::new(peer);
        config.allowed_ips = ips.iter().copied().map(net).collect();
        table.apply(&config, Instant::now()).unwrap()
    }

    #[test]
    fn adds_and_indexes_a_peer() {
        let mut table = table();
        let a = key();
        let id = add(&mut table, a, &["10.0.0.0/16"]);

        assert_eq!(table.get(&a), Some(id));
        let index = table.peer(id).unwrap().index();
        assert_eq!(table.by_index(index << 8), Some(id));
        assert_eq!(table.by_destination(ip("10.0.3.4")), Some(id));
        assert_eq!(table.allowed_ips(id), vec![net("10.0.0.0/16")]);
    }

    #[test]
    fn source_check_uses_the_longest_match_across_peers() {
        let mut table = table();
        let peer_a = add(&mut table, key(), &["10.0.0.0/16"]);
        let peer_b = add(&mut table, key(), &["10.0.1.0/24"]);

        // 10.0.1.5 belongs to B even though it is also inside A's /16.
        assert!(!table.routes_to(ip("10.0.1.5"), peer_a));
        assert!(table.routes_to(ip("10.0.1.5"), peer_b));
        assert!(table.routes_to(ip("10.0.2.5"), peer_a));
        assert!(!table.routes_to(ip("192.0.2.1"), peer_a));
    }

    #[test]
    fn updates_an_existing_peer_in_place() {
        let mut table = table();
        let a = key();
        let id = add(&mut table, a, &["10.0.0.0/24"]);
        let index = table.peer(id).unwrap().index();

        let path = Path {
            transport: TransportId::new(1),
            addr: "192.0.2.1:51820".parse().unwrap(),
            ecn: Ecn::NotEct,
        };
        let mut config = PeerConfig::new(a);
        config.path = Some(path);
        config.persistent_keepalive = Some(25);
        config.preshared_key = Some([7; 32]);
        config.allowed_ips = vec![net("10.0.1.0/24")];
        assert_eq!(table.apply(&config, Instant::now()), Ok(id));

        let p = table.peer(id).unwrap();
        assert_eq!(p.index(), index, "the peer keeps its sessions");
        assert_eq!(p.path(), Some(path));
        assert_eq!(p.persistent_keepalive(), Some(25));
        assert_eq!(p.preshared_key(), Some(&[7; 32]));
        // Without replace_allowed_ips the new range is added.
        assert_eq!(
            table.allowed_ips(id),
            vec![net("10.0.0.0/24"), net("10.0.1.0/24")]
        );
    }

    #[test]
    fn replace_allowed_ips_drops_the_old_ranges() {
        let mut table = table();
        let a = key();
        let id = add(&mut table, a, &["10.0.0.0/24", "10.0.1.0/24"]);

        let mut config = PeerConfig::new(a);
        config.replace_allowed_ips = true;
        config.allowed_ips = vec![net("10.0.2.0/24")];
        table.apply(&config, Instant::now()).unwrap();

        assert_eq!(table.allowed_ips(id), vec![net("10.0.2.0/24")]);
        assert!(table.by_destination(ip("10.0.0.1")).is_none());
    }

    #[test]
    fn an_allowed_ip_moves_to_the_peer_that_claims_it_last() {
        let mut table = table();
        let peer_a = add(&mut table, key(), &["10.0.0.0/24"]);
        let peer_b = add(&mut table, key(), &["10.0.0.0/24"]);

        assert_eq!(table.allowed_ips(peer_a), Vec::new());
        assert!(table.routes_to(ip("10.0.0.1"), peer_b));
    }

    #[test]
    fn zero_preshared_key_clears_it() {
        let mut table = table();
        let a = key();
        let mut config = PeerConfig::new(a);
        config.preshared_key = Some([7; 32]);
        let id = table.apply(&config, Instant::now()).unwrap();

        let mut config = PeerConfig::new(a);
        config.preshared_key = Some([0; 32]);
        table.apply(&config, Instant::now()).unwrap();
        assert_eq!(table.peer(id).unwrap().preshared_key(), None);
    }

    #[test]
    fn remove_drops_every_index() {
        let mut table = table();
        let a = key();
        let id = add(&mut table, a, &["10.0.0.0/24"]);
        let index = table.peer(id).unwrap().index();

        assert_eq!(table.remove(&a), Some(id));

        assert!(table.get(&a).is_none());
        assert!(table.peer(id).is_none());
        assert!(table.by_index(index << 8).is_none());
        assert!(table.by_destination(ip("10.0.0.1")).is_none());
        assert_eq!(table.len(), 0);
        assert_eq!(table.remove(&a), None);
    }

    #[test]
    fn peer_ids_are_not_reused() {
        let mut table = table();
        let a = key();
        let first = add(&mut table, a, &[]);
        assert_eq!(first, PeerId::new(1));
        table.remove(&a);
        let second = add(&mut table, a, &[]);
        assert_ne!(second, first);
        table.clear();
        let third = add(&mut table, a, &[]);
        assert!(third > second);
        assert_eq!(table.iter().map(|(id, _)| id).collect::<Vec<_>>(), [third]);
    }

    #[test]
    fn peers_need_a_private_key() {
        let mut table = PeerTable::new(100, false);
        assert!(table.key_pair().is_none());
        assert!(table.rate_limiter().is_none());
        assert_eq!(
            table.apply(&PeerConfig::new(key()), Instant::now()),
            Err(PeerTableError::NoPrivateKey)
        );
    }

    #[test]
    fn set_private_key_rekeys_the_table() {
        let mut table = table();
        let id = add(&mut table, key(), &[]);
        let own = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&own);

        table.set_private_key(own.clone());
        assert_eq!(table.key_pair().map(|(_, p)| *p), Some(public));
        assert!(table.rate_limiter().is_some());
        // Setting the same key again keeps the gate.
        let gate: *const RateLimiter = table.rate_limiter().unwrap();
        table.set_private_key(own);
        assert!(std::ptr::eq(gate, table.rate_limiter().unwrap()));
        assert_eq!(table.iter().count(), 1);
        assert!(
            table
                .peer(id)
                .unwrap()
                .time_since_last_handshake(Instant::now())
                .is_none()
        );
    }

    #[test]
    fn only_a_shared_table_shares_tunnels() {
        let mut table = table();
        let id = add(&mut table, key(), &[]);
        assert!(!table.shared_tunnels());
        assert!(table.peer(id).unwrap().shared_tunnel().is_none());

        let mut table = PeerTable::new(100, true);
        table.set_private_key(StaticSecret::random_from_rng(OsRng));
        let id = add(&mut table, key(), &[]);
        assert!(table.shared_tunnels());
        assert!(table.peer(id).unwrap().shared_tunnel().is_some());
    }

    /// The inbound destinations of `id`; `None` if it is unchecked.
    fn destinations(table: &PeerTable, id: PeerId) -> Option<Vec<AllowedIp>> {
        let set = table.inbound_destinations(table.slot(id)?)?;
        Some(
            set.iter()
                .map(|(&(), addr, cidr)| AllowedIp { addr, cidr })
                .collect(),
        )
    }

    fn add_with_destinations(table: &mut PeerTable, peer: PublicKey, nets: &[&str]) -> PeerId {
        let mut config = PeerConfig::new(peer);
        config.inbound_destinations = Some(nets.iter().copied().map(net).collect());
        table.apply(&config, Instant::now()).unwrap()
    }

    #[test]
    fn inbound_destinations_are_unchecked_by_default() {
        let mut table = table();
        let id = add(&mut table, key(), &["10.0.0.0/24"]);
        assert_eq!(destinations(&table, id), None);
    }

    #[test]
    fn inbound_destinations_match_by_prefix_and_add_no_routes() {
        let mut table = table();
        let id = add_with_destinations(&mut table, key(), &["10.1.0.0/16", "fd01::/64"]);
        let set = table.inbound_destinations(table.slot(id).unwrap()).unwrap();

        assert!(set.find(ip("10.1.2.3")).is_some());
        assert!(set.find(ip("10.2.0.1")).is_none());
        assert!(set.find(ip("fd01::5")).is_some());
        assert!(set.find(ip("fd02::5")).is_none());
        assert!(table.by_destination(ip("10.1.2.3")).is_none());
        assert_eq!(table.allowed_ips(id), Vec::new());
    }

    #[test]
    fn an_update_without_inbound_destinations_keeps_them() {
        let mut table = table();
        let a = key();
        let id = add_with_destinations(&mut table, a, &["10.1.0.0/16"]);

        add(&mut table, a, &["10.0.0.0/24"]);
        assert_eq!(destinations(&table, id), Some(vec![net("10.1.0.0/16")]));

        add_with_destinations(&mut table, a, &["10.2.0.0/16"]);
        assert_eq!(destinations(&table, id), Some(vec![net("10.2.0.0/16")]));

        add_with_destinations(&mut table, a, &[]);
        assert_eq!(destinations(&table, id), Some(Vec::new()));
    }

    #[test]
    fn inbound_destinations_are_set_and_removed_by_peer() {
        let mut table = table();
        let a = key();
        let b = key();
        let peer_a = add(&mut table, a, &[]);
        let peer_b = add_with_destinations(&mut table, b, &["10.1.0.0/16"]);

        table.set_inbound_destinations(peer_a, Some(&[net("fd01::/64")]));
        assert_eq!(destinations(&table, peer_a), Some(vec![net("fd01::/64")]));
        table.set_inbound_destinations(peer_b, None);
        assert_eq!(destinations(&table, peer_b), None);

        // Removing a peer keeps the others' sets at their slots, and a peer added again
        // starts unchecked.
        table.set_inbound_destinations(peer_b, Some(&[net("10.2.0.0/16")]));
        table.remove(&a);
        assert_eq!(destinations(&table, peer_b), Some(vec![net("10.2.0.0/16")]));
        let peer_a = add(&mut table, a, &[]);
        assert_eq!(destinations(&table, peer_a), None);
        table.clear();
        let peer_b = add(&mut table, b, &[]);
        assert_eq!(destinations(&table, peer_b), None);
    }

    #[test]
    fn peer_state_is_mutable_through_the_table() {
        let mut table = table();
        let a = key();
        let id = add(&mut table, a, &[]);
        let path = Path {
            transport: TransportId::new(2),
            addr: "[2001:db8::1]:51820".parse().unwrap(),
            ecn: Ecn::Ect0,
        };

        let peer = table.peer_mut(id).unwrap();
        peer.set_path(path);
        peer.add_data_rx(100);
        let mut dst = [0u8; 256];
        assert!(!matches!(
            peer.update_timers(Instant::now(), &mut dst),
            TunnResult::Err(_)
        ));
        for (_, peer) in table.iter_mut() {
            peer.add_data_rx(20);
        }

        let peer = table.peer(id).unwrap();
        assert_eq!(peer.public_key(), &a);
        assert_eq!(peer.path(), Some(path));
        assert_eq!(peer.data_rx(), 120);
    }
}
