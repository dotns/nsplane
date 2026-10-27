// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The local identities and the peers of the core, indexed by peer id, identity and public
//! key, session index and allowed IP.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use nsplane_noise::noise::rate_limiter::{HandshakeBudget, RateLimiter};
use nsplane_noise::noise::{Tunn, TunnResult};
use nsplane_noise::x25519::{PublicKey, StaticSecret};
use nsplane_packet::{PeerId, TransportId};
use rand_core::{OsRng, RngCore};

use crate::allowed_ips::AllowedIps;
use crate::peer::Peer;
use crate::types::{AllowedIp, InboundDestinations, LocalIdentityId, PeerConfig};

/// Why a [`PeerConfig`] could not be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerTableError {
    /// No private key is set, so no tunnel can be created.
    NoPrivateKey,
    /// All 2^24 session indices are in use.
    IndicesExhausted,
    /// All peer ids have been handed out.
    IdsExhausted,
    /// The config names a local identity the table does not hold.
    UnknownIdentity,
}

/// An own key pair and the handshake gate derived from it.
pub(crate) struct OwnKey {
    pub(crate) private: StaticSecret,
    pub(crate) public: PublicKey,
    /// Verifies handshakes before they are demultiplexed to a peer. Every peer's `Tunn` of
    /// the identity shares it, so the cookie it hands out also passes the tunnel's own
    /// verification. It counts against the table's one handshake budget.
    pub(crate) gate: Arc<RateLimiter>,
}

/// A local identity: an optional key pair (only the default identity may lack one) and the
/// transports it is restricted to.
pub(crate) struct Identity {
    pub(crate) id: LocalIdentityId,
    pub(crate) key: Option<OwnKey>,
    /// The transports the identity answers handshakes on; `None` for any transport.
    pub(crate) transports: Option<Arc<[TransportId]>>,
    /// Number of peers bound to the identity.
    pub(crate) peers: usize,
    /// The allowed IPs of the identity's peers.
    ips: AllowedIps<PeerId>,
}

impl Identity {
    /// Whether the identity answers handshakes arriving on `transport`.
    pub(crate) fn serves(&self, transport: TransportId) -> bool {
        self.transports
            .as_deref()
            .is_none_or(|set| set.contains(&transport))
    }
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

/// The local identities and the peers of the core.
///
/// Peers are reachable by id, by identity and public key, by the session index in received
/// messages, and by allowed IP (cryptokey routing). Session indices and peer ids are shared by
/// all identities, so they are unique across them. Peer ids are never reused.
///
/// Each identity routes its peers' allowed IPs in its own prefix-length hash tables
/// ([`AllowedIps`]): within an identity, a range claimed by a newer peer moves away from
/// its previous owner. Unrouted local packets
/// take the fallback table: the default identity's, or the merged table of all identities while
/// a non-default identity holds allowed IPs. In the merged table the last insert owns a range;
/// a range its owner loses goes to the lowest identity that still holds exactly that range.
/// Source sets pick the identity whose table routes a local packet, by its source. A peer's
/// inbound destinations are kept apart from the routing tables, by slot.
pub(crate) struct PeerTable {
    /// Ids of the peers, ascending: ids are handed out in order, so a new peer goes last.
    ids: Vec<PeerId>,
    /// The peers, at the position of their id in `ids`.
    peers: Vec<Peer>,
    /// The inbound destinations of the peers, at the position of their id in `ids`; `None`
    /// for an unchecked peer.
    destinations: Vec<Option<Destinations>>,
    by_key: HashMap<(LocalIdentityId, PublicKey), PeerId>,
    by_index: HashMap<u32, PeerId, BuildHasherDefault<IndexHasher>>,
    /// The allowed IPs of all identities, while a non-default identity holds some.
    merged: Option<AllowedIps<PeerId>>,
    /// The source sets of the identities, while one has a set.
    sources: Option<AllowedIps<LocalIdentityId>>,
    next_index: IndexLfsr,
    next_id: u32,
    /// The local identities, ascending by id; the default identity is first.
    identities: Vec<Identity>,
    /// The id of the next local identity.
    next_identity: u32,
    /// The handshake counters shared by the gates of all identities.
    budget: Arc<HandshakeBudget>,
    /// Whether peers share their tunnels with crypto jobs.
    shared_tunnels: bool,
    /// Moves on every change of the routing state: the peers' slots, the identities, their
    /// allowed IPs, the merged table and the source sets.
    generation: u64,
}

impl std::fmt::Debug for PeerTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerTable")
            .field("peers", &self.len())
            .finish_non_exhaustive()
    }
}

impl PeerTable {
    /// Creates an empty table with only the default identity, without a private key.
    /// `handshake_rate_limit` is the number of handshakes per second (per source address) the
    /// gates of all identities together tolerate before replying with cookies. With
    /// `shared_tunnels` every peer keeps its tunnel behind a lock, to share it with crypto
    /// jobs; otherwise it owns the tunnel.
    pub(crate) fn new(handshake_rate_limit: u64, shared_tunnels: bool) -> Self {
        Self {
            ids: Vec::new(),
            peers: Vec::new(),
            destinations: Vec::new(),
            by_key: HashMap::new(),
            by_index: HashMap::default(),
            merged: None,
            sources: None,
            next_index: IndexLfsr::default(),
            next_id: 1,
            identities: vec![Identity {
                id: LocalIdentityId::DEFAULT,
                key: None,
                transports: None,
                peers: 0,
                ips: AllowedIps::new(),
            }],
            next_identity: 1,
            budget: Arc::new(HandshakeBudget::new(handshake_rate_limit)),
            shared_tunnels,
            generation: 0,
        }
    }

    /// The generation of the routing state: lookups of the peers' slots, routes and source
    /// checks stay valid while it stays the same.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Records a change of the routing state.
    const fn changed(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    /// The key pair of `private_key` with a gate on the shared budget.
    fn own_key(&self, private_key: StaticSecret) -> OwnKey {
        let public = PublicKey::from(&private_key);
        OwnKey {
            gate: Arc::new(RateLimiter::with_budget(&public, Arc::clone(&self.budget))),
            private: private_key,
            public,
        }
    }

    /// Whether an identity holds `public_key`.
    fn holds(&self, public_key: &PublicKey) -> bool {
        self.identities
            .iter()
            .any(|i| i.key.as_ref().is_some_and(|k| k.public == *public_key))
    }

    /// Sets the private key of the default identity, re-keys its peers (clearing their
    /// sessions) and replaces its handshake gate. Setting the current key again changes
    /// nothing; a key another identity holds is ignored.
    pub(crate) fn set_private_key(&mut self, private_key: StaticSecret) {
        let public_key = PublicKey::from(&private_key);

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if self.holds(&public_key) {
            if self
                .key_pair()
                .is_none_or(|(_, public)| *public != public_key)
            {
                tracing::debug!("Private key ignored: another local identity holds it");
            }
            return;
        }

        let own = self.own_key(private_key);
        for peer in &mut self.peers {
            if peer.local_identity() == LocalIdentityId::DEFAULT {
                peer.tunnel_mut().set_static_private(
                    own.private.clone(),
                    own.public,
                    Some(Arc::clone(&own.gate)),
                );
            }
        }
        if let Some(default) = self.identities.first_mut() {
            default.key = Some(own);
        }
    }

    /// Adds a local identity with `private_key`, answering handshakes on `transports` only,
    /// or on any transport with `None`. `None` if an identity already holds the key, or
    /// if every identity id was handed out.
    pub(crate) fn add_identity(
        &mut self,
        private_key: StaticSecret,
        transports: Option<Arc<[TransportId]>>,
    ) -> Option<LocalIdentityId> {
        if self.holds(&PublicKey::from(&private_key)) {
            return None;
        }
        self.changed();
        let id = LocalIdentityId::new(self.next_identity);
        self.next_identity = self.next_identity.checked_add(1)?;
        let key = Some(self.own_key(private_key));
        self.identities.push(Identity {
            id,
            key,
            transports,
            peers: 0,
            ips: AllowedIps::new(),
        });
        Some(id)
    }

    /// Removes a local identity without peers, with its source set; `false` for the default
    /// identity, an unknown one or one that still has peers.
    pub(crate) fn remove_identity(&mut self, id: LocalIdentityId) -> bool {
        if id == LocalIdentityId::DEFAULT {
            return false;
        }
        let Ok(i) = self.identities.binary_search_by_key(&id, |i| i.id) else {
            return false;
        };
        if self
            .identities
            .get(i)
            .is_none_or(|identity| identity.peers > 0)
        {
            return false;
        }
        self.changed();
        self.identities.remove(i);
        if let Some(sources) = &mut self.sources {
            sources.remove(&|owner: &LocalIdentityId| *owner == id);
            if sources.is_empty() {
                self.sources = None;
            }
        }
        self.commit();
        true
    }

    /// The local identity `id`.
    pub(crate) fn identity(&self, id: LocalIdentityId) -> Option<&Identity> {
        let i = self.identities.binary_search_by_key(&id, |i| i.id).ok()?;
        self.identities.get(i)
    }

    fn identity_mut(&mut self, id: LocalIdentityId) -> Option<&mut Identity> {
        let i = self.identities.binary_search_by_key(&id, |i| i.id).ok()?;
        self.identities.get_mut(i)
    }

    /// All local identities, ascending by id.
    pub(crate) fn identities(&self) -> &[Identity] {
        &self.identities
    }

    /// The local identities with a key, ascending by id, with their key.
    pub(crate) fn keyed_identities(&self) -> impl Iterator<Item = (&Identity, &OwnKey)> {
        self.identities
            .iter()
            .filter_map(|i| i.key.as_ref().map(|k| (i, k)))
    }

    /// Resets the handshake budget shared by all identities if a reset period passed at
    /// `now`.
    pub(crate) fn reset_handshake_budget(&self, now: Instant) {
        if let Some((_, own)) = self.keyed_identities().next() {
            own.gate.reset_count_at(now);
        }
    }

    /// Whether peers share their tunnels with crypto jobs.
    pub(crate) const fn shared_tunnels(&self) -> bool {
        self.shared_tunnels
    }

    /// The key pair of the default identity, if set.
    pub(crate) fn key_pair(&self) -> Option<(&StaticSecret, &PublicKey)> {
        let own = self.identities.first()?.key.as_ref()?;
        Some((&own.private, &own.public))
    }

    /// The handshake gate of the default identity, if its key is set.
    #[cfg(test)]
    fn rate_limiter(&self) -> Option<&RateLimiter> {
        Some(&*self.identities.first()?.key.as_ref()?.gate)
    }

    /// Adds the peer, or updates it in place if its identity and public key are known. A new
    /// peer's tunnel runs its timers on the clock of `now`.
    pub(crate) fn apply(
        &mut self,
        config: &PeerConfig,
        now: Instant,
    ) -> Result<PeerId, PeerTableError> {
        // An all-zero key means "no preshared key" in the UAPI.
        self.changed();
        let preshared_key = config.preshared_key.map(|k| (k != [0; 32]).then_some(k));
        let identity = config.local_identity.unwrap_or(LocalIdentityId::DEFAULT);

        let id = if let Some(&id) = self.by_key.get(&(identity, config.public_key)) {
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
            let owner = self
                .identities
                .iter()
                .find(|i| i.id == identity)
                .ok_or(PeerTableError::UnknownIdentity)?;
            let own = owner.key.as_ref().ok_or(PeerTableError::NoPrivateKey)?;
            let transports = owner.transports.clone();
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
            )
            .with_identity(identity, transports);
            self.next_id = next_id;
            self.ids.push(id);
            self.peers.push(peer);
            self.destinations.push(
                config
                    .inbound_destinations
                    .as_deref()
                    .map(|nets| Destinations::Owned(Box::new(destination_set(nets)))),
            );
            self.by_key.insert((identity, config.public_key), id);
            self.by_index.insert(index, id);
            if let Some(owner) = self.identity_mut(identity) {
                owner.peers += 1;
            }
            tracing::info!("Peer added");
            id
        };

        if config.replace_allowed_ips {
            self.remove_allowed_ips(identity, id);
        }
        for &ip in &config.allowed_ips {
            self.insert_allowed_ip(identity, ip, id);
        }
        self.drop_unused_merged();
        self.commit();
        Ok(id)
    }

    /// Routes `ip` to `peer` of `identity`, in the identity's table and in the merged table,
    /// which the first allowed IP of a non-default identity builds from the default one's.
    fn insert_allowed_ip(&mut self, identity: LocalIdentityId, ip: AllowedIp, peer: PeerId) {
        if identity != LocalIdentityId::DEFAULT && self.merged.is_none() {
            let mut merged = AllowedIps::new();
            if let Some(default) = self.identities.first() {
                for (&owner, addr, cidr) in default.ips.iter() {
                    merged.insert(addr, cidr, owner);
                }
            }
            self.merged = Some(merged);
        }
        if let Some(owner) = self.identity_mut(identity) {
            owner.ips.insert(ip.addr, ip.cidr, peer);
        }
        if let Some(merged) = &mut self.merged {
            merged.insert(ip.addr, ip.cidr, peer);
        }
    }

    /// Removes the allowed IPs of `peer` of `identity`. A range the peer owned in the merged
    /// table goes to the lowest identity that still holds exactly that range.
    fn remove_allowed_ips(&mut self, identity: LocalIdentityId, peer: PeerId) {
        let Ok(i) = self.identities.binary_search_by_key(&identity, |i| i.id) else {
            return;
        };
        let owned: Vec<(IpAddr, u8)> = match (&self.merged, self.identities.get(i)) {
            (Some(_), Some(owner)) => owner
                .ips
                .iter()
                .filter(|(p, _, _)| **p == peer)
                .map(|(_, addr, cidr)| (addr, cidr))
                .collect(),
            _ => Vec::new(),
        };
        if let Some(owner) = self.identities.get_mut(i) {
            owner.ips.remove(&|p: &PeerId| *p == peer);
        }
        let Some(merged) = &mut self.merged else {
            return;
        };
        for (addr, cidr) in owned {
            if merged.get(addr, cidr) != Some(&peer) {
                continue;
            }
            match self.identities.iter().find_map(|i| i.ips.get(addr, cidr)) {
                Some(&next) => merged.insert(addr, cidr, next),
                None => merged.remove_network(addr, cidr),
            };
        }
    }

    /// Drops the merged table once no non-default identity holds allowed IPs.
    fn drop_unused_merged(&mut self) {
        if self.merged.is_some() && self.identities.iter().skip(1).all(|i| i.ips.is_empty()) {
            self.merged = None;
        }
    }

    /// Rebuilds what the configuration change written so far left dirty in the tables, once
    /// per family; every entry point that writes one ends with it.
    fn commit(&mut self) {
        for identity in &mut self.identities {
            identity.ips.commit();
        }
        if let Some(merged) = &mut self.merged {
            merged.commit();
        }
        if let Some(sources) = &mut self.sources {
            sources.commit();
        }
    }

    /// Removes the peer of `identity` with `public_key` and returns its id.
    pub(crate) fn remove(
        &mut self,
        identity: LocalIdentityId,
        public_key: &PublicKey,
    ) -> Option<PeerId> {
        let id = self.by_key.remove(&(identity, *public_key))?;
        self.changed();
        if let Some(owner) = self.identity_mut(identity) {
            owner.peers = owner.peers.saturating_sub(1);
        }
        // Found a peer to remove, now purge all references to it:
        if let Ok(i) = self.ids.binary_search(&id) {
            self.ids.remove(i);
            let peer = self.peers.remove(i);
            self.destinations.remove(i);
            self.by_index.remove(&peer.index());
        }
        self.remove_allowed_ips(identity, id);
        self.drop_unused_merged();
        self.commit();

        tracing::info!("Peer removed");
        Some(id)
    }

    /// Removes all peers of every identity; the identities and their source sets stay.
    pub(crate) fn clear(&mut self) {
        self.changed();
        for identity in &mut self.identities {
            identity.peers = 0;
            identity.ips.clear();
        }
        self.ids.clear();
        self.peers.clear();
        self.destinations.clear();
        self.by_key.clear();
        self.by_index.clear();
        self.merged = None;
        self.commit();
    }

    /// The peer of `identity` with this public key.
    pub(crate) fn get(&self, identity: LocalIdentityId, public_key: &PublicKey) -> Option<PeerId> {
        self.by_key.get(&(identity, *public_key)).copied()
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

    /// The fallback table: the merged one while it exists, otherwise the default identity's.
    fn fallback(&self) -> Option<&AllowedIps<PeerId>> {
        self.merged
            .as_ref()
            .or_else(|| self.identities.first().map(|i| &i.ips))
    }

    /// The peer to send a packet for `dst` to in the fallback table (cryptokey routing).
    pub(crate) fn by_destination(&self, dst: IpAddr) -> Option<PeerId> {
        self.fallback()?.find(dst).copied()
    }

    /// Whether an identity has a source set.
    pub(crate) const fn has_sources(&self) -> bool {
        self.sources.is_some()
    }

    /// The identity whose source set holds the longest match of `src`.
    pub(crate) fn source_identity(&self, src: IpAddr) -> Option<LocalIdentityId> {
        self.sources.as_ref()?.find(src).copied()
    }

    /// The peer to send a packet for `dst` to in the table of `identity` alone, or in the
    /// fallback table for `None`.
    pub(crate) fn route_in(
        &self,
        identity: Option<LocalIdentityId>,
        dst: IpAddr,
    ) -> Option<PeerId> {
        match identity {
            Some(id) => self.identity(id)?.ips.find(dst).copied(),
            None => self.by_destination(dst),
        }
    }

    /// The peer to send a packet from `src` to `dst` to: in the table of the identity whose
    /// source set matches `src`, otherwise in the fallback table.
    pub(crate) fn route_from(&self, src: IpAddr, dst: IpAddr) -> Option<PeerId> {
        if !self.has_sources() {
            return self.by_destination(dst);
        }
        self.route_in(self.source_identity(src), dst)
    }

    /// Whether `peer` may send packets from `src`: the longest allowed-IP match of `src`
    /// among the peers of `peer`'s identity must be `peer` itself.
    pub(crate) fn routes_to(&self, src: IpAddr, peer: PeerId) -> bool {
        let ips = match self.merged {
            // Only the default identity holds allowed IPs: either they are the peer's
            // identity's or the peer has none.
            None => self.identities.first().map(|i| &i.ips),
            Some(_) => self
                .peer(peer)
                .and_then(|p| self.identity(p.local_identity()))
                .map(|i| &i.ips),
        };
        ips.and_then(|ips| ips.find(src)) == Some(&peer)
    }

    /// The allowed IPs of `peer`.
    pub(crate) fn allowed_ips(&self, peer: PeerId) -> Vec<AllowedIp> {
        let Some(owner) = self
            .peer(peer)
            .and_then(|p| self.identity(p.local_identity()))
        else {
            return Vec::new();
        };
        owner
            .ips
            .iter()
            .filter(|(p, _, _)| **p == peer)
            .map(|(_, addr, cidr)| AllowedIp { addr, cidr })
            .collect()
    }

    /// Replaces the source set of `identity` with `sources`; an empty list clears it. `false`,
    /// changing nothing, for an unknown identity or a network another identity's set holds.
    pub(crate) fn set_sources(&mut self, identity: LocalIdentityId, sources: &[AllowedIp]) -> bool {
        if self.identity(identity).is_none() {
            return false;
        }
        if let Some(set) = &self.sources
            && sources.iter().any(|ip| {
                set.get(ip.addr, ip.cidr)
                    .is_some_and(|owner| *owner != identity)
            })
        {
            return false;
        }
        self.changed();
        let set = self.sources.get_or_insert_with(AllowedIps::new);
        set.remove(&|owner: &LocalIdentityId| *owner == identity);
        for ip in sources {
            set.insert(ip.addr, ip.cidr, identity);
        }
        if set.is_empty() {
            self.sources = None;
        }
        self.commit();
        true
    }

    /// The source set of `identity`.
    pub(crate) fn sources(&self, identity: LocalIdentityId) -> Vec<AllowedIp> {
        self.sources.as_ref().map_or_else(Vec::new, |set| {
            set.iter()
                .filter(|(owner, _, _)| **owner == identity)
                .map(|(_, addr, cidr)| AllowedIp { addr, cidr })
                .collect()
        })
    }

    /// Whether the merged table exists.
    #[cfg(test)]
    pub(crate) const fn merged(&self) -> bool {
        self.merged.is_some()
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
            *set = destinations.map(|nets| Destinations::Owned(Box::new(destination_set(nets))));
        }
    }

    /// Sets the caller-updated source of the inbound destinations of `peer`, replacing an
    /// owned list, or with `None` removes it.
    pub(crate) fn set_inbound_destination_source(
        &mut self,
        peer: PeerId,
        source: Option<Arc<dyn InboundDestinations>>,
    ) {
        if let Some(slot) = self.slot(peer)
            && let Some(set) = self.destinations.get_mut(slot)
        {
            *set = source.map(Destinations::Shared);
        }
    }

    /// The inbound destinations of the peer at `slot`; `None` if it is unchecked.
    pub(crate) fn inbound_destinations(&self, slot: usize) -> Option<&Destinations> {
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

/// The inbound destinations of a checked peer.
pub(crate) enum Destinations {
    /// An owned list, replaced by configuration changes; boxed to keep the slots small.
    Owned(Box<AllowedIps<()>>),
    /// A caller-updated source, consulted per packet.
    Shared(Arc<dyn InboundDestinations>),
}

/// The networks of `destinations` as a lookup table.
fn destination_set(destinations: &[AllowedIp]) -> AllowedIps<()> {
    let mut set = AllowedIps::new();
    for &AllowedIp { addr, cidr } in destinations {
        set.insert(addr, cidr, ());
    }
    set.commit();
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

        assert_eq!(table.get(LocalIdentityId::DEFAULT, &a), Some(id));
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

        assert_eq!(table.remove(LocalIdentityId::DEFAULT, &a), Some(id));

        assert!(table.get(LocalIdentityId::DEFAULT, &a).is_none());
        assert!(table.peer(id).is_none());
        assert!(table.by_index(index << 8).is_none());
        assert!(table.by_destination(ip("10.0.0.1")).is_none());
        assert_eq!(table.len(), 0);
        assert_eq!(table.remove(LocalIdentityId::DEFAULT, &a), None);
    }

    #[test]
    fn peer_ids_are_not_reused() {
        let mut table = table();
        let a = key();
        let first = add(&mut table, a, &[]);
        assert_eq!(first, PeerId::new(1));
        table.remove(LocalIdentityId::DEFAULT, &a);
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
    /// The owned inbound destinations of `id`.
    fn owned(table: &PeerTable, id: PeerId) -> Option<&AllowedIps<()>> {
        match table.inbound_destinations(table.slot(id)?)? {
            Destinations::Owned(set) => Some(set),
            Destinations::Shared(_) => panic!("a shared source"),
        }
    }

    fn destinations(table: &PeerTable, id: PeerId) -> Option<Vec<AllowedIp>> {
        let set = owned(table, id)?;
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
        let set = owned(&table, id).unwrap();

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
        table.remove(LocalIdentityId::DEFAULT, &a);
        assert_eq!(destinations(&table, peer_b), Some(vec![net("10.2.0.0/16")]));
        let peer_a = add(&mut table, a, &[]);
        assert_eq!(destinations(&table, peer_a), None);
        table.clear();
        let peer_b = add(&mut table, b, &[]);
        assert_eq!(destinations(&table, peer_b), None);
    }

    #[test]
    fn a_source_and_an_owned_list_replace_each_other() {
        let mut table = table();
        let a = key();
        let id = add_with_destinations(&mut table, a, &["10.1.0.0/16"]);
        let shared = |table: &PeerTable| {
            matches!(
                table.inbound_destinations(table.slot(id).unwrap()),
                Some(Destinations::Shared(_))
            )
        };

        let source: Arc<dyn InboundDestinations> = Arc::new(|_: IpAddr| true);
        table.set_inbound_destination_source(id, Some(Arc::clone(&source)));
        assert!(shared(&table));
        // An update without inbound destinations keeps the source.
        add(&mut table, a, &["10.0.0.0/24"]);
        assert!(shared(&table));
        // An owned list replaces it.
        add_with_destinations(&mut table, a, &["10.2.0.0/16"]);
        assert_eq!(destinations(&table, id), Some(vec![net("10.2.0.0/16")]));

        table.set_inbound_destination_source(id, Some(source));
        table.set_inbound_destinations(id, Some(&[net("10.3.0.0/16")]));
        assert_eq!(destinations(&table, id), Some(vec![net("10.3.0.0/16")]));
        table.set_inbound_destination_source(id, None);
        assert_eq!(destinations(&table, id), None);
    }

    /// The static key the peer `id` initiates handshakes with, as the remote `responder`
    /// decrypts it from an initiation.
    fn initiator_key(table: &mut PeerTable, id: PeerId, responder: &StaticSecret) -> PublicKey {
        use nsplane_noise::noise::Packet;
        use nsplane_noise::noise::handshake::parse_handshake_anon;

        let mut dst = [0u8; 256];
        let peer = table.peer_mut(id).unwrap();
        let mut tunnel = peer.tunnel_mut();
        let TunnResult::WriteToNetwork(init) = tunnel.format_handshake_initiation(&mut dst, true)
        else {
            panic!("expected an initiation");
        };
        let Ok(Packet::HandshakeInit(init)) = Tunn::parse_incoming_packet(init) else {
            panic!("expected an initiation");
        };
        let half = parse_handshake_anon(responder, &PublicKey::from(responder), &init).unwrap();
        PublicKey::from(half.peer_static_public)
    }

    fn add_in(table: &mut PeerTable, identity: LocalIdentityId, peer: PublicKey) -> PeerId {
        let mut config = PeerConfig::new(peer);
        config.local_identity = Some(identity);
        table.apply(&config, Instant::now()).unwrap()
    }

    #[test]
    fn identities_are_added_refused_and_removed() {
        let mut table = PeerTable::new(100, false);
        let default = StaticSecret::random_from_rng(OsRng);
        table.set_private_key(default.clone());
        let own = StaticSecret::random_from_rng(OsRng);

        let first = table.add_identity(own.clone(), None).unwrap();
        assert_ne!(first, LocalIdentityId::DEFAULT);
        // A key held by any identity, the default one included, is refused.
        assert_eq!(table.add_identity(own, None), None);
        assert_eq!(table.add_identity(default, None), None);

        let transports: Arc<[TransportId]> = Arc::from([TransportId::new(3)]);
        let second = table
            .add_identity(
                StaticSecret::random_from_rng(OsRng),
                Some(Arc::clone(&transports)),
            )
            .unwrap();
        assert!(second > first);
        let identity = table.identity(second).unwrap();
        assert!(identity.serves(TransportId::new(3)));
        assert!(!identity.serves(TransportId::new(4)));
        assert!(table.identity(first).unwrap().serves(TransportId::new(4)));
        assert_eq!(
            table.identities().iter().map(|i| i.id).collect::<Vec<_>>(),
            [LocalIdentityId::DEFAULT, first, second]
        );
        assert_eq!(table.keyed_identities().count(), 3);

        assert!(!table.remove_identity(LocalIdentityId::DEFAULT));
        assert!(table.remove_identity(first));
        assert!(!table.remove_identity(first), "already removed");
        assert!(table.identity(first).is_none());

        // Ids are never reused.
        let third = table
            .add_identity(StaticSecret::random_from_rng(OsRng), None)
            .unwrap();
        assert!(third > second);
    }

    #[test]
    fn the_default_identity_may_lack_a_key_but_its_peers_need_one() {
        let mut table = PeerTable::new(100, false);
        let identity = table
            .add_identity(StaticSecret::random_from_rng(OsRng), None)
            .unwrap();
        assert_eq!(table.keyed_identities().count(), 1);
        assert_eq!(
            table.apply(&PeerConfig::new(key()), Instant::now()),
            Err(PeerTableError::NoPrivateKey)
        );
        add_in(&mut table, identity, key());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn a_peer_of_an_unknown_identity_is_refused() {
        let mut table = table();
        let identity = table
            .add_identity(StaticSecret::random_from_rng(OsRng), None)
            .unwrap();
        assert!(table.remove_identity(identity));
        let mut config = PeerConfig::new(key());
        config.local_identity = Some(identity);
        assert_eq!(
            table.apply(&config, Instant::now()),
            Err(PeerTableError::UnknownIdentity)
        );
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn one_remote_key_under_two_identities_is_two_peers() {
        let mut table = table();
        let identity = table
            .add_identity(StaticSecret::random_from_rng(OsRng), None)
            .unwrap();
        let remote = key();
        let default_peer = add(&mut table, remote, &["10.0.0.0/24"]);
        let other_peer = add_in(&mut table, identity, remote);

        assert_ne!(default_peer, other_peer);
        assert_eq!(
            table.get(LocalIdentityId::DEFAULT, &remote),
            Some(default_peer)
        );
        assert_eq!(table.get(identity, &remote), Some(other_peer));
        let (a, b) = (
            table.peer(default_peer).unwrap(),
            table.peer(other_peer).unwrap(),
        );
        assert_eq!(a.local_identity(), LocalIdentityId::DEFAULT);
        assert_eq!(b.local_identity(), identity);
        assert_ne!(a.index(), b.index());
        assert_eq!(table.by_index(a.index() << 8), Some(default_peer));
        assert_eq!(table.by_index(b.index() << 8), Some(other_peer));
        assert_eq!(table.identity(identity).unwrap().peers, 1);
        assert_eq!(table.identity(LocalIdentityId::DEFAULT).unwrap().peers, 1);

        // An update naming the identity changes its peer only.
        let mut config = PeerConfig::new(remote);
        config.local_identity = Some(identity);
        config.persistent_keepalive = Some(25);
        assert_eq!(table.apply(&config, Instant::now()), Ok(other_peer));
        assert_eq!(
            table.peer(other_peer).unwrap().persistent_keepalive(),
            Some(25)
        );
        assert_eq!(
            table.peer(default_peer).unwrap().persistent_keepalive(),
            None
        );
    }

    #[test]
    fn removal_drops_only_that_identitys_peer_and_index() {
        let mut table = table();
        let identity = table
            .add_identity(StaticSecret::random_from_rng(OsRng), None)
            .unwrap();
        let remote = key();
        let default_peer = add(&mut table, remote, &["10.0.0.0/24"]);
        let other_peer = add_in(&mut table, identity, remote);
        let index = table.peer(other_peer).unwrap().index();

        // An identity with peers is not removed by the table.
        assert!(!table.remove_identity(identity));
        assert_eq!(table.remove(identity, &remote), Some(other_peer));
        assert!(table.by_index(index << 8).is_none());
        assert_eq!(table.identity(identity).unwrap().peers, 0);
        assert!(table.remove_identity(identity));

        assert_eq!(
            table.get(LocalIdentityId::DEFAULT, &remote),
            Some(default_peer)
        );
        assert_eq!(table.by_destination(ip("10.0.0.1")), Some(default_peer));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn every_routing_change_moves_the_generation() {
        let mut table = table();
        let mut last = table.generation();
        let mut moved = |table: &PeerTable| {
            let moved = table.generation() != last;
            last = table.generation();
            moved
        };
        let identity = table
            .add_identity(StaticSecret::random_from_rng(OsRng), None)
            .unwrap();
        assert!(moved(&table));
        let peer = key();
        add(&mut table, peer, &["10.0.0.0/8"]);
        assert!(moved(&table));
        assert!(table.set_sources(identity, &[net("192.0.2.0/24")]));
        assert!(moved(&table));
        table.remove(LocalIdentityId::DEFAULT, &peer).unwrap();
        assert!(moved(&table));
        add(&mut table, key(), &["10.0.0.0/8"]);
        assert!(moved(&table));
        table.clear();
        assert!(moved(&table));
        assert!(table.remove_identity(identity));
        assert!(moved(&table));
    }

    #[test]
    fn clear_keeps_the_identities() {
        let mut table = table();
        let identity = table
            .add_identity(StaticSecret::random_from_rng(OsRng), None)
            .unwrap();
        add_in(&mut table, identity, key());
        add(&mut table, key(), &[]);
        table.clear();
        assert_eq!(table.len(), 0);
        assert_eq!(table.identities().len(), 2);
        assert!(table.identities().iter().all(|i| i.peers == 0));
        add_in(&mut table, identity, key());
    }

    #[test]
    fn peers_initiate_with_their_identitys_key_and_set_private_key_rekeys_default_peers_only() {
        let mut table = table();
        let own = StaticSecret::random_from_rng(OsRng);
        let identity = table.add_identity(own.clone(), None).unwrap();
        let remote = StaticSecret::random_from_rng(OsRng);
        let default_peer = add(&mut table, PublicKey::from(&remote), &[]);
        let other_peer = add_in(&mut table, identity, PublicKey::from(&remote));

        let old_default = *table.key_pair().unwrap().1;
        assert_eq!(
            initiator_key(&mut table, default_peer, &remote),
            old_default
        );
        assert_eq!(
            initiator_key(&mut table, other_peer, &remote),
            PublicKey::from(&own)
        );

        let new_default = StaticSecret::random_from_rng(OsRng);
        table.set_private_key(new_default.clone());
        assert_eq!(
            initiator_key(&mut table, default_peer, &remote),
            PublicKey::from(&new_default)
        );
        assert_eq!(
            initiator_key(&mut table, other_peer, &remote),
            PublicKey::from(&own)
        );

        // A key another identity holds is ignored.
        table.set_private_key(own);
        assert_eq!(
            table.key_pair().map(|(_, p)| *p),
            Some(PublicKey::from(&new_default))
        );
        assert_eq!(
            initiator_key(&mut table, default_peer, &remote),
            PublicKey::from(&new_default)
        );
    }

    #[test]
    fn restricted_identities_restrict_their_peers() {
        let mut table = table();
        let transports: Arc<[TransportId]> = Arc::from([TransportId::new(1), TransportId::new(2)]);
        let identity = table
            .add_identity(StaticSecret::random_from_rng(OsRng), Some(transports))
            .unwrap();
        let restricted = add_in(&mut table, identity, key());
        let unrestricted = add(&mut table, key(), &[]);

        let peer = table.peer(restricted).unwrap();
        assert!(peer.accepts(TransportId::new(1)));
        assert!(peer.accepts(TransportId::new(2)));
        assert!(!peer.accepts(TransportId::new(3)));
        assert!(
            table
                .peer(unrestricted)
                .unwrap()
                .accepts(TransportId::new(3))
        );
    }

    fn add_ips_in(
        table: &mut PeerTable,
        identity: LocalIdentityId,
        peer: PublicKey,
        ips: &[&str],
    ) -> PeerId {
        let mut config = PeerConfig::new(peer);
        config.local_identity = Some(identity);
        config.allowed_ips = ips.iter().copied().map(net).collect();
        table.apply(&config, Instant::now()).unwrap()
    }

    fn identity(table: &mut PeerTable) -> LocalIdentityId {
        table
            .add_identity(StaticSecret::random_from_rng(OsRng), None)
            .unwrap()
    }

    #[test]
    fn one_identity_builds_no_merged_trie() {
        let mut table = table();
        let a = key();
        let peer_a = add(&mut table, a, &["10.0.0.0/16"]);
        let peer_b = add(&mut table, key(), &["10.0.1.0/24"]);
        // A non-default identity without allowed IPs needs none either.
        let other = identity(&mut table);
        let other_peer = add_in(&mut table, other, key());
        let mut config = PeerConfig::new(a);
        config.replace_allowed_ips = true;
        config.allowed_ips = vec![net("10.0.0.0/16"), net("fd00::/64")];
        table.apply(&config, Instant::now()).unwrap();
        assert!(!table.merged());

        for (src, dst, peer) in [
            ("10.9.0.1", "10.0.1.5", Some(peer_b)),
            ("10.9.0.1", "10.0.2.5", Some(peer_a)),
            ("10.9.0.1", "fd00::1", Some(peer_a)),
            ("10.9.0.1", "192.0.2.1", None),
        ] {
            assert_eq!(table.by_destination(ip(dst)), peer);
            assert_eq!(table.route_from(ip(src), ip(dst)), peer);
        }
        assert!(table.routes_to(ip("10.0.2.5"), peer_a));
        assert!(!table.routes_to(ip("10.0.1.5"), peer_a));
        assert!(!table.routes_to(ip("10.0.2.5"), other_peer));
    }

    #[test]
    fn the_same_ranges_under_two_identities_are_checked_per_identity() {
        let mut table = table();
        let other = identity(&mut table);
        let remote = key();
        let default_peer = add(&mut table, remote, &["10.0.0.0/24"]);
        assert!(!table.merged());
        let other_peer = add_ips_in(&mut table, other, remote, &["10.0.0.0/24"]);
        assert!(table.merged());

        assert!(table.routes_to(ip("10.0.0.1"), default_peer));
        assert!(table.routes_to(ip("10.0.0.1"), other_peer));
        assert!(!table.routes_to(ip("10.0.1.1"), other_peer));
        assert_eq!(table.allowed_ips(default_peer), vec![net("10.0.0.0/24")]);
        assert_eq!(table.allowed_ips(other_peer), vec![net("10.0.0.0/24")]);
        // The fallback table: the last insert owns the range.
        assert_eq!(table.by_destination(ip("10.0.0.1")), Some(other_peer));

        // Within an identity the last insert still moves a range.
        let third = add_ips_in(&mut table, other, key(), &["10.0.0.0/24"]);
        assert_eq!(table.allowed_ips(other_peer), Vec::new());
        assert!(!table.routes_to(ip("10.0.0.1"), other_peer));
        assert!(table.routes_to(ip("10.0.0.1"), third));
        assert!(table.routes_to(ip("10.0.0.1"), default_peer));
    }

    #[test]
    fn a_lost_range_goes_to_the_lowest_identity_that_holds_it() {
        let mut table = table();
        let (first, second) = (identity(&mut table), identity(&mut table));
        let (a, b, c) = (key(), key(), key());
        let default_peer = add(&mut table, a, &["10.0.0.0/24"]);
        let second_peer = add_ips_in(&mut table, second, b, &["10.0.0.0/24", "10.0.1.0/24"]);
        let first_peer = add_ips_in(&mut table, first, c, &["10.0.0.0/24", "10.0.1.0/24"]);
        assert_eq!(table.by_destination(ip("10.0.0.1")), Some(first_peer));

        // Replaced away: the default identity holds the range, and comes first.
        let mut config = PeerConfig::new(c);
        config.local_identity = Some(first);
        config.replace_allowed_ips = true;
        config.allowed_ips = vec![net("10.0.2.0/24")];
        table.apply(&config, Instant::now()).unwrap();
        assert_eq!(table.by_destination(ip("10.0.0.1")), Some(default_peer));
        assert_eq!(table.by_destination(ip("10.0.1.1")), Some(second_peer));
        assert_eq!(table.by_destination(ip("10.0.2.1")), Some(first_peer));

        // A range owned by another peer is left alone.
        assert_eq!(
            table.remove(LocalIdentityId::DEFAULT, &a),
            Some(default_peer)
        );
        assert_eq!(table.by_destination(ip("10.0.0.1")), Some(second_peer));
        assert_eq!(table.remove(second, &b), Some(second_peer));
        assert_eq!(table.by_destination(ip("10.0.0.1")), None);
        assert_eq!(table.by_destination(ip("10.0.2.1")), Some(first_peer));
        assert!(table.merged());

        // No non-default identity holds allowed IPs: the merged table goes.
        assert_eq!(table.remove(first, &c), Some(first_peer));
        assert!(!table.merged());
        let default_peer = add(&mut table, a, &["10.0.0.0/24"]);
        assert_eq!(table.by_destination(ip("10.0.0.1")), Some(default_peer));
        assert!(!table.merged());

        add_ips_in(&mut table, second, b, &["10.0.3.0/24"]);
        table.clear();
        assert!(!table.merged());
        assert_eq!(table.by_destination(ip("10.0.0.1")), None);
    }

    #[test]
    fn source_sets_select_an_identity() {
        let mut table = table();
        let (first, second) = (identity(&mut table), identity(&mut table));
        let remote = key();
        let default_peer = add(&mut table, remote, &["10.0.0.0/24"]);
        let first_peer = add_ips_in(&mut table, first, remote, &["10.0.0.0/24"]);
        add_in(&mut table, second, remote);
        assert!(!table.has_sources());

        assert!(table.set_sources(first, &[net("100.64.0.0/16")]));
        assert!(table.set_sources(LocalIdentityId::DEFAULT, &[net("100.64.1.0/24")]));
        assert!(table.set_sources(second, &[net("100.65.0.0/16")]));
        assert!(table.has_sources());
        // The most specific set wins.
        assert_eq!(
            table.route_from(ip("100.64.1.1"), ip("10.0.0.1")),
            Some(default_peer)
        );
        assert_eq!(
            table.route_from(ip("100.64.2.1"), ip("10.0.0.1")),
            Some(first_peer)
        );
        // A selected identity without a route has none, whatever the others route.
        assert_eq!(table.route_from(ip("100.65.0.1"), ip("10.0.0.1")), None);
        // No set: the fallback table.
        assert_eq!(
            table.route_from(ip("192.0.2.1"), ip("10.0.0.1")),
            table.by_destination(ip("10.0.0.1"))
        );

        // The same network after truncation, held by another identity: refused, unchanged.
        assert!(!table.set_sources(second, &[net("100.66.0.0/16"), net("100.64.9.9/16")]));
        assert_eq!(table.sources(second), vec![net("100.65.0.0/16")]);
        // An unknown identity is refused.
        assert!(!table.set_sources(LocalIdentityId::new(99), &[net("100.67.0.0/16")]));
        // A set is replaced as a whole, and an identity may restate its own networks.
        assert!(table.set_sources(first, &[net("100.64.0.0/16"), net("100.68.0.0/16")]));
        assert_eq!(
            table.sources(first),
            vec![net("100.64.0.0/16"), net("100.68.0.0/16")]
        );

        // Clearing keeps the sets; removing an identity drops its set.
        table.clear();
        assert_eq!(table.sources(second), vec![net("100.65.0.0/16")]);
        assert!(table.remove_identity(second));
        assert_eq!(table.sources(second), Vec::new());
        assert!(table.set_sources(first, &[]));
        assert!(table.set_sources(LocalIdentityId::DEFAULT, &[]));
        assert!(!table.has_sources());
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

    #[test]
    fn a_configuration_change_rebuilds_each_family_once() {
        let mut table = table();
        let rebuilds = |table: &PeerTable| table.identities[0].ips.rebuilds;
        // Networks of both families in one change.
        let nets: Vec<String> = (0..64)
            .flat_map(|i| [format!("10.{i}.0.0/16"), format!("fd00:{i:x}::/32")])
            .collect();
        let nets: Vec<&str> = nets.iter().map(String::as_str).collect();
        let a = key();
        let peer_a = add(&mut table, a, &nets);
        assert_eq!(rebuilds(&table), 2);
        assert_eq!(table.by_destination(ip("10.63.1.1")), Some(peer_a));
        // Replacing them removes and inserts in one change.
        let mut config = PeerConfig::new(a);
        config.replace_allowed_ips = true;
        config.allowed_ips = vec![net("10.0.0.0/8"), net("fd00::/16")];
        table.apply(&config, Instant::now()).unwrap();
        assert_eq!(rebuilds(&table), 4);
        // An update without allowed IPs rebuilds nothing.
        add(&mut table, a, &[]);
        assert_eq!(rebuilds(&table), 4);
        // The worst load order, in one change: 10 k /128 networks, then one network of each
        // other length.
        let mut config = PeerConfig::new(key());
        config.allowed_ips = (0..10_000_u128)
            .map(|i| AllowedIp {
                addr: IpAddr::from(((0xfd01_u128 << 112) | i).to_be_bytes()),
                cidr: 128,
            })
            .chain((0..128).map(|cidr| AllowedIp {
                addr: ip("fd01::"),
                cidr,
            }))
            .collect();
        let peer_b = table.apply(&config, Instant::now()).unwrap();
        assert_eq!(rebuilds(&table), 5);
        assert_eq!(table.by_destination(ip("fd01::5")), Some(peer_b));
        assert_eq!(table.by_destination(ip("fd00::1")), Some(peer_a));
        // A removed peer's networks go in one change: IPv4 loses its last /8 and rebuilds,
        // IPv6 keeps a /16 and removes in place.
        assert_eq!(table.remove(LocalIdentityId::DEFAULT, &a), Some(peer_a));
        assert_eq!(rebuilds(&table), 6);
        assert_eq!(table.by_destination(ip("fd00::1")), Some(peer_b));
        assert_eq!(table.by_destination(ip("10.0.0.1")), None);
        // Removing all peers leaves nothing to rebuild.
        table.clear();
        assert_eq!(rebuilds(&table), 6);
        assert_eq!(table.by_destination(ip("fd01::5")), None);
    }

    #[test]
    fn every_trie_is_rebuilt_once_per_change() {
        let mut table = table();
        let (first, second) = (identity(&mut table), identity(&mut table));
        let rebuilds = |table: &PeerTable, i: usize| table.identities[i].ips.rebuilds;
        let merged = |table: &PeerTable| table.merged.as_ref().map(|set| set.rebuilds);
        let sources = |table: &PeerTable| table.sources.as_ref().map(|set| set.rebuilds);
        let default_peer = add(&mut table, key(), &["10.0.0.0/24", "fd00::/64"]);
        assert_eq!(rebuilds(&table, 0), 2);
        assert_eq!(merged(&table), None);

        // The first allowed IPs of another identity build the merged table from the default
        // one's, in the same change.
        let first_peer = add_ips_in(&mut table, first, key(), &["10.0.1.0/24", "10.0.2.0/24"]);
        assert_eq!(rebuilds(&table, 1), 1);
        assert_eq!(merged(&table), Some(2));
        assert_eq!(table.by_destination(ip("fd00::1")), Some(default_peer));
        assert_eq!(table.by_destination(ip("10.0.2.1")), Some(first_peer));
        let c = key();
        // Networks of a length the merged table uses go in place.
        let second_peer = add_ips_in(&mut table, second, c, &["10.0.1.0/24", "10.0.3.0/24"]);
        assert_eq!(merged(&table), Some(2));
        assert_eq!(table.by_destination(ip("10.0.1.1")), Some(second_peer));
        // A removal re-fills the merged table in the same change, in place.
        assert_eq!(table.remove(second, &c), Some(second_peer));
        assert_eq!(rebuilds(&table, 2), 2);
        assert_eq!(merged(&table), Some(2));
        assert_eq!(table.by_destination(ip("10.0.1.1")), Some(first_peer));
        assert_eq!(table.by_destination(ip("10.0.3.1")), None);

        // Source sets.
        assert!(table.set_sources(first, &[net("100.64.0.0/16"), net("fd64::/16")]));
        assert_eq!(sources(&table), Some(2));
        assert!(table.set_sources(second, &[net("100.65.0.0/16")]));
        assert_eq!(sources(&table), Some(2));
        assert_eq!(table.source_identity(ip("100.65.0.1")), Some(second));
        assert!(!table.set_sources(second, &[net("100.64.0.0/16")]));
        assert_eq!(sources(&table), Some(2));
        // A removed identity's source set goes in one change, in place.
        assert!(table.remove_identity(second));
        assert_eq!(sources(&table), Some(2));
        assert_eq!(table.source_identity(ip("100.65.0.1")), None);
        assert_eq!(table.source_identity(ip("fd64::1")), Some(first));

        // Inbound destination sets are built in one change.
        let nets = ["192.0.2.0/24", "2001:db8::/32", "198.51.100.0/24"];
        let d = add_with_destinations(&mut table, key(), &nets);
        assert_eq!(owned(&table, d).map(|set| set.rebuilds), Some(2));
        table.set_inbound_destinations(d, Some(&[net("203.0.113.0/24")]));
        assert_eq!(owned(&table, d).map(|set| set.rebuilds), Some(1));
        assert_eq!(owned(&table, d).unwrap().find(ip("203.0.113.9")), Some(&()));
    }
}
