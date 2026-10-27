// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Peer and local identity management, queries and configuration changes.

use std::net::IpAddr;
use std::time::Instant;

use nsplane_noise::x25519;
use nsplane_packet::{Path, PeerId, TransportId};

use super::Core;
use crate::peer::Peer;
use crate::peer_table::PeerTableError;
use crate::policy::MessageKind;
use crate::reasons;
use crate::types::{
    AllowedIp, ConfigChange, LocalIdentityId, LocalIdentityInfo, PeerConfig, PeerStats,
};

impl Core {
    /// The own public key of the default identity, once a private key is set.
    pub fn public_key(&self) -> Option<x25519::PublicKey> {
        self.peers.key_pair().map(|(_, public)| *public)
    }

    /// The peer of the default identity with this public key.
    pub fn peer_id(&self, key: &x25519::PublicKey) -> Option<PeerId> {
        self.peers.get(LocalIdentityId::DEFAULT, key)
    }

    /// The peer of `identity` with this public key.
    pub fn peer_id_in(&self, identity: LocalIdentityId, key: &x25519::PublicKey) -> Option<PeerId> {
        self.peers.get(identity, key)
    }

    /// Adds a local identity with its own static key, answering handshakes on every
    /// transport; see [`Core::add_local_identity_on`].
    pub fn add_local_identity(&mut self, key: x25519::StaticSecret) -> Option<LocalIdentityId> {
        self.peers.add_identity(key, None)
    }

    /// Adds a local identity with its own static key that answers handshakes only on
    /// `transports` (none for an empty set); returns its id, or `None` if an identity
    /// (the default one included) already holds the key or identity ids are exhausted.
    ///
    /// Bind peers to it with [`PeerConfig::local_identity`]. A handshake initiation is
    /// dispatched to the identity whose key its mac1 is computed with: an identity is skipped
    /// on a transport outside its set as if its key did not exist (no response, no cookie
    /// reply), so it cannot be probed there. Its peers accept handshake responses, cookie
    /// replies and transport data only on its transports; a message on another transport is
    /// dropped like one for an unknown session index. What is sent is not restricted: a
    /// peer's path may name any transport.
    ///
    /// Each identity has its own mac1 and cookie keys and cookie secret, while one handshake
    /// budget ([`CoreConfig::handshake_rate_limit`]) holds across all of them. With several
    /// identities, an initiation costs one keyed BLAKE2s per identity tried before it.
    ///
    /// [`CoreConfig::handshake_rate_limit`]: crate::CoreConfig::handshake_rate_limit
    pub fn add_local_identity_on(
        &mut self,
        key: x25519::StaticSecret,
        transports: impl IntoIterator<Item = TransportId>,
    ) -> Option<LocalIdentityId> {
        self.peers
            .add_identity(key, Some(transports.into_iter().collect()))
    }

    /// Removes a local identity and its peers, each exactly as
    /// [`ConfigChange::RemovePeer`] would, and its source set; `false` for
    /// [`LocalIdentityId::DEFAULT`] or an unknown identity. Its id is not reused.
    pub fn remove_local_identity(&mut self, identity: LocalIdentityId) -> bool {
        if identity == LocalIdentityId::DEFAULT || self.peers.identity(identity).is_none() {
            return false;
        }
        let keys: Vec<x25519::PublicKey> = self
            .peers
            .iter()
            .filter(|(_, p)| p.local_identity() == identity)
            .map(|(_, p)| *p.public_key())
            .collect();
        for key in &keys {
            self.remove_peer(identity, key);
        }
        self.peers.remove_identity(identity)
    }

    /// The local identities, ascending by id; the default identity is first.
    pub fn local_identities(&self) -> impl Iterator<Item = LocalIdentityInfo> + '_ {
        self.peers.identities().iter().map(|i| LocalIdentityInfo {
            id: i.id,
            public_key: i.key.as_ref().map(|k| k.public),
            peers: i.peers,
            transports: i.transports.as_deref().map(<[TransportId]>::to_vec),
            sources: self.peers.sources(i.id),
        })
    }

    /// Replaces the source set of `identity` with `sources`; an empty list clears it. Returns
    /// `false` and changes nothing for an unknown identity, or if another identity's set
    /// holds one of the networks (compared after truncation to the prefix length).
    ///
    /// A local packet whose source lies in a set is routed among the allowed IPs of that
    /// set's identity only (the most specific network of all sets wins): without a route
    /// there it is dropped as [`reasons::NO_ROUTE`], whatever other identities' peers allow.
    /// A packet whose source lies in no set is routed as without sets, see [`Core::route`].
    /// While no identity has a set, local packets are routed without looking at their source.
    /// The default identity may have a set too.
    ///
    /// Removing an identity drops its set; [`ConfigChange::RemoveAllPeers`] keeps the sets.
    pub fn set_local_sources(&mut self, identity: LocalIdentityId, sources: &[AllowedIp]) -> bool {
        self.peers.set_sources(identity, sources)
    }

    /// All peers, in id order.
    pub fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peers.iter().map(|(id, _)| id)
    }

    /// Whether `peer` currently has a sending session with an unexhausted key.
    /// Returns `None` for an unknown peer. This reads the actual tunnel state,
    /// not the age of its last handshake, and does not start a handshake.
    /// Session expiry follows the core's normal timer processing.
    /// A session alone does not prove that a transport path is reachable.
    pub fn peer_has_session(&self, peer: PeerId) -> Option<bool> {
        self.peers.peer(peer).map(Peer::has_session)
    }

    /// Configuration and counters of `peer`; the time since its last handshake is measured
    /// up to the `now` of the latest call that passed the time.
    pub fn peer_stats(&self, peer: PeerId) -> Option<PeerStats> {
        let p = self.peers.peer(peer)?;
        let last_handshake = self.now.and_then(|now| p.time_since_last_handshake(now));
        Some(PeerStats {
            peer,
            public_key: *p.public_key(),
            local_identity: p.local_identity(),
            path: p.path(),
            allowed_ips: self.peers.allowed_ips(peer),
            preshared_key: p.preshared_key().copied(),
            persistent_keepalive: p.persistent_keepalive(),
            rx: p.rx(),
            tx: p.tx(),
            data_rx: p.data_rx(),
            data_tx: p.data_tx(),
            last_handshake,
        })
    }

    /// Handshake initiations transmitted to `peer` that got no response; `None` for an
    /// unknown peer.
    ///
    /// An initiation counts once when another one is transmitted to the peer while it is
    /// still unanswered (a retry after `REKEY_TIMEOUT`, a [`Core::force_handshake`], ...) or
    /// when the peer's handshake attempt gives up (`Event::SessionExpired`). A completed
    /// handshake answers it. The count is monotonic; a peer that only ever responds to
    /// handshakes stays at 0.
    pub fn unanswered_handshakes(&self, peer: PeerId) -> Option<u64> {
        self.peers.peer(peer).map(Peer::unanswered_handshakes)
    }

    /// The sum of [`Core::unanswered_handshakes`] over every peer, including the peers
    /// removed since the core was created: monotonic.
    ///
    /// Cheap to poll (one pass over the peers, without locks): a consumer that keeps a
    /// registry of its peers (e.g. a control plane) can watch this total and act on an
    /// increase, such as a registry resync when a peer stops answering, then find the peer
    /// with [`Core::unanswered_handshakes`].
    pub fn total_unanswered_handshakes(&self) -> u64 {
        self.peers
            .iter()
            .fold(self.removed_unanswered_handshakes, |total, (_, p)| {
                total.saturating_add(p.unanswered_handshakes())
            })
    }

    /// The peer a packet to `dst` is routed to when its source lies in no source set (see
    /// [`Core::set_local_sources`]): the longest allowed-IP match among the peers of the
    /// default identity or, while another identity's peers hold allowed IPs, among the peers
    /// of all identities, the range going to the peer that claimed it last. Use it to pick
    /// the `peer` of [`Core::inject_inbound`] for a locally generated reply about a packet to
    /// `dst`; [`Core::route_from`] is the send path's decision for a known source.
    pub fn route(&self, dst: IpAddr) -> Option<PeerId> {
        self.peers.by_destination(dst)
    }

    /// The peer a local packet from `src` to `dst` is routed to, as on the send path: the
    /// longest allowed-IP match among the peers of the identity whose source set holds `src`
    /// (see [`Core::set_local_sources`]), otherwise [`Core::route`].
    pub fn route_from(&self, src: IpAddr, dst: IpAddr) -> Option<PeerId> {
        self.peers.route_from(src, dst)
    }

    /// The path `peer`'s next transport data message would leave on: the one the policy
    /// selects for [`MessageKind::Data`], or the peer's current path. `None` for an unknown
    /// peer, or when neither the policy nor the peer supplies a path.
    pub fn data_path(&self, peer: PeerId) -> Option<Path> {
        let current = self.peers.peer(peer)?.path();
        self.policy.select(peer, MessageKind::Data).or(current)
    }

    /// Whether `index` is the receiver index `peer`'s current session puts on its transport
    /// data messages (the index the peer assigned to it), e.g. to check that a quoted
    /// datagram is ours. `false` for an unknown peer or one without a session.
    pub fn is_remote_index(&self, peer: PeerId, index: u32) -> bool {
        self.peers
            .peer(peer)
            .is_some_and(|p| p.remote_index() == Some(index))
    }

    /// Caps the padding of `peer`'s transport data at `limit` bytes of plaintext, as the
    /// kernel pads to the interface MTU: set it to the peer's inner MTU so that a packet at
    /// that MTU makes a datagram of exactly the MTU plus 32 bytes. Packets of at least
    /// `limit` bytes are not padded. `None` (the default) pads every packet to a multiple of
    /// 16 bytes. Both [`Core::handle_input`] and [`CryptoJob`]s honor it. Unknown peers are
    /// ignored.
    ///
    /// [`CryptoJob`]: crate::CryptoJob
    pub fn set_peer_pad_limit(&mut self, peer: PeerId, limit: Option<u16>) {
        if let Some(p) = self.peers.peer_mut(peer) {
            p.tunnel_mut().set_pad_limit(limit.map(usize::from));
        }
    }

    /// Removes the peer of `identity` with `key`, keeping its unanswered handshakes in the
    /// total.
    fn remove_peer(&mut self, identity: LocalIdentityId, key: &x25519::PublicKey) {
        if let Some(p) = self
            .peers
            .get(identity, key)
            .and_then(|id| self.peers.peer(id))
        {
            self.removed_unanswered_handshakes = self
                .removed_unanswered_handshakes
                .saturating_add(p.unanswered_handshakes());
        }
        self.peers.remove(identity, key);
    }

    /// Applies a configuration change.
    ///
    /// Peers cannot be added without a private key; such a change is reported as
    /// `Event::Dropped { peer: None, reason: reasons::NO_PRIVATE_KEY }`, and a peer of an
    /// unknown local identity as `reasons::UNKNOWN_LOCAL_IDENTITY`. Changes to unknown
    /// peers are ignored.
    // Rare: out of line, so the data path that shares `handle_input` keeps a small frame.
    #[inline(never)]
    pub(super) fn configure(&mut self, change: ConfigChange, now: Instant) {
        let (identity, change) = match change {
            ConfigChange::InLocalIdentity { identity, change } => match *change {
                change @ (ConfigChange::RemovePeer(_)
                | ConfigChange::SetAllowedIps { .. }
                | ConfigChange::SetPresharedKey { .. }
                | ConfigChange::SetKeepalive { .. }
                | ConfigChange::SetPath { .. }
                | ConfigChange::SetInboundDestinations { .. }
                | ConfigChange::SetInboundDestinationSource { .. }) => (identity, change),
                ConfigChange::SetPrivateKey(_)
                | ConfigChange::AddOrUpdatePeer(_)
                | ConfigChange::RemoveAllPeers
                | ConfigChange::InLocalIdentity { .. } => return,
            },
            change => (LocalIdentityId::DEFAULT, change),
        };
        let config = match change {
            ConfigChange::SetPrivateKey(key) => {
                self.peers.set_private_key(key);
                return;
            }
            ConfigChange::AddOrUpdatePeer(config) => config,
            // Only AddOrUpdatePeer may add a peer.
            ConfigChange::SetAllowedIps { peer, .. }
            | ConfigChange::SetPresharedKey { peer, .. }
            | ConfigChange::SetKeepalive { peer, .. }
            | ConfigChange::SetPath { peer, .. }
            | ConfigChange::SetInboundDestinations { peer, .. }
            | ConfigChange::SetInboundDestinationSource { peer, .. }
                if self.peers.get(identity, &peer).is_none() =>
            {
                return;
            }
            ConfigChange::RemovePeer(key) => return self.remove_peer(identity, &key),
            // Unwrapped above.
            ConfigChange::InLocalIdentity { .. } => return,
            ConfigChange::RemoveAllPeers => {
                self.removed_unanswered_handshakes = self.total_unanswered_handshakes();
                self.peers.clear();
                return;
            }
            ConfigChange::SetAllowedIps { peer, allowed_ips } => PeerConfig {
                allowed_ips,
                replace_allowed_ips: true,
                local_identity: Some(identity),
                ..PeerConfig::new(peer)
            },
            ConfigChange::SetPresharedKey { peer, key } => PeerConfig {
                // An all-zero key removes it.
                preshared_key: Some(key.unwrap_or([0; 32])),
                local_identity: Some(identity),
                ..PeerConfig::new(peer)
            },
            ConfigChange::SetKeepalive { peer, interval } => PeerConfig {
                persistent_keepalive: Some(interval.unwrap_or(0)),
                local_identity: Some(identity),
                ..PeerConfig::new(peer)
            },
            ConfigChange::SetPath { peer, path } => PeerConfig {
                path: Some(path),
                local_identity: Some(identity),
                ..PeerConfig::new(peer)
            },
            ConfigChange::SetInboundDestinations { peer, destinations } => {
                // A `None` in a PeerConfig leaves them unchanged: remove them directly.
                if let Some(id) = self.peers.get(identity, &peer) {
                    self.peers
                        .set_inbound_destinations(id, destinations.as_deref());
                }
                return;
            }
            ConfigChange::SetInboundDestinationSource { peer, source } => {
                if let Some(id) = self.peers.get(identity, &peer) {
                    self.peers.set_inbound_destination_source(id, source);
                }
                return;
            }
        };
        if let Err(e) = self.peers.apply(&config, now) {
            let reason = match e {
                PeerTableError::NoPrivateKey => reasons::NO_PRIVATE_KEY,
                PeerTableError::IndicesExhausted => reasons::NO_FREE_SESSION_INDEX,
                PeerTableError::IdsExhausted => reasons::NO_FREE_PEER_ID,
                PeerTableError::UnknownIdentity => reasons::UNKNOWN_LOCAL_IDENTITY,
            };
            self.dropped(None, reason);
        }
    }
}
