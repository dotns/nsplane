//! Peer identities: the labels and local identity of each peer.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard};

use nsplane_core::LocalIdentityId;
use nsplane_packet::PeerId;

use crate::net::IpNet;
use crate::rules::LabelSet;

#[cfg(doc)]
use super::AclFilter;
#[cfg(doc)]
use super::scope::{AclFilterScope, AclFilterScopes};
#[cfg(doc)]
use crate::reasons;

/// Resolves the [`LabelSet`] of a peer: the labels the rules, namespaces,
/// grants and pinholes see for its packets.
///
/// Implemented by closures `Fn(PeerId) -> Option<LabelSet>`, by
/// [`PeerLabelMap`] and by `Arc<T>` of any implementation, so a caller can
/// keep a handle to update the labels while the filter uses them.
pub trait PeerIdentity: Send + Sync + 'static {
    /// The labels of `peer`; `None`: unknown peer (its inbound packets are
    /// dropped with [`reasons::UNKNOWN_PEER`]).
    fn labels(&self, peer: PeerId) -> Option<LabelSet>;

    /// The labels of `peer` for a packet whose remote address is `remote`:
    /// the IP source of an inbound packet, the IP destination of an
    /// outbound one. [`AclFilter`] resolves every source through this
    /// method.
    ///
    /// The default ignores `remote` and returns [`labels`](Self::labels).
    fn labels_for(&self, peer: PeerId, remote: IpAddr) -> Option<LabelSet> {
        let _ = remote;
        self.labels(peer)
    }

    /// Whether [`labels_for`](Self::labels_for) of `peer` depends on the
    /// address. [`AclFilter`] asks once per peer and identity generation,
    /// then caches the labels of such a peer per address, and of any other
    /// peer per peer; so a versioned implementation must return `true` for
    /// every peer whose labels depend on the address. Default `false`.
    fn by_source(&self, peer: PeerId) -> bool {
        let _ = peer;
        false
    }

    /// The identity generation: a non-zero value that changes whenever any
    /// answer may have changed (bumped once the change is visible to
    /// [`labels_for`](Self::labels_for) and [`by_source`](Self::by_source)).
    /// [`AclFilter`] caches the resolved peers and the flow verdicts under
    /// it.
    ///
    /// The default, 0, means "not versioned": the filter then resolves the
    /// peer and evaluates the policy on every packet (no label cache, no
    /// flow verdict cache, no bypass), so correctness never depends on it.
    /// Closures keep the default; [`PeerLabelMap`] is versioned.
    fn generation(&self) -> u64 {
        0
    }

    /// The local identity `peer` was added under (`nsplane-core`
    /// `PeerConfig::local_identity`): it selects the peer's
    /// [`AclFilterScope`] among the [`AclFilterScopes`] of the filter.
    ///
    /// It must return the identity the peer was added under; the engine does
    /// not check it, and a mismatch selects the wrong scope. Since a peer's
    /// identity is fixed when it is added, the answer is static per peer.
    /// A versioned implementation must bump its
    /// [`generation`](Self::generation) when it changes. [`AclFilter`] asks
    /// a versioned identity once per peer and identity generation, and one
    /// that is not versioned on every packet that needs a scope, only while
    /// some identity has a scope of its own.
    ///
    /// The default is [`LocalIdentityId::DEFAULT`].
    fn local_identity(&self, peer: PeerId) -> LocalIdentityId {
        let _ = peer;
        LocalIdentityId::DEFAULT
    }
}

impl<F> PeerIdentity for F
where
    F: Fn(PeerId) -> Option<LabelSet> + Send + Sync + 'static,
{
    fn labels(&self, peer: PeerId) -> Option<LabelSet> {
        self(peer)
    }
}

impl<T: PeerIdentity + ?Sized> PeerIdentity for Arc<T> {
    fn labels(&self, peer: PeerId) -> Option<LabelSet> {
        (**self).labels(peer)
    }

    fn labels_for(&self, peer: PeerId, remote: IpAddr) -> Option<LabelSet> {
        (**self).labels_for(peer, remote)
    }

    fn by_source(&self, peer: PeerId) -> bool {
        (**self).by_source(peer)
    }

    fn generation(&self) -> u64 {
        (**self).generation()
    }

    fn local_identity(&self, peer: PeerId) -> LocalIdentityId {
        (**self).local_identity(peer)
    }
}

/// A concurrent, versioned map from peers to their labels and local
/// identities.
///
/// Wrap it in an `Arc` and hand a clone to the filter to update it at runtime.
/// Every [`insert`](Self::insert), [`insert_by_source`](Self::insert_by_source),
/// [`set_local_identity`](Self::set_local_identity) and
/// [`remove`](Self::remove) bumps its [generation](PeerIdentity::generation)
/// under its write lock, so the filter's cached labels, identities and
/// verdicts never outlive a change.
#[derive(Debug)]
pub struct PeerLabelMap {
    map: RwLock<HashMap<PeerId, Entry>>,
    /// The local identities other than [`LocalIdentityId::DEFAULT`].
    identities: RwLock<HashMap<PeerId, LocalIdentityId>>,
    generation: AtomicU64,
}

/// The labels of a peer in a [`PeerLabelMap`].
#[derive(Debug)]
enum Entry {
    Labels(LabelSet),
    /// Labels per remote address, longest prefix first.
    BySource(Vec<(IpNet, LabelSet)>),
}

impl Default for PeerLabelMap {
    fn default() -> Self {
        Self {
            map: RwLock::default(),
            identities: RwLock::default(),
            generation: AtomicU64::new(1),
        }
    }
}

impl PeerLabelMap {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the labels of `peer`, replacing any previous entry.
    pub fn insert(&self, peer: PeerId, labels: LabelSet) {
        self.set(peer, Entry::Labels(labels));
    }

    /// Set the labels of `peer` per remote address, replacing any previous
    /// entry: the longest prefix of `by_address` containing the address wins
    /// (the first one listed among equally long prefixes), and an address
    /// outside every prefix makes the source unknown. For a peer whose
    /// packets carry several source addresses.
    /// [`labels`](PeerIdentity::labels) of such a peer is `None`.
    pub fn insert_by_source(&self, peer: PeerId, mut by_address: Vec<(IpNet, LabelSet)>) {
        // Stable: equally long prefixes keep their order.
        by_address.sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix_len()));
        self.set(peer, Entry::BySource(by_address));
    }

    fn set(&self, peer: PeerId, entry: Entry) {
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        map.insert(peer, entry);
        // Still under the write lock: a reader seeing the new generation
        // also sees the new labels.
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn read(&self) -> RwLockReadGuard<'_, HashMap<PeerId, Entry>> {
        self.map.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Set the local identity of `peer` ([`PeerIdentity::local_identity`]):
    /// the identity it was added under. Without one a peer is of
    /// [`LocalIdentityId::DEFAULT`]. Independent of its labels: inserting
    /// labels keeps it, [`remove`](Self::remove) clears it.
    pub fn set_local_identity(&self, peer: PeerId, id: LocalIdentityId) {
        let mut identities = self
            .identities
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        identities.insert(peer, id);
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Remove the entry and the local identity of `peer`; the peer becomes
    /// unknown.
    pub fn remove(&self, peer: PeerId) {
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        let mut identities = self
            .identities
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        map.remove(&peer);
        identities.remove(&peer);
        self.generation.fetch_add(1, Ordering::Release);
    }
}

impl PeerIdentity for PeerLabelMap {
    fn labels(&self, peer: PeerId) -> Option<LabelSet> {
        match self.read().get(&peer)? {
            Entry::Labels(labels) => Some(labels.clone()),
            Entry::BySource(_) => None,
        }
    }

    fn labels_for(&self, peer: PeerId, remote: IpAddr) -> Option<LabelSet> {
        match self.read().get(&peer)? {
            Entry::Labels(labels) => Some(labels.clone()),
            Entry::BySource(by_address) => by_address
                .iter()
                .find(|(net, _)| net.contains(&remote))
                .map(|(_, labels)| labels.clone()),
        }
    }

    fn by_source(&self, peer: PeerId) -> bool {
        matches!(self.read().get(&peer), Some(Entry::BySource(_)))
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn local_identity(&self, peer: PeerId) -> LocalIdentityId {
        let identities = self
            .identities
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        identities
            .get(&peer)
            .copied()
            .unwrap_or(LocalIdentityId::DEFAULT)
    }
}
