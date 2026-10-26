//! The bounded fragment and flow tables and what they hold.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use nsplane_core::LocalIdentityId;
use nsplane_packet::{FiveTuple, PeerId};

use super::identity::PeerIdentity;
use super::outcome::Outcome;
use super::replies::is_pending;
use crate::engine::{Membership, ReplyDependency, Snapshot};
use crate::lru::{FlowHash, LruMap};
use crate::rules::LabelSet;

#[cfg(doc)]
use super::config::FragmentMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct FragmentKey {
    pub(super) peer: PeerId,
    pub(super) outbound: bool,
    pub(super) src: IpAddr,
    pub(super) dst: IpAddr,
    pub(super) protocol: u8,
    pub(super) id: u16,
}

/// First-fragment outcomes in insertion order; when full, the oldest is
/// evicted (O(1)). `allowed` is the table of [`FragmentMode::AllowOnly`]:
/// the engine-clock time each accepted first fragment was recorded.
#[derive(Debug, Default)]
pub(super) struct FragmentTable {
    pub(super) entries: LruMap<FragmentKey, Outcome>,
    pub(super) allowed: HashMap<AllowedKey, Instant>,
}

/// The key of [`FragmentMode::AllowOnly`]: no peer, no direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct AllowedKey {
    pub(super) src: Ipv4Addr,
    pub(super) dst: Ipv4Addr,
    pub(super) protocol: u8,
    pub(super) id: u16,
}

/// The flow table, behind one lock: for each peer, direction and tuple
/// ([`EntryKey`]) either a reply allowance or a cached verdict, plus the
/// pending dependencies and the resolved peers.
///
/// Reply allowances: inbound allowances (remote -> local, recorded by
/// outbound packets) and outbound allowances (local -> remote, recorded by
/// accepted inbound packets from outbound-restricted peers).
///
/// Cached verdicts: the decision of a flow's first packet, tagged with the
/// policy and identity generations it was computed under; a hit under other
/// generations (or whose pinhole is gone) is removed and re-evaluated. A
/// verdict and an allowance for the same key never coexist: the allowance
/// wins, as the reply check comes first.
///
/// Bounds: allowances and verdicts share `reply_capacity`. When full, cached
/// verdicts make room first (all of them are flushed, counted in
/// `verdict_evictions`), so an allowance is evicted (the least recently seen,
/// in O(1): the entries are kept in recency order) exactly when the table
/// holds allowances only, as without the cache. A new verdict is not cached when the table is
/// full and fewer than an eighth of it are verdicts.
///
/// `pending` remembers the dependency of inbound flows accepted through a
/// grant, a pinhole, a dependent allowance or a rule towards another
/// namespace member, keyed by the packet's tuple:
/// the inbound allowance recorded when the flow leaves again (forwarded to
/// another peer, or answered by the local node) inherits it, so it is revoked
/// with the grant or pinhole even towards an unrestricted peer. Same bounds
/// as allowances (evictions counted in `pending_evictions`); an idle entry is
/// dropped silently.
///
/// `peers` caches the resolved peers, bounded by `reply_capacity` too. A
/// peer whose labels depend on the packet's address
/// ([`PeerIdentity::by_source`]) is cached there as a marker, and resolved
/// per remote address in `sources`, bounded by `reply_capacity` as well (when
/// full, the least recently used entry is evicted in O(1); an evicted address
/// is only resolved again).
#[derive(Debug, Default)]
pub(super) struct FlowTable {
    pub(super) entries: LruMap<EntryKey, FlowEntry>,
    /// How many of `entries` are cached verdicts.
    pub(super) verdicts: usize,
    pub(super) pending: LruMap<FiveTuple, ReplyEntry>,
    pub(super) peers: HashMap<PeerId, Arc<PeerInfo>, FlowHash>,
    pub(super) sources: LruMap<(PeerId, IpAddr), Arc<PeerInfo>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct EntryKey {
    pub(super) peer: PeerId,
    pub(super) outbound: bool,
    pub(super) tuple: FiveTuple,
}

#[derive(Debug)]
pub(super) enum FlowEntry {
    Allowance(ReplyEntry),
    Verdict(CachedVerdict),
}

#[derive(Debug, Clone)]
pub(super) struct ReplyEntry {
    pub(super) last_seen: Instant,
    /// Revokes the allowance when it is gone from the engine snapshot.
    pub(super) dependency: Option<ReplyDependency>,
}

/// The decision about a flow and the side effects each of its packets has.
#[derive(Debug, Clone)]
pub(super) struct FlowVerdict {
    pub(super) outcome: Outcome,
    /// What an accepted flow depends on: its pending entry, and the outbound
    /// allowance of `restricted`, inherit it.
    pub(super) dependency: Option<ReplyDependency>,
    /// An accepted inbound flow from an outbound-restricted peer records the
    /// outbound reply allowance.
    pub(super) restricted: bool,
}

impl FlowVerdict {
    pub(super) const fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            dependency: None,
            restricted: false,
        }
    }

    /// The dependency the flow's pending entry records.
    pub(super) fn pending(&self) -> Option<&ReplyDependency> {
        self.dependency
            .as_ref()
            .filter(|dependency| is_pending(dependency))
    }
}

#[derive(Debug)]
pub(super) struct CachedVerdict {
    pub(super) generation: u64,
    pub(super) identity: u64,
    pub(super) verdict: FlowVerdict,
}

/// What the flow table holds for a packet.
pub(super) enum Hit {
    /// A live reply allowance (refreshed), with its dependency.
    Allowance(Option<ReplyDependency>),
    /// A verdict cached under the current generations.
    Verdict(FlowVerdict),
}

/// A peer (or a by-source peer and a remote address) resolved under one
/// policy and identity generation.
#[derive(Debug)]
pub(super) struct PeerInfo {
    pub(super) generation: u64,
    pub(super) identity: u64,
    /// A marker: the peer's labels depend on the packet's address and are
    /// resolved per address. Its other fields are those of an unknown peer.
    pub(super) by_source: bool,
    /// The peer's local identity ([`PeerIdentity::local_identity`]), when
    /// cached (`identity` non-zero); else [`LocalIdentityId::DEFAULT`], never
    /// read.
    pub(super) local_identity: LocalIdentityId,
    /// The peer's labels, `None` for an unknown peer.
    pub(super) labels: Option<LabelSet>,
    /// The peer's namespaces (the union over its labels, computed once
    /// here), `None` when it is in no namespace.
    pub(super) membership: Option<Arc<Membership>>,
    /// How the policy governs the peer.
    pub(super) governed: Governed,
    /// Some pinhole belongs to the peer.
    pub(super) pinholes: bool,
    /// Every new inbound TCP or UDP flow of the peer is accepted without a
    /// dependency or an outbound allowance, so its evaluation is skipped.
    pub(super) bypass: bool,
}

/// How the policy governs a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Governed {
    /// In no namespace: the default policy.
    Default,
    /// A namespace member, outbound unrestricted.
    Member,
    /// A namespace member, outbound-restricted.
    Restricted,
}

impl PeerInfo {
    /// Resolve `peer` for packets whose remote address is `src`.
    pub(super) fn resolve(
        identity: &dyn PeerIdentity,
        snapshot: &Snapshot,
        peer: PeerId,
        src: IpAddr,
        generation: u64,
    ) -> Self {
        let local_identity = if generation == 0 {
            LocalIdentityId::DEFAULT
        } else {
            identity.local_identity(peer)
        };
        Self::new(
            identity.labels_for(peer, src),
            snapshot,
            generation,
            false,
            local_identity,
        )
    }

    pub(super) fn new(
        labels: Option<LabelSet>,
        snapshot: &Snapshot,
        generation: u64,
        by_source: bool,
        local_identity: LocalIdentityId,
    ) -> Self {
        let membership = labels
            .as_ref()
            .and_then(|labels| snapshot.membership_of(labels));
        Self {
            generation: snapshot.generation(),
            identity: generation,
            by_source,
            local_identity,
            governed: match &membership {
                None => Governed::Default,
                Some(membership) if membership.outbound_restricted() => Governed::Restricted,
                Some(_) => Governed::Member,
            },
            pinholes: labels
                .as_ref()
                .is_some_and(|labels| snapshot.has_pinholes_of(labels)),
            bypass: labels.is_some() && snapshot.bypasses(membership.as_deref()),
            labels,
            membership,
        }
    }
}
