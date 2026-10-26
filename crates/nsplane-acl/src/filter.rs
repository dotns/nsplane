//! [`AclFilter`]: a sans-I/O [`PacketFilter`] enforcing the ACL policy on
//! inbound packets and the outbound rules of restricted peers.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use nsplane_core::cell::SnapshotCell;
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{FiveTuple, PacketBuf, PeerId};

use crate::engine::AclEngine;
use outcome::Counters;
use scope::ScopeSet;
use table::{FlowTable, FragmentTable};

#[cfg(doc)]
use crate::reasons;
#[cfg(doc)]
use crate::rules::Flow;

mod cache;
mod config;
mod identity;
mod inbound;
mod outbound;
mod outcome;
mod packet;
mod replies;
mod scope;
mod table;

pub use config::{AclFilterConfig, AclFilterStats, FragmentMode, Ipv6Mode};
pub use identity::{PeerIdentity, PeerLabelMap};
pub use scope::{
    AclFilterScope, AclFilterScopeError, AclFilterScopes, OtherProtocol, OtherProtocolRule,
};

/// A [`PacketFilter`] enforcing an [`AclEngine`] policy on inbound packets.
///
/// Inbound packets from a peer are evaluated as a new [`Flow`] from the
/// peer's labels (resolved by its [`PeerIdentity`]) unless a reply allowance or
/// a cached verdict holds them, exactly as
/// [`AclEngine::evaluate`] decides; anything the policy does not accept is
/// dropped with a [`reasons`] constant. With nothing loaded every inbound
/// packet is dropped (fail-closed). Outbound packets are accepted,
/// except to outbound-restricted peers (see the crate docs on namespaces) and
/// from sources outside [`AclFilterScope::outbound_sources`] when set.
///
/// **Stateful replies, not a conntrack/NAT**: with
/// [`AclFilterConfig::stateful_replies`] on, an accepted outbound TCP or UDP
/// packet, or ICMP or `ICMPv6` echo request, to a peer records an allowance for
/// the reversed tuple from that same peer, so its replies pass even when the
/// policy would not accept them as new inbound traffic. Allowances expire after [`AclFilterConfig::reply_idle_timeout`]
/// without traffic.
///
/// **Per-flow hook**: with a versioned identity
/// ([`PeerIdentity::generation`] non-zero, e.g. a [`PeerLabelMap`]), the
/// filter caches each peer's resolved labels and the verdict of each TCP or
/// UDP flow's first packet from a namespace member, tagged with the engine's
/// [generation](AclEngine::generation) and the identity generation; later
/// packets of the flow reuse it until either changes. Peers whose policy
/// accepts everything skip the evaluation altogether (see the crate docs on
/// the ACL hook). Verdicts and counters are the same as without the cache.
///
/// **Scopes**: each packet is judged under one [`AclFilterScope`], that of
/// its peer's [local identity](PeerIdentity::local_identity) in the
/// published [`AclFilterScopes`], or their default one when that identity has
/// none. [`with_scope`](Self::with_scope) gives the default scope at build
/// (scope generation 0); [`replace_scopes`](Self::replace_scopes) replaces
/// every scope at runtime in one atomic store and bumps the
/// [scope generation](Self::scope_generation). A packet loads the scopes
/// once, so it never mixes fields of two generations. A versioned identity's
/// answer is cached with the peer's labels; one that is not versioned is
/// asked per packet, only while some identity has a scope of its own. While
/// no scope constrains anything, a packet reads one flag and skips them.
///
/// IPv4 fragments: a first fragment is evaluated and its outcome recorded;
/// later fragments of the same packet follow it, and a later fragment with no
/// recorded first fragment is dropped. [`AclFilterConfig::fragments`] selects
/// how inbound IPv4 fragments are recorded ([`FragmentMode`]).
///
/// Clones share all state, so one clone can go to the engine and another can
/// read [`stats`](Self::stats).
#[derive(Clone)]
pub struct AclFilter {
    inner: Arc<Inner>,
}

struct Inner {
    engine: Arc<AclEngine>,
    identity: Box<dyn PeerIdentity>,
    config: AclFilterConfig,
    /// The published [`AclFilterScopes`].
    scopes: SnapshotCell<ScopeSet>,
    /// No published scope constrains anything, so packets skip the scopes.
    /// Read before them; it is true only while the latest published set is
    /// unscoped.
    unscoped: AtomicBool,
    /// Serializes [`AclFilter::replace_scopes`].
    scope_writer: Mutex<()>,
    /// Cache peers and verdicts (always, except in the differential tests).
    cache: bool,
    fragments: Mutex<FragmentTable>,
    flows: Mutex<FlowTable>,
    counters: Counters,
}

impl fmt::Debug for AclFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AclFilter")
            .field("engine", &self.inner.engine)
            .field("config", &self.inner.config)
            .field("scopes", &*self.inner.scopes.load())
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl AclFilter {
    /// A filter with the default [`AclFilterConfig`].
    pub fn new(engine: Arc<AclEngine>, identity: impl PeerIdentity) -> Self {
        Self::with_config(engine, identity, AclFilterConfig::default())
    }

    /// A filter with the given settings.
    pub fn with_config(
        engine: Arc<AclEngine>,
        identity: impl PeerIdentity,
        config: AclFilterConfig,
    ) -> Self {
        Self::with_scope(engine, identity, config, AclFilterScope::default())
    }

    /// A filter with the given settings and default address scope (scope
    /// generation 0; see [`replace_scopes`](Self::replace_scopes)).
    pub fn with_scope(
        engine: Arc<AclEngine>,
        identity: impl PeerIdentity,
        config: AclFilterConfig,
        scope: AclFilterScope,
    ) -> Self {
        Self::build(engine, Box::new(identity), config, scope, true)
    }

    /// A filter that never caches peers or verdicts: the reference the
    /// differential tests compare the cached filter with.
    #[cfg(test)]
    pub(crate) fn uncached(
        engine: Arc<AclEngine>,
        identity: impl PeerIdentity,
        config: AclFilterConfig,
    ) -> Self {
        Self::build(
            engine,
            Box::new(identity),
            config,
            AclFilterScope::default(),
            false,
        )
    }

    fn build(
        engine: Arc<AclEngine>,
        identity: Box<dyn PeerIdentity>,
        config: AclFilterConfig,
        scope: AclFilterScope,
        cache: bool,
    ) -> Self {
        let scopes = ScopeSet {
            generation: 0,
            default: scope,
            by_identity: HashMap::default(),
        };
        Self {
            inner: Arc::new(Inner {
                engine,
                identity,
                config,
                unscoped: AtomicBool::new(scopes.is_unscoped()),
                scopes: SnapshotCell::new(scopes),
                scope_writer: Mutex::default(),
                cache,
                fragments: Mutex::default(),
                flows: Mutex::default(),
                counters: Counters::default(),
            }),
        }
    }

    /// Validate `scopes` and publish them atomically; returns the new scope
    /// generation. A rejected set changes nothing.
    ///
    /// Each packet loads the published set once and is judged under one
    /// whole scope of one generation: packets that load it before the store
    /// see the previous scopes, those after see the new ones, and none mixes
    /// fields of both. Any clone of the filter can replace them. State
    /// recorded under the previous scopes (reply allowances, fragment
    /// outcomes) is kept. While the scopes are unchanged a packet reads them
    /// with one atomic load and a per-thread cache lookup, a few dependent
    /// loads more than a scope fixed at build; per-identity scopes add the
    /// identity resolution described in [`AclFilterScopes`].
    pub fn replace_scopes(&self, scopes: AclFilterScopes) -> Result<u64, AclFilterScopeError> {
        let inner = &*self.inner;
        let _writer = inner
            .scope_writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let set = ScopeSet::new(inner.scopes.read(|set| set.generation) + 1, scopes)?;
        let (generation, unscoped) = (set.generation, set.is_unscoped());
        // `unscoped` is cleared before a constrained set is stored and set
        // after an unscoped one is, so a packet reading it true is judged as
        // under the latest published set.
        if !unscoped {
            inner.unscoped.store(false, Ordering::Release);
        }
        inner.scopes.store(set);
        if unscoped {
            inner.unscoped.store(true, Ordering::Release);
        }
        Ok(generation)
    }

    /// The generation of the published scopes: 0 for the scope given at
    /// build, then increased by every [`replace_scopes`](Self::replace_scopes).
    #[must_use]
    pub fn scope_generation(&self) -> u64 {
        self.inner.scopes.read(|set| set.generation)
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> AclFilterStats {
        let c = &self.inner.counters;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        AclFilterStats {
            accepted: load(&c.accepted),
            replies: load(&c.replies),
            denied: load(&c.denied),
            no_policy: load(&c.no_policy),
            policy_failed: load(&c.policy_failed),
            unknown_peer: load(&c.unknown_peer),
            protocol: load(&c.protocol),
            fragment: load(&c.fragment),
            malformed: load(&c.malformed),
            fragment_evictions: load(&c.fragment_evictions),
            reply_evictions: load(&c.reply_evictions),
            reply_expired: load(&c.reply_expired),
            cross_namespace: load(&c.cross_namespace),
            outbound_denied: load(&c.outbound_denied),
            outbound_replies: load(&c.outbound_replies),
            reply_revoked: load(&c.reply_revoked),
            pending_evictions: load(&c.pending_evictions),
            verdict_evictions: load(&c.verdict_evictions),
            bypassed: load(&c.bypassed),
            ipv6_accepted: load(&c.ipv6_accepted),
            outbound_source: load(&c.outbound_source),
            internal: load(&c.internal),
            policy_state: self.inner.engine.policy_state(),
        }
    }
}

impl Inner {
    fn table(&self) -> MutexGuard<'_, FlowTable> {
        self.flows.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The identity generation; 0 (nothing is cached) when the identity is
    /// not versioned or the cache is off.
    fn identity_generation(&self) -> u64 {
        if self.cache {
            self.identity.generation()
        } else {
            0
        }
    }
}

/// `tuple` seen from the other end: addresses and ports swapped.
pub(crate) const fn reversed(tuple: FiveTuple) -> FiveTuple {
    FiveTuple {
        src: tuple.dst,
        dst: tuple.src,
        protocol: tuple.protocol,
        src_port: tuple.dst_port,
        dst_port: tuple.src_port,
    }
}

impl PacketFilter for AclFilter {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let outcome = self.inner.inbound(peer, packet.as_packet());
        outcome.count(&self.inner.counters);
        outcome.verdict()
    }

    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let outcome = self.inner.outbound(peer, packet.as_packet());
        outcome.count(&self.inner.counters);
        outcome.verdict()
    }
}

#[cfg(test)]
mod tests;
