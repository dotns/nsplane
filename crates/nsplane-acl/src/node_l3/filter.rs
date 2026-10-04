//! [`NodeL3Filter`]: the [`NodeL3Gate`] and an optional [`AclFilter`] as one
//! ordered [`PacketFilter`], with the gateway-consumer divert.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, Path, PeerId};

use super::hash::FastMap;
use super::{GatewayConsumerPacket, NodeL3Decision, NodeL3Gate, NodeL3Reason};
use crate::filter::AclFilter;

/// Drop reason for a packet from or to a peer without a WireGuard public key.
const UNKNOWN_PEER: &str = "node l3: unknown peer";

// ── Peer keys ─────────────────────────────────────────────────────────────────

/// Resolves the WireGuard public key the [`NodeL3Gate`] keys its decisions by.
///
/// Implemented by closures `Fn(PeerId) -> Option<[u8; 32]>`, by
/// [`PeerKeyMap`] and by `Arc<T>` of any implementation, so a caller can keep
/// a handle to update the keys while the filter uses them.
pub trait PeerPublicKeys: Send + Sync + 'static {
    /// The WireGuard public key of `peer`, or `None` when the peer is unknown.
    fn public_key(&self, peer: PeerId) -> Option<[u8; 32]>;
}

impl<F> PeerPublicKeys for F
where
    F: Fn(PeerId) -> Option<[u8; 32]> + Send + Sync + 'static,
{
    fn public_key(&self, peer: PeerId) -> Option<[u8; 32]> {
        self(peer)
    }
}

impl<T: PeerPublicKeys + ?Sized> PeerPublicKeys for Arc<T> {
    fn public_key(&self, peer: PeerId) -> Option<[u8; 32]> {
        (**self).public_key(peer)
    }
}

/// A concurrent map from peers to their WireGuard public keys.
///
/// Readers load one immutable map without locking; writers copy it. Wrap it
/// in an `Arc` and hand a clone to the filter to update it at runtime.
#[derive(Debug, Default)]
pub struct PeerKeyMap {
    keys: ArcSwap<FastMap<PeerId, [u8; 32]>>,
}

impl PeerKeyMap {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the whole map.
    pub fn replace(&self, keys: impl IntoIterator<Item = (PeerId, [u8; 32])>) {
        self.keys.store(Arc::new(keys.into_iter().collect()));
    }

    /// Set the key of `peer`, replacing any previous one.
    pub fn insert(&self, peer: PeerId, key: [u8; 32]) {
        self.keys.rcu(|keys| {
            let mut keys = FastMap::clone(keys);
            keys.insert(peer, key);
            keys
        });
    }

    /// Remove the key of `peer`; the peer becomes unknown.
    pub fn remove(&self, peer: PeerId) {
        self.keys.rcu(|keys| {
            let mut keys = FastMap::clone(keys);
            keys.remove(&peer);
            keys
        });
    }
}

impl PeerPublicKeys for PeerKeyMap {
    fn public_key(&self, peer: PeerId) -> Option<[u8; 32]> {
        self.keys.load().get(&peer).copied()
    }
}

// ── Gateway-consumer sink ─────────────────────────────────────────────────────

/// Takes a [`GatewayConsumerPacket`] the gate denied as a Node packet but
/// captured as a gateway return (MD-3).
///
/// The sink is called synchronously on the packet path and must not block: a
/// bounded queue's non-blocking send is the intended implementation. The
/// consumer rechecks the candidate's authority
/// ([`NodeL3Gate::gateway_consumer_authority_current`]) and its exact flow
/// before delivery.
///
/// Implemented by closures `Fn(PeerId, GatewayConsumerPacket) -> bool` and by
/// `Arc<T>` of any implementation.
pub trait GatewayConsumerSink: Send + Sync + 'static {
    /// Offer `candidate` from `peer`; `true` when the consumer accepted it
    /// (the packet is then [`Verdict::Handled`]), `false` when it is full or
    /// closed (the packet is dropped).
    fn try_divert(&self, peer: PeerId, candidate: GatewayConsumerPacket) -> bool;
}

impl<F> GatewayConsumerSink for F
where
    F: Fn(PeerId, GatewayConsumerPacket) -> bool + Send + Sync + 'static,
{
    fn try_divert(&self, peer: PeerId, candidate: GatewayConsumerPacket) -> bool {
        self(peer, candidate)
    }
}

impl<T: GatewayConsumerSink + ?Sized> GatewayConsumerSink for Arc<T> {
    fn try_divert(&self, peer: PeerId, candidate: GatewayConsumerPacket) -> bool {
        (**self).try_divert(peer, candidate)
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

/// Counters of a [`NodeL3Filter`], in packets, both directions together.
///
/// The gate's own decision counters stay in [`NodeL3Gate::counters`] (an
/// Observe-mode prospective denial is counted there, not here).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeL3FilterStats {
    /// Accepted by an enforced gate allow or a Subnet transport admission.
    pub gate_accepted: u64,
    /// Dropped for an enforced gate denial (including rejected diverts).
    pub gate_denied: u64,
    /// Inbound denials handed to the gateway-consumer sink
    /// ([`Verdict::Handled`]).
    pub diverted: u64,
    /// Inbound gateway-consumer candidates the sink refused (then dropped).
    pub divert_rejected: u64,
    /// Dropped because the peer has no public key.
    pub unknown_peer: u64,
    /// Handed to the wrapped [`AclFilter`].
    pub passed_to_acl: u64,
}

#[derive(Debug, Default)]
struct Counters {
    gate_accepted: AtomicU64,
    gate_denied: AtomicU64,
    diverted: AtomicU64,
    divert_rejected: AtomicU64,
    unknown_peer: AtomicU64,
    passed_to_acl: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

// ── Filter ────────────────────────────────────────────────────────────────────

/// The Node L3 gate and an optional [`AclFilter`] as one ordered
/// [`PacketFilter`].
///
/// One filter rather than a chain, because an enforced gate allow ends the
/// decision before the ACL, which an accept-means-continue chain cannot
/// express. This is the gate part of ns `AccountFilter`
/// (`crates/ns/src/account_engine/filters.rs`); its steps map to nsplane as
/// follows:
///
/// | ns `AccountFilter` step | nsplane location |
/// | --- | --- |
/// | peer id to WireGuard key (`PeerKeys`), unknown peer dropped | here: [`PeerPublicKeys`] / [`PeerKeyMap`], dropped as `node l3: unknown peer` in both directions |
/// | recovery-probe drop | not here: link-layer concern, answered by the link layer before the filters |
/// | Subnet LAN DNS transport admission (`SUBNET_LAN_DNS_TRANSPORT_PORT`) | here, when [`with_subnet_transport_port`](Self::with_subnet_transport_port) is set |
/// | `evaluate_inbound`: enforced allow skips the ACL, enforced deny drops | here (inbound IPv4) |
/// | gateway-consumer split after a `SourceBinding` / `OrphanFragment` denial | here: [`with_divert`](Self::with_divert), [`Verdict::Handled`] |
/// | local Node packet, ICMP echo reply, `acl_check_packet` | the wrapped [`AclFilter`] (MD-A `AclFilterConfig` flags `accept_to_local` / `accept_icmp_echo_reply`) |
/// | inbound IPv6: dynamic L3 lease, Subnet return identity, enforced Subnet ingress | nsplane-core per-peer inbound destinations (see below) |
/// | IPv6 route owner (`outbound_route`, `ROUTE_OWNER`) | routing / MD-6, not a filter |
/// | outbound Subnet transport, then `evaluate_outbound` enforced deny | here (outbound) |
///
/// **Inbound.** Unknown peer: dropped. IPv4: with a Subnet transport port
/// set, an admitted reserved transport request is an enforced allow
/// ([`NodeL3Reason::SubnetGrant`]); otherwise [`NodeL3Gate::evaluate_inbound`]
/// decides. An enforced allow is [`Verdict::Accept`] without the ACL. An
/// enforced denial for [`NodeL3Reason::SourceBinding`] or
/// [`NodeL3Reason::OrphanFragment`] whose packet the gate captures as a
/// gateway-consumer candidate ([`NodeL3Gate::gateway_consumer_packet`]) and
/// the [`GatewayConsumerSink`] accepts is [`Verdict::Handled`]; every other
/// enforced denial is dropped with [`NodeL3Reason::drop_reason`]. Legacy and
/// Observe (the gate only counts) pass the packet to the wrapped
/// [`AclFilter`] (both [`PacketFilter::inbound`] and
/// [`PacketFilter::inbound_from`] are forwarded), or accept it without one.
/// IPv6 and non-IP packets skip the gate and go to the ACL (or are accepted).
///
/// The IPv6 Subnet ingress authorization is not checked here: ns folds
/// [`NodeL3Gate::enforced_subnet_ingress_prefixes`] into nsplane-core's
/// per-peer inbound destinations (`PeerConfig::inbound_destinations`,
/// `ConfigChange::SetInboundDestinations`,
/// `EngineHandle::set_inbound_destinations`) and recomputes them whenever
/// [`NodeL3Gate::authorization_generation`] changes.
///
/// **Outbound** is the gate only, as in ns: unknown peer dropped; a Subnet
/// transport admission accepts; an enforced [`NodeL3Gate::evaluate_outbound`]
/// denial drops with [`NodeL3Reason::drop_reason`]; everything else
/// (including IPv6 and non-IP, which the gate leaves to legacy) is accepted.
/// [`with_acl_outbound`](Self::with_acl_outbound) additionally runs the
/// wrapped [`AclFilter`]'s outbound for every packet the gate did not deny,
/// for callers using namespace outbound rules; ns does not. Route-owner
/// checks stay with routing (MD-6).
///
/// Clones share all state (the gate, the ACL filter, the counters).
#[derive(Clone)]
pub struct NodeL3Filter {
    gate: Arc<NodeL3Gate>,
    keys: Arc<dyn PeerPublicKeys>,
    acl: Option<AclFilter>,
    acl_outbound: bool,
    subnet_transport_port: Option<u16>,
    divert: Option<Arc<dyn GatewayConsumerSink>>,
    counters: Arc<Counters>,
}

impl fmt::Debug for NodeL3Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeL3Filter")
            .field("gate", &self.gate)
            .field("acl", &self.acl)
            .field("acl_outbound", &self.acl_outbound)
            .field("subnet_transport_port", &self.subnet_transport_port)
            .field("divert", &self.divert.is_some())
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl NodeL3Filter {
    /// A filter judging with `gate`, resolving peers through `keys`; no ACL,
    /// no Subnet transport port, no divert.
    #[must_use]
    pub fn new(gate: Arc<NodeL3Gate>, keys: impl PeerPublicKeys) -> Self {
        Self {
            gate,
            keys: Arc::new(keys),
            acl: None,
            acl_outbound: false,
            subnet_transport_port: None,
            divert: None,
            counters: Arc::default(),
        }
    }

    /// Run `acl` for packets the gate leaves to legacy or observes.
    #[must_use]
    pub fn with_acl(mut self, acl: AclFilter) -> Self {
        self.acl = Some(acl);
        self
    }

    /// Also run the ACL's outbound for every outbound packet the gate did not
    /// deny (namespace outbound rules). Default `false`, as in ns.
    #[must_use]
    pub const fn with_acl_outbound(mut self, enabled: bool) -> Self {
        self.acl_outbound = enabled;
        self
    }

    /// Admit the reserved Subnet transport on this destination port (ns:
    /// tunnel-wg `SUBNET_LAN_DNS_TRANSPORT_PORT`, 53535). Default: none.
    #[must_use]
    pub const fn with_subnet_transport_port(mut self, port: u16) -> Self {
        self.subnet_transport_port = Some(port);
        self
    }

    /// Divert gateway-consumer candidates of enforced denials to `sink`.
    #[must_use]
    pub fn with_divert(mut self, sink: impl GatewayConsumerSink) -> Self {
        self.divert = Some(Arc::new(sink));
        self
    }

    /// The gate this filter judges with.
    #[must_use]
    pub const fn gate(&self) -> &Arc<NodeL3Gate> {
        &self.gate
    }

    /// A snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> NodeL3FilterStats {
        let c = &self.counters;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        NodeL3FilterStats {
            gate_accepted: load(&c.gate_accepted),
            gate_denied: load(&c.gate_denied),
            diverted: load(&c.diverted),
            divert_rejected: load(&c.divert_rejected),
            unknown_peer: load(&c.unknown_peer),
            passed_to_acl: load(&c.passed_to_acl),
        }
    }

    fn unknown_peer(&self) -> Verdict {
        bump(&self.counters.unknown_peer);
        Verdict::Drop {
            reason: UNKNOWN_PEER,
        }
    }

    /// The inbound steps; `acl` runs the wrapped filter's inbound.
    fn inbound_with(
        &self,
        peer: PeerId,
        packet: &mut PacketBuf,
        acl: impl FnOnce(&AclFilter, &mut PacketBuf) -> Verdict,
    ) -> Verdict {
        let Some(key) = self.keys.public_key(peer) else {
            return self.unknown_peer();
        };
        let data = packet.as_packet();
        if data.first().is_some_and(|byte| byte >> 4 == 4) {
            match self.inbound_ipv4_decision(key, data) {
                NodeL3Decision::Enforce { allow: true, .. } => {
                    bump(&self.counters.gate_accepted);
                    return Verdict::Accept;
                }
                NodeL3Decision::Enforce {
                    allow: false,
                    reason,
                } => return self.inbound_denied(peer, key, data, reason),
                NodeL3Decision::Legacy | NodeL3Decision::Observe { .. } => {}
            }
        }
        self.acl.as_ref().map_or(Verdict::Accept, |filter| {
            bump(&self.counters.passed_to_acl);
            acl(filter, packet)
        })
    }

    fn inbound_ipv4_decision(&self, key: [u8; 32], data: &[u8]) -> NodeL3Decision {
        if let Some(port) = self.subnet_transport_port
            && self.gate.evaluate_subnet_transport_inbound(key, data, port)
        {
            return NodeL3Decision::Enforce {
                allow: true,
                reason: NodeL3Reason::SubnetGrant,
            };
        }
        self.gate.evaluate_inbound(key, data)
    }

    /// An enforced inbound denial: divert a gateway return (MD-3) or drop.
    fn inbound_denied(
        &self,
        peer: PeerId,
        key: [u8; 32],
        data: &[u8],
        reason: NodeL3Reason,
    ) -> Verdict {
        if matches!(
            reason,
            NodeL3Reason::SourceBinding | NodeL3Reason::OrphanFragment
        ) && let Some(sink) = &self.divert
            && let Some(candidate) = self.gate.gateway_consumer_packet(key, data)
        {
            if sink.try_divert(peer, candidate) {
                bump(&self.counters.diverted);
                return Verdict::Handled;
            }
            bump(&self.counters.divert_rejected);
        }
        bump(&self.counters.gate_denied);
        Verdict::Drop {
            reason: reason.drop_reason(),
        }
    }
}

impl PacketFilter for NodeL3Filter {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.inbound_with(peer, packet, |acl, packet| acl.inbound(peer, packet))
    }

    fn inbound_from(&self, peer: PeerId, from: &Path, packet: &mut PacketBuf) -> Verdict {
        self.inbound_with(peer, packet, |acl, packet| {
            acl.inbound_from(peer, from, packet)
        })
    }

    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let Some(key) = self.keys.public_key(peer) else {
            return self.unknown_peer();
        };
        let data = packet.as_packet();
        if let Some(port) = self.subnet_transport_port
            && self
                .gate
                .evaluate_subnet_transport_outbound(key, data, port)
        {
            bump(&self.counters.gate_accepted);
        } else {
            match self.gate.evaluate_outbound(key, data) {
                NodeL3Decision::Enforce {
                    allow: false,
                    reason,
                } => {
                    bump(&self.counters.gate_denied);
                    return Verdict::Drop {
                        reason: reason.drop_reason(),
                    };
                }
                NodeL3Decision::Enforce { allow: true, .. } => {
                    bump(&self.counters.gate_accepted);
                }
                NodeL3Decision::Legacy | NodeL3Decision::Observe { .. } => {}
            }
        }
        match &self.acl {
            Some(acl) if self.acl_outbound => {
                bump(&self.counters.passed_to_acl);
                acl.outbound(peer, packet)
            }
            _ => Verdict::Accept,
        }
    }
}

#[cfg(test)]
#[path = "tests/filter.rs"]
mod tests;
