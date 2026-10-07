//! [`GateFilter`]: the [`FlowGate`] and an optional [`AclFilter`] as one
//! ordered [`PacketFilter`], with the divert of enforced denials.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, Path, PeerId};

use super::{DivertedPacket, FlowGate, GateDecision, GateReason};
use crate::filter::AclFilter;

/// Takes enforced denials offered by
/// [`UnboundAction::Divert`](super::UnboundAction::Divert) rules.
///
/// Called synchronously on the packet path; it must not block (a bounded
/// queue's non-blocking send is the intended implementation). Implemented by
/// closures `Fn(PeerId, DivertedPacket) -> bool` and by `Arc<T>` of any
/// implementation.
pub trait GateDivert: Send + Sync + 'static {
    /// Offer `packet` from `peer`: `true` when taken (the packet is then
    /// [`Verdict::Handled`]), `false` when refused (it is dropped).
    fn divert(&self, peer: PeerId, packet: DivertedPacket) -> bool;
}

impl<F> GateDivert for F
where
    F: Fn(PeerId, DivertedPacket) -> bool + Send + Sync + 'static,
{
    fn divert(&self, peer: PeerId, packet: DivertedPacket) -> bool {
        self(peer, packet)
    }
}

impl<T: GateDivert + ?Sized> GateDivert for Arc<T> {
    fn divert(&self, peer: PeerId, packet: DivertedPacket) -> bool {
        (**self).divert(peer, packet)
    }
}

/// Counters of a [`GateFilter`], in packets, both directions together.
///
/// The gate's own decision counters stay in [`FlowGate::counters`] (an
/// observed denial is counted there, not here).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateFilterStats {
    /// Accepted by an enforced gate allow.
    pub gate_accepted: u64,
    /// Dropped for an enforced gate denial (including refused diverts).
    pub gate_denied: u64,
    /// Inbound denials taken by the [`GateDivert`] ([`Verdict::Handled`]).
    pub diverted: u64,
    /// Inbound divert candidates the [`GateDivert`] refused (then dropped).
    pub divert_rejected: u64,
    /// Handed to the wrapped [`AclFilter`].
    pub passed_to_acl: u64,
}

#[derive(Debug, Default)]
struct Counters {
    gate_accepted: AtomicU64,
    gate_denied: AtomicU64,
    diverted: AtomicU64,
    divert_rejected: AtomicU64,
    passed_to_acl: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// The [`FlowGate`] and an optional [`AclFilter`] as one ordered
/// [`PacketFilter`].
///
/// One filter rather than a chain, because an enforced gate allow ends the
/// decision before the ACL, which an accept-means-continue chain cannot
/// express.
///
/// **Inbound.** [`FlowGate::evaluate_inbound`] decides first. An enforced
/// allow is [`Verdict::Accept`] without the ACL. An enforced
/// [`GateReason::Unbound`] or [`GateReason::OrphanFragment`] denial is
/// offered to the [`GateDivert`] ([`with_divert`](Self::with_divert)) when
/// the packet is TCP or UDP and matches an
/// [`UnboundAction::Divert`](super::UnboundAction::Divert) rule for the peer
/// of the one enforcing scope governing its destination, its source is no
/// local, binding or unbound address of any scope, and no hold matches: taken, it is
/// [`Verdict::Handled`]; refused, it is counted in
/// [`GateFilterStats::divert_rejected`] and dropped. Every other enforced
/// denial is dropped with [`GateReason::drop_reason`].
/// [`GateDecision::Pass`] and [`GateDecision::Observe`] hand the packet to
/// the wrapped [`AclFilter`] (both [`PacketFilter::inbound`] and
/// [`PacketFilter::inbound_from`] are forwarded), or accept it without one.
///
/// **Outbound.** An enforced denial of [`FlowGate::evaluate_outbound`] is
/// dropped; everything else is accepted, or with
/// [`with_acl_outbound(true)`](Self::with_acl_outbound) handed to the
/// [`AclFilter`]'s outbound.
///
/// The filter keeps no peer table: a peer without a binding is
/// [`GateReason::Unbound`] on a governed address and passes elsewhere, and
/// the wrapped [`AclFilter`] drops unknown peers inbound
/// ([`reasons::UNKNOWN_PEER`](crate::reasons::UNKNOWN_PEER)).
///
/// Clones share all state (the gate, the ACL filter, the counters).
#[derive(Clone)]
pub struct GateFilter {
    gate: Arc<FlowGate>,
    acl: Option<AclFilter>,
    acl_outbound: bool,
    divert: Option<Arc<dyn GateDivert>>,
    counters: Arc<Counters>,
}

impl fmt::Debug for GateFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GateFilter")
            .field("gate", &self.gate)
            .field("acl", &self.acl)
            .field("acl_outbound", &self.acl_outbound)
            .field("divert", &self.divert.is_some())
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl GateFilter {
    /// A filter judging with `gate`; no ACL, no divert.
    #[must_use]
    pub fn new(gate: Arc<FlowGate>) -> Self {
        Self {
            gate,
            acl: None,
            acl_outbound: false,
            divert: None,
            counters: Arc::default(),
        }
    }

    /// Run `acl` for packets the gate passes or observes.
    #[must_use]
    pub fn with_acl(mut self, acl: AclFilter) -> Self {
        self.acl = Some(acl);
        self
    }

    /// Also run the ACL's outbound for every outbound packet the gate did not
    /// deny (namespace outbound rules). Default `false`.
    #[must_use]
    pub const fn with_acl_outbound(mut self, enabled: bool) -> Self {
        self.acl_outbound = enabled;
        self
    }

    /// Offer divert candidates of enforced denials to `divert`.
    #[must_use]
    pub fn with_divert(mut self, divert: impl GateDivert) -> Self {
        self.divert = Some(Arc::new(divert));
        self
    }

    /// The gate this filter judges with.
    #[must_use]
    pub const fn gate(&self) -> &Arc<FlowGate> {
        &self.gate
    }

    /// A snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> GateFilterStats {
        let c = &self.counters;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        GateFilterStats {
            gate_accepted: load(&c.gate_accepted),
            gate_denied: load(&c.gate_denied),
            diverted: load(&c.diverted),
            divert_rejected: load(&c.divert_rejected),
            passed_to_acl: load(&c.passed_to_acl),
        }
    }

    /// The inbound steps; `acl` runs the wrapped filter's inbound.
    fn inbound_with(
        &self,
        peer: PeerId,
        packet: &mut PacketBuf,
        acl: impl FnOnce(&AclFilter, &mut PacketBuf) -> Verdict,
    ) -> Verdict {
        let data = packet.as_packet();
        match self.gate.evaluate_inbound(peer, data) {
            GateDecision::Enforce { allow: true, .. } => {
                bump(&self.counters.gate_accepted);
                return Verdict::Accept;
            }
            GateDecision::Enforce {
                allow: false,
                reason,
                ..
            } => return self.inbound_denied(peer, data, reason),
            GateDecision::Pass | GateDecision::Observe { .. } => {}
        }
        self.acl.as_ref().map_or(Verdict::Accept, |filter| {
            bump(&self.counters.passed_to_acl);
            acl(filter, packet)
        })
    }

    /// An enforced inbound denial: divert it or drop it.
    fn inbound_denied(&self, peer: PeerId, data: &[u8], reason: GateReason) -> Verdict {
        if matches!(reason, GateReason::Unbound | GateReason::OrphanFragment)
            && let Some(divert) = &self.divert
            && let Some(candidate) = self.gate.divert_candidate(peer, data)
        {
            if divert.divert(peer, candidate) {
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

impl PacketFilter for GateFilter {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.inbound_with(peer, packet, |acl, packet| acl.inbound(peer, packet))
    }

    fn inbound_from(&self, peer: PeerId, from: &Path, packet: &mut PacketBuf) -> Verdict {
        self.inbound_with(peer, packet, |acl, packet| {
            acl.inbound_from(peer, from, packet)
        })
    }

    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        match self.gate.evaluate_outbound(peer, packet.as_packet()) {
            GateDecision::Enforce {
                allow: false,
                reason,
                ..
            } => {
                bump(&self.counters.gate_denied);
                return Verdict::Drop {
                    reason: reason.drop_reason(),
                };
            }
            GateDecision::Enforce { allow: true, .. } => bump(&self.counters.gate_accepted),
            GateDecision::Pass | GateDecision::Observe { .. } => {}
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
