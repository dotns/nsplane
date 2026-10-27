//! Scope-qualified decisions: [`FlowGate::evaluate_inbound_in`] and
//! [`FlowGate::evaluate_outbound_in`].

use std::cell::{Cell, OnceCell, RefCell};
use std::sync::atomic::Ordering;

use nsplane_packet::PeerId;
use thiserror::Error;

use super::config::ScopeId;
use super::state::FlowState;
use super::{FlowGate, GateDecision, GateReason, PacketDirection};
use crate::rules::RuleId;

/// One scope, or a non-empty set of scopes, a scoped decision is valid for.
///
/// Built from scope ids, which need not be in the published policy: a scope
/// the policy does not have never decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeSelection {
    /// Sorted, without repeats, never empty.
    scopes: Box<[ScopeId]>,
}

/// [`ScopeSelection::any_of`] was given no scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("a scope selection needs at least one scope")]
pub struct EmptySelection;

impl ScopeSelection {
    /// The selection of `scope` alone.
    #[must_use]
    pub fn one(scope: ScopeId) -> Self {
        Self {
            scopes: Box::new([scope]),
        }
    }

    /// The selection of every scope in `scopes`, in any order, repeats
    /// ignored.
    ///
    /// # Errors
    /// [`EmptySelection`] when `scopes` is empty.
    pub fn any_of(scopes: impl IntoIterator<Item = ScopeId>) -> Result<Self, EmptySelection> {
        let mut scopes: Vec<_> = scopes.into_iter().collect();
        if scopes.is_empty() {
            return Err(EmptySelection);
        }
        scopes.sort_unstable();
        scopes.dedup();
        Ok(Self {
            scopes: scopes.into(),
        })
    }

    /// The position of `scope` in the selection.
    fn position(&self, scope: &ScopeId) -> Option<usize> {
        self.scopes.binary_search(scope).ok()
    }
}

/// The decision of [`FlowGate::evaluate_inbound_in`] or
/// [`FlowGate::evaluate_outbound_in`] for a [`ScopeSelection`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScopedDecision {
    /// The decision; always enforced outside the selection, never
    /// [`GateDecision::Pass`].
    pub decision: GateDecision,
    /// The deciding scope, when it is in the selection.
    pub scope: Option<ScopeId>,
    /// The grant: admitting or suspended for a new flow, the flow's grant for
    /// a packet of a live flow or an ICMP error quoting one. `None` for a
    /// later fragment and for every other decision.
    pub rule: Option<RuleId>,
    /// The policy generation the decision was taken under.
    pub generation: u64,
}

/// An enforced denial with `reason` and no rule.
pub(super) const fn enforced_denial(reason: GateReason) -> GateDecision {
    GateDecision::Enforce {
        allow: false,
        reason,
        rule: None,
    }
}

/// The selection of a scoped evaluation and what one attempt found beside
/// the decision.
#[derive(Debug)]
pub(super) struct Scoping<'a> {
    selection: &'a ScopeSelection,
    /// The position in `selection` of the deciding scope.
    position: Cell<Option<usize>>,
    /// The grant of the live flow a packet belongs to or an ICMP error quotes.
    flow_rule: RefCell<Option<RuleId>>,
    /// The generation of the snapshot the decision was taken under.
    generation: Cell<u64>,
}

impl<'a> Scoping<'a> {
    const fn new(selection: &'a ScopeSelection) -> Self {
        Self {
            selection,
            position: Cell::new(None),
            flow_rule: RefCell::new(None),
            generation: Cell::new(0),
        }
    }

    /// Forget what an earlier attempt found.
    pub(super) fn reset(&self) {
        self.position.set(None);
        self.flow_rule.replace(None);
    }

    /// Whether `scope` is selected; if so it is the deciding scope.
    pub(super) fn select(&self, scope: &ScopeId) -> bool {
        let position = self.selection.position(scope);
        self.position.set(position);
        position.is_some()
    }

    /// Remember the generation the decision is taken under.
    pub(super) fn taken_under(&self, generation: u64) {
        self.generation.set(generation);
    }

    /// Remember the grant of `flow`, which the packet belongs to or quotes.
    pub(super) fn found_flow(&self, flow: &FlowState) {
        self.flow_rule.replace(Some(flow.rule.clone()));
    }

    /// The scoped decision of `decision`.
    fn finish(&self, decision: GateDecision) -> ScopedDecision {
        let rule = match &decision {
            GateDecision::Observe {
                reason: GateReason::ValidState,
                ..
            }
            | GateDecision::Enforce {
                reason: GateReason::ValidState,
                ..
            } => self.flow_rule.take(),
            GateDecision::Observe { rule, .. } | GateDecision::Enforce { rule, .. } => rule.clone(),
            GateDecision::Pass => None,
        };
        ScopedDecision {
            decision,
            scope: self
                .position
                .get()
                .map(|position| self.selection.scopes[position].clone()),
            rule,
            generation: self.generation.get(),
        }
    }
}

impl FlowGate {
    /// Evaluate a packet received from `peer` for `selection`: the decision
    /// [`evaluate_inbound`](Self::evaluate_inbound) takes when the packet's
    /// scope is in the selection, using that scope's state only; otherwise an
    /// enforced denial that reads and writes no state (see
    /// [`ScopedDecision`] and the reference's decision table).
    #[must_use]
    pub fn evaluate_inbound_in(
        &self,
        peer: PeerId,
        packet: &[u8],
        selection: &ScopeSelection,
    ) -> ScopedDecision {
        self.evaluate_in(PacketDirection::Inbound, peer, packet, selection)
    }

    /// Evaluate a packet to be sent to `peer` for `selection`, like
    /// [`evaluate_inbound_in`](Self::evaluate_inbound_in).
    #[must_use]
    pub fn evaluate_outbound_in(
        &self,
        peer: PeerId,
        packet: &[u8],
        selection: &ScopeSelection,
    ) -> ScopedDecision {
        self.evaluate_in(PacketDirection::Outbound, peer, packet, selection)
    }

    /// Evaluate, count and report one packet for `selection`. A packet of
    /// another version is out of scope.
    fn evaluate_in(
        &self,
        direction: PacketDirection,
        peer: PeerId,
        packet: &[u8],
        selection: &ScopeSelection,
    ) -> ScopedDecision {
        let scoping = Scoping::new(selection);
        let decision = if matches!(packet.first().map(|byte| byte >> 4), Some(4 | 6)) {
            self.evaluate_with(direction, peer, packet, OnceCell::new(), Some(&scoping))
        } else {
            scoping.taken_under(self.generation());
            enforced_denial(GateReason::OutOfScope)
        };
        let scoped = scoping.finish(decision);
        self.record_decision(&scoped.decision);
        if self.events_on.load(Ordering::Relaxed) {
            self.emit_event(peer, packet, &scoped.decision);
        }
        scoped
    }
}
