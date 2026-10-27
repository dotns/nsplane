//! Packet evaluation and decision recording.

use std::cell::OnceCell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::MutexGuard;
use std::sync::atomic::Ordering;
use std::time::Instant;

use nsplane_packet::PeerId;

use super::addr::GateAddr;
use super::config::UnboundAction;
use super::packet::{PacketMeta, flow_key, related_flow_key};
use super::policy::{Authorization, BindingKey, CompiledScope};
use super::scoped::{Scoping, enforced_denial};
use super::snapshot::Snapshot;
use super::state::{
    Admission, FlowKey, FlowState, FragmentDisposition, Lookup, Shard, TcpClose, protocol_timeout,
};
use super::{FlowGate, GateDecision, GateReason, PacketDirection, mode_decision};

/// The scopes a packet's addresses fall under.
#[derive(Debug, Clone, Copy)]
struct Applicable<'a> {
    /// The scope when exactly one applies.
    single: Option<&'a CompiledScope>,
    any: bool,
    any_enforce: bool,
}

impl<'a> Applicable<'a> {
    fn of(scopes: impl Iterator<Item = &'a CompiledScope>) -> Self {
        let mut applicable = Self {
            single: None,
            any: false,
            any_enforce: false,
        };
        for scope in scopes {
            applicable.single = (!applicable.any).then_some(scope);
            applicable.any = true;
            applicable.any_enforce |= scope.enforce;
        }
        applicable
    }

    /// A denial enforced when any applicable scope enforces, observed when
    /// one observes, else a pass.
    const fn deny(&self, reason: GateReason) -> GateDecision {
        if self.any {
            mode_decision(self.any_enforce, false, reason, None)
        } else {
            GateDecision::Pass
        }
    }
}

const fn held() -> GateDecision {
    GateDecision::Enforce {
        allow: false,
        reason: GateReason::Held,
        rule: None,
    }
}

const fn deny(scope: &CompiledScope, reason: GateReason) -> GateDecision {
    mode_decision(scope.enforce, false, reason, None)
}

const fn valid_state(scope: &CompiledScope) -> GateDecision {
    mode_decision(scope.enforce, true, GateReason::ValidState, None)
}

/// Outcome of one evaluation attempt against one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Step<T> {
    Done(T),
    /// A writer migrated the state since the snapshot was loaded.
    Retry,
    /// A global limit was hit; sweep every shard and evaluate again.
    SweepAll,
}

/// One packet of the family `A` being evaluated, with what persists across
/// attempts.
#[derive(Debug, Clone)]
pub(super) struct PacketInput<'a, A: GateAddr> {
    pub(super) direction: PacketDirection,
    pub(super) peer: PeerId,
    pub(super) packet: &'a [u8],
    /// `None` when the packet cannot be parsed.
    pub(super) meta: Option<PacketMeta<A>>,
    /// Read from the clock once the packet reaches the state.
    pub(super) now: OnceCell<Instant>,
    /// Every shard was swept for this packet; a global limit now fails closed.
    pub(super) swept: bool,
    /// The selection of a scoped evaluation.
    pub(super) scoping: Option<&'a Scoping<'a>>,
}

impl<A: GateAddr> PacketInput<'_, A> {
    /// Report the grant of `flow` to a scoped evaluation.
    fn found_flow(&self, flow: &FlowState) {
        if let Some(scoping) = self.scoping {
            scoping.found_flow(flow);
        }
    }
}

impl FlowGate {
    pub(super) fn record_decision(&self, decision: &GateDecision) {
        let bump = |counter: &std::sync::atomic::AtomicU64| {
            counter.fetch_add(1, Ordering::Relaxed);
        };
        match decision {
            GateDecision::Enforce { allow: true, .. } => bump(&self.counters.enforced_allowed),
            GateDecision::Enforce {
                allow: false,
                reason,
                ..
            } => {
                bump(&self.counters.enforced_denied);
                if *reason == GateReason::Unbound {
                    bump(&self.counters.unbound_denied);
                }
                if *reason == GateReason::StateCapacity {
                    bump(&self.counters.state_capacity_denied);
                }
            }
            GateDecision::Observe { allow: false, .. } => bump(&self.counters.observed_denied),
            GateDecision::Pass | GateDecision::Observe { .. } => {}
        }
    }

    /// Evaluate one packet at `now` without recording counters.
    #[cfg(test)]
    pub(super) fn evaluate_at(
        &self,
        direction: PacketDirection,
        peer: PeerId,
        packet: &[u8],
        now: Instant,
    ) -> GateDecision {
        self.evaluate_with(direction, peer, packet, OnceCell::from(now), None)
    }

    /// Evaluate one packet without recording counters, for `scoping`'s
    /// selection if given; `now` is read from the clock on first use unless
    /// already set. The version nibble picks the family once; a packet of
    /// another version passes.
    pub(super) fn evaluate_with(
        &self,
        direction: PacketDirection,
        peer: PeerId,
        packet: &[u8],
        now: OnceCell<Instant>,
        scoping: Option<&Scoping<'_>>,
    ) -> GateDecision {
        match packet.first().map(|byte| byte >> 4) {
            Some(4) => self.evaluate_family::<Ipv4Addr>(direction, peer, packet, now, scoping),
            Some(6) => self.evaluate_family::<Ipv6Addr>(direction, peer, packet, now, scoping),
            _ => GateDecision::Pass,
        }
    }

    /// [`evaluate_with`](Self::evaluate_with) of a packet of the family `A`.
    fn evaluate_family<A: GateAddr>(
        &self,
        direction: PacketDirection,
        peer: PeerId,
        packet: &[u8],
        now: OnceCell<Instant>,
        scoping: Option<&Scoping<'_>>,
    ) -> GateDecision {
        let mut input = PacketInput {
            direction,
            peer,
            packet,
            meta: A::parse(packet),
            now,
            swept: false,
            scoping,
        };
        loop {
            if let Some(scoping) = scoping {
                scoping.reset();
            }
            match self.snapshot.read(|snapshot| {
                let step = self.evaluate_once(snapshot, &input);
                if let (Some(scoping), Step::Done(_)) = (scoping, &step) {
                    scoping.taken_under(snapshot.generation);
                }
                step
            }) {
                Step::Done(decision) => return decision,
                Step::Retry => {}
                Step::SweepAll => {
                    self.state.sweep_all(self.now(&input));
                    input.swept = true;
                }
            }
        }
    }

    /// The evaluation time of `input`, read from the clock once.
    fn now<A: GateAddr>(&self, input: &PacketInput<'_, A>) -> Instant {
        *input.now.get_or_init(|| (self.clock)())
    }

    /// Lock `peer`'s shard if its state belongs to `snapshot`.
    pub(super) fn lock_shard(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
    ) -> Option<MutexGuard<'_, Shard>> {
        let shard = self.state.lock(peer);
        (shard.epoch == snapshot.generation).then_some(shard)
    }

    /// Evaluate `input` against `snapshot`.
    pub(super) fn evaluate_once<A: GateAddr>(
        &self,
        snapshot: &Snapshot,
        input: &PacketInput<'_, A>,
    ) -> Step<GateDecision> {
        if snapshot.inert {
            return Step::Done(if input.scoping.is_some() {
                enforced_denial(GateReason::OutOfScope)
            } else {
                GateDecision::Pass
            });
        }
        let (direction, peer) = (input.direction, input.peer);
        let Some(meta) = &input.meta else {
            let decision = malformed_decision::<A>(snapshot, direction, peer, input.packet);
            return Step::Done(if input.scoping.is_some() && decision != held() {
                enforced_denial(GateReason::Malformed)
            } else {
                decision
            });
        };
        let (remote, local) = meta.endpoints(direction);
        if snapshot.held(direction, peer, local, remote) {
            return Step::Done(held());
        }
        let (scope, peer_keyed) = match self.bound_scope(snapshot, input, meta, local, remote) {
            Ok(bound) => bound,
            Err(step) => return step,
        };
        let counts = &self.state.counts;

        if let Some(step) = self.fragment_or_icmp_error(snapshot, scope, input, meta) {
            return step;
        }

        let Some(flow_key) = flow_key(scope.slot, direction, peer, meta) else {
            return Step::Done(deny(scope, GateReason::Malformed));
        };
        let Some(mut shard) = self.lock_shard(snapshot, peer) else {
            return Step::Retry;
        };
        if let Some(step) = self.established(&mut shard, scope, &flow_key, input, meta) {
            return step;
        }
        if meta.is_reverse_only() {
            return Step::Done(deny(scope, GateReason::ReverseNewFlow));
        }
        let Some(transport) = meta.transport() else {
            return Step::Done(deny(scope, GateReason::OrphanFragment));
        };
        let destination = match direction {
            PacketDirection::Inbound => local,
            PacketDirection::Outbound => remote,
        };
        let binding = BindingKey { peer, ip: remote };
        let labels = if peer_keyed {
            &scope.peer_bindings[&peer]
        } else {
            &A::scope(scope).bindings[&binding]
        };
        let rule = match scope.authorize(direction, labels, destination, transport) {
            Authorization::Granted(rule) => rule,
            Authorization::Suspended(rule) => {
                return Step::Done(mode_decision(
                    scope.enforce,
                    false,
                    GateReason::Suspended,
                    Some(rule.clone()),
                ));
            }
            Authorization::NoGrant => return Step::Done(deny(scope, GateReason::NoGrant)),
        };
        let now = self.now(input);
        let admission = shard.insert_flow_with_fragment(
            flow_key,
            FlowState {
                initiator: direction,
                opened: transport,
                rule: rule.clone(),
                enforced: scope.enforce,
                close: TcpClose::default(),
                expires_at: now + protocol_timeout::<A>(meta.protocol, &counts.timeouts),
            },
            meta.more_fragments
                .then(|| meta.fragment_key(scope.slot, direction, peer)),
            now,
            counts,
            input.swept,
        );
        Step::Done(match admission {
            Admission::Admitted => {
                mode_decision(scope.enforce, true, GateReason::Granted, Some(rule.clone()))
            }
            Admission::Full => deny(scope, GateReason::StateCapacity),
            Admission::SweepAll => return Step::SweepAll,
        })
    }

    /// Step 4 for a packet that is neither malformed nor held: the one scope
    /// binding it and whether through a peer-keyed binding, or the decision
    /// for a packet binding no scope (or none of the selection) or more than
    /// one.
    #[inline]
    fn bound_scope<'s, A: GateAddr>(
        &self,
        snapshot: &'s Snapshot,
        input: &PacketInput<'_, A>,
        meta: &PacketMeta<A>,
        local: A,
        remote: A,
    ) -> Result<(&'s CompiledScope, bool), Step<GateDecision>> {
        let binding = BindingKey {
            peer: input.peer,
            ip: remote,
        };
        let mut matches = Applicable::of(
            snapshot
                .bound(&binding)
                .filter(|scope| scope.governs(local)),
        );
        // Most specific first: the peer-keyed bindings only when no scope
        // binds the exact pair.
        let peer_keyed = !matches.any && snapshot.has_peer_keyed();
        if peer_keyed {
            matches = Applicable::of(
                snapshot
                    .peer_keyed(input.peer)
                    .filter(|scope| scope.governs(local)),
            );
        }
        if !matches.any {
            if input.scoping.is_some() {
                return Err(Step::Done(enforced_denial(GateReason::OutOfScope)));
            }
            return Err(self.unbound_decision(snapshot, input, meta, local, remote));
        }
        let Some(scope) = matches.single else {
            return Err(Step::Done(if input.scoping.is_some() {
                enforced_denial(GateReason::Ambiguous)
            } else {
                matches.deny(GateReason::Ambiguous)
            }));
        };
        if let Some(scoping) = input.scoping
            && !scoping.select(&scope.id)
        {
            return Err(Step::Done(enforced_denial(GateReason::OutOfScope)));
        }
        Ok((scope, peer_keyed))
    }

    /// The verdict for a later fragment or an ICMP error of a bound packet,
    /// which only ever match existing state.
    fn fragment_or_icmp_error<A: GateAddr>(
        &self,
        snapshot: &Snapshot,
        scope: &CompiledScope,
        input: &PacketInput<'_, A>,
        meta: &PacketMeta<A>,
    ) -> Option<Step<GateDecision>> {
        let (direction, peer) = (input.direction, input.peer);
        let counts = &self.state.counts;
        if meta.fragment_offset != 0 {
            let fragment_key = meta.fragment_key(scope.slot, direction, peer);
            let Some(mut shard) = self.lock_shard(snapshot, peer) else {
                return Some(Step::Retry);
            };
            return Some(Step::Done(
                match shard
                    .family()
                    .fragment_disposition(&fragment_key, self.now(input), counts)
                {
                    Some(FragmentDisposition::Allow) => valid_state(scope),
                    // A pass disposition belongs to an unbound packet; a
                    // bound later fragment colliding with it fails closed.
                    Some(FragmentDisposition::Pass) | None => {
                        deny(scope, GateReason::OrphanFragment)
                    }
                },
            ));
        }

        if meta.is_icmp_error() {
            let Some(related_key) =
                related_flow_key::<A>(scope.slot, direction, peer, input.packet)
            else {
                return Some(Step::Done(deny(scope, GateReason::Malformed)));
            };
            let Some(mut shard) = self.lock_shard(snapshot, peer) else {
                return Some(Step::Retry);
            };
            let now = self.now(input);
            let quoted = shard
                .family()
                .with_live_flow(&related_key, now, counts, |flow| {
                    flow.touch::<A>(related_key.protocol, now, &counts.timeouts);
                    input.found_flow(flow);
                });
            return Some(Step::Done(if quoted == Lookup::Missing {
                deny(scope, GateReason::ReverseNewFlow)
            } else {
                valid_state(scope)
            }));
        }
        None
    }

    /// The verdict for a packet of an existing live flow, if there is one.
    fn established<A: GateAddr>(
        &self,
        shard: &mut Shard,
        scope: &CompiledScope,
        flow_key: &FlowKey<A>,
        input: &PacketInput<'_, A>,
        meta: &PacketMeta<A>,
    ) -> Option<Step<GateDecision>> {
        let counts = &self.state.counts;
        let now = self.now(input);
        let touched = shard
            .family()
            .with_live_flow(flow_key, now, counts, |existing| {
                // Flow keys are direction-independent so return traffic finds
                // the initiator's state. A bare SYN in the opposite direction is
                // nevertheless a new connection, not a return packet. Terminal
                // state also cannot be recycled into another connection until
                // its short FIN/RST tail expires.
                if meta.tcp_initial_syn()
                    && (existing.close.closing() || input.direction != existing.initiator)
                {
                    return false;
                }
                existing.touch::<A>(flow_key.protocol, now, &counts.timeouts);
                input.found_flow(existing);
                true
            });
        match touched {
            Lookup::Missing => return None,
            Lookup::Found(false) => {
                return Some(Step::Done(deny(scope, GateReason::ReverseNewFlow)));
            }
            Lookup::Found(true) => {}
        }
        if meta.more_fragments {
            let fragment_key = meta.fragment_key(scope.slot, input.direction, input.peer);
            match shard.remember_fragment(
                fragment_key,
                FragmentDisposition::Allow,
                now,
                counts,
                input.swept,
            ) {
                Admission::Admitted => {}
                Admission::Full => {
                    return Some(Step::Done(deny(scope, GateReason::StateCapacity)));
                }
                Admission::SweepAll => return Some(Step::SweepAll),
            }
        }
        if meta.tcp_terminal()
            && let Some(flow) = shard.family().flows.get_mut(flow_key)
        {
            // Keep the short terminal tail so FIN/ACK or RST acknowledgement
            // packets remain valid, then reclaim deterministically.
            flow.observe_tcp_close(input.direction, meta.tcp_flags, now, &counts.timeouts);
        }
        Some(Step::Done(valid_state(scope)))
    }

    fn unbound_decision<A: GateAddr>(
        &self,
        snapshot: &Snapshot,
        input: &PacketInput<'_, A>,
        meta: &PacketMeta<A>,
        local: A,
        remote: A,
    ) -> Step<GateDecision> {
        let applicable = match input.direction {
            PacketDirection::Inbound => Applicable::of(snapshot.with_local(local)),
            // Every route to a bound remote address or over a peer-keyed
            // peer is governed, even when the selected peer or the local
            // source is not the bound one.
            PacketDirection::Outbound => Applicable::of(
                snapshot
                    .with_remote(remote)
                    .chain(snapshot.peer_keyed(input.peer)),
            ),
        };
        if input.direction == PacketDirection::Inbound
            && let Some(scope) = applicable.single
            && scope.enforce
            && let Some(step) = self.unbound_rules(snapshot, scope, input, meta)
        {
            return step;
        }
        Step::Done(applicable.deny(GateReason::Unbound))
    }

    /// The unbound rules of `scope`, the one enforcing scope governing an
    /// unbound inbound packet's local address.
    fn unbound_rules<A: GateAddr>(
        &self,
        snapshot: &Snapshot,
        scope: &CompiledScope,
        input: &PacketInput<'_, A>,
        meta: &PacketMeta<A>,
    ) -> Option<Step<GateDecision>> {
        let peer = input.peer;
        let counts = &self.state.counts;
        let Some(transport) = meta.transport() else {
            // A later fragment of a peer an unbound rule names follows its
            // first fragment's pass disposition.
            if !scope.unbound.iter().any(|rule| rule.has_peer(peer)) {
                return None;
            }
            let fragment = meta.fragment_key(scope.slot, input.direction, peer);
            let Some(mut shard) = self.lock_shard(snapshot, peer) else {
                return Some(Step::Retry);
            };
            return Some(Step::Done(
                match shard
                    .family()
                    .fragment_disposition(&fragment, self.now(input), counts)
                {
                    Some(FragmentDisposition::Pass) => GateDecision::Pass,
                    Some(FragmentDisposition::Allow) | None => {
                        deny(scope, GateReason::OrphanFragment)
                    }
                },
            ));
        };
        if !scope.unbound.iter().any(|rule| {
            rule.action == UnboundAction::Pass && rule.matches(peer, meta.protocol, Some(transport))
        }) {
            return None;
        }
        if meta.more_fragments {
            let fragment = meta.fragment_key(scope.slot, input.direction, peer);
            let Some(mut shard) = self.lock_shard(snapshot, peer) else {
                return Some(Step::Retry);
            };
            match shard.remember_fragment(
                fragment,
                FragmentDisposition::Pass,
                self.now(input),
                counts,
                input.swept,
            ) {
                Admission::Admitted => {}
                Admission::Full => {
                    return Some(Step::Done(deny(scope, GateReason::StateCapacity)));
                }
                Admission::SweepAll => return Some(Step::SweepAll),
            }
        }
        Some(Step::Done(GateDecision::Pass))
    }
}

fn malformed_decision<A: GateAddr>(
    snapshot: &Snapshot,
    direction: PacketDirection,
    peer: PeerId,
    packet: &[u8],
) -> GateDecision {
    let Some((source, destination)) = A::endpoints(packet) else {
        return GateDecision::Pass;
    };
    let (remote, local) = match direction {
        PacketDirection::Inbound => (source, destination),
        PacketDirection::Outbound => (destination, source),
    };
    if snapshot.held(direction, peer, local, remote) {
        return held();
    }
    let applicable = match direction {
        PacketDirection::Inbound => Applicable::of(snapshot.with_local(local)),
        PacketDirection::Outbound => Applicable::of(
            snapshot
                .with_remote(remote)
                .chain(snapshot.peer_keyed(peer)),
        ),
    };
    applicable.deny(GateReason::Malformed)
}
