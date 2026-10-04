//! Packet evaluation, decision recording and Provider flow queries.

use std::cell::OnceCell;
use std::net::SocketAddr;
use std::sync::MutexGuard;
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::config::{NodeL3Mode, NodeL3ServiceProtocol};
use super::packet::{PacketMeta, flow_key, packet_ipv4_endpoints, related_flow_key};
use super::policy::{CompiledPolicy, NodeIdentity};
use super::snapshot::Snapshot;
use super::state::{
    Admission, FlowKey, FlowState, FragmentDisposition, LiveFlow, ServiceFlowAuthorization, Shard,
    TcpClose, protocol_timeout,
};
use super::{NodeL3Decision, NodeL3Gate, NodeL3Reason, PacketDirection, mode_decision};

/// The policies a packet's addresses fall under.
#[derive(Debug, Clone, Copy)]
struct Applicable<'a> {
    /// The policy when exactly one applies.
    single: Option<&'a CompiledPolicy>,
    any: bool,
    any_enforce: bool,
}

impl<'a> Applicable<'a> {
    fn of(policies: impl Iterator<Item = &'a CompiledPolicy>) -> Self {
        let mut applicable = Self {
            single: None,
            any: false,
            any_enforce: false,
        };
        for policy in policies {
            applicable.single = (!applicable.any).then_some(policy);
            applicable.any = true;
            applicable.any_enforce |= policy.mode == NodeL3Mode::Enforce;
        }
        applicable
    }

    /// Enforce when any applicable policy enforces, Observe when one
    /// observes, else Legacy.
    const fn decision(&self, allow: bool, reason: NodeL3Reason) -> NodeL3Decision {
        if self.any_enforce {
            NodeL3Decision::Enforce { allow, reason }
        } else if self.any {
            NodeL3Decision::Observe {
                would_allow: allow,
                reason,
            }
        } else {
            NodeL3Decision::Legacy
        }
    }
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

impl NodeL3Gate {
    pub(super) fn record_decision(&self, decision: &NodeL3Decision) {
        match decision {
            NodeL3Decision::Enforce { allow: true, .. } => {
                self.counters
                    .enforced_allowed
                    .fetch_add(1, Ordering::Relaxed);
            }
            NodeL3Decision::Enforce {
                allow: false,
                reason,
            } => {
                self.counters
                    .enforced_denied
                    .fetch_add(1, Ordering::Relaxed);
                if *reason == NodeL3Reason::SourceBinding {
                    self.counters
                        .source_binding_denied
                        .fetch_add(1, Ordering::Relaxed);
                }
                if *reason == NodeL3Reason::StateCapacity {
                    self.counters
                        .state_capacity_denied
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            NodeL3Decision::Observe {
                would_allow: false, ..
            } => {
                self.counters
                    .observed_denied
                    .fetch_add(1, Ordering::Relaxed);
            }
            NodeL3Decision::Legacy | NodeL3Decision::Observe { .. } => {}
        }
    }

    /// Return whether the provider's exact accepted socket flow was
    /// pre-authorized by the current Node L3 generation for this Service.
    #[must_use]
    pub fn service_flow_authorized(
        &self,
        remote: SocketAddr,
        local: SocketAddr,
        target_machine_id: &str,
        protocol: NodeL3ServiceProtocol,
        service_id: &str,
    ) -> bool {
        let (SocketAddr::V4(remote), SocketAddr::V4(local)) = (remote, local) else {
            return false;
        };
        let now = (self.clock)();
        let protocol = protocol.ip_protocol();
        // With every shard held no writer can publish, so the snapshot and
        // the state are consistent.
        let mut shards = self.state.lock_all();
        let snapshot = self.snapshot.load();
        let counts = &self.state.counts;
        for shard in &mut shards {
            let mut authorized = false;
            shard.retain_flows(counts, |key, flow| {
                if authorized
                    || key.remote_ip != *remote.ip()
                    || key.local_ip != *local.ip()
                    || key.remote_port != remote.port()
                    || key.local_port != local.port()
                    || key.protocol != protocol
                {
                    return true;
                }
                let policy_matches_listener =
                    snapshot.policies.get(&key.net).is_some_and(|policy| {
                        policy.generation == key.generation
                            && policy.target_machine_id == target_machine_id
                            && policy.local.ip == *local.ip()
                            && policy
                                .service_for(policy.local.idx, protocol, local.port())
                                .is_some_and(|service| **service == *service_id)
                    });
                if !policy_matches_listener {
                    return true;
                }
                if flow.expires_at <= now {
                    return false;
                }
                flow.touch(key.protocol, now);
                authorized = flow.enforced
                    && match &flow.service_authorization {
                        ServiceFlowAuthorization::NodeWide => true,
                        ServiceFlowAuthorization::Exact(id) => **id == *service_id,
                        ServiceFlowAuthorization::None => false,
                    };
                true
            });
            if authorized {
                return true;
            }
        }
        false
    }

    /// Evaluate one packet at `now` without recording counters.
    #[cfg(test)]
    pub(super) fn evaluate_at(
        &self,
        direction: PacketDirection,
        peer_key: [u8; 32],
        packet: &[u8],
        now: Instant,
    ) -> NodeL3Decision {
        self.evaluate_with(direction, peer_key, packet, OnceCell::from(now))
    }

    /// Evaluate one packet without recording counters; `now` is read from
    /// the clock on first use unless already set.
    pub(super) fn evaluate_with(
        &self,
        direction: PacketDirection,
        peer_key: [u8; 32],
        packet: &[u8],
        now: OnceCell<Instant>,
    ) -> NodeL3Decision {
        let mut input = PacketInput {
            direction,
            peer_key,
            packet,
            meta: PacketMeta::parse(packet),
            now,
            swept: false,
        };
        loop {
            let snapshot = self.snapshot.load();
            match self.evaluate_once(&snapshot, &input) {
                Step::Done(decision) => return decision,
                Step::Retry => {}
                Step::SweepAll => {
                    drop(snapshot);
                    self.state.sweep_all(self.now(&input));
                    input.swept = true;
                }
            }
        }
    }

    /// The evaluation time of `input`, read from the clock once.
    fn now(&self, input: &PacketInput<'_>) -> Instant {
        *input.now.get_or_init(|| (self.clock)())
    }

    /// Lock `peer_key`'s shard if its state belongs to `snapshot`.
    pub(super) fn lock_shard(
        &self,
        snapshot: &Snapshot,
        peer_key: &[u8; 32],
    ) -> Option<MutexGuard<'_, Shard>> {
        let shard = self.state.lock(peer_key);
        (shard.epoch == snapshot.epoch).then_some(shard)
    }

    /// Evaluate `input` against `snapshot`.
    pub(super) fn evaluate_once(
        &self,
        snapshot: &Snapshot,
        input: &PacketInput<'_>,
    ) -> Step<NodeL3Decision> {
        let (direction, peer_key) = (input.direction, input.peer_key);
        let Some(meta) = &input.meta else {
            return Step::Done(malformed_decision(
                snapshot,
                direction,
                peer_key,
                input.packet,
            ));
        };
        if snapshot.policy_pending(direction, peer_key, meta.source, meta.destination) {
            return Step::Done(NodeL3Decision::Enforce {
                allow: false,
                reason: NodeL3Reason::PolicyPending,
            });
        }
        let (binding, local_ip) = meta.remote_binding(direction, peer_key);
        let matches = Applicable::of(
            snapshot
                .bound(&binding)
                .filter(|policy| policy.local.ip == local_ip),
        );
        if !matches.any {
            return self.unbound_decision(snapshot, input, meta);
        }
        let Some(policy) = matches.single else {
            return Step::Done(matches.decision(false, NodeL3Reason::AmbiguousNetwork));
        };
        let counts = &self.state.counts;

        if let Some(step) = self.fragment_or_icmp_error(snapshot, policy, input, meta) {
            return step;
        }

        let Some(flow_key) = flow_key(policy, direction, peer_key, meta) else {
            return Step::Done(mode_decision(
                policy.mode,
                false,
                NodeL3Reason::MalformedPacket,
            ));
        };
        let Some(mut shard) = self.lock_shard(snapshot, &peer_key) else {
            return Step::Retry;
        };
        if let Some(step) = self.established(&mut shard, policy, &flow_key, input, meta) {
            return step;
        }
        if meta.is_reverse_only() {
            return Step::Done(mode_decision(
                policy.mode,
                false,
                NodeL3Reason::ReverseNewFlow,
            ));
        }
        let remote = &policy.bindings[&binding];
        let (source, target) = match direction {
            PacketDirection::Inbound => (remote, &policy.local),
            PacketDirection::Outbound => (&policy.local, remote),
        };
        let (allowed, reason, service_authorization) =
            authorize_new_flow(snapshot, policy, source, target, direction, meta);
        if allowed {
            let now = self.now(input);
            let admission = shard.insert_flow_with_fragment(
                flow_key,
                FlowState {
                    initiator: direction,
                    service_authorization,
                    enforced: policy.mode == NodeL3Mode::Enforce,
                    close: TcpClose::default(),
                    expires_at: now + protocol_timeout(meta.protocol),
                },
                meta.more_fragments
                    .then(|| meta.fragment_key(policy, direction, peer_key)),
                now,
                counts,
                input.swept,
            );
            match admission {
                Admission::Admitted => {}
                Admission::Full => {
                    return Step::Done(mode_decision(
                        policy.mode,
                        false,
                        NodeL3Reason::StateCapacity,
                    ));
                }
                Admission::SweepAll => return Step::SweepAll,
            }
        }
        Step::Done(mode_decision(policy.mode, allowed, reason))
    }

    /// The verdict for a later fragment or an ICMP error of a bound packet,
    /// which only ever match existing state.
    fn fragment_or_icmp_error(
        &self,
        snapshot: &Snapshot,
        policy: &CompiledPolicy,
        input: &PacketInput<'_>,
        meta: &PacketMeta,
    ) -> Option<Step<NodeL3Decision>> {
        let (direction, peer_key) = (input.direction, input.peer_key);
        let counts = &self.state.counts;
        if meta.fragment_offset != 0 {
            let fragment_key = meta.fragment_key(policy, direction, peer_key);
            let Some(mut shard) = self.lock_shard(snapshot, &peer_key) else {
                return Some(Step::Retry);
            };
            return Some(Step::Done(
                match shard.fragment_disposition(&fragment_key, self.now(input), counts) {
                    Some(FragmentDisposition::EnforceAllow) => {
                        mode_decision(policy.mode, true, NodeL3Reason::ValidState)
                    }
                    // A legacy-L4 fragment cannot enter this bound-Node branch in a
                    // valid generation. Treat any such collision as fail closed.
                    Some(FragmentDisposition::LegacyL4) | None => {
                        mode_decision(policy.mode, false, NodeL3Reason::OrphanFragment)
                    }
                },
            ));
        }

        if meta.is_icmp_error() {
            let Some(related_key) = related_flow_key(policy, direction, peer_key, input.packet)
            else {
                return Some(Step::Done(mode_decision(
                    policy.mode,
                    false,
                    NodeL3Reason::MalformedPacket,
                )));
            };
            let Some(mut shard) = self.lock_shard(snapshot, &peer_key) else {
                return Some(Step::Retry);
            };
            let allowed = shard.touch_flow(&related_key, self.now(input), counts);
            return Some(Step::Done(mode_decision(
                policy.mode,
                allowed,
                if allowed {
                    NodeL3Reason::ValidState
                } else {
                    NodeL3Reason::ReverseNewFlow
                },
            )));
        }
        None
    }

    /// The verdict for a packet of an existing live flow, if there is one.
    fn established(
        &self,
        shard: &mut Shard,
        policy: &CompiledPolicy,
        flow_key: &FlowKey,
        input: &PacketInput<'_>,
        meta: &PacketMeta,
    ) -> Option<Step<NodeL3Decision>> {
        let counts = &self.state.counts;
        let now = self.now(input);
        let touched = shard.with_live_flow(flow_key, now, counts, |existing| {
            // Flow keys are intentionally direction-independent so return
            // traffic finds the initiator's state. A bare SYN in the opposite
            // direction is nevertheless a new connection, not a return
            // packet. Terminal state also cannot be recycled into another
            // connection until its short FIN/RST tail expires.
            if meta.tcp_initial_syn()
                && (existing.close.closing() || input.direction != existing.initiator)
            {
                return false;
            }
            existing.touch(flow_key.protocol, now);
            true
        });
        match touched {
            LiveFlow::Missing => return None,
            LiveFlow::Found(false) => {
                return Some(Step::Done(mode_decision(
                    policy.mode,
                    false,
                    NodeL3Reason::ReverseNewFlow,
                )));
            }
            LiveFlow::Found(true) => {}
        }
        if meta.more_fragments {
            let fragment_key = meta.fragment_key(policy, input.direction, input.peer_key);
            match shard.remember_fragment(
                fragment_key,
                FragmentDisposition::EnforceAllow,
                now,
                counts,
                input.swept,
            ) {
                Admission::Admitted => {}
                Admission::Full => {
                    return Some(Step::Done(mode_decision(
                        policy.mode,
                        false,
                        NodeL3Reason::StateCapacity,
                    )));
                }
                Admission::SweepAll => return Some(Step::SweepAll),
            }
        }
        if meta.tcp_terminal()
            && let Some(flow) = shard.flows.get_mut(flow_key)
        {
            // Keep the short terminal tail so FIN/ACK or RST acknowledgement
            // packets remain valid, then reclaim deterministically.
            flow.observe_tcp_close(input.direction, meta.tcp_flags, now);
        }
        Some(Step::Done(mode_decision(
            policy.mode,
            true,
            NodeL3Reason::ValidState,
        )))
    }

    fn unbound_decision(
        &self,
        snapshot: &Snapshot,
        input: &PacketInput<'_>,
        meta: &PacketMeta,
    ) -> Step<NodeL3Decision> {
        let (direction, peer_key) = (input.direction, input.peer_key);
        let applicable = match direction {
            PacketDirection::Inbound => Applicable::of(snapshot.with_local_ip(meta.destination)),
            // Every route to a known Node IP is authoritative even when
            // the selected peer or inner source is spoofed. Service and
            // Gateway `/32`s sharing that peer remain on the legacy L4
            // path because they are not Node resources in this snapshot.
            PacketDirection::Outbound => Applicable::of(snapshot.with_remote_ip(meta.destination)),
        };
        let counts = &self.state.counts;
        if let Some(policy) = applicable.single
            && direction == PacketDirection::Inbound
            && policy.mode == NodeL3Mode::Enforce
            && snapshot.gateway_carrier_installed(peer_key, policy)
        {
            if meta.fragment_offset != 0 {
                let fragment = meta.fragment_key(policy, direction, peer_key);
                let Some(mut shard) = self.lock_shard(snapshot, &peer_key) else {
                    return Step::Retry;
                };
                return Step::Done(
                    match shard.fragment_disposition(&fragment, self.now(input), counts) {
                        Some(FragmentDisposition::LegacyL4) => NodeL3Decision::Legacy,
                        Some(FragmentDisposition::EnforceAllow) | None => NodeL3Decision::Enforce {
                            allow: false,
                            reason: NodeL3Reason::OrphanFragment,
                        },
                    },
                );
            }
            // Terminate/Public gateways authenticate the carrier hop, not the
            // original Node identity, so their inner source cannot satisfy a
            // Node binding. Hand only an exact, currently owned Provider
            // listener back to the legacy L4 PEP. Every raw Node port and
            // every inferred/unknown peer remains under the Enforce verdict.
            if meta.dst_port.is_some_and(|port| {
                snapshot
                    .listeners
                    .target_listens(&policy.target_machine_id, meta.protocol, port)
            }) {
                if meta.more_fragments {
                    let fragment = meta.fragment_key(policy, direction, peer_key);
                    let Some(mut shard) = self.lock_shard(snapshot, &peer_key) else {
                        return Step::Retry;
                    };
                    match shard.remember_fragment(
                        fragment,
                        FragmentDisposition::LegacyL4,
                        self.now(input),
                        counts,
                        input.swept,
                    ) {
                        Admission::Admitted => {}
                        Admission::Full => {
                            return Step::Done(NodeL3Decision::Enforce {
                                allow: false,
                                reason: NodeL3Reason::StateCapacity,
                            });
                        }
                        Admission::SweepAll => return Step::SweepAll,
                    }
                }
                return Step::Done(NodeL3Decision::Legacy);
            }
        }
        Step::Done(applicable.decision(false, NodeL3Reason::SourceBinding))
    }
}

/// One packet being evaluated, with what persists across attempts.
#[derive(Debug, Clone)]
pub(super) struct PacketInput<'a> {
    pub(super) direction: PacketDirection,
    pub(super) peer_key: [u8; 32],
    pub(super) packet: &'a [u8],
    /// `None` when the packet cannot be parsed.
    pub(super) meta: Option<PacketMeta>,
    /// Read from the clock once the packet reaches the state.
    pub(super) now: OnceCell<Instant>,
    /// Every shard was swept for this packet; a global limit now fails closed.
    pub(super) swept: bool,
}

/// Whether a new flow from `source` to `target` is authorized, why, and what
/// it authorizes for Provider sockets.
fn authorize_new_flow(
    snapshot: &Snapshot,
    policy: &CompiledPolicy,
    source: &NodeIdentity,
    target: &NodeIdentity,
    direction: PacketDirection,
    meta: &PacketMeta,
) -> (bool, NodeL3Reason, ServiceFlowAuthorization) {
    if source.owner_id == target.owner_id {
        return (
            true,
            NodeL3Reason::SameOwner,
            ServiceFlowAuthorization::NodeWide,
        );
    }
    if policy.has_node_grant(source.idx, target.idx) {
        return (
            true,
            NodeL3Reason::NodeGrant,
            ServiceFlowAuthorization::NodeWide,
        );
    }
    let Some(port) = meta.dst_port else {
        return (false, NodeL3Reason::NoGrant, ServiceFlowAuthorization::None);
    };
    match policy.service_for(target.idx, meta.protocol, port) {
        Some(service) if policy.has_service_grant(source.idx, target.idx, meta.protocol, port) => {
            if direction == PacketDirection::Outbound
                || snapshot.listeners.contains(
                    &policy.target_machine_id,
                    service,
                    meta.protocol,
                    port,
                )
            {
                (
                    true,
                    NodeL3Reason::ServiceGrant,
                    ServiceFlowAuthorization::Exact(service.clone()),
                )
            } else {
                (
                    false,
                    NodeL3Reason::ServiceProjection,
                    ServiceFlowAuthorization::None,
                )
            }
        }
        _ => (false, NodeL3Reason::NoGrant, ServiceFlowAuthorization::None),
    }
}

fn malformed_decision(
    snapshot: &Snapshot,
    direction: PacketDirection,
    peer_key: [u8; 32],
    packet: &[u8],
) -> NodeL3Decision {
    let endpoint = packet_ipv4_endpoints(packet);
    if let Some((source, destination)) = endpoint
        && snapshot.policy_pending(direction, peer_key, source, destination)
    {
        return NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        };
    }
    let applicable = match (direction, endpoint) {
        (PacketDirection::Inbound, Some((_, destination))) => {
            Applicable::of(snapshot.with_local_ip(destination))
        }
        (PacketDirection::Outbound, Some((_, destination))) => {
            Applicable::of(snapshot.with_remote_ip(destination))
        }
        _ => Applicable::of(std::iter::empty()),
    };
    applicable.decision(false, NodeL3Reason::MalformedPacket)
}
