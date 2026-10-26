//! Inbound packets: bypasses, fragments and evaluation.

use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use nsplane_packet::{FiveTuple, IpPacket, PeerId};

use super::config::{FragmentMode, Ipv6Mode};
use super::outcome::Outcome;
use super::packet::{
    EchoType, echo_type, ipv4_fragment, is_icmp, is_icmp_echo_reply, is_to_local, other_transport,
    tcp_udp_flow,
};
use super::replies::is_pending;
use super::table::{
    AllowedKey, CachedVerdict, EntryKey, FlowVerdict, FragmentKey, Governed, Hit, PeerInfo,
};
use super::{Inner, reversed};
use crate::engine::{Evaluation, FlowOrigin, Membership, ReplyDependency, Snapshot};
use crate::net::Protocol;
use crate::reasons;
use crate::rules::{Flow, PolicyState};

#[cfg(doc)]
use crate::engine::AclEngine;

impl Inner {
    /// Sweep the expired pinholes when a lookup saw one.
    pub(super) fn sweep_if(&self, sweep: bool) {
        if sweep {
            self.engine.expire_pinholes();
        }
    }

    /// Whether [`Ipv6Mode::Accept`] passes `bytes` unevaluated.
    pub(super) fn accepts_ipv6(&self, bytes: &[u8]) -> bool {
        self.config.ipv6 == Ipv6Mode::Accept && bytes.first().is_some_and(|b| b >> 4 == 6)
    }

    pub(super) fn inbound(&self, peer: PeerId, bytes: &[u8]) -> Outcome {
        if self.accepts_ipv6(bytes) {
            return Outcome::Ipv6Accepted;
        }
        if let Some(local) = self.config.accept_to_local
            && is_to_local(bytes, local)
        {
            return Outcome::Bypassed;
        }
        if self.config.accept_icmp_echo_reply && is_icmp_echo_reply(bytes) {
            return Outcome::Bypassed;
        }
        // `Some` for an IPv4 packet in the allow-only mode.
        let allow_only = match self.config.fragments {
            FragmentMode::AllowOnly { ttl, capacity } => {
                ipv4_fragment(bytes).map(|fragment| (fragment, ttl, capacity))
            }
            FragmentMode::Outcome => None,
        };
        if let Some(((key, true, _), ttl, _)) = allow_only {
            return self.follow_allowed(key, ttl);
        }
        // `move`: borrowing `allow_only` would spill it to the stack before
        // the branch above, and the later fragment then reloads its key with a
        // load that store forwarding cannot serve.
        self.engine.read_snapshot(move |snapshot| {
            if !snapshot.is_loaded() {
                return match snapshot.policy_state() {
                    PolicyState::Failed => Outcome::PolicyFailed,
                    PolicyState::NotInstalled | PolicyState::Installed { .. } => Outcome::NoPolicy,
                };
            }
            let Ok(packet) = IpPacket::parse(bytes) else {
                return Outcome::Malformed;
            };
            let Some(((key, _, first_of_many), ttl, capacity)) = allow_only else {
                return self.with_fragments(peer, false, &packet, Outcome::Fragment, |packet| {
                    self.evaluate(snapshot, peer, packet)
                });
            };
            let outcome = self.evaluate(snapshot, peer, &packet);
            if first_of_many && matches!(outcome, Outcome::Accepted | Outcome::Reply) {
                self.remember_allowed(key, ttl, capacity);
            }
            outcome
        })
    }

    /// [`FragmentMode::AllowOnly`]: whether the first fragment of `key` was
    /// accepted less than `ttl` ago; an expired entry is removed.
    fn follow_allowed(&self, key: AllowedKey, ttl: Duration) -> Outcome {
        let now = self.engine.now();
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match table.allowed.get(&key) {
            Some(&recorded) if now.duration_since(recorded) < ttl => Outcome::Accepted,
            Some(_) => {
                table.allowed.remove(&key);
                Outcome::Fragment
            }
            None => Outcome::Fragment,
        }
    }

    /// [`FragmentMode::AllowOnly`]: record the accepted first fragment of
    /// `key`, removing the expired entries first when the table is full and
    /// recording nothing when it is still full.
    fn remember_allowed(&self, key: AllowedKey, ttl: Duration, capacity: usize) {
        let now = self.engine.now();
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if table.allowed.len() >= capacity {
            table
                .allowed
                .retain(|_, &mut recorded| now.duration_since(recorded) < ttl);
            if table.allowed.len() >= capacity {
                return;
            }
        }
        table.allowed.insert(key, now);
    }

    /// Run `evaluate` on an unfragmented packet or a first fragment, recording
    /// a first fragment's outcome; later fragments follow it, or get `orphan`
    /// when none is recorded.
    pub(super) fn with_fragments(
        &self,
        peer: PeerId,
        outbound: bool,
        packet: &IpPacket<'_>,
        orphan: Outcome,
        evaluate: impl FnOnce(&IpPacket<'_>) -> Outcome,
    ) -> Outcome {
        let fragment = packet.fragment();
        let key = fragment.map(|f| FragmentKey {
            peer,
            outbound,
            src: packet.src(),
            dst: packet.dst(),
            protocol: packet.protocol(),
            id: f.id,
        });
        match (fragment, key) {
            (Some(f), Some(key)) if !f.is_first() => {
                self.follow_fragment(key, f.is_last()).unwrap_or(orphan)
            }
            (_, key) => {
                let outcome = evaluate(packet);
                if let Some(key) = key {
                    self.record_fragment(key, outcome);
                }
                outcome
            }
        }
    }

    fn evaluate(&self, snapshot: &Snapshot, peer: PeerId, packet: &IpPacket<'_>) -> Outcome {
        let Some(tuple) = packet.five_tuple() else {
            return Outcome::Malformed;
        };
        let Some(protocol) = Protocol::from_ip_number(tuple.protocol) else {
            return self.evaluate_other(snapshot, peer, packet, tuple);
        };
        let identity = self.identity_generation();
        let key = EntryKey {
            peer,
            outbound: false,
            tuple,
        };
        let mut sweep = false;
        let mut table = self.table();
        let info = match self.lookup(&mut table, snapshot, key, identity, &mut sweep) {
            Some(Hit::Allowance(dependency)) => {
                if let Some(dependency) = dependency.filter(is_pending) {
                    self.record_pending(&mut table, tuple, dependency);
                }
                drop(table);
                self.sweep_if(sweep);
                return Outcome::Reply;
            }
            Some(Hit::Verdict(verdict)) => {
                self.replay(&mut table, peer, tuple, &verdict);
                return verdict.outcome;
            }
            None if identity == 0 => None,
            None => {
                let Some(info) =
                    self.cached_peer(&mut table, snapshot, peer, Some(tuple.src), identity)
                else {
                    drop(table);
                    self.sweep_if(sweep);
                    return Outcome::Internal;
                };
                if info.bypass {
                    // As an evaluation would: a flow forwarded to another
                    // member records its pending dependency.
                    if self.config.stateful_replies
                        && info.membership.is_some()
                        && snapshot.is_member(tuple.dst)
                    {
                        let flow = tcp_udp_flow(&tuple, protocol);
                        let dependency = Self::flow_origin(snapshot, peer, info, flow, true);
                        self.record_pending(&mut table, tuple, dependency);
                    }
                    drop(table);
                    self.sweep_if(sweep);
                    return Outcome::Accepted;
                }
                if info.governed == Governed::Default {
                    // The default rules: a few rules and no side effects,
                    // cheaper to evaluate under this lock than to cache.
                    let flow = tcp_udp_flow(&tuple, protocol);
                    let (verdict, _) = self.evaluate_new(snapshot, peer, info, flow);
                    drop(table);
                    self.sweep_if(sweep);
                    return verdict.outcome;
                }
                Some(Arc::clone(info))
            }
        };
        drop(table);
        self.sweep_if(sweep);
        let info = info.unwrap_or_else(|| {
            Arc::new(PeerInfo::resolve(
                &*self.identity,
                snapshot,
                peer,
                tuple.src,
                0,
            ))
        });
        let flow = tcp_udp_flow(&tuple, protocol);
        let (verdict, cacheable) = self.evaluate_new(snapshot, peer, &info, flow);
        let cache = cacheable && identity != 0;
        if cache || verdict.pending().is_some() || verdict.restricted {
            let mut table = self.table();
            self.replay(&mut table, peer, tuple, &verdict);
            if cache {
                let cached = CachedVerdict {
                    generation: snapshot.generation(),
                    identity,
                    verdict: verdict.clone(),
                };
                self.cache_verdict(&mut table, key, cached);
            }
        }
        verdict.outcome
    }

    /// Evaluate an inbound packet that is neither TCP nor UDP.
    fn evaluate_other(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        packet: &IpPacket<'_>,
        tuple: FiveTuple,
    ) -> Outcome {
        if self.config.stateful_replies
            && (!is_icmp(tuple.protocol) || echo_type(packet) == Some(EchoType::Reply))
        {
            let key = EntryKey {
                peer,
                outbound: false,
                tuple,
            };
            let mut sweep = false;
            let mut table = self.table();
            let reply = match self.lookup(&mut table, snapshot, key, 0, &mut sweep) {
                Some(Hit::Allowance(dependency)) => {
                    if let Some(dependency) = dependency.filter(is_pending) {
                        self.record_pending(&mut table, tuple, dependency);
                    }
                    true
                }
                Some(Hit::Verdict(_)) | None => false,
            };
            drop(table);
            self.sweep_if(sweep);
            if reply {
                return Outcome::Reply;
            }
        }
        if self.config.allow_other_protocols {
            return Outcome::Accepted;
        }
        // An ICMP message other than an echo request records no reply
        // allowance.
        let allows_reply = self.config.stateful_replies
            && (!is_icmp(tuple.protocol) || echo_type(packet) == Some(EchoType::Request));
        let scoped = if self.unscoped.load(Ordering::Acquire) {
            Some(false)
        } else {
            self.scopes.read(|set| {
                self.inbound_scope(set, snapshot, peer, tuple.src)
                    .map(|scope| scope.accepts_other(packet))
            })
        };
        let Some(scoped) = scoped else {
            return Outcome::Internal;
        };
        if scoped {
            if allows_reply {
                self.allow_restricted_reply(snapshot, peer, tuple);
            }
            return Outcome::Accepted;
        }
        self.evaluate_other_rules(snapshot, peer, packet, tuple, allows_reply)
    }

    /// The rule step of an inbound packet that is neither TCP nor UDP: the
    /// evaluation of a new flow, without a verdict cache; every denial is
    /// [`Outcome::Protocol`].
    fn evaluate_other_rules(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        packet: &IpPacket<'_>,
        tuple: FiveTuple,
        allows_reply: bool,
    ) -> Outcome {
        let Some(transport) = other_transport(packet, tuple.protocol) else {
            return Outcome::Protocol;
        };
        let flow = Flow {
            src: tuple.src,
            dst: tuple.dst,
            transport,
        };
        let identity = self.identity_generation();
        let mut table = self.table();
        let info = if identity == 0 {
            Arc::new(PeerInfo::resolve(
                &*self.identity,
                snapshot,
                peer,
                tuple.src,
                0,
            ))
        } else {
            let Some(info) =
                self.cached_peer(&mut table, snapshot, peer, Some(tuple.src), identity)
            else {
                return Outcome::Internal;
            };
            Arc::clone(info)
        };
        drop(table);
        let (verdict, _) = self.evaluate_new(snapshot, peer, &info, flow);
        if verdict.outcome != Outcome::Accepted {
            return Outcome::Protocol;
        }
        if verdict.pending().is_some() || (verdict.restricted && allows_reply) {
            let mut table = self.table();
            if let Some(dependency) = verdict.pending() {
                self.record_pending(&mut table, tuple, dependency.clone());
            }
            if verdict.restricted && allows_reply {
                self.record_reply(
                    &mut table,
                    None,
                    peer,
                    true,
                    reversed(tuple),
                    verdict.dependency,
                );
            }
        }
        Outcome::Accepted
    }

    /// Record the outbound reply allowance of an inbound packet accepted by a
    /// scope rule when `peer` is outbound-restricted.
    fn allow_restricted_reply(&self, snapshot: &Snapshot, peer: PeerId, tuple: FiveTuple) {
        let identity = self.identity_generation();
        if identity == 0 {
            let info = PeerInfo::resolve(&*self.identity, snapshot, peer, tuple.src, 0);
            if info.governed == Governed::Restricted {
                self.record_reply(&mut self.table(), None, peer, true, reversed(tuple), None);
            }
            return;
        }
        let mut table = self.table();
        let info = self.cached_peer(&mut table, snapshot, peer, Some(tuple.src), identity);
        // Without the peer no allowance is recorded: its replies stay denied.
        if info.is_some_and(|info| info.governed == Governed::Restricted) {
            self.record_reply(&mut table, None, peer, true, reversed(tuple), None);
        }
    }

    /// The dependency of `flow` from `peer`, accepted by the rules under the
    /// snapshot and `info`'s identity generation; `forwarded`: to another
    /// namespace member.
    const fn flow_origin(
        snapshot: &Snapshot,
        peer: PeerId,
        info: &PeerInfo,
        flow: Flow,
        forwarded: bool,
    ) -> ReplyDependency {
        ReplyDependency::Flow(FlowOrigin {
            peer,
            flow,
            generation: snapshot.generation(),
            identity: info.identity,
            forwarded,
        })
    }

    /// Evaluate a new inbound `flow` from the resolved peer `info`, as
    /// [`AclEngine::evaluate`] does. Returns the verdict and whether it may
    /// be cached.
    pub(super) fn evaluate_new(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        info: &PeerInfo,
        flow: Flow,
    ) -> (FlowVerdict, bool) {
        let Some(labels) = &info.labels else {
            return (FlowVerdict::new(Outcome::UnknownPeer), true);
        };
        let membership = info.membership.as_deref();
        let evaluation = snapshot.evaluate(labels, membership, &flow, || self.engine.now());
        let outcome = match evaluation {
            Evaluation::Rule { .. }
            | Evaluation::Grant(_)
            | Evaluation::Pinhole(_)
            | Evaluation::NotInstalled => Outcome::Accepted,
            Evaluation::PinholeExpired => {
                self.engine.expire_pinholes();
                return (FlowVerdict::new(Outcome::Denied), false);
            }
            Evaluation::Deny(reason) => {
                let outcome = match reason {
                    reasons::CROSS_NAMESPACE => Outcome::CrossNamespace,
                    reasons::NO_POLICY => Outcome::NoPolicy,
                    reasons::POLICY_FAILED => Outcome::PolicyFailed,
                    _ => Outcome::Denied,
                };
                return (FlowVerdict::new(outcome), true);
            }
        };
        let dependency = match evaluation {
            Evaluation::Rule { to_member, .. } if self.config.stateful_replies => {
                Some(Self::flow_origin(snapshot, peer, info, flow, to_member))
            }
            Evaluation::NotInstalled if self.config.stateful_replies => {
                Some(Self::flow_origin(snapshot, peer, info, flow, false))
            }
            evaluation => evaluation.dependency(),
        };
        let verdict = FlowVerdict {
            outcome,
            dependency,
            restricted: membership.is_some_and(Membership::outbound_restricted),
        };
        (verdict, true)
    }
}
