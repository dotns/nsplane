//! Outbound packets: source scope, restricted peers and pinholes.

use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard};

use nsplane_core::LocalIdentityId;
use nsplane_packet::{FiveTuple, IpPacket, PeerId, protocol};

use super::outcome::Outcome;
use super::packet::{EchoType, echo_type, is_icmp, other_transport, tcp_udp_flow};
use super::scope::ScopeSet;
use super::table::{CachedVerdict, EntryKey, FlowTable, FlowVerdict, Governed, Hit, PeerInfo};
use super::{Inner, reversed};
use crate::engine::{PinholeMatch, ReplyDependency, Snapshot};
use crate::net::Protocol;
use crate::pinhole::Direction;
use crate::rules::LabelSet;

impl Inner {
    pub(super) fn outbound(&self, peer: PeerId, bytes: &[u8]) -> Outcome {
        if self.accepts_ipv6(bytes) {
            return Outcome::Ipv6Accepted;
        }
        // The engine snapshot is read first, as on the inbound path: a read
        // nested in another one cannot fill the thread's cache.
        self.engine.read_snapshot(|snapshot| {
            if self.unscoped.load(Ordering::Acquire) {
                return self.outbound_under(snapshot, peer, bytes, None);
            }
            self.scopes
                .read(|set| self.outbound_under(snapshot, peer, bytes, Some(set)))
        })
    }

    /// [`outbound`](Self::outbound) under the engine `snapshot` and the scopes
    /// `set`, `None` when they constrain nothing.
    fn outbound_under(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        bytes: &[u8],
        set: Option<&ScopeSet>,
    ) -> Outcome {
        // Without per-identity scopes the scope is known before the peer.
        let early = set
            .filter(|set| set.by_identity.is_empty())
            .map(|set| &set.default);
        if early.is_some_and(|scope| !scope.allows_source(bytes)) {
            return Outcome::OutboundSource;
        }
        let identity = self.identity_generation();
        let parsed = IpPacket::parse(bytes);
        // The remote address; a by-source peer is unknown without it.
        let dst = parsed.as_ref().ok().map(IpPacket::dst);
        let mut table = self.table();
        let mut local = LocalIdentityId::DEFAULT;
        // `None`: an unrestricted peer without pinholes.
        let info = if identity != 0 {
            let Some(info) = self.cached_peer(&mut table, snapshot, peer, dst, identity) else {
                return Outcome::Internal;
            };
            local = info.local_identity;
            (info.governed == Governed::Restricted || info.pinholes).then(|| Arc::clone(info))
        } else if snapshot.has_outbound_restrictions() || snapshot.has_pinholes() {
            let labels = dst.map_or_else(
                || self.identity.labels(peer),
                |dst| self.identity.labels_for(peer, dst),
            );
            Some(Arc::new(PeerInfo::new(
                labels,
                snapshot,
                0,
                false,
                LocalIdentityId::DEFAULT,
            )))
        } else {
            None
        };
        if let (None, Some(set)) = (early, set) {
            if identity == 0 {
                local = self.identity.local_identity(peer);
            }
            if !set.select(local).allows_source(bytes) {
                return Outcome::OutboundSource;
            }
        }
        let restricted = info
            .as_ref()
            .is_some_and(|info| info.governed == Governed::Restricted);
        let Ok(packet) = parsed else {
            return if restricted {
                Outcome::OutboundDenied
            } else {
                Outcome::OutboundAccepted
            };
        };
        let info = match info {
            Some(info) if restricted => info,
            info => {
                let info = info.as_deref();
                self.outbound_unrestricted(snapshot, peer, info, &packet, table);
                return Outcome::OutboundAccepted;
            }
        };
        if packet.fragment().is_none() {
            return self.evaluate_outbound(snapshot, peer, &info, identity, &packet, table);
        }
        drop(table);
        self.with_fragments(peer, true, &packet, Outcome::OutboundDenied, |packet| {
            self.evaluate_outbound(snapshot, peer, &info, identity, packet, self.table())
        })
    }

    /// An outbound packet to an unrestricted peer (`info`: with pinholes):
    /// accepted anyway; an outbound pinhole still owns the replies.
    fn outbound_unrestricted(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        info: Option<&PeerInfo>,
        packet: &IpPacket<'_>,
        mut table: MutexGuard<'_, FlowTable>,
    ) {
        let Some(tuple) = packet.five_tuple() else {
            return;
        };
        let mut sweep = false;
        let dependency = info
            .and_then(|info| info.labels.as_ref())
            .and_then(|labels| self.outbound_pinhole(snapshot, labels, &tuple, &mut sweep));
        self.track_outbound(&mut table, snapshot, peer, tuple, packet, dependency);
        drop(table);
        self.sweep_if(sweep);
    }

    /// The open outbound pinhole of `labels` for `tuple`, as a reply
    /// dependency. Sets `sweep` when only expired pinholes match.
    fn outbound_pinhole(
        &self,
        snapshot: &Snapshot,
        labels: &LabelSet,
        tuple: &FiveTuple,
        sweep: &mut bool,
    ) -> Option<ReplyDependency> {
        let protocol = Protocol::from_ip_number(tuple.protocol)?;
        match snapshot.match_pinhole(
            labels,
            Direction::Outbound,
            protocol,
            tuple.dst_port,
            || self.engine.now(),
        ) {
            PinholeMatch::Open(id) => Some(ReplyDependency::Pinhole(id)),
            PinholeMatch::Expired => {
                *sweep = true;
                None
            }
            PinholeMatch::Absent => None,
        }
    }

    /// Evaluate an outbound packet to the outbound-restricted peer `info`,
    /// holding the flow table.
    fn evaluate_outbound(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        info: &PeerInfo,
        identity: u64,
        packet: &IpPacket<'_>,
        mut table: MutexGuard<'_, FlowTable>,
    ) -> Outcome {
        let Some(tuple) = packet.five_tuple() else {
            return Outcome::OutboundDenied;
        };
        let Some(protocol) = Protocol::from_ip_number(tuple.protocol) else {
            if self.config.allow_other_protocols {
                self.track_outbound(&mut table, snapshot, peer, tuple, packet, None);
                return Outcome::OutboundAccepted;
            }
            return self.outbound_other(snapshot, peer, info, tuple, packet, table);
        };
        let key = EntryKey {
            peer,
            outbound: true,
            tuple,
        };
        let mut sweep = false;
        let verdict = match self.lookup(&mut table, snapshot, key, identity, &mut sweep) {
            Some(Hit::Allowance(dependency)) => FlowVerdict {
                outcome: Outcome::OutboundReply,
                dependency,
                restricted: false,
            },
            Some(Hit::Verdict(verdict)) => verdict,
            None => {
                let (verdict, cacheable) =
                    self.evaluate_new_outbound(snapshot, info, protocol, &tuple, &mut sweep);
                if cacheable && identity != 0 {
                    let cached = CachedVerdict {
                        generation: snapshot.generation(),
                        identity,
                        verdict: verdict.clone(),
                    };
                    self.cache_verdict(&mut table, key, cached);
                }
                verdict
            }
        };
        if verdict.outcome != Outcome::OutboundDenied {
            self.track_outbound(
                &mut table,
                snapshot,
                peer,
                tuple,
                packet,
                verdict.dependency,
            );
        }
        drop(table);
        self.sweep_if(sweep);
        verdict.outcome
    }

    /// An outbound packet to the outbound-restricted peer `info` that is
    /// neither TCP nor UDP, without `allow_other_protocols`: accepted as the
    /// reply allowed by an accepted inbound packet, or by an outbound rule.
    fn outbound_other(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        info: &PeerInfo,
        tuple: FiveTuple,
        packet: &IpPacket<'_>,
        mut table: MutexGuard<'_, FlowTable>,
    ) -> Outcome {
        if self.config.stateful_replies
            && (!is_icmp(tuple.protocol) || echo_type(packet) == Some(EchoType::Reply))
        {
            let key = EntryKey {
                peer,
                outbound: true,
                tuple,
            };
            let mut sweep = false;
            let reply = matches!(
                self.lookup(&mut table, snapshot, key, 0, &mut sweep),
                Some(Hit::Allowance(_))
            );
            if reply {
                drop(table);
                self.sweep_if(sweep);
                return Outcome::OutboundReply;
            }
            self.sweep_if(sweep);
        }
        let rule = other_transport(packet, tuple.protocol).is_some_and(|transport| {
            info.membership
                .as_deref()
                .is_some_and(|membership| snapshot.outbound_rule_accepts(membership, transport))
        });
        if !rule {
            return Outcome::OutboundDenied;
        }
        self.track_outbound(&mut table, snapshot, peer, tuple, packet, None);
        Outcome::OutboundAccepted
    }

    /// Evaluate a new outbound TCP or UDP flow to the outbound-restricted
    /// peer `info`. Returns the verdict and whether it may be cached.
    fn evaluate_new_outbound(
        &self,
        snapshot: &Snapshot,
        info: &PeerInfo,
        protocol: Protocol,
        tuple: &FiveTuple,
        sweep: &mut bool,
    ) -> (FlowVerdict, bool) {
        let transport = tcp_udp_flow(tuple, protocol).transport;
        let rule = info
            .membership
            .as_deref()
            .is_some_and(|membership| snapshot.outbound_rule_accepts(membership, transport));
        if rule {
            return (FlowVerdict::new(Outcome::OutboundAccepted), true);
        }
        let mut expired = false;
        let dependency = info
            .labels
            .as_ref()
            .and_then(|labels| self.outbound_pinhole(snapshot, labels, tuple, &mut expired));
        let outcome = if dependency.is_some() {
            Outcome::OutboundAccepted
        } else {
            Outcome::OutboundDenied
        };
        // Only expired pinholes matched: not cached, the sweep publishes a
        // new generation anyway.
        *sweep |= expired;
        let verdict = FlowVerdict {
            outcome,
            dependency,
            restricted: false,
        };
        (verdict, !expired)
    }

    /// Record the inbound reply allowance of an accepted outbound packet: a
    /// TCP or UDP packet, or an ICMP or `ICMPv6` echo request, whose reply
    /// matches the reversed tuple (the echo identifier included).
    fn track_outbound(
        &self,
        table: &mut FlowTable,
        snapshot: &Snapshot,
        peer: PeerId,
        tuple: FiveTuple,
        packet: &IpPacket<'_>,
        dependency: Option<ReplyDependency>,
    ) {
        if !self.config.stateful_replies {
            return;
        }
        let tracked = match tuple.protocol {
            protocol::TCP | protocol::UDP => true,
            p if is_icmp(p) => echo_type(packet) == Some(EchoType::Request),
            _ => false,
        };
        if tracked {
            self.record_reply(
                table,
                Some(snapshot),
                peer,
                false,
                reversed(tuple),
                dependency,
            );
        }
    }
}
