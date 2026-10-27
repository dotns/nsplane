//! Reply allowances and the pending dependencies of inbound flows.

use std::sync::Arc;
use std::time::Instant;

use nsplane_packet::{FiveTuple, PeerId};

use super::outcome::{Outcome, bump};
use super::packet::tcp_udp_flow;
use super::table::{EntryKey, FlowEntry, FlowTable, PeerInfo, ReplyEntry};
use super::{Inner, reversed};
use crate::engine::{ReplyDependency, Snapshot};
use crate::lru::LruMap;
use crate::net::Protocol;

impl Inner {
    /// Record or refresh the allowance of `tuple`. A new inbound allowance
    /// without a dependency inherits the pending one, or else (with `origin`)
    /// the one of the inbound flow `tuple` itself when the policy accepts it.
    pub(super) fn record_reply(
        &self,
        table: &mut FlowTable,
        origin: Option<&Snapshot>,
        peer: PeerId,
        outbound: bool,
        tuple: FiveTuple,
        dependency: Option<ReplyDependency>,
    ) {
        let now = self.engine.now();
        let key = EntryKey {
            peer,
            outbound,
            tuple,
        };
        // A refresh without a dependency keeps the allowance's own.
        if let Some(FlowEntry::Allowance(allowance)) = table.entries.get_mut(&key) {
            allowance.last_seen = now;
            if dependency.is_some() {
                allowance.dependency = dependency;
            } else if allowance.dependency.is_none() && !outbound {
                allowance.dependency = self.pending_dependency(&table.pending, tuple, now);
            }
            table.entries.touch(&key);
            return;
        }
        let dependency = match dependency {
            None if !outbound => self
                .pending_dependency(&table.pending, tuple, now)
                .or_else(|| origin.and_then(|snapshot| self.inbound_origin(table, snapshot, key))),
            dependency => dependency,
        };
        let allowance = ReplyEntry {
            last_seen: now,
            dependency,
        };
        let capacity = self.config.reply_capacity.max(1);
        if !table.entries.contains_key(&key) && table.entries.len() >= capacity {
            if table.verdicts > 0 {
                self.flush_verdicts(table);
            }
            // Only allowances are left: the oldest is the least recently seen.
            if table.entries.len() >= capacity && table.entries.pop_oldest().is_some() {
                bump(&self.counters.reply_evictions);
            }
        }
        let old = table.entries.insert(key, FlowEntry::Allowance(allowance));
        if matches!(old, Some(FlowEntry::Verdict(_))) {
            table.verdicts -= 1;
        }
    }

    /// The dependency of the inbound flow an inbound allowance for `tuple`
    /// continues: the same tuple forwarded to another peer, or the reply of
    /// the local node.
    fn pending_dependency(
        &self,
        pending: &LruMap<FiveTuple, ReplyEntry>,
        tuple: FiveTuple,
        now: Instant,
    ) -> Option<ReplyDependency> {
        if pending.is_empty() {
            return None;
        }
        [tuple, reversed(tuple)]
            .iter()
            .find_map(|tuple| {
                pending.get(tuple).filter(|pending| {
                    now.duration_since(pending.last_seen) <= self.config.reply_idle_timeout
                })
            })
            .and_then(|pending| pending.dependency.clone())
    }

    /// The dependency of the inbound TCP or UDP flow of the allowance `key`
    /// when the policy accepts it (its verdict cached under the current
    /// generations, else evaluated), `None` when it does not: the allowance
    /// then belongs to a flow the local node opened.
    fn inbound_origin(
        &self,
        table: &mut FlowTable,
        snapshot: &Snapshot,
        key: EntryKey,
    ) -> Option<ReplyDependency> {
        let protocol = Protocol::from_ip_number(key.tuple.protocol)?;
        let identity = self.identity_generation();
        if let Some(FlowEntry::Verdict(cached)) = table.entries.get(&key)
            && identity != 0
            && cached.generation == snapshot.generation()
            && cached.identity == identity
        {
            return (cached.verdict.outcome == Outcome::Accepted)
                .then(|| cached.verdict.dependency.clone())
                .flatten();
        }
        let info = if identity == 0 {
            Arc::new(PeerInfo::resolve(
                &*self.identity,
                snapshot,
                key.peer,
                key.tuple.src,
                0,
            ))
        } else {
            Arc::clone(self.cached_peer(
                table,
                snapshot,
                key.peer,
                Some(key.tuple.src),
                identity,
            )?)
        };
        let flow = tcp_udp_flow(&key.tuple, protocol);
        let (verdict, _) = self.evaluate_new(snapshot, key.peer, &info, flow);
        (verdict.outcome == Outcome::Accepted)
            .then_some(verdict.dependency)
            .flatten()
    }

    /// Remember that the inbound flow `tuple` depends on `dependency`.
    pub(super) fn record_pending(
        &self,
        table: &mut FlowTable,
        tuple: FiveTuple,
        dependency: ReplyDependency,
    ) {
        if !self.config.stateful_replies {
            return;
        }
        let capacity = self.config.reply_capacity.max(1);
        if !table.pending.contains_key(&tuple)
            && table.pending.len() >= capacity
            && table.pending.pop_oldest().is_some()
        {
            bump(&self.counters.pending_evictions);
        }
        table.pending.insert(
            tuple,
            ReplyEntry {
                last_seen: self.engine.now(),
                dependency: Some(dependency),
            },
        );
    }
}

/// Whether a packet carrying `dependency` records it as pending: a grant, a
/// pinhole, or a flow forwarded to another member (the dependency of a flow
/// to the local node stays with its allowances).
pub(super) const fn is_pending(dependency: &ReplyDependency) -> bool {
    match dependency {
        ReplyDependency::Flow(origin) => origin.forwarded,
        ReplyDependency::Grant(_) | ReplyDependency::Pinhole(_) => true,
    }
}
