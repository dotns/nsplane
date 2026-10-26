//! The flow table: resolved peers, cached verdicts and fragment outcomes.

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Instant;

use nsplane_packet::{FiveTuple, PeerId};

use super::outcome::{Outcome, bump};
use super::replies::is_pending;
use super::table::{
    CachedVerdict, EntryKey, FlowEntry, FlowTable, FlowVerdict, FragmentKey, Hit, PeerInfo,
};
use super::{Inner, reversed};
use crate::engine::{FlowOrigin, ReplyDependency, Snapshot};
use crate::lru::LruMap;

impl Inner {
    /// The side effects of an inbound packet of a flow with `verdict`.
    pub(super) fn replay(
        &self,
        table: &mut FlowTable,
        peer: PeerId,
        tuple: FiveTuple,
        verdict: &FlowVerdict,
    ) {
        if let Some(dependency) = verdict.pending() {
            self.record_pending(table, tuple, dependency.clone());
        }
        if verdict.restricted && self.config.stateful_replies {
            self.record_reply(
                table,
                None,
                peer,
                true,
                reversed(tuple),
                verdict.dependency.clone(),
            );
        }
    }

    /// The resolved `peer` for packets whose remote address is `src` under
    /// the snapshot's generation and `identity`, resolving it again when
    /// missing or stale. A by-source peer is resolved per address; with no
    /// address it is unknown. `None` if the cache lost the entry it just
    /// stored (an invariant failure the caller drops the packet on).
    pub(super) fn cached_peer<'t>(
        &self,
        table: &'t mut FlowTable,
        snapshot: &Snapshot,
        peer: PeerId,
        src: Option<IpAddr>,
        identity: u64,
    ) -> Option<&'t Arc<PeerInfo>> {
        let generation = snapshot.generation();
        let capacity = self.config.reply_capacity.max(1);
        if table.peers.len() >= capacity && !table.peers.contains_key(&peer) {
            table
                .peers
                .retain(|_, info| info.generation == generation && info.identity == identity);
            if table.peers.len() >= capacity {
                table.peers.clear();
            }
        }
        let resolve = || {
            let local = || self.identity.local_identity(peer);
            let info = match src {
                _ if self.identity.by_source(peer) => {
                    PeerInfo::new(None, snapshot, identity, true, local())
                }
                Some(src) => PeerInfo::resolve(&*self.identity, snapshot, peer, src, identity),
                None => PeerInfo::new(
                    self.identity.labels(peer),
                    snapshot,
                    identity,
                    false,
                    local(),
                ),
            };
            Arc::new(info)
        };
        let info = table.peers.entry(peer).or_insert_with(resolve);
        if info.generation != generation || info.identity != identity {
            *info = resolve();
        }
        match src {
            Some(src) if info.by_source => {
                self.cached_source(&mut table.sources, snapshot, peer, src, identity)
            }
            _ => Some(info),
        }
    }

    /// The resolved by-source `peer` for the remote address `src`, as
    /// [`cached_peer`](Self::cached_peer).
    fn cached_source<'t>(
        &self,
        sources: &'t mut LruMap<(PeerId, IpAddr), Arc<PeerInfo>>,
        snapshot: &Snapshot,
        peer: PeerId,
        src: IpAddr,
        identity: u64,
    ) -> Option<&'t Arc<PeerInfo>> {
        let key = (peer, src);
        let fresh = sources.get(&key).is_some_and(|info| {
            info.generation == snapshot.generation() && info.identity == identity
        });
        if fresh {
            sources.touch(&key);
        } else {
            if !sources.contains_key(&key) && sources.len() >= self.config.reply_capacity.max(1) {
                sources.pop_oldest();
            }
            let info = PeerInfo::resolve(&*self.identity, snapshot, peer, src, identity);
            sources.insert(key, Arc::new(info));
        }
        sources.get(&key)
    }

    /// The live reply allowance (refreshed) or the valid cached verdict for
    /// `key`. Expired and revoked allowances are removed and counted (`sweep`
    /// is set when a pinhole may have expired); stale verdicts are removed.
    pub(super) fn lookup(
        &self,
        table: &mut FlowTable,
        snapshot: &Snapshot,
        key: EntryKey,
        identity: u64,
        sweep: &mut bool,
    ) -> Option<Hit> {
        match table.entries.get_mut(&key)? {
            FlowEntry::Allowance(allowance) => {
                let now = Instant::now();
                if now.duration_since(allowance.last_seen) > self.config.reply_idle_timeout {
                    table.entries.remove(&key);
                    bump(&self.counters.reply_expired);
                    return None;
                }
                match &allowance.dependency {
                    Some(ReplyDependency::Flow(origin)) if !self.is_current(snapshot, origin) => {
                        let origin = *origin;
                        return self.revalidate(table, snapshot, key, origin, now);
                    }
                    Some(dependency) if !snapshot.is_live(dependency, || self.engine.now()) => {
                        // The pinhole may only have expired: sweep it.
                        *sweep = matches!(dependency, ReplyDependency::Pinhole(_));
                        table.entries.remove(&key);
                        bump(&self.counters.reply_revoked);
                        return None;
                    }
                    _ => {}
                }
                allowance.last_seen = now;
                let dependency = allowance.dependency.clone();
                table.entries.touch(&key);
                Some(Hit::Allowance(dependency))
            }
            FlowEntry::Verdict(cached) => {
                // Only a pinhole can close without a generation change: it
                // expires.
                let valid = identity != 0
                    && cached.generation == snapshot.generation()
                    && cached.identity == identity
                    && cached.verdict.dependency.as_ref().is_none_or(|dependency| {
                        matches!(dependency, ReplyDependency::Grant(_))
                            || snapshot.is_live(dependency, || self.engine.now())
                    });
                if valid {
                    // The dependency is only needed for the side effects.
                    let verdict = &cached.verdict;
                    return Some(Hit::Verdict(FlowVerdict {
                        outcome: verdict.outcome,
                        dependency: verdict
                            .dependency
                            .as_ref()
                            .filter(|dependency| verdict.restricted || is_pending(dependency))
                            .cloned(),
                        restricted: verdict.restricted,
                    }));
                }
                table.entries.remove(&key);
                table.verdicts -= 1;
                None
            }
        }
    }

    /// Whether `origin` was accepted under the snapshot's generation and the
    /// current identity generation (never with an unversioned identity).
    fn is_current(&self, snapshot: &Snapshot, origin: &FlowOrigin) -> bool {
        let identity = self.identity_generation();
        identity != 0 && origin.generation == snapshot.generation() && origin.identity == identity
    }

    /// Evaluate the flow of the allowance under `key` again from its origin
    /// peer: still accepted, the allowance is refreshed with the new
    /// dependency; else it is revoked.
    fn revalidate(
        &self,
        table: &mut FlowTable,
        snapshot: &Snapshot,
        key: EntryKey,
        origin: FlowOrigin,
        now: Instant,
    ) -> Option<Hit> {
        let identity = self.identity_generation();
        let info = if identity == 0 {
            Some(Arc::new(PeerInfo::resolve(
                &*self.identity,
                snapshot,
                origin.peer,
                origin.flow.src,
                0,
            )))
        } else {
            self.cached_peer(
                table,
                snapshot,
                origin.peer,
                Some(origin.flow.src),
                identity,
            )
            .map(Arc::clone)
        };
        let verdict = info.map(|info| {
            self.evaluate_new(snapshot, origin.peer, &info, origin.flow)
                .0
        });
        let Some(FlowVerdict {
            outcome: Outcome::Accepted,
            dependency,
            ..
        }) = verdict
        else {
            table.entries.remove(&key);
            bump(&self.counters.reply_revoked);
            return None;
        };
        if let Some(FlowEntry::Allowance(allowance)) = table.entries.get_mut(&key) {
            allowance.last_seen = now;
            allowance.dependency.clone_from(&dependency);
        }
        table.entries.touch(&key);
        Some(Hit::Allowance(dependency))
    }

    /// Cache `cached` under `key`, unless an allowance holds it or the table
    /// is full of allowances.
    pub(super) fn cache_verdict(
        &self,
        table: &mut FlowTable,
        key: EntryKey,
        cached: CachedVerdict,
    ) {
        match table.entries.get_mut(&key) {
            Some(FlowEntry::Allowance(_)) => return,
            Some(FlowEntry::Verdict(old)) => {
                *old = cached;
                return;
            }
            None => {}
        }
        let capacity = self.config.reply_capacity.max(1);
        if table.entries.len() >= capacity {
            if table.verdicts < (capacity / 8).max(1) {
                return;
            }
            self.flush_verdicts(table);
        }
        table.entries.insert(key, FlowEntry::Verdict(cached));
        table.verdicts += 1;
    }

    /// Remove every cached verdict, counting them as evictions.
    pub(super) fn flush_verdicts(&self, table: &mut FlowTable) {
        table
            .entries
            .retain(|_, entry| matches!(entry, FlowEntry::Allowance(_)));
        self.counters
            .verdict_evictions
            .fetch_add(table.verdicts as u64, Ordering::Relaxed);
        table.verdicts = 0;
    }

    pub(super) fn follow_fragment(&self, key: FragmentKey, last: bool) -> Option<Outcome> {
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last {
            table.entries.remove(&key)
        } else {
            table.entries.get(&key).copied()
        }
    }

    pub(super) fn record_fragment(&self, key: FragmentKey, outcome: Outcome) {
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let capacity = self.config.fragment_capacity.max(1);
        if !table.entries.contains_key(&key)
            && table.entries.len() >= capacity
            && table.entries.pop_oldest().is_some()
        {
            bump(&self.counters.fragment_evictions);
        }
        table.entries.insert(key, outcome);
    }
}
