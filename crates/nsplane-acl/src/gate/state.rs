//! Bounded flow and fragment state, sharded by peer.
//!
//! Expiry is lazy: an expired entry is dropped when it is looked up, and a
//! shard (or every shard) is swept only when a limit would be hit, so a
//! capacity verdict is reached only after expired entries were reclaimed.

use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use nsplane_packet::PeerId;

use super::PacketDirection;
use super::config::{GateConfig, GateTimeouts};
use super::hash::FastMap;
use super::policy::Slot;
use crate::rules::{RuleId, Transport};

/// Number of state shards.
pub(super) const SHARD_COUNT: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FlowKey {
    pub(super) slot: Slot,
    pub(super) peer: PeerId,
    pub(super) remote_ip: Ipv4Addr,
    pub(super) local_ip: Ipv4Addr,
    pub(super) protocol: u8,
    pub(super) remote_port: u16,
    pub(super) local_port: u16,
}

impl Hash for FlowKey {
    /// Two words: the peer and the remote address; the local address, the
    /// ports, the scope slot and the protocol folded together. Hashing a
    /// subset of the key's bits keeps equal keys equal.
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64((u64::from(self.peer.get()) << 32) | u64::from(self.remote_ip.to_bits()));
        state.write_u64(
            (u64::from(self.local_ip.to_bits()) << 32)
                ^ (u64::from(self.remote_port) << 16)
                ^ u64::from(self.local_port)
                ^ (u64::from(self.slot) << 40)
                ^ (u64::from(self.protocol) << 56),
        );
    }
}

/// What a live flow lookup found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lookup<T> {
    /// No live flow; an expired one was dropped.
    Missing,
    /// The live flow, mapped.
    Found(T),
}

/// FIN/RST progress of a TCP flow.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct TcpClose {
    pub(super) fin_initiator: bool,
    pub(super) fin_responder: bool,
    pub(super) reset: bool,
}

impl TcpClose {
    pub(super) const fn closing(self) -> bool {
        self.fin_initiator || self.fin_responder || self.reset
    }

    const fn terminal(self) -> bool {
        self.reset || (self.fin_initiator && self.fin_responder)
    }
}

#[derive(Debug, Clone)]
pub(super) struct FlowState {
    pub(super) initiator: PacketDirection,
    /// The transport of the packet that opened the flow, to re-authorize it.
    pub(super) opened: Transport,
    /// The grant that admitted the flow.
    pub(super) rule: RuleId,
    pub(super) enforced: bool,
    pub(super) close: TcpClose,
    pub(super) expires_at: Instant,
}

impl FlowState {
    /// Refresh the idle lifetime after a packet of an existing flow.
    pub(super) fn touch(&mut self, protocol: u8, now: Instant, timeouts: &GateTimeouts) {
        if self.close.terminal() && protocol == 6 {
            // A final ACK may arrive after FIN/RST. It is valid tail traffic,
            // but must not turn a closed TCP entry back into the normal two-hour
            // lifetime and exhaust the per-peer state quota.
            self.expires_at = self.expires_at.min(now + timeouts.tcp_closed);
        } else if self.close.closing() && protocol == 6 {
            // A half-closed flow may continue carrying data in the remaining
            // direction, but uses a bounded idle lifetime instead of two hours.
            self.expires_at = now + timeouts.tcp_half_closed;
        } else {
            self.expires_at = now + protocol_timeout(protocol, timeouts);
        }
    }

    pub(super) fn observe_tcp_close(
        &mut self,
        direction: PacketDirection,
        tcp_flags: u8,
        now: Instant,
        timeouts: &GateTimeouts,
    ) {
        if tcp_flags & 0x04 != 0 {
            self.close.reset = true;
        }
        if tcp_flags & 0x01 != 0 {
            if direction == self.initiator {
                self.close.fin_initiator = true;
            } else {
                self.close.fin_responder = true;
            }
        }
        if self.close.terminal() {
            self.expires_at = self.expires_at.min(now + timeouts.tcp_closed);
        } else if self.close.closing() {
            self.expires_at = self.expires_at.min(now + timeouts.tcp_half_closed);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct FragmentKey {
    pub(super) slot: Slot,
    pub(super) direction: PacketDirection,
    pub(super) peer: PeerId,
    pub(super) source: Ipv4Addr,
    pub(super) destination: Ipv4Addr,
    pub(super) protocol: u8,
    pub(super) identification: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FragmentDisposition {
    /// The first fragment opened or matched a flow.
    Allow,
    /// The first fragment passed under an unbound rule.
    Pass,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct FragmentState {
    pub(super) disposition: FragmentDisposition,
    pub(super) expires_at: Instant,
}

/// Outcome of an attempt to create state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    Admitted,
    /// A limit holds after reclaiming expired entries: fail closed.
    Full,
    /// A global limit was hit; sweep every shard and evaluate again.
    SweepAll,
}

/// Global entry counts, the configured limits and the timeouts.
#[derive(Debug)]
pub(super) struct Counts {
    pub(super) flows: AtomicUsize,
    pub(super) fragments: AtomicUsize,
    pub(super) global_limit: usize,
    pub(super) peer_limit: usize,
    pub(super) fragment_limit: usize,
    pub(super) timeouts: GateTimeouts,
}

impl Counts {
    /// Take one slot of `counter` unless it is at `limit`.
    fn reserve(counter: &AtomicUsize, limit: usize) -> bool {
        let mut count = counter.load(Ordering::Acquire);
        while count < limit {
            match counter.compare_exchange_weak(
                count,
                count + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => count = actual,
            }
        }
        false
    }

    fn reserve_flow(&self) -> bool {
        Self::reserve(&self.flows, self.global_limit)
    }

    fn reserve_fragment(&self) -> bool {
        Self::reserve(&self.fragments, self.fragment_limit)
    }

    fn release_flows(&self, count: usize) {
        if count != 0 {
            self.flows.fetch_sub(count, Ordering::AcqRel);
        }
    }

    fn release_fragments(&self, count: usize) {
        if count != 0 {
            self.fragments.fetch_sub(count, Ordering::AcqRel);
        }
    }
}

/// One shard: the flows and fragments of the remote peers hashed to it.
#[derive(Debug, Default)]
pub(super) struct Shard {
    /// Epoch of the snapshot this shard's state was last migrated to.
    pub(super) epoch: u64,
    pub(super) flows: FastMap<FlowKey, FlowState>,
    pub(super) fragments: FastMap<FragmentKey, FragmentState>,
    pub(super) peer_flows: FastMap<PeerId, usize>,
}

impl Shard {
    fn forget_peer_flow(&mut self, peer: PeerId) {
        if let Some(count) = self.peer_flows.get_mut(&peer) {
            *count -= 1;
            if *count == 0 {
                self.peer_flows.remove(&peer);
            }
        }
    }

    fn remove_flow(&mut self, key: &FlowKey, counts: &Counts) {
        if self.flows.remove(key).is_some() {
            self.forget_peer_flow(key.peer);
            counts.release_flows(1);
        }
    }

    fn remove_fragment(&mut self, key: &FragmentKey, counts: &Counts) {
        if self.fragments.remove(key).is_some() {
            counts.release_fragments(1);
        }
    }

    /// `with` applied to the live flow for `key` (one lookup), dropping the
    /// flow when expired.
    pub(super) fn with_live_flow<T>(
        &mut self,
        key: &FlowKey,
        now: Instant,
        counts: &Counts,
        with: impl FnOnce(&mut FlowState) -> T,
    ) -> Lookup<T> {
        let Some(state) = self.flows.get_mut(key) else {
            return Lookup::Missing;
        };
        if state.expires_at > now {
            return Lookup::Found(with(state));
        }
        self.remove_flow(key, counts);
        Lookup::Missing
    }

    /// Whether `key` has a live flow; its idle lifetime is refreshed.
    pub(super) fn touch_flow(&mut self, key: &FlowKey, now: Instant, counts: &Counts) -> bool {
        self.with_live_flow(key, now, counts, |state| {
            state.touch(key.protocol, now, &counts.timeouts);
        }) != Lookup::Missing
    }

    pub(super) fn fragment_disposition(
        &mut self,
        key: &FragmentKey,
        now: Instant,
        counts: &Counts,
    ) -> Option<FragmentDisposition> {
        let state = *self.fragments.get(key)?;
        if state.expires_at <= now {
            self.remove_fragment(key, counts);
            return None;
        }
        Some(state.disposition)
    }

    /// Remove every expired entry of this shard.
    pub(super) fn sweep(&mut self, now: Instant, counts: &Counts) {
        self.retain_flows(counts, |_, state| state.expires_at > now);
        self.retain_fragments(counts, |_, state| state.expires_at > now);
    }

    pub(super) fn retain_flows(
        &mut self,
        counts: &Counts,
        mut keep: impl FnMut(&FlowKey, &mut FlowState) -> bool,
    ) {
        let before = self.flows.len();
        let peer_flows = &mut self.peer_flows;
        self.flows.retain(|key, state| {
            let kept = keep(key, state);
            if !kept && let Some(count) = peer_flows.get_mut(&key.peer) {
                *count -= 1;
                if *count == 0 {
                    peer_flows.remove(&key.peer);
                }
            }
            kept
        });
        counts.release_flows(before - self.flows.len());
    }

    pub(super) fn retain_fragments(
        &mut self,
        counts: &Counts,
        mut keep: impl FnMut(&FragmentKey, &FragmentState) -> bool,
    ) {
        let before = self.fragments.len();
        self.fragments.retain(|key, state| keep(key, state));
        counts.release_fragments(before - self.fragments.len());
    }

    fn peer_flow_count(&self, peer: PeerId) -> usize {
        self.peer_flows.get(&peer).copied().unwrap_or(0)
    }

    /// Insert a new flow and, for a first fragment, its fragment authority,
    /// both or neither. `swept` is set once every shard has been swept for
    /// this packet, so a global limit then fails closed.
    pub(super) fn insert_flow_with_fragment(
        &mut self,
        key: FlowKey,
        state: FlowState,
        fragment: Option<FragmentKey>,
        now: Instant,
        counts: &Counts,
        swept: bool,
    ) -> Admission {
        if self
            .flows
            .get(&key)
            .is_some_and(|flow| flow.expires_at <= now)
        {
            self.remove_flow(&key, counts);
        }
        if let Some(fragment) = &fragment
            && self
                .fragments
                .get(fragment)
                .is_some_and(|existing| existing.expires_at <= now)
        {
            self.remove_fragment(fragment, counts);
        }

        let new_flow = !self.flows.contains_key(&key);
        if new_flow {
            if self.peer_flow_count(key.peer) >= counts.peer_limit {
                self.sweep(now, counts);
                if self.peer_flow_count(key.peer) >= counts.peer_limit {
                    return Admission::Full;
                }
            }
            if !counts.reserve_flow() {
                return if swept {
                    Admission::Full
                } else {
                    Admission::SweepAll
                };
            }
        }
        if let Some(fragment) = &fragment {
            let admission = match self.fragments.get(fragment) {
                Some(existing) if existing.disposition != FragmentDisposition::Allow => {
                    Admission::Full
                }
                Some(_) => Admission::Admitted,
                None if counts.reserve_fragment() => Admission::Admitted,
                None if swept => Admission::Full,
                None => Admission::SweepAll,
            };
            if admission != Admission::Admitted {
                if new_flow {
                    counts.release_flows(1);
                }
                return admission;
            }
        }

        if new_flow {
            *self.peer_flows.entry(key.peer).or_default() += 1;
        }
        self.flows.insert(key, state);
        if let Some(fragment) = fragment {
            self.fragments.insert(
                fragment,
                FragmentState {
                    disposition: FragmentDisposition::Allow,
                    expires_at: now + counts.timeouts.fragment,
                },
            );
        }
        Admission::Admitted
    }

    /// Remember a first fragment's disposition for its later fragments.
    pub(super) fn remember_fragment(
        &mut self,
        key: FragmentKey,
        disposition: FragmentDisposition,
        now: Instant,
        counts: &Counts,
        swept: bool,
    ) -> Admission {
        match self.fragments.get(&key) {
            Some(existing) if existing.expires_at <= now => self.remove_fragment(&key, counts),
            Some(existing) if existing.disposition != disposition => return Admission::Full,
            _ => {}
        }
        if !self.fragments.contains_key(&key) && !counts.reserve_fragment() {
            return if swept {
                Admission::Full
            } else {
                Admission::SweepAll
            };
        }
        self.fragments.insert(
            key,
            FragmentState {
                disposition,
                expires_at: now + counts.timeouts.fragment,
            },
        );
        Admission::Admitted
    }
}

/// The sharded state table.
#[derive(Debug)]
pub(super) struct StateTable {
    shards: Box<[Mutex<Shard>]>,
    pub(super) counts: Counts,
}

impl StateTable {
    pub(super) fn new(config: &GateConfig) -> Self {
        Self {
            shards: (0..SHARD_COUNT).map(|_| Mutex::default()).collect(),
            counts: Counts {
                flows: AtomicUsize::new(0),
                fragments: AtomicUsize::new(0),
                global_limit: config.limits.flows,
                peer_limit: config.limits.flows_per_peer,
                fragment_limit: config.limits.fragments,
                timeouts: config.timeouts,
            },
        }
    }

    /// Lock the shard holding `peer`'s state.
    pub(super) fn lock(&self, peer: PeerId) -> MutexGuard<'_, Shard> {
        self.shards[shard_index(peer)]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Lock every shard in index order (the only order any thread uses when
    /// holding more than one shard).
    pub(super) fn lock_all(&self) -> Vec<MutexGuard<'_, Shard>> {
        self.shards
            .iter()
            .map(|shard| shard.lock().unwrap_or_else(PoisonError::into_inner))
            .collect()
    }

    /// Reclaim every expired entry. The caller holds no shard lock.
    pub(super) fn sweep_all(&self, now: Instant) {
        for mut shard in self.lock_all() {
            shard.sweep(now, &self.counts);
        }
    }
}

/// Shard of a peer: its id multiplied by an odd constant, top bits.
pub(super) fn shard_index(peer: PeerId) -> usize {
    let hash = u64::from(peer.get()).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    usize::try_from(hash >> 58).unwrap_or(0)
}

pub(super) const fn protocol_timeout(protocol: u8, timeouts: &GateTimeouts) -> Duration {
    match protocol {
        6 => timeouts.tcp,
        17 => timeouts.udp,
        1 => timeouts.icmp,
        _ => timeouts.other,
    }
}
