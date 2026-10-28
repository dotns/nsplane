//! Ingress labels: the label of each lifetime, the checks of labeled input, the revoke of a
//! label and its tombstones.
//!
//! The tag of a packet sent into the sink is its ingress label. A lifetime takes the label
//! of its first input (`None` is a label of its own) and later input with another label is
//! dropped. UDP flows keep the label on their `FlowState`, compared on the flow lookup every
//! datagram takes anyway. Inbound TCP lifetimes have an entry per tuple from their SYN on,
//! which segments are checked against only while some entry carries a label or the segment
//! does, so an unlabeled stack keeps its path.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::{Arc, Weak};

use nsplane_packet::protocol;
use smoltcp::iface::SocketHandle;

use crate::flow::{Fence, FlowState, RetirementOutcome};
use crate::stats::{self};

use super::Driver;
use super::wire::{tcp_segment, tcp_tuple};

/// Most labels whose input the ingress queue may still hold at once; a revoke that needs
/// one more fails.
const MAX_INGRESS_FENCES: usize = 1024;

#[cfg(test)]
thread_local! {
    /// Replaces [`MAX_INGRESS_FENCES`] for the stacks a test drives on its thread.
    pub(super) static INGRESS_FENCE_LIMIT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(not(test))]
const fn ingress_fence_limit() -> usize {
    MAX_INGRESS_FENCES
}

#[cfg(test)]
fn ingress_fence_limit() -> usize {
    INGRESS_FENCE_LIMIT
        .with(std::cell::Cell::get)
        .unwrap_or(MAX_INGRESS_FENCES)
}

/// `(remote, local)` of an inbound TCP lifetime: the source and destination of its input.
type Tuple = (SocketAddr, SocketAddr);

/// A TCP segment's addresses and ports as they appear in the packet: source and
/// destination address, then source and destination port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawTuple {
    V4(u64, u32),
    V6([u8; 36]),
}

impl RawTuple {
    /// A slot of [`Labels::recent`]: the top bits of a Fibonacci hash of a mix of the
    /// addresses and ports.
    fn slot(&self) -> usize {
        let mixed = match *self {
            Self::V4(addresses, ports) => addresses ^ u64::from(ports).rotate_left(32),
            Self::V6(raw) => {
                let word = |at: usize| {
                    raw.get(at..at + 8)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map_or(0, u64::from_ne_bytes)
                };
                word(8) ^ word(24) ^ word(28)
            }
        };
        let top = mixed.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - RECENT.trailing_zeros());
        usize::try_from(top).unwrap_or(0)
    }

    /// The tuple of the TCP segment `packet`, read without parsing the IP header further.
    #[inline]
    fn of(packet: &[u8]) -> Option<Self> {
        let &first = packet.first()?;
        if first >> 4 == 4 && packet.get(9) == Some(&protocol::TCP) {
            let header = usize::from(first & 0xf) * 4;
            let addresses = u64::from_ne_bytes(*packet.get(12..20)?.first_chunk::<8>()?);
            let ports = u32::from_ne_bytes(*packet.get(header..)?.first_chunk::<4>()?);
            return Some(Self::V4(addresses, ports));
        }
        let ports = tcp_segment(packet)?.first_chunk::<4>()?;
        let mut raw = [0; 36];
        raw[..32].copy_from_slice(packet.get(8..40)?);
        raw[32..].copy_from_slice(ports);
        Some(Self::V6(raw))
    }
}

/// Slots of [`Labels::recent`], a power of two.
const RECENT: usize = 64;

/// A tuple recently looked up in the TCP table, and the result.
#[derive(Debug, Clone, Copy)]
struct Recent {
    /// The table's generation at the lookup; 0 for none.
    generation: u64,
    tuple: RawTuple,
    held: Held,
}

impl Recent {
    const EMPTY: Self = Self {
        generation: 0,
        tuple: RawTuple::V4(0, 0),
        held: Held::None,
    };
}

/// What the TCP table holds for a tuple.
#[derive(Debug, Clone, Copy)]
enum Held {
    /// No inbound lifetime.
    None,
    /// The label of the inbound lifetime.
    Label(Option<NonZeroU64>),
}

/// The label of an inbound TCP lifetime.
#[derive(Debug, Clone, Copy)]
struct TcpEntry {
    label: Option<NonZeroU64>,
    /// The listener socket that took the SYN; `None` until smoltcp's poll.
    socket: Option<SocketHandle>,
}

/// The driver's label state.
#[derive(Debug)]
pub(super) struct Labels {
    /// Inbound TCP lifetimes by tuple, from the bare SYN until the socket is released.
    tcp: HashMap<Tuple, TcpEntry>,
    /// Entries of `tcp` with a label: while 0, unlabeled segments are not looked up.
    tcp_labeled: usize,
    /// Tuples of recent segments and what `tcp` held for them, by [`RawTuple::slot`]:
    /// segments read the table once per connection while it does not change. A slot is
    /// valid while its generation is `generation`.
    recent: Box<[Recent; RECENT]>,
    /// Advanced whenever `tcp` changes, which invalidates every slot of `recent`.
    generation: u64,
    /// Entries of `tcp` added by SYNs of this turn; a SYN no socket took expires with the
    /// poll. Empty between turns.
    syns: Vec<Tuple>,
    /// Labeled lifetimes by label, at every stage, handed-out ones included. Weak: a
    /// lifetime nothing refers to any more has nothing left to retire.
    lifetimes: HashMap<NonZeroU64, Vec<Weak<FlowState>>>,
    /// The number of lifetimes in `lifetimes`, and after the last prune.
    registered: usize,
    pruned: usize,
    /// Revoked labels, and the order to forget them in.
    tombstones: HashSet<NonZeroU64>,
    order: VecDeque<NonZeroU64>,
    max_tombstones: usize,
    /// Revoked labels whose input the ingress queue may still hold: input of the label at
    /// an ingress position before the end is dropped.
    fences: Vec<(NonZeroU64, u64)>,
    /// Ingress packets taken while `fences` is not empty: the position of the next one.
    processed: u64,
    /// Egress fences a revoke of the label could not record; a later revoke retries them.
    unfenced: Vec<(NonZeroU64, Fence)>,
    /// Revoked labels taken in this turn and not retired yet, with the states behind their
    /// receipts; empty between turns.
    pub(super) revoking: Vec<(NonZeroU64, Arc<FlowState>)>,
}

impl Labels {
    pub(super) fn new(max_tombstones: usize) -> Self {
        Self {
            tcp: HashMap::new(),
            tcp_labeled: 0,
            recent: Box::new([Recent::EMPTY; RECENT]),
            generation: 1,
            syns: Vec::new(),
            lifetimes: HashMap::new(),
            registered: 0,
            pruned: 0,
            tombstones: HashSet::new(),
            order: VecDeque::new(),
            max_tombstones,
            fences: Vec::new(),
            processed: 0,
            unfenced: Vec::new(),
            revoking: Vec::new(),
        }
    }

    /// Whether unlabeled TCP input must be looked up: some inbound lifetime has a label.
    pub(super) const fn tcp_labeled(&self) -> bool {
        self.tcp_labeled > 0
    }

    /// Whether input with `label` must pass [`Driver::admit_label`]: ingress positions are
    /// counted while some revoked label may still be queued, and labeled input is checked
    /// against the tombstones while there are any.
    pub(super) fn screens(&self, label: Option<NonZeroU64>) -> bool {
        !self.fences.is_empty() || (label.is_some() && !self.tombstones.is_empty())
    }

    /// Whether the TCP segment `packet` with `label` matches the label of its lifetime, or
    /// has no inbound lifetime. Segments of a connection read the table once while it does
    /// not change.
    pub(super) fn tcp_matches(&mut self, packet: &[u8], label: Option<NonZeroU64>) -> bool {
        let Some(raw) = RawTuple::of(packet) else {
            return true;
        };
        let slot = &mut self.recent[raw.slot()];
        let held = if slot.generation == self.generation && slot.tuple == raw {
            slot.held
        } else {
            let held = tcp_tuple(packet)
                .and_then(|tuple| self.tcp.get(&tuple))
                .map_or(Held::None, |entry| Held::Label(entry.label));
            *slot = Recent {
                generation: self.generation,
                tuple: raw,
                held,
            };
            held
        };
        match held {
            Held::None => true,
            Held::Label(held) => held == label,
        }
    }

    /// Whether an ICMP error with `label` quoting the segment from `local` to `remote` may
    /// apply: it is unlabeled, or labeled like the connection.
    pub(super) fn icmp_matches(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        label: Option<NonZeroU64>,
    ) -> bool {
        label.is_none()
            || self
                .tcp
                .get(&(remote, local))
                .is_none_or(|entry| entry.label == label)
    }

    /// Records the label of the bare SYN `packet` going into smoltcp, unless its tuple has
    /// a lifetime.
    pub(super) fn record_syn(&mut self, packet: &[u8], label: Option<NonZeroU64>) {
        let Some(tuple) = tcp_tuple(packet) else {
            return;
        };
        if self.tcp.contains_key(&tuple) {
            return;
        }
        self.insert(tuple, label, None);
        self.syns.push(tuple);
    }

    /// Binds the entry of `tuple` to the listener socket that took its SYN.
    pub(super) fn bind_socket(&mut self, tuple: Tuple, socket: SocketHandle) {
        match self.tcp.get_mut(&tuple) {
            Some(entry) => entry.socket = Some(socket),
            None => self.insert(tuple, None, Some(socket)),
        }
    }

    /// Forgets the SYNs of this turn that no listener socket took.
    pub(super) fn expire_syns(&mut self) {
        for tuple in std::mem::take(&mut self.syns) {
            if self
                .tcp
                .get(&tuple)
                .is_some_and(|entry| entry.socket.is_none())
            {
                self.remove(&tuple);
            }
        }
    }

    /// The label of the lifetime of `socket` on `tuple`.
    pub(super) fn socket_label(&self, tuple: Tuple, socket: SocketHandle) -> Option<NonZeroU64> {
        self.tcp
            .get(&tuple)
            .filter(|entry| entry.socket == Some(socket))
            .and_then(|entry| entry.label)
    }

    /// Forgets the entry of `tuple` when `socket`, its listener socket, is released.
    pub(super) fn release(&mut self, tuple: Tuple, socket: SocketHandle) {
        if self
            .tcp
            .get(&tuple)
            .is_some_and(|entry| entry.socket == Some(socket))
        {
            self.remove(&tuple);
        }
    }

    fn insert(&mut self, tuple: Tuple, label: Option<NonZeroU64>, socket: Option<SocketHandle>) {
        self.generation += 1;
        self.tcp_labeled += usize::from(label.is_some());
        if let Some(old) = self.tcp.insert(tuple, TcpEntry { label, socket }) {
            self.tcp_labeled -= usize::from(old.label.is_some());
        }
    }

    fn remove(&mut self, tuple: &Tuple) {
        self.generation += 1;
        if let Some(entry) = self.tcp.remove(tuple) {
            self.tcp_labeled -= usize::from(entry.label.is_some());
        }
    }

    /// Adds a lifetime to its label's, if it has one, pruning ended lifetimes once their
    /// number doubled since the last prune.
    pub(super) fn register(&mut self, flow: &Arc<FlowState>) {
        let Some(label) = flow.label() else {
            return;
        };
        if self.registered >= self.pruned.max(64).saturating_mul(2) {
            self.lifetimes.retain(|_, flows| {
                flows.retain(|flow| flow.strong_count() > 0);
                !flows.is_empty()
            });
            self.registered = self.lifetimes.values().map(Vec::len).sum();
            self.pruned = self.registered;
        }
        self.registered += 1;
        self.lifetimes
            .entry(label)
            .or_default()
            .push(Arc::downgrade(flow));
    }

    /// Records the tombstone of `label`, forgetting the oldest beyond the bound.
    fn bury(&mut self, label: NonZeroU64) {
        if self.max_tombstones == 0 || !self.tombstones.insert(label) {
            return;
        }
        self.order.push_back(label);
        while self.order.len() > self.max_tombstones {
            if let Some(oldest) = self.order.pop_front() {
                self.tombstones.remove(&oldest);
            }
        }
    }
}

impl Driver {
    /// Whether ingress input with `label` may go on: not queued before a revoke of its
    /// label, and not of a revoked label. Counts every packet while a fence exists.
    #[cold]
    #[inline(never)]
    pub(super) fn admit_label(&mut self, label: Option<NonZeroU64>) -> bool {
        let labels = &mut self.labels;
        if !labels.fences.is_empty() {
            let position = labels.processed;
            labels.processed += 1;
            let fenced = label.is_some_and(|label| {
                labels
                    .fences
                    .iter()
                    .any(|&(held, end)| held == label && position < end)
            });
            let processed = labels.processed;
            labels.fences.retain(|&(_, end)| processed < end);
            if fenced {
                stats::add(&self.stats.retired, 1);
                return false;
            }
        }
        if label.is_some_and(|label| labels.tombstones.contains(&label)) {
            stats::add(&self.stats.label_revoked, 1);
            return false;
        }
        true
    }

    /// Revokes the labels taken from the handles since the last turn, see
    /// [`revoke_label`](Self::revoke_label).
    pub(super) fn retire_labels(&mut self) {
        // Each receipt stays in `revoking` until its outcome is written, so a panic leaves
        // the rest to `Drop`, which reports them unknown. Oldest first: a full table fails
        // the later calls.
        self.labels.revoking.reverse();
        while let Some((label, receipt)) = self.labels.revoking.last().cloned() {
            let outcome = self.revoke_label(label);
            receipt.finish(outcome);
            self.labels.revoking.pop();
        }
    }

    /// Retires every lifetime of `label` at its stage, drops the label's input still in
    /// the stack and records its tombstone; `Failed` if a fence did not fit.
    fn revoke_label(&mut self, label: NonZeroU64) -> RetirementOutcome {
        self.labels.bury(label);
        let mut fenced = self.fence_ingress(label);
        if let Some(reassembler) = self.reassembler.as_mut() {
            reassembler.discard_tagged(label);
        }
        fenced &= self.retry_fences(label);
        let lifetimes = self.labels.lifetimes.remove(&label).unwrap_or_default();
        self.labels.registered -= lifetimes.len();
        for flow in lifetimes.iter().filter_map(Weak::upgrade) {
            // A lifetime revoked on its own is retired by its own revoke.
            if !flow.revoke_in_driver() {
                continue;
            }
            let outcome = match self.remove_lifetime(&flow) {
                Ok(()) => RetirementOutcome::Retired,
                Err(fence) => {
                    self.labels.unfenced.push((label, fence));
                    fenced = false;
                    RetirementOutcome::Failed
                }
            };
            flow.finish(outcome);
        }
        // Handshakes of lifetimes without state yet: listener sockets in SYN-RECEIVED on a
        // stack without `Admission::Decide`.
        let handshakes: Vec<(Tuple, SocketHandle)> = self
            .labels
            .tcp
            .iter()
            .filter(|(_, entry)| entry.label == Some(label))
            .filter_map(|(&tuple, entry)| entry.socket.map(|socket| (tuple, socket)))
            .filter(|(_, socket)| {
                self.inbound
                    .get(socket)
                    .is_some_and(|inbound| inbound.flow.is_none())
            })
            .collect();
        for ((remote, local), socket) in handshakes {
            let start = self.inbound.get(&socket).map_or(0, |inbound| inbound.start);
            self.release_handshake(socket);
            if let Err(fence) = self.purge_tcp(local, remote, start, self.position()) {
                self.labels.unfenced.push((label, fence));
                fenced = false;
            }
        }
        if fenced {
            RetirementOutcome::Retired
        } else {
            RetirementOutcome::Failed
        }
    }

    /// Holds back the input of `label` the ingress queue holds now; `false` if the table
    /// is full.
    fn fence_ingress(&mut self, label: NonZeroU64) -> bool {
        let queued = usize::from(self.carried.is_some()) + self.ingress.len();
        if queued == 0 {
            return true;
        }
        let labels = &mut self.labels;
        let end = labels.processed + queued as u64;
        let processed = labels.processed;
        labels.fences.retain(|&(_, end)| processed < end);
        if let Some((_, held)) = labels.fences.iter_mut().find(|(held, _)| *held == label) {
            *held = end;
            return true;
        }
        if labels.fences.len() >= ingress_fence_limit() {
            return false;
        }
        labels.fences.push((label, end));
        true
    }

    /// Records the egress fences an earlier revoke of `label` could not, and forgets the
    /// ones the source passed; `false` if one still does not fit.
    fn retry_fences(&mut self, label: NonZeroU64) -> bool {
        if self.labels.unfenced.is_empty() {
            return true;
        }
        let oldest = self.oldest_queued();
        let mut fitted = true;
        let mut kept = Vec::new();
        for (held, mut fence) in std::mem::take(&mut self.labels.unfenced) {
            if fence.passed(oldest) {
                continue;
            }
            if held != label {
                kept.push((held, fence));
                continue;
            }
            if let Err(fence) = self.fences.insert(fence) {
                fitted = false;
                kept.push((held, fence));
            }
        }
        self.labels.unfenced = kept;
        fitted
    }
}
