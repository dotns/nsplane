//! Drop counters.

use std::sync::atomic::{AtomicU64, Ordering};

/// A snapshot of the stack's drop counters, one per reason.
///
/// Every packet, datagram or connection the stack discards is counted in exactly one
/// field. Counters only grow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetStackStats {
    /// Ingress packets that are not a parseable IPv4/IPv6 packet, or whose TCP/UDP header
    /// is truncated or inconsistent.
    pub malformed: u64,
    /// Ingress packets whose destination is not one of the stack's addresses.
    pub no_address: u64,
    /// Ingress packets of a protocol other than TCP or UDP, and IPv4 fragments.
    pub unsupported: u64,
    /// Bare SYNs beyond the listener pool; the stack answers them with RST.
    pub syn_refused: u64,
    /// Accepted TCP connections dropped because `incoming_tcp` was full or not consumed
    /// (without `accept_backpressure`), or gone.
    pub tcp_not_accepted: u64,
    /// Bare SYNs left unanswered because `incoming_tcp` was full, with
    /// `NetStackConfig::accept_backpressure`; the peer retransmits them.
    pub syn_deferred: u64,
    /// Datagrams dropped because their UDP flow or bound socket queue was full.
    pub udp_queue_full: u64,
    /// Datagrams dropped because opening their flow would exceed the flow limit.
    pub udp_flow_limit: u64,
    /// New UDP flows dropped because `incoming_udp` was full or not consumed.
    pub udp_not_accepted: u64,
    /// Packets the stack produced while its egress backlog was full.
    pub egress_full: u64,
}

/// The live counters behind [`NetStackStats`].
#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub(crate) malformed: AtomicU64,
    pub(crate) no_address: AtomicU64,
    pub(crate) unsupported: AtomicU64,
    pub(crate) syn_refused: AtomicU64,
    pub(crate) tcp_not_accepted: AtomicU64,
    pub(crate) syn_deferred: AtomicU64,
    pub(crate) udp_queue_full: AtomicU64,
    pub(crate) udp_flow_limit: AtomicU64,
    pub(crate) udp_not_accepted: AtomicU64,
    pub(crate) egress_full: AtomicU64,
}

/// Adds `n` to `counter`.
pub(crate) fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

impl Counters {
    /// The current values.
    pub(crate) fn snapshot(&self) -> NetStackStats {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        NetStackStats {
            malformed: get(&self.malformed),
            no_address: get(&self.no_address),
            unsupported: get(&self.unsupported),
            syn_refused: get(&self.syn_refused),
            tcp_not_accepted: get(&self.tcp_not_accepted),
            syn_deferred: get(&self.syn_deferred),
            udp_queue_full: get(&self.udp_queue_full),
            udp_flow_limit: get(&self.udp_flow_limit),
            udp_not_accepted: get(&self.udp_not_accepted),
            egress_full: get(&self.egress_full),
        }
    }
}
