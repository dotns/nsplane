//! Drop counters.

use std::sync::atomic::{AtomicU64, Ordering};

/// A snapshot of the stack's drop counters, one per reason.
///
/// Every packet, datagram or connection the stack discards is counted in exactly one
/// field; with [`NetStackConfig::reassembly`](crate::NetStackConfig::reassembly) the
/// reassembly counters also count datagrams completed. Counters only grow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetStackStats {
    /// Ingress packets that are not a parseable IPv4/IPv6 packet, or whose TCP/UDP header
    /// is truncated or inconsistent.
    pub malformed: u64,
    /// Ingress packets whose destination is not one of the stack's addresses.
    pub no_address: u64,
    /// Ingress packets of a protocol other than TCP or UDP (ICMP and `ICMPv6` included,
    /// except the messages counted in [`icmp_ignored`](Self::icmp_ignored) and those
    /// applied), and (without
    /// [`NetStackConfig::reassembly`](crate::NetStackConfig::reassembly)) IPv4 fragments
    /// and IPv6 Fragment-header packets.
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
    /// Datagrams reassembled from fragments and handed on as one packet. Always 0 without
    /// [`NetStackConfig::reassembly`](crate::NetStackConfig::reassembly).
    pub reassembled: u64,
    /// Incomplete datagrams discarded with their fragments after the reassembly timeout.
    /// Always 0 without [`NetStackConfig::reassembly`](crate::NetStackConfig::reassembly).
    pub reassembly_timeout: u64,
    /// Fragments dropped at the reassembly bounds: a fragment of a further datagram once
    /// `max_datagrams` are held, or one that grows its datagram beyond `max_bytes` (the
    /// datagram's held fragments go with it). Fragments the reassembler rejects as
    /// invalid or overlapping count as [`malformed`](Self::malformed). Also counts the
    /// fragments dropped after
    /// [`NetStackHandle::discard_fragments`](crate::NetStackHandle::discard_fragments).
    /// Always 0 without [`NetStackConfig::reassembly`](crate::NetStackConfig::reassembly).
    pub reassembly_overflow: u64,
    /// ICMP Fragmentation Needed and `ICMPv6` Packet Too Big messages the stack did not
    /// apply to one of its TCP connections: the quote is not a TCP segment the stack sent
    /// within the unacknowledged range of a live connection, or the MTU is 0, below the
    /// family's minimum (576 for IPv4, 1280 for IPv6), or not below the configured MTU
    /// and the connection's current path MTU. Applied messages are not counted.
    pub icmp_ignored: u64,
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
    pub(crate) reassembled: AtomicU64,
    pub(crate) reassembly_timeout: AtomicU64,
    pub(crate) reassembly_overflow: AtomicU64,
    pub(crate) icmp_ignored: AtomicU64,
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
            reassembled: get(&self.reassembled),
            reassembly_timeout: get(&self.reassembly_timeout),
            reassembly_overflow: get(&self.reassembly_overflow),
            icmp_ignored: get(&self.icmp_ignored),
        }
    }
}
