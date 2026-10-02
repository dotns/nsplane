//! [`FlowTracker`]: a pass-through [`PacketFilter`] counting traffic per flow.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{FiveTuple, IpPacket, PacketBuf, PeerId};

use crate::filter::reversed;

/// Identifies a flow with a peer, oriented remote -> local.
///
/// Inbound packets use their tuple as parsed; outbound packets use it with
/// addresses and ports swapped, so both directions of one flow share a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// The peer the flow runs through.
    pub peer: PeerId,
    /// The flow's five-tuple, source = remote end, destination = local end.
    pub tuple: FiveTuple,
}

/// Traffic counters of one flow. Bytes are IP packet lengths.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowStats {
    /// Packets received from the peer.
    pub rx_packets: u64,
    /// Bytes received from the peer.
    pub rx_bytes: u64,
    /// Packets sent to the peer.
    pub tx_packets: u64,
    /// Bytes sent to the peer.
    pub tx_bytes: u64,
}

#[derive(Debug, Default)]
struct FlowTable {
    /// Each flow's counters and the sequence number of its last update.
    flows: HashMap<FlowKey, (FlowStats, u64)>,
    next_seq: u64,
}

/// A [`PacketFilter`] that accepts every packet and counts traffic per flow.
///
/// The table holds at most `capacity` flows (at least 1); a new flow arriving
/// when it is full evicts the least recently seen flow, found by an
/// O(capacity) scan. Packets without a five-tuple (non-first fragments,
/// malformed or truncated packets) are counted as untracked.
///
/// Clones share all state, so one clone can go to the engine and another can
/// read the flows.
#[derive(Debug, Clone)]
pub struct FlowTracker {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    capacity: usize,
    table: Mutex<FlowTable>,
    evictions: AtomicU64,
    untracked: AtomicU64,
}

impl FlowTracker {
    /// A tracker holding at most `capacity` flows (at least 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                capacity: capacity.max(1),
                table: Mutex::default(),
                evictions: AtomicU64::new(0),
                untracked: AtomicU64::new(0),
            }),
        }
    }

    /// The counters of the flow `key`, if tracked.
    pub fn flow(&self, key: &FlowKey) -> Option<FlowStats> {
        self.table().flows.get(key).map(|(stats, _)| *stats)
    }

    /// Every tracked flow with its counters, in no particular order.
    pub fn flows(&self) -> Vec<(FlowKey, FlowStats)> {
        self.table()
            .flows
            .iter()
            .map(|(key, (stats, _))| (*key, *stats))
            .collect()
    }

    /// Number of tracked flows.
    pub fn len(&self) -> usize {
        self.table().flows.len()
    }

    /// Whether no flow is tracked.
    pub fn is_empty(&self) -> bool {
        self.table().flows.is_empty()
    }

    /// Flows evicted because the table was full.
    pub fn evictions(&self) -> u64 {
        self.inner.evictions.load(Ordering::Relaxed)
    }

    /// Packets that had no five-tuple and were not tracked.
    pub fn untracked(&self) -> u64 {
        self.inner.untracked.load(Ordering::Relaxed)
    }

    /// Forget every flow. The eviction and untracked counters are kept.
    pub fn clear(&self) {
        self.table().flows.clear();
    }

    fn table(&self) -> std::sync::MutexGuard<'_, FlowTable> {
        self.inner
            .table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, peer: PeerId, packet: &PacketBuf, inbound: bool) {
        let tuple = IpPacket::parse(packet.as_packet())
            .ok()
            .and_then(|p| p.five_tuple());
        let Some(tuple) = tuple else {
            self.inner.untracked.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let key = FlowKey {
            peer,
            tuple: if inbound { tuple } else { reversed(tuple) },
        };
        let bytes = u64::try_from(packet.len()).unwrap_or(u64::MAX);

        let mut table = self.table();
        if !table.flows.contains_key(&key) && table.flows.len() >= self.inner.capacity {
            let oldest = table
                .flows
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                table.flows.remove(&oldest);
                self.inner.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        let seq = table.next_seq;
        table.next_seq += 1;
        let (stats, last) = table.flows.entry(key).or_default();
        *last = seq;
        if inbound {
            stats.rx_packets += 1;
            stats.rx_bytes += bytes;
        } else {
            stats.tx_packets += 1;
            stats.tx_bytes += bytes;
        }
    }
}

impl PacketFilter for FlowTracker {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.record(peer, packet, true);
        Verdict::Accept
    }

    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.record(peer, packet, false);
        Verdict::Accept
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use nsplane_packet::protocol;

    use super::*;
    use crate::test_packets::{Frag, ip_frag, tcp_packet, udp_packet};

    const PEER: PeerId = PeerId::new(1);

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn remote() -> IpAddr {
        addr("10.0.0.1")
    }

    fn local() -> IpAddr {
        addr("10.0.0.2")
    }

    fn key(peer: PeerId, sport: u16, dport: u16) -> FlowKey {
        FlowKey {
            peer,
            tuple: FiveTuple {
                src: remote(),
                dst: local(),
                protocol: protocol::TCP,
                src_port: sport,
                dst_port: dport,
            },
        }
    }

    fn inbound(t: &FlowTracker, peer: PeerId, mut packet: PacketBuf) {
        assert_eq!(t.inbound(peer, &mut packet), Verdict::Accept);
    }

    fn outbound(t: &FlowTracker, peer: PeerId, mut packet: PacketBuf) {
        assert_eq!(t.outbound(peer, &mut packet), Verdict::Accept);
    }

    #[test]
    fn both_directions_share_a_key() {
        let t = FlowTracker::new(16);
        let rx = tcp_packet(remote(), 4000, local(), 80);
        let rx_len = u64::try_from(rx.len()).unwrap();
        inbound(&t, PEER, rx);
        inbound(&t, PEER, tcp_packet(remote(), 4000, local(), 80));
        let tx = tcp_packet(local(), 80, remote(), 4000);
        let tx_len = u64::try_from(tx.len()).unwrap();
        outbound(&t, PEER, tx);
        assert_eq!(t.len(), 1);
        assert_eq!(
            t.flow(&key(PEER, 4000, 80)),
            Some(FlowStats {
                rx_packets: 2,
                rx_bytes: 2 * rx_len,
                tx_packets: 1,
                tx_bytes: tx_len,
            })
        );
    }

    #[test]
    fn distinct_flows() {
        let t = FlowTracker::new(16);
        inbound(&t, PEER, tcp_packet(remote(), 4000, local(), 80));
        inbound(&t, PEER, tcp_packet(remote(), 4001, local(), 80));
        inbound(&t, PeerId::new(2), tcp_packet(remote(), 4000, local(), 80));
        inbound(&t, PEER, udp_packet(remote(), 4000, local(), 80));
        assert_eq!(t.len(), 4);
        assert_eq!(t.flows().len(), 4);
        assert_eq!(t.flow(&key(PEER, 4001, 80)).unwrap().rx_packets, 1);
        assert!(t.flow(&key(PEER, 4002, 80)).is_none());
    }

    #[test]
    fn evicts_least_recently_seen() {
        let t = FlowTracker::new(2);
        inbound(&t, PEER, tcp_packet(remote(), 1, local(), 80));
        inbound(&t, PEER, tcp_packet(remote(), 2, local(), 80));
        // Touch flow 1 so flow 2 is the least recently seen.
        outbound(&t, PEER, tcp_packet(local(), 80, remote(), 1));
        inbound(&t, PEER, tcp_packet(remote(), 3, local(), 80));
        assert_eq!(t.evictions(), 1);
        assert_eq!(t.len(), 2);
        assert!(t.flow(&key(PEER, 1, 80)).is_some());
        assert!(t.flow(&key(PEER, 2, 80)).is_none());
        assert!(t.flow(&key(PEER, 3, 80)).is_some());
    }

    #[test]
    fn untracked_packets() {
        let t = FlowTracker::new(16);
        let frag = ip_frag(
            remote(),
            local(),
            protocol::TCP,
            &[0; 8],
            Some(Frag {
                id: 1,
                offset_units: 4,
                more: false,
            }),
        );
        inbound(&t, PEER, frag);
        outbound(&t, PEER, PacketBuf::from_packet(&[0x45]));
        assert_eq!(t.untracked(), 2);
        assert!(t.is_empty());
    }

    #[test]
    fn clear_and_shared_clones() {
        let t = FlowTracker::new(16);
        let handle = t.clone();
        inbound(&t, PEER, tcp_packet(remote(), 4000, local(), 80));
        assert_eq!(handle.len(), 1);
        handle.clear();
        assert!(t.is_empty());
    }
}
