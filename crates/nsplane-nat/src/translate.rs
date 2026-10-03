//! The stateless IPv4 <-> IPv6 translator (RFC 7915), as a [`PacketFilter`].
//!
//! [`Translator`] rewrites packets in place according to a
//! [`TranslationTable`]: local applications use IPv4 (and IPv6 aliases),
//! the tunnel carries IPv6 only.
//!
//! # Outbound (local -> tunnel, after the core routed the packet to `peer`)
//!
//! - IPv4 to a peer's `alias4` -> IPv6 to that peer's `node4`.
//! - IPv4 into a LAN prefix behind a peer -> IPv6 to the paired `lan6` address.
//! - In both cases the source must be `self4` (-> the self `node4`) or inside a
//!   local LAN prefix (-> its `lan6` address), and the destination mapping
//!   must belong to `peer`; otherwise the packet is dropped.
//! - IPv6 to a peer's `alias6` -> destination rewritten to its `node6`.
//! - Everything else passes unchanged, so native IPv4 and IPv6 tunnels keep
//!   working.
//!
//! # Inbound (tunnel -> local, after decryption)
//!
//! - IPv6 to the self `node4` or into a local `lan6` prefix -> IPv4 to `self4`
//!   or the paired `lan4` address. The source must be `peer`'s `node4`
//!   (-> its `alias4`) or inside a `lan6` prefix behind `peer` (-> `lan4`).
//! - IPv6 from `peer`'s `node6`, when the peer has an `alias6` -> source
//!   rewritten to the `alias6`.
//! - A packet whose source is one of this node's local-view addresses (an
//!   `alias4`, an address inside a LAN IPv4 prefix, an `alias6`) is a spoof and
//!   is dropped.
//! - Everything else passes unchanged.
//!
//! # Translation
//!
//! Headers are translated as RFC 7915 describes: the TTL / hop limit is
//! decremented (a packet that would reach zero is dropped), the traffic class
//! is copied, the flow label is zero, IPv4 options are dropped (an unexhausted
//! source route is refused), IPv6 extension headers are skipped (a routing
//! header with segments left is refused) and DF is set on translated IPv4
//! packets above 1260 bytes. TCP and UDP checksums are verified and moved to
//! the new pseudo-header incrementally. ICMP echo and errors are mapped to
//! `ICMPv6` and back, including the MTU of fragmentation needed / Packet Too
//! Big (adjusted by the 20-byte header difference) and the parameter problem
//! pointer; the packet quoted in an error is translated in the reverse
//! direction through the same table.
//!
//! IPv4 fragments become IPv6 fragments with a fragment header (the 16-bit
//! identification, offset and M flag; RFC 7915 section 5.1.1) and IPv6
//! fragments become IPv4 fragments. A fragmented IPv4 UDP datagram without a
//! checksum is reassembled first, since IPv6 needs a checksum over the whole
//! datagram; the reassembled packet is sent unfragmented. Only fragments
//! that follow the first one are joined: a later fragment that arrives
//! before its first fragment is translated on its own, so such a datagram
//! cannot complete. Pending fragments are consumed ([`Verdict::Handled`]).
//!
//! A translated IPv4 packet grows by 20 bytes (28 with a fragment header),
//! in place when the packet buffer's capacity allows it. A packet without
//! that room (e.g. from [`PacketBuf::from_packet`] or
//! [`PacketBuf::from_shared`]) is copied into a fresh buffer with the
//! standard headroom and translated there, which
//! [`TranslatorStats::grown_copies`] counts; sources that leave 28 bytes of
//! room past the MTU keep translation in place. Callers that fragment IPv4
//! before the core can use [`Translator::ipv4_translated_predicate`] to
//! reserve the 28 bytes only for translated destinations.
//!
//! # Routing and filter order
//!
//! The core routes a local packet by its destination before the filters run,
//! and checks a decrypted packet's source against the peer's allowed IPs
//! before them. So each peer's allowed IPs must contain its `alias4/32`, the
//! LAN IPv4 prefixes behind it (for outbound routing), its `alias6` if any,
//! and as usual its `node4`, `node6` and the `lan6` prefixes behind it (for
//! the inbound source check).
//!
//! The core's filter chain is an onion: filters are installed from the wire
//! side to the local side, decrypted packets run through them in install
//! order and local packets in reverse. Install the translator **last**, next
//! to the local side; the recommended stack is
//! `[AclFilter, PortMap, Translator]`. The ACL and the `PortMap` then see
//! tunnel-side IPv6 in both directions: inbound before the translator maps
//! the peer's real `node4`/`node6`/`lan6` addresses (which policies and
//! source assertions name) to node-local aliases (which differ per node),
//! outbound after it has mapped the local view back. Policies need no rules
//! for the IPv4 aliases, and the ACL's stateful-reply tracking matches the
//! replies of translated flows, because it records and looks up the same
//! IPv6 five-tuple both ways.

mod fragment;
mod icmp;
mod parse;
pub mod reasons;
mod rfc7915;
#[cfg(test)]
mod tests;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use arc_swap::ArcSwap;
use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{PacketBuf, PeerId};

use crate::TranslationTable;
use fragment::{Limits, Reassembly};
use parse::addr6;
use rfc7915::{Context, Done};

/// A translation result: the drop reason on error.
type Result<T> = std::result::Result<T, &'static str>;

/// Bounds of the zero-checksum UDP reassembly.
const REASSEMBLY_LIMITS: Limits = Limits {
    max_entries: 256,
    max_bytes: 1 << 20,
};

/// What the translator did with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    /// Not a translated packet: passed unchanged.
    Pass,
    /// Translated between IPv4 and IPv6.
    Translated,
    /// An IPv6 address rewritten between `alias6` and `node6`.
    Rewritten,
    /// A fragment stored for reassembly.
    Pending,
}

impl From<Done> for Action {
    fn from(done: Done) -> Self {
        match done {
            Done::Translated => Self::Translated,
            Done::Pending => Self::Pending,
        }
    }
}

/// Counters of one direction.
#[derive(Debug, Default)]
struct DirectionCounters {
    translated: AtomicU64,
    rewritten: AtomicU64,
    dropped: AtomicU64,
}

impl DirectionCounters {
    fn count(&self, result: Result<Action>) -> Verdict {
        let counter = match result {
            Ok(Action::Pass) => return Verdict::Accept,
            Ok(Action::Pending) => return Verdict::Handled,
            Ok(Action::Translated) => &self.translated,
            Ok(Action::Rewritten) => &self.rewritten,
            Err(_) => &self.dropped,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        match result {
            Err(reason) => Verdict::Drop { reason },
            Ok(_) => Verdict::Accept,
        }
    }
}

/// A snapshot of a [`Translator`]'s counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TranslatorStats {
    /// Outbound IPv4 packets translated to IPv6.
    pub translated_out: u64,
    /// Inbound IPv6 packets translated to IPv4.
    pub translated_in: u64,
    /// Outbound IPv6 packets whose `alias6` destination became `node6`.
    pub rewritten_out: u64,
    /// Inbound IPv6 packets whose `node6` source became `alias6`.
    pub rewritten_in: u64,
    /// Outbound packets dropped.
    pub dropped_out: u64,
    /// Inbound packets dropped.
    pub dropped_in: u64,
    /// Zero-checksum UDP datagrams reassembled from IPv4 fragments.
    pub reassembled: u64,
    /// Packets, in either direction, whose buffer had no room for the
    /// translation and were copied into a larger one (the slow path).
    pub grown_copies: u64,
}

/// Stateless IPv4 <-> IPv6 translation filter; see the [module docs](self).
///
/// The table can be replaced at any time with [`store`](Self::store); a
/// packet is translated with either the old or the new table, never a mix.
#[derive(Debug)]
pub struct Translator {
    table: Arc<ArcSwap<TranslationTable>>,
    reassembly: Mutex<Reassembly>,
    epoch: Instant,
    outbound: DirectionCounters,
    inbound: DirectionCounters,
    grown_copies: AtomicU64,
}

impl Translator {
    /// A translator driven by `table`.
    pub fn new(table: TranslationTable) -> Self {
        Self {
            table: Arc::new(ArcSwap::from_pointee(table)),
            reassembly: Mutex::new(Reassembly::new(REASSEMBLY_LIMITS)),
            epoch: Instant::now(),
            outbound: DirectionCounters::default(),
            inbound: DirectionCounters::default(),
            grown_copies: AtomicU64::new(0),
        }
    }

    /// Replaces the table atomically; packets in flight see the old or the new one.
    pub fn store(&self, table: TranslationTable) {
        self.table.store(Arc::new(table));
    }

    /// The current table.
    pub fn table(&self) -> Arc<TranslationTable> {
        self.table.load_full()
    }

    /// Returns a predicate that is true for the IPv4 destinations this
    /// translator turns into IPv6 (a peer's `alias4`, or an address inside a
    /// LAN prefix behind a peer), always reading the current table: it
    /// follows later [`store`](Self::store) calls.
    pub fn ipv4_translated_predicate(&self) -> Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync> {
        let table = Arc::clone(&self.table);
        Arc::new(move |dst| translated_ipv4(&table.load(), dst))
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> TranslatorStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let reassembly = self
            .reassembly
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .counters();
        TranslatorStats {
            translated_out: load(&self.outbound.translated),
            translated_in: load(&self.inbound.translated),
            rewritten_out: load(&self.outbound.rewritten),
            rewritten_in: load(&self.inbound.rewritten),
            dropped_out: load(&self.outbound.dropped),
            dropped_in: load(&self.inbound.dropped),
            reassembled: reassembly.completed,
            grown_copies: load(&self.grown_copies),
        }
    }

    /// Counts a packet whose buffer the translation replaced: a grown copy
    /// starts at a new address.
    fn count_grown(&self, start: *const u8, packet: &PacketBuf) {
        if packet.as_packet().as_ptr() != start {
            self.grown_copies.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn outbound_v4(
        &self,
        table: &TranslationTable,
        peer: PeerId,
        packet: &mut PacketBuf,
    ) -> Result<Action> {
        let Some((src, dst)) = addrs4(packet.as_packet()) else {
            return Ok(Action::Pass);
        };
        let dst6 = if let Some((owner, mapping)) = table.by_alias4(dst) {
            same_peer(owner, peer)?;
            mapping.node4
        } else if let Some((lan6, Some(owner))) = table.lan4_to_lan6(dst) {
            same_peer(owner, peer)?;
            lan6
        } else {
            return Ok(Action::Pass);
        };
        let src6 = local4_to_6(table, src).ok_or(reasons::UNMAPPED)?;
        let cx = Context {
            table,
            reassembly: &self.reassembly,
            now: self.epoch.elapsed().as_secs(),
        };
        rfc7915::v4_to_v6(packet, src6, dst6, cx).map(Action::from)
    }
}

impl PacketFilter for Translator {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let table = self.table.load();
        let start = packet.as_packet().as_ptr();
        let result = match packet.as_packet().first().map(|byte| byte >> 4) {
            Some(4) => inbound_v4(&table, packet),
            Some(6) => inbound_v6(&table, peer, packet),
            _ => Ok(Action::Pass),
        };
        self.count_grown(start, packet);
        self.inbound.count(result)
    }

    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let table = self.table.load();
        let start = packet.as_packet().as_ptr();
        let result = match packet.as_packet().first().map(|byte| byte >> 4) {
            Some(4) => self.outbound_v4(&table, peer, packet),
            Some(6) => outbound_v6(&table, peer, packet),
            _ => Ok(Action::Pass),
        };
        self.count_grown(start, packet);
        self.outbound.count(result)
    }
}

fn outbound_v6(table: &TranslationTable, peer: PeerId, packet: &mut PacketBuf) -> Result<Action> {
    let Some((src, dst)) = addrs6(packet.as_packet()) else {
        return Ok(Action::Pass);
    };
    let Some((owner, mapping)) = table.by_alias6(dst) else {
        return Ok(Action::Pass);
    };
    same_peer(owner, peer)?;
    let quoted = |addr| table.by_alias6(addr).map(|(_, mapping)| mapping.node6);
    rfc7915::rewrite_v6(packet, src, mapping.node6, &quoted)?;
    Ok(Action::Rewritten)
}

fn inbound_v4(table: &TranslationTable, packet: &PacketBuf) -> Result<Action> {
    let Some((src, _)) = addrs4(packet.as_packet()) else {
        return Ok(Action::Pass);
    };
    if table.by_alias4(src).is_some() || table.lan4_to_lan6(src).is_some() {
        return Err(reasons::SPOOFED_SOURCE);
    }
    Ok(Action::Pass)
}

fn inbound_v6(table: &TranslationTable, peer: PeerId, packet: &mut PacketBuf) -> Result<Action> {
    let Some((src, dst)) = addrs6(packet.as_packet()) else {
        return Ok(Action::Pass);
    };
    if table.by_alias6(src).is_some() {
        return Err(reasons::SPOOFED_SOURCE);
    }
    if let Some(dst4) = local6_to_4(table, dst) {
        let src4 = peer6_to_4(table, peer, src)?;
        rfc7915::v6_to_v4(packet, src4, dst4, table)?;
        return Ok(Action::Translated);
    }
    match table.by_node6(src) {
        Some((owner, mapping)) if owner == peer => {
            let Some(alias6) = mapping.alias6 else {
                return Ok(Action::Pass);
            };
            let quoted = |addr| table.by_node6(addr).and_then(|(_, mapping)| mapping.alias6);
            rfc7915::rewrite_v6(packet, alias6, dst, &quoted)?;
            Ok(Action::Rewritten)
        }
        _ => Ok(Action::Pass),
    }
}

/// Whether `dst` is an IPv4 destination the translator turns into IPv6.
fn translated_ipv4(table: &TranslationTable, dst: Ipv4Addr) -> bool {
    table.by_alias4(dst).is_some()
        || table
            .lan4_to_lan6(dst)
            .is_some_and(|(_, owner)| owner.is_some())
}

fn same_peer(owner: PeerId, peer: PeerId) -> Result<()> {
    if owner == peer {
        Ok(())
    } else {
        Err(reasons::PEER_MISMATCH)
    }
}

/// Maps a local IPv4 source (`self4` or the local LAN) to IPv6.
fn local4_to_6(table: &TranslationTable, addr: Ipv4Addr) -> Option<Ipv6Addr> {
    if let Some(own) = table.self_mapping()
        && own.self4 == addr
    {
        return Some(own.node4);
    }
    match table.lan4_to_lan6(addr) {
        Some((lan6, None)) => Some(lan6),
        _ => None,
    }
}

/// Maps a local IPv6 destination (the self `node4` or the local LAN) to IPv4.
fn local6_to_4(table: &TranslationTable, addr: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(own) = table.self_mapping()
        && own.node4 == addr
    {
        return Some(own.self4);
    }
    match table.lan6_to_lan4(addr) {
        Some((lan4, None)) => Some(lan4),
        _ => None,
    }
}

/// Maps the IPv6 source of a packet from `peer` to IPv4: its `node4` to its
/// `alias4`, or an address of a LAN behind it to `lan4`.
fn peer6_to_4(table: &TranslationTable, peer: PeerId, addr: Ipv6Addr) -> Result<Ipv4Addr> {
    if let Some((owner, mapping)) = table.by_node4(addr) {
        same_peer(owner, peer)?;
        return mapping.alias4.ok_or(reasons::UNMAPPED);
    }
    match table.lan6_to_lan4(addr) {
        Some((lan4, Some(owner))) => same_peer(owner, peer).map(|()| lan4),
        Some((_, None)) => Err(reasons::SPOOFED_SOURCE),
        None => Err(reasons::UNMAPPED),
    }
}

/// Maps any IPv4 address of the table to IPv6 (for packets quoted in ICMP errors).
fn map4to6(table: &TranslationTable, addr: Ipv4Addr) -> Option<Ipv6Addr> {
    if let Some(own) = table.self_mapping()
        && own.self4 == addr
    {
        return Some(own.node4);
    }
    table
        .by_alias4(addr)
        .map(|(_, mapping)| mapping.node4)
        .or_else(|| table.lan4_to_lan6(addr).map(|(lan6, _)| lan6))
}

/// Maps any IPv6 address of the table to IPv4 (for packets quoted in ICMP errors).
fn map6to4(table: &TranslationTable, addr: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(own) = table.self_mapping()
        && own.node4 == addr
    {
        return Some(own.self4);
    }
    table
        .by_node4(addr)
        .and_then(|(_, mapping)| mapping.alias4)
        .or_else(|| table.lan6_to_lan4(addr).map(|(lan4, _)| lan4))
}

/// The source and destination of an IPv4 packet, if it holds a full header.
fn addrs4(bytes: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let header = bytes.get(..20)?;
    let addr =
        |at: usize| Ipv4Addr::new(header[at], header[at + 1], header[at + 2], header[at + 3]);
    Some((addr(12), addr(16)))
}

/// The source and destination of an IPv6 packet, if it holds a full header.
fn addrs6(bytes: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
    let header = bytes.get(..40)?;
    Some((addr6(&header[8..24]), addr6(&header[24..40])))
}
