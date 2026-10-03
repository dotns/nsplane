//! Local-side IPv6 masquerade (`Masquerade`): stateful source NAPT of routed
//! LAN ingress, with the reverse restore of the replies.
//!
//! A [`Masquerade`] rewrites the IPv6 flows a LAN host opens (say
//! `fd00:aa::10` port 10 000 to `fd00:1:2:1::b01` port 53) to a source the
//! caller picks per flow (say the gateway's return identity
//! `fd00:1:2:2::6440:1`) and a source port allocated from a range, so the
//! replies come back to this node; ported from ns `subnet/ingress.rs`
//! (`SubnetLanIngressTranslator`):
//!
//! - **Forward** ([`Masquerade::forward`]): an IPv6 TCP, UDP or `ICMPv6`
//!   Echo request (type 128) packet of an untracked flow asks the decision
//!   closure once. [`Some`] gives the flow's source
//!   ([`MasqueradeDecision::source`]) and a `route` fingerprint; the packet's
//!   source address becomes that source and its source port (TCP/UDP) or Echo
//!   identifier becomes a token from [`MasqueradeConfig::ports`], and the
//!   flow is recorded. [`None`] passes the packet unchanged and records
//!   nothing. Later packets of the flow reuse its source and token without
//!   asking again.
//! - **Reverse** ([`Masquerade::reverse`]): a reply of a recorded flow (TCP
//!   or UDP from the original destination to the source and token, or an
//!   `ICMPv6` Echo reply, type 129, with the token as its identifier) gets
//!   the LAN host's address and port or identifier back as its destination.
//!   Before that, the decision closure is asked again with the flow's
//!   original tuple: when it answers [`None`] or another `route`, the flow is
//!   removed and the reply dropped ([`reasons::ROUTE_CHANGED`]), ns's "route
//!   fingerprint must remain current" rule.
//! - Everything else passes unchanged ([`MasqueradeVerdict::Pass`]): IPv4,
//!   IPv6 with extension headers (fragments included), other protocols and
//!   `ICMPv6` types, unparsable packets, packets whose length differs from
//!   their IPv6 payload length, and replies of unknown flows. ns drops these.
//!
//! The transport checksum of a rewritten packet is recomputed over the IPv6
//! pseudo-header, as ns (a result of zero is written as `0xffff`). With
//! [`MasqueradeConfig::verify_checksums`], a forward packet with an invalid
//! transport checksum (a zero checksum field included) is dropped
//! ([`reasons::BAD_CHECKSUM`]) before the decision closure is asked, and so
//! is a reply of a recorded flow; the recomputation would otherwise launder
//! the corruption. ns verifies every packet the same way.
//!
//! # Flows
//!
//! A flow is keyed by its first packet's protocol, addresses and ports (the
//! Echo identifier as the source port of an Echo request). Its token is
//! unique per (protocol, original destination, destination port, source), so
//! replies map back to exactly one flow. Tokens are searched from a cursor
//! that walks [`MasqueradeConfig::ports`] and wraps from its end to its
//! start, as ns; after [`MasqueradeConfig::tries`] tokens in use the packet
//! is dropped ([`reasons::TOKENS_EXHAUSTED`]).
//!
//! - **Idle timeouts** per protocol (TCP, UDP, `ICMPv6`); every hit in either
//!   direction refreshes a flow. Expiry is lazy: an expired flow goes when a
//!   packet finds it, when its token is needed, when the table is full and
//!   by [`Masquerade::len`]. ns sweeps the whole table on every packet.
//! - **Bounded**: a new flow when [`MasqueradeConfig::max_flows`] flows are
//!   live is dropped ([`reasons::CAPACITY`]); no flow is evicted, matching
//!   ns.
//! - **TCP**: with [`MasqueradeConfig::tcp_new_flow_requires_syn`], only a
//!   SYN (SYN set, ACK clear) opens a flow; another TCP packet the closure
//!   would masquerade without a flow is dropped ([`reasons::TCP_NOT_SYN`]).
//!   TCP flows keep no state beyond their idle time.
//! - Unlike ns, the forward direction does not ask the decision closure
//!   again for a recorded flow; a changed route is noticed on the next reply.
//!
//! The flows do not live in a [`Conntrack`](crate::Conntrack): a full
//! `Conntrack` evicts its least recently seen flow, while the masquerade must
//! refuse new flows instead, and it stores no per-flow route or token. The
//! masquerade keeps a small table of its own (two hash maps behind one
//! mutex).
//!
//! # Drops
//!
//! A [`MasqueradeVerdict::Drop`] carries one of the [`reasons`], each
//! counted in [`MasqueradeStats`]: [`reasons::TCP_NOT_SYN`],
//! [`reasons::CAPACITY`], [`reasons::ROUTE_CHANGED`],
//! [`reasons::TOKENS_EXHAUSTED`] and [`reasons::BAD_CHECKSUM`]. ns drops in
//! all five cases; `bad_checksum` is the one the contract did not list. The
//! new source is an [`Ipv6Addr`], so the closure cannot answer a source the
//! masquerade could not write.
//!
//! # Concurrency
//!
//! All methods take `&self`, and a `Masquerade` is `Send + Sync`. The
//! decision closure never runs while the table lock is held, so it may call
//! back into the `Masquerade`. When the first packets of one flow race on two
//! threads, both may ask the closure, but only one flow is recorded: the
//! loser finds the winner's flow under the lock and takes its source and
//! token.

pub mod reasons;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use nsplane_packet::checksum::transport_checksum_v6;
use nsplane_packet::{FiveTuple, PacketBuf, protocol};

/// Length of the IPv6 fixed header.
const IPV6_HEADER: usize = 40;
/// Offset of the source address in the IPv6 header.
const SRC_ADDR: usize = 8;
/// Offset of the destination address in the IPv6 header.
const DST_ADDR: usize = 24;
/// `ICMPv6` Echo request and reply types.
const ECHO_REQUEST: u8 = 128;
const ECHO_REPLY: u8 = 129;
/// TCP flag bits as found in byte 13 of the TCP header.
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// The decision closure of a [`Masquerade`].
type Decide = Box<dyn Fn(&FiveTuple) -> Option<MasqueradeDecision> + Send + Sync>;

/// How to masquerade a new flow, as answered by the decision closure of a
/// [`Masquerade`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MasqueradeDecision {
    /// The flow's new source address.
    pub source: Ipv6Addr,
    /// A fingerprint of the route the flow takes. A reply is restored only
    /// while the closure still answers the same `route` for the flow.
    pub route: u64,
}

/// Settings of a [`Masquerade`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueradeConfig {
    /// The source ports (TCP/UDP) and Echo identifiers (`ICMPv6`) handed out
    /// as tokens. Default `49152..=65535`, as ns.
    pub ports: RangeInclusive<u16>,
    /// Tokens tried for a new flow before it is dropped with
    /// [`reasons::TOKENS_EXHAUSTED`]. Default 16 384, as ns.
    pub tries: u16,
    /// Maximum number of live flows; a new flow beyond it is dropped with
    /// [`reasons::CAPACITY`]. Default 4096, as ns.
    pub max_flows: usize,
    /// Idle timeout of a TCP flow. Default 5 min, as ns.
    pub tcp_timeout: Duration,
    /// Idle timeout of a UDP flow. Default 2 min, as ns.
    pub udp_timeout: Duration,
    /// Idle timeout of an `ICMPv6` Echo flow. Default 30 s, as ns.
    pub icmp_timeout: Duration,
    /// Whether only a TCP SYN (SYN set, ACK clear) opens a flow; another TCP
    /// packet without a flow is dropped with [`reasons::TCP_NOT_SYN`].
    /// Default `true`, as ns.
    pub tcp_new_flow_requires_syn: bool,
    /// Whether the transport checksum of a packet is verified before it is
    /// rewritten; see the [module docs](self). Default `true`, as ns.
    pub verify_checksums: bool,
}

impl Default for MasqueradeConfig {
    fn default() -> Self {
        Self {
            ports: 49_152..=65_535,
            tries: 16_384,
            max_flows: 4096,
            tcp_timeout: Duration::from_mins(5),
            udp_timeout: Duration::from_mins(2),
            icmp_timeout: Duration::from_secs(30),
            tcp_new_flow_requires_syn: true,
            verify_checksums: true,
        }
    }
}

impl MasqueradeConfig {
    /// The idle timeout of a flow of `protocol`.
    const fn timeout(&self, protocol: u8) -> Duration {
        match protocol {
            protocol::TCP => self.tcp_timeout,
            protocol::UDP => self.udp_timeout,
            _ => self.icmp_timeout,
        }
    }
}

/// What [`Masquerade::forward`] or [`Masquerade::reverse`] did with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MasqueradeVerdict {
    /// The packet was rewritten in place.
    Rewritten,
    /// Not a packet of a masqueraded flow; it is unchanged.
    Pass,
    /// The packet must be dropped, for one of the [`reasons`].
    Drop(&'static str),
}

/// A snapshot of a [`Masquerade`]'s counters, in packets unless stated
/// otherwise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MasqueradeStats {
    /// Packets rewritten by [`Masquerade::forward`].
    pub forwarded: u64,
    /// Replies restored by [`Masquerade::reverse`].
    pub reversed: u64,
    /// Packets left alone in either direction ([`MasqueradeVerdict::Pass`]).
    pub passed: u64,
    /// Packets dropped with [`reasons::TCP_NOT_SYN`].
    pub tcp_not_syn: u64,
    /// Packets dropped with [`reasons::CAPACITY`].
    pub capacity: u64,
    /// Replies dropped with [`reasons::ROUTE_CHANGED`], each removing its
    /// flow.
    pub route_changed: u64,
    /// Packets dropped with [`reasons::TOKENS_EXHAUSTED`].
    pub tokens_exhausted: u64,
    /// Packets dropped with [`reasons::BAD_CHECKSUM`].
    pub bad_checksum: u64,
    /// Live flows now, as [`Masquerade::len`].
    pub flows: usize,
    /// Flows recorded, in flows.
    pub created: u64,
    /// Flows removed because their idle timeout passed, in flows.
    pub expired: u64,
}

#[derive(Debug, Default)]
struct Counters {
    forwarded: AtomicU64,
    reversed: AtomicU64,
    passed: AtomicU64,
    tcp_not_syn: AtomicU64,
    capacity: AtomicU64,
    route_changed: AtomicU64,
    tokens_exhausted: AtomicU64,
    bad_checksum: AtomicU64,
}

/// A flow key: a packet's protocol, addresses and ports (an Echo identifier
/// is the source port of a request and the destination port of a reply).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    protocol: u8,
    src: Ipv6Addr,
    src_port: u16,
    dst: Ipv6Addr,
    dst_port: u16,
}

impl Key {
    /// The key of the replies of the flow `self` once its source is
    /// `source` and its source port `token`.
    const fn reply(&self, source: Ipv6Addr, token: u16) -> Self {
        Self {
            protocol: self.protocol,
            src: self.dst,
            src_port: self.dst_port,
            dst: source,
            dst_port: token,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Flow {
    /// The first packet's tuple, as the decision closure saw it.
    tuple: FiveTuple,
    source: Ipv6Addr,
    token: u16,
    route: u64,
    last_seen: Instant,
}

/// The flow table, behind the [`Masquerade`]'s mutex.
#[derive(Debug)]
struct Table {
    /// Flows by the key of their forward packets.
    flows: HashMap<Key, Flow>,
    /// Forward keys by the key of the replies.
    replies: HashMap<Key, Key>,
    /// The next token tried.
    next_token: u16,
    created: u64,
    expired: u64,
}

impl Table {
    fn new(config: &MasqueradeConfig) -> Self {
        Self {
            flows: HashMap::new(),
            replies: HashMap::new(),
            next_token: *config.ports.start(),
            created: 0,
            expired: 0,
        }
    }

    fn is_expired(flow: &Flow, now: Instant, config: &MasqueradeConfig) -> bool {
        now.saturating_duration_since(flow.last_seen) >= config.timeout(flow.tuple.protocol)
    }

    fn remove(&mut self, key: &Key) -> Option<Flow> {
        let flow = self.flows.remove(key)?;
        self.replies.remove(&key.reply(flow.source, flow.token));
        Some(flow)
    }

    /// The live flow of forward key `key`, refreshed; an expired one is
    /// removed.
    fn hit(&mut self, key: &Key, now: Instant, config: &MasqueradeConfig) -> Option<Flow> {
        let flow = self.flows.get_mut(key)?;
        if Self::is_expired(flow, now, config) {
            self.remove(key);
            self.expired += 1;
            return None;
        }
        flow.last_seen = now;
        Some(*flow)
    }

    /// Removes every expired flow.
    fn expire_all(&mut self, now: Instant, config: &MasqueradeConfig) {
        let before = self.flows.len();
        self.flows
            .retain(|_, flow| !Self::is_expired(flow, now, config));
        if self.flows.len() != before {
            let flows = &self.flows;
            self.replies.retain(|_, key| flows.contains_key(key));
            self.expired += (before - self.flows.len()) as u64;
        }
    }

    /// A token for a new flow of forward key `key` with source `source`,
    /// unused by the live flows to the same destination from `source`.
    fn allocate(
        &mut self,
        key: &Key,
        source: Ipv6Addr,
        now: Instant,
        config: &MasqueradeConfig,
    ) -> Result<u16, &'static str> {
        let (start, end) = (*config.ports.start(), *config.ports.end());
        if start > end {
            return Err(reasons::TOKENS_EXHAUSTED);
        }
        for _ in 0..config.tries {
            let token = self.next_token.clamp(start, end);
            self.next_token = if token == end { start } else { token + 1 };
            let Some(&owner) = self.replies.get(&key.reply(source, token)) else {
                return Ok(token);
            };
            if self
                .flows
                .get(&owner)
                .is_none_or(|flow| Self::is_expired(flow, now, config))
            {
                self.remove(&owner);
                self.replies.remove(&key.reply(source, token));
                self.expired += 1;
                return Ok(token);
            }
        }
        Err(reasons::TOKENS_EXHAUSTED)
    }
}

/// Local-side IPv6 source NAPT; see the [module docs](self).
pub struct Masquerade {
    config: MasqueradeConfig,
    decide: Decide,
    table: Mutex<Table>,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
    counters: Counters,
}

impl fmt::Debug for Masquerade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Masquerade")
            .field("config", &self.config)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl Masquerade {
    /// A masquerade whose new flows take the source `decide` answers.
    ///
    /// `decide` gets the first packet's tuple (as
    /// [`IpPacket::five_tuple`](nsplane_packet::IpPacket::five_tuple)
    /// reads it: the Echo identifier in both ports of an Echo request) and
    /// runs without any lock of the `Masquerade` held; see the
    /// [module docs](self#concurrency).
    pub fn new(
        decide: impl Fn(&FiveTuple) -> Option<MasqueradeDecision> + Send + Sync + 'static,
        config: MasqueradeConfig,
    ) -> Self {
        Self::with_clock(decide, config, Instant::now)
    }

    /// As [`new`](Self::new), with idle timeouts that follow `clock` instead
    /// of [`Instant::now`].
    pub fn with_clock(
        decide: impl Fn(&FiveTuple) -> Option<MasqueradeDecision> + Send + Sync + 'static,
        config: MasqueradeConfig,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        Self {
            table: Mutex::new(Table::new(&config)),
            config,
            decide: Box::new(decide),
            clock: Box::new(clock),
            counters: Counters::default(),
        }
    }

    /// The masquerade's settings.
    pub const fn config(&self) -> &MasqueradeConfig {
        &self.config
    }

    /// The number of live flows; removes the expired ones first.
    pub fn len(&self) -> usize {
        let now = (self.clock)();
        let mut table = self.lock();
        table.expire_all(now, &self.config);
        table.flows.len()
    }

    /// Whether no flow is live; see [`len`](Self::len).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A snapshot of the counters; removes the expired flows first.
    pub fn stats(&self) -> MasqueradeStats {
        let flows = self.len();
        let (created, expired) = {
            let table = self.lock();
            (table.created, table.expired)
        };
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let c = &self.counters;
        MasqueradeStats {
            forwarded: load(&c.forwarded),
            reversed: load(&c.reversed),
            passed: load(&c.passed),
            tcp_not_syn: load(&c.tcp_not_syn),
            capacity: load(&c.capacity),
            route_changed: load(&c.route_changed),
            tokens_exhausted: load(&c.tokens_exhausted),
            bad_checksum: load(&c.bad_checksum),
            flows,
            created,
            expired,
        }
    }

    /// Rewrites the source of a LAN packet to its flow's source and token, in
    /// place, asking the decision closure for an untracked flow; see the
    /// [module docs](self).
    pub fn forward(&self, packet: &mut PacketBuf) -> MasqueradeVerdict {
        let result = self.forward_inner(packet);
        self.count(result, &self.counters.forwarded)
    }

    /// Restores the destination of a reply of a recorded flow to the LAN
    /// host, in place, after checking the flow's route with the decision
    /// closure; see the [module docs](self).
    pub fn reverse(&self, packet: &mut PacketBuf) -> MasqueradeVerdict {
        let result = self.reverse_inner(packet);
        self.count(result, &self.counters.reversed)
    }

    /// Counts a packet: `Ok(true)` under `rewritten`, `Ok(false)` as passed,
    /// a drop under its reason.
    fn count(
        &self,
        result: Result<bool, &'static str>,
        rewritten: &AtomicU64,
    ) -> MasqueradeVerdict {
        let c = &self.counters;
        let (counter, verdict) = match result {
            Ok(true) => (rewritten, MasqueradeVerdict::Rewritten),
            Ok(false) => (&c.passed, MasqueradeVerdict::Pass),
            Err(reason) => {
                let counter = match reason {
                    reasons::TCP_NOT_SYN => &c.tcp_not_syn,
                    reasons::CAPACITY => &c.capacity,
                    reasons::ROUTE_CHANGED => &c.route_changed,
                    reasons::TOKENS_EXHAUSTED => &c.tokens_exhausted,
                    _ => &c.bad_checksum,
                };
                (counter, MasqueradeVerdict::Drop(reason))
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
        verdict
    }

    fn forward_inner(&self, packet: &mut PacketBuf) -> Result<bool, &'static str> {
        let Some(info) = Info::parse(packet.as_packet(), false) else {
            return Ok(false);
        };
        if self.config.verify_checksums && !info.checksum_valid(packet.as_packet()) {
            return Err(reasons::BAD_CHECKSUM);
        }
        let now = (self.clock)();
        let hit = self.lock().hit(&info.key, now, &self.config);
        let (source, token) = match hit {
            Some(flow) => (flow.source, flow.token),
            None => match self.new_flow(&info)? {
                Some(found) => found,
                None => return Ok(false),
            },
        };
        info.rewrite(packet.as_packet_mut(), SRC_ADDR, source, token);
        Ok(true)
    }

    fn reverse_inner(&self, packet: &mut PacketBuf) -> Result<bool, &'static str> {
        let Some(info) = Info::parse(packet.as_packet(), true) else {
            return Ok(false);
        };
        let now = (self.clock)();
        let found = {
            let mut table = self.lock();
            let key = table.replies.get(&info.key).copied();
            key.and_then(|key| table.hit(&key, now, &self.config).map(|flow| (key, flow)))
        };
        let Some((key, flow)) = found else {
            return Ok(false);
        };
        if self.config.verify_checksums && !info.checksum_valid(packet.as_packet()) {
            return Err(reasons::BAD_CHECKSUM);
        }
        // No lock is held here: the closure may call back into `self`.
        let current = (self.decide)(&flow.tuple);
        if current.map(|decision| decision.route) != Some(flow.route) {
            let mut table = self.lock();
            // Remove the flow unless another thread replaced it meanwhile.
            if table
                .flows
                .get(&key)
                .is_some_and(|live| live.token == flow.token && live.route == flow.route)
            {
                table.remove(&key);
            }
            return Err(reasons::ROUTE_CHANGED);
        }
        info.rewrite(packet.as_packet_mut(), DST_ADDR, key.src, key.src_port);
        Ok(true)
    }

    /// Asks the decision closure about a new flow and records it; returns
    /// its source and token, or `None` when the packet passes.
    fn new_flow(&self, info: &Info) -> Result<Option<(Ipv6Addr, u16)>, &'static str> {
        let tuple = info.tuple();
        // No lock is held here: the closure may call back into `self`.
        let Some(decision) = (self.decide)(&tuple) else {
            return Ok(None);
        };
        let source = decision.source;
        let now = (self.clock)();
        let config = &self.config;
        let mut table = self.lock();
        // A concurrent packet of the same flow may have recorded it first;
        // its source and token win.
        if let Some(flow) = table.hit(&info.key, now, config) {
            return Ok(Some((flow.source, flow.token)));
        }
        if info.key.protocol == protocol::TCP && config.tcp_new_flow_requires_syn && !info.syn {
            return Err(reasons::TCP_NOT_SYN);
        }
        if table.flows.len() >= config.max_flows {
            table.expire_all(now, config);
            if table.flows.len() >= config.max_flows {
                return Err(reasons::CAPACITY);
            }
        }
        let token = table.allocate(&info.key, source, now, config)?;
        table
            .replies
            .insert(info.key.reply(source, token), info.key);
        table.flows.insert(
            info.key,
            Flow {
                tuple,
                source,
                token,
                route: decision.route,
                last_seen: now,
            },
        );
        table.created += 1;
        Ok(Some((source, token)))
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the masquerade needs of a packet it may rewrite.
struct Info {
    key: Key,
    /// Offset of the source port (forward) or destination port (reverse), or
    /// of the Echo identifier.
    token_at: usize,
    /// Offset of the transport checksum.
    checksum_at: usize,
    /// Whether a TCP packet has SYN set and ACK clear.
    syn: bool,
}

impl Info {
    /// `None` for packets the masquerade never touches: not IPv6, with
    /// extension headers, neither TCP, UDP nor the `ICMPv6` Echo type of the
    /// direction (request forward, reply reverse), truncated, or longer or
    /// shorter than the IPv6 payload length says.
    fn parse(bytes: &[u8], reply: bool) -> Option<Self> {
        if bytes.len() < IPV6_HEADER + 8 || bytes[0] >> 4 != 6 {
            return None;
        }
        let payload_len = usize::from(be16(bytes, 4));
        if payload_len != bytes.len() - IPV6_HEADER {
            return None;
        }
        let src = addr(bytes, SRC_ADDR);
        let dst = addr(bytes, DST_ADDR);
        let l4 = IPV6_HEADER;
        let protocol = bytes[6];
        let (src_port, dst_port, checksum_at, syn) = match protocol {
            protocol::TCP => {
                let header_len = usize::from(*bytes.get(l4 + 12)? >> 4) * 4;
                if header_len < 20 || header_len > payload_len {
                    return None;
                }
                let flags = bytes[l4 + 13];
                let syn = flags & (TCP_SYN | TCP_ACK) == TCP_SYN;
                (be16(bytes, l4), be16(bytes, l4 + 2), l4 + 16, syn)
            }
            protocol::UDP => {
                if usize::from(be16(bytes, l4 + 4)) != payload_len {
                    return None;
                }
                (be16(bytes, l4), be16(bytes, l4 + 2), l4 + 6, false)
            }
            protocol::ICMPV6 => {
                let expected = if reply { ECHO_REPLY } else { ECHO_REQUEST };
                if bytes[l4] != expected || bytes[l4 + 1] != 0 {
                    return None;
                }
                let id = be16(bytes, l4 + 4);
                let ports = if reply { (0, id) } else { (id, 0) };
                (ports.0, ports.1, l4 + 2, false)
            }
            _ => return None,
        };
        let token_at = match protocol {
            protocol::ICMPV6 => l4 + 4,
            _ if reply => l4 + 2,
            _ => l4,
        };
        Some(Self {
            key: Key {
                protocol,
                src,
                src_port,
                dst,
                dst_port,
            },
            token_at,
            checksum_at,
            syn,
        })
    }

    /// The packet's tuple as `IpPacket::five_tuple` reads it (the Echo
    /// identifier in both ports of an Echo request).
    const fn tuple(&self) -> FiveTuple {
        let key = &self.key;
        FiveTuple {
            src: IpAddr::V6(key.src),
            dst: IpAddr::V6(key.dst),
            protocol: key.protocol,
            src_port: key.src_port,
            dst_port: if key.protocol == protocol::ICMPV6 {
                key.src_port
            } else {
                key.dst_port
            },
        }
    }

    /// Whether the transport checksum of `bytes` is valid and not zero.
    fn checksum_valid(&self, bytes: &[u8]) -> bool {
        be16(bytes, self.checksum_at) != 0
            && transport_checksum_v6(
                self.key.src,
                self.key.dst,
                self.key.protocol,
                &bytes[IPV6_HEADER..],
            ) == 0
    }

    /// Writes `address` at `address_at` (the source or destination) and
    /// `token` as the port or identifier, then recomputes the transport
    /// checksum.
    fn rewrite(&self, bytes: &mut [u8], address_at: usize, address: Ipv6Addr, token: u16) {
        bytes[address_at..address_at + 16].copy_from_slice(&address.octets());
        bytes[self.token_at..self.token_at + 2].copy_from_slice(&token.to_be_bytes());
        bytes[self.checksum_at..self.checksum_at + 2].fill(0);
        let (src, dst) = (addr(bytes, SRC_ADDR), addr(bytes, DST_ADDR));
        let checksum = transport_checksum_v6(src, dst, self.key.protocol, &bytes[IPV6_HEADER..]);
        let checksum = if checksum == 0 { 0xffff } else { checksum };
        bytes[self.checksum_at..self.checksum_at + 2].copy_from_slice(&checksum.to_be_bytes());
    }
}

const fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn addr(bytes: &[u8], at: usize) -> Ipv6Addr {
    let mut octets = [0; 16];
    octets.copy_from_slice(&bytes[at..at + 16]);
    Ipv6Addr::from(octets)
}
