//! Stateful NAT64 to a LAN (NAPT) for subnet routing (`Nat64Lan`).
//!
//! A [`Nat64Lan`] lets IPv6 peers reach an IPv4 LAN behind this node, ported
//! from ns `SubnetRoute` / `SubnetConntrack`. Each [`LanRoute`] maps an IPv6
//! /96 (`mapped`) to an IPv4 prefix (`real`); the low 32 bits of a mapped
//! address are the LAN host:
//!
//! - **Forward** ([`Nat64Lan::forward`]): an IPv6 TCP or UDP packet or
//!   `ICMPv6` echo request to an address of a route's `mapped` prefix becomes
//!   an IPv4 packet to the embedded LAN host, from the route's `snat_source`
//!   with a source port (or ICMP echo identifier) reserved for the flow.
//!   Exactly one route must resolve the destination, as ns
//!   `SubnetRouteSet::route_for`: a destination that several routes resolve
//!   is dropped ([`reasons::AMBIGUOUS_ROUTE`]), and a destination inside a
//!   `mapped` prefix that no route resolves to a safe address of its `real`
//!   prefix (see [`LanRoute::resolve`]) is dropped
//!   ([`reasons::UNSAFE_TARGET`]).
//! - **Reverse** ([`Nat64Lan::reverse`]): an IPv4 TCP or UDP packet or ICMP
//!   echo reply of a tracked flow becomes the IPv6 reply to the original
//!   source, from the mapped address of the LAN host. An ICMP Fragmentation
//!   Needed quoting a tracked flow becomes an `ICMPv6` Packet Too Big with the
//!   next-hop MTU plus 20 (at least 1280).
//! - **TCP MSS clamp** ([`Nat64LanConfig::max_tcp_mss`]): the MSS option of
//!   SYN packets is lowered in both directions.
//! - Everything else (other protocols and ICMP types, IPv6 extension headers
//!   and fragments, IPv4 options and fragments, destinations outside every
//!   route, replies of unknown flows) is not ours ([`Nat64Verdict::NotOurs`])
//!   and left unchanged.
//!
//! Packets are rewritten in place: a forwarded packet shrinks by 20 bytes
//! (its start moves forward inside the buffer) and a reply grows by 20 bytes
//! into its headroom; a reply whose buffer has less than 20 bytes of headroom
//! is copied once into a buffer with the standard headroom. Checksums are
//! recomputed, as ns does. Translated IPv4 packets leave DF clear, as ns
//! does, unless [`Nat64LanConfig::set_df`] is on. The hop limit and TTL are
//! copied, as ns does: the node forwarding the translated packet decrements
//! them.
//!
//! # Routes
//!
//! The routes gate every forward packet, not just the first of a flow: a
//! packet whose destination no longer resolves through exactly one route is
//! not translated, even if its flow is still tracked. A flow whose
//! destination still resolves after a route replacement keeps the SNAT
//! address it was created with; to revoke the flows of a removed route, call
//! [`Nat64Lan::remove_flow`] for them, as ns does.
//!
//! # Flows and limits
//!
//! Flows live in a [`Conntrack`] ([`Nat64LanConfig::conntrack`]): bounded
//! (the least recently seen flow is evicted from a full table) with idle
//! timeouts per protocol and TCP state. A new flow tries up to
//! [`Nat64LanConfig::port_tries`] (32) [`SnatPorts::candidate`] ports and
//! takes the first one that [`SnatPorts::reserve`] accepts and that no live
//! flow uses for the same LAN host; a saturated port range drops the packet
//! ([`reasons::PORT_EXHAUSTED`]) rather than aliasing another flow. The port
//! is released through [`SnatPorts::release`] whenever the flow goes: idle
//! expiry, eviction, or [`Nat64Lan::remove_flow`]. Ports are reserved per
//! `(snat_source, port)` for the flow's lifetime, so a caller can couple
//! them to host sockets, as ns does with [`SnatPorts`].
//!
//! Differences from ns: routes are replaced through the caller's
//! [`ArcSwap`]; flows expire when idle (ns keeps them until
//! `remove_translated_flow`); DF can be turned on with
//! [`Nat64LanConfig::set_df`].
//!
//! # Placement
//!
//! LAN replies are addressed to `snat_source`, which no peer's allowed IPs
//! contain, so the core cannot route them to a peer before a filter runs.
//! The translation therefore sits on the local side, around the packets the
//! core delivers and the local packets it receives: `forward` on decrypted
//! IPv6 packets before they reach the local stack (which routes the IPv4
//! result to the LAN), `reverse` on local packets before the core routes
//! them (the IPv6 result goes to the peer that owns the original source).
//! `forward` and `reverse` are plain functions on [`PacketBuf`];
//! [`Nat64LanSink`] and [`Nat64LanSource`] wrap the engine's sink and source
//! with them.

pub mod reasons;

mod io;
mod packet;
mod ports;
mod route;
#[cfg(test)]
mod tests;

use std::fmt;
use std::net::{IpAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use nsplane_packet::{FiveTuple, PacketBuf, PeerId, protocol};

pub use self::io::{Nat64LanSink, Nat64LanSource};
pub use self::ports::{DefaultSnatPorts, SnatPorts};
pub use self::route::{LanRoute, Nat64LanError};
use crate::conntrack::{Conntrack, ConntrackConfig, ConntrackError, ConntrackStats, FlowDirection};

/// The peer recorded in every flow: flows are told apart by their tuples.
const PEER: PeerId = PeerId::new(0);

/// Settings of a [`Nat64Lan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Nat64LanConfig {
    /// Lower the MSS option of TCP SYN packets to this value in both
    /// directions (e.g. the local link MTU minus 60). Default `None`.
    pub max_tcp_mss: Option<u16>,
    /// SNAT port candidates a new flow tries before it is dropped with
    /// [`reasons::PORT_EXHAUSTED`]. Default 32, as ns.
    pub port_tries: u8,
    /// The flow table: size and idle timeouts.
    pub conntrack: ConntrackConfig,
    /// Set DF on translated IPv4 packets above 1260 bytes (RFC 7915).
    /// Default `false`, as ns.
    ///
    /// With DF, LAN hosts and routers answer an oversized packet with ICMP
    /// Fragmentation Needed, which [`Nat64Lan::reverse`] turns into an
    /// `ICMPv6` Packet Too Big, so the peer lowers its path MTU; a LAN that
    /// filters ICMP then black-holes those packets. Without DF there is no
    /// such black hole, but oversized packets are fragmented on the LAN.
    pub set_df: bool,
}

impl Default for Nat64LanConfig {
    fn default() -> Self {
        Self {
            max_tcp_mss: None,
            port_tries: 32,
            conntrack: ConntrackConfig::default(),
            set_df: false,
        }
    }
}

/// What [`Nat64Lan::forward`] or [`Nat64Lan::reverse`] did with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Nat64Verdict {
    /// The packet was translated in place.
    Translated,
    /// Not a packet of this translator; it is unchanged.
    NotOurs,
    /// The packet must be dropped, for one of the [`reasons`].
    Drop(&'static str),
}

/// A snapshot of a [`Nat64Lan`]'s counters, in packets unless stated
/// otherwise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Nat64LanStats {
    /// IPv6 packets translated to the LAN.
    pub forwarded: u64,
    /// LAN replies translated back to IPv6.
    pub reversed: u64,
    /// ICMP Fragmentation Needed errors turned into `ICMPv6` Packet Too Big.
    pub packet_too_big: u64,
    /// Packets dropped with [`reasons::UNSAFE_TARGET`].
    pub unsafe_target: u64,
    /// Packets dropped with [`reasons::AMBIGUOUS_ROUTE`].
    pub ambiguous_route: u64,
    /// Packets dropped with [`reasons::PORT_EXHAUSTED`].
    pub port_exhausted: u64,
    /// Packets dropped with [`reasons::MALFORMED`] or
    /// [`reasons::CONNTRACK_FULL`].
    pub other_drops: u64,
    /// Packets left alone in either direction ([`Nat64Verdict::NotOurs`]).
    pub not_ours: u64,
    /// The flow table, in flows.
    pub conntrack: ConntrackStats,
}

#[derive(Debug, Default)]
struct Counters {
    forwarded: AtomicU64,
    reversed: AtomicU64,
    packet_too_big: AtomicU64,
    unsafe_target: AtomicU64,
    ambiguous_route: AtomicU64,
    port_exhausted: AtomicU64,
    other_drops: AtomicU64,
    not_ours: AtomicU64,
}

/// Stateful NAT64 to a LAN; see the [module docs](self).
pub struct Nat64Lan {
    routes: Arc<ArcSwap<Vec<LanRoute>>>,
    config: Nat64LanConfig,
    ports: Arc<dyn SnatPorts>,
    conntrack: Conntrack,
    /// The `seq` of the next [`SnatPorts::candidate`].
    next_candidate: AtomicU32,
    counters: Counters,
}

impl fmt::Debug for Nat64Lan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nat64Lan")
            .field("routes", &self.routes.load())
            .field("config", &self.config)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl Nat64Lan {
    /// A translator over `routes`, which the caller may replace atomically at
    /// any time, with a [`DefaultSnatPorts`] allocator.
    pub fn new(routes: Arc<ArcSwap<Vec<LanRoute>>>, config: Nat64LanConfig) -> Self {
        Self::with_snat_ports(routes, config, Arc::new(DefaultSnatPorts::new()))
    }

    /// As [`new`](Self::new), reserving SNAT ports through `ports`.
    pub fn with_snat_ports(
        routes: Arc<ArcSwap<Vec<LanRoute>>>,
        config: Nat64LanConfig,
        ports: Arc<dyn SnatPorts>,
    ) -> Self {
        Self::with_conntrack(routes, config, ports, Conntrack::new(config.conntrack))
    }

    /// Builds the translator around `conntrack` (tests inject a clock).
    fn with_conntrack(
        routes: Arc<ArcSwap<Vec<LanRoute>>>,
        config: Nat64LanConfig,
        ports: Arc<dyn SnatPorts>,
        conntrack: Conntrack,
    ) -> Self {
        let hook_ports = Arc::clone(&ports);
        let conntrack = conntrack.with_removal_hook(move |flow| {
            if let Some(snat) = snat_of(&flow.translated) {
                hook_ports.release(flow.translated.protocol, snat);
            }
        });
        Self {
            routes,
            config,
            ports,
            conntrack,
            next_candidate: AtomicU32::new(0),
            counters: Counters::default(),
        }
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> Nat64LanStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let c = &self.counters;
        Nat64LanStats {
            forwarded: load(&c.forwarded),
            reversed: load(&c.reversed),
            packet_too_big: load(&c.packet_too_big),
            unsafe_target: load(&c.unsafe_target),
            ambiguous_route: load(&c.ambiguous_route),
            port_exhausted: load(&c.port_exhausted),
            other_drops: load(&c.other_drops),
            not_ours: load(&c.not_ours),
            conntrack: self.conntrack.stats(),
        }
    }

    /// Translates an IPv6 packet to a routed LAN host to IPv4, in place; see
    /// the [module docs](self).
    pub fn forward(&self, packet: &mut PacketBuf) -> Nat64Verdict {
        let result = self.forward_inner(packet);
        self.count(result, &self.counters.forwarded)
    }

    /// Translates a LAN reply (or a Fragmentation Needed error) of a tracked
    /// flow back to IPv6, in place; see the [module docs](self).
    pub fn reverse(&self, packet: &mut PacketBuf) -> Nat64Verdict {
        let bytes = packet.as_packet();
        if let Some((reply, flags)) = packet::reply_tuple(bytes) {
            let Some(original) = self.reply_flow(&reply, Some(flags)) else {
                return self.count(Ok(false), &self.counters.reversed);
            };
            packet::to_ipv6(packet, &original, self.config.max_tcp_mss);
            return self.count(Ok(true), &self.counters.reversed);
        }
        let found = packet::fragmentation_needed(bytes).and_then(|error| {
            let original = self.reply_flow(&error.reply, None)?;
            Some((error, original))
        });
        let Some((error, original)) = found else {
            return self.count(Ok(false), &self.counters.packet_too_big);
        };
        packet::packet_too_big(packet, &original, &error);
        self.count(Ok(true), &self.counters.packet_too_big)
    }

    /// Removes the flow from `snat` to the LAN `target` (TCP or UDP; for ICMP
    /// the echo identifier is `snat`'s port and `target`'s port is ignored)
    /// and releases its SNAT port, as ns `remove_translated_flow`. Returns
    /// whether a flow was removed.
    pub fn remove_flow(&self, protocol: u8, snat: SocketAddrV4, target: SocketAddrV4) -> bool {
        let target_port = match protocol {
            protocol::TCP | protocol::UDP => target.port(),
            protocol::ICMP => snat.port(),
            _ => return false,
        };
        let reply = FiveTuple {
            src: IpAddr::V4(*target.ip()),
            dst: IpAddr::V4(*snat.ip()),
            protocol,
            src_port: target_port,
            dst_port: snat.port(),
        };
        self.conntrack.remove(&reply).is_some()
    }

    /// Counts a packet: `Ok(true)` under `translated`, `Ok(false)` as not
    /// ours, a drop under its reason.
    fn count(&self, result: Result<bool, &'static str>, translated: &AtomicU64) -> Nat64Verdict {
        let c = &self.counters;
        let (counter, verdict) = match result {
            Ok(true) => (translated, Nat64Verdict::Translated),
            Ok(false) => (&c.not_ours, Nat64Verdict::NotOurs),
            Err(reason) => {
                let counter = match reason {
                    reasons::UNSAFE_TARGET => &c.unsafe_target,
                    reasons::AMBIGUOUS_ROUTE => &c.ambiguous_route,
                    reasons::PORT_EXHAUSTED => &c.port_exhausted,
                    _ => &c.other_drops,
                };
                (counter, Nat64Verdict::Drop(reason))
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
        verdict
    }

    fn forward_inner(&self, packet: &mut PacketBuf) -> Result<bool, &'static str> {
        let bytes = packet.as_packet();
        let Some(request) = packet::request(bytes) else {
            return Ok(false);
        };
        let routes = self.routes.load();
        let mut resolving = routes
            .iter()
            .filter_map(|route| Some((route, route.resolve(request.dst)?)));
        let Some((route, target)) = resolving.next() else {
            if routes.iter().any(|route| route.maps(request.dst)) {
                return Err(reasons::UNSAFE_TARGET);
            }
            return Ok(false);
        };
        if resolving.next().is_some() {
            return Err(reasons::AMBIGUOUS_ROUTE);
        }
        let (original, flags) = packet::request_tuple(bytes, request).ok_or(reasons::MALFORMED)?;
        let translated = match self.conntrack.lookup(&original, Some(flags)) {
            Some(found) if found.direction == FlowDirection::Original => found.flow.translated,
            _ => self.new_flow(&original, route.snat_source, target, flags)?,
        };
        packet::to_ipv4(
            packet,
            &translated,
            self.config.max_tcp_mss,
            self.config.set_df,
        );
        Ok(true)
    }

    /// Reserves a SNAT port for a new flow and records it; returns the
    /// translated tuple.
    fn new_flow(
        &self,
        original: &FiveTuple,
        snat_source: std::net::Ipv4Addr,
        target: std::net::Ipv4Addr,
        flags: u8,
    ) -> Result<FiveTuple, &'static str> {
        let protocol = original.protocol;
        for _ in 0..self.config.port_tries {
            let seq = self.next_candidate.fetch_add(1, Ordering::Relaxed);
            let port = self.ports.candidate(protocol, snat_source, seq);
            let snat = SocketAddrV4::new(snat_source, port);
            if !self.ports.reserve(protocol, snat) {
                continue;
            }
            let translated = FiveTuple {
                src: IpAddr::V4(snat_source),
                dst: IpAddr::V4(target),
                protocol,
                src_port: port,
                dst_port: if protocol == protocol::ICMP {
                    port
                } else {
                    original.dst_port
                },
            };
            match self.conntrack.insert(PEER, *original, translated, flags) {
                Ok(flow) => {
                    // A concurrent packet of the same flow recorded it first.
                    if flow.translated != translated {
                        self.ports.release(protocol, snat);
                    }
                    return Ok(flow.translated);
                }
                Err(ConntrackError::Conflict) => self.ports.release(protocol, snat),
                Err(ConntrackError::Full) => {
                    self.ports.release(protocol, snat);
                    return Err(reasons::CONNTRACK_FULL);
                }
                Err(ConntrackError::Unsupported) => {
                    self.ports.release(protocol, snat);
                    return Err(reasons::MALFORMED);
                }
            }
        }
        Err(reasons::PORT_EXHAUSTED)
    }

    /// The original tuple of the flow a LAN packet with `reply` answers.
    fn reply_flow(&self, reply: &FiveTuple, flags: Option<u8>) -> Option<FiveTuple> {
        let found = self.conntrack.lookup(reply, flags)?;
        (found.direction == FlowDirection::Reply).then_some(found.flow.original)
    }
}

/// The SNAT address and port of a translated tuple.
const fn snat_of(translated: &FiveTuple) -> Option<SocketAddrV4> {
    match translated.src {
        IpAddr::V4(addr) => Some(SocketAddrV4::new(addr, translated.src_port)),
        IpAddr::V6(_) => None,
    }
}
