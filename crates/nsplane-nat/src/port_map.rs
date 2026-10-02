//! Port mapping (DNAT/SNAT) filter for service publishing (`PortMap`).
//!
//! A [`PortMap`] publishes local services to tunnel peers. Each
//! [`PortMapRule`] maps a tunnel-facing `listen` address and port (e.g. this
//! node's `node6`) to a local `target` service, optionally for a set of peers
//! only:
//!
//! - **Inbound**, a TCP or UDP packet to a `listen` address and port from an
//!   allowed peer is rewritten to the `target` (DNAT) and its flow is recorded
//!   in the [`Conntrack`]; later packets of the flow reuse the recorded
//!   mapping. A packet to a `listen` port from a peer the rule does not allow
//!   is dropped ([`reasons::PEER_NOT_ALLOWED`]).
//! - **Outbound**, a reply of a recorded flow (from the `target` to the
//!   peer's address and port) is rewritten back to come from `listen` (SNAT),
//!   provided it is routed to the flow's peer; otherwise it is dropped
//!   ([`reasons::WRONG_PEER`]).
//! - **ICMP errors** quoting a recorded flow (ICMP destination unreachable,
//!   time exceeded and parameter problem; `ICMPv6` the same plus packet too
//!   big) get their quoted packet rewritten the same way, and the outer
//!   address too when it is the `target` (outbound) or `listen` (inbound)
//!   address, so path MTU discovery and port-unreachable errors work through
//!   the mapping. ns `packet_nat` leaves ICMP errors alone; this is an
//!   addition.
//! - Everything else, including packets of recorded flows going the wrong
//!   way, passes unchanged.
//!
//! Addresses and ports are rewritten in place with incremental (RFC 1624)
//! checksum updates of the IPv4 header and the TCP/UDP checksum; a UDP packet
//! over IPv4 without a checksum keeps none. The ICMP checksum of a rewritten
//! error is updated from the sum of the message before and after the rewrite.
//!
//! Only unfragmented packets are mapped: an IPv4 fragment or an IPv6 packet
//! with extension headers passes unchanged. Published services are reached
//! through the tunnel MTU, so TCP (MSS) and well-behaved UDP services do not
//! fragment.
//!
//! # Place in the filter chain
//!
//! The core runs its filters in the same order in both directions: the first
//! filter sees decrypted packets first on inbound and local packets first on
//! outbound. A `PortMap` needs to see the packets of a flow with the same
//! addresses in both directions, so **no filter that rewrites addresses may
//! run before it**. With the `Translator`, install the `PortMap` before it:
//! inbound, the `PortMap` sees the packet as it came out of the tunnel and
//! DNATs it before the `Translator` runs; outbound, it SNATs the local reply
//! before the `Translator` runs. Rules therefore name tunnel-side addresses
//! (`listen`, e.g. this node's `node6`) and a `target` of the same family
//! (e.g. `node6` on another port, or `[::1]`); 4 <-> 6 translation of a
//! published service is not done here. Filters that only drop (the ACL) may
//! run before or after it; before it, they judge the `listen` address.
//!
//! Replacing the rules ([`PortMap::set_rules`]) is atomic and removes the
//! recorded flows of every rule that is gone or changed (target or allowed
//! peers), so their next packets are judged by the new rules.

pub mod reasons;
mod rewrite;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{PoisonError, RwLock};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{FiveTuple, IpPacket, PacketBuf, PeerId, protocol};
use thiserror::Error;

use crate::conntrack::{Conntrack, ConntrackError, Flow, FlowDirection, reverse};

use self::rewrite::End;

/// The transport protocol of a [`PortMapRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortMapProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl PortMapProtocol {
    /// The IP protocol number.
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => protocol::TCP,
            Self::Udp => protocol::UDP,
        }
    }

    const fn from_number(number: u8) -> Option<Self> {
        match number {
            protocol::TCP => Some(Self::Tcp),
            protocol::UDP => Some(Self::Udp),
            _ => None,
        }
    }
}

/// One published service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapRule {
    /// The transport protocol.
    pub protocol: PortMapProtocol,
    /// The tunnel-facing address and port peers send to, e.g. this node's
    /// `node6`. Only the IP address and port are used.
    pub listen: SocketAddr,
    /// The local service, of the same address family as `listen`. Only the
    /// IP address and port are used.
    pub target: SocketAddr,
    /// The peers that may use the rule; `None` allows every peer.
    pub peers: Option<Vec<PeerId>>,
}

impl PortMapRule {
    fn allows(&self, peer: PeerId) -> bool {
        self.peers
            .as_ref()
            .is_none_or(|peers| peers.contains(&peer))
    }
}

/// Why a set of rules was refused. The previous rules stay in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PortMapError {
    /// `listen` and `target` are of different address families.
    #[error("listen {listen} and target {target} are of different address families")]
    FamilyMismatch {
        /// The rule's listen address.
        listen: SocketAddr,
        /// The rule's target address.
        target: SocketAddr,
    },
    /// A `listen` or `target` port is 0.
    #[error("port 0 in rule for {0}")]
    ZeroPort(SocketAddr),
    /// Two rules have the same protocol and `listen` address and port.
    #[error("duplicate listen address {0}")]
    DuplicateListen(SocketAddr),
}

/// Length of the fixed IPv6 header.
const IPV6_HEADER_LEN: usize = 40;

/// The rules, keyed by protocol and listen address and port.
type Rules = HashMap<(PortMapProtocol, IpAddr, u16), PortMapRule>;

/// A [`PacketFilter`] publishing local services to tunnel peers. See the
/// [module docs](self).
#[derive(Debug)]
pub struct PortMap {
    rules: RwLock<Rules>,
    conntrack: Conntrack,
}

impl PortMap {
    /// A port map with `rules` and a [`Conntrack`] with default settings.
    pub fn new(rules: impl IntoIterator<Item = PortMapRule>) -> Result<Self, PortMapError> {
        Self::with_conntrack(rules, Conntrack::default())
    }

    /// A port map with `rules` that records its flows in `conntrack`.
    pub fn with_conntrack(
        rules: impl IntoIterator<Item = PortMapRule>,
        conntrack: Conntrack,
    ) -> Result<Self, PortMapError> {
        Ok(Self {
            rules: RwLock::new(compile(rules)?),
            conntrack,
        })
    }

    /// Replaces the rules atomically and removes the recorded flows of every
    /// rule that is gone or changed. On error nothing changes.
    pub fn set_rules(
        &self,
        rules: impl IntoIterator<Item = PortMapRule>,
    ) -> Result<(), PortMapError> {
        let rules = compile(rules)?;
        let mut current = self.rules.write().unwrap_or_else(PoisonError::into_inner);
        *current = rules;
        self.conntrack.retain(|flow| {
            rule_for(&current, &flow.original)
                .is_some_and(|rule| maps_to(rule, flow) && rule.allows(flow.peer))
        });
        Ok(())
    }

    /// The current rules, in no particular order.
    pub fn rules(&self) -> Vec<PortMapRule> {
        self.rules
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// The connection tracking table of the mapped flows.
    pub const fn conntrack(&self) -> &Conntrack {
        &self.conntrack
    }

    /// Records the flow of a first packet `tuple` from `peer`. `Ok(None)`
    /// when no rule matches.
    fn new_flow(
        &self,
        peer: PeerId,
        tuple: FiveTuple,
        tcp_flags: u8,
    ) -> Result<Option<Flow>, &'static str> {
        // Hold the rules while inserting, so `set_rules` cannot miss the flow.
        let rules = self.rules.read().unwrap_or_else(PoisonError::into_inner);
        let Some(rule) = rule_for(&rules, &tuple) else {
            return Ok(None);
        };
        if !rule.allows(peer) {
            return Err(reasons::PEER_NOT_ALLOWED);
        }
        let translated = FiveTuple {
            dst: rule.target.ip(),
            dst_port: rule.target.port(),
            ..tuple
        };
        match self.conntrack.insert(peer, tuple, translated, tcp_flags) {
            Ok(flow) => Ok(Some(flow)),
            Err(ConntrackError::Full) => Err(reasons::CONNTRACK_FULL),
            Err(ConntrackError::Conflict) => Err(reasons::FLOW_CONFLICT),
            Err(ConntrackError::Unsupported) => Err(reasons::MALFORMED),
        }
    }

    /// Rewrites an ICMP error quoting a recorded flow; `inbound` tells the
    /// direction of the error.
    fn icmp_error(&self, peer: PeerId, packet: &mut PacketBuf, inbound: bool) -> Verdict {
        let Some(error) = rewrite::IcmpError::parse(packet.as_packet()) else {
            return Verdict::Accept;
        };
        // An inbound error quotes a reply (listen -> peer), an outbound error
        // a mapped packet (peer -> target); either reversed finds the flow.
        let expected = if inbound {
            FlowDirection::Original
        } else {
            FlowDirection::Reply
        };
        let flow = match self.conntrack.lookup(&reverse(&error.inner), None) {
            Some(found) if found.direction == expected => found.flow,
            _ => return Verdict::Accept,
        };
        if flow.peer != peer {
            return dropped(reasons::WRONG_PEER);
        }
        let listen = flow.original.dst;
        let target = flow.translated.dst;
        let done = if inbound {
            error.rewrite(
                packet.as_packet_mut(),
                (End::Src, target, flow.translated.dst_port),
                (End::Dst, listen, target),
            )
        } else {
            error.rewrite(
                packet.as_packet_mut(),
                (End::Dst, listen, flow.original.dst_port),
                (End::Src, target, listen),
            )
        };
        verdict(done)
    }
}

impl PacketFilter for PortMap {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let Some(info) = Info::parse(packet) else {
            return Verdict::Accept;
        };
        let Some(tuple) = info.tuple else {
            return self.icmp_error(peer, packet, true);
        };
        let flow = match self.conntrack.lookup(&tuple, Some(info.tcp_flags)) {
            Some(found) if found.direction == FlowDirection::Original => found.flow,
            _ => match self.new_flow(peer, tuple, info.tcp_flags) {
                Ok(Some(flow)) => flow,
                Ok(None) => return Verdict::Accept,
                Err(reason) => return dropped(reason),
            },
        };
        // Also covers a concurrent insert of the same tuple by another peer.
        if flow.peer != peer {
            return dropped(reasons::WRONG_PEER);
        }
        verdict(rewrite::endpoint(
            packet.as_packet_mut(),
            info.l4,
            End::Dst,
            flow.translated.dst,
            flow.translated.dst_port,
        ))
    }

    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let Some(info) = Info::parse(packet) else {
            return Verdict::Accept;
        };
        let Some(tuple) = info.tuple else {
            return self.icmp_error(peer, packet, false);
        };
        let flow = match self.conntrack.lookup(&tuple, Some(info.tcp_flags)) {
            Some(found) if found.direction == FlowDirection::Reply => found.flow,
            _ => return Verdict::Accept,
        };
        if flow.peer != peer {
            return dropped(reasons::WRONG_PEER);
        }
        verdict(rewrite::endpoint(
            packet.as_packet_mut(),
            info.l4,
            End::Src,
            flow.original.dst,
            flow.original.dst_port,
        ))
    }
}

/// What the filter needs of a packet it may map.
struct Info {
    /// The TCP/UDP flow key; `None` for an ICMP / `ICMPv6` packet.
    tuple: Option<FiveTuple>,
    /// Offset of the transport header.
    l4: usize,
    /// TCP flags, 0 for other protocols.
    tcp_flags: u8,
}

impl Info {
    /// `None` for packets the filter never touches: malformed, fragmented,
    /// or neither TCP, UDP nor ICMP.
    fn parse(packet: &PacketBuf) -> Option<Self> {
        let ip = IpPacket::parse(packet.as_packet()).ok()?;
        if ip.fragment().is_some() {
            return None;
        }
        let l4 = match &ip {
            IpPacket::V4 { header, .. } => header.header_len(),
            IpPacket::V6 { .. } => IPV6_HEADER_LEN,
        };
        match ip.protocol() {
            protocol::ICMP | protocol::ICMPV6 => Some(Self {
                tuple: None,
                l4,
                tcp_flags: 0,
            }),
            protocol::TCP | protocol::UDP => {
                let tuple = ip.five_tuple()?;
                let tcp_flags = if tuple.protocol == protocol::TCP {
                    ip.payload().get(13).copied().unwrap_or(0)
                } else {
                    0
                };
                Some(Self {
                    tuple: Some(tuple),
                    l4,
                    tcp_flags,
                })
            }
            _ => None,
        }
    }
}

/// Validates `rules` and keys them by protocol and listen address and port.
fn compile(rules: impl IntoIterator<Item = PortMapRule>) -> Result<Rules, PortMapError> {
    let mut map = Rules::new();
    for rule in rules {
        if rule.listen.is_ipv4() != rule.target.is_ipv4() {
            return Err(PortMapError::FamilyMismatch {
                listen: rule.listen,
                target: rule.target,
            });
        }
        for addr in [rule.listen, rule.target] {
            if addr.port() == 0 {
                return Err(PortMapError::ZeroPort(addr));
            }
        }
        let key = (rule.protocol, rule.listen.ip(), rule.listen.port());
        if map.insert(key, rule).is_some() {
            return Err(PortMapError::DuplicateListen(SocketAddr::new(key.1, key.2)));
        }
    }
    Ok(map)
}

/// The rule a packet with `tuple` is sent to.
fn rule_for<'a>(rules: &'a Rules, tuple: &FiveTuple) -> Option<&'a PortMapRule> {
    let protocol = PortMapProtocol::from_number(tuple.protocol)?;
    rules.get(&(protocol, tuple.dst, tuple.dst_port))
}

/// Whether `rule` maps to the target `flow` was mapped to.
fn maps_to(rule: &PortMapRule, flow: &Flow) -> bool {
    rule.target.ip() == flow.translated.dst && rule.target.port() == flow.translated.dst_port
}

const fn dropped(reason: &'static str) -> Verdict {
    Verdict::Drop { reason }
}

/// Accept a rewritten packet; drop one that could not be rewritten.
const fn verdict(rewritten: Option<()>) -> Verdict {
    match rewritten {
        Some(()) => Verdict::Accept,
        None => dropped(reasons::MALFORMED),
    }
}
