//! Local-side redirect of IPv4 TCP/UDP flows to caller-chosen endpoints
//! (`Redirect`): DNAT with the reverse SNAT of the replies.
//!
//! A [`Redirect`] sends the flows a local application opens to a service
//! address (say `100.64.0.10:80`) to an endpoint the caller picks per flow
//! (say a user-space stack listening on `10.99.0.1:40000`), ported from ns
//! `tun_service/rewrite.rs`:
//!
//! - **Forward** ([`Redirect::forward`]): a packet from the application gets
//!   the flow's endpoint as its destination; the source is kept. The first
//!   packet of an untracked flow asks the decision closure, which answers
//!   [`RedirectDecision::Redirect`] with the endpoint, [`Pass`] (the packet
//!   is left alone and nothing is recorded) or [`Drop`]
//!   ([`reasons::DENIED`]). Later packets of the flow reuse its endpoint
//!   without asking again.
//! - **Reverse** ([`Redirect::reverse`]): a reply from the endpoint gets the
//!   service address the application sent to as its source, so the
//!   application sees the service answer.
//! - Everything else (IPv6, IPv4 fragments, protocols other than TCP and
//!   UDP, unparsable packets, replies of untracked flows) passes unchanged
//!   ([`RedirectVerdict::Pass`]).
//!
//! Packets are rewritten in place with RFC 1624 incremental checksum updates
//! (the IPv4 header and the transport checksum); a UDP packet without a
//! checksum (zero) keeps it zero. ns recomputes both checksums.
//!
//! [`Pass`]: RedirectDecision::Pass
//! [`Drop`]: RedirectDecision::Drop
//!
//! # Flows
//!
//! Flows live in a [`Conntrack`]: bounded (the least recently seen flow is
//! evicted from a full table) with idle timeouts per protocol and TCP state;
//! ns keeps flows until they are removed. A flow's `original` tuple is its
//! first packet (application -> service), its `translated` tuple the same
//! packet after the rewrite (application -> endpoint); [`Flow::peer`] is
//! always `PeerId::new(0)` and carries no meaning here.
//!
//! An endpoint must not be shared by two live flows from the same source
//! address and port, or their replies could not be told apart: when the
//! endpoint the closure picked is in use that way, the closure is asked
//! again, up to 32 times, before the packet is dropped
//! ([`reasons::ENDPOINT_EXHAUSTED`]). Flows go when idle, when evicted,
//! through [`Redirect::remove_flow`] (by the endpoint's view of the flow,
//! as a user-space stack reports a closed connection) and through
//! [`Redirect::retain`] (e.g. when a service is revoked).
//!
//! # Concurrency
//!
//! All methods take `&self`. The decision closure never runs while a lock of
//! the `Redirect` or its `Conntrack` is held, so it may call back into the
//! `Redirect` ([`remove_flow`](Redirect::remove_flow),
//! [`retain`](Redirect::retain),
//! [`original_destination`](Redirect::original_destination), even
//! [`forward`](Redirect::forward)). When the first packets of one flow race
//! on two threads, both may ask the closure, but only one flow is recorded:
//! the loser's insert returns the flow already recorded for the same
//! original tuple, and its packet takes that flow's endpoint.

pub mod reasons;

#[cfg(test)]
mod tests;

use std::fmt;
use std::net::{IpAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};

use nsplane_packet::{FiveTuple, IpPacket, PacketBuf, PeerId, protocol};

use crate::conntrack::{
    Conntrack, ConntrackConfig, ConntrackError, ConntrackStats, Flow, FlowDirection,
};
use crate::port_map::rewrite::{self, End};

/// The peer recorded in every flow: flows are told apart by their tuples.
const PEER: PeerId = PeerId::new(0);

/// Decisions asked for a new flow before it is dropped with
/// [`reasons::ENDPOINT_EXHAUSTED`], as ns tries its endpoint pool.
const ENDPOINT_TRIES: usize = 32;

/// The decision closure of a [`Redirect`].
type Decide = Box<dyn Fn(&FiveTuple) -> RedirectDecision + Send + Sync>;

/// What to do with a new flow, as answered by the decision closure of a
/// [`Redirect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedirectDecision {
    /// Send the flow to this endpoint.
    Redirect(SocketAddrV4),
    /// Leave the packet alone and record nothing; the next packet of the
    /// flow asks again.
    Pass,
    /// Drop the packet ([`reasons::DENIED`]); nothing is recorded.
    Drop,
}

/// What [`Redirect::forward`] or [`Redirect::reverse`] did with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedirectVerdict {
    /// The packet was rewritten in place.
    Rewritten,
    /// Not a packet of a redirected flow; it is unchanged.
    Pass,
    /// The packet must be dropped, for one of the [`reasons`].
    Drop(&'static str),
}

/// A snapshot of a [`Redirect`]'s counters, in packets unless stated
/// otherwise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RedirectStats {
    /// Packets rewritten to their endpoint by [`Redirect::forward`].
    pub redirected: u64,
    /// Replies rewritten to the service address by [`Redirect::reverse`].
    pub reversed: u64,
    /// Packets left alone in either direction ([`RedirectVerdict::Pass`]).
    pub passed: u64,
    /// Packets dropped with [`reasons::DENIED`], [`reasons::CONNTRACK_FULL`]
    /// or [`reasons::MALFORMED`].
    pub dropped: u64,
    /// Packets dropped with [`reasons::ENDPOINT_EXHAUSTED`].
    pub conflicts: u64,
    /// The flow table, in flows.
    pub conntrack: ConntrackStats,
}

#[derive(Debug, Default)]
struct Counters {
    redirected: AtomicU64,
    reversed: AtomicU64,
    passed: AtomicU64,
    dropped: AtomicU64,
    conflicts: AtomicU64,
}

/// Local-side redirect of IPv4 TCP/UDP flows; see the [module docs](self).
pub struct Redirect {
    conntrack: Conntrack,
    decide: Decide,
    counters: Counters,
}

impl fmt::Debug for Redirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redirect")
            .field("conntrack", &self.conntrack)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl Redirect {
    /// A redirect whose new flows go where `decide` says, with flows in a
    /// [`Conntrack`] of the default [`ConntrackConfig`].
    ///
    /// `decide` gets the first packet's tuple (application -> service) and
    /// runs without any lock of the `Redirect` held, so it may call back into
    /// it; see the [module docs](self#concurrency).
    pub fn new(decide: impl Fn(&FiveTuple) -> RedirectDecision + Send + Sync + 'static) -> Self {
        Self::with_conntrack(Conntrack::new(ConntrackConfig::default()), decide)
    }

    /// As [`new`](Self::new), with flows in `conntrack` (its size and idle
    /// timeouts, a clock or a removal hook). Every flow it holds gets
    /// `PeerId::new(0)` as its [`Flow::peer`].
    ///
    /// `decide` runs without the `Conntrack` lock or any lock of the
    /// `Redirect` held, so it may call [`remove_flow`](Self::remove_flow),
    /// [`retain`](Self::retain) or
    /// [`original_destination`](Self::original_destination) without
    /// deadlocking.
    pub fn with_conntrack(
        conntrack: Conntrack,
        decide: impl Fn(&FiveTuple) -> RedirectDecision + Send + Sync + 'static,
    ) -> Self {
        Self {
            conntrack,
            decide: Box::new(decide),
            counters: Counters::default(),
        }
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> RedirectStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let c = &self.counters;
        RedirectStats {
            redirected: load(&c.redirected),
            reversed: load(&c.reversed),
            passed: load(&c.passed),
            dropped: load(&c.dropped),
            conflicts: load(&c.conflicts),
            conntrack: self.conntrack.stats(),
        }
    }

    /// Rewrites the destination of a local packet (application -> service)
    /// to its flow's endpoint, in place, asking the decision closure for an
    /// untracked flow; see the [module docs](self).
    pub fn forward(&self, packet: &mut PacketBuf) -> RedirectVerdict {
        let result = self.forward_inner(packet);
        self.count(result, &self.counters.redirected)
    }

    /// Rewrites the source of a reply (endpoint -> application) of a tracked
    /// flow to the service address, in place; see the [module docs](self).
    pub fn reverse(&self, packet: &mut PacketBuf) -> RedirectVerdict {
        let result = self.reverse_inner(packet);
        self.count(result, &self.counters.reversed)
    }

    /// The service address the application sent the flow between `endpoint`
    /// and `remote` (the application's address) to, as the endpoint sees the
    /// flow; `None` without a live TCP or UDP flow. Refreshes the flow.
    pub fn original_destination(
        &self,
        protocol: u8,
        endpoint: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> Option<SocketAddrV4> {
        let reply = reply_tuple(protocol, endpoint, remote)?;
        let found = self.conntrack.lookup(&reply, None)?;
        if found.direction != FlowDirection::Reply {
            return None;
        }
        match found.flow.original.dst {
            IpAddr::V4(addr) => Some(SocketAddrV4::new(addr, found.flow.original.dst_port)),
            IpAddr::V6(_) => None,
        }
    }

    /// Removes the flow between `endpoint` and `remote` (the application's
    /// address), as the endpoint sees it, as ns `remove_netstack_flow`.
    /// Returns whether a flow was removed; the next packet of the flow asks
    /// the decision closure again.
    pub fn remove_flow(&self, protocol: u8, endpoint: SocketAddrV4, remote: SocketAddrV4) -> bool {
        reply_tuple(protocol, endpoint, remote)
            .is_some_and(|reply| self.conntrack.remove(&reply).is_some())
    }

    /// Removes every flow for which `keep` returns `false` (e.g. the flows
    /// to a revoked service, or every UDP flow) and returns how many were
    /// removed.
    ///
    /// `keep` runs under the `Conntrack` lock, so it must not call back into
    /// this `Redirect`.
    pub fn retain(&self, keep: impl FnMut(&Flow) -> bool) -> usize {
        self.conntrack.retain(keep)
    }

    /// Counts a packet: `Ok(true)` under `rewritten`, `Ok(false)` as passed,
    /// a drop under its reason.
    fn count(&self, result: Result<bool, &'static str>, rewritten: &AtomicU64) -> RedirectVerdict {
        let c = &self.counters;
        let (counter, verdict) = match result {
            Ok(true) => (rewritten, RedirectVerdict::Rewritten),
            Ok(false) => (&c.passed, RedirectVerdict::Pass),
            Err(reason) => {
                let counter = match reason {
                    reasons::ENDPOINT_EXHAUSTED => &c.conflicts,
                    _ => &c.dropped,
                };
                (counter, RedirectVerdict::Drop(reason))
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
        verdict
    }

    fn forward_inner(&self, packet: &mut PacketBuf) -> Result<bool, &'static str> {
        let Some(info) = Info::parse(packet) else {
            return Ok(false);
        };
        let translated = match self.conntrack.lookup(&info.tuple, Some(info.tcp_flags)) {
            Some(found) if found.direction == FlowDirection::Original => found.flow.translated,
            _ => match self.new_flow(&info.tuple, info.tcp_flags)? {
                Some(translated) => translated,
                None => return Ok(false),
            },
        };
        rewrite::endpoint(
            packet.as_packet_mut(),
            info.l4,
            End::Dst,
            translated.dst,
            translated.dst_port,
        )
        .ok_or(reasons::MALFORMED)?;
        Ok(true)
    }

    fn reverse_inner(&self, packet: &mut PacketBuf) -> Result<bool, &'static str> {
        let Some(info) = Info::parse(packet) else {
            return Ok(false);
        };
        let original = match self.conntrack.lookup(&info.tuple, Some(info.tcp_flags)) {
            Some(found) if found.direction == FlowDirection::Reply => found.flow.original,
            _ => return Ok(false),
        };
        rewrite::endpoint(
            packet.as_packet_mut(),
            info.l4,
            End::Src,
            original.dst,
            original.dst_port,
        )
        .ok_or(reasons::MALFORMED)?;
        Ok(true)
    }

    /// Asks the decision closure for the endpoint of a new flow and records
    /// it; returns the translated tuple, or `None` when the flow passes.
    fn new_flow(&self, original: &FiveTuple, flags: u8) -> Result<Option<FiveTuple>, &'static str> {
        for _ in 0..ENDPOINT_TRIES {
            // No lock is held here: the closure may call back into `self`.
            let endpoint = match (self.decide)(original) {
                RedirectDecision::Redirect(endpoint) => endpoint,
                RedirectDecision::Pass => return Ok(None),
                RedirectDecision::Drop => return Err(reasons::DENIED),
            };
            let translated = FiveTuple {
                dst: IpAddr::V4(*endpoint.ip()),
                dst_port: endpoint.port(),
                ..*original
            };
            match self.conntrack.insert(PEER, *original, translated, flags) {
                // A concurrent packet of the same flow may have recorded it
                // first; its endpoint wins.
                Ok(flow) => return Ok(Some(flow.translated)),
                Err(ConntrackError::Conflict) => {}
                Err(ConntrackError::Full) => return Err(reasons::CONNTRACK_FULL),
                Err(ConntrackError::Unsupported) => return Err(reasons::MALFORMED),
            }
        }
        Err(reasons::ENDPOINT_EXHAUSTED)
    }
}

/// What the redirect needs of a packet it may rewrite.
struct Info {
    tuple: FiveTuple,
    /// Offset of the transport header.
    l4: usize,
    /// TCP flags, 0 for UDP.
    tcp_flags: u8,
}

impl Info {
    /// `None` for packets the redirect never touches: malformed, IPv6,
    /// fragmented, or neither TCP nor UDP.
    fn parse(packet: &PacketBuf) -> Option<Self> {
        let ip = IpPacket::parse(packet.as_packet()).ok()?;
        let IpPacket::V4 { header, .. } = &ip else {
            return None;
        };
        if ip.fragment().is_some() || !matches!(ip.protocol(), protocol::TCP | protocol::UDP) {
            return None;
        }
        let tuple = ip.five_tuple()?;
        let tcp_flags = if tuple.protocol == protocol::TCP {
            ip.payload().get(13).copied().unwrap_or(0)
        } else {
            0
        };
        Some(Self {
            tuple,
            l4: header.header_len(),
            tcp_flags,
        })
    }
}

/// The tuple of a reply from `endpoint` to `remote`; `None` unless
/// `protocol` is TCP or UDP.
fn reply_tuple(protocol: u8, endpoint: SocketAddrV4, remote: SocketAddrV4) -> Option<FiveTuple> {
    matches!(protocol, protocol::TCP | protocol::UDP).then(|| FiveTuple {
        src: IpAddr::V4(*endpoint.ip()),
        dst: IpAddr::V4(*remote.ip()),
        protocol,
        src_port: endpoint.port(),
        dst_port: remote.port(),
    })
}
