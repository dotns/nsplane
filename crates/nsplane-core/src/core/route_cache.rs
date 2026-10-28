// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The allowed-IP lookups of the data path: per batch and across calls.

use std::fmt;
use std::net::IpAddr;

use nsplane_packet::PeerId;

use crate::allowed_ips::AllowedIps;
use crate::peer_table::PeerTable;

/// Lookups that consecutive data packets of a batch share: the peer and slot of a session and
/// a destination a peer may send to. Only configuration changes the peer table, and a batch
/// holds none, so they stay valid for the whole batch; a batch of datagrams still starts over
/// after every handshake message, the only other message it holds. Routes and source checks
/// are kept across calls in the [`RouteCache`].
#[derive(Debug, Default)]
pub(super) struct Lookups {
    /// The last receiver index, with its peer and slot.
    session: Option<(u32, PeerId, usize)>,
    /// The last destination accepted from a peer with inbound destinations.
    destination: Option<(IpAddr, PeerId)>,
}

impl Lookups {
    /// The peer and slot that own the session of `receiver_idx`.
    pub(super) fn session(
        &mut self,
        peers: &PeerTable,
        receiver_idx: u32,
    ) -> Option<(PeerId, usize)> {
        if let Some((idx, id, slot)) = self.session
            && idx == receiver_idx
        {
            return Some((id, slot));
        }
        let id = peers.by_index(receiver_idx)?;
        let slot = peers.slot(id)?;
        self.session = Some((receiver_idx, id, slot));
        Some((id, slot))
    }

    /// Whether peer `id`, whose inbound destinations are `set`, may send packets to `dst`.
    pub(super) fn destination_allowed(
        &mut self,
        set: &AllowedIps<()>,
        dst: IpAddr,
        id: PeerId,
    ) -> bool {
        if self.destination == Some((dst, id)) {
            return true;
        }
        let allowed = set.find(dst).is_some();
        if allowed {
            self.destination = Some((dst, id));
        }
        allowed
    }
}

/// Entries of each table of the [`RouteCache`]; a power of two.
const ROUTE_CACHE_ENTRIES: usize = 64;

/// The place of `addr` in a table of the [`RouteCache`].
fn cache_index(addr: IpAddr) -> usize {
    let word = match addr {
        IpAddr::V4(a) => u64::from(u32::from(a)),
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            u64::try_from((bits ^ (bits >> 64)) & u128::from(u64::MAX)).unwrap_or(0)
        }
    };
    let hash =
        word.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - ROUTE_CACHE_ENTRIES.trailing_zeros());
    usize::try_from(hash).unwrap_or(0)
}

/// A source (`None` if unreadable) and a destination, with the peer and slot they are routed
/// to with source sets.
type SelectedRoute = (Option<IpAddr>, IpAddr, PeerId, usize);

/// The allowed-IP lookups of the data path, kept across calls: the peer and slot a destination
/// is routed to, with source sets the same for a source and a destination (so a known flow
/// skips the source-set lookup), and the sources a peer may send from. Only positive answers
/// are kept. Each table is direct mapped on a hash of the address; a new entry replaces the
/// one in its place. Every entry is dropped once the peer table changes (its generation
/// moves), so an entry always holds what the peer table answers.
pub(super) struct RouteCache {
    /// The peer table generation the entries were looked up in.
    generation: u64,
    /// Destinations, with the peer and slot they are routed to.
    route: [Option<(IpAddr, PeerId, usize)>; ROUTE_CACHE_ENTRIES],
    /// With source sets: sources and destinations, with their route.
    selected_route: [Option<SelectedRoute>; ROUTE_CACHE_ENTRIES],
    /// Sources accepted from a peer.
    source: [Option<(IpAddr, PeerId)>; ROUTE_CACHE_ENTRIES],
}

impl fmt::Debug for RouteCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteCache")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl RouteCache {
    pub(super) const fn new(generation: u64) -> Self {
        Self {
            generation,
            route: [None; ROUTE_CACHE_ENTRIES],
            selected_route: [None; ROUTE_CACHE_ENTRIES],
            source: [None; ROUTE_CACHE_ENTRIES],
        }
    }

    /// Drops every entry if the peer table changed since they were looked up.
    const fn sync(&mut self, peers: &PeerTable) {
        if self.generation != peers.generation() {
            *self = Self::new(peers.generation());
        }
    }

    /// The peer and slot a packet to `dst` is routed to.
    pub(super) fn route(&mut self, peers: &PeerTable, dst: IpAddr) -> Option<(PeerId, usize)> {
        self.sync(peers);
        let entry = self.route.get_mut(cache_index(dst))?;
        if let Some((last, id, slot)) = *entry
            && last == dst
        {
            return Some((id, slot));
        }
        let id = peers.by_destination(dst)?;
        let slot = peers.slot(id)?;
        *entry = Some((dst, id, slot));
        Some((id, slot))
    }

    /// The peer and slot a packet from `src` to `dst` is routed to, with source sets: in the
    /// table of the identity whose set matches `src`, otherwise in the fallback table.
    pub(super) fn route_from(
        &mut self,
        peers: &PeerTable,
        src: Option<IpAddr>,
        dst: IpAddr,
    ) -> Option<(PeerId, usize)> {
        self.sync(peers);
        let index = cache_index(dst) ^ src.map_or(0, cache_index);
        let entry = self.selected_route.get_mut(index)?;
        if let Some((last_src, last, id, slot)) = *entry
            && last_src == src
            && last == dst
        {
            return Some((id, slot));
        }
        let identity = src.and_then(|src| peers.source_identity(src));
        let id = peers.route_in(identity, dst)?;
        let slot = peers.slot(id)?;
        *entry = Some((src, dst, id, slot));
        Some((id, slot))
    }

    /// Whether peer `id` may send packets from `src`.
    pub(super) fn source_allowed(&mut self, peers: &PeerTable, src: IpAddr, id: PeerId) -> bool {
        self.sync(peers);
        let Some(entry) = self.source.get_mut(cache_index(src)) else {
            return false;
        };
        if *entry == Some((src, id)) {
            return true;
        }
        let allowed = peers.routes_to(src, id);
        if allowed {
            *entry = Some((src, id));
        }
        allowed
    }
}
