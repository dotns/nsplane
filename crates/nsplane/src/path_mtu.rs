//! Per-path MTU ceilings: what the outer paths carry, and the inner MTU each peer gets.
//!
//! Two kinds of ceiling limit the datagrams of a path:
//!
//! - per transport, the largest WireGuard datagram (the bytes handed to
//!   [`Transport::send`]) the caller sets for it
//!   ([`EngineBuilder::transport_max_datagram`], [`EngineHandle::set_transport_max_datagram`]);
//! - per path (transport and remote address), the outer IP MTU learned from reports
//!   ([`EngineHandle::report_path_mtu`], [`Transport::path_mtu_reports`]); it only goes down,
//!   and expires a while after the last report that confirmed it, which restores the
//!   transport's ceiling.
//!
//! The inner MTU of a peer follows the path its data leaves on ([`Core::data_path`]):
//! `min(source MTU, ceiling - 32)`, where the ceiling of a path is the lower of its
//! transport's ceiling and its learned MTU less the IP (20 for IPv4 and IPv4-mapped, 40 for
//! IPv6) and UDP (8) headers, and 32 is the transport data message's overhead. A path
//! without a ceiling leaves the source MTU, and a ceiling never takes the inner MTU below
//! the IPv6 minimum of 1280. A path MTU of 1500 over IPv6 gives 1420. The padding of a
//! constrained peer's data stops at its inner MTU ([`Core::set_peer_pad_limit`]), as the
//! kernel pads to the MTU, so a packet at the inner MTU makes an outer packet of exactly the
//! path MTU (earlier, padding to a multiple of 16 bytes could overshoot it by up to 15).
//!
//! The inner MTU reaches the local kernel or stack only through the fragmentation stage
//! ([`EngineBuilder::fragmenter`]: Packet Too Big, Fragmentation Needed and fragments sized
//! for the destination's peer) or through ICMP the caller generates from
//! [`EngineHandle::peer_mtus`]; without a fragmenter the per-peer value is visible only
//! there. The source MTU ([`EngineHandle::mtu`], `Event::MtuChanged`) keeps its meaning.
//! Linux learns path MTUs from the socket's ICMP errors; macOS and Windows deliver no
//! Packet Too Big to the transport, so the explicit API is the way to set ceilings there.
//! There is no probing: a ceiling only rises when it expires.
//!
//! The engine keeps this state only once the feature is used; until then nothing of it
//! costs anything.
//!
//! [`Transport::send`]: crate::Transport::send
//! [`Transport::path_mtu_reports`]: crate::Transport::path_mtu_reports
//! [`EngineBuilder::transport_max_datagram`]: crate::EngineBuilder::transport_max_datagram
//! [`EngineBuilder::fragmenter`]: crate::EngineBuilder::fragmenter
//! [`EngineHandle::set_transport_max_datagram`]: crate::EngineHandle::set_transport_max_datagram
//! [`EngineHandle::report_path_mtu`]: crate::EngineHandle::report_path_mtu
//! [`EngineHandle::peer_mtus`]: crate::EngineHandle::peer_mtus
//! [`EngineHandle::mtu`]: crate::EngineHandle::mtu

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use nsplane_core::Core;
use nsplane_packet::{Path, PeerId, TransportId};

use crate::handle::{PathMtuStats, PeerMtus};
use crate::transport::PathMtuReport;

/// How long a learned path MTU lasts after the last report that confirmed it.
pub(crate) const DEFAULT_EXPIRY: Duration = Duration::from_secs(600);
/// Header and authentication tag of a transport data message.
const DATA_OVERHEAD: u16 = 32;
/// UDP header.
const UDP_HEADER: u16 = 8;
/// No ceiling takes a peer's inner MTU below the IPv6 minimum MTU.
const MIN_INNER: u16 = 1280;
/// The smallest outer MTU accepted for an IPv6 path (the IPv6 minimum MTU)...
const MIN_OUTER_V6: u16 = 1280;
/// ... and for an IPv4 path (the minimum reassembly size).
const MIN_OUTER_V4: u16 = 576;
/// RFC 1191 plateaus for a report that does not carry the MTU, highest first.
const PLATEAUS: [u16; 4] = [1492, 1280, 1006, 576];
/// The WireGuard message type of transport data, the first byte of a quoted datagram.
const TRANSPORT_DATA: u8 = 4;

/// What the table needs to know about the peers: [`Core`], or a stand-in in tests.
pub(crate) trait Peers {
    /// Every peer.
    fn ids(&self) -> Vec<PeerId>;
    /// The path the peer's data leaves on ([`Core::data_path`]).
    fn data_path(&self, peer: PeerId) -> Option<Path>;
    /// The peer's stored (current) path.
    fn stored_path(&self, peer: PeerId) -> Option<Path>;
    /// [`Core::is_remote_index`].
    fn is_remote_index(&self, peer: PeerId, index: u32) -> bool;
}

impl Peers for Core {
    fn ids(&self) -> Vec<PeerId> {
        self.peers().collect()
    }

    fn data_path(&self, peer: PeerId) -> Option<Path> {
        Self::data_path(self, peer)
    }

    fn stored_path(&self, peer: PeerId) -> Option<Path> {
        self.peer_stats(peer)?.path
    }

    fn is_remote_index(&self, peer: PeerId, index: u32) -> bool {
        Self::is_remote_index(self, peer, index)
    }
}

/// A path MTU learned from reports.
#[derive(Debug, Clone, Copy)]
struct Learned {
    mtu: u16,
    expires: Instant,
}

/// What a report did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Not accepted: unknown path, wrong quote, or nothing lower.
    Ignored,
    /// The learned value was confirmed; it expires later.
    Refreshed,
    /// The path's MTU went down; the peers' inner MTUs need recomputing.
    Lowered,
}

/// The ceilings and the inner MTU of every peer below the source MTU; see the module docs.
#[derive(Debug)]
pub(crate) struct PathMtu {
    expiry: Duration,
    /// Largest WireGuard datagram per transport.
    transports: BTreeMap<TransportId, u16>,
    /// Learned outer IP MTU per path.
    paths: HashMap<(TransportId, SocketAddr), Learned>,
    /// The earliest expiry of `paths`.
    earliest: Option<Instant>,
    /// The inner MTU of every peer below the source MTU.
    peers: BTreeMap<PeerId, u16>,
    /// The lowest inner MTU any path can have under the current ceilings; `u16::MAX`
    /// without ceilings.
    lowest: u16,
    /// `peers` changed since the last [`PathMtu::take_changed`].
    changed: bool,
    stats: PathMtuStats,
}

impl PathMtu {
    pub(crate) fn new(expiry: Duration) -> Self {
        Self {
            expiry,
            transports: BTreeMap::new(),
            paths: HashMap::new(),
            earliest: None,
            peers: BTreeMap::new(),
            lowest: u16::MAX,
            changed: false,
            stats: PathMtuStats::default(),
        }
    }

    /// Sets or clears the largest datagram of `transport`; whether it changed.
    pub(crate) fn set_transport_max(&mut self, transport: TransportId, max: Option<u16>) -> bool {
        let old = match max {
            Some(max) => self.transports.insert(transport, max),
            None => self.transports.remove(&transport),
        };
        let changed = old != max;
        if changed {
            self.update_lowest();
        }
        changed
    }

    /// Validates and applies `report` (see [`crate::EngineHandle::report_path_mtu`]).
    pub(crate) fn report(
        &mut self,
        report: &PathMtuReport,
        now: Instant,
        peers: &impl Peers,
    ) -> Verdict {
        self.stats.reports += 1;
        let verdict = self.judge(report, now, peers);
        match verdict {
            Verdict::Ignored => self.stats.ignored += 1,
            Verdict::Refreshed | Verdict::Lowered => self.stats.applied += 1,
        }
        verdict
    }

    fn judge(&mut self, report: &PathMtuReport, now: Instant, peers: &impl Peers) -> Verdict {
        let path = report.path;
        let same = |p: Option<Path>| {
            p.is_some_and(|p| p.transport == path.transport && p.addr == path.addr)
        };
        let owners: Vec<PeerId> = peers
            .ids()
            .into_iter()
            .filter(|&peer| same(peers.data_path(peer)) || same(peers.stored_path(peer)))
            .collect();
        if owners.is_empty() {
            tracing::debug!(?path, "path MTU report for an unknown path");
            return Verdict::Ignored;
        }
        let quote = report.quote();
        if quote.first().is_some_and(|&kind| kind != TRANSPORT_DATA) {
            tracing::debug!(?path, "path MTU report quoting no transport data");
            return Verdict::Ignored;
        }
        if let Some(index) = quote.get(4..8) {
            let index = u32::from_le_bytes([index[0], index[1], index[2], index[3]]);
            if !owners
                .iter()
                .any(|&peer| peers.is_remote_index(peer, index))
            {
                tracing::debug!(?path, index, "path MTU report quoting another session");
                return Verdict::Ignored;
            }
        }

        let key = (path.transport, path.addr);
        let header = ip_overhead(path.addr) + UDP_HEADER;
        // The outer MTU the transport ceiling alone allows.
        let unconstrained = self
            .transports
            .get(&path.transport)
            .map_or(u32::MAX, |&max| u32::from(max) + u32::from(header));
        let learned = self.paths.get(&key).map(|learned| learned.mtu);
        let mtu = match report.mtu {
            0 => {
                let current = learned.map_or(unconstrained, u32::from);
                PLATEAUS
                    .into_iter()
                    .find(|&plateau| u32::from(plateau) < current)
                    .unwrap_or(MIN_OUTER_V4)
            }
            mtu => mtu,
        };
        let mtu = mtu.max(if is_ipv6(path.addr) {
            MIN_OUTER_V6
        } else {
            MIN_OUTER_V4
        });
        if u32::from(mtu) >= unconstrained {
            return Verdict::Ignored;
        }
        let expires = now + self.expiry;
        match learned {
            Some(learned) if mtu > learned => Verdict::Ignored,
            Some(learned) if mtu == learned => {
                self.learn(key, mtu, expires);
                Verdict::Refreshed
            }
            _ => {
                tracing::debug!(?path, mtu, "path MTU lowered");
                self.learn(key, mtu, expires);
                self.update_lowest();
                Verdict::Lowered
            }
        }
    }

    fn learn(&mut self, key: (TransportId, SocketAddr), mtu: u16, expires: Instant) {
        let old = self.paths.insert(key, Learned { mtu, expires });
        self.earliest = match (old, self.earliest) {
            // The entry that expired first may have moved later.
            (Some(old), Some(earliest)) if old.expires == earliest => {
                self.paths.values().map(|learned| learned.expires).min()
            }
            (_, earliest) => Some(earliest.map_or(expires, |e| e.min(expires))),
        };
    }

    /// Forgets the learned MTUs that expired at `now`; whether any did.
    pub(crate) fn expire(&mut self, now: Instant) -> bool {
        if self.earliest.is_none_or(|earliest| earliest > now) {
            return false;
        }
        let before = self.paths.len();
        self.paths.retain(|_, learned| learned.expires > now);
        let expired = before - self.paths.len();
        self.stats.expired += expired as u64;
        self.earliest = self.paths.values().map(|learned| learned.expires).min();
        self.update_lowest();
        tracing::debug!(expired, "path MTUs expired");
        expired > 0
    }

    /// When the next learned MTU expires; `None` while there is none.
    pub(crate) const fn next_expiry(&self) -> Option<Instant> {
        self.earliest
    }

    /// The largest datagram `path` carries; `None` without a ceiling.
    fn ceiling(&self, path: Path) -> Option<u16> {
        let transport = self.transports.get(&path.transport).copied();
        let learned = self.paths.get(&(path.transport, path.addr)).map(|learned| {
            learned
                .mtu
                .saturating_sub(ip_overhead(path.addr) + UDP_HEADER)
        });
        match (transport, learned) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The inner MTU of a peer whose data leaves on `path`, under the source MTU `source`.
    pub(crate) fn inner(&self, path: Option<Path>, source: u16) -> u16 {
        path.and_then(|path| self.ceiling(path))
            .map_or(source, |ceiling| source.min(inner_of(ceiling)))
    }

    /// The fragmentation stage's fast check: no peer's inner MTU is below this, whatever
    /// path it uses.
    pub(crate) fn floor(&self, source: u16) -> u16 {
        source.min(self.lowest)
    }

    fn update_lowest(&mut self) {
        let transports = self.transports.values().copied();
        let paths = self.paths.iter().filter_map(|(&(transport, addr), _)| {
            self.ceiling(Path {
                transport,
                addr,
                ecn: nsplane_packet::Ecn::NotEct,
            })
        });
        self.lowest = transports
            .chain(paths)
            .map(inner_of)
            .min()
            .unwrap_or(u16::MAX);
    }

    /// The inner MTU of `peer` whose data leaves on `path`; records it when it changed.
    pub(crate) fn peer(&mut self, peer: PeerId, path: Option<Path>, source: u16) -> u16 {
        let mtu = self.inner(path, source);
        let old = if mtu < source {
            self.peers.insert(peer, mtu)
        } else {
            self.peers.remove(&peer)
        };
        if old.unwrap_or(source) != mtu {
            self.changed = true;
        }
        mtu
    }

    /// Recomputes the inner MTU of every peer.
    pub(crate) fn recompute(&mut self, peers: &impl Peers, source: u16) {
        let ids = peers.ids();
        let before = self.peers.len();
        self.peers.retain(|peer, _| ids.binary_search(peer).is_ok());
        if self.peers.len() != before {
            self.changed = true;
        }
        for peer in ids {
            self.peer(peer, peers.data_path(peer), source);
        }
    }

    /// Whether the peers' inner MTUs changed since the last [`PathMtu::take_changed`].
    pub(crate) const fn changed(&self) -> bool {
        self.changed
    }

    /// Whether the peers' inner MTUs changed since the last call.
    pub(crate) const fn take_changed(&mut self) -> bool {
        std::mem::replace(&mut self.changed, false)
    }

    /// The published form under the source MTU `source`.
    pub(crate) fn peer_mtus(&self, source: u16) -> PeerMtus {
        PeerMtus {
            min: self.peers.values().copied().fold(source, u16::min),
            peers: self.peers.clone(),
        }
    }

    pub(crate) fn stats(&self) -> PathMtuStats {
        PathMtuStats {
            paths: self.paths.len(),
            ..self.stats
        }
    }
}

/// The inner MTU under a datagram ceiling, at least [`MIN_INNER`].
fn inner_of(ceiling: u16) -> u16 {
    ceiling.saturating_sub(DATA_OVERHEAD).max(MIN_INNER)
}

/// Whether the outer packets to `addr` are IPv6 (IPv4-mapped addresses are IPv4).
const fn is_ipv6(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(_) => false,
        IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none(),
    }
}

/// The IP header of the outer packets to `addr`.
const fn ip_overhead(addr: SocketAddr) -> u16 {
    if is_ipv6(addr) { 40 } else { 20 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsplane_packet::Ecn;

    const T1: TransportId = TransportId::new(1);
    const T2: TransportId = TransportId::new(2);
    const A: PeerId = PeerId::new(1);
    const B: PeerId = PeerId::new(2);
    const EXPIRY: Duration = Duration::from_secs(60);

    fn path(transport: TransportId, addr: &str) -> Path {
        Path {
            transport,
            addr: addr.parse().unwrap(),
            ecn: Ecn::NotEct,
        }
    }

    fn v6() -> Path {
        path(T1, "[2001:db8::1]:51820")
    }

    fn v4() -> Path {
        path(T1, "192.0.2.1:51820")
    }

    fn mapped() -> Path {
        path(T1, "[::ffff:192.0.2.1]:51820")
    }

    /// A peer, its data path, its stored path and its remote index.
    type FakePeer = (PeerId, Option<Path>, Option<Path>, Option<u32>);

    /// Peers with fixed data paths, stored paths and remote indexes.
    #[derive(Default)]
    struct Fake(Vec<FakePeer>);

    impl Fake {
        fn with(mut self, peer: PeerId, data: Path, index: u32) -> Self {
            self.0.push((peer, Some(data), Some(data), Some(index)));
            self
        }
    }

    impl Peers for Fake {
        fn ids(&self) -> Vec<PeerId> {
            self.0.iter().map(|p| p.0).collect()
        }

        fn data_path(&self, peer: PeerId) -> Option<Path> {
            self.0.iter().find(|p| p.0 == peer)?.1
        }

        fn stored_path(&self, peer: PeerId) -> Option<Path> {
            self.0.iter().find(|p| p.0 == peer)?.2
        }

        fn is_remote_index(&self, peer: PeerId, index: u32) -> bool {
            self.0.iter().any(|p| p.0 == peer && p.3 == Some(index))
        }
    }

    fn quote(index: u32) -> Vec<u8> {
        let mut quote = vec![4, 0, 0, 0];
        quote.extend_from_slice(&index.to_le_bytes());
        quote
    }

    #[test]
    fn derivation_by_address_family() {
        let now = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        let peers = Fake::default().with(A, v6(), 1).with(B, v4(), 2);
        assert_eq!(table.inner(Some(v6()), 1500), 1500);
        assert_eq!(table.inner(None, 1500), 1500);

        table.report(&PathMtuReport::new(v6(), 1500), now, &peers);
        assert_eq!(table.inner(Some(v6()), 9000), 1420);
        table.report(&PathMtuReport::new(v4(), 1500), now, &peers);
        assert_eq!(table.inner(Some(v4()), 9000), 1440);
        // IPv4-mapped is IPv4 on the wire.
        let mapped_peers = Fake::default().with(A, mapped(), 1);
        table.report(&PathMtuReport::new(mapped(), 1500), now, &mapped_peers);
        assert_eq!(table.inner(Some(mapped()), 9000), 1440);
        // The source MTU caps it.
        assert_eq!(table.inner(Some(v6()), 1400), 1400);
    }

    #[test]
    fn transport_and_path_ceilings_take_the_lower() {
        let now = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        let peers = Fake::default().with(A, v6(), 1);
        assert!(table.set_transport_max(T1, Some(1400)));
        assert!(!table.set_transport_max(T1, Some(1400)));
        assert_eq!(table.inner(Some(v6()), 1500), 1368);
        // Another transport is not limited.
        assert_eq!(table.inner(Some(path(T2, "[2001:db8::1]:1")), 1500), 1500);
        // A path MTU below the transport ceiling wins: 1400 - 48 - 32.
        assert_eq!(
            table.report(&PathMtuReport::new(v6(), 1400), now, &peers),
            Verdict::Lowered
        );
        assert_eq!(table.inner(Some(v6()), 1500), 1320);
        // Clearing the transport ceiling leaves the path's.
        assert!(table.set_transport_max(T1, None));
        assert_eq!(table.inner(Some(v6()), 1500), 1320);
    }

    #[test]
    fn ceilings_never_go_below_1280() {
        let mut table = PathMtu::new(EXPIRY);
        table.set_transport_max(T1, Some(600));
        assert_eq!(table.inner(Some(v6()), 1500), 1280);
        assert_eq!(table.floor(1500), 1280);
        // A source below 1280 stays the cap.
        assert_eq!(table.inner(Some(v6()), 1000), 1000);
        assert_eq!(table.floor(1000), 1000);
    }

    #[test]
    fn unknown_paths_wrong_types_and_wrong_indexes_are_ignored() {
        let now = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        let peers = Fake::default().with(A, v6(), 7);
        let ignored = |table: &mut PathMtu, report: PathMtuReport| {
            table.report(&report, now, &peers) == Verdict::Ignored
        };
        assert!(ignored(&mut table, PathMtuReport::new(v4(), 1400)));
        // Same address on another transport.
        let other = path(T2, "[2001:db8::1]:51820");
        assert!(ignored(&mut table, PathMtuReport::new(other, 1400)));
        assert!(ignored(
            &mut table,
            PathMtuReport::with_quote(v6(), 1400, &[1])
        ));
        let mut init = quote(7);
        init[0] = 1;
        assert!(ignored(
            &mut table,
            PathMtuReport::with_quote(v6(), 1400, &init)
        ));
        assert!(ignored(
            &mut table,
            PathMtuReport::with_quote(v6(), 1400, &quote(8))
        ));
        assert_eq!(table.stats().ignored, 5);
        assert_eq!(table.stats().applied, 0);
        assert_eq!(table.inner(Some(v6()), 1500), 1500);

        // A type alone, the right index, or no quote are accepted.
        assert_eq!(
            table.report(&PathMtuReport::with_quote(v6(), 1450, &[4, 0]), now, &peers),
            Verdict::Lowered
        );
        assert_eq!(
            table.report(
                &PathMtuReport::with_quote(v6(), 1400, &quote(7)),
                now,
                &peers
            ),
            Verdict::Lowered
        );
        assert_eq!(
            table.report(&PathMtuReport::new(v6(), 1300), now, &peers),
            Verdict::Lowered
        );
        let stats = table.stats();
        assert_eq!((stats.reports, stats.applied, stats.paths), (8, 3, 1));
    }

    #[test]
    fn stored_paths_count_as_known() {
        let now = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        // Data goes on v6 by policy, the stored path is v4.
        let peers = Fake(vec![(A, Some(v6()), Some(v4()), None)]);
        assert_eq!(
            table.report(&PathMtuReport::new(v4(), 1000), now, &peers),
            Verdict::Lowered
        );
    }

    #[test]
    fn missing_mtus_take_the_next_plateau() {
        let now = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        let peers = Fake::default().with(A, v4(), 1);
        for expected in [1492, 1280, 1006, 576] {
            assert_eq!(
                table.report(&PathMtuReport::new(v4(), 0), now, &peers),
                Verdict::Lowered
            );
            assert_eq!(table.paths[&(T1, v4().addr)].mtu, expected);
        }
        // At the lowest plateau: confirmed, no lower.
        assert_eq!(
            table.report(&PathMtuReport::new(v4(), 0), now, &peers),
            Verdict::Refreshed
        );
        // Below the transport ceiling's outer size: 1300 + 28.
        let mut table = PathMtu::new(EXPIRY);
        table.set_transport_max(T1, Some(1300));
        table.report(&PathMtuReport::new(v4(), 0), now, &peers);
        assert_eq!(table.paths[&(T1, v4().addr)].mtu, 1280);
    }

    #[test]
    fn reports_are_clamped_to_the_family_minimum() {
        let now = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        let peers = Fake::default().with(A, v6(), 1).with(B, v4(), 2);
        table.report(&PathMtuReport::new(v6(), 500), now, &peers);
        assert_eq!(table.paths[&(T1, v6().addr)].mtu, 1280);
        table.report(&PathMtuReport::new(v4(), 68), now, &peers);
        assert_eq!(table.paths[&(T1, v4().addr)].mtu, 576);
    }

    #[test]
    fn only_decreases_apply_and_equal_reports_refresh() {
        let start = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        let peers = Fake::default().with(A, v6(), 1);
        assert_eq!(
            table.report(&PathMtuReport::new(v6(), 1400), start, &peers),
            Verdict::Lowered
        );
        assert_eq!(
            table.report(&PathMtuReport::new(v6(), 1450), start, &peers),
            Verdict::Ignored
        );
        assert_eq!(table.next_expiry(), Some(start + EXPIRY));
        let later = start + Duration::from_secs(30);
        assert_eq!(
            table.report(&PathMtuReport::new(v6(), 1400), later, &peers),
            Verdict::Refreshed
        );
        assert_eq!(table.next_expiry(), Some(later + EXPIRY));
        assert_eq!(table.inner(Some(v6()), 1500), 1320);

        // At or above the transport ceiling's outer size: nothing to learn.
        let mut table = PathMtu::new(EXPIRY);
        table.set_transport_max(T1, Some(1352));
        assert_eq!(
            table.report(&PathMtuReport::new(v6(), 1400), start, &peers),
            Verdict::Ignored
        );
        assert_eq!(
            table.report(&PathMtuReport::new(v6(), 1399), start, &peers),
            Verdict::Lowered
        );
    }

    #[test]
    fn expiry_restores_the_transport_ceiling() {
        let start = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        let peers = Fake::default().with(A, v6(), 1);
        table.set_transport_max(T1, Some(1400));
        table.report(&PathMtuReport::new(v6(), 1300), start, &peers);
        assert_eq!(table.inner(Some(v6()), 1500), 1280);
        assert!(!table.expire(start + Duration::from_secs(59)));
        assert!(table.expire(start + EXPIRY));
        assert_eq!(table.inner(Some(v6()), 1500), 1368);
        assert_eq!(table.next_expiry(), None);
        assert_eq!(table.stats().expired, 1);
        assert_eq!(table.stats().paths, 0);
    }

    #[test]
    fn the_earliest_expiry_is_tracked() {
        let start = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        let peers = Fake::default().with(A, v6(), 1).with(B, v4(), 2);
        assert_eq!(table.next_expiry(), None);
        table.report(&PathMtuReport::new(v6(), 1400), start, &peers);
        let later = start + Duration::from_secs(10);
        table.report(&PathMtuReport::new(v4(), 1400), later, &peers);
        assert_eq!(table.next_expiry(), Some(start + EXPIRY));
        // Refreshing the first moves the earliest to the second.
        let latest = start + Duration::from_secs(20);
        table.report(&PathMtuReport::new(v6(), 1400), latest, &peers);
        assert_eq!(table.next_expiry(), Some(later + EXPIRY));
        assert!(table.expire(later + EXPIRY));
        assert_eq!(table.next_expiry(), Some(latest + EXPIRY));
        assert_eq!(table.inner(Some(v4()), 1500), 1500);
        assert_eq!(table.inner(Some(v6()), 1500), 1320);
    }

    #[test]
    fn peers_below_the_source_are_recorded() {
        let now = Instant::now();
        let mut table = PathMtu::new(EXPIRY);
        let peers = Fake::default().with(A, v6(), 1).with(B, v4(), 2);
        table.recompute(&peers, 1420);
        assert!(!table.take_changed());
        table.report(&PathMtuReport::new(v6(), 1400), now, &peers);
        assert_eq!(table.floor(1420), 1320);
        table.recompute(&peers, 1420);
        assert!(table.take_changed());
        let published = table.peer_mtus(1420);
        assert_eq!(published.min, 1320);
        assert_eq!(published.peers, BTreeMap::from([(A, 1320)]));

        // The source going below the peer's value removes it.
        table.recompute(&peers, 1300);
        assert!(table.take_changed());
        assert_eq!(table.peer_mtus(1300).peers, BTreeMap::new());
        assert_eq!(table.peer_mtus(1300).min, 1300);

        // A peer that went away is dropped.
        table.recompute(&peers, 1420);
        table.take_changed();
        table.recompute(&Fake::default().with(B, v4(), 2), 1420);
        assert!(table.take_changed());
        assert!(table.peer_mtus(1420).peers.is_empty());

        // A peer whose data path changed is updated on lookup.
        assert_eq!(table.peer(B, Some(v6()), 1420), 1320);
        assert!(table.take_changed());
        assert_eq!(table.peer(B, Some(v6()), 1420), 1320);
        assert!(!table.take_changed());
    }
}
