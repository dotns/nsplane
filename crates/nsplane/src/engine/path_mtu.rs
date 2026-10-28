//! The owner task's path MTU state and the peers' inner MTUs.

use std::collections::BTreeMap;
use std::time::Duration;

use nsplane_packet::{PeerId, TransportId};
use tokio::sync::{mpsc, watch};

use super::{Owner, now};
use crate::handle::{Command, PeerMtus};
use crate::path_mtu::{PathMtu, Verdict};
use crate::transport::PathMtuReport;

/// The per-path MTU state of the owner task.
pub(super) struct PathMtus {
    /// The ceilings; `None` until a ceiling is set or a report arrives.
    pub(super) table: Option<Box<PathMtu>>,
    /// How long a learned path MTU lasts.
    expiry: Duration,
    /// The queue the transports' report forwarders feed; `None` until a transport has
    /// reports.
    pub(super) reports: Option<(mpsc::Sender<PathMtuReport>, mpsc::Receiver<PathMtuReport>)>,
    /// Publishes the peers' inner MTUs.
    pub(super) published: watch::Sender<PeerMtus>,
    /// The padding limit set in the core for each peer; empty while there is no table.
    pad_limits: BTreeMap<PeerId, u16>,
}

impl PathMtus {
    /// No table unless the builder set transport ceilings.
    pub(super) fn new(
        mtu: u16,
        transport_max: BTreeMap<TransportId, u16>,
        expiry: Duration,
    ) -> Self {
        let table = (!transport_max.is_empty()).then(|| {
            let mut table = PathMtu::new(expiry);
            for (id, max) in transport_max {
                table.set_transport_max(id, Some(max));
            }
            Box::new(table)
        });
        Self {
            table,
            expiry,
            reports: None,
            published: watch::Sender::new(PeerMtus::unconstrained(mtu)),
            pad_limits: BTreeMap::new(),
        }
    }

    /// The table, created on first use.
    fn table(&mut self) -> &mut PathMtu {
        let expiry = self.expiry;
        self.table
            .get_or_insert_with(|| Box::new(PathMtu::new(expiry)))
    }
}

impl Owner {
    /// Handles a command about the path MTUs.
    pub(super) fn path_mtu_command(&mut self, command: Command) {
        match command {
            Command::SetTransportMaxDatagram(id, max, reply) => {
                self.set_transport_max(id, max);
                let _ = reply.send(());
            }
            Command::ReportPathMtu(report, reply) => {
                let _ = reply.send(self.report_path_mtu(&report));
            }
            Command::PeerMtu(peer, reply) => {
                let _ = reply.send(self.peer_mtu(peer));
            }
            Command::PeerMtus(reply) => {
                let _ = reply.send(self.path_mtus.published.subscribe());
            }
            Command::PathMtuStats(reply) => {
                let stats = self.path_mtus.table.as_ref().map(|table| table.stats());
                let _ = reply.send(stats.unwrap_or_default());
            }
            _ => {}
        }
    }

    /// Sets or clears the largest datagram of transport `id`.
    fn set_transport_max(&mut self, id: TransportId, max: Option<u16>) {
        if max.is_none() && self.path_mtus.table.is_none() {
            return;
        }
        if self.path_mtus.table().set_transport_max(id, max) {
            self.recompute_peer_mtus();
        }
    }

    /// Validates and applies a path MTU report; whether it was accepted.
    pub(super) fn report_path_mtu(&mut self, report: &PathMtuReport) -> bool {
        let now = now();
        let verdict = self.path_mtus.table().report(report, now, &self.core);
        if verdict == Verdict::Lowered {
            self.recompute_peer_mtus();
        }
        verdict != Verdict::Ignored
    }

    /// The inner MTU of `peer`; `None` for an unknown peer.
    fn peer_mtu(&mut self, peer: PeerId) -> Option<u16> {
        self.core.peer_stats(peer)?;
        let Some(table) = &mut self.path_mtus.table else {
            return Some(self.mtu);
        };
        let mtu = table.peer(peer, self.core.data_path(peer), self.mtu);
        if table.changed() {
            self.publish_peer_mtus();
        }
        Some(mtu)
    }

    /// Recomputes every peer's inner MTU and publishes the result if it changed.
    pub(super) fn recompute_peer_mtus(&mut self) {
        if let Some(table) = &mut self.path_mtus.table {
            table.recompute(&self.core, self.mtu);
        }
        self.publish_peer_mtus();
    }

    /// Publishes the peers' inner MTUs, if they differ from the published ones, and caps the
    /// padding of every peer's data at its inner MTU once there is a table.
    pub(super) fn publish_peer_mtus(&mut self) {
        let mtus = match &mut self.path_mtus.table {
            Some(table) => {
                table.take_changed();
                table.peer_mtus(self.mtu)
            }
            None => PeerMtus::unconstrained(self.mtu),
        };
        self.set_pad_limits(&mtus);
        self.path_mtus.published.send_if_modified(|current| {
            let modified = *current != mtus;
            if modified {
                *current = mtus;
            }
            modified
        });
    }

    /// Caps the padding of every peer's data at its inner MTU in `mtus` (the source MTU for a
    /// peer not listed). A packet at that MTU fits the path only when the outer ceiling can
    /// carry the 1280-byte inner floor plus encapsulation headers. Without a table nothing
    /// is set and the padding stays as it always was. The table is never dropped once
    /// created, so the limits are never cleared as a whole; they also follow the source MTU.
    fn set_pad_limits(&mut self, mtus: &PeerMtus) {
        if self.path_mtus.table.is_none() {
            return;
        }
        let peers: Vec<PeerId> = self.core.peers().collect();
        let limits = &mut self.path_mtus.pad_limits;
        limits.retain(|peer, _| peers.binary_search(peer).is_ok());
        for peer in peers {
            let limit = mtus.peers.get(&peer).copied().unwrap_or(self.mtu);
            if limits.insert(peer, limit) != Some(limit) {
                self.core.set_peer_pad_limit(peer, Some(limit));
            }
        }
    }
}
