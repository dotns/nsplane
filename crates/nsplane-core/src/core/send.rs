// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The send path: routing, outbound filters, sealing and transmission.

use std::collections::VecDeque;
use std::mem;
use std::net::IpAddr;
use std::time::Instant;

use nsplane_noise::noise::{DATA_HEADER_SZ, Tunn, TunnResult};
use nsplane_packet::{Ecn, HEADROOM, PacketBuf, PacketPool, Path, PeerId, TAILROOM};

use super::{BUF_SIZE, Core, HANDSHAKE_INIT_SZ, message_kind};
use crate::filter::Verdict;
use crate::job::{self, CryptoJob, Outcome};
use crate::peer::Peer;
use crate::policy::{MessageKind, PathPolicy, Roam};
use crate::reasons;
use crate::types::{Event, Output};

impl Core {
    /// Delivers `packet` as if it came from `peer`, bypassing the inbound filters and the
    /// allowed-IP source check.
    ///
    /// Part of the contract: no inbound [`PacketFilter`] sees the packet, so a stateful
    /// filter records nothing about it and a translating filter does not translate it.
    ///
    /// [`PacketFilter`]: crate::PacketFilter
    pub fn inject_inbound(&mut self, peer: PeerId, packet: PacketBuf) {
        self.outputs
            .push_back(Output::Deliver { from: peer, packet });
    }

    /// Encrypts `packet` like `Input::Local`, bypassing the outbound filters.
    ///
    /// Part of the contract, which will not change silently: no outbound [`PacketFilter`]
    /// sees the packet. A stateful filter (e.g. `nsplane-acl`'s `AclFilter`) records no reply
    /// state for it, so the peer's replies are judged by the inbound rules alone, and a
    /// translating filter does not translate it.
    ///
    /// [`PacketFilter`]: crate::PacketFilter
    pub fn inject_outbound(&mut self, packet: PacketBuf, now: Instant) {
        self.start_schedule(now);
        self.send(packet, false);
    }

    /// Encrypts `packet` for `peer` in its current session and transmits it on `path`
    /// (unmarked ECN), bypassing routing, the outbound filters and [`PathPolicy::select`]:
    /// e.g. a probe on a candidate path while the peer's traffic stays on its path, which is
    /// not changed. The tunnel counts it as sent data like any packet. Without a current
    /// session the packet is dropped as [`reasons::NO_SESSION`], neither queued nor a reason
    /// to start a handshake. Unknown peers are ignored.
    ///
    /// Like [`Core::inject_outbound`], part of the contract: no outbound [`PacketFilter`]
    /// sees the packet, so a stateful filter records no reply state for it (its replies are
    /// judged by the inbound rules alone) and a translating filter does not translate it.
    ///
    /// [`PacketFilter`]: crate::PacketFilter
    pub fn inject_outbound_on(
        &mut self,
        peer: PeerId,
        path: Path,
        packet: PacketBuf,
        now: Instant,
    ) {
        self.start_schedule(now);
        let Some(slot) = self.peers.slot(peer) else {
            return self.pool.put(packet);
        };
        let Some(p) = self.peers.at_mut(slot) else {
            return self.pool.put(packet);
        };
        if !p.tunnel_mut().has_session() {
            self.pool.put(packet);
            return self.dropped(Some(peer), reasons::NO_SESSION);
        }
        let (mut packet, len) = self.layout_for_sealing(packet);
        let Some(p) = self.peers.at_mut(slot) else {
            return self.pool.put(packet);
        };
        let outcome = job::seal(&mut p.tunnel_mut(), &mut packet, len);
        let path = Path {
            ecn: Ecn::NotEct,
            ..path
        };
        sealed(
            &mut self.outputs,
            &mut self.pool,
            &Fixed(path),
            peer,
            p,
            packet,
            outcome,
        );
    }

    /// Encrypts a local packet in place and transmits it to the peer it is routed to.
    pub(super) fn send(&mut self, packet: PacketBuf, filter: bool) {
        let Some((id, slot, mut packet, len)) = self.prepare_send(packet, filter) else {
            return;
        };
        let Some(peer) = self.peers.at_mut(slot) else {
            return self.pool.put(packet);
        };
        let outcome = job::seal(&mut peer.tunnel_mut(), &mut packet, len);
        sealed(
            &mut self.outputs,
            &mut self.pool,
            self.policy.as_ref(),
            id,
            peer,
            packet,
            outcome,
        );
    }

    /// Hands out the encryption of a local packet as a job.
    pub(super) fn seal_job(&mut self, packet: PacketBuf) -> Option<CryptoJob> {
        let (id, slot, packet, len) = self.prepare_send(packet, true)?;
        let Some(peer) = self.peers.at_mut(slot) else {
            self.pool.put(packet);
            return None;
        };
        Some(CryptoJob::seal(id, &mut peer.tunnel_mut(), packet, len))
    }

    /// Routes a local packet, runs the outbound filters with `filter` and lays the packet out
    /// for sealing in place; returns its peer and the peer's slot, its buffer and its length.
    fn prepare_send(
        &mut self,
        mut packet: PacketBuf,
        filter: bool,
    ) -> Option<(PeerId, usize, PacketBuf, usize)> {
        let route = match Tunn::dst_address(packet.as_packet()) {
            Some(dst) if self.peers.has_sources() => {
                self.routes
                    .route_from(&self.peers, src_address(packet.as_packet()), dst)
            }
            Some(dst) => self.routes.route(&self.peers, dst),
            None => None,
        };
        let Some((id, slot)) = route else {
            self.pool.put(packet);
            self.dropped(None, reasons::NO_ROUTE);
            return None;
        };

        if filter {
            // Onion order: the chain is installed from the wire side to the local side, so
            // local packets meet it in reverse.
            for f in self.filters.iter().rev() {
                match f.outbound(id, &mut packet) {
                    Verdict::Accept => {}
                    Verdict::Drop { reason } => {
                        self.pool.put(packet);
                        self.dropped(Some(id), reason);
                        return None;
                    }
                    Verdict::Handled => {
                        self.pool.put(packet);
                        return None;
                    }
                }
            }
        }

        let (packet, len) = self.layout_for_sealing(packet);
        Some((id, slot, packet, len))
    }

    /// Lays a local packet out for sealing in place; returns its buffer and its length.
    pub(super) fn layout_for_sealing(&mut self, mut packet: PacketBuf) -> (PacketBuf, usize) {
        let len = packet.len();
        // The datagram is sealed in place with its data header in the headroom, so it starts
        // where it is written. The tail needs room for the tag and the padding, or for a
        // handshake initiation if the packet is queued instead.
        if packet.reserve_front(DATA_HEADER_SZ).is_err() {
            // E.g. a slice of a shared buffer: copy it behind the data header of a pooled
            // buffer.
            let mut copy = self.pool.get((len + TAILROOM).max(HANDSHAKE_INIT_SZ));
            copy.set_len(DATA_HEADER_SZ + len);
            copy.as_packet_mut()[DATA_HEADER_SZ..].copy_from_slice(packet.as_packet());
            self.pool.put(mem::replace(&mut packet, copy));
        }
        packet.set_len((DATA_HEADER_SZ + len + TAILROOM).max(HANDSHAKE_INIT_SZ));
        (packet, len)
    }

    /// Transmits the packets the tunnel of `peer` queued while it had no session.
    pub(super) fn flush_queue(&mut self, id: PeerId) {
        let Some(peer) = self.peers.peer_mut(id) else {
            return;
        };
        loop {
            let mut buf = self.pool.get_len(BUF_SIZE);
            let queued =
                peer.tunnel_mut()
                    .decapsulate(None, &[], &mut buf.with_headroom_mut()[HEADROOM..]);
            let TunnResult::WriteToNetwork(packet) = queued else {
                return self.pool.put(buf);
            };
            let len = packet.len();
            buf.set_len(len);
            transmit(
                &mut self.outputs,
                &mut self.pool,
                self.policy.as_ref(),
                id,
                peer,
                MessageKind::Data,
                buf,
            );
        }
    }

    /// Transmits a message of `kind` to `peer` on the path chosen by the policy.
    pub(super) fn transmit(&mut self, id: PeerId, kind: MessageKind, data: PacketBuf) {
        let Some(peer) = self.peers.peer_mut(id) else {
            return self.pool.put(data);
        };
        transmit(
            &mut self.outputs,
            &mut self.pool,
            self.policy.as_ref(),
            id,
            peer,
            kind,
            data,
        );
    }
}

/// A policy that sends everything on one path, for [`Core::inject_outbound_on`].
pub(super) struct Fixed(pub(super) Path);

impl PathPolicy for Fixed {
    fn select(&self, _peer: PeerId, _kind: MessageKind) -> Option<Path> {
        Some(self.0)
    }

    fn on_authenticated(&self, _peer: PeerId, _from: &Path, _kind: MessageKind) -> Roam {
        Roam::Keep
    }
}

/// Transmits the local packet that peer `id`'s tunnel sealed in `packet` with `outcome`.
pub(super) fn sealed(
    outputs: &mut VecDeque<Output>,
    pool: &mut PacketPool,
    policy: &dyn PathPolicy,
    id: PeerId,
    peer: &mut Peer,
    mut packet: PacketBuf,
    outcome: Outcome,
) {
    let sealed_len = match outcome {
        Outcome::Sealed(len) => len,
        // Queued behind a handshake in progress.
        Outcome::Queued => return pool.put(packet),
        Outcome::Failed(e) => {
            tracing::debug!(message = "Encapsulate error", error = ?e);
            pool.put(packet);
            return outputs.push_back(Output::Event(Event::Dropped {
                peer: Some(id),
                reason: reasons::ENCAPSULATE_ERROR,
            }));
        }
        Outcome::Opened { .. } | Outcome::Unexpected => {
            tracing::debug!("Unexpected result from encapsulate");
            return pool.put(packet);
        }
    };
    packet.set_len(sealed_len);
    let kind = message_kind(packet.as_packet());
    transmit(outputs, pool, policy, id, peer, kind, packet);
}

/// Queues `data` for peer `id` on the path the policy selects for `kind`, or on the peer's
/// current path, and counts it as sent; drops it if there is neither.
pub(super) fn transmit(
    outputs: &mut VecDeque<Output>,
    pool: &mut PacketPool,
    policy: &dyn PathPolicy,
    id: PeerId,
    peer: &mut Peer,
    kind: MessageKind,
    data: PacketBuf,
) {
    let current = peer.path();
    if let Some(path) = policy.select(id, kind).or(current) {
        peer.add_tx(data.len() as u64);
        if kind == MessageKind::HandshakeInit {
            peer.initiation_sent();
        }
        outputs.push_back(Output::Transmit { path, data });
    } else {
        pool.put(data);
        outputs.push_back(Output::Event(Event::Dropped {
            peer: Some(id),
            reason: reasons::NO_PATH,
        }));
    }
}

/// The source address of an IP packet.
fn src_address(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let src: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            Some(IpAddr::from(src))
        }
        6 if packet.len() >= 40 => {
            let src: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            Some(IpAddr::from(src))
        }
        _ => None,
    }
}
