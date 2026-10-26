// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The receive path: transport data, handshake messages and roaming.

use std::net::IpAddr;
use std::time::Duration;

use nsplane_noise::noise::handshake::parse_handshake_anon;
use nsplane_noise::noise::{DATA_HEADER_SZ, Packet, Tunn, TunnResult};
use nsplane_noise::x25519;
use nsplane_packet::{Ecn, HEADROOM, PacketBuf, Path, PeerId, TransportId};

use super::route_cache::Lookups;
use super::{
    BUF_SIZE, Core, HANDSHAKE_INIT_SZ, handshakes_completed, message_kind, roams, same_route,
};
use crate::filter::Verdict;
use crate::job::{self, CryptoJob, Outcome};
use crate::peer_table::{Destinations, OwnKey, PeerTable};
use crate::policy::{MessageKind, Roam};
use crate::reasons;
use crate::types::{Event, LocalIdentityId, Output};

impl Core {
    /// Handles a datagram from `path`.
    pub(super) fn receive(&mut self, path: Path, data: PacketBuf) {
        if let Some((data, index)) = self.classify(path, data) {
            self.receive_data(path, data, index, &mut Lookups::default());
        }
    }

    /// Handles a datagram from `path` unless it is transport data, which is returned with its
    /// receiver index.
    pub(super) fn classify(&mut self, path: Path, data: PacketBuf) -> Option<(PacketBuf, u32)> {
        let data_index = match Tunn::parse_incoming_packet(data.as_packet()) {
            Ok(Packet::PacketData(p)) => Some(p.receiver_idx),
            Ok(_) => None,
            Err(_) => {
                self.pool.put(data);
                self.dropped(None, reasons::INVALID_PACKET);
                return None;
            }
        };
        if let Some(index) = data_index {
            return Some((data, index));
        }
        self.receive_handshake(path, data.as_packet());
        self.pool.put(data);
        None
    }

    /// Decrypts transport data in place and delivers it in the datagram's buffer.
    pub(super) fn receive_data(
        &mut self,
        path: Path,
        mut data: PacketBuf,
        receiver_idx: u32,
        lookups: &mut Lookups,
    ) {
        let Some((id, slot)) = lookups.session(&self.peers, receiver_idx) else {
            self.pool.put(data);
            return self.dropped(None, reasons::UNKNOWN_SESSION);
        };
        let Some(peer) = self.peers.at_mut(slot) else {
            return self.pool.put(data);
        };
        // A restricted identity's peer knows no session on another transport.
        if !peer.accepts(path.transport) {
            self.pool.put(data);
            return self.dropped(None, reasons::UNKNOWN_SESSION);
        }
        let outcome = job::open(&mut peer.tunnel_mut(), path, &mut data);
        match self.opened(id, Some(slot), path, &data, outcome, lookups) {
            Some(plain_len) => self.deliver_opened(id, Some(slot), path, data, plain_len),
            None => self.pool.put(data),
        }
    }

    /// Hands out the decryption of transport data as a job.
    pub(super) fn open_job(
        &mut self,
        path: Path,
        data: PacketBuf,
        receiver_idx: u32,
        lookups: &mut Lookups,
    ) -> Option<CryptoJob> {
        // A restricted identity's peer knows no session on another transport.
        let peer = lookups
            .session(&self.peers, receiver_idx)
            .and_then(|(id, slot)| Some((id, self.peers.at(slot)?)))
            .filter(|(_, peer)| peer.accepts(path.transport));
        let Some((id, peer)) = peer else {
            self.pool.put(data);
            self.dropped(None, reasons::UNKNOWN_SESSION);
            return None;
        };
        Some(peer.with_tunnel(|tunnel| CryptoJob::open(id, tunnel, data, path)))
    }

    /// Delivers the `plain_len` bytes of plaintext opened in `data` from peer `id` at `slot`,
    /// received on `path`, after the inbound filters.
    pub(super) fn deliver_opened(
        &mut self,
        id: PeerId,
        slot: Option<usize>,
        path: Path,
        mut data: PacketBuf,
        plain_len: usize,
    ) {
        // The plaintext lies behind the data header: move the packet start past it. A
        // decrypted datagram is longer than its header, so this does not fail.
        if data.advance(DATA_HEADER_SZ).is_err() {
            self.pool.put(data);
            return self.dropped(Some(id), reasons::DECAPSULATE_ERROR);
        }
        data.set_len(plain_len);
        self.deliver_filtered(id, slot, path, data, plain_len);
    }

    /// Delivers `packet`, `len` bytes from peer `id` at `slot` that arrived on `path` and
    /// passed the address checks, after the inbound filters.
    pub(super) fn deliver_filtered(
        &mut self,
        id: PeerId,
        slot: Option<usize>,
        path: Path,
        mut packet: PacketBuf,
        len: usize,
    ) {
        for filter in &self.filters {
            match filter.inbound_from(id, &path, &mut packet) {
                Verdict::Accept => {}
                Verdict::Drop { reason } => {
                    self.pool.put(packet);
                    return self.dropped(Some(id), reason);
                }
                Verdict::Handled => {
                    self.pool.put(packet);
                    return;
                }
            }
        }

        if let Some(peer) = slot.and_then(|slot| self.peers.at_mut(slot)) {
            peer.add_data_rx(len as u64);
        }
        self.outputs.push_back(Output::Deliver { from: id, packet });
    }

    /// Accounts for `datagram` from `path` that the tunnel of peer `id` at `slot` opened in
    /// place with `outcome`; returns the plaintext length if it carries a packet to deliver.
    pub(super) fn opened(
        &mut self,
        id: PeerId,
        slot: Option<usize>,
        path: Path,
        datagram: &PacketBuf,
        outcome: Outcome,
        lookups: &mut Lookups,
    ) -> Option<usize> {
        let (plain_len, src, handshakes) = match outcome {
            Outcome::Opened {
                plain_len,
                src,
                handshakes,
            } => (plain_len, src, handshakes),
            Outcome::Failed(e) => {
                tracing::debug!(message = "Decapsulate error", error = ?e);
                self.dropped(Some(id), reasons::DECAPSULATE_ERROR);
                return None;
            }
            Outcome::Sealed(_) | Outcome::Queued | Outcome::Unexpected => {
                tracing::debug!("Unexpected result from decapsulate");
                return None;
            }
        };
        let slot = slot?;
        let peer = self.peers.at_mut(slot)?;
        peer.add_rx(datagram.len() as u64);
        let completed = peer.take_handshakes_up_to(handshakes);

        let kind = if src.is_some() {
            MessageKind::Data
        } else {
            MessageKind::Keepalive
        };
        // Steady state (no completed handshake, same source) has nothing to report or adopt,
        // unless the policy observes every message.
        if completed > 0
            || self.observe_every_message
            || !peer
                .path()
                .is_some_and(|current| same_route(&current, &path))
        {
            self.authenticated(id, path, kind, completed);
        }

        let src = src?;
        let dst = || {
            datagram
                .as_packet()
                .get(DATA_HEADER_SZ..DATA_HEADER_SZ + plain_len)
                .and_then(Tunn::dst_address)
        };
        self.addresses_allowed(id, slot, src, dst, lookups)
            .then_some(plain_len)
    }

    /// Whether peer `id` at `slot` may send a packet from `src` to `dst` (read only when the
    /// peer has inbound destinations): the allowed-IP source check and the peer's inbound
    /// destinations; a refusal is reported.
    pub(super) fn addresses_allowed(
        &mut self,
        id: PeerId,
        slot: usize,
        src: IpAddr,
        dst: impl FnOnce() -> Option<IpAddr>,
        lookups: &mut Lookups,
    ) -> bool {
        if !self.routes.source_allowed(&self.peers, src, id) {
            self.dropped(Some(id), reasons::SOURCE_NOT_ALLOWED);
            return false;
        }
        if let Some(destinations) = self.peers.inbound_destinations(slot) {
            let dst = dst();
            // A shared source is consulted per packet, never cached: it may change any time.
            let allowed = dst.is_some_and(|dst| match destinations {
                Destinations::Owned(set) => lookups.destination_allowed(set, dst, id),
                Destinations::Shared(source) => source.allows(dst),
            });
            if !allowed {
                self.dropped(Some(id), reasons::DESTINATION_NOT_ALLOWED);
                return false;
            }
        }
        true
    }

    /// Verifies a handshake message with the handshake gate of the local identity it is for,
    /// finds its peer and lets the peer's tunnel answer it. The gate counts each message once;
    /// the tunnel does not verify or count it again.
    ///
    /// With a single local identity that has a key and serves every transport, its gate
    /// verifies every message. Otherwise an initiation goes to the first identity serving
    /// the arrival transport whose mac1 key it matches, and a response or cookie reply to the
    /// identity of the peer that owns its receiver index.
    // Rare: out of line, so the data path that shares `handle_input` keeps a small frame.
    #[inline(never)]
    fn receive_handshake(&mut self, path: Path, datagram: &[u8]) {
        let (first, second) = {
            let mut keyed = self.peers.keyed_identities();
            (keyed.next(), keyed.next())
        };
        let Some(first) = first else {
            return self.dropped(None, reasons::NO_PRIVATE_KEY);
        };
        let sole = (second.is_none() && first.0.transports.is_none()).then_some(first);

        // Handshake messages are small: copy them out, so the reply can go to a pooled buffer.
        let mut message = [0u8; HANDSHAKE_INIT_SZ];
        let Some(message) = message.get_mut(..datagram.len()) else {
            return self.dropped(None, reasons::INVALID_PACKET);
        };
        message.copy_from_slice(datagram);

        let target = match sole {
            Some((identity, own)) => Ok((identity.id, own, None)),
            None => dispatch_handshake(&self.peers, path.transport, message),
        };
        let (identity, own, responder) = match target {
            Ok(target) => target,
            Err(reason) => return self.dropped(None, reason),
        };
        let (private, public, gate) = (&own.private, &own.public, &own.gate);

        let mut reply = self.pool.get_len(BUF_SIZE);
        let packet = match gate.verify_packet(
            Some(path.addr),
            message,
            &mut reply.with_headroom_mut()[HEADROOM..],
        ) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                let len = cookie.len();
                reply.set_len(len);
                self.outputs
                    .push_back(Output::Transmit { path, data: reply });
                return;
            }
            Err(_) => {
                self.pool.put(reply);
                return self.dropped(None, reasons::INVALID_HANDSHAKE);
            }
        };

        let (peer, kind) = match &packet {
            Packet::HandshakeInit(p) => (
                parse_handshake_anon(private, public, p)
                    .ok()
                    .and_then(|hh| {
                        self.peers
                            .get(identity, &x25519::PublicKey::from(hh.peer_static_public))
                    }),
                MessageKind::HandshakeInit,
            ),
            Packet::HandshakeResponse(p) => (
                responder.or_else(|| self.peers.by_index(p.receiver_idx)),
                MessageKind::HandshakeResponse,
            ),
            Packet::PacketCookieReply(p) => (
                responder.or_else(|| self.peers.by_index(p.receiver_idx)),
                MessageKind::CookieReply,
            ),
            Packet::PacketData(_) => (None, MessageKind::Data),
        };
        let Some(id) = peer else {
            self.pool.put(reply);
            return self.dropped(None, reasons::UNKNOWN_PEER);
        };
        let Some(p) = self.peers.peer_mut(id) else {
            return self.pool.put(reply);
        };

        let verified = p
            .tunnel_mut()
            .handle_verified_packet(packet, &mut reply.with_headroom_mut()[HEADROOM..]);
        let reply_len = match verified {
            TunnResult::Done => None,
            TunnResult::WriteToNetwork(packet) => Some(packet.len()),
            TunnResult::Err(e) => {
                tracing::debug!(message = "Handshake error", error = ?e);
                self.pool.put(reply);
                return self.dropped(Some(id), reasons::HANDSHAKE_REJECTED);
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                tracing::debug!("Unexpected result from handle_verified_packet");
                return self.pool.put(reply);
            }
        };
        // Like the kernel, count handshake messages on the wire but not cookie replies.
        if kind != MessageKind::CookieReply {
            p.add_rx(datagram.len() as u64);
        }
        let completed = p.take_completed_handshakes();

        let Some(reply_len) = reply_len else {
            self.pool.put(reply);
            return self.authenticated(id, path, kind, completed);
        };
        reply.set_len(reply_len);
        let reply_kind = message_kind(reply.as_packet());
        self.authenticated(id, path, kind, completed);
        self.transmit(id, reply_kind, reply);
        self.flush_queue(id);
    }

    /// Records an authenticated message of `kind` from `peer` on `path`: reports the
    /// handshakes the message `completed` and a new off-path source, and lets the policy
    /// decide about roaming.
    fn authenticated(&mut self, id: PeerId, path: Path, kind: MessageKind, completed: u64) {
        let Some(peer) = self.peers.peer_mut(id) else {
            return;
        };

        if completed > 0 {
            peer.expired = false;
            peer.initiation_answered();
            peer.forget_reported_from();
            let rtt = (kind == MessageKind::HandshakeResponse)
                .then(|| peer.tunnel_mut().stats().4)
                .flatten()
                .map(|ms| Duration::from_millis(u64::from(ms)));
            handshakes_completed(&mut self.outputs, id, completed, Some(path), rtt);
        }

        // Cookie replies are not authenticated by the peer's keys and never move the path.
        if !roams(kind) {
            return;
        }
        if peer
            .path()
            .is_some_and(|current| same_route(&current, &path))
        {
            if self.observe_every_message {
                // Already the peer's path: the answer changes nothing.
                let _ = self.policy.on_authenticated(id, &path, kind);
            }
            return;
        }
        // The policy sees every message, but a source is reported once until the path
        // changes or a handshake completes; an adoption is always reported first.
        let roam = self.policy.on_authenticated(id, &path, kind);
        if peer.report_from(path) || roam == Roam::Adopt {
            self.outputs.push_back(Output::Event(Event::Authenticated {
                peer: id,
                from: path,
            }));
        }
        if roam == Roam::Adopt {
            // The ECN mark of a received datagram says nothing about what to send.
            let path = Path {
                ecn: Ecn::NotEct,
                ..path
            };
            peer.set_path(path);
            self.outputs
                .push_back(Output::Event(Event::PathAdopted { peer: id, path }));
        }
    }
}

/// The local identity a handshake message arriving on `transport` is for, its key, and the
/// peer that owns the receiver index of a response or cookie reply; with several local
/// identities, or one restricted to some transports.
///
/// An initiation goes to the first identity serving `transport` whose mac1 key it matches,
/// or is dropped as [`reasons::UNKNOWN_LOCAL_IDENTITY`] before any budget is counted. A
/// response or cookie reply goes to its peer's identity, or is dropped as
/// [`reasons::UNKNOWN_PEER`] for an unknown receiver index or a peer that does not accept
/// `transport`.
fn dispatch_handshake<'a>(
    peers: &'a PeerTable,
    transport: TransportId,
    message: &[u8],
) -> Result<(LocalIdentityId, &'a OwnKey, Option<PeerId>), &'static str> {
    let receiver_idx = match Tunn::parse_incoming_packet(message) {
        Ok(Packet::HandshakeInit(_)) => {
            return peers
                .keyed_identities()
                .find(|(identity, own)| {
                    identity.serves(transport) && own.gate.mac1_matches(message)
                })
                .map(|(identity, own)| (identity.id, own, None))
                .ok_or(reasons::UNKNOWN_LOCAL_IDENTITY);
        }
        Ok(Packet::HandshakeResponse(p)) => p.receiver_idx,
        Ok(Packet::PacketCookieReply(p)) => p.receiver_idx,
        Ok(Packet::PacketData(_)) | Err(_) => return Err(reasons::INVALID_HANDSHAKE),
    };
    let id = peers.by_index(receiver_idx).ok_or(reasons::UNKNOWN_PEER)?;
    let peer = peers
        .peer(id)
        .filter(|p| p.accepts(transport))
        .ok_or(reasons::UNKNOWN_PEER)?;
    let own = peers
        .identity(peer.local_identity())
        .and_then(|identity| identity.key.as_ref())
        .ok_or(reasons::UNKNOWN_PEER)?;
    Ok((peer.local_identity(), own, Some(id)))
}
