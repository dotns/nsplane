// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The sans-I/O engine: receive demultiplexing, the send path and the timers.

use std::collections::VecDeque;
use std::fmt;
use std::mem;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use nsplane_noise::noise::errors::WireGuardError;
use nsplane_noise::noise::handshake::parse_handshake_anon;
use nsplane_noise::noise::{DATA_HEADER_SZ, Packet, Tunn, TunnResult};
use nsplane_noise::x25519;
use nsplane_packet::{Ecn, HEADROOM, PacketBuf, PacketPool, Path, PeerId};

use crate::filter::{PacketFilter, Verdict};
use crate::job::{self, CryptoJob, Direction, Outcome};
use crate::peer::Peer;
use crate::peer_table::{PeerTable, PeerTableError};
use crate::policy::{MessageKind, PathPolicy, Roam};
use crate::reasons;
use crate::types::{ConfigChange, CoreConfig, Event, Input, Output, PeerConfig, PeerStats};

/// Interval of the peer timers, as in the device.
const TICK: Duration = Duration::from_millis(250);
/// Interval of the handshake gate's rate limiter reset.
const RATE_LIMITER_RESET: Duration = Duration::from_secs(1);
/// Room behind a packet for its padding (up to 15 bytes) and the AEAD tag (16 bytes).
const TAIL_ROOM: usize = 15 + 16;
/// Size of a handshake initiation, the largest handshake message.
const HANDSHAKE_INIT_SZ: usize = 148;
/// Size of a transport data message without payload.
const KEEPALIVE_SZ: usize = DATA_HEADER_SZ + 16;
/// Capacity of the pooled buffers for handshake replies, timer output and queued packets.
const BUF_SIZE: usize = 2048;

/// When the next timer tick, rate limiter reset and stats report are due.
#[derive(Debug, Clone, Copy)]
struct Schedule {
    tick: Instant,
    rate_limiter_reset: Instant,
    stats: Option<Instant>,
}

/// The sans-I/O WireGuard engine.
///
/// Feed it with [`Core::handle_input`] and [`Core::handle_timeout`], then drain
/// [`Core::poll_output`] until it returns `None`. The core never reads the clock: every call
/// that needs the time takes `now`, and the first such call starts the timer schedule
/// reported by [`Core::poll_timeout`].
pub struct Core {
    peers: PeerTable,
    policy: Box<dyn PathPolicy>,
    filters: Vec<Box<dyn PacketFilter>>,
    stats_interval: Option<Duration>,
    pool: PacketPool,
    outputs: VecDeque<Output>,
    schedule: Option<Schedule>,
    /// The `now` of the latest call that passed the time.
    now: Option<Instant>,
}

impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Core")
            .field("peers", &self.peers)
            .field("filters", &self.filters.len())
            .field("outputs", &self.outputs.len())
            .field("schedule", &self.schedule)
            .finish_non_exhaustive()
    }
}

impl Core {
    /// Creates a core from `config`; it has no peers yet.
    pub fn new(config: CoreConfig) -> Self {
        let mut peers = PeerTable::new(config.handshake_rate_limit);
        if let Some(private_key) = config.private_key {
            peers.set_private_key(private_key);
        }
        Self {
            peers,
            policy: config.policy,
            filters: config.filters,
            stats_interval: config.stats_interval,
            pool: PacketPool::new(config.pool_size),
            outputs: VecDeque::new(),
            schedule: None,
            now: None,
        }
    }

    /// Processes one input; the results are queued for [`Core::poll_output`].
    ///
    /// A datagram is consumed: when it carries a packet to deliver, it is decrypted in place
    /// and its buffer travels on in `Output::Deliver`; otherwise the buffer goes to the pool.
    pub fn handle_input(&mut self, input: Input, now: Instant) {
        self.start_schedule(now);
        match input {
            Input::Datagram { path, data } => self.receive(path, data),
            Input::Local { packet } => self.send(packet, true),
            Input::Config(change) => self.configure(change, now),
        }
    }

    /// Processes one input like [`Core::handle_input`], except that the encryption of a local
    /// packet or the decryption of a received transport data message is returned as a job
    /// instead of being run: run it anywhere with [`CryptoJob::run`], then hand it back with
    /// [`Core::complete_job`]. Everything else (handshakes, configuration, packets that are
    /// dropped before their cryptography) is processed at once and returns `None`.
    pub fn handle_input_deferred(&mut self, input: Input, now: Instant) -> Option<CryptoJob> {
        self.start_schedule(now);
        match input {
            Input::Datagram { path, data } => {
                let (data, index) = self.classify(path, data)?;
                let peer = self.peers.by_index(index).and_then(|id| {
                    let tunnel = self.peers.peer(id)?.shared_tunnel();
                    Some((id, tunnel))
                });
                let Some((id, tunnel)) = peer else {
                    self.pool.put(data);
                    self.dropped(None, reasons::UNKNOWN_SESSION);
                    return None;
                };
                Some(CryptoJob::new(id, tunnel, data, Direction::Open { path }))
            }
            Input::Local { packet } => {
                let (id, packet, len) = self.prepare_send(packet, true)?;
                let Some(peer) = self.peers.peer(id) else {
                    self.pool.put(packet);
                    return None;
                };
                let tunnel = peer.shared_tunnel();
                Some(CryptoJob::new(id, tunnel, packet, Direction::Seal { len }))
            }
            Input::Config(change) => {
                self.configure(change, now);
                None
            }
        }
    }

    /// Finishes a job from [`Core::handle_input_deferred`], running it first if it has not
    /// run; the results are queued for [`Core::poll_output`] as with [`Core::handle_input`].
    /// A job whose peer was removed in the meantime is discarded.
    pub fn complete_job(&mut self, mut job: CryptoJob) {
        let outcome = job.take_outcome();
        let id = job.peer;
        match job.direction {
            Direction::Seal { .. } => match self.peers.peer_mut(id) {
                Some(peer) => sealed(
                    &mut self.outputs,
                    &mut self.pool,
                    self.policy.as_ref(),
                    id,
                    peer,
                    job.buf,
                    outcome,
                ),
                None => self.pool.put(job.buf),
            },
            Direction::Open { path } => {
                let len = job.buf.len();
                match self.opened(id, path, len, outcome) {
                    Some(plain_len) => self.deliver_opened(id, job.buf, plain_len),
                    None => self.pool.put(job.buf),
                }
            }
        }
    }

    /// The next queued output, oldest first.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    /// When [`Core::handle_timeout`] must be called next; `None` until the first call that
    /// passes the time.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.schedule.map(|s| s.tick)
    }

    /// Runs the timers that are due at `now`: handshake retries, keepalives, session expiry,
    /// rate limiter resets and periodic `Event::PeerStats`.
    pub fn handle_timeout(&mut self, now: Instant) {
        let schedule = self.start_schedule(now);
        if now < schedule.tick {
            return;
        }

        let mut buf = self.pool.get_len(BUF_SIZE);
        for (id, peer) in self.peers.iter_mut() {
            let result = peer.update_timers(now, &mut buf.with_headroom_mut()[HEADROOM..]);
            let completed = peer.take_completed_handshakes();
            if completed > 0 {
                peer.expired = false;
                handshakes_completed(&mut self.outputs, id, completed, None, None);
            }
            match result {
                TunnResult::Done => peer.expired = false,
                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    if !mem::replace(&mut peer.expired, true) {
                        self.outputs
                            .push_back(Output::Event(Event::SessionExpired { peer: id }));
                    }
                }
                TunnResult::Err(e) => {
                    peer.expired = false;
                    tracing::debug!(message = "Timer error", error = ?e);
                }
                TunnResult::WriteToNetwork(packet) => {
                    peer.expired = false;
                    let len = packet.len();
                    buf.set_len(len);
                    let kind = message_kind(buf.as_packet());
                    let data = mem::replace(&mut buf, self.pool.get_len(BUF_SIZE));
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
                TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                    tracing::debug!("Unexpected result from update_timers");
                }
            }
        }
        self.pool.put(buf);

        let mut schedule = schedule;
        if now >= schedule.rate_limiter_reset {
            if let Some(gate) = self.peers.rate_limiter() {
                gate.reset_count_at(now);
            }
            schedule.rate_limiter_reset = now + RATE_LIMITER_RESET;
        }
        if let (Some(due), Some(interval)) = (schedule.stats, self.stats_interval)
            && now >= due
        {
            for (peer, p) in self.peers.iter() {
                self.outputs.push_back(Output::Event(Event::PeerStats {
                    peer,
                    rx: p.rx(),
                    tx: p.tx(),
                    data_rx: p.data_rx(),
                    data_tx: p.data_tx(),
                    last_handshake: p.time_since_last_handshake(now),
                }));
            }
            schedule.stats = Some(now + interval);
        }
        schedule.tick = now + TICK;
        self.schedule = Some(schedule);
    }

    /// The own public key, once a private key is set.
    pub fn public_key(&self) -> Option<x25519::PublicKey> {
        self.peers.key_pair().map(|(_, public)| *public)
    }

    /// The peer with this public key.
    pub fn peer_id(&self, key: &x25519::PublicKey) -> Option<PeerId> {
        self.peers.get(key)
    }

    /// All peers, in id order.
    pub fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peers.iter().map(|(id, _)| id)
    }

    /// Configuration and counters of `peer`; the time since its last handshake is measured
    /// up to the `now` of the latest call that passed the time.
    pub fn peer_stats(&self, peer: PeerId) -> Option<PeerStats> {
        let p = self.peers.peer(peer)?;
        let last_handshake = self.now.and_then(|now| p.time_since_last_handshake(now));
        Some(PeerStats {
            peer,
            public_key: *p.public_key(),
            path: p.path(),
            allowed_ips: self.peers.allowed_ips(peer),
            preshared_key: p.preshared_key().copied(),
            persistent_keepalive: p.persistent_keepalive(),
            rx: p.rx(),
            tx: p.tx(),
            data_rx: p.data_rx(),
            data_tx: p.data_tx(),
            last_handshake,
        })
    }

    /// The peer a packet to `dst` is routed to: the longest allowed-IP match, as on the send
    /// path. Use it to pick the `peer` of [`Core::inject_inbound`] for a locally generated
    /// reply about a packet to `dst`.
    pub fn route(&self, dst: IpAddr) -> Option<PeerId> {
        self.peers.by_destination(dst)
    }

    /// Delivers `packet` as if it came from `peer`, bypassing the inbound filters and the
    /// allowed-IP source check.
    pub fn inject_inbound(&mut self, peer: PeerId, packet: PacketBuf) {
        self.outputs
            .push_back(Output::Deliver { from: peer, packet });
    }

    /// Encrypts `packet` like `Input::Local`, bypassing the outbound filters.
    pub fn inject_outbound(&mut self, packet: PacketBuf, now: Instant) {
        self.start_schedule(now);
        self.send(packet, false);
    }

    /// Starts a handshake with `peer` now, even if one is in progress. A `path` becomes the
    /// peer's path first, without an `Event::PathAdopted`. Unknown peers are ignored.
    pub fn force_handshake(&mut self, peer: PeerId, path: Option<Path>, now: Instant) {
        self.start_schedule(now);
        let Some(p) = self.peers.peer_mut(peer) else {
            return;
        };
        if let Some(path) = path {
            p.set_path(path);
        }

        let mut buf = self.pool.get_len(BUF_SIZE);
        let initiation = p
            .tunnel()
            .format_handshake_initiation(&mut buf.with_headroom_mut()[HEADROOM..], true);
        match initiation {
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.set_len(len);
                transmit(
                    &mut self.outputs,
                    &mut self.pool,
                    self.policy.as_ref(),
                    peer,
                    p,
                    MessageKind::HandshakeInit,
                    buf,
                );
            }
            result => {
                tracing::debug!(message = "Handshake initiation failed", ?result);
                self.pool.put(buf);
            }
        }
    }

    /// Returns a buffer the driver is done with (e.g. a delivered packet) to the pool.
    pub fn recycle(&mut self, buf: PacketBuf) {
        self.pool.put(buf);
    }

    /// Starts the timer schedule on the first call that passes the time.
    fn start_schedule(&mut self, now: Instant) -> Schedule {
        self.now = Some(now);
        *self.schedule.get_or_insert_with(|| Schedule {
            tick: now + TICK,
            rate_limiter_reset: now + RATE_LIMITER_RESET,
            stats: self.stats_interval.map(|interval| now + interval),
        })
    }

    /// Applies a configuration change.
    ///
    /// Peers cannot be added without a private key; such a change is reported as
    /// `Event::Dropped { peer: None, reason: reasons::NO_PRIVATE_KEY }`. Changes to unknown
    /// peers are ignored.
    // Rare: out of line, so the data path that shares `handle_input` keeps a small frame.
    #[inline(never)]
    fn configure(&mut self, change: ConfigChange, now: Instant) {
        let config = match change {
            ConfigChange::SetPrivateKey(key) => {
                self.peers.set_private_key(key);
                return;
            }
            ConfigChange::AddOrUpdatePeer(config) => config,
            // Only AddOrUpdatePeer may add a peer.
            ConfigChange::SetAllowedIps { peer, .. }
            | ConfigChange::SetPresharedKey { peer, .. }
            | ConfigChange::SetKeepalive { peer, .. }
            | ConfigChange::SetPath { peer, .. }
                if self.peers.get(&peer).is_none() =>
            {
                return;
            }
            ConfigChange::RemovePeer(key) => {
                self.peers.remove(&key);
                return;
            }
            ConfigChange::RemoveAllPeers => {
                self.peers.clear();
                return;
            }
            ConfigChange::SetAllowedIps { peer, allowed_ips } => PeerConfig {
                allowed_ips,
                replace_allowed_ips: true,
                ..PeerConfig::new(peer)
            },
            ConfigChange::SetPresharedKey { peer, key } => PeerConfig {
                // An all-zero key removes it.
                preshared_key: Some(key.unwrap_or([0; 32])),
                ..PeerConfig::new(peer)
            },
            ConfigChange::SetKeepalive { peer, interval } => PeerConfig {
                persistent_keepalive: Some(interval.unwrap_or(0)),
                ..PeerConfig::new(peer)
            },
            ConfigChange::SetPath { peer, path } => PeerConfig {
                path: Some(path),
                ..PeerConfig::new(peer)
            },
        };
        if let Err(e) = self.peers.apply(&config, now) {
            let reason = match e {
                PeerTableError::NoPrivateKey => reasons::NO_PRIVATE_KEY,
                PeerTableError::IndicesExhausted => reasons::NO_FREE_SESSION_INDEX,
                PeerTableError::IdsExhausted => reasons::NO_FREE_PEER_ID,
            };
            self.dropped(None, reason);
        }
    }

    /// Handles a datagram from `path`.
    fn receive(&mut self, path: Path, data: PacketBuf) {
        if let Some((data, index)) = self.classify(path, data) {
            self.receive_data(path, data, index);
        }
    }

    /// Handles a datagram from `path` unless it is transport data, which is returned with its
    /// receiver index.
    fn classify(&mut self, path: Path, data: PacketBuf) -> Option<(PacketBuf, u32)> {
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
    fn receive_data(&mut self, path: Path, mut data: PacketBuf, receiver_idx: u32) {
        let Some((id, plain_len)) = self.open(path, &mut data, receiver_idx) else {
            return self.pool.put(data);
        };
        self.deliver_opened(id, data, plain_len);
    }

    /// Delivers the `plain_len` bytes of plaintext opened in `data` from peer `id`, after
    /// the inbound filters.
    fn deliver_opened(&mut self, id: PeerId, mut data: PacketBuf, plain_len: usize) {
        // The plaintext lies behind the data header: move the packet start past it. A
        // decrypted datagram is longer than its header, so this does not fail.
        if data.advance(DATA_HEADER_SZ).is_err() {
            self.pool.put(data);
            return self.dropped(Some(id), reasons::DECAPSULATE_ERROR);
        }
        data.set_len(plain_len);
        let mut packet = data;

        for filter in &self.filters {
            match filter.inbound(id, &mut packet) {
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

        if let Some(peer) = self.peers.peer_mut(id) {
            peer.add_data_rx(plain_len as u64);
        }
        self.outputs.push_back(Output::Deliver { from: id, packet });
    }

    /// Decrypts transport data in place; returns the peer and the plaintext length if the
    /// datagram carries a packet to deliver.
    fn open(
        &mut self,
        path: Path,
        data: &mut PacketBuf,
        receiver_idx: u32,
    ) -> Option<(PeerId, usize)> {
        let Some(id) = self.peers.by_index(receiver_idx) else {
            self.dropped(None, reasons::UNKNOWN_SESSION);
            return None;
        };
        let len = data.len();
        let outcome = job::open(&mut self.peers.peer(id)?.tunnel(), path, data);
        self.opened(id, path, len, outcome)
            .map(|plain_len| (id, plain_len))
    }

    /// Accounts for a datagram of `len` bytes from `path` that peer `id`'s tunnel opened
    /// with `outcome`; returns the plaintext length if it carries a packet to deliver.
    fn opened(&mut self, id: PeerId, path: Path, len: usize, outcome: Outcome) -> Option<usize> {
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
        let peer = self.peers.peer_mut(id)?;
        peer.add_rx(len as u64);
        let completed = peer.take_handshakes_up_to(handshakes);

        let kind = if src.is_some() {
            MessageKind::Data
        } else {
            MessageKind::Keepalive
        };
        // Steady state (no completed handshake, same source) has nothing to report or adopt.
        if completed > 0
            || !peer
                .path()
                .is_some_and(|current| same_route(&current, &path))
        {
            self.authenticated(id, path, kind, completed);
        }

        let src = src?;
        if !self.peers.routes_to(src, id) {
            self.dropped(Some(id), reasons::SOURCE_NOT_ALLOWED);
            return None;
        }
        Some(plain_len)
    }

    /// Verifies a handshake message with the handshake gate, finds its peer and lets the
    /// peer's tunnel answer it. The gate counts each message once; the tunnel does not verify
    /// or count it again.
    // Rare: out of line, so the data path that shares `handle_input` keeps a small frame.
    #[inline(never)]
    fn receive_handshake(&mut self, path: Path, datagram: &[u8]) {
        let (Some((private, public)), Some(gate)) =
            (self.peers.key_pair(), self.peers.rate_limiter())
        else {
            return self.dropped(None, reasons::NO_PRIVATE_KEY);
        };

        // Handshake messages are small: copy them out, so the reply can go to a pooled buffer.
        let mut message = [0u8; HANDSHAKE_INIT_SZ];
        let Some(message) = message.get_mut(..datagram.len()) else {
            return self.dropped(None, reasons::INVALID_PACKET);
        };
        message.copy_from_slice(datagram);

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
                            .get(&x25519::PublicKey::from(hh.peer_static_public))
                    }),
                MessageKind::HandshakeInit,
            ),
            Packet::HandshakeResponse(p) => (
                self.peers.by_index(p.receiver_idx),
                MessageKind::HandshakeResponse,
            ),
            Packet::PacketCookieReply(p) => (
                self.peers.by_index(p.receiver_idx),
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
            .tunnel()
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

    /// Encrypts a local packet in place and transmits it to the peer it is routed to.
    fn send(&mut self, packet: PacketBuf, filter: bool) {
        let Some((id, mut packet, len)) = self.prepare_send(packet, filter) else {
            return;
        };
        let Some(peer) = self.peers.peer_mut(id) else {
            return self.pool.put(packet);
        };
        let outcome = job::seal(&mut peer.tunnel(), &mut packet, len);
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

    /// Routes a local packet, runs the outbound filters with `filter` and lays the packet out
    /// for sealing in place; returns its peer, its buffer and its length.
    fn prepare_send(
        &mut self,
        mut packet: PacketBuf,
        filter: bool,
    ) -> Option<(PeerId, PacketBuf, usize)> {
        let Some(id) =
            Tunn::dst_address(packet.as_packet()).and_then(|dst| self.peers.by_destination(dst))
        else {
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

        let len = packet.len();
        // The datagram is sealed in place with its data header in the headroom, so it starts
        // where it is written. The tail needs room for the tag and the padding, or for a
        // handshake initiation if the packet is queued instead.
        if packet.reserve_front(DATA_HEADER_SZ).is_err() {
            // E.g. a slice of a shared buffer: copy it behind the data header of a pooled
            // buffer.
            let mut copy = self.pool.get((len + TAIL_ROOM).max(HANDSHAKE_INIT_SZ));
            copy.set_len(DATA_HEADER_SZ + len);
            copy.as_packet_mut()[DATA_HEADER_SZ..].copy_from_slice(packet.as_packet());
            self.pool.put(mem::replace(&mut packet, copy));
        }
        packet.set_len((DATA_HEADER_SZ + len + TAIL_ROOM).max(HANDSHAKE_INIT_SZ));
        Some((id, packet, len))
    }

    /// Transmits the packets the tunnel of `peer` queued while it had no session.
    fn flush_queue(&mut self, id: PeerId) {
        let Some(peer) = self.peers.peer_mut(id) else {
            return;
        };
        loop {
            let mut buf = self.pool.get_len(BUF_SIZE);
            let queued =
                peer.tunnel()
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

    /// Records an authenticated message of `kind` from `peer` on `path`: reports the
    /// handshakes the message `completed` and a new source, and lets the policy decide about
    /// roaming.
    fn authenticated(&mut self, id: PeerId, path: Path, kind: MessageKind, completed: u64) {
        let Some(peer) = self.peers.peer_mut(id) else {
            return;
        };

        if completed > 0 {
            peer.expired = false;
            let rtt = (kind == MessageKind::HandshakeResponse)
                .then(|| peer.tunnel().stats().4)
                .flatten()
                .map(|ms| Duration::from_millis(u64::from(ms)));
            handshakes_completed(&mut self.outputs, id, completed, Some(path), rtt);
        }

        // Cookie replies are not authenticated by the peer's keys and never move the path.
        if !roams(kind)
            || peer
                .path()
                .is_some_and(|current| same_route(&current, &path))
        {
            return;
        }
        self.outputs.push_back(Output::Event(Event::Authenticated {
            peer: id,
            from: path,
        }));
        if self.policy.on_authenticated(id, &path, kind) == Roam::Adopt {
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

    /// Transmits a message of `kind` to `peer` on the path chosen by the policy.
    fn transmit(&mut self, id: PeerId, kind: MessageKind, data: PacketBuf) {
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

    /// Reports a dropped packet.
    fn dropped(&mut self, peer: Option<PeerId>, reason: &'static str) {
        self.outputs
            .push_back(Output::Event(Event::Dropped { peer, reason }));
    }
}

/// Transmits the local packet that peer `id`'s tunnel sealed in `packet` with `outcome`.
fn sealed(
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
fn transmit(
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
        outputs.push_back(Output::Transmit { path, data });
    } else {
        pool.put(data);
        outputs.push_back(Output::Event(Event::Dropped {
            peer: Some(id),
            reason: reasons::NO_PATH,
        }));
    }
}

/// The kind of an outgoing WireGuard message.
fn message_kind(datagram: &[u8]) -> MessageKind {
    match Tunn::parse_incoming_packet(datagram) {
        Ok(Packet::HandshakeInit(_)) => MessageKind::HandshakeInit,
        Ok(Packet::HandshakeResponse(_)) => MessageKind::HandshakeResponse,
        Ok(Packet::PacketCookieReply(_)) => MessageKind::CookieReply,
        Ok(Packet::PacketData(_)) if datagram.len() == KEEPALIVE_SZ => MessageKind::Keepalive,
        Ok(Packet::PacketData(_)) | Err(_) => MessageKind::Data,
    }
}

/// Reports `count` handshakes of `peer` completed on `path` with this `rtt`.
fn handshakes_completed(
    outputs: &mut VecDeque<Output>,
    peer: PeerId,
    count: u64,
    path: Option<Path>,
    rtt: Option<Duration>,
) {
    for _ in 0..count {
        outputs.push_back(Output::Event(Event::HandshakeCompleted { peer, path, rtt }));
    }
}

/// Whether an authenticated message of this kind may move the peer's path.
///
/// Cookie replies are encrypted with a key derived from the peer's public key only, so they do
/// not prove that the sender holds the peer's private key; they never cause roaming.
const fn roams(kind: MessageKind) -> bool {
    !matches!(kind, MessageKind::CookieReply)
}

/// Whether two paths lead to the same place; their ECN marks may differ.
fn same_route(a: &Path, b: &Path) -> bool {
    a.transport == b.transport && a.addr == b.addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_replies_do_not_roam() {
        let mut reply = [0u8; 64];
        reply[0] = 3;
        let kind = message_kind(&reply);
        assert_eq!(kind, MessageKind::CookieReply);
        assert!(!roams(kind));

        let mut data = [0u8; 32];
        data[0] = 4;
        let kind = message_kind(&data);
        assert_eq!(kind, MessageKind::Keepalive);
        assert!(roams(kind));
    }

    #[test]
    fn peers_need_a_private_key() {
        let mut core = Core::new(CoreConfig::default());
        assert_eq!(core.poll_timeout(), None);
        let key = x25519::PublicKey::from([7; 32]);

        let now = Instant::now();
        core.handle_input(
            Input::Config(ConfigChange::AddOrUpdatePeer(PeerConfig::new(key))),
            now,
        );
        assert_eq!(core.poll_timeout(), Some(now + TICK));
        assert!(matches!(
            core.poll_output(),
            Some(Output::Event(Event::Dropped {
                peer: None,
                reason: reasons::NO_PRIVATE_KEY
            }))
        ));
        assert!(core.poll_output().is_none());
        assert_eq!(core.peers().count(), 0);
    }

    #[test]
    fn changes_to_unknown_peers_are_ignored() {
        let mut core = Core::new(CoreConfig {
            private_key: Some(x25519::StaticSecret::from([1; 32])),
            ..CoreConfig::default()
        });
        let key = x25519::PublicKey::from([7; 32]);
        core.handle_input(
            Input::Config(ConfigChange::SetKeepalive {
                peer: key,
                interval: Some(25),
            }),
            Instant::now(),
        );
        assert!(core.poll_output().is_none());
        assert_eq!(core.peer_id(&key), None);

        core.handle_input(
            Input::Config(ConfigChange::AddOrUpdatePeer(PeerConfig::new(key))),
            Instant::now(),
        );
        let id = core.peer_id(&key).unwrap();
        assert_eq!(core.peers().collect::<Vec<_>>(), [id]);
        assert_eq!(core.peer_stats(id).unwrap().public_key, key);
    }

    #[test]
    fn routes_by_the_longest_allowed_ip_match() {
        let mut core = Core::new(CoreConfig {
            private_key: Some(x25519::StaticSecret::from([1; 32])),
            ..CoreConfig::default()
        });
        let mut add = |key: [u8; 32], allowed: &[&str]| {
            let key = x25519::PublicKey::from(key);
            let mut config = PeerConfig::new(key);
            config.allowed_ips = allowed.iter().map(|a| a.parse().unwrap()).collect();
            core.handle_input(
                Input::Config(ConfigChange::AddOrUpdatePeer(config)),
                Instant::now(),
            );
            key
        };
        let wide = add([7; 32], &["10.0.0.0/8", "fd00::/8"]);
        let narrow = add([8; 32], &["10.1.0.0/16"]);
        let wide = core.peer_id(&wide).unwrap();
        let narrow = core.peer_id(&narrow).unwrap();

        assert_eq!(core.route("10.2.0.1".parse().unwrap()), Some(wide));
        assert_eq!(core.route("10.1.0.1".parse().unwrap()), Some(narrow));
        assert_eq!(core.route("fd00::1".parse().unwrap()), Some(wide));
        assert_eq!(core.route("192.0.2.1".parse().unwrap()), None);
    }
}
