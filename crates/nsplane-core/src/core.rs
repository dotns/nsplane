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
use crate::peer_table::{PeerTable, PeerTableError};
use crate::policy::{MessageKind, PathPolicy, Roam};
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
    /// A datagram may be decrypted in place: when it carries a packet to deliver, `data` is
    /// swapped for a pooled buffer and the packet travels on in `Output::Deliver`.
    pub fn handle_input(&mut self, input: Input<'_>, now: Instant) {
        self.start_schedule(now);
        match input {
            Input::Datagram { path, data } => self.receive(path, data, now),
            Input::Local { packet } => self.send(packet, true),
            Input::Config(change) => self.configure(change, now),
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

        let mut buf = self.pool.get(BUF_SIZE);
        for (id, peer) in self.peers.iter_mut() {
            // The timers may expire sessions or start a handshake.
            peer.reset_rx_session();
            buf.set_len(BUF_SIZE);
            match peer.update_timers(now, &mut buf.with_headroom_mut()[HEADROOM..]) {
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
                    let data = mem::replace(&mut buf, self.pool.get(BUF_SIZE));
                    transmit(
                        &mut self.outputs,
                        &mut self.pool,
                        self.policy.as_ref(),
                        id,
                        peer.path(),
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
                let (_, tx, rx, ..) = p.tunnel.stats();
                self.outputs.push_back(Output::Event(Event::PeerStats {
                    peer,
                    rx: rx as u64,
                    tx: tx as u64,
                    data_rx: p.data_rx(),
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
        let (_, tx, rx, ..) = p.tunnel.stats();
        let last_handshake = self.now.and_then(|now| p.time_since_last_handshake(now));
        Some(PeerStats {
            peer,
            public_key: *p.public_key(),
            path: p.path(),
            allowed_ips: self.peers.allowed_ips(peer),
            preshared_key: p.preshared_key().copied(),
            persistent_keepalive: p.persistent_keepalive(),
            rx: rx as u64,
            tx: tx as u64,
            data_rx: p.data_rx(),
            last_handshake,
        })
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
        p.reset_rx_session();

        let mut buf = self.pool.get(BUF_SIZE);
        buf.set_len(BUF_SIZE);
        match p
            .tunnel
            .format_handshake_initiation(&mut buf.with_headroom_mut()[HEADROOM..], true)
        {
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.set_len(len);
                transmit(
                    &mut self.outputs,
                    &mut self.pool,
                    self.policy.as_ref(),
                    peer,
                    p.path(),
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
    /// `Event::Dropped { peer: None, reason: "no private key" }`. Changes to unknown peers are
    /// ignored.
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
                PeerTableError::NoPrivateKey => "no private key",
                PeerTableError::IndicesExhausted => "no free session index",
                PeerTableError::IdsExhausted => "no free peer id",
            };
            self.dropped(None, reason);
        }
    }

    /// Handles a datagram from `path`.
    fn receive(&mut self, path: Path, data: &mut PacketBuf, now: Instant) {
        let data_index = match Tunn::parse_incoming_packet(data.as_packet()) {
            Ok(Packet::PacketData(p)) => Some(p.receiver_idx),
            Ok(_) => None,
            Err(_) => return self.dropped(None, "invalid packet"),
        };
        match data_index {
            Some(index) => self.receive_data(path, data, index, now),
            None => self.receive_handshake(path, data.as_packet(), now),
        }
    }

    /// Decrypts transport data in place and delivers it.
    fn receive_data(&mut self, path: Path, data: &mut PacketBuf, receiver_idx: u32, now: Instant) {
        let Some(id) = self.peers.by_index(receiver_idx) else {
            return self.dropped(None, "unknown session");
        };
        let Some(peer) = self.peers.peer_mut(id) else {
            return;
        };
        // Only transport data on a new session, or after the sessions may have changed, can
        // complete a handshake: data on the established session leaves the clock alone.
        let new_session = peer.is_new_session(receiver_idx);
        let before = if new_session {
            peer.time_since_last_handshake(now)
        } else {
            None
        };
        let len = data.len();
        let (plain_len, src) = match peer.tunnel.decapsulate_in_place(
            Some(path.addr),
            &mut data.with_headroom_mut()[HEADROOM..],
            len,
        ) {
            TunnResult::Done => (0, None),
            TunnResult::WriteToTunnelV4(packet, src) => (packet.len(), Some(IpAddr::V4(src))),
            TunnResult::WriteToTunnelV6(packet, src) => (packet.len(), Some(IpAddr::V6(src))),
            TunnResult::Err(e) => {
                tracing::debug!(message = "Decapsulate error", error = ?e);
                return self.dropped(Some(id), "decapsulate error");
            }
            TunnResult::WriteToNetwork(_) => {
                tracing::debug!("Unexpected result from decapsulate");
                return;
            }
        };
        let completed = new_session && {
            peer.set_rx_session(receiver_idx);
            new_handshake(before, peer.time_since_last_handshake(now))
        };

        let kind = if src.is_some() {
            MessageKind::Data
        } else {
            MessageKind::Keepalive
        };
        self.authenticated(id, path, kind, completed);

        let Some(src) = src else {
            return;
        };
        if !self.peers.routes_to(src, id) {
            return self.dropped(Some(id), "source not allowed");
        }

        // The plaintext lies behind the data header: hand the caller's buffer on and move
        // the packet to the start of it.
        let fresh = self.pool.get(data.capacity());
        let mut packet = mem::replace(data, fresh);
        let start = HEADROOM + DATA_HEADER_SZ;
        packet
            .with_headroom_mut()
            .copy_within(start..start + plain_len, HEADROOM);
        packet.set_len(plain_len);

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

    /// Verifies a handshake message, finds its peer and lets the peer's tunnel answer it.
    fn receive_handshake(&mut self, path: Path, datagram: &[u8], now: Instant) {
        let (Some((private, public)), Some(gate)) =
            (self.peers.key_pair(), self.peers.rate_limiter())
        else {
            return self.dropped(None, "no private key");
        };

        // Handshake messages are small: copy them out, so the reply can go to a pooled buffer.
        let mut message = [0u8; HANDSHAKE_INIT_SZ];
        let Some(message) = message.get_mut(..datagram.len()) else {
            return self.dropped(None, "invalid packet");
        };
        message.copy_from_slice(datagram);

        let mut reply = self.pool.get(BUF_SIZE);
        reply.set_len(BUF_SIZE);
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
                return self.dropped(None, "invalid handshake");
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
            return self.dropped(None, "unknown peer");
        };
        let Some(p) = self.peers.peer_mut(id) else {
            return self.pool.put(reply);
        };

        p.reset_rx_session();
        let before = p.time_since_last_handshake(now);
        let reply_len = match p.tunnel.decapsulate(
            Some(path.addr),
            message,
            &mut reply.with_headroom_mut()[HEADROOM..],
        ) {
            TunnResult::Done => None,
            TunnResult::WriteToNetwork(packet) => Some(packet.len()),
            TunnResult::Err(e) => {
                tracing::debug!(message = "Handshake error", error = ?e);
                self.pool.put(reply);
                return self.dropped(Some(id), "handshake rejected");
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                tracing::debug!("Unexpected result from decapsulate");
                return self.pool.put(reply);
            }
        };
        let completed = new_handshake(before, p.time_since_last_handshake(now));

        let Some(reply_len) = reply_len else {
            self.pool.put(reply);
            return self.authenticated(id, path, kind, completed);
        };
        reply.set_len(reply_len);
        let reply_kind = message_kind(reply.as_packet());
        if reply_kind == MessageKind::CookieReply {
            // The tunnel is under load and asks for a cookie: nothing was authenticated.
            self.outputs
                .push_back(Output::Transmit { path, data: reply });
            return;
        }

        self.authenticated(id, path, kind, completed);
        self.transmit(id, reply_kind, reply);
        self.flush_queue(id);
    }

    /// Encrypts a local packet in place and transmits it to the peer it is routed to.
    fn send(&mut self, mut packet: PacketBuf, filter: bool) {
        let Some(id) =
            Tunn::dst_address(packet.as_packet()).and_then(|dst| self.peers.by_destination(dst))
        else {
            self.pool.put(packet);
            return self.dropped(None, "no route");
        };

        if filter {
            for f in &self.filters {
                match f.outbound(id, &mut packet) {
                    Verdict::Accept => {}
                    Verdict::Drop { reason } => {
                        self.pool.put(packet);
                        return self.dropped(Some(id), reason);
                    }
                    Verdict::Handled => return self.pool.put(packet),
                }
            }
        }

        let Some(peer) = self.peers.peer_mut(id) else {
            return self.pool.put(packet);
        };
        let len = packet.len();
        // The datagram is sealed from the headroom on and then moved up by the data header,
        // so the packet needs room for the header, the tag and the padding, or for a handshake
        // initiation if the packet is queued instead.
        packet.set_len((len + DATA_HEADER_SZ + TAIL_ROOM).max(HANDSHAKE_INIT_SZ));
        let start = HEADROOM - DATA_HEADER_SZ;
        let sealed_len = match peer
            .tunnel
            .encapsulate_in_place(&mut packet.with_headroom_mut()[start..], len)
        {
            TunnResult::WriteToNetwork(datagram) => datagram.len(),
            TunnResult::Done => {
                // Queued behind a handshake in progress.
                peer.reset_rx_session();
                return self.pool.put(packet);
            }
            TunnResult::Err(e) => {
                tracing::debug!(message = "Encapsulate error", error = ?e);
                self.pool.put(packet);
                return self.dropped(Some(id), "encapsulate error");
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                tracing::debug!("Unexpected result from encapsulate");
                return self.pool.put(packet);
            }
        };

        // The datagram starts in the headroom: move it to the start of the packet.
        packet
            .with_headroom_mut()
            .copy_within(start..start + sealed_len, HEADROOM);
        packet.set_len(sealed_len);
        let kind = message_kind(packet.as_packet());
        if kind == MessageKind::HandshakeInit {
            // Queued, and a handshake starts.
            peer.reset_rx_session();
        }
        self.transmit(id, kind, packet);
    }

    /// Transmits the packets the tunnel of `peer` queued while it had no session.
    fn flush_queue(&mut self, id: PeerId) {
        let Some(peer) = self.peers.peer_mut(id) else {
            return;
        };
        loop {
            let mut buf = self.pool.get(BUF_SIZE);
            buf.set_len(BUF_SIZE);
            let TunnResult::WriteToNetwork(packet) =
                peer.tunnel
                    .decapsulate(None, &[], &mut buf.with_headroom_mut()[HEADROOM..])
            else {
                return self.pool.put(buf);
            };
            let len = packet.len();
            buf.set_len(len);
            transmit(
                &mut self.outputs,
                &mut self.pool,
                self.policy.as_ref(),
                id,
                peer.path(),
                MessageKind::Data,
                buf,
            );
        }
    }

    /// Records an authenticated message of `kind` from `peer` on `path`: reports a new
    /// handshake if the message `completed` one and a new source, and lets the policy decide
    /// about roaming.
    fn authenticated(&mut self, id: PeerId, path: Path, kind: MessageKind, completed: bool) {
        let Some(peer) = self.peers.peer_mut(id) else {
            return;
        };

        if completed {
            peer.expired = false;
            let rtt = (kind == MessageKind::HandshakeResponse)
                .then(|| peer.tunnel.stats().4)
                .flatten()
                .map(|ms| Duration::from_millis(u64::from(ms)));
            self.outputs
                .push_back(Output::Event(Event::HandshakeCompleted {
                    peer: id,
                    path: Some(path),
                    rtt,
                }));
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
        let current = self.peers.peer(id).and_then(crate::peer::Peer::path);
        transmit(
            &mut self.outputs,
            &mut self.pool,
            self.policy.as_ref(),
            id,
            current,
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

/// Queues `data` for `peer` on the path the policy selects for `kind`, or on the peer's
/// `current` path; drops it if there is neither.
fn transmit(
    outputs: &mut VecDeque<Output>,
    pool: &mut PacketPool,
    policy: &dyn PathPolicy,
    peer: PeerId,
    current: Option<Path>,
    kind: MessageKind,
    data: PacketBuf,
) {
    if let Some(path) = policy.select(peer, kind).or(current) {
        outputs.push_back(Output::Transmit { path, data });
    } else {
        pool.put(data);
        outputs.push_back(Output::Event(Event::Dropped {
            peer: Some(peer),
            reason: "no path",
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

/// Whether a message established a new session, from the time since the last handshake
/// before and after it was processed: a new session makes that time shrink (or appear).
fn new_handshake(before: Option<Duration>, after: Option<Duration>) -> bool {
    after.is_some_and(|after| before.is_none_or(|before| after < before))
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
                reason: "no private key"
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
}
