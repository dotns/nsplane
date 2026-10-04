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

use crate::allowed_ips::AllowedIps;
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

/// Lookups that consecutive data packets of a batch share: a peer's slot in the peer table, the
/// peer a destination is routed to, a source a peer may send from and a destination a peer may
/// send to. Only configuration changes the peer table, and a batch holds none, so they stay
/// valid for the whole batch; a batch of datagrams still starts over after every handshake
/// message, the only other message it holds.
#[derive(Debug, Default)]
struct Lookups {
    /// The last receiver index, with its peer and slot.
    session: Option<(u32, PeerId, usize)>,
    /// The last destination, with the peer and slot it is routed to.
    route: Option<(IpAddr, PeerId, usize)>,
    /// The last source accepted from a peer.
    source: Option<(IpAddr, PeerId)>,
    /// The last destination accepted from a peer with inbound destinations.
    destination: Option<(IpAddr, PeerId)>,
}

impl Lookups {
    /// The peer and slot that own the session of `receiver_idx`.
    fn session(&mut self, peers: &PeerTable, receiver_idx: u32) -> Option<(PeerId, usize)> {
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

    /// The peer and slot a packet to `dst` is routed to.
    fn route(&mut self, peers: &PeerTable, dst: IpAddr) -> Option<(PeerId, usize)> {
        if let Some((last, id, slot)) = self.route
            && last == dst
        {
            return Some((id, slot));
        }
        let id = peers.by_destination(dst)?;
        let slot = peers.slot(id)?;
        self.route = Some((dst, id, slot));
        Some((id, slot))
    }

    /// Whether peer `id` may send packets from `src`.
    fn source_allowed(&mut self, peers: &PeerTable, src: IpAddr, id: PeerId) -> bool {
        if self.source == Some((src, id)) {
            return true;
        }
        let allowed = peers.routes_to(src, id);
        if allowed {
            self.source = Some((src, id));
        }
        allowed
    }

    /// Whether peer `id`, whose inbound destinations are `set`, may send packets to `dst`.
    fn destination_allowed(&mut self, set: &AllowedIps<()>, dst: IpAddr, id: PeerId) -> bool {
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

/// The sans-I/O WireGuard engine.
///
/// Feed it with [`Core::handle_input`] (or batches of data packets with
/// [`Core::handle_datagrams`] and [`Core::handle_locals`]) and [`Core::handle_timeout`], then
/// drain [`Core::poll_output`] until it returns `None`. The core never reads the clock: every call
/// that needs the time takes `now`, and the first such call starts the timer schedule
/// reported by [`Core::poll_timeout`].
pub struct Core {
    peers: PeerTable,
    policy: Box<dyn PathPolicy>,
    /// [`PathPolicy::observe_every_message`], read once.
    observe_every_message: bool,
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
        let mut peers = PeerTable::new(config.handshake_rate_limit, config.crypto_jobs);
        if let Some(private_key) = config.private_key {
            peers.set_private_key(private_key);
        }
        Self {
            peers,
            observe_every_message: config.policy.observe_every_message(),
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
            Input::Local { packet } => self.send(packet, true, &mut Lookups::default()),
            Input::Config(change) => self.configure(change, now),
        }
    }

    /// Processes received datagrams exactly like feeding each to [`Core::handle_input`] as an
    /// `Input::Datagram`, in order: same outputs, events, drops and counters.
    ///
    /// The batch shares the work around each datagram: one schedule update, room in the output
    /// queue for the whole batch, and one session and peer lookup (and one allowed-IP check)
    /// for consecutive transport data of the same session.
    pub fn handle_datagrams(
        &mut self,
        batch: impl IntoIterator<Item = (Path, PacketBuf)>,
        now: Instant,
    ) {
        let mut batch = batch.into_iter().peekable();
        if batch.peek().is_none() {
            return;
        }
        self.start_schedule(now);
        self.outputs.reserve(batch.size_hint().0);
        let mut lookups = Lookups::default();
        for (path, data) in batch {
            match self.classify(path, data) {
                Some((data, index)) => self.receive_data(path, data, index, &mut lookups),
                None => lookups = Lookups::default(),
            }
        }
    }

    /// Processes local packets exactly like feeding each to [`Core::handle_input`] as an
    /// `Input::Local`, in order: same outputs, events, drops and counters.
    ///
    /// The batch shares the work around each packet: one schedule update, room in the output
    /// queue for the whole batch, and one route and peer lookup for consecutive packets to the
    /// same destination.
    pub fn handle_locals(&mut self, batch: impl IntoIterator<Item = PacketBuf>, now: Instant) {
        let mut batch = batch.into_iter().peekable();
        if batch.peek().is_none() {
            return;
        }
        self.start_schedule(now);
        self.outputs.reserve(batch.size_hint().0);
        let mut lookups = Lookups::default();
        for packet in batch {
            self.send(packet, true, &mut lookups);
        }
    }

    /// Processes received datagrams like [`Core::handle_datagrams`], except that it hands out
    /// jobs like [`Core::handle_input_deferred`]: the same as feeding each datagram to it in
    /// order and pushing every job it returns onto `jobs`.
    pub fn handle_datagrams_deferred(
        &mut self,
        batch: impl IntoIterator<Item = (Path, PacketBuf)>,
        now: Instant,
        jobs: &mut Vec<CryptoJob>,
    ) {
        if !self.peers.shared_tunnels() {
            return self.handle_datagrams(batch, now);
        }
        let mut batch = batch.into_iter().peekable();
        if batch.peek().is_none() {
            return;
        }
        self.start_schedule(now);
        jobs.reserve(batch.size_hint().0);
        let mut lookups = Lookups::default();
        for (path, data) in batch {
            match self.classify(path, data) {
                Some((data, index)) => jobs.extend(self.open_job(path, data, index, &mut lookups)),
                None => lookups = Lookups::default(),
            }
        }
    }

    /// Processes local packets like [`Core::handle_locals`], except that it hands out jobs
    /// like [`Core::handle_input_deferred`]: the same as feeding each packet to it in order and
    /// pushing every job it returns onto `jobs`.
    pub fn handle_locals_deferred(
        &mut self,
        batch: impl IntoIterator<Item = PacketBuf>,
        now: Instant,
        jobs: &mut Vec<CryptoJob>,
    ) {
        if !self.peers.shared_tunnels() {
            return self.handle_locals(batch, now);
        }
        let mut batch = batch.into_iter().peekable();
        if batch.peek().is_none() {
            return;
        }
        self.start_schedule(now);
        jobs.reserve(batch.size_hint().0);
        let mut lookups = Lookups::default();
        for packet in batch {
            jobs.extend(self.seal_job(packet, &mut lookups));
        }
    }

    /// Processes one input like [`Core::handle_input`], except that the encryption of a local
    /// packet or the decryption of a received transport data message is returned as a job
    /// instead of being run: run it anywhere with [`CryptoJob::run`], then hand it back with
    /// [`Core::complete_job`]. Everything else (handshakes, configuration, packets that are
    /// dropped before their cryptography) is processed at once and returns `None`.
    ///
    /// A core built without [`CoreConfig::crypto_jobs`] hands out no jobs: it processes every
    /// input at once like [`Core::handle_input`] and returns `None`.
    pub fn handle_input_deferred(&mut self, input: Input, now: Instant) -> Option<CryptoJob> {
        if !self.peers.shared_tunnels() {
            self.handle_input(input, now);
            return None;
        }
        self.start_schedule(now);
        match input {
            Input::Datagram { path, data } => {
                let (data, index) = self.classify(path, data)?;
                self.open_job(path, data, index, &mut Lookups::default())
            }
            Input::Local { packet } => self.seal_job(packet, &mut Lookups::default()),
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
                let slot = self.peers.slot(id);
                let opened =
                    self.opened(id, slot, path, &job.buf, outcome, &mut Lookups::default());
                match opened {
                    Some(plain_len) => self.deliver_opened(id, slot, path, job.buf, plain_len),
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

    /// The path `peer`'s next transport data message would leave on: the one the policy
    /// selects for [`MessageKind::Data`], or the peer's current path. `None` for an unknown
    /// peer or one without a path.
    pub fn data_path(&self, peer: PeerId) -> Option<Path> {
        let current = self.peers.peer(peer)?.path();
        self.policy.select(peer, MessageKind::Data).or(current)
    }

    /// Whether `index` is the receiver index `peer`'s current session puts on its transport
    /// data messages (the index the peer assigned to it), e.g. to check that a quoted
    /// datagram is ours. `false` for an unknown peer or one without a session.
    pub fn is_remote_index(&self, peer: PeerId, index: u32) -> bool {
        self.peers
            .peer(peer)
            .is_some_and(|p| p.remote_index() == Some(index))
    }

    /// Delivers `packet` as if it came from `peer`, bypassing the inbound filters and the
    /// allowed-IP source check.
    ///
    /// Part of the contract: no inbound [`PacketFilter`] sees the packet, so a stateful
    /// filter records nothing about it and a translating filter does not translate it.
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
    pub fn inject_outbound(&mut self, packet: PacketBuf, now: Instant) {
        self.start_schedule(now);
        self.send(packet, false, &mut Lookups::default());
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

    /// Starts a handshake with `peer` now, even if one is in progress. A `path` becomes the
    /// peer's path first, without an `Event::PathAdopted`. Unknown peers are ignored.
    pub fn force_handshake(&mut self, peer: PeerId, path: Option<Path>, now: Instant) {
        self.start_schedule(now);
        if let (Some(p), Some(path)) = (self.peers.peer_mut(peer), path) {
            p.set_path(path);
        }
        self.initiate(peer, None);
    }

    /// Sends a handshake initiation to `peer` on `path` now, even if a handshake is in
    /// progress, without changing the peer's path: e.g. to open a session through a
    /// candidate path. The rest of the handshake (retries included) follows the policy and
    /// the peer's path. Unknown peers are ignored.
    pub fn force_handshake_on(&mut self, peer: PeerId, path: Path, now: Instant) {
        self.start_schedule(now);
        self.initiate(peer, Some(path));
    }

    /// Formats a handshake initiation for `peer` and transmits it on `on`, or as the policy
    /// selects.
    fn initiate(&mut self, peer: PeerId, on: Option<Path>) {
        let Some(p) = self.peers.peer_mut(peer) else {
            return;
        };

        let mut buf = self.pool.get_len(BUF_SIZE);
        let initiation = p
            .tunnel_mut()
            .format_handshake_initiation(&mut buf.with_headroom_mut()[HEADROOM..], true);
        match initiation {
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.set_len(len);
                let fixed;
                let policy: &dyn PathPolicy = match on {
                    Some(path) => {
                        fixed = Fixed(Path {
                            ecn: Ecn::NotEct,
                            ..path
                        });
                        &fixed
                    }
                    None => self.policy.as_ref(),
                };
                transmit(
                    &mut self.outputs,
                    &mut self.pool,
                    policy,
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
            | ConfigChange::SetInboundDestinations { peer, .. }
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
            ConfigChange::SetInboundDestinations { peer, destinations } => {
                // A `None` in a PeerConfig leaves them unchanged: remove them directly.
                if let Some(id) = self.peers.get(&peer) {
                    self.peers
                        .set_inbound_destinations(id, destinations.as_deref());
                }
                return;
            }
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
            self.receive_data(path, data, index, &mut Lookups::default());
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
    fn receive_data(
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
        let outcome = job::open(&mut peer.tunnel_mut(), path, &mut data);
        match self.opened(id, Some(slot), path, &data, outcome, lookups) {
            Some(plain_len) => self.deliver_opened(id, Some(slot), path, data, plain_len),
            None => self.pool.put(data),
        }
    }

    /// Hands out the decryption of transport data as a job.
    fn open_job(
        &mut self,
        path: Path,
        data: PacketBuf,
        receiver_idx: u32,
        lookups: &mut Lookups,
    ) -> Option<CryptoJob> {
        let peer = lookups
            .session(&self.peers, receiver_idx)
            .and_then(|(id, slot)| Some((id, self.peers.at(slot)?.shared_tunnel()?)));
        let Some((id, tunnel)) = peer else {
            self.pool.put(data);
            self.dropped(None, reasons::UNKNOWN_SESSION);
            return None;
        };
        Some(CryptoJob::new(id, tunnel, data, Direction::Open { path }))
    }

    /// Delivers the `plain_len` bytes of plaintext opened in `data` from peer `id` at `slot`,
    /// received on `path`, after the inbound filters.
    fn deliver_opened(
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
        let mut packet = data;

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
            peer.add_data_rx(plain_len as u64);
        }
        self.outputs.push_back(Output::Deliver { from: id, packet });
    }

    /// Accounts for `datagram` from `path` that the tunnel of peer `id` at `slot` opened in
    /// place with `outcome`; returns the plaintext length if it carries a packet to deliver.
    fn opened(
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
        if !lookups.source_allowed(&self.peers, src, id) {
            self.dropped(Some(id), reasons::SOURCE_NOT_ALLOWED);
            return None;
        }
        if let Some(set) = self.peers.inbound_destinations(slot) {
            let dst = datagram
                .as_packet()
                .get(DATA_HEADER_SZ..DATA_HEADER_SZ + plain_len)
                .and_then(Tunn::dst_address);
            if !dst.is_some_and(|dst| lookups.destination_allowed(set, dst, id)) {
                self.dropped(Some(id), reasons::DESTINATION_NOT_ALLOWED);
                return None;
            }
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

    /// Encrypts a local packet in place and transmits it to the peer it is routed to.
    fn send(&mut self, packet: PacketBuf, filter: bool, lookups: &mut Lookups) {
        let Some((id, slot, mut packet, len)) = self.prepare_send(packet, filter, lookups) else {
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
    fn seal_job(&mut self, packet: PacketBuf, lookups: &mut Lookups) -> Option<CryptoJob> {
        let (id, slot, packet, len) = self.prepare_send(packet, true, lookups)?;
        let Some(tunnel) = self.peers.at(slot).and_then(Peer::shared_tunnel) else {
            self.pool.put(packet);
            return None;
        };
        Some(CryptoJob::new(id, tunnel, packet, Direction::Seal { len }))
    }

    /// Routes a local packet, runs the outbound filters with `filter` and lays the packet out
    /// for sealing in place; returns its peer and the peer's slot, its buffer and its length.
    fn prepare_send(
        &mut self,
        mut packet: PacketBuf,
        filter: bool,
        lookups: &mut Lookups,
    ) -> Option<(PeerId, usize, PacketBuf, usize)> {
        let Some((id, slot)) =
            Tunn::dst_address(packet.as_packet()).and_then(|dst| lookups.route(&self.peers, dst))
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

        let (packet, len) = self.layout_for_sealing(packet);
        Some((id, slot, packet, len))
    }

    /// Lays a local packet out for sealing in place; returns its buffer and its length.
    fn layout_for_sealing(&mut self, mut packet: PacketBuf) -> (PacketBuf, usize) {
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
        (packet, len)
    }

    /// Transmits the packets the tunnel of `peer` queued while it had no session.
    fn flush_queue(&mut self, id: PeerId) {
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

/// A policy that sends everything on one path, for [`Core::inject_outbound_on`].
struct Fixed(Path);

impl PathPolicy for Fixed {
    fn select(&self, _peer: PeerId, _kind: MessageKind) -> Option<Path> {
        Some(self.0)
    }

    fn on_authenticated(&self, _peer: PeerId, _from: &Path, _kind: MessageKind) -> Roam {
        Roam::Keep
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
    fn inbound_destinations_of_unknown_peers_are_ignored() {
        let mut core = Core::new(CoreConfig {
            private_key: Some(x25519::StaticSecret::from([1; 32])),
            ..CoreConfig::default()
        });
        let key = x25519::PublicKey::from([7; 32]);
        let change = ConfigChange::SetInboundDestinations {
            peer: key,
            destinations: Some(vec!["10.1.0.0/16".parse().unwrap()]),
        };
        assert!(format!("{change:?}").contains("10.1.0.0"));
        core.handle_input(Input::Config(change), Instant::now());
        assert!(core.poll_output().is_none());
        assert_eq!(core.peer_id(&key), None);

        let mut config = PeerConfig::new(key);
        assert!(format!("{config:?}").contains("inbound_destinations: None"));
        config.inbound_destinations = Some(Vec::new());
        core.handle_input(
            Input::Config(ConfigChange::AddOrUpdatePeer(config)),
            Instant::now(),
        );
        let id = core.peer_id(&key).unwrap();
        let slot = core.peers.slot(id).unwrap();
        assert!(core.peers.inbound_destinations(slot).is_some());
        core.handle_input(
            Input::Config(ConfigChange::SetInboundDestinations {
                peer: key,
                destinations: None,
            }),
            Instant::now(),
        );
        assert!(core.peers.inbound_destinations(slot).is_none());
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

    /// Sends data on a fixed path, everything else on the current one.
    struct DataOn(Path);

    impl PathPolicy for DataOn {
        fn select(&self, _peer: PeerId, kind: MessageKind) -> Option<Path> {
            (kind == MessageKind::Data).then_some(self.0)
        }

        fn on_authenticated(&self, _peer: PeerId, _from: &Path, _kind: MessageKind) -> Roam {
            Roam::Keep
        }
    }

    #[test]
    fn data_path_follows_the_policy_then_the_current_path() {
        let path = |port| Path {
            transport: nsplane_packet::TransportId::new(1),
            addr: std::net::SocketAddr::from(([192, 0, 2, 1], port)),
            ecn: Ecn::NotEct,
        };
        let add = |core: &mut Core, with_path: bool| {
            let key = x25519::PublicKey::from([7; 32]);
            let mut config = PeerConfig::new(key);
            config.path = with_path.then(|| path(1));
            core.handle_input(
                Input::Config(ConfigChange::AddOrUpdatePeer(config)),
                Instant::now(),
            );
            core.peer_id(&key).unwrap()
        };
        let private_key = Some(x25519::StaticSecret::from([1; 32]));

        let mut core = Core::new(CoreConfig {
            private_key: private_key.clone(),
            ..CoreConfig::default()
        });
        assert_eq!(core.data_path(PeerId::new(99)), None);
        let id = add(&mut core, false);
        assert_eq!(core.data_path(id), None);
        let id = add(&mut core, true);
        assert_eq!(core.data_path(id), Some(path(1)));
        assert!(!core.is_remote_index(id, 0));
        assert!(!core.is_remote_index(PeerId::new(99), 0));

        let mut core = Core::new(CoreConfig {
            private_key,
            policy: Box::new(DataOn(path(2))),
            ..CoreConfig::default()
        });
        let id = add(&mut core, true);
        assert_eq!(core.data_path(id), Some(path(2)));
    }
}
