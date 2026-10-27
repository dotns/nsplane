// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The sans-I/O engine: receive demultiplexing, the send path and the timers.

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use nsplane_noise::noise::{DATA_HEADER_SZ, Packet, Tunn};
use nsplane_packet::{PacketBuf, PacketPool, Path, PeerId};

use crate::filter::PacketFilter;
use crate::job::{CryptoJob, Direction, Outcome};
use crate::peer_table::PeerTable;
use crate::policy::{MessageKind, PathPolicy};
use crate::types::{CoreConfig, Event, Input, Output};

mod config;
mod receive;
mod route_cache;
mod send;
#[cfg(test)]
mod tests;
mod timers;

use route_cache::{Lookups, RouteCache};
use send::{not_sent, sealed, token};

/// Interval of the peer timers, as in the device.
const TICK: Duration = Duration::from_millis(250);
/// Interval of the handshake gate's rate limiter reset.
const RATE_LIMITER_RESET: Duration = Duration::from_secs(1);
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
/// Feed it with [`Core::handle_input`] (or batches of data packets with
/// [`Core::handle_datagrams`] and [`Core::handle_locals`]) and [`Core::handle_timeout`], then
/// drain [`Core::poll_output`] until it returns `None`. The core never reads the clock: every call
/// that needs the time takes `now`, and the first such call starts the timer schedule
/// reported by [`Core::poll_timeout`].
pub struct Core {
    peers: PeerTable,
    /// The allowed-IP lookups of the data path, valid for the current peer table.
    routes: Box<RouteCache>,
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
    /// Unanswered handshake initiations of the peers removed so far.
    removed_unanswered_handshakes: u64,
    /// Some peer is marked for plaintext egress (or was, until the next mark changes).
    plaintext_egress: bool,
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
            routes: Box::new(RouteCache::new(peers.generation())),
            peers,
            observe_every_message: config.policy.observe_every_message(),
            policy: config.policy,
            filters: config.filters,
            stats_interval: config.stats_interval,
            pool: PacketPool::new(config.pool_size),
            outputs: VecDeque::new(),
            schedule: None,
            now: None,
            removed_unanswered_handshakes: 0,
            plaintext_egress: false,
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
        for packet in batch {
            self.send(packet, true);
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
        for packet in batch {
            jobs.extend(self.seal_job(packet));
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
            Input::Local { packet } => self.seal_job(packet),
            Input::Config(change) => {
                self.configure(change, now);
                None
            }
        }
    }

    /// Finishes a job from [`Core::handle_input_deferred`], running it first if it has not
    /// run; the results are queued for [`Core::poll_output`] as with [`Core::handle_input`].
    /// A received message is only now marked as received in its session's replay window, so
    /// a duplicate is rejected here; a datagram sealed in a session that expired or was
    /// replaced in the meantime is dropped and counted under [`reasons::ENCAPSULATE_ERROR`].
    /// A job whose peer was removed in the meantime is discarded.
    ///
    /// Complete the jobs of one peer in the order they were handed out to keep its packets
    /// in order; see [`CryptoJob`].
    ///
    /// [`reasons::ENCAPSULATE_ERROR`]: crate::reasons::ENCAPSULATE_ERROR
    pub fn complete_job(&mut self, mut job: CryptoJob) {
        let id = job.peer;
        match job.direction {
            Direction::Seal { len } => {
                let Some(peer) = self.peers.peer_mut(id) else {
                    not_sent(
                        &mut self.outputs,
                        token(&job.buf),
                        Some(id),
                        crate::reasons::NO_ROUTE,
                    );
                    return self.pool.put(job.buf);
                };
                let outcome = job.finish(&mut peer.tunnel_mut());
                sealed(
                    &mut self.outputs,
                    &mut self.pool,
                    self.policy.as_ref(),
                    id,
                    peer,
                    job.buf,
                    outcome,
                    len,
                );
            }
            Direction::Open { path } => {
                let slot = self.peers.slot(id);
                let outcome = match slot.and_then(|slot| self.peers.at_mut(slot)) {
                    Some(peer) => job.finish(&mut peer.tunnel_mut()),
                    // The peer is gone: only a failure is counted.
                    None => match job.failure() {
                        Some(e) => Outcome::Failed(e),
                        None => return self.pool.put(job.buf),
                    },
                };
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

    /// Reports a dropped packet.
    fn dropped(&mut self, peer: Option<PeerId>, reason: &'static str) {
        self.outputs
            .push_back(Output::Event(Event::Dropped { peer, reason }));
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
pub(crate) fn same_route(a: &Path, b: &Path) -> bool {
    a.transport == b.transport && a.addr == b.addr
}
