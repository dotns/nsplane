//! The relay's demultiplexer: what to do with each datagram on the shared port.
//!
//! [`Router`] is sans-I/O: [`Router::route`] takes a datagram, its [`Source`] and the
//! clocks, and returns an [`Action`]: hand it to the relay's own engine, forward it to
//! another source, answer it with a control frame, or drop it with a counted
//! [`DropReason`]. The rules are the design note's
//! (`docs/decisions/2026-10-02-single-port-relay.md`):
//!
//! - handshake initiation: mac1 of the own key goes to the own engine; mac1 of exactly one
//!   target with a known source is forwarded there and installs the route
//!   `(initiator sender index, target source) -> initiator source`;
//! - handshake response: the route `(receiver index, source)` first, which also installs
//!   the reverse route `(responder sender index, initiator source) -> target source`; no
//!   route goes to the own engine;
//! - cookie reply and transport data: the route first, else the own engine;
//! - several destinations at once (own key and a target, two targets with one key, a route
//!   whose index the own engine also uses, a route that would change its destination):
//!   dropped as [`DropReason::Ambiguous`];
//! - control: `register_source` (signed by the target's pinned machine key, fresh, not
//!   replayed) teaches the target's source; a reflexive request from a pinned machine is
//!   answered with the observed address, echoing its nonce. Nothing else is ever sent.
//!
//! Routes expire after [`SESSION_TTL`] without traffic and learned sources after
//! [`LEARNED_SOURCE_TTL`] without a registration or traffic from them; both tables are
//! bounded and evictions are counted.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::envelope::{Error, ReplayGuard};
use super::mac1::Mac1Key;
use super::messages::{
    LEARNED_SOURCE_TTL, SESSION_TTL, build_reflexive_response, open_reflexive_request,
    open_register_source,
};
use super::wire::{self, ControlType, Frame, WgKind};

/// Where a datagram came from or goes to.
///
/// UDP sources are socket addresses; a stream carrier (WebSocket) names its connections by
/// id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// A UDP peer.
    Udp(SocketAddr),
    /// A WebSocket connection.
    Ws(u64),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "{addr}"),
            Self::Ws(id) => write!(f, "ws:{id}"),
        }
    }
}

/// Why a datagram was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// It matches more than one destination.
    Ambiguous,
    /// It names no target, or a target without a known source.
    UnknownTarget,
    /// Malformed, a reserved or unexpected control type, or not a datagram at all.
    Invalid,
    /// Its source exceeded the handshake or control rate.
    RateLimited,
    /// A control message whose nonce was seen before or whose timestamp is stale.
    Replay,
    /// A control message not signed by the pinned machine key.
    BadSignature,
}

impl DropReason {
    /// The counter name, as in the status file (`dropped_<name>`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ambiguous => "ambiguous",
            Self::UnknownTarget => "unknown_target",
            Self::Invalid => "invalid",
            Self::RateLimited => "rate_limited",
            Self::Replay => "replay",
            Self::BadSignature => "bad_signature",
        }
    }
}

/// What to do with a datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Hand it to the relay's own WireGuard engine.
    OwnEngine,
    /// Send it, unchanged, to this source.
    Forward(Source),
    /// A control message was handled; send this frame back to its source.
    Reply(Vec<u8>),
    /// A control message was handled; nothing to send.
    Handled,
    /// Drop it.
    Drop(DropReason),
}

/// The Ed25519 machine a target's control messages must be signed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachinePin {
    /// The machine id its envelopes carry.
    pub machine_id: String,
    /// The Ed25519 public key.
    pub machine_key: [u8; 32],
}

/// One relay target: a WireGuard key the relay forwards handshakes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetConfig {
    /// The target's WireGuard public key (the mac1 key of initiations addressed to it).
    pub wg_public_key: [u8; 32],
    /// The machine that may register the target's source.
    pub pin: Option<MachinePin>,
    /// A fixed source, for native WireGuard peers that cannot register.
    pub static_source: Option<Source>,
}

/// Timers and table bounds of a [`Router`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Idle lifetime of a route.
    pub session_ttl: Duration,
    /// Lifetime of a learned source without a registration or traffic.
    pub learned_source_ttl: Duration,
    /// Most routes kept; the least recently used one is evicted.
    pub max_routes: usize,
    /// Most routes of initiations without a response yet.
    pub max_pending: usize,
    /// Relayed handshake initiations accepted per source and second.
    pub handshakes_per_sec: u32,
    /// Control messages accepted per source and second (checked before verification).
    pub controls_per_sec: u32,
    /// Most sources rate state is kept for.
    pub max_sources: usize,
}

impl Default for Limits {
    /// nsgw's values: 3 min sessions, 90 s learned sources, 4096 routes, 1024 pending
    /// initiations, 128 handshakes per second.
    fn default() -> Self {
        Self {
            session_ttl: SESSION_TTL,
            learned_source_ttl: LEARNED_SOURCE_TTL,
            max_routes: 4096,
            max_pending: 1024,
            handshakes_per_sec: 128,
            controls_per_sec: 16,
            max_sources: 4096,
        }
    }
}

/// The router's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Datagrams handed to the own engine.
    pub own_engine: u64,
    /// Datagrams forwarded.
    pub forwarded: u64,
    /// Control frames received.
    pub control_rx: u64,
    /// Control frames sent (reflexive responses).
    pub control_tx: u64,
    /// Accepted source registrations.
    pub registrations: u64,
    /// Routes evicted to stay within the bounds.
    pub route_evictions: u64,
    /// Drops: [`DropReason::Ambiguous`].
    pub dropped_ambiguous: u64,
    /// Drops: [`DropReason::UnknownTarget`].
    pub dropped_unknown_target: u64,
    /// Drops: [`DropReason::Invalid`].
    pub dropped_invalid: u64,
    /// Drops: [`DropReason::RateLimited`].
    pub dropped_rate_limited: u64,
    /// Drops: [`DropReason::Replay`].
    pub dropped_replay: u64,
    /// Drops: [`DropReason::BadSignature`].
    pub dropped_bad_signature: u64,
}

impl Counters {
    const fn count(&mut self, action: &Action) {
        let counter = match action {
            Action::OwnEngine => &mut self.own_engine,
            Action::Forward(_) => &mut self.forwarded,
            Action::Reply(_) => &mut self.control_tx,
            Action::Handled => return,
            Action::Drop(reason) => match reason {
                DropReason::Ambiguous => &mut self.dropped_ambiguous,
                DropReason::UnknownTarget => &mut self.dropped_unknown_target,
                DropReason::Invalid => &mut self.dropped_invalid,
                DropReason::RateLimited => &mut self.dropped_rate_limited,
                DropReason::Replay => &mut self.dropped_replay,
                DropReason::BadSignature => &mut self.dropped_bad_signature,
            },
        };
        *counter += 1;
    }
}

/// A route, as reported by [`Router::routes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInfo {
    /// The receiver index datagrams on this route carry.
    pub receiver_index: u32,
    /// The source they arrive from.
    pub from: Source,
    /// Where they are forwarded.
    pub to: Source,
    /// Time since the route last carried a datagram.
    pub idle: Duration,
    /// Whether the handshake that installed it was answered.
    pub confirmed: bool,
}

/// A target, as reported by [`Router::targets`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    /// The target's WireGuard public key.
    pub wg_public_key: [u8; 32],
    /// The pinned machine key, if any.
    pub machine_key: Option<[u8; 32]>,
    /// Where initiations to it are forwarded now: the learned source, else the static one.
    pub source: Option<Source>,
    /// Time since the source was learned or refreshed; `None` when not learned.
    pub learned_ago: Option<Duration>,
}

#[derive(Debug)]
struct Target {
    config: TargetConfig,
    mac1: Mac1Key,
    learned: Option<(Source, Instant)>,
}

impl Target {
    fn new(config: TargetConfig) -> Self {
        Self {
            mac1: Mac1Key::new(&config.wg_public_key),
            config,
            learned: None,
        }
    }

    fn source(&self, now: Instant, ttl: Duration) -> Option<Source> {
        self.learned
            .filter(|(_, at)| now.saturating_duration_since(*at) < ttl)
            .map(|(source, _)| source)
            .or(self.config.static_source)
    }
}

#[derive(Debug, Clone, Copy)]
struct Route {
    to: Source,
    last_used: Instant,
    confirmed: bool,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    count: u32,
}

/// Fixed one-second windows per source.
#[derive(Debug, Default)]
struct RateLimiter {
    windows: HashMap<Source, Window>,
}

impl RateLimiter {
    fn admit(&mut self, source: Source, per_sec: u32, max_sources: usize, now: Instant) -> bool {
        const WINDOW: Duration = Duration::from_secs(1);
        if !self.windows.contains_key(&source) && self.windows.len() >= max_sources {
            self.windows
                .retain(|_, window| now.saturating_duration_since(window.start) < WINDOW);
            if self.windows.len() >= max_sources {
                self.windows.clear();
            }
        }
        let window = self.windows.entry(source).or_insert(Window {
            start: now,
            count: 0,
        });
        if now.saturating_duration_since(window.start) >= WINDOW {
            *window = Window {
                start: now,
                count: 0,
            };
        }
        if window.count >= per_sec {
            return false;
        }
        window.count += 1;
        true
    }
}

/// The relay's routing state. See the [module documentation](self).
#[derive(Debug)]
pub struct Router {
    own_mac1: Mac1Key,
    gateway_id: String,
    relay_addr: SocketAddr,
    limits: Limits,
    targets: Vec<Target>,
    routes: HashMap<(u32, Source), Route>,
    own_indices: HashMap<u32, Instant>,
    handshakes: RateLimiter,
    controls: RateLimiter,
    replay: ReplayGuard,
    counters: Counters,
    last_prune: Option<Instant>,
}

impl Router {
    /// A router for a relay whose own engine has the WireGuard public key `own_public`,
    /// named `gateway_id` and listening on `relay_addr` (both carried in reflexive
    /// responses).
    pub fn new(own_public: [u8; 32], gateway_id: String, relay_addr: SocketAddr) -> Self {
        Self::with_limits(own_public, gateway_id, relay_addr, Limits::default())
    }

    /// [`Router::new`] with explicit timers and bounds.
    pub fn with_limits(
        own_public: [u8; 32],
        gateway_id: String,
        relay_addr: SocketAddr,
        limits: Limits,
    ) -> Self {
        Self {
            own_mac1: Mac1Key::new(&own_public),
            gateway_id,
            relay_addr,
            limits,
            targets: Vec::new(),
            routes: HashMap::new(),
            own_indices: HashMap::new(),
            handshakes: RateLimiter::default(),
            controls: RateLimiter::default(),
            replay: ReplayGuard::new(),
            counters: Counters::default(),
            last_prune: None,
        }
    }

    /// Replaces the targets. A target whose key and pin are unchanged keeps its learned
    /// source.
    pub fn set_targets(&mut self, configs: Vec<TargetConfig>) {
        let mut old = std::mem::take(&mut self.targets);
        self.targets = configs
            .into_iter()
            .map(|config| {
                let mut target = Target::new(config);
                if let Some(pos) = old.iter().position(|o| {
                    o.config.wg_public_key == target.config.wg_public_key
                        && o.config.pin == target.config.pin
                }) {
                    target.learned = old.swap_remove(pos).learned;
                }
                target
            })
            .collect();
    }

    /// The counters.
    pub const fn counters(&self) -> Counters {
        self.counters
    }

    /// The live routes.
    pub fn routes(&self, now: Instant) -> Vec<RouteInfo> {
        let mut routes: Vec<RouteInfo> = self
            .routes
            .iter()
            .map(|(&(receiver_index, from), route)| RouteInfo {
                receiver_index,
                from,
                to: route.to,
                idle: now.saturating_duration_since(route.last_used),
                confirmed: route.confirmed,
            })
            .collect();
        routes.sort_by_key(|route| (route.receiver_index, route.idle));
        routes
    }

    /// The configured targets and where they are reached.
    pub fn targets(&self, now: Instant) -> Vec<TargetInfo> {
        let ttl = self.limits.learned_source_ttl;
        self.targets
            .iter()
            .map(|target| TargetInfo {
                wg_public_key: target.config.wg_public_key,
                machine_key: target.config.pin.as_ref().map(|pin| pin.machine_key),
                source: target.source(now, ttl),
                learned_ago: target
                    .learned
                    .map(|(_, at)| now.saturating_duration_since(at))
                    .filter(|ago| *ago < ttl),
            })
            .collect()
    }

    /// Records a datagram the own engine sends: the sender index of its handshakes, so a
    /// route reusing the index is recognized as ambiguous.
    pub fn note_own_send(&mut self, datagram: &[u8], now: Instant) {
        if let Some(index) = wire::sender_index(datagram) {
            self.own_indices.insert(index, now);
        }
    }

    /// Decides what to do with `datagram` from `from`. `now` drives the timers,
    /// `unix_now` (seconds) the control envelopes' freshness.
    pub fn route(&mut self, datagram: &[u8], from: Source, now: Instant, unix_now: u64) -> Action {
        self.prune(now);
        let action = match wire::classify(datagram) {
            Frame::WireGuard(kind) => {
                self.refresh_learned(from, now);
                match kind {
                    WgKind::HandshakeInit => self.route_init(datagram, from, now),
                    WgKind::HandshakeResponse => self.route_response(datagram, from, now),
                    WgKind::CookieReply | WgKind::TransportData => {
                        self.route_by_index(datagram, from, now)
                    }
                }
            }
            Frame::Control { .. } => {
                self.counters.control_rx += 1;
                self.control(datagram, from, now, unix_now)
            }
            Frame::Invalid => Action::Drop(DropReason::Invalid),
        };
        self.counters.count(&action);
        action
    }

    fn refresh_learned(&mut self, from: Source, now: Instant) {
        let ttl = self.limits.learned_source_ttl;
        for target in &mut self.targets {
            if let Some((source, at)) = &mut target.learned
                && *source == from
                && now.saturating_duration_since(*at) < ttl
            {
                *at = now;
            }
        }
    }

    fn route_init(&mut self, packet: &[u8], from: Source, now: Instant) -> Action {
        let own = self.own_mac1.matches(packet);
        let mut matched = self
            .targets
            .iter()
            .filter(|target| target.mac1.matches(packet));
        let (first, second) = (matched.next(), matched.next());
        let target = match (own, first, second) {
            (true, None, _) => return Action::OwnEngine,
            (true, Some(_), _) | (false, Some(_), Some(_)) => {
                return Action::Drop(DropReason::Ambiguous);
            }
            (false, None, _) => return Action::Drop(DropReason::UnknownTarget),
            (false, Some(target), None) => target,
        };
        let Some(to) = target.source(now, self.limits.learned_source_ttl) else {
            return Action::Drop(DropReason::UnknownTarget);
        };
        if to == from {
            return Action::Drop(DropReason::Invalid);
        }
        if !self.handshakes.admit(
            from,
            self.limits.handshakes_per_sec,
            self.limits.max_sources,
            now,
        ) {
            return Action::Drop(DropReason::RateLimited);
        }
        let Some(index) = wire::sender_index(packet) else {
            return Action::Drop(DropReason::Invalid);
        };
        if !self.install(index, to, from, false, now) {
            return Action::Drop(DropReason::Ambiguous);
        }
        Action::Forward(to)
    }

    fn route_response(&mut self, packet: &[u8], from: Source, now: Instant) -> Action {
        let (Some(receiver), Some(sender)) =
            (wire::receiver_index(packet), wire::sender_index(packet))
        else {
            return Action::Drop(DropReason::Invalid);
        };
        let Some(route) = self.routes.get_mut(&(receiver, from)) else {
            return Action::OwnEngine;
        };
        if self.own_indices.contains_key(&receiver) {
            return Action::Drop(DropReason::Ambiguous);
        }
        route.last_used = now;
        route.confirmed = true;
        let to = route.to;
        if !self.install(sender, to, from, true, now) {
            return Action::Drop(DropReason::Ambiguous);
        }
        Action::Forward(to)
    }

    fn route_by_index(&mut self, packet: &[u8], from: Source, now: Instant) -> Action {
        let Some(receiver) = wire::receiver_index(packet) else {
            return Action::Drop(DropReason::Invalid);
        };
        let Some(route) = self.routes.get_mut(&(receiver, from)) else {
            return Action::OwnEngine;
        };
        if self.own_indices.contains_key(&receiver) {
            return Action::Drop(DropReason::Ambiguous);
        }
        route.last_used = now;
        Action::Forward(route.to)
    }

    /// Installs `(index, from) -> to`; `false` if a live route with that key leads
    /// elsewhere.
    fn install(
        &mut self,
        index: u32,
        from: Source,
        to: Source,
        confirmed: bool,
        now: Instant,
    ) -> bool {
        if let Some(route) = self.routes.get_mut(&(index, from)) {
            if route.to != to {
                return false;
            }
            route.last_used = now;
            route.confirmed |= confirmed;
            return true;
        }
        if !confirmed {
            let pending = self.routes.values().filter(|r| !r.confirmed).count();
            if pending >= self.limits.max_pending {
                self.evict(|route| !route.confirmed);
            }
        }
        if self.routes.len() >= self.limits.max_routes {
            self.evict(|_| true);
        }
        self.routes.insert(
            (index, from),
            Route {
                to,
                last_used: now,
                confirmed,
            },
        );
        true
    }

    /// Evicts the least recently used route among those `eligible` selects.
    fn evict(&mut self, eligible: impl Fn(&Route) -> bool) {
        let oldest = self
            .routes
            .iter()
            .filter(|(_, route)| eligible(route))
            .min_by_key(|(_, route)| route.last_used)
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.routes.remove(&key);
            self.counters.route_evictions += 1;
        }
    }

    /// Expires routes, own indices and learned sources, at most once a second.
    fn prune(&mut self, now: Instant) {
        if self
            .last_prune
            .is_some_and(|at| now.saturating_duration_since(at) < Duration::from_secs(1))
        {
            return;
        }
        self.last_prune = Some(now);
        let (session, learned) = (self.limits.session_ttl, self.limits.learned_source_ttl);
        self.routes
            .retain(|_, route| now.saturating_duration_since(route.last_used) < session);
        self.own_indices
            .retain(|_, at| now.saturating_duration_since(*at) < session);
        for target in &mut self.targets {
            if target
                .learned
                .is_some_and(|(_, at)| now.saturating_duration_since(at) >= learned)
            {
                target.learned = None;
            }
        }
    }

    fn control(&mut self, datagram: &[u8], from: Source, now: Instant, unix_now: u64) -> Action {
        if !self.controls.admit(
            from,
            self.limits.controls_per_sec,
            self.limits.max_sources,
            now,
        ) {
            return Action::Drop(DropReason::RateLimited);
        }
        let Ok((msg_type, payload)) = wire::decode_control(datagram) else {
            return Action::Drop(DropReason::Invalid);
        };
        let result = match msg_type {
            ControlType::RegisterSource => self.register(payload, from, now, unix_now),
            ControlType::ReflexiveRequest => self.reflexive(payload, from, unix_now),
            // The relay only ever sends responses.
            ControlType::ReflexiveResponse => Err(DropReason::Invalid),
        };
        result.unwrap_or_else(Action::Drop)
    }

    /// The single pinned target with WireGuard key `key`.
    fn pinned(&self, key: &[u8; 32]) -> Result<(usize, MachinePin), DropReason> {
        let mut found = self
            .targets
            .iter()
            .enumerate()
            .filter(|(_, t)| &t.config.wg_public_key == key && t.config.pin.is_some());
        match (found.next(), found.next()) {
            (Some((i, target)), None) => target
                .config
                .pin
                .clone()
                .map(|pin| (i, pin))
                .ok_or(DropReason::UnknownTarget),
            (Some(_), Some(_)) => Err(DropReason::Ambiguous),
            (None, _) => Err(DropReason::UnknownTarget),
        }
    }

    fn register(
        &mut self,
        payload: &[u8],
        from: Source,
        now: Instant,
        unix_now: u64,
    ) -> Result<Action, DropReason> {
        let request = open_register_source(payload, unix_now).map_err(|e| reason(&e))?;
        let (i, pin) = self.pinned(&request.payload.nsn_pubkey)?;
        request
            .admit(&pin.machine_id, &pin.machine_key, &self.replay, unix_now)
            .map_err(|e| reason(&e))?;
        if let Some(target) = self.targets.get_mut(i) {
            target.learned = Some((from, now));
        }
        self.counters.registrations += 1;
        Ok(Action::Handled)
    }

    fn reflexive(&self, payload: &[u8], from: Source, unix_now: u64) -> Result<Action, DropReason> {
        let Source::Udp(observed) = from else {
            return Err(DropReason::Invalid);
        };
        let request = open_reflexive_request(payload, unix_now).map_err(|e| reason(&e))?;
        let (_, pin) = self.pinned(&request.payload.peer_key_pub)?;
        request
            .admit(&pin.machine_id, &pin.machine_key, &self.replay, unix_now)
            .map_err(|e| reason(&e))?;
        let frame = build_reflexive_response(
            &request.payload,
            observed,
            &self.gateway_id,
            self.relay_addr,
            unix_now.saturating_mul(1000),
        )
        .map_err(|_| DropReason::Invalid)?;
        Ok(Action::Reply(frame))
    }
}

/// The drop reason of a failed control message.
const fn reason(error: &Error) -> DropReason {
    match error {
        Error::InvalidSignature | Error::InvalidKey | Error::UnknownMachine => {
            DropReason::BadSignature
        }
        Error::Replay | Error::ClockSkew { .. } => DropReason::Replay,
        Error::InvalidVersion(_)
        | Error::CborDecode(_)
        | Error::CborEncode(_)
        | Error::ClockBeforeEpoch
        | Error::UnexpectedApi(_) => DropReason::Invalid,
    }
}

/// The machine id a relay expects for `machine_key`: its standard base64. Nodes sign
/// with the same id ([`super::messages::build_register_source`]).
pub fn machine_id(machine_key: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(machine_key)
}

#[cfg(test)]
mod tests {
    use nsplane_noise::noise::{Tunn, TunnResult};
    use nsplane_noise::x25519::{PublicKey, StaticSecret};

    use super::super::envelope::{MachineKey, unix_now_secs};
    use super::super::messages::{PendingNonces, build_reflexive_request, build_register_source};
    use super::*;

    fn udp(port: u16) -> Source {
        Source::Udp(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn secret(byte: u8) -> StaticSecret {
        StaticSecret::from([byte; 32])
    }

    fn public(byte: u8) -> [u8; 32] {
        PublicKey::from(&secret(byte)).to_bytes()
    }

    /// An initiation from key `from` to key `to` with sender index `index << 8`, and the
    /// response.
    fn handshake(from: u8, to: u8, index: u32) -> (Vec<u8>, Vec<u8>) {
        let mut initiator = Tunn::new(
            secret(from),
            PublicKey::from(public(to)),
            None,
            None,
            index,
            None,
        );
        let mut responder = Tunn::new(
            secret(to),
            PublicKey::from(public(from)),
            None,
            None,
            index + 1,
            None,
        );
        let mut buf = vec![0u8; 2048];
        let TunnResult::WriteToNetwork(init) =
            initiator.format_handshake_initiation(&mut buf, false)
        else {
            panic!("no initiation");
        };
        let init = init.to_vec();
        let mut out = vec![0u8; 2048];
        let TunnResult::WriteToNetwork(response) = responder.decapsulate(None, &init, &mut out)
        else {
            panic!("no response");
        };
        (init, response.to_vec())
    }

    fn data(receiver: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 32];
        packet[0] = 4;
        packet[4..8].copy_from_slice(&receiver.to_le_bytes());
        packet
    }

    const OWN: u8 = 1;
    const A: u8 = 2;
    const B: u8 = 3;

    fn router() -> Router {
        Router::new(public(OWN), "relay".into(), "127.0.0.1:9".parse().unwrap())
    }

    fn pinned(key: u8, machine: &MachineKey) -> TargetConfig {
        TargetConfig {
            wg_public_key: public(key),
            pin: Some(MachinePin {
                machine_id: machine_id(&machine.public()),
                machine_key: machine.public(),
            }),
            static_source: None,
        }
    }

    fn register(router: &mut Router, key: u8, machine: &MachineKey, from: Source) -> Action {
        let frame =
            build_register_source(&machine_id(&machine.public()), machine, public(key)).unwrap();
        router.route(&frame, from, Instant::now(), unix_now_secs().unwrap())
    }

    fn route(router: &mut Router, packet: &[u8], from: Source) -> Action {
        router.route(packet, from, Instant::now(), unix_now_secs().unwrap())
    }

    #[test]
    fn initiation_to_the_own_key_goes_to_the_own_engine() {
        let mut router = router();
        let (init, _) = handshake(A, OWN, 1 << 8);
        assert_eq!(route(&mut router, &init, udp(1)), Action::OwnEngine);
        assert_eq!(router.counters().own_engine, 1);
    }

    #[test]
    fn relayed_handshake_and_data_follow_the_routes() {
        let mut router = router();
        let machine = MachineKey::generate();
        router.set_targets(vec![pinned(B, &machine)]);
        assert_eq!(register(&mut router, B, &machine, udp(20)), Action::Handled);

        let (init, response) = handshake(A, B, 1 << 8);
        assert_eq!(route(&mut router, &init, udp(10)), Action::Forward(udp(20)));
        let initiator_index = wire::sender_index(&init).unwrap();
        let responder_index = wire::sender_index(&response).unwrap();
        assert_eq!(
            route(&mut router, &response, udp(20)),
            Action::Forward(udp(10))
        );
        assert_eq!(
            route(&mut router, &data(responder_index), udp(10)),
            Action::Forward(udp(20))
        );
        assert_eq!(
            route(&mut router, &data(initiator_index), udp(20)),
            Action::Forward(udp(10))
        );
        // No route for this index from this source: the own engine's.
        assert_eq!(
            route(&mut router, &data(responder_index), udp(11)),
            Action::OwnEngine
        );
        assert_eq!(router.counters().forwarded, 4);
        assert_eq!(router.routes(Instant::now()).len(), 2);
        assert!(router.routes(Instant::now()).iter().all(|r| r.confirmed));
    }

    #[test]
    fn response_without_route_goes_to_the_own_engine() {
        let mut router = router();
        let (_, response) = handshake(OWN, A, 1 << 8);
        assert_eq!(route(&mut router, &response, udp(10)), Action::OwnEngine);
    }

    #[test]
    fn a_target_with_the_own_key_is_ambiguous() {
        let mut router = router();
        router.set_targets(vec![TargetConfig {
            wg_public_key: public(OWN),
            pin: None,
            static_source: Some(udp(30)),
        }]);
        let (init, _) = handshake(A, OWN, 1 << 8);
        assert_eq!(
            route(&mut router, &init, udp(10)),
            Action::Drop(DropReason::Ambiguous)
        );
        assert_eq!(router.counters().dropped_ambiguous, 1);
    }

    #[test]
    fn two_targets_with_one_key_are_ambiguous() {
        let mut router = router();
        let target = TargetConfig {
            wg_public_key: public(B),
            pin: None,
            static_source: Some(udp(30)),
        };
        router.set_targets(vec![target.clone(), target]);
        let (init, _) = handshake(A, B, 1 << 8);
        assert_eq!(
            route(&mut router, &init, udp(10)),
            Action::Drop(DropReason::Ambiguous)
        );
    }

    #[test]
    fn a_route_changing_its_destination_is_ambiguous() {
        let mut router = router();
        router.set_targets(vec![TargetConfig {
            wg_public_key: public(B),
            pin: None,
            static_source: Some(udp(20)),
        }]);
        let (init, _) = handshake(A, B, 1 << 8);
        assert_eq!(route(&mut router, &init, udp(10)), Action::Forward(udp(20)));
        // The same sender index towards the same target from another initiator.
        assert_eq!(
            route(&mut router, &init, udp(11)),
            Action::Drop(DropReason::Ambiguous)
        );
        assert_eq!(route(&mut router, &init, udp(10)), Action::Forward(udp(20)));
    }

    #[test]
    fn a_route_on_an_own_engine_index_is_ambiguous() {
        let mut router = router();
        router.set_targets(vec![TargetConfig {
            wg_public_key: public(B),
            pin: None,
            static_source: Some(udp(20)),
        }]);
        let (init, _) = handshake(A, B, 1 << 8);
        assert_eq!(route(&mut router, &init, udp(10)), Action::Forward(udp(20)));
        // The own engine sends a handshake with the same sender index.
        let (own_init, _) = handshake(OWN, A, 1 << 8);
        router.note_own_send(&own_init, Instant::now());
        let index = wire::sender_index(&init).unwrap();
        assert_eq!(
            route(&mut router, &data(index), udp(20)),
            Action::Drop(DropReason::Ambiguous)
        );
    }

    #[test]
    fn unknown_targets_are_dropped() {
        let mut router = router();
        let (init, _) = handshake(A, B, 1 << 8);
        assert_eq!(
            route(&mut router, &init, udp(10)),
            Action::Drop(DropReason::UnknownTarget)
        );
        // Configured, but its source was never learned.
        router.set_targets(vec![pinned(B, &MachineKey::generate())]);
        assert_eq!(
            route(&mut router, &init, udp(10)),
            Action::Drop(DropReason::UnknownTarget)
        );
        assert_eq!(router.counters().dropped_unknown_target, 2);
    }

    #[test]
    fn static_targets_need_no_registration() {
        let mut router = router();
        router.set_targets(vec![TargetConfig {
            wg_public_key: public(B),
            pin: None,
            static_source: Some(udp(20)),
        }]);
        let (init, _) = handshake(A, B, 1 << 8);
        assert_eq!(route(&mut router, &init, udp(10)), Action::Forward(udp(20)));
    }

    #[test]
    fn registration_needs_the_pinned_machine_and_a_fresh_nonce() {
        let mut router = router();
        let machine = MachineKey::generate();
        let intruder = MachineKey::generate();
        router.set_targets(vec![pinned(B, &machine)]);

        // Signed by another machine under its own id, and under the pinned id.
        assert_eq!(
            register(&mut router, B, &intruder, udp(66)),
            Action::Drop(DropReason::BadSignature)
        );
        let forged =
            build_register_source(&machine_id(&machine.public()), &intruder, public(B)).unwrap();
        assert_eq!(
            route(&mut router, &forged, udp(66)),
            Action::Drop(DropReason::BadSignature)
        );
        // A key nobody pinned.
        assert_eq!(
            register(&mut router, A, &machine, udp(66)),
            Action::Drop(DropReason::UnknownTarget)
        );
        assert_eq!(router.targets(Instant::now())[0].source, None);

        let frame =
            build_register_source(&machine_id(&machine.public()), &machine, public(B)).unwrap();
        assert_eq!(route(&mut router, &frame, udp(20)), Action::Handled);
        assert_eq!(
            route(&mut router, &frame, udp(66)),
            Action::Drop(DropReason::Replay)
        );
        assert_eq!(router.targets(Instant::now())[0].source, Some(udp(20)));
        let counters = router.counters();
        assert_eq!(counters.registrations, 1);
        assert_eq!(counters.dropped_bad_signature, 2);
        assert_eq!(counters.dropped_replay, 1);
        assert_eq!(counters.control_rx, 5);
        assert_eq!(counters.control_tx, 0);
    }

    #[test]
    fn reflexive_requests_are_answered_with_their_nonce() {
        let mut router = router();
        let machine = MachineKey::generate();
        router.set_targets(vec![pinned(A, &machine)]);
        let mut pending = PendingNonces::new();
        let nonce = pending.issue(Instant::now());
        let request =
            build_reflexive_request(&machine_id(&machine.public()), &machine, public(A), nonce)
                .unwrap();
        let Action::Reply(frame) = route(&mut router, &request, udp(10)) else {
            panic!("no reply");
        };
        let (msg_type, payload) = wire::decode_control(&frame).unwrap();
        assert_eq!(msg_type, ControlType::ReflexiveResponse);
        let response = pending.accept(payload, Instant::now()).unwrap();
        assert_eq!(response.observed_addr, "127.0.0.1:10".parse().unwrap());
        assert_eq!(response.relay_socket_addr, "127.0.0.1:9".parse().unwrap());
        assert_eq!(router.counters().control_tx, 1);

        // An unpinned key gets nothing.
        let other = MachineKey::generate();
        let request =
            build_reflexive_request(&machine_id(&other.public()), &other, public(B), nonce)
                .unwrap();
        assert_eq!(
            route(&mut router, &request, udp(10)),
            Action::Drop(DropReason::UnknownTarget)
        );
    }

    #[test]
    fn responses_and_reserved_controls_are_never_answered() {
        let mut router = router();
        let response = wire::encode_control(ControlType::ReflexiveResponse, b"x");
        assert_eq!(
            route(&mut router, &response, udp(10)),
            Action::Drop(DropReason::Invalid)
        );
        assert_eq!(
            route(&mut router, &[0xF1, 0, 0, 0, 1], udp(10)),
            Action::Drop(DropReason::Invalid)
        );
        assert_eq!(
            route(&mut router, &[0xF0, 0, 0, 0, 1, 0xFF], udp(10)),
            Action::Drop(DropReason::Invalid)
        );
        assert_eq!(
            route(&mut router, b"hello", udp(10)),
            Action::Drop(DropReason::Invalid)
        );
        assert_eq!(router.counters().control_tx, 0);
        assert_eq!(router.counters().dropped_invalid, 4);
    }

    #[test]
    fn control_is_rate_limited_per_source() {
        let mut router = Router::with_limits(
            public(OWN),
            "relay".into(),
            "127.0.0.1:9".parse().unwrap(),
            Limits {
                controls_per_sec: 2,
                ..Limits::default()
            },
        );
        let junk = [0xF0, 0, 0, 0, 1, 0xFF];
        let now = Instant::now();
        for _ in 0..2 {
            assert_eq!(
                router.route(&junk, udp(10), now, 0),
                Action::Drop(DropReason::Invalid)
            );
        }
        assert_eq!(
            router.route(&junk, udp(10), now, 0),
            Action::Drop(DropReason::RateLimited)
        );
        assert_eq!(
            router.route(&junk, udp(11), now, 0),
            Action::Drop(DropReason::Invalid)
        );
        assert_eq!(
            router.route(&junk, udp(10), now + Duration::from_secs(1), 0),
            Action::Drop(DropReason::Invalid)
        );
    }

    #[test]
    fn relayed_handshakes_are_rate_limited_per_source() {
        let mut router = Router::with_limits(
            public(OWN),
            "relay".into(),
            "127.0.0.1:9".parse().unwrap(),
            Limits {
                handshakes_per_sec: 1,
                ..Limits::default()
            },
        );
        router.set_targets(vec![TargetConfig {
            wg_public_key: public(B),
            pin: None,
            static_source: Some(udp(20)),
        }]);
        let (init, _) = handshake(A, B, 1 << 8);
        let now = Instant::now();
        assert_eq!(
            router.route(&init, udp(10), now, 0),
            Action::Forward(udp(20))
        );
        assert_eq!(
            router.route(&init, udp(10), now, 0),
            Action::Drop(DropReason::RateLimited)
        );
    }

    #[test]
    fn routes_and_learned_sources_expire() {
        let limits = Limits {
            session_ttl: Duration::from_secs(10),
            learned_source_ttl: Duration::from_secs(5),
            ..Limits::default()
        };
        let mut router = Router::with_limits(
            public(OWN),
            "relay".into(),
            "127.0.0.1:9".parse().unwrap(),
            limits,
        );
        let machine = MachineKey::generate();
        router.set_targets(vec![pinned(B, &machine)]);
        let t0 = Instant::now();
        let frame =
            build_register_source(&machine_id(&machine.public()), &machine, public(B)).unwrap();
        let unix = unix_now_secs().unwrap();
        assert_eq!(router.route(&frame, udp(20), t0, unix), Action::Handled);
        let (init, _) = handshake(A, B, 1 << 8);
        assert_eq!(
            router.route(&init, udp(10), t0, 0),
            Action::Forward(udp(20))
        );
        let index = wire::sender_index(&init).unwrap();

        // Traffic from the target refreshes its learned source.
        let t4 = t0 + Duration::from_secs(4);
        assert_eq!(
            router.route(&data(index), udp(20), t4, 0),
            Action::Forward(udp(10))
        );
        let t8 = t0 + Duration::from_secs(8);
        assert_eq!(router.targets(t8)[0].source, Some(udp(20)));
        // Learned source gone 5 s after the last traffic; the route 10 s after.
        let t10 = t0 + Duration::from_secs(10);
        assert_eq!(router.targets(t10)[0].source, None);
        assert_eq!(
            router.route(&init, udp(10), t10, 0),
            Action::Drop(DropReason::UnknownTarget)
        );
        let t15 = t0 + Duration::from_secs(15);
        assert_eq!(
            router.route(&data(index), udp(20), t15, 0),
            Action::OwnEngine
        );
        assert_eq!(router.routes(t15), Vec::<RouteInfo>::new());
    }

    #[test]
    fn route_tables_are_bounded() {
        let limits = Limits {
            max_routes: 4,
            max_pending: 2,
            ..Limits::default()
        };
        let mut router = Router::with_limits(
            public(OWN),
            "relay".into(),
            "127.0.0.1:9".parse().unwrap(),
            limits,
        );
        router.set_targets(vec![TargetConfig {
            wg_public_key: public(B),
            pin: None,
            static_source: Some(udp(20)),
        }]);
        let now = Instant::now();
        for i in 0..3 {
            let (init, _) = handshake(A, B, (i + 1) << 8);
            assert_eq!(
                router.route(&init, udp(10), now + Duration::from_millis(u64::from(i)), 0),
                Action::Forward(udp(20))
            );
        }
        assert_eq!(router.routes(now).len(), 2);
        assert_eq!(router.counters().route_evictions, 1);
    }

    #[test]
    fn retargeting_keeps_learned_sources() {
        let mut router = router();
        let machine = MachineKey::generate();
        router.set_targets(vec![pinned(B, &machine)]);
        assert_eq!(register(&mut router, B, &machine, udp(20)), Action::Handled);
        router.set_targets(vec![
            pinned(A, &MachineKey::generate()),
            pinned(B, &machine),
        ]);
        let targets = router.targets(Instant::now());
        assert_eq!(targets[0].source, None);
        assert_eq!(targets[1].source, Some(udp(20)));
        // A new pin forgets the source.
        router.set_targets(vec![pinned(B, &MachineKey::generate())]);
        assert_eq!(router.targets(Instant::now())[0].source, None);
    }
}
