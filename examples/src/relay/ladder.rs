//! The path ladder: per peer, direct UDP first and the relay as the fallback.
//!
//! A peer is on the ladder once it has direct candidates and its configured endpoint is
//! an extension-capable relay ([`Ladder::engage`]). Then, with [`Pin::Auto`]:
//!
//! 1. Direct first: every message goes to the candidate (hole punching: both sides send
//!    handshakes and keepalives towards each other). An authenticated message from it
//!    confirms the direct path.
//! 2. No authenticated message within [`LadderTimers::direct_timeout`], or a confirmed
//!    direct path that stops answering (sending without receiving for three times that
//!    long), falls back to the relay; a handshake is forced through it so the relay
//!    learns the routes.
//! 3. On the relay, a probe every [`LadderTimers::probe_interval`] sends handshakes and
//!    keepalives to a candidate for `direct_timeout`; an authenticated message from a
//!    direct address ([`PathPolicy::on_authenticated`]) returns to the direct path.
//!
//! [`Pin::Direct`] and [`Pin::Relay`] force one path. [`Ladder`] is the clock-driven state
//! ([`Ladder::tick`] returns the [`Command`]s the driver runs on the engine);
//! [`LadderPolicy`] is the engine's [`PathPolicy`] over it. Peers off the ladder roam as
//! standard WireGuard. Every transition is logged.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::ValueEnum;
use nsplane::{Ecn, Path, PathPolicy, PeerId, TransportId};
use nsplane_core::{MessageKind, Roam};

use super::client::Activity;
use super::server::lock;
use crate::node::encode_key;

/// Which path a peer on the ladder uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, ValueEnum)]
pub enum Pin {
    /// Direct first, the relay as fallback.
    #[default]
    Auto,
    /// Always direct.
    Direct,
    /// Always the relay.
    Relay,
}

/// The ladder's timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LadderTimers {
    /// How long a direct path may take to authenticate before the relay is used, and how
    /// long a probe from the relay lasts. A confirmed direct path is dead after sending
    /// without receiving for three times this long.
    pub direct_timeout: Duration,
    /// How often the direct path is probed while on the relay.
    pub probe_interval: Duration,
}

impl Default for LadderTimers {
    /// 5 s direct timeout, a probe every 30 s.
    fn default() -> Self {
        Self {
            direct_timeout: Duration::from_secs(5),
            probe_interval: Duration::from_secs(30),
        }
    }
}

/// The path a peer on the ladder uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Active {
    /// Direct UDP to the peer.
    Direct,
    /// Through the relay.
    Relay,
}

impl Active {
    /// `direct` or `relay`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

/// An engine call the ladder needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Start a handshake with the peer now (its path is chosen by the policy).
    ForceHandshake(PeerId),
    /// Make `path` the peer's current path (the peer's WireGuard public key).
    SetPath([u8; 32], Path),
}

/// A peer on the ladder, as reported by [`Ladder::paths`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathInfo {
    /// The peer's WireGuard public key.
    pub key: [u8; 32],
    /// The path in use.
    pub active: Active,
    /// Whether the direct path authenticated (meaningful while `active` is direct).
    pub confirmed: bool,
    /// The direct address in use or being probed.
    pub direct: SocketAddr,
    /// The relay.
    pub relay: SocketAddr,
    /// The direct candidates.
    pub candidates: Vec<SocketAddr>,
    /// Transitions relay to direct.
    pub to_direct: u64,
    /// Transitions direct to relay.
    pub to_relay: u64,
}

#[derive(Debug)]
struct PeerPath {
    key: [u8; 32],
    relay: SocketAddr,
    candidates: Vec<SocketAddr>,
    next_candidate: usize,
    active: Active,
    direct: SocketAddr,
    confirmed: bool,
    since: Instant,
    probe_until: Option<Instant>,
    next_probe: Instant,
    to_direct: u64,
    to_relay: u64,
}

/// The ladder state of all peers. See the [module documentation](self).
#[derive(Debug)]
pub struct Ladder {
    transport: TransportId,
    pin: Pin,
    timers: LadderTimers,
    activity: Arc<Activity>,
    peers: Mutex<HashMap<PeerId, PeerPath>>,
}

impl Ladder {
    /// A ladder for paths on `transport`, whose datagrams `activity` records.
    pub fn new(
        transport: TransportId,
        pin: Pin,
        timers: LadderTimers,
        activity: Arc<Activity>,
    ) -> Self {
        Self {
            transport,
            pin,
            timers,
            activity,
            peers: Mutex::new(HashMap::new()),
        }
    }

    const fn path(&self, addr: SocketAddr) -> Path {
        Path {
            transport: self.transport,
            addr,
            ecn: Ecn::NotEct,
        }
    }

    /// Puts `peer` on the ladder with its relay and direct candidates, or updates them.
    /// `candidates` must not be empty.
    pub fn engage(
        &self,
        peer: PeerId,
        key: [u8; 32],
        relay: SocketAddr,
        candidates: Vec<SocketAddr>,
        now: Instant,
    ) -> Vec<Command> {
        let Some(&first) = candidates.first() else {
            return self.disengage(peer);
        };
        let mut peers = lock(&self.peers);
        if let Some(state) = peers.get_mut(&peer) {
            state.relay = relay;
            if !candidates.contains(&state.direct) && !state.confirmed {
                state.direct = first;
            }
            state.candidates = candidates;
            return Vec::new();
        }
        let active = if self.pin == Pin::Relay {
            Active::Relay
        } else {
            Active::Direct
        };
        tracing::info!(peer = %encode_key(&key), path = active.as_str(), direct = %first, %relay, "peer on the path ladder");
        peers.insert(
            peer,
            PeerPath {
                key,
                relay,
                candidates,
                next_candidate: 1,
                active,
                direct: first,
                confirmed: false,
                since: now,
                probe_until: None,
                next_probe: now + self.timers.probe_interval,
                to_direct: 0,
                to_relay: 0,
            },
        );
        // The engine starts from the relay either way: off the ladder the peer may have
        // roamed to a direct address already, and the engine only asks the policy about
        // messages from a path other than the current one, so the direct path would never
        // be confirmed.
        let mut commands = vec![Command::SetPath(key, self.path(relay))];
        if active == Active::Direct {
            commands.push(Command::ForceHandshake(peer));
        }
        commands
    }

    /// Takes `peer` off the ladder; it goes back to its relay endpoint.
    pub fn disengage(&self, peer: PeerId) -> Vec<Command> {
        lock(&self.peers)
            .remove(&peer)
            .map_or_else(Vec::new, |state| {
                tracing::info!(peer = %encode_key(&state.key), "peer off the path ladder");
                vec![Command::SetPath(state.key, self.path(state.relay))]
            })
    }

    /// Whether `peer` is on the ladder.
    pub fn is_engaged(&self, peer: PeerId) -> bool {
        lock(&self.peers).contains_key(&peer)
    }

    /// Runs the timers: direct timeouts, dead direct paths, probes from the relay.
    pub fn tick(&self, now: Instant) -> Vec<Command> {
        if self.pin != Pin::Auto {
            return Vec::new();
        }
        let mut commands = Vec::new();
        let mut peers = lock(&self.peers);
        for (&peer, state) in peers.iter_mut() {
            match state.active {
                Active::Direct if !state.confirmed => {
                    if now.saturating_duration_since(state.since) >= self.timers.direct_timeout {
                        self.fall_back(
                            peer,
                            state,
                            now,
                            "direct path did not authenticate",
                            &mut commands,
                        );
                    }
                }
                Active::Direct => {
                    if self.is_dead(state.direct, now) {
                        self.fall_back(
                            peer,
                            state,
                            now,
                            "direct path stopped answering",
                            &mut commands,
                        );
                    }
                }
                Active::Relay => {
                    if state.probe_until.is_some_and(|until| now >= until) {
                        state.probe_until = None;
                    }
                    if now >= state.next_probe {
                        let next = state.next_candidate % state.candidates.len().max(1);
                        state.direct = state.candidates.get(next).copied().unwrap_or(state.direct);
                        state.next_candidate = state.next_candidate.wrapping_add(1);
                        state.probe_until = Some(now + self.timers.direct_timeout);
                        state.next_probe = now + self.timers.probe_interval;
                        tracing::debug!(peer = %encode_key(&state.key), direct = %state.direct, "probing the direct path");
                        commands.push(Command::ForceHandshake(peer));
                    }
                }
            }
        }
        commands
    }

    /// Sending to `addr` without an answer for three direct timeouts.
    fn is_dead(&self, addr: SocketAddr, now: Instant) -> bool {
        self.activity
            .get(addr)
            .unanswered_since
            .is_some_and(|since| {
                now.saturating_duration_since(since) >= self.timers.direct_timeout * 3
            })
    }

    fn fall_back(
        &self,
        peer: PeerId,
        state: &mut PeerPath,
        now: Instant,
        why: &str,
        commands: &mut Vec<Command>,
    ) {
        state.active = Active::Relay;
        state.confirmed = false;
        state.to_relay += 1;
        state.probe_until = None;
        state.next_probe = now + self.timers.probe_interval;
        tracing::info!(peer = %encode_key(&state.key), relay = %state.relay, reason = why, "path transition direct -> relay");
        commands.push(Command::SetPath(state.key, self.path(state.relay)));
        commands.push(Command::ForceHandshake(peer));
    }

    /// The path for the next message of `kind` to `peer`; `None` off the ladder.
    pub fn select_at(&self, peer: PeerId, kind: MessageKind, now: Instant) -> Option<Path> {
        let peers = lock(&self.peers);
        let state = peers.get(&peer)?;
        let addr = match state.active {
            Active::Direct => state.direct,
            Active::Relay => {
                let probing = state.probe_until.is_some_and(|until| now < until)
                    && matches!(kind, MessageKind::HandshakeInit | MessageKind::Keepalive);
                if probing { state.direct } else { state.relay }
            }
        };
        Some(self.path(addr))
    }

    /// An authenticated message of `kind` from `peer` arrived on `from`: whether to adopt
    /// it.
    pub fn authenticated_at(
        &self,
        peer: PeerId,
        from: &Path,
        kind: MessageKind,
        now: Instant,
    ) -> Roam {
        if kind == MessageKind::CookieReply {
            return Roam::Keep;
        }
        let mut peers = lock(&self.peers);
        let Some(state) = peers.get_mut(&peer) else {
            return Roam::Adopt;
        };
        if from.addr == state.relay {
            return match (self.pin, state.active) {
                (Pin::Relay, _) | (Pin::Auto, Active::Relay) => Roam::Adopt,
                (Pin::Direct, _) => Roam::Keep,
                (Pin::Auto, Active::Direct) => {
                    let fresh = self.activity.get(state.direct).rx.is_some_and(|rx| {
                        now.saturating_duration_since(rx) < self.timers.direct_timeout
                    });
                    if state.confirmed && !fresh {
                        state.active = Active::Relay;
                        state.confirmed = false;
                        state.to_relay += 1;
                        state.next_probe = now + self.timers.probe_interval;
                        tracing::info!(peer = %encode_key(&state.key), relay = %state.relay, reason = "peer answers through the relay", "path transition direct -> relay");
                        Roam::Adopt
                    } else {
                        Roam::Keep
                    }
                }
            };
        }
        if self.pin == Pin::Relay {
            return Roam::Keep;
        }
        if state.active == Active::Relay {
            state.to_direct += 1;
            tracing::info!(peer = %encode_key(&state.key), direct = %from.addr, "path transition relay -> direct");
        } else if !state.confirmed || state.direct != from.addr {
            tracing::info!(peer = %encode_key(&state.key), direct = %from.addr, "direct path confirmed");
        }
        state.active = Active::Direct;
        state.direct = from.addr;
        state.confirmed = true;
        state.probe_until = None;
        Roam::Adopt
    }

    /// Every peer on the ladder.
    pub fn paths(&self) -> Vec<PathInfo> {
        let mut paths: Vec<PathInfo> = lock(&self.peers)
            .values()
            .map(|state| PathInfo {
                key: state.key,
                active: state.active,
                confirmed: state.confirmed,
                direct: state.direct,
                relay: state.relay,
                candidates: state.candidates.clone(),
                to_direct: state.to_direct,
                to_relay: state.to_relay,
            })
            .collect();
        paths.sort_by_key(|path| path.key);
        paths
    }
}

/// The engine's [`PathPolicy`] over a shared [`Ladder`].
#[derive(Debug, Clone)]
pub struct LadderPolicy(pub Arc<Ladder>);

impl PathPolicy for LadderPolicy {
    fn select(&self, peer: PeerId, kind: MessageKind) -> Option<Path> {
        self.0.select_at(peer, kind, Instant::now())
    }

    fn on_authenticated(&self, peer: PeerId, from: &Path, kind: MessageKind) -> Roam {
        self.0.authenticated_at(peer, from, kind, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: PeerId = PeerId::new(1);
    const KEY: [u8; 32] = [5; 32];
    const T: TransportId = TransportId::new(0);

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    const RELAY: u16 = 1;
    const DIRECT: u16 = 2;

    fn path(port: u16) -> Path {
        Path {
            transport: T,
            addr: addr(port),
            ecn: Ecn::NotEct,
        }
    }

    fn timers() -> LadderTimers {
        LadderTimers {
            direct_timeout: Duration::from_secs(5),
            probe_interval: Duration::from_secs(30),
        }
    }

    fn ladder(pin: Pin) -> (Ladder, Arc<Activity>) {
        let activity = Arc::new(Activity::default());
        (
            Ladder::new(T, pin, timers(), Arc::clone(&activity)),
            activity,
        )
    }

    fn select(ladder: &Ladder, kind: MessageKind, now: Instant) -> u16 {
        ladder.select_at(PEER, kind, now).unwrap().addr.port()
    }

    #[test]
    fn off_the_ladder_is_standard_roaming() {
        let (ladder, _) = ladder(Pin::Auto);
        let now = Instant::now();
        assert_eq!(ladder.select_at(PEER, MessageKind::Data, now), None);
        assert_eq!(
            ladder.authenticated_at(PEER, &path(9), MessageKind::Data, now),
            Roam::Adopt
        );
        assert_eq!(
            ladder.authenticated_at(PEER, &path(9), MessageKind::CookieReply, now),
            Roam::Keep
        );
    }

    #[test]
    fn direct_first_then_confirmed() {
        let (ladder, _) = ladder(Pin::Auto);
        let t0 = Instant::now();
        let commands = ladder.engage(PEER, KEY, addr(RELAY), vec![addr(DIRECT)], t0);
        // The engine path is reset to the relay so the first direct message reaches the
        // policy even if the peer roamed to the direct address before it was engaged.
        assert_eq!(
            commands,
            vec![
                Command::SetPath(KEY, path(RELAY)),
                Command::ForceHandshake(PEER)
            ]
        );
        assert_eq!(select(&ladder, MessageKind::HandshakeInit, t0), DIRECT);
        assert_eq!(select(&ladder, MessageKind::Data, t0), DIRECT);
        assert_eq!(
            ladder.authenticated_at(PEER, &path(DIRECT), MessageKind::HandshakeResponse, t0),
            Roam::Adopt
        );
        let info = &ladder.paths()[0];
        assert_eq!((info.active, info.confirmed), (Active::Direct, true));
        assert_eq!((info.to_direct, info.to_relay), (0, 0));
        // Confirmed: no timeout fallback.
        assert_eq!(
            ladder.tick(t0 + Duration::from_secs(60)),
            Vec::<Command>::new()
        );
    }

    #[test]
    fn unanswered_direct_falls_back_to_the_relay() {
        let (ladder, _) = ladder(Pin::Auto);
        let t0 = Instant::now();
        ladder.engage(PEER, KEY, addr(RELAY), vec![addr(DIRECT)], t0);
        assert_eq!(
            ladder.tick(t0 + Duration::from_secs(4)),
            Vec::<Command>::new()
        );
        let commands = ladder.tick(t0 + Duration::from_secs(5));
        assert_eq!(
            commands,
            vec![
                Command::SetPath(KEY, path(RELAY)),
                Command::ForceHandshake(PEER)
            ]
        );
        let t5 = t0 + Duration::from_secs(5);
        assert_eq!(select(&ladder, MessageKind::HandshakeInit, t5), RELAY);
        assert_eq!(select(&ladder, MessageKind::Data, t5), RELAY);
        assert_eq!(ladder.paths()[0].to_relay, 1);
    }

    #[test]
    fn relay_probes_direct_and_returns_on_authentication() {
        let (ladder, _) = ladder(Pin::Auto);
        let t0 = Instant::now();
        ladder.engage(PEER, KEY, addr(RELAY), vec![addr(DIRECT)], t0);
        ladder.tick(t0 + Duration::from_secs(5));
        // Authenticated traffic through the relay is adopted.
        let t6 = t0 + Duration::from_secs(6);
        assert_eq!(
            ladder.authenticated_at(PEER, &path(RELAY), MessageKind::Data, t6),
            Roam::Adopt
        );
        // The probe: handshakes and keepalives go direct, data stays on the relay.
        let t35 = t0 + Duration::from_secs(35);
        assert_eq!(ladder.tick(t35), vec![Command::ForceHandshake(PEER)]);
        assert_eq!(select(&ladder, MessageKind::HandshakeInit, t35), DIRECT);
        assert_eq!(select(&ladder, MessageKind::Keepalive, t35), DIRECT);
        assert_eq!(select(&ladder, MessageKind::Data, t35), RELAY);
        // The probe window closes.
        let t40 = t0 + Duration::from_secs(40);
        assert_eq!(ladder.tick(t40), Vec::<Command>::new());
        assert_eq!(select(&ladder, MessageKind::HandshakeInit, t40), RELAY);
        // An authenticated message from the direct address returns to it.
        assert_eq!(
            ladder.authenticated_at(PEER, &path(DIRECT), MessageKind::HandshakeInit, t40),
            Roam::Adopt
        );
        assert_eq!(select(&ladder, MessageKind::Data, t40), DIRECT);
        let info = &ladder.paths()[0];
        assert_eq!((info.to_direct, info.to_relay), (1, 1));
    }

    #[test]
    fn a_silent_direct_path_falls_back() {
        let (ladder, activity) = ladder(Pin::Auto);
        let t0 = Instant::now();
        ladder.engage(PEER, KEY, addr(RELAY), vec![addr(DIRECT)], t0);
        activity.tx(addr(DIRECT), t0);
        activity.rx(addr(DIRECT), t0);
        ladder.authenticated_at(PEER, &path(DIRECT), MessageKind::HandshakeResponse, t0);
        // Idle both ways: alive.
        assert_eq!(
            ladder.tick(t0 + Duration::from_secs(60)),
            Vec::<Command>::new()
        );
        // Sending without answers for 3 × 5 s: dead.
        activity.tx(addr(DIRECT), t0 + Duration::from_secs(61));
        assert_eq!(
            ladder.tick(t0 + Duration::from_secs(75)),
            Vec::<Command>::new()
        );
        let commands = ladder.tick(t0 + Duration::from_secs(76));
        assert_eq!(commands.len(), 2);
        assert_eq!(ladder.paths()[0].active, Active::Relay);
    }

    #[test]
    fn traffic_through_the_relay_moves_a_stale_direct_path() {
        let (ladder, activity) = ladder(Pin::Auto);
        let t0 = Instant::now();
        ladder.engage(PEER, KEY, addr(RELAY), vec![addr(DIRECT)], t0);
        activity.rx(addr(DIRECT), t0);
        ladder.authenticated_at(PEER, &path(DIRECT), MessageKind::Data, t0);
        // Fresh direct: the relay copy is not adopted.
        assert_eq!(
            ladder.authenticated_at(
                PEER,
                &path(RELAY),
                MessageKind::Data,
                t0 + Duration::from_secs(1)
            ),
            Roam::Keep
        );
        assert_eq!(
            ladder.authenticated_at(
                PEER,
                &path(RELAY),
                MessageKind::HandshakeInit,
                t0 + Duration::from_secs(6)
            ),
            Roam::Adopt
        );
        assert_eq!(ladder.paths()[0].active, Active::Relay);
    }

    #[test]
    fn pins_force_one_path() {
        let (relay, _) = ladder(Pin::Relay);
        let t0 = Instant::now();
        assert_eq!(
            relay.engage(PEER, KEY, addr(RELAY), vec![addr(DIRECT)], t0),
            vec![Command::SetPath(KEY, path(RELAY))]
        );
        assert_eq!(select(&relay, MessageKind::HandshakeInit, t0), RELAY);
        assert_eq!(
            relay.authenticated_at(PEER, &path(DIRECT), MessageKind::Data, t0),
            Roam::Keep
        );
        assert_eq!(
            relay.tick(t0 + Duration::from_secs(100)),
            Vec::<Command>::new()
        );

        let (direct, _) = ladder(Pin::Direct);
        direct.engage(PEER, KEY, addr(RELAY), vec![addr(DIRECT)], t0);
        assert_eq!(
            direct.tick(t0 + Duration::from_secs(100)),
            Vec::<Command>::new()
        );
        assert_eq!(select(&direct, MessageKind::Data, t0), DIRECT);
        assert_eq!(
            direct.authenticated_at(PEER, &path(RELAY), MessageKind::Data, t0),
            Roam::Keep
        );
    }

    #[test]
    fn disengage_returns_to_the_relay_endpoint() {
        let (ladder, _) = ladder(Pin::Auto);
        let t0 = Instant::now();
        ladder.engage(PEER, KEY, addr(RELAY), vec![addr(DIRECT)], t0);
        assert!(ladder.is_engaged(PEER));
        assert_eq!(
            ladder.disengage(PEER),
            vec![Command::SetPath(KEY, path(RELAY))]
        );
        assert!(!ladder.is_engaged(PEER));
        assert_eq!(ladder.select_at(PEER, MessageKind::Data, t0), None);
    }
}
