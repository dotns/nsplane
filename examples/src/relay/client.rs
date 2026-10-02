//! The node side of the shared port: capability discovery, registration, reflexive
//! address, and the extension-aware transport.
//!
//! [`ExtTransport`] wraps the node's transport (a [`UdpTransport`]). WireGuard passes
//! through unchanged; control frames never reach the engine: a reflexive response from a
//! configured relay endpoint is taken by the [`Prober`] if it echoes an outstanding nonce,
//! everything else is dropped. Control messages are sent from the client's own task, never
//! from the engine's send or receive path.
//!
//! Capability discovery, never assumption: an endpoint starts as `unknown` and is probed
//! with reflexive requests, with exponential backoff (1, 2, 4, 8, 16 s by default), and
//! `stopped` after the last attempt goes unanswered. Only an authenticated,
//! nonce-bound reflexive response makes it `capable` (ns has no registration ack, so a
//! reflexive request is the discovery probe). A capable relay gets a `register_source`
//! every [`RELAY_REGISTER_INTERVAL`] and a reflexive request every
//! [`REFLEXIVE_GATHER_INTERVAL`], from the same socket as WireGuard. Until then the node
//! sends it nothing but WireGuard.
//!
//! [`RelayClient`] ties it together for an engine: [`RelayClient::new`] builds the
//! transport and the [`LadderPolicy`], [`RelayClient::start`] runs the driver that feeds
//! the ladder (candidates, relay capability) and executes its commands.
//!
//! [`UdpTransport`]: nsplane::UdpTransport

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use nsplane::x25519::PublicKey;
use nsplane::{Ecn, EngineHandle, PacketBuf, Path, PeerId, Transport, TransportId};
use serde_json::{Map, Value, json};
use tokio::task::JoinHandle;

use super::envelope::{MachineKey, unix_now_secs};
use super::ladder::{Command, Ladder, LadderPolicy, LadderTimers, Pin};
use super::messages::{
    PendingNonces, REFLEXIVE_GATHER_INTERVAL, RELAY_REGISTER_INTERVAL, build_reflexive_request,
    build_register_source,
};
use super::router::machine_id;
use super::server::lock;
use super::wire::{self, ControlType, Frame};
use crate::node::{decode_key, encode_key};

/// How often the control task and the driver wake up.
const TICK: Duration = Duration::from_millis(100);
/// How often the driver re-reads the candidates file.
const CANDIDATES_POLL: Duration = Duration::from_secs(1);
/// Most addresses [`Activity`] tracks.
const MAX_ACTIVITY: usize = 4096;

/// The probing timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeTimers {
    /// Wait after the first unanswered probe; doubled after each further one.
    pub backoff: Duration,
    /// Probes before an endpoint that never answered is stopped.
    pub attempts: u32,
    /// Registration interval with a capable relay.
    pub register_interval: Duration,
    /// Reflexive request interval with a capable relay.
    pub reflexive_interval: Duration,
    /// Most control messages per endpoint and second.
    pub max_per_sec: u32,
}

impl Default for ProbeTimers {
    /// 1 s backoff, 5 attempts, ns's register and reflexive intervals, 4 per second.
    fn default() -> Self {
        Self {
            backoff: Duration::from_secs(1),
            attempts: 5,
            register_interval: RELAY_REGISTER_INTERVAL,
            reflexive_interval: REFLEXIVE_GATHER_INTERVAL,
            max_per_sec: 4,
        }
    }
}

/// What an endpoint is known to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointState {
    /// Not probed yet.
    Unknown,
    /// Probed, no answer yet.
    Probing,
    /// Answered a probe with an authenticated, nonce-bound reply.
    Capable,
    /// Never answered; no more probes until reconfigured.
    Stopped,
}

impl EndpointState {
    /// `unknown`, `probing`, `capable` or `stopped`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Probing => "probing",
            Self::Capable => "capable",
            Self::Stopped => "stopped",
        }
    }
}

/// A control message the [`Prober`] wants sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// A reflexive request with this nonce.
    Reflexive([u8; 16]),
    /// A source registration.
    Register,
}

/// An endpoint, as reported by [`Prober::endpoints`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointInfo {
    /// The endpoint.
    pub addr: SocketAddr,
    /// Its state.
    pub state: EndpointState,
    /// Discovery probes sent while not capable.
    pub attempts: u32,
    /// Control messages sent.
    pub control_sent: u64,
    /// Accepted replies.
    pub control_answered: u64,
    /// Control messages held back by the per-endpoint rate limit.
    pub rate_limited: u64,
    /// This node's address as the endpoint last saw it.
    pub reflexive: Option<SocketAddr>,
}

#[derive(Debug)]
struct Endpoint {
    info: EndpointInfo,
    next_probe: Instant,
    next_register: Instant,
    nonces: PendingNonces,
    window: (Instant, u32),
}

/// Capability discovery and the control cadence, per endpoint (sans-I/O).
#[derive(Debug)]
pub struct Prober {
    timers: ProbeTimers,
    endpoints: Vec<Endpoint>,
}

impl Prober {
    /// Probes `addrs`, starting at `now`.
    pub fn new(addrs: &[SocketAddr], timers: ProbeTimers, now: Instant) -> Self {
        let mut prober = Self {
            timers,
            endpoints: Vec::new(),
        };
        prober.set_endpoints(addrs, now);
        prober
    }

    /// Replaces the endpoints: known ones keep their state, new ones start `unknown`
    /// (this is how a stopped endpoint is probed again: reconfigure it).
    pub fn set_endpoints(&mut self, addrs: &[SocketAddr], now: Instant) {
        let mut old = std::mem::take(&mut self.endpoints);
        for &addr in addrs {
            if let Some(pos) = old.iter().position(|e| e.info.addr == addr) {
                self.endpoints.push(old.swap_remove(pos));
            } else if !self.endpoints.iter().any(|e| e.info.addr == addr) {
                self.endpoints.push(Endpoint {
                    info: EndpointInfo {
                        addr,
                        state: EndpointState::Unknown,
                        attempts: 0,
                        control_sent: 0,
                        control_answered: 0,
                        rate_limited: 0,
                        reflexive: None,
                    },
                    next_probe: now,
                    next_register: now,
                    nonces: PendingNonces::new(),
                    window: (now, 0),
                });
            }
        }
    }

    /// The control messages due at `now`.
    pub fn poll(&mut self, now: Instant) -> Vec<(SocketAddr, Probe)> {
        let timers = self.timers;
        let mut due = Vec::new();
        for endpoint in &mut self.endpoints {
            let info = &mut endpoint.info;
            match info.state {
                EndpointState::Stopped => {}
                EndpointState::Unknown | EndpointState::Probing => {
                    if now < endpoint.next_probe {
                        continue;
                    }
                    if info.attempts >= timers.attempts {
                        info.state = EndpointState::Stopped;
                        tracing::info!(endpoint = %info.addr, attempts = info.attempts, "endpoint never answered, probing stopped");
                        continue;
                    }
                    if !admit(
                        &mut endpoint.window,
                        &mut info.rate_limited,
                        timers.max_per_sec,
                        now,
                    ) {
                        continue;
                    }
                    let wait = timers.backoff.saturating_mul(1 << info.attempts.min(16));
                    info.attempts += 1;
                    info.state = EndpointState::Probing;
                    info.control_sent += 1;
                    endpoint.next_probe = now + wait;
                    due.push((info.addr, Probe::Reflexive(endpoint.nonces.issue(now))));
                }
                EndpointState::Capable => {
                    if now >= endpoint.next_register
                        && admit(
                            &mut endpoint.window,
                            &mut info.rate_limited,
                            timers.max_per_sec,
                            now,
                        )
                    {
                        info.control_sent += 1;
                        endpoint.next_register = now + timers.register_interval;
                        due.push((info.addr, Probe::Register));
                    }
                    if now >= endpoint.next_probe
                        && admit(
                            &mut endpoint.window,
                            &mut info.rate_limited,
                            timers.max_per_sec,
                            now,
                        )
                    {
                        info.control_sent += 1;
                        endpoint.next_probe = now + timers.reflexive_interval;
                        due.push((info.addr, Probe::Reflexive(endpoint.nonces.issue(now))));
                    }
                }
            }
        }
        due
    }

    /// A control frame `datagram` arrived from `from`. Returns the reflexive address it
    /// carries if it is an accepted reply of a configured endpoint.
    pub fn on_control(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
        now: Instant,
    ) -> Option<SocketAddr> {
        let endpoint = self.endpoints.iter_mut().find(|e| e.info.addr == from)?;
        let Ok((ControlType::ReflexiveResponse, payload)) = wire::decode_control(datagram) else {
            return None;
        };
        let response = endpoint.nonces.accept(payload, now).ok()?;
        let info = &mut endpoint.info;
        info.control_answered += 1;
        info.reflexive = Some(response.observed_addr);
        if info.state != EndpointState::Capable {
            tracing::info!(endpoint = %from, reflexive = %response.observed_addr, "endpoint is extension-capable");
            info.state = EndpointState::Capable;
            endpoint.next_register = now;
            endpoint.next_probe = now + self.timers.reflexive_interval;
        }
        Some(response.observed_addr)
    }

    /// Whether `addr` is a capable endpoint.
    pub fn is_capable(&self, addr: SocketAddr) -> bool {
        self.endpoints
            .iter()
            .any(|e| e.info.addr == addr && e.info.state == EndpointState::Capable)
    }

    /// Every endpoint.
    pub fn endpoints(&self) -> Vec<EndpointInfo> {
        self.endpoints.iter().map(|e| e.info).collect()
    }
}

/// A per-second send budget.
fn admit(window: &mut (Instant, u32), limited: &mut u64, per_sec: u32, now: Instant) -> bool {
    if now.saturating_duration_since(window.0) >= Duration::from_secs(1) {
        *window = (now, 0);
    }
    if window.1 >= per_sec {
        *limited += 1;
        return false;
    }
    window.1 += 1;
    true
}

/// When WireGuard datagrams were last received from and sent to an address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Seen {
    /// Last received.
    pub rx: Option<Instant>,
    /// Last sent.
    pub tx: Option<Instant>,
    /// First sent since the last receive: how long sending has gone unanswered.
    pub unanswered_since: Option<Instant>,
}

/// Per-address WireGuard activity of a transport, which the ladder reads to find dead
/// direct paths.
#[derive(Debug, Default)]
pub struct Activity {
    seen: Mutex<HashMap<SocketAddr, Seen>>,
}

impl Activity {
    fn update(&self, addr: SocketAddr, f: impl FnOnce(&mut Seen)) {
        let mut seen = lock(&self.seen);
        if !seen.contains_key(&addr) && seen.len() >= MAX_ACTIVITY {
            seen.clear();
        }
        f(seen.entry(addr).or_default());
    }

    /// Records a datagram received from `addr`.
    pub fn rx(&self, addr: SocketAddr, now: Instant) {
        self.update(addr, |seen| {
            seen.rx = Some(now);
            seen.unanswered_since = None;
        });
    }

    /// Records a datagram sent to `addr`.
    pub fn tx(&self, addr: SocketAddr, now: Instant) {
        self.update(addr, |seen| {
            seen.tx = Some(now);
            seen.unanswered_since.get_or_insert(now);
        });
    }

    /// The activity of `addr`.
    pub fn get(&self, addr: SocketAddr) -> Seen {
        lock(&self.seen).get(&addr).copied().unwrap_or_default()
    }
}

/// What the node side shares between its transport, its tasks and the status.
#[derive(Debug)]
struct ClientState {
    machine_key: MachineKey,
    machine_id: String,
    wg_public: OnceLock<[u8; 32]>,
    relays: Vec<SocketAddr>,
    prober: Mutex<Prober>,
    activity: Arc<Activity>,
    reflexive: Mutex<Option<(SocketAddr, SocketAddr)>>,
    reflexive_out: Option<PathBuf>,
    peer_candidates: Option<PathBuf>,
    candidates: Mutex<HashMap<[u8; 32], Vec<SocketAddr>>>,
    dropped_invalid: AtomicU64,
    dropped_control: AtomicU64,
}

impl ClientState {
    fn on_control(&self, from: SocketAddr, datagram: &[u8]) {
        let reflexive = lock(&self.prober).on_control(from, datagram, Instant::now());
        match reflexive {
            Some(addr) => *lock(&self.reflexive) = Some((addr, from)),
            None => {
                self.dropped_control.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The node's extension-aware transport. See the [module documentation](self).
#[derive(Debug)]
pub struct ExtTransport<T> {
    shared: Arc<ExtShared<T>>,
}

#[derive(Debug)]
struct ExtShared<T> {
    inner: T,
    client: Arc<ClientState>,
}

impl<T: Transport> Transport for ExtTransport<T> {
    fn id(&self) -> TransportId {
        self.shared.inner.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        loop {
            let (len, path) = self.shared.inner.recv(buf).await?;
            let client = &self.shared.client;
            match wire::classify(buf.as_packet()) {
                Frame::WireGuard(_) => {
                    client.activity.rx(path.addr, Instant::now());
                    return Ok((len, path));
                }
                Frame::Control { .. } => client.on_control(path.addr, buf.as_packet()),
                Frame::Invalid => {
                    client.dropped_invalid.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        self.shared.client.activity.tx(to.addr, Instant::now());
        self.shared.inner.send(datagram, to).await
    }
}

/// The node-side options.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Relay endpoints to discover.
    pub relays: Vec<SocketAddr>,
    /// The machine key control messages are signed with (machine id: its public key in
    /// base64).
    pub machine_key: MachineKey,
    /// Path pinning of the ladder.
    pub pin: Pin,
    /// Probing timers.
    pub probe: ProbeTimers,
    /// Ladder timers.
    pub ladder: LadderTimers,
    /// JSON `{"<wg pubkey b64>": ["ip:port", ...]}` of direct candidates, re-read every
    /// second.
    pub peer_candidates: Option<PathBuf>,
    /// Where to write the learned reflexive address as JSON.
    pub reflexive_out: Option<PathBuf>,
}

/// The node side of the relay for one engine. Clones share the state.
#[derive(Debug, Clone)]
pub struct RelayClient {
    state: Arc<ClientState>,
    ladder: Arc<Ladder>,
}

impl RelayClient {
    /// Wraps `inner` and builds the ladder policy; spawns the control task (so it must run
    /// inside a tokio runtime). Control messages start once [`RelayClient::start`] (or
    /// [`RelayClient::set_public_key`]) gave the WireGuard public key they carry.
    pub fn new<T: Transport>(
        inner: T,
        config: ClientConfig,
    ) -> (Self, ExtTransport<T>, LadderPolicy) {
        let activity = Arc::new(Activity::default());
        let ladder = Arc::new(Ladder::new(
            inner.id(),
            config.pin,
            config.ladder,
            Arc::clone(&activity),
        ));
        let state = Arc::new(ClientState {
            machine_id: machine_id(&config.machine_key.public()),
            machine_key: config.machine_key,
            wg_public: OnceLock::new(),
            prober: Mutex::new(Prober::new(&config.relays, config.probe, Instant::now())),
            relays: config.relays,
            activity,
            reflexive: Mutex::new(None),
            reflexive_out: config.reflexive_out,
            peer_candidates: config.peer_candidates,
            candidates: Mutex::new(HashMap::new()),
            dropped_invalid: AtomicU64::new(0),
            dropped_control: AtomicU64::new(0),
        });
        let shared = Arc::new(ExtShared {
            inner,
            client: Arc::clone(&state),
        });
        tokio::spawn(control_task(Arc::downgrade(&shared)));
        let client = Self {
            state,
            ladder: Arc::clone(&ladder),
        };
        (client, ExtTransport { shared }, LadderPolicy(ladder))
    }

    /// Sets the WireGuard public key the control messages carry; later calls are ignored.
    pub fn set_public_key(&self, key: [u8; 32]) {
        let _ = self.state.wg_public.set(key);
    }

    /// The WireGuard public key, once set.
    pub fn public_key(&self) -> Option<[u8; 32]> {
        self.state.wg_public.get().copied()
    }

    /// Sets the public key and spawns the driver for the engine behind `handle`: it
    /// reads the candidates file, puts the `peers` (public key, configured endpoint) whose
    /// endpoint is a capable relay and that have candidates on the ladder, and runs the
    /// ladder's commands. It ends when the engine stops.
    pub fn start(
        &self,
        handle: EngineHandle,
        public_key: [u8; 32],
        peers: Vec<([u8; 32], Option<SocketAddr>)>,
    ) -> JoinHandle<()> {
        self.set_public_key(public_key);
        let client = self.clone();
        tokio::spawn(async move {
            if let Err(e) = client.drive(&handle, &peers).await {
                tracing::debug!(error = format!("{e:#}"), "relay client driver stopped");
            }
        })
    }

    async fn drive(
        &self,
        handle: &EngineHandle,
        peers: &[([u8; 32], Option<SocketAddr>)],
    ) -> anyhow::Result<()> {
        let mut ids: HashMap<[u8; 32], PeerId> = HashMap::new();
        let mut last_read: Option<Instant> = None;
        let mut ticks = tokio::time::interval(TICK);
        loop {
            ticks.tick().await;
            let now = Instant::now();
            if let Some(path) = &self.state.peer_candidates
                && last_read.is_none_or(|at| now.saturating_duration_since(at) >= CANDIDATES_POLL)
            {
                last_read = Some(now);
                match read_candidates(path).await {
                    Ok(candidates) => self.set_candidates(candidates),
                    Err(e) => tracing::debug!(error = format!("{e:#}"), "candidates not read"),
                }
            }
            let mut commands = Vec::new();
            for &(key, endpoint) in peers {
                let Some(relay) = endpoint.filter(|addr| self.state.relays.contains(addr)) else {
                    continue;
                };
                let id = match ids.get(&key) {
                    Some(&id) => id,
                    None => match handle.peer_id(PublicKey::from(key)).await? {
                        Some(id) => *ids.entry(key).or_insert(id),
                        None => continue,
                    },
                };
                let candidates = lock(&self.state.candidates)
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                let capable = lock(&self.state.prober).is_capable(relay);
                if capable && !candidates.is_empty() {
                    commands.extend(self.ladder.engage(id, key, relay, candidates, now));
                } else if self.ladder.is_engaged(id) {
                    commands.extend(self.ladder.disengage(id));
                }
            }
            commands.extend(self.ladder.tick(now));
            for command in commands {
                match command {
                    Command::ForceHandshake(peer) => handle.force_handshake(peer, None).await?,
                    Command::SetPath(key, path) => {
                        handle.set_path(PublicKey::from(key), path).await?;
                    }
                }
            }
        }
    }

    /// Replaces the direct candidates (WireGuard public key to addresses).
    pub fn set_candidates(&self, candidates: HashMap<[u8; 32], Vec<SocketAddr>>) {
        *lock(&self.state.candidates) = candidates;
    }

    /// Every relay endpoint and what it is known to be.
    pub fn endpoints(&self) -> Vec<EndpointInfo> {
        lock(&self.state.prober).endpoints()
    }

    /// The ladder.
    pub const fn ladder(&self) -> &Arc<Ladder> {
        &self.ladder
    }

    /// The latest reflexive address and the endpoint that reported it.
    pub fn reflexive(&self) -> Option<(SocketAddr, SocketAddr)> {
        *lock(&self.state.reflexive)
    }

    /// The status file's `extra.relay` object of a node:
    ///
    /// ```json
    /// {"reflexive": "ip:port", "reflexive_from": "ip:port",
    ///  "dropped_invalid": 0, "dropped_control": 0,
    ///  "endpoints": {"<ip:port>": {"state": "capable", "attempts": 1, "control_sent": 3,
    ///                              "control_answered": 2, "rate_limited": 0,
    ///                              "reflexive": "ip:port"}}}
    /// ```
    pub fn relay_json(&self) -> Value {
        let endpoints: Map<String, Value> = self
            .endpoints()
            .iter()
            .map(|e| {
                (
                    e.addr.to_string(),
                    json!({
                        "state": e.state.as_str(),
                        "attempts": e.attempts,
                        "control_sent": e.control_sent,
                        "control_answered": e.control_answered,
                        "rate_limited": e.rate_limited,
                        "reflexive": e.reflexive.map(|addr| addr.to_string()),
                    }),
                )
            })
            .collect();
        let reflexive = self.reflexive();
        json!({
            "reflexive": reflexive.map(|(addr, _)| addr.to_string()),
            "reflexive_from": reflexive.map(|(_, from)| from.to_string()),
            "dropped_invalid": self.state.dropped_invalid.load(Ordering::Relaxed),
            "dropped_control": self.state.dropped_control.load(Ordering::Relaxed),
            "endpoints": endpoints,
        })
    }

    /// The status file's `extra.paths` object:
    ///
    /// ```json
    /// {"<peer pubkey b64>": {"active": "direct", "confirmed": true, "direct": "ip:port",
    ///                        "relay": "ip:port", "candidates": ["ip:port"],
    ///                        "to_direct": 0, "to_relay": 0}}
    /// ```
    pub fn paths_json(&self) -> Value {
        let paths: Map<String, Value> = self
            .ladder
            .paths()
            .iter()
            .map(|p| {
                let candidates: Vec<String> =
                    p.candidates.iter().map(ToString::to_string).collect();
                (
                    encode_key(&p.key),
                    json!({
                        "active": p.active.as_str(),
                        "confirmed": p.confirmed,
                        "direct": p.direct.to_string(),
                        "relay": p.relay.to_string(),
                        "candidates": candidates,
                        "to_direct": p.to_direct,
                        "to_relay": p.to_relay,
                    }),
                )
            })
            .collect();
        Value::Object(paths)
    }
}

/// Parses the candidates file: `{"<wg pubkey b64>": ["ip:port", ...]}`.
pub fn parse_candidates(text: &str) -> anyhow::Result<HashMap<[u8; 32], Vec<SocketAddr>>> {
    let raw: HashMap<String, Vec<SocketAddr>> =
        serde_json::from_str(text).context("invalid candidates file")?;
    raw.into_iter()
        .map(|(key, addrs)| Ok((decode_key(&key)?, addrs)))
        .collect()
}

async fn read_candidates(
    path: &std::path::Path,
) -> anyhow::Result<HashMap<[u8; 32], Vec<SocketAddr>>> {
    let text = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("cannot read {}", path.display()))?;
    parse_candidates(&text)
}

/// Sends the prober's control messages and writes the reflexive file, until the
/// transport is dropped.
async fn control_task<T: Transport>(shared: Weak<ExtShared<T>>) {
    let mut written: Option<(SocketAddr, SocketAddr)> = None;
    let mut ticks = tokio::time::interval(TICK);
    loop {
        ticks.tick().await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let client = &shared.client;
        let Some(&wg_public) = client.wg_public.get() else {
            continue;
        };
        let due = lock(&client.prober).poll(Instant::now());
        for (addr, probe) in due {
            let frame = match probe {
                Probe::Reflexive(nonce) => build_reflexive_request(
                    &client.machine_id,
                    &client.machine_key,
                    wg_public,
                    nonce,
                ),
                Probe::Register => {
                    build_register_source(&client.machine_id, &client.machine_key, wg_public)
                }
            };
            let frame = match frame {
                Ok(frame) => frame,
                Err(e) => {
                    tracing::warn!(error = %e, "control message not built");
                    continue;
                }
            };
            let to = Path {
                transport: shared.inner.id(),
                addr,
                ecn: Ecn::NotEct,
            };
            if let Err(e) = shared.inner.send(&frame, &to).await {
                tracing::debug!(%addr, error = %e, "control message not sent");
            }
        }
        let reflexive = *lock(&client.reflexive);
        if reflexive != written
            && let (Some(path), Some((addr, from))) = (&client.reflexive_out, reflexive)
        {
            match write_reflexive(path, addr, from).await {
                Ok(()) => written = reflexive,
                Err(e) => tracing::warn!(error = format!("{e:#}"), "reflexive address not written"),
            }
        }
    }
}

/// Writes `{"reflexive": "ip:port", "relay": "ip:port", "unix_ms": N}` to `path`
/// (through `<path>.tmp` and a rename).
async fn write_reflexive(
    path: &std::path::Path,
    addr: SocketAddr,
    relay: SocketAddr,
) -> anyhow::Result<()> {
    let body = json!({
        "reflexive": addr.to_string(),
        "relay": relay.to_string(),
        "unix_ms": unix_now_secs().unwrap_or_default().saturating_mul(1000),
    });
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    tokio::fs::write(&tmp, serde_json::to_vec_pretty(&body)?)
        .await
        .with_context(|| format!("cannot write {}", path.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::super::messages::{GatewayReflexiveRequest, build_reflexive_response};
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn reply(nonce: [u8; 16]) -> Vec<u8> {
        let request = GatewayReflexiveRequest {
            peer_key_pub: [1; 32],
            nonce,
        };
        build_reflexive_response(&request, addr(4000), "relay", addr(1), 0).unwrap()
    }

    fn nonce_of(probe: Probe) -> [u8; 16] {
        match probe {
            Probe::Reflexive(nonce) => nonce,
            Probe::Register => panic!("not a reflexive probe"),
        }
    }

    #[test]
    fn a_silent_endpoint_backs_off_and_stops() {
        let t0 = Instant::now();
        let mut prober = Prober::new(&[addr(1)], ProbeTimers::default(), t0);
        assert_eq!(prober.endpoints()[0].state, EndpointState::Unknown);
        let mut sent_at = Vec::new();
        for ms in (0..40_000).step_by(100) {
            let now = t0 + Duration::from_millis(ms);
            for (to, probe) in prober.poll(now) {
                assert_eq!(to, addr(1));
                assert!(matches!(probe, Probe::Reflexive(_)));
                sent_at.push(ms / 1000);
            }
        }
        assert_eq!(sent_at, vec![0, 1, 3, 7, 15]);
        let info = prober.endpoints()[0];
        assert_eq!(info.state, EndpointState::Stopped);
        assert_eq!(
            (info.attempts, info.control_sent, info.control_answered),
            (5, 5, 0)
        );
        assert!(!prober.is_capable(addr(1)));
    }

    #[test]
    fn a_nonce_bound_reply_makes_the_endpoint_capable() {
        let t0 = Instant::now();
        let mut prober = Prober::new(&[addr(1)], ProbeTimers::default(), t0);
        let probes = prober.poll(t0);
        let nonce = nonce_of(probes[0].1);
        // Unsolicited, foreign or replayed replies are ignored.
        assert_eq!(prober.on_control(addr(2), &reply(nonce), t0), None);
        assert_eq!(prober.on_control(addr(1), &reply([9; 16]), t0), None);
        assert_eq!(
            prober.on_control(addr(1), &reply(nonce), t0),
            Some(addr(4000))
        );
        assert_eq!(prober.on_control(addr(1), &reply(nonce), t0), None);
        assert!(prober.is_capable(addr(1)));
        // Registration right away, then on the cadence.
        assert_eq!(prober.poll(t0), vec![(addr(1), Probe::Register)]);
        assert_eq!(
            prober.poll(t0 + Duration::from_secs(19)),
            Vec::<(SocketAddr, Probe)>::new()
        );
        let due = prober.poll(t0 + Duration::from_secs(20));
        assert!(matches!(due.as_slice(), [(_, Probe::Reflexive(_))]));
        let due = prober.poll(t0 + Duration::from_secs(30));
        assert_eq!(due, vec![(addr(1), Probe::Register)]);
        let info = prober.endpoints()[0];
        assert_eq!((info.control_sent, info.control_answered), (4, 1));
        assert_eq!(info.reflexive, Some(addr(4000)));
    }

    #[test]
    fn control_sends_are_rate_limited_per_endpoint() {
        let t0 = Instant::now();
        let timers = ProbeTimers {
            max_per_sec: 1,
            ..ProbeTimers::default()
        };
        let mut prober = Prober::new(&[addr(1)], timers, t0);
        let nonce = nonce_of(prober.poll(t0)[0].1);
        prober.on_control(addr(1), &reply(nonce), t0);
        // Register is due but the budget of this second is spent.
        assert_eq!(prober.poll(t0), Vec::<(SocketAddr, Probe)>::new());
        assert_eq!(prober.endpoints()[0].rate_limited, 1);
        assert_eq!(
            prober.poll(t0 + Duration::from_secs(1)),
            vec![(addr(1), Probe::Register)]
        );
    }

    #[test]
    fn reconfiguring_restarts_a_stopped_endpoint() {
        let t0 = Instant::now();
        let timers = ProbeTimers {
            attempts: 1,
            ..ProbeTimers::default()
        };
        let mut prober = Prober::new(&[addr(1)], timers, t0);
        assert_eq!(prober.poll(t0).len(), 1);
        assert_eq!(
            prober.poll(t0 + Duration::from_secs(1)),
            Vec::<(SocketAddr, Probe)>::new()
        );
        assert_eq!(prober.endpoints()[0].state, EndpointState::Stopped);
        prober.set_endpoints(&[addr(1), addr(2)], t0);
        assert_eq!(prober.endpoints()[0].state, EndpointState::Stopped);
        prober.set_endpoints(&[addr(2)], t0);
        prober.set_endpoints(&[addr(1), addr(2)], t0);
        assert_eq!(prober.endpoints()[0].state, EndpointState::Unknown);
    }

    #[test]
    fn candidates_file_parses() {
        let key = encode_key(&[3; 32]);
        let parsed =
            parse_candidates(&format!(r#"{{"{key}": ["127.0.0.1:5", "[::1]:6"]}}"#)).unwrap();
        assert_eq!(parsed[&[3; 32]], vec![addr(5), "[::1]:6".parse().unwrap()]);
        assert!(parse_candidates(r#"{"x": []}"#).is_err());
    }
}
