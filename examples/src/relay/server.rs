//! The relay side of the shared port: a [`Transport`] that runs the [`Router`] on every
//! received datagram, and the relay's configuration file.
//!
//! [`RelayServerTransport`] wraps the transport of the port (a [`UdpTransport`]). Its
//! receive loop hands the own engine only the datagrams the router assigns to it;
//! relayed datagrams are forwarded and control replies sent on the same transport from
//! inside the loop, and everything else is dropped and counted. What the own engine
//! sends goes out unchanged (its handshake sender indices are noted for the router).
//!
//! With a [`WsHub`] ([`RelayServerTransport::with_ws`]) the loop also routes the
//! datagrams of the hub's WebSocket connections, and datagrams for a connection (forwarded,
//! control replies, the own engine's sends to its peer address) leave on it.
//!
//! [`UdpTransport`]: nsplane::UdpTransport

use std::io;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow};
use nsplane::{Ecn, PacketBuf, Path, Transport, TransportId};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::task::JoinHandle;

use super::envelope::unix_now_secs;
use super::router::{Action, MachinePin, Router, Source, TargetConfig, machine_id};
use super::wss::fill;
use super::wss::server::{Inbound, WsHub};
use crate::node::{decode_key, encode_key};

/// How often [`watch_config`] polls the configuration file.
pub const CONFIG_POLL: Duration = Duration::from_secs(1);

/// Locks `mutex`, ignoring poisoning (the protected state stays consistent per call).
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A shared [`Router`].
pub type SharedRouter = Arc<Mutex<Router>>;

/// The relay's wrapping transport. See the [module documentation](self).
#[derive(Debug)]
pub struct RelayServerTransport<T> {
    inner: T,
    router: SharedRouter,
    ws: Option<Arc<WsHub>>,
}

/// What the receive loop got.
enum Received {
    Udp(io::Result<(usize, Path)>),
    Ws(Inbound),
}

impl<T: Transport> RelayServerTransport<T> {
    /// Routes the datagrams `inner` receives through `router`.
    pub const fn new(inner: T, router: SharedRouter) -> Self {
        Self {
            inner,
            router,
            ws: None,
        }
    }

    /// Also routes the datagrams of `hub`'s WebSocket connections (a hub of the same
    /// router).
    #[must_use]
    pub fn with_ws(mut self, hub: Arc<WsHub>) -> Self {
        self.ws = Some(hub);
        self
    }

    /// Sends a datagram the router produced to `to`; failures are logged, not returned, so
    /// one unreachable destination does not stop the receive loop.
    async fn deliver(&self, datagram: &[u8], to: Source, path: &Path, what: &str) {
        match (to, &self.ws) {
            (Source::Udp(addr), _) => {
                let to = Path { addr, ..*path };
                if let Err(e) = self.inner.send(datagram, &to).await {
                    tracing::debug!(to = %to.addr, error = %e, "relay {what} not sent");
                }
            }
            (Source::Ws(id), Some(hub)) => hub.send_to(id, datagram),
            (Source::Ws(id), None) => {
                tracing::debug!(id, "relay {what} to a connection without a hub");
            }
        }
    }

    /// The next datagram from the socket or a connection, with its path and source.
    async fn next(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path, Source)> {
        let Some(hub) = &self.ws else {
            let (len, path) = self.inner.recv(buf).await?;
            return Ok((len, path, Source::Udp(path.addr)));
        };
        loop {
            let received = tokio::select! {
                udp = self.inner.recv(buf) => Received::Udp(udp),
                inbound = hub.next_inbound() => Received::Ws(inbound),
            };
            match received {
                Received::Udp(udp) => {
                    let (len, path) = udp?;
                    return Ok((len, path, Source::Udp(path.addr)));
                }
                Received::Ws(inbound) => {
                    let Some(len) = fill(buf, &inbound.data) else {
                        hub.count_oversized();
                        continue;
                    };
                    let path = Path {
                        transport: self.inner.id(),
                        addr: inbound.peer,
                        ecn: Ecn::NotEct,
                    };
                    return Ok((len, path, Source::Ws(inbound.id)));
                }
            }
        }
    }
}

impl<T: Transport> Transport for RelayServerTransport<T> {
    fn id(&self) -> TransportId {
        self.inner.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        loop {
            let (len, path, source) = self.next(buf).await?;
            let unix_now = unix_now_secs().unwrap_or_default();
            let action =
                lock(&self.router).route(buf.as_packet(), source, Instant::now(), unix_now);
            match action {
                Action::OwnEngine => return Ok((len, path)),
                Action::Forward(to) => {
                    self.deliver(buf.as_packet(), to, &path, "forward").await;
                }
                Action::Reply(frame) => {
                    let path = Path {
                        ecn: Ecn::NotEct,
                        ..path
                    };
                    self.deliver(&frame, source, &path, "control reply").await;
                }
                Action::Drop(reason) => {
                    tracing::trace!(from = %source, reason = reason.as_str(), "relay drop");
                }
                Action::Handled => {}
            }
        }
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        lock(&self.router).note_own_send(datagram, Instant::now());
        if let Some(hub) = &self.ws
            && let Some(id) = hub.conn_at(to.addr)
        {
            hub.send_to(id, datagram);
            return Ok(());
        }
        self.inner.send(datagram, to).await
    }
}

/// The relay configuration file:
///
/// ```json
/// {"machine_keys": [{"machine_key": "<ed25519 public, base64>", "wg_public_key": "<base64>"}],
///  "static_targets": [{"wg_public_key": "<base64>", "endpoint": "192.0.2.7:51820"}]}
/// ```
///
/// A `machine_keys` entry pins the machine allowed to register the WireGuard key's
/// source (its machine id is the key's base64); a `static_targets` entry forwards
/// handshakes for the key to a fixed endpoint, for native WireGuard peers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Pinned machines.
    #[serde(default)]
    pub machine_keys: Vec<MachineKeyEntry>,
    /// Targets at fixed endpoints.
    #[serde(default)]
    pub static_targets: Vec<StaticTargetEntry>,
}

/// One `machine_keys` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineKeyEntry {
    /// The Ed25519 machine public key, base64.
    pub machine_key: String,
    /// The WireGuard public key it may register, base64.
    pub wg_public_key: String,
}

/// One `static_targets` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticTargetEntry {
    /// The WireGuard public key, base64.
    pub wg_public_key: String,
    /// Where its handshakes are forwarded.
    pub endpoint: SocketAddr,
}

impl RelayConfig {
    /// Parses a configuration file's contents.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        serde_json::from_str(text).context("invalid relay configuration")
    }

    /// Reads and parses a configuration file.
    pub fn load(path: &FsPath) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    /// The router targets of this configuration.
    pub fn targets(&self) -> anyhow::Result<Vec<TargetConfig>> {
        let pinned = self.machine_keys.iter().map(|entry| {
            let machine_key = decode_key(&entry.machine_key)
                .with_context(|| format!("machine key `{}`", entry.machine_key))?;
            Ok(TargetConfig {
                wg_public_key: decode_key(&entry.wg_public_key)?,
                pin: Some(MachinePin {
                    machine_id: machine_id(&machine_key),
                    machine_key,
                }),
                static_source: None,
            })
        });
        let fixed = self.static_targets.iter().map(|entry| {
            Ok(TargetConfig {
                wg_public_key: decode_key(&entry.wg_public_key)?,
                pin: None,
                static_source: Some(Source::Udp(entry.endpoint)),
            })
        });
        pinned.chain(fixed).collect()
    }
}

/// Parses `<left>=<right>`, the form of the relay's `--target` and `--static-target`.
///
/// A base64 32-byte key ends in one `=` of padding, so after such a key the separator is
/// the second `=` of `==`.
pub fn split_pair(text: &str) -> anyhow::Result<(&str, &str)> {
    if let Some(pos) = text.find("==") {
        return Ok((&text[..=pos], &text[pos + 2..]));
    }
    text.split_once('=')
        .ok_or_else(|| anyhow!("`{text}` is not `<key>=<value>`"))
}

/// Re-reads the configuration file `path` every [`CONFIG_POLL`].
///
/// When its contents change, the router's targets become `base` plus the file's. An
/// unreadable or invalid file keeps the previous targets. `current` is the contents
/// already applied.
pub fn watch_config(
    path: PathBuf,
    base: Vec<TargetConfig>,
    router: SharedRouter,
    mut current: String,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(CONFIG_POLL);
        loop {
            ticks.tick().await;
            let Ok(text) = tokio::fs::read_to_string(&path).await else {
                continue;
            };
            if text == current {
                continue;
            }
            match RelayConfig::parse(&text).and_then(|config| config.targets()) {
                Ok(targets) => {
                    let mut all = base.clone();
                    all.extend(targets);
                    tracing::info!(path = %path.display(), targets = all.len(), "relay configuration reloaded");
                    lock(&router).set_targets(all);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = format!("{e:#}"), "relay configuration not reloaded");
                }
            }
            current = text;
        }
    })
}

/// The status file's `extra.relay` object of a relay:
///
/// ```json
/// {"counters": {"own_engine": 0, "forwarded": 0, "control_rx": 0, "control_tx": 0,
///               "registrations": 0, "route_evictions": 0, "dropped_ambiguous": 0,
///               "dropped_unknown_target": 0, "dropped_invalid": 0,
///               "dropped_rate_limited": 0, "dropped_replay": 0, "dropped_bad_signature": 0},
///  "routes": [{"receiver_index": 1, "from": "ip:port", "to": "ip:port", "idle_secs": 0,
///              "confirmed": true}],
///  "targets": [{"wg_public_key": "<base64>", "machine_key": "<base64>",
///               "source": "ip:port", "learned_secs_ago": 3}]}
/// ```
pub fn status_json(router: &Router, now: Instant) -> Value {
    let c = router.counters();
    let routes: Vec<Value> = router
        .routes(now)
        .iter()
        .map(|route| {
            json!({
                "receiver_index": route.receiver_index,
                "from": route.from.to_string(),
                "to": route.to.to_string(),
                "idle_secs": route.idle.as_secs(),
                "confirmed": route.confirmed,
            })
        })
        .collect();
    let targets: Vec<Value> = router
        .targets(now)
        .iter()
        .map(|target| {
            json!({
                "wg_public_key": encode_key(&target.wg_public_key),
                "machine_key": target.machine_key.as_ref().map(encode_key),
                "source": target.source.map(|source| source.to_string()),
                "learned_secs_ago": target.learned_ago.map(|ago| ago.as_secs()),
            })
        })
        .collect();
    json!({
        "counters": {
            "own_engine": c.own_engine,
            "forwarded": c.forwarded,
            "control_rx": c.control_rx,
            "control_tx": c.control_tx,
            "registrations": c.registrations,
            "route_evictions": c.route_evictions,
            "dropped_ambiguous": c.dropped_ambiguous,
            "dropped_unknown_target": c.dropped_unknown_target,
            "dropped_invalid": c.dropped_invalid,
            "dropped_rate_limited": c.dropped_rate_limited,
            "dropped_replay": c.dropped_replay,
            "dropped_bad_signature": c.dropped_bad_signature,
        },
        "routes": routes,
        "targets": targets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_and_maps_to_targets() {
        let machine = encode_key(&[7; 32]);
        let wg = encode_key(&[8; 32]);
        let text = format!(
            r#"{{"machine_keys": [{{"machine_key": "{machine}", "wg_public_key": "{wg}"}}],
                "static_targets": [{{"wg_public_key": "{wg}", "endpoint": "192.0.2.7:51820"}}]}}"#
        );
        let targets = RelayConfig::parse(&text).unwrap().targets().unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].wg_public_key, [8; 32]);
        let pin = targets[0].pin.as_ref().unwrap();
        assert_eq!(pin.machine_key, [7; 32]);
        assert_eq!(pin.machine_id, machine);
        assert_eq!(
            targets[1].static_source,
            Some(Source::Udp("192.0.2.7:51820".parse().unwrap()))
        );
        assert_eq!(RelayConfig::parse("{}").unwrap(), RelayConfig::default());
        assert!(RelayConfig::parse(r#"{"bogus": 1}"#).is_err());
        let bad = r#"{"machine_keys": [{"machine_key": "eA==", "wg_public_key": "eA=="}]}"#;
        assert!(RelayConfig::parse(bad).unwrap().targets().is_err());
    }

    #[test]
    fn pairs_split_after_padded_keys() {
        let (machine, wg) = (encode_key(&[7; 32]), encode_key(&[8; 32]));
        let pair = format!("{machine}={wg}");
        assert_eq!(split_pair(&pair).unwrap(), (machine.as_str(), wg.as_str()));
        let pair = format!("{wg}=192.0.2.7:51820");
        assert_eq!(split_pair(&pair).unwrap(), (wg.as_str(), "192.0.2.7:51820"));
        assert_eq!(split_pair("a=b").unwrap(), ("a", "b"));
        assert!(split_pair("ab").is_err());
    }
}
