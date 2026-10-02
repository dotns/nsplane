//! The `--status-file` JSON snapshot.
//!
//! [`Status::spawn`] rewrites the file every second (written to `<path>.tmp`, then
//! renamed, so readers never see a partial file):
//!
//! ```json
//! {"public_key": "<base64>", "listen": "0.0.0.0:51820", "mtu": 1420,
//!  "peers": [{"public_key": "<base64>", "endpoint": "192.0.2.1:51820", "transport": 0,
//!             "rx": 1234, "tx": 1234, "last_handshake_secs_ago": 3,
//!             "peer": 0, "data_rx": 1000, "data_tx": 1000,
//!             "allowed_ips": ["10.0.0.2/32"], "persistent_keepalive": 25}],
//!  "drops": {"<reason>": 1},
//!  "extra": {}}
//! ```
//!
//! `endpoint`, `transport`, `last_handshake_secs_ago` and `persistent_keepalive` are `null`
//! when unknown. `extra` is filled by the example through [`Status::extra`] (netstack
//! counters, relay state, ...).

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use nsplane::{EngineHandle, PeerStats};
use serde_json::{Map, Value, json};
use tokio::task::JoinHandle;

use crate::node::{encode_key, encode_public_key};

/// How often [`Status::spawn`] rewrites the file.
pub const INTERVAL: Duration = Duration::from_secs(1);

/// Adds entries to the `extra` object of a snapshot.
pub type ExtraFn = dyn Fn(&mut Map<String, Value>) + Send + Sync;

/// The status file of one node. Cloning yields another writer of the same file.
#[derive(Clone)]
pub struct Status {
    path: PathBuf,
    handle: EngineHandle,
    listen: SocketAddr,
    extras: Vec<Arc<ExtraFn>>,
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Status")
            .field("path", &self.path)
            .field("listen", &self.listen)
            .field("extras", &self.extras.len())
            .finish_non_exhaustive()
    }
}

impl Status {
    /// A status file at `path` for the engine behind `handle`, which listens on `listen`.
    pub const fn new(path: PathBuf, handle: EngineHandle, listen: SocketAddr) -> Self {
        Self {
            path,
            handle,
            listen,
            extras: Vec::new(),
        }
    }

    /// Adds a contributor to `extra`; contributors run in the order they were added, on
    /// every snapshot.
    #[must_use]
    pub fn extra(
        mut self,
        extra: impl Fn(&mut Map<String, Value>) + Send + Sync + 'static,
    ) -> Self {
        self.extras.push(Arc::new(extra));
        self
    }

    /// The current snapshot.
    pub async fn snapshot(&self) -> anyhow::Result<Value> {
        let public_key = self
            .handle
            .public_key()
            .await?
            .map(|key| encode_public_key(&key));
        let mtu = self.handle.mtu().await?;
        let peers: Vec<Value> = self.handle.peers().await?.iter().map(peer_json).collect();
        let drops: Map<String, Value> = self
            .handle
            .drop_counters()
            .await?
            .into_iter()
            .map(|(reason, n)| (reason.to_owned(), Value::from(n)))
            .collect();
        let mut extra = Map::new();
        for contribute in &self.extras {
            contribute(&mut extra);
        }
        Ok(json!({
            "public_key": public_key,
            "listen": self.listen.to_string(),
            "mtu": mtu,
            "peers": peers,
            "drops": drops,
            "extra": extra,
        }))
    }

    /// Writes one snapshot: to `<path>.tmp`, then renamed to `<path>`.
    pub async fn write(&self) -> anyhow::Result<()> {
        let snapshot = self.snapshot().await?;
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let body = serde_json::to_vec_pretty(&snapshot)?;
        tokio::fs::write(&tmp, body)
            .await
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        tokio::fs::rename(&tmp, &self.path)
            .await
            .with_context(|| format!("cannot write {}", self.path.display()))
    }

    /// Writes a snapshot every [`INTERVAL`] until the engine stops or the task is aborted.
    pub fn spawn(&self) -> JoinHandle<()> {
        let status = self.clone();
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(INTERVAL);
            loop {
                ticks.tick().await;
                if let Err(e) = status.write().await {
                    tracing::debug!(error = format!("{e:#}"), "status file not written");
                    if status.handle.mtu().await.is_err() {
                        return;
                    }
                }
            }
        })
    }
}

/// One peer of the snapshot.
fn peer_json(peer: &PeerStats) -> Value {
    let allowed_ips: Vec<String> = peer
        .allowed_ips
        .iter()
        .map(|ip| format!("{}/{}", ip.addr, ip.cidr))
        .collect();
    json!({
        "public_key": encode_key(peer.public_key.as_bytes()),
        "endpoint": peer.path.map(|path| path.addr.to_string()),
        "transport": peer.path.map(|path| path.transport.get()),
        "rx": peer.rx,
        "tx": peer.tx,
        "last_handshake_secs_ago": peer.last_handshake.map(|elapsed| elapsed.as_secs()),
        "peer": peer.peer.get(),
        "data_rx": peer.data_rx,
        "data_tx": peer.data_tx,
        "allowed_ips": allowed_ips,
        "persistent_keepalive": peer.persistent_keepalive,
    })
}
