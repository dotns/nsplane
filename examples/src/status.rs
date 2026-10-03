//! The `--status-file` JSON snapshot.
//!
//! [`Status::spawn`] rewrites the file every second (written to a temporary file next to
//! it, then renamed, so readers never see a partial file):
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use nsplane::{EngineHandle, PeerStats};
use serde_json::{Map, Value, json};
use tokio::task::JoinHandle;

use crate::node::{encode_key, encode_public_key};

/// How often [`Status::spawn`] rewrites the file.
pub const INTERVAL: Duration = Duration::from_secs(1);

/// Numbers the temporary files of [`Status::write`] within this process.
static WRITES: AtomicU64 = AtomicU64::new(0);

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

    /// Writes one snapshot: to `<path>.<pid>.<n>.tmp`, then renamed to `<path>`. Every
    /// write has its own temporary file, so concurrent writes of the same path never
    /// collide; the last rename wins.
    pub async fn write(&self) -> anyhow::Result<()> {
        let snapshot = self.snapshot().await?;
        write_atomic(&self.path, &serde_json::to_vec_pretty(&snapshot)?).await
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

/// Replaces the file at `path` with `body` through a temporary file unique to this write.
async fn write_atomic(path: &std::path::Path, body: &[u8]) -> anyhow::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = PathBuf::from(tmp);
    tokio::fs::write(&tmp, body)
        .await
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e).with_context(|| format!("cannot write {}", path.display()));
    }
    Ok(())
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

/// The drop counters of a netstack, for an `extra.netstack` object.
pub fn netstack_json(stack: &nsplane_netstack::NetStackHandle) -> Value {
    let stats = stack.stats();
    json!({
        "malformed": stats.malformed,
        "no_address": stats.no_address,
        "unsupported": stats.unsupported,
        "syn_refused": stats.syn_refused,
        "tcp_not_accepted": stats.tcp_not_accepted,
        "udp_queue_full": stats.udp_queue_full,
        "udp_flow_limit": stats.udp_flow_limit,
        "udp_not_accepted": stats.udp_not_accepted,
        "egress_full": stats.egress_full,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writes_never_collide() {
        let dir = std::env::temp_dir().join(format!("nsplane-status-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("status.json");
        let writers: Vec<_> = (0..16)
            .map(|i| {
                let path = path.clone();
                tokio::spawn(async move {
                    for j in 0..50 {
                        write_atomic(&path, format!("{{\"w\":{i},\"n\":{j}}}").as_bytes())
                            .await
                            .unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.await.unwrap();
        }
        write_atomic(&path, b"{\"final\":true}").await.unwrap();
        let body = tokio::fs::read(&path).await.unwrap();
        assert_eq!(body, b"{\"final\":true}");
        let mut entries = tokio::fs::read_dir(&dir).await.unwrap();
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            names.push(entry.file_name());
        }
        assert_eq!(names, ["status.json"], "temporary files are left behind");
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }
}
