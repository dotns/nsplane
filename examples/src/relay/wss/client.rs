//! The node side of the WSS carrier: [`WssTransport`].
//!
//! The transport keeps one WebSocket-over-TLS connection to the relay in a
//! [`LinkTransport`], dialed by an [`nsplane_wss::WssDialer`] that pins the relay's
//! certificate, keeps the connection alive with pings and reconnects with bounded
//! exponential backoff. Datagrams to the relay's address leave as binary messages; while
//! the connection is down they wait in the link's queue (256 datagrams; a full queue fails
//! the send at once, so the engine never waits for it). Received messages come out of
//! [`Transport::recv`] with the relay's address as their path. Datagrams to any other
//! address go to an optional UDP socket (the direct paths of the ladder) or are dropped.
//!
//! Wrapped in the extension-aware transport
//! ([`RelayClient::new`](crate::relay::client::RelayClient::new)), discovery, registration
//! and the ladder work as over UDP; a registration sent over the connection binds the
//! WireGuard key to it at the relay. [`rediscover_on_connect`] restarts discovery after
//! every (re)connect, so a restarted relay learns the node again right away.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nsplane::{LinkConfig, LinkTransport, PacketBuf, Path, Transport, TransportId, UdpTransport};
use nsplane_wss::{WssDialer, WssTls};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

use super::{MAX_DATAGRAM, fill};
use crate::relay::client::RelayClient;

/// Where and how [`WssTransport`] connects.
#[derive(Debug, Clone)]
pub struct WssConfig {
    /// The `wss://` URL of the WebSocket request.
    pub url: String,
    /// The TLS server name: the SNI and the name the certificate must carry.
    pub server_name: ServerName<'static>,
    /// The relay's socket address: where to connect, and the address of its datagrams.
    pub relay: SocketAddr,
    /// The client TLS configuration (see [`super::client_tls`]).
    pub tls: Arc<ClientConfig>,
    /// First wait before reconnecting, doubled after each failure.
    pub backoff_min: Duration,
    /// Longest wait before reconnecting.
    pub backoff_max: Duration,
}

impl WssConfig {
    /// 250 ms to 5 s reconnect backoff.
    pub const fn new(
        url: String,
        server_name: ServerName<'static>,
        relay: SocketAddr,
        tls: Arc<ClientConfig>,
    ) -> Self {
        Self {
            url,
            server_name,
            relay,
            tls,
            backoff_min: Duration::from_millis(250),
            backoff_max: Duration::from_secs(5),
        }
    }
}

/// The transport's counters: the dialer's, plus the drops of the transport itself.
#[derive(Debug)]
pub struct WssStats {
    relay: SocketAddr,
    url: String,
    link: Arc<nsplane_wss::WssStats>,
    connects: watch::Sender<u64>,
    dropped_queue_full: AtomicU64,
    dropped_oversized: AtomicU64,
    dropped_no_route: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn get(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

impl WssStats {
    /// Whether the connection is up.
    pub fn connected(&self) -> bool {
        self.link.connected()
    }

    /// Successful connects.
    pub fn connects(&self) -> u64 {
        self.link.connects()
    }

    /// Successful connects after the first.
    pub fn reconnects(&self) -> u64 {
        self.connects().saturating_sub(1)
    }

    /// Failed connection attempts.
    pub fn connect_failures(&self) -> u64 {
        self.link.connect_failures()
    }

    /// Datagrams sent over the connection.
    pub fn tx(&self) -> u64 {
        self.link.tx()
    }

    /// Datagrams received over the connection.
    pub fn rx(&self) -> u64 {
        self.link.rx()
    }

    /// Datagrams dropped as too long, by the dialer or by `recv`.
    fn dropped_oversized(&self) -> u64 {
        self.link.dropped_oversized() + get(&self.dropped_oversized)
    }

    /// Datagrams dropped, for any reason.
    pub fn drops(&self) -> u64 {
        get(&self.dropped_queue_full)
            + self.link.dropped_text()
            + self.dropped_oversized()
            + get(&self.dropped_no_route)
    }

    /// Watches the connect count.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.connects.subscribe()
    }

    /// The status file's `extra.wss` object of a node:
    ///
    /// ```json
    /// {"url": "wss://relay.example:8443/", "relay": "ip:port", "connected": true,
    ///  "reconnects": 0, "connect_failures": 0, "tx": 10, "rx": 9, "drops": 0,
    ///  "dropped": {"disconnected": 0, "queue_full": 0, "text": 0, "oversized": 0,
    ///              "no_route": 0}}
    /// ```
    ///
    /// `dropped.disconnected` stays 0: datagrams wait in the queue while the connection
    /// is down. `dropped.queue_full` counts sends that failed on a full queue.
    pub fn status_json(&self) -> Value {
        json!({
            "url": self.url,
            "relay": self.relay.to_string(),
            "connected": self.connected(),
            "reconnects": self.reconnects(),
            "connect_failures": self.connect_failures(),
            "tx": self.tx(),
            "rx": self.rx(),
            "drops": self.drops(),
            "dropped": {
                "disconnected": 0,
                "queue_full": get(&self.dropped_queue_full),
                "text": self.link.dropped_text(),
                "oversized": self.dropped_oversized(),
                "no_route": get(&self.dropped_no_route),
            },
        })
    }
}

/// A [`Transport`] over a WSS connection to the relay. See the
/// [module documentation](self).
#[derive(Debug)]
pub struct WssTransport {
    id: TransportId,
    relay: SocketAddr,
    direct: Option<UdpTransport>,
    stats: Arc<WssStats>,
    link: LinkTransport,
    /// Receives from the link while `recv`'s buffer waits on the direct socket.
    scratch: Mutex<PacketBuf>,
}

impl WssTransport {
    /// Starts connecting to the relay of `config` (inside a tokio runtime). `direct`
    /// carries datagrams to other addresses; it should have the same `id`.
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] on a URL that is not `wss://` with a
    /// host.
    pub fn connect(
        id: TransportId,
        config: WssConfig,
        direct: Option<UdpTransport>,
    ) -> io::Result<Self> {
        let relay = config.relay;
        let wss = nsplane_wss::WssConfig::new(config.url.clone(), WssTls::Config(config.tls))
            .connect_addr(relay)
            .server_name(config.server_name.to_str())
            .backoff(config.backoff_min, config.backoff_max);
        let dialer = WssDialer::new(wss)?;
        let stats = Arc::new(WssStats {
            relay,
            url: config.url,
            link: dialer.stats(),
            connects: watch::Sender::new(0),
            dropped_queue_full: AtomicU64::new(0),
            dropped_oversized: AtomicU64::new(0),
            dropped_no_route: AtomicU64::new(0),
        });
        // The dialer counts a connect before it publishes the state, so the count read
        // after a change includes it. The watch ends with the dialer.
        let mut state = dialer.state();
        let counted = Arc::clone(&stats);
        tokio::spawn(async move {
            while state.changed().await.is_ok() {
                let connects = counted.link.connects();
                counted.connects.send_if_modified(|n| {
                    let changed = *n != connects;
                    *n = connects;
                    changed
                });
            }
        });
        let link = dialer.into_transport(id, relay, LinkConfig::default());
        Ok(Self {
            id,
            relay,
            direct,
            stats,
            link,
            scratch: Mutex::new(PacketBuf::with_capacity(MAX_DATAGRAM)),
        })
    }

    /// The relay's address: the path address of everything the connection carries.
    pub const fn relay(&self) -> SocketAddr {
        self.relay
    }

    /// The local address of the direct UDP socket.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.direct.as_ref().map(UdpTransport::local_addr)
    }

    /// The counters.
    pub fn stats(&self) -> Arc<WssStats> {
        Arc::clone(&self.stats)
    }
}

impl Transport for WssTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        loop {
            let from_link = async {
                let mut scratch = self.scratch.lock().await;
                let received = self.link.recv(&mut scratch).await;
                (scratch, received)
            };
            let (scratch, received) = match &self.direct {
                Some(udp) => tokio::select! {
                    udp = udp.recv(buf) => return udp,
                    link = from_link => link,
                },
                None => from_link.await,
            };
            let (_, path) = received?;
            if let Some(len) = fill(buf, scratch.as_packet()) {
                return Ok((len, path));
            }
            bump(&self.stats.dropped_oversized);
        }
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        if to.addr != self.relay {
            if let Some(udp) = &self.direct {
                return udp.send(datagram, to).await;
            }
            bump(&self.stats.dropped_no_route);
            return Ok(());
        }
        self.link.send(datagram, to).await.inspect_err(|e| {
            if e.kind() == io::ErrorKind::WouldBlock {
                bump(&self.stats.dropped_queue_full);
            }
        })
    }
}

/// Restarts discovery of the relay at `relay` on `client` after every connect of the
/// transport behind `stats`, until the transport is dropped.
pub fn rediscover_on_connect(
    client: RelayClient,
    stats: &WssStats,
    relay: SocketAddr,
) -> JoinHandle<()> {
    let mut connects = stats.subscribe();
    tokio::spawn(async move {
        while connects.changed().await.is_ok() {
            tracing::debug!(%relay, "wss (re)connected, discovering the relay again");
            client.rediscover(relay);
        }
    })
}
