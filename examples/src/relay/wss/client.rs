//! The node side of the WSS carrier: [`WssTransport`].
//!
//! The transport keeps one WebSocket-over-TLS connection to the relay, from a background
//! task that reconnects with bounded exponential backoff. Datagrams to the relay's address
//! leave as binary messages; while the connection is down they are dropped and counted,
//! so the engine never waits for it. Received messages come out of [`Transport::recv`]
//! with the relay's address as their path. Datagrams to any other address go to an
//! optional UDP socket (the direct paths of the ladder) or are dropped.
//!
//! Wrapped in the extension-aware transport
//! ([`RelayClient::new`](crate::relay::client::RelayClient::new)), discovery, registration
//! and the ladder work as over UDP; a registration sent over the connection binds the
//! WireGuard key to it at the relay. [`rediscover_on_connect`] restarts discovery after
//! every (re)connect, so a restarted relay learns the node again right away.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{Ecn, PacketBuf, Path, Transport, TransportId, UdpTransport};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use super::{MAX_DATAGRAM, fill, ws_config};
use crate::relay::client::RelayClient;

/// Datagrams queued towards the relay.
const OUTBOUND_QUEUE: usize = 256;
/// Datagrams queued from the relay towards the engine.
const INBOUND_QUEUE: usize = 1024;
/// Time a connection attempt (TCP, TLS, WebSocket) may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Interval of keepalive pings; a connection silent for three of them is closed.
const PING_INTERVAL: Duration = Duration::from_secs(10);

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

/// The transport's counters, shared with its task.
#[derive(Debug)]
pub struct WssStats {
    relay: SocketAddr,
    url: String,
    connected: AtomicBool,
    connects: watch::Sender<u64>,
    connect_failures: AtomicU64,
    tx: AtomicU64,
    rx: AtomicU64,
    dropped_disconnected: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_text: AtomicU64,
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
        self.connected.load(Ordering::Relaxed)
    }

    /// Successful connects.
    pub fn connects(&self) -> u64 {
        *self.connects.borrow()
    }

    /// Successful connects after the first.
    pub fn reconnects(&self) -> u64 {
        self.connects().saturating_sub(1)
    }

    /// Failed connection attempts.
    pub fn connect_failures(&self) -> u64 {
        get(&self.connect_failures)
    }

    /// Datagrams sent over the connection.
    pub fn tx(&self) -> u64 {
        get(&self.tx)
    }

    /// Datagrams received over the connection.
    pub fn rx(&self) -> u64 {
        get(&self.rx)
    }

    /// Datagrams dropped, for any reason.
    pub fn drops(&self) -> u64 {
        [
            &self.dropped_disconnected,
            &self.dropped_queue_full,
            &self.dropped_text,
            &self.dropped_oversized,
            &self.dropped_no_route,
        ]
        .into_iter()
        .map(get)
        .sum()
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
                "disconnected": get(&self.dropped_disconnected),
                "queue_full": get(&self.dropped_queue_full),
                "text": get(&self.dropped_text),
                "oversized": get(&self.dropped_oversized),
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
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    task: JoinHandle<()>,
}

/// What the receive loop got.
enum Received {
    Udp(io::Result<(usize, Path)>),
    Ws(Option<Vec<u8>>),
}

impl WssTransport {
    /// Starts connecting to the relay of `config` (inside a tokio runtime). `direct`
    /// carries datagrams to other addresses; it should have the same `id`.
    pub fn connect(id: TransportId, config: WssConfig, direct: Option<UdpTransport>) -> Self {
        let stats = Arc::new(WssStats {
            relay: config.relay,
            url: config.url.clone(),
            connected: AtomicBool::new(false),
            connects: watch::Sender::new(0),
            connect_failures: AtomicU64::new(0),
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            dropped_disconnected: AtomicU64::new(0),
            dropped_queue_full: AtomicU64::new(0),
            dropped_text: AtomicU64::new(0),
            dropped_oversized: AtomicU64::new(0),
            dropped_no_route: AtomicU64::new(0),
        });
        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let (inbound_tx, inbound) = mpsc::channel(INBOUND_QUEUE);
        let relay = config.relay;
        let task = tokio::spawn(run(config, Arc::clone(&stats), outbound_rx, inbound_tx));
        Self {
            id,
            relay,
            direct,
            stats,
            outbound,
            inbound: tokio::sync::Mutex::new(inbound),
            task,
        }
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

    async fn next_inbound(&self) -> Option<Vec<u8>> {
        self.inbound.lock().await.recv().await
    }
}

impl Drop for WssTransport {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Transport for WssTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        loop {
            let received = match &self.direct {
                Some(udp) => tokio::select! {
                    udp = udp.recv(buf) => Received::Udp(udp),
                    datagram = self.next_inbound() => Received::Ws(datagram),
                },
                None => Received::Ws(self.next_inbound().await),
            };
            let datagram = match received {
                Received::Udp(udp) => return udp,
                Received::Ws(Some(datagram)) => datagram,
                Received::Ws(None) => return Err(io::ErrorKind::BrokenPipe.into()),
            };
            let Some(len) = fill(buf, &datagram) else {
                bump(&self.stats.dropped_oversized);
                continue;
            };
            let path = Path {
                transport: self.id,
                addr: self.relay,
                ecn: Ecn::NotEct,
            };
            return Ok((len, path));
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
        if !self.stats.connected() {
            bump(&self.stats.dropped_disconnected);
        } else if self.outbound.try_send(datagram.to_vec()).is_err() {
            bump(&self.stats.dropped_queue_full);
        }
        Ok(())
    }
}

type Ws = WebSocketStream<TlsStream<TcpStream>>;

/// Connects, runs the connection, and reconnects with backoff, until aborted.
async fn run(
    config: WssConfig,
    stats: Arc<WssStats>,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
) {
    let mut backoff = config.backoff_min;
    loop {
        match tokio::time::timeout(CONNECT_TIMEOUT, open(&config)).await {
            Ok(Ok(ws)) => {
                backoff = config.backoff_min;
                // What queued up before the connection is stale.
                while outbound.try_recv().is_ok() {
                    bump(&stats.dropped_disconnected);
                }
                stats.connected.store(true, Ordering::Relaxed);
                stats.connects.send_modify(|n| *n += 1);
                tracing::info!(url = %config.url, relay = %config.relay, "wss connected");
                session(ws, &stats, &mut outbound, &inbound).await;
                stats.connected.store(false, Ordering::Relaxed);
                tracing::info!(url = %config.url, "wss disconnected");
            }
            Ok(Err(e)) => {
                bump(&stats.connect_failures);
                tracing::debug!(url = %config.url, error = format!("{e:#}"), "wss connect failed");
            }
            Err(_) => {
                bump(&stats.connect_failures);
                tracing::debug!(url = %config.url, "wss connect timed out");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(config.backoff_max);
    }
}

/// TCP, TLS with the pinned certificate, and the WebSocket upgrade.
async fn open(config: &WssConfig) -> anyhow::Result<Ws> {
    let tcp = TcpStream::connect(config.relay).await?;
    tcp.set_nodelay(true)?;
    let tls = TlsConnector::from(Arc::clone(&config.tls))
        .connect(config.server_name.clone(), tcp)
        .await?;
    let (ws, _) =
        tokio_tungstenite::client_async_with_config(config.url.as_str(), tls, Some(ws_config()))
            .await?;
    Ok(ws)
}

/// Moves datagrams between the connection and the queues until the connection ends.
async fn session(
    mut ws: Ws,
    stats: &WssStats,
    outbound: &mut mpsc::Receiver<Vec<u8>>,
    inbound: &mpsc::Sender<Vec<u8>>,
) {
    let mut pings = tokio::time::interval(PING_INTERVAL);
    pings.tick().await;
    let mut silent = 0u32;
    loop {
        tokio::select! {
            message = ws.next() => {
                silent = 0;
                match message {
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() > MAX_DATAGRAM {
                            bump(&stats.dropped_oversized);
                        } else if inbound.try_send(data.to_vec()).is_ok() {
                            bump(&stats.rx);
                        } else {
                            bump(&stats.dropped_queue_full);
                        }
                    }
                    Some(Ok(Message::Text(_))) => bump(&stats.dropped_text),
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "wss connection failed");
                        return;
                    }
                }
            }
            datagram = outbound.recv() => {
                let Some(datagram) = datagram else { return };
                if let Err(e) = ws.send(Message::Binary(datagram.into())).await {
                    tracing::debug!(error = %e, "wss send failed");
                    return;
                }
                bump(&stats.tx);
            }
            _ = pings.tick() => {
                silent += 1;
                if silent > 3 {
                    tracing::debug!("wss connection silent, closing");
                    return;
                }
                if ws.send(Message::Ping(Vec::new().into())).await.is_err() {
                    return;
                }
            }
        }
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
