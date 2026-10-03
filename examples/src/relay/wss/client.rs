//! The node side of the WSS carrier: [`WssTransport`].
//!
//! The transport keeps one WebSocket-over-TLS connection to the relay in a
//! [`LinkTransport`], dialed by a [`WssDialer`] that reconnects with bounded exponential
//! backoff. Datagrams to the relay's address leave as binary messages; while the
//! connection is down they wait in the link's queue (256 datagrams; a full queue fails
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{
    BoxFuture, LinkConfig, LinkDialer, LinkReceiver, LinkSender, LinkState, LinkTransport,
    PacketBuf, Path, Transport, TransportId, UdpTransport,
};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Bytes, Message};

use super::{MAX_DATAGRAM, fill, ws_config};
use crate::relay::client::RelayClient;

/// Time a connection attempt (TCP, TLS, WebSocket) may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Interval of keepalive pings.
const PING_INTERVAL: Duration = Duration::from_secs(10);
/// A connection silent this long (three and a half [`PING_INTERVAL`]s without any frame, pongs
/// included) is closed and dialed again.
///
/// The receiver applies it to every frame rather than through
/// [`LinkConfig::read_idle_timeout`]: that one only sees datagrams, so pongs would not
/// count and an idle but healthy connection would be cut.
const READ_IDLE: Duration = Duration::from_secs(35);

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

/// The transport's counters, shared with its dialer.
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
    link: LinkTransport,
    /// Receives from the link while `recv`'s buffer waits on the direct socket.
    scratch: Mutex<PacketBuf>,
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
        let relay = config.relay;
        let dialer = WssDialer::new(config, Arc::clone(&stats));
        let link = LinkTransport::new(id, relay, Arc::new(dialer), LinkConfig::default());
        Self {
            id,
            relay,
            direct,
            stats,
            link,
            scratch: Mutex::new(PacketBuf::with_capacity(MAX_DATAGRAM)),
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

type Ws = WebSocketStream<TlsStream<TcpStream>>;

/// Dials the WSS connections of a [`WssTransport`]'s link.
///
/// Each dial is TCP, TLS with the pinned certificate and the WebSocket upgrade, within
/// [`CONNECT_TIMEOUT`]. Every dial but the first waits first: `backoff_min` after a
/// connection that came up, doubled after each failure up to `backoff_max`.
#[derive(Debug)]
struct WssDialer {
    config: WssConfig,
    stats: Arc<WssStats>,
    /// The wait before the next dial; `None` before the first.
    backoff: StdMutex<Option<Duration>>,
}

impl WssDialer {
    /// A dialer for the relay of `config` that counts into `stats`.
    const fn new(config: WssConfig, stats: Arc<WssStats>) -> Self {
        Self {
            config,
            stats,
            backoff: StdMutex::new(None),
        }
    }

    fn set_backoff(&self, backoff: Duration) {
        *self.backoff.lock().unwrap_or_else(PoisonError::into_inner) = Some(backoff);
    }

    /// TCP, TLS with the pinned certificate, and the WebSocket upgrade.
    async fn open(&self) -> anyhow::Result<Ws> {
        let config = &self.config;
        let tcp = TcpStream::connect(config.relay).await?;
        tcp.set_nodelay(true)?;
        let tls = TlsConnector::from(Arc::clone(&config.tls))
            .connect(config.server_name.clone(), tcp)
            .await?;
        let (ws, _) = tokio_tungstenite::client_async_with_config(
            config.url.as_str(),
            tls,
            Some(ws_config()),
        )
        .await?;
        Ok(ws)
    }
}

impl LinkDialer for WssDialer {
    fn dial(&self) -> BoxFuture<'_, io::Result<(Box<dyn LinkSender>, Box<dyn LinkReceiver>)>> {
        Box::pin(async move {
            let wait = *self.backoff.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(wait) = wait {
                tokio::time::sleep(wait).await;
            }
            let failed = |reason: String| {
                bump(&self.stats.connect_failures);
                let next = wait.map_or(self.config.backoff_min, |wait| {
                    wait.saturating_mul(2).min(self.config.backoff_max)
                });
                self.set_backoff(next);
                tracing::debug!(url = %self.config.url, error = reason, "wss connect failed");
                io::Error::other(reason)
            };
            let ws = match tokio::time::timeout(CONNECT_TIMEOUT, self.open()).await {
                Ok(Ok(ws)) => ws,
                Ok(Err(e)) => return Err(failed(format!("{e:#}"))),
                Err(_) => return Err(failed("timed out".to_owned())),
            };
            self.set_backoff(self.config.backoff_min);
            let (sink, stream) = ws.split();
            let sink = Arc::new(Mutex::new(sink));
            let sender = WssSender {
                sink: Arc::clone(&sink),
                stats: Arc::clone(&self.stats),
                pings: tokio::spawn(ping(sink)),
            };
            let receiver = WssReceiver {
                stream,
                stats: Arc::clone(&self.stats),
            };
            let link: (Box<dyn LinkSender>, Box<dyn LinkReceiver>) =
                (Box::new(sender), Box::new(receiver));
            Ok(link)
        })
    }

    fn on_state(&self, state: LinkState) {
        match state {
            LinkState::Connected => {
                self.stats.connected.store(true, Ordering::Relaxed);
                self.stats.connects.send_modify(|n| *n += 1);
                tracing::info!(url = %self.config.url, relay = %self.config.relay, "wss connected");
            }
            LinkState::Disconnected => {
                self.stats.connected.store(false, Ordering::Relaxed);
                tracing::info!(url = %self.config.url, "wss disconnected");
            }
            _ => {}
        }
    }
}

/// The sending half of a WSS connection, shared with its ping task.
type Sink = Arc<Mutex<SplitSink<Ws, Message>>>;

/// Sends a keepalive ping every [`PING_INTERVAL`] until a send fails; the receiver then
/// sees the connection end, or [`READ_IDLE`] pass.
async fn ping(sink: Sink) {
    let mut pings = tokio::time::interval(PING_INTERVAL);
    pings.tick().await;
    loop {
        pings.tick().await;
        if sink
            .lock()
            .await
            .send(Message::Ping(Bytes::new()))
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Sends datagrams as binary messages; owns the connection's ping task.
struct WssSender {
    sink: Sink,
    stats: Arc<WssStats>,
    pings: JoinHandle<()>,
}

impl Drop for WssSender {
    fn drop(&mut self) {
        self.pings.abort();
    }
}

impl LinkSender for WssSender {
    fn send(&mut self, message: &[u8]) -> BoxFuture<'_, io::Result<()>> {
        let message = Message::Binary(Bytes::copy_from_slice(message));
        Box::pin(async move {
            self.sink
                .lock()
                .await
                .send(message)
                .await
                .map_err(io::Error::other)?;
            bump(&self.stats.tx);
            Ok(())
        })
    }
}

/// Yields the payloads of binary messages; counts and skips the rest.
struct WssReceiver {
    stream: SplitStream<Ws>,
    stats: Arc<WssStats>,
}

impl LinkReceiver for WssReceiver {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Option<Bytes>>> {
        Box::pin(async move {
            loop {
                let Ok(message) = tokio::time::timeout(READ_IDLE, self.stream.next()).await else {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "wss connection silent",
                    ));
                };
                match message {
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() > MAX_DATAGRAM {
                            bump(&self.stats.dropped_oversized);
                        } else {
                            bump(&self.stats.rx);
                            return Ok(Some(data));
                        }
                    }
                    Some(Ok(Message::Text(_))) => bump(&self.stats.dropped_text),
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_))) | None => return Ok(None),
                    Some(Err(e)) => return Err(io::Error::other(e)),
                }
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
