//! [`WssDialer`]: dials the WSS links of a [`LinkTransport`].

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{
    BoxFuture, LinkConfig, LinkDialer, LinkReceiver, LinkSender, LinkState, LinkTransport,
    TransportId,
};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::MAX_DATAGRAM;
use crate::config::WssConfig;
use crate::connect::{Connector, DialCounters, Ws, bump, get};

/// The two halves of a link, as [`LinkDialer::dial`] returns them.
type Link = (Box<dyn LinkSender>, Box<dyn LinkReceiver>);

/// The counters of a [`WssDialer`] and its links.
#[derive(Debug, Default)]
pub struct WssStats {
    connected: AtomicBool,
    connects: AtomicU64,
    dial: DialCounters,
    tx: AtomicU64,
    rx: AtomicU64,
    dropped_text: AtomicU64,
    dropped_oversized: AtomicU64,
}

impl WssStats {
    /// Whether a link is up.
    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Links that came up.
    pub fn connects(&self) -> u64 {
        get(&self.connects)
    }

    /// Failed dials, rejections included.
    pub fn connect_failures(&self) -> u64 {
        get(&self.dial.connect_failures)
    }

    /// Dials rejected with 401 Unauthorized.
    pub fn rejected_unauthorized(&self) -> u64 {
        get(&self.dial.rejected_unauthorized)
    }

    /// Dials rejected with 403 Forbidden.
    pub fn rejected_forbidden(&self) -> u64 {
        get(&self.dial.rejected_forbidden)
    }

    /// Datagrams sent.
    pub fn tx(&self) -> u64 {
        get(&self.tx)
    }

    /// Datagrams received.
    pub fn rx(&self) -> u64 {
        get(&self.rx)
    }

    /// Text messages received and dropped.
    pub fn dropped_text(&self) -> u64 {
        get(&self.dropped_text)
    }

    /// Datagrams longer than [`MAX_DATAGRAM`], sent or received, dropped.
    pub fn dropped_oversized(&self) -> u64 {
        get(&self.dropped_oversized)
    }
}

/// Dials the WSS links of a [`LinkTransport`]; see the [crate documentation](crate).
pub struct WssDialer {
    connector: Connector,
    stats: Arc<WssStats>,
}

impl fmt::Debug for WssDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WssDialer")
            .field("connector", &self.connector)
            .field("stats", &self.stats)
            .finish()
    }
}

impl WssDialer {
    /// A dialer for `config`.
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] on a URL that is not `wss://` with a
    /// host, an invalid server name or header, or TLS roots no configuration can be built
    /// from.
    pub fn new(config: WssConfig) -> io::Result<Self> {
        Ok(Self {
            connector: Connector::new(config)?,
            stats: Arc::new(WssStats::default()),
        })
    }

    /// The counters.
    pub fn stats(&self) -> Arc<WssStats> {
        Arc::clone(&self.stats)
    }

    /// Watches the link state: [`LinkState::Disconnected`] at first,
    /// [`LinkState::Connected`] while a link is up, [`LinkState::Rejected`] after a dial
    /// was refused with 401 or 403 (until a link comes up).
    pub fn state(&self) -> watch::Receiver<LinkState> {
        self.connector.state()
    }

    /// A [`LinkTransport`] to `peer` running on this dialer (inside a tokio runtime); take
    /// [`stats`](Self::stats) and [`state`](Self::state) first.
    pub fn into_transport(
        self,
        id: TransportId,
        peer: SocketAddr,
        config: LinkConfig,
    ) -> LinkTransport {
        LinkTransport::new(id, peer, Arc::new(self), config)
    }
}

impl LinkDialer for WssDialer {
    fn dial(&self) -> BoxFuture<'_, io::Result<Link>> {
        Box::pin(async move {
            let ws = self.connector.connect(&self.stats.dial).await?;
            let config = self.connector.config();
            let (sink, stream) = ws.split();
            let sink = Arc::new(Mutex::new(sink));
            let sender = WssSender {
                sink: Arc::clone(&sink),
                stats: Arc::clone(&self.stats),
                pings: tokio::spawn(ping(sink, config.ping_interval)),
            };
            let receiver = WssReceiver {
                stream,
                stats: Arc::clone(&self.stats),
                read_idle: config.read_idle,
            };
            let link: Link = (Box::new(sender), Box::new(receiver));
            Ok(link)
        })
    }

    fn on_state(&self, state: LinkState) {
        let url = &self.connector.config().url;
        match state {
            LinkState::Connected => {
                self.stats.connected.store(true, Ordering::Relaxed);
                bump(&self.stats.connects);
                tracing::info!(url = %url, "wss connected");
            }
            LinkState::Disconnected => {
                self.stats.connected.store(false, Ordering::Relaxed);
                tracing::info!(url = %url, "wss disconnected");
            }
            _ => {}
        }
        self.connector.set_state(state);
    }
}

/// The sending half of a WSS link, shared with its ping task.
type Sink = Arc<Mutex<SplitSink<Ws, Message>>>;

/// Sends a ping every `interval` until a send fails; the receiver then sees the link end,
/// or its read idle pass.
async fn ping(sink: Sink, interval: Duration) {
    let mut pings = tokio::time::interval(interval);
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

/// Sends datagrams as binary messages; owns the link's ping task.
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
        if message.len() > MAX_DATAGRAM {
            bump(&self.stats.dropped_oversized);
            return Box::pin(std::future::ready(Ok(())));
        }
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
    read_idle: Duration,
}

impl LinkReceiver for WssReceiver {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Option<Bytes>>> {
        Box::pin(async move {
            loop {
                let Ok(message) = tokio::time::timeout(self.read_idle, self.stream.next()).await
                else {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "wss link silent"));
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
