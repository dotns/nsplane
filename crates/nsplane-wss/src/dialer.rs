//! [`WssDialer`]: dials the WSS links of a [`LinkTransport`].

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{
    BoxFuture, LinkConfig, LinkDialer, LinkReceiver, LinkSender, LinkState, LinkTransport,
    TransportId,
};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use crate::config::{WssConfig, WssTls};
use crate::{MAX_DATAGRAM, MAX_MESSAGE};

/// The two halves of a link, as [`LinkDialer::dial`] returns them.
type Link = (Box<dyn LinkSender>, Box<dyn LinkReceiver>);

type Ws = WebSocketStream<TlsStream<TcpStream>>;

/// Locks `mutex`, ignoring poisoning: the guarded state stays consistent.
fn lock<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn get(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// The counters of a [`WssDialer`] and its links.
#[derive(Debug, Default)]
pub struct WssStats {
    connected: AtomicBool,
    connects: AtomicU64,
    connect_failures: AtomicU64,
    rejected_unauthorized: AtomicU64,
    rejected_forbidden: AtomicU64,
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
        get(&self.connect_failures)
    }

    /// Dials rejected with 401 Unauthorized.
    pub fn rejected_unauthorized(&self) -> u64 {
        get(&self.rejected_unauthorized)
    }

    /// Dials rejected with 403 Forbidden.
    pub fn rejected_forbidden(&self) -> u64 {
        get(&self.rejected_forbidden)
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

/// What the next dial waits for.
#[derive(Debug, Default)]
enum Retry {
    /// Nothing: the first dial.
    #[default]
    Now,
    /// This backoff.
    Backoff(Duration),
    /// After a 401: a token other than the refused one.
    NewToken(Option<String>),
}

/// The backoff after a failed dial that waited `wait`: `min` first, then doubling up to
/// `max`.
fn next_backoff(wait: Option<Duration>, min: Duration, max: Duration) -> Duration {
    wait.map_or(min, |wait| wait.saturating_mul(2).min(max))
        .min(max)
}

/// The HTTP status of a refused upgrade that is a rejection (401 or 403).
fn rejection(error: &WsError) -> Option<u16> {
    let WsError::Http(response) = error else {
        return None;
    };
    let status = response.status().as_u16();
    matches!(status, 401 | 403).then_some(status)
}

/// The WebSocket request to `url` with `headers` and, when `token` is set, a bearer
/// `Authorization` header (replacing one in `headers`).
fn request(url: &str, headers: &[(String, String)], token: Option<&str>) -> io::Result<Request> {
    let mut request = url
        .into_client_request()
        .map_err(|e| invalid(format!("invalid WebSocket URL `{url}`: {e}")))?;
    let map = request.headers_mut();
    for (name, value) in headers {
        let header = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| invalid(format!("invalid header name `{name}`: {e}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|e| invalid(format!("invalid value of header `{name}`: {e}")))?;
        map.append(header, value);
    }
    if let Some(token) = token {
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| invalid("invalid bearer token".to_owned()))?;
        value.set_sensitive(true);
        map.insert(AUTHORIZATION, value);
    }
    Ok(request)
}

/// The WebSocket limits of a link.
fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
}

/// Dials the WSS links of a [`LinkTransport`]; see the [crate documentation](crate).
pub struct WssDialer {
    config: WssConfig,
    /// The host and port of the URL, dialed when no connect address is set.
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    tls: TlsConnector,
    stats: Arc<WssStats>,
    state: watch::Sender<LinkState>,
    retry: StdMutex<Retry>,
}

impl fmt::Debug for WssDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WssDialer")
            .field("config", &self.config)
            .field("stats", &self.stats)
            .field("state", &*self.state.borrow())
            .finish_non_exhaustive()
    }
}

impl WssDialer {
    /// A dialer for `config`.
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] on a URL that is not `wss://` with a
    /// host, an invalid server name or header, or TLS roots no configuration can be built
    /// from.
    pub fn new(config: WssConfig) -> io::Result<Self> {
        let probe = request(&config.url, &config.headers, None)?;
        let uri = probe.uri();
        if uri.scheme_str() != Some("wss") {
            return Err(invalid(format!("`{}` is not a wss:// URL", config.url)));
        }
        let host = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| invalid(format!("`{}` has no host", config.url)))?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned();
        let port = uri.port_u16().unwrap_or(443);
        let name = config.server_name.clone().unwrap_or_else(|| host.clone());
        let server_name = ServerName::try_from(name.clone())
            .map_err(|e| invalid(format!("invalid TLS server name `{name}`: {e}")))?;
        let client = match &config.tls {
            WssTls::Roots(roots) => {
                let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
                let client = ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .map_err(|e| invalid(format!("no TLS protocol version: {e}")))?
                    .with_root_certificates(roots.clone())
                    .with_no_client_auth();
                Arc::new(client)
            }
            WssTls::Config(client) => Arc::clone(client),
        };
        Ok(Self {
            config,
            host,
            port,
            server_name,
            tls: TlsConnector::from(client),
            stats: Arc::new(WssStats::default()),
            state: watch::Sender::new(LinkState::Disconnected),
            retry: StdMutex::new(Retry::default()),
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
        self.state.subscribe()
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

    /// The bearer token of the next dial.
    async fn token(&self) -> io::Result<Option<String>> {
        match &self.config.bearer {
            Some(bearer) => bearer.token().await,
            None => Ok(None),
        }
    }

    /// Polls the bearer provider until it yields a token other than `refused`, or
    /// [`WssConfig::token_wait`] passed.
    async fn token_other_than(&self, refused: Option<String>) -> io::Result<Option<String>> {
        let deadline = Instant::now() + self.config.token_wait;
        loop {
            tokio::time::sleep(self.config.token_poll).await;
            let token = self.token().await;
            if Instant::now() >= deadline || !matches!(&token, Ok(token) if *token == refused) {
                return token;
            }
        }
    }

    /// TCP, TLS and the WebSocket upgrade.
    async fn open(&self, token: Option<&str>) -> Result<Ws, WsError> {
        let config = &self.config;
        let request = request(&config.url, &config.headers, token)?;
        let tcp = match config.connect_addr {
            Some(addr) => TcpStream::connect(addr).await?,
            None => TcpStream::connect((self.host.as_str(), self.port)).await?,
        };
        tcp.set_nodelay(true)?;
        let tls = self.tls.connect(self.server_name.clone(), tcp).await?;
        let (ws, _) =
            tokio_tungstenite::client_async_with_config(request, tls, Some(ws_config())).await?;
        Ok(ws)
    }

    /// Records a failed dial that waited `wait` and returns its error.
    fn failed(&self, wait: Option<Duration>, error: &dyn fmt::Display) -> io::Error {
        bump(&self.stats.connect_failures);
        let config = &self.config;
        *lock(&self.retry) =
            Retry::Backoff(next_backoff(wait, config.backoff_min, config.backoff_max));
        tracing::debug!(url = %config.url, %error, "wss connect failed");
        io::Error::other(format!("wss connect failed: {error}"))
    }

    /// Records a dial refused with `status` and returns its error.
    fn rejected(&self, wait: Option<Duration>, status: u16, token: Option<String>) -> io::Error {
        let config = &self.config;
        bump(&self.stats.connect_failures);
        if status == 401 {
            bump(&self.stats.rejected_unauthorized);
        } else {
            bump(&self.stats.rejected_forbidden);
        }
        *lock(&self.retry) = if status == 401 && config.bearer.is_some() {
            // The same token is refused again: wait for a new one instead of backing off.
            Retry::NewToken(token)
        } else {
            Retry::Backoff(next_backoff(wait, config.backoff_min, config.backoff_max))
        };
        self.state.send_replace(LinkState::Rejected(status));
        tracing::warn!(url = %config.url, status, "wss upgrade rejected");
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("wss upgrade rejected with HTTP {status}"),
        )
    }
}

impl LinkDialer for WssDialer {
    fn dial(&self) -> BoxFuture<'_, io::Result<Link>> {
        Box::pin(async move {
            let retry = std::mem::take(&mut *lock(&self.retry));
            let (wait, token) = match retry {
                Retry::Now => (None, self.token().await),
                Retry::Backoff(wait) => {
                    tokio::time::sleep(wait).await;
                    (Some(wait), self.token().await)
                }
                Retry::NewToken(refused) => (None, self.token_other_than(refused).await),
            };
            let token = match token {
                Ok(token) => token,
                Err(e) => return Err(self.failed(wait, &format_args!("bearer token: {e}"))),
            };
            let opened =
                tokio::time::timeout(self.config.connect_timeout, self.open(token.as_deref()))
                    .await;
            let ws = match opened {
                Ok(Ok(ws)) => ws,
                Ok(Err(e)) => {
                    return Err(rejection(&e).map_or_else(
                        || self.failed(wait, &e),
                        |status| self.rejected(wait, status, token),
                    ));
                }
                Err(_) => return Err(self.failed(wait, &"timed out")),
            };
            *lock(&self.retry) = Retry::Backoff(self.config.backoff_min);
            let (sink, stream) = ws.split();
            let sink = Arc::new(Mutex::new(sink));
            let sender = WssSender {
                sink: Arc::clone(&sink),
                stats: Arc::clone(&self.stats),
                pings: tokio::spawn(ping(sink, self.config.ping_interval)),
            };
            let receiver = WssReceiver {
                stream,
                stats: Arc::clone(&self.stats),
                read_idle: self.config.read_idle,
            };
            let link: Link = (Box::new(sender), Box::new(receiver));
            Ok(link)
        })
    }

    fn on_state(&self, state: LinkState) {
        match state {
            LinkState::Connected => {
                self.stats.connected.store(true, Ordering::Relaxed);
                bump(&self.stats.connects);
                tracing::info!(url = %self.config.url, "wss connected");
            }
            LinkState::Disconnected => {
                self.stats.connected.store(false, Ordering::Relaxed);
                tracing::info!(url = %self.config.url, "wss disconnected");
            }
            _ => {}
        }
        self.state.send_replace(state);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::RootCertStore;
    use tokio_tungstenite::tungstenite::http::Response;

    fn roots() -> WssTls {
        WssTls::Roots(RootCertStore::empty())
    }

    /// The backoff doubles from the floor to the cap and then holds, so a link that keeps
    /// failing (a 403 for a pairing the far end has not learned yet, an offline relay)
    /// backs off instead of dialing at the floor forever.
    #[test]
    fn backoff_doubles_to_the_cap_and_holds() {
        let (min, max) = (Duration::from_secs(2), Duration::from_secs(60));
        let mut wait = None;
        let mut seen = Vec::new();
        for _ in 0..9 {
            let next = next_backoff(wait, min, max);
            seen.push(next.as_secs());
            wait = Some(next);
        }
        assert_eq!(seen, [2, 4, 8, 16, 32, 60, 60, 60, 60]);
        assert_eq!(next_backoff(Some(max), min, max), max);
        assert_eq!(next_backoff(Some(Duration::MAX), min, max), max);
        // A floor above the cap is capped.
        assert_eq!(next_backoff(None, max * 2, max), max);
    }

    fn http(status: u16) -> WsError {
        WsError::Http(Box::new(
            Response::builder().status(status).body(None).unwrap(),
        ))
    }

    /// 401 and 403 are rejections, told apart by their status; transport loss and other
    /// statuses are ordinary failures.
    #[test]
    fn rejections_are_told_apart_from_failures() {
        assert_eq!(rejection(&http(401)), Some(401));
        assert_eq!(rejection(&http(403)), Some(403));
        assert_eq!(rejection(&http(500)), None);
        assert_eq!(rejection(&http(404)), None);
        assert_eq!(rejection(&WsError::ConnectionClosed), None);
        assert_eq!(rejection(&WsError::AlreadyClosed), None);
        assert_eq!(
            rejection(&WsError::Io(io::ErrorKind::TimedOut.into())),
            None
        );
    }

    #[test]
    fn requests_carry_headers_and_the_bearer() {
        let headers = [
            ("X-Node".to_owned(), "n1".to_owned()),
            ("Authorization".to_owned(), "Basic old".to_owned()),
        ];
        let req = request("wss://relay.example:8443/wss-relay?a=1", &headers, None).unwrap();
        assert_eq!(req.uri().path(), "/wss-relay");
        assert_eq!(req.headers()["x-node"], "n1");
        assert_eq!(req.headers()[AUTHORIZATION], "Basic old");
        assert!(req.headers().contains_key("sec-websocket-key"));

        let req = request("wss://relay.example/", &headers, Some("t0k")).unwrap();
        let auth: Vec<_> = req.headers().get_all(AUTHORIZATION).iter().collect();
        assert_eq!(auth, ["Bearer t0k"]);
        assert!(auth[0].is_sensitive());

        let bad_name = [("bad name".to_owned(), "v".to_owned())];
        let bad_value = [("X-A".to_owned(), "a\nb".to_owned())];
        for err in [
            request("wss://relay.example/", &bad_name, None).unwrap_err(),
            request("wss://relay.example/", &bad_value, None).unwrap_err(),
            request("wss://relay.example/", &[], Some("a\nb")).unwrap_err(),
            request("not a url", &[], None).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn urls_and_names_are_checked() {
        let dialer = WssDialer::new(WssConfig::new("wss://relay.example:8443/x", roots())).unwrap();
        assert_eq!((dialer.host.as_str(), dialer.port), ("relay.example", 8443));
        assert_eq!(
            dialer.server_name,
            ServerName::try_from("relay.example").unwrap()
        );
        assert_eq!(*dialer.state().borrow(), LinkState::Disconnected);

        let dialer = WssDialer::new(WssConfig::new("wss://[::1]/", roots())).unwrap();
        assert_eq!((dialer.host.as_str(), dialer.port), ("::1", 443));

        let config = WssConfig::new("wss://192.0.2.1/", roots()).server_name("relay.test");
        let dialer = WssDialer::new(config).unwrap();
        assert_eq!(
            dialer.server_name,
            ServerName::try_from("relay.test").unwrap()
        );

        for url in [
            "ws://relay.example/",
            "https://relay.example/",
            "wss:///x",
            "relay",
        ] {
            let err = WssDialer::new(WssConfig::new(url, roots())).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{url}");
        }
        let config = WssConfig::new("wss://relay.example/", roots()).server_name("bad name!");
        assert!(WssDialer::new(config).is_err());
        let config = WssConfig::new("wss://relay.example/", roots()).header("bad name", "v");
        assert!(WssDialer::new(config).is_err());
    }
}
