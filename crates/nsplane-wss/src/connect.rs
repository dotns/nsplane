//! The connection setup shared by the carriers: URL, TLS, request headers and the bearer,
//! 401/403 classification, the dial backoff and the dial events.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use nsplane::LinkState;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, watch};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::handshake::client::{Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::MAX_MESSAGE;
use crate::config::{WssConfig, WssTls};

/// A dialed WebSocket connection.
pub(crate) type Ws = WebSocketStream<Carrier>;

/// The byte stream under a WebSocket connection: TLS for `wss://`, plain TCP for `ws://`.
/// The TLS stream is boxed (once per dial) to keep the plain variant small.
pub(crate) enum Carrier {
    Tls(Box<TlsStream<TcpStream>>),
    Plain(TcpStream),
}

impl AsyncRead for Carrier {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Carrier {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tls(stream) => stream.is_write_vectored(),
            Self::Plain(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A WebSocket upgrade refused with an HTTP response: the inner error of the
/// [`io::Error`] a failed dial returns, reached with
/// `error.get_ref().and_then(|e| e.downcast_ref::<WssDialError>())`.
///
/// Its message is the dial error's: `wss upgrade rejected with HTTP <status>` for a 401 or
/// 403 (an [`io::ErrorKind::PermissionDenied`] error), `wss connect failed: HTTP error:
/// <status>` for any other status (an [`io::ErrorKind::Other`] error).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WssDialError {
    /// The HTTP status of the response.
    pub status: u16,
    /// The response headers, as name and value, in order; a value that is not UTF-8 is
    /// converted lossily.
    pub headers: Vec<(String, String)>,
    /// The start of the response body: the bytes that arrived with the response head, at
    /// most [`MAX_BODY`](Self::MAX_BODY).
    pub body: Bytes,
}

impl WssDialError {
    /// The most body bytes kept.
    pub const MAX_BODY: usize = 512;

    fn new(response: &Response) -> Self {
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
                (name.as_str().to_owned(), value)
            })
            .collect();
        let body = response.body().as_deref().unwrap_or_default();
        Self {
            status: response.status().as_u16(),
            headers,
            body: Bytes::copy_from_slice(&body[..body.len().min(Self::MAX_BODY)]),
        }
    }
}

impl fmt::Display for WssDialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if is_rejection(self.status) {
            return write!(f, "wss upgrade rejected with HTTP {}", self.status);
        }
        match StatusCode::from_u16(self.status) {
            Ok(status) => write!(f, "wss connect failed: HTTP error: {status}"),
            Err(_) => write!(f, "wss connect failed: HTTP error: {}", self.status),
        }
    }
}

impl std::error::Error for WssDialError {}

/// One dial or connection of a [`WssDialer`](crate::WssDialer) or a
/// [`WssStreamClient`](crate::WssStreamClient), as their `events()` receivers see it: one
/// event per occurrence.
///
/// Events go out on a [`broadcast`] channel of [`CAPACITY`](Self::CAPACITY) events; a
/// receiver that falls further behind loses the oldest ones and sees
/// [`RecvError::Lagged`](broadcast::error::RecvError::Lagged) with their count. Without a
/// receiver, nothing is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WssDialEvent {
    /// A link or session came up.
    Connected,
    /// A link or session that came up ended: closed, failed, or silent past
    /// [`WssConfig::read_idle`].
    Lost,
    /// A dial failed: TCP, TLS, the bearer token, or an upgrade refused with an HTTP status
    /// other than 401 and 403.
    DialFailed,
    /// A dial did not finish within [`WssConfig::connect_timeout`].
    TimedOut,
    /// A dial was refused with this HTTP status, 401 or 403.
    Rejected(u16),
}

impl WssDialEvent {
    /// How many events a receiver may fall behind before it loses the oldest.
    pub const CAPACITY: usize = 64;
}

/// Locks `mutex`, ignoring poisoning: the guarded state stays consistent.
pub(crate) fn lock<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn add(counter: &AtomicU64, n: usize) {
    counter.fetch_add(n as u64, Ordering::Relaxed);
}

pub(crate) fn get(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

pub(crate) fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// The dial counters every carrier reports.
#[derive(Debug, Default)]
pub(crate) struct DialCounters {
    pub(crate) connect_failures: AtomicU64,
    pub(crate) rejected_unauthorized: AtomicU64,
    pub(crate) rejected_forbidden: AtomicU64,
}

/// What the next dial waits for.
#[derive(Debug, Default)]
enum Retry {
    /// Nothing: the first dial.
    #[default]
    Now,
    /// This backoff.
    Backoff(Duration),
    /// After a connection that came up: [`WssConfig::reconnect_delay`]; a dial failing
    /// after it backs off from the floor.
    Reconnect(Duration),
    /// After a 401: a token other than the refused one.
    NewToken(Option<String>),
}

/// The backoff after a failed dial that waited `wait`: `min` first, then doubling up to
/// `max`.
fn next_backoff(wait: Option<Duration>, min: Duration, max: Duration) -> Duration {
    wait.map_or(min, |wait| wait.saturating_mul(2).min(max))
        .min(max)
}

/// The detail of an upgrade refused with an HTTP response.
fn refusal(error: &WsError) -> Option<WssDialError> {
    let WsError::Http(response) = error else {
        return None;
    };
    Some(WssDialError::new(response))
}

/// Whether a refusal with `status` is a rejection (401 or 403).
const fn is_rejection(status: u16) -> bool {
    matches!(status, 401 | 403)
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

/// The WebSocket limits of a connection.
fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
}

/// Dials the WSS connections of one [`WssConfig`], one at a time, with its backoff and
/// rejection handling, and owns the state watch and the dial events.
pub(crate) struct Connector {
    config: WssConfig,
    /// The host and port of the URL, dialed when no connect address is set.
    host: String,
    port: u16,
    /// The TLS client and server name of a `wss://` URL; `None` for `ws://`.
    tls: Option<(TlsConnector, ServerName<'static>)>,
    state: watch::Sender<LinkState>,
    events: broadcast::Sender<WssDialEvent>,
    retry: StdMutex<Retry>,
}

impl fmt::Debug for Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connector")
            .field("config", &self.config)
            .field("state", &*self.state.borrow())
            .finish_non_exhaustive()
    }
}

impl Connector {
    /// A connector for `config`.
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] on a URL that is not `wss://` (or `ws://`
    /// with [`WssConfig::allow_plaintext`]) with a host, an invalid server name or header,
    /// or TLS roots no configuration can be built from.
    pub(crate) fn new(config: WssConfig) -> io::Result<Self> {
        let probe = request(&config.url, &config.headers, None)?;
        let uri = probe.uri();
        let secure = match uri.scheme_str() {
            Some("wss") => true,
            Some("ws") if config.allow_plaintext => false,
            Some("ws") => {
                return Err(invalid(format!(
                    "`{}` is a ws:// URL, but allow_plaintext is not set",
                    config.url
                )));
            }
            _ if config.allow_plaintext => {
                return Err(invalid(format!(
                    "`{}` is not a wss:// or ws:// URL",
                    config.url
                )));
            }
            _ => return Err(invalid(format!("`{}` is not a wss:// URL", config.url))),
        };
        let host = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| invalid(format!("`{}` has no host", config.url)))?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned();
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
        let tls = if secure {
            Some(tls(&config, &host)?)
        } else {
            None
        };
        Ok(Self {
            config,
            host,
            port,
            tls,
            state: watch::Sender::new(LinkState::Disconnected),
            events: broadcast::Sender::new(WssDialEvent::CAPACITY),
            retry: StdMutex::new(Retry::default()),
        })
    }

    pub(crate) const fn config(&self) -> &WssConfig {
        &self.config
    }

    /// Watches the state: [`LinkState::Disconnected`] at first.
    pub(crate) fn state(&self) -> watch::Receiver<LinkState> {
        self.state.subscribe()
    }

    pub(crate) fn set_state(&self, state: LinkState) {
        self.state.send_replace(state);
    }

    /// Receives the dial events from now on.
    pub(crate) fn events(&self) -> broadcast::Receiver<WssDialEvent> {
        self.events.subscribe()
    }

    /// Sends `event` to the event receivers, if any.
    pub(crate) fn emit(&self, event: WssDialEvent) {
        let _ = self.events.send(event);
    }

    /// The wait before the dial after a connection that came up: the reconnect delay, or
    /// without one the backoff floor (the first step of the failure backoff).
    fn reconnect(&self) -> Retry {
        self.config
            .reconnect_delay
            .map_or(Retry::Backoff(self.config.backoff_min), Retry::Reconnect)
    }

    /// Lets the next dial go at once (a dial for more capacity, not after a loss).
    pub(crate) fn retry_now(&self) {
        *lock(&self.retry) = Retry::Now;
    }

    /// Records a lost connection: the next dial waits the reconnect delay, or the backoff
    /// floor without one, unless it already waits.
    pub(crate) fn lost(&self) {
        let mut retry = lock(&self.retry);
        if matches!(*retry, Retry::Now) {
            *retry = self.reconnect();
        }
    }

    /// Waits as the last dial asks, then dials: TCP, TLS (for `wss://`) and the WebSocket
    /// upgrade. A success makes the next dial wait the reconnect delay (or the backoff
    /// floor); a failure doubles the wait, starting from the floor, and a 401 or 403 also
    /// sets [`LinkState::Rejected`]. An upgrade refused with an HTTP response fails with a
    /// [`WssDialError`] inside. Every failure sends its event; the carriers send
    /// [`WssDialEvent::Connected`] themselves.
    pub(crate) async fn connect(&self, counters: &DialCounters) -> io::Result<Ws> {
        let retry = std::mem::take(&mut *lock(&self.retry));
        let (wait, token) = match retry {
            Retry::Now => (None, self.token().await),
            Retry::Backoff(wait) => {
                tokio::time::sleep(wait).await;
                (Some(wait), self.token().await)
            }
            Retry::Reconnect(delay) => {
                tokio::time::sleep(delay).await;
                (None, self.token().await)
            }
            Retry::NewToken(refused) => (None, self.token_other_than(refused).await),
        };
        let token = match token {
            Ok(token) => token,
            Err(e) => {
                let error = format_args!("bearer token: {e}");
                return Err(self.failed(counters, wait, &error, WssDialEvent::DialFailed));
            }
        };
        let opened =
            tokio::time::timeout(self.config.connect_timeout, self.open(token.as_deref())).await;
        match opened {
            Ok(Ok(ws)) => {
                *lock(&self.retry) = self.reconnect();
                Ok(ws)
            }
            Ok(Err(e)) => Err(match refusal(&e) {
                Some(detail) if is_rejection(detail.status) => {
                    self.rejected(counters, wait, detail, token)
                }
                Some(detail) => {
                    self.count_failure(counters, wait, &e, WssDialEvent::DialFailed);
                    io::Error::other(detail)
                }
                None => self.failed(counters, wait, &e, WssDialEvent::DialFailed),
            }),
            Err(_) => Err(self.failed(counters, wait, &"timed out", WssDialEvent::TimedOut)),
        }
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

    /// TCP, TLS (for `wss://`) and the WebSocket upgrade.
    async fn open(&self, token: Option<&str>) -> Result<Ws, WsError> {
        let config = &self.config;
        let request = request(&config.url, &config.headers, token)?;
        let tcp = match config.connect_addr {
            Some(addr) => TcpStream::connect(addr).await?,
            None => TcpStream::connect((self.host.as_str(), self.port)).await?,
        };
        tcp.set_nodelay(true)?;
        let stream = match &self.tls {
            Some((tls, name)) => Carrier::Tls(Box::new(tls.connect(name.clone(), tcp).await?)),
            None => Carrier::Plain(tcp),
        };
        let (ws, _) =
            tokio_tungstenite::client_async_with_config(request, stream, Some(ws_config())).await?;
        Ok(ws)
    }

    /// Records a failed dial that waited `wait`, sends `event` and returns its error.
    fn failed(
        &self,
        counters: &DialCounters,
        wait: Option<Duration>,
        error: &dyn fmt::Display,
        event: WssDialEvent,
    ) -> io::Error {
        self.count_failure(counters, wait, error, event);
        io::Error::other(format!("wss connect failed: {error}"))
    }

    /// Records a failed dial that waited `wait` and sends `event`.
    fn count_failure(
        &self,
        counters: &DialCounters,
        wait: Option<Duration>,
        error: &dyn fmt::Display,
        event: WssDialEvent,
    ) {
        bump(&counters.connect_failures);
        self.emit(event);
        let config = &self.config;
        *lock(&self.retry) =
            Retry::Backoff(next_backoff(wait, config.backoff_min, config.backoff_max));
        tracing::debug!(url = %config.url, %error, "wss connect failed");
    }

    /// Records a dial refused with a 401 or 403 and returns its error.
    fn rejected(
        &self,
        counters: &DialCounters,
        wait: Option<Duration>,
        detail: WssDialError,
        token: Option<String>,
    ) -> io::Error {
        let config = &self.config;
        let status = detail.status;
        bump(&counters.connect_failures);
        if status == 401 {
            bump(&counters.rejected_unauthorized);
        } else {
            bump(&counters.rejected_forbidden);
        }
        *lock(&self.retry) = if status == 401 && config.bearer.is_some() {
            // The same token is refused again: wait for a new one instead of backing off.
            Retry::NewToken(token)
        } else {
            Retry::Backoff(next_backoff(wait, config.backoff_min, config.backoff_max))
        };
        self.state.send_replace(LinkState::Rejected(status));
        self.emit(WssDialEvent::Rejected(status));
        tracing::warn!(url = %config.url, status, "wss upgrade rejected");
        io::Error::new(io::ErrorKind::PermissionDenied, detail)
    }
}

/// The TLS client and server name dialing `host` with `config`.
fn tls(config: &WssConfig, host: &str) -> io::Result<(TlsConnector, ServerName<'static>)> {
    let name = config
        .server_name
        .clone()
        .unwrap_or_else(|| host.to_owned());
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
    Ok((TlsConnector::from(client), server_name))
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

    /// A lost connection only raises an immediate retry to the floor; a longer failure
    /// backoff stays.
    #[test]
    fn loss_waits_at_least_the_floor() {
        let connector = Connector::new(WssConfig::new("wss://relay.example/", roots())).unwrap();
        connector.retry_now();
        connector.lost();
        assert!(
            matches!(*lock(&connector.retry), Retry::Backoff(wait) if wait == Duration::from_secs(2))
        );
        *lock(&connector.retry) = Retry::Backoff(Duration::from_secs(8));
        connector.lost();
        assert!(
            matches!(*lock(&connector.retry), Retry::Backoff(wait) if wait == Duration::from_secs(8))
        );
    }

    /// A loss after a session came up waits the reconnect delay (when set), and a dial
    /// failing after it backs off from the floor rather than from that delay; capacity
    /// dials still go at once. Each failure is one event.
    #[tokio::test]
    async fn reconnect_delay_then_failures_back_off_from_the_floor() {
        let ms = Duration::from_millis;
        // A port nothing listens on: every dial is refused at once.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let config = WssConfig::new(format!("ws://{addr}/"), roots())
            .allow_plaintext(true)
            .backoff(ms(10), ms(40))
            .reconnect_delay(ms(5));
        let connector = Connector::new(config).unwrap();
        let mut events = connector.events();
        let retry = || match *lock(&connector.retry) {
            Retry::Now => "now".to_owned(),
            Retry::Backoff(wait) => format!("backoff {}", wait.as_millis()),
            Retry::Reconnect(delay) => format!("reconnect {}", delay.as_millis()),
            Retry::NewToken(_) => "token".to_owned(),
        };
        connector.lost();
        assert_eq!(retry(), "reconnect 5");
        // A further loss keeps the pending wait.
        connector.lost();
        assert_eq!(retry(), "reconnect 5");

        let counters = DialCounters::default();
        let mut seen = Vec::new();
        for _ in 0..4 {
            assert!(connector.connect(&counters).await.is_err());
            seen.push(retry());
            assert_eq!(events.try_recv(), Ok(WssDialEvent::DialFailed));
        }
        assert_eq!(
            seen,
            ["backoff 10", "backoff 20", "backoff 40", "backoff 40"]
        );
        assert!(events.try_recv().is_err());
        assert_eq!(get(&counters.connect_failures), 4);

        // A capacity dial goes at once, and a loss then waits the reconnect delay again.
        connector.retry_now();
        assert_eq!(retry(), "now");
        connector.lost();
        assert_eq!(retry(), "reconnect 5");
    }

    fn http(status: u16) -> WsError {
        WsError::Http(Box::new(
            Response::builder().status(status).body(None).unwrap(),
        ))
    }

    /// The status of a refusal with an HTTP response, if it is a rejection.
    fn rejection(error: &WsError) -> Option<u16> {
        refusal(error)
            .map(|detail| detail.status)
            .filter(|&status| is_rejection(status))
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
        assert!(refusal(&WsError::ConnectionClosed).is_none());
        assert_eq!(refusal(&http(500)).map(|detail| detail.status), Some(500));
    }

    /// Every refusal keeps its status, headers (non-UTF-8 values lossily) and the body up
    /// to the limit; its message is the dial error's of before.
    #[test]
    fn refusals_keep_their_detail() {
        let body = vec![b'x'; WssDialError::MAX_BODY + 100];
        let response = Response::builder()
            .status(401)
            .header("X-Reason", "expired")
            .header("X-Raw", HeaderValue::from_bytes(b"a\xffb").unwrap())
            .body(Some(body.clone()))
            .unwrap();
        let detail = refusal(&WsError::Http(Box::new(response))).unwrap();
        assert_eq!(detail.status, 401);
        assert_eq!(
            detail.headers,
            [
                ("x-reason".to_owned(), "expired".to_owned()),
                ("x-raw".to_owned(), "a\u{fffd}b".to_owned()),
            ]
        );
        assert_eq!(detail.body, body[..WssDialError::MAX_BODY]);
        assert_eq!(detail.to_string(), "wss upgrade rejected with HTTP 401");

        let short = Response::builder()
            .status(503)
            .body(Some(b"busy".to_vec()))
            .unwrap();
        let detail = refusal(&WsError::Http(Box::new(short))).unwrap();
        assert_eq!(detail.body, &b"busy"[..]);
        assert_eq!(
            detail.to_string(),
            "wss connect failed: HTTP error: 503 Service Unavailable"
        );
        assert_eq!(
            detail.to_string(),
            format!("wss connect failed: {}", http(503))
        );
        let detail = refusal(&http(403)).unwrap();
        assert!(detail.headers.is_empty() && detail.body.is_empty());
        assert_eq!(detail.to_string(), "wss upgrade rejected with HTTP 403");
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
        let connector =
            Connector::new(WssConfig::new("wss://relay.example:8443/x", roots())).unwrap();
        assert_eq!(
            (connector.host.as_str(), connector.port),
            ("relay.example", 8443)
        );
        assert_eq!(
            connector.tls.as_ref().map(|(_, name)| name.clone()),
            Some(ServerName::try_from("relay.example").unwrap())
        );
        assert_eq!(*connector.state().borrow(), LinkState::Disconnected);

        let connector = Connector::new(WssConfig::new("wss://[::1]/", roots())).unwrap();
        assert_eq!((connector.host.as_str(), connector.port), ("::1", 443));

        let config = WssConfig::new("wss://192.0.2.1/", roots()).server_name("relay.test");
        let connector = Connector::new(config).unwrap();
        assert_eq!(
            connector.tls.as_ref().map(|(_, name)| name.clone()),
            Some(ServerName::try_from("relay.test").unwrap())
        );

        for url in [
            "ws://relay.example/",
            "https://relay.example/",
            "wss:///x",
            "relay",
        ] {
            let err = Connector::new(WssConfig::new(url, roots())).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{url}");
        }
        let err = Connector::new(WssConfig::new("ws://relay.example/", roots())).unwrap_err();
        assert!(err.to_string().contains("allow_plaintext"), "{err}");
        let config = WssConfig::new("wss://relay.example/", roots()).server_name("bad name!");
        assert!(Connector::new(config).is_err());
        let config = WssConfig::new("wss://relay.example/", roots()).header("bad name", "v");
        assert!(Connector::new(config).is_err());
    }

    /// `ws://` is dialed without TLS (port 80 unless given) only with `allow_plaintext`;
    /// `wss://` stays TLS and other schemes stay refused.
    #[test]
    fn plain_urls_need_allow_plaintext() {
        let plain = |url: &str| Connector::new(WssConfig::new(url, roots()).allow_plaintext(true));
        let connector = plain("ws://relay.example/x").unwrap();
        assert_eq!(
            (connector.host.as_str(), connector.port),
            ("relay.example", 80)
        );
        assert!(connector.tls.is_none());
        let connector = plain("ws://127.0.0.1:8080/x").unwrap();
        assert_eq!(
            (connector.host.as_str(), connector.port),
            ("127.0.0.1", 8080)
        );
        // The server name is a TLS setting: unused, so unchecked, for ws://.
        let config = WssConfig::new("ws://[::1]/", roots())
            .allow_plaintext(true)
            .server_name("bad name!");
        let connector = Connector::new(config).unwrap();
        assert_eq!((connector.host.as_str(), connector.port), ("::1", 80));

        let connector = plain("wss://relay.example/").unwrap();
        assert_eq!(connector.port, 443);
        assert!(connector.tls.is_some());

        for url in [
            "https://relay.example/",
            "http://relay.example/",
            "ws:///x",
            "relay",
        ] {
            let err = plain(url).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{url}");
        }
    }
}
