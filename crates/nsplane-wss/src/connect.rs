//! The connection setup shared by the carriers: URL, TLS, request headers and the bearer,
//! 401/403 classification and the dial backoff.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError};
use std::time::Duration;

use nsplane::LinkState;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::MAX_MESSAGE;
use crate::config::{WssConfig, WssTls};

/// A dialed WSS connection.
pub(crate) type Ws = WebSocketStream<TlsStream<TcpStream>>;

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

/// The WebSocket limits of a connection.
fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
}

/// Dials the WSS connections of one [`WssConfig`], one at a time, with its backoff and
/// rejection handling, and owns the state watch.
pub(crate) struct Connector {
    config: WssConfig,
    /// The host and port of the URL, dialed when no connect address is set.
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    tls: TlsConnector,
    state: watch::Sender<LinkState>,
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
    /// Fails with [`io::ErrorKind::InvalidInput`] on a URL that is not `wss://` with a
    /// host, an invalid server name or header, or TLS roots no configuration can be built
    /// from.
    pub(crate) fn new(config: WssConfig) -> io::Result<Self> {
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
            state: watch::Sender::new(LinkState::Disconnected),
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

    /// Lets the next dial go at once (a dial for more capacity, not after a loss).
    pub(crate) fn retry_now(&self) {
        *lock(&self.retry) = Retry::Now;
    }

    /// Records a lost connection: the next dial waits at least the backoff floor.
    pub(crate) fn lost(&self) {
        let mut retry = lock(&self.retry);
        if matches!(*retry, Retry::Now) {
            *retry = Retry::Backoff(self.config.backoff_min);
        }
    }

    /// Waits as the last dial asks, then dials: TCP, TLS and the WebSocket upgrade. A
    /// success makes the next dial wait the backoff floor; a failure doubles the wait, and a
    /// 401 or 403 also sets [`LinkState::Rejected`].
    pub(crate) async fn connect(&self, counters: &DialCounters) -> io::Result<Ws> {
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
            Err(e) => {
                return Err(self.failed(counters, wait, &format_args!("bearer token: {e}")));
            }
        };
        let opened =
            tokio::time::timeout(self.config.connect_timeout, self.open(token.as_deref())).await;
        match opened {
            Ok(Ok(ws)) => {
                *lock(&self.retry) = Retry::Backoff(self.config.backoff_min);
                Ok(ws)
            }
            Ok(Err(e)) => Err(rejection(&e).map_or_else(
                || self.failed(counters, wait, &e),
                |status| self.rejected(counters, wait, status, token),
            )),
            Err(_) => Err(self.failed(counters, wait, &"timed out")),
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
    fn failed(
        &self,
        counters: &DialCounters,
        wait: Option<Duration>,
        error: &dyn fmt::Display,
    ) -> io::Error {
        bump(&counters.connect_failures);
        let config = &self.config;
        *lock(&self.retry) =
            Retry::Backoff(next_backoff(wait, config.backoff_min, config.backoff_max));
        tracing::debug!(url = %config.url, %error, "wss connect failed");
        io::Error::other(format!("wss connect failed: {error}"))
    }

    /// Records a dial refused with `status` and returns its error.
    fn rejected(
        &self,
        counters: &DialCounters,
        wait: Option<Duration>,
        status: u16,
        token: Option<String>,
    ) -> io::Error {
        let config = &self.config;
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
        tracing::warn!(url = %config.url, status, "wss upgrade rejected");
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("wss upgrade rejected with HTTP {status}"),
        )
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
        let connector =
            Connector::new(WssConfig::new("wss://relay.example:8443/x", roots())).unwrap();
        assert_eq!(
            (connector.host.as_str(), connector.port),
            ("relay.example", 8443)
        );
        assert_eq!(
            connector.server_name,
            ServerName::try_from("relay.example").unwrap()
        );
        assert_eq!(*connector.state().borrow(), LinkState::Disconnected);

        let connector = Connector::new(WssConfig::new("wss://[::1]/", roots())).unwrap();
        assert_eq!((connector.host.as_str(), connector.port), ("::1", 443));

        let config = WssConfig::new("wss://192.0.2.1/", roots()).server_name("relay.test");
        let connector = Connector::new(config).unwrap();
        assert_eq!(
            connector.server_name,
            ServerName::try_from("relay.test").unwrap()
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
        let config = WssConfig::new("wss://relay.example/", roots()).server_name("bad name!");
        assert!(Connector::new(config).is_err());
        let config = WssConfig::new("wss://relay.example/", roots()).header("bad name", "v");
        assert!(Connector::new(config).is_err());
    }
}
