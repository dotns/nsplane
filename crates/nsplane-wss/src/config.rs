//! The settings of a [`WssDialer`](crate::WssDialer) or a
//! [`WssStreamClient`](crate::WssStreamClient).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nsplane::BoxFuture;
use rustls::{ClientConfig, RootCertStore};

/// Supplies the bearer token of each dial.
pub trait BearerProvider: Send + Sync + 'static {
    /// The token for the next dial: sent as `Authorization: Bearer <token>`; `None` sends
    /// no `Authorization` header. Called once per dial, and every
    /// [`WssConfig::token_poll`] while waiting for a new token after a 401. An error fails
    /// the dial, which then backs off.
    fn token(&self) -> BoxFuture<'_, io::Result<Option<String>>>;
}

/// The TLS trust of a [`WssDialer`](crate::WssDialer) or a
/// [`WssStreamClient`](crate::WssStreamClient).
///
/// No system or web PKI roots are bundled: the caller supplies what to trust, as a root
/// store or a complete client configuration, for instance with the aws-lc-rs provider:
///
/// ```
/// use std::sync::Arc;
///
/// use nsplane_wss::{WssConfig, WssTls};
///
/// # fn config(roots: rustls::RootCertStore) -> Result<WssConfig, rustls::Error> {
/// let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
/// let client = rustls::ClientConfig::builder_with_provider(provider)
///     .with_safe_default_protocol_versions()?
///     .with_root_certificates(roots)
///     .with_no_client_auth();
/// let config = WssConfig::new("wss://relay.example/wss-relay", WssTls::Config(Arc::new(client)));
/// # Ok(config)
/// # }
/// # config(rustls::RootCertStore::empty()).unwrap();
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WssTls {
    /// Trusts these roots; the client configuration is built with the aws-lc-rs provider,
    /// the safe default protocol versions and no client authentication.
    Roots(RootCertStore),
    /// This client configuration, used as is (its ALPN protocols included).
    Config(Arc<ClientConfig>),
}

/// Where and how a [`WssDialer`](crate::WssDialer) or a
/// [`WssStreamClient`](crate::WssStreamClient) connects.
#[derive(Clone)]
#[non_exhaustive]
pub struct WssConfig {
    /// The `wss://` URL of the WebSocket request, or a `ws://` one when
    /// [`allow_plaintext`](Self::allow_plaintext) is set.
    pub url: String,
    /// Accepts a `ws://` URL: dialed over plain TCP (port 80 by default), without TLS, so
    /// [`server_name`](Self::server_name) and [`tls`](Self::tls) go unused. `false` (the
    /// default) accepts `wss://` only.
    pub allow_plaintext: bool,
    /// Where to connect; `None` (the default) resolves the URL's host.
    pub connect_addr: Option<SocketAddr>,
    /// The TLS server name (SNI and the name the certificate must carry); `None` (the
    /// default) is the URL's host.
    pub server_name: Option<String>,
    /// The TLS trust.
    pub tls: WssTls,
    /// Extra request headers, as name and value; none by default.
    pub headers: Vec<(String, String)>,
    /// The bearer token source; `None` (the default) sends no `Authorization` header but
    /// one in [`headers`](Self::headers).
    pub bearer: Option<Arc<dyn BearerProvider>>,
    /// The wait before a dial after a link that came up, and after the first failed dial;
    /// it doubles after each further failure. 2 s by default.
    pub backoff_min: Duration,
    /// The longest wait before a dial. 60 s by default.
    pub backoff_max: Duration,
    /// How often the bearer provider is asked for a new token after a 401. 2 s by default.
    pub token_poll: Duration,
    /// How long to wait for a new token after a 401 before dialing with the old one.
    /// 300 s by default.
    pub token_wait: Duration,
    /// The interval of keepalive pings. 10 s by default.
    pub ping_interval: Duration,
    /// Ends the link when no frame at all (pongs included) arrived for this long. 35 s by
    /// default.
    pub read_idle: Duration,
    /// The time a dial (TCP, TLS and the WebSocket upgrade) may take. 10 s by default.
    pub connect_timeout: Duration,
}

impl WssConfig {
    /// The default settings for `url`, trusting `tls`.
    pub fn new(url: impl Into<String>, tls: WssTls) -> Self {
        Self {
            url: url.into(),
            allow_plaintext: false,
            connect_addr: None,
            server_name: None,
            tls,
            headers: Vec::new(),
            bearer: None,
            backoff_min: Duration::from_secs(2),
            backoff_max: Duration::from_secs(60),
            token_poll: Duration::from_secs(2),
            token_wait: Duration::from_secs(300),
            ping_interval: Duration::from_secs(10),
            read_idle: Duration::from_secs(35),
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Sets [`allow_plaintext`](Self::allow_plaintext).
    #[must_use]
    pub const fn allow_plaintext(mut self, allow: bool) -> Self {
        self.allow_plaintext = allow;
        self
    }

    /// Sets [`connect_addr`](Self::connect_addr).
    #[must_use]
    pub const fn connect_addr(mut self, addr: SocketAddr) -> Self {
        self.connect_addr = Some(addr);
        self
    }

    /// Sets [`server_name`](Self::server_name).
    #[must_use]
    pub fn server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Adds a request header to [`headers`](Self::headers).
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets [`bearer`](Self::bearer).
    #[must_use]
    pub fn bearer(mut self, provider: Arc<dyn BearerProvider>) -> Self {
        self.bearer = Some(provider);
        self
    }

    /// Sets [`backoff_min`](Self::backoff_min) and [`backoff_max`](Self::backoff_max).
    #[must_use]
    pub const fn backoff(mut self, min: Duration, max: Duration) -> Self {
        self.backoff_min = min;
        self.backoff_max = max;
        self
    }

    /// Sets [`token_poll`](Self::token_poll) and [`token_wait`](Self::token_wait).
    #[must_use]
    pub const fn token_refresh(mut self, poll: Duration, wait: Duration) -> Self {
        self.token_poll = poll;
        self.token_wait = wait;
        self
    }

    /// Sets [`ping_interval`](Self::ping_interval) and [`read_idle`](Self::read_idle).
    #[must_use]
    pub const fn keepalive(mut self, ping_interval: Duration, read_idle: Duration) -> Self {
        self.ping_interval = ping_interval;
        self.read_idle = read_idle;
        self
    }

    /// Sets [`connect_timeout`](Self::connect_timeout).
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
}

impl fmt::Debug for WssConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("WssConfig")
            .field("url", &self.url)
            .field("allow_plaintext", &self.allow_plaintext)
            .field("connect_addr", &self.connect_addr)
            .field("server_name", &self.server_name)
            .field("tls", &self.tls)
            .field("headers", &headers)
            .field("bearer", &self.bearer.is_some())
            .field("backoff_min", &self.backoff_min)
            .field("backoff_max", &self.backoff_max)
            .field("token_poll", &self.token_poll)
            .field("token_wait", &self.token_wait)
            .field("ping_interval", &self.ping_interval)
            .field("read_idle", &self.read_idle)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config = WssConfig::new(
            "wss://relay.example/",
            WssTls::Roots(RootCertStore::empty()),
        );
        assert_eq!(config.url, "wss://relay.example/");
        assert!(!config.allow_plaintext);
        assert_eq!(config.connect_addr, None);
        assert_eq!(config.server_name, None);
        assert_eq!(config.headers.len(), 0);
        assert!(config.bearer.is_none());
        assert_eq!(config.backoff_min, Duration::from_secs(2));
        assert_eq!(config.backoff_max, Duration::from_secs(60));
        assert_eq!(config.token_poll, Duration::from_secs(2));
        assert_eq!(config.token_wait, Duration::from_secs(300));
        assert_eq!(config.ping_interval, Duration::from_secs(10));
        assert_eq!(config.read_idle, Duration::from_secs(35));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));

        let ms = Duration::from_millis;
        let config = config
            .allow_plaintext(true)
            .connect_addr("127.0.0.1:9".parse().unwrap())
            .server_name("relay.test")
            .header("X-A", "1")
            .backoff(ms(1), ms(2))
            .token_refresh(ms(3), ms(4))
            .keepalive(ms(5), ms(6))
            .connect_timeout(ms(7));
        assert!(config.allow_plaintext);
        assert_eq!(config.connect_addr, Some("127.0.0.1:9".parse().unwrap()));
        assert_eq!(config.server_name.as_deref(), Some("relay.test"));
        assert_eq!(config.headers, [("X-A".to_owned(), "1".to_owned())]);
        assert_eq!((config.backoff_min, config.backoff_max), (ms(1), ms(2)));
        assert_eq!((config.token_poll, config.token_wait), (ms(3), ms(4)));
        assert_eq!((config.ping_interval, config.read_idle), (ms(5), ms(6)));
        assert_eq!(config.connect_timeout, ms(7));
        // Header values (tokens, say) stay out of the debug output.
        let config = config.header("X-Secret", "hidden");
        assert!(!format!("{config:?}").contains("hidden"));
    }
}
