#![forbid(unsafe_code)]

//! WebSocket-over-TLS (WSS) carriers for nsplane.
//!
//! The carriers share one connection setup ([`WssConfig`]):
//!
//! - [`WssDialer`], the datagram carrier for [`LinkTransport`](nsplane::LinkTransport),
//!   below.
//! - [`WssStreamClient`], the stream carrier: TCP streams ([`WssTcpStream`]) and UDP flows
//!   ([`WssUdpFlow`]) to targets behind a WSS terminate, multiplexed over sessions with the
//!   `WsFrame` protocol of the [`frame`] module (the wire of ns and NSGW).
//! - [`WssStreamServer`], the terminate leg of that protocol: it dials the relay too and
//!   relays each opened stream to the backend a [`WssResolver`] picks.
//!
//! [`WssDialer`] is a [`LinkDialer`](nsplane::LinkDialer) for
//! [`LinkTransport`](nsplane::LinkTransport): each link is one WSS connection, and each
//! datagram is one binary WebSocket message carrying its raw bytes (no framing).
//!
//! - **Dialing**: TCP, TLS (rustls with the aws-lc-rs provider) and the WebSocket upgrade,
//!   within [`WssConfig::connect_timeout`]. The request carries the extra
//!   [`headers`](WssConfig::headers) and, when a [`BearerProvider`] is set, an
//!   `Authorization: Bearer <token>` header with a token fetched for that dial. A `ws://`
//!   URL is dialed the same way without TLS (port 80 by default), but only with
//!   [`WssConfig::allow_plaintext`] set; otherwise it is refused like any non-`wss://` URL.
//! - **Rejections**: an upgrade answered with an HTTP response (any status but 101) fails
//!   the dial with a [`WssDialError`] inside the [`std::io::Error`]: the status, the
//!   response headers and the start of the body (at most [`WssDialError::MAX_BODY`]
//!   bytes). One answered with 401 or 403 is also reported as
//!   [`LinkState::Rejected`](nsplane::LinkState::Rejected) on the
//!   [state watch](WssDialer::state). After a 401 the next dial waits until the provider
//!   yields a different token (polled every [`WssConfig::token_poll`], at most
//!   [`WssConfig::token_wait`]), since the same token would be refused again; a 403, and a
//!   401 without a bearer provider, back off like any other failure.
//! - **Backoff**: every dial but the first waits: [`WssConfig::backoff_min`] after a link
//!   that came up, doubled after each failed dial up to [`WssConfig::backoff_max`].
//! - **Keepalive**: the sending half pings every [`WssConfig::ping_interval`]; the
//!   receiving half ends the link when no frame at all (pongs included) arrived for
//!   [`WssConfig::read_idle`].
//! - **Messages**: text messages and binary messages longer than [`MAX_DATAGRAM`] are
//!   dropped and counted; a close frame or the end of the stream ends the link.
//!
//! TLS trust is the caller's: [`WssTls::Roots`] with the certificates to trust, or a
//! complete [`rustls::ClientConfig`] in [`WssTls::Config`] (see there for building one
//! with the aws-lc-rs provider). This crate bundles no system or web PKI roots.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use nsplane::{LinkConfig, TransportId};
//! use nsplane_wss::{WssConfig, WssDialer, WssTls};
//!
//! # fn run(roots: rustls::RootCertStore) -> std::io::Result<()> {
//! let config = WssConfig::new("wss://relay.example/wss-relay", WssTls::Roots(roots))
//!     .header("X-Node", "n1");
//! let dialer = WssDialer::new(config)?;
//! let stats = dialer.stats();
//! let mut state = dialer.state();
//! let transport =
//!     dialer.into_transport(TransportId::new(2), "192.0.2.1:443".parse().unwrap(), LinkConfig::default());
//! # Ok(())
//! # }
//! ```
//!
//! The stream carrier on the same kind of configuration:
//!
//! ```no_run
//! use nsplane_wss::{WssConfig, WssStreamClient, WssStreamLimits, WssTls};
//! use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
//!
//! # async fn run(roots: rustls::RootCertStore) -> std::io::Result<()> {
//! let config = WssConfig::new("wss://gateway.example/client", WssTls::Roots(roots));
//! let client = WssStreamClient::new(config, WssStreamLimits::default())?;
//!
//! let mut stream = client.open_tcp("10.0.0.2:80".parse().unwrap()).await?;
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
//! stream.shutdown().await?;
//! let mut reply = Vec::new();
//! stream.read_to_end(&mut reply).await?;
//!
//! let mut dns = client.open_udp("10.0.0.2:53".parse().unwrap()).await?;
//! dns.send(b"query").await?;
//! let answer = dns.recv().await?;
//! # Ok(())
//! # }
//! ```
//!
//! The terminate leg, on its own configuration:
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//!
//! use nsplane::BoxFuture;
//! use nsplane_wss::{
//!     Denied, WssConfig, WssOpen, WssResolver, WssServerLimits, WssStreamServer, WssTls,
//! };
//!
//! /// Serves only port 80, on a local backend.
//! struct Web;
//!
//! impl WssResolver for Web {
//!     fn resolve(&self, open: WssOpen) -> BoxFuture<'_, Result<SocketAddr, Denied>> {
//!         let backend = if open.target.port() == 80 {
//!             Ok(SocketAddr::from(([127, 0, 0, 1], 8080)))
//!         } else {
//!             Err(Denied)
//!         };
//!         Box::pin(std::future::ready(backend))
//!     }
//! }
//!
//! # async fn run(roots: rustls::RootCertStore) -> std::io::Result<()> {
//! let config = WssConfig::new("wss://relay.example/terminate", WssTls::Roots(roots));
//! let server = WssStreamServer::new(config, WssServerLimits::default(), Arc::new(Web))?;
//! let stats = server.stats();
//! let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
//! // `stop.send(())`, or dropping `stop`, ends the run.
//! server.run(async { let _ = stopped.await; }).await;
//! # Ok(())
//! # }
//! ```

mod config;
mod connect;
mod dialer;
pub mod frame;
mod server;
mod stream;

pub use config::{BearerProvider, WssConfig, WssTls};
pub use connect::WssDialError;
pub use dialer::{WssDialer, WssStats};
pub use server::{
    Denied, WssCloseReason, WssOpen, WssResolver, WssServerLimits, WssServerStats, WssStreamEvent,
    WssStreamEventKind, WssStreamServer,
};
pub use stream::{
    MAX_DATA_PAYLOAD, WssStreamClient, WssStreamLimits, WssStreamStats, WssTcpStream, WssUdpFlow,
};

/// The longest datagram a message (or a UDP flow's DATA frame) may carry; longer ones are
/// dropped and counted, or refused on send.
pub const MAX_DATAGRAM: usize = 65_535;

/// The longest WebSocket message or frame read at all; a longer one ends the link or
/// session.
pub const MAX_MESSAGE: usize = 4 * MAX_DATAGRAM;
