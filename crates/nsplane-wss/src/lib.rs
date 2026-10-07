#![forbid(unsafe_code)]

//! WebSocket-over-TLS (WSS) carriers for nsplane.
//!
//! The dialing carriers share one connection setup ([`WssConfig`]):
//!
//! - [`WssDialer`], the datagram carrier for [`LinkTransport`](nsplane::LinkTransport),
//!   below.
//! - [`WssStreamClient`], the stream carrier (deprecated): TCP streams ([`WssTcpStream`])
//!   and UDP flows ([`WssUdpFlow`]) to targets behind a WSS server, multiplexed over
//!   sessions with the `WsFrame` protocol of the [`frame`] module.
//! - [`WssStreamServer`], the server side of that protocol (deprecated): it dials the relay
//!   too and relays each opened stream to the backend a [`WssResolver`] picks.
//!
//! [`WssServerTransport`] is the server side of [`WssDialer`]'s links: a transport over
//! the WebSocket sessions the embedder accepts (see [below](#server-transport)).
//!
//! The stream carrier has no remaining consumer and will be removed once its users have
//! switched; a WireGuard peer over [`WssDialer`] replaces it.
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
//! - **Backoff**: every dial but the first waits: [`WssConfig::reconnect_delay`] after a
//!   link that came up ([`WssConfig::backoff_min`] when unset), and after a failed dial
//!   [`WssConfig::backoff_min`], doubled after each further failure up to
//!   [`WssConfig::backoff_max`]. Without a reconnect delay, the wait after a link is the
//!   first step of that doubling. A [`WssStreamClient`] open waits for that dial unless
//!   [`WssStreamLimits::open_timeout`] is set; past it the open fails with the last dial
//!   error while the dial goes on.
//! - **Keepalive**: the sending half pings every [`WssConfig::ping_interval`], or never
//!   when it is zero ([`WssConfig::ping_interval(None)`](WssConfig::ping_interval)); the
//!   receiving half ends the link when no frame at all (pongs included) arrived for
//!   [`WssConfig::read_idle`].
//! - **Events**: [`WssDialer::events`] (and [`WssStreamClient::events`]) receive one
//!   [`WssDialEvent`] per link that came up or was lost, failed dial, dial timeout and
//!   401/403 rejection, on a broadcast channel of [`WssDialEvent::CAPACITY`] events.
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
//! # Server transport
//!
//! [`WssServerTransport`] is a [`Transport`](nsplane::Transport) over WebSocket sessions
//! the embedder accepts: it runs the listener, TLS, its own checks of the request (path,
//! token) and the upgrade (with [`WssAcceptor::ws_config`]), then hands each session to a
//! [`WssAcceptor`]. The wire is [`WssDialer`]'s: one datagram per binary message.
//!
//! - **Endpoints**: each session gets an address of its own, never reused: IPv6 in
//!   `100::/64` (the RFC 6666 discard-only prefix) with the session count as interface id,
//!   port 0. A WSS peer's endpoint (in the engine's status and in UAPI) shows such an
//!   address; it identifies a session, not a host.
//! - **Replies** follow the engine's path, which roams on authenticated messages, so they
//!   go to the session the peer last authenticated on. A send to an address without a live
//!   session fails at once with [`std::io::ErrorKind::NotConnected`]: between a session
//!   closing and the peer's redial, datagrams to that peer are lost by design (counted as
//!   send errors); WireGuard retransmits its handshakes and the peer's next authenticated
//!   datagram on the new session moves its path.
//! - **Limits**: a bounded queue per session (a full one fails the send at once), one
//!   shared inbound queue that pushes back on the sessions' readers, keepalive pings, a read
//!   idle, and at most [`WssServerConfig::max_sessions`] sessions.
//!
//! ```no_run
//! use nsplane::TransportId;
//! use nsplane_wss::{WssAcceptor, WssServerConfig, WssServerTransport};
//! use tokio::net::TcpListener;
//!
//! # async fn run() -> std::io::Result<()> {
//! let (transport, acceptor) = WssServerTransport::new(TransportId::new(3), WssServerConfig::default());
//! let stats = transport.stats();
//! // Hand `transport` to the engine, then accept sessions (behind TLS in practice).
//! let listener = TcpListener::bind("0.0.0.0:8080").await?;
//! loop {
//!     let (tcp, _) = listener.accept().await?;
//!     let acceptor = acceptor.clone();
//!     tokio::spawn(async move {
//!         let config = Some(WssAcceptor::ws_config());
//!         if let Ok(ws) = tokio_tungstenite::accept_async_with_config(tcp, config).await {
//!             if let Ok(session) = acceptor.accept(ws) {
//!                 println!("session {}", session.addr());
//!             }
//!         }
//!     });
//! }
//! # }
//! ```
//!
//! The stream carrier on the same kind of configuration:
//!
//! ```no_run
//! # #![allow(deprecated, reason = "an example of the deprecated stream carrier")]
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
//! The server side, on its own configuration:
//!
//! ```no_run
//! # #![allow(deprecated, reason = "an example of the deprecated stream carrier")]
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
//! let config = WssConfig::new("wss://relay.example/server", WssTls::Roots(roots));
//! let server = WssStreamServer::new(config, WssServerLimits::default(), Arc::new(Web))?;
//! let stats = server.stats();
//! let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
//! // `stop.send(())`, or dropping `stop`, ends the run.
//! server.run(async { let _ = stopped.await; }).await;
//! # Ok(())
//! # }
//! ```

mod accept;
mod config;
mod connect;
mod dialer;
pub mod frame;
mod server;
mod stream;

pub use accept::{
    WssAcceptor, WssServerConfig, WssServerTransport, WssServerTransportStats, WssSession,
    WssSessionStats,
};
pub use config::{BearerProvider, WssConfig, WssTls};
pub use connect::{WssDialError, WssDialEvent};
pub use dialer::{WssDialer, WssStats};
#[expect(deprecated, reason = "re-exports of the deprecated stream carrier")]
pub use server::{
    Denied, WssCloseReason, WssOpen, WssResolver, WssServerLimits, WssServerStats, WssStreamEvent,
    WssStreamEventKind, WssStreamServer,
};
#[expect(deprecated, reason = "re-exports of the deprecated stream carrier")]
pub use stream::{
    MAX_DATA_PAYLOAD, WssStreamClient, WssStreamLimits, WssStreamStats, WssTcpStream, WssUdpFlow,
};

/// The longest datagram a message (or a UDP flow's DATA frame) may carry; longer ones are
/// dropped and counted, or refused on send.
pub const MAX_DATAGRAM: usize = 65_535;

/// The longest WebSocket message or frame read at all; a longer one ends the link or
/// session.
pub const MAX_MESSAGE: usize = 4 * MAX_DATAGRAM;
