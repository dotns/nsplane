#![forbid(unsafe_code)]

//! WebSocket-over-TLS (WSS) carriers for nsplane.
//!
//! [`WssDialer`] is a [`LinkDialer`](nsplane::LinkDialer) for
//! [`LinkTransport`](nsplane::LinkTransport): each link is one WSS connection, and each
//! datagram is one binary WebSocket message carrying its raw bytes (no framing).
//!
//! - **Dialing**: TCP, TLS (rustls with the aws-lc-rs provider) and the WebSocket upgrade,
//!   within [`WssConfig::connect_timeout`]. The request carries the extra
//!   [`headers`](WssConfig::headers) and, when a [`BearerProvider`] is set, an
//!   `Authorization: Bearer <token>` header with a token fetched for that dial.
//! - **Rejections**: an upgrade answered with 401 or 403 is reported as
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
//! complete [`rustls::ClientConfig`] in [`WssTls::Config`]. This crate bundles no system
//! or web PKI roots.
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

mod config;
mod dialer;

pub use config::{BearerProvider, WssConfig, WssTls};
pub use dialer::{WssDialer, WssStats};

/// The longest datagram a message may carry; longer ones are dropped and counted.
pub const MAX_DATAGRAM: usize = 65_535;

/// The longest WebSocket message or frame read at all; a longer one ends the link.
pub const MAX_MESSAGE: usize = 4 * MAX_DATAGRAM;
