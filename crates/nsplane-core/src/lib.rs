//! Sans-I/O WireGuard engine core for the nsplane data plane.
//!
//! The [`Core`] performs no I/O and keeps no clock of its own: datagrams and local packets go
//! in, datagrams to transmit, decrypted packets to deliver and events come out. Path selection
//! and roaming are delegated to a [`PathPolicy`]; local packet rewriting and interception to
//! [`PacketFilter`]s.
//!
//! A driver owns one core and loops: feed [`Input`]s with [`Core::handle_input`], call
//! [`Core::handle_timeout`] when [`Core::poll_timeout`] is due, and drain [`Core::poll_output`]
//! after each call. Packets go through in place: a local packet is sealed in its own buffer and
//! leaves as the `Transmit`, a datagram is opened in its buffer and leaves as the `Deliver`.
//! Buffers the driver is done with go back through [`Core::recycle`].
//!
//! A driver that encrypts and decrypts on several threads builds the core with
//! [`CoreConfig::crypto_jobs`] and feeds inputs with [`Core::handle_input_deferred`] instead:
//! the cryptography of each data packet comes back as a [`CryptoJob`] to run anywhere,
//! finished with [`Core::complete_job`].

#![forbid(unsafe_code)]

mod allowed_ips;
mod core;
mod filter;
mod job;
mod peer;
mod peer_table;
mod policy;
pub mod reasons;
mod types;

pub use crate::core::Core;
pub use filter::{PacketFilter, Verdict};
pub use job::CryptoJob;
pub use nsplane_noise::{noise, x25519};
pub use nsplane_packet::PacketBuf;
pub use nsplane_packet::{Ecn, Path, PeerId, TransportId};
pub use policy::{MessageKind, PathPolicy, Roam, StandardRoaming};
pub use types::{AllowedIp, ConfigChange, CoreConfig, Event, Input, Output, PeerConfig, PeerStats};
