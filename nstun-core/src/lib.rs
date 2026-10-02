//! Sans-I/O WireGuard engine core for the nstun data plane.
//!
//! The core performs no I/O and keeps no clock of its own: datagrams and local packets go in,
//! datagrams to transmit, decrypted packets to deliver and events come out. Path selection
//! and roaming are delegated to a [`PathPolicy`]; local packet rewriting and interception to
//! [`PacketFilter`]s.

#![forbid(unsafe_code)]

mod allowed_ips;
mod filter;
mod peer;
mod peer_table;
mod policy;
mod types;

pub use boringtun::{noise, x25519};
pub use filter::{PacketFilter, Verdict};
pub use nstun_packet::PacketBuf;
pub use nstun_packet::{Ecn, Path, PeerId, TransportId};
pub use policy::{MessageKind, PathPolicy, Roam, StandardRoaming};
pub use types::{AllowedIp, ConfigChange, CoreConfig, Event, Input, Output, PeerConfig, PeerStats};
