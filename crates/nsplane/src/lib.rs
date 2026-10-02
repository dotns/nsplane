//! Tokio driver for the nsplane data plane.
//!
//! Defines the I/O traits the engine runs on: [`PacketSource`] and [`PacketSink`] for
//! the local side (TUN, netstack, host bridge) and [`Transport`] for the network side,
//! plus in-memory channel implementations for tests and embedders.

#![forbid(unsafe_code)]

mod builder;
mod channel;
mod engine;
pub mod events;
mod handle;
mod io;
mod transport;
mod udp;

pub use builder::EngineBuilder;
pub use channel::{ChannelSink, ChannelSource, ChannelTransport};
pub use engine::Engine;
pub use events::{
    DROP_NO_TRANSPORT, DROP_SINK_CLOSED, DROP_SINK_FULL, DROP_TRANSMIT_FULL, DROP_TRANSPORT_CLOSED,
    Event,
};
pub use handle::{EngineError, EngineHandle, Peer};
pub use io::{PacketSink, PacketSource};
pub use nsplane_core::reasons;
pub use nsplane_core::{AllowedIp, PacketFilter, PathPolicy, PeerStats, StandardRoaming, x25519};
pub use nsplane_packet::{
    Ecn, HEADROOM, MAX_BATCH, PacketBatch, PacketBuf, PacketPool, Path, PeerId, TransportId,
};
pub use transport::Transport;
pub use udp::UdpTransport;
