//! Tokio driver for the nstun data plane.
//!
//! Defines the I/O traits the engine runs on: [`PacketSource`] and [`PacketSink`] for
//! the local side (TUN, netstack, host bridge) and [`Transport`] for the network side,
//! plus in-memory channel implementations for tests and embedders.

#![forbid(unsafe_code)]

mod channel;
mod io;
mod transport;
mod udp;

pub use channel::{ChannelSink, ChannelSource, ChannelTransport};
pub use io::{PacketSink, PacketSource};
pub use nstun_packet::{
    Ecn, HEADROOM, MAX_BATCH, PacketBatch, PacketBuf, PacketPool, Path, PeerId, TransportId,
};
pub use transport::Transport;
pub use udp::UdpTransport;
