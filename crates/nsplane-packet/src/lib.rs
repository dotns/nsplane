//! Packet buffers, IP header views and shared value types for the nsplane data plane.
//!
//! This crate is pure data: it performs no I/O and spawns no tasks. Every other
//! data-plane crate builds on the types defined here.

#![forbid(unsafe_code)]

mod buf;
pub mod build;
pub mod checksum;
pub mod hash;
pub mod icmp;
mod ip;
pub mod reassembly;
mod types;

pub use buf::{BoundsError, HEADROOM, MAX_BATCH, PacketBatch, PacketBuf, PacketPool, TAILROOM};
pub use build::{UdpBuildError, udp_packet, write_udp};
pub use ip::{
    FiveTuple, Fragment, IcmpHeader, IpPacket, Ipv4Header, Ipv6Header, Malformed, TcpHeader,
    UdpHeader, protocol,
};
pub use types::{Ecn, Path, PeerId, TransportId};
