//! Packet buffers and shared value types for the nstun data plane.
//!
//! This crate is pure data: it performs no I/O and spawns no tasks. Every other
//! data-plane crate builds on the types defined here.

#![forbid(unsafe_code)]

mod buf;
mod types;

pub use buf::{HEADROOM, MAX_BATCH, PacketBatch, PacketBuf, PacketPool};
pub use types::{Ecn, Path, PeerId, TransportId};
