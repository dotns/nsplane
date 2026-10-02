//! Engine events and the drop reasons the engine counts on its own.
//!
//! Events are the core's [`Event`]s, published on a [`tokio::sync::broadcast`] channel
//! (see [`EngineHandle::subscribe`]). They are best effort: publishing never blocks the data
//! path, and a subscriber that falls more than the channel capacity behind loses the oldest
//! events (its next `recv` returns [`broadcast::error::RecvError::Lagged`]).
//!
//! Drops the engine decides itself are published as [`Event::Dropped`] too and counted
//! together with the core's in [`EngineHandle::drop_counters`].
//!
//! [`EngineHandle::subscribe`]: crate::EngineHandle::subscribe
//! [`EngineHandle::drop_counters`]: crate::EngineHandle::drop_counters
//! [`broadcast::error::RecvError::Lagged`]: tokio::sync::broadcast::error::RecvError::Lagged

#[cfg(doc)]
use tokio::sync::broadcast;

pub use nsplane_core::Event;

/// A decrypted packet was dropped because the sink queue was full.
pub const DROP_SINK_FULL: &str = nsplane_core::reasons::SINK_FULL;
/// A decrypted packet was dropped because the sink has shut down.
pub const DROP_SINK_CLOSED: &str = nsplane_core::reasons::SINK_CLOSED;
/// A datagram was dropped because no transport with the id its path names is installed:
/// none was added under that id, or it was removed (taking its waiting datagrams with it).
pub const DROP_NO_TRANSPORT: &str = nsplane_core::reasons::NO_TRANSPORT;
/// A datagram caused by a received datagram or a timer was dropped because the transmit
/// queue and the datagrams waiting for it were full.
pub const DROP_TRANSMIT_FULL: &str = nsplane_core::reasons::TRANSMIT_FULL;
/// A datagram was dropped because the transport has shut down.
pub const DROP_TRANSPORT_CLOSED: &str = nsplane_core::reasons::TRANSPORT_CLOSED;
