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

pub use nstun_core::Event;

/// A decrypted packet was dropped because the sink queue was full.
pub const DROP_SINK_FULL: &str = "sink full";
/// A decrypted packet was dropped because the sink has shut down.
pub const DROP_SINK_CLOSED: &str = "sink closed";
/// A datagram was dropped because the engine has no transport.
pub const DROP_NO_TRANSPORT: &str = "no transport";
/// A datagram was dropped because the transport has shut down.
pub const DROP_TRANSPORT_CLOSED: &str = "transport closed";
