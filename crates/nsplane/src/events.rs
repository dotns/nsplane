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
/// none was added under that id, or it was removed.
///
/// The datagrams still queued for a transport when it is removed count under
/// [`DROP_TRANSPORT_REMOVED`] instead.
pub const DROP_NO_TRANSPORT: &str = nsplane_core::reasons::NO_TRANSPORT;
/// A datagram caused by a local packet, a received datagram or a timer was dropped because
/// the transmit queue and the datagrams waiting for it were full.
pub const DROP_TRANSMIT_FULL: &str = nsplane_core::reasons::TRANSMIT_FULL;
/// A datagram was dropped because the transport has shut down.
pub const DROP_TRANSPORT_CLOSED: &str = nsplane_core::reasons::TRANSPORT_CLOSED;
/// A datagram still queued for a transport (being sent, in its transmit queue or waiting
/// for room in it) was dropped because the transport was removed.
pub const DROP_TRANSPORT_REMOVED: &str = nsplane_core::reasons::TRANSPORT_REMOVED;
/// A datagram was dropped because the transport failed to send it (any I/O error, such as
/// a datagram too large for the path).
pub const DROP_TRANSPORT_SEND_ERROR: &str = nsplane_core::reasons::TRANSPORT_SEND_ERROR;
/// A local packet above the MTU was dropped by the fragmentation stage without an ICMP
/// error.
///
/// An error about it is not allowed (it is an ICMP error, multicast or broadcast, or a
/// fragment other than the first), or it cannot be split.
pub const DROP_FRAGMENT_OVERSIZE: &str = nsplane_core::reasons::FRAGMENT_OVERSIZE;
/// A local packet above the MTU was dropped by the fragmentation stage, and no ICMP error
/// was sent because its destination is routed to no peer.
pub const DROP_FRAGMENT_NO_ROUTE: &str = nsplane_core::reasons::FRAGMENT_NO_ROUTE;
/// A local packet above the MTU was dropped by the fragmentation stage, and no ICMP error
/// was sent because of the error rate limit.
pub const DROP_FRAGMENT_RATE_LIMITED: &str = nsplane_core::reasons::FRAGMENT_RATE_LIMITED;
