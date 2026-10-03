//! The reasons of [`Event::Dropped`](crate::Event::Dropped).
//!
//! The core emits the reasons from [`INVALID_PACKET`] to [`NO_FREE_PEER_ID`]; the driver
//! (`nsplane`) emits the rest for drops it decides itself. Packet filters may drop with
//! reasons of their own.

/// A datagram is not a WireGuard message (wrong type or size).
pub const INVALID_PACKET: &str = "invalid packet";
/// Transport data arrived for a receiver index no peer uses.
pub const UNKNOWN_SESSION: &str = "unknown session";
/// Transport data could not be decrypted (no such session, bad tag, replay, expired keys).
pub const DECAPSULATE_ERROR: &str = "decapsulate error";
/// A decrypted packet's source address is not in the sending peer's allowed IPs.
pub const SOURCE_NOT_ALLOWED: &str = "source not allowed";
/// A handshake message arrived, or a peer was to be added, before a private key was set.
pub const NO_PRIVATE_KEY: &str = "no private key";
/// A handshake message failed the handshake gate's mac1 check.
pub const INVALID_HANDSHAKE: &str = "invalid handshake";
/// A verified handshake message names no configured peer.
pub const UNKNOWN_PEER: &str = "unknown peer";
/// The peer's tunnel rejected a verified handshake message (bad keys, replayed timestamp,
/// no matching handshake in flight).
pub const HANDSHAKE_REJECTED: &str = "handshake rejected";
/// A local packet's destination is in no peer's allowed IPs.
pub const NO_ROUTE: &str = "no route";
/// A local packet could not be encrypted.
pub const ENCAPSULATE_ERROR: &str = "encapsulate error";
/// A datagram for a peer was dropped because neither the policy nor the peer has a path.
pub const NO_PATH: &str = "no path";
/// A peer could not be added: every session index is in use.
pub const NO_FREE_SESSION_INDEX: &str = "no free session index";
/// A peer could not be added: every peer id is in use.
pub const NO_FREE_PEER_ID: &str = "no free peer id";

/// Emitted by the driver: a decrypted packet was dropped because the sink queue was full.
pub const SINK_FULL: &str = "sink full";
/// Emitted by the driver: a decrypted packet was dropped because the sink has shut down.
pub const SINK_CLOSED: &str = "sink closed";
/// Emitted by the driver: a datagram was dropped because no transport serves its path.
pub const NO_TRANSPORT: &str = "no transport";
/// Emitted by the driver: a datagram caused by a local packet, a received datagram or a timer
/// was dropped because its transport's transmit queue and the datagrams waiting for it were
/// full.
pub const TRANSMIT_FULL: &str = "transmit full";
/// Emitted by the driver: a datagram was dropped because the transport has shut down.
pub const TRANSPORT_CLOSED: &str = "transport closed";
/// Emitted by the driver: a datagram queued for a transport was dropped because the
/// transport was removed.
pub const TRANSPORT_REMOVED: &str = "transport removed";
/// Emitted by the driver: the transport failed to send a datagram (any I/O error, such as a
/// datagram too large for the path).
pub const TRANSPORT_SEND_ERROR: &str = "transport send error";
/// Emitted by the driver: a local packet above the MTU was dropped by the fragmentation
/// stage without an ICMP error (an error about it is not allowed, or it cannot be split).
pub const FRAGMENT_OVERSIZE: &str = "oversize packet";
/// Emitted by the driver: a local packet above the MTU was dropped by the fragmentation
/// stage, and no ICMP error was sent because its destination has no route.
pub const FRAGMENT_NO_ROUTE: &str = "no route for ICMP error";
/// Emitted by the driver: a local packet above the MTU was dropped by the fragmentation
/// stage, and no ICMP error was sent because of the error rate limit.
pub const FRAGMENT_RATE_LIMITED: &str = "ICMP error rate limited";
