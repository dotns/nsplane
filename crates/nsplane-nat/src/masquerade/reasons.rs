//! The drop reasons of [`Masquerade`](crate::Masquerade).

/// A TCP packet would open a new flow but is not a SYN (SYN set, ACK clear),
/// with [`MasqueradeConfig::tcp_new_flow_requires_syn`](crate::MasqueradeConfig::tcp_new_flow_requires_syn).
pub const TCP_NOT_SYN: &str = "tcp_not_syn";
/// A new flow could not be recorded: the table holds
/// [`MasqueradeConfig::max_flows`](crate::MasqueradeConfig::max_flows) live
/// flows. No flow is evicted.
pub const CAPACITY: &str = "capacity";
/// The decision closure no longer answers a reply's flow with the route the
/// flow was recorded with (or answers `None`); the flow was removed.
///
/// With [`MasqueradeConfig::recheck_route_on_forward`](crate::MasqueradeConfig::recheck_route_on_forward),
/// a forward packet of a recorded flow is checked and dropped the same way.
pub const ROUTE_CHANGED: &str = "route_changed";
/// No token of [`MasqueradeConfig::ports`](crate::MasqueradeConfig::ports)
/// is free for a new flow within
/// [`MasqueradeConfig::tries`](crate::MasqueradeConfig::tries) attempts.
pub const TOKENS_EXHAUSTED: &str = "tokens_exhausted";
/// The transport checksum of a packet that would be rewritten is invalid
/// (a zero checksum field counts as invalid), with
/// [`MasqueradeConfig::verify_checksums`](crate::MasqueradeConfig::verify_checksums).
pub const BAD_CHECKSUM: &str = "bad_checksum";
