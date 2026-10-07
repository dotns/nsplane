//! The drop reasons of [`Nat64Lan`](crate::Nat64Lan).

/// The destination is inside a route's `mapped` prefix but is no safe LAN
/// host.
///
/// No route resolves it to a safe address of its `real` prefix: it is
/// outside the prefix, or unspecified, loopback, link-local, multicast or a
/// broadcast address.
pub const UNSAFE_TARGET: &str = "nat64 lan unsafe target";
/// More than one route resolves the destination; it is dropped
/// rather than translated through whichever route comes first.
pub const AMBIGUOUS_ROUTE: &str = "nat64 lan ambiguous route";
/// A new flow found no free SNAT port within `port_tries` candidates.
pub const PORT_EXHAUSTED: &str = "nat64 lan ports exhausted";
/// A new flow could not be recorded: the conntrack table holds no flows at
/// all (`max_entries` is 0).
pub const CONNTRACK_FULL: &str = "nat64 lan conntrack full";
/// A packet to a routed destination is malformed (its length disagrees with
/// its header, its transport header is truncated) or would not fit an IPv4
/// packet.
pub const MALFORMED: &str = "nat64 lan malformed";
