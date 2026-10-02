//! The drop reasons of [`PortMap`](crate::PortMap).
//!
//! The core reports them in `Event::Dropped` for packets the filter drops.

/// An inbound packet to a published `listen` port comes from a peer the rule
/// does not allow.
pub const PEER_NOT_ALLOWED: &str = "port map peer not allowed";
/// A packet of a recorded flow (or an ICMP error quoting one) goes to or
/// comes from another peer than the one that opened the flow.
pub const WRONG_PEER: &str = "port map wrong peer";
/// A new flow would share its reply tuple with a live flow of another rule
/// (two `listen` addresses mapped to one target, used by the same client
/// address and port), so its replies could not be told apart.
pub const FLOW_CONFLICT: &str = "port map flow conflict";
/// A new flow could not be recorded: the conntrack table holds no flows at
/// all (`max_entries` is 0).
pub const CONNTRACK_FULL: &str = "conntrack full";
/// A packet that matched a rule or flow could not be rewritten.
pub const MALFORMED: &str = "port map malformed";
