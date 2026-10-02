//! The drop reasons of [`AclFilter`](crate::AclFilter).
//!
//! The core reports them in `Event::Dropped` for packets the filter drops,
//! inbound and (for [`OUTBOUND`]) outbound.

/// The policy has no rule accepting the packet.
pub const DENIED: &str = "acl denied";
/// No policy is loaded, so every inbound packet is dropped (fail-closed).
pub const NO_POLICY: &str = "acl no policy";
/// The sending peer has no source assertion in the [`PeerIdentity`](crate::PeerIdentity).
pub const UNKNOWN_PEER: &str = "acl unknown peer";
/// The packet is neither TCP nor UDP and other protocols are not allowed.
pub const PROTOCOL: &str = "acl protocol";
/// A non-first IPv4 fragment arrived without a recorded first fragment.
pub const FRAGMENT: &str = "acl fragment without first";
/// The packet is not a well-formed IP packet or its transport header is truncated.
pub const MALFORMED: &str = "acl malformed";
/// The packet goes from a namespace member to another peer that shares no
/// namespace with it, and no directed grant accepts it.
pub const CROSS_NAMESPACE: &str = "acl cross namespace";
/// An outbound packet to an outbound-restricted peer matches no outbound rule,
/// no open outbound pinhole and no reply allowance (or is not TCP/UDP while
/// other protocols are not allowed).
pub const OUTBOUND: &str = "acl outbound denied";
