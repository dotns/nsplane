//! The drop reasons of [`AclFilter`](crate::AclFilter).
//!
//! The core reports them in `Event::Dropped` for packets the filter drops,
//! inbound and (for [`OUTBOUND`] and [`OUTBOUND_SOURCE`]) outbound.

/// The policy has no rule accepting the packet.
pub const DENIED: &str = "acl denied";
/// No rule set is installed and the engine denies meanwhile.
///
/// Under [`NotInstalled::Deny`](crate::NotInstalled::Deny), new flows from
/// sources in no namespace are dropped, and every inbound packet is dropped
/// while nothing else is loaded (fail-closed).
pub const NO_POLICY: &str = "acl no policy";
/// The caller reported that its rules failed.
///
/// In [`PolicyState::Failed`](crate::PolicyState::Failed), new flows from
/// sources in no namespace are dropped, and every inbound packet is dropped
/// while nothing else is loaded (fail-closed).
pub const POLICY_FAILED: &str = "acl policy failed";
/// The sending peer has no source assertion in the [`PeerIdentity`](crate::PeerIdentity).
pub const UNKNOWN_PEER: &str = "acl unknown peer";
/// The packet is neither TCP nor UDP, other protocols are not allowed and no
/// [`AclFilterScope::other_protocols`](crate::AclFilterScope::other_protocols)
/// rule accepts it.
pub const PROTOCOL: &str = "acl protocol";
/// A non-first IPv4 fragment arrived without a recorded first fragment.
pub const FRAGMENT: &str = "acl fragment without first";
/// The packet is not a well-formed IP packet or its transport header is truncated.
pub const MALFORMED: &str = "acl malformed";
/// The packet goes from a namespace member to another peer that shares no
/// namespace with it, and no directed grant accepts it.
pub const CROSS_NAMESPACE: &str = "acl cross namespace";
/// An outbound packet to an outbound-restricted peer matches no outbound rule,
/// no open outbound pinhole and no reply allowance.
///
/// While other protocols are not allowed, a packet that is neither TCP nor UDP
/// is dropped too unless a reply allowance holds it.
pub const OUTBOUND: &str = "acl outbound denied";
/// The source address of an outbound packet is outside
/// [`AclFilterScope::outbound_sources`](crate::AclFilterScope::outbound_sources).
pub const OUTBOUND_SOURCE: &str = "acl outbound source";
/// The filter's own tables failed an internal invariant; the packet is
/// dropped rather than evaluated without its peer (fail-closed). Not expected
/// in operation: a nonzero count is a bug to report.
pub const INTERNAL: &str = "acl internal error";
