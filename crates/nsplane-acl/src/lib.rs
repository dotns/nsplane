#![forbid(unsafe_code)]

//! Accept-only ACL policy engine and packet filters for nsplane.
//!
//! Evaluates per-connection access requests against an [`AclPolicy`]. The
//! model is **accept-only with default deny**: rules can only grant access to
//! specific source/destination pairs, and anything no rule accepts is denied.
//!
//! - **Policy model** ([`AclPolicy`]): named host aliases, ordered accept
//!   rules (`src`, `dst` as `host:ports`, optional protocol) and built-in
//!   tests that must pass before a policy is accepted.
//! - **Layered merge** ([`merge_layered`]): combines an optional local policy
//!   with any number of remote policies into one deduplicated policy with
//!   per-rule provenance.
//! - **Deny scope** ([`apply_deny_scope`]): an operator-authored post-filter
//!   that removes rules reaching forbidden CIDRs. It edits the policy text
//!   before compilation, so matching itself stays accept-only.
//! - **Compiled policy** ([`CompiledPolicy`]): an immutable, validated policy
//!   ready for evaluation.
//! - **Engine** ([`AclEngine`]): shares the current compiled policy, the rule
//!   namespaces and the directed grants across threads as one snapshot and
//!   swaps it atomically on every update. It is fail-closed: with nothing
//!   loaded every request is denied, and a rejected update keeps the previous
//!   state in effect.
//! - **Namespaces** ([`namespace`]): per-source rule sets with their member
//!   peers, opt-in outbound rules and directed [`Grant`]s between them; see
//!   [Namespaces](#namespaces).
//! - **Packet filter** ([`AclFilter`]): a sans-I/O
//!   [`PacketFilter`](nsplane_core::PacketFilter) that evaluates inbound
//!   packets against the engine, with the principal of each peer resolved by
//!   a [`PeerIdentity`] (for example a [`PeerIdentityMap`]). It gates IPv4
//!   fragments on their first fragment and accepts replies to flows the local
//!   side opened (stateful replies, not a conntrack/NAT). Drop reasons are in
//!   [`reasons`].
//! - **Flow tracker** ([`FlowTracker`]): a pass-through
//!   [`PacketFilter`](nsplane_core::PacketFilter) counting packets and bytes
//!   per [`FlowKey`] in a bounded table.
//!
//! The filters are `Clone` and clones share their state: box one clone into
//! the engine and keep another to read [`AclFilter::stats`] or
//! [`FlowTracker::flows`].
//!
//! # Namespaces
//!
//! A node can hold peers from several sources (NSDs, the Quick allow list,
//! app sessions). Each source is a rule namespace ([`NamespaceId`]: e.g.
//! `nsd:<uuid>`, `quick`, `app:<session>`) stored with
//! [`AclEngine::store_namespace`]: its members ([`NamespaceMember`], a
//! principal plus its tunnel addresses), its accept rules (an [`AclPolicy`]
//! with the usual semantics) and optional outbound rules ([`OutboundRule`]).
//! Storing, replacing or removing one namespace leaves the others untouched.
//! The engine's default policy ([`AclEngine::load`]) applies only to
//! principals that are members of no namespace, exactly as before namespaces
//! existed.
//!
//! The principal of a peer is its [`SourceAssertion::source_anchor`]. An
//! inbound packet from a namespace member `P` to address `d` is evaluated
//! after the reply table, in this order:
//!
//! 1. `d` is resolved to a member peer `Q` (longest matching member address);
//!    otherwise `d` is local and the local node is in every namespace.
//! 2. The common namespaces are `P`'s non-app namespaces that also contain
//!    `Q` (all of them when `d` is local). A rule of any common namespace
//!    accepts the packet (the union across namespaces).
//! 3. When `d` is another peer, a directed [`Grant`] whose `from` is `P` or
//!    one of its namespaces and whose `to` is `Q` or one of its namespaces,
//!    with matching protocol and ports, accepts the packet. Grants are
//!    one-way and never open the local node.
//! 4. Otherwise the packet is dropped with [`reasons::CROSS_NAMESPACE`] when
//!    `d` is another peer sharing no namespace with `P`, else with
//!    [`reasons::DENIED`].
//!
//! Cross-namespace traffic is therefore denied by default. App namespaces
//! ([`NamespaceId::is_app`]) never widen permissions on their own: they
//! cannot carry accept rules or allow app pinholes, so a member only of app
//! namespaces gets nothing inbound.
//!
//! Outbound traffic is unrestricted by default. A peer is
//! **outbound-restricted** when it is a member of at least one namespace and
//! every namespace it belongs to sets [`NamespacePolicy::outbound`]. An
//! outbound packet to a restricted peer is accepted when it matches an
//! outbound rule of one of its namespaces or is a reply to an inbound flow
//! from that peer the filter accepted; anything else (including non-TCP/UDP
//! packets unless [`AclFilterConfig::allow_other_protocols`] is set) is
//! dropped with [`reasons::OUTBOUND`].
//!
//! A grant stops accepting new flows as soon as it is removed
//! ([`AclEngine::remove_grant`]). For an outbound-restricted peer, the reply
//! allowances of a flow a grant accepted (both directions) depend on that
//! grant: once it is gone they are removed on their next lookup (counted in
//! [`AclFilterStats::reply_revoked`]) and the flow's packets are evaluated
//! from scratch. For an unrestricted peer, outbound packets record reply
//! allowances without a dependency, as they always have.

pub mod deny_scope;
pub mod engine;
mod filter;
mod flow;
pub mod matcher;
pub mod merge;
pub mod namespace;
pub mod net;
pub mod policy;
pub mod reasons;
#[cfg(test)]
mod test_packets;

pub use deny_scope::{DenyScope, DenyScopeOutcome, DropReason, DroppedRule, apply_deny_scope};
pub use engine::{
    AccessRequest, AclDecision, AclEngine, AclTestFailure, CompiledPolicy, SourceAssertion,
    TerminateBinding, wg_peer_anchor,
};
pub use filter::{AclFilter, AclFilterConfig, AclFilterStats, PeerIdentity, PeerIdentityMap};
pub use flow::{FlowKey, FlowStats, FlowTracker};
pub use merge::{
    MergeStats, MergedPolicy, PolicyLayers, RemotePolicy, RuleProvenance, acl_rule_key,
    acl_test_key, merge_layered,
};
pub use namespace::{Grant, GrantEnd, NamespaceId, NamespaceMember, NamespacePolicy, OutboundRule};
pub use net::{IpNet, ParseIpNetError, Protocol};
pub use policy::{AclAction, AclPolicy, AclRule, AclTest};

use thiserror::Error;

/// Errors produced by the ACL crate.
#[derive(Debug, Error)]
pub enum Error {
    /// A host alias or deny-scope entry is not a valid CIDR.
    #[error("invalid CIDR '{addr}': {reason}")]
    InvalidCidr {
        /// The offending CIDR text.
        addr: String,
        /// Why it failed to parse.
        reason: String,
    },

    /// A rule destination is not a valid `host:ports` matcher.
    #[error("invalid destination '{dst}': {reason}")]
    InvalidDst {
        /// The offending destination text.
        dst: String,
        /// Why it failed to parse.
        reason: String,
    },

    /// A rule references a host alias that the policy does not define.
    #[error("unknown host alias: '{0}'")]
    UnknownAlias(String),

    /// One or more built-in policy tests failed.
    #[error("{count} policy test(s) failed")]
    TestsFailed {
        /// Number of failed tests.
        count: usize,
    },

    /// The policy is malformed (bad rule source, destination or protocol).
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
}
