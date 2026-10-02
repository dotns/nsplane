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
//! - **Engine** ([`AclEngine`]): shares the current compiled policy across
//!   threads and swaps it atomically on reload. It is fail-closed: with no
//!   policy loaded every request is denied, and a rejected reload keeps the
//!   previous policy in effect.
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

pub mod deny_scope;
pub mod engine;
mod filter;
mod flow;
pub mod matcher;
pub mod merge;
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
