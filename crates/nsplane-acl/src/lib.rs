#![forbid(unsafe_code)]

//! Accept-only ACL policy engine for nsplane.
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

pub mod deny_scope;
pub mod engine;
pub mod matcher;
pub mod merge;
pub mod net;
pub mod policy;

pub use deny_scope::{DenyScope, DenyScopeOutcome, DropReason, DroppedRule, apply_deny_scope};
pub use engine::{
    AccessRequest, AclDecision, AclEngine, AclTestFailure, CompiledPolicy, SourceAssertion,
    TerminateBinding, wg_peer_anchor,
};
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
