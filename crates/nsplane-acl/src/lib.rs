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
//! - **Pinholes** ([`pinhole`]): short-lived, source-gated openings for one
//!   app session, closed by dropping a [`PinholeGuard`]; see
//!   [Pinholes](#pinholes).
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
//! 4. When `d` is local, an open inbound pinhole of `P` for the packet's
//!    protocol and destination port accepts it (see [Pinholes](#pinholes)).
//! 5. Otherwise the packet is dropped with [`reasons::CROSS_NAMESPACE`] when
//!    `d` is another peer sharing no namespace with `P`, else with
//!    [`reasons::DENIED`].
//!
//! Cross-namespace traffic is therefore denied by default. App namespaces
//! ([`NamespaceId::is_app`]) never widen permissions on their own: they
//! cannot carry accept rules or allow app pinholes and no grant can name
//! them, so a member only of app namespaces gets nothing inbound except
//! through its pinholes.
//!
//! Outbound traffic is unrestricted by default. A peer is
//! **outbound-restricted** when it is a member of at least one namespace and
//! every namespace it belongs to sets [`NamespacePolicy::outbound`]. An
//! outbound packet to a restricted peer is accepted when it matches an
//! outbound rule of one of its namespaces, an open outbound pinhole of that
//! peer, or is a reply to an inbound flow from that peer the filter accepted;
//! anything else (including non-TCP/UDP packets unless
//! [`AclFilterConfig::allow_other_protocols`] is set) is dropped with
//! [`reasons::OUTBOUND`].
//!
//! A grant stops accepting new flows as soon as it is removed
//! ([`AclEngine::remove_grant`]). The reply allowances of a flow a grant
//! accepted depend on that grant, in both directions and whether the peers
//! are outbound-restricted or not: the filter remembers the dependency of
//! each inbound flow accepted through a grant (or a pinhole, or a dependent
//! reply allowance), and the inbound allowance recorded when that flow leaves
//! again (forwarded to another peer, or answered by the local node) inherits
//! it. Once the grant is gone these allowances are removed on their next
//! lookup (counted in [`AclFilterStats::reply_revoked`]) and the flow's
//! packets are evaluated from scratch. A hub forwarding `A -> C` under a
//! grant therefore stops passing `C`'s replies to `A` as soon as the grant is
//! removed. Other outbound packets to unrestricted peers record allowances
//! without a dependency, as they always have.
//!
//! # Pinholes
//!
//! An app session (a file transfer, ...) gets access to a peer only through
//! pinholes in its app namespace, never through the namespace itself.
//! [`AclEngine::open_pinhole`] opens one for a [`PinholeSpec`]: one peer (by
//! principal), one [`Direction`], one protocol and one destination port, with
//! a caller-chosen maximum lifetime (`expires_at`). There is no reverse rule:
//! the opened flows' replies pass only through the filter's reply allowances,
//! which depend on the pinhole (an inbound pinhole records an outbound reply
//! allowance when the peer is outbound-restricted; an outbound pinhole records
//! an inbound one). An inbound pinhole opens the local node only; an outbound
//! pinhole matters for outbound-restricted peers (outbound to an unrestricted
//! peer is accepted anyway, but its replies still depend on the pinhole).
//!
//! **Permissions.** The app namespace must be stored, be an app namespace,
//! and contain the peer; `expires_at` must be in the future. The pinhole is
//! source-gated: when the peer is a member of at least one source (non-app)
//! namespace, one of them must list the app kind in
//! [`NamespacePolicy::allow_app_pinholes`], else the request fails with
//! [`PinholeError::NotPermitted`] and nothing changes. A peer that is only in
//! app namespaces (a session-only peer) is governed by its own pinholes. Each
//! failure is a [`PinholeError`] variant.
//!
//! **Lifecycle and close reasons** (counted in [`PinholeStats`], each pinhole
//! exactly once):
//!
//! - `closed`: the session dropped its [`PinholeGuard`] or called
//!   [`PinholeGuard::close`], so policy stops when the transfer ends. The
//!   guard holds a weak reference; a guard outliving its engine is harmless.
//! - `expired`: the engine clock reached `expires_at`, the safety net for a
//!   session that crashed without dropping its guard.
//! - `namespace_removed`: the app namespace was removed.
//! - `revoked`: the peer left the app namespace, or its source namespaces no
//!   longer allow the app kind (a source namespace changed or was removed,
//!   including a peer dropped from its last source namespace when the pinhole
//!   was opened under one).
//!
//! After a pinhole closes, new flows are dropped ([`reasons::DENIED`]
//! inbound, [`reasons::OUTBOUND`] outbound to a restricted peer), the reply
//! allowances that depend on it stop matching (counted in
//! [`AclFilterStats::reply_revoked`]), and other traffic and namespaces are
//! unaffected.
//!
//! **Clock and lazy expiry.** Expiry follows the engine clock: [`Instant::now`]
//! by default, or the closure given to [`AclEngine::with_clock`] (e.g. paused
//! tokio time, or a manual clock in tests). Evaluation treats an expired
//! pinhole as absent immediately; the pinhole is removed and counted by the
//! next engine update, by [`AclEngine::expire_pinholes`], or by the
//! evaluation that sees it, whichever comes first.
//!
//! # Performance
//!
//! `cargo bench -p nsplane-acl --bench namespaces` measures the filter per
//! packet (IPv6 TCP, new inbound flows; one run in the dev image, x86-64):
//!
//! | Scenario | Inbound | Outbound |
//! | --- | --- | --- |
//! | No namespaces (default policy, 3 rules) | 71 ns | 116 ns |
//! | 8 namespaces x 64 members, 4 grants, 16 pinholes: local rule | 468 ns | 543 ns |
//! | same, through a grant (peer to peer) | 675 ns | |
//! | same, through an inbound pinhole | 557 ns | |
//! | same, outbound-restricted peer (outbound rule) | | 579 ns |
//!
//! Once any namespace is stored, the remaining overhead is mostly resolving
//! the peer's principal (its identity and source anchor) per packet; member
//! destination addresses resolve through a hash map for host addresses.
//!
//! [`Instant::now`]: std::time::Instant::now

pub mod deny_scope;
pub mod engine;
mod filter;
mod flow;
pub mod matcher;
pub mod merge;
pub mod namespace;
pub mod net;
pub mod pinhole;
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
pub use pinhole::{Direction, PinholeError, PinholeGuard, PinholeId, PinholeSpec, PinholeStats};
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
