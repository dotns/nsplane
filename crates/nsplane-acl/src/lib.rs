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
//! **Fail-closed with namespaces.** "No policy" means:
//!
//! - A principal in no namespace, while no default policy is loaded, has its
//!   new inbound flows dropped with [`reasons::NO_POLICY`] (replies to flows
//!   the local side opened still pass while anything else is loaded).
//! - A principal that is a member of a namespace is governed by its
//!   namespaces' rules, plus grants and pinholes, whether or not a default
//!   policy is loaded.
//! - When nothing at all is loaded (no default policy and no namespace),
//!   every inbound packet, replies included, is dropped with
//!   [`reasons::NO_POLICY`].
//! - [`AclEngine::clear`] removes only the default policy;
//!   [`AclEngine::clear_all`] is the emergency stop that removes the default
//!   policy, every namespace, grant and pinhole in one atomic swap.
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
//! - `cleared`: [`AclEngine::clear_all`] removed everything.
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
//! # ACL hook
//!
//! The filter is a per-flow hook: a flow's first packet is evaluated, the
//! later ones reuse its verdict, and with no [`AclFilter`] installed the
//! engine's filter chain costs nothing.
//!
//! - **Generations.** [`AclEngine::generation`] increases on every published
//!   change: [`load`](AclEngine::load), [`store`](AclEngine::store),
//!   [`clear`](AclEngine::clear), [`clear_all`](AclEngine::clear_all),
//!   storing or removing a namespace or a grant, and opening, closing,
//!   sweeping or revoking a pinhole. A versioned [`PeerIdentity`] (its
//!   [`generation`](PeerIdentity::generation), bumped by every
//!   [`PeerIdentityMap`] change) versions the identities.
//! - **Principal cache.** Per peer, the filter keeps its source assertion,
//!   principal (an `Arc<str>`, no allocation per packet) and flags
//!   (outbound-restricted, pinholes, bypass) under both generations. A peer
//!   terminating by source address
//!   ([`PeerIdentityMap::insert_by_source`], [`PeerIdentity::by_source`]) has
//!   one principal per remote address ([`PeerIdentity::assertion_for`]),
//!   cached per peer and address in a least-recently-used table bounded by
//!   [`AclFilterConfig::reply_capacity`], and is bypassed per address.
//! - **Flow verdict cache.** The reply table also holds, per peer, direction
//!   and five-tuple, the verdict of a namespace member's TCP or UDP flow's
//!   first packet (accepted with its grant or pinhole dependency, or dropped
//!   with its reason; a peer under the default policy is evaluated on every
//!   packet, as a few rules cost less than the cache) under both
//!   generations: one table, one lock, one capacity
//!   ([`AclFilterConfig::reply_capacity`]). A hit under other generations is
//!   evaluated again, so a change applies to the very next packet; an
//!   accepted verdict that depends on a pinhole is also checked against the
//!   pinhole's expiry on every hit. Each hit has the side effects of an
//!   evaluation (pending dependencies, the outbound allowance of a restricted
//!   peer). A reply allowance for the same key takes precedence, as the reply
//!   check comes first. When the table is full, cached verdicts are flushed
//!   (counted in [`AclFilterStats::verdict_evictions`]) before an allowance
//!   is evicted, so allowances behave as without the cache. The tables keep
//!   their entries in recency order, so evicting the least recently seen
//!   allowance or pending dependency (or the oldest fragment) is O(1).
//! - **Bypass.** On every update the engine computes the principals whose
//!   inbound flows are all accepted by a rule (a common source namespace
//!   with an accept rule from `*` to `*:*` for TCP and UDP for every
//!   destination: the local node and every member address) and that are not
//!   outbound-restricted, and whether the default policy accepts everything
//!   (for principals in no namespace). A new inbound TCP or UDP flow from
//!   such a peer is accepted without evaluation (counted in
//!   [`AclFilterStats::accepted`] as before). The reply table is still
//!   consulted first, so replies and the dependencies they carry behave as
//!   before.
//!
//! Fragments, malformed packets, protocols other than TCP and UDP and the
//! fail-closed rules (nothing loaded: every inbound packet dropped) are
//! unchanged, and verdicts and counters equal a full evaluation of every
//! packet. A [`PeerIdentity`] that is not versioned (generation 0, e.g. a
//! closure) gets no cache: every packet is evaluated.
//!
//! # Performance
//!
//! `cargo bench -p nsplane-acl --bench namespaces` measures the filter per
//! packet (IPv6 TCP; "new flow": the source port changes with every packet,
//! "established": one five-tuple repeated; release, dev image, x86-64, mean
//! of two runs):
//!
//! | Scenario | New flow | Established | Outbound |
//! | --- | --- | --- | --- |
//! | No namespaces (default policy, 3 rules, not cached) | 55 ns | 55 ns | 76 ns |
//! | 8 namespaces x 64 members, 4 grants, 16 pinholes: local rule | 184 ns | 51 ns | 95 ns |
//! | same, through a grant (peer to peer) | 343 ns | 272 ns | |
//! | same, through an inbound pinhole | 210 ns | | |
//! | same, outbound-restricted peer (outbound rule) | | | 156 ns |
//! | Bypass (a namespace accepting everything) | 38 ns | 37 ns | 77 ns |
//!
//! Before the hook every packet was a new flow: 71 ns (default policy),
//! 669 ns (namespaces), 1.75 us (grant, established), 937 ns (bypass peer),
//! 580/623 ns outbound; a new flow through a grant took 38 us and through a
//! pinhole 15-20 us before full tables evicted in O(1). The floor
//! every packet pays is parsing its five-tuple (6-7.5 ns) and loading the
//! engine snapshot (9-11.5 ns), 16-19 ns; an established flow adds one
//! flow-table lookup under its lock, and a bypass peer the reply check and
//! its cached principal under that lock. Skipping the reply check would be
//! exact only for unidirectional traffic, so it stays: verdicts and counters
//! equal a full evaluation (checked by a differential test). A new flow
//! accepted through a grant or a pinhole also records a pending dependency.
//!
//! [`Instant::now`]: std::time::Instant::now

pub mod deny_scope;
#[cfg(test)]
mod differential;
pub mod engine;
mod filter;
mod flow;
mod lru;
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
