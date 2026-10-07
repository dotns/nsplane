#![forbid(unsafe_code)]

//! Accept-only ACL policy engine and packet filters for nsplane.
//!
//! Evaluates flows against typed accept rules ([`Rule`]). The model is
//! **accept-only with default deny**: rules can only grant access to
//! specific flows, and anything no rule accepts is denied.
//!
//! - **Typed rules** ([`rules`]): opaque source [`Label`]s carried in a
//!   [`LabelSet`], and [`Rule`]s with an opaque [`RuleId`] matching a flow by
//!   source label, source and destination prefix, and [`ProtocolMatch`]
//!   (TCP or UDP ports, ICMP types, other IP protocols); validated into an
//!   immutable [`RuleSet`]. See [Typed rules](#typed-rules).
//! - **Policy model** ([`AclPolicy`]): named host aliases, ordered accept
//!   rules (`src`, `dst` as `host:ports`, optional protocol) and built-in
//!   tests that must pass before a policy is accepted.
//! - **Layered merge** ([`merge_layered`]): combines an optional local policy
//!   with any number of remote policies into one deduplicated policy with
//!   per-rule provenance.
//! - **Deny scope** ([`apply_deny_scope`]): an operator-authored post-filter
//!   that removes rules reaching forbidden CIDRs. It edits the policy text
//!   before compilation, so matching itself stays accept-only.
//!   [`RuleSet::from_document`] compiles it into typed rules.
//! - **Engine** ([`AclEngine`]): shares the default rule set with its
//!   [`PolicyState`], the rule namespaces and the directed grants across
//!   threads as one snapshot and swaps it atomically on every update. It is
//!   fail-closed: with nothing loaded every flow is denied, and a rejected
//!   update keeps the previous state in effect.
//!   [`AclEngine::evaluate`] decides a [`Flow`] described without a packet
//!   from a source with a [`LabelSet`] and reports the [`Decision`] with the
//!   accepting rule's [`RuleId`].
//! - **Namespaces** ([`namespace`]): per-source rule sets with their member
//!   labels, opt-in outbound rules and directed [`Grant`]s between them; see
//!   [Namespaces](#namespaces).
//! - **Pinholes** ([`pinhole`]): short-lived, source-gated openings for one
//!   session, closed by dropping a [`PinholeGuard`]; see
//!   [Pinholes](#pinholes).
//! - **Packet filter** ([`AclFilter`]): a sans-I/O
//!   [`PacketFilter`](nsplane_core::PacketFilter) that evaluates inbound
//!   packets against the engine, with the [`LabelSet`] of each peer resolved
//!   by a [`PeerIdentity`] (for example a [`PeerLabelMap`]). It gates IPv4
//!   fragments on their first fragment and accepts replies to flows the local
//!   side opened (stateful replies, not a conntrack/NAT). Drop reasons are in
//!   [`reasons`].
//! - **Node L3 gate** ([`NodeL3Gate`]): target-bound Node / Service / Subnet
//!   grants with source binding and bounded flow state for the Node-address
//!   plane, configured by [`NodeL3Config`] snapshots and the WireGuard
//!   projection [`NodeL3Transport`]; inert unless constructed.
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
//! A node can hold peers from several sources. Each source is a rule
//! namespace (an opaque [`NamespaceId`], e.g. `team-a`) stored with
//! [`AclEngine::store_namespace`]: its kind ([`NamespaceKind`]), its members
//! ([`NamespaceMember`], a [`Label`] plus the addresses it owns), its accept
//! rules (an [`AclPolicy`] with the usual semantics) and optional outbound
//! rules ([`OutboundRule`]).
//! Storing, replacing or removing one namespace leaves the others untouched.
//! The engine's default rule set ([`AclEngine::install`]) applies only to
//! sources whose labels are members of no namespace, exactly as before
//! namespaces existed.
//!
//! **Policy states.** The default rule set is in one [`PolicyState`]:
//!
//! - [`PolicyState::NotInstalled`] (the start, and after
//!   [`AclEngine::uninstall`]): the engine's [`NotInstalled`] action applies
//!   to sources in no namespace. [`NotInstalled::Deny`] (the default) drops
//!   their new inbound flows with [`reasons::NO_POLICY`];
//!   [`NotInstalled::Accept`] ([`AclEngine::with_not_installed`]) accepts
//!   every flow they send.
//! - [`PolicyState::Installed`] ([`AclEngine::install`]): the rules decide;
//!   an empty rule set denies every new flow with [`reasons::DENIED`].
//! - [`PolicyState::Failed`] ([`AclEngine::fail`], for a caller whose own
//!   rule compilation failed): new flows of sources in no namespace are
//!   dropped with [`reasons::POLICY_FAILED`].
//!
//! The engine counts as loaded when rules are installed, a namespace is
//! stored, or nothing is installed under [`NotInstalled::Accept`]. While it
//! is not loaded every inbound packet, replies included, is dropped with
//! [`reasons::NO_POLICY`] (or [`reasons::POLICY_FAILED`] when failed);
//! otherwise replies to flows the local side opened still pass. A source
//! that is a member of a namespace is governed by its namespaces' rules,
//! plus grants and pinholes, in every state. [`AclEngine::clear_all`] is the
//! emergency stop that removes the default rules, every namespace, grant and
//! pinhole in one atomic swap and leaves the state failed. The state is
//! reported by [`AclEngine::policy_state`] and
//! [`AclFilterStats::policy_state`].
//!
//! **Membership is keyed by label.** Every [`NamespaceMember`] places its
//! label in the namespace; a source whose [`LabelSet`] is `S` is a member of
//! the union of the namespaces of every label in `S` (computed once when the
//! filter resolves the source, never per packet). A destination address
//! resolves to the member label owning it: the longest member prefix, and the
//! smallest label (in [`Label`] order) when several labels own it. An
//! inbound packet from a namespace member with labels `S` to address `d` is
//! evaluated after the reply table, in this order:
//!
//! 1. `d` is resolved to its owner label `Q`; otherwise `d` is local and the
//!    local node is in every namespace.
//! 2. The common namespaces are the source's [`NamespaceKind::Rules`]
//!    namespaces that also contain `Q` (all of them when `d` is local). A
//!    rule of any common namespace accepts the packet (the union across
//!    namespaces).
//! 3. When `d` is another member, a directed [`Grant`] whose `from` is a
//!    label in `S` ([`GrantEnd::Label`]) or one of the source's rule
//!    namespaces and whose `to` is `Q` or one of `Q`'s rule namespaces, with
//!    matching protocol and ports, accepts the packet. Grants are one-way and
//!    never open the local node.
//! 4. When `d` is local, an open inbound pinhole of a label in `S` for the
//!    packet's protocol and destination port accepts it (see
//!    [Pinholes](#pinholes)).
//! 5. Otherwise the packet is dropped with [`reasons::CROSS_NAMESPACE`] when
//!    `d` is another member sharing no namespace with the source, else with
//!    [`reasons::DENIED`].
//!
//! Cross-namespace traffic is therefore denied by default.
//! [`NamespaceKind::Pinholes`] namespaces never widen permissions on their
//! own: they cannot carry accept rules or pinhole kinds and no grant can name
//! them, so a member only of pinhole namespaces gets nothing inbound except
//! through its pinholes.
//!
//! Outbound traffic is unrestricted by default. A source is
//! **outbound-restricted** when it is a member of at least one namespace and
//! every namespace it belongs to sets [`NamespacePolicy::outbound`]. An
//! outbound packet to a restricted peer (its labels resolved for the
//! packet's destination address) is accepted when it matches an outbound
//! rule of one of its namespaces, an open outbound pinhole of one of its
//! labels, or is a reply to an inbound flow from that peer the filter accepted;
//! anything else (including non-TCP/UDP packets unless
//! [`AclFilterConfig::allow_other_protocols`] is set or an outbound rule
//! accepts them) is dropped with [`reasons::OUTBOUND`].
//!
//! **Protocols other than TCP and UDP.** An inbound packet that is neither
//! TCP nor UDP is accepted by, in this order: a reply allowance,
//! [`AclFilterConfig::allow_other_protocols`], an
//! [`AclFilterScope::other_protocols`] rule, or the rule evaluation above
//! (default rules, namespace rules and grants with [`ProtocolMatch::Icmp`],
//! [`ProtocolMatch::Ip`] or [`ProtocolMatch::Any`] entries; pinholes are TCP
//! and UDP only). Otherwise it is dropped with [`reasons::PROTOCOL`], which
//! also reports every denial of the rule evaluation. Such flows get no
//! verdict cache; an accepted one has the side effects of an accepted TCP or
//! UDP flow (a grant dependency, the outbound allowance of a restricted
//! peer). Rules without such entries therefore behave as for TCP and UDP
//! only.
//!
//! Independently of the namespaces, a filter built with
//! [`AclFilter::with_scope`] can constrain the source address of every
//! outbound packet ([`AclFilterScope::outbound_sources`]): a packet from
//! outside the allowed prefixes is dropped with [`reasons::OUTBOUND_SOURCE`]
//! before any destination rule is consulted.
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
//! # Typed rules
//!
//! A [`Rule`] matches a [`Flow`] from a source with label set `S` when all of
//! these hold: its `labels` are empty or `S` contains one of them (a source
//! with an empty set matches only label-free rules); its `sources` are empty
//! or contain the flow's source address; its `destinations` are empty or
//! contain the flow's destination address; and one of its `protocols`
//! matches. Rules are a union: the verdict does not depend on their order,
//! and the reported [`RuleId`] is that of the first matching rule. Rule IDs
//! need not be unique. [`RuleSet::new`] rejects invalid rules with
//! [`Error::InvalidRule`] before anything is published.
//!
//! Every full evaluation logs at debug level the flow's addresses, protocol
//! and port, and the accepting rule, grant or pinhole or the denial reason.
//! Drop verdicts carry the [`reasons`] constant only.
//!
//! # Pinholes
//!
//! A session gets access to a source only through pinholes in a
//! [`NamespaceKind::Pinholes`] namespace, never through the namespace
//! itself. [`AclEngine::open_pinhole`] opens one for a [`PinholeSpec`]: one
//! [`Label`] (every source carrying it uses the pinhole), one [`Direction`],
//! one protocol and one destination port, with a caller-chosen maximum
//! lifetime (`expires_at`). There is no reverse rule:
//! the opened flows' replies pass only through the filter's reply allowances,
//! which depend on the pinhole (an inbound pinhole records an outbound reply
//! allowance when the peer is outbound-restricted; an outbound pinhole records
//! an inbound one). An inbound pinhole opens the local node only; an outbound
//! pinhole matters for outbound-restricted peers (outbound to an unrestricted
//! peer is accepted anyway, but its replies still depend on the pinhole).
//!
//! **Permissions.** The namespace must be stored, be of kind
//! [`NamespaceKind::Pinholes`], and contain the label; `expires_at` must be
//! in the future. The pinhole is source-gated: when the label is a member of
//! at least one [`NamespaceKind::Rules`] namespace, one of them must list the
//! pinhole kind in [`NamespacePolicy::pinhole_kinds`], else the request fails
//! with [`PinholeError::NotPermitted`] and nothing changes. A label that is
//! only in pinhole namespaces is governed by its own pinholes. Each failure
//! is a [`PinholeError`] variant.
//!
//! **Lifecycle and close reasons** (counted in [`PinholeStats`], each pinhole
//! exactly once):
//!
//! - `closed`: the session dropped its [`PinholeGuard`] or called
//!   [`PinholeGuard::close`], so policy stops when the transfer ends. The
//!   guard holds a weak reference; a guard outliving its engine is harmless.
//! - `expired`: the engine clock reached `expires_at`, the safety net for a
//!   session that crashed without dropping its guard.
//! - `namespace_removed`: the pinhole namespace was removed.
//! - `cleared`: [`AclEngine::clear_all`] removed everything.
//! - `revoked`: the label left the pinhole namespace, or its rule namespaces
//!   no longer permit the pinhole kind (a rule namespace changed or was
//!   removed, including a label dropped from its last rule namespace when the
//!   pinhole was opened under one).
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
//!   change: [`install`](AclEngine::install),
//!   [`uninstall`](AclEngine::uninstall), [`fail`](AclEngine::fail),
//!   [`load`](AclEngine::load), [`clear_all`](AclEngine::clear_all),
//!   storing or removing a namespace or a grant, and opening, closing,
//!   sweeping or revoking a pinhole. A versioned [`PeerIdentity`] (its
//!   [`generation`](PeerIdentity::generation), bumped by every
//!   [`PeerLabelMap`] change) versions the identities.
//! - **Label cache.** Per peer, the filter keeps its [`LabelSet`] (one
//!   `Arc`, no allocation per packet), its namespace membership (the union
//!   over its labels) and flags (outbound-restricted, pinholes, bypass) under
//!   both generations. A peer whose labels depend on the remote address
//!   ([`PeerLabelMap::insert_by_source`], [`PeerIdentity::by_source`]) has
//!   one label set per remote address ([`PeerIdentity::labels_for`]),
//!   cached per peer and address in a least-recently-used table bounded by
//!   [`AclFilterConfig::reply_capacity`], and is bypassed per address.
//! - **Flow verdict cache.** The reply table also holds, per peer, direction
//!   and five-tuple, the verdict of a namespace member's TCP or UDP flow's
//!   first packet (accepted with its grant or pinhole dependency, or dropped
//!   with its reason; a peer under the default rules is evaluated on every
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
//! - **Bypass.** On every update the engine computes the rule namespaces
//!   with a rule accepting every TCP and UDP flow from any source to any
//!   destination, the distinct namespace sets of the address owners, and
//!   whether the default rules accept everything (installed rules with such
//!   a rule, or nothing installed under [`NotInstalled::Accept`]). When a
//!   peer is resolved it bypasses if it is not outbound-restricted and one
//!   of those namespaces of its labels it shares with every destination (the
//!   local node and every member address); a peer in no namespace bypasses
//!   when the default rules accept everything, and an unknown peer never
//!   does. A new inbound TCP or UDP flow from
//!   such a peer is accepted without evaluation (counted in
//!   [`AclFilterStats::accepted`] as before). The reply table is still
//!   consulted first, so replies and the dependencies they carry behave as
//!   before.
//!
//! Fragments, malformed packets, protocols other than TCP and UDP and the
//! fail-closed rules (nothing loaded: every inbound packet dropped) are
//! never cached, and verdicts and counters equal a full evaluation of every
//! packet. A [`PeerIdentity`] that is not versioned (generation 0, e.g. a
//! closure) gets no cache: every packet is evaluated.
//!
//! # The ns `crates/acl` mode
//!
//! [`AclFilterConfig::crates_acl`] makes the filter judge inbound IPv4
//! packets as the ACL step of an ns account (`is_local_node_packet ||
//! is_icmp_echo_reply || acl_check_packet`): packets to the local tunnel
//! address and ICMP echo replies pass without the policy
//! ([`AclFilterConfig::accept_to_local`],
//! [`AclFilterConfig::accept_icmp_echo_reply`]), non-first fragments pass
//! only after an accepted first fragment of the same datagram within 15 s
//! ([`FragmentMode::AllowOnly`]), and there are no reply allowances
//! ([`AclFilterConfig::stateful_replies`] off). IPv6 packets pass in both
//! directions without the policy ([`Ipv6Mode::Accept`]): ns runs no ACL on
//! IPv6 and authorizes it only by destination, which the core's per-peer
//! inbound destinations do. Each of these settings is off by default and
//! costs one branch when off.
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
//! | Default policy, by-source peer (best of 3 runs) | 79 ns | 79 ns | |
//! | `crates_acl` preset, by-source peer, IPv4 TCP (best of 3 runs) | 71 ns | 80 ns | |
//! | same, non-first fragment after an accepted first fragment | | 29 ns | |
//!
//! Before the hook every packet was a new flow: 71 ns (default policy),
//! 669 ns (namespaces), 1.75 us (grant, established), 937 ns (bypass peer),
//! 580/623 ns outbound; a new flow through a grant took 38 us and through a
//! pinhole 15-20 us before full tables evicted in O(1). The floor
//! every packet pays is parsing its five-tuple (6-7.5 ns) and loading the
//! engine snapshot (9-11.5 ns), 16-19 ns; an established flow adds one
//! flow-table lookup under its lock, and a bypass peer the reply check and
//! its cached labels under that lock. Skipping the reply check would be
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
mod matcher;
pub mod merge;
pub mod namespace;
pub mod net;
mod node_l3;
pub mod pinhole;
pub mod policy;
pub mod reasons;
pub mod rules;
#[cfg(test)]
mod test_packets;

pub use deny_scope::{DenyScope, DenyScopeOutcome, DropReason, DroppedRule, apply_deny_scope};
pub use engine::{AclEngine, AclTestFailure};
pub use filter::{
    AclFilter, AclFilterConfig, AclFilterScope, AclFilterStats, FragmentMode, Ipv6Mode,
    OtherProtocol, OtherProtocolRule, PeerIdentity, PeerLabelMap,
};
pub use flow::{FlowKey, FlowStats, FlowTracker};
pub use merge::{
    MergeStats, MergedPolicy, PolicyLayers, RemotePolicy, RuleProvenance, acl_rule_key,
    acl_test_key, merge_layered,
};
pub use namespace::{
    Grant, GrantEnd, NamespaceId, NamespaceKind, NamespaceMember, NamespacePolicy, OutboundRule,
};
pub use net::{IpNet, ParseIpNetError, Protocol};
pub use node_l3::{
    GatewayConsumerAuthority, GatewayConsumerPacket, GatewayConsumerSink, NODE_L3_SCHEMA_VERSION,
    NodeL3Applied, NodeL3Config, NodeL3ConfigError, NodeL3Counters, NodeL3Decision, NodeL3Filter,
    NodeL3FilterStats, NodeL3Gate, NodeL3Grant, NodeL3Mode, NodeL3Node, NodeL3PeerBinding,
    NodeL3PeerPolicyRequirement, NodeL3PeerReadiness, NodeL3PeerReadinessReason, NodeL3Reason,
    NodeL3Resource, NodeL3ServiceEndpoint, NodeL3ServiceProtocol, NodeL3SubnetAuthorization,
    NodeL3Transport, NodeL3TransportError, NodeL3TransportPeer, PeerKeyMap, PeerPublicKeys,
};
pub use pinhole::{Direction, PinholeError, PinholeGuard, PinholeId, PinholeSpec, PinholeStats};
pub use policy::{AclAction, AclPolicy, AclRule, AclTest};
pub use rules::{
    Decision, Flow, IcmpTypes, Label, LabelSet, Matched, NotInstalled, PolicyState, PortSet,
    ProtocolMatch, Rule, RuleId, RuleSet, Transport,
};

use thiserror::Error;

/// Errors produced by the ACL crate.
#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// A typed rule is invalid ([`RuleSet::new`]).
    #[error("invalid rule '{id}': {reason}")]
    InvalidRule {
        /// The rule's identifier.
        id: RuleId,
        /// Why it is invalid.
        reason: String,
    },

    /// A namespace is invalid ([`AclEngine::store_namespace`]).
    #[error("invalid namespace '{id}': {reason}")]
    InvalidNamespace {
        /// The namespace's identifier.
        id: NamespaceId,
        /// Why it is invalid.
        reason: String,
    },

    /// A grant is invalid ([`AclEngine::store_grant`]).
    #[error("invalid grant '{id}': {reason}")]
    InvalidGrant {
        /// The grant's identifier.
        id: RuleId,
        /// Why it is invalid.
        reason: String,
    },
}
