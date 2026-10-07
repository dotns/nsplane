# nsplane-acl generic API (AG-1..AG-4) — design note

- **Status**: proposed (workstream AC, subtask C1)
- **Scope**: the public API of `crates/nsplane-acl` after items AG-1..AG-4 of task
  `20261006-1500-business-agnostic-cleanup`, under ADR `2026-10-06-business-agnostic-scope`
  and plan `20261007-0900-business-agnostic`.
- **Gate**: section 5 (the generic flow gate) is the yellow gate for L1 and the owner.
  Section 8 lists the open questions.

This note fixes the API that the later slices C2..C5 implement. The API does not name a
product. This note names ns only where it maps an ns semantic onto the generic API.

Terms used below:

- **Source**: the remote end of a flow as the filter sees it.
- **Label**: an opaque string that a source carries. nsplane compares labels for equality
  and never interprets them.
- **Rule ID**: an opaque string that a caller attaches to a rule, a grant or a gate rule.
  nsplane reports it and never interprets it.
- **New flow**: the first packet of a TCP or UDP five-tuple (or of another protocol's
  flow) that matches no reply allowance or flow state.

## 1. Public item inventory

Each item exported today by `lib.rs` or a public module gets one of these fates:
**keep** (unchanged apart from rustdoc wording), **rename** (new name), **replace** (by a
new item), or **remove**. The slice column says which later step (C2..C5, section 7) does
it.

### 1.1 Modules

| Item | Fate | Generic replacement / reason | Slice |
| --- | --- | --- | --- |
| `pub mod engine` | keep | Engine, `RuleSet` and evaluation | C2 |
| `pub mod namespace` | keep | Typed rules and labels (1.5) | C3, C4 |
| `pub mod net` | keep | `IpNet`, `Protocol` | - |
| `pub mod pinhole` | keep | Spec keyed by label | C3 |
| `pub mod reasons` | keep | Plus `POLICY_FAILED` | C2 |
| `pub mod rules` | new | `Label`, `LabelSet`, `RuleId`, `Rule`, `ProtocolMatch`, `PortSet`, `IcmpTypes`, `Flow`, `Transport`, `Decision`, `Matched`, `PolicyState`, `NotInstalled` | C2 |
| `pub mod gate` | new | The generic flow gate (section 5) | C5 |
| `pub mod policy` | remove | The JSON policy document belongs to the product (AG-3) | C4 |
| `pub mod merge` | remove | Layering product policy sources is control-plane work | C4 |
| `pub mod deny_scope` | remove | It edits the policy text before compilation. That is product work | C4 |
| `pub mod matcher` | remove (made private) | Its items are already `pub(crate)`. The string parsers go away in C4, and the compiled matchers move into `rules` | C2, C4 |
| `mod node_l3` | replace | `pub mod gate` | C5 |

### 1.2 Policy document, merge and deny scope (AG-3)

| Item | Fate | Reason / replacement | Slice |
| --- | --- | --- | --- |
| `AclPolicy` (`hosts`, `acls`, `tests`) | remove | Product document. Replacement: `Vec<Rule>` / `RuleSet`. Host aliases are expanded by the product | C4 |
| `AclRule` | remove | Replaced by `Rule` (one typed rule per src x dst-host combination) | C4 |
| `AclAction` | remove | The model is accept-only, so an action field adds nothing | C4 |
| `AclTest` | remove | Policy self-tests are a product feature. Replacement: `RuleSet::matching` / `AclEngine::evaluate` on `Flow`s the product builds | C4 |
| `merge_layered` | remove | Merges product sources (local / remote by source id / last-good cache) into one document. Replacement: one namespace per source (`store_namespace`), or the product merges into one `RuleSet` | C4 |
| `PolicyLayers`, `RemotePolicy` | remove | Inputs of `merge_layered` | C4 |
| `MergedPolicy`, `MergeStats` | remove | Output of `merge_layered` | C4 |
| `RuleProvenance` | remove | Provenance becomes the product's `RuleId` text | C4 |
| `acl_rule_key`, `acl_test_key` | remove | Dedup keys of the document text | C4 |
| `apply_deny_scope` | remove | Edits the document. Replacement: the product drops rules before `RuleSet::new` | C4 |
| `DenyScope`, `DenyScopeOutcome`, `DroppedRule`, `DropReason` | remove | Inputs and outputs of `apply_deny_scope` | C4 |

### 1.3 Engine and evaluation (AG-1, AG-2)

| Item | Fate | Reason / replacement | Slice |
| --- | --- | --- | --- |
| `AccessRequest` (`from_ip`, `with_wg_peer_key`) | replace | `Flow` plus `&LabelSet` (2.5) | C2 |
| `AclDecision` (`allowed`, `matched_rule_index`, `reason: String`) | replace | `Decision` (`Accept(Matched)` with a `RuleId`, or `Deny(&'static str)`) | C2 |
| `CompiledPolicy` | replace | `RuleSet` (validated typed rules, cheap to share through `Arc`) | C2 |
| `CompiledPolicy::compile(AclPolicy)` | replace | `RuleSet::new(rules)`. A temporary `RuleSet::from_document(AclPolicy)` adapter lives until C4 | C2, C4 |
| `CompiledPolicy::permit_all` | remove | Use `AclEngine::with_not_installed(NotInstalled::Accept)`, or install a rule with `ProtocolMatch::Any` | C2 |
| `CompiledPolicy::is_allowed` | replace | `RuleSet::matching(&LabelSet, &Flow) -> Option<&RuleId>` | C2 |
| `CompiledPolicy::validate_tests` | remove | Self-tests are the product's job (see `AclTest`) | C4 |
| `AclTestFailure` | remove | Same as `AclTest` | C4 |
| `AclEngine` | keep (API changes in 2.6) | `load` -> removed (C4). `store` -> `install`. `clear` -> `uninstall`. New `fail`, `policy_state`, `with_not_installed`. `policy` -> `rules`. `is_allowed` -> removed (use `rules()?.matching`). `evaluate` takes `(&LabelSet, &Flow)`. `memberships` takes `&Label`. `store_grant` takes `impl Into<RuleId>` | C2..C4 |
| `SourceAssertion` (`WgPeerKey`, `Terminate`, `External`), `source_class`, `source_anchor`, `ip` | remove | Product identity model. Replacement: `LabelSet` from `PeerIdentity` | C3 |
| `TerminateBinding` | remove | Same as `SourceAssertion` | C3 |
| `wg_peer_anchor` | remove | Encodes a product principal (`key:<hex>`). The product builds its own label text | C3 |
| `Error::InvalidCidr` | remove | Only alias and deny-scope text could produce it. Typed `IpNet`s are parsed by the caller (`ParseIpNetError`) | C4 |
| `Error::InvalidDst` | remove | Only the `host:ports` text could produce it | C4 |
| `Error::UnknownAlias` | remove | Host aliases are gone | C4 |
| `Error::TestsFailed` | remove | Self-tests are gone | C4 |
| `Error::InvalidPolicy(String)` | replace | `Error::InvalidRule { id: RuleId, reason: String }`, `Error::InvalidNamespace { id: NamespaceId, reason: String }`, `Error::InvalidGrant { id: RuleId, reason: String }` (`#[non_exhaustive]`) | C2 (add), C4 (remove old) |

### 1.4 Filter, identity, flows

| Item | Fate | Reason / replacement | Slice |
| --- | --- | --- | --- |
| `AclFilter` (`new`, `with_config`, `with_scope`, `stats`) | keep | Resolves labels instead of principals (section 3) | C3 |
| `AclFilterConfig::crates_acl(local)` | remove | Product preset (ADR: no product presets). The spec lists its field values | C4 |
| `AclFilterConfig::{fragment_capacity, allow_other_protocols, stateful_replies, reply_capacity, reply_idle_timeout}` | keep | Generic | - |
| `AclFilterConfig::fragments` / `FragmentMode::{Outcome, AllowOnly}` | keep | Generic gating modes. The rustdoc no longer cites a product type | C4 |
| `FragmentMode::ALLOW_ONLY` | remove | A product's values (15 s, 4096). The spec keeps them | C4 |
| `AclFilterConfig::accept_to_local` | keep | Generic: an IPv4 address whose inbound packets skip the policy | - |
| `AclFilterConfig::accept_icmp_echo_reply` | keep | Generic | - |
| `AclFilterConfig::ipv6` / `Ipv6Mode::{Evaluate, Accept}` | keep | Generic. The rustdoc drops the product rationale | C4 |
| `AclFilterScope` (`outbound_sources`, `other_protocols`, `new`, `with_*`) | keep | Generic | - |
| `OtherProtocolRule`, `OtherProtocol::{IcmpEcho, Icmp, Ip}` | keep | Generic scope rules. They are not label-gated and still run before the rules (2.4) | - |
| `AclFilterStats` | keep + 2 fields | New `policy_failed: u64` counter and `policy_state: PolicyState` (read at `stats()`) | C2 |
| `PeerIdentity` | keep (rewritten) | Yields `LabelSet`s (section 3) | C3 |
| `PeerIdentityMap` | rename | `PeerLabelMap` | C3 |
| `PeerIdentityMap::insert(peer, SourceAssertion)` | replace | `PeerLabelMap::insert(peer, LabelSet)` | C3 |
| `PeerIdentityMap::insert_by_source(peer)` | replace | `PeerLabelMap::insert_by_source(peer, Vec<(IpNet, LabelSet)>)`: labels per remote address, longest prefix wins (section 3) | C3 |
| `PeerIdentityMap::remove` | keep | | C3 |
| `FlowTracker`, `FlowKey`, `FlowStats` | keep | Generic per-flow counters | - |
| `IpNet`, `ParseIpNetError` | keep | | - |
| `Protocol` (`Tcp`, `Udp`, `from_ip_number`) | keep | The port-carrying protocols, used by pinholes and `find_flow`. Rules use `ProtocolMatch` | - |
| `reasons::{DENIED, NO_POLICY, UNKNOWN_PEER, PROTOCOL, FRAGMENT, MALFORMED, CROSS_NAMESPACE, OUTBOUND, OUTBOUND_SOURCE, INTERNAL}` | keep | `NO_POLICY` is now "not installed, default deny". `UNKNOWN_PEER` is now "identity returned `None`" | C2, C3 |
| `reasons::POLICY_FAILED` | new | `"acl policy failed"` (the `Failed` state, 2.3) | C2 |

### 1.5 Namespaces, grants, pinholes

| Item | Fate | Reason / replacement | Slice |
| --- | --- | --- | --- |
| `NamespaceId` | keep | Opaque id | - |
| `NamespaceId::is_app` and the `"app:"` prefix | replace | `NamespacePolicy::kind: NamespaceKind::{Rules, Pinholes}`. A magic id prefix encodes a product convention | C3 |
| `NamespaceMember::principal: String` | replace | `NamespaceMember::label: Label` | C3 |
| `NamespaceMember::addresses` | keep | | - |
| `NamespacePolicy::policy: AclPolicy` | replace | `NamespacePolicy::rules: Vec<Rule>` | C4 |
| `NamespacePolicy::allow_app_pinholes` | rename | `pinhole_kinds: BTreeSet<String>` | C3 |
| `NamespacePolicy::outbound` | keep | `Option<Vec<OutboundRule>>` | - |
| `OutboundRule::{proto: Option<String>, ports: String}` | replace | `OutboundRule { id: RuleId, protocols: Vec<ProtocolMatch> }` | C4 |
| `Grant::{proto, ports}` (strings) | replace | `Grant::protocols: Vec<ProtocolMatch>` | C4 |
| `GrantEnd::Peer(String)` | replace | `GrantEnd::Label(Label)` | C3 |
| `GrantEnd::Namespace` | keep | It may not name a `Pinholes` namespace | - |
| `PinholeSpec::peer: String` | replace | `PinholeSpec::label: Label` | C3 |
| `PinholeSpec::kind` | keep | Opaque, checked against `pinhole_kinds` | - |
| `PinholeSpec::{protocol, direction, dst_port, expires_at}` | keep | | - |
| `PinholeError::NotAppNamespace` | rename | `NotPinholeNamespace` | C3 |
| `PinholeError::{UnknownNamespace, NotMember, NotPermitted, Expired}` | keep | | - |
| `PinholeGuard`, `PinholeId`, `PinholeStats`, `Direction` | keep | `Direction` is also used by the gate (rustdoc made generic) | - |

### 1.6 Node L3 gate (AG-4)

| Item | Fate | Reason / replacement | Slice |
| --- | --- | --- | --- |
| `NodeL3Gate` | replace | `gate::FlowGate` | C5 |
| `NodeL3Gate::{new, new_for_targets, with_limits, with_clock}` | replace | `FlowGate::new(GateConfig)`, `FlowGate::with_clock(GateConfig, clock)`. Target machine ids are a product authority concept | C5 |
| `NodeL3Gate::{apply, apply_from_source, withdraw_source}` | replace | `FlowGate::replace(GatePolicy)`. Sources, tombstones, stale/phase checks move to the product | C5 |
| `NodeL3Gate::{replace_transport_projection, replace_transport_projection_after_build, stage_transport_projection, withdraw_transport_projection}` | remove | The product compiles its device projection into `GateBinding`s, `GateHolds` and `UnboundRule`s | C5 |
| `NodeL3Gate::replace_provider_listeners` | remove | The product sets `GateGrant::suspended` and recompiles | C5 |
| `NodeL3Gate::{ready_for_ack, peer_readiness_snapshot}` | remove | Pure functions of product state | C5 |
| `NodeL3Gate::{enforced_subnet_authorizations, enforced_subnet_return_peer_key, enforced_subnet_return_owners, enforced_subnet_ingress_authorized, enforced_subnet_ingress_prefixes}` | remove | Pure queries over product config. Not packet state | C5 |
| `NodeL3Gate::{authorization_generation, set_on_authorization_change}` | remove | The product's own change marker | C5 |
| `NodeL3Gate::{evaluate_inbound, evaluate_outbound}(peer_key, packet)` | replace | `FlowGate::{evaluate_inbound, evaluate_outbound}(PeerId, packet)` | C5 |
| `NodeL3Gate::{evaluate_subnet_transport_inbound, evaluate_subnet_transport_outbound}` | remove | Compiled as ordinary `GateGrant`s (5.4) | C5 |
| `NodeL3Gate::service_flow_authorized` | replace | `FlowGate::find_flow(remote, local, Protocol) -> Option<LiveFlow>` | C5 |
| `NodeL3Gate::{gateway_consumer_packet, gateway_consumer_authority_current}` | replace | `UnboundRule { action: Divert }`, `GateDivert`, `DivertedPacket`, `FlowGate::generation` | C5 |
| `NodeL3Gate::counters` / `NodeL3Counters` | rename | `FlowGate::counters` / `GateCounters` (`source_binding_denied` -> `unbound_denied`) | C5 |
| `NodeL3Config`, `NODE_L3_SCHEMA_VERSION` | replace / remove | `GatePolicy` / `GateScope`. The schema version is a product wire concern | C5 |
| `NodeL3Mode::{Disabled, Observe, Enforce}` | rename | `GateMode::{Off, Observe, Enforce}` | C5 |
| `NodeL3Node`, `NodeL3PeerBinding` | replace | `GateBinding { peer: PeerId, addresses, labels }` | C5 |
| `NodeL3Grant`, `NodeL3Resource` | replace | `GateGrant { id, direction, labels, destinations, protocols, suspended }` | C5 |
| `NodeL3ServiceEndpoint` | remove | Folded into grants by the product | C5 |
| `NodeL3ServiceProtocol` | replace | `Protocol` | C5 |
| `NodeL3PeerPolicyRequirement` | replace | `GateHolds` | C5 |
| `NodeL3Transport`, `NodeL3TransportPeer`, `NodeL3TransportError` | remove | Product device projection | C5 |
| `NodeL3Applied` | replace | `replace` returns the new gate generation (`u64`) | C5 |
| `NodeL3ConfigError` | replace | `GatePolicyError` (generic validation only) | C5 |
| `NodeL3SubnetAuthorization` | remove | Product query result | C5 |
| `NodeL3PeerReadiness`, `NodeL3PeerReadinessReason` | remove | Product status | C5 |
| `NodeL3Decision::{Legacy, Observe, Enforce}`, `enforced_verdict` | rename | `GateDecision::{Pass, Observe, Enforce}`, `enforced_verdict` | C5 |
| `NodeL3Reason` (`as_str`, `drop_reason`) | replace | `GateReason` (table in 5.3) | C5 |
| `NodeL3Filter` (`new`, `with_acl`, `with_acl_outbound`, `with_subnet_transport_port`, `with_divert`, `gate`, `stats`) | rename | `GateFilter`. `with_subnet_transport_port` is removed (5.4) | C5 |
| `NodeL3FilterStats` | rename | `GateFilterStats` (without `unknown_peer`) | C5 |
| `PeerPublicKeys`, `PeerKeyMap` | remove | The gate binds by `PeerId` in its policy (5.1) | C5 |
| `GatewayConsumerSink` | replace | `GateDivert` | C5 |
| `GatewayConsumerPacket` | replace | `DivertedPacket` | C5 |
| `GatewayConsumerAuthority` (`gateway_id`, `source_id`, `same_snapshot`) | replace | `DivertedPacket::{generation, scope, rule, peer}` | C5 |

## 2. AG-1: generic core

### 2.1 Labels and rule IDs

```rust
/// An opaque source label. nsplane compares labels for equality only.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Label(/* Arc<str> plus a precomputed 64-bit hash */);
impl Label {
    pub fn new(text: impl Into<Arc<str>>) -> Self;
    pub fn as_str(&self) -> &str;
}
impl From<&str> for Label; impl From<String> for Label; impl fmt::Display for Label;

/// A set of labels, sorted and without duplicates. Clone is one `Arc` increment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LabelSet(/* Arc<[Label]> sorted by (hash, text) */);
impl LabelSet {
    pub fn new(labels: impl IntoIterator<Item = Label>) -> Self;
    pub fn empty() -> Self;
    pub fn contains(&self, label: &Label) -> bool;
    pub fn intersects(&self, labels: &[Label]) -> bool;
    pub fn iter(&self) -> impl Iterator<Item = &Label>;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}
impl FromIterator<Label> for LabelSet;

/// An opaque rule identifier, carried into decisions and logs. Need not be unique.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RuleId(/* Arc<str> */);
impl RuleId { pub fn new(text: impl Into<Arc<str>>) -> Self; pub fn as_str(&self) -> &str; }
impl From<&str> for RuleId; impl From<String> for RuleId; impl fmt::Display for RuleId;
```

No allocation per packet:

- Labels and sets are built by the caller.
- The filter caches each peer's `LabelSet` (section 3).
- Rules keep their labels sorted by the same `(hash, text)` order. A match is a merge over
  the two sorted slices that compares hashes and compares strings only when two hashes are
  equal.
- A `RuleId` is cloned only when a `Decision` is built (`evaluate`), when a gate flow is
  created, or when a log line is enabled. The filter's verdict cache stores no `RuleId`.

### 2.2 Typed rules

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    /// Source labels; empty: any source.
    pub labels: Vec<Label>,
    /// Source address prefixes; empty: any source address.
    pub sources: Vec<IpNet>,
    /// Destination address prefixes; empty: any destination address.
    pub destinations: Vec<IpNet>,
    /// Protocols (with ports or ICMP types); must not be empty.
    pub protocols: Vec<ProtocolMatch>,
}
impl Rule { pub fn new(id: impl Into<RuleId>, protocols: Vec<ProtocolMatch>) -> Self; /* with_labels, with_sources, with_destinations builders */ }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolMatch {
    /// Every protocol, every port and ICMP type.
    Any,
    /// TCP to these destination ports.
    Tcp(PortSet),
    /// UDP to these destination ports.
    Udp(PortSet),
    /// ICMP (IPv4) or ICMPv6 (IPv6), by message type.
    Icmp(IcmpTypes),
    /// Another IP protocol number (not 1, 6, 17 or 58: use the variants above).
    Ip(u8),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortSet { Any, Ranges(Vec<RangeInclusive<u16>>) }   // PortSet::single(p), ::list(..)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcmpTypes { Any, Only(Vec<u8>) }

/// A validated, immutable rule list (default policy or one namespace's rules).
pub struct RuleSet { /* rules plus their compiled form */ }
impl RuleSet {
    pub fn new(rules: impl IntoIterator<Item = Rule>) -> Result<Self, Error>;
    pub fn empty() -> Self;
    pub fn rules(&self) -> &[Rule];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    /// The first rule matching `flow` from a source with `labels` (rules only: no
    /// namespaces, grants or pinholes). For product self-tests.
    pub fn matching(&self, labels: &LabelSet, flow: &Flow) -> Option<&RuleId>;
}
```

`RuleSet::new` rejects these with `Error::InvalidRule { id, reason }`:

- an empty `protocols` list;
- a range with start greater than end;
- an empty `PortSet::Ranges` or an empty `IcmpTypes::Only` (they would match nothing);
- `Ip(1 | 6 | 17 | 58)`.

**Matching semantics.** Rule `r` matches flow `f` from a source with label set `S` when
all four conditions hold:

1. **Labels**: `r.labels` is empty, or `S` contains at least one of `r.labels`
   (any-match). A source with an empty `S` matches only rules whose `labels` is empty.
   An unknown source (the identity returned `None`) never reaches the rules (2.5).
2. **Source prefixes**: `r.sources` is empty, or `f.src` lies in one of them. An address
   of the other family never matches.
3. **Destination prefixes**: `r.destinations` is empty, or `f.dst` lies in one of them.
4. **Protocol**: some entry of `r.protocols` matches `f.transport`:
   - `Any` matches every flow.
   - `Tcp(p)` matches `Transport::Tcp` when `p` contains `dst_port`. `Udp(p)` works the
     same way for UDP.
   - `PortSet::Any` contains every port. `Ranges` contains a port that lies in one of the
     inclusive ranges.
   - `Icmp(t)` matches `Transport::Icmp` (protocol 1 on IPv4, 58 on IPv6) when `t` is
     `Any` or lists the message type.
   - `Ip(n)` matches `Transport::Ip(n)`.

Conditions 1-4 are a conjunction. A rule that sets both `labels` and `sources` therefore
matches only a source that carries one of the labels **and** sends from inside one of the
prefixes. A product uses this to give address rules to one class of sources only (4.2).

Rules are a union. The verdict does not depend on rule order, and the reported `RuleId` is
that of the first matching rule in list order. Rule IDs need not be unique, so a product can
split one rule of its own into several typed rules that share an ID.

**Today's semantics.** For comparison, an `AclRule` source today is `*`, `key:<hex>`, a
CIDR or a host alias:

- A `key:<hex>` source matches only a `WgPeerKey` assertion.
- A CIDR source matches only an IP-bearing `Terminate` binding.
- The destination is a list of `host:ports`, and `proto` is TCP, UDP or both.

The typed model expresses each of these:

- `key:<hex>` becomes a label.
- A CIDR source becomes `sources`, plus a label that only address-bound sources carry.
- One rule becomes one typed rule per destination entry.
- `proto` becomes `Tcp(p)`, `Udp(p)` or both.

### 2.3 Policy states

```rust
/// What applies to sources in no namespace while no rule set is installed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NotInstalled { #[default] Deny, Accept }

/// The state of the engine's default rule set (sources in no namespace).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PolicyState {
    /// Nothing installed: the engine's `NotInstalled` action applies.
    #[default] NotInstalled,
    /// A rule set is installed (possibly empty: every new flow denied).
    Installed { rules: usize },
    /// The caller reported a failure: fail closed.
    Failed,
}
```

Each state decides as follows for a new inbound flow from a source in no namespace:

| State | Decision | Counter | When nothing else is loaded (no namespace) |
| --- | --- | --- | --- |
| `NotInstalled`, `Deny` (default) | `Deny(NO_POLICY)` | `no_policy` | every inbound packet, replies included, dropped `NO_POLICY` (today's "unloaded") |
| `NotInstalled`, `Accept` | `Accept(Matched::NotInstalled)` | `accepted` | every inbound packet accepted (replaces `permit_all`) |
| `Installed`, empty | `Deny(DENIED)` | `denied` | replies to flows the local side opened still pass |
| `Installed`, non-empty | the rules decide | `accepted` / `denied` | as today with a loaded default policy |
| `Failed` | `Deny(POLICY_FAILED)` | `policy_failed` | every inbound packet, replies included, dropped `POLICY_FAILED` |

The engine counts as loaded when any of these holds: the state is `Installed`, a namespace
is stored, or the state is `NotInstalled` with `Accept`. Namespace members are governed by
their namespaces in every state, as today. The state is visible in three places:

- `AclEngine::policy_state()`;
- `AclFilterStats::policy_state`, read at `stats()`;
- the counters `no_policy` and `policy_failed`.

### 2.4 Namespaces, outbound rules, grants and pinholes on typed rules and labels

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamespaceKind {
    /// Members are governed by the namespace's rules (today's source namespaces).
    #[default] Rules,
    /// No rules; members get access only through pinholes (today's `app:` namespaces).
    Pinholes,
}
pub struct NamespaceMember { pub label: Label, pub addresses: Vec<IpNet> }
pub struct NamespacePolicy {
    pub kind: NamespaceKind,
    pub members: Vec<NamespaceMember>,
    pub rules: Vec<Rule>,
    pub outbound: Option<Vec<OutboundRule>>,
    pub pinhole_kinds: BTreeSet<String>,
}
pub struct OutboundRule { pub id: RuleId, pub protocols: Vec<ProtocolMatch> }
pub enum GrantEnd { Namespace(NamespaceId), Label(Label) }
pub struct Grant { pub from: GrantEnd, pub to: GrantEnd, pub protocols: Vec<ProtocolMatch> }
pub struct PinholeSpec {
    pub label: Label, pub kind: String, pub protocol: Protocol,
    pub direction: Direction, pub dst_port: u16, pub expires_at: Instant,
}
```

Validation:

- `store_namespace` compiles `rules` into a `RuleSet` and validates `outbound`. A
  `Pinholes` namespace with rules or `pinhole_kinds` is rejected with
  `Error::InvalidNamespace`.
- `store_grant(id: impl Into<RuleId>, grant)` validates `protocols`. A grant end that names
  a `Pinholes` namespace is rejected with `Error::InvalidGrant`.

**Membership** is keyed by label. Every `NamespaceMember` places its `label` in the
namespace. A source with label set `S` is a member of the union of the namespaces of every
label in `S`. It is outbound-restricted when it is a member of at least one namespace and
every namespace it belongs to sets `outbound`.

A destination address resolves to the member label owning it: longest prefix first, and
the smallest label (in `Label` order) on a tie. That label's namespaces are the
destination's namespaces.

The evaluation order of today's crate docs stays as it is, with labels in place of
principals:

1. Common `Rules` namespaces: the rules of each common namespace are matched.
2. A directed grant: `GrantEnd::Label(l)` matches the source end when `l` is in `S`, and
   the destination end when `l` is the destination's member label. `GrantEnd::Namespace`
   matches by membership. The grant's `protocols` must match the flow.
3. An inbound pinhole whose `label` is in `S`, for a local destination.
4. Otherwise `CROSS_NAMESPACE` or `DENIED`, as today.

Outbound rules match the protocol and destination port (or ICMP type) of a flow towards a
restricted peer. Pinhole permission (`pinhole_kinds`) is checked against the source's
`Rules` namespaces.

**Non-TCP/UDP inbound packets** now also reach the rules. The order is:

1. reply allowance;
2. `allow_other_protocols`;
3. `AclFilterScope::other_protocols`;
4. the rule evaluation above, including namespace rules and grants with `Icmp` / `Ip` /
   `Any` entries. Pinholes stay TCP/UDP only;
5. drop with `PROTOCOL`.

Every denial of a non-TCP/UDP flow is reported as `PROTOCOL`, as today. Such flows get no
verdict cache. Their side effects are those of an accepted TCP/UDP flow: a grant
dependency, and the outbound allowance of a restricted peer.

Outbound non-TCP/UDP packets to a restricted peer are checked in this order:
`allow_other_protocols`, the reply allowance, the outbound rules (new), then a drop with
`OUTBOUND`.

A rule set without `Icmp`, `Ip` or `Any` entries therefore behaves exactly as today (see
open question Q3).

### 2.5 Packet-independent evaluation

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flow { pub src: IpAddr, pub dst: IpAddr, pub transport: Transport }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp { src_port: u16, dst_port: u16 },
    Udp { src_port: u16, dst_port: u16 },
    Icmp { icmp_type: u8 },
    Ip(u8),
}
impl Flow {
    pub fn tcp(src: SocketAddr, dst: SocketAddr) -> Self;
    pub fn udp(src: SocketAddr, dst: SocketAddr) -> Self;
    pub fn icmp(src: IpAddr, dst: IpAddr, icmp_type: u8) -> Self;
    pub fn ip(src: IpAddr, dst: IpAddr, protocol: u8) -> Self;
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    Accept(Matched),
    /// A `reasons::*` constant.
    Deny(&'static str),
}
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Matched {
    Rule { namespace: Option<NamespaceId>, id: RuleId },
    Grant(RuleId),
    Pinhole(PinholeId),
    /// `PolicyState::NotInstalled` with `NotInstalled::Accept`.
    NotInstalled,
}
impl Decision {
    pub fn is_accept(&self) -> bool;
    pub fn rule_id(&self) -> Option<&RuleId>;      // Rule or Grant
    pub fn reason(&self) -> Option<&'static str>;  // Deny only
}

impl AclEngine {
    /// The decision for a new inbound flow `flow` from a source with `labels`.
    pub fn evaluate(&self, labels: &LabelSet, flow: &Flow) -> Decision;
}
```

`evaluate` with a family-mixed `flow` returns `Deny(MALFORMED)`. A pinhole that has expired
but has not been swept is swept, as today. `evaluate` always runs the full evaluation (no
bypass shortcut), so an accepted flow reports the rule, grant or pinhole that accepts it.

**Equivalence with the filter.** Take an `AclFilter` over engine `E` and identity `I`, an
inbound packet from peer `P`, and `L = I.labels_for(P, src)`. Assume all of these hold:

- `L` is `Some(labels)`;
- the packet is well formed, unfragmented or a first fragment;
- it is not taken by `Ipv6Mode::Accept`, `accept_to_local` or `accept_icmp_echo_reply`;
- no reply allowance exists for its tuple;
- for non-TCP/UDP packets: neither `allow_other_protocols` nor a scope rule accepts it.

Then:

- The filter accepts the packet exactly when `E.evaluate(&labels, &flow)` is `Accept`,
  where `flow` is the packet's five-tuple (or ICMP type, or protocol).
- When `evaluate` returns `Deny(r)`, the filter drops the packet with reason `r` and bumps
  the counter of `r`.
- A cached verdict, or a bypass, gives the same verdict and counters as this full
  evaluation. That is the existing engine guarantee, now extended to labels and policy
  states, and the differential test checks it.

When `L` is `None`, the filter drops the packet with `UNKNOWN_PEER`, which `evaluate`
cannot express. `RuleSet::matching` equals `evaluate` for a source in no namespace while
that set is installed.

**Logs.** Every full evaluation emits `tracing::debug!` with `src`, `dst`, `proto`, `port`,
and either `rule` (the `RuleId`), `grant`, `pinhole` or `reason`.

**Drop events.** `Verdict::Drop { reason: &'static str }` is the nsplane-core contract and
does not change. An accept-only model has no rule behind a drop. Drops carry the step's
reason constant, and rule IDs travel in `Decision`, in gate decisions and in logs (Q1).

### 2.6 Engine API after C2..C4

```rust
impl AclEngine {
    pub fn new() -> Self;
    pub fn with_clock(clock: impl Fn() -> Instant + Send + Sync + 'static) -> Self;
    #[must_use] pub fn with_not_installed(self, action: NotInstalled) -> Self;
    pub fn install(&self, rules: impl Into<Arc<RuleSet>>);   // state Installed, one swap
    pub fn uninstall(&self);                                  // state NotInstalled
    pub fn fail(&self);                                       // state Failed
    pub fn policy_state(&self) -> PolicyState;
    pub fn rules(&self) -> Option<Arc<RuleSet>>;
    pub fn clear_all(&self);   // namespaces, grants, pinholes removed; state Failed (Q2)
    pub fn evaluate(&self, labels: &LabelSet, flow: &Flow) -> Decision;
    pub fn store_namespace(&self, id: impl Into<NamespaceId>, policy: NamespacePolicy) -> Result<(), Error>;
    pub fn remove_namespace(&self, id: &str) -> bool;
    pub fn namespaces(&self) -> Vec<NamespaceId>;
    pub fn memberships(&self, label: &Label) -> Vec<NamespaceId>;
    pub fn store_grant(&self, id: impl Into<RuleId>, grant: Grant) -> Result<(), Error>;
    pub fn remove_grant(&self, id: &str) -> bool;
    pub fn grants(&self) -> Vec<(RuleId, Grant)>;
    pub fn open_pinhole(self: &Arc<Self>, namespace: impl Into<NamespaceId>, spec: PinholeSpec) -> Result<PinholeGuard, PinholeError>;
    pub fn expire_pinholes(&self) -> usize;
    pub fn generation(&self) -> u64;
    pub fn pinhole_stats(&self) -> PinholeStats;
}
```

Every mutation publishes one immutable snapshot under a new generation, as today.
Validation happens before publication: `RuleSet::new`, `store_namespace` and `store_grant`
return `Err` and change nothing, so a rejected update keeps the previous state.

`fail()` is for a product whose own compilation failed. nsplane never moves to `Failed`
on its own.

## 3. AG-2: source identity to labels

```rust
pub trait PeerIdentity: Send + Sync + 'static {
    /// The labels of `peer`; `None`: unknown peer (dropped with `UNKNOWN_PEER`).
    fn labels(&self, peer: PeerId) -> Option<LabelSet>;
    /// The labels of `peer` for a packet whose remote address is `remote` (the IP source
    /// of an inbound packet, the IP destination of an outbound one). The filter resolves
    /// every source through this method. Default: `labels(peer)`.
    fn labels_for(&self, peer: PeerId, remote: IpAddr) -> Option<LabelSet> {
        let _ = remote;
        self.labels(peer)
    }
    /// Whether `labels_for(peer, _)` depends on the address. Default `false`.
    fn by_source(&self, peer: PeerId) -> bool { let _ = peer; false }
    /// Non-zero and changed whenever any answer may have changed; 0: not versioned.
    fn generation(&self) -> u64 { 0 }
}
impl<F> PeerIdentity for F where F: Fn(PeerId) -> Option<LabelSet> + Send + Sync + 'static;
impl<T: PeerIdentity + ?Sized> PeerIdentity for Arc<T>;

/// A concurrent, versioned map from peers to labels.
pub struct PeerLabelMap { /* RwLock<HashMap<PeerId, Entry>>, AtomicU64 generation */ }
impl PeerLabelMap {
    pub fn new() -> Self;
    pub fn insert(&self, peer: PeerId, labels: LabelSet);
    /// Labels per remote address: the longest prefix containing the address wins; an
    /// address outside every prefix makes the source unknown.
    pub fn insert_by_source(&self, peer: PeerId, by_address: Vec<(IpNet, LabelSet)>);
    pub fn remove(&self, peer: PeerId);
}
```

**Generation and by-source contract.** These carry over from today unchanged:

- The filter asks `by_source` once per peer and identity generation.
- It caches a by-source peer's labels per (peer, address), and any other peer's labels per
  peer.
- A versioned implementation must return `true` from `by_source` for every peer whose
  labels depend on the address. It bumps `generation` after a change becomes visible
  (`PeerLabelMap` does so under its write lock).
- Generation 0 disables every cache and the bypass. The filter then resolves and evaluates
  every packet.

**Cache.** `PeerInfo` replaces `{ source: SourceAssertion, principal: Arc<str> }` with the
following fields:

- `labels: Option<LabelSet>`;
- `membership: Option<Arc<Membership>>`, the union over the labels, computed once at
  resolution;
- `governed` (`Default` / `Member` / `Restricted`), `pinholes`, `bypass`.

It is tagged with the engine and identity generations, as today. The bounds, the LRU table
for by-source addresses (`reply_capacity`) and the lock layout are unchanged. On the packet
path, a cached peer costs one `Arc` already held under the flow-table lock and allocates
nothing.

**Namespace membership is keyed by label** (2.4). The snapshot keeps:

- `HashMap<Label, Membership>`;
- host addresses `HashMap<IpAddr, Label>`;
- other member prefixes `Vec<(IpNet, Label)>`.

The union for a multi-label source is built at resolution time, not per packet.

**Bypass on labels.** On every publication the snapshot precomputes these:

- `default_bypass`: the state is `NotInstalled` with `Accept`, or the installed set holds a
  rule with empty `labels`, `sources` and `destinations` whose protocols cover all TCP and
  all UDP;
- the open namespaces: `Rules` namespaces with such a rule;
- the distinct namespace sets of the destination owners (every member label owning an
  address).

When a peer is resolved, it bypasses if it is not outbound-restricted and its open
namespaces intersect every distinct owner set. This takes a few set intersections per
resolution and nothing per packet. A source in no namespace bypasses when
`default_bypass` holds. An unknown source never bypasses.

## 4. AG-3: document removal

### 4.1 Removal list

In code:

- `src/policy.rs`: `AclPolicy`, `AclRule`, `AclAction`, `AclTest`, and the hosts
  deserializer.
- `src/merge.rs` and `src/deny_scope.rs`, with every item in 1.2.
- The string parsers in `src/matcher.rs` (`parse_src`, `parse_dst`, `parse_ports`,
  `parse_protocol`, `parse_hex32`). The compiled matchers move into `rules`.
- `CompiledPolicy::compile`, `validate_tests` and `parse_test_dst`, and
  `RuleSet::from_document`.
- `AclEngine::load`.
- `AclFilterConfig::crates_acl` and `FragmentMode::ALLOW_ONLY`.
- The string `proto` / `ports` of `OutboundRule` and `Grant`.
- `NamespacePolicy::policy`.
- `Error::{InvalidCidr, InvalidDst, UnknownAlias, TestsFailed, InvalidPolicy}`.

Tests and fixtures:

- `tests/crates_acl_parity.rs` and `tests/fixtures/crates_acl_parity.json`. They move to
  the product side through the AG-3 spec `docs/specs/acl-policy-document.md`, which keeps
  the fixture as `docs/specs/data/acl-crates-acl-parity.json` together with the rule
  compilation (4.2).

Docs:

- The crate docs section "The ns `crates/acl` mode", and the rustdoc that cites ns in
  `filter.rs` and `lib.rs`.

### 4.2 How a product rebuilds the old semantics

These mappings go into the specs, not into nsplane:

- **Hosts**: alias to CIDR, expanded by the product.
- **`src`**: `*` gives no labels and no sources. `key:<hex>` gives `labels: ["key:<hex>"]`.
  A CIDR or alias gives `sources: [cidr]` plus `labels: [A]`, where `A` is a product label
  given only to address-bound sources. That reproduces the rule that a CIDR source matches
  only IP-bearing (terminate) principals.
- **`dst`**: each `host:ports` entry becomes its own rule with
  `destinations: [cidr]` (none for `*`). A port list or range becomes `PortSet::Ranges`,
  and `*` becomes `PortSet::Any`.
- **`proto`**: `tcp` gives `Tcp(p)`, `udp` gives `Udp(p)`, and absent gives both.
- **Rule id**: `"<layer>:<index>"` (`acl-policy-document.md` section 3).
- **Tests**: evaluated by the product with `RuleSet::matching` on `Flow`s built from
  `src` / `dst` / `proto`.
- **The `crates_acl` preset** sets these `AclFilterConfig` fields explicitly:
  `stateful_replies = false`, `allow_other_protocols = false`,
  `fragments = AllowOnly { ttl: 15 s, capacity: 4096 }`, `accept_to_local = Some(local)`,
  `accept_icmp_echo_reply = true`, `ipv6 = Ipv6Mode::Accept`.
- **Identities**:
  - a relay client gets `PeerLabelMap::insert(peer, {"key:<hex>"})`;
  - every other peer gets `insert(peer, {A})`. A per-address principal is not needed,
    because CIDR rules now read the flow's source address directly.

### 4.3 Generic tests replacing the parity and differential tests

`tests/crates_acl_parity.rs` exercised these semantics. Each one gets a generic unit test
in `src/filter.rs` (existing tests are kept and ported to labels, the missing ones are
added) and the case named in parentheses:

- the `accept_to_local` bypass precedes everything except `Ipv6Mode::Accept`
  (`accept_to_local_precedes_the_policy`);
- the `accept_icmp_echo_reply` raw-header checks (IHL, 8 bytes after the header), including
  a non-first fragment (`echo_reply_bypass_reads_the_raw_header`);
- `FragmentMode::AllowOnly`:
  - only accepted first fragments are recorded, keyed without peer or direction;
  - the TTL follows the engine clock, and the last fragment keeps the entry;
  - when the table is full, expired entries are removed first and nothing is recorded if
    it is still full;
  - non-first fragments are judged before the no-policy check
  (`allow_only_fragments_*`, existing, ported);
- with `stateful_replies` off there are no allowances in either direction, and replies are
  judged by the rules (`stateless_replies_are_judged_by_the_rules`);
- `Ipv6Mode::Accept` works in both directions and keeps no state (existing, ported);
- malformed IPv4 is dropped `MALFORMED`: a total length beyond the buffer or below the
  header, or a truncated TCP/UDP header. The later fragments of such a first fragment are
  dropped `FRAGMENT` (`malformed_ipv4_is_dropped`, `fragments_of_a_malformed_first_are_dropped`);
- a rule with `labels` and `sources` matches only a labelled source inside the prefix, and a
  label-only rule ignores the address (`prefix_and_label_rule_needs_both`);
- an unknown peer is dropped `UNKNOWN_PEER`, while an empty label set matches only
  label-free rules (`unknown_peer_and_empty_labels`);
- default deny, rule order and the reported `RuleId`, port `Any` / list / range, the
  protocol set, and ICMP types (`rules.rs` unit tests).

`src/differential.rs` (the cached filter against the uncached one, verdicts and counters)
stays. It is generic and is ported to labels. The generator gains:

- sources with several labels, a label held by a by-source table, and an empty label set;
- rules with labels plus prefixes, `Icmp` and `Ip` entries, and `Any`;
- `install` / `uninstall` / `fail` transitions, and an engine with `NotInstalled::Accept`;
- `Pinholes`-kind namespaces with non-product ids;
- one more configuration in `cached_verdicts_match_other_configs`: stateless replies,
  `AllowOnly`, `accept_to_local`, `accept_icmp_echo_reply` and `Ipv6Mode::Accept`. This is
  the old preset, now covered on generated rules.

## 5. AG-4: generic stateful flow gate

### 5.1 API

```rust
pub mod gate {
/// An opaque scope identifier, unique within one `GatePolicy`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId(/* Arc<str> */);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GateMode {
    /// The scope decides nothing (the same as leaving it out).
    #[default] Off,
    /// Decisions are reported and state is kept, but packets pass on.
    Observe,
    /// Decisions are authoritative.
    Enforce,
}

/// One policy snapshot, replaced atomically as a whole.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GatePolicy { pub scopes: Vec<GateScope>, pub holds: GateHolds }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateScope {
    pub id: ScopeId,
    pub mode: GateMode,
    /// The local addresses this scope governs.
    pub local: Vec<IpAddr>,
    /// The remote sources bound to the scope.
    pub bindings: Vec<GateBinding>,
    /// Accept-only grants for new flows.
    pub grants: Vec<GateGrant>,
    /// What happens to unbound packets of designated peers.
    pub unbound: Vec<UnboundRule>,
}

/// Packets of `peer` with a remote address in `addresses` are bound to the scope and
/// carry `labels`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateBinding { pub peer: PeerId, pub addresses: Vec<IpAddr>, pub labels: LabelSet }

/// A new flow initiated in `direction` may open when the remote binding carries one of
/// `labels` (empty: any binding of the scope), the destination address lies in
/// `destinations` (empty: any) and a `protocols` entry matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateGrant {
    pub id: RuleId,
    pub direction: Direction,     // Inbound: remote initiates; Outbound: local initiates
    pub labels: Vec<Label>,
    pub destinations: Vec<IpNet>,
    pub protocols: Vec<ProtocolMatch>,
    /// Present but not admitting: a new flow it alone would admit is denied `Suspended`.
    pub suspended: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnboundAction { Pass, Divert }
/// For inbound packets of `peers` to a local address of an `Enforce` scope that bind to
/// no scope: `Pass` hands matching packets on (`GateDecision::Pass`); `Divert` offers
/// the enforced denial to the filter's `GateDivert`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnboundRule {
    pub id: RuleId,
    pub peers: Vec<PeerId>,
    pub action: UnboundAction,
    pub protocols: Vec<ProtocolMatch>,
}

/// Packets held fail closed (`Enforce`, `Held`) before any scope is consulted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GateHolds {
    pub inbound: Vec<HoldRule>,
    pub outbound: Vec<HoldRule>,
    /// Exact (peer, remote address) pairs exempt from the inbound holds.
    pub release: Vec<(PeerId, IpAddr)>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HoldRule {
    pub peers: Option<Vec<PeerId>>,   // None: any peer
    pub local: Vec<IpNet>,            // empty: any local address
    pub remote: Vec<IpNet>,           // empty: any remote address
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateLimits { pub flows: usize, pub flows_per_peer: usize, pub fragments: usize }
// Default: 16_384, 2_048, 4_096.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateTimeouts {
    pub tcp: Duration, pub tcp_half_closed: Duration, pub tcp_closed: Duration,
    pub udp: Duration, pub icmp: Duration, pub other: Duration, pub fragment: Duration,
}
// Default: 2 h, 5 min, 30 s, 2 min, 30 s, 60 s, 30 s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GateConfig { pub limits: GateLimits, pub timeouts: GateTimeouts }

pub struct FlowGate { /* ArcSwap<Snapshot>, inert flag, writer mutex, sharded state, counters, clock */ }
impl FlowGate {
    /// No policy: every packet `Pass` without parsing. Coarse monotonic clock on
    /// Linux/Android, `Instant::now` elsewhere.
    pub fn new(config: GateConfig) -> Arc<Self>;
    pub fn with_clock(config: GateConfig, clock: impl Fn() -> Instant + Send + Sync + 'static) -> Arc<Self>;
    /// Validate, publish atomically and migrate the state; returns the new generation.
    pub fn replace(&self, policy: GatePolicy) -> Result<u64, GatePolicyError>;
    pub fn generation(&self) -> u64;
    pub fn evaluate_inbound(&self, peer: PeerId, packet: &[u8]) -> GateDecision;
    pub fn evaluate_outbound(&self, peer: PeerId, packet: &[u8]) -> GateDecision;
    /// The live flow between `remote` and `local` (refreshed), if any.
    pub fn find_flow(&self, remote: SocketAddr, local: SocketAddr, protocol: Protocol) -> Option<LiveFlow>;
    pub fn counters(&self) -> GateCounters;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveFlow { pub scope: ScopeId, pub rule: RuleId, pub enforced: bool }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Pass,
    Observe { allow: bool, reason: GateReason, rule: Option<RuleId> },
    Enforce { allow: bool, reason: GateReason, rule: Option<RuleId> },
}
impl GateDecision { pub const fn enforced_verdict(&self) -> Option<bool>; }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GateReason {
    ValidState, Granted, Unbound, ReverseNewFlow, NoGrant, Suspended, Held,
    OrphanFragment, StateCapacity, Ambiguous, Malformed,
}
impl GateReason {
    pub const fn as_str(self) -> &'static str;       // "valid_state", ...
    pub const fn drop_reason(self) -> &'static str;  // "flow gate: no grant", ...
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GateCounters {
    pub enforced_allowed: u64, pub enforced_denied: u64, pub observed_denied: u64,
    pub unbound_denied: u64, pub state_capacity_denied: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GatePolicyError {
    DuplicateScope(ScopeId),
    DuplicateBinding { scope: ScopeId, peer: PeerId, address: IpAddr },
    InvalidRule { id: RuleId, reason: String },
}

/// Takes enforced denials offered by `UnboundRule { action: Divert }`. Called on the
/// packet path; must not block.
pub trait GateDivert: Send + Sync + 'static {
    /// `true`: taken (the packet becomes `Verdict::Handled`); `false`: dropped.
    fn divert(&self, peer: PeerId, packet: DivertedPacket) -> bool;
}
impl<F: Fn(PeerId, DivertedPacket) -> bool + Send + Sync + 'static> GateDivert for F;
impl<T: GateDivert + ?Sized> GateDivert for Arc<T>;

/// No public constructor and no mutable access.
#[derive(Debug)]
pub struct DivertedPacket { /* generation, peer, scope, rule, packet: Box<[u8]> */ }
impl DivertedPacket {
    pub const fn generation(&self) -> u64;   // compare with FlowGate::generation()
    pub const fn peer(&self) -> PeerId;
    pub fn scope(&self) -> &ScopeId;
    pub fn rule(&self) -> &RuleId;           // the UnboundRule's id
    pub fn packet(&self) -> &[u8];
    pub fn into_packet(self) -> Box<[u8]>;
}

/// The gate and an optional `AclFilter` as one ordered `PacketFilter`.
#[derive(Clone)]
pub struct GateFilter { /* Arc<FlowGate>, Option<AclFilter>, acl_outbound, Option<Arc<dyn GateDivert>>, counters */ }
impl GateFilter {
    pub fn new(gate: Arc<FlowGate>) -> Self;
    #[must_use] pub fn with_acl(self, acl: AclFilter) -> Self;
    #[must_use] pub const fn with_acl_outbound(self, enabled: bool) -> Self;
    #[must_use] pub fn with_divert(self, divert: impl GateDivert) -> Self;
    pub const fn gate(&self) -> &Arc<FlowGate>;
    pub fn stats(&self) -> GateFilterStats;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GateFilterStats {
    pub gate_accepted: u64, pub gate_denied: u64, pub diverted: u64,
    pub divert_rejected: u64, pub passed_to_acl: u64,
}
}
```

**How a packet's source labels are obtained.** The labels come from the policy's own
`GateBinding`s and not from `PeerIdentity`:

1. The engine's `PeerId` and the packet's remote address (inbound: IP source; outbound: IP
   destination) select the binding.
2. Its `labels` are the source labels.

Bindings, grants and holds are therefore published in one atomic swap. The packet path
does one hash lookup of `(PeerId, address)` in the snapshot, which replaces today's
`PeerKeyMap` load plus the `(key, address)` lookup. A product republishes the policy when
its peers change (Q4).

**Evaluation.** The gate handles IPv4 only. Every other packet is `Pass` (Q5).

Inbound, with `local` = destination and `remote` = source:

1. **Inert**: no scope with a mode other than `Off`, and no holds. The result is `Pass`,
   without parsing the packet or reading the clock.
2. **Malformed**: when the header is unparsable but the addresses are readable, a matching
   hold gives `Enforce(Held)`. Otherwise the scopes whose `local` contains the destination
   decide `Malformed` under their mode. When there is no such scope the result is `Pass`.
3. **Holds**: `(peer, remote)` in `release` skips the inbound holds. Otherwise a matching
   `HoldRule` gives `Enforce { allow: false, Held }`.
4. **Binding**: collect the scopes whose `local` contains `local` and that bind
   `(peer, remote)`.
   - More than one: `Ambiguous`. The mode is `Enforce` if any of them enforces, else
     `Observe`.
   - None: take the scopes whose `local` contains `local`.
     - When exactly one exists and it enforces, an `UnboundRule` with `Pass` that matches
       `peer` and the packet's protocol and port gives `Pass`. Its first fragment records a
       pass disposition, and a later fragment follows that disposition or is denied
       `OrphanFragment`.
     - Otherwise the result is `Unbound` under the mode of those scopes, or `Pass` when
       none exists.
5. **Bound** in scope `S` with labels `L`:
   - A non-first fragment follows its first fragment's state (`ValidState`) or is denied
     `OrphanFragment`.
   - An ICMP error (types 3, 4, 11, 12) refreshes the quoted flow (`ValidState`), or is
     denied `ReverseNewFlow`. An unparsable quote gives `Malformed`.
   - An existing flow gives `ValidState`. These keep today's rules: a SYN against the
     initiator, and a terminal TCP tail.
   - A reverse-only packet (TCP without SYN or with ACK; ICMP echo reply or error) gives
     `ReverseNewFlow`.
6. **New flow**: the first non-suspended grant of `S` matches when all of these hold:
   `direction` is `Inbound`; `labels` is empty or intersects `L`; `destinations` is empty or
   contains `local`; and a `protocols` entry matches.
   - The flow is admitted with that grant's id: `Granted`, `rule: Some(id)`. Its state is
     recorded even in `Observe` mode, as today.
   - When only suspended grants match, the result is `Suspended`. When no grant matches,
     it is `NoGrant`.
   - A flow that the limits refuse is denied `StateCapacity` (no eviction; expired entries
     are reclaimed first).

Outbound, with `local` = source and `remote` = destination, follows the same steps with
three differences:

- the outbound holds apply and `release` does not;
- unbound means that `remote` is a binding address of some scope but `(peer, remote)` is
  not bound in a scope whose `local` contains `local`. That gives `Unbound` under the mode
  of the scopes holding the address. When no scope holds it, the result is `Pass`;
- grants with `direction: Outbound` and `destinations` checked against `remote`.

Decisions take each scope's mode: `Off` is ignored, `Observe` gives `Observe { .. }`, and
`Enforce` gives `Enforce { .. }`. Holds always give `Enforce`. Counters are bumped as today.

**Replace and state migration.** `replace` validates the whole policy:

- scope ids must be unique;
- a `(peer, address)` pair may appear only once per scope;
- protocols are validated as in `RuleSet::new`.

Then, with every shard locked, it publishes the new snapshot and migrates the state:

- The flows and fragments of a scope whose content is unchanged are kept untouched.
- The flows and fragments of a removed scope, or of one that is now `Off`, are dropped.
- Each flow of a changed scope is re-authorized as a new flow by its initiator: its
  binding `(peer, remote)` must still be in the scope with `local` still in `local`, and a
  non-suspended grant must still match. The flow keeps its 5-tuple and its idle deadline,
  and takes the matching grant's id and `enforced = (mode == Enforce)`. Otherwise it is
  dropped.
- The fragments of a changed scope are dropped. A later fragment does not carry the
  ports needed to re-authorize it.

This is today's `revalidate_network` generalized. A packet never sees a policy together
with state of another policy, because the shard epochs work as today.

**GateFilter.** The steps are those of `NodeL3Filter` without the peer-key map and without
the Subnet transport port. Inbound:

- `Enforce` allow gives `Accept`, without the ACL.
- `Enforce` deny with reason `Unbound` or `OrphanFragment` is offered to the divert when
  all of these hold: the packet is TCP or UDP and matches an `UnboundRule { Divert }` of
  the single enforcing scope at `local` for `peer`; `remote` is no binding address of any
  scope; and no hold matches.
  - Taken: `Handled`.
  - Refused: counted in `divert_rejected` and then dropped.
- Every other enforced denial is dropped with `GateReason::drop_reason`.
- `Pass` and `Observe` go to the wrapped `AclFilter` (`inbound` and `inbound_from` are
  forwarded). Without an `AclFilter` they are accepted.

Outbound:

- An enforced denial is dropped.
- Otherwise the packet is accepted, or, with `with_acl_outbound(true)`, it goes to the
  ACL's `outbound`.

Unlike `NodeL3Filter`, there is no "unknown peer" drop: the gate has no key map. A packet
of a peer without a binding is `Unbound` on the governed plane and `Pass` elsewhere. The
wrapped `AclFilter` still drops unknown peers inbound (`UNKNOWN_PEER`).

### 5.2 ns semantics compiled onto the gate

For each ns Network snapshot that ns accepts, ns builds one `GateScope`. ns keeps doing the
following on its side: target binding, source authority, tombstones, generation and phase
checks, ACK readiness and schema version. It then calls `replace` with all its scopes plus
the holds. Labels below are written `n/<net>/<node>` (Node) and `o/<net>/<owner>` (owner).
They are product strings that nsplane never parses.

| ns semantic | Compilation onto the generic gate | Status |
| --- | --- | --- |
| Source binding `(peer key, inner Node IPv4)` | `GateBinding { peer: PeerId of the key, addresses: [node ip], labels: {n/<net>/<node>, o/<net>/<owner>} }`. Several Nodes on one key are several bindings or addresses. ns maps keys to `PeerId`s and republishes on peer changes | implementable |
| Local Node | `GateScope::local = [local node ip]` | implementable |
| Same-owner rule | Grant `Inbound { labels: [o/<net>/<local owner>], destinations: [local/32], [Any] }` and grant `Outbound { labels: [o/<net>/<local owner>], destinations: [], [Any] }`, listed first, id `owner` | implementable |
| Node grant X -> T | When T is local: `Inbound { labels: [n/X], destinations: [local/32], [Any] }`. When X is local: `Outbound { labels: [n/T], destinations: [T ip/32], [Any] }`. Id `node:<grant_id>` | implementable |
| Service grant X -> (T, proto, port) | As a Node grant with `[Tcp(port)]` or `[Udp(port)]`, id `service:<service_id>:<grant_id>`, emitted only for a projected service | implementable |
| Service projection ("inbound only while the local Provider listener is installed") | The inbound service grant has `suspended = !listener_installed(target, service, proto, port)`. ns recompiles and calls `replace` on every listener change. A flow it alone would admit is denied `Suspended`. Existing flows under it are dropped on that `replace`, as `authorize_existing_flow` does today | implementable |
| Subnet grant, `enforced_subnet_*` queries, `authorization_generation`, callback | Computed in ns from its applied snapshots and its WireGuard projection. They are pure functions of configuration, with no packet state. ns bumps its own change marker when it recompiles | implementable (moves to ns) |
| Subnet LAN DNS admission (UDP 53535) | For each Enforce scope with an exact Subnet grant source S -> routing R and the binding live: when R is local, `Inbound { labels: [n/S], destinations: [local/32], [Udp(53535)] }`; when S is local, `Outbound { labels: [n/R], destinations: [R ip/32], [Udp(53535)] }`. Id `subnet:<grant_id>`. Replies and fragments use the normal state, as today | implementable |
| Grant precedence (same owner, then Node, then Service) | Grant list order. The first match's id is reported | implementable |
| Multiple Networks; ambiguous Network | One scope per Network. A binding present in two scopes with the same local address gives `Ambiguous` (mode from the scopes) | implementable |
| Legacy (no snapshot) | No scopes and no holds: the gate is inert and returns `Pass` | implementable |
| Observe / enforce; `disabled` | `GateMode::Observe` / `Enforce`. `disabled` (withdrawal) means the scope is left out (or `Off`). The phase change observe -> enforce at the same generation is a changed scope, so its flows are revalidated and become `enforced` | implementable |
| Policy pending marker on a WireGuard peer | `GateHolds`, computed by ns from its transport projection and applied snapshots: `outbound = [{ remote: pending node ips }]`; `inbound = [{ local: authoritative local ips, remote: pending node ips }, { peers: Some(peers with a pending binding), local: authoritative local ips }]`; `release` = authoritative bindings that are ready. This is exactly `Snapshot::policy_pending`. Without a projection, ns sends no holds | implementable |
| Malformed packet under a pending marker | Step 2 checks the holds on the raw endpoints, as `malformed_decision` does | implementable |
| Peer readiness (`peer_readiness_snapshot`, `ready_for_ack`) | Computed in ns (pure function of its projection and applied snapshots) | implementable (moves to ns) |
| Gateway carrier pass (an exact owned Provider listener handed back to L4) | `UnboundRule { peers: [installed, non-relayed gateway carrier PeerIds], action: Pass, protocols: [Tcp/Udp(port) of each owned listener] }`, in the scope whose local address is the device's. Its fragments get a pass disposition | implementable |
| Gateway consumer divert | `UnboundRule { action: Divert, peers: [carrier PeerIds], protocols: [Tcp(Any), Udp(Any)], id: "gw:<gateway_id>" }` and `GateFilter::with_divert`. The consumer reads `rule()` for the gateway id and keeps `scope -> source id` itself. `same_snapshot` becomes equal `generation`, `peer` and `rule`. `gateway_consumer_authority_current` becomes `packet.generation() == gate.generation()` | implementable; stricter (Q6) |
| `service_flow_authorized(remote, local, target, proto, service)` | `find_flow(remote, local, proto)`. The flow counts when `enforced` is set and its `rule` is `owner`, `node:*` or `service:<service>:*`, and ns checks that the current snapshot projects `service` on `local`'s port for `target`. Migration already guarantees that the flow is authorized by the current generation | implementable |
| Reason mapping | `Legacy` -> `Pass`. `ValidState` -> `ValidState`. `SameOwner` / `NodeGrant` / `ServiceGrant` / `SubnetGrant` -> `Granted` with `rule` (decoded by ns from its id). `SourceBinding` -> `Unbound`. `ReverseNewFlow` -> `ReverseNewFlow`. `NoGrant` -> `NoGrant`. `ServiceProjection` -> `Suspended`. `PolicyPending` -> `Held`. `OrphanFragment` -> `OrphanFragment`. `StateCapacity` -> `StateCapacity`. `AmbiguousNetwork` -> `Ambiguous`. `MalformedPacket` -> `Malformed`. Drop strings change from `node l3: *` to `flow gate: *` | implementable (strings change) |
| Counters | `NodeL3Counters` -> `GateCounters` (`source_binding_denied` -> `unbound_denied`). `NodeL3FilterStats` -> `GateFilterStats` without `unknown_peer` | implementable |
| Unknown peer drop of `NodeL3Filter` (both directions) | Inbound: the wrapped `AclFilter` drops `UNKNOWN_PEER`, and on the governed plane the gate gives `Unbound`. Outbound to a peer missing from ns's tables, off the governed plane, is no longer dropped by the gate filter | deviation (Q7) |
| Wrong target, authority conflict, stale generation, phase regression, tombstones, schema version, `NodeL3Applied` ACK | ns validates before `replace`. `replace` returns the gate generation | implementable (moves to ns) |
| State limits, timeouts, coarse clock | `GateConfig::default()` equals today's constants. `with_clock` for tests | implementable |
| IPv6 Subnet ingress | Unchanged: nsplane-core inbound destinations, computed by ns | implementable |

No ns semantic is left without a mapping. There are two deviations, Q6 (stricter divert
authority) and Q7 (no unknown-peer drop off the plane). The 6,361-step differential
fixture (`src/node_l3/fixtures/differential.json`) moves to the AG-4 spec as product
parity data.

### 5.3 Generic gate tests (C5)

The existing node_l3 unit tests are ported to scopes, bindings and grants, each with
generic names:

- `grants_flow`
- `state_table`
- `packets_fragments`
- `concurrency`
- `filter`
- `subnet`, which becomes `grant_kinds`: suspended, port and ICMP grants
- `transport_policy`, which becomes `holds_and_unbound`

The fixture-driven `tests/differential.rs` is replaced by `tests/model.rs`. That test
compares the gate against a simple reference model of 5.1 (one map, no shards, no lazy
expiry) on seeded random sequences of packets, `replace` calls and clock steps. It requires
equal decisions and counters, so that migration and lazy expiry never change a verdict.

## 6. Data path

The A/B runs against main with like-for-like setups through `scripts/bench/slot.sh`
(interleaved, one A/B per invocation).

### 6.1 `benches/namespaces.rs`

| Scenario (main name) | Branch setup | Branch name |
| --- | --- | --- |
| `default/inbound`, `default/inbound_established`, `default/outbound`, `default/outbound_source_scope` | The 3 default rules, compiled as 4.2 does: the two CIDR rules carry `sources` and the address label `A`, which key-labelled peers do not hold, so the same rules fail early. Peers labelled `{"k<i>"}` | same |
| `namespaces/inbound`, `_established`, `_grant`, `_grant_established`, `_pinhole`, `namespaces/outbound`, `namespaces/outbound_restricted` | 8 `Rules` namespaces x 64 members with label `k<i>`. 4 grants with `Label` / `Namespace` ends and `[Tcp(..)]`. 16 pinholes in one `Pinholes` namespace | same |
| `bypass/inbound`, `_established`, `bypass/outbound` | One namespace with rule `[Tcp(Any), Udp(Any)]` | same |
| `by_source/inbound`, `_established` | `PeerLabelMap::insert_by_source(peer, [(fd00::/16, {A})])`: labels resolved per address through the same LRU as today | same |
| `other/icmp_echo_scope` | Unchanged (scope rule) | same |
| `crates_acl/inbound`, `_established`, `_fragment` | The preset's fields set explicitly (4.2) | `stateless/inbound`, `_established`, `_fragment` |
| `floor/five_tuple`, `floor/snapshot` | Unchanged | same |

### 6.2 `benches/node_l3.rs` -> `benches/gate.rs`

| Scenario (main) | Branch setup | Branch name |
| --- | --- | --- |
| `established/filter` | `GateFilter` + accept-all `AclFilter`, one scope, a same-owner grant | same |
| `established/gate`, `established/outbound` | `FlowGate::evaluate_{inbound,outbound}(PeerId, ..)` | same |
| `new_flow/node_grant` | Grant `[Any]` to local/32 | `new_flow/any_grant` |
| `new_flow/service_grant` | Grant `[Tcp(port)]`, not suspended | `new_flow/port_grant` |
| `baseline/acl_established` | Unchanged | same |
| `baseline/legacy_filter`, `baseline/legacy_gate` | Gate with no policy (inert) | `baseline/pass_filter`, `baseline/pass_gate` |
| `contention/1ms`, `contention/10ms` | `replace` every 1 or 10 ms with an unrelated grant toggled in the same scope (a changed scope, revalidated as today's `apply`) | same |

### 6.3 Hot-path risks and how the design avoids them

- **Label matching** replaces a principal string compare. Labels are compared over
  precomputed hashes. A rule with no labels skips the step. The source's sorted set is
  cached per peer.
- **Membership union** for multi-label sources is computed per resolution, never per
  packet.
- **Rule IDs** stay off the packet path: `FlowVerdict` has no `RuleId`. The gate clones one
  `Arc` per new flow only.
- **Rule shape**: `Vec<ProtocolMatch>` is compiled to a flat form (TCP ports, UDP ports,
  ICMP types, IP numbers) next to the prefixes, so a rule check stays a few branches.
- **Policy state** replaces `Option<Arc<CompiledPolicy>>` with an enum: the same branch.
- **Non-TCP/UDP rule evaluation** runs only for packets that today are already dropped
  `PROTOCOL` or accepted by a scope rule. TCP and UDP are unaffected.
- **Gate binding** by `(PeerId, address)` removes the per-packet `PeerKeyMap` load and
  shrinks the flow key from a 32-byte key to a `u32`. Timeouts read a config field instead
  of a constant.
- **Watch item**: the default-policy path (`default/*`) evaluates on every packet. If it
  regresses beyond noise, C2 adds the same per-peer verdict cache that namespace members
  have.

## 7. Implementation slicing

Each slice keeps `just check` green (workspace, examples, e2e build), updates
`CHANGELOG.md [Unreleased]` with every removal and its replacement, and updates
`docs/architecture.md` (nsplane-acl section and the public-interfaces rows) for what it
changes.

### C2: AG-1 core

- **Files**:
  - `crates/nsplane-acl/src/lib.rs`;
  - new `src/rules.rs` (Label, LabelSet, RuleId, Rule, ProtocolMatch, PortSet, IcmpTypes,
    RuleSet, Flow, Transport, Decision, Matched, PolicyState, NotInstalled);
  - `src/engine.rs` (`install`, `uninstall`, `fail`, `policy_state`, `with_not_installed`,
    `rules`, `evaluate(&LabelSet, &Flow)`; `AccessRequest`, `AclDecision`, `is_allowed`
    and `permit_all` removed; `CompiledPolicy` becomes `RuleSet` with a temporary
    `from_document(AclPolicy)`);
  - `src/matcher.rs` (compiles the document into typed rules: `key:` becomes a label, a
    CIDR or alias becomes `sources` plus a crate-private address label);
  - `src/filter.rs` (an internal `SourceAssertion` -> `LabelSet` adapter that adds the
    address label to IP-bearing assertions; non-TCP/UDP rule step; `policy_failed`,
    `policy_state`);
  - `src/reasons.rs`;
  - `src/namespace.rs` (internal compile through `RuleSet`);
  - `src/differential.rs` (states, ICMP rules);
  - `benches/namespaces.rs` (compiles).
- **Generic tests**: `rules.rs` unit tests (2.2 matching, validation, rule order and id);
  engine tests for every policy state and `clear_all`; filter tests for the non-TCP/UDP
  rule step; `evaluate` against the filter for the first packet on a seeded generator.
- **Users**: `crates/nsplane-e2e/tests/*` and `examples/` only where `permit_all`,
  `store`, `clear`, `is_allowed` or `AccessRequest` appear.
- **e2e**: new `crates/nsplane-e2e/tests/acl_rules.rs`: typed rules through `install`,
  rule IDs from `evaluate`, `NotInstalled::{Deny, Accept}`, installed-empty with replies
  passing, `fail()` dropping replies when nothing else is loaded, and `evaluate` equal to
  the delivered/dropped outcome of the first packet over the engine.
- **Bench A/B**: `namespaces` against main.

### C3: AG-2 identity to labels

- **Files**:
  - `src/lib.rs`;
  - `src/engine.rs` (`SourceAssertion`, `TerminateBinding` and `wg_peer_anchor` removed;
    membership by label; bypass on labels; `memberships(&Label)`);
  - `src/filter.rs` (`PeerIdentity` on labels, `PeerLabelMap`, label-set cache; adapter
    and address label removed, so CIDR sources now match by address);
  - `src/matcher.rs` (the document's CIDR source compiles to `sources` only);
  - `src/namespace.rs` (`NamespaceMember::label`, `GrantEnd::Label`, `NamespaceKind`,
    `pinhole_kinds`);
  - `src/pinhole.rs` (`PinholeSpec::label`, `NotPinholeNamespace`);
  - `src/differential.rs`;
  - `tests/crates_acl_parity.rs` (rewritten with a test-local compiler from the fixture's
    document to typed rules and labels per 4.2; it must still pass on all 12,181 packets,
    which proves that the label model reproduces the preset);
  - `benches/namespaces.rs`, `benches/node_l3.rs` (the ACL behind the gate);
  - e2e `acl.rs`, `acl_hook.rs`, `acl_namespaces.rs`, `acl_parity.rs`, `acl_scope.rs`,
    `node_l3.rs`, `inject_filters.rs`, `port_map.rs`, `container.rs`;
  - `examples/src/bin/acl_gateway.rs` (`--identity <PUB>=<label>[,<label>]`),
    `examples/src/bin/app_session.rs`, `examples/README.md`.
- **Spec**: `docs/specs/acl-source-identity.md`. It covers WireGuard key, terminate binding
  and IdP assertion as labels, the address label for CIDR rules, and `app:` namespaces as
  `Pinholes`.
- **Generic tests**:
  - multi-label membership union and outbound restriction;
  - label grant ends, including the smallest-label owner of a shared address;
  - pinhole by label, and permission through `pinhole_kinds`;
  - `insert_by_source` prefix table (longest prefix, outside means unknown);
  - bypass for a multi-label source;
  - the differential test with multi-label and by-source sources.
- **e2e**: `acl_namespaces.rs` gets a two-label peer that is a member of two namespaces
  through different labels. Every listed e2e file is ported.

### C4: AG-3 document removal

- **Files**:
  - `src/lib.rs`, `src/policy.rs` (deleted), `src/merge.rs` (deleted), `src/deny_scope.rs`
    (deleted), `src/matcher.rs` (parsers deleted);
  - `src/engine.rs` (`load` and `from_document` removed; the `Error` variants);
  - `src/filter.rs` (`crates_acl`, `ALLOW_ONLY`, ns rustdoc);
  - `src/namespace.rs` (`rules`, typed `OutboundRule` and `Grant`);
  - `src/differential.rs` (typed rules, the old-preset configuration);
  - `tests/crates_acl_parity.rs` and its fixture deleted. The fixture moves to
    `docs/specs/data/acl-crates-acl-parity.json`;
  - `benches/namespaces.rs` (`stateless/*`), `benches/node_l3.rs`;
  - e2e `acl.rs` (`AclTest` cases become `RuleSet::matching` cases), `acl_hook.rs`,
    `acl_namespaces.rs`, `acl_parity.rs` (renamed `acl_options.rs`, with the options set
    explicitly), `node_l3.rs`, `inject_filters.rs`, `port_map.rs`, `container.rs`;
  - `examples/src/bin/acl_gateway.rs` (a JSON `Vec<Rule>` file),
    `examples/policies/acl_gateway.json`, `examples/src/bin/app_session.rs`,
    `examples/README.md`;
  - `scripts/e2e/examples.sh`: the `jq` edit of the sample policy in
    `scenario_acl_gateway`. This is a file shared with AN's term scan, so coordinate the
    change through L2.
- **Spec**: `docs/specs/acl-policy-document.md`. It covers the document format, host
  aliases, `tests`, merge layering and deny scope as product features, the preset values,
  the 4.2 compilation, and the fixture.
- **Generic tests**: the 4.3 list (the preset semantics on explicit options) and typed
  grant and outbound-rule validation.
- **e2e**: `acl_options.rs` (ported `acl_parity.rs`) and `acl.rs`, with typed rules
  everywhere.

### C5: AG-4 gate

- **Files**:
  - `src/lib.rs`;
  - `src/node_l3.rs` and `src/node_l3/**` -> `src/gate.rs` and `src/gate/**`: `config.rs`
    (GatePolicy and friends); `policy.rs` (compiled scopes); `snapshot.rs`
    (binding/local/remote indexes, holds); `decisions.rs`; `state.rs` (flow key by
    `PeerId`, timeouts from config); `packet.rs`; `filter.rs` (`GateFilter`, `GateDivert`);
    `divert.rs` (was `gateway_consumer.rs`); `migrate.rs` (was `sources.rs`, keeping only
    revalidation). `projection.rs` and `subnet.rs` are deleted, and `clock.rs` and
    `hash.rs` are kept;
  - the tests under `src/gate/tests/` (5.3). `fixtures/differential.json` moves to
    `docs/specs/data/node-l3-differential.json`;
  - `benches/node_l3.rs` -> `benches/gate.rs`, and the `[[bench]]` entry in
    `crates/nsplane-acl/Cargo.toml`;
  - e2e `node_l3.rs` -> `flow_gate.rs`.
- **Spec**: `docs/specs/node-l3.md`. It covers the 5.2 table in full: label scheme,
  grant ids, holds derivation, divert, subnet queries, readiness, and reason and counter
  mapping, plus the fixture.
- **Generic tests**: 5.3.
- **e2e**: `flow_gate.rs` ports every `node_l3.rs` test to generic terms. It adds a held
  peer (`Held` until the hold is released), a suspended grant (`Suspended`, then admitted
  after `replace`), an `UnboundRule { Pass }` handing a packet to the ACL, and divert
  generation staleness.
- **Bench A/B**: `gate` against main `node_l3`, using 6.2.

### File overlaps

C3 and C4 touch the same files:

- `src/{lib,engine,filter,matcher,namespace,differential}.rs`;
- `tests/crates_acl_parity.rs` (C3 rewrites it, C4 deletes it);
- `benches/namespaces.rs`, `benches/node_l3.rs`;
- e2e `acl.rs`, `acl_hook.rs`, `acl_namespaces.rs`, `acl_parity.rs`, `node_l3.rs`,
  `inject_filters.rs`, `port_map.rs`, `container.rs`;
- `examples/src/bin/{acl_gateway,app_session}.rs`, `examples/README.md`;
- `CHANGELOG.md`, `docs/architecture.md`.

C4 must start from the merged C3. C5 overlaps C3 and C4 in `src/lib.rs`,
`benches/node_l3.rs`, e2e `node_l3.rs` (the ACL behind the gate), `CHANGELOG.md` and
`docs/architecture.md`. It must start from the merged C4. Nothing outside
`crates/nsplane-acl`, `crates/nsplane-e2e/tests`, `examples/` and the docs is touched,
except the one `scripts/e2e/examples.sh` line in C4.

## 8. Open questions for L1 and the owner

Each question comes with a recommendation.

1. **Q1: Rule IDs in drop events.** `Verdict::Drop` carries a `&'static str` (the
   nsplane-core contract), and an accept-only drop has no rule.
   *Recommendation*: no core change. Rule IDs go into `Decision`, `GateDecision` and logs.
   A per-flow decision observer can come later as a generic request.
2. **Q2: `clear_all` state.** *Recommendation*: `clear_all` leaves the state `Failed`, so
   the emergency stop stays fail-closed even on an engine built with
   `NotInstalled::Accept`. `uninstall` returns to `NotInstalled`.
3. **Q3: ICMP types and other protocols in the ACL.** The typed model matches them.
   *Recommendation*: the filter evaluates non-TCP/UDP inbound packets against the rules
   after its scope rules (2.4). This changes nothing for rule sets without such entries,
   and it keeps `evaluate` and the filter equal.
4. **Q4: Gate bindings by `PeerId`** in the policy instead of labels from `PeerIdentity`.
   *Recommendation*: yes. Bindings and grants are atomic, there is no per-packet identity
   lookup, and the cost is a product `replace` on peer changes (ns already republishes on
   every device change).
5. **Q5: Gate address family.** *Recommendation*: IPv4 only, as today. The types use
   `IpAddr` and `IpNet`, so IPv6 can come later without an API break, as a generic
   request.
6. **Q6: Divert authority.** A queued candidate is current only while the gate generation
   is unchanged. Today it stays current while its Network policy and transport are
   unchanged. *Recommendation*: accept the stricter rule (fail-closed, it only affects
   packets queued across a `replace`).
7. **Q7: Unknown-peer drop of the gate filter.** *Recommendation*: drop it. Inbound, the
   ACL's `UNKNOWN_PEER` and the gate's `Unbound` cover it. Outbound off the governed plane
   is the product's routing concern.
8. **Q8: serde on typed rules.** *Recommendation*: keep `Serialize`/`Deserialize` on
   `Label`, `LabelSet`, `RuleId`, `Rule`, `ProtocolMatch`, `PortSet`, `IcmpTypes` and the
   namespace types (they have it today). This is plain data with no aliases or tests, so
   it is not a policy document. No serde on gate types.
