# nsplane-acl

Access control for the engine's filter chain: typed rules, rule namespaces, grants and
pinholes evaluated per flow (`AclEngine`, `AclFilter`), per-flow accounting (`FlowTracker`), and
a stateful flow gate for bound peers (`gate::FlowGate`, `GateFilter`). Builds on
`nsplane-core` and `nsplane-packet`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `AclEngine` (`install` / `uninstall` / `fail`, `policy_state`, `with_not_installed`, `rules`, `evaluate`, `store_namespace` / `remove_namespace`, `store_grant` / `remove_grant`, `open_pinhole`, `expire_pinholes`, `clear_all`, `generation`, `pinhole_stats`), `AclFilter` (`new`, `with_config`, `with_scope`, `replace_scopes`, `scope_generation`, `stats`), `FlowTracker` | typed rules `Label`, `LabelSet`, `RuleId`, `Rule`, `ProtocolMatch`, `PortSet`, `IcmpTypes`, `RuleSet`; flows `Flow`, `Transport`, `Decision`, `Matched`; states `PolicyState`, `NotInstalled`; `Protocol`, `IpNet`; identity `PeerIdentity` (`local_identity`), `PeerLabelMap` (`set_local_identity`); namespaces `NamespaceId`, `NamespaceKind`, `NamespacePolicy`, `NamespaceMember`, `OutboundRule`, `Grant`, `GrantEnd`; pinholes `PinholeSpec`, `PinholeGuard`, `PinholeId`, `Direction`, `PinholeError`, `PinholeStats`; scopes `AclFilterScope`, `AclFilterScopes`, `AclFilterScopeError`, `OtherProtocolRule`, `OtherProtocol`; stats `AclFilterStats`, `FlowKey`, `FlowStats`; `reasons`; flow gate (`gate` module, IPv4 and IPv6) `FlowGate` (`new`, `with_clock`, `replace`, `generation`, `evaluate_inbound` / `evaluate_outbound`, `evaluate_inbound_in` / `evaluate_outbound_in`, `find_flow` (either family), `counters`, `enable_events` / `disable_events`), `GateFilter` (`new`, `with_acl`, `with_acl_outbound`, `with_divert`, `gate`, `stats`), `GateDivert`, `DivertedPacket`, `GatePolicy`, `GateScope`, `ScopeId`, `GateMode`, `GateBinding` (empty `addresses`: peer-keyed), `GateGrant`, `UnboundRule`, `UnboundAction`, `GateHolds`, `HoldRule`, `GateConfig`, `GateLimits`, `GateTimeouts`, `GateDecision`, `GateReason` (`OutOfScope` for scoped decisions), scoped decisions `ScopeSelection` (`one`, `any_of`), `EmptySelection`, `ScopedDecision` (`decision`, `scope`, `rule`, `generation`), `GateCounters` (`events_emitted`, `events_dropped`), decision events `GateEventsConfig` (`capacity`, `rate`, `burst`), `GateEvent` (`at`, `peer`, `protocol`, `src`, `dst`, `allow`, `enforced`, `reason`, `rule`), `GateEvents` (`try_recv`, `recv`, `recv_timeout`, `drain`), `LiveFlow`, `GateFilterStats`, `GatePolicyError` (`DuplicatePeerBinding`) |

## Behavior

### Engine and state

The ACL evaluates business-agnostic flows. Product policy is compiled above nsplane into
typed rules, labels and gate policies, and no product concept is added here (ADR
`2026-10-06-business-agnostic-scope`). A source is an opaque `LabelSet`.
Product mappings onto this API are in the specs listed under [See also](#see-also).

`AclEngine` holds its whole state (the default `RuleSet` and its policy state, the rule
namespaces, the directed grants and the open pinholes) as one immutable snapshot in a
`nsplane_core::cell::SnapshotCell` ([snapshot cell](nsplane-core.md#snapshot-cell)): writers
serialize on a mutex and publish a new snapshot, and evaluation takes one closure read per
packet. `install` swaps a `RuleSet` that `RuleSet::new` validated in atomically, and a rejected update (`RuleSet::new`, `store_namespace` or `store_grant`
returning an error) leaves the previous state in effect. With nothing loaded every flow is
denied; `clear_all` removes everything in one swap. nsplane takes typed rules only: parsing
a policy language, merging rule sources and dropping forbidden rules happen above it.

### Typed rules

A `Rule` carries an opaque `RuleId` and matches a flow when all of these
hold: its `labels` are empty or the source's `LabelSet` holds one of them (opaque strings
compared by a precomputed hash and the text; the sets are `Arc`-backed and sorted, so a
match is a merge over two sorted slices); its `sources` and `destinations` prefixes are
empty or contain the flow's addresses; and one of its `protocols` (`ProtocolMatch::Any`,
`Tcp` / `Udp` with a `PortSet`, `Icmp` with `IcmpTypes`, `Ip(number)`) matches. Rules are a
union; the first match in list order reports its id, and ids need not be unique.
`RuleSet::new` validates a list and compiles each rule's protocols to a flat form;
`RuleSet::matching(&LabelSet, &Flow)` is the rule-only check; a caller uses it to test rules
on `Flow`s before installing them.

### Policy states

The default rule set, for sources whose labels are in no namespace, is
`PolicyState::NotInstalled` (the engine's `NotInstalled` action applies: `Deny`, the
default, drops their new flows with `reasons::NO_POLICY`; `Accept`, set with
`with_not_installed`, accepts every flow), `Installed { rules }` (`install`; an empty set
denies every new flow with `reasons::DENIED`), or `Failed` (`fail`, for a caller whose own
compilation failed: `reasons::POLICY_FAILED`, counted in `AclFilterStats::policy_failed`).
`uninstall` returns to `NotInstalled`; `clear_all` leaves `Failed`, so the emergency stop
stays fail-closed under `NotInstalled::Accept`. The engine is loaded when rules are
installed, a namespace is stored, or nothing is installed under `Accept`; while it is not,
every inbound packet, replies included, is dropped with the state's reason. The state is
read with `AclEngine::policy_state` and `AclFilterStats::policy_state`.

### Evaluation without a packet

`AclEngine::evaluate(&LabelSet, &Flow)` returns the
`Decision` the filter applies to the first packet of a new inbound flow, with namespaces,
grants and pinholes: `Accept(Matched)` names the accepting rule (and its namespace), grant,
pinhole or the not-installed action, `Deny` carries the `reasons` constant. A
family-mixed flow is `reasons::MALFORMED`. Every full evaluation logs the flow and the rule,
grant, pinhole or reason at debug level; drop events keep their `&'static str` reason, and
rule ids travel only in decisions and logs.

### AclFilter

`AclFilter` is a `PacketFilter` for the engine's filter chain. The `LabelSet` of an inbound
packet's peer comes from a `PeerIdentity` (`labels_for(peer, remote)`; `None` is an unknown
peer, dropped with `reasons::UNKNOWN_PEER`, e.g. a `PeerLabelMap` filled by the caller); a
new flow is evaluated as `evaluate` does on the packet's own addresses, and anything not
accepted is dropped with a `reasons` constant.
Non-first IPv4 fragments follow the outcome of their first fragment, and accepted outbound
TCP/UDP packets and ICMP / `ICMPv6` echo requests record reply allowances (with an idle
timeout) so replies to flows the local side opened pass. An echo request's allowance admits
only the echo reply of its reversed tuple, identifier included; it is consulted before the
`reasons::PROTOCOL` drop, and no other ICMP message or unsolicited echo reply passes through
it. `FlowTracker` placed after it counts packets and bytes per flow in a bounded
table.

### Namespaces

A node holds peers from several sources; each source is a rule namespace
(an opaque `NamespaceId`) stored with `store_namespace` and replaced or removed on its own.
A `NamespacePolicy` has a `kind` (`NamespaceKind::Rules`, the default, or `Pinholes`), its
members (`NamespaceMember`: a `Label` with the addresses it owns), its accept `rules` (a
`Vec<Rule>`, validated as by `RuleSet::new`), optional `outbound` rules (`OutboundRule`: an
id and `ProtocolMatch`es) and the pinhole kinds its members may open
(`pinhole_kinds`). `Pinholes` namespaces never widen permissions: they carry no accept
rules or pinhole kinds, no grant names them (a namespace grant end matches `Rules`
namespaces only), and their members get access only through pinholes. Membership is keyed
by label: a source with label set `S` is a member of the union of the namespaces of every
label in `S` (computed when the filter resolves the source). The default rules apply only
to sources in no namespace, so a node without namespaces uses the default rules alone. An inbound
packet from a member with labels `S` to address `d` is evaluated after the reply table:

1. `d` resolves to the member label `Q` owning it (longest prefix, then the smallest
   label); otherwise it is local, and the local node is in every namespace.
2. A rule of any `Rules` namespace common to the source and `d` accepts it.
3. When `d` is another member, a directed `Grant` (from a label in `S`, `GrantEnd::Label`,
   or one of the source's namespaces, to `Q` or one of its namespaces, with protocol and
   ports) accepts it; grants are one-way.
4. When `d` is local, an open inbound pinhole of a label in `S` for the protocol and port
   accepts it.
5. Otherwise it is dropped with `reasons::CROSS_NAMESPACE` (`d` shares no namespace with
   the source) or `reasons::DENIED`.

### Outbound

Outbound traffic is unrestricted by default. A peer (its labels resolved for
the packet's destination address) is outbound-restricted only when it is in at least one
namespace and every one of them sets `outbound` (union: one unrestricted namespace keeps it
unrestricted). Outbound packets to a restricted peer pass
when they match an outbound rule, an open outbound pinhole or the reply allowance of an
inbound flow from that peer the filter accepted; anything else is dropped with
`reasons::OUTBOUND`.

### Outbound source scope

`AclFilter::with_scope` takes an `AclFilterScope`, address
scopes beside `AclFilterConfig`, as the default scope (generation 0). With `outbound_sources: Some(prefixes)` every
outbound packet (any peer, restricted or not, any protocol, every fragment) whose source
address, read from the raw IPv4 or IPv6 header, is in none of the prefixes is dropped with
`reasons::OUTBOUND_SOURCE` (`AclFilterStats::outbound_source`) before the outbound rules,
pinholes and reply allowances, and records no state; a buffer too short for the source is
dropped too, and an empty list drops every outbound packet. Only `Ipv6Mode::Accept` runs
before it. The default (`None`) costs one branch per outbound packet. Set to the local
addresses, it keeps a packet into the tunnel from carrying a foreign source.

### Other-protocol rules

`AclFilterScope::other_protocols` holds `OtherProtocolRule`s
(`OtherProtocol::IcmpEcho`, `Icmp` or `Ip(number)`, plus destination prefixes) for inbound
packets that are neither TCP nor UDP. After the reply allowances and `allow_other_protocols`
(which still accepts everything), and behind a loaded policy, a packet some rule matches by
protocol and destination address is accepted (`AclFilterStats::accepted`); anything else is
dropped with `reasons::PROTOCOL`. Non-first fragments follow their first fragment.
After the scope rules such a packet is evaluated against the rules as a new flow (default
rules, namespace rules and grants with `Icmp`, `Ip` or `Any` entries; pinholes are TCP and
UDP only, and there is no verdict cache); an accepted one has the side effects of an
accepted TCP or UDP flow, and every denial is reported as `reasons::PROTOCOL`. Outbound such
packets to a restricted peer pass `allow_other_protocols`, a reply allowance or an outbound
rule. Rules without such entries change nothing.
With `stateful_replies`, an accepted packet from an outbound-restricted peer (an echo request,
or a non-ICMP packet) records the outbound allowance its reply passes through
(`outbound_replies`). Rules match destinations only, never sources. The empty
default costs nothing on the TCP/UDP path and one branch for other protocols.

### Runtime scopes per local identity

`AclFilter::replace_scopes(AclFilterScopes)` publishes
a default scope plus one scope per `LocalIdentityId` atomically and returns the new scope
generation (`scope_generation()`); a duplicate identity is
`AclFilterScopeError::DuplicateIdentity` and publishes nothing. Any clone of the filter is the
runtime handle. A packet loads the set once, so it is judged under one whole scope of one
generation. The scope is chosen by the peer's local identity, which the filter learns from
`PeerIdentity::local_identity` (`PeerLabelMap::set_local_identity`): it must be the identity
the peer was added under (`PeerConfig::local_identity`), which the engine does not check. An
identity without an entry uses the default scope. A versioned identity is asked once per
peer and identity generation; while no scope constrains anything, one flag load keeps the
unscoped cost. `nsplane-e2e` `acl_scope_runtime` covers per-identity selection, the default
fallback and replaces under traffic.

### Pinholes

A session reaches a source only through pinholes in a `Pinholes` namespace:
`open_pinhole` opens one label (`PinholeSpec::label`; every source carrying it uses the
pinhole), direction, protocol and destination port until a caller-chosen `expires_at`, and
returns a `PinholeGuard`. The namespace must be a `Pinholes` namespace (else
`PinholeError::NotPinholeNamespace`) containing the label, and when the label is in any
`Rules` namespace one of them must list the kind in `pinhole_kinds` (else
`PinholeError::NotPermitted`). A pinhole closes when its guard is dropped, when it expires
on the engine clock (`Instant::now`, or `AclEngine::with_clock`; `expire_pinholes`
sweeps), when its namespace is removed, on `clear_all`, or when it is revoked (the label
left the pinhole namespace or its rule namespaces no longer permit the kind);
`PinholeStats` counts each reason.

Reply allowances recorded for flows accepted through a grant or a pinhole depend on it.
Removal is lazy: once the grant or pinhole is gone from the current snapshot, a dependent
allowance is removed on its next lookup (`AclFilterStats::reply_revoked`) and the flow's
packets are evaluated from scratch.

Reply allowances of an inbound flow accepted by a rule (default or namespace) or by
`NotInstalled::Accept` depend on that flow: the reply of the local node, the outbound
allowance of a restricted peer and, for a flow forwarded to another member, the allowance
of the destination's replies. After any policy or identity generation change, the flow is
evaluated again from its source peer on the next lookup of such an allowance: still
accepted, the allowance stays (and depends on whatever accepts the flow now, a grant
included); otherwise it is revoked as above. An unversioned `PeerIdentity` gets this check
on every lookup. A new inbound allowance recorded by an outbound packet with no inbound flow
behind it (a flow the local node opened) depends on nothing and survives policy changes,
unless the inbound rules also accept its reverse direction when it is recorded. Under the
default rules (no namespace) only the local node's replies are tied to the flow; the replies
of a flow forwarded between two peers expire with the idle timeout.

### Flow verdict cache

The filter evaluates a flow once, not every packet. `AclEngine::generation`
increases on every published change (default rules and their state, namespaces, grants,
pinholes opened, closed, swept or revoked, `clear_all`), and a versioned `PeerIdentity`
(`PeerIdentity::generation`, bumped by `PeerLabelMap`) on every identity change. The
filter caches per peer its label set (one `Arc`), the union of its labels' namespace
memberships and flags, and per peer, direction and
five-tuple the verdict of a namespace member's TCP/UDP flow's first packet (the default
policy is cheaper to evaluate than to cache), in the reply table (one lock, one
capacity, cached verdicts flushed first when full), both tagged with the two generations: a
hit under other generations is evaluated again, so a change applies to the very next
packet, and a verdict accepted through a pinhole is also checked against the pinhole's
expiry. Peers whose namespaces (or the default rules, or `NotInstalled::Accept`) accept
every destination and TCP and UDP port and are not outbound-restricted bypass the
evaluation: every update computes the open namespaces and the distinct namespace sets of the
address owners, and each peer resolution intersects them. The cache does not change the reply table, fragments or the fail-closed rules: verdicts and
counters equal a full evaluation (a differential test checks it). The crate docs
(`crates/nsplane-acl/src/lib.rs`, *Namespaces*, *Pinholes*, *ACL hook* and *Cost*) state the
full rules; the per-packet costs are in [Performance](../performance.md#acl).

### Labels per source address

`PeerIdentity::labels_for(peer, remote)` resolves the label
set for the packet's remote address (the source of an inbound packet, the destination of an
outbound one); its default ignores the address and returns `labels(peer)`.
`PeerLabelMap::insert_by_source(peer, prefixes)` gives a peer whose packets carry several
source addresses a prefix table: the longest prefix containing the address wins, and an
address outside every prefix is an unknown source; `insert(peer, labels)` gives a fixed
set. The filter asks `PeerIdentity::by_source` once per peer and identity generation and
caches such a peer's labels per address in a least-recently-used table bounded by
`AclFilterConfig::reply_capacity`; the bypass and the flow verdict cache work per address
too, so verdicts still equal a full evaluation (the differential test covers multi-label
and by-source sources).

### Fragment modes and bypass flags

`AclFilterConfig::fragments` selects how inbound
non-first IPv4 fragments are gated. `FragmentMode::Outcome` (default) is the gate described
above: the outcome of each first fragment, accepted or dropped, per peer and direction, the
last fragment freeing it. `FragmentMode::AllowOnly { ttl, capacity }` records only accepted
first fragments, keyed (source, destination, protocol, identification) without the peer,
live for `ttl` on the engine clock; a non-first fragment is judged before anything but the
bypass flags and dropped with `reasons::FRAGMENT` without a live entry; a full table drops
expired entries and otherwise records nothing. `accept_to_local: Option<Ipv4Addr>` and
`accept_icmp_echo_reply` (read from the raw header: IHL, 8 bytes after it, protocol 1,
type 0) accept an inbound IPv4 packet before anything else without the policy, counted in
`AclFilterStats::bypassed`. Both are off by default and cost one branch each when off.

### Stateless options

`stateful_replies: false` records no reply allowance in either
direction and no pending dependency, so replies are judged by the rules. `Ipv6Mode::Accept`
passes every IPv6 packet in both directions (fragments, `ICMPv6` and packets malformed beyond
the version included) before anything else, records no flow, reply or fragment state and
counts it in `AclFilterStats::ipv6_accepted`; where IPv6 may be addressed is then checked by
the core's `PeerConfig::inbound_destinations`. The default, `Ipv6Mode::Evaluate`, judges IPv6
like IPv4, and `Accept` costs one branch per packet when off. Malformed IPv4 (TCP/UDP header
truncated, total length inconsistent with the buffer) is dropped as `reasons::MALFORMED` in
every mode. These options combine freely; there is no preset. nsplane covers each option
with unit tests, the differential test on the stateless combination (no replies,
`AllowOnly { 15 s, 4096 }`, both bypasses, IPv6 accepted), and `nsplane-e2e`'s `acl_options`
between two engines.

nsplane only enforces: peer source lifecycles, rendezvous and session state machines stay
with the caller, which stores namespaces, grants and pinholes through this API.
`examples/src/bin/app_session.rs` shows a file transfer on it.

### Flow gate

`gate::FlowGate` is a generic stateful gate for decrypted inbound and plaintext outbound IPv4
and IPv6 packets.

- **Policy.** `replace(GatePolicy)` validates and publishes one whole policy atomically and
  returns the new gate generation (`generation()`); a rejected policy
  (`GatePolicyError`: duplicate scope, duplicate binding, a peer-keyed binding beside another
  binding of the same peer in one scope (`DuplicatePeerBinding`), invalid protocols, an
  unbound address listed twice or also bound in its scope) changes nothing. Every address and
  prefix may be IPv4 or IPv6, and a packet only matches entries of its own family. A
  policy is a list of `GateScope`s plus `GateHolds`. A scope has an opaque `ScopeId`, a
  `GateMode` (`Off`, `Observe`, `Enforce`), the local addresses it governs, `GateBinding`s
  (`PeerId` + remote addresses -> `LabelSet`; no addresses: peer-keyed),
  `unbound_addresses` (remote addresses of the
  scope without a `PeerId` binding; default empty), accept-only `GateGrant`s (direction,
  labels, destination prefixes, `ProtocolMatch`es, `suspended`) and `UnboundRule`s (`Pass`
  or `Divert` for designated peers).
- **Binding.** A packet belongs to a scope only through one of its bindings, the scope
  governing the packet's other address: first the exact `(PeerId, remote address)` pair;
  only when no scope governing the local address binds it, a peer-keyed binding of the
  `PeerId` (empty `addresses`: every remote address of either family). Two scopes at the
  chosen level is `Ambiguous`; none is `Unbound` under the mode of the scopes governing the
  local address (inbound) or holding the remote address as a binding address or in
  `unbound_addresses` or binding the peer peer-keyed (outbound), and `Pass` off the governed
  addresses. Outbound and outbound malformed packets to an unbound address, or to a
  peer-keyed peer from a source the scope does not govern, are therefore `Unbound` /
  `Malformed` under the scope's mode, and such an address is never a divert candidate. A
  policy without any peer-keyed binding skips the fallback (one flag). With exactly one
  enforcing scope at the local
  address, an `UnboundAction::Pass` rule passes matching packets of its peers on (first
  fragments remember that disposition for their later fragments).
- **Grants.** The first matching grant that is not suspended admits a new flow and its
  `RuleId` is reported (`GateReason::Granted`); only suspended matches give `Suspended`,
  none `NoGrant`. Grants never admit a reply-only packet.
- **State.** An admitted flow creates state that admits its replies, later fragments and ICMP
  errors (matched through the quoted header): idle timeouts (`GateTimeouts`, defaults TCP
  2 h, half-closed 5 min, closed 30 s, UDP 2 min, ICMP 30 s, other 60 s, fragments 30 s). A
  reply-only packet without state is `ReverseNewFlow`, as is a new SYN on a closing flow or
  from the responder; a later fragment without its first is `OrphanFragment`. Limits
  (`GateLimits`, defaults 16,384 flows, 2,048 per peer, 4,096 fragments): a full table
  sweeps expired entries and then fails closed with `StateCapacity`, never evicting a live
  entry.
- **Holds.** Inbound and outbound `HoldRule`s (peers, local and remote prefixes) deny with
  `Held` in every mode before any scope is consulted, malformed packets with readable
  addresses included; `GateHolds::release` exempts exact `(PeerId, address)` pairs from the
  inbound holds.
- **Modes.** No scope and no hold (or only `Off` scopes) is inert: `GateDecision::Pass`
  without parsing or a clock read. `Observe` reports `GateDecision::Observe` and counts
  denials (`GateCounters::observed_denied`) but keeps state; `Enforce` is authoritative.
  `GateReason` has stable names (`as_str`) and drop reasons (`drop_reason`, `flow gate:
  <reason>`).
- **IPv6.** Hop-by-Hop, Routing, Destination Options and Fragment headers are walked (at
  most 8, the Fragment header counted, in later fragments too, within the payload length; AH is skipped by its own length, ESP and No Next Header
  carry no ports); a truncated or longer chain, a second Fragment header or a first fragment
  without its whole upper-layer header is `Malformed` as for IPv4, and a packet shorter than
  the 40-byte fixed header passes as unreadable. Fragments are keyed by the 32-bit
  identification without reassembly; an atomic fragment is an unfragmented packet. `ICMPv6`
  errors (types 1-4) refresh the flow they quote, echo request 128 opens a flow and echo reply
  129 is reverse-only; Neighbor Discovery and other types need a grant like any new flow.
  Each shard keeps one flow and fragment map per family under one budget.
- **Queries.** `find_flow(remote, local, Protocol)` returns the live flow of a five-tuple of
  either family (`LiveFlow`: scope, grant id, enforced) and refreshes it; `None` for a
  mixed-family pair.

#### Scoped decisions

`evaluate_inbound_in(peer, packet, &ScopeSelection)` and `evaluate_outbound_in` decide for a
caller's selection of scopes: one (`ScopeSelection::one`) or a non-empty set
(`ScopeSelection::any_of`, order and repeats ignored; an empty set is refused with
`EmptySelection`). The ids need not be in the policy; a scope the policy does not have never
decides. The call takes the same steps on the same snapshot, state and counters as
`evaluate_inbound` / `evaluate_outbound`, with one check once the packet's scope is resolved
(the binding step) and before any state is read or written. It returns a `ScopedDecision`:

- `decision`: the gate's decision, as in the table below; never `GateDecision::Pass`.
- `scope`: the deciding scope, when it is in the selection.
- `rule`: the admitting grant (`Granted`) or the first matching suspended grant
  (`Suspended`) of a new flow, and the flow's grant for a packet of a live flow
  (`ValidState`) or an ICMP error quoting one; `None` for a later fragment and every other
  decision.
- `generation`: the policy generation the decision was taken under.

| Situation | Scoped decision |
| --- | --- |
| The resolved scope is in the selection | the decision of that scope: its mode, its state only (every flow and fragment key carries the scope), with `scope` and `rule` |
| The resolved scope is outside the selection | `Enforce { allow: false, reason: OutOfScope }`, no state read or written |
| No scope binds the packet (unbound, also with an `UnboundAction::Pass` rule; an inert gate; another IP version) | `Enforce { allow: false, reason: OutOfScope }`; an unbound first fragment records no pass disposition and a later one does not follow one |
| A hold matches | `Enforce { allow: false, reason: Held }` |
| More than one scope binds the packet | `Enforce { allow: false, reason: Ambiguous }`, whatever the scopes' modes |
| The packet cannot be parsed (or its addresses read) | `Enforce { allow: false, reason: Malformed }`, whatever the scopes' modes |

A scoped call creates, refreshes or migrates no state outside the selection; reclaiming
expired entries when a limit is reached is the same as for every evaluation. An `OutOfScope`
denial counts in `GateCounters::enforced_denied` and emits a decision event like any denial
(a scoped denial of a packet without readable addresses has no event and counts in
`events_dropped`). `evaluate_inbound`, `evaluate_outbound`, `GateFilter` and `find_flow`
take no selection: the unscoped calls share the evaluation with the scoped ones, which costs
them a few untaken branches per packet. A scoped call on an established flow also looks up
the scope id in the selection and clones the flow's grant id.

#### Decision events

`FlowGate::enable_events(GateEventsConfig)` opts in to a channel of `GateEvent`s and returns
its receiver, `GateEvents`; a second call replaces (and disconnects) the earlier receiver,
and `disable_events` turns them off again.

- **What emits.** New-flow decisions: a `GateReason::Granted` allow and every denial,
  enforced or observed, whatever its reason. Packets of existing flows
  (`GateReason::ValidState`), `GateDecision::Pass` and an inert gate emit nothing. An event
  carries `at` (the gate clock), the `peer`, the IP `protocol` (for IPv6 behind the
  extension headers), `src` and `dst` with ports (0 when the packet has none or they cannot
  be parsed), `allow`, `enforced` (`Enforce` rather than `Observe`), the `reason` and the
  `rule`: the admitting grant, or the first matching suspended grant for `Suspended`.
- **Bounded.** `capacity` events are buffered (default 1024). With 0 an event is delivered
  only to a receiver blocked in `recv` or `recv_timeout` at that moment.
- **Rate limited.** A token bucket of `burst` tokens (default 1000) refilled at `rate` per
  second of the gate clock (default 1000) limits emission; the bucket starts full, `rate` 0
  never refills it and `burst` 0 emits nothing.
- **Lossy.** The packet path never blocks on the channel: an event beyond the bucket,
  finding the buffer full or the receiver gone is dropped and counted in
  `GateCounters::events_dropped`; delivered events are counted in `events_emitted`. Dropping
  the `GateEvents` does not stop emission: events are counted as dropped until
  `disable_events`.
- **Receiver.** `try_recv` and `drain` never wait, `recv` and `recv_timeout` block the
  calling thread (use them off the async runtime). The receiver is disconnected once the
  gate is dropped or its events are disabled or replaced; buffered events are still
  received.
- **Cost.** Without events the packet path reads one relaxed flag. With events, each
  emitting decision also reads the clock, takes a short lock on the token bucket and
  reparses the packet's header for the event; established flows pay nothing more.

#### Migration and locking

Packet paths take one read of an immutable snapshot
(in a `SnapshotCell`) with the compiled scopes and their indexes (`(PeerId, address)` to
scopes, local and binding addresses to scopes) and the holds, and then lock only the state
shard of their peer: 64 shards by `PeerId`, each tagged with the generation it was migrated
to. Flow keys carry a scope slot that stays stable while the scope id stays in the policy.
Writers serialize on one mutex, compile the next snapshot, and with every shard locked
publish it and migrate the state: an unchanged scope keeps its flows and fragments; a
removed or `Off` scope loses them; each flow of a changed scope is re-authorized as a new
flow by its initiator (binding, local address, a matching grant that is not suspended) and
keeps its five-tuple and deadline with the new grant id and mode, or is dropped; the
fragments of a changed scope are dropped. A packet whose shard generation differs from its
snapshot retries, so it never sees a policy together with state of another one. The clock is
the coarse monotonic clock on Linux and Android (`Instant::now` elsewhere), or injected
(`with_clock`) for tests and benches.

#### Composition

`GateFilter` runs the gate as one `PacketFilter`, with an optional
`AclFilter` behind it (`with_acl`), because an enforced allow must end the decision before
the L4 ACL, which an accept-means-continue chain cannot express. Inbound: an enforced allow
is `Accept` without the ACL, an enforced denial drops with the gate's reason, and `Pass` and
`Observe` go on to the ACL (or are accepted without one). Outbound: an enforced denial drops;
`with_acl_outbound(true)` also runs the ACL's outbound for the rest. There is no peer table
in the filter: the wrapped `AclFilter` drops unknown peers inbound (`reasons::UNKNOWN_PEER`).
`GateFilterStats` counts the steps.

#### Divert

With `with_divert(divert)`, an inbound enforced `Unbound` or `OrphanFragment`
denial of a TCP or UDP packet that matches an `UnboundAction::Divert` rule of the one
enforcing scope at its destination, from an address that is no local, binding or unbound
address of any scope and that no hold matches, is offered to the `GateDivert` as a `DivertedPacket`
(generation, peer, scope, rule id, packet): taken, it is `Verdict::Handled` (no delivery, no
drop event); refused, it is counted and dropped with the gate's reason. The taker treats a
packet as current only while its `generation()` equals `FlowGate::generation()`.

#### Tests

`src/gate/tests/` covers grants and flow state (`grants_flow`), suspended, port,
ICMP and outbound grants (`grant_kinds`), ICMP errors, fragments and malformed packets
(`packets_fragments`), the IPv6 header walk, fragments and `ICMPv6` (`ipv6_packets`,
`ipv6_flows`), peer-keyed bindings (`peer_keyed`), holds and unbound rules
(`holds_and_unbound`), the state limits,
validation and the epoch retry (`state_table`), a writer racing packet threads
(`concurrency`), the filter (`filter`), decision events (`events`), scoped decisions
(`scoped`: two scopes with the same five-tuple, each scope's state untouched by a call for
the other, every row of the table), and `model`, which compares the gate on seeded
random sequences of packets, `replace` calls and clock steps against a reference model of
the gate (one map, no shards, no lazy expiry) for equal decisions and counters.
`nsplane-e2e` `flow_gate` runs the filter on one of two engines: grants, suspension,
bindings, state, limits and expiry (injected clock), modes, holds, unbound pass, ICMP errors,
divert with generation staleness, unbound addresses, and outbound; `flow_gate_v6` runs it
with a peer-keyed binding: an IPv6 flow admitted and denied, outbound IPv6 to the enforced
peer denied while its inbound flows arrive, and one binding governing both families.

## Configuration and defaults

| Feature | How to enable | Default | Cost when not enabled |
|---|---|---|---|
| ACL | `EngineBuilder::filter(Box::new(AclFilter::new(engine, identity)))` (`AclFilter::with_config`) | not installed | none |
| ACL not-installed action | `AclEngine::new().with_not_installed(NotInstalled::Accept)` | `NotInstalled::Deny` | none: the same branch as a missing rule set |
| ACL labels by source address | `PeerLabelMap::insert_by_source(peer, prefixes)` (or a `PeerIdentity` overriding `labels_for` and `by_source`) | per peer: one label set per peer | one cached flag per peer; no per-address table is filled |
| ACL fragment mode | `AclFilterConfig::fragments = FragmentMode::AllowOnly { ttl, capacity }` | `FragmentMode::Outcome` | none |
| ACL bypass flags | `AclFilterConfig::accept_to_local = Some(addr)`, `accept_icmp_echo_reply = true` | off | one branch per inbound packet each |
| ACL IPv6 mode | `AclFilterConfig::ipv6 = Ipv6Mode::Accept` | `Ipv6Mode::Evaluate` | one branch per packet |
| Flow accounting | `EngineBuilder::filter(Box::new(FlowTracker::new(capacity)))` | not installed | none |
| Flow gate | `EngineBuilder::filter(Box::new(GateFilter::new(gate).with_acl(acl)))` with `FlowGate::new(GateConfig::default())` and `FlowGate::replace(policy)` | not installed; constructed without a policy, inert | none; an inert gate passes every packet after one flag load |
| Flow gate decision events | `FlowGate::enable_events(GateEventsConfig::default())` (1024 buffered, 1000/s, burst 1000); `disable_events` | off | one relaxed flag read per decision |

## Errors and drop reasons

`AclFilter` drops with the constants of `reasons` (among them `NO_POLICY`, `DENIED`,
`POLICY_FAILED`, `UNKNOWN_PEER`, `CROSS_NAMESPACE`, `OUTBOUND`, `OUTBOUND_SOURCE`, `PROTOCOL`,
`FRAGMENT`, `MALFORMED`) and counts them in `AclFilterStats`. The gate reports a `GateReason`;
an enforced denial drops with `GateReason::drop_reason` (`flow gate: <reason>`), counted in
`GateCounters` and `GateFilterStats`. `RuleSet::new`, `store_namespace` and `store_grant`
reject invalid input and leave the previous state in effect; `open_pinhole` returns a
`PinholeError`; `FlowGate::replace` returns a `GatePolicyError`; `ScopeSelection::any_of`
returns `EmptySelection` for an empty set; `replace_scopes` returns an
`AclFilterScopeError`.

## Limits and bounds

- Reply allowances and per-address label caches: `AclFilterConfig::reply_capacity`; cached
  verdicts are flushed first when the table is full.
- `FragmentMode::AllowOnly { ttl, capacity }`: a full table drops expired entries and then
  records nothing.
- `FlowTracker`: a bounded table of the capacity it is created with.
- Flow gate: `GateLimits` (defaults 16,384 flows, 2,048 per peer, 4,096 fragments); a full
  table fails closed with `GateReason::StateCapacity` and never evicts a live entry.
- IPv6 header walk in the gate: at most 8 extension headers, the Fragment header included.
- Gate decision events: `GateEventsConfig::capacity` buffered events and a token bucket of
  `burst` tokens refilled at `rate` per second; events beyond them are dropped and counted
  in `GateCounters::events_dropped`.

## See also

- [Usage guide: access control](../guide.md#10-access-control-nsplane-acl)
- Specs: [source identity](../specs/acl-source-identity.md),
  [policy document](../specs/acl-policy-document.md), [node L3](../specs/node-l3.md)
- [Performance: ACL](../performance.md#acl) and [flow gate](../performance.md#flow-gate)
