# Node L3 model and its compilation onto the flow gate (AG-4) — product specification

- **Status**: specification of items removed from `nsplane-acl` in slice C5 of plan
  `20261007-0900-business-agnostic`.
- **Audience**: a product (ns first) that keeps the ns Node L3 model (Networks, Nodes,
  owners, Node / Service / Subnet grants, policy markers, gateway consumer divert) on top
  of the generic stateful flow gate.
- **Generic API**: [`acl-generic-api.md`](acl-generic-api.md) section 5 (`gate::FlowGate`,
  `GatePolicy`, `GateScope`, `GateBinding`, `GateGrant`, `UnboundRule`, `GateHolds`,
  `GateFilter`, `GateDivert`). Section 5 and its compile table (5.2) are approved as
  written. Snippets here are illustrative; the final names follow the merged C5 code.
- **Parity data**: [`data/node-l3-differential.json`](data/node-l3-differential.json),
  see [`data/README.md`](data/README.md) and section 5.

## 1. Scope and status

Before C5, `nsplane-acl` contained `NodeL3Gate`, a port of ns tunnel-wg `node_l3`. It
held per-Network ns policy snapshots, the local WireGuard projection and the local Provider
listeners, and judged decrypted inbound and plaintext outbound IPv4 packets on the Node
address plane. Under ADR
[`2026-10-06-business-agnostic-scope`](../decisions/2026-10-06-business-agnostic-scope.md)
nsplane keeps only a generic stateful flow gate: scopes, bindings by `PeerId`, labelled
accept-only grants, holds and unbound rules. Networks, Nodes, owners, Services, Subnets,
gateways, control sources and the snapshot wire schema are ns concepts. C5 removes:

| Removed item | Product replacement (this spec) |
| --- | --- |
| `NodeL3Gate::{new, new_for_targets, with_limits, with_clock}` | `FlowGate::new(GateConfig)` / `FlowGate::with_clock`; target machine ids stay in ns (2.6) |
| `NodeL3Gate::{apply, apply_from_source, withdraw_source}`, `NodeL3Applied`, `NodeL3ConfigError` | ns validates sources, tombstones, generations and phases (2.6), compiles (3) and calls `FlowGate::replace`; `GatePolicyError` covers generic validation only |
| `NodeL3Gate::{replace_transport_projection, replace_transport_projection_after_build, stage_transport_projection, withdraw_transport_projection}`, `NodeL3Transport`, `NodeL3TransportPeer`, `NodeL3TransportError` | ns keeps its device projection (2.5) and compiles it into `GateHolds` and `UnboundRule`s (3.6, 3.7) |
| `NodeL3Gate::replace_provider_listeners` | ns sets `GateGrant::suspended` and the carrier pass ports, then recompiles (3.4, 3.7) |
| `NodeL3Gate::{ready_for_ack, peer_readiness_snapshot}`, `NodeL3PeerReadiness`, `NodeL3PeerReadinessReason` | Pure ns functions (3.9) |
| `NodeL3Gate::{enforced_subnet_authorizations, enforced_subnet_return_peer_key, enforced_subnet_return_owners, enforced_subnet_ingress_authorized, enforced_subnet_ingress_prefixes}`, `NodeL3SubnetAuthorization` | Pure ns functions (3.8) |
| `NodeL3Gate::{authorization_generation, set_on_authorization_change}` | ns's own change marker (3.8) |
| `NodeL3Gate::{evaluate_inbound, evaluate_outbound}(peer_key, packet)` | `FlowGate::{evaluate_inbound, evaluate_outbound}(PeerId, packet)` |
| `NodeL3Gate::{evaluate_subnet_transport_inbound, evaluate_subnet_transport_outbound}`, `NodeL3Filter::with_subnet_transport_port` | Ordinary `GateGrant`s with id `subnet:<grant_id>` (3.5) |
| `NodeL3Gate::service_flow_authorized` | `FlowGate::find_flow` plus an ns check (3.10) |
| `NodeL3Gate::{gateway_consumer_packet, gateway_consumer_authority_current}`, `GatewayConsumerSink`, `GatewayConsumerPacket`, `GatewayConsumerAuthority` | `UnboundRule { action: Divert }`, `GateDivert`, `DivertedPacket`, `FlowGate::generation` (3.7) |
| `NodeL3Gate::counters`, `NodeL3Counters` | `FlowGate::counters`, `GateCounters` (3.11) |
| `NodeL3Config`, `NODE_L3_SCHEMA_VERSION`, `NodeL3Mode`, `NodeL3Node`, `NodeL3PeerBinding`, `NodeL3Grant`, `NodeL3Resource`, `NodeL3ServiceEndpoint`, `NodeL3ServiceProtocol`, `NodeL3PeerPolicyRequirement` | ns `control::messages` types (2.1); compiled to `GatePolicy` (3) |
| `NodeL3Decision`, `NodeL3Reason` | `GateDecision`, `GateReason` (3.11) |
| `NodeL3Filter`, `NodeL3FilterStats` | `GateFilter`, `GateFilterStats` (no unknown-peer drop, 4.2) |
| `PeerPublicKeys`, `PeerKeyMap` | ns maps WireGuard keys to `PeerId`s itself and binds by `PeerId` (3.2) |
| `src/node_l3/fixtures/differential.json`, `src/node_l3/tests/differential.rs` | Parity data under `docs/specs/data/` and the replay procedure (5) |

ns owns: the snapshot schema and its versioning, target binding, control-source authority,
tombstones, generations and phases, the ACK, the WireGuard projection and markers, the
Provider listeners, the Subnet queries and change marker, peer readiness, the gateway
consumer queue and its flow check, and the label and rule-id scheme of section 3. nsplane
owns enforcement of the resulting `GatePolicy`: atomic generation-tagged publication,
bounded flow state, its migration across `replace`, and the decisions and counters.

## 2. Semantics of the ns model

This section fixes the behaviour of the removed gate, which is the behaviour of ns
`tunnel-wg::node_l3::NodeL3Runtime` at the fixture's ns commit (section 5). It is the
contract that section 3 compiles.

### 2.1 Policy snapshot

One snapshot per Network (JSON, field names as below; `NODE_L3_SCHEMA_VERSION` = 1):

```text
NodeL3Config {
  schema_version: u16,            // must be 1
  network_id: String,             // globally unique, non-empty
  target_machine_id: String,      // the machine this snapshot is bound to, non-empty
  generation: u64,                // non-zero unless mode is disabled
  mode: "disabled" | "observe" | "enforce",
  local_node: { node_id, owner_id, ip: Ipv4Addr },          // this machine's Node
  bindings: [{ peer_public_key: [u8; 32], node_id, owner_id, ip: Ipv4Addr }],   // default []
  services: [{ service_id, node_id, protocol: "tcp" | "udp", port: u16 }],     // default []
  grants:   [{ grant_id, source_node_id, resource }],                           // default []
}
resource =
    { kind: "node",    node_id }
  | { kind: "service", service_id, node_id, protocol, port }
  | { kind: "subnet",  subnet_id: "<canonical decimal, non-zero u32>",
                       routing_node_id, prefix: "<IPv6 prefix, length >= 96>" }
```

- **Nodes.** The local Node plus every Node named by a binding. A Node has one owner and
  one IPv4 address. Nodes of one owner reach each other (same-owner rule, 2.3).
- **Bindings.** A binding ties a Node to the WireGuard public key that carries it. One key
  may carry several Nodes (one binding each). One Node may be bound under several keys
  only with the same address.
- **Services.** A Service is a virtual listener `(node, protocol, port)` on a Node's
  address. `port` is the overlay port, not the backend port. One listener maps to exactly
  one `service_id`.
- **Grants.** A directed edge from a source Node to a resource. `grant_id` is provenance,
  not a key: several edges may share one id.

Validation (the snapshot is rejected as a whole, nothing is published):

| Check | Error |
| --- | --- |
| `schema_version != 1` | `UnsupportedSchema` |
| `target_machine_id` not one of this process's targets | `WrongTarget` |
| Empty (after trim) `network_id`, `target_machine_id`, `local_node.{node_id, owner_id}`, `bindings.{node_id, owner_id}`, `grants.{grant_id, source_node_id}`, `services.{service_id, node_id}`, source id | `EmptyField` |
| `generation == 0` with mode other than `disabled` | `ZeroGeneration` |
| A binding naming the local Node id or the local address | `Conflict("local node peer binding")` |
| One Node id with two owners or two addresses | `Conflict("node identity")` |
| One address for two Node ids | `Conflict("node IP")` |
| One `(key, address)` for two Node ids | `Conflict("peer/source binding")` |
| One Node bound at two addresses | `Conflict("node transport binding")` |
| One `(node, protocol, port)` for two service ids | `Conflict("service listener")` |
| Service port 0 | `ZeroServicePort` |
| Grant source, Node target, Subnet routing Node or Service Node unknown | `UnknownNode` |
| Service grant whose `(node, protocol, port)` is not projected, or is projected for another `service_id` | `UnknownService` |
| Subnet id not canonical non-zero decimal `u32` | `InvalidSubnetId` |
| Subnet prefix not IPv6 or shorter than `/96` | `InvalidSubnetPrefix` |
| Source, generation and phase checks | 2.6 |

A `disabled` snapshot is not compiled beyond the schema, target and source checks.

### 2.2 Source binding

A packet belongs to a Network only through the exact pair `(peer key, remote Node
address)` of one of the Network's bindings, where the remote address is the IP source
inbound and the IP destination outbound, and the Network's local Node address equals the
packet's other address. Nothing else (route tables, the endpoint, the key alone) binds a
packet.

- **Several Networks** bind the same pair at the same local address: `ambiguous_network`,
  denied under `enforce` if any of them enforces, else `observe`.
- **Unbound inbound** packets to a local Node address: `source_binding` under the mode of
  the Networks with that local address (`enforce` if any enforces). A packet to an
  address no Network owns is `legacy`.
- **Unbound outbound** packets to an address that some Network holds as a remote Node
  address: `source_binding` under the mode of those Networks, even when the selected peer
  is not the bound one. Other destinations are `legacy`.

### 2.3 Grants

A new flow from Node `S` to Node `T` (inbound: `S` remote, `T` local; outbound: `S` local,
`T` remote) is admitted by the first that holds:

1. **Same owner** (`same_owner`): `S.owner == T.owner`. Full IPv4 access.
2. **Node grant** (`node_grant`): a `node` grant `S -> T`. Full IPv4 access to `T`.
3. **Service grant** (`service_grant`): the packet has a destination port, a Service
   `(T, protocol, port)` is projected and a `service` grant `S -> (T, protocol, port)` exists.
   Inbound additionally requires that the local Provider listener of that exact
   `(target_machine_id, service_id, protocol, port)` is installed (2.5); without it the
   flow is denied `service_projection`. Outbound needs no listener.
4. Otherwise `no_grant`.

Grants never admit a reply-only packet (2.4). Subnet grants admit only the Subnet LAN DNS
transport (2.3.1) and otherwise feed the queries of 3.8.

#### 2.3.1 Subnet LAN DNS admission

ns reserves UDP port 53535 (`SUBNET_LAN_DNS_TRANSPORT_PORT`). Before the normal
evaluation, a UDP first fragment (offset 0) to that destination port is admitted, and its
flow recorded as enforced, when exactly one Network satisfies all of:

- its mode is `enforce` and it is the live enforced generation of its Network;
- the device transport is installed and its local address is the Network's local address;
- inbound: destination is the local address and `(key, source)` is bound to Node `S`;
  outbound: source is the local address and `(key, destination)` is bound to Node `R`;
- that binding is live: installed on the device with the exact `enforce` marker of the
  Network's generation (2.5);
- a Subnet grant with source `S` and routing Node `R` exists, where inbound `R` is the
  local Node and outbound `S` is the local Node.

An existing flow of the same five-tuple is refreshed and admitted. A refused request falls
through to the normal evaluation. Replies and fragments use the normal flow state.

### 2.4 Flow state

The gate keeps a direction-independent flow per `(Network, generation, peer key, remote
address, local address, protocol, remote port, local port)`; ICMP echo uses its identifier
as both ports, other protocols use 0. TCP or UDP with a port 0 is `malformed_packet`.

For a bound packet, in order:

1. **Later fragment** (offset != 0): admitted (`valid_state`) only when its first fragment
   was admitted (fragment key: Network, generation, peer, addresses, protocol, IP id),
   else `orphan_fragment`.
2. **ICMP error** (types 3, 4, 11, 12): admitted (`valid_state`) when the quoted packet,
   read in the opposite direction, matches a live flow (which is refreshed), else
   `reverse_new_flow`; an unreadable quote is `malformed_packet`. Errors never create
   state.
3. **Existing flow**: `valid_state`, except a TCP initial SYN (SYN without ACK) from the
   responder or on a closing flow, which is `reverse_new_flow`. FIN and RST are tracked
   per direction.
4. **Reverse-only packet** without state: TCP without SYN or with ACK; ICMP types 0, 3,
   4, 5, 11, 12: `reverse_new_flow`.
5. **New flow**: grants (2.3). An admitted flow is recorded with its initiator direction,
   its service authorization (node-wide for same owner and Node grants, the exact
   `service_id` for a Service grant, none for a Subnet admission) and `enforced = (mode ==
   enforce)`. State is recorded in `observe` mode too. A first fragment with more
   fragments also remembers its fragment key.

Idle timeouts: TCP 2 h, half-closed TCP (one FIN or RST seen) 5 min, terminal TCP (FIN
both ways or RST) 30 s and never extended, UDP 2 min, ICMP 30 s, other 60 s, fragments
30 s. Limits: 16,384 flows in all, 2,048 per peer key, 4,096 fragments. Expiry is lazy; a
limit sweeps expired entries (the peer's shard first, then all) and then denies
`state_capacity`. A live flow is never evicted. The default clock is the coarse monotonic
clock on Linux and Android and `Instant::now` elsewhere.

### 2.5 Transport projection, policy markers and Provider listeners

The WireGuard device projection is:

```text
NodeL3Transport { local_ip: Ipv4Addr, peers: [NodeL3TransportPeer] }
NodeL3TransportPeer {
  public_key: [u8; 32], allowed_ips: [IpNet], gateway_id: Option<String>, relayed: bool,
  node_l3_policy: Option<{ network_id, generation: u64, mode, node_ips: [Ipv4Addr] }>,
}
```

- **Transport bindings**: every exact IPv4 `/32` of `allowed_ips` other than `local_ip`,
  as `(key, ip)`.
- **Policy marker** (`node_l3_policy`): the peer proves it belongs to that Network
  generation and phase for exactly `node_ips`. Rejected (`InvalidPolicyMarker`) when the
  Network id is empty, the generation is 0, the mode is `disabled`, `node_ips` is empty,
  an ip is not an exact `/32` of the peer, or one `(key, ip)` gets two markers; two peers
  marking one ip is `AmbiguousNodeRoute`. Marked `(key, ip)` pairs are the
  **authoritative bindings**.
- **Gateway carrier**: a peer with a non-empty `gateway_id`, no marker, not relayed and
  declared once (a duplicated key is never a carrier).
- **Install cycle**: `stage` (before a replacement device can receive packets) publishes
  the new projection as not installed and keeps, until the next install, the previous
  authoritative local addresses and markers of bindings the new config dropped.
  `replace` / `replace_after_build(desired, installed)` publishes the installed one; the
  installed projection must be a subset of the desired one with equal local address,
  markers and carriers (`InvalidInstalledProjection`), the bindings and carriers are the
  installed ones and the markers the desired ones. `withdraw` marks the projection not
  installed and keeps its authority.

**Policy pending (`policy_pending`).** With a projection present, an authoritative binding
`(key, ip)` with marker `m` is **ready** when the projection is installed, the binding is
installed, a policy for `m.network_id` is applied with `generation == m.generation`,
`mode == m.mode` and local address equal to the device's, that policy binds `(key, ip)`,
and either `m.mode == enforce` or the bound Node has the local owner. Every other
authoritative binding is pending. Then, before any binding lookup:

- outbound: the destination is the ip of a pending binding;
- inbound: the destination is an authoritative local address and either `(key, source)`
  is an authoritative binding that is pending, or `(key, source)` is not authoritative and
  the source is the ip of a pending binding or `key` carries a pending binding.

Such packets are denied `enforce:policy_pending` regardless of mode. A malformed packet
whose IPv4 addresses are readable takes the same check. Without a projection nothing is
pending.

**Provider listeners.** Per target machine, the set of installed `(service_id, protocol,
port)` (empty ids and port 0 ignored). They gate inbound Service grants (2.3) and the
gateway carrier pass (2.7).

### 2.6 Sources, generations and phases

ns enforces these before publishing; the gate's tests and the fixture cover them.

- **Source authority.** `apply` uses source `target:<target_machine_id>`. The first
  source to publish a Network id owns it for the process lifetime, also after withdrawal
  (`AuthorityConflict`).
- **Tombstone.** Per Network: owning source, target, generation, mode and the snapshot
  content with `observe` normalized to `enforce` (phase is not content).
- **Generations.** Older than the tombstone: `StaleGeneration`. Newer: published. Equal:
  after a withdrawal, identical content is an idempotent replay and other content is
  `Conflict`; a `disabled` snapshot always replaces the live phase; otherwise different
  content is `Conflict`, `enforce -> observe` is `PhaseRegression`, the same phase is an
  idempotent replay and `observe -> enforce` publishes.
- **`withdraw_source`.** Disables every Network owned by the source, clearing the
  tombstone content so every same-generation replay conflicts.
- **ACK.** A published snapshot yields `{network_id, target_machine_id, generation, mode}`;
  `ready_for_ack` is in 3.9.

### 2.7 Gateway carriers and the consumer divert

Terminate and Public gateways authenticate the carrier hop, not the original Node, so
their inner source cannot satisfy a binding. For an inbound unbound packet when exactly one
Network has the destination as local address, it enforces, and the key is a carrier of the
installed projection on that local address:

- **Carrier pass**: a first fragment (TCP or UDP) whose destination port is any installed
  Provider listener of the Network's target is `legacy` (handed to the L4 ACL). A first
  fragment with more fragments remembers a pass disposition; later fragments follow it,
  else `orphan_fragment`. Every transport replacement forgets the pass dispositions.
- **Divert**: with a divert sink installed on the filter, an enforced `source_binding` or
  `orphan_fragment` denial of a TCP or UDP packet is offered to the sink when exactly one
  Network has the destination as local address and enforces, the source is no Node address
  of any Network, the packet is not policy-pending, the installed projection's local
  address is the destination, and the key is a carrier. The candidate carries the
  authority `(key, gateway_id, source id, policy, projection)`. Accepted is
  `Verdict::Handled`; refused is counted and dropped. Before delivery the consumer checks
  `gateway_consumer_authority_current` (the same policy and projection objects are still
  published) and its exact live flow. `same_snapshot` compares two candidates' authority.

### 2.8 Modes, decisions, reasons and counters

- **No snapshot / `disabled`**: `legacy` (the packet goes on to the ACL). A gate with no
  policy and no projection answers `legacy` without parsing or reading the clock.
- **`observe`**: decisions are reported as `observe:<allow|deny>:<reason>` and state is
  kept, but the packet goes on to the ACL.
- **`enforce`**: authoritative. An allow skips the ACL, a denial drops with
  `node l3: <reason>`.
- **`policy_pending`** is always `enforce`.

Reasons (`as_str`): `legacy`, `valid_state`, `same_owner`, `node_grant`, `service_grant`,
`subnet_grant`, `source_binding`, `reverse_new_flow`, `no_grant`, `service_projection`,
`policy_pending`, `orphan_fragment`, `state_capacity`, `ambiguous_network`,
`malformed_packet`.

Gate counters: `enforced_allowed`, `enforced_denied`, `observed_denied`,
`source_binding_denied`, `state_capacity_denied` (each per decision; a Subnet admission
bumps `enforced_allowed`, or `state_capacity_denied` alone when the table is full). Filter
stats: `gate_accepted`, `gate_denied`, `diverted`, `divert_rejected`, `unknown_peer`,
`passed_to_acl`.

### 2.9 State migration

- **Apply** of a Network: each of its flows is re-authorized as a new flow by its
  initiator (binding, local address, same owner / Node / Service grant, inbound listener)
  and kept with its deadline and the new generation and `enforced`, or dropped. A flow
  that only a Subnet admission covers is dropped (re-authorization has no Subnet branch).
  The Network's fragments are dropped. Disable drops all its state.
- **Listener change** of a target: inbound flows with an exact service authorization whose
  listener is gone are dropped (outbound and node-wide flows stay); the fragments of the
  target's Networks are dropped.
- **Transport change**: pass dispositions are dropped; flows stay.

## 3. Compilation onto the generic gate

ns compiles its whole state (applied snapshots, the projection, the listeners and its
`PeerId`s) into one `GatePolicy` and calls `FlowGate::replace` whenever any input
changes. The result is published atomically; `replace` returns the gate generation.

### 3.1 Procedure

```text
recompile():
  policy = GatePolicy::default()
  for each applied Network snapshot N with mode observe or enforce:   // disabled: no scope
    policy.scopes.push(scope(N))                                      // 3.2 .. 3.7
  policy.holds = holds()                                              // 3.6
  gate.replace(policy)?          // GatePolicyError means an ns compiler bug: fail closed
  bump ns change marker          // 3.8
```

Trigger: every published apply or withdrawal (2.6), every transport stage, install or
withdrawal, every listener change, and every `PeerId` change of a key that appears in a
binding, carrier or marker (Q4: bindings are by `PeerId`). Unchanged scopes keep their
state across `replace` (design note 5.1); so a recompile that does not change a Network's
scope does not disturb its flows.

### 3.2 Scope, labels and bindings

```rust
let net = &n.network_id;
GateScope {
    id: ScopeId::from(net.as_str()),
    mode: if n.mode == Enforce { GateMode::Enforce } else { GateMode::Observe },
    local: vec![IpAddr::V4(n.local_node.ip)],
    bindings: n.bindings.iter().filter_map(|b| Some(GateBinding {
        peer: peer_id_of(b.peer_public_key)?,          // key without a PeerId: no binding
        addresses: vec![IpAddr::V4(b.ip)],
        labels: labels([
            format!("n/{net}/{}", b.node_id),          // Node label
            format!("o/{net}/{}", b.owner_id),         // owner label
        ] + live_label(n, b)),                         // 3.5
    })).collect(),
    grants: grants(n),                                 // 3.3 .. 3.5
    unbound: unbound(n),                               // 3.7
}
```

Label scheme (product strings; nsplane never parses them):

| Label | Carried by | Used by |
| --- | --- | --- |
| `n/<network>/<node>` | every binding of Node `node` | Node and Service grants |
| `o/<network>/<owner>` | every binding of a Node of `owner` | same-owner grants |
| `l/<network>/<node>` | only bindings of `node` that are live (2.3.1) in an enforced Network | Subnet admission grants (3.5) |

A key that ns cannot map to a `PeerId` (the peer is not on the engine) carries no
traffic, so leaving its binding out is equivalent. Several bindings of one key (several
Nodes) are several `GateBinding`s with the same `peer`.

### 3.3 Grant list and ids

Grants are emitted in this order; the gate reports the first match's id, which gives the
old precedence (same owner, then Node, then Service, then Subnet):

| Order | ns semantic | `GateGrant` | Id |
| --- | --- | --- | --- |
| 1 | Same owner, inbound | `Inbound`, labels `[o/<net>/<local owner>]`, destinations `[local/32]`, `[Any]` | `owner` |
| 2 | Same owner, outbound | `Outbound`, labels `[o/<net>/<local owner>]`, destinations `[]`, `[Any]` | `owner` |
| 3 | Node grant `X -> local` | `Inbound`, labels `[n/<net>/X]`, `[local/32]`, `[Any]` | `node:<grant_id>` |
| 3 | Node grant `local -> T` | `Outbound`, labels `[n/<net>/T]`, `[T ip/32]`, `[Any]` | `node:<grant_id>` |
| 4 | Service grant `X -> (local, p, port)` | `Inbound`, labels `[n/<net>/X]`, `[local/32]`, `[Tcp(port)]` or `[Udp(port)]`, `suspended` per 3.4 | `service:<service_id>:<grant_id>` |
| 4 | Service grant `local -> (T, p, port)` | `Outbound`, labels `[n/<net>/T]`, `[T ip/32]`, `[Tcp(port)]` or `[Udp(port)]`, never suspended | `service:<service_id>:<grant_id>` |
| 5 | Subnet admission | 3.5 | `subnet:<grant_id>` |

Grants whose source and target are both remote are not emitted (the old gate never
consulted them). A Node grant from the local Node to itself is not emitted. Grants with
`X == T` cannot arise from a valid snapshot. Same-owner peers are covered by grants 1 and 2
whatever their Node grants say.

### 3.4 Service projection (suspended grants)

An inbound Service grant has `suspended = !listeners(n.target_machine_id).contains(
(service_id, protocol, port))`. When it alone would admit a new flow the gate denies
`Suspended` (old `service_projection`); when another grant matches first (same owner, a
Node grant) that grant admits, as before. A listener change recompiles; the scope changes,
and flows under the now-suspended grant are dropped by the gate's re-authorization, as
`replace_provider_listeners` did (2.9).

### 3.5 Subnet admission grants

For each `enforce` Network that is the live enforced generation of its tombstone, with the
transport installed on its local address, and for each Subnet grant `S -> R` (routing Node
`R`) of the snapshot:

- `R` is the local Node: `Inbound { labels: [l/<net>/S], destinations: [local/32],
  protocols: [Udp(53535)] }`;
- `S` is the local Node: `Outbound { labels: [l/<net>/R], destinations: [R ip/32],
  protocols: [Udp(53535)] }`.

Id `subnet:<grant_id>`, emitted after the Service grants. The `l/` label is carried only by
the live bindings (installed, exact `enforce` marker of this generation), which makes the
grant exactly the old `binding_live` condition. The design note's 5.2 row writes
`labels: [n/S]` "with the binding live"; the two are equal when every binding of `S` in
the scope is live, and the `l/` form keeps them equal when a Node also has a non-live
binding (open point O3). A later fragment is not a new flow, so the grant needs no
fragment check.

### 3.6 Holds (policy pending)

Computed from the projection and the applied snapshots exactly as 2.5:

```rust
let Some(t) = projection else { return GateHolds::default() };     // no projection: no holds
let pending: Vec<(Key, Ipv4Addr)> = t.authoritative.iter().filter(|b| !ready(b)).collect();
let ips: Vec<IpNet> = pending.iter().map(|(_, ip)| net32(*ip)).dedup().collect();
let peers: Vec<PeerId> = pending.iter().filter_map(|(k, _)| peer_id_of(*k)).dedup().collect();
let locals: Vec<IpNet> = t.authoritative_local_ips.iter().map(net32).collect();
GateHolds {
    outbound: if ips.is_empty() { vec![] }
              else { vec![HoldRule { peers: None, local: vec![], remote: ips.clone() }] },
    inbound: [
        (!ips.is_empty()).then(|| HoldRule { peers: None, local: locals.clone(), remote: ips }),
        (!peers.is_empty()).then(|| HoldRule { peers: Some(peers), local: locals, remote: vec![] }),
    ].into_iter().flatten().collect(),
    release: t.authoritative.iter().filter(|b| ready(b))
              .filter_map(|(k, ip)| Some((peer_id_of(*k)?, IpAddr::V4(*ip)))).collect(),
}
```

Rules with an empty `remote` or `local` match any address, so an empty ip or peer list
must drop its rule instead of emitting it. `release` makes an exact ready binding skip
the inbound holds even when its key also carries a pending binding, which is the old
"exact authoritative binding decides" branch. Holds are checked before bindings, give
`Enforce(Held)` in every mode, and apply to malformed packets with readable addresses
(design note 5.1 step 2). Holds are not part of a scope, so a holds-only change does not
revalidate flows.

### 3.7 Gateway carriers: pass and divert

With an installed projection whose local address is `N`'s local address and `N` in
`enforce`, let `C` be the `PeerId`s of the projection's carriers:

```rust
unbound: vec![
    UnboundRule {                                   // carrier pass
        id: "gw-pass".into(),
        peers: C.clone(),
        action: UnboundAction::Pass,
        protocols: listeners(n.target_machine_id).map(|(_, p, port)| p.with_port(port)).collect(),
    },
    UnboundRule {                                   // consumer divert, one per gateway id
        id: format!("gw:{gateway_id}").into(),
        peers: carriers_of(gateway_id),
        action: UnboundAction::Divert,
        protocols: vec![Tcp(PortSet::Any), Udp(PortSet::Any)],
    },
]
```

The pass rule is omitted when there are no listeners, and both are omitted when the
projection is not installed or `N` observes. The gate applies them only when exactly one
scope holds the local address and it enforces, as the old gate did. `GateFilter::
with_divert(sink)` replaces `with_divert`. The consumer maps the candidate:

| Old | New |
| --- | --- |
| `authority().gateway_id()` | `rule()` without the `gw:` prefix |
| `authority().source_id()` | ns map `scope() -> source id` (the Network's tombstone) |
| `same_snapshot(a, b)` | equal `generation()`, `peer()` and `rule()` |
| `gateway_consumer_authority_current(a)` | `packet.generation() == gate.generation()` (Q6, 4.1) |
| `packet()`, `into_packet()` | `packet()`, `into_packet()` |

### 3.8 Subnet queries and the change marker

These are pure functions over the applied snapshots and the installed projection; ns
computes them itself. "Enforced Networks" are those in `enforce` that are the live
enforced generation of their tombstone; "live" is 2.3.1. All return nothing without an
installed projection.

- **`enforced_subnet_authorizations`**: for each enforced Network on the device's local
  address and each Subnet grant whose source is the local Node, the first binding (in
  snapshot order) of the routing Node, if live, gives `{source_id, network_id,
  generation, grant_id, subnet_id, routing_node_id, prefix, peer_key}`. Sorted by
  `(source_id, subnet_id, prefix, grant_id)`.
- **`enforced_subnet_return_peer_key(identity)`**: `identity` must have bytes 6-7 equal to
  `0x0002` and bytes 8-11 zero; bytes 12-15 are the consumer Node IPv4. Candidates: Subnet
  grants routed by the local Node whose prefix shares the first 6 bytes, and the first
  binding of the grant's source Node at that IPv4, if live. The key when all candidates
  agree, else none.
- **`enforced_subnet_return_owners`**: every identity the previous query resolves (prefix
  bytes 0-5, `0x0002`, zeros, Node IPv4), with its key, sorted by identity; disagreeing
  identities are withheld.
- **`enforced_subnet_ingress_authorized(key, dst)`**: some enforced Network on the device's
  local address has a Subnet grant routed by the local Node whose prefix contains `dst`
  and a live binding of the grant's source Node under `key`.
- **`enforced_subnet_ingress_prefixes`**: all such `(key, prefix)` pairs, sorted and
  deduplicated. ns folds them into nsplane-core's per-peer inbound destinations
  (`EngineHandle::set_inbound_destinations`), as today.
- **Change marker** (was `authorization_generation`): ns bumps its own counter after every
  published apply, `withdraw_source` that withdrew a Network, and every transport stage,
  install or withdrawal, and then recomputes the queries.

### 3.9 Readiness and ACK

- **`ready_for_ack(applied)`**: the Network's tombstone has the applied target,
  generation and mode. `disabled` is then ready. Otherwise the policy is published with
  those values, the projection is installed with the policy's local address, every
  installed transport binding whose ip is a remote Node of the policy is usable and
  carries a marker equal to `(network_id, generation, mode)`, and every desired marker of
  this Network is equal, installed and usable. Usable: the policy binds `(key, ip)` and
  either the mode is `enforce` or the Node has the local owner.
- **`peer_readiness_snapshot`**: one row per authoritative binding, with the first failing
  reason in this order: `transport_not_installed`, `binding_not_installed`,
  `policy_missing`, `generation_mismatch`, `mode_mismatch`, `local_ip_mismatch`,
  `binding_missing`, `observe_owner_mismatch`, else `ready`. Sorted by `(ip, network_id,
  marker_generation)`.

ns ACKs after `replace` returned. The gate generation is not part of the ACK.

### 3.10 Provider flow authorization

`service_flow_authorized(remote, local, target, protocol, service_id)` becomes:

```rust
let ok = gate.find_flow(remote, local, protocol.into()).is_some_and(|f| {
    let n = ns.network_of_scope(&f.scope);
    f.enforced
        && n.target_machine_id == target
        && IpAddr::V4(n.local_node.ip) == local.ip()
        && n.service_for(n.local_node, protocol, local.port()) == Some(service_id)
        && (f.rule == "owner" || f.rule.starts_with("node:")
            || f.rule.starts_with(&format!("service:{service_id}:")))
});
```

`find_flow` refreshes the flow and ignores expired ones. The projection check makes the
`service:` prefix match unambiguous (one listener has one service id). Subnet flows
(`subnet:*`) never authorize a Provider socket, as before. Non-IPv4 addresses give
`false`.

### 3.11 Reasons, decisions and counters

| Old | New |
| --- | --- |
| `NodeL3Decision::Legacy` | `GateDecision::Pass` |
| `Observe { would_allow, reason }` / `Enforce { allow, reason }` | `Observe { allow, reason, rule }` / `Enforce { allow, reason, rule }` |
| `valid_state` | `ValidState` |
| `same_owner`, `node_grant`, `service_grant`, `subnet_grant` | `Granted` with `rule` `owner`, `node:*`, `service:*`, `subnet:*` |
| `source_binding` | `Unbound` |
| `reverse_new_flow` | `ReverseNewFlow` |
| `no_grant` | `NoGrant` |
| `service_projection` | `Suspended` |
| `policy_pending` | `Held` |
| `orphan_fragment` | `OrphanFragment` |
| `state_capacity` | `StateCapacity` |
| `ambiguous_network` | `Ambiguous` |
| `malformed_packet` | `Malformed` |
| drop string `node l3: <reason>` | `flow gate: <reason>` (`GateReason::drop_reason`) |
| `NodeL3Counters` (`source_binding_denied`) | `GateCounters` (`unbound_denied`) |
| `NodeL3FilterStats` | `GateFilterStats` without `unknown_peer` |

ns decodes the old reason from `(reason, rule)` where it needs it (status, logs). Limits
and timeouts: `GateConfig::default()` equals 2.4; tests use `FlowGate::with_clock`.

### 3.12 Coverage of the design note's table (5.2)

| 5.2 row | Here |
| --- | --- |
| Source binding | 3.2 |
| Local Node | 3.2 |
| Same-owner rule | 3.3 |
| Node grant | 3.3 |
| Service grant | 3.3 |
| Service projection | 3.4 |
| Subnet grant, `enforced_subnet_*`, `authorization_generation`, callback | 3.8 |
| Subnet LAN DNS admission | 3.5 |
| Grant precedence | 3.3 |
| Multiple Networks; ambiguous Network | 3.2 (one scope per Network), 2.2 |
| Legacy (no snapshot) | 3.1 (no scopes, no holds: inert, `Pass`) |
| Observe / enforce; `disabled` | 3.1, 3.2; observe -> enforce is a changed scope whose flows are revalidated and become enforced |
| Policy pending marker | 3.6 |
| Malformed packet under a pending marker | 3.6 |
| Peer readiness | 3.9 |
| Gateway carrier pass | 3.7 |
| Gateway consumer divert | 3.7, 4.1 |
| `service_flow_authorized` | 3.10 |
| Reason mapping | 3.11 |
| Counters | 3.11 |
| Unknown peer drop | 4.2 |
| Wrong target, authority, stale, phase, tombstones, schema, ACK | 2.6, 3.9 |
| State limits, timeouts, coarse clock | 3.11, 2.4 |
| IPv6 Subnet ingress | 3.8 (`enforced_subnet_ingress_prefixes` into nsplane-core inbound destinations) |

## 4. Differences visible to ns

### 4.1 Divert authority is one gate generation (Q6)

Old: a queued candidate stayed current while its Network's policy object and the device
projection object were unchanged; other Networks' applies and listener changes did not
invalidate it. New: `DivertedPacket::generation()` must equal `FlowGate::generation()`, so
every `replace` (any Network, listeners, holds, `PeerId` changes) invalidates queued
candidates. This is stricter and fail-closed; it only affects packets queued across a
`replace`. Two fragments are under the same authority when generation, peer and rule are
equal.

### 4.2 No unknown-peer drop in the gate filter (Q7)

`NodeL3Filter` dropped any packet of a peer without a WireGuard key (`node l3: unknown
peer`, both directions). `GateFilter` has no key map. Inbound, the wrapped `AclFilter`
drops unknown peers (`UNKNOWN_PEER`), and on the governed plane a peer without a binding
is `Unbound` in the gate. Outbound to a peer missing from ns's tables, off the governed
plane, is no longer dropped by the gate filter; that is ns's routing concern.

### 4.3 Address family (Q5)

The gate handles IPv4 only; every other packet (IPv6, non-IP) is `GateDecision::Pass`,
which equals the old behaviour (`legacy`, and the filter skipped IPv6 inbound). The
policy types use `IpAddr` and `IpNet`. The design note does not say whether `replace`
rejects or ignores IPv6 entries in `local`, `addresses`, `destinations`, holds or
`release`: **to be fixed by C5** (open point O1). ns emits IPv4 only.

### 4.4 Further differences

Found while writing this spec, not listed in the design note; C5 confirms or closes them
(open point O2):

- **Subnet admission order and reason.** Old: a 53535 request was tried as a Subnet
  admission first and reported `subnet_grant`. New: Subnet grants come last, so a request
  that a same-owner or Node grant also admits reports that grant's id. The verdict is the
  same.
- **Subnet admission counters.** Old: a full table bumped only `state_capacity_denied`,
  then the packet fell through to the normal evaluation and was counted again. New: one
  decision, counted once.
- **Subnet flow migration.** Old: an apply dropped flows that only a Subnet admission
  covered, and a transport change left them alone. New:
  they are re-authorized like any flow: kept while the `subnet:` grant still matches,
  dropped when a transport change removes the `l/` label or the grant.
- **Pass dispositions.** Old: every transport replacement forgot them. New: they are
  dropped when their scope changes; a transport replacement that leaves the carriers and
  listeners unchanged keeps them (at most 30 s). A withdrawal removes the unbound rules,
  which changes the scope, so the "re-install within 30 s" case stays closed.
- **Divert source check.** Old: the source must be no Node address of any Network, local
  addresses included. New (note 5.1, `GateFilter`): no binding address of any scope. A
  carrier packet whose source is another Network's local Node address is now offered.
- **Drop strings** change from `node l3: *` to `flow gate: *` (3.11).

### 4.5 Open points

- **O1**: IPv6 entries in a `GatePolicy`: rejected by `replace` or ignored (4.3).
- **O2**: the differences of 4.4.
- **O3**: the `l/<network>/<node>` live label of 3.5, which refines the note's
  `labels: [n/S]`.
- **O4**: outbound malformed packets. The old gate took the Networks holding the
  destination as a remote Node address; note 5.1 step 2 speaks of the scopes whose `local`
  contains the destination. C5 keeps the old rule for outbound (the scopes holding the
  destination as a binding address) or states the change.
- **Paths**: note section 7 (C5) names this spec `docs/specs/acl-node-l3.md` and the data
  `docs/specs/fixtures/acl/node_l3_differential.json`; the files are
  `docs/specs/node-l3.md` and `docs/specs/data/node-l3-differential.json`. C5 references
  these.

## 5. Parity data

[`data/node-l3-differential.json`](data/node-l3-differential.json) is byte-identical to
`crates/nsplane-acl/src/node_l3/fixtures/differential.json` as last changed in commit
`de314a863e4c2b2a90eec39f72b20d04ea0d6d13` (sha256 in [`data/README.md`](data/README.md)).
It records ns `tunnel-wg::node_l3::NodeL3Runtime` results at ns commit
`e98259bc97e5d2053e4d971d76b5099826bf511a` (branch `refactor/nsplane`).

### 5.1 Format

```text
{
  "ns_commit": "<sha>",
  "scenarios": [{
    "name": "<scenario>",
    "targets": ["machine-1", ...],          // the process's target machine ids
    "steps": [ <step>, ... ]                // replayed in order on one fresh gate
  }]
}
step (tagged by "op"):
  { op: "apply", source?: "<source id>", config: <NodeL3Config JSON, 2.1>, expect }
        // no source: "target:<target_machine_id>"; expect "ok" or the error variant name
  { op: "withdraw_source", source, expect }          // "ok:<count>" or an error name
  { op: "transport", desired: <transport>, installed?: <transport>, expect }
        // no installed: installed = desired; expect "ok" or the error variant name
  { op: "stage_transport", config: <transport>, expect }
  { op: "withdraw_transport" }
  { op: "listeners", target, listeners: [{ service_id, protocol, port }] }
  { op: "inbound" | "outbound", peer: "<64 hex>", packet: "<IPv4 hex>", expect }
        // expect: "legacy" | "observe:<allow|deny>:<reason>" | "enforce:<allow|deny>:<reason>"
  { op: "gateway_consumer", peer, packet, expect: bool }    // a divert candidate exists
  { op: "subnet_inbound" | "subnet_outbound", peer, packet, port, expect: bool }
        // the Subnet LAN DNS admission (2.3.1) on port `port`
<transport> = { local_ip, peers: [{ public_key: "<64 hex>", allowed_ips: ["a.b.c.d/n"],
                gateway_id, relayed, node_l3_policy }] }
```

`peer_public_key` inside `config` is an array of 32 integers; packet and key strings are
hex without a prefix. `<reason>` is the old `as_str` (2.8).

Counts (verified with `jq`): 26 scenarios, 6,693 steps, of which **6,361 packet steps**
(3,175 `inbound`, 2,923 `outbound`, 126 `gateway_consumer`, 69 `subnet_inbound`, 68
`subnet_outbound`) and 332 operation steps (169 `apply`, 97 `transport`, 8
`stage_transport`, 11 `withdraw_transport`, 6 `withdraw_source`, 41 `listeners`). 25
scripted scenarios (same_owner, node_grant, service_grant_inbound,
service_grant_outbound, cross_owner_no_grant, source_binding, reverse_new_flow,
tcp_close, udp_icmp_flows, fragments, fragments_observe, malformed_packets, modes,
disabled_first, generation_change, observe_to_enforce, withdraw_source, policy_pending,
policy_pending_observe, transport_errors, gateway_delegation, subnet_transport_consumer,
subnet_transport_publisher, multi_network, multi_target_validation) and
`seeded_sequence` (6,193 steps over a two-Network config with interleaved policy,
transport and listener changes). Every reason except `subnet_grant` (reported only by the
filter) and `state_capacity` appears in the packet expectations. 136 Subnet steps use the
reserved port 53535 and one (`subnet_transport_publisher` step 7) uses port 53. ns has no
clock hook and private limits, so nothing time-dependent and no state capacity is
recorded; the gate's model test (design note 5.3) covers those.

### 5.2 Origin

Generated by a throwaway crate (never committed) that drove only the public ns
`NodeL3Runtime` API at `ns_commit`, converted ns config and `WgConfig` structs to the JSON
shapes above, and drew the seeded sequence from a fixed-seed `SplitMix64`. Re-running it
yields identical bytes. The generator layout and command are documented in the module docs
of `crates/nsplane-acl/src/node_l3/tests/differential.rs` (removed by C5; see its history
at the commit above).

### 5.3 Replay procedure

A product proves that its model (section 2) plus its compiler (section 3) plus the generic
gate reproduces ns by replaying every scenario:

1. Per scenario, create the product model with `targets`, a `FlowGate::new(GateConfig::
   default())`, and a key -> `PeerId` map that assigns a fresh `PeerId` to every key on
   first sight.
2. Operation steps run the product model (2.5, 2.6); the result is `"ok"`, `"ok:<n>"` or
   the old error variant name and must equal `expect`. Every published change runs
   `recompile()` (3.1).
3. `inbound` / `outbound`: `gate.evaluate_*(peer_id(peer), packet)`, mapped back with
   3.11: `Pass` -> `legacy`; `Granted` with rule `owner` / `node:*` / `service:*` /
   `subnet:*` -> `same_owner` / `node_grant` / `service_grant` / `subnet_grant`; the other
   reasons by the table; the text is `<observe|enforce>:<allow|deny>:<reason>`.
4. `subnet_inbound` / `subnet_outbound` with `port` 53535: the fixture calls the old
   admission alone, without the normal evaluation. The product evaluates the 2.3.1
   precondition first. When it holds, `gate.evaluate_*` must give an enforced allow and
   the result is `true`. Otherwise the result is `false` and the gate is not called, since
   the old admission never created state through another grant.
5. `gateway_consumer`: the old query was a pure predicate that recorded no state. The
   result is the 2.7 candidate predicate evaluated in the product model; the gate is not
   called. A product may cross-check that the scope has a matching `gw:` divert rule.
6. Require zero mismatches over all 6,361 packet steps and all operation steps, apart
   from the deviations below. Report the first mismatches with scenario name, step index,
   op, peer, packet hex, expected and actual, and `ns_commit`.

**Deviations.** These come from the fixture recording the raw old calls, while the old
filter combined them as "admission, then evaluation":

- **`subnet-port`**: a Subnet step whose `port` is not 53535 (one step,
  `subnet_transport_publisher` step 7, port 53). The compiled grants carry the product's
  one reserved port, so only the 2.3.1 precondition is compared.
- **`subnet-admission-in-gate`**: an `inbound` / `outbound` step that the gate admits with
  a `subnet:` rule while the fixture recorded the raw evaluation (`no_grant` or a
  reverse/denial reason). Example: `subnet_transport_consumer` step 13, an outbound UDP
  request to 53535 from a new source port with the routing Node's binding live. The old
  filter would have admitted it through the admission, so the new verdict equals the old
  production verdict. A later step of the same five-tuple then sees `valid_state` where
  the fixture recorded a denial; it is counted under the same deviation. The product
  reports the count of these deviations next to the mismatch count; each one must satisfy
  the 2.3.1 precondition.

nsplane's own test is the model test of design note 5.3; the replay above is the product's
parity check of its compiler and is not part of nsplane's suite after C5.
