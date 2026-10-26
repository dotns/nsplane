# 20261026-0822-node-gateway-requests Node and gateway requests at 0.19.2, and two defects: design and release grouping

- **status**: implementing (releases A and B approved; release C designed first, design note
  for review)
- **createdAt**: 2026-10-26 08:22
- **approvedAt**: 2026-10-26
- **relatedTask**: 20261026-0819-node-gateway-requests

## Context

Task `20261026-0819-node-gateway-requests` records six interface requests (R1-R6) from the node
and the gateway and two confirmed defects (D1, D2), all checked against `main` at `52eb983`
(v0.19.2). The two commits after v0.19.1 (`afae107`, where the requests were first verified)
raise the `tokio` requirement of nsplane-tun and nsplane-ether and lower the level of routine
handshake timer logs in `nsplane-noise` `timers.rs`; every source path, reference page and
record this plan cites is unchanged between the two. The requests fix the guarantee and leave the shape to nsplane; this plan proposes the
shapes, the behaviour and refusal rules, the tests, the costs, the documentation and how the
work is cut into releases. Nothing is implemented before the owner approves.

Code the design builds on (all at `52eb983`):

- Netstack admission and delivery (`crates/nsplane-netstack/src/stack.rs`, `pending.rs`,
  `flow.rs`). Under `TransparentConfig::admission = Admission::Decide` the driver holds a bare
  SYN or a first UDP datagram in `Pending` and offers a `PendingFlow`. `Driver::take_decisions`
  injects an accepted SYN into smoltcp, where a pooled listener socket takes it
  (`prepare_tcp_listeners`, `track_inbound` records the tuple and the egress mark in
  `Driver::inbound`); `Driver::promote` and `Driver::adopt` create the `FlowState` and the
  `TcpConnection` once the handshake completes, and `Driver::offer` / `flush_waiting` hand it to
  `incoming_tcp` or keep it in `Driver::waiting`. An accepted datagram goes through
  `Driver::dispatch_flow`, which creates the `FlowState` and queues the `UdpFlow` on
  `incoming_udp` at once. `FlowState` carries one immutable `Target`, the revoke flag, the
  outcome, the end position and the `FlowContext`; `Driver::retire` resolves a revoke by
  target. The ordinary stack has no admission point: `Driver::ingest` calls `admit_syn` only
  with `settings.transparent`.
- Netstack ingress (`NetStackSink`): an `mpsc::Sender<PacketBuf>`; `send` ignores the `PeerId`.
  The driver takes a batch (`ingest_batch`, `poll_recv_many`), runs `Driver::reassemble`
  (`nsplane_packet::reassembly::Reassembler`, completed datagrams are new buffers), then
  `classify` and either smoltcp (`device.inject`) or the UDP dispatch.
- Flow gate (`crates/nsplane-acl/src/gate.rs`, `gate/decisions.rs`). `FlowGate::evaluate_once`
  resolves one scope per packet (exact binding of `(peer, remote)` among the scopes governing
  `local`, else the peer-keyed ones, more than one is `Ambiguous`) before it touches state, and
  every flow and fragment key includes that scope's slot (`flow_key`, `fragment_key`), so
  state never crosses scopes. The scope is not reported: `GateDecision` has `allow`, `reason`,
  `rule`, and `valid_state` reports `rule: None` although `FlowState::rule` holds the grant.
  `GateReason` is `#[non_exhaustive]`; `GateDecision` and `GateCounters` are exhaustive.
- Core and engine (`crates/nsplane-core/src/core.rs`, `crates/nsplane/src/engine.rs`). Inbound,
  `Core::opened` runs the authenticated bookkeeping, `routes.source_allowed`
  (`SOURCE_NOT_ALLOWED`) and the inbound destinations (`DESTINATION_NOT_ALLOWED`);
  `Core::deliver_opened` runs `PacketFilter::inbound_from` in install order and pushes
  `Output::Deliver`. `Core::inject_inbound` pushes `Output::Deliver` directly (documented
  bypass). Outbound, `read_source` moves packets from the `PacketSource` into a bounded batch
  queue; `Owner::input_locals` runs the fragmenter, then `Core::handle_locals` (or
  `handle_locals_deferred`, whose `seal_job` also calls `prepare_send` in the owner task, so
  with crypto workers only sealing is deferred). `Core::prepare_send` routes and runs
  `PacketFilter::outbound` in reverse install order; without a session the tunnel queues a copy
  of the packet (`nsplane-noise` `Tunn::queue_packet`, `Vec<u8>`, at most 256, silently
  dropped beyond that and cleared by the timers) and `Core::flush_queue` sends it later.
  `TransportSlot::send_now` learns per call how many datagrams were sent and how many failed,
  not which. `PeerId`s are never reused (`peer_table.rs`). `Output` is exhaustive.
  `EngineError` means "the engine has stopped".
- Packet buffers (`crates/nsplane-packet/src/buf.rs`): `PacketBuf` is a `BytesMut`, `start`,
  `end` and a `shared` flag (56 bytes on 64-bit targets) with no metadata.
- Defects: `crates/nsplane-packet/src/vnet.rs` (`segment`, `fix_segment`, `pseudo_sum`),
  `crates/nsplane-tun/src/offload.rs` (`Coalescer::finish`, `checksum_valid`, `pseudo_sum`,
  `classify`), `crates/nsplane-acl/src/gate/packet.rs` (`walk_v6`, used by `parse_v6` and twice
  for quoted ICMPv6 errors).

Policy: ADR `2026-10-08-feature-freeze-0-11` keeps nsplane frozen except for owner exceptions
(ten so far, the last for the smoltcp rebase and RTO bounds). A bug fix keeps the API, has a
regression test, passes the full gate (`just check` including the term scan, `just cross`,
`just test-windows`, `cargo doc`, the e2e scripts) and gets a slot A/B when it touches the data
path. Every request here is a feature and needs an exception. ADR
`2026-10-06-business-agnostic-scope` applies: listeners, aliases and reference paths stay
consumer concepts; the APIs below are generic and the product documents name no consumer.

## Proposal

### Workstreams

| Workstream | Items | Crates and files written | Release |
| --- | --- | --- | --- |
| W0 defects | D1, D2 | `nsplane-packet/src/vnet.rs`, `nsplane-tun/src/offload.rs`, `nsplane-acl/src/gate/packet.rs`, `nsplane-acl/src/gate/tests/ipv6_packets.rs` | A |
| W1 netstack control from the first input | R1 | `nsplane-netstack/src/{config,pending,flow,stack,tcp,udp,lib}.rs`, its tests, a new `nsplane-e2e` test file | B |
| W2 scoped gate decisions | R3 | `nsplane-acl/src/gate.rs`, `gate/decisions.rs`, a new `gate/scoped.rs` and `gate/tests/scoped.rs`, `benches/gate.rs` | B |
| W3 engine entries | R4 (barrier), R5 part 1 | `nsplane-core/src/{core,reasons}.rs`, `nsplane/src/{engine,handle,builder,lib}.rs`, their tests, a new `nsplane-e2e` test file | B |
| W4 packet tag | carrier for R2, R5 part 2, R6 | `nsplane-packet/src/{buf,pool}.rs`, the copy sites in `nsplane-core`, `nsplane` (`fragment.rs`) and `nsplane-netstack` | C |
| W5 netstack ingress labels | R2 | `nsplane-netstack` (after W1) | C |
| W6 plaintext egress and send receipts | R5 part 2, R6 | `nsplane-core`, `nsplane`, possibly `nsplane-noise` (O9) | C |

Write scopes are disjoint within a release. W0 and W2 both touch `nsplane-acl` but different
files, and W0 ships first. Each workstream updates the reference page of the crates it writes;
the integrator owns `CHANGELOG.md`, `docs/architecture.md`, `docs/performance.md`, the ADR
amendment, `docs/changelog.md`, the version bumps and these task and plan files.

### W0 defects (D1, D2)

D1, `vnet.rs`: discriminate by IP version, not header length. `segment` already knows the
version (from the GSO type, or the first nibble for `GSO_UDP_L4`); it passes it to
`fix_segment` and `pseudo_sum`, which branch on `version == 6`. `offload.rs` gets the same
change for consistency: `classify` already computes `v6`; the group keeps it and
`Coalescer::finish`, `checksum_valid` and `pseudo_sum` use it. No API change (`segment`'s
signature stays; the helpers are private).

D2, `walk_v6`: count consumed headers, not loop iterations. The loop consumes at most
`MAX_EXTENSION_HEADERS` headers; a ninth header of any kind, a later Fragment header included,
is `None` (malformed). The upper-layer read stays after the loop. This keeps the documented rule
("At most 8 extension headers") and makes first and later fragments obey the same limit; the
module docs need no change, the `walk_v6` comment is reworded to say that the Fragment header
counts. Behaviour change: such a later fragment is denied `Malformed` instead of passing as
`ValidState`.

Tests (RED first, then the fix):

```rust
// crates/nsplane-packet/src/vnet.rs, mod tests
#[test]
fn segments_ipv4_with_twenty_option_bytes() {
    for proto in [TCP, UDP] {
        let mut s = spec(false, proto);
        // 20 bytes of IPv4 options, 19 NOPs and End of Options List: IHL 10, a 40-byte
        // header, the length of an IPv6 header.
        s.ip_options = vec![1; 19];
        s.ip_options.push(0);
        assert_eq!(s.ip_len(), 40);
        let (hdr, packet) = super_packet(&s, 2500, 1000);
        let segments = run(&hdr, &packet).unwrap();
        assert_eq!(segments.len(), 3);
        for (i, seg) in segments.iter().enumerate() {
            let data = payload(i * 1000, 1000.min(2500 - i * 1000));
            assert_eq!(*seg, build(&s.nth(i, i * 1000), &data), "proto {proto} segment {i}");
            assert_eq!(l4_checksum(false, proto, &seg[40..]), 0);
        }
    }
}

// crates/nsplane-acl/src/gate/tests/ipv6_packets.rs
#[test]
fn a_later_fragment_as_ninth_header_is_malformed() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    let id = 0x0bad_cafe;
    assert_eq!(
        gate.evaluate_inbound(PEER, &first_fragment6(REMOTE6, LOCAL6, 40_000, 53, id)),
        granted("in")
    );
    let mut nine = vec![options(60, 1); 8];
    nine.push(fragment6(id, 2, true));
    assert_eq!(
        gate.evaluate_inbound(PEER, &ipv6_with(REMOTE6, LOCAL6, &nine, 17, &[0; 8])),
        denied(GateReason::Malformed)
    );
    let mut eight = vec![options(60, 1); 7];
    eight.push(fragment6(id, 2, true));
    assert_eq!(
        gate.evaluate_inbound(PEER, &ipv6_with(REMOTE6, LOCAL6, &eight, 17, &[0; 8])),
        valid(),
        "eight headers, the Fragment header included, are walked"
    );
}
```

The first test is the D1 reproduction, the second the D2 reproduction plus the boundary that
stays allowed; the D2 row is also added to `at_most_eight_extension_headers_are_walked`. The D1
test covers UDP, which the existing `segments_tcp_with_options` (TCP options only) does not.
Further: an `offload.rs` test that an IPv4 packet with options is still not merged
(`classify`); the `nsplane-ether` packet-socket reads use the same `vnet::segment`.

Costs: one more argument through two private functions; the gate walk does one comparison per
header, as now. Slot A/B under the freeze rules: `cargo bench -p nsplane-packet --bench vnet`,
`cargo bench -p nsplane-tun --bench offload`, `cargo bench -p nsplane-acl --bench gate`
(`established/*`, the IPv6 cases).

Documentation: `CHANGELOG.md` `Fixed` (both, the D2 behaviour change stated);
`docs/reference/nsplane-packet.md` (`vnet`: IPv4 options of any length);
`docs/reference/nsplane-acl.md` (flow gate IPv6 rules: the Fragment header counts, later
fragments included).

### W1 netstack: control from the first input (R1)

API (additive):

```rust
pub struct NetStackConfig {
    // ...
    /// How a new connection or flow is admitted, for every stack. Default
    /// `Admission::Immediate`.
    pub admission: Admission,
}

impl PendingFlow {
    /// The control of this connection's or flow's lifetime, from its first input on.
    pub fn control(&self) -> FlowControl;
}

impl FlowControl {
    /// The receipt of the hand-out: delivered, or never delivered and why.
    pub fn delivery(&self) -> DeliveryReceipt;
}

#[derive(Clone)]
pub struct DeliveryReceipt { /* outcome(), async wait(), like RetirementReceipt */ }

#[non_exhaustive]
pub enum DeliveryOutcome {
    /// Handed out on `incoming_tcp` / `incoming_udp`, or opened by the application.
    Delivered,
    /// Never handed out; no handle of this lifetime appears afterwards.
    NotDelivered(Undelivered),
}

#[non_exhaustive]
pub enum Undelivered {
    Rejected,         // reject() or the item dropped
    TimedOut,         // no decision within Admission::Decide::timeout
    ConnectionLimit,  // TransparentConfig::max_connections at accept
    NoListener,       // the accepted SYN found no listener socket (listener_pool)
    HandshakeFailed,  // SYN-received socket reset, timed out or closed
    AcceptQueueFull,  // incoming_tcp / incoming_udp full (no accept_backpressure)
    AcceptQueueGone,  // the incoming stream was dropped
    FlowLimit,        // max_udp_flows at accept
    Revoked,          // FlowControl::revoke before the hand-out
    Stopped,          // the stack stopped first
}
```

Behaviour:

- The `FlowState` of a lifetime is created when the driver holds its first input, not at
  adoption. `FlowState` gains a lifecycle stage and its target becomes bound once by the driver
  (held, then admitted by tuple, then the socket or flow entry). Every control, context and
  receipt of the lifetime is that one state, before and after the hand-out, so the delivered
  `TcpConnection::control` / `UdpFlow::control` equals `PendingFlow::control` (`FlowContext`
  bound on it at the decision stays on the handle).
- Each lifetime has exactly one delivery outcome, fixed by one compare-and-swap on the stage:
  at the hand-out (the `incoming_tcp` / `incoming_udp` stream takes the item from its channel,
  or the application opens the flow) or at the first terminal event (reject, timeout, limits,
  handshake failure, full or gone queue, revoke, stop). A stream that finds an item whose
  stage is already terminal skips it, so a lifetime revoked while it sits in the channel is
  never returned; a handle dropped undelivered with the channel resolves `AcceptQueueGone`.
- `revoke` before the hand-out retires the lifetime in the next driver turn: the `Pending`
  entry, the `SynReceived` listener socket (released like a revoked connection, without an RST;
  its SYN-ACK still in the egress queue fenced by the existing TCP fence from the egress mark
  `track_inbound` recorded), the entry in `Driver::waiting`, the UDP flow entry and its queued
  datagrams, and a reassembly barrier as today. `RetirementOutcome` is unchanged: `Retired`
  only when the stack holds nothing of the lifetime, `Failed` when a bounded table is full,
  `Unknown` when the stack stopped. A later packet on the tuple is a new lifetime.
- Refusals as today: `bind_context` on a revoked lifetime, a second bind, exhausted
  instances; `tcp_egress_drained` with another stack's control or a lifetime not yet adopted
  is an `InvalidInput` error.
- Scope: lifetimes held under `Admission::Decide`, on transparent and, with the new
  `NetStackConfig::admission`, ordinary stacks (on an ordinary stack `Decide` applies to SYNs
  and first datagrams to the stack's own addresses, rejections are sourced from them, and
  `max_connections` does not exist). `Immediate` has no point before the hand-out and keeps its
  path; its handles report `Delivered` at once. Flows the application opens report `Delivered`.
- Statistics and flow events stay. The reasons map to the existing counters (`rejected_hook`,
  `rejected_timeout`, `rejected_connection_limit`, `syn_refused`, `tcp_not_accepted`,
  `udp_not_accepted`, `udp_flow_limit`); a handshake that never completes gets a new
  `NetStackStats::handshake_failed` field, as earlier releases added counters.

Tests: unit tests for every stage x revoke (held, accepted before the next turn, `SynReceived`,
established in `waiting`, in the channel, after the hand-out) with the delivery outcome, the
retirement outcome and the absence of a later handle; every `Undelivered` reason; the CAS race
(revoke concurrent with the stream's poll, repeated under `tokio::test` with a multi-thread
runtime); same tuple after revoke is a new lifetime; ordinary stack with `Decide` (TCP and UDP,
own addresses); `FlowContext` bound on the pending control visible on the handle. A new
`nsplane-e2e` test through two engines: revoke under load at each stage, no handle and no
packet of the revoked lifetime leaves the stack.

Costs: `Immediate` admission: no change on the per-packet path (the hold path is `#[cold]`
already). `Decide`: the `FlowState` allocation moves from adoption to the hold, plus one CAS
per hand-out and one stage check per item in the stream. A/B: `send_stream` (`netstack_send`,
`netstack_udp_send`, including `flows_4`, the case that showed +4.1 % when flow state was
added) with the default configuration.

Documentation: `docs/reference/nsplane-netstack.md` (Admission for every stack, a "Control from
the first input" section next to "Per-flow control and retirement", the delivery receipt, Limits
and bounds); `CHANGELOG.md` `Added`.

### W2 scoped flow-gate decisions (R3)

API (additive):

```rust
/// One scope, or a non-empty set of scopes, a decision is valid for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeSelection { /* never empty */ }

impl ScopeSelection {
    pub fn one(scope: ScopeId) -> Self;
    /// # Errors
    /// `EmptySelection` when `scopes` is empty.
    pub fn any_of(scopes: impl IntoIterator<Item = ScopeId>) -> Result<Self, EmptySelection>;
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedDecision {
    /// The decision; always enforced outside the selection.
    pub decision: GateDecision,
    /// The deciding scope, when it is in the selection.
    pub scope: Option<ScopeId>,
    /// The grant: admitting or suspended for a new flow, the flow's grant for a packet of a
    /// live flow or an ICMP error quoting one.
    pub rule: Option<RuleId>,
    /// The policy generation the decision was taken under.
    pub generation: u64,
}

impl FlowGate {
    pub fn evaluate_inbound_in(&self, peer: PeerId, packet: &[u8], selection: &ScopeSelection) -> ScopedDecision;
    pub fn evaluate_outbound_in(&self, peer: PeerId, packet: &[u8], selection: &ScopeSelection) -> ScopedDecision;
}

// GateReason (non_exhaustive) gains:
/// The packet belongs to no scope of the caller's selection.
OutOfScope,
```

Behaviour: the scoped call runs the same steps on the same snapshot, shards and counters as
`evaluate_inbound` / `evaluate_outbound`, with one check placed after the scope is resolved and
before any state is read or written:

| Situation | Scoped decision |
| --- | --- |
| Resolved scope in the selection | the normal decision of that scope (its mode, its state only, since every key carries the scope's slot) with `scope` and `rule` |
| Resolved scope outside the selection | `Enforce { allow: false, reason: OutOfScope }`, no state touched |
| No scope (unbound, including an `UnboundAction::Pass` rule; inert gate; other IP version) | `Enforce { allow: false, reason: OutOfScope }`; an unbound first fragment records no pass disposition |
| Held | `Enforce { allow: false, reason: Held }` |
| Ambiguous | `Enforce { allow: false, reason: Ambiguous }`, enforced whatever the scopes' modes |
| Malformed | `Enforce { allow: false, reason: Malformed }` |

Expiry sweeps (`SweepAll`) reclaim only expired entries, as every evaluation does; no live
state outside the selection is created, refreshed or migrated. An empty selection cannot be
built. `evaluate_inbound` / `evaluate_outbound`, `GateFilter` and `find_flow` are unchanged.
Counters and events: an `OutOfScope` denial counts as an enforced denial and emits a decision
event like any denial; `GateCounters` gets no new field (it is an exhaustive struct; see O5).

Tests: two scopes binding the same peer and remote with the same five-tuple flows, each opened
under its scope: a scoped call for scope A never returns `ValidState` for B's flow and leaves
B's flow, fragment and expiry untouched (checked through `find_flow` and a clock); new flows,
`ValidState` with the flow's rule, later fragments, ICMP errors quoting a flow of the other
scope, peer-keyed fallback, ambiguity, unbound pass rules, holds, malformed and inert gates;
selection of several scopes; replace between two calls (generation reported, migration
unchanged); the unscoped results are identical before and after the change (existing suite).

Costs: the existing entries keep their path; the selection reaches `evaluate_once` as an
`Option` (or a const generic, if the A/B shows any difference). A/B: `gate` bench
`established/gate`, `established/outbound`, `established/filter`, `baseline/pass_gate` (an
inert gate must stay a constant pass), plus new `scoped/established` and `scoped/out_of_scope`
cases.

Documentation: `docs/reference/nsplane-acl.md` (flow gate: scoped decisions, the table above);
`CHANGELOG.md` `Added`.

### W3 engine entries (R4 barrier, R5 part 1)

R4, local barrier (proposal B of the request; the tag of proposal A comes with W4):

```rust
impl EngineHandle {
    /// Waits until every packet the engine took from its `PacketSource` before this call has
    /// been routed and passed or been dropped by the outbound filters (or dropped for no
    /// route, fragmentation or the tunnel queue).
    ///
    /// # Errors
    /// `EngineError` once the engine stopped before that; never reports a barrier it did not
    /// pass.
    pub async fn local_barrier(&self) -> Result<(), EngineError>;
}
```

Mechanism: `read_source` adds the number of packets each `recv_batch` returned to a shared
counter before it queues them; the call reads that counter synchronously (the barrier position)
and sends it to the owner, which completes the barrier once its own count of packets it took
from the local queue and handed through the fragmenter and `Core::handle_locals` /
`handle_locals_deferred` reaches the position. Routing and the outbound filters run in that
call on the owner task, also with crypto workers. Packets counted include those `read_source`
holds while the local queue is full. A suspended engine completes the barrier after it resumes;
a stopped one returns the error. Packets in a kernel TUN queue, or in the consumer's own queue
before `PacketSource::recv`, are outside, as the request states; with its own source-side fence
the consumer bounds the window exactly.

R5 part 1, validated plaintext ingress:

```rust
impl<Src, Snk> EngineBuilder<Src, Snk> {
    /// A bounded entry for plaintext packets attributed to a peer, checked like decrypted
    /// data; see `PlaintextIngress`.
    pub fn plaintext_ingress(self, capacity: usize) -> (Self, PlaintextIngress);
}

impl PlaintextIngress {
    /// Queues `packet` as received from `peer` on `from`; waits while the queue is full.
    pub async fn send(&self, peer: PeerId, from: Path, packet: PacketBuf) -> Result<(), EngineError>;
    /// Like `send`, but refuses at once with the packet when the queue is full.
    pub fn try_send(&self, peer: PeerId, from: Path, packet: PacketBuf) -> Result<(), PlaintextRefused>;
}

impl Core {
    /// Runs `packet` from `peer` through the checks and filters of a decrypted data packet.
    pub fn receive_plaintext(&mut self, peer: PeerId, from: Path, packet: PacketBuf);
}

// reasons:
pub const UNKNOWN_PLAINTEXT_PEER: &str = "plaintext from unknown peer";
```

Behaviour: `Core::receive_plaintext` runs exactly the post-decryption code of a data packet:
the source check and the inbound destinations of `Core::opened` and the filter loop and
delivery of `Core::deliver_opened`, moved into shared functions so both paths execute the same
code. Drops report the same reasons (`SOURCE_NOT_ALLOWED`, `DESTINATION_NOT_ALLOWED`, filter
reasons); an unknown or removed peer is dropped as `UNKNOWN_PLAINTEXT_PEER`, never delivered; a
packet without a readable IPv4 or IPv6 source address is dropped as `SOURCE_NOT_ALLOWED`
(proposed). It does not run the authenticated-message bookkeeping: no handshake
accounting, no `PathPolicy::on_authenticated`, no roaming and no `Event::Authenticated`; the
filters see `from` as the arrival path. Delivered bytes count in `data_rx`, not in `rx` (O7).
The queue is bounded by `capacity`; the owner polls it with the datagram queue and takes at
most a batch per turn. `inject_inbound` keeps its bypass contract.

Tests: core unit tests that a plaintext packet and a decrypted packet of the same peer meet the
same verdicts for every check (source not allowed, destination not allowed, filter drop,
handled, accept) with a recording filter that sees the same `(peer, path)`; unknown and removed
peer; IPv4 and IPv6; no `Event::Authenticated` and no path change. Engine tests: back-pressure
and `try_send` refusal, stop. Barrier: packets in the source queue, in `read_source` while the
local queue is full, with the fragmenter, with crypto workers; a filter that records the order
proves every pre-barrier packet passed before the barrier returned; stop returns the error.

Costs: the barrier adds one atomic add per source batch and a counter in the owner; the ingress
queue is polled only when built. A/B: `nsplane` `local_graph`, `nsplane-core` `data_path`
(`core_round_trip/64`, 417 ns) for the refactored delivery functions.

Documentation: `docs/reference/nsplane.md` (local barrier, plaintext ingress queue),
`docs/reference/nsplane-core.md` (Injected packets next to validated plaintext; Errors and drop
reasons), `docs/architecture.md` (Data flow: the plaintext entry), `CHANGELOG.md` `Added`.

### W4-W6: one carrier through the engine and the stack (R2, R5 part 2, R6)

These three need a per-packet property that survives the queues between a consumer and the
point where nsplane decides: the netstack's ingress stages (R2), the engine's local path to the
outbound filters and sealing (R5 part 2, R6, and R4 proposal A). The proposal is one generic
carrier instead of three side channels, and a design note before any code.

W4, packet tag: `PacketBuf` gains an opaque `Option<NonZeroU64>` tag (`tag`, `set_tag`) that
nsplane never interprets and never puts on the wire. It is preserved wherever nsplane moves a
packet into another buffer (`Core::layout_for_sealing`'s copy, each fragment of the
fragmenter, `CryptoJob`, the engine's datagram queue up to the transport call) and cleared when
a buffer returns to a `PacketPool`. A reassembled datagram carries a tag only if every fragment
carried the same one. `PacketFilter::outbound` and `inbound_from` see the tag on the packet
they receive, which gives R4 proposal A without a trait change. Size: 56 to 64 bytes per
`PacketBuf` unless `start` / `end` shrink to `u32`; to be measured.

W5, netstack ingress labels (R2, proposal A of the request): the tag of a packet sent into
`NetStackSink` is its ingress label.

- A new lifetime takes the label of its first input (W1 records it on the `FlowState`):
  `PendingFlow::ingress_label`, `TcpConnection::ingress_label`, `UdpFlow::ingress_label`; a
  `UdpSocket` from `bind_udp` returns the label with each datagram (`recv_labeled`).
- Input with another label than its lifetime's is dropped and counted (`label_mismatch`): a TCP
  segment, a handshake ACK or a datagram for a labeled lifetime; a fragment set whose labels
  differ is discarded and counted. Unlabeled input on an unlabeled stack keeps today's path.
- `NetStackHandle::revoke_label(label) -> RetirementReceipt`: retires every lifetime with that
  label at every stage (W1's per-stage retirement), drops reassembly entries with that label,
  and drops later-dequeued input with it until the ingress queue has passed every packet sent
  before the call (a bounded table of ingress positions, like the egress fences; full means
  `Failed`). The consumer stops sending the label before revoking it. `Retired` means no input
  with the label is delivered from then on; a stopped stack reports `Unknown`.

W6, plaintext egress (R5 part 2) and send receipts (R6):

- Plaintext egress: `Core::set_plaintext_egress(peer, bool)` and the engine equivalent mark a
  peer whose routed local packets, after the outbound filters, leave as a new
  `Output::Plaintext { to, packet }` instead of being sealed; the engine hands them to a bounded
  `PlaintextEgress` receiver from the builder. Full queue: dropped as `PLAINTEXT_EGRESS_FULL`;
  receiver gone: `PLAINTEXT_EGRESS_CLOSED`. Packets carry the routed `PeerId`, which is never
  reused, so a packet of a removed peer is never attributed to a later one. Such a peer starts
  no handshake for data (O8). Adding an `Output` variant is a breaking change for code that
  drives `Core` itself; `Output` becomes `#[non_exhaustive]` in the same release.
- Send receipts: `EngineBuilder::tracked_sender(capacity) -> (Self, TrackedSender,
  SendResults)`. `TrackedSender::send(packet, token)` enters the normal local path (fragmenter,
  routing, filters, sealing, transport); `SendResults` yields exactly one `SendResult { token,
  outcome }` per accepted packet: `Sent { peer, bytes }` when the transport call that carried
  its datagram succeeded, `NotSent { reason }` with the existing reason strings (no route,
  filter drop, handled by a filter, no session, transmit full, transport closed, removed or
  send error, engine stopped). Outstanding tokens are bounded by `capacity`; `send` waits and
  `try_send` refuses when it is reached, so results are never dropped. A tracked datagram ends
  its transmit batch so the per-call counts of `TransportSlot::send_now` attribute it exactly.
  Without a session a tracked packet is `NotSent { no session }` at once and starts the
  handshake an untracked packet would start (O9); one that needs fragmentation is
  `NotSent { oversize }` (O10). Untracked packets are unaffected.

Tests (design note to list them per carrier site): the tag survives each copy site and is
cleared in the pool; W5 the node's two reproduced cases (a partial datagram completed after a
listener replacement; queued complete input) as netstack tests with labels; each stage of
`revoke_label`; W6 exactly one result per token under every drop site, transport failure in the
middle of a batch, stop with tokens outstanding; plaintext egress full, closed, peer removed and
re-added.

Costs: every packet carries the tag word; untagged traffic must stay within the A/B noise on
`core_round_trip/64`, `core_round_trip_batch32`, `send_stream` (`netstack_udp_send/flows_4`
included), `local_graph`, `udp_offload`. Label checks in the netstack run only for labeled
lifetimes; receipts cost only for tracked packets.

Documentation: `nsplane-packet.md` (tag), `nsplane-netstack.md` (ingress labels),
`nsplane.md` and `nsplane-core.md` (plaintext egress, receipts, reasons),
`docs/architecture.md` (contracts: the tag, the reference entries), `docs/performance.md`,
`CHANGELOG.md` (`Added`, `Changed`, the breaking `Output` change under its own heading).

### Release grouping

| Release | Content | Policy | Ready |
| --- | --- | --- | --- |
| A, 0.19.3 | W0: D1, D2 | bug-fix release under the freeze rules (regression tests, full gate, slot A/B of `vnet`, `offload`, `gate`) | on approval |
| B, 0.20.0 | W1 (R1), W2 (R3), W3 (R4 barrier, R5 part 1) | eleventh freeze exception; additive API, no cost on default paths | on approval of this plan and O1-O7 |
| C, 0.21.0 | W4 (tag), W5 (R2), W6 (R5 part 2, R6) | twelfth exception; breaking (`Output`, `PacketBuf` size); after a design note the owner and both consumers review | needs more design |

Within B the workstreams run in parallel and merge in the order W2, W3, W1 (smallest first);
each passes the full gate on its own. B can also ship as smaller releases (R3 alone is the
smallest and unblocks per-scope admission) if the owner prefers. C's design note covers the
carrier sites, the per-packet budget, O8-O11 and the consumers' adoption path; C starts only
after it is approved.

### Owner decisions needed

1. Approve release A as a bug-fix release, including the D2 behaviour change.
2. Approve the eleventh exception for release B with the shapes above (or name changes).
3. Answer O1-O7 for release B; O8-O12 can wait for C's design note.
4. Approve that release C is designed first, as one carrier (the packet tag), not three side
   channels.

### Open questions

- O1 (R1) Admission on ordinary stacks: a top-level `NetStackConfig::admission` with
  `TransparentConfig::admission` deprecated (recommended; transparent stacks honour either
  until removal in a breaking release), or ordinary stacks keep no admission point and R1 stays
  transparent-only.
- O2 (R1) A revoke before the hand-out sends nothing, like every revoke (recommended); the
  consumer that wants the peer told calls `reject` while it still holds the `PendingFlow`.
- O3 (R1) R1 applies to `Decide` lifetimes only (recommended); with `Immediate` there is no
  consumer point before the hand-out.
- O4 (R3) A later fragment's scoped decision reports `rule: None`; fragment state would need one
  more pointer per entry to report the grant. Recommended: `None`.
- O5 (R3) `OutOfScope` denials count as enforced denials and emit events, without a new
  `GateCounters` field (an exhaustive struct, adding one breaks literals). Alternative: a
  separate scoped counter accessor.
- O6 (R4) The barrier now (recommended), the per-packet tag with release C, or both.
- O7 (R5 part 1) `from: Path` mandatory (recommended) or optional with the peer's current path;
  authenticated bookkeeping not run (recommended); bytes in `data_rx`.
- O8 (R5 part 2) Opt-in per peer through a call (recommended) or a `PeerConfig` field; whether a
  plaintext-egress peer may still handshake for inbound sealed traffic.
- O9 (R6) Without a session: `NotSent` at once (recommended), or carry tags through the tunnel
  queue, which means changing `nsplane-noise` so its queue keeps the tag and reports overflow and
  expiry.
- O10 (R6) A tracked packet above the MTU: `NotSent { oversize }` (recommended) or one result
  after all fragments.
- O11 (C) The tag on `PacketBuf` (recommended) or per-queue side fields; `Output` made
  `#[non_exhaustive]`.
- O12 (R2) Labels (recommended: composes with W1, attributes every handle without timing) or a
  barrier with ingress sequence numbers on handles (completion waits on handshakes that may
  never finish, and every handle needs the sequence anyway).

## Risks

- R1 rewires the driver's admission path (pending table, listener pool, promotion, waiting
  queue, accept channels). A stage missed by retirement would deliver a revoked lifetime; the
  stage-by-stage tests and the single CAS at the hand-out are the guard. `Immediate` stacks must
  be bit-for-bit unchanged; the existing netstack suite and e2e run unmodified.
- R3 must not change unscoped results; the scoped check sits after scope resolution, which is
  shared. Migration and expiry are untouched.
- R4: a barrier that completes early would let stale packets through under new ownership; the
  ordering test with a recording filter and the fragmenter and crypto-worker variants cover the
  queues; a stopped engine never completes.
- R5 part 1 opens a second entry to the inbound filter chain; filters that answer on the path
  (`inbound_from`) answer on the caller's `from`, which the documentation must state.
- Release C carries a per-packet cost and two breaking changes; a carrier site that forgets the
  tag loses attribution silently. The design note lists every site; tests assert each.
- D2 is a behaviour change: a peer that sends later fragments with nine extension headers is now
  denied. The documented rule always said eight.
- Each exception extends the freeze's exception list; release A needs none.

## Scope

- A: 4 files, two private helpers and two tests; about 100 lines.
- B: three workstreams; W1 is the largest (the netstack driver, roughly 600-900 lines with
  tests), W2 about 300, W3 about 400 including the core refactor and tests.
- C: cross-crate, sized in its design note.
- Documentation as listed per workstream; no new crate, no new dependency.

## Alternatives

- R1: return the control from `PendingFlow::accept` (changes its return type, and gives no
  control while held) instead of `PendingFlow::control`; or deliver handles at the decision
  (a `TcpConnection` before the handshake), which changes the meaning of `incoming_tcp`.
- R2: a barrier receipt (O12); one `NetStack` per listener lifetime on the consumer side (needs
  no nsplane change but multiplies stacks and needs the consumer to route by lifetime);
  `NetStackSink::send_labeled` as an inherent method instead of the packet tag, if the owner
  declines W4.
- R3: report the deciding scope on `GateDecision` (attribution only; state of other scopes could
  still admit the packet); one `FlowGate` per scope on the consumer side (duplicates state and
  evaluation); a `PeerId` filter on `find_flow` (a separate query, not bound to the decision).
- R4: the per-packet tag (W4) checked by the consumer's outbound filter, alone or with the
  barrier.
- R5 part 2: a wire-side-most `PacketFilter` returning `Verdict::Handled` that copies packets
  out: no engine change, but no queue, cancellation or lifetime contract and not available
  inbound.
- R6: per-peer aggregate counters (`data_tx` deltas) or the lossy `Event::Dropped`; neither
  attributes one packet.

## Annotations

Owner decisions, 2026-10-26:

1. Release A (0.19.3, W0: D1 and D2) is approved as a bug-fix release, including the D2
   behaviour change (a later fragment as a ninth extension header is denied `Malformed`).
2. Release B (0.20.0: W1 R1, W2 R3, W3 R4 barrier and R5 part 1) is approved as the eleventh
   freeze exception with the shapes above.
3. O1-O7 take the recommended answers:
   - O1: a top-level `NetStackConfig::admission`; `TransparentConfig::admission` is deprecated
     and transparent stacks honour either until its removal in a breaking release.
   - O2: a revoke before the hand-out sends nothing.
   - O3: R1 applies to `Decide` lifetimes only.
   - O4: a later fragment's scoped decision reports `rule: None`.
   - O5: `OutOfScope` denials count as enforced denials and emit decision events; `GateCounters`
     gets no new field.
   - O6: the barrier now; the per-packet tag comes with release C.
   - O7: `from: Path` is mandatory, the authenticated bookkeeping is not run, delivered bytes
     count in `data_rx`.
4. Release C (0.21.0) is designed first as one carrier, the packet tag, in a design note for
   review by the owner and both consumers; it is not implemented. O8-O12, and O13 which the
   note adds, are answered in that note's review. Design note:
   [notes/20261026-0834-packet-tag-carrier.md](notes/20261026-0834-packet-tag-carrier.md)
   (status: for owner and consumer review).
