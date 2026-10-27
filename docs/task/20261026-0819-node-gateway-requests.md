# 20261026-0819-node-gateway-requests Requests from the node and the gateway at 0.19.2, and two defects

- **status**: in progress (D1, D2, R1, R3, R4 barrier and R5 part 1 released in 0.20.0; R2,
  R4 tag variant, R5 part 2 and R6 are release C, in design)
- **plan**: 20261026-0822-node-gateway-requests
- **priority**: P2
- **owner**: (unassigned)
- **createdAt**: 2026-10-26 08:19

## Description

Two consumers asked for six interface additions, and two defects were reported with a
reproduction each. Every item was checked against `main` at `52eb983` (v0.19.2). The two
commits after v0.19.1 (`afae107`) change only the `tokio` requirement of nsplane-tun and
nsplane-ether and the level of routine handshake timer logs in nsplane-noise; none of the code
cited here differs between the two. The requests
state the guarantee they need and leave the API shape to nsplane; the consumers adopt it from
an immutable tag. Nothing here is implemented yet: the plan proposes the design and the release
grouping for the owner's approval.

Consumers:

- the node, as the Subnet provider (it owns NAT and translation state of a provider flow from
  the first translated input, before its private user-space stack accepts the flow) and as the
  host of ordinary application-service listeners on one shared stack (a listener can be
  replaced, or withdrawn and reinstalled with the identical resource);
- the gateway, for alias retirement and reuse, a kernel reference data path that must go
  through the engine's validated ingress and outbound filters, and echo replies it sends on a
  client's behalf and wants to account for.

| Id | Prio | Request | Assessment at 0.19.2 |
|---|---|---|---|
| R1 | P1 | netstack: flow control from the first input. At a new tuple's first input (bare SYN, first UDP datagram) the consumer gets a `FlowControl` for that one lifetime; revoking it at any stage (held, accepted, SYN-received, established but queued for `incoming_tcp` / `incoming_udp`) retires it and no handle for it is delivered afterwards; the delivered handle carries the same control; every lifetime ends in one definite per-item result (delivered, or not delivered with a reason); `RetirementOutcome` keeps its meaning; also for an ordinary (non-transparent) stack | Partly met. `Admission::Decide` holds the first input as a `PendingFlow` (transparent mode only). After `accept` nothing can revoke the lifetime until a handle exists: the SYN goes into smoltcp (`Driver::take_decisions`), sits on a pooled listener socket in `SynReceived`, and gets its `FlowState` only in `Driver::adopt`; an accepted UDP datagram gets its `FlowState` in `Driver::dispatch_flow` and is queued on `incoming_udp` at once. No link from a `PendingFlow` to the delivered handle (`PendingFlow::id` and `Key` are private). A decision after the timeout or stop does nothing silently; timeouts, never-completed handshakes and full or gone accept queues end without a per-item notice (`rejected_timeout`, `tcp_not_accepted`, `udp_not_accepted` counters and lossy `FlowEvent`s only) |
| R2 | P2 | netstack: ingress lifetime attribution through delivery. Input the consumer admitted under one lifetime of its own (a listener incarnation) is never delivered as, or into, a handle attributed to another lifetime, across every stage between `NetStackSink` and the handle. Either a caller label carried by each packet and readable on every handle and datagram, with a revoke of all not-yet-delivered input of a label (receipt), or a barrier receipt with pre/post-barrier attribution | Missing. `NetStackSink::send` ignores the `PeerId` and takes no label; the raw ingress queue, the `ingest_batch` batch, `Driver::reassemble`, listener sockets in `SynReceived`, `Driver::waiting`, the accept channels and the per-flow datagram queues carry nothing. `FlowControl::revoke` applies only after delivery; `discard_fragments` needs the datagram key. The node reproduced old input reaching a replacement listener: a partial datagram completed into the new listener's flow, and queued complete input delivered to it |
| R3 | P1 | nsplane-acl: scope-qualified `FlowGate` decisions. A decision taken on the existing snapshot and state that is valid only for a caller-selected scope or scope set: in-selection the normal decision, otherwise a distinct denial that creates, refreshes or migrates no state outside the selection; an empty selection is refused; the output names the deciding `ScopeId`, the `RuleId` (also for `ValidState`) and the policy generation | Missing at the API. `FlowGate::evaluate_once` already resolves exactly one scope per packet (exact binding, else peer-keyed, else `Ambiguous`) and keys flow and fragment state by that scope's slot, but `GateDecision` names no scope, `ValidState` has `rule: None`, and `find_flow` has no `PeerId` and is a separate call. `RuleId`s are unique only within a scope |
| R4 | P2 | engine: protection of local input before routing. A consumer that changes the ownership of an address can make sure that no local packet admitted before the change is routed and passed to `PacketFilter::outbound` under the new ownership: a per-packet tag visible to the outbound filter, or a barrier receipt that completes once every packet the engine took from its `PacketSource` before the call has been routed and filtered or dropped. A stopped engine never reports the barrier completed | Missing. `read_source` moves packets into the engine's bounded local queue untagged (`PacketBuf` has no metadata); `Core::prepare_send` routes and runs the outbound filters when the owner task takes them; nothing reports when the packets taken before a point have passed |
| R5 | P2 | engine: validated plaintext ingress and a bounded plaintext reverse handoff, for a reference data path. (1) An entry that runs an IPv4 / IPv6 plaintext packet attributed to a `PeerId` through exactly the post-decryption steps (allowed-IP source check, inbound destination check, `PacketFilter::inbound_from` in install order, delivery), refusing unknown peers, bounded. (2) Opt-in: local packets routed to selected peers are handed to the consumer as plaintext after the outbound filters, instead of being sealed, through a bounded queue with defined full, cancelled and peer-removal behaviour | Missing. The ordered checks run only for decrypted data (`Core::opened`, `Core::deliver_opened`); `inject_inbound` bypasses the source check and the filters by contract. Outbound, `Core::prepare_send` is followed by sealing; `inject_outbound` / `inject_outbound_on` bypass the filters. A wire-side-most filter returning `Verdict::Handled` can copy packets out, but that is not an engine contract (no queue, cancellation or peer-lifetime semantics) |
| R6 | P2 | engine: per-packet send receipt on the normal outbound path. A local packet submitted with an opaque token through routing, outbound filters, sealing and transport gets exactly one result: `Sent { peer, bytes }` once the sealed datagram was handed to the transport, or `NotSent { reason }`. Not lossy for tokened packets (a full result channel refuses new tokened submissions); untokened traffic unaffected | Missing. `PacketSource::recv` returns only a packet; `Event::Dropped` names no packet and is broadcast and lossy; `PeerStats::data_tx` is aggregate. A packet without a session waits in the tunnel's queue (`nsplane-noise` `Tunn::queue_packet`, a copy without identity, silently dropped when 256 are queued or when the timers clear the queue) and is sent later by `Core::flush_queue` |
| D1 | P1 | nsplane-packet `vnet`: an IPv4 GSO super-packet with IHL = 10 is segmented as IPv6 | Defect, confirmed with a reproduction. `segment` passes only `ip_len` on; `fix_segment` and `pseudo_sum` take the IPv6 branch for `ip_len == IPV6_HDR` (40), which an IPv4 header with 20 option bytes also has. Every segment keeps the super-packet's total length, gets its identification overwritten with the would-be IPv6 payload length, keeps a stale header checksum, and has invalid TCP / UDP checksums. Reached by `nsplane-tun` offload reads (`Tun::segment`) and `nsplane-ether` packet-socket reads. `nsplane-tun` `offload.rs` (`Coalescer::finish`, `checksum_valid`, `pseudo_sum`) has the same test, unreachable today because `classify` merges only `ihl == IPV4_HDR`. Rare input; the receiver drops the segments; no crash or out-of-bounds access |
| D2 | P2 | nsplane-acl `walk_v6`: a later fragment accepted as a ninth extension header | Defect, confirmed with a reproduction. The loop runs `0..=MAX_EXTENSION_HEADERS` (nine iterations) and returns as soon as a Fragment header with a nonzero offset is consumed, so eight Destination Options headers plus a later Fragment header of an admitted datagram is `Enforce { allow: true, reason: ValidState }`, where the gate's IPv6 rules and the `walk_v6` comment say at most eight headers (malformed). Not an authorization bypass: such a fragment passes only behind an admitted first fragment and opens no flow |

### Reproductions

Both were run in an export of `afae107` (v0.19.1) and fail there as described; the code they
exercise is identical at `52eb983` (v0.19.2). The plan's test section
carries them as the regression tests.

- D1: in `crates/nsplane-packet/src/vnet.rs` `mod tests`, IPv4 TCP and UDP super-packets with
  19 NOP and one EOL option byte (IHL = 10), 2500 payload bytes, `gso_size` 1000,
  `F_NEEDS_CSUM`, built and segmented with the module's helpers (`spec`, `super_packet`, `run`,
  `build`); every segment must equal the packet a sender would build. TCP segment 0 has total
  length 2560 instead of 1060 and identification `0x03fc` instead of `0xfff0`.
- D2: in `crates/nsplane-acl/src/gate/tests/ipv6_packets.rs`, an Enforce gate with an open IPv6
  scope admits a first fragment; then eight Destination Options headers plus a Fragment header
  of the same identification with offset 2 and M = 1 must be `Malformed`. Controls: with a first
  fragment as the ninth header, and with ten headers, it is `Malformed` today; without an
  admitted first fragment, `OrphanFragment`.

### Constraints

- The feature freeze (ADR `2026-10-08-feature-freeze-0-11`) is in force with owner exceptions:
  R1-R6 each need an exception; D1 and D2 are bug fixes under the freeze's rules (existing API,
  regression test, full gate, slot A/B when the data path is touched).
- ADR `2026-10-06-business-agnostic-scope`: the listener, the alias and the reference path are
  consumer concepts. nsplane offers generic mechanisms (flow lifetimes, opaque labels, scope
  selections, barriers, plaintext entries and receipts) and names no consumer in product
  documents.

## Dependencies

- **blocked by**: (none; the owner approved releases A and B and O1-O7 on 2026-10-26, see the
  plan's annotations). Release C waits for the review of its design note.
- **blocks**: (none)

## Notes

- Related, partly overlapping: task `20261017-1700-flow-lifecycle-request`, whose deferred R3
  (a context carried through the engine and the transports, gates at the real delivery points)
  covers ground that R2, R4, R5 and R6 share. The plan's release B proposes one generic carrier
  for it.
