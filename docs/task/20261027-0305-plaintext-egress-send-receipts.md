# 20261027-0305-plaintext-egress-send-receipts Plaintext egress and per-packet send receipts (release C, W6)

- **status**: pending
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-10-27 03:05
- **relatedPlan**: 20261026-0822-node-gateway-requests (W6, release C, requests R5 part 2 and R6)

## Description

Workstream W6 of release C (0.21.0), approved by the owner on 2026-10-27 as the twelfth freeze
exception. The specification is the approved design note
`docs/plan/notes/20261026-0834-packet-tag-carrier.md` (sections "W6, plaintext egress",
"W6, send receipts", O8, O9, O10, O13, the breaking-change list).

Scope, plaintext egress (R5 part 2, O8):

- `Core::set_plaintext_egress(peer, bool)` and the engine equivalent: runtime state that follows
  the `PeerId` (kept on an in-place update, absent after remove and re-add); routed local packets
  of such a peer leave after the outbound filters as `Output::Plaintext { to, packet }` (marker
  cleared) instead of being sealed; the engine hands them to a bounded `PlaintextEgress`
  receiver from the builder; full: dropped as `PLAINTEXT_EGRESS_FULL`; receiver gone:
  `PLAINTEXT_EGRESS_CLOSED`.
- The documented add-closed, read back, mark, then open order for consumers that learn the
  `PeerId` by readback; packets queued in the tunnel before the flag stay sealed; such a peer
  starts no handshake for data and still answers and starts handshakes for inbound sealed
  traffic.
- `Output` becomes `#[non_exhaustive]` together with `Output::Plaintext` (breaking).

Scope, send receipts (R6, O9, O10, O13):

- `EngineBuilder::tracked_sender(capacity) -> (Self, TrackedSender, SendResults)`;
  `TrackedSender::send` / `try_send` take a tagged packet (token = tag), mark it, and enter the
  normal local path; outstanding results bounded by `capacity` (`send` waits, `try_send`
  refuses), so results are never dropped.
- Exactly one `SendResult { tag, outcome }` per accepted packet: `Sent { peer, bytes }` (routed
  `PeerId`; plaintext length handed to sealing, as `data_tx` counts) once the transport call
  carrying its datagram succeeded; `NotSent { reason }` at every drop site: no route, filter
  drop, handled, no session (O9: at once, inline and with crypto workers, handshake started as
  for an untracked packet, no `nsplane-noise` change), oversize with a fragmenter (O10; without
  one the packet is sealed and its result follows the transport call), `NO_PATH`,
  `ENCAPSULATE_ERROR`, transmit full, transport closed, removed or send error, plaintext egress
  (`PLAINTEXT_EGRESS`), engine stopped.
- A tracked datagram ends its transmit batch (`staged`, `Handoff`, the transmit task's calls),
  so the per-call counts attribute it exactly.
- `local_barrier` counts packets `TrackedSender` accepts, at acceptance.
- Documentation: `docs/reference/nsplane.md` and `nsplane-core.md` (plaintext egress, receipts,
  reasons, the add-closed order); `docs/architecture.md` is the integrator's.

Write scope: `crates/nsplane-core/src/` (`types.rs` for `Output`, `core/send.rs`,
`core/receive.rs` where hand-outs clear the marker, `peer.rs` for the flag, `reasons.rs`) and
their tests; `crates/nsplane/src/` (`builder.rs`, `handle.rs`, `lib.rs`,
`engine/{input,output,run,transport,command,tasks}.rs`, the transmit path in `engine/queue.rs`)
and their tests; a new `nsplane-e2e` test file; the reference pages; `CHANGELOG.md` entries
under Unreleased.

Acceptance criteria (tests first):

- Exactly one result per tracked packet under every drop site above and through every copy
  site; a tracked packet above the MTU without a fragmenter sealed and reported by its transport
  call; `Sent { bytes }` equal to the plaintext length; a clone of a tracked packet untracked;
  the marker cleared on `Output::Deliver`, `Output::Plaintext` and recycled buffers;
  `local_barrier` waiting for packets `TrackedSender` accepted before the call; a transport
  failure in the middle of a batch; stop with results outstanding.
- Plaintext egress: full, closed, peer removed and re-added, the flag kept across an update and
  absent after remove and re-add, no packet of a removed peer under a new id, the add-closed,
  mark, open order, tunnel-queued packets sealed after the flag is set.
- Benchmarks: untracked traffic and peers without the flag within the noise against the base on
  `nsplane-core` `data_path` (`core_round_trip/64`, `core_round_trip_batch32`), `nsplane`
  `local_graph` and `udp_offload`; receipts cost only for tracked packets.
- Full gate, rustdoc with warnings denied, `cargo semver-checks` listing exactly the intended
  break (`Output`).

## ActiveForm

Adding plaintext egress and per-packet send receipts

## Dependencies

- **blocked by**: `20261027-0305-packet-tag-carrier` (W4: the tag, the receipt marker and the
  carrier sites)
- **blocks**: (none)

## Notes

(none)
