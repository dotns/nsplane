# 20261027-0305-netstack-ingress-labels Netstack ingress labels and label revocation (release C, W5)

- **status**: pending
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-10-27 03:05
- **relatedPlan**: 20261026-0822-node-gateway-requests (W5, release C, request R2)

## Description

Workstream W5 of release C (0.21.0), approved by the owner on 2026-10-27 as the twelfth freeze
exception. The specification is the approved design note
`docs/plan/notes/20261026-0834-packet-tag-carrier.md` (sections "nsplane-netstack (R2)" of the
carrier sites, the labeled-path bar of the budget, "W5, netstack ingress labels", O12, O14).
The tag of a packet sent into `NetStackSink` is its ingress label: input the consumer admitted
under one lifetime of its own is never delivered as, or into, a handle of another.

Scope:

- A lifetime takes the label of its first input; `None` is a label of its own; mismatched input
  (TCP segment, retransmitted SYN, handshake ACK, datagram for a labeled flow, a fragment set
  with mixed labels) is dropped and counted (`label_mismatch`); an unlabeled stack keeps
  today's path.
- Labels on every stack, with or without `Admission`: a bare SYN's label recorded per tuple
  before `device.inject`, moved by `track_inbound` to the listener socket's entry and by
  adoption to the lifetime's `FlowState`; the UDP label stored with the flow entry and compared
  on `dispatch_flow`'s lookup; under `Admission::Decide` the held input's first-input state.
- ICMP errors: unlabeled ones accepted for a labeled connection, differently labeled ones
  ignored and counted.
- `TcpConnection::ingress_label`, `UdpFlow::ingress_label`, `PendingFlow::ingress_label`.
- `NetStackHandle::revoke_label(label) -> RetirementReceipt`: retires every lifetime of the
  label at every stage, handed-out handles included; drops its reassembly entries
  (`Reassembler::discard_tagged`) and its input still in the ingress queue (a bounded table of
  ingress positions); `Retired`, `Failed` (a full table; everything found is still retired; the
  call is idempotent and may be repeated), `Unknown` (stopped).
- Tombstones (O14): `NetStackConfig::max_revoked_labels`, default 65,536; a label used after its
  revoke is dropped and counted (`label_revoked`) and never opens a lifetime while its
  tombstone is held.
- The same tuple after `Retired` opens a fresh lifetime with another label (UDP and TCP).
- No `recv_labeled` on bound or connected sockets.
- Documentation: `docs/reference/nsplane-netstack.md` (ingress labels, `revoke_label`, the
  rules above, limits and bounds).

Write scope: `crates/nsplane-netstack/src/` (`stack/{ingress,admission,accept,retire,fragments,`
`connections,handle,netstack}.rs`, `stack.rs`, `flow.rs`, `pending.rs`, `tcp.rs`, `udp.rs`,
`config.rs`, `stats.rs`, `pmtu.rs` where ICMP is attributed) and its tests;
`crates/nsplane-netstack/benches/send_stream.rs` (labeled runs and the new
`netstack_udp_flow_send` group); a new `nsplane-e2e` test file; the reference page;
`CHANGELOG.md` entries under Unreleased.

Acceptance criteria (tests first), on an ordinary stack and on a transparent one with
`Immediate` and `Decide`:

- The node's two reproduced cases as netstack tests with labels: a partial datagram completed
  after a listener replacement (the middle fragment carrying the old and the new label); queued
  complete input, new resource and identical reinstall.
- Mixed-label fragments; a labeled SYN, its retransmission with another label and the handshake
  ACK; established segments with another label and with `None`; unlabeled and differently
  labeled ICMP errors for a labeled connection.
- Each stage of `revoke_label`, handles already handed out included; `Failed` with a full
  table, then a second call reporting `Retired`; a label used after its revoke dropped and
  counted, not opening a lifetime; the same tuple after `Retired` opening a fresh lifetime with
  a new label, for UDP and for TCP.
- Benchmarks: unlabeled `send_stream` (`netstack_send/*`, `netstack_udp_send/*` with `flows_4`)
  within the noise against the base; labeled against unlabeled on the same build, interleaved,
  within the noise plus the owner's allowance (proposed 3 %) on `netstack_send/streams_{1,4}`,
  `netstack_send_1cpu/*` and the new `netstack_udp_flow_send/flows_{1,4}`. If TCP misses the
  bar, measure the per-socket label alternative of the note.
- Full gate, rustdoc with warnings denied, `cargo semver-checks` (additive for nsplane-netstack:
  its structs are `#[non_exhaustive]` since 0.20.0).

## ActiveForm

Adding netstack ingress labels and label revocation

## Dependencies

- **blocked by**: `20261027-0305-packet-tag-carrier` (W4: the tag on `PacketBuf`,
  `push_tagged`, `discard_tagged`)
- **blocks**: (none)

## Notes

(none)
