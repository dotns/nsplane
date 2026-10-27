# 20261027-0305-netstack-ingress-labels Netstack ingress labels and label revocation (release C, W5)

- **status**: completed on `feat/netstack-ingress-labels` (not merged, not released)
- **priority**: P1
- **owner**: w5/netstack-ingress-labels
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
  within the noise plus 3 % (owner decision, 2026-10-27) on `netstack_send/streams_{1,4}`,
  `netstack_send_1cpu/*` and the new `netstack_udp_flow_send/flows_{1,4}`. If TCP misses the
  bar, the per-socket label checked after smoltcp's demultiplexing is measured instead.
- Full gate, rustdoc with warnings denied, `cargo semver-checks` (additive for nsplane-netstack:
  its structs are `#[non_exhaustive]` since 0.20.0).

## ActiveForm

Adding netstack ingress labels and label revocation

## Dependencies

- **blocked by**: `20261027-0305-packet-tag-carrier` (W4: the tag on `PacketBuf`,
  `push_tagged`, `discard_tagged`)
- **blocks**: (none)

## Notes

Implemented on `feat/netstack-ingress-labels` from `feat/packet-tag-carrier` at `dbee734` (W4,
on `v0.20.1`), 2026-10-27; not rebased onto `v0.20.2` (the release integration does that).

Design as built (the note's W5 section):

- Labels per lifetime: `FlowState` keeps the label of the first input. TCP: a bare SYN's
  label is recorded per tuple in the driver's label table (`stack/labels.rs`) before
  `device.inject`, on every stack (under `Decide` when the accepted SYN is injected);
  `track_inbound` binds the entry to the listener socket that took the SYN, a SYN no socket
  took is forgotten after the poll, adoption gives the label to the connection's
  `FlowState`, and the entry goes with the socket's release. Segments are checked against it
  before `inject` while some entry carries a label or the segment does. UDP: the flow's
  `FlowState` label, compared on `dispatch_flow`'s lookup. Held lifetimes: `FlowState::held`
  with the label; further SYNs and datagrams of a held lifetime with another label count in
  `label_mismatch`.
- Fragments: `Reassembler::push_tagged`; `Mixed` is dropped and counted in `label_mismatch`,
  `Same(label)` gives the datagram its label.
- `revoke_label`: queued with the flow revocations and taken at the start of the next driver
  turn, oldest first. It records the tombstone, fences the label's input in the ingress queue
  (end position = packets the driver holds or the queue holds at that turn; at most 1024
  labels at once), `discard_tagged`, retries the egress fences an earlier call of the label
  could not record, then retires every registered lifetime of the label through the same
  removal as `FlowControl::revoke` (handles revoked in the driver, no requeue) and the
  ordinary stacks' handshakes, which have no `FlowState` yet. No tuple barrier is added: the
  label discard is exact.
- Per-segment cost: the first build looked the tuple up per segment (`tcp_tuple`, SipHash
  over two `SocketAddr`s): +5.2 % labeled on `netstack_send/streams_1`. A one-entry cache cut
  that to +2.9 % but `streams_4` (four interleaved connections) stayed at +8 to +31 %. The
  shipped build reads the IPv4 tuple as two words and probes a 64-slot direct-mapped cache of
  recent tuples, invalidated by a generation counter whenever the table changes; the table
  itself keeps the standard hasher (peers choose the tuples). Isolated cost: 4 ns per cached
  check, 15 ns per table lookup (was 9 ns for the first cache).

Deviations and choices the note leaves open, with reasons:

- Lifetimes the application opens (`connect_tcp`, `bind_udp`, `connect_udp`) carry no label
  and their input is not checked: the note's rules name the inbound SYN and `dispatch_flow`,
  and bound and connected sockets stay unchanged (no `recv_labeled`).
- A labeled ICMP error that quotes a connection of another label is counted in
  `label_mismatch` (not `icmp_ignored`), so each discard counts in one field.
- A connection or flow revoked while it waits in `incoming_tcp` / `incoming_udp` is now
  skipped under `Admission::Immediate` too (`HandOut` writes `Revoked` first, so the skipped
  handle's drop cannot fix the delivery otherwise). Without it, `revoke_label` could not keep
  an accepted connection of the label from being handed out on an `Immediate` stack. The
  first version of this check raced `first_input::a_revoke_racing_the_hand_out_*` (1 failure
  in 7 runs: `AcceptQueueGone` instead of `Revoked`); fixed before the commit.
- The ingress fence ends where the queue stood when the driver took the call, not at the
  call: input of the label sent between the call and that turn is dropped too, counted in
  `retired_drops` rather than `label_revoked`. A repeated revoke of a tombstoned label does
  not move its tombstone to the end of the eviction order.
- Files outside the listed write scope: `stack/labels.rs` (new), `stack/commands.rs`
  (`FlowState::new` takes the label); `pmtu.rs` is untouched (the ICMP check sits in
  `ingress.rs`); test helpers `tests/pmtu.rs` (`too_big` made
  `pub(super)`) and `tests/flow_control.rs` (`Fences::insert` returns the fence).
- Bench: the labeled variant also runs for `netstack_udp_send` (bound sockets, so only the
  tag check) and `netstack_udp_flow_send` has a `_1cpu` group, like the other groups.
- The e2e test was written after the code (it does not build against the base: the API is
  new); the unit tests below were all run failing first.

Rule / test matrix (`src/stack/tests/labels.rs`, `revoke_label.rs`, each over an ordinary
stack and a transparent one with `Immediate` and `Decide` unless noted). "Fails before": run
against the API stubs (labels `None`, `revoke_label` reporting `Unknown`, no checks) before
the implementation; 17 of 19 failed.

| Rule | Test | Fails before |
| --- | --- | --- |
| TCP: the SYN's label is the connection's; data with it passes | `labels::a_connection_takes_the_label_of_its_syn` | yes |
| handshake ACK and retransmitted SYN with another label (and `None`) dropped and counted; same label passes | `labels::a_handshake_ack_and_a_retransmitted_syn_with_another_label_are_dropped` | yes |
| established segments with another label and with `None` dropped and counted; an unlabeled connection takes no labeled segment | `labels::established_segments_with_another_label_or_none_are_dropped` | yes |
| unlabeled ICMP error applies to a labeled connection; another label ignored and counted | `labels::icmp_errors_unlabeled_apply_and_with_another_label_are_ignored` | yes |
| UDP: first datagram's label, `None` distinct, mismatches counted | `labels::a_flow_takes_the_label_of_its_first_datagram` | yes |
| `Decide`: `PendingFlow::ingress_label`; held input with another label counted, with the same label absorbed / `udp_queue_full` | `labels::held_lifetimes_keep_the_label_of_their_first_input` (transparent `Decide`) | yes |
| mixed-label fragments (the node's case: the middle fragment with the old and the new label; a tag and none) dropped and counted; same label kept | `labels::fragments_with_mixed_labels_are_dropped_and_counted` | yes |
| an unlabeled stack: labels `None`, no label counter moves | `labels::an_unlabeled_stack_counts_no_label` | no (today's behaviour) |
| `revoke_label`, UDP: handed out (queued datagram discarded), accept queue skipped, other labels and `None` untouched | `revoke_label::revoking_a_label_retires_its_flows_at_every_stage` | yes |
| `revoke_label`, held TCP and UDP (`Pending`): revoked, `NotDelivered(Revoked)`, a later accept does nothing | `revoke_label::revoking_a_label_retires_held_lifetimes` (transparent `Decide`) | yes |
| `revoke_label`, TCP: handed out (reads `ConnectionAborted`), established in the accept queue, SYN-RECEIVED (SYN-ACK never leaves), other label untouched | `revoke_label::revoking_a_label_retires_its_connections_at_every_stage` | yes |
| `revoke_label`, TCP waiting for the accept queue (`accept_backpressure`) | `revoke_label::revoking_a_label_retires_connections_waiting_for_the_accept_queue` | yes |
| the ingress queue (the node's case: queued complete input; new resource; identical reinstall) | `revoke_label::revoking_a_label_drops_its_input_still_queued_in_the_stack` | yes |
| reassembly entries (the node's case: partial datagram, replacement, rest with the new label) | `revoke_label::revoking_a_label_discards_its_partial_datagrams` | yes |
| `Failed` with a full table (ingress positions, bound 1 in the test), everything found still retired, a second call `Retired` | `revoke_label::a_full_table_fails_the_revoke_and_a_later_call_retires` | yes |
| a label used after its revoke: dropped, `label_revoked`, no new flow, no SYN-ACK | `revoke_label::a_label_used_after_its_revoke_is_dropped_and_opens_nothing` | yes |
| the same tuple after `Retired`: fresh lifetime with the new label, UDP and TCP | `revoke_label::the_same_tuple_after_retired_opens_a_fresh_lifetime` | yes |
| tombstones bounded by `max_revoked_labels` | `revoke_label::tombstones_are_bounded_by_max_revoked_labels` (ordinary) | yes |
| `Unknown` on a stopped stack | `revoke_label::revoking_a_label_on_a_stopped_stack_is_unknown` (ordinary) | no (the stub reported `Unknown`) |
| two engines: switch the label, revoke the old one, fresh flow and connection echo 1 MiB | `nsplane-e2e` `tests/netstack_ingress_labels.rs` | not run before |

Benchmarks (slot 0, `scripts/bench/slot.sh`, each invocation started at a 1-minute load below 3;
the host's Campaign 2 load rose during runs; criterion means; tables in `docs/performance.md`,
"Netstack ingress labels"):

- Labeled against unlabeled, same build, three rounds (load 1.6 at the start, up to 7): TCP
  `netstack_send/streams_1` +0.7 / +0.1 / +2.5 %, `streams_4` +2.9 % (two disturbed unlabeled
  runs), `netstack_send_1cpu/streams_1` +0.7 / +0.7 % (one disturbed run), `streams_4` +0.8 /
  -1.0 / +2.5 %; UDP `netstack_udp_flow_send/flows_1` +0.2 / -1.9 % (one disturbed),
  `flows_4` +1.5 % (two disturbed), `_1cpu` -0.5 .. +0.9 %. Within the noise plus 3 % for
  every clean pair; the per-socket alternative was not needed. Earlier TCP checks, for the
  record: +5.2 % (lookup per segment), +2.9 % and `streams_4` +8 to +31 % (one-entry cache).

- Untagged against `dbee734`, three invocations of rotated rounds (4, 3, 3): medians
  `netstack_send/streams_1` +0.8 %, `streams_4` +1.2 %, `netstack_send_1cpu/streams_1` +2.1 %
  (8 of 10 rounds +1.6 to +3.8 %; the base alone spreads 2.4 % across invocations: at the edge
  of the noise), `streams_4` +1.6 %, `netstack_udp_send/flows_1` -1.1 %, `_1cpu` +1.4 % and
  +0.8 %. `netstack_udp_send/flows_4` is bimodal on this host for both binaries (480 us or
  550-940 us, the base once 51 % slower than the build); the build was high in more rounds,
  median +16 %, not attributed: a diagnostic build without the `FlowState` label field ran at
  937 us in the round where the build ran at 487 us and the base at 479 us. Open for the
  release integration's quiet re-measure, with W4's `flows_4`. A variant with the revoke and
  the TCP check out of the driver's hot functions, and one with the label state boxed, were
  not faster and were not kept.
- `data_path`, `local_graph`, `udp_offload`: bench binaries byte-identical to the base's (no
  `nsplane-netstack` in them); their interleaved runs give the slot noise (`data_path` -1.5 ..
  +1.0 %, `udp_offload` -6.2 .. -0.2 %, `local_graph` mostly within ±3 %).

Gates: `flock /tmp/nsplane-heavy.lock just check` passes (2456 tests; at most 6 cargo jobs;
an earlier run hit `nsplane-dns::passthrough::policy_keeps_messages_local` with `AddrInUse`
from the shared host's ports, untouched by W5, passing 5 of 5 alone and in the reruns);
`RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean;
`cargo semver-checks --workspace --baseline-rev v0.20.1`: no semver update required in any
crate (W5's items are additive).

