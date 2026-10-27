# 20261027-0305-plaintext-egress-send-receipts Plaintext egress and per-packet send receipts (release C, W6)

- **status**: completed (integrated into 0.21.0 on `release/0.21.0`, not released)
- **priority**: P1
- **owner**: w6/plaintext-egress-send-receipts
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

Implemented on `feat/plaintext-egress-send-receipts` from W5's `feat/netstack-ingress-labels`
(`25debab`, W5 on W4 on `v0.20.1`), 2026-10-27. Not rebased onto `v0.20.2` (the release
integration's).

Design as built:

- Core: `Output` is `#[non_exhaustive]` with `Output::Plaintext { to, packet }` and
  `Output::Tracked { tag, peer, outcome }` (`TrackedOutcome::{Sealed { bytes }, NotSent {
  reason }}`): the core reports each tracked packet once, `Sealed` right before the
  `Output::Transmit` of its datagram (so the engine learns the peer and the plaintext length
  without a wider queue item), `NotSent` at its drop sites. `Core::set_plaintext_egress`
  keeps a `bool` per peer and one in the core (some peer marked), so unmarked traffic pays
  one load of the core's `bool`. Without a session a tracked packet is checked with
  `Tunn::has_session` and an initiation formatted with `format_handshake_initiation(false)`
  into a pooled buffer; no `nsplane-noise` change.
- Engine: a receipt table (`tracked.rs`) shared by the `TrackedSender`s, `SendResults`, the
  owner and the transmit tasks: outstanding tags with their peer and length once sealed,
  results, a semaphore of `capacity` permits returned when a result is received, and the
  accepted count for the barrier. Results are found by the datagram's tag at the transport
  call or drop site. A guard in the owner (and in a builder that is never built) reports every
  outstanding packet `ENGINE_STOPPED` when the engine stops, is dropped or aborted.
- The tracked queue is a second local queue polled next to the source's (alternating), under
  the same room; the barrier position is a pair (source reads, tracked acceptances), the
  owner counts both.
- A tracked datagram ends the owner's inline call (sent at once), the staged message to the
  transmit task (handed over at once, also from the backlog) and the transmit task's call
  (its batch stops after it). On `BrokenPipe` the transmit task closes and drains its queue
  and reports the tracked datagrams it did not get to `TRANSPORT_CLOSED`.

Deviations from the description, with reasons:

- `TrackedSender` refuses a tag that is outstanding (`TrackedRefused::Duplicate`): results are
  matched by tag, so an outstanding tag must be unique for `Sent { peer, bytes }` to be
  exact. A tag is free again once its result is out.
- Two reasons beyond the scope list, for drop sites without an existing string:
  `reasons::FILTER_HANDLED` (`Verdict::Handled`) and `reasons::ENGINE_STOPPED`; plus
  `reasons::PLAINTEXT_EGRESS_FULL` / `_CLOSED` with their engine aliases
  `DROP_PLAINTEXT_EGRESS_FULL` / `_CLOSED` (`events.rs`).
- The core undoes what an outbound filter does to a tracked packet's tag or marker (the tag
  is the token), and clears the marker of a marked packet without a tag (not tracked).
- A tracked packet without a session also counts as a `NO_SESSION` drop (`Event::Dropped`),
  since unlike an untracked one it is dropped, not queued. `FILTER_HANDLED`,
  `PLAINTEXT_EGRESS` and `ENGINE_STOPPED` are results only.
- `inject_outbound` is routed and follows the plaintext-egress mark; `inject_outbound_on`
  bypasses routing and is sealed. (The engine clears the marker on both, so neither is
  tracked through the engine.)
- A crypto worker that panics loses its jobs; their tracked packets are reported
  `ENGINE_STOPPED` when the engine stops.
- Files outside the listed scope: new `crates/nsplane/src/tracked.rs`;
  `crates/nsplane/src/{engine.rs,events.rs,fragment.rs}` (owner fields, the Engine rustdoc,
  the drop aliases, the fragmenter never splitting a tracked packet);
  `crates/nsplane-core/src/{core.rs,lib.rs,job.rs,core/config.rs}` (`complete_job`, the
  sealed length on `CryptoJob`, the setter); test support `crates/nsplane/tests/support/`;
  two W4 tests adapted to O9/O10 (`nsplane-core` `tests/tags.rs` sends an untracked tagged
  packet into the no-session queue; `fragment::tests::every_fragment_carries_the_tag_and_none_the_marker`
  splits an untracked tagged packet); the core benches' `Output` matches
  (`data_path`, `handshake`) and the new bench cases (`data_path`, `worker_pool`).
  `core/receive.rs` needed no change (the engine already clears the marker on delivery).
- `docs/architecture.md` is left to the integrator, as the task says.

Rule / test matrix ("fails before": run against the API stubs, logs kept outside the
repository; core 18 of 19 and engine 23 of 28 failed):

| Rule | Test | Fails before |
| --- | --- | --- |
| marked peer: plaintext after the filters, tag kept, marker cleared, not sealed; a filter drop still drops (inline, jobs) | core `plaintext_egress::a_marked_peer_gets_its_routed_local_packets_after_the_filters_as_plaintext`; engine `plaintext_egress::a_marked_peer_gets_its_packets_after_the_filters_as_plaintext` (0, 2 workers) | yes / yes |
| routed before the mark sealed, after it plaintext, unmarked sealed | core `the_mark_applies_to_packets_routed_after_it_and_reverts_with_the_call` | yes |
| tunnel-queued packets stay sealed | core `packets_queued_in_the_tunnel_before_the_mark_stay_sealed`; engine `packets_routed_before_the_mark_stay_sealed` | yes / no (today's behaviour) |
| mark kept across an update, absent after remove and re-add, no packet of a removed peer under the new id | core and engine `the_mark_is_kept_across_an_update_and_absent_after_remove_and_re_add` | yes / yes |
| add closed, read back, mark, open | core and engine `the_add_closed_read_back_mark_open_order_seals_nothing` | yes / yes |
| no handshake for data | core `a_marked_peer_starts_no_handshake_for_data` (inline, jobs) | yes |
| answers handshakes, inbound sealed traffic delivered | core `a_marked_peer_answers_handshakes_and_delivers_inbound_sealed_traffic`; engine `a_marked_peer_answers_handshakes_and_its_inbound_traffic_is_delivered` | yes / yes |
| starts handshakes for inbound sealed traffic (initiator's rekey on receive) | core `a_marked_peer_starts_handshakes_for_inbound_sealed_traffic` | yes |
| egress full / closed / none built | engine `a_full_queue_drops_and_counts`, `a_closed_or_missing_receiver_drops_and_counts` | yes / yes |
| tracked to a plaintext peer: `NotSent PLAINTEXT_EGRESS`, handed over untracked | core and engine `a_tracked_packet_to_a_plaintext_egress_peer_is_handed_out_untracked` | yes / yes |
| `Sealed { bytes }` = plaintext length = `data_tx`, before its datagram (inline, jobs) | core `a_sealed_tracked_packet_reports_its_peer_and_plaintext_length_before_its_datagram` | yes |
| `Sent { peer, bytes }` after the transport call (task, inline, 2 workers) | engine `a_tracked_packet_is_sent_once_its_transport_call_succeeded` | yes |
| one result through the copy site (no headroom) | core `a_packet_without_headroom_yields_one_result_through_the_copy` | yes |
| only marked and tagged packets are tracked; a clone is untracked | core `only_marked_and_tagged_packets_are_tracked`; engine `a_clone_of_a_tracked_packet_is_untracked` | no / no (W4's rules) |
| filter cannot change the token or marker | core `a_filter_cannot_change_the_tag_or_the_marker_of_a_tracked_packet` | yes |
| no route, filter drop, handled | core and engine `no_route_filter_drops_and_handled_packets_are_not_sent` (0, 2 workers) | yes / yes |
| no session at once, inline and jobs, handshake as untracked, never sent later; retry works | core `without_a_session_a_tracked_packet_is_not_sent_and_the_handshake_starts`, `without_a_session_a_handshake_in_progress_is_not_restarted`; engine same name (0, 2 workers) | yes / yes |
| oversize with a fragmenter (split and DF) | engine `above_the_mtu_with_a_fragmenter_a_tracked_packet_is_not_sent`; unit `fragment::tests::a_tracked_packet_is_never_split` | yes / written with the change |
| above the MTU without a fragmenter: sealed, result from the call | engine `above_the_mtu_without_a_fragmenter_a_tracked_packet_is_sealed_and_sent` | yes |
| `NO_PATH` | core and engine `a_peer_without_a_path_for_data_is_no_path` | yes / yes |
| `ENCAPSULATE_ERROR` (job of a cleared session) | core `a_tracked_packet_sealed_in_a_replaced_session_is_an_encapsulate_error` | yes |
| job whose peer was removed | core `a_tracked_job_whose_peer_was_removed_is_not_sent` | yes |
| no transport | engine `a_path_to_no_installed_transport_is_no_transport` | yes |
| transmit full | engine `a_full_transmit_backlog_is_transmit_full` | yes |
| send error in the middle of a batch; tracked datagrams end their calls | engine `a_transport_failure_in_the_middle_of_a_batch_fails_only_its_datagram`, `tracked_datagrams_end_their_transport_calls` (task, inline, 2 workers) | yes / yes |
| transport closed (the call's datagram send error, the rest closed; inline and task) | engine `a_closing_transport_fails_the_datagram_of_its_call_and_closes_the_rest` | yes |
| removed / replaced transport | engine `a_removed_transport_reports_its_queued_tracked_datagrams`, `a_replaced_transport_sends_the_queued_tracked_datagrams` | yes / yes |
| engine stopped (shutdown and drop), refused afterwards | engine `stopping_the_engine_reports_the_outstanding_packets`, `dropping_the_engine_reports_the_outstanding_packets` | no (the receipt table was written with the API) |
| tag required, outstanding tag refused | engine `the_tracked_sender_needs_a_tag_and_refuses_an_outstanding_one` | yes |
| capacity: `try_send` `Full`, `send` waits for a received result | engine `outstanding_results_are_bounded_by_the_capacity` | yes |
| `local_barrier` waits for accepted tracked packets (0, 2 workers) | engine `the_local_barrier_waits_for_the_packets_the_tracked_sender_accepted` | yes |
| second `tracked_sender` call replaces the first | engine `results_follow_the_engine_after_a_second_sender_replaces_the_first` | no (receipt table) |
| marker cleared on `Output::Deliver` and recycled buffers | W4's `nsplane` `tests/tags.rs` (`inject_calls_keep_the_tag_and_clear_the_marker`, `recycled_buffers_reach_the_source_untagged_and_unmarked`) | W4 |
| two engines over UDP: results, plaintext egress, unmark, stop (0, 2 workers) | `nsplane-e2e` `send_receipts::tracked_packets_and_plaintext_egress_between_two_engines` | written after the code (does not build on the base) |

Benchmarks (slot 0, interleaved base `25debab` / build, each `slot.sh` invocation started at a
1-minute load below 3 and polled until then; the shared host rose to 4-16 during many runs;
tables in `docs/performance.md`, "Plaintext egress and send receipts"):

- Untracked against `25debab`: `data_path` `core_round_trip/64` -1.1 / -1.3 %,
  `core_round_trip_batch32/64` -0.1 / +2.2 %, `/1420` +0.8 / -0.6 % and -1.2 / +0.7 % (quiet
  invocation; a first one at load up to 7.9: -2.0 to +2.1 % apart from two disturbed base
  runs); `local_graph` `pipe/*` -0.4 to +2.7 %; `udp_offload` -5.6 to +6.3 %, both signs;
  `send_stream` undisturbed rounds `streams_1` +1.5 / -2.1 / +0.7 %, `streams_4` -1.0 / -2.0 /
  -1.1 %, `flows_1` -1.9 / -3.4 / -2.7 %. `send_stream`, `local_graph` and `udp_offload` do
  not run the engine or the core.
- Unresolved, for the integration's quiet re-measure: `netstack_udp_send/flows_4` is bimodal
  on both binaries again (runs near 480 us or between 580 and 870 us, the base's included),
  as in W4 and W5.
- Engine path (extra, not on the list): `engine_one_way` (identical bench on both trees)
  -9.6 / -6.5 % at 64 B and +7.5 / +0.1 % at 1420 B in the two quiet rounds, both signs; the
  eight-spoke `worker_pool` groups spread -43 to +45 % while the load rose to 7.3, not usable.
- Costs on the build: tracked core round trip +1.6 / +1.8 % at 64 B and -0.2 / +0.9 % at
  1420 B (first invocation +0.5 to +1.7 %); plaintext egress 29 / 34 ns per packet against
  215 / 620 ns of sealing; `tracked_send` through an engine (256 packets one way, tracked
  against untracked) +2.7 / +0.1 / +16 % at 64 B (the last run disturbed) and +2.0 / -0.2 /
  +5.7 % at 1420 B.

Gates on the code head (`bd5a539` plus these records):

- `flock /tmp/nsplane-heavy.lock just check` with 6 cargo jobs: pass (2505 tests, 34
  skipped).
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`: clean.
- `cargo semver-checks --workspace --baseline-rev v0.20.1` (0.51.0): one finding,
  `enum_marked_non_exhaustive` on `nsplane_core::Output` (`types.rs`); the new variants are
  covered by it. Every other crate: no semver update required.

Integration into 0.21.0 (`release/0.21.0` from `v0.20.2`, 2026-10-27): merged as `dfd8ef3`,
commits unchanged; the only conflict was this file. The integration reviewed the deviations
against the design note (the specification):

- `TrackedRefused::Duplicate`: stands. The note makes the tag the token and reports
  `SendResult { tag, outcome }`; with two outstanding packets under one tag neither the
  engine nor the consumer could tell their results apart. The note says nothing about
  duplicates, refusing returns the packet, and the tag is free again once its result is out.
- `reasons::FILTER_HANDLED` and `reasons::ENGINE_STOPPED`: stand. The note lists "handled by a
  filter" and "engine stopped" among the outcomes "with the existing reason strings", but
  `v0.20.2` has no string for either (`Verdict::Handled` was never a drop, a stop never a
  drop reason), so they need names; both are results only and never counted as drops.
  `PLAINTEXT_EGRESS_FULL` / `_CLOSED` are the plan's names, and the engine aliases follow the
  `DROP_*` convention.
- A tracked packet without a session also counted as a `NO_SESSION` drop: stands. The note
  defines the result (`NotSent { no session }` at once) and not the counters; unlike an
  untracked packet, which the tunnel queues, a tracked one is discarded, and drops are
  counted (principle 5); `inject_outbound_on` already counts the same case as a
  `NO_SESSION` drop.
- The core undoing what an outbound filter does to a tracked packet's tag or marker: stands.
  The carrier table lets a filter read and set the tag (R4 proposal A reads it), but for a
  tracked packet the tag is the token, and "exactly one result per accepted packet" needs
  the token to reach the result. The review found the case next to it uncovered: a marker a
  filter set on an untracked tagged packet was kept, so the core reported that packet
  `Sealed` under its tag, and the engine could post it as the result of an outstanding
  tracked packet with the same tag; this contradicts O13 ("a mark set elsewhere never
  produces a result"). Fixed with the integration: the core clears the marker of every other
  packet after the chain (`a_filter_cannot_make_an_untracked_packet_tracked`, inline and
  crypto jobs, failed before the fix), and `PacketFilter::outbound` states the rule.
- `inject_outbound` following the plaintext egress mark: stands. The note marks the peer's
  routed local packets; `inject_outbound` is routed (it only bypasses the filters, by its
  contract) and `inject_outbound_on` names its path and is not routed, so it stays sealed.
  The engine clears the marker on both entries as the note requires, so neither is tracked
  through the engine. The rustdoc of both `inject_outbound` entries now says so.
- The remaining deviations (the marker of an untagged packet cleared, jobs of a panicked
  crypto worker reported `ENGINE_STOPPED`, files outside the listed scope, two W4 tests
  adapted to O9 and O10, the extra benches) follow the note or are scope notes; recorded.
