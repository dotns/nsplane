# 20261027-0305-packet-tag-carrier Packet tag carrier on PacketBuf (release C, W4)

- **status**: completed (integrated into 0.21.0 on `release/0.21.0`, not released)
- **priority**: P1
- **owner**: w4/packet-tag-carrier
- **createdAt**: 2026-10-27 03:05
- **relatedPlan**: 20261026-0822-node-gateway-requests (W4, release C)

## Description

Workstream W4 of release C (0.21.0), approved by the owner on 2026-10-27 as the twelfth freeze
exception. The specification is the approved design note
`docs/plan/notes/20261026-0834-packet-tag-carrier.md` (sections "The carrier", "Carrier sites",
"Per-packet budget", W6 "send receipts" for the marker, O11, O13). W4 adds the carrier that W5
(netstack ingress labels) and W6 (plaintext egress and send receipts) and R4 proposal A use: one
opaque tag per packet, preserved wherever nsplane moves a packet into another buffer, never on
the wire, plus the documented receipt marker.

Scope:

- `PacketBuf::{tag, set_tag, take_tag}` (`Option<NonZeroU64>`) and the receipt marker
  `PacketBuf::{is_tracked, set_tracked}`; `Clone` copies the tag and clears the marker; new and
  pooled buffers carry neither. Layout variant A (64 bytes) first; variant B (`u32` offsets,
  56 bytes) only if A is outside the noise (O11).
- `Reassembler::{push_tagged, discard_tagged}` and `FragmentTags::{Same, Mixed}`; a
  `mixed_tags` counter in `ReassemblyStats`.
- Every carrier site of the note, with its rule: preserve on moves; copy the tag (and the
  marker where the same packet moves to a new buffer) in `Core::layout_for_sealing`'s copy,
  nsplane-nat `make_room` and `to_ipv6`; copy the tag but never the marker to each
  `split_ipv4` fragment; clear both where a buffer stops being the packet (`sealed` for
  non-data messages, `PacketSource::recycle` hand-offs from the engine and from `pump`); clear
  the marker on the engine's entries (`read_source`, inject calls, `PlaintextIngress`) and on
  every packet it hands out (`Output::Deliver`, buffers given back for recycling).
- nsplane-nat translator reassembly: a `Mixed` set is dropped and counted;
  `TranslatorStats` becomes `#[non_exhaustive]` with `fragment_mixed_tags` (breaking).
- Documentation: `nsplane-packet.md` (tag, marker, `push_tagged`), `nsplane-core.md`,
  `nsplane.md` (recycle hand-offs, entries), `nsplane-nat.md`, `docs/architecture.md` (contracts:
  the tag) is the integrator's.

Write scope: `crates/nsplane-packet/src/{buf,pool,reassembly}.rs` (`PacketBatch` lives in
`buf.rs`) and their tests; `crates/nsplane-core/src/core/send.rs` (`layout_for_sealing`,
`sealed`); `crates/nsplane/src/` `engine/{tasks,output,input}.rs`, `fragment.rs`, `pump.rs`;
`crates/nsplane-nat/src/translate/` `{rfc7915,fragment}.rs`,
`crates/nsplane-nat/src/translate.rs` (`TranslatorStats`),
`crates/nsplane-nat/src/nat64_lan/packet.rs`; the reference pages above; `CHANGELOG.md` entries
under Unreleased.

Acceptance criteria (tests first for every rule):

- Tag unit tests: new buffers untagged and unmarked; `Clone` copies the tag and clears the
  marker; both pools return untagged, unmarked buffers; `PacketBatch` preserves;
  `push_tagged` same, mixed (a tag and `None` included), untagged, expiry, `discard_tagged`.
- Core: the tag at a recording outbound filter; on the `Output::Transmit` datagram inline and
  with crypto workers; after the shared-slice copy in `layout_for_sealing`; the no-session
  handshake initiation untagged and unmarked; `inject_*` and `receive_plaintext` preserve the
  tag; an inbound filter's tag reaches `Output::Deliver`, unmarked.
- Engine: the tag through `ChannelSource` and `PipeSource` to the outbound filter and the
  transport; a marked packet from a source or an inject call is untracked; every `split_ipv4`
  fragment carries the tag and no marker; recycled buffers reach `PacketSource::recycle`
  untagged and unmarked (engine and `pump`).
- nsplane-nat: `make_room`, `to_ipv6` and translator reassembly (same tags pass, mixed dropped
  and counted).
- No nsplane runtime path clones a `PacketBuf` (re-checked by building the workspace's
  libraries and binaries without `Clone`).
- Benchmarks (slot A/B, interleaved, against the release base), untagged traffic within the
  noise: `nsplane-core` `data_path` (`core_round_trip/64`, `core_round_trip_batch32`),
  `nsplane-netstack` `send_stream` (`netstack_send/*`, `netstack_udp_send/*` with `flows_4`),
  `nsplane` `local_graph` and `udp_offload`, `nsplane-packet` `vnet`, `nsplane-nat`
  `translate`; variant A and variant B both measured, B taken only if A is outside the noise.
- Full gate (`just check`), rustdoc with warnings denied, `cargo semver-checks` listing exactly
  the intended breaks (`TranslatorStats`).

## ActiveForm

Adding the packet tag carrier on PacketBuf

## Dependencies

- **blocked by**: (none; approved 2026-10-27)
- **blocks**: `20261027-0305-netstack-ingress-labels` (W5),
  `20261027-0305-plaintext-egress-send-receipts` (W6)

## Notes

Implemented on `feat/packet-tag-carrier` from `v0.20.0` (`d09a0ed`), 2026-10-27, and rebased
onto `v0.20.1` (`7ff04fd`) once it was released; the one conflict, `read_source`, keeps
0.20.1's per-poll read accounting and adds the marker clear. The benchmarks below ran on the
branch before the rebase, against `v0.20.0`.

Deviations from the description, with reasons:

- `TranslatorStats` stays exhaustive: the brief for this workstream required semver-checks
  against `v0.20.0` to be additive only. The translator's mixed-tag drop is counted through
  the new drop reason `reasons::FRAGMENT_MIXED_TAGS` (in `dropped_out` and the engine's
  `drop_counters`) instead of a `fragment_mixed_tags` field. Adding the field, with
  `#[non_exhaustive]`, stays open for the release C integration if the owner wants it.
- Layout variant B was taken (`PacketBuf` stays 56 bytes, `u32` offsets): variant A was
  outside the noise on `local_graph` (below). A packet ends at most `u32::MAX` bytes into its
  buffer; `set_len`, `extend_from_slice` and `PacketPool::get_len` stop there instead of
  panicking, `from_shared` and `reserve_front` return `BoundsError` past it.
- The engine's inject entry clears the marker in `engine/command.rs` and
  `PacketSource::recycle`'s docs are in `io.rs`; both are outside the listed files.
- `docs/architecture.md` (contracts: the tag) is left to the integrator, as the task says.
  No netstack change: the netstack sites of the note belong to W5.

Carrier-site test matrix (every copy and clear site failed before its change; the failing
output was recorded during the work):

| Site | Rule | Test |
| --- | --- | --- |
| new buffers, `PacketPool::{get, get_len, put}` | none | `buf::tests::new_buffers_are_untagged_and_untracked`, `pool_hands_out_untagged_untracked_buffers` |
| `SharedPacketPool::{alloc, alloc_from, recycle}` | none | `pool::tests::recycled_buffers_come_back_untagged_and_untracked` |
| `Clone` | tag copied, marker cleared | `buf::tests::clone_copies_the_tag_and_clears_the_marker` |
| `PacketBatch` push / drain / into_iter / rejected push | move | `buf::tests::batch_preserves_tags_and_markers` |
| `Reassembler::push_tagged` (same, untagged, mixed incl. `None`, duplicates, expiry), `discard_tagged` | merge | `reassembly::tests::push_tagged_*`, `discard_tagged_drops_the_datagrams_holding_the_tag` |
| `Core::prepare_send` filter loop (read and set) | move | `nsplane-core` `tests/tags.rs` `local_packets_carry_the_tag_to_the_filter_and_the_datagram` (inline and crypto jobs) |
| `layout_for_sealing` copy | copy tag and marker (failed before) | `a_packet_without_headroom_keeps_its_tag_and_marker_through_the_copy` |
| `sealed` for non-data (no-session initiation), `flush_queue` | clear (failed before); untagged | `a_handshake_initiation_written_into_a_packet_carries_neither` (inline and crypto jobs) |
| `inject_inbound`, `inject_outbound`, `inject_outbound_on`, `receive_plaintext` | move | `inject_calls_and_plaintext_keep_the_tag` |
| inbound filter tag to `Output::Deliver` | move | `an_inbound_filter_tag_reaches_the_delivery` |
| `read_source` from `ChannelSource` / `PipeSource` to filter and transport (`send_batch`, `try_send_batch`) | move, marker cleared (failed before) | `nsplane` `tests/tags.rs` `the_tag_goes_from_a_{channel,pipe}_source_to_the_filter_and_the_transport` (0 and 2 workers) |
| engine inject calls, `PlaintextIngress`, `Output::Deliver` | marker cleared (failed before) | `inject_calls_keep_the_tag_and_clear_the_marker`, `plaintext_ingress_keeps_the_tag_and_clears_the_marker` |
| `read_source` recycle hand-off | clear (failed before) | `recycled_buffers_reach_the_source_untagged_and_unmarked` (0 and 2 workers) |
| `pump` recycle hand-off | clear (failed before) | `pump::tests::spent_buffers_reach_recycle_untagged_and_unmarked` |
| `split_ipv4` | tag to every fragment, no marker (failed before) | `fragment::tests::every_fragment_carries_the_tag_and_none_the_marker` (native and translated) |
| `Action::Send`, `Action::Reply` | move; new buffer untagged | `sent_packets_keep_the_tag_and_marker_and_replies_carry_neither` |
| `rfc7915::make_room` | copy tag and marker (failed before) | `translate::tests::tags::a_grown_copy_keeps_the_tag_and_the_marker` |
| translator reassembly | same tag kept, mixed dropped and counted (failed before) | `a_reassembled_datagram_keeps_the_tag_its_fragments_share`, `fragments_with_different_tags_are_dropped_and_counted` |
| `nat64_lan::to_ipv6` | copy tag and marker (failed before) | `nat64_lan::tests::reverse_keeps_the_tag_and_the_marker_in_place_and_through_the_copy` |

No runtime path clones a `PacketBuf`: with `Clone` removed, `cargo check --workspace
--all-features --lib --bins` builds all 14 crates; only tests need it.

Benchmarks (slot 0, interleaved against `v0.20.0`, each run started at load < 3; tables in
`docs/performance.md`, "Packet tag carrier against 0.20.0"):

- Variant A (64 bytes) against 0.20.0: `data_path` -1.3 % (`core_round_trip/64`), -1.1 %
  (`batch32/64`); `send_stream` -1 % to -3 %; `vnet` +0.5 %; `translate` -7 % to +1 %; but
  `local_graph` `splitter/*` +6.5 to +8.3 % in all four rotated rounds (+10 to +22 % in the
  first two), `pipe/send_recv_1420` +3.4 %, `swap_sink/bare_send_*` +2.5 to +4.4 %: outside
  the noise. Prototype B (56 bytes): `local_graph` -5 % to -13 %, the rest within the noise.
  Decision per O11: variant B.
- Shipped build (B) against 0.20.0: `data_path` -4.6 % to +1.7 % (`core_round_trip/64`
  +0.5 %, `batch32/64` +0.4 %); `local_graph` -12 % to -1 %; `udp_offload` -2.3 % to +2.1 %;
  `translate` -3.1 % to +4.8 % (both signs per round); `vnet` +1.7 % (+53 ns per 64 KiB
  packet: the bound in `set_len` / `extend_from_slice`, 45 segments); `send_stream` +1.0 % to
  +2.1 % on the 1-CPU cases, `streams_4` -3.3 %, `streams_1` +3.1 %, `flows_1` +4.4 % and
  `flows_4` +42 % from disturbed runs (B intervals [725, 862] / [523, 597] us at load up to
  5.2; base tight at 476-488 us; prototype B equal to base here). Open: re-measure
  `send_stream` `streams_1`, `flows_1` and `flows_4` on a quiet host before the release.
- The labeled-path bar (noise plus 3 %) belongs to W5; W4 adds no labeled path.

Integration into 0.21.0 (`release/0.21.0` from `v0.20.2`, 2026-10-27): merged as `dbee734`,
commits unchanged. Conflicts were in documents only (`CHANGELOG.md`, `docs/changelog.md`,
`docs/reference/nsplane-nat.md`, where 0.20.2's `Nat64LanSink::send_batch_spent` sentence and
the tag sentence are both kept, and this file). 0.20.2's wrapper sinks (`MapSink`,
`AbortSink`, `SwapSink`, `Splitter`, `Nat64LanSink`) forward `send_batch_spent` and append
the buffers of the packets they drop; those buffers keep their tag and marker until `pump`
clears both before `PacketSource::recycle`, so the carrier rule holds without a change. Added
with the integration: `pump::tests::wrapper_sinks_hand_spent_and_dropped_buffers_back_untagged_and_unmarked`
(kept packets reach the inner sink with tag and marker; dropped and spent buffers reach the
source with neither; fails with `pump`'s clear removed) and a sentence on
`PacketSink::send_batch_spent` that spent buffers still carry both. The owner accepted variant
B and the exhaustive `TranslatorStats` with `reasons::FRAGMENT_MIXED_TAGS` (2026-10-27).
