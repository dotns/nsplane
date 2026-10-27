# 20261027-0305-packet-tag-carrier Packet tag carrier on PacketBuf (release C, W4)

- **status**: pending
- **priority**: P1
- **owner**: (unassigned)
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

(none)
