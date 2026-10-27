# 20261027-0349-barrier-count-window Local barrier: cover a packet the source is handing out

- **status**: in_progress
- **priority**: P1
- **owner**: w3/barrier-count-0201
- **createdAt**: 2026-10-27 03:49
- **relatedPlan**: 20261026-0822-node-gateway-requests

## Description

Owner decision 2026-10-27: fix the count window of `EngineHandle::local_barrier` (task
`20261026-0836-local-barrier-plaintext-ingress`, released in 0.20.0) and release it alone as
0.20.1. The gateway-side review of the release C note (section 1 point 2, section 6 items 4
and 5) and the 0.20.0 rustdoc describe it: `read_source` added a read's packets to the shared
count only after `PacketSource::recv_batch` returned, so a barrier taken between the source
handing out a packet and that `fetch_add` left the packet out and could pass before the
packet was routed and filtered. A consumer cannot close it with a fence of its own without a
rendezvous with the source task.

Acceptance criteria:

- A deterministic test, failing on 0.20.0: a barrier taken while the source task is inside
  the read that hands out a packet waits for that packet (controlled source, no sleeps).
- Fix at the cause with the public API unchanged; the barrier means every local packet the
  engine took before the call. Decide whether packets of a future `TrackedSender` would be
  counted (not in 0.20.1; the design must not exclude it).
- Rustdoc without the window caveat, reference page, `CHANGELOG.md` 0.20.1 (Fixed),
  `docs/changelog.md`; slot A/B against `v0.20.0` (`local_graph`, `data_path`) on a quiet
  host; full gate, rustdoc with warnings denied, `cargo semver-checks` against `v0.20.0`.

## ActiveForm

Fixing the local barrier's count window

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- Base: `main` at `3e9f684` (the `v0.20.0` release `d09a0ed` plus a docs-only merge), branch
  `fix/0.20.1-barrier-count`.
- Test (`nsplane-e2e/tests/engine_entries.rs`,
  `a_barrier_covers_a_packet_the_source_is_handing_out`): `HeldSource` takes packet 7 from its
  channel and then blocks inside the same poll on a `Hold` until released; with the source
  task held there, `local_barrier` must still be pending, and once released it returns only
  after packet 7 met the outbound filter. On 0.20.0 it fails in 4 ms ("the barrier passed
  before packet 7 met the filter"): the position was read before the count.
- Fix (`engine/tasks.rs`): `SourceTaken` replaces the bare `AtomicU64`; its word is twice the
  count plus one while the source task polls `recv_batch`. The task is its only writer
  (`Reading`): it sets the bit before each poll of a read, clears it after a pending poll and,
  after the poll that ends the read, stores the new count with the bit clear (two release
  stores per poll, no read-modify-write; `Drop` clears the bit if the task is dropped or
  unwinds inside a read). `local_barrier` loads the word with acquire and yields while the
  bit is set, then takes the count. A packet the source handed out before the call (its hand
  out happens before the call) is in a poll whose bit store precedes it, so the barrier sees
  the bit or the count that includes the packet. The owner side is unchanged.
- `TrackedSender` (release C): not in 0.20.1. Its packets do not pass `read_source`; the
  design leaves room to count them at acceptance in a second counter that `local_barrier`
  reads with the source position and the owner counts in `Barriers`, so the barrier keeps
  meaning every local packet the engine took before the call, as the review recommends.
- Slot A/B against `v0.20.0` (`d09a0ed`), interleaved A, B, A, B, `scripts/bench/slot.sh`:
  - `nsplane-core` `data_path`, slot 0, load 1.2-1.6 (the bench binaries are byte-identical):
    `core_round_trip/64` 416 / 414 ns (-0.5 %), `core_round_trip_batch32/64` 12.99 / 13.02 us
    (+0.3 %), `core_round_trip/1420` 1.229 / 1.222 us (-0.6 %), `core_round_trip_batch32/1420`
    39.44 / 39.34 us (-0.2 %).
  - `nsplane` `local_graph`, slot 1, every side started below load 3 (1.2-2.9): all 34 cases
    -1.6 % .. +3.2 %, 31 within 1 % (`map_sink/send_after_1420` +3.2 %,
    `map_sink/send_batch_after_1420` +1.6 %, `swap_sink/swap_send_batch_1420` -1.6 %); this
    bench runs no engine. An earlier run under load 3-7 spread -20 % .. +21 % and is discarded.
- Gates: `flock /tmp/nsplane-heavy.lock just check` exit 0 (2405 tests passed, 34 skipped; a
  first run hit `AddrInUse` in `nsplane-dns` `passthrough`, whose stub binds TCP on the UDP
  port it got, intermittent on the busy host and untouched here; 5 of 5 reruns passed);
  `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --all-features` clean;
  `cargo semver-checks --workspace --baseline-rev v0.20.0`: no semver update required (all
  12 crates).
