# 20261112-0103-sink-contract-outside-the-engine The sink batch contract outside the engine, and the macOS privilege drop

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 01:03

## Description

Three items left by the audit follow-ups (see `20261112-0006-driver-sink-recovery.md`, "Not
changed"):

1. `pump` trusted a `PacketSink` to keep the batch contract.
2. `Splitter::send_batch_spent` trusted its sinks the same way; check the other wrappers.
3. `nsplane-cli` keeps root's supplementary GIDs after the privilege drop on macOS.

Acceptance: each fix has a test seen failing first; the gates pass for `nsplane` and
`nsplane-cli`; public API changes are additive.

## ActiveForm

Making `pump` and `Splitter` robust against sinks that break the batch contract.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

### 1. `pump`

Findings before the fix: a sink error other than `BrokenPipe` already ended the pump, so
there was no endless loop. With a sink that returned `Ok` and left packets, the leftovers
were offered again with the next read: the batch grew by one read per round for as long as
the source produced, nothing behind the first kept packet was delivered, and when the source
ended the pump returned `Ok` with all of them undelivered.

Fix: a batch is offered until it is empty or the sink returns an error; a call that returned
`Ok` and took nothing loses the front packet. The batch is therefore one read (at most
`MAX_BATCH` packets) again. A call that returned `Ok` and took some packets is called again
with the rest and loses nothing.

Not counted: `PumpStats` is a public struct with public fields and is not
`#[non_exhaustive]`, so a new field would break callers that build or match it. The loss is
logged at warn the first time, and `PumpStats::packets` counts only what the sink took. The
dropped buffer is not offered to `PacketSource::recycle`.

### 2. `Splitter` and the other wrappers

Findings in `Splitter::send_batch_spent` before the fix:

- A sink that returned `Ok` without taking its run got the same run again, forever, when the
  run ended the batch (and always for a `Splitter::new_map` splitter, whose runs are one
  packet). With a sink that never waits the loop does not yield.
- When another packet followed the run, the route remembered for that packet was used for
  the front of the run that came back: the packets a sink left were delivered to the sink of
  the packet behind them.
- An error that left the failed packet in the run was returned with that packet still at
  the front of the batch.

Fix: when a sink took nothing out of its run, the front packet of the run is dropped and
its buffer appended to `spent`. After an `Ok` it is counted in `SplitterStats::failed`, whose
documentation now names the case; after an error it is the failed packet, which was already
counted. Whenever a sink leaves part of its run the remembered route is discarded and the
rest is routed again. As in the engine, a sink that took some packets and then failed one
without dropping it cannot be told from one that kept the contract; the caller gets the
error and the packet at the front of the batch, and the next call drops it.

Already safe, no change:

- `Splitter::send`, the default `send_batch` (one `send` per packet) and the default
  `try_send_batch` (`WouldBlock`).
- `SwapSink`, `MapSink`, `AbortSink`: each batch method calls the inner sink once and returns
  its result with what it left in the batch, so they neither loop nor keep packets; the
  caller (the engine, `pump`, a `Splitter`) deals with what is left. Their counts assume
  the contract: `SwapSink::dropped` counts one packet too many when a replaced or gone sink
  failed a packet and left it, and the `after` hook of a `MapSink` is skipped for the last
  delivered packet when the inner sink failed a packet and left it. Left as they are.
- `ChannelSink`, `PipeSink`: they deliver themselves and call no other sink.

### 3. Supplementary GIDs on macOS

No code change. `nix` 0.31.3 excludes `setgroups`, `initgroups`, `getgroups` and
`getgrouplist` on Apple targets (`#[cfg(not(apple_targets))]`). Among the sources of every
crate in `Cargo.lock` only `libc` declares these functions, as `unsafe extern` items, and
`std` has no stable call for the current process. The CLI denies `unsafe_code` with one
allowed block and must not gain another or a `libc` dependency, so no safe call exists.
The gap is stated in `docs/reference/nsplane-cli.md`: on macOS the daemon keeps the
supplementary GIDs it started with after the drop.

The gap was closed by `20261112-0202-sys-wrapper-crate.md`.

## Validation

Seen failing before the fixes:

- Item 1: `pump::tests::sink_that_keeps_packets_loses_them_only` (the sink took `[1]` of
  `[1, 2, 3]`).
- Item 2: `splitter::tests::sink_that_leaves_its_run_loses_the_front_packet` (endless loop,
  ended by the 5 s timeout of the test), `packets_a_sink_left_do_not_reach_the_next_sink`
  (the second sink got the packet the first one left) and
  `packet_a_sink_failed_and_left_is_dropped`.

All pass after the fixes, with the gates listed in the hand-over. Item 3 has no test.
