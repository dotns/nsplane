# 20261112-0006-driver-sink-recovery Sink recovery and local I/O robustness in the driver

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 00:06

## Description

Four audited robustness items in `nsplane`, the tokio driver:

1. `SwapSink` forwarded the `BrokenPipe` of its current sink, so the engine closed its sink
   side for good and a later `replace()` could not bring delivery back.
2. `read_source` and `write_sink` called again at once after any error that is not a close:
   a lasting error spun a core and logged at warn every time.
3. The engine trusted `PacketSink` implementations to keep the batch contract.
4. The per-thread cache of `SnapshotCell` (`nsplane-core`) can keep replaced values alive.

Acceptance: each fix has a test seen failing first; the gates pass for `nsplane`,
`nsplane-e2e` and `nsplane-examples`; public API changes are additive.

## ActiveForm

Making the driver's sink side recover and its local I/O loops robust.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

### 1. `SwapSink`

- A `BrokenPipe` from the current sink marks the slot gone (the sink stays in the slot, so
  `replace` still returns it with its counters, but it is not called again). The failed
  packet, the rest of the batch and every later packet are dropped, counted in `dropped()`
  and answered `Ok`. `replace` clears the mark.
- "A handle that can replace exists" is `Arc::strong_count(state) > 1`: every clone can
  call `replace`, so any other clone counts, whoever holds it. No new field or API was
  needed. Two clones held by one engine (the same swap sink under two wrappers, or in two
  engines) keep each other open for good; that is documented on the type.
- Once the called value is the last clone and the slot is empty or gone, every call returns
  `BrokenPipe`. For the batch forms the front packet is dropped and counted (appended to
  `spent` by `send_batch_spent`) and the rest stays, as the contract in `io.rs` asks. When
  the last clone is the first to find its sink gone, the sink's own error is returned: the
  sink already dropped the failed packet, and nothing is counted.
- Behavior change that follows from the decided semantics: a lone `SwapSink::new(None)`, or
  one whose slot was emptied before the other clones were dropped, used to drop and return
  `Ok` forever; it now returns `BrokenPipe`. A test in `pump.rs` relied on the old form and
  keeps a clone now.
- `try_send_batch` absorbs only `BrokenPipe`; other errors of a replaced sink are returned
  as before (`WouldBlock` must leave the packets with the caller).
- No explicit `close()` was added: dropping the other clones is the close.
- `Splitter` needs no change. It marks a sub-sink gone only on `BrokenPipe`, which a swap
  sink with another clone alive never returns
  (`splitter::tests::nested_swap_sink_recovers_after_its_sink_is_gone`).

### 2. Backoff in the source and sink tasks

- The wait of the transport receive loop moved into `ErrorBackoff` in `engine/tasks.rs`
  (1 ms doubling up to 64 ms for errors in a row, reset on success) and is used by
  `receive`, `read_source` and `write_sink`.
- Source and sink errors are logged at warn for the first error in a row and at debug for
  the ones behind it; the transport receive errors stay at debug.
- Consequence: a sink that fails every packet with an error other than `BrokenPipe` now
  takes them at up to one per 64 ms; the deliver queue fills and the engine drops the rest
  as `sink_full`. Before, each failed packet was consumed at once.
- The owner task's inline delivery (`deliver_inline`) cannot wait; each of its failed calls
  consumes a packet, so it is bounded by the batch.

### 3. Sinks that break the batch contract

Findings before the fix:

- `write_sink`, error without removing the failed packet: the loop called again forever on
  the same packet (a busy loop before item 2, a stall of all later deliveries after it).
- `write_sink`, `Ok` with packets left: the loop ended, the leftovers were offered again with
  the next batch, the batch grew without bound when the sink kept leaving them, and
  `outstanding` was lowered by more than it was raised, so it wrapped below zero and the
  owner task never delivered inline again.
- `deliver_inline` (owner task), error from `try_send_batch` without removing the packet:
  an endless loop that never yields, which hung the whole engine.
- `deliver_inline`, `Ok` or `WouldBlock` with packets left: already safe, the rest is queued
  for the sink task.

Fix: a call that did not report the close and took nothing out of the batch loses the front
packet; in the sink task a batch is offered until it is empty. The sink task logs the first
such packet at warn. These packets are not counted in the drop counters: a drop reason
lives in `nsplane-core`, out of scope here, and a packet the sink fails by the contract is
not counted either.

Not changed: `pump` and `Splitter::send_batch_spent` call other sinks under the same
contract. `pump` offers leftovers again with the next batch (they pile up if the sink never
takes them); a `Splitter` whose sub-sink returns `Ok` without taking its run routes it
again. Both are outside the engine and were left as they are.

### 4. `SnapshotCell` retention

No code change. The cache already holds at most one value per cell per thread and replaces
it when the thread reads that cell at a newer generation, so "drop on a newer generation" is
what it does. What remains is a thread that stops reading a cell: it keeps that one replaced
value until it reads the cell again, evicts the entry or exits (at most 8 values per
thread). The readers are the engine's owner task and crypto worker tasks, which run on the
tokio worker threads; nothing reads on the blocking pool, whose threads exit when idle. A
worker thread that goes idle while another keeps the traffic can therefore pin one replaced
table per cell for as long as it stays idle. Releasing it from another thread would need a
shared registry or atomic counts on the read path, which is what the cache exists to avoid,
and a bound of 1 would evict on every packet for a filter that reads several cells. The
retention is already stated in the module docs of `crates/nsplane-core/src/cell.rs` and in
`docs/reference/nsplane-core.md`.

## Validation

Seen failing before the fixes:

- Item 1: `swap::tests::swap_gone_current_sink_drops_until_replaced`,
  `swap_last_clone_with_a_gone_sink_is_closed`, `swap_last_clone_with_an_empty_slot_is_closed`,
  `splitter::tests::nested_swap_sink_recovers_after_its_sink_is_gone` and the engine test
  `swap_sink_delivers_again_after_its_sink_is_gone`.
- Item 2: `lasting_source_errors_back_off` and `lasting_sink_errors_back_off`.
- Item 3: `sink_that_keeps_packets_does_not_stall_the_sink_task` (timed out; before item 2
  it also spun and had to be killed) and
  `sink_that_keeps_a_failed_packet_inline_does_not_hang_the_engine` (hung, killed after
  90 s).

All pass after the fixes, with the gates listed in the hand-over.
