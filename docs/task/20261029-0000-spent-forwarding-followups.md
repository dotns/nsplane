# 20261029-0000-spent-forwarding-followups Spent buffer forwarding: the remaining sinks

- **status**: completed (merged 2026-10-29)
- **priority**: P3
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-29 00:00
- **plan**: 20261027-0433-post-freeze-schedule

## Description

Left out of task `20261027-0433-sink-spent-forwarding` (released in 0.20.2):

- `Splitter` delivers `send_batch_spent` one packet at a time; consecutive packets for the same
  sink can go as one inner batch. The retry contract (packets left after an error, re-mapping
  by `new_map`) must stay what `send` gives today.
- `SlotSink` (`nsplane-tun`) keeps the default `send_batch_spent` and returns no written buffers.
- The examples' hybrid `SharedSplitter` forwards only `send`, so its splitter path does not
  recycle.

Additive, no public API change. Since 0.21.0 spent and dropped buffers are handed back untagged
and unmarked; the new paths keep that.

## Acceptance

- Tests first per item (order and retry for `Splitter` runs; a `SlotSink` test that gets its
  written buffers back; the example forwards).
- `local_graph` `pump/*` A/B through `scripts/bench/slot.sh`, plus a `Splitter` spent case.
- Full gate.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
