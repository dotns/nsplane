# 20261027-0433-sink-spent-forwarding Wrapper sinks forward send_batch_spent

- **status**: pending
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-27 04:33
- **plan**: 20261027-0433-post-freeze-schedule

## Description

`AbortSink`, `MapSink`, `SwapSink`, `Splitter` and `Nat64LanSink` keep the default
`PacketSink::send_batch_spent`, so a `TunSink` wrapped by any of them returns no written buffers
and `pump` cannot recycle them (the loop closes only for a bare sink). Each wrapper forwards the
call with the contract of its own `send_batch`. Additive, no API change; ships in 0.20.1. Deferred
follow-up of the QR round (task `20261003-2200-ns-local-side`).

## Acceptance

- A unit test per wrapper over an inner sink that appends to `spent`.
- `nsplane-e2e` `recycle_loop` with a wrapped `TunSink`: no fresh allocation after warm-up.
- `local_graph` `pump/*` A/B through `scripts/bench/slot.sh` unchanged on the default path.
- Full gate.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
