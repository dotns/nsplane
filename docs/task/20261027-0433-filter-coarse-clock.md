# 20261027-0433-filter-coarse-clock AclFilter and AclEngine on the coarse clock

- **status**: pending
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-27 04:33
- **plan**: 20261027-0433-post-freeze-schedule

## Description

The flow gate reads the coarse monotonic clock (`gate/clock.rs`), but `AclFilter` calls
`Instant::now` on every reply allowance hit and record (`filter/cache.rs`, `filter/replies.rs`)
and `AclEngine::new` defaults to `Instant::now`. Both move to the shared coarse clock. Expiry
granularity becomes one scheduler tick (1-4 ms); the owner accepted it on 2026-10-27. No API
change; documented behavior change; ships in 0.20.1.

## Acceptance

- The clock module is shared at crate level; `AclEngine::with_clock` and the gate's
  `with_clock` keep working for manual clocks.
- Docs of `reply_idle_timeout`, the engine clock (`lib.rs` "Clock and lazy expiry") and the
  CHANGELOG state the granularity.
- `gate` and `namespaces` A/B through `scripts/bench/slot.sh` against `main`.
- Full gate.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
