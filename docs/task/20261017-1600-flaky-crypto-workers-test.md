# 20261017-1600-flaky-crypto-workers-test Flaky sink count in a crypto-workers e2e test

- **status**: completed (2026-10-26)
- **priority**: P3
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-17 16:00

## Description

`nsplane-e2e::fast_path::crypto_workers_keep_the_tasks_sending_and_delivering` failed once in a
full `just check` on main after the NL merge (2026-10-17): `assert_eq!(node.sink.task_done(), 201)`
at `crates/nsplane-e2e/tests/fast_path.rs:784` saw 200. Run alone it passed 30 of 30 times, and the
next full `just check` passed. NL touched only nsplane-nat, so the flake predates it.

The test asserts an exact count of sink task completions (200 packets plus one more), which
depends on timing under load. Fix: find what the 201st completion is, and either wait for it
deterministically or assert what the test means (every packet delivered by the task, no
`try_send` on the sink) without the exact count.

## Resolution

The count was right; the scripted transport and sink in `tests/fast_path.rs` counted a delivery
after handing the packet off, so the test could read the 200th packet before its count. All four
counters (`task_done` and `try_done` of both mocks) now count before the hand-off; the channel
hand-off orders the count before the read. Verified: `fast_path` run 100 times, no failure.
