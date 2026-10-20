# 20261020-1026-synchronize-regression-fixtures Synchronize concurrent regression fixtures

- **status**: completed
- **priority**: P1
- **owner**: A/01a15732
- **createdAt**: 2026-10-20 10:26 UTC

## Description

Repair the two existing concurrency-sensitive fixtures identified by the UDP repair's quality gate, according to the [plan](../plan/20261020-1026-synchronize-regression-fixtures.md). The owner requires their repair in this delivery instead of accepting a baseline-failure exception.

## Acceptance

- [x] Warmup duplicates cannot contaminate the measured replay count.
- [x] The stalled WSS writer is explicitly observed blocked before measuring overflow.
- [x] Original packet, counter and deadline assertions remain enforced.
- [x] Repeated checks, containing suites, lint and the integrated Linux quality gate pass.

## ActiveForm

Synchronizing the measured phases of the replay and stalled-session regressions.

Validation: integrated Linux `just check` passed on Rust 1.99.0 (1,949 tests passed, 33 skipped); privileged UDP tests were validated separately. Both fixture regressions also passed 20 ordinary and 20 single-CPU iterations. No gate exception was used.

- complete: Related suites, repeated scheduling checks, lint and integrated Linux quality gate passed.
