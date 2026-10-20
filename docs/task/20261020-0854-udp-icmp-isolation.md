# 20261020-0854-udp-icmp-isolation Isolate asynchronous errors on shared UDP sockets

- **status**: completed
- **priority**: P1
- **owner**: A/01a15732
- **createdAt**: 2026-10-20 08:54

## Description

With Linux PMTU error reception enabled, an ICMP error for an earlier destination can fail the next send to a reachable destination. A standalone public-API reproduction on v0.16.1 confirms the behavior. The owner authorized the smallest upstream repair after this attribution was confirmed. Preserve PMTU reports, genuine synchronous errors and batch accounting across transport and side-channel sends without adding product policy.

## Acceptance

- [x] The new regression fails on the original implementation and passes after the fix.
- [x] Single, batched, nonblocking batched and synchronous/asynchronous side sends cover IPv4, IPv6, dual-stack and offload on/off.
- [x] Reachable packets are neither lost nor duplicated; genuine errors, partial batches, PMTU reports, cancellation and backpressure remain correct.
- [x] Focused tests and repository `just check` pass; public behavior documentation is updated.

## ActiveForm

Isolating asynchronous UDP errors and validating the regression.

## Dependencies

- **blocked by**: (none)
- **blocks**: downstream recovery E2E under normal network configuration

## Notes

The owner approved an upstream fix after confirming ownership in the current conversation. A standalone 144-case reproduction found ECONNREFUSED and no delivery for the first reachable send in all 48 cases with discovery enabled and no preceding receive. The second sends and discovery-off/receive-first controls succeeded. Base: 82cbece; branch: fix/udp-icmp-isolation. Existing primary checkouts remain untouched. Claimed with the PMA serializer on the isolated Linux source mirror.

Native macOS gate failures reproduced on the unmodified base are tracked separately in [20261020-1000-macos-quality-gates](20261020-1000-macos-quality-gates.md). Their implementation is outside this repair.

Final focused Linux validation passed 46 UDP tests and all four privileged tests, including the strengthened backpressure test without caller retries. The independent public-API reproduction delivered all 288 healthy sends with no send errors or failed counter. The privileged tests ran in a disposable network namespace; host buffer limits were restored after the full suite.

The pinned Rust 1.99 Linux full gate passed every clippy feature group, then reported 1,946 passing tests and three failures. The heavy-loss test passed its bounded recheck. Two failures also reproduce on unmodified 82cbece: `stalled_session_does_not_block_the_others` times out waiting for every datagram to overflow, and `duplicates_opened_on_different_workers_are_rejected_as_replays` counts 2,001 instead of 2,000. The latter passed ten ordinary rechecks, then failed on iteration six with the original test process restricted to one CPU. Neither test uses UDP transport. They remain failures, not passing gate evidence; no test or assertion was disabled.

Format, spelling, product terminology and documentation checks pass on Linux. The remaining gates (doc tests, dependency checks, MSRV and examples) pass on both macOS and Linux. The owner clarified that both existing test failures must be repaired in this delivery; no baseline-failure exception is selected. Their repair is tracked in [20261020-1026-synchronize-regression-fixtures](20261020-1026-synchronize-regression-fixtures.md), followed by the integrated Linux quality gate.

Validation: integrated Linux `just check` passed on Rust 1.99.0 (1,949 tests passed, 33 skipped); privileged UDP tests were validated separately. Both fixture regressions also passed 20 ordinary and 20 single-CPU iterations. No gate exception was used.

- complete: UDP regressions, privileged tests, independent reproduction and integrated Linux quality gate passed.
