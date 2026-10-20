# 20261020-1026-synchronize-regression-fixtures Synchronize concurrent regression fixtures

- **status**: completed
- **createdAt**: 2026-10-20 10:26 UTC
- **approvedAt**: Owner clarification in the current conversation requires both existing failures to be repaired rather than waived.
- **relatedTask**: 20261020-1026-synchronize-regression-fixtures

## Scope and evidence

Both failures reproduce on unmodified 82cbece. The replay test snapshots its counter before the warmup duplicate necessarily completes. The WSS test infers permanent backpressure from a short quiet period, although its TCP proxy can still complete an outstanding read and kernel buffers can continue progressing. An earlier queue overflow also does not prove the queue remains full after the writer removes its in-flight datagram; the blocked writer must be observed before refilling and observing another overflow.

Enable duplication only for the measured phase and await completion of the measured replay count. Replace the stalled WSS proxy with an observable, permanently blocked writer on the test connection. Preserve the real WebSocket transport, healthy-session traffic, exact replay count, overflow accounting and existing deadlines.

No production API or runtime changes, no ignored tests, relaxed counters or increased timeouts. Validate the two regressions repeatedly under ordinary and single-CPU scheduling, run their containing suites and lint, then complete the integrated Linux quality gate before publishing the repair blocks.

## Exit criteria

- Both repaired fixtures retain their original behavioral assertions and pass repeated checks.
- Related suites and lint pass.
- The integrated Linux `just check` passes without a baseline-failure exception.

## Validation

All 48 containing tests and targeted lint pass on macOS. Both regressions pass 20 ordinary Linux iterations and 20 single-CPU iterations (80 test executions). The integrated Linux `just check` passes on Rust 1.99.0 with 1,949 passing tests and 33 skipped tests; no baseline-failure exception was used.
