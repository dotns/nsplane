# 20261106-0900-netstack-label-followups Netstack label review follow-ups

- **status**: completed
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-11-06 09:00

## Description

Review of the active packet lifetime labels. Keep the connected UDP check: `None` stays a label
of its own, which matches the rule of accepted lifetimes and the use of `ns`, the only consumer
that tags input. Pin it with a test and record the change from 0.21.0 as breaking. The device
table keeps only labeled TCP lifetimes, so an unlabeled stack skips the output lookup again.
Record the labeled active APIs and the `mixed_tags` semantics in the release notes.

## ActiveForm

Applying the review follow-ups.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Validation

`just check` (2499 tests, 34 skipped), `cargo doc` with denied warnings, `just cross` and
`just test-windows` pass.

`send_stream` A/B with the accepted side sending, A = 71e3273 (before the active labels),
B = this change, slot runs at loadavg 1.3-5.2, 6 interleaved pairs, medians:

| Bench | A | B | B/A | Pair range |
| --- | --- | --- | --- | --- |
| `netstack_send/streams_1` | 3199 us | 3150 us | -1.5 % | 0.970-0.995 |
| `netstack_send_1cpu/streams_1` | 3503 us | 3526 us | +0.7 % | 0.979-1.026 |
| `netstack_send/streams_1_labeled` | 3253 us | 3387 us | +4.1 % | 1.025-1.070 |
| `netstack_send_1cpu/streams_1_labeled` | 3546 us | 3793 us | +6.9 % | 1.047-1.090 |

The unlabeled path is back at the baseline (before this change: +4.6 % and +8.1 %). The labeled
rows are the cost of the output lookup a labeled lifetime pays by design.
