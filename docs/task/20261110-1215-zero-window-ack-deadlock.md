# 20261110-1215-zero-window-ack-deadlock A zero receive window drops the ACK that would reopen it

- **status**: in_progress
- **priority**: P1
- **owner**: L3/t570f88i
- **createdAt**: 2026-11-10 12:15

## Description

Reported from netseed-ns (L1 elcock9k): a 32 MiB echo from a Linux TUN peer into the user-space
stack stalls for good in about 1 run of 25. In the smoltcp fork at `v0.14.0-nsplane.7`,
`scaled_window` rounds the advertised window up to the scale unit, Linux fills it, and the stack
ends at RCV.WND 0 with the remote's SND.NXT past RCV.NXT. Every later pure ACK carries that SEQ
and failed the acceptability test before its ACK and window were taken (RFC 9293 3.10.7.4 asks
for them to be processed). With both windows closed, neither side ever sends again.

Acceptance: the fork processes such ACKs (SND.UNA..=SND.NXT, SND.WND by the WL1/WL2 rule) with
its own tests and lints passing; a netstack regression test holds the deadlock; `just check`
passes against the fixed fork; the ns stall loop (75 runs) shows no stall. No push, tag or
release: the owner decides.

## ActiveForm

Fixing the zero-window ACK path in the smoltcp fork and proving it in nsplane and ns.

## Dependencies

- **blocked by**: a fork tag `v0.14.0-nsplane.8` for the committed pin
- **blocks**: the ns nsplane bump

## Notes

Approval given up front in the issue. The fix is in the fork (branch `fix/zero-window-ack`); this
branch adds the regression test only, and it fails against `v0.14.0-nsplane.7` until the pin
moves. The rounding up in `scaled_window` stays: rounding down moves the advertised right edge
left (fork commit 419f085 removed that), and the bytes past the buffer are trimmed and
retransmitted, which is harmless once the following ACKs are taken.

## Validation

`stack::tests::zero_window::an_ack_past_a_zero_window_reopens_the_send_window` fails at
`v0.14.0-nsplane.7` and passes against the fixed fork through a local `[patch]` (10 of 10). `just check` passes with the `[patch]` (2515 tests, 34 skipped).

ns re-check: mini-ns `a34e0b403` plus `tests/e2e/stall` from `10bfdfdb7`, with nsplane and smoltcp
patched to this branch and the fork fix, `RUNS=75 STALLS=75 tests/e2e/stall/repro.sh`: runs 75,
stalls 0 (echo 219-748 ms, median 311 ms). Baseline on the same commit: 3 stalls in 78.

Pending the owner's tag: the pin commit moves `smoltcp` in `crates/nsplane-netstack/Cargo.toml`
to `tag = "v0.14.0-nsplane.8"` and adds a CHANGELOG entry; then status goes to completed.
