# 20261118-0900-downstream-fault-check-fixes Fix the faults of the downstream fault check

- **status**: completed
- **priority**: P1
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-11-18 09:00

## Description

A downstream fault check of 0.23.0 and smoltcp fork `v0.14.0-nsplane.8` (detection only, kept
in the consumer's repository) found faults of nsplane and of the fork. Owner decision
2026-11-18: rebase the fork on the current upstream, fix them and release 0.24.0.

| Id | Fault | Fix |
| --- | --- | --- |
| F2 | An idle timeout with a paused reader moved later bytes into the discarded buffer: a hole, then `Ok(0)` | No bytes move into an aborted connection; the read ends with `TimedOut` |
| F1 | A peer's RST read as `Ok(0)` | Fork `Socket::reset_received`; the read ends with `ConnectionReset` (breaking) |
| a5 | A lost fast retransmission waited for the RTO: every new segment pushed the probe out | Fork: no probe re-arm by new segments in loss recovery |
| c | Windows: the first exclusive open after a killed holder refused with `AdapterExists` | Wait up to 0.5 s for an alias Wintun cannot open before refusing |
| F6 | Slow start after a mid-flow MTU drop | Not changed: enabling New Reno partial ACKs after `reduce_mss` would resend on every ACK of the resent flight; needs a reproduction of its own |

Limits by design the check also lists (no SACK scoreboard, RTO backoff, idle timeout counting
payload only, listener pool RST, handshake timeouts) are not changed here.

## ActiveForm

Fixing the downstream fault check findings.

## Dependencies

- **blocked by**: (none)
- **blocks**: 0.24.0

## Validation

- smoltcp fork `v0.14.0-nsplane.9`: 714 library tests with the default features, 457 with the
  features nsplane uses; each fix has a regression test that failed before it.
- F1 and F2: `a_peer_reset_ends_the_read_with_connection_reset` and
  `the_idle_timeout_ends_a_paused_read_with_an_error_and_no_hole` failed before the fix (EOF
  after the reset; the first byte read came from past the discarded buffer). Three tests that
  asserted `Ok(0)` after a reset now assert `ConnectionReset`.
- c, on the Windows 11 test VM with the consumer's reopen program built against this branch:
  the 0.23.0 build refused the first open after `taskkill /F` in 5 of 5; this branch opened at
  the first attempt in 20 of 20 at `kill@0` and 20 of 20 at `kill@2` (200-280 ms), and 20 of 20
  after a clean exit.
