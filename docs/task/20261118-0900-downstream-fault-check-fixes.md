# 20261118-0900-downstream-fault-check-fixes Fix the faults of the downstream fault check

- **status**: in progress
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
