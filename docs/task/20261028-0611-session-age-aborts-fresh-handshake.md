# 20261028-0611-session-age-aborts-fresh-handshake Idle expiry aborts a handshake started just before it

- **status**: pending
- **priority**: P3
- **owner**: (unassigned)
- **createdAt**: 2026-10-28 06:11
- **plan**: 20261027-0433-post-freeze-schedule

## Description

Follow-up O5 (b) of the design note `docs/plan/notes/20261027-0433-peer-expiry-signal.md`,
decided by the owner on 2026-10-28 as a task after 0.21.0. The `REJECT_AFTER_TIME * 3`
(540 s) expiry in `nsplane-noise` `Tunn::check_expiry` measures from the last established
session (or the timer origin), not from the current handshake attempt. A handshake initiation
sent shortly before the 540 s mark is therefore aborted by the idle expiry (reported as
`ExpiryCause::SessionAge`, or not at all for a peer that was never up) instead of getting its
`REKEY_ATTEMPT_TIME` of retries. Investigate against the WireGuard whitepaper and the kernel
implementation, and decide whether an outstanding initiation should defer the idle expiry.

## Acceptance

- A core test on the fake clock that reproduces the abort.
- A proposal (protocol timers are behaviour; the change and its compatibility are called out).

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Not implemented in 0.21.0.
