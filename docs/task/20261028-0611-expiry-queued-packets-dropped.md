# 20261028-0611-expiry-queued-packets-dropped Report packets a tunnel expiry discards

- **status**: pending
- **priority**: P3
- **owner**: (unassigned)
- **createdAt**: 2026-10-28 06:11
- **plan**: 20261027-0433-post-freeze-schedule

## Description

Follow-up O5 (a) of the design note `docs/plan/notes/20261027-0433-peer-expiry-signal.md`,
decided by the owner on 2026-10-28 as a task after 0.21.0. When a peer's tunnel expires
(`nsplane-noise` `Tunn::check_expiry`, either cause), `clear_all` discards the packets queued in
the tunnel for the handshake without any `Event::Dropped` or drop counter: they vanish
silently. Decide whether the core reports them (count and reason, e.g. a new
`reasons::EXPIRED`-like drop), how a tracked packet among them gets its `NotSent` result if it
can be queued there at all, and the cost (only on the expiry path).

## Acceptance

- A proposal with the reporting contract and its compatibility (additive or not).
- Tests that an expiry with queued packets reports them; the data path is unchanged.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Not implemented in 0.21.0.
