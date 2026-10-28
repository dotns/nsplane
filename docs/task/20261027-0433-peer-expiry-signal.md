# 20261027-0433-peer-expiry-signal Peer-level connection expiry signal (design)

- **status**: in_progress (design note merged 2026-10-27; owner decided O1-O5 on 2026-10-28;
  implemented on `feat/0.21.0-m3-removals` for 0.21.0)
- **priority**: P3
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-27 04:33
- **plan**: 20261027-0433-post-freeze-schedule

## Description

Since 0.19.2 the `CONNECTION_EXPIRED` timer events of `nsplane-noise` log at debug, and a
consumer learns that a peer's session expired only by polling handshake ages. Design an `Event`
variant and/or a `PeerStats` counter for it. `Event` and `PeerStats` are exhaustive, so the
addition is breaking; the owner decided on 2026-10-27 to ship it in 0.21.0 with release C and to
make both `#[non_exhaustive]` in the same release.

## Acceptance

- A design note under `docs/plan/notes/`: the signal (variant fields, counter semantics, which
  timer paths emit it), the `#[non_exhaustive]` change, and the CHANGELOG `#### Breaking`
  migration example.
- Owner review of the note before implementation.

## Dependencies

- **blocked by**: (none)
- **blocks**: implementation in 0.21.0

## Decisions

Owner, 2026-10-28, all as recommended in the design note
[20261027-0433-peer-expiry-signal](../plan/notes/20261027-0433-peer-expiry-signal.md):

- O1: the `SessionAge` expiry of a peer that was never up is not reported (D2).
- O2: one `expirations` counter (D3).
- O3: `#[non_exhaustive]` on `Event` and `PeerStats` at enum / struct level only (D6).
- O4: `PeerStats::new` is added.
- O5: (a) packets queued for a handshake discarded on expiry without `Dropped`, and (b) path 1
  aborting a handshake started just before the 540 s mark, are follow-ups after 0.21.0:
  tasks `20261028-0611-expiry-queued-packets-dropped` and
  `20261028-0611-session-age-aborts-fresh-handshake`.

## Notes

Implementation (test first, on `feat/0.21.0-m3-removals` from `release/0.21.0` `bcb68f1`):
