# 20261027-0433-peer-expiry-signal Peer-level connection expiry signal (design)

- **status**: pending
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
