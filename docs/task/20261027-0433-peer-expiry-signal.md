# 20261027-0433-peer-expiry-signal Peer-level connection expiry signal (design)

- **status**: completed (on `release/0.21.0` 2026-10-28; ships in 0.21.0, not yet tagged)
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

- Tests first. The noise and core behaviour tests were seen failing against API stubs
  (`Tunn::expiry_cause` returning `None`, the counter at 0, no suppression); the size test pins
  the values measured before the change; the e2e lagging test was written after the core
  change (it exercises the engine path, which needed no code of its own):
  - `nsplane-noise` `noise::tests`: `expiry_cause_is_none_on_a_fresh_tunnel_and_after_a_handshake`,
    `an_unanswered_initiation_expires_for_handshake_timeout`,
    `a_session_left_alone_expires_for_session_age`,
    `a_tunnel_without_a_session_expires_for_session_age`,
    `a_handshake_initiation_after_the_expiry_clears_the_cause` (4 of 5 failed before).
  - `nsplane-core` `tests/timers.rs`: the two existing expiry tests assert the cause and
    `expirations` (1; 2 over two episodes); new `a_never_contacted_peer_reports_no_expiry`
    (nothing at 541 s and 1141 s, `expirations == 0`; D2),
    `a_never_up_peer_reports_handshake_timeout_after_an_unreported_idle_expiry` (episode guard
    after a suppressed expiry; `expirations == 1`),
    `expirations_count_the_reported_expiries` (one episode per cause, unchanged by a completed
    handshake, the responder counts only its own), `peer_stats_after_an_expiry_count_it` (with
    `stats_interval` = one tick: the `PeerStats` right after the `SessionExpired` carries
    `expirations: 1`, every `PeerStats` counts the expiries before it; D4.2). 6 of 14 failed
    before.
  - `nsplane-core` unit: `output_size_is_unchanged_by_the_expiry_signal` (`Output` 96 bytes,
    `Event` 64, as measured on `bcb68f1`; D5).
  - `nsplane-e2e`: `timers.rs` `a_lagging_subscriber_reads_the_expiry_from_the_counter`
    (`event_capacity(1)`, the subscriber lags past the expiry, `peer_stats(..).expirations == 1`
    and the next periodic `PeerStats` carries it); `timers.rs` and `suspend.rs` assert
    `ExpiryCause::SessionAge` on the existing expiry checks; `uapi.rs` zeroes `expirations`.
- Compile changes of D6: `nsplane-uapi` test with `PeerStats::new`; core `batch.rs`,
  `tunnel_storage.rs` and e2e `uapi.rs` assign fields instead of `..base`;
  `examples/src/bin/events_stats.rs` prints the cause and `expirations` and has a wildcard arm.
- Deviations from the note: `Peer::handshakes_at_expiry` instead of `up: bool` (no store in
  `Core::authenticated`, `core/receive.rs` unchanged); a `ConnectionExpired` from the timers
  while the tunnel is not expired is not reported (see the note's owner-decision section).
