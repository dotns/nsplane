# 20261027-0433-post-freeze-schedule Schedule of the follow-ups the 0.11 freeze left open

- **status**: implementing
- **createdAt**: 2026-10-27 04:33
- **approvedAt**: 2026-10-27 (owner: "三个都同意" — the coarse clock with millisecond expiry, the
  peer expiry signal in 0.21.0 with `Event` / `PeerStats` made `#[non_exhaustive]`, and this
  plan with BKD issues)
- **relatedTask**: 20261027-0433-sink-spent-forwarding, 20261027-0433-filter-coarse-clock,
  20261027-0433-peer-expiry-signal, 20261028-0615-remove-wss-stream-carrier,
  20261028-0615-remove-transparent-admission, 20261028-0611-expiry-queued-packets-dropped,
  20261028-0611-session-age-aborts-fresh-handshake

## Goal

Schedule the follow-ups that waited during the freeze (ADR `2026-10-27-normal-maintenance`) by
release, so additive work ships early and breaking changes ship together in one minor release.

## Schedule

| Release | Item | Kind | Task |
| --- | --- | --- | --- |
| 0.20.1 | M1: wrapper sinks forward `PacketSink::send_batch_spent` | additive | 20261027-0433-sink-spent-forwarding |
| 0.20.1 | M2: `AclFilter` reply allowances and `AclEngine` default on the coarse clock | behavior (expiry granularity) | 20261027-0433-filter-coarse-clock |
| 0.21.0 | M3: peer-level connection expiry signal; `Event` and `PeerStats` `#[non_exhaustive]` | breaking | 20261027-0433-peer-expiry-signal (owner decided O1-O5 2026-10-28; released in 0.21.0) |
| 0.21.0 | Release C of plan `20261026-0822-node-gateway-requests` (packet tag carrier) | breaking | that plan; released in 0.21.0 |
| 0.21.0 | Remove the deprecated `WsFrame` stream carrier and `TransparentConfig::admission` | breaking | 20261028-0615-remove-wss-stream-carrier, 20261028-0615-remove-transparent-admission (released in 0.21.0) |
| after 0.21.0 | M3 follow-ups O5: packets an expiry discards are not reported; the idle expiry can abort a fresh handshake | to decide | 20261028-0611-expiry-queued-packets-dropped, 20261028-0611-session-age-aborts-fresh-handshake |
| after 0.21.0 | Netstack SACK: a 1-2 day study of netstack against kernel TCP under loss before any fork work; with it the next smoltcp fork round (vectorized `checksum::data`, the advertised window edge) | study | not opened |
| on request | NG-6 hub measurement support; `EngineHandle::recycle` | additive | not opened: nsgw measures L4 itself; no consumer that does not produce has asked |
| not pursued | Length without zero-fill in `nsplane-packet` | needs `unsafe` | conflicts with `#![forbid(unsafe_code)]` |

## Work

### M1 wrapper sinks forward `send_batch_spent`

`AbortSink`, `MapSink`, `SwapSink`, `Splitter` (and `Nat64LanSink`) keep the trait default, which
appends nothing, so a TUN sink under one of them never returns its written buffers and the
recycle loop of `pump` stays open. Each forwards to its inner sink(s) with the same contract as
its `send_batch`: `MapSink` maps and removes dropped packets first (a dropped packet's buffer may
be appended to `spent`), `AbortSink` races the inner call and counts aborted packets as today,
`SwapSink` forwards to the current sink, `Splitter` to each target. Verify: a unit test per
wrapper over a sink that appends; `nsplane-e2e` `recycle_loop` with a wrapped `TunSink` shows no
fresh allocation after warm-up; `local_graph` `pump/*` A/B unchanged on the default path.

### M2 coarse clock in the filter

The flow gate already reads the coarse monotonic clock (`gate/clock.rs`; `CLOCK_MONOTONIC_COARSE`
on Linux and Android, `Instant::now` elsewhere). `AclFilter` still calls `Instant::now` for every
reply allowance hit and record (`filter/cache.rs`, `filter/replies.rs`), and `AclEngine::new`
defaults to `Instant::now`. Move the clock to a crate-level module, use it in both, and document
the granularity (one scheduler tick, 1-4 ms) next to `reply_idle_timeout` and the engine clock.
Owner decision: millisecond expiry granularity is accepted. Verify: the existing expiry tests on
a manual clock; `gate` / `namespaces` A/B through `slot.sh` (expected: `established/filter`,
`bypass/*`, `stateless/*` lower).

### M3 peer-level connection expiry signal (design for 0.21.0)

A consumer sees a peer whose session expired (`CONNECTION_EXPIRED` in `nsplane-noise` timers,
now logged at debug) only by polling handshake ages. Design an `Event` variant and/or a
`PeerStats` counter, and make `Event` and `PeerStats` `#[non_exhaustive]` in the same release so
later additions are not breaking. Output: a design note under `docs/plan/notes/` with the
migration example for the CHANGELOG `#### Breaking` entry; implementation is scheduled with
release C.

## Constraints

- Normal maintenance (ADR `2026-10-27-normal-maintenance`): breaking changes are called out in
  the proposal and the CHANGELOG and ship in a minor release.
- No new dependency. Gate per merge: `just check`, `cargo doc -D warnings`, `just cross`,
  `just test-windows`; data-path changes add a `slot.sh` A/B.
