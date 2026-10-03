# 20261003-1215-traffic-status Engine status snapshot and per-transport traffic counters

- **status**: completed
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-03 12:15

## Description

Every counter of the engine is reachable, but only one call at a time (`peers`,
`drop_counters`, `queue_stats`, `fragment_stats`), and traffic is split by peer only. Add:

1. `TransportStats` per installed transport: datagrams and bytes received, datagrams and bytes
   the transport was done with on the send side, and how many of those failed. Counted by the
   transport's own receive and transmit tasks (relaxed atomics, one update per batch, no
   owner-task work); kept across `replace_transport` (same id), gone with `remove_transport`.
   `EngineHandle::transport_stats()`.
2. `EngineHandle::status()`: one owner-task call returning `EngineStatus` (public key, MTU,
   suspended, peers, transports, drop counters, queue stats, fragment stats), so a report is a
   consistent snapshot.

Out of scope (user decision 2026-10-03, recommendation accepted): rates, metrics export and
the direct-vs-relay view stay in ns (ns maps transport ids and paths to its own labels and
exports through the ns-shared `telemetry` names). No new dependencies.

## Acceptance

- e2e (`nsplane-e2e`): traffic over two transports shows matching per-transport counters on
  both engines; counters survive `replace_transport` and disappear with `remove_transport`;
  a failing transport counts its failed datagrams; `status()` agrees with the single calls.
- just check, cross, test-windows, cargo doc -D warnings; data_path bench no regression.

## ActiveForm

Adding the engine status snapshot and per-transport counters

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
- **related**: 20261002-1509-phase1-followups

## Notes
2026-10-03: done. `TransportStats` / `EngineHandle::transport_stats` and `EngineStatus` /
`EngineHandle::status`; covered by `nsplane-e2e`'s `traffic` tests
(`transports_count_what_peers_send_and_receive`, `counters_survive_replace_and_leave_with_remove`,
`failed_sends_are_counted_on_their_transport`, `status_agrees_with_the_single_calls`). Gate (913
tests, cross, test-windows, cargo doc), linux.sh and lib.sh green.
