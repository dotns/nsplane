# 20261026-0836-local-barrier-plaintext-ingress Engine local barrier and validated plaintext ingress

- **status**: completed
- **priority**: P2
- **owner**: w3/local-barrier-plaintext-ingress
- **createdAt**: 2026-10-26 08:36
- **relatedPlan**: 20261026-0822-node-gateway-requests

## Description

Release B workstream W3 of plan `20261026-0822-node-gateway-requests` (requests R4 and R5
part 1 of task `20261026-0819-node-gateway-requests`), with the owner's answers O6 (the
barrier now) and O7 (`from: Path` mandatory, no authenticated bookkeeping, bytes in
`data_rx`).

- R4: `EngineHandle::local_barrier` completes once every packet the engine took from its
  `PacketSource` before the call has been routed and passed or been dropped by the outbound
  filters (or dropped for no route, fragmentation or the tunnel queue); a stopped engine
  returns `EngineError` and never reports a barrier it did not pass.
- R5 part 1: `Core::receive_plaintext` runs a plaintext packet attributed to a peer through
  exactly the post-decryption checks of a data packet (source check, inbound destinations,
  `PacketFilter::inbound_from` in install order, delivery), sharing their code; unknown or
  removed peers are dropped as `UNKNOWN_PLAINTEXT_PEER`. The engine offers it as a bounded
  `PlaintextIngress` from `EngineBuilder::plaintext_ingress`.

Acceptance criteria:

- Tests first for every behaviour listed in the plan's W3 section (core verdict parity with
  a recording filter, unknown and removed peers, IPv4 and IPv6, no `Event::Authenticated`
  and no path change; ingress back-pressure, `try_send` refusal, stop; barrier with packets
  in the source queue, held by the source task, with the fragmenter and with crypto
  workers, ordering through a recording outbound filter, stop).
- Default paths unchanged in cost: slot A/B of `nsplane` `local_graph` and `nsplane-core`
  `data_path` (`core_round_trip/64`).
- Reference pages `docs/reference/nsplane.md` and `docs/reference/nsplane-core.md`, a
  `CHANGELOG.md` entry under Unreleased; full gate green.

## ActiveForm

Adding the engine's local barrier and validated plaintext ingress

## Dependencies

- **blocked by**: (none; the plan and O6, O7 were approved by the owner on 2026-10-26)
- **blocks**: (none)

## Notes

- 2026-10-26: implemented on branch `feat/local-barrier-plaintext-ingress` from `52eb983`.
  - Core: `Core::opened` / `Core::deliver_opened` split into the shared
    `Core::addresses_allowed` (source check, inbound destinations; the destination is read
    lazily as before) and `Core::deliver_filtered` (inbound filters, `data_rx`, delivery);
    `Core::receive_plaintext` calls both. A plaintext packet is read like decrypted data
    (`ip_source`: version, header, IP length, cut to it); one that is not a whole IPv4 or
    IPv6 packet is `SOURCE_NOT_ALLOWED` (the plan's proposed rule, extended to a length beyond
    the buffer). Unknown peers drop with `Some(peer)` in the event.
  - Engine: `read_source` adds each read's size to an `Arc<AtomicU64>` the handles share,
    before queueing; `local_barrier` reads it and sends `Command::LocalBarrier(position)`;
    the owner counts the packets `input_locals` took through the fragmenter and
    `handle_locals` / `handle_locals_deferred` and replies when it reaches the position (at
    once once the source closed). Stop drops the pending replies (`EngineError`).
    `PlaintextIngress` is a bounded `mpsc` polled in `poll_datagrams` (alternating with the
    datagram queue, under the deliver-room check), at most `MAX_BATCH` per turn.
  - Boundary of "taken": a packet counts once `recv_batch` returned it and the source task
    counted it, right after the read (no await in between). A consumer that observes its
    own source's hand-off could in principle call the barrier in the instant between the
    return and the count; the consumer's own source-side fence (no stale packet returned
    after the ownership change) plus the barrier bounds the window as the plan states.
  - `Owner::command` and `spawn` exceeded clippy's line limit: `replace_transport` and
    `InlineSink::new` were extracted unchanged; the new owner state is grouped in
    `Barriers` and `PlaintextQueue` (clippy's bool count).
  - Tests: 5 core unit tests (`core::tests::plaintext`), 10 e2e tests
    (`nsplane-e2e/tests/engine_entries.rs`). Two mutations (barrier replying at once; counting
    after queueing) are caught by the barrier tests. The tests poll the barrier future on the
    test thread: a spawned task woken by the owner sits in the held worker's LIFO slot.
  - `docs/architecture.md` (Data flow: the plaintext entry) is left to the integrator, who
    owns that file in this release.
- Slot A/B, 2026-10-26, `scripts/bench/slot.sh`, A = `52eb983`, B = this branch, criterion
  means of two interleaved rounds each:
  - `nsplane-core` `data_path` (slot 0, load 4.6-5.3): `core_round_trip/64` A 423.5 ns,
    B 423.3 ns (-0.0 %); `core_round_trip_batch32/64` 13.23 / 13.32 us (+0.7 %);
    `core_round_trip/1420` 1.252 / 1.251 us; `core_round_trip_batch32/1420` 40.04 /
    39.99 us. A first run (slot 1, load 4.6-6.4) with the destination slice computed
    eagerly read +3.2 % on `core_round_trip/64`; the destination is read lazily again, as
    on `main`, before the run above.
  - `nsplane` `local_graph` (slot 0, all 34 cases, load 3.7-21): pipe, pump and splitter
    within -4.8 % .. +1.9 %; `map_sink` / `swap_sink` showed +10-32 % in one B round only,
    in a contiguous window under a load spike. Re-run of those 20 cases in order B, A, B, A
    on a quiet host (load 1.0-1.7): -1.7 % .. +1.3 %. These cases do not run the changed code.
- Full gate `flock /tmp/nsplane-heavy.lock just check`: exit 0 (2362 tests passed, 34
  skipped; deny, shear, typos, MSRV, examples, product terms and docs clean);
  `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --all-features` clean. Earlier,
  under load, `nsplane` `udp::tests::burst_fits_default_buffer` and the `offload_udp`
  `bulk_transfer_*_on_workers` cases timed out on this branch and on `52eb983` alike.

- complete: local barrier and plaintext ingress implemented; gate green
