# 20261026-0838-first-input-flow-control Netstack flow control from the first input

- **status**: completed (released in 0.20.0)
- **priority**: P1
- **owner**: w1/first-input-flow-control
- **createdAt**: 2026-10-26 08:38
- **plan**: 20261026-0822-node-gateway-requests (W1, request R1)

## Description

Under `Admission::Decide` the consumer gets a `FlowControl` for one connection or flow
lifetime at its first input (bare SYN, first UDP datagram), through `PendingFlow::control`.
Revoking it at any stage (held, accepted before the next driver turn, SYN-received,
established and waiting for `incoming_tcp`, in the accept channel) retires the lifetime and
no handle of it is delivered afterwards; the delivered handle carries the same control.
Every lifetime ends with exactly one `DeliveryOutcome` (delivered, or not delivered with an
`Undelivered` reason) on a `DeliveryReceipt`. `RetirementOutcome` keeps its meaning.
Admission moves to a top-level `NetStackConfig::admission` that also applies to ordinary
stacks; `TransparentConfig::admission` is deprecated and still honoured.

Owner decisions: O1 top-level admission with the transparent field deprecated; O2 a revoke
before the hand-out sends nothing; O3 the delivery receipt covers `Decide` lifetimes, other
handles report `Delivered` at once.

Acceptance criteria:

- Unit tests for every stage x revoke, every `Undelivered` reason, the hand-out race
  (multi-thread runtime), same tuple after a revoke, an ordinary stack with `Decide`
  (TCP and UDP) and a context bound on the pending control seen on the handle.
- An `nsplane-e2e` test through two engines: revoke at each stage, no handle and no packet
  of a revoked lifetime leaves the stack.
- `Immediate` stacks unchanged; slot A/B of `send_stream` (`netstack_send`,
  `netstack_udp_send` including `flows_4`) within noise.
- Reference page, `CHANGELOG.md` `Added`; full gate green.

## ActiveForm

Implementing netstack flow control from the first input

## Dependencies

- **blocked by**: (none; approved 2026-10-26 as part of release B)
- **blocks**: (none)

## Notes

- Lifetime state: `FlowState` is created at the hold (`FlowState::held`), its target bound
  once by the driver (the listener socket at SYN-RECEIVED, the flow entry at accept); the
  delivery stage is one `AtomicU8` fixed by compare-and-swap (`deliver` at the stream,
  `undeliver(reason)` at the first terminal event, the revoke included). Rejection, timeout
  and connection-limit answers are sent only when the driver wins that swap, so a
  concurrent revoke never ends `Revoked` with an answer sent.
- Retirement per stage: held entry removed; accepted SYN dropped in `take_decisions` when
  revoked; SYN-RECEIVED socket removed without RST plus TCP fence from the socket's start
  mark; connection removed from `waiting`; the flow entry; a reassembly barrier from the
  held tuple. A SYN refused by the pool after a concurrent revoke has smoltcp's RST purged.
- `tcp_egress_drained` rejects a lifetime without a connection (adopted flag), as the plan
  states.
- An accepted UDP lifetime opens in the flow table directly (no socket precedence), so the
  lifetime always maps to one `UdpFlow`.
- Stop: `Pending` keeps weak references to open lifetimes, pruned on doubling; the driver's
  drop ends them `Stopped` before its fields drop.
- Out-of-scope files touched only to migrate off the deprecated field: the
  `dns_netstack` example, `nsplane-e2e` `netstack_transparent.rs` and the guide snippets
  (English and Chinese).
- Slot A/B, `cargo bench -p nsplane-netstack --bench send_stream`, default configuration,
  A = 52eb983, B = this branch, interleaved A,B,A,B per `scripts/bench/slot.sh`, means in
  ms (TCP) and us (UDP):

  | Case | Run 1 A | Run 1 B | Run 2 (round 2) A | B | Run 4 A (3 rounds) | B |
  | --- | --- | --- | --- | --- | --- | --- |
  | `netstack_send/streams_1` | 3.273, 3.263 | 3.243, 3.260 | 3.294 | 3.240 | | |
  | `netstack_send/streams_4` | 2.086, 2.441* | 2.050, 2.062 | 2.038 | 2.012 | | |
  | `netstack_udp_send/flows_1` | 563.6, 564.4 | 566.2, 571.6 | 570.9 | 563.6 | 594.6, 583.3, 597.6 | 579.2, 592.7, 585.2 |
  | `netstack_udp_send/flows_4` | 474.3, 480.6 | 477.0, 475.7 | 482.0 | 471.4 | 491.8, 527.0*, 486.2 | 491.0, 483.4, 481.1 |

  Run 1 measured the implementation commit, runs 2-4 the final head (run 2's round 1, at
  load 6-7, and run 3, at load 12-39, were discarded). `*`: outliers with wide intervals,
  seen on either side. Within noise; no regression on the default path.
- Gate: `just check` exit 100 on two tests outside this change
  (`nsplane udp::tests::burst_fits_default_buffer`,
  `nsplane-e2e offload_udp bulk_transfer_ipv6_offload_on_on_workers`, both 5 s timeouts on
  kernel loopback UDP); they fail identically on 52eb983 on this host. Every other test
  (2367) and every other recipe (fmt, clippy, doc-test, deny, shear, typos, msrv, examples,
  product-terms, docs) passes; `cargo doc` with warnings denied passes. `just cross` was
  not run: `cargo-zigbuild` is not installed on this host.

- complete: implemented on feat/first-input-flow-control; merges last in release B
- Follow-up (owner decision: 0.20.0 is breaking for both structs): `NetStackConfig` and
  `NetStackStats` are `#[non_exhaustive]`. Callers outside the crate build from
  `NetStackConfig::new` / `Default::default()` and assign fields; no builder or new
  constructor was needed. Call sites changed outside the W1 write scope (approved for these
  mechanical changes): `nsplane-e2e` tests `netstack_buffers`, `netstack_flow_retirement`,
  `netstack_multistream`, `netstack_fragment_admission`, `netstack_progress`,
  `netstack_reassembly`, `netstack_transparent`; `examples/tests/vm_wireguard.rs`;
  `docs/guide.md`, `docs/guide.zh-CN.md`. Inside scope: `config.rs` (doc tests), `stats.rs`,
  `tests/tcp_pipeline.rs`, e2e `netstack_first_input`, the reference page, `CHANGELOG.md`.
- `cargo semver-checks check-release -p nsplane-netstack --baseline-rev 52eb983`
  (0.51.0): "semver requires new major version", one failed lint
  `struct_marked_non_exhaustive` on both structs (it has no lint for the fields added to
  the formerly exhaustive structs).
- Gate on fddd325: `just check` exit 100 at `test`, 2366 passed, 3 failed: the two known
  host failures plus `offload_udp bulk_transfer_ipv4_offload_on_on_workers`. All three are
  kernel loopback UDP 5 s timeouts in crates this branch does not change; the two
  `offload_on_on_workers` tests interleaved branch/base over 4 rounds passed 1 of 8 on each
  side. fmt and clippy passed before `test`; doc-test, deny, shear, typos, msrv, examples,
  product-terms and docs pass (exit 0); rustdoc with warnings denied passes.
- Other exhaustive public types with the same exposure: `TransparentConfig`,
  `FlowEventsConfig`, the enum `PendingProtocol`, and the re-exported `ReassemblyConfig`
  (defined in `nsplane-packet`).
- Second follow-up (owner decision): `TransparentConfig`, `FlowEventsConfig` and
  `PendingProtocol` are `#[non_exhaustive]` too, with rustdoc examples (default-then-assign;
  a wildcard arm for `PendingProtocol`); `ReassemblyConfig` stays as it is. No exhaustive
  match on `PendingProtocol` existed outside the crate. Call sites changed outside the W1
  write scope: `nsplane-e2e` `netstack_transparent.rs` (an `in_prefixes` helper),
  `examples/src/bin/dns_netstack.rs`, `examples/tests/vm_wireguard.rs`, `docs/guide.md`,
  `docs/guide.zh-CN.md`. Inside scope: `config.rs`, `events.rs`, `pending.rs`, the reference
  page, `CHANGELOG.md` (the Breaking entry names all five types, with a `match` migration).
- `cargo semver-checks` against 52eb983: major; `enum_marked_non_exhaustive`
  (`PendingProtocol`) and `struct_marked_non_exhaustive` (`NetStackConfig`,
  `TransparentConfig`, `FlowEventsConfig`, `NetStackStats`).
- Gate on 00a8704: `just check` exit 0, 2369 of 2369 tests passed (the three host-flaky
  UDP tests passed in this run), every recipe through `docs` green.
