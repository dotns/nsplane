# 20261013-1600-perf-residuals Performance residuals left after 0.13/0.14

- **status**: in_progress (PR-1, PR-2 fixed by OQ, released in 0.14.1; PR-3 profiled 2026-10-16, open)
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-13 16:00

## Description

Residuals found by the quiet slot A/B passes of 2026-10-13. Each was accepted and documented
when its campaign merged, and none is a correctness issue. Each item needs a bisect or a profile
before any fix.

| Item | What | Measured | Probable cause |
| --- | --- | --- | --- |
| PR-1 (closed by OQ, 2026-10-15: at or below 0.12.0) | nsplane-nat translate | on main (2026-10-14) against 0.12.0: `eam4_out` 64 B +1.4 %, 1420 B +2.8 %; `eam4_in` 64 B +2.6 %, 1420 B +5.1 % | bisected: GF is at par (-1.8..+0.7 %), AS adds +8.5..12.4 %, OP recovers most of it. The rest is the translator's cell reads (`read` with the predicate), not a dependency |
| PR-2 (closed by OQ, 2026-10-15: 13.5-19.8 % below 0.12.0) | nsplane-acl gate established path | `established/gate` +6.3 %, `outbound` +6.7 %, `filter` +2.7 % against 0.12.0 on main (2026-10-14) | NOT the gate rework: GF alone is at par or faster (-3.4 %). The cost comes with the AS cell (+10.5 % at fc91922) and only part of it is recovered by OP; the gate's per-packet `read`s cost more than arc-swap's loads did |
| PR-3 | nsplane-core routing with source sets | `core_round_trip_two_identities/64` 604.9 ns against 545 ns for one identity (+60 ns) | the LR selection step plus the per-identity source check with the merged trie; paid only when source sets exist; more than one trie lookup should cost |

Method: slot.sh, interleaved A/B, the quiet host rule; see docs/plan/20261013-1330-snapshot-cell-read-cost.md.

## Measurements, 2026-10-14

Four points, interleaved in one slot invocation per bench, 3 rounds, criterion medians. The load
was below 3 at each start (1.1-2.9) and the spreads were 0.1-2.7 %:
- v12 = v0.12.0;
- gf = daf76cf, GF merged;
- as = fc91922, AS merged;
- main = d8b5d14, with OP and OP-4.

| Row | v12 | gf | as | main |
|---|---|---|---|---|
| translate `eam4_out/udp/64B/1` | 43.66 | 42.86 | 49.09 | 44.27 |
| translate `eam4_out/udp/1420B/1` | 80.96 | 80.74 | 87.98 | 83.25 |
| translate `eam4_in/udp/64B/1` | 56.77 | 56.60 | 63.49 | 58.24 |
| translate `eam4_in/udp/1420B/1` | 79.35 | 79.90 | 86.11 | 83.38 |
| gate `established/gate` | 51.41 | 49.64 | 56.82 | 54.65 |
| gate `established/outbound` | 51.19 | 49.55 | 56.61 | 54.61 |
| gate `established/filter` | 54.12 | 54.38 | 62.36 | 55.57 |
| gate `baseline/acl_established` | 37.32 | 37.57 | 45.53 | 31.44 |
| namespaces `floor/snapshot` | 8.80 | 8.82 | 15.87 | 2.97 |
| namespaces `default/inbound` | 50.52 | 51.45 | 57.27 | 44.28 |
| namespaces `stateless/inbound_fragment` | 26.19 | 26.06 | 27.03 | 26.68 |

Conclusions:
- Every residual comes from the snapshot cell (AS), not from GF and not from a dependency.
- OP turned the ACL engine paths into wins, but the gate and translator paths keep 1-7 %.
- OP-4's fragment fix holds on main (26.68 ns against 27.03 in 0.13.0).
- Next step for PR-1/PR-2: profile the per-packet `read`s on the gate and translator paths
  (count of reads per packet, the cost of a TLS-cache hit against the arc-swap guard), and
  consider one read per packet or a lighter hit path.

## Results (OQ), 2026-10-15

V12 = v0.12.0; M = main 6339377 (main is now 660db1a, a `Cargo.lock`-only rustls bump; rustls is
not in the dependency graph of nsplane-nat, nsplane-acl or nsplane-core); B = this branch with
OQ-2 (c7e8561, 3cef768). One slot invocation per bench, the three points interleaved (V12, M, B
x 3 rounds), default criterion settings, ns, medians of the 3 round medians. Spread is
(max - min) / min over a point's rounds. Target: PR-1 and PR-2 rows within max(2 %, V12 spread)
of V12; the OP wins (`floor/snapshot`, `baseline/acl_established`, `default/inbound`) within
max(2 %, M spread) of M. Logs: `.tmp/oq3-*.log` in the OQ-3 worktree (not committed).

| # | Bench | Points | Slot | CPUs | Load start | Load end | Rounds | Spread (rows below) |
|---|---|---|---|---|---|---|---|---|
| 1 | core cell (hit row) | V12, M, B | 0 | 1-7 | 2.56 | 2.02 | 3 | 0.3-1.3 % |
| 2 | nat translate | V12, M, B | 0 | 1-7 | 1.15 | 21.70 | discarded | B round 3 up to 84 % |
| 3 | nat translate (re-run of 2) | V12, M, B | 0 | 1-7 | 1.18 | 1.40 | 3 | 0.2-5.2 % |
| 4 | acl gate | V12, M, B | 0 | 1-7 | 2.85 | 3.97 | 3 | 0.4-4.5 % (`pass_gate` M 10.9 %) |
| 5 | acl namespaces | V12, M, B | 0 | 1-7 | 1.58 | 1.68 | 3 | 0.3-4.7 % |

Invocation 2: a load spike (load 21.7 at the end) hit B's round 3 (`eam4_out/tcp/1400B` 140.6
ns), so it was discarded and run once more (3). Invocation 4: the load was 4.86 at B's round 3
(below 6); `baseline/pass_gate` (sub-ns) has M at 0.99 ns in round 3. The largest spreads in 3
and 5 are single rounds (M `eam4_in/udp/64B` 61.0 ns, B `default/outbound` 78.2 ns).

Cell read hit (invocation 1). M and B: `cell/read_1_thread` of crates/nsplane-core/benches/cell.rs
(`SnapshotCell<u64>::read(|v| *v)` of an unchanged value on one thread). V12: a scratch criterion
bench in a v0.12.0 worktree (not committed; arc-swap 1.9.2 and criterion 0.8.2 from v0.12.0's
`Cargo.lock`, `--locked`) that does `ArcSwap::<u64>::load()` on an unchanged value, derefs the
guard to the `u64` (`black_box(**guard)`) and drops the guard, on one thread.

| Row | V12 | M | B | B vs V12 | B vs M | Target (B not slower than M) |
|---|---|---|---|---|---|---|
| `cell read hit` | 9.23 | 3.14 | 2.97 | -67.8 % | -5.4 % | met |

Translate (invocation 3):

| Row | V12 | M | B | B vs V12 | B vs M | Target |
|---|---|---|---|---|---|---|
| `eam4_out/tcp/64B/1` | 42.52 | 43.96 | 39.15 | -7.9 % | -11.0 % | met |
| `eam4_out/udp/64B/1` | 43.09 | 44.59 | 39.39 | -8.6 % | -11.7 % | met |
| `eam4_out/tcp/1400B/1` | 81.53 | 81.70 | 81.05 | -0.6 % | -0.8 % | met |
| `eam4_out/udp/1420B/1` | 82.00 | 81.56 | 81.75 | -0.3 % | +0.2 % | met |
| `eam4_in/tcp/64B/1` | 57.04 | 58.59 | 53.00 | -7.1 % | -9.6 % | met |
| `eam4_in/udp/64B/1` | 56.81 | 58.05 | 52.19 | -8.1 % | -10.1 % | met |
| `eam4_in/tcp/1400B/1` | 80.60 | 84.74 | 76.07 | -5.6 % | -10.2 % | met |
| `eam4_in/udp/1420B/1` | 79.53 | 83.74 | 74.90 | -5.8 % | -10.6 % | met |

Gate (invocation 4):

| Row | V12 | M | B | B vs V12 | B vs M | Target |
|---|---|---|---|---|---|---|
| `established/gate` | 50.31 | 54.19 | 40.34 | -19.8 % | -25.6 % | met |
| `established/outbound` | 50.41 | 54.47 | 40.57 | -19.5 % | -25.5 % | met |
| `established/filter` | 52.85 | 55.27 | 45.73 | -13.5 % | -17.3 % | met |
| `baseline/acl_established` | 36.84 | 31.03 | 30.19 | -18.1 % | -2.7 % | met |
| `baseline/pass_filter` | 41.22 | 36.04 | 35.46 | -14.0 % | -1.6 % | - |
| `baseline/pass_gate` | 0.90 | 0.90 | 0.80 | -10.8 % | -10.9 % | - |

Namespaces (invocation 5):

| Row | V12 | M | B | B vs V12 | B vs M | Target |
|---|---|---|---|---|---|---|
| `floor/snapshot` | 8.79 | 2.95 | 3.10 | -64.8 % | +5.0 % | not met (+0.15 ns against M, every B round 3.08-3.12, M 2.94-2.97); accepted by L1 (2026-10-15) |
| `default/inbound` | 50.56 | 44.06 | 44.22 | -12.5 % | +0.4 % | met |
| `default/outbound` | 81.83 | 75.86 | 74.84 | -8.5 % | -1.3 % | - |
| `other/icmp_echo_scope` | 38.70 | 36.44 | 37.16 | -4.0 % | +2.0 % | - |
| `stateless/inbound_fragment` | 26.15 | 26.72 | 27.07 | +3.5 % | +1.3 % | - |

`floor/snapshot` is the one row that misses its target (+0.15 ns against M, still -64.8 % against
V12); L1 accepted it as an explained residual on 2026-10-15 (see Annotations).

Conclusions:
- PR-1: every translate row is at or below V12 (-0.3 to -8.6 %) and below M except
  `eam4_out/udp/1420B` (+0.2 %, within M's 2.8 % spread). Target met.
- PR-2: `established/gate`, `outbound` and `filter` are 13.5-19.8 % below V12. Target met.
- Cell hit: B 2.97 ns against M 3.14 ns (-5.4 %) and V12's arc-swap guard 9.23 ns.
- OP wins against M: `baseline/acl_established` -2.7 % and `default/inbound` +0.4 % hold;
  `floor/snapshot` is +5.0 % (3.10 against 2.95 ns), outside M's 1.2 % spread; accepted by L1
  (2026-10-15).

Data path (L2, after OQ-3). A = main 660db1a; B = `bkd/ybrk0a5w` a6bac13 (code identical to
0f96d37). One slot invocation, the two points interleaved (A, B x 3 rounds), criterion medians.
Reference: the 0.10.0 numbers (530 ns for 64 B, 1.334 us for 1420 B).

| # | Bench | Points | Slot | CPUs | Load start | Load end | Rounds | Spread (A) |
|---|---|---|---|---|---|---|---|---|
| 6 | core data_path | A, B | 0 | 1-7 | 2.44 | 1.61 | 3 | 0.4-0.6 % |

| Row | A rounds | A | B rounds | B | B vs A | B vs 0.10.0 |
|---|---|---|---|---|---|---|
| `data_path/core_round_trip/64` (ns) | 533.33 / 535.39 / 535.39 | 535.39 | 535.12 / 531.80 / 536.43 | 535.12 | -0.05 % (par) | +1.0 % |
| `data_path/core_round_trip/1420` (us) | 1.3444 / 1.3358 / 1.3379 | 1.3379 | 1.3324 / 1.3354 / 1.3404 | 1.3354 | -0.2 % (par) | +0.1 % |

Conclusion: the core data path (no cell on the path) is at par; no regression beyond noise.

## PR-3 profile, 2026-10-16

0.14.1 (de521e5), slot 0 (CPUs 1-7), load 2.2 at start; criterion medians of one invocation and a
`perf record -g` of each case (`ai-agent/nstun-perf`, 10 s profile time):

| Case, 64 B | Time | Trie lookups per packet |
|---|---|---|
| `tunn_round_trip` | 373.4 ns | 0 |
| `device_equivalent_round_trip` | 471.6 ns | 2 |
| `core_round_trip` | 527.9 ns | 2 (destination on send, source on receive) |
| `core_round_trip_two_identities` | 593.5 ns | 3 (plus the source set on send) |

- One allowed-IP lookup (`ip_network_table` tree bitmap `longest_match`) costs about 49 ns:
  the two lookups of `device_equivalent_round_trip` add 98 ns to the bare round trip.
- perf: `longest_match` is 23.6 % of `core_round_trip` (~125 ns, two lookups) and 28.8 % of the
  two-identity case (~171 ns, three lookups). Seal and open are 56 % and 50 %.
- So PR-3's +66 ns is the extra source-set lookup on send (~49 ns) plus ~15 ns of the
  identity selection and the owner lookup of `PeerTable::routes_to` on receive (peer binary
  search, identity, then its trie). It is the cost of the feature, not a defect.
- `Lookups` caches a route only within one batch, and `route_from` looks the source set up
  before its cache check, so a batch of one flow still pays the source lookup per packet.
  Keying `selected_route` on (source, destination) would skip it within a batch; it does not
  help single-packet calls.
- The larger cost is the lookup itself in every case: ~49 ns per lookup, two per round trip,
  about 9 % of the per-packet budget at 64 B. A faster longest-prefix match or a per-flow
  cache would help all configurations, not only source sets.

## Annotations

- 2026-10-14, OQ design note (OQ-1 ou76wjbz): option B approved. Single call site for `f` with a
  per-thread `Rc<Lent<T>>` on a hit. Conditions: (1) wording "no lock and no atomic reference
  count (one thread-local, non-atomic count)" in cell.rs docs and architecture.md, with the
  retention "at most 8 cached values per thread, plus one per read in progress on the stack";
  (2) TDD tests for nested-read cache fill, eviction under 9+ inner reads with the outer &T
  valid, and a Drop that reads a cell; (3) OQ-3 adds a `cell read hit` micro row for v0.12.0,
  main and the branch, and the Rc version must not lose on the hit; (4) codegen check that the
  gate and translator bodies are inlined again; (5) scope cell.rs, its tests, the docs and
  CHANGELOG only.
- 2026-10-15, L1 decision: option A. `floor/snapshot` +0.15 ns (+5 % against main, -65 % against
  v0.12.0) is an explained residual: the cost of the thread-local, non-atomic `Rc` increment and
  decrement around the single call site, on a closure that only reads one value. Every per-packet
  path is at or below v0.12.0, and the cell hit row is faster than main. No further work.
