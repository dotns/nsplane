# 20261013-1330-snapshot-cell-read-cost Restore 0.12 read cost after the arc-swap removal

- **status**: completed
- **createdAt**: 2026-10-13 13:30
- **approvedAt**: 2026-10-13 (owner: optimize now that the host is quiet; a fix of a 0.13.0 regression, so
  allowed under the freeze)
- **relatedTask**: 20261012-1830-no-arc-swap (performance pass)

## Context

The quiet performance pass of 0.13.0 ran on 2026-10-13. A = v0.12.0, B = v0.13.0, interleaved, 3
rounds, slots 0/1, load 0.6-2.7 during gate/translate/data_path, up to 10.9 at the end of
namespaces. Logs are in `.tmp/perf-*.log`.

| Case | 0.12.0 | 0.13.0 | Delta | after (B = f33360d, vs 0.12.0 run) | Delta vs 0.12.0 (0.12.0 in that run) |
|---|---|---|---|---|---|
| namespaces `floor/snapshot` (one engine snapshot load) | 9.0 ns | 16.2 ns | +7.2 ns | 2.96 ns | -5.8 ns (8.79 ns) |
| gate `established/gate` | 50.1 ns | 55.2 ns | +10.2 % | 54.0 ns | +6.2 % (50.8 ns) |
| gate `established/filter` | 52.8 ns | 60.7 ns | +15.0 % | 55.5 ns | +3.8 % (53.5 ns) |
| gate `baseline/acl_established` | 36.7 ns | 44.5 ns | +21.3 % | 31.3 ns | -16.0 % (37.3 ns) |
| translate `eam4_out/udp/64B/1` | 43.3 ns | 49.4 ns | +14.0 % | 45.1 ns | +5.9 % (42.6 ns) |
| translate `eam4_in/udp/64B/1` | 58.0 ns | 64.6 ns | +11.5 % | 57.9 ns | +2.1 % (56.7 ns) |
| namespaces `other/icmp_echo_scope` | 39.6 ns | 51.1 ns | +29.1 % | 36.1 ns | -6.5 % (38.6 ns) |
| data_path (core; no cell) | 532.5 ns | 535.7 ns | +0.6 % (par) | not re-run (L1) | not re-run (L1) |

Every `SnapshotCell::load` (a shard read lock, an `Arc` clone, an unlock and a drop) costs about
7 ns more than arc-swap's load, and a packet loads one to three cells. The A spread is 0.2-1.9 %
on these rows. The IPv6 gate numbers (B only) are 53.6-109.0 ns.

## Results (OP)

B = f33360d (OP fix), M = main 89c939e (pre-LR, pre-LP), V12 = v0.12.0. Medians of 3 interleaved
rounds (A,B,A,B), ns; the A spread is (max - min) / min over A's rounds. Logs:
`/tmp/op3-bench-*.log`.

| # | Bench | A vs B | Slot | CPUs | Load start | Load end | Rounds | A spread (rows below) |
|---|---|---|---|---|---|---|---|---|
| 1 | acl gate | V12 vs B | 1 | 8-15 | 2.74 | 11.56 | 3 (B round 3 discarded) | 0.2-1.4 % |
| 2 | acl gate | M vs B | 0 | 1-7 | 15.42 | 2.78 | 3 | 0.5-12.7 % |
| 3 | acl namespaces | V12 vs B | 0 | 1-7 | 0.52 | 2.17 | 3 | 0.1-0.6 % |
| 4 | acl namespaces | M vs B | 0 | 1-7 | 0.65 | 1.01 | 3 | 0.0-1.0 % |
| 5 | nat translate | V12 vs B | 0 | 1-7 | 0.35 | 1.41 | 3 | 0.1-2.3 % |
| 6 | nat translate | M vs B | 0 | 1-7 | 0.47 | 1.24 | 3 | 0.0-0.6 % |
| 7 | core cell | M vs B | 0 | 1-7 | 0.22 | 2.89 | 3 | 31.8-47.4 % |
| 8 | core data_path | M vs B | - | - | - | - | not run: stopped by L2 (L1 decision) | - |

Invocation 1: a load spike to 11.08 hit B's round 3 (`established/gate` 112.2 ns), so B there is
the median of rounds 1-2. Invocation 2 started at load 15.42 (M's round 1); M's spread is up to
12.7 % there (`baseline/pass_filter`), and its IPv6 rows are not usable (spread 27-84 %).

Gate (invocations 1 and 2):

| Row | V12 | B | Delta | M | B | Delta |
|---|---|---|---|---|---|---|
| `established/filter` | 53.5 | 55.5 | +3.8 % | 60.9 | 55.0 | -9.7 % |
| `established/gate` | 50.8 | 54.0 | +6.2 % | 55.5 | 53.1 | -4.4 % |
| `established/outbound` | 50.8 | 53.9 | +5.9 % | 55.3 | 53.2 | -3.7 % |
| `baseline/acl_established` | 37.3 | 31.3 | -16.0 % | 45.2 | 30.6 | -32.3 % |
| `baseline/pass_filter` | 42.0 | 36.4 | -13.3 % | 50.0 | 35.9 | -28.3 % |
| `baseline/pass_gate` | 0.92 | 0.93 | +1.0 % | 0.55 | 0.91 | +66.7 % |
| `established/gate_v6` | - | 61.7 | - | 62.4 | 61.2 | -1.9 % |
| `established/outbound_v6` | - | 61.7 | - | 65.7 | 60.9 | -7.4 % |
| `established/extension_chain_v6` | - | 72.6 | - | 73.2 | 72.0 | -1.6 % |

Namespaces (invocations 3 and 4):

| Row | V12 | B | Delta | M | B | Delta |
|---|---|---|---|---|---|---|
| `floor/snapshot` | 8.79 | 2.96 | -5.8 ns | 15.8 | 2.93 | -12.9 ns |
| `default/inbound` | 50.3 | 44.4 | -11.6 % | 56.9 | 44.5 | -21.8 % |
| `default/inbound_established` | 49.7 | 43.7 | -12.1 % | 56.5 | 43.7 | -22.5 % |
| `default/outbound` | 80.8 | 76.2 | -5.7 % | 88.0 | 76.1 | -13.6 % |
| `default/outbound_source_scope` | 81.9 | 81.3 | -0.8 % | 89.5 | 81.4 | -9.1 % |
| `other/icmp_echo_scope` | 38.6 | 36.1 | -6.5 % | 47.8 | 36.2 | -24.3 % |
| `stateless/inbound` | 53.0 | 47.2 | -10.9 % | 60.2 | 47.2 | -21.6 % |
| `stateless/inbound_established` | 52.0 | 46.5 | -10.6 % | 60.0 | 46.4 | -22.6 % |
| `stateless/inbound_fragment` | 26.1 | 29.6 | +13.4 % | 26.9 | 29.6 | +10.1 % |

Translate (invocations 5 and 6; the `/1000` rows match the `/1` rows within 0.6 %):

| Row | V12 | B | Delta | M | B | Delta |
|---|---|---|---|---|---|---|
| `eam4_out/tcp/64B/1` | 42.4 | 45.1 | +6.6 % | 48.8 | 44.9 | -7.9 % |
| `eam4_out/udp/64B/1` | 42.6 | 45.1 | +5.9 % | 48.5 | 45.1 | -7.1 % |
| `eam4_out/tcp/1400B/1` | 80.9 | 87.1 | +7.7 % | 87.3 | 86.5 | -1.0 % |
| `eam4_out/udp/1420B/1` | 80.8 | 86.5 | +7.0 % | 87.4 | 86.6 | -0.9 % |
| `eam4_in/tcp/64B/1` | 56.6 | 58.1 | +2.6 % | 63.6 | 58.2 | -8.4 % |
| `eam4_in/udp/64B/1` | 56.7 | 57.9 | +2.1 % | 63.4 | 57.9 | -8.6 % |
| `eam4_in/tcp/1400B/1` | 79.6 | 79.4 | -0.2 % | 85.2 | 79.3 | -7.0 % |
| `eam4_in/udp/1420B/1` | 79.5 | 80.2 | +0.9 % | 85.0 | 80.0 | -5.9 % |

Cell (invocation 7; per round M / B):

| Row | M rounds | B rounds | M | B |
|---|---|---|---|---|
| `cell/load_1_thread` | 22.8 / 17.9 / 17.3 | 23.4 / 18.4 / 22.4 | 17.9 | 22.4 |
| `cell/load_8_threads` | 50.7 / 34.4 / 35.2 | 26.9 / 24.7 / 25.0 | 35.2 | 25.0 |
| `cell/read_1_thread` | - | 3.12 / 3.14 / 3.13 | - | 3.13 |
| `cell/read_8_threads` | - | 4.92 / 4.91 / 4.94 | - | 4.92 |
| `cell/read_4_cells_interleaved` | - | 3.14 / 3.16 / 3.14 | - | 3.14 |

`load_1_thread` is noisy on both sides (A spread 31.8 %): the earlier +0.8 ns of B over M is
neither confirmed nor ruled out.

Residuals (L1 decisions):

- Gate `established/gate`, `filter` and `outbound` are +3.4..6.7 % against 0.12.0 per round and
  4-10 % better than main. Attributed to the 0.13.0 peer-keyed gate (probable, not isolated).
- Translate `eam4_out` is +6..7 % against 0.12.0 at 64 B and 1420 B and is present on main at
  1420 B. Not caused by the cell; a probable dependency or codegen change, not isolated. Tracked in
  `docs/task/20261013-1600-perf-residuals.md`.
- `stateless/inbound_fragment` is +2.7 ns against main (B 29.6, M 26.9, V12 26.1). Fixed after
  the release by OP-4 (`tpy63es1`, 64b2dfa, a `move` closure in `AclFilter` inbound); its numbers
  are in the OP-4 report.

## Work (one L2)

1. Design note to L1. A cheaper read path in `nsplane_core::cell`, safe and std-only. The
   candidate is GF-4's `ScopeCell` pattern generalized:
   - a published generation (Acquire);
   - a small fixed-size per-thread cache keyed by a never-reused cell id;
   - a closure read that lends `&T` without a refcount or lock on a hit;
   - a fall back to the shard load on a miss or a nested borrow.
   The note covers:
   - the cache size, given that a packet touches several cells, and its eviction;
   - the bounded retention of old values per thread;
   - correctness ordering, which must not regress the guarantees of AS;
   - which call sites move to the closure read;
   - whether `ScopeCell` folds into it.
2. Implementation, unit tests (the existing cell tests plus several cells interleaved on one
   thread, nested reads, replace under load) and moving the hot call sites:
   - acl: engine snapshot, gate snapshot, filter scopes;
   - nat: translate, LAN routes.
3. Slot A/B against v0.12.0 and v0.13.0 of the rows above. The target is 0.12.0 par within
   max(2 %, spread).

## Annotations
- 2026-10-13: dispatched OP `gcxn1i1c` (campaign `nsplane-op-202610131330`).
- 2026-10-13: OP design note approved.
  - `SnapshotCell::read(|&T| ..)`: a published generation (Acquire), and a per-thread cache of
    4-8 entries keyed by a never-reused cell id that holds an `Arc<dyn Any>`. A hit costs no
    refcount and no lock; a miss loads the shard until the generation matches.
  - A writer mutex inside the cell makes concurrent stores safe.
  - Retention is bounded (at most 8 values per thread).
  - `ScopeCell` folds in.
  - The hot call sites in acl and nat move to `read`.
  - An e2e test checks replaces under traffic.
- 2026-10-13: OP A/B, invocations 1-4. B = f33360d.
  - Improvements:
    - `floor/snapshot` 8.8 -> 2.9 ns (0.12.0) and 15.8 -> 2.9 ns (main);
    - `icmp_echo_scope` -6.4 % against 0.12.0;
    - most filter and namespaces rows 5-15 % faster than 0.12.0.
  - Residuals:
    - `stateless/inbound_fragment` +2.7 ns against main. OP-4 fixes it (filter.rs, fragment early
      return).
    - Gate `established/*` +3.4..6.7 % against 0.12.0, but 4-10 % better than main. Accepted and
      attributed to the 0.13.0 peer-keyed gate (probable, not isolated).
- 2026-10-13: completed.
  - OP-1 and OP-2 shipped in 0.14.0 (`26f9c77`, release `b28d649`).
  - OP-3 added the results in this file. OP-4 fixed `stateless/inbound_fragment` after the
    release: a closure borrow made LLVM spill the key with narrow stores and reload it with a
    wider load, a store-forwarding stall. It is now 26.5 ns against 26.9 on main. The entry is
    in [Unreleased] for 0.14.1.
  - Other residuals: task `20261013-1600-perf-residuals`.
