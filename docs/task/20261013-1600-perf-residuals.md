# 20261013-1600-perf-residuals Performance residuals left after 0.13/0.14

- **status**: in_progress (PR-1, PR-2: L2 OQ `ybrk0a5w`, campaign `nsplane-oq-202610142230`, 2026-10-14; target 0.14.1)
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-13 16:00

## Description

Residuals found by the quiet slot A/B passes of 2026-10-13. Each was accepted and documented
when its campaign merged, and none is a correctness issue. Each item needs a bisect or a profile
before any fix.

| Item | What | Measured | Probable cause |
| --- | --- | --- | --- |
| PR-1 | nsplane-nat translate | on main (2026-10-14) against 0.12.0: `eam4_out` 64 B +1.4 %, 1420 B +2.8 %; `eam4_in` 64 B +2.6 %, 1420 B +5.1 % | bisected: GF is at par (-1.8..+0.7 %), AS adds +8.5..12.4 %, OP recovers most of it. The rest is the translator's cell reads (`read` with the predicate), not a dependency |
| PR-2 | nsplane-acl gate established path | `established/gate` +6.3 %, `outbound` +6.7 %, `filter` +2.7 % against 0.12.0 on main (2026-10-14) | NOT the gate rework: GF alone is at par or faster (-3.4 %). The cost comes with the AS cell (+10.5 % at fc91922) and only part of it is recovered by OP; the gate's per-packet `read`s cost more than arc-swap's loads did |
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
