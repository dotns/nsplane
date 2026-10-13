# 20261013-1600-perf-residuals Performance residuals left after 0.13/0.14

- **status**: pending (measured residuals to investigate; not scheduled)
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-13 16:00

## Description

Residuals found by the quiet slot A/B passes of 2026-10-13. Each was accepted and documented
when its campaign merged, and none is a correctness issue. Each item needs a bisect or a profile
before any fix.

| Item | What | Measured | Probable cause |
| --- | --- | --- | --- |
| PR-1 | nsplane-nat translate outbound | `eam4_out/*` +6..7 % against 0.12.0 at 64 B and 1420 B (inbound at par); present on main 89c939e at 1420 B before the cell fix | a dependency (nsplane-packet or nsplane-core buffers) or codegen change between v0.12.0 and 89c939e; nsplane-nat itself changed only in the AS commit. Bisect v0.12.0..89c939e on `eam4_out/udp/1420B/1` |
| PR-2 | nsplane-acl gate established path | `established/gate`, `filter` and `outbound` +3.4..6.7 % against 0.12.0 after the cell fix | the 0.13.0 peer-keyed, family-generic gate (GF); not isolated |
| PR-3 | nsplane-core routing with source sets | `core_round_trip_two_identities/64` 604.9 ns against 545 ns for one identity (+60 ns) | the LR selection step plus the per-identity source check with the merged trie; paid only when source sets exist; more than one trie lookup should cost |

Method: slot.sh, interleaved A/B, the quiet host rule; see docs/plan/20261013-1330-snapshot-cell-read-cost.md.
