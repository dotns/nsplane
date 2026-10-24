# 20261024-1453-smoltcp-upstream-fixes smoltcp fork: rebase onto upstream main and reapply the fork patches

- **status**: in progress (merged into main 51eccd7; fork tag `v0.14.0-nsplane.7`; ships with the next release)
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-24 14:53
- **plan**: 20261024-1453-smoltcp-upstream-fixes

## Description

Upstream smoltcp `main` (`24bda3b`) is 16 commits past `v0.14.0`, the base of the fork
(`v0.14.0-nsplane.6`): TCP fixes (`336a1dd` window underflow on a FIN at a zero-window edge,
`bd424c8` fast retransmission retry, `bfe5f95` RTO and zero-window probe timers), per-socket
RTO bounds (`51c662c` and the two commits before it), MLD behind the `multicast` feature and
a Cubic `no_std` fix. The owner asked to sync the fork with the full upstream `main`, reapply
the fork's patches on top, include the per-socket RTO bounds, and measure the performance
impact.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- TCP send microbenchmarks are about 1-2 % slower on `.7` (reproducible; not caused by the
  Cubic change; end-to-end throughput unchanged). Accepted by L1.
