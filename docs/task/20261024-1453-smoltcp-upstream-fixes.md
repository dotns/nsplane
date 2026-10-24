# 20261024-1453-smoltcp-upstream-fixes smoltcp fork: upstream TCP fixes since v0.14.0

- **status**: in progress (owner approved 2026-10-24: "修复smoltcp的fork然后测试一下当前的性能影响")
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-24 14:53
- **plan**: 20261024-1453-smoltcp-upstream-fixes

## Description

Upstream smoltcp `main` carries TCP fixes after `v0.14.0` that the fork (`v0.14.0-nsplane.6`) lacks or covers differently: `336a1dd` (window arithmetic underflow when a FIN arrives at a zero-window edge), `bd424c8` (retry a fast retransmission whose emit failed) and `bfe5f95` (RTO and zero-window probe timer interaction). The owner asked to fix the fork and measure the performance impact. The per-socket RTO bounds (`51c662c` and the two commits before it) are a new API and not part of this task.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
