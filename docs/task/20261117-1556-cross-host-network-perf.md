# 20261117-1556-cross-host-network-perf Performance tests across systems and networks

- **status**: completed
- **priority**: P2
- **owner**: perf-net
- **createdAt**: 2026-11-17 15:56

## Description

Performance is measured on one Linux host over a docker network only. Extend the tests to
macOS and Windows hosts, to a real Wi-Fi link and to shaped links (delay, loss, reordering,
rate limit, held delivery), with an underlay baseline for every tunnel number, and add a
deterministic test for acknowledgements that arrive late and in clumps.

Origin: a consumer's report of Wi-Fi packet loss and a 10-minute 4 MiB transfer from a
macOS host. Verified on 2026-11-17: the loss figure is an artefact of an unpaced burst, the
nsplane tunnel is healthy on that link (205 to 540 Mbit/s TCP, no UDP loss at 300 Mbit/s),
and the slow transfer shows late, clumped acknowledgements rather than loss. Measurements
and plan: `docs/plan/20261117-1556-cross-host-network-perf.md`.

Acceptance: the plan's work items 1 to 7, each criterion of its section 3 either met or
filed as its own task, results in `docs/performance.md`.

## ActiveForm

Adding performance tests across systems and networks.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

2026-11-18: done but for the TUN row on Windows
(`20261118-2040-windows-tun-bench-row`) and CPU time across hosts. Tools:
`netstack_bench --bytes/--interval/--start-delay`, `net_probe`, `scripts/bench/netem.sh`,
`scripts/bench/cross-host.sh`, the in-process `netstack_held` and `netstack_jitter` tests.
Results in `docs/performance.md`, Shaped links and Across hosts and networks. Two failed
criteria became tasks `20261118-0001` and `20261118-0002` (both fixed), one is open
(`20261118-1832-timeouts-under-heavy-loss`).
