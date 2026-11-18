# 20261118-2040-windows-tun-bench-row A TUN throughput row on Windows

- **status**: pending
- **priority**: P3
- **owner**: (unassigned)
- **createdAt**: 2026-11-18 20:40

## Description

Left over from `docs/plan/20261117-1556-cross-host-network-perf.md`, work item 6. The
cross-host tables of `docs/performance.md` have a TUN row for macOS (`tun_node` on utun
against wireguard-go) and none for Windows: `nsplane-cli` and the `tun_node` example are
Unix programs, so nothing in the repository runs the engine on a Wintun adapter outside
`nsplane-tun`'s tests.

Needed: a Windows build of `tun_node` (adapter address and MTU through `netsh` or the IP
helper API, peers from the flags, no UAPI), `wintun.dll` and iperf3 on the test VM, and a
row measured as the macOS one. WireGuard for Windows as the reference only if it installs
without leaving a service on the VM.

Acceptance: a Windows row in `docs/performance.md`, Across hosts and networks, with TCP
throughput in both directions and UDP loss at 50 Mbit/s.
