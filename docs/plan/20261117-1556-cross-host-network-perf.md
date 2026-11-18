# 20261117-1556-cross-host-network-perf Performance tests across systems and networks

- **status**: completed
- **createdAt**: 2026-11-17 15:56
- **approvedAt**: 2026-11-18
- **relatedTask**: 20261117-1556-cross-host-network-perf

## Context

Every number in `docs/performance.md` comes from one Linux x86-64 host: two containers on a
docker network (`scripts/bench/wg-compare.sh`), Criterion benches, and in-process engine
pairs (`nsplane-e2e`: `netstack_lossy`, `netstack_buffers`, `latency`). Nothing is measured
on macOS or Windows, over a real link, or over a shaped link (delay, reordering, rate limit,
delayed delivery).

A consumer reported, for a macOS host on Wi-Fi and a Linux host on the same LAN: 19.9 % and
8.7 % "path loss", and a 4 MiB transfer from the Mac that took 591 to 655 s over a direct
UDP path while the other direction took 1.6 to 35.9 s. Checked on 2026-11-17 against the
same two hosts (Wi-Fi 11ax, 5 GHz, 80 MHz, RSSI -49 dBm), nsplane 0.23.0:

| Measurement | Mac -> Linux | Linux -> Mac |
|---|---|---|
| Raw UDP, 3227 x 1300 B unpaced (the reported probe), two runs | 37.7 %, 9.5 % loss | 87.9 %, 61.4 % loss |
| Raw UDP, 500 Mbit/s paced | 0.3 % | 21.1 % |
| Raw UDP, 200 Mbit/s paced | 0 % | 12.9 % |
| Raw UDP, 50 Mbit/s paced | 0 % | 1.5 % |
| Raw UDP, 10 Mbit/s paced | 0 % | 0 % |
| Ping, 50 ms interval, avg / max | | 2.8 / 38 ms |
| Ping, 0.5 s and 1 s interval, avg / max | | 50 to 55 / 112 ms |
| Tunnel (`netstack_bench`), TCP 1 stream, 10 s, each run | 205, 389, 441 Mbit/s | 532, 540 Mbit/s |
| Tunnel, UDP 50 and 300 Mbit/s paced, 5 s | 0 % loss | 0 % loss |
| Tunnel, 1-byte request/response, p50 / p99 | 2.9 / 3.9 ms | 3.1 / 3.9 ms |

Findings:

1. The reported loss figure is the result of a 32 ms unpaced burst of 4 MiB, not a property
   of the link: it varies from 9 % to 88 % between runs, comes with several hundred
   reordered datagrams, and is zero at 10 Mbit/s paced in both directions. Raw UDP towards
   the Mac does lose above about 50 Mbit/s paced.
2. The nsplane tunnel is healthy on that link in both directions; the slow transfer does not
   reproduce with nsplane's own load generator.
3. The consumer's captures of the slow transfer show no loss on the wire: per 20 s the Linux
   side received exactly the data packets the Mac sent (311/311, 151/151, ...), about 10 per
   second. The Linux side answered each within a millisecond, but the answers reached the
   Mac's interface in clumps 0.2 to 1.2 s later; in between the Mac retransmitted single
   segments after 0.3 to 0.7 s, then sent 10 to 14 segments when a clump arrived.
4. Deliveries to an idle Wi-Fi client are held (power save): sparse traffic sees 50 to
   110 ms where dense traffic sees 3 ms. A sender that has fallen back to a trickle stays in
   that regime. Holds of a second, as in the captures, were not reproduced on 2026-11-17 and
   their cause is open.
5. Whether the stalled sender was `nsplane-netstack`'s TCP or the consumer's own layer is
   not established. The pattern (retransmission timer shorter than the acknowledgement
   delay, congestion window that does not grow) is one the netstack must be tested against
   either way; no existing test delivers acknowledgements late and in clumps.

Seen while testing: on macOS 26 a process detached from the SSH session (`nohup ... &`) got
`EHOSTUNREACH` for every send to a LAN address, while the same binary in the foreground of
the session did not. A harness must keep the remote process in the session's foreground.

## Proposal

### 1. Dimensions

| Dimension | Values |
|---|---|
| System | Linux x86-64 (bench host), macOS arm64 (test host), Windows 11 x86-64 (test VM) |
| Local side | netstack (`netstack_bench`); TUN (`nsplane-cli` on Linux TUN, utun, Wintun) |
| Peer | nsplane; kernel WireGuard (Linux) and wireguard-go (macOS, Windows) as references |
| Direction | both, as separate rows |

Networks:

| Id | Network | Where |
|---|---|---|
| N0 | docker network on one host (today's setup) | Linux |
| N1 | wired or virtual LAN between two hosts | Linux <-> Windows VM |
| N2 | Wi-Fi client <-> wired host | macOS <-> Linux |
| N3 | shaped link through a Linux router container with `tc netem` / `tbf` | Linux <-> Linux |
| N4 | N2 or N1 with the shaping of N3 applied on the Linux end | macOS, Windows <-> Linux |

Shaping profiles for N3 and N4, each applied per direction:

| Profile | Shaping |
|---|---|
| `delay` | 20 ms and 100 ms, 10 % jitter |
| `loss` | 1 % and 5 % independent; 1 % in bursts (Gilbert-Elliott) |
| `reorder` | 25 % of packets 5 ms early |
| `rate` | 10 and 100 Mbit/s with a 64-packet queue |
| `burst-queue` | 1 Gbit/s with a 256-packet queue (the reported unpaced burst) |
| `held` | delivery in slots: packets released every 100 ms, and every 1 s (`netem slot`) |
| `held-ack` | `held` on the return direction only: data arrives at once, acknowledgements late |

### 2. Measurements

Per cell, median of 3 repetitions, with the underlay baseline taken in the same run:

- underlay baseline: raw UDP loss at paced rates (10, 50, 200 Mbit/s) and unpaced, with
  reordering and longest loss run; ping at 50 ms and 1 s intervals; on Wi-Fi the PHY mode,
  channel, RSSI and rate. A tunnel number without its baseline is not recorded;
- TCP throughput, 1 and 4 streams, 10 s;
- completion time of a fixed transfer (4 MiB and 64 MiB) written in one go, so the start is
  the unpaced burst of the report;
- UDP loss through the tunnel at the paced rates where the baseline loses nothing;
- 1-byte request/response p50/p99, back to back and with 1 s between requests (the held
  regime);
- CPU seconds per GB per side where the platform reports process CPU time;
- attribution: the engine's drop counters and the transport's send-error count before and
  after, so loss is assigned to the underlay, the transport or a queue.

### 3. Pass criteria

- No tunnel loss at a rate where the underlay baseline loses nothing.
- Tunnel TCP throughput at least 60 % of the reference peer's in the same cell (same
  shaping, same run), netstack and TUN separately.
- The 4 MiB transfer completes within 5 s plus 20 round trips of the shaped delay in every
  profile but `loss 5 %`; no profile leaves a transfer below 10 % of the shaped rate for
  more than 10 s.
- `held` and `held-ack`: the congestion window grows across rounds and no segment is
  retransmitted while its acknowledgement is only late.

A failed criterion becomes its own task; this plan adds tests and tooling, not fixes.

### 4. Work, in order

1. **Deterministic test first** (`nsplane-e2e`, in process, no network): an engine pair
   whose link delivers one direction in slots (100 ms, 1 s) and optionally drops the first
   burst beyond a queue bound; assert the criteria of `held` / `held-ack` on
   `nsplane-netstack`'s TCP. This settles finding 5 on Linux in seconds.
2. **`netstack_bench`**: `--bytes N` (fixed transfer, completion time, stall time above
   1 s), `--interval` for request/response, engine counters in the JSON line.
3. **Underlay probe** `scripts/bench/net-probe.py` (sequence-numbered UDP, paced or
   unpaced, loss/reorder/longest run) and its use in every cross-host run.
4. **Shaped lab** `scripts/bench/netem.sh`: endpoint, router and endpoint containers on two
   docker networks through `slot.sh`, profiles of section 1, pairs `netstack` and
   `nsplane-nsplane` with `kernel-kernel` as reference.
5. **Cross-host driver** `scripts/bench/cross-host.sh <ssh target> <os>`: builds or copies
   the binary, runs the baseline and the measurements both ways between a local container
   and the remote host, optional shaping on the local end (N4), cleans up the remote host.
   macOS: build natively on the host. Windows: cross-built `x86_64-pc-windows-gnu`, under
   the VM's lock.
6. **TUN rows** on macOS (utun) and Windows (Wintun) with `nsplane-cli` and iperf3, with
   wireguard-go as the reference where it installs without changing the host.
7. **`docs/performance.md`**: a section "Across hosts and networks" with the tables, the
   method and the pass criteria; `scripts/bench/README.md` gains the three scripts.

Items 1 to 4 need only the Linux host. None of it joins `just check`: the cross-host runs
depend on shared machines and a radio link.

## Risks

- Shared hosts and a radio link make numbers noisy: medians of interleaved repetitions, the
  baseline and the link state recorded with every row, criteria as ratios to a reference
  measured in the same run rather than absolute numbers.
- `tc netem` needs `NET_ADMIN` in the router container only; nothing on the host changes.
- The Windows VM's network is virtual; its rows describe the stack, not a physical NIC.
- The 1 s holds of finding 3 may be specific to the consumer's traffic pattern; `held` and
  `held-ack` cover the effect, not its cause.

## Scope

`examples/src/bin/netstack_bench.rs`, `crates/nsplane-e2e/tests`, `scripts/bench`,
`docs/performance.md`, `scripts/bench/README.md`, changelog and tracking. No change to a
library crate unless a criterion fails and its own task is approved.

## Alternatives

- Reusing the consumer's punch harness: it measures the consumer's whole stack, so a result
  cannot be attributed to nsplane.
- Wi-Fi rows only, no shaping: not repeatable, and the regimes that matter (held delivery,
  burst into a short queue) appear only by chance.
- iperf3 over TUN only: leaves out the netstack, which is the path the report concerns.

## Annotations

2026-11-18, work item 1 (`crates/nsplane-e2e/tests/netstack_held.rs`, `HeldTransport`):
finding 5 is settled. The stalled sender is the netstack's TCP. With the first 4 data
messages passed at once and acknowledgements then held in 100 ms slots, 4 MiB does not
complete in 12 s; with 300 ms slots one run took 210 s with about 1860 needless
retransmissions. Cause and a tried fix: `docs/task/20261118-0001-probe-timeout-on-held-acks.md`.
The two asserted tests are ignored until that task is done.

2026-11-18, work item 2: `netstack_bench --bytes`, `--interval`, `max_us`, `drops` and
`netstack` in every result. On the Wi-Fi link of the Context: 4 MiB in 0.12 to 0.15 s and
64 MiB in 1.1 to 1.4 s in both directions, no drops; 1-byte round trips 1 s apart p50 3.4 ms
and max 7.8 ms from the Mac, p50 8.3 ms and max 61.9 ms towards it. The link did not hold
acknowledgements during these runs, so the defect did not show; the shaped lab (item 4)
has to produce it on demand.

Work item 3 changes form: the probe becomes a mode of a Rust example binary instead of a
Python script, since the Windows host has no Python.
2026-11-18, work item 4 (`scripts/bench/netem.sh`, `just bench-netem`,
`netstack_bench --start-delay`): the router is a third container on the same docker
network that forwards on one interface (a router between two docker networks is filtered
by the host's bridge rules), and shaping on the senders' own interfaces was dropped because
a local queue throttles kernel TCP directly. The stream measurement became the late
transfer. Profiles `delay*` lost their jitter and `jitter20`/`jitter100` carry it, since
jitter reorders. Results in `docs/performance.md`, Shaped links. Failed criteria, each
filed: late transfers on held or delayed links
(`docs/task/20261118-0001-probe-timeout-on-held-acks.md`), reordering and `loss5`
(`docs/task/20261118-0002-reordering-tolerance.md`).

2026-11-18, both filed tasks are done in smoltcp fork tag `v0.14.0-nsplane.11`: the
asserted tests of `netstack_held.rs` run, `netstack_jitter.rs` (`JitterTransport`) asserts
a reordering link, and the Shaped links table was taken again. `loss5` is unchanged and
has a task of its own (`docs/task/20261118-1832-timeouts-under-heavy-loss.md`).

2026-11-18, work items 3, 5, 6 and 7: `net_probe` (examples), `scripts/bench/cross-host.sh`
with `just bench-cross`, and `docs/performance.md`, Across hosts and networks, with the
macOS Wi-Fi and Windows VM tables, the Wi-Fi link with held egress (N4) and the macOS TUN
row against wireguard-go. All criteria hold except on the Wi-Fi link with the data held
towards the Mac, where kernel TCP on the same path is five times slower than the netstack:
the shaping point, not the stack. `netem.sh` gained `held-data300` to show the same shaping
on a wired link. Not done: a TUN row on Windows, since no TUN node binary exists for it
(`docs/task/20261118-2040-windows-tun-bench-row.md`), and CPU seconds per GB across hosts.

