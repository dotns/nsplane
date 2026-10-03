# WireGuard implementation benchmark

`scripts/bench/wg-compare.sh` measures throughput, latency and CPU per GB of WireGuard
implementations on one Linux host. It is a manual tool, not part of `just check`.

## Setup

Per pair the script starts two fresh containers from `ai-agent/nsplane-bench`
(`scripts/bench/Dockerfile`: debian trixie-slim with iperf3, wireguard-tools, iproute2,
iputils-ping, jq, procps) on a dedicated docker network it creates (`<prefix>-net`):

- side a (sender, iperf3 client) pinned to `BENCH_CPUS_A`, side b (receiver, iperf3 server)
  pinned to `BENCH_CPUS_B` with `--cpuset-cpus`; the two sets must not overlap;
- `--cap-add NET_ADMIN --device /dev/net/tun`, real TUN devices, nothing on the host is
  reconfigured;
- tunnel 10.77.0.1/24 (a) and 10.77.0.2/24 (b), MTU 1420, fresh keys from `wg genkey`, UDP
  port 51820 (nsplane-cli: its ephemeral startup port, see Pairs) over the docker network.

Every implementation speaks the cross-platform UAPI, so all of them are configured like kernel
WireGuard: the interface is created (`ip link add wg0 type wireguard`, `nsplane-cli wg0` with
`WG_SUDO=1`, or `wireguard-go -f wg0`), then `wg set`, `ip addr`, `ip link set mtu 1420 up`.

Requirements: docker, the `wireguard` kernel module on the host, `jq` and `git` where the
script runs. Bind-mounted paths (`NSPLANE_CLI_BIN`) must be valid on the docker host; the
other binaries are copied into the containers with `docker cp`.

## Pairs

| Pair | Side a | Side b |
|---|---|---|
| `kernel-kernel` | kernel WireGuard | kernel WireGuard |
| `nsplane-nsplane` | nsplane-cli | nsplane-cli, one row per variant (`BENCH_NSPLANE_VARIANTS`) |
| `nsplane-kernel` | nsplane-cli | kernel WireGuard |
| `kernel-nsplane` | kernel WireGuard | nsplane-cli |
| `wggo-wggo` | wireguard-go | wireguard-go |
| `netstack` | `netstack_bench` client | `netstack_bench` server |

`nsplane-nsplane` runs one row per variant, the same configuration on both sides. The default
variants cover offload on/off x crypto workers 0/2:

| Variant | nsplane-cli environment |
|---|---|
| `default` | none: offload on, no crypto workers |
| `w2` | `WG_CRYPTO_WORKERS=2` |
| `nooffload` | `WG_NO_OFFLOAD=1` (no TUN offload, no UDP GSO/GRO) |
| `nooffload-w2` | `WG_NO_OFFLOAD=1 WG_CRYPTO_WORKERS=2` |

`nsplane-kernel` and `kernel-nsplane` always run the default nsplane-cli configuration.
nsplane-cli sides keep the UDP port bound at startup (read back with `wg show wg0
listen-port`) instead of setting `listen-port 51820`: a `listen-port` set over the UAPI binds
a new socket with offload on, which would undo `WG_NO_OFFLOAD`.

wireguard-go is built from upstream source at a pinned tag in the builder image
`ai-agent/wireguard-go` (`scripts/bench/wireguard-go/Dockerfile`, build arg
`WIREGUARD_GO_TAG`); the results record its tag and commit. It is a benchmark tool only.

`netstack` is nsplane's user-space mode: one process per side runs the engine, the netstack
and an iperf-style load generator (`examples/src/bin/netstack_bench.rs`), no TUN and no
iperf3. The pair is skipped with a note when `NETSTACK_BENCH_BIN` is missing. Its latency
columns are 1-byte TCP request/response round trips (`--mode rr`); the loaded run uses a
second peer (10.77.0.3) next to a saturating TCP stream from the first.

## Metrics

Per pair and repetition (the table reports the median of `BENCH_REPS`):

- TCP single stream and 4 streams (`iperf3 -J -P1` / `-P4`, a -> b), Gbit/s from the
  receiver-side sum;
- UDP at each `BENCH_UDP_RATES` rate (`-u -b RATE -l 1380`), loss %;
- ping p50/p99 idle (`ping -i 0.01 -c BENCH_PING_COUNT`, percentiles of the per-reply times),
  and the same next to one saturating TCP stream;
- CPU seconds per GB per side: `usage_usec` of `/sys/fs/cgroup/cpu.stat` in each container
  before and after the TCP single-stream run, divided by the GB received;
- load average (`/proc/loadavg`) at the start and end of the run and before and after each
  pair, kernel version, CPU model, CPU sets, nsplane-cli path and git commit, wireguard-go
  and iperf3 versions.

## Caveats

- Kernel WireGuard encrypts in kernel workqueue threads that are not charged to the container
  cgroup, so the CPU per GB of a kernel side is an undercount (marked `†`). iperf3's own CPU is
  included for every pair.
- The host is shared: compare numbers only within one run or with the load averages next to
  them. Short smoke runs (5 s, 1 rep) show that the harness works, not performance.

## Knobs

| Variable | Default | Meaning |
|---|---|---|
| `BENCH_PAIRS` | all six pairs | comma-separated pair names (table above) |
| `BENCH_DURATION` | `30` | seconds per iperf3 / netstack_bench run |
| `BENCH_REPS` | `3` | repetitions; medians are reported |
| `BENCH_UDP_RATES` | `1G,3G` | comma-separated UDP rates, iperf3 `-b` units |
| `BENCH_PING_COUNT` | `1000` | pings (or rr round trips) per latency run, 10 ms apart |
| `BENCH_CPUS_A` | `2-5` | `--cpuset-cpus` of side a |
| `BENCH_CPUS_B` | `6-9` | `--cpuset-cpus` of side b |
| `BENCH_NSPLANE_VARIANTS` | the four variants under Pairs | `;`-separated `NAME[:ENV[:ARGS]]`; ENV (space-separated `KEY=VALUE`) and ARGS are given to nsplane-cli on both sides of `nsplane-nsplane`, one row each |
| `NSPLANE_CLI_BIN` | `target/release/nsplane-cli` | nsplane-cli under test, e.g. built in another worktree |
| `NETSTACK_BENCH_BIN` | `target/release/netstack_bench` | netstack pair binary |
| `BENCH_OUT` | `.tmp/bench/<UTC timestamp>` | run directory (gitignored) |
| `BENCH_PREFIX` | `nsplane-bench-<pid>` | unique prefix of container and network names |

## Output

The run directory holds `results.md` (setup block, one table row per pair/variant, load
averages, notes such as skipped pairs), `run.log`, and per pair the raw iperf3 JSON, ping
output and netstack_bench JSON of every repetition plus the daemon logs and `wg show`.

Containers and the network are removed on every exit path; the images are kept for reuse
(labelled `ai-agent=true`).

## Reproduce

```bash
just bench-wg                                   # full run: 30 s x 3 reps, all pairs

# smoke run
BENCH_DURATION=5 BENCH_REPS=1 BENCH_UDP_RATES=500M scripts/bench/wg-compare.sh

# a binary from another branch, nsplane pairs only, with variants
NSPLANE_CLI_BIN=../other-worktree/target/release/nsplane-cli \
BENCH_PAIRS=nsplane-nsplane,nsplane-kernel \
BENCH_NSPLANE_VARIANTS='default;threads2:WG_THREADS=2' \
  scripts/bench/wg-compare.sh
```

To measure another wireguard-go release, change the `WIREGUARD_GO_TAG` default in
`scripts/bench/wireguard-go/Dockerfile`; the script rebuilds the image on every run.
