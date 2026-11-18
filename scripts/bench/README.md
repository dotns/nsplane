# WireGuard implementation benchmark

`scripts/bench/wg-compare.sh` measures throughput, latency and CPU per GB of WireGuard
implementations on one Linux host. It is a manual tool, not part of `just check`.

## Setup

Per pair the script starts two fresh containers from `ai-agent/nsplane-bench`
(`scripts/bench/Dockerfile`: debian trixie-slim with iperf3, wireguard-tools, iproute2,
iputils-ping, jq, procps) on a dedicated docker network it creates (`<prefix>-net`):

- run through `scripts/bench/slot.sh`, which picks one of two bench slots (one CCD each:
  slot 0 = CPUs 1-3 / 4-7, slot 1 = CPUs 8-11 / 12-15, SMT siblings unused) and exports the CPU
  sets, so two measurements can run at once; compare A and B only within one slot run;
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
listen-port`) instead of setting `listen-port 51820`, avoiding a socket rebind. A UAPI
`listen-port` rebind preserves the CLI's offload setting, including `WG_NO_OFFLOAD`.

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
| `BENCH_CPUS_A` | `8-11` | `--cpuset-cpus` of side a (set by `slot.sh`) |
| `BENCH_CPUS_B` | `12-15` | `--cpuset-cpus` of side b (set by `slot.sh`) |
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

## Shaped links

`scripts/bench/netem.sh` measures netstack TCP over a link shaped with `tc netem`, next to
kernel TCP over the same link. It is a manual tool like `wg-compare.sh` and runs through
`slot.sh` (`just bench-netem`).

Three containers from `ai-agent/nsplane-bench` on one docker network: a (client), b (server)
and r. a and b have a host route to each other through r, which forwards on its one
interface. A `prio` qdisc on r sorts by destination into one band per direction, and a
profile puts a `netem` qdisc on a band: forward is a to b (the data), return is b to a (the
acknowledgements). Only the containers have `NET_ADMIN`; nothing on the host changes.

| Profile | Forward and return, unless noted |
|---|---|
| `none` | unshaped |
| `delay20`, `delay100` | `delay 20ms`, `delay 100ms` |
| `jitter20`, `jitter100` | `delay 20ms 2ms`, `delay 100ms 10ms`: the jitter reorders packets |
| `loss1`, `loss5` | `loss 1%`, `loss 5%` |
| `reorder` | `delay 5ms reorder 25%` |
| `rate10` | `rate 10mbit limit 64` |
| `burst-queue` | `rate 1gbit limit 256` |
| `held100`, `held1000` | `slot 100ms`, `slot 1000ms`: packets leave in slots, at once |
| `held-ack100`, `held-ack300`, `held-ack1000` | the slot on the return direction only |
| `held-data300` | a 300 ms slot on the forward direction only |

Pairs: `netstack` (`netstack_bench` on a and b, WireGuard over the shaped link) and `kernel`
(iperf3 over kernel TCP on the shaped link without a tunnel, as what TCP achieves there).

Per profile and pair, from a to b:

- transfer: `BENCH_BYTES` (default 4 MiB) written at once with the shaping in place, in
  seconds (`netstack_bench --bytes`, `iperf3 -n`);
- late transfer, netstack only: the connection opens on the unshaped link, the shaping
  applies one second later and the transfer starts after another (`--start-delay 2000`).
  The sender has then measured a fast round trip before the link changes.

A run that takes longer than `BENCH_LIMIT` (default 120 s) is reported as stalled. iperf3
stops when the sender has written the bytes, so its time is scaled by sent over received
bytes, and it reports a transfer shorter than a second as 1 s. Other knobs: `BENCH_PROFILES`,
`BENCH_PAIRS`, `BENCH_CPUS_A`/`_B`, `NETSTACK_BENCH_BIN`, `BENCH_OUT`
(`.tmp/bench/netem-<UTC timestamp>`), `BENCH_PREFIX`. The run directory holds `results.md`,
`run.log` and the JSON of every run.

```bash
just bench-netem
BENCH_PROFILES='none held-ack300' BENCH_LIMIT=60 scripts/bench/slot.sh scripts/bench/netem.sh
```

## Across hosts

`scripts/bench/cross-host.sh <ssh target> <unix|windows>` measures the netstack tunnel
between a container on this host and another host, in both directions, next to what the
path between them loses without a tunnel. It is a manual tool and runs through `slot.sh`
(`just bench-cross <ssh target> <unix|windows>`). The remote host is used over SSH only:
its processes run in the foreground of SSH sessions the script holds open (on macOS a
process detached from its session cannot send to the LAN), and its directory
(`BENCH_PREFIX` in the login directory) and processes are removed on every exit path.

"up" is remote to local, "down" is local to remote. Per direction, the median of
`BENCH_REPS` (default 3) runs:

- baseline (`net_probe`, `examples/README.md`): loss of 3227 unpaced 1300-byte datagrams
  and at 10, 50 and 200 Mbit/s paced, the reordered datagrams and the longest loss run at
  200 Mbit/s; ping from the local container at 50 ms and 1 s intervals;
- tunnel (`netstack_bench` on both ends): TCP for 10 s with 1 and 4 streams, 4 MiB and
  64 MiB written at once, UDP at 50 Mbit/s paced for 5 s, 1-byte round trips back to back
  and 1 s apart (sparse traffic, which a Wi-Fi access point holds for a client in power
  save).

A tunnel number is read against the baseline of the same run: loss the path has on its own
is not the tunnel's.

| Variable | Default | Meaning |
|---|---|---|
| `BENCH_LOCAL_ADDR` | required | address of this host as the remote reaches it, or `container` for the local container's own address (a remote on a docker network of this host) |
| `BENCH_REMOTE_ADDR` | unset | address of the remote as this host reaches it. Unset for a remote behind NAT: the baseline and ping towards it are left out, and the remote's server restarts for every down run, since a local node without the remote's address waits for the remote's handshake |
| `BENCH_PORT` | `47920` | tunnel UDP port on both ends; the probe uses the next one |
| `BENCH_NETWORK` | default bridge | docker network of the local container; on the default bridge both ports are published on this host |
| `BENCH_SSH`, `BENCH_SCP` | `ssh -o BatchMode=yes`, `scp -q -o BatchMode=yes` | how the remote is reached, e.g. with a key file |
| `BENCH_REMOTE_BIN` | unset | local directory with `netstack_bench` and `net_probe` built for the remote (`.exe` for `windows`, where it is required). Without it the work tree is copied to the remote and built there with cargo |
| `BENCH_NETEM` | unset | `tc netem` arguments for the local container's egress, e.g. `slot 300ms`: shapes what the local end sends, which is the data of "down" and the acknowledgements of "up" |
| `BENCH_LOCK` | unset | a lock file held for the run, for a remote host that other harnesses use |
| `BENCH_REPS`, `BENCH_LIMIT` | `3`, `120` | runs per measurement; seconds after which a run counts as failed |
| `BENCH_RR_COUNT` | `1000` | back-to-back round trips per run; fewer on a link shaped with a long delay, or the run exceeds `BENCH_LIMIT` |
| `NETSTACK_BENCH_BIN`, `NET_PROBE_BIN` | `target/release/...` | the local binaries |
| `BENCH_OUT`, `BENCH_PREFIX` | `.tmp/bench/cross-host-<UTC timestamp>`, `nsplane-cross-<pid>` | run directory; name of the container and the remote directory |

The run directory holds `results.md` and the JSON of every run. Not recorded by the script:
the radio state of a Wi-Fi remote (PHY mode, channel, RSSI), which belongs next to its rows.

```bash
# macOS or Linux on the LAN; the remote builds the binaries itself
BENCH_LOCAL_ADDR=192.0.2.10 BENCH_REMOTE_ADDR=192.0.2.20 just bench-cross user@192.0.2.20 unix

# Windows guest behind NAT on a docker network of this host, binaries cross-built here
cargo build --release --locked --target x86_64-pc-windows-gnu -p nsplane-examples --bin netstack_bench --bin net_probe
BENCH_REMOTE_BIN=target/x86_64-pc-windows-gnu/release BENCH_NETWORK=bench-net BENCH_LOCAL_ADDR=container \
  just bench-cross user@windows-guest windows
```
