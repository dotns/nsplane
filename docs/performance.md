# Performance

How nsplane's performance is measured and the current numbers. Each table states its method
and the run it comes from; a new measurement replaces the row it supersedes. What a component
does is in the [reference](reference/); this page holds only measured results.

## Method

- Host: x86-64, 32 CPUs (two CCDs), the `ai-agent/nstun-dev` image, release or bench
  profile. The host is shared, so every comparison is an interleaved A/B (A, B, A, B) inside
  one `scripts/bench/slot.sh` invocation, and the 1-minute load is recorded with each run.
- `scripts/bench/slot.sh <command>` runs a command on one CCD's physical cores (slot 0: CPUs
  1-7, slot 1: CPUs 8-15) and exports `BENCH_CPUS_A`, `BENCH_CPUS_B` and `BENCH_CPUS`; one A/B
  per invocation, 120 s between invocations.
- Criterion benches report means; the tables give the mean of the rounds, or the range when
  the rounds spread.
- `scripts/bench/wg-compare.sh` runs two tunnel endpoints in containers pinned to
  `BENCH_CPUS_A` / `BENCH_CPUS_B` and measures iperf3 TCP and UDP, ping, and CPU per GB
  (`scripts/bench/README.md`).

```text
scripts/bench/slot.sh scripts/bench/wg-compare.sh
cargo bench -p nsplane-core --bench data_path
cargo bench -p nsplane --bench worker_pool
cargo bench -p nsplane --bench local_graph
cargo bench -p nsplane-acl --bench namespaces
cargo bench -p nsplane-acl --bench gate
cargo bench -p nsplane-nat --bench translate
cargo bench -p nsplane-netstack --bench send_stream
cargo test --release -p nsplane-e2e --test netstack_lossy -- --ignored --nocapture
cargo test --release -p nsplane-e2e --test netstack_buffers -- --ignored --nocapture
cargo test --release -p nsplane-e2e --test latency -- --ignored --nocapture
```

## WireGuard implementations

`wg-compare.sh` at de521e5 (0.14.1), 2026-10-16, CPU sets 1-3 / 4-7, 30 s x 3 repetitions,
medians, MTU 1420, load 1.6-3.7. Throughput is the receiver-side sum; loaded ping runs next
to one saturating TCP stream; CPU s/GB includes iperf3's own CPU.

| Pair (a -> b) | TCP P1 Gbit/s | TCP P4 Gbit/s | UDP loss 1G / 3G % | ping p50 / p99 idle ms | ping p50 / p99 loaded ms | CPU s/GB a / b |
| --- | --- | --- | --- | --- | --- | --- |
| kernel-kernel | 4.73 | 4.65 | 0.00 / 0.02 | 0.591 / 1.310 | 1.340 / 1.630 | 0.08 † / 0.74 † |
| nsplane-nsplane | 11.00 | 11.81 | 0.00 / 0.00 | 0.192 / 0.280 | 2.370 / 4.710 | 0.91 / 0.94 |
| nsplane-nsplane (2 crypto workers) | 14.05 | 14.75 | 0.00 / 0.01 | 0.223 / 0.338 | 2.040 / 4.240 | 1.02 / 1.13 |
| nsplane-nsplane (no offload) | 3.76 | 3.70 | 0.00 / 0.00 | 0.189 / 0.281 | 1.080 / 1.950 | 2.90 / 3.11 |
| nsplane-nsplane (no offload, 2 workers) | 5.41 | 5.52 | 0.00 / 0.02 | 0.210 / 0.342 | 0.891 / 1.840 | 2.52 / 3.26 |
| nsplane-kernel | 7.59 | 7.14 | 0.00 / 0.01 | 0.517 / 1.380 | 3.260 / 5.390 | 1.91 / 0.31 † |
| kernel-nsplane | 7.17 | 7.17 | 0.00 / 0.02 | 0.484 / 1.020 | 2.050 / 5.590 | 0.12 † / 1.63 |
| wireguard-go | 11.08 | 11.06 | 0.01 / 0.11 | 0.227 / 0.342 | 2.190 / 5.710 | 1.38 / 1.55 |
| netstack (user-space) | 8.25 | 10.59 | 0.00 / 0.00 | 0.028 / 0.066 | 0.130 / 0.893 | 1.60 / 1.40 |

† Kernel WireGuard encrypts in kernel threads that are not charged to the container cgroup,
so its side is an undercount. The netstack pair runs the engine and an in-process load
generator (`netstack_bench`) in one process per side, without TUN; its ping columns are 1-byte
TCP request/response round trips.

## Core data path

`cargo bench -p nsplane-core --bench data_path` (0.14.2): one encrypt plus decrypt round trip
through `Core`, criterion means.

| Case | 64 B | 1420 B |
| --- | --- | --- |
| `core_round_trip`, one packet per call | 417.1 ns | 1.22 µs |
| `core_round_trip_batch32`, per batch of 32 | 13.1 µs | 39.2 µs |
| `flows256`, 256 destinations | 430.5 ns | 1.25 µs |
| `two_identities`, two local identities | 421.2 ns | 1.23 µs |

## Handshake dispatch

`data_path`'s handshake group with several local identities (0.14.0): a handshake initiation
is tried against each identity's static key until one matches.

| Case | Time |
| --- | --- |
| initiation, 1 identity | 129.11 µs |
| initiation, 4 identities | 130.14 µs |
| initiation, 16 identities | 132.25 µs |
| no match, 16 identities | 3.10 µs (about 0.2 µs per identity tried) |

## Allowed-IP writes

Writes to a 10,000-entry allowed-IP table (0.14.2), IPv4 / IPv6:

| Operation | IPv4 | IPv6 |
| --- | --- | --- |
| insert plus remove, each its own change | 0.25 µs | 0.31 µs |
| remove by value, per change (either family) | 52 µs | 52 µs |
| drain a peer's networks (10k / 1k peers), per change | 8 µs | 10 µs |
| rebuild of one family | 0.9 ms | 1.5 ms |
| load 10k networks in one change | 1.9 ms | 2.5 ms |
| 10k separate changes | 3.0 ms | 5.5 ms |
| memory per network | ≤ 0.6 KB | ≤ 0.75 KB |

## Crypto worker pool

`cargo bench -p nsplane --bench worker_pool`, 2026-10-03, bench profile with LTO,
multi-threaded runtime, two runs. Hub case: a hub engine with 8 peers on in-memory links
sends 120 packets to every peer while every peer sends 120 to it (1920 packets per
iteration). One-peer case (`worker_pool_one_peer`, 2026-10-05, load below 4.2): the hub
linked to one spoke with as many workers, the same packets per iteration.

| Case | Pool off (0 or 1) | 2 workers | 4 workers |
| --- | --- | --- | --- |
| hub, 64 B | 1.49-1.55 Mpps | 1.64-1.68 Mpps | 1.61-1.64 Mpps |
| hub, 1420 B | 869-906 kpps (9.9-10.3 Gbit/s) | 0.94-1.20 Mpps (10.6-13.6 Gbit/s) | 1.17-1.26 Mpps (13.3-14.3 Gbit/s) |
| one peer, 1420 B | 792 kpps | 1.30 Mpps | 1.41 Mpps |

## Engine latency

`cargo test --release -p nsplane-e2e --test latency`, 2026-10-03: two engines over UDP
loopback with builder defaults, 2000 pings, two runs.

| Case | p50 | p99 | lost pings |
| --- | --- | --- | --- |
| idle | 11.2-11.3 µs | 36.0-40.3 µs | 0 |
| next to a saturating bulk flow | 2.13-2.15 ms | 4.69-5.16 ms | 13-18 |

## Queue depths

High-water marks (`EngineHandle::queue_stats`) with the default capacity of 1024, two
engines linked in process, release, 4-thread runtime, the highest mark of either engine over
three runs (2026-10-02). These runs predate the owner's inline output; without crypto
workers, `transmit`, `deliver` and `recycle` now stay lower while the tasks keep up.

| Load | local | datagrams | deliver | recycle | transmit | backlog | Drops |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ping-pong, 1300 B, one packet in flight | 1 | 1 | 1 | 1 | 1 | 0 | none |
| UDP paced, 64 x 1300 B per ms, channel link | 64 | 41 | 53 | 64 | 64 | 0 | none |
| UDP paced, 64 x 1300 B per ms, loopback `UdpTransport` | 103 | 43 | 64 | 107 | 107 | 0 | none |
| UDP flood, 100k x 1300 B, channel link | 1024 | 341 | 866 | 1023 | 1024 | 449 | none |
| UDP flood, 100k x 1300 B, loopback `UdpTransport` | 1024 | 120 | 239 | 1013 | 1024 | 280 | none (the kernel drops ~25 %) |
| Netstack TCP, 1 connection, 32 MiB echoed | 668 | 642 | 212 | 247 | 665 | 0 | none |
| Netstack TCP, 4 connections, 32 MiB echoed | 1024 | 1024 | 1024 | 469 | 1024 | 1024 | `DROP_SINK_FULL` in 3 of 6 runs |
| Netstack TCP, 8-16 connections, 32 MiB echoed | 1024 | 1024 | 1024 | 896 | 1024 | 1024 | `DROP_SINK_FULL` in every run |

The command and event queues never passed 1 and 0. With capacity 2048, 8 and 16 netstack
connections ran without a drop; with 512 and 256, 4 connections dropped at the deliver queue.

## Local-side graph

`cargo bench -p nsplane --bench local_graph`, per packet, 1024 packets per iteration,
2026-10-03 (load 10-30).

| Case | 64 B | 1420 B |
| --- | --- | --- |
| `pipe`: send plus `recv_batch`, current-thread runtime | ~68 ns | ~68 ns |
| `pipe` with `PipeSink::alloc` and `recycle` | about +14 ns over plain `pipe` | about +14 ns |
| `pump` pipe to pipe, two spawned tasks | ~146 ns | ~170 ns |

`pump` into a device-like sink, per 1024 packets (slot 0, load 9.3): a sink that returns its
buffers (`send_batch_spent`) 99.40 / 98.37 µs at 64 / 1420 B, against 106.86 / 129.53 µs for
one that drops them.

## ACL

`cargo bench -p nsplane-acl --bench namespaces`, IPv6 TCP ("new flow": the source port
changes with every packet; "established": one five-tuple repeated), 2026-10-07, slot 0,
load 1.0-2.2, mean of three interleaved rounds.

| Scenario | New flow | Established | Outbound |
| --- | --- | --- | --- |
| No namespaces (default policy, 3 rules, not cached) | 50 ns | 50 ns | 82 ns |
| 8 namespaces x 64 members, 4 grants, 16 pinholes: local rule | 172 ns | 51 ns | 100 ns |
| same, through a grant (peer to peer) | 353 ns | 244 ns | |
| same, through an inbound pinhole | 213 ns | | |
| same, outbound-restricted peer (outbound rule) | | | 135 ns |
| Bypass (a namespace accepting everything) | 39 ns | 39 ns | 82 ns |
| Default policy, by-source peer | 74 ns | 73 ns | |
| Stateless options, by-source peer, IPv4 TCP | 53 ns | 52 ns | |
| same, non-first fragment after an accepted first fragment | | 26 ns | |

Re-measured on 0.14.1 (2026-10-15, interleaved A/B, slot.sh): `floor/snapshot` (the engine
snapshot read every packet pays) 3.10 ns, `default/inbound` 44.22 ns, `default/outbound`
74.84 ns, `stateless/inbound_fragment` 27.07 ns.

## Flow gate

`cargo bench -p nsplane-acl --bench gate` on 0.14.1, 2026-10-15, interleaved A/B, slot.sh.

| Case | Time |
| --- | --- |
| `established/gate` | 40.34 ns |
| `established/outbound` | 40.57 ns |
| `established/filter` (`GateFilter` with an `AclFilter`) | 45.73 ns |
| `baseline/acl_established` (`AclFilter` alone) | 30.19 ns |
| `baseline/pass_filter` (inert gate in front of the ACL) | 35.46 ns |
| `baseline/pass_gate` (inert gate alone) | 0.80 ns |

Scoped decisions (`evaluate_inbound_in`, 0.20.0, slot 0, 2026-10-27, load 0.9-1.0):
`scoped/established` 58.2-58.5 ns, `scoped/out_of_scope` 25.5-26.0 ns.

## Translator

`cargo bench -p nsplane-nat --bench translate` on 0.14.1, 2026-10-15, interleaved A/B,
slot.sh: `Translator::outbound` of IPv4 to a peer's `eam4` (`eam4_out`) and `inbound` of the
IPv6 reply (`eam4_in`), one peer in the table (1000 peers cost the same), in a buffer with
the TUN reader's room.

| Case | 64 B | 1400 B (TCP) / 1420 B (UDP) |
| --- | --- | --- |
| `eam4_out`, TCP | 39.15 ns | 81.05 ns |
| `eam4_out`, UDP | 39.39 ns | 81.75 ns |
| `eam4_in`, TCP | 53.00 ns | 76.07 ns |
| `eam4_in`, UDP | 52.19 ns | 74.90 ns |

## Netstack

`tests/netstack_lossy.rs` `throughput`, smoltcp `v0.14.0-nsplane.7`, 2026-10-24: two
netstacks over two engines on an in-process `ChannelTransport` pair, one TCP connection, MTU
1420; `LossyTransport` drops a deterministic fraction of the data messages, `Bottleneck` is
25 MB/s behind a 64-datagram drop-tail buffer. Median [range] of 10 interleaved runs, slot 0,
load 0.1-5.9. The lossy rows are bimodal: about 0.1 s, or about 1.1 s when a retransmission
timeout at the 1 s minimum RTO fires.

| Case | Time |
| --- | --- |
| TCP, 64 MiB, no loss | 0.161 s [0.117-0.169] |
| TCP, 16 MiB, 1 % loss | 0.12 s [0.08-1.09] |
| TCP, 16 MiB, 3 % loss | 0.83 s [0.29-3.27] |
| TCP, 16 MiB, bottleneck | 0.79 s [0.78-0.80] |

With `NetStackConfig::tcp_min_rto` at 20 ms on both stacks (one run, interleaved with the
default, load 0.4): no loss 0.159 s (default 0.158 s), 1 % loss 0.106 s (1.100 s), 3 % loss
0.300 s (0.356 s), bottleneck 0.796 s (0.793 s); the `parallel_echo_with_loss` test (eight
echoes through 256-packet engine queues, 2 % loss) 133 ms (1073 ms).

`tests/netstack_multistream.rs` (1 GiB per run split between the streams, default
configuration, release, 12 pairs, load 3.2-5.5, 2026-10-05): one stream 669-782 MB/s, four
streams 689-841 MB/s (1.00-1.11x the one stream), with 251-577 `DROP_SINK_FULL` per
four-stream run.

UDP queue: between two `netstack_bench` nodes (the harness pair, 2026-10-06), 1380-byte
datagrams lost 1.24 % at 1 Gbit/s and 5.21 % at 3 Gbit/s with a `datagram_capacity` of 128,
and 0.00 % and 2.62 % with 256; the rest at 3 Gbit/s is the receiving engine's full sink.

### Socket buffers

`tests/netstack_buffers.rs` `throughput`, 64 MiB, three runs, release, load 17-31
(2026-10-03, smoltcp `.3`):

| Buffers on both stacks | MB/s, median [range] | `DROP_SINK_FULL` per run |
| --- | --- | --- |
| Default, 512 segments (about 690 KiB) | 287 [200-336] | 0 |
| 1 MiB | 315 [298-334] | 0 |
| 4 MiB, about 3000 segments | 52 [37-53] | 101-312 |

A window of more segments than the receiving engine's 1024-packet sink queue holds loses its
tail there; 4 MiB ran without drops once the engine and stack queues held 8192 packets.

## Netstack ingress labels

`send_stream` with netstack ingress labels (release C, W5), 2026-10-27, slot 0, `BENCH_CPUS`,
each `slot.sh` invocation started at a 1-minute load below 3 (the shared host rose to 4-9
during runs), criterion means per round.

Labeled against unlabeled on the same build (head of `feat/netstack-ingress-labels`): the wire
into the receiving stack sets the label on every packet, so each data segment or datagram is
checked against its connection's or flow's label; the two cases of a count run back to back,
three rounds. The bar is the noise plus 3 %.

| Case | Unlabeled | Labeled | Change per round |
| --- | --- | --- | --- |
| `netstack_send/streams_1` | 3332 / 3421 / 3329 us | 3353 / 3424 / 3412 us | +0.7 / +0.1 / +2.5 % |
| `netstack_send/streams_4` | 2090 / 2316 / 2303 us | 2151 / 2125 / 2100 us | +2.9 % (the other two unlabeled runs disturbed, intervals 2.1-2.6 ms) |
| `netstack_send_1cpu/streams_1` | 3452 / 3469 / 3478 us | 3476 / 3493 / 4599 us | +0.7 / +0.7 % (third labeled run disturbed) |
| `netstack_send_1cpu/streams_4` | 4179 / 4331 / 4396 us | 4214 / 4287 / 4504 us | +0.8 / -1.0 / +2.5 % |
| `netstack_udp_flow_send/flows_1` | 572.1 / 580.3 / 602.4 us | 573.3 / 609.8 / 590.7 us | +0.2 / +5.1 / -1.9 % (second labeled run disturbed) |
| `netstack_udp_flow_send/flows_4` | 480.2 / 484.6 / 552.1 us | 487.3 / 601.7 / 483.4 us | +1.5 % (the other two disturbed) |
| `netstack_udp_flow_send_1cpu/flows_1` | 493.1 / 436.1 / 439.8 us | 440.5 / 439.8 / 442.9 us | +0.9 / +0.7 % |
| `netstack_udp_flow_send_1cpu/flows_4` | 448.2 / 440.2 / 441.2 us | 446.2 / 443.0 / 443.8 us | -0.5 / +0.6 / +0.6 % |

Earlier builds of the TCP check, same method: a lookup per segment (`SocketAddr` pair,
SipHash) cost +5.2 % on `netstack_send/streams_1` (+4.8 % on 1 CPU); a one-entry cache of the
last tuple +2.9 %, but `streams_4` (four interleaved connections) stayed at +8 to +31 %. The
shipped check reads the IPv4 tuple as two words and probes a 64-slot cache: 4 ns per check
in isolation (15 ns per table lookup), against about 340 ns per segment for the whole
four-thread pipeline. The per-socket alternative of the design note was not needed.

Untagged traffic against `dbee734` (the packet tag carrier), rotated base / build rounds in
three `slot.sh` invocations (four, three and three rounds), all rounds:

| Case | Rounds (build against base) | Median |
| --- | --- | --- |
| `netstack_send/streams_1` | -1.6 .. +2.6 % (7) | +0.8 % |
| `netstack_send/streams_4` | -53 .. +6.8 % (7; the base swung) | +1.2 % |
| `netstack_send_1cpu/streams_1` | -15.9, -3.1, +1.6 .. +3.8 % (10) | +2.1 % |
| `netstack_send_1cpu/streams_4` | -3.0 .. +1.7 % (4) | +1.6 % |
| `netstack_udp_send/flows_1` | -3.8 .. +2.9 % (4) | -1.1 % |
| `netstack_udp_send/flows_4` | -50.8 .. +66 % (10) | +16 % |
| `netstack_udp_send_1cpu/flows_1` | -0.5 .. +11.3 % (10) | +1.4 % |
| `netstack_udp_send_1cpu/flows_4` | +0.2 .. +2.9 % (4) | +0.8 % |

`netstack_udp_send/flows_4` (four connected sockets of one stack to four bound sockets of the
other, four runtime threads) is bimodal on the shared host: single runs of either binary land
near 480 us or between 550 and 940 us with wide intervals, the base's included (one round
-51 % for the build). The build landed high in more rounds, but a diagnostic build without the
label field in the connection state (the only change on this path besides one tag read per
datagram) ran at 937 us in the round where the build ran at 487 us and the base at 479 us.
Not attributed; to be measured again on a quiet host with the release integration, like the
packet tag carrier's disturbed `flows_4`. `netstack_send_1cpu/streams_1` sits at +2.1 %
(median of 10 rounds, 8 of them +1.6 to +3.8 %), against a 2.4 % spread of the base alone
across the three invocations: at the edge of the noise. A build with the label revoke and
the TCP check moved out of the driver's hot functions (smaller code, the driver loop below
the base's size) was not faster.

`data_path`, `local_graph` and `udp_offload` do not link `nsplane-netstack`: their bench
binaries are byte-identical to the base's. The interleaved runs (two rounds each) measure the
slot's noise: `data_path` `core_round_trip{,_batch32}/{64,1420}` -1.5 .. +1.0 %;
`udp_offload` -6.2 .. -0.2 %; `local_graph`, 34 cases, mostly within ±3 % per round, single
rounds up to -15 % and +35 %.


## Packet tag carrier against 0.20.0

The packet tag and receipt marker on `PacketBuf` (untagged traffic) against `v0.20.0`,
2026-10-27, slot 0, interleaved base / build in one `slot.sh` invocation per bench, each run
started at a 1-minute load below 3 (the shared host rose to 3-7 during some runs), criterion
means of the rounds. `data_path`, `local_graph`, `vnet` and `translate` (the eight one-peer
cases of each direction) ran on `BENCH_CPUS_A`, `send_stream` and `udp_offload` on
`BENCH_CPUS`. Two layouts were built: A, the tag added to the 56-byte `PacketBuf` (64 bytes),
and B, `u32` packet offsets (56 bytes); the shipped build is B.

First run, base / A / B in that order per round (`data_path` and `vnet` three rounds, the
others two):

| Bench / case | 0.20.0 | A (64 B) | B (56 B) |
| --- | --- | --- | --- |
| `data_path` `core_round_trip/64` | 424.9 ns | -1.3 % | -1.3 % |
| `data_path` `core_round_trip_batch32/64` | 13.36 us | -1.1 % | -1.4 % |
| `data_path` `core_round_trip/1420` | 1.243 us | +0.6 % | -0.5 % |
| `send_stream` `netstack_send/streams_{1,4}` | 3.221 / 2.053 ms | -2.7 / -2.5 % | +1.7 / +0.4 % |
| `send_stream` `netstack_udp_send/flows_{1,4}` | 554.6 / 474.5 us | -1.1 / -2.1 % | +1.0 / -0.1 % |
| `local_graph`, 34 cases | | -1.3 % to +22 % (`splitter/*` +10 to +22 %) | -8.7 % to +8.8 % |
| `udp_offload`, 4 cases | | -2.1 % to +3.8 % | -8.9 % to +0.5 % |
| `vnet` `segment_tcpv4_64k` | 3.110 us | +0.5 % | +0.7 % |
| `translate`, 16 cases | | -7.2 % to +0.7 % | -11.1 % to +3.9 % |

`local_graph` again, its 16 pipe, splitter, map and bare swap cases, four rounds with the order
rotated: A against 0.20.0 `splitter/*` +6.5 to +8.3 % in every round, `pipe/send_recv_1420`
+3.4 %, `swap_sink/bare_send_*` +2.5 to +4.4 %, the rest -2.5 % to +2.2 %; B -5.5 % to -12.6 %
in every case. A is outside the noise on the local graph, so B ships.

The shipped build (B, with the bounds at `u32::MAX`) against 0.20.0:

| Bench / case | 0.20.0 | B | Change |
| --- | --- | --- | --- |
| `data_path` `core_round_trip/64` | 421.9 ns | 424.2 ns | +0.5 % |
| `data_path` `core_round_trip_batch32/64` | 13.18 us | 13.23 us | +0.4 % |
| `data_path` `core_round_trip/1420` | 1.239 us | 1.248 us | +0.8 % |
| `data_path` `core_round_trip_batch32/1420` | 39.73 us | 39.77 us | +0.1 % |
| `data_path`, the other 16 cases | | | -4.6 % to +1.7 % |
| `local_graph`, 34 cases | | | -12.0 % to -1.2 % |
| `send_stream` `netstack_send/streams_{1,4}` | 3.226 / 2.217 ms | 3.325 / 2.144 ms | +3.1 / -3.3 % |
| `send_stream` `netstack_send_1cpu/streams_{1,4}` | 3.385 / 4.107 ms | 3.437 / 4.191 ms | +1.5 / +2.1 % |
| `send_stream` `netstack_udp_send/flows_{1,4}` | 566.4 / 479.3 us | 591.5 / 681.9 us | +4.4 / +42 % (disturbed, below) |
| `send_stream` `netstack_udp_send_1cpu/flows_{1,4}` | 425.3 / 427.8 us | 429.6 / 428.2 us | +1.0 / +0.1 % |
| `udp_offload`, 4 cases | | | -2.3 % to +2.1 % |
| `vnet` `segment_tcpv4_64k` | 3.112 us | 3.170 / 3.167 us | +1.7 % (a third run at 5.2 us disturbed) |
| `translate`, 16 cases | | | -3.1 % to +4.8 %, both signs per round |

The B runs of `netstack_udp_send/flows_4` had wide intervals ([725, 862] us and [523, 597] us,
the load rising to 5.2) where the base runs were tight ([476, 488] us, [473, 479] us); the same
layout before the bounds measured 475.4 / 472.6 us against 473.9 / 475.2 us. That case and
`streams_1` are to be measured again on a quiet host. `vnet` segments a 64 KiB packet into 45
buffers through `set_len` and `extend_from_slice`, where the bound adds a compare: +53 ns per
packet, about 1 ns per segment.

## 0.20.0 against 0.19.3

The integrated 0.20.0 head (netstack control from the first input, scoped flow gate
decisions, local barrier and plaintext ingress, the 0.19.4 fixes) against `fb67db9` (0.19.3
with the large module split), 2026-10-27, interleaved A/B in one `slot.sh` invocation per
bench, slot 0, criterion means of the rounds. `data_path`, `gate` and `local_graph` ran on
`BENCH_CPUS_A`, `send_stream` on `BENCH_CPUS` (its four runtime workers and both stacks need
more than three CPUs). The 1-minute load per round: `data_path` 0.9-1.5 (two runs, five rounds
a side), `gate` 0.7-1.0 (a first run at 3.8-5.3 was discarded), `send_stream` 1.4-2.4,
`local_graph` 0.4-1.3.

| Bench / case | 0.19.3 | 0.20.0 | Change |
| --- | --- | --- | --- |
| `data_path` `core_round_trip/64` | 417.1 ns | 416.5 ns | -0.1 % |
| `data_path` `core_round_trip_batch32/64` | 13.02 us | 13.04 us | +0.1 % |
| `data_path` `core_round_trip/1420` | 1.227 us | 1.247 us | +1.7 % |
| `data_path` `core_round_trip_batch32/1420` | 39.11 us | 39.24 us | +0.3 % |
| `gate` `established/gate` | 42.73 / 40.92 ns | 41.74 / 41.40 ns | +1.2 % in round 2 |
| `gate` `established/outbound` | 42.88 / 40.78 ns | 41.98 / 41.58 ns | +2.0 % in round 2 |
| `gate` `established/filter` | 45.59 / 45.54 ns | 45.97 / 45.59 ns | +0.5 % |
| `gate` `baseline/pass_gate` | 0.62 ns | 0.62 ns | 0 |
| `send_stream` `netstack_send/streams_1` | 3.268 ms | 3.240 ms | -0.9 % |
| `send_stream` `netstack_send/streams_4` | 2.082 ms | 2.128 ms | +2.2 % (one wide B round) |
| `send_stream` `netstack_send_1cpu/streams_1` | 3.406 ms | 3.400 ms | -0.2 % |
| `send_stream` `netstack_send_1cpu/streams_4` | 4.152 ms | 4.131 ms | -0.5 % |
| `send_stream` `netstack_udp_send/flows_1` | 563.7 us | 552.9 us | -1.9 % |
| `send_stream` `netstack_udp_send/flows_4` | 479.1 us | 472.0 us | -1.5 % |
| `send_stream` `netstack_udp_send_1cpu/flows_1` | 428.8 us | 423.7 us | -1.2 % |
| `send_stream` `netstack_udp_send_1cpu/flows_4` | 430.4 us | 427.0 us | -0.8 % |
| `local_graph`, all 34 cases | | | -1.3 % to +1.1 %, and `swap_sink/bare_send_batch_*` +3.4 % from one B round (equal in the other) |

The gate's first A round had wide intervals (`pass_gate` 2.34 ns), so the changes on the
established paths are taken from the second round: the scoped check costs about 0.5-0.8 ns
there, as measured on its branch (+0.5 to +1 ns). `core_round_trip/1420` is +20 ns in each of
five rounds with tight intervals, while the 64-byte and batched round trips are unchanged; this
is code placement, not added work (below). The other changes
stay within the noise. Per workstream, each against `52eb983` on its branch before the rebase:

- Netstack control from the first input, default configuration: `netstack_send/streams_{1,4}`
  and `netstack_udp_send/flows_{1,4}` within the noise over four runs (the `Decide` path is
  not on these benches).
- Scoped flow gate decisions: `established/gate` +0.5 to +1 ns, new flows, later fragments and
  ICMP errors +1.5 to +2.5 ns, the inert gate unchanged; a const-generic variant was rejected
  for outlining shared helpers (+6 ns on `icmp_error/v6`).
- Local barrier and plaintext ingress: `core_round_trip/64` 423.5 / 423.3 ns,
  `core_round_trip_batch32/64` +0.7 %; `local_graph` -1.7 % to +1.3 % on a quiet host.
- The 0.19.4 fixes: `vnet/segment_tcpv4_64k` 3.185 / 3.183 us, the coalescer unchanged, the
  gate's IPv6 cases within the noise.

`core_round_trip/1420` by step (2026-10-27, slot 0, three interleaved rounds per build, load
1.2-2.0, change of the mean against `fb67db9`):

| Build | Code | Version | `/1420` | `/64` |
| --- | --- | --- | --- | --- |
| `fb67db9` | 0.19.3 | 0.19.3 | reference | reference |
| release A, W2, W1 (each alone) | binary identical to `fb67db9` | 0.19.3 | +0.1 % (release A) | -0.3 % |
| W3 alone, and the integration before the version commit (binary identical to W3) | release B | 0.19.3 | +0.0 % / -0.1 % | -0.6 % |
| `fb67db9` with the version set to 0.20.0 | 0.19.3 | 0.20.0 | -0.0 % | -0.1 % |
| 0.20.0 head | release B | 0.20.0 | +1.8 % / +0.8 % | -0.4 % / -0.5 % |
| 0.20.0 head with the version set to 0.20.1 | release B | 0.20.1 | -1.0 % | -0.1 % |

Only `nsplane-core`, `nsplane-packet` and `nsplane-noise` reach this bench, so the binaries of
release A, W2 and W1 equal `fb67db9`'s, and the merges from W3 on up to the version commit equal
W3's.
The cost appears with the version change alone, and the same source at 0.20.1 is faster than
0.19.3. The version is part of every crate's symbol hash, so it moves functions in the binary:
`objdump` of the W3 and the 0.20.0 builds shows the same instruction count (526,948) with every
function body of equal length, the 81 bodies that differ differing only in RIP-relative data
offsets, and the round-trip routines of the bench (the criterion closures the core path is
inlined into, `encapsulate_batch`, `decapsulate_batch`) starting at another 16-byte offset of a
cache line. The 0.20.0 and 0.20.1 builds agree in every hot function's instructions as well. The
AEAD code is at the same alignment in all of them. A per-packet cost of this size that depends on
the version string is placement; nothing is added on the 1420-byte path.
