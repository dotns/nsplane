# nsplane Architecture

This page describes what is on `main`. The target design and roadmap are in
[design.md](design.md).

## Crates

| Crate | Path | Role |
|---|---|---|
| `nsplane-noise` | `crates/nsplane-noise/` | The Noise protocol state machine (`noise`); no I/O |
| `nsplane-packet` | `crates/nsplane-packet/` | Packet buffers (`PacketBuf`, `PacketPool`, `PacketBatch`), IP header views, shared value types (`PeerId`, `TransportId`, `Path`, `Ecn`) |
| `nsplane-core` | `crates/nsplane-core/` | Sans-I/O engine core: peers, cryptokey routing, timers, path policy, packet filters |
| `nsplane` | `crates/nsplane/` | Tokio driver: `Engine`, `EngineBuilder`, `EngineHandle`, events, the I/O traits, `UdpTransport`, the fragmentation stage (`FragmentConfig`) |
| `nsplane-acl` | `crates/nsplane-acl/` | Accept-only ACL policy engine (`AclEngine`), the `AclFilter` and `FlowTracker` packet filters |
| `nsplane-nat` | `crates/nsplane-nat/` | IPv4/IPv6 translation (`Translator`, `TranslationTable`) and service-publishing DNAT/SNAT (`PortMap`, `Conntrack`) packet filters |
| `nsplane-tun` | `crates/nsplane-tun/` | OS TUN devices as `PacketSource`/`PacketSink` |
| `nsplane-netstack` | `crates/nsplane-netstack/` | User-space TCP/IP stack on smoltcp as `PacketSource`/`PacketSink`: TCP and UDP endpoints for IPv4 and IPv6 |
| `nsplane-uapi` | `crates/nsplane-uapi/` | The `wg` UAPI over an `EngineHandle`; Unix socket listener |
| `nsplane-cli` | `crates/nsplane-cli/` | Linux/macOS development daemon: TUN + engine + UAPI |
| `nsplane-examples` | `examples/` | Not published: runnable example binaries on the public APIs (`src/bin/`) and their shared node code (`src/lib.rs`), including the single-port relay and its UDP and WSS client transports |

```text
nsplane-noise (noise) ─► nsplane-core ─► nsplane ─► nsplane-tun, nsplane-uapi ─► nsplane-cli
nsplane-packet ────────► nsplane-core, nsplane
nsplane, nsplane-packet ─► nsplane-netstack
nsplane-core, nsplane-packet ─► nsplane-acl, nsplane-nat
```

## nsplane-noise

- `noise`: transport-agnostic protocol core. `Tunn` owns the handshake, the session ring,
  the timers, and the per-peer packet queue. It never does I/O: callers pass datagrams in
  and get back a `TunnResult` telling them what to write and where.
  - `handshake`: Noise_IKpsk2 handshake and cookie handling.
  - `session`: transport-data AEAD and the anti-replay window.
  - `rate_limiter`: mac1/mac2 verification and cookie replies under load.
  - `timers`: the WireGuard timer state machine (rekey, keepalive, expiry).
- `noise::wire`: `zerocopy` views of the four message layouts. Transport data is sealed
  and opened in place (`Tunn::encapsulate_in_place` / `decapsulate_in_place`).

## nsplane-core

`Core` performs no I/O and keeps no clock of its own. A driver feeds it `Input`s (local
packets, received datagrams, configuration changes) with `handle_input`, calls
`handle_timeout` when `poll_timeout` is due, and drains `poll_output`: datagrams to
transmit, packets to deliver, and events. Packets go through in place: a local packet is
sealed in its own buffer and leaves as the transmit, a datagram is opened in its buffer and
leaves as the delivery; buffers come back through `recycle`. Peers are looked up by key,
session index and allowed IP (cryptokey routing). Path selection and roaming are delegated
to a `PathPolicy` (`StandardRoaming` by default), local packet rewriting and interception to
`PacketFilter`s.

The filter chain is an onion: filters are installed from the wire side to the local side,
decrypted packets run through them in install order and local packets in reverse. A local
packet is routed by its destination (longest allowed-IP match) before the filters run, and a
decrypted packet's source is checked against the peer's allowed IPs before them, so filters
that rewrite addresses need those addresses in the peers' allowed IPs. `Core::route` exposes
the routing decision, e.g. to pick the peer `Core::inject_inbound` delivers a locally
generated reply as.

`handle_input_deferred` is the same entry point for a driver that encrypts on several
threads: the cryptography of a local packet or a received transport data message comes back
as a `CryptoJob` (everything before it, such as routing and the outbound filters, has
already run), `CryptoJob::run` seals or opens the packet under the lock of that peer's
tunnel only, and `complete_job` does the rest in the core (counters, completed handshakes,
roaming, the source check, the inbound filters, the output). Each peer's tunnel sits behind
its own mutex for this; without jobs every lock is uncontended.

## nsplane (driver)

One owner task owns the `Core` and loops: it waits for a handle command, a local packet, a
received datagram or the core's next timeout, feeds the core and drains its outputs. Four
I/O tasks surround it, each connected through a bounded queue (1024 packets by default):

```text
PacketSource ─► source task ─┐                       ┌─► transmit task ─► Transport::send
                             ├─► owner task (Core) ──┤
Transport::recv ─► recv task ┘          ▲            └─► sink task ─► PacketSink
                                        │
                          EngineHandle commands (64)
```

The core is never shared; the only lock on the data path is each peer's tunnel mutex, which
is uncontended unless the crypto worker pool is on.

- `EngineHandle` sends commands to the owner (peers, keys, allowed IPs, path, transport,
  stats, injection, shutdown) and returns their replies.
- Events are published on a `broadcast` channel (`EngineHandle::subscribe`); publishing never
  blocks, and a lagging subscriber loses the oldest events.
- Drops are counted per reason (`EngineHandle::drop_counters`) and published as events.

Backpressure:

- Local packets are never dropped by the engine: when the transmit queue is full, datagrams
  wait in the owner task and the owner stops reading local packets until they have moved to
  the queue, which holds back the source.
- Datagrams caused by received datagrams or timers that find the waiting datagrams at the
  queue capacity are dropped (`DROP_TRANSMIT_FULL`).
- A full sink queue drops the decrypted packet (`DROP_SINK_FULL`); a closed sink or
  transport drops with `DROP_SINK_CLOSED` / `DROP_TRANSPORT_CLOSED`, and without a transport
  datagrams are dropped with `DROP_NO_TRANSPORT`.
- An I/O side that reports `BrokenPipe` stops its task; the engine keeps running without it.

### Queue depths

`EngineHandle::queue_stats` reports, for every bounded queue, its capacity and high-water
mark (the most items it held at once) since the start or the last `take_queue_stats`, which
also restarts the marks. The owner task samples each queue whenever it sends to or receives
from it (a receive sees the occupancy just before it, which is the peak since the previous
receive), with plain fields and no locks or atomics on the data path. The event channel is
sampled only for events other than `Event::Dropped`, because reading its occupancy takes the
channel's locks.

| Queue | Capacity | Producer -> consumer |
| --- | --- | --- |
| `command` | 64 | handles -> owner |
| `local` | `queue_capacity` | source task -> owner |
| `datagrams` | `queue_capacity` | every receive task -> owner |
| `deliver` | `queue_capacity` | owner -> sink task |
| `recycle` | `queue_capacity` | every transmit task -> owner (full: buffer dropped) |
| `transmit` | `queue_capacity` per transport | owner -> transmit task |
| `backlog` | `queue_capacity` per transport | owner, waiting for room in `transmit` |
| `events` | `event_capacity` | owner -> subscribers |

Measured with the default capacity of 1024 on two engines linked in process (release
build, 4-thread runtime, 32-core host shared with other jobs, so throughput is noisy); the
highest mark of either engine over three runs:

| Load | local | datagrams | deliver | recycle | transmit | backlog | command | events | Drops |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Ping-pong, 1300 B, one packet in flight (the `data_path` pattern) | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | none |
| UDP paced, 64 x 1300 B per ms, channel link | 64 | 41 | 53 | 64 | 64 | 0 | 0 | 0 | none |
| UDP paced, 64 x 1300 B per ms, loopback `UdpTransport` | 103 | 43 | 64 | 107 | 107 | 0 | 0 | 0 | none |
| UDP flood, 100k x 1300 B, channel link | 1024 | 341 | 866 | 1023 | 1024 | 449 | 0 | 0 | none |
| UDP flood, 100k x 1300 B, loopback `UdpTransport` | 1024 | 120 | 239 | 1013 | 1024 | 280 | 0 | 0 | none (the kernel drops ~25%) |
| Netstack TCP, 1 connection, 32 MiB echoed (2.5-7.4 Gbit/s) | 668 | 642 | 212 | 247 | 665 | 0 | 0 | 0 | none |
| Netstack TCP, 4 connections, 32 MiB echoed | 1024 | 1024 | 1024 | 469 | 1024 | 1024 | 0 | 0 | `DROP_SINK_FULL` in 3 of 6 runs |
| Netstack TCP, 8-16 connections, 32 MiB echoed | 1024 | 1024 | 1024 | 896 | 1024 | 1024 | 0 | 0 | `DROP_SINK_FULL` in every run |

With capacity 2048, 8 and 16 netstack connections ran without a drop (deliver peaked at
494 and 2021); with 512 and 256, even 4 connections dropped at the deliver queue. Once the
deliver queue drops, the netstack's TCP throughput collapses (to 130-450 Mbit/s), and in
some runs the connections stalled for good with every engine queue empty, a loss recovery
problem of the netstack rather than of the queues.

Defaults, from these numbers:

- `queue_capacity` stays at 1024. A single bulk TCP flow, the heaviest paced load, peaks at
  about 670 (1.5x headroom), and paced or request/response traffic stays far below. Floods
  and many parallel bulk flows fill every queue upstream of the bottleneck whatever the
  capacity (the in-process loop is bounded by the TCP windows, not by a link rate), so a
  larger default would only add latency and memory, and a smaller one turns the sink-full
  drops of the multi-flow case into a single-flow problem. Since queued packets are sized
  to their contents, an idle or lightly loaded queue costs little.
- The command queue stays at 64: every handle call waits for its reply, so it holds at most
  one command per concurrent caller (the marks never passed 1).
- `event_capacity` stays at 1024: without a subscriber the channel holds nothing, and a
  subscriber that stops reading fills any capacity.

Embedders that run many parallel bulk flows through a userspace netstack should raise
`queue_capacity` (2048 held 16 flows without a drop here) and watch the marks and
`DROP_SINK_FULL` with `queue_stats` and `drop_counters`.

### Crypto worker pool

The single owner task is the limit of one engine's throughput: it seals and opens every
packet. `EngineBuilder::crypto_workers(n)` with `n` of 2 or more moves that cryptography to
`n` worker tasks; 0 or 1 (the default) keeps today's single task, which then never calls the
deferred API.

```text
local packets ─┐           ┌─► worker 0     ─┐
               ├─► owner ──┼─► worker 1     ─┼─► done queue ─► owner ─► sink, transmit tasks
datagrams     ─┘           └─► worker n - 1 ─┘
```

- Sharding by peer. The owner feeds each local packet and received datagram to
  `Core::handle_input_deferred`, which routes it (receiver index or destination), runs the
  outbound filters and returns a `CryptoJob` for the peer's tunnel. The job goes to worker
  `peer id % n`; each worker runs its jobs in arrival order and hands them back on one done
  queue, and the owner completes them (`Core::complete_job`) in the order they come back. So
  all packets of one peer, in both directions, are sealed, opened and emitted in arrival
  order, while different peers are processed in parallel. Peer ids are handed out in order,
  so peers spread evenly over the workers; a single peer never uses more than one.
- Batches. Jobs go to a worker in batches of up to 64 (`MAX_BATCH`): a worker's batch is
  handed over when it is full, together with every other batch, or when the owner has
  nothing else ready, and a worker hands each batch back whole. A busy owner thus wakes each
  worker once per batch instead of once per packet; handing over every packet on its own
  cost as much as the cryptography it moved and gained nothing.
- Everything else stays on the owner: handshakes (the gate, the responses, flushing the
  packets queued behind a handshake), timers, configuration, events, drop counters, roaming
  and the per-peer counters. A handshake or a timer that touches a peer's tunnel while a
  worker holds it waits for that one packet. The order on the wire stays the arrival order
  even when the owner seals a keepalive or flushes queued packets while newer packets of the
  peer are with a worker: those are emitted only once they come back.
- Bounds: at most `queue_capacity` jobs are with the workers. While that many are, the owner
  stops reading local packets and received datagrams (handle calls, timers and finished jobs
  are still served), which holds back the sources as a full transmit queue does. Every
  worker queue and the done queue hold that many jobs, so neither side ever waits on them.
- Handle calls that read or change peers, sessions or counters (configuration, peer stats,
  injection, forced handshakes, drop counters) first wait for every job in flight, so they
  act after every packet read before them, exactly as without workers: per-peer stats and
  drop counters stay exact, and a removed peer's packets read before the removal still go
  out while later ones are dropped as `no route` / `unknown session`.
- Parallelism needs a multi-threaded tokio runtime; on a current-thread runtime the workers
  interleave with the owner and only add overhead.

Throughput note, from `cargo bench -p nsplane --bench worker_pool` (bench profile with
LTO, multi-threaded runtime, 32-core host shared with other jobs; the range of two runs): a
hub engine with 8 peers, each its own engine without workers on an in-memory link, sends
120 packets to every peer while every peer sends 120 to the hub, so the hub seals and opens
all 1920 packets of an iteration. The pool off is the default of 0 workers; 1 worker is the
same code path.

| Packet | Pool off (0 or 1) | 2 workers | 4 workers |
| --- | --- | --- | --- |
| 64 B | 0.96-1.10 Mpps | 1.02-1.36 Mpps | 0.97-1.26 Mpps |
| 1420 B | 566-696 kpps (6.4-7.9 Gbit/s) | 0.88-1.08 Mpps (10.0-12.3 Gbit/s) | 0.88-1.03 Mpps (10.0-11.6 Gbit/s) |

With full-size packets the pool moves the hub about 1.5x further; small packets gain little,
since there the cryptography is a small part of the owner's work per packet (queues,
routing, counters). Beyond 2 workers the owner task itself, which still touches every
packet twice, is the limit, so 4 workers do not add to 2. Sharding `Core` itself by peer
(one owner per shard) would lift that limit, at the cost of splitting the handshake gate,
the peer table and the allowed IPs across shards.

The pool off costs one uncontended lock of the peer's tunnel per packet. The core's
`data_path` bench, base and branch alternating three times, showed no change beyond the
run-to-run spread (medians: `core_round_trip` 616 -> 569 ns at 64 B and 1347 -> 1362 ns at
1420 B, `core_encapsulate` 297 -> 281 ns and 693 -> 674 ns, `core_decapsulate` 266 -> 286 ns
and 705 -> 695 ns; single runs varied by up to 15%).

`UdpTransport` is the network side: one dual-stack UDP socket with fwmark and ECN support,
4 MiB socket buffers requested (clamped by `net.core.rmem_max` / `wmem_max`) and segmentation
offload through `quinn-udp`.
`ChannelSource`, `ChannelSink` and `ChannelTransport` are in-memory implementations for tests
and embedders.

**Fragmentation.** `EngineBuilder::fragmenter(FragmentConfig)` installs a stage on the local
path, in the owner task before the core, that keeps every local packet within the source's
MTU (`PacketSource::mtu`, so it follows MTU changes); without it local packets enter the
core whatever their size.

- An IPv6 packet above the MTU is answered with an ICMPv6 Packet Too Big carrying the MTU.
- An IPv4 packet above its ceiling is answered with an ICMP Fragmentation Needed carrying
  the ceiling when DF is set, and is otherwise split into IPv4 fragments that enter the core
  one by one. The ceiling is the MTU for native IPv4 and 20 bytes lower for destinations
  that `FragmentConfig::translated` (e.g. `Translator::ipv4_translated_predicate`) reports
  as translated to IPv6, whose fragments are sized to fit the MTU once translated with an
  IPv6 Fragment header (MTU - 28). A UDP datagram without a checksum toward a translated
  destination gets one before it is split, so each fragment translates on its own.
- The errors look as if the packet's destination had sent them: they are delivered to the
  local side as coming from the peer `Core::route` picks for that destination (no route: no
  error) through `Core::inject_inbound`. They are rate-limited (a burst of 10, then 5 per
  second) and never sent about ICMP errors, multicast or broadcast packets, or non-first
  fragments.

For a hybrid local side, e.g. a TUN device next to a userspace netstack, `Splitter` is a
`PacketSink` that routes each delivered packet to one of several sinks by a closure
(`Fn(PeerId, &PacketBuf) -> usize`) and `MergeSource` is a `PacketSource` that serves
several sources round-robin and reports the smallest of their MTUs. The splitter awaits
only the chosen sink, but a waiting sink still holds back the engine's next delivery;
packets routed to an index out of range are dropped and counted (`Splitter::misrouted`).

**Batched I/O.** The I/O tasks move up to `MAX_BATCH` (64) packets or datagrams per call
through `PacketSource::recv_batch`, `PacketSink::send_batch`, `Transport::recv_batch` and
`Transport::send_batch` (default methods that fall back to one at a time; `DynTransport`
mirrors them), with the same backpressure, stop handback and recycling as single calls:

```text
TUN read (vnet hdr + up to 64 KiB) ─► segments (<= MTU) ─► core seals ─► GSO UDP send
UDP GRO read ─► zero-copy slices ─► core opens in place ─► coalesced TUN writev
```

Offload is negotiated where the device or socket is opened. `Tun::create` (Linux,
Android) asks for `IFF_VNET_HDR` with checksum offload and TSO, plus USO when the kernel
accepts it, and falls back to a plain `IFF_NO_PI` device; `Tun::offload` reports the
result. `UdpTransport::bind` sets the socket up with `quinn-udp`: GSO on send where the
platform has it, GRO on receive on Linux and Android, each GRO datagram a
`PacketBuf::from_shared` slice of the read buffer without headroom. A segmented send that
fails with `EIO`/`EINVAL` falls back to one datagram per send, and where `quinn-udp`
cannot set the socket up (Wine) the transport sends with plain `send_to`. With offload on
the socket sets DF, so outer datagrams above the path MTU fail with `EMSGSIZE`; the engine
counts them under `TRANSPORT_SEND_ERROR`. `TunOptions::offload(false)`,
`UdpTransport::bind_with_offload(.., false)` and the examples' `--no-offload` opt out.

## nsplane-tun

`Tun::create` opens a TUN device, `Tun::from_fd` (Unix) adopts one, and `Tun::split`
yields a `TunSource` and a `TunSink` registered with the tokio reactor.

- `linux`: `/dev/net/tun` (Linux, Android), raw IP packets, or with `IFF_VNET_HDR` a
  10-byte virtio-net header per read and write.
- `offload`: the virtio-net codec: GSO segmentation of read super-packets and TCP/UDP
  coalescing for writes (one `writev` of header and packet pieces per super-packet).
- `darwin` and `utun`: the utun control socket (macOS, iOS), packets framed by a 4-byte
  address-family header.
- `unix`: non-blocking fd I/O shared by both.
- `windows`: a Wintun adapter; a reader thread feeds the source.

## nsplane-netstack

`NetStack::new` starts a user-space TCP/IP stack on smoltcp for the addresses in its
`NetStackConfig`, and `NetStack::split` yields a `NetStackSource` (egress) and a
`NetStackSink` (ingress) that an `EngineBuilder` takes in place of a TUN device. The
application side is `NetStackHandle`: `incoming_tcp` and `incoming_udp` accept connections
and flows to any port of the stack's addresses, `connect_tcp` and `bind_udp` open them.

One driver task owns smoltcp. Each iteration takes a bounded batch of ingress packets,
sizes the TCP listener pool to the batch's SYNs, then ingests the packets one by one with a
single smoltcp egress turn after each (`poll_ingress_single` / `poll_egress`), moves
connection bytes between smoltcp and the applications, and flushes egress. UDP bypasses
smoltcp on its own dispatch path.

- Every queue is bounded (ingress, egress, accept and datagram capacities in
  `NetStackConfig`); the sink waits while ingress is full.
- Everything the stack discards is counted per reason in `NetStackHandle::stats`
  (`NetStackStats`): malformed, foreign or unsupported packets, refused SYNs, connections
  and flows not accepted, full UDP queues, the flow limit, and egress produced while the
  egress backlog is full.
- smoltcp sees the configured MTU as its device MTU, so it advertises an MSS of `mtu - 40`
  (IPv4) or `mtu - 60` (IPv6) and no emitted packet exceeds the MTU, which the source
  reports and never changes. Socket buffers hold 512 IPv4-sized segments, so the window
  scales with the MSS.
- Every TCP socket (connect and listener pool) runs CUBIC congestion control (smoltcp
  feature `socket-tcp-cubic`, no extra crate). Without it smoltcp sends the whole peer
  window at once and, after a retransmission timeout, all of it again; a hop that drops
  part of the burst (a full socket buffer on a loaded host) drops the retransmission too,
  and the timeouts (1 s minimum, doubling) add up past 30 s. CUBIC rather than Reno: both
  restart from one segment after a timeout and measured alike on the bottleneck below
  (32 MiB in 40-41 s with CUBIC, 40-50 s with Reno), CUBIC recovered faster at 1 % random
  loss (16 MiB in 1.1-4.1 s, Reno 4.1-5.1 s) and is the default of Linux, Windows and macOS;
  its `f64` arithmetic is no concern on the targets nsplane runs on.
- Two smoltcp 0.14 defects stalled connections for good under loss when both ends send
  (an echo, request and response); the driver works around both without touching
  smoltcp.
  - After a retransmission timeout smoltcp rewinds its next sequence number to the oldest
    byte it saw acknowledged and stamps its pure ACKs with it. If the peer had already
    received past that point (only its ACKs were lost), the peer drops those ACKs as old,
    acknowledgement included. With both ends in that state each resends data the other
    has, cwnd stays at one segment and the timeouts back off to 60 s (traced: both sides
    one segment in flight, retransmission timeout 32 s, each receiver 15-72 KB past the
    other's `snd_una`). The device records the highest acknowledgement number each connection's
    peer sent (`device::note_peer_ack`, also from segments smoltcp drops) and moves an
    outgoing pure ACK whose sequence number lies before it up to it
    (`device::fix_ack_seq`, checksum adjusted): that is where the peer's window starts,
    which smoltcp always accepts, and what Linux would send.
  - When a lost segment was the last in the peer's window, window scaling rounds the few
    bytes left down to a zero window, the sender switches to zero-window probes and never
    retransmits the lost bytes, and the receiver drops the sender's ACKs, whose sequence
    number now lies past its window (traced: sender `remote_win_len` 0, 4 bytes in flight,
    timer `Idle` after its probe timed out). A connection that moved no application bytes
    for 1 s takes up to 1 KiB more into a full application buffer to reopen its window,
    and keeps a 1 s keep-alive while it has bytes to send, standing in for the persist
    timer (`stack::nudge_stalled`).

  The engine's `DROP_SINK_FULL` is ordinary loss to TCP: a decrypted segment the engine
  drops at the full sink is never acknowledged, the retransmission timer stays armed and
  smoltcp resends it; the stalls above only needed such a loss at the wrong moment.
  `parallel_echo_*` in `tests/netstack_lossy.rs` run eight 1 MiB echoes through
  256-packet engine queues, without loss and at 2 % loss; they passed 10 consecutive runs
  in debug (2 % loss: 8.3-17.3 s) and in release (9.0-23.1 s), where without the two
  workarounds 1 of 10 debug and 3 of 10 release runs stalled a flow for 60 s.

### Netstack throughput

Release, two netstacks over two engines on an in-process `ChannelTransport` pair (no
latency), one TCP connection, MTU 1420; the link wrappers are `nsplane_e2e::LossyTransport`
(drops a deterministic fraction of the data messages in each direction) and
`nsplane_e2e::Bottleneck` (25 MB/s behind a 64-datagram drop-tail buffer, like a socket
buffer drained by a busy receiver). Two runs each; "after" is CUBIC with both stall
workarounds:

```text
cargo test --release -p nsplane-e2e --test netstack_lossy -- --ignored --nocapture
```

| Case | Before (no congestion control) | After |
| --- | --- | --- |
| TCP, 64 MiB, no loss | 440.5 / 441.0 MB/s | 321.1 / 319.4 MB/s |
| TCP, 16 MiB, 1 % loss | 41.1 s / 35.1 s (0.4-0.5 MB/s) | 4.09 s / 2.09 s (4.1-8.0 MB/s) |
| TCP, 16 MiB, 3 % loss | not done after 60 s (both) | 54.2 s / 59.2 s (0.3 MB/s) |
| TCP, 16 MiB, bottleneck | not done after 60 s (both, ~2650 drops) | 20.9 s / 18.9 s (0.8-0.9 MB/s, ~330 drops) |
| UDP, 50 000 x 1200 B, no loss | 902.7 / 468.4 MB/s | 587.1 / 608.7 MB/s |

Without loss the stack is not the limit (runs of the same build spread from 320 to
460 MB/s for TCP and 470 to 900 MB/s for UDP: scheduling noise) and congestion control
costs nothing. With loss, smoltcp 0.14 recovers one lost segment per window by fast
retransmit and any further one by a retransmission timeout of at least 1 s (no SACK, no
retransmission on a partial ACK), so elapsed times come in whole seconds and random loss of
2 % or more stays timeout-bound. Congestion control turns the stalls on a congested hop into
completed transfers. A smaller default window was measured and not adopted (see
`WINDOW_SEGMENTS` in `config.rs`): through the bottleneck, 64 segments lose nothing
(32 MiB in 2.9 s), but a window that small caps a connection at 1.8 MB/s over a 50 ms path,
and without loss it gains nothing. `tests/netstack_lossy.rs` asserts that 8 MiB complete
intact at 1 % loss within 15 s, next to a loss-free reference.

L2's queue harness (4 and 8 parallel 32 MiB-total echo connections over two engines at
queue capacity 512 and 1024, release, 3 runs per cell) completed every run after the
change (sink drops in one 8-connection run at 512, recovered in 2.2 s); before it, the
same harness stalled a connection for good in 2 of 20 runs at 8 connections and 512.

## nsplane-uapi and the CLI

`Uapi` answers `get=1` and `set=1` over an `EngineHandle`; `listen_port` and `fwmark` bind a
new `UdpTransport` and install it with `EngineHandle::set_transport`. Over an engine whose
transport the UAPI does not own (`Uapi::with_external_transport`, e.g. a relay or WSS
carrier) they never replace it: the reported value is a no-op, any other fails with
`EADDRINUSE`. On Unix,
`UapiListener` binds `/var/run/wireguard/<iface>.sock`. Windows has no listener yet.

`nsplane-cli` builds a tokio multi-thread runtime (`--threads` workers), creates the TUN,
builds an engine on it, binds an ephemeral UDP port, serves the UAPI, drops privileges to
`SUDO_UID`/`SUDO_GID`, and runs until SIGINT or SIGTERM.

## nsplane-acl

`AclEngine` holds its whole state (the compiled default `AclPolicy`, the rule namespaces,
the directed grants and the open pinholes) as one immutable snapshot behind an `ArcSwap`:
writers serialize on a mutex and publish a new snapshot, and evaluation takes one lock-free
load per packet. `load` compiles and runs the policy's tests and swaps it in atomically, and
a rejected update leaves the previous state in effect. With nothing loaded every request is
denied; `clear_all` removes everything in one swap. `merge_layered` combines a local and
remote policies with per-rule provenance; `apply_deny_scope` removes rules reaching
forbidden CIDRs before compilation, so matching stays accept-only.

`AclFilter` is a `PacketFilter` for the engine's filter chain. Inbound packets become
`AccessRequest`s whose principal (a WireGuard key or a terminate binding with a tunnel IP)
comes from a `PeerIdentity`; anything not accepted is dropped with a `reasons` constant.
Non-first IPv4 fragments follow the outcome of their first fragment, and outbound TCP/UDP
packets record reply allowances (with an idle timeout) so replies to flows the local side
opened pass. `FlowTracker` placed after it counts packets and bytes per flow in a bounded
table.

**Namespaces.** A node holds peers from several sources (NSDs, the Quick allow list, app
sessions); each source is a rule namespace (`NamespaceId`: `nsd:<uuid>`, `quick`, or an app
namespace `app:<session>`) stored with `store_namespace` and replaced or removed on its own.
A `NamespacePolicy` names its members by principal (the peer's `source_anchor`, e.g.
`key:<hex>`) with their tunnel addresses, its accept rules (an `AclPolicy`), optional
`outbound` rules and the app kinds allowed to open pinholes (`allow_app_pinholes`). App
namespaces never widen permissions: they carry no accept rules, allow no pinholes and no
grant names them. The default policy applies only to principals that are members of no
namespace, so a node without namespaces behaves as before. An inbound packet from member
`P` to address `d` is evaluated after the reply table:

1. `d` resolves to a member peer `Q` by longest address match; otherwise it is local, and
   the local node is in every namespace.
2. A rule of any namespace common to `P` (its non-app namespaces) and `d` accepts it.
3. When `d` is another peer, a directed `Grant` (from `P` or one of its namespaces to `Q` or
   one of its namespaces, with protocol and ports) accepts it; grants are one-way.
4. When `d` is local, an open inbound pinhole of `P` for the protocol and port accepts it.
5. Otherwise it is dropped with `reasons::CROSS_NAMESPACE` (`d` is a peer sharing no
   namespace with `P`) or `reasons::DENIED`.

**Outbound.** Outbound traffic is unrestricted by default. A peer is outbound-restricted
only when it is in at least one namespace and every one of them sets `outbound` (union: one
unrestricted namespace keeps it unrestricted). Outbound packets to a restricted peer pass
when they match an outbound rule, an open outbound pinhole or the reply allowance of an
inbound flow from that peer the filter accepted; anything else is dropped with
`reasons::OUTBOUND`.

**Pinholes.** An app session reaches a peer only through pinholes in its app namespace:
`open_pinhole` opens one peer, direction, protocol and destination port until a
caller-chosen `expires_at`, and returns a `PinholeGuard`. The app namespace must contain the
peer, and when the peer is in any source namespace one of them must list the app kind in
`allow_app_pinholes` (else `PinholeError::NotPermitted`). A pinhole closes when its guard is
dropped, when it expires on the engine clock (`Instant::now`, or `AclEngine::with_clock`;
`expire_pinholes` sweeps), when its namespace is removed, on `clear_all`, or when it is
revoked (the peer left the app namespace or its source namespaces no longer allow the app
kind); `PinholeStats` counts each reason.

Reply allowances recorded for flows accepted through a grant or a pinhole depend on it.
Removal is lazy: once the grant or pinhole is gone from the current snapshot, a dependent
allowance is removed on its next lookup (`AclFilterStats::reply_revoked`) and the flow's
packets are evaluated from scratch.

**ACL hook.** The filter evaluates a flow once, not every packet. `AclEngine::generation`
increases on every published change (default policy, namespaces, grants, pinholes opened,
closed, swept or revoked, `clear_all`), and a versioned `PeerIdentity`
(`PeerIdentity::generation`, bumped by `PeerIdentityMap`) on every identity change. The
filter caches per peer its resolved principal and flags, and per peer, direction and
five-tuple the verdict of a namespace member's TCP/UDP flow's first packet (the default
policy is cheaper to evaluate than to cache), in the reply table (one lock, one
capacity, cached verdicts flushed first when full), both tagged with the two generations: a
hit under other generations is evaluated again, so a change applies to the very next
packet, and a verdict accepted through a pinhole is also checked against the pinhole's
expiry. Peers whose namespaces (or the default policy) accept every destination, port and
protocol and are not outbound-restricted, as computed on every update, bypass the
evaluation. The reply table, fragments and fail-closed rules are unchanged, and verdicts and
counters equal a full evaluation (a differential test checks it). The full rules and
per-packet bench numbers (`cargo bench -p nsplane-acl --bench namespaces`) are in the crate
docs (`crates/nsplane-acl/src/lib.rs`, *Namespaces*, *Pinholes*, *ACL hook* and
*Performance*).

nsplane only enforces: the peer source lifecycle (`PeerSource`), rendezvous and the
pairing and transfer state machines stay in ns, which stores namespaces, grants and pinholes
through this API. `examples/src/bin/app_session.rs` shows a file transfer on it.

## nsplane-nat

Packet filters for the engine's filter chain; they rewrite packets in place and keep no I/O.

**Address model.** Every peer owns a /127 IPv6 group, `node6` (native) and `node4` (its IPv4
side). This node presents a peer to local applications as an IPv4 alias (`alias4 <-> node4`)
and optionally an IPv6 alias (`alias6 <-> node6`); the node itself is `self4 <-> node4`, and
IPv4 LAN prefixes pair with IPv6 /96 prefixes holding the IPv4 address in the low 32 bits
(`lan4 <-> lan6`), behind this node or behind a peer. `TranslationTable` (built and validated
by `TranslationTableBuilder`) holds this model immutably; `Translator::store` replaces it
atomically while traffic flows.

**Translator.** A stateless RFC 7915 translator: local IPv4 to an `alias4` or a peer's LAN
leaves as IPv6 to `node4` / `lan6`, IPv6 to `alias6` is rewritten to `node6`, and the
replies are mapped back; native IPv4 and IPv6 pass unchanged and packets spoofing a
local-view address are dropped. TTL/hop limit, ICMP/ICMPv6 (echo and errors, including the
quoted packet and the MTU of Fragmentation Needed / Packet Too Big) and fragments (with an
IPv6 Fragment header) are translated; TCP/UDP checksums are verified and updated
incrementally. A fragmented IPv4 UDP datagram without a checksum is reassembled first,
which completes only when the first fragment arrives first. A translated packet grows by 20
bytes (28 with a fragment header) inside its buffer, so packets need that much spare
capacity (else `reasons::NO_ROOM`). Since the core routes and checks sources before the
filters, each peer's allowed IPs must contain its `alias4/32`, the LAN IPv4 prefixes behind
it, its `alias6`, `node4`, `node6` and the `lan6` prefixes behind it.

**PortMap and Conntrack.** `PortMap` publishes local services to peers: a `PortMapRule` maps a
tunnel-facing `listen` address and port (TCP or UDP) to a local `target` of the same family,
optionally for some peers only (other peers are dropped). Inbound packets are DNATed and
their flow recorded in a `Conntrack`; replies are SNATed back to `listen` when routed to the
flow's peer, and ICMP errors quoting a flow are rewritten too. `Conntrack` is bounded (least
recently seen flow evicted), expires flows on per-protocol idle timeouts (TCP state aware)
without a background task, and takes an injectable clock. `PortMap::set_rules` swaps rules
atomically and drops the flows of changed rules.

**Order.** The recommended chain is `[AclFilter, PortMap, Translator]`: the translator sits
next to the local side, so the ACL and the port map see overlay IPv6 in both directions and
ACL policies need no rules for the IPv4 aliases. With the engine's fragmentation stage and
`Translator::ipv4_translated_predicate`, oversized local IPv4 to translated destinations is
fragmented to fit the MTU after translation.

## Unsafe code

`unsafe` lives only in `nsplane-tun`'s platform
modules (`unix`, `linux`, `darwin`, and loading Wintun in `windows`), each with SAFETY
comments. `nsplane-packet`, `nsplane-core`, `nsplane`, `nsplane-acl`, `nsplane-nat`, `nsplane-netstack`, `nsplane-uapi` and `nsplane-cli` declare
`#![forbid(unsafe_code)]`. See `docs/decisions/2026-10-01-unsafe-code-in-boringtun.md`.

## Crypto

- ChaCha20-Poly1305 (transport data, handshake fields): `aws-lc-rs` (`aws-lc-sys` C/asm core,
  the pma-rust pre-sanctioned crypto exception).
- Constant-time comparisons: `subtle`.
- XChaCha20-Poly1305 (cookies), BLAKE2s, HMAC: RustCrypto.
- X25519: `x25519-dalek`.

## Testing

`just check` runs the unit and integration tests of every crate (the engine against
in-memory channels). `just e2e` (`scripts/e2e/linux.sh`) runs `nsplane-cli` against kernel
WireGuard in two containers. `just e2e-examples` (`scripts/e2e/examples.sh`) runs the
`nsplane-examples` binaries in containers as a matrix of local sides and transports plus
relay scenarios, against each other and kernel WireGuard (see `examples/README.md`).

`nsplane-e2e`'s `translate`, `port_map` and `fragment` tests run the `nsplane-nat` filters
and the fragmentation stage between engines over channel transports (including the full
`[AclFilter, PortMap, Translator]` stack); the `translate_node` and `port_map` example
scenarios run them in containers against kernel WireGuard.
