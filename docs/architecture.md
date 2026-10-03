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
| `nsplane-nat` | `crates/nsplane-nat/` | IPv4/IPv6 translation (`Translator`, `TranslationTable`) and service-publishing DNAT/SNAT (`PortMap`, `Conntrack`) packet filters; NAT64 to a LAN (`Nat64Lan`) on the local side |
| `nsplane-wss` | `crates/nsplane-wss/` | WebSocket-over-TLS carriers: `WssDialer` for `LinkTransport`, the `WsFrame` stream client (`WssStreamClient`) and terminate leg (`WssStreamServer`) |
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
nsplane ─► nsplane-nat
nsplane ─► nsplane-wss
```

## Public interfaces

Every public item has rustdoc (`cargo doc --workspace --no-deps --open`); that is the
reference for signatures and contracts. This table is the map: what each crate exports and
where it is described below.

| Crate | Entry points | Supporting types |
|---|---|---|
| `nsplane-noise` | `noise::Tunn` (handshake, sessions, timers; `encapsulate_in_place` / `decapsulate_in_place`), `noise::rate_limiter::RateLimiter`, `x25519` keys | `TunnResult`, `noise::errors::WireGuardError` |
| `nsplane-packet` | `PacketBuf` (headroom, `advance` / `reserve_front`, `from_shared`, fallible bounds), `PacketPool`, `PacketBatch`, `IpPacket`, `reassembly::Reassembler` (`push`, `expire`, `stats`, `pending`) | `reassembly::{ReassemblyConfig, ReassemblyStats, Outcome}`; `Path`, `TransportId`, `PeerId`, `Ecn`; header views `Ipv4Header`, `Ipv6Header`, `TcpHeader`, `UdpHeader`, `IcmpHeader`, `Fragment`, `FiveTuple`; `checksum`, `protocol`; errors `Malformed`, `BoundsError`; `HEADROOM`, `MAX_BATCH` |
| `nsplane-core` | `Core` (`handle_input`, `handle_datagrams` / `handle_locals`, the `_deferred` forms and `complete_job`, `handle_timeout` / `poll_timeout`, `poll_output`, `inject_inbound` / `inject_outbound` / `inject_outbound_on`, `force_handshake` / `force_handshake_on`, `route`, `peer_stats`, `recycle`); traits `PathPolicy` (`select`, `on_authenticated`, `observe_every_message`) and `PacketFilter` (`inbound`, `inbound_from`, `outbound`) | `CoreConfig`, `Input`, `Output`, `ConfigChange`, `PeerConfig`, `AllowedIp`, `PeerStats`, `Event`, `Verdict`, `Roam`, `MessageKind`, `StandardRoaming`, `CryptoJob`, `reasons` |
| `nsplane` | `EngineBuilder` (`transport`, `private_key`, `policy`, `filter`, `fragmenter`, `crypto_workers`, `queue_capacity`, `event_capacity`, `stats_interval`, `build`), `Engine` (`handle`, `wait`), `EngineHandle` (peers, keys, allowed IPs, PSK, keepalive, `set_path`, `add_transport` / `remove_transport` / `replace_transport`, `inject_inbound` / `inject_outbound` / `inject_outbound_on`, `force_handshake` / `force_handshake_on`, `suspend` / `resume`, `subscribe`, `peers` / `peer_stats`, `drop_counters`, `queue_stats`, `fragment_stats`, `transport_stats`, `status`, `shutdown`); traits `PacketSource`, `PacketSink`, `Transport` (each with batch methods), `DynTransport`; `LinkTransport` with the traits `LinkDialer`, `LinkSender`, `LinkReceiver` | `UdpTransport` (`with_side_channel`), `SideSender`, `SideDatagram`, `SideStats`, `LinkConfig`, `LinkState`, `ChannelSource` / `ChannelSink` / `ChannelTransport`, `Splitter`, `MergeSource`, `FragmentConfig` / `FragmentStats`, `EngineStatus`, `TransportStats`, `QueueStats` / `QueueDepth`, `Peer`, `Event`, the `DROP_*` reasons, `EngineError`, `TransportError`, `BuildError`, `BoxFuture`; re-exports of the value types |
| `nsplane-wss` | `WssDialer` (`new`, `into_transport`, `state`, `stats`), `WssStreamClient` (`new`, `connect`, `open_tcp`, `open_udp`, `state`, `stats`), `WssStreamServer` (`new`, `with_events`, `run`, `state`, `stats`); traits `BearerProvider`, `WssResolver` | `WssConfig`, `WssTls`, `WssStats`, `WssStreamLimits`, `WssStreamStats`, `WssTcpStream`, `WssUdpFlow`, `WssServerLimits`, `WssServerStats`, `WssOpen`, `Denied`, `WssStreamEvent` / `WssStreamEventKind`, `WssCloseReason`; `frame` (`WsFrame`, `FrameCommand`, `Protocol`, `FrameError`, the command and protocol bytes); `MAX_DATAGRAM`, `MAX_MESSAGE`, `MAX_DATA_PAYLOAD` |
| `nsplane-tun` | `Tun` (`create`, `create_with`, `from_fd` / `from_raw_fd` on Unix, `split`, `offload`, `mtu`, `name`) | `TunOptions`, `TunSource`, `TunSink`, `Offload`, `adopt_fd` (Unix), `MTU_POLL_INTERVAL` |
| `nsplane-netstack` | `NetStack` (`new`, `split`), `NetStackHandle` (`incoming_tcp`, `incoming_udp`, `connect_tcp`, `connect_tcp_from`, `bind_udp`, `stats`, `owns`) | `Ownership`, `NetStackConfig` (`udp_allow_fragmentation`, `reassembly`), `ReassemblyConfig` (re-export), `NetStackSource`, `NetStackSink`, `TcpConnection` (`AsyncRead` + `AsyncWrite`, `unacked`, `last_ack`), `UdpFlow`, `UdpReply`, `UdpSocket`, `NetStackStats`, `DEFAULT_MTU`, `MIN_MTU` |
| `nsplane-acl` | `AclEngine` (`load`, `store_namespace` / `remove_namespace`, `store_grant` / `remove_grant`, `open_pinhole`, `expire_pinholes`, `clear_all`, `is_allowed`, `generation`, `pinhole_stats`), `AclFilter` (`new`, `with_config`, `stats`), `FlowTracker` | policy model `AclPolicy`, `AclRule`, `AclAction`, `AclTest`, `Protocol`, `IpNet`; requests `AccessRequest`, `SourceAssertion`, `TerminateBinding`, `AclDecision`; identity `PeerIdentity`, `PeerIdentityMap`, `wg_peer_anchor`; namespaces `NamespaceId`, `NamespacePolicy`, `NamespaceMember`, `OutboundRule`, `Grant`, `GrantEnd`; pinholes `PinholeSpec`, `PinholeGuard`, `PinholeId`, `Direction`, `PinholeError`, `PinholeStats`; layering `PolicyLayers`, `RemotePolicy`, `merge_layered`, `MergedPolicy`, `MergeStats`, `RuleProvenance`, `apply_deny_scope`, `DenyScope`; stats `AclFilterStats`, `FlowKey`, `FlowStats`; `CompiledPolicy`, `reasons` |
| `nsplane-nat` | `Translator` (`new`, `store`, `set_mtu`, `ipv4_translated_predicate`, `stats`), `TranslationTableBuilder` / `TranslationTable`, `PortMap` (`new`, `with_conntrack`, `set_rules`), `Conntrack` (`remove`, `with_removal_hook`), `Nat64Lan` (`new`, `with_snat_ports`, `forward`, `reverse`, `remove_flow`, `stats`), `Nat64LanSink` / `Nat64LanSource`; trait `SnatPorts` | `PeerMapping`, `SelfMapping`, `LanPrefix`, `TableError`, `TranslatorStats`, `PortMapRule`, `PortMapProtocol`, `PortMapError`, `ConntrackConfig`, `ConntrackStats`, `ConntrackError`, `Flow`, `FlowMatch`, `FlowDirection`, `TcpState`, `LanRoute`, `Nat64LanConfig`, `Nat64LanStats`, `Nat64LanError`, `Nat64Verdict`, `DefaultSnatPorts`, `nat64_lan::reasons`, `checksum` |
| `nsplane-nat` (local side) | `Redirect` (`new`, `with_conntrack`, `forward`, `reverse`, `original_destination`, `remove_flow`, `retain`, `stats`) | `RedirectDecision`, `RedirectVerdict`, `RedirectStats`, `redirect::reasons` |
| `nsplane-uapi` | `Uapi` (`new`, `with_external_transport`, `with_listen_port`, `handle_request`, `serve_stream`), `UapiListener` (Unix socket; named pipe on Windows) | `udp_transport`, `TRANSPORT_ID`, `socket_path` / `pipe_path` |

Not public API: `nsplane-cli` (a binary), `nsplane-e2e` (test harness) and
`nsplane-examples` (example binaries, including the single-port relay and its client
transports; the relay wire format is the Proposed ADR `2026-10-02-single-port-relay`).

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
leaves as the delivery; buffers come back through `recycle`. `handle_datagrams` and
`handle_locals` take a batch of received datagrams or local packets and behave exactly like
feeding each to `handle_input` in order, but share one schedule update, the output queue's
room and the session, route and peer lookups of consecutive packets. Peers are looked up by key,
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

Hooks for a path ladder (ns account mode, quick-v2 §9), each unused by default:

- `Core::inject_outbound_on` (`EngineHandle::inject_outbound_on`) seals one packet for a
  peer in its current session and transmits it on an explicit path, bypassing routing, the
  outbound filters and `PathPolicy::select`; the peer's path is not changed. It is how probes
  reach a candidate path while the peer's traffic stays on its path. Without a current
  session the packet is dropped as `reasons::NO_SESSION` and no handshake starts.
  `force_handshake_on` likewise sends one handshake initiation on an explicit path without
  changing the peer's path (`force_handshake` with a path makes it the peer's path).
- `PacketFilter::inbound_from` is what the core calls for every decrypted datagram, with the
  path it arrived on; its default calls `inbound`. A probe responder overrides it to match a
  reply with the exact tuple it probed, or to answer on the path a request came from.
- `PathPolicy::observe_every_message` (read once when the core is built, `false` by default)
  makes the core call `on_authenticated` for every authenticated message, on the current path
  too, where the answer changes nothing; by default the core asks only about messages from
  another path, which keeps the steady-state data path free
  of the call. `Event::Authenticated` stays limited to path changes.

`handle_input_deferred` is the same entry point for a driver that encrypts on several
threads: the cryptography of a local packet or a received transport data message comes back
as a `CryptoJob` (everything before it, such as routing and the outbound filters, has
already run), `CryptoJob::run` seals or opens the packet under the lock of that peer's
tunnel only, and `complete_job` does the rest in the core (counters, completed handshakes,
roaming, the source check, the inbound filters, the output); `handle_datagrams_deferred`
and `handle_locals_deferred` do the same for batches. Only a core built with
`CoreConfig::crypto_jobs` hands out jobs, and only then does each peer's tunnel sit behind
its own mutex, shared with its jobs; otherwise every peer owns its tunnel and the data path
takes no lock (`handle_input_deferred` then processes every input at once).

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

The core is never shared, and without the crypto worker pool the data path takes no lock;
with the pool, each peer's tunnel is behind a mutex shared with the workers.

When the owner wakes for a received datagram or a local packet, it also takes the ones
already queued behind it (up to `MAX_BATCH`, 64) and feeds them to the core as one batch
(`Core::handle_datagrams`, `Core::handle_locals`). It never waits for a batch to fill and
runs no timer for it, so a lone packet goes through at once. Received datagrams are taken
up to the sink queue's room; local packets up to the transmit room (see the backpressure
list below).

- `EngineHandle` sends commands to the owner (peers, keys, allowed IPs, path, transport,
  stats, injection, shutdown) and returns their replies.
- Events are published on a `broadcast` channel (`EngineHandle::subscribe`); publishing never
  blocks, and a lagging subscriber loses the oldest events.
- Drops are counted per reason (`EngineHandle::drop_counters`) and published as events.
- Traffic is counted per peer (`PeerStats`: wire bytes and plaintext bytes) and per transport
  (`EngineHandle::transport_stats`: datagrams and bytes each way, failed sends), the latter by
  the transport's own tasks with one relaxed atomic update per batch. `EngineHandle::status`
  returns the key, MTU, suspension, peers, transports, drops, queue and fragmentation stats in
  one owner call. Counters only grow; rates, metric export and labels such as direct vs relay
  are left to the caller (ns), which samples `status` and maps transport ids to its paths.

Backpressure:

- Local packets are never dropped by an engine with one transport: when the transmit queue
  is full, datagrams wait in the owner task (the transport's backlog). The owner reads local
  packets only while some transport has room for them and takes no more at once than the
  largest room, counting one datagram per packet; a transport's room is its free transmit
  slots while its backlog is empty, plus `min(MAX_BATCH, capacity)` minus its backlog. With
  no room it stops reading, which holds back the source, so a saturated transport keeps at
  most `MAX_BATCH` local datagrams in its backlog.
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
| `crypto` | `queue_capacity` (the bound of jobs in flight) with 2 or more crypto workers, else 0 | owner -> workers -> owner (jobs not completed yet) |
| `crypto_done` | `queue_capacity` with 2 or more crypto workers, else 0 | workers -> owner (batches of finished jobs) |

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
LTO, multi-threaded runtime, 32-core host shared with other jobs; the range of two runs,
taken after the Phase 5 follow-ups #1 and #17: batched core input, no lock without
workers): a
hub engine with 8 peers, each its own engine without workers on an in-memory link, sends
120 packets to every peer while every peer sends 120 to the hub, so the hub seals and opens
all 1920 packets of an iteration. The pool off is the default of 0 workers; 1 worker is the
same code path.

| Packet | Pool off (0 or 1) | 2 workers | 4 workers |
| --- | --- | --- | --- |
| 64 B | 1.49-1.55 Mpps (1.29 / 1.24 ms) | 1.64-1.68 Mpps (1.14 / 1.17 ms) | 1.61-1.64 Mpps (1.19 / 1.17 ms) |
| 1420 B | 869-906 kpps (9.9-10.3 Gbit/s; 2.21 / 2.12 ms) | 0.94-1.20 Mpps (10.6-13.6 Gbit/s; 2.05 / 1.60 ms) | 1.17-1.26 Mpps (13.3-14.3 Gbit/s; 1.53 / 1.64 ms) |

Before those follow-ups, in the same session, the mean iteration times were 1.59 / 1.79 ms
(64 B, pool off), 1.48 / 1.51 ms (64 B, 2 workers), 1.53 / 1.52 ms (64 B, 4 workers),
2.84 / 2.84 ms (1420 B, pool off), 1.88 / 1.92 ms (1420 B, 2 workers) and 1.96 / 1.96 ms
(1420 B, 4 workers): every case is about 15-25 % faster now, except 1420 B with 2 workers,
which is within the run-to-run noise.

With full-size packets the pool moves the hub up to about 1.4x further; small packets gain little,
since there the cryptography is a small part of the owner's work per packet (queues,
routing, counters). Beyond 2 workers the owner task itself, which still touches every
packet twice, is the limit, so 4 workers do not add to 2. Sharding `Core` itself by peer
(one owner per shard) would lift that limit, at the cost of splitting the handshake gate,
the peer table and the allowed IPs across shards.

The pool off takes no lock (follow-up #17): the core hands out crypto jobs only when built
with `CoreConfig::crypto_jobs`, which the engine sets for 2 or more workers, and otherwise
every peer owns its tunnel outright. With the pool, each peer's tunnel is shared with its
jobs behind a mutex. The lock had cost no more than the run-to-run spread when it was added
(`core_round_trip` medians 616 -> 569 ns at 64 B and 1347 -> 1362 ns at 1420 B); without it
the `data_path` core round trip measures 532 ns at 64 B (device-equivalent 474 ns, raw
`Tunn` 359 ns) and 1.348 us at 1420 B (device-equivalent 1.282 us), against 546 ns and
1.354 us on main 64131c7.

`UdpTransport` is the network side: one dual-stack UDP socket with fwmark and ECN support,
4 MiB socket buffers requested (clamped by `net.core.rmem_max` / `wmem_max`) and segmentation
offload through `quinn-udp`.
`ChannelSource`, `ChannelSink` and `ChannelTransport` are in-memory implementations for tests
and embedders.

**UDP side channel.** Another protocol can share the `UdpTransport`'s port (ns control
messages next to WireGuard, say). `UdpTransport::with_side_channel(classify, capacity)`
runs `classify` on every received datagram, each GRO segment on its own, in the receive
path of `recv` and `recv_batch`; a datagram it picks is copied into a `SideDatagram`
(`from`, unmapped as `Path::addr` reports it, and `datagram`) and `try_send`-ed to the
returned receiver of `capacity` entries, never reaching the engine; a full or closed
receiver drops it. `SideSender::stats` counts both (`SideStats { received, dropped }`);
they live on the sender, not in `TransportStats`, because side datagrams never reach the
engine's transport tasks. `SideSender::send_to` writes straight to the non-blocking socket
without an ECN mark: it never waits behind the engine's traffic and fails with
`WouldBlock` when the send buffer is full. A capacity of 0 is raised to 1; a second call replaces
the channel (the old receiver closes once drained). Without a side channel nothing is
classified; the receive path checks one `Option` per datagram.

**Message links.** `LinkTransport` (opt-in; nothing runs unless one is created) carries
datagrams to one peer as messages over a link the embedder dials, so `nsplane` itself has
no WebSocket or TLS dependency. Its task asks the `LinkDialer` for a link (a `LinkSender`
and a `LinkReceiver`), drains the send queue into it and hands received messages to
`recv`, reported from `Path { transport: id, addr: peer, ecn: NotEct }`; sends to another address are
dropped and count as sent.

- `LinkConfig::queue` (256) bounds the datagrams waiting for the link, also while none is
  up; `send` never waits, and on a full queue fails with `WouldBlock`, which the engine
  counts under `DROP_TRANSPORT_SEND_ERROR`.
- A link ends when the receiver yields `None` or an error, a send fails (that datagram is
  lost; the queued ones go out on the next link) or `LinkConfig::read_idle_timeout`
  (default `None`) passes without a message. The task reports `LinkState::Disconnected`
  to `LinkDialer::on_state` and dials again at once, also after a failed dial; the dialer
  owns the backoff and may sleep in `dial`.
- The idle timeout is reset only by messages the receiver yields, so a dialer whose
  keepalive frames are consumed inside its receiver does its own idle detection. The
  examples' WSS client (`examples/src/relay/wss/client.rs`, a tokio-tungstenite dialer)
  does: it pings every 10 s and closes a connection silent for 35 s.

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
- `EngineHandle::fragment_stats` returns the stage's `FragmentStats` (all zero without a
  stage): IPv4 packets fragmented, fragments emitted, Packet Too Big and Fragmentation
  Needed errors sent, and oversized packets dropped without an error for the rate limit
  (`rate_limited`), for no route (`no_route`) or because no error is allowed or the packet
  cannot be split (`dropped`). The drops are counted in `drop_counters` too, under
  `DROP_FRAGMENT_RATE_LIMITED`, `DROP_FRAGMENT_NO_ROUTE` and `DROP_FRAGMENT_OVERSIZE`.

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

`Transport::send_batch` reports in its `failed` argument which of the datagrams it was done
with failed, so `TRANSPORT_SEND_ERROR` counts exactly the lost datagrams: a failed segmented
`UdpTransport` send loses its run, not the runs handed off before it in the same call.

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
`UdpTransport::bind_with_offload(.., false)` and the examples' `--no-offload` opt out. Plain
TUN reads (no virtio-net header, and Wintun reads on Windows) leave the same 28 bytes of
room behind each packet as segmented ones (a read still takes at most the MTU), so a
translator grows full-MTU IPv4 in place with offload off too.

## nsplane-wss

`nsplane-wss` carries data-plane traffic over WebSocket over TLS (ADR
`2026-10-03-data-channel-protocols-in-nsplane`: both legs of each data-channel protocol live
in nsplane). It is a separate crate on `nsplane`, so `nsplane` itself stays free of
WebSocket and TLS; only an application that adds it pulls in `tokio-tungstenite` and
`rustls` (aws-lc-rs provider). It is `#![forbid(unsafe_code)]` and publishes once
`nsplane` 0.8.0 is on crates.io (it has no unpublished dependencies).

**Connections.** Every carrier dials the same way, from one `WssConfig`:

- TCP, TLS and the WebSocket upgrade within `connect_timeout` (10 s), to `connect_addr`
  or the URL's host, with `server_name` (default the URL's host), the extra `headers` and,
  with a `BearerProvider`, `Authorization: Bearer <token>` fetched per dial.
- An upgrade answered with 401 or 403 is reported as `LinkState::Rejected(status)` on the
  carrier's `state()` watch (and counted in its stats). After a 401 the next dial waits
  until the provider yields a different token (polled every `token_poll`, 2 s, at most
  `token_wait`, 300 s); a 403, and a 401 without a provider, back off like any failure.
- Backoff: every dial but the first waits `backoff_min` (2 s) after a link that came up,
  doubled after each failed dial up to `backoff_max` (60 s).
- Keepalive: a ping every `ping_interval` (10 s); the link ends when no frame at all
  (pongs included) arrived for `read_idle` (35 s). No message above `MAX_MESSAGE`
  (4 x 65 535 bytes) is read.
- TLS trust is the caller's: there are no built-in system or web PKI roots. `WssTls::Roots`
  takes a `RootCertStore` (the client configuration is built with aws-lc-rs, the safe
  default protocol versions and no client auth); `WssTls::Config` takes a complete
  `Arc<rustls::ClientConfig>` used as is (ns passes its `control::tls::client_config()`).
  Built-in roots may become an optional feature later if a consumer needs them.

**Datagram carrier.** `WssDialer` is a `LinkDialer`: `into_transport(id, peer, config)`
returns a `LinkTransport` whose links are WSS connections. Each datagram is one binary
message carrying its raw bytes (the wire of ns `OpaquePump` and the examples' relay); text
messages and messages above `MAX_DATAGRAM` (65 535) are dropped and counted in
`WssStats`, a close frame or the end of the stream ends the link.

**Stream carrier wire.** `WsFrame` (module `frame`) is ns `tunnel-ws`'s and NSGW's protocol,
byte for byte: every binary message is one frame, big-endian.

| Field / command | Bytes | Content |
|---|---|---|
| `stream_id` | 4 | the stream, per session (never 0 from the client) |
| `command` | 1 | one of the commands below |
| `OPEN_V4` (`0x01`) | 4 + 2 + 1 | IPv4 address, port, protocol (`0x00` TCP, `0x01` UDP) |
| `OPEN_V6` (`0x02`) | 16 + 2 + 1 | IPv6 address, port, protocol |
| `DATA` (`0x10`) | rest | stream bytes (at most `MAX_DATA_PAYLOAD`, 65 531, per frame), or one UDP datagram |
| `CLOSE` (`0x20`) | 0 | close the stream |
| `CLOSE_ACK` (`0x21`) | 0 | acknowledge a CLOSE |

As in ns, bytes after a complete OPEN, CLOSE or `CLOSE_ACK` are ignored and any protocol
byte but `0x01` is TCP. The protocol has no open reply and no flow control: a refused
OPEN is answered with CLOSE, and a stream whose peer outruns its receive budget is closed.

**Stream client.** `WssStreamClient` (the client leg, ns `proxy/wire.rs` and
`wss_flow.rs`) opens TCP streams (`open_tcp`, a `WssTcpStream` with `AsyncRead` and
`AsyncWrite`) and UDP flows (`open_udp`, a `WssUdpFlow` with `send` / `recv`) to targets
behind a terminate (NSGW, or `WssStreamServer`).

- Sessions: dialed lazily on the first open (or `connect`). Every TCP stream and UDP flow
  is multiplexed over one session until it holds
  `WssStreamLimits::max_streams_per_session` live ones (default 1024, NSGW's default
  `PER_SESSION_STREAM_CAP`); only then is one more session dialed. One dial runs at a time
  and waiting opens share it. The wire format is ns's, unchanged. NSGW caveats: it rejects
  OPENs beyond its own per-session cap, which its operator can set below 1024 (keep
  `max_streams_per_session` at most the gateway's cap), and it writes all streams of a
  session through one shared writer queue.
- Stream ids count up from 1 per session, skipping ids still in use; an id stays in use
  until the peer's CLOSE or `CLOSE_ACK`. An open returns once its OPEN is queued.
- Half-close: `shutdown` sends CLOSE behind the data already written (the wire has no
  other half-close) and the stream keeps reading until the peer's CLOSE or `CLOSE_ACK`,
  then reads EOF; this matches the ns terminate and `WssStreamServer`, which drain the
  stream to the backend before ending it. A peer's CLOSE reads as EOF after the bytes
  before it and is answered with `CLOSE_ACK`; dropping a stream sends CLOSE.
- Queues and bounds (`WssStreamLimits`, ns's defaults): a control queue (OPEN,
  `CLOSE_ACK`, reset CLOSE, pings; 64 messages) written before the data queue (DATA and
  orderly CLOSE; 256 messages), and receive budgets of 4 MiB per stream
  (`stream_buffer`) and 32 MiB per session (`session_buffer`), each received frame
  costing its payload plus 64 bytes. Over budget, a TCP stream is reset (reads fail with
  `ConnectionReset`) and a UDP datagram is dropped while the flow stays.
- Reconnection: when a session ends (socket error, close, read idle) every stream and flow
  on it fails; the next open dials again after the backoff. Frames for unknown stream ids
  are ignored and counted in `WssStreamStats`.

**Terminate leg.** `WssStreamServer` (ported from ns `tunnel-ws` `WsTunnel`) dials the
relay like the client and serves the protocol on the session; `run(shutdown)` drives it.

- Resolution is the embedder's: `WssResolver::resolve(WssOpen { session, stream_id,
  target, protocol })` returns the backend `SocketAddr` or `Denied` (answered with CLOSE).
  It runs on the stream's own task, so a slow answer delays only that stream. ns keeps its
  resolution (`OverlayResolver`, services.toml, FQID, ACL, gateway identity) behind it.
- An OPEN for an id in use, or beyond `max_streams` (1024), is answered with CLOSE. The
  server connects a TCP stream or a connected UDP socket (bound to the backend's address
  family) and relays: TCP bytes in DATA frames of at most `MAX_DATA_PAYLOAD`, one datagram
  per DATA frame for UDP.
- A CLOSE is always answered with `CLOSE_ACK`; the stream's queued data is still written
  to the backend, then its write side is shut. A backend EOF sends CLOSE behind the
  stream's data; a failed connect, a backend error (a failed UDP receive included) sends
  CLOSE at once.
- Queues and bounds (`WssServerLimits`, ns's defaults): 4 MiB per stream
  (`stream_buffer`), 32 MiB per session (`session_buffer`), 64 frames per stream
  (`stream_queue`), each received frame costing its payload plus 64 bytes until written;
  a frame over a bound closes its stream only (`WssCloseReason::Overflow`). Control queue
  64 messages (`CLOSE_ACK`, refusing or resetting CLOSE, pings), written before the data
  queue of 256 (DATA and the CLOSE after a backend's end).
- Events: `with_events(mpsc::Sender<WssStreamEvent>)` reports each stream's `Open` and
  `Close { reason, to_backend, from_backend }`; sending never waits, an event that does
  not fit is counted in `WssServerStats::event_drops`.
- Reconnection: one session at a time carries every stream. When it ends its streams are
  closed (`WssCloseReason::SessionEnded`) and the next session is dialed after the
  backoff; a shutdown closes the open streams and the session.

ns `WsTunnel` has had no consumer since ns 0aef94a0 (2026-08-28); with the terminate leg
here, ns can delete `tunnel-ws` whole.

**Deviations from ns.** An orderly CLOSE is queued behind the stream's data on both legs.
Client: an over-budget UDP datagram is dropped and the flow kept, and the receive budgets
count payload plus 64 bytes per frame instead of ns's 64-message cap per stream. Server:
on a peer's CLOSE the queued data is drained to the backend and its write side shut (ns
dropped it), the half-close the client relies on; a failed UDP backend receive sends
CLOSE; the UDP socket binds to the backend's address family.

**Tests.** Unit tests next to the code (`frame`, `stream`, `server`, `connect`, `config`);
`crates/nsplane-wss/tests/stream.rs` runs the client and the server through a TLS test
relay and checks the frames against the ns layouts; `nsplane-e2e` `wss_datagram` runs two
engines over `WssDialer` (401, 403, reconnect, read idle); `examples/tests/wss.rs` and the
`relay-wss` cells of `just e2e-examples` run the examples' relay client on it.

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
- A full accept queue closes new TCP connections (`tcp_not_accepted`) by default. With
  `NetStackConfig::accept_backpressure`, bare SYNs are left unanswered while it is full
  (`syn_deferred`; the peer retransmits) and connections that completed their handshake
  meanwhile wait in the stack, bounded by the listener pool, until the application accepts
  them.
- `connect_tcp` takes an ephemeral port; `connect_tcp_from` a caller-chosen one (`AddrInUse`
  when a connection or listener of the stack has it). Ephemeral TCP and UDP ports start at a
  random point of 49152-65535 per stack and then go up in order.
- Everything the stack discards is counted per reason in `NetStackHandle::stats`
  (`NetStackStats`): malformed, foreign or unsupported packets, refused SYNs, connections
  and flows not accepted, full UDP queues, the flow limit, and egress produced while the
  egress backlog is full.
- smoltcp sees the configured MTU as its device MTU, so it advertises an MSS of `mtu - 40`
  (IPv4) or `mtu - 60` (IPv6) and no emitted packet exceeds the MTU, which the source
  reports and never changes. Socket buffers hold 512 IPv4-sized segments, so the window
  scales with the MSS.
- UDP datagrams are built with DF set over IPv4 and an application payload whose packet
  exceeds the MTU fails with `InvalidInput`. With `NetStackConfig::udp_allow_fragmentation`
  an IPv4 one instead leaves as a single oversize packet with DF clear (up to the 65 535-byte
  total length), for the engine's fragmenter (`EngineBuilder::fragmenter`) to split; the
  UDP egress bypasses smoltcp, so nothing in the stack caps it, and the source keeps
  reporting the configured MTU. IPv6 still fails.
- `TcpConnection::unacked` and `TcpConnection::last_ack` report send progress: after
  smoltcp ran, each bridge pass reads the socket's send queue (bytes taken from the
  application and not acknowledged; smoltcp exposes no SND.NXT, so bytes held back for the
  peer's window count too) and stores it in an atomic shared with the connection when it
  changed; a queue smaller than at the end of the previous pass means SND.UNA advanced
  (only an acknowledgement shrinks it, except a reset, which leaves the socket closed and
  is not counted), so the pass's time is stored as `last_ack`. No lock, no per-packet or
  per-byte work; the values stay readable after the socket is released.
- `NetStackHandle::owns(packet)` answers `Ownership::{Flow, Listener, None}` synchronously
  for a local side that shares one decrypted stream between the stack and other consumers
  (a `Splitter` closure). It reads one table of tuples behind a mutex, keyed
  `(local, remote)`: TCP connections are registered when a connect is queued (by the handle
  for `connect_tcp_from` with a port, by the driver before the SYN is emitted for an
  ephemeral port), when a listener socket enters SYN-RECEIVED (after the poll that ingested
  the SYN, before the SYN-ACK is flushed) and when a socket is adopted as a connection;
  bound UDP sockets and UDP flows when they are created. Each registration is dropped with
  what holds it (the released connection, the abandoned or failed connect, a handshake
  socket back in `Listen` or closed, the dropped `UdpSocket` or `UdpFlow`, whose
  registration goes before its queue closes so a rebind or a new flow never races it), so
  the table changes per connection, never per packet, and costs nothing per packet when
  `owns` is not called. `Flow` is an exact tuple match (any remote for a bound UDP socket)
  or an ICMP/ICMPv6 error quoting a packet sent on a registered tuple; `Listener` a bare SYN
  or UDP datagram to a stack address otherwise; `None` everything else, fragments (dropped
  by the stack) and every packet once the driver stopped. The answer reflects the state at
  the call. With reassembly on, TCP and UDP fragments to a stack address are the stack's:
  `Flow` for a first fragment on a registered tuple, `Listener` for any other first
  fragment and for every later one (it carries no ports, and the reassembler's state is the
  driver's, not shared with `owns`).
- `NetStackConfig::reassembly` gives the driver one `nsplane_packet::reassembly::Reassembler`
  (none is created without it). Before `classify`, every ingress packet to a stack address
  is pushed into it: a non-fragment passes unchanged, a fragment is held, and a completed
  datagram continues through the normal ingress as one packet (UDP dispatch, or smoltcp for
  TCP). Expiry runs at the start of each driver turn, which the driver's existing timer
  (at most `MAX_POLL_DELAY`, 50 ms) already wakes, and is a single emptiness check while no
  datagram is held. The reassembler's counts are added to `NetStackStats` after each push
  or expiry: `reassembled`, `reassembly_timeout`, `reassembly_overflow`, and overlapping or
  invalid fragments as `malformed`. Without it, fragments count as `unsupported`.
- Every TCP socket (connect and listener pool) runs CUBIC congestion control (smoltcp
  feature `socket-tcp-cubic`, no extra crate). Without it smoltcp sends the whole peer
  window at once and, after a retransmission timeout, all of it again; a hop that drops
  part of the burst (a full socket buffer on a loaded host) drops the retransmission too,
  and the timeouts (1 s minimum, doubling) add up past 30 s. CUBIC rather than Reno: both
  restart from one segment after a timeout and measured alike on the bottleneck below
  (32 MiB in 40-41 s with CUBIC, 40-50 s with Reno), CUBIC recovered faster at 1 % random
  loss (16 MiB in 1.1-4.1 s, Reno 4.1-5.1 s) and is the default of Linux, Windows and macOS;
  its `f64` arithmetic is no concern on the targets nsplane runs on.
- smoltcp is the `dotns/smoltcp` fork (tag `v0.14.0-nsplane.3`, ADR
  `docs/decisions/2026-10-03-smoltcp-fork.md`): v0.14.0 plus fixes for four defects that
  stalled connections for good under loss when both ends send (an echo, request and
  response).
  - After a retransmission timeout smoltcp 0.14 rewound its next sequence number to the
    oldest unacknowledged byte and stamped its pure ACKs with it. If the peer had already
    received past that point (only its ACKs were lost), the peer dropped those ACKs as old,
    acknowledgement included; with both ends in that state each resent data the other had
    and the timeouts backed off to 60 s. The fork sends every empty segment with the
    highest sequence number sent (RFC 9293 `SEQ=SND.NXT`), and such a segment no longer
    moves the send position, so the rewind for retransmission stays in effect.
  - When an ACK closed the peer's window while data was in flight (window scaling rounds
    a few free bytes down to zero), the zero-window probe timer replaced the retransmission
    timer, so lost bytes were never resent, and no timer ran once the window reopened. The
    fork keeps outstanding data under the retransmission timer (RFC 6298 5.1) and probes
    from the oldest unacknowledged byte when a timeout finds the window closed.
  - The third duplicate ACK reset the retransmission timer and dropped the pending fast
    retransmission before the segment reached the device; with the egress backlog full the
    segment was never sent and no timer ran (traced: `LAST-ACK`, 360 KB in flight above
    cwnd, timer idle). The fork keeps it pending until it is emitted.
  - Three duplicate ACKs while only the FIN was outstanding replaced its retransmission
    timer by a fast retransmission, which resends data only (traced: `FIN-WAIT-1`, empty
    send buffer, FIN in flight, timer idle). The fork leaves a FIN to the retransmission
    timer.

  Phase 5 worked around the first two in the driver (an outgoing pure-ACK sequence
  rewrite, and a stalled connection taking up to 1 KiB past its application buffer's bound
  and keeping a 1 s keep-alive in place of the persist timer); all of it is gone.

  The engine's `DROP_SINK_FULL` is ordinary loss to TCP: a decrypted segment the engine
  drops at the full sink is never acknowledged, the retransmission timer stays armed and
  smoltcp resends it; the stalls above only needed such a loss at the wrong moment.
  `parallel_echo_*` in `tests/netstack_lossy.rs` run eight 1 MiB echoes through
  256-packet engine queues, without loss and at 2 % loss. On the fork without any driver
  workaround they passed 10 consecutive runs in debug (2 % loss: 10.2-16.2 s) and in
  release (11.0-21.0 s), as they did on smoltcp 0.14 with the Phase 5 workarounds (8.3-17.3 s
  and 9.0-23.1 s).

### Netstack throughput

Release, two netstacks over two engines on an in-process `ChannelTransport` pair (no
latency), one TCP connection, MTU 1420; the link wrappers are `nsplane_e2e::LossyTransport`
(drops a deterministic fraction of the data messages in each direction) and
`nsplane_e2e::Bottleneck` (25 MB/s behind a 64-datagram drop-tail buffer, like a socket
buffer drained by a busy receiver). "After" is CUBIC with the Phase 5 stall workarounds
on smoltcp 0.14 (two runs each); "fork" is the same on `v0.14.0-nsplane.3` without any
workaround (four runs each, on a host shared with other builds, load 7-11 on 32 cores):

```text
cargo test --release -p nsplane-e2e --test netstack_lossy -- --ignored --nocapture
```

| Case | Before (no congestion control) | After | Fork |
| --- | --- | --- | --- |
| TCP, 64 MiB, no loss | 440.5 / 441.0 MB/s | 321.1 / 319.4 MB/s | 308.6 / 129.2 / 246.7 / 228.9 MB/s |
| TCP, 16 MiB, 1 % loss | 41.1 s / 35.1 s (0.4-0.5 MB/s) | 4.09 s / 2.09 s (4.1-8.0 MB/s) | 1.09 / 6.16 / 1.14 / 3.13 s (2.7-15.3 MB/s) |
| TCP, 16 MiB, 3 % loss | not done after 60 s (both) | 54.2 s / 59.2 s (0.3 MB/s) | 53.2 s once, 3 of 4 not done after 60 s |
| TCP, 16 MiB, bottleneck | not done after 60 s (both, ~2650 drops) | 20.9 s / 18.9 s (0.8-0.9 MB/s, ~330 drops) | 18.9 / 15.9 / 19.8 / 17.9 s (0.8-1.1 MB/s, 276-472 drops) |
| UDP, 50 000 x 1200 B, no loss | 902.7 / 468.4 MB/s | 587.1 / 608.7 MB/s | 303.3 / 530.1 / 644.5 / 411.1 MB/s |

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

The fork changes nothing on the loss-free path (its fixes only touch retransmission and
empty segments, and the driver lost per-packet work); the loss-free spread above is the
shared host, as the 320-460 MB/s spread of one build was before. With loss the results
stay in the same range: 1 % loss completes in 1.1-6.2 s (before 2.1-4.1 s; whole seconds
are retransmission timeouts), the bottleneck in 15.9-19.8 s (before 18.9-20.9 s), and 3 %
loss stays timeout-bound right at the 60 s limit, as before.

L2's queue harness (4 and 8 parallel 32 MiB-total echo connections over two engines at
queue capacity 512 and 1024, release, 3 runs per cell) completed every run after the
change (sink drops in one 8-connection run at 512, recovered in 2.2 s); before it, the
same harness stalled a connection for good in 2 of 20 runs at 8 connections and 512. The
5C-T7 re-run of these cases is in [Performance](#performance).

## nsplane-uapi and the CLI

`Uapi` answers `get=1` and `set=1` over an `EngineHandle`; `listen_port` and `fwmark` bind a
new `UdpTransport` and install it with `EngineHandle::replace_transport`. Over an engine whose
transport the UAPI does not own (`Uapi::with_external_transport`, e.g. a relay or WSS
carrier) they never replace it: the reported value is a no-op, any other fails with
`EADDRINUSE`. On Unix,
`UapiListener` binds `/var/run/wireguard/<iface>.sock`. The Windows named-pipe listener
exists since Phase 2; real-host verification of its `ProtectedPrefix` path and security
descriptor is still pending.

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
*Performance*) and in [Performance](#performance).

Measured results (5C-T3 record): a bypass peer costs ~41-54 ns (937 ns before the hook); an
established flow 50-55 ns under namespaces and 62 ns under the default policy (deliberately
uncached); new flows 60-75 ns (default policy), ~200-400 ns (namespaces), 0.34-0.56 us
through a grant and 240-280 ns through a pinhole (38 us and 15-20 us before full tables
evicted in O(1)). The floor is the five-tuple parse (6-7.5 ns) plus the snapshot load
(9.5-11.5 ns), 16-19 ns; skipping the reply check would be exact only for unidirectional
traffic. Exactness was not weakened (differential test).

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
incrementally. A fragmented IPv4 UDP datagram without a checksum is reassembled first, in
any fragment order: only the first fragment shows the checksum, so later fragments that
arrive before it are held (at most 256 datagrams and 1 MiB, for 60 s; a fragment after the
expiry starts a new entry). A datagram with a checksum whose later fragments came first is
reassembled the same way and sent unfragmented; with nothing held, in-order fragments of a
checksummed datagram are translated one by one, without holding or waiting. A reassembled
datagram larger than the translator's MTU (`Translator::set_mtu`, 1280 by default; set it
to the tunnel MTU) is dropped as `reasons::REASSEMBLED_TOO_BIG`, never sent oversize.
`TranslatorStats` counts `fragments_held`, `fragment_timeouts`, `fragment_budget_drops`,
`fragment_marker_evictions` and `reassembled_too_big`. A translated packet grows by 20
bytes (28 with a fragment header) inside its buffer when it has the room, else it is copied
into a larger buffer (`TranslatorStats::grown_copies`); TUN reads leave that room. Since the core routes and checks sources before the
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

**Nat64Lan.** A stateful NAT64 to an IPv4 LAN (NAPT) for a subnet gateway, ported from ns
`SubnetRoute`. A `LanRoute` maps an IPv6 /96 (`mapped`) to an IPv4 prefix (`real`); the
prefixes are `(Ipv6Addr, u8)` / `(Ipv4Addr, u8)` pairs validated by `LanRoute::new`, like
`LanPrefix`, since no IP network crate is a dependency. IPv6 TCP, UDP and ICMPv6 echo to
`mapped` plus a safe address of `real` (not broadcast, loopback, link-local, multicast or
unspecified; other mapped targets are dropped and counted) become IPv4 from the route's
`snat_source`, with a port (or echo identifier) reserved for the flow through the caller's
`SnatPorts` and given back when the flow expires, is evicted or is removed
(`Nat64Lan::remove_flow`, built on `Conntrack::remove` and its removal hook); a saturated
range drops the packet rather than aliasing a flow. Replies and Fragmentation Needed (as
Packet Too Big) are translated back; TCP MSS can be clamped. As in ns, translated packets
leave DF clear (`Nat64LanConfig::set_df` sets it above 1260 bytes, trading LAN
fragmentation for a PMTU black hole when the LAN filters ICMP), and a destination that more
than one route resolves is dropped and counted (`reasons::AMBIGUOUS_ROUTE`). The routes gate
every forward packet; a flow keeps its SNAT address across a route replacement, and the
caller revokes the flows of a removed route with `remove_flow`. Unlike the filters above it sits
on the **local side**: the LAN's replies are addressed to `snat_source`, which no peer's
allowed IPs contain, so the core could not route them to a peer before a filter ran.
`Nat64LanSink` runs `forward` on the packets the engine delivers and `Nat64LanSource` runs
`reverse` on local packets before the core routes them (the IPv6 result goes to the peer
owning the original source). The clients route the mapped /96 to the gateway (it is in their
allowed IPs for it), and the gateway's local side routes `snat_source` back to itself. The
wrappers make `nsplane-nat` depend on `nsplane`; `nsplane` does not depend on `nsplane-nat`.

**Redirect.** `Redirect` is not a filter: it runs on the local side, on `PacketBuf`s before
they reach a local endpoint (`forward`) and on that endpoint's replies (`reverse`). It
sends the IPv4 TCP/UDP flows a local application opens to a service address to an
endpoint a caller-supplied closure picks for each new flow (`RedirectDecision::Redirect`,
`Pass` or `Drop`), for example a `nsplane-netstack` listening on its own address, and
rewrites the replies so they come from the service address; the source is kept. Flows
live in a `Conntrack` (translated tuple: application to endpoint; `Flow::peer` unused); an
endpoint already used by a live flow from the same source is refused and the closure asked
again, up to 32 times. `remove_flow` (by the endpoint's view of the flow) and `retain` end
flows; `original_destination` gives the service address of an accepted flow. The closure
never runs under a lock, so it may call back into the `Redirect`. IPv6, fragments, other
protocols and untracked replies pass unchanged.

**Order.** The recommended chain is `[AclFilter, PortMap, Translator]`: the translator sits
next to the local side, so the ACL and the port map see overlay IPv6 in both directions and
ACL policies need no rules for the IPv4 aliases. With the engine's fragmentation stage and
`Translator::ipv4_translated_predicate`, oversized local IPv4 to translated destinations is
fragmented to fit the MTU after translation.

## Optional features and defaults

A basic client is an `EngineBuilder` on a TUN device and a `UdpTransport` with peers and
no filters. Every feature below is optional; one that is not installed is not on the data
path, so such a client pays no extra latency for it.

| Feature | Crate | How to enable | Default | Cost when not enabled |
|---|---|---|---|---|
| IPv4/IPv6 translation | `nsplane-nat` | `EngineBuilder::filter(Box::new(Translator::new(table)))`; `Translator::set_mtu` to the tunnel MTU | not installed | none: the core's filter chain is empty |
| Service publishing (DNAT/SNAT) | `nsplane-nat` | `EngineBuilder::filter(Box::new(PortMap::new(rules)?))`, or `PortMap::with_conntrack` for a sized `Conntrack` | not installed | none |
| NAT64 to LAN (NAPT) | `nsplane-nat` | wrap the local side: `EngineBuilder::new(Nat64LanSource::new(source, nat.clone()), Nat64LanSink::new(sink, nat))` | not installed | none |
| Local-side redirect (DNAT) | `nsplane-nat` | call `Redirect::forward` / `Redirect::reverse` on the local path | not used | none |
| ACL | `nsplane-acl` | `EngineBuilder::filter(Box::new(AclFilter::new(engine, identity)))` (`AclFilter::with_config`) | not installed | none |
| Flow accounting | `nsplane-acl` | `EngineBuilder::filter(Box::new(FlowTracker::new(capacity)))` | not installed | none |
| Fragmentation stage | `nsplane` | `EngineBuilder::fragmenter(FragmentConfig::default())`; `FragmentConfig::translated` for destinations a translator turns into IPv6 | off | one `Option` check per local packet; local packets enter the core whatever their size |
| Crypto worker pool | `nsplane` | `EngineBuilder::crypto_workers(n)`, `n` >= 2 | 0: the owner task encrypts and decrypts | one `Option` check per packet, no tasks spawned; without crypto workers each peer owns its tunnel and the data path takes no lock (with workers it is shared behind a `Mutex`) |
| User-space TCP/IP stack | `nsplane-netstack` | `NetStack::new(NetStackConfig)`, `NetStack::split` as the builder's source and sink | not used | none: the crate is not a dependency of `nsplane` or `nsplane-tun` |
| Stack reassembly | `nsplane-netstack` | `NetStackConfig::reassembly = Some(ReassemblyConfig::default())` (64 datagrams, 30 s, 65 535 bytes) | off: fragments are dropped (`unsupported`) | one `Option` check per ingress packet; no reassembler is allocated |
| Oversize IPv4 UDP sends | `nsplane-netstack` | `NetStackConfig::udp_allow_fragmentation = true`, with `EngineBuilder::fragmenter` on the stack's engine | off: a packet above the MTU fails with `InvalidInput` | one length comparison per send, as before |
| Hybrid local side | `nsplane` | `Splitter::new(route).sink(..)` as the sink, `MergeSource::new().source(..)` as the source | not used | none: plain types, used only when passed to the builder |
| TUN segmentation offload | `nsplane-tun` | `Tun::create` turns it on; `Tun::create_with(name, TunOptions::new().offload(false))` opts out; `Tun::offload` reports it | on where the kernel supports it (Linux, Android); macOS, iOS and Windows have none | off: one read or write system call per packet |
| UDP segmentation offload (GSO/GRO) | `nsplane` | `UdpTransport::bind` turns it on; `UdpTransport::bind_with_offload(id, addr, false)` or `set_offload(false)` opts out | on: GSO where the platform has it, GRO on Linux and Android | off: one system call per datagram |
| UDP side channel | `nsplane` | `UdpTransport::with_side_channel(classify, capacity)` | off | one `Option` check per received datagram; nothing is classified, no task or copy |
| Message-link transport | `nsplane` | `LinkTransport::new(id, peer, dialer, config)` as a transport | not used | none: no task is spawned and no dependency added; the dialer (WebSocket, TLS) is the embedder's |
| WSS carriers | `nsplane-wss` | `WssDialer::new(config)?.into_transport(..)`, `WssStreamClient::new`, `WssStreamServer::new` | not a dependency | none: a separate crate; `nsplane` gains no WebSocket or TLS dependency (`tokio-tungstenite`, `rustls` with aws-lc-rs come only with `nsplane-wss`) |

**Crates of a minimal client.** `nsplane` and `nsplane-tun`, which pull in `nsplane-core`,
`nsplane-packet` and `nsplane-noise`. `nsplane-acl`, `nsplane-nat` and `nsplane-netstack`
are separate crates that `nsplane` and `nsplane-tun` do not depend on (`nsplane-nat` and
`nsplane-netstack` depend on `nsplane`, not the other way round), so they are not
built or linked unless the application adds them; `nsplane-uapi` is only needed to serve
the `wg` UAPI. None of the crates has optional Cargo features.

**Address family.** IPv4-only, IPv6-only or dual stack is the caller's choice and needs no
switch: the transport's bind address (`0.0.0.0:port` for IPv4 only, an IPv6 address for
IPv6 only, `[::]:port` for a dual-stack socket), the addresses and routes configured on the
TUN device (outside nsplane, e.g. `ip addr`), and the peers' allowed IPs.

**A minimal IPv4-only client** (one TUN device, one UDP socket, one peer, no filters):

```rust
use std::error::Error;
use std::net::SocketAddr;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{Ecn, EngineBuilder, Path, Peer, TransportId, UdpTransport};
use nsplane_tun::Tun;

async fn client(
    key: StaticSecret,
    server_key: PublicKey,
    server: SocketAddr, // e.g. 198.51.100.1:51820
) -> Result<(), Box<dyn Error>> {
    const UDP: TransportId = TransportId::new(0);
    // The caller sets up the TUN device's addresses and routes, e.g.
    // `ip addr add 10.0.0.2/32 dev wg0` and `ip route add 10.0.0.0/24 dev wg0`.
    let (source, sink) = Tun::create("wg0")?.split()?;
    let udp = UdpTransport::bind(UDP, "0.0.0.0:0".parse()?)?;
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    let mut peer = Peer::new(server_key);
    peer.allowed_ips = vec!["10.0.0.0/24".parse()?];
    peer.persistent_keepalive = Some(25);
    peer.path = Some(Path { transport: UDP, addr: server, ecn: Ecn::NotEct });
    engine.handle().add_or_update_peer(peer).await?;
    engine.wait().await?;
    Ok(())
}
```

**Offload never waits for more packets.** Batching and offload only group work that is
already there; nothing holds a packet back to fill a batch:

- the engine's I/O tasks fill a batch with non-blocking `try_recv` after the first packet
  and send what they have (no timers, no linger);
- TUN GSO/GRO writes coalesce only the packets of the batch they are handed;
- UDP GSO segments only runs of datagrams within the current batch;
- a GRO or segmented TUN read returns what one receive yields;
- the crypto worker pool hands a batch to a worker when it is full or when the owner task
  runs out of other work, never on a timer.

## Performance

Phase 5 numbers: release / bench profile in the dev image, x86-64, 32-core host shared with
other jobs, criterion means. The `data_path`, worker pool and engine latency rows are from
the Phase 5 follow-ups (campaign `nsplane-fu-202610030716`, workstream FA, 2026-10-03:
follow-ups #1 batched input and #17 no lock without workers); the other rows were re-run on
the merged 5C branch (5C-T7, 2026-10-03, 1-minute load 0.8-5.1), two runs each. The
subsections linked below hold each subtask's own measurements and analysis.

```text
cargo bench -p nsplane-core --bench data_path
cargo bench -p nsplane-acl --bench namespaces
cargo bench -p nsplane --bench worker_pool
cargo test --release -p nsplane-e2e --test netstack_lossy -- --ignored --nocapture
cargo test --release -p nsplane-e2e --test latency -- --ignored --nocapture
```

| Area | Case | Result (run 1 / run 2) | Reference |
| --- | --- | --- | --- |
| `data_path`, 64 B round trip | raw `Tunn` / device-equivalent / core, one packet per call | 359 ns, 472-474 ns, 530-533 ns (core vs device +12 %) | main 64131c7 core 546 ns; Phase 3+4 core 540 ns |
| `data_path`, 1420 B round trip | device-equivalent / core, one packet per call | 1.278-1.294 us, 1.331-1.351 us (core vs device +4-5 %) | main 64131c7 core 1.354 us; Phase 3+4 core 1.37 us |
| `data_path`, 64 B batched | core, 32 per call (`core_round_trip_batch32`), per packet | 13.15-13.21 us per batch = 411-413 ns (core vs device -12.5 % to -13.0 %) | |
| `data_path`, 1420 B batched | core, 32 per call, per packet | 39.24-39.31 us per batch = 1.227 us (core vs device -4.0 % to -5.2 %) | |
| `data_path`, instructions per round trip (callgrind) | raw `Tunn` / device-equivalent / core / core batched, 64 B and 1420 B | 3090 / 4435 / 5299 / 3910 (batched vs device -11.8 %); 18168 / 19513 / 20370 / 18980 (-2.7 %) | core before #1's batching 5289 / 20359 |
| `data_path`, one direction (5C) | core encapsulate / decapsulate, 64 B and 1420 B | 273 / 273 ns and 278 / 278 ns; 673 / 674 ns and 692 / 685 ns | |
| ACL hook, established flow | namespace member / default policy (not cached) | 51.2 / 51.0 ns, 54.9 / 54.6 ns | before the hook: every packet a new flow, 669 ns / 71 ns |
| ACL hook, bypass peer | new flow / established | 38.1 / 37.9 ns, 37.5 / 37.3 ns | 937 ns before the hook |
| ACL hook, new flow | default policy / namespaces / grant / pinhole | 55.4 / 55.2 ns, 184 / 184 ns, 346 / 339 ns, 216 / 205 ns | |
| ACL hook, grant established / outbound | grant / outbound (default, namespaces, restricted, bypass) | 268 / 276 ns; 76, 95, 156, 77 ns | 1.75 us grant, 580/623 ns outbound before |
| ACL hook, floor | five-tuple parse + snapshot load | 5.7 + 8.8 ns | |
| Queues | default capacities | `queue_capacity` 1024, command 64, `event_capacity` 1024 | [Queue depths](#queue-depths) |
| Worker pool, 64 B | off / 2 / 4 workers | 1.49 / 1.55 Mpps, 1.68 / 1.64 Mpps, 1.61 / 1.64 Mpps | before #1/#17: 1.21 / 1.07, 1.30 / 1.27, 1.25 / 1.26 Mpps; [Crypto worker pool](#crypto-worker-pool) |
| Worker pool, 1420 B | off / 2 / 4 workers | 869 / 906 kpps (9.9 / 10.3 Gbit/s), 0.94 / 1.20 Mpps (10.6 / 13.6 Gbit/s), 1.26 / 1.17 Mpps (14.3 / 13.3 Gbit/s) | before #1/#17: 676 / 676 kpps, 1.02 / 1.00 Mpps, 0.98 / 0.98 Mpps |
| Engine latency, idle | two engines over UDP loopback, builder defaults, 2000 pings, p50 / p99 | 11.3 / 36.0 us, 11.2 / 40.3 us | before #1's engine batching: 20.9 / 41.0 us, 11.0 / 23.7 us; [Engine batching under load](#engine-batching-under-load) |
| Engine latency, loaded | the same next to a saturating bulk flow, p50 / p99 / lost pings | 2.15 / 4.69 ms / 13, 2.13 / 5.16 ms / 18 | before: 2.71 / 6.91 ms / 2, 2.36 / 4.74 ms / 1 |
| Netstack TCP, no loss | 64 MiB, one connection | 439.0 / 430.0 MB/s | [Netstack throughput](#netstack-throughput) |
| Netstack TCP, 1 % loss | 16 MiB | 2.07 / 2.08 s (8.1 MB/s) | |
| Netstack TCP, 3 % loss | 16 MiB | not done after 60 s (833 / 715 drops) | 5C-T6: 54.2 / 59.2 s |
| Netstack TCP, bottleneck | 16 MiB, 25 MB/s, 64-datagram buffer | 12.9 / 16.8 s (1.3 / 1.0 MB/s, 320 / 341 drops) | 5C-T6: 20.9 / 18.9 s |
| Netstack UDP, no loss | 50 000 x 1200 B | 614.7 / 670.2 MB/s | |

- Data path. Follow-up #1 (5C) removed the rx buffer swap, the `copy_within` shifts and the
  `set_len` zero-fills, leaving ~695 instructions of dispatch per 64 B round trip. The
  batched entry points (`Core::handle_datagrams`, `Core::handle_locals`) share that dispatch
  across a batch: at 32 packets per call the core is 11.8 % (64 B) and 2.7 % (1420 B) below
  the device-equivalent baseline by instruction count, and 12.5-13.0 % and 4.0-5.2 % below it
  in wall clock, so the 10 % target is met at 64 B for batched input. One packet per call
  still costs +12 % (64 B) and +4-5 % (1420 B) over the baseline; the empty lookup cache adds
  10 instructions to it. The engine feeds the core in batches of what is already queued, so
  a lone packet takes the single-packet cost and a busy one approaches the batched cost.
- No lock without workers (#17). The core round trip measures 532 ns at 64 B (device-equivalent
  474 ns, raw 359 ns) and 1.348 us at 1420 B (device-equivalent 1.282 us), against 546 ns and
  1.354 us on main 64131c7: removing the per-peer tunnel lock from the pool-off path is a
  small gain within the run-to-run spread, and the worker pool no longer costs it to
  embedders that do not use the pool.
- ACL hook. An established flow costs about the same as the default policy's three rules,
  and a bypass peer less than either: the floor every packet pays is parsing its five-tuple
  and loading the engine snapshot (5C-T3: 6-7.5 ns + 9.5-11.5 ns = 16-19 ns), and the rest is
  the flow-table lookup under its lock. Skipping the reply check would be exact only for
  unidirectional traffic, so it stays. Exactness was not weakened: a differential test
  checks verdicts and counters against a full evaluation of every packet. See
  [nsplane-acl](#nsplane-acl).
- Worker pool. The batched input and the lock-free pool-off path make every case about
  15-25 % faster than before the follow-ups (1420 B with 2 workers within the noise). The
  pool moves full-size packets up to about 1.4x further, small packets little; 4 workers do
  not add much to 2, as the owner task stays the limit.
- Netstack. Without loss the stack is not the limit (same-build spread 320-460 MB/s TCP,
  470-900 MB/s UDP). At 3 % random loss smoltcp's timeout-bound recovery lands right at the
  test's 60 s limit (5C-T6 finished in 54-59 s); the 1 % case and the bottleneck complete.

### Engine batching under load

Follow-up #1's engine side feeds the core what is already queued, in batches of up to
`MAX_BATCH`, with no wait and no timer, and reads local packets only up to the transmit
room (see *Backpressure* under [nsplane (driver)](#nsplane-driver)). Measured with
`crates/nsplane-e2e/tests/latency.rs` (`round_trip_latency`, `round_trip_latency_queue_256`):
two engines over UDP loopback with the builder defaults, 2000 one-packet pings, idle and
next to a saturating bulk flow between the same engines; "before" is the same branch
without the engine batching, two runs each, 1-minute load 2.8-5.9.

| Case | p50 / p99 / lost pings, after | before |
| --- | --- | --- |
| Idle, no workers | 11.3 / 36.0 us, 11.2 / 40.3 us | 20.9 / 41.0 us, 11.0 / 23.7 us |
| Loaded, no workers | 2.15 / 4.69 ms / 13, 2.13 / 5.16 ms / 18 | 2.71 / 6.91 ms / 2, 2.36 / 4.74 ms / 1 |
| Loaded, no workers, `queue_capacity` 256 | 1.75 / 12.0 ms / 100, 1.59 / 3.89 ms / 93 | 1.51 / 3.85 ms / 0, 1.52 / 3.81 ms / 0 |
| Loaded, 2 workers (for information) | 7.40 / 21.7 ms / 286, 7.25 / 11.8 ms / 387 | 3.53 / 9.96 ms / 316, 3.36 / 9.59 ms / 267 |

- Idle latency is unchanged within the run-to-run spread: a lone packet goes through at
  once. Under load, p50 is lower in both runs and the worst p99 is lower (5.16 against
  6.91 ms) than before, and the
  sender's backlog stays at 64 (`MAX_BATCH`) because local intake follows the transmit room.
  A first attempt that read local packets without that bound filled the sender's transmit
  queue and backlog to 1024 each, and its loaded p99 rose to 7.8-19 ms.
- The extra loss under a saturating flow happens only at the receiver's full sink. A
  diagnostic run moved 1093 packets per ms of bulk traffic after the change against 919
  before (about 19 % more), and the receiver dropped 486 251 packets under `DROP_SINK_FULL`
  against 717 before; the sender dropped nothing. Batching raises the tunnel's throughput
  until it outruns the receiving application. High-water marks, loaded without workers:
  after, sender `local` 1024, `transmit` 1024, `backlog` 64, receiver `datagrams` 1024,
  `deliver` 1024; before, sender `transmit` 284-640, `backlog` 0, receiver `deliver`
  363-372. The lost pings are these sink drops, which a smaller `queue_capacity` makes more
  frequent.
- A sink slower than the tunnel must therefore size `queue_capacity` for its bursts or apply
  its own flow control (e.g. TCP through the netstack); the engine does not pace the sender
  to the receiver's sink. Sender pacing and receiver-side backpressure are an open design
  item (`docs/task/20261002-1509-phase1-followups.md` item 21).
- With 2 workers the loaded latency is higher in both builds, as the jobs in flight sit at
  their bound (`QueueStats::crypto` at `queue_capacity`) with the queueing delay that adds;
  these rows are for information only.

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

`nsplane-e2e`'s `nat64_lan` test runs `Nat64Lan` around a gateway engine's local side, with an
IPv6 client engine reaching an IPv4 netstack LAN host over channel transports.
The `subnet_gateway` example scenario runs it in containers: a kernel WireGuard peer reaches
an IPv4 LAN host through the mapped /96.
