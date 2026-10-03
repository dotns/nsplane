# nsplane Architecture

This page describes what is on `main`. The target design and roadmap are in
[design.md](design.md).

## Crates

| Crate | Path | Role |
|---|---|---|
| `nsplane-noise` | `crates/nsplane-noise/` | The Noise protocol state machine (`noise`); no I/O |
| `nsplane-packet` | `crates/nsplane-packet/` | Packet buffers (`PacketBuf`, `PacketPool`, `PacketBatch`), IP header views, shared value types (`PeerId`, `TransportId`, `Path`, `Ecn`) |
| `nsplane-core` | `crates/nsplane-core/` | Sans-I/O engine core: peers, cryptokey routing, timers, path policy, packet filters |
| `nsplane` | `crates/nsplane/` | Tokio driver: `Engine`, `EngineBuilder`, `EngineHandle`, events, the I/O traits, `UdpTransport` |
| `nsplane-acl` | `crates/nsplane-acl/` | Accept-only ACL policy engine (`AclEngine`), the `AclFilter` and `FlowTracker` packet filters |
| `nsplane-tun` | `crates/nsplane-tun/` | OS TUN devices as `PacketSource`/`PacketSink` |
| `nsplane-netstack` | `crates/nsplane-netstack/` | User-space TCP/IP stack on smoltcp as `PacketSource`/`PacketSink`: TCP and UDP endpoints for IPv4 and IPv6 |
| `nsplane-uapi` | `crates/nsplane-uapi/` | The `wg` UAPI over an `EngineHandle`; Unix socket listener |
| `nsplane-cli` | `crates/nsplane-cli/` | Linux/macOS development daemon: TUN + engine + UAPI |
| `nsplane-examples` | `examples/` | Not published: runnable example binaries on the public APIs (`src/bin/`) and their shared node code (`src/lib.rs`), including the single-port relay and its UDP and WSS client transports |

```text
nsplane-noise (noise) ─► nsplane-core ─► nsplane ─► nsplane-tun, nsplane-uapi ─► nsplane-cli
nsplane-packet ────────► nsplane-core, nsplane
nsplane, nsplane-packet ─► nsplane-netstack
nsplane-core, nsplane-packet ─► nsplane-acl
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

The core is never shared, so there are no locks on the data path.

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

`UdpTransport` is the network side: one dual-stack UDP socket with fwmark and ECN support.
`ChannelSource`, `ChannelSink` and `ChannelTransport` are in-memory implementations for tests
and embedders.

For a hybrid local side, e.g. a TUN device next to a userspace netstack, `Splitter` is a
`PacketSink` that routes each delivered packet to one of several sinks by a closure
(`Fn(PeerId, &PacketBuf) -> usize`) and `MergeSource` is a `PacketSource` that serves
several sources round-robin and reports the smallest of their MTUs. The splitter awaits
only the chosen sink, but a waiting sink still holds back the engine's next delivery;
packets routed to an index out of range are dropped and counted (`Splitter::misrouted`).

## nsplane-tun

`Tun::create` opens a TUN device, `Tun::from_fd` (Unix) adopts one, and `Tun::split`
yields a `TunSource` and a `TunSink` registered with the tokio reactor.

- `linux`: `/dev/net/tun` (Linux, Android), raw IP packets.
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

## nsplane-uapi and the CLI

`Uapi` answers `get=1` and `set=1` over an `EngineHandle`; `listen_port` and `fwmark` bind a
new `UdpTransport` and install it with `EngineHandle::set_transport`. On Unix,
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

## Unsafe code

`unsafe` lives only in `nsplane-tun`'s platform
modules (`unix`, `linux`, `darwin`, and loading Wintun in `windows`), each with SAFETY
comments. `nsplane-packet`, `nsplane-core`, `nsplane`, `nsplane-acl`, `nsplane-netstack`, `nsplane-uapi` and `nsplane-cli` declare
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
