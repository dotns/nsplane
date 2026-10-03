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

`UdpTransport` is the network side: one dual-stack UDP socket with fwmark and ECN support,
4 MiB socket buffers requested (clamped by `net.core.rmem_max` / `wmem_max`) and segmentation
offload through `quinn-udp`.
`ChannelSource`, `ChannelSink` and `ChannelTransport` are in-memory implementations for tests
and embedders.

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
packets are evaluated from scratch. The full rules and per-packet bench numbers (`cargo
bench -p nsplane-acl --bench namespaces`) are in the crate docs
(`crates/nsplane-acl/src/lib.rs`, *Namespaces*, *Pinholes* and *Performance*).

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
