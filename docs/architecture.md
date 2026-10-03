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

`UdpTransport` is the network side: one dual-stack UDP socket with fwmark and ECN support.
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
packets are evaluated from scratch. The full rules and per-packet bench numbers (`cargo
bench -p nsplane-acl --bench namespaces`) are in the crate docs
(`crates/nsplane-acl/src/lib.rs`, *Namespaces*, *Pinholes* and *Performance*).

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
