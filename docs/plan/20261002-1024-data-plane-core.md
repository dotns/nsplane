# 20261002-1024-data-plane-core Complete data plane: transport, netstack and ACL inside nstun

- **status**: implementing
- **createdAt**: 2026-10-02 10:24
- **approvedAt**: 2026-10-02 10:50
- **relatedTask**: 20261002-1020-data-plane-core

## Context

Goal: nstun becomes the complete data plane. ns keeps only business logic (control plane,
pairing, policy decisions, path selection rules) and calls a library that owns packet I/O
(TUN or an in-process netstack), the WireGuard engine, the transports, and the ACL.

### What nstun has today (after plan 20261001-1859)

- `boringtun::noise`: the transport-agnostic WireGuard core (`Tunn`, in-place seal/open,
  `RateLimiter`, zerocopy message views). This is the part ns uses and it stays.
- `boringtun::device`: a classic `wg` daemon. Shared pieces that carry over: `PeerTable`
  (by key / session index / allowed IP, longest-match source check), `uapi` (get/set over
  any reader/writer), `receive_datagram` / `send_from_tun` / `update_timers` (the per-packet
  logic), and the TUN backends (`tun_linux`, `tun_darwin`, `windows/tun` on Wintun).
- What does not carry over: the sync epoll/kqueue event loop and the Windows thread model
  (ns is tokio), the fixed TUN → kernel UDP → one endpoint per peer pipeline, and UAPI text
  as the only configuration path.

### What ns has today (working tree of a05b6f55 plus uncommitted changes, 2026-10-02)

ns is **mid-refactor by another session**: `keynet-*` crates were renamed to `quick-*`,
rustls moved from `ring` to `aws-lc-rs`, 316 files uncommitted. Findings below use the
current tree; names may still move. Nothing in ns is modified by this plan.

ns runs **two independent WireGuard data planes**, both on crates.io `boringtun 0.7`:

1. `tunnel-wg` (account mode, ~10k lines): tokio; `Vec<PeerState>` behind one mutex;
   two modes selected by `DataPlaneMode`:
   - **UserSpace**: UDP → `Tunn` → ACL (`acl::AclEngine`, `nat::FragmentAclGate`) → mpsc →
     `netstack::NetStack` (smoltcp 0.13.1, channel-driven `VirtualDevice`) → proxy.
   - **TUN**: UDP → `Tunn` → `nat::tun_forward_packet` (ACL + DNAT/SNAT + conntrack) →
     local services via the kernel TUN, remote services via smoltcp.
   Around the core: relay source registration, reflexive probes, hole punching, the
   direct-link promote/demote state machine, recovery challenges, per-peer roaming
   policy (pinned / roaming / recovery endpoint), node-L3 gate, dynamic L3 (IPv6 subnet)
   routes, GSO/GRO batching through `quinn-udp`, status reporting.
   Receive demux: by `receiver_idx >> 8` for data/response/cookie; handshake initiations
   are matched by source endpoint and tried against every peer sharing that endpoint
   (nstun's `parse_handshake_anon` resolves this by decrypting the static key instead).
2. `quick-runtime` (Quick mode): sans-I/O. `DataPlane<P, D: TunDevice>` drives `Tunn`
   from a provider snapshot; `TransportAdapter` owns per-peer path selection
   (`PathSelection::{Direct, Relay{carrier}}`), bounded queues with a control reserve, and
   relay sources; `BridgeRuntime` abstracts a TCP/UDP bridge platform (in-memory variants
   for tests). IPv6 ↔ IPv4 alias translation lives here too.

Supporting crates: `netstack` (smoltcp, 1.7k lines), `acl` (2.4k lines: accept-only rules,
`SourceAssertion::{WgPeerKey, Terminate, External}`, deny scope, layered merge, policy
tests; depends on `common` for `Protocol`/`AclConfig`), `nat` (conntrack, packet NAT,
`ServiceRouter`; depends on `control`, `common`, `telemetry`), `proxy`, `tunnel-ws` (WSS
carriers, opaque WireGuard-over-WSS pump), `ns::tun_device` (OS TUN packet I/O for
Linux/macOS/Windows/Android/iOS host writers), `ns-windows-platform` (own Wintun code).

ns conventions that constrain the design: `#![forbid(unsafe_code)]` everywhere except
listed platform crates (ADR 2026-10-01-unsafe-owning-crates), tokio throughout, `Bytes`
on the channels, bounded queues with counted drops, no `panic` in runtime code.

### Reference designs (design only; no code is copied)

- **Tailscale `net/tstun` + `wgengine`** (BSD-3-Clause, Go): `tstun.Wrapper` wraps a
  `tun.Device` and adds (a) filter hooks on both directions, pre and post
  (`PreFilterPacketInboundFromWireGuard`, `PostFilterPacketOutboundToWireGuard`, ...),
  (b) the ACL (`filter.Filter`) run inbound and outbound with a per-peer "jailed" variant,
  (c) packet injection in both directions (`InjectInbound*` toward the OS/netstack,
  `InjectOutbound` toward WireGuard), (d) per-peer SNAT/DNAT from a `peerConfigTable`,
  (e) a leading header gap in every buffer (`WritePacketStartOffset`) so WireGuard seals
  in place. gVisor netstack attaches purely through those hooks and injection. The
  multi-path transport (direct UDP + DERP relay) is `magicsock`, a `conn.Bind`
  implementation that picks the path per peer and hides it from the WireGuard device.
  `wgengine.Engine` is the facade: `Reconfig`, `SetFilter`, `SetPeerForIPFunc`, status
  callbacks, `Ping`.
- **mullvad/gotatun** (MPL-2.0): `IpSend`/`IpRecv` traits for packet I/O (TUN or tokio
  channel), `UdpTransportFactory`/`UdpSend`/`UdpRecv` for the network side with batched
  variants, `DeviceBuilder<Udp, TunTx, TunRx>` generic over both, a programmatic
  `DeviceWrite` API (`add_or_update_peer`, `modify_peer`, `remove_peer`, `set_endpoint`),
  tasks `incoming`/`outgoing`/`timers`, `suspend`/`resume`, an `MtuWatcher`, and a
  channel-based UDP-over-IP transport for nesting tunnels.

### Survey of comparable projects (GitHub, 2026-10-02)

| Project | Lang / license | What it shows for this plan |
|---|---|---|
| firezone/firezone `rust/libs/connlib` (9.1k stars, boringtun-based, production) | Rust / Apache-2.0 | The closest design. **Sans-I/O core**: `snownet::Node` and `tunnel-proto` state machines expose `decapsulate`/`encapsulate`, `poll_transmit`, `poll_event`, `poll_timeout`, `handle_timeout`; one `tunnel::Io` struct drives TUN, UDP sockets (GSO via `quinn-udp`), DNS and timers under tokio. Multi-path (ICE direct + TURN relay) is inside the core; `Transmit { src, dst, payload, ecn }` carries ECN. Supporting crates: `ip-packet` (zero-copy views on `ingot`, fragments, ICMP errors), `bufferpool` (`Buffer<B>` returns to its pool on drop), `tun` (trait over `PacketBatch` channels) with per-platform `tun-linux/-apple/-android/-windows` and `tun-offload` (virtio-net GSO/GRO coalesce/split), `flow-tracker`, `l3-tcp` (smoltcp, only for DNS over TCP). |
| tailscale `net/tstun`, `wgengine` | Go / BSD-3 | Filter hooks pre/post in both directions, injection both ways, per-peer NAT table, header room in every buffer, netstack attached only through hooks and injection. |
| mullvad/gotatun (1.4k) | Rust / MPL-2.0 | `IpSend`/`IpRecv` + `UdpSend`/`UdpRecv` traits, `DeviceBuilder` generic over them, programmatic `DeviceWrite`, `suspend`/`resume`, MTU watcher. |
| NordSecurity/NepTUN | Rust / BSD-3 | boringtun fork: crypto moved off the event-loop threads into worker threads fed by bounded batch channels (Apple stays inline). Shows the crypto-worker split is worth keeping separable from I/O. |
| WireGuard/wireguard-go `conn.Bind`, netbirdio/netbird `ICEBind` | Go / MIT, BSD | The single-transport-object alternative. netbird has to invent fake `127.1.x.x` endpoints to represent relayed peers behind `Bind`, which is the cost of hiding paths from the engine. |
| EasyTier (13.9k) | Rust / LGPL-3.0 | Transports selected by URL scheme (udp/tcp/ws/quic/wg), smoltcp gateway; confirms multi-transport as a first-class concept. LGPL: design only. |
| aramperes/onetun (1k), vi/wgslirpy | Rust / MIT | boringtun + smoltcp virtual device bridging; small, same `VirtualDevice` pattern ns uses. |
| narrowlink/ipstack (1.0.x, used by tun2proxy 1.4k), cavivie/netstack-smoltcp (smoltcp 0.12), spacemeowx2/tokio-smoltcp | Rust / Apache-2.0, MIT | Off-the-shelf userspace stacks. `ipstack` implements its own TCP on `etherparse` (no ICMP, less control over MSS/windows); `netstack-smoltcp` lags smoltcp. ns's own smoltcp driver (single egress turn, MSS/MTU coupling) is kept; smoltcp is at 0.14.0, ns pins 0.13.1. |
| DefGuard/wireguard-rs | Rust / other | Management API over kernel and userspace WireGuard; not a data plane. |
| rich7420/rustguard | Rust | GSO/GRO + recvmmsg userspace WireGuard; confirms the Linux offload path matters for throughput. |

### Architecture review against the survey

Changes adopted into the proposal below:

1. **Sans-I/O engine core** (firezone, and ns's own `quick-runtime`). The WireGuard engine
   becomes a side-effect-free state machine in `nstun-core`: it takes datagrams and local
   packets in, returns `Transmit`/`Deliver`/`Event` out, and is ticked with `handle_timeout`.
   A separate `nstun` crate is the tokio driver (sockets, TUN, netstack, batching, timers).
   Why: deterministic tests without a runtime or mocks; the same core can be embedded by
   `quick-runtime` (already sans-I/O), by `tunnel-wg` (through the driver), and by mobile
   hosts that own their event loop; no locks on the hot path, which removes ns's whole
   class of "lock held across await" hazards. Cost: batching and crypto workers must be
   designed at the driver boundary instead of falling out of async tasks.
2. **Buffers on `bytes`**: `PacketBuf` wraps a `BytesMut` with header room in front; the
   driver keeps a pool of `BytesMut` buffers and reuses them (firezone shows why: the
   per-packet `Vec` in ns's loops costs an allocation per packet). No hand-written pool.
3. **ECN/DSCP carried on `Path`/`Transmit`** (firezone, rustguard): cheap now, hard later.
4. **Offload is two layers** (firezone `tun-offload` + `socket-factory`, tstun, rustguard):
   Linux TUN virtio-net header GSO/GRO on the local side and UDP GSO/GRO on the network side.
   Phase 5 covers both; the `PacketBatch` type exists from Phase 1 so the API does not
   change when batching arrives.
5. **Optional crypto worker pool** (NepTUN): the driver may hand sealed/opened batches to
   worker threads. Designed as a driver option in Phase 5, not in the core.
6. **Per-flow accounting as a filter** (firezone `flow-tracker`): covers ns's
   `data_bytes_rx`-style counters without special cases in the engine. Phase 4.
7. **Transport + PathPolicy stay split** (not `conn.Bind`): the netbird fake-endpoint
   workaround is the failure mode of hiding paths; ns's ladder needs to know which path
   authenticated and to be asked before roaming.
8. **smoltcp 0.14** for `nstun-netstack`, porting ns's driver; `ipstack` evaluated and not
   chosen (own TCP implementation, no ICMP, less MSS/window control).

License handling (decided 2026-10-02): **no code is copied or vendored from any reference
project**, whatever its license; every reference is design-only. Where a mature crate
exists for a building block, use the crate instead of writing or copying one: the buffer
type is `bytes` (`BytesMut`/`Bytes`, 1.12.x), pooling is `BytesMut` reuse plus an
off-the-shelf object pool if measurements show it pays. Code that ns owns (`acl`,
`netstack`) may be moved into nstun in Phases 3-4 because it is the same owner.

### Gaps between nstun's device layer and what ns needs

| ns need | nstun today | plan |
|---|---|---|
| Packet I/O that is not a TUN (netstack, iOS/Android host bridge) | TUN only | `PacketSource`/`PacketSink` traits |
| Several paths per peer (direct, relay UDP, WSS, candidates) and policy on roaming | one `SocketAddr`, roam on any authenticated packet | `Transport` + `PathPolicy` traits; default = plain UDP + standard roaming |
| Hooks between decrypt/encrypt and the packet owner (ACL, NAT, node-L3, probes) | none | `PacketFilter` chain, both directions |
| In-process TCP/UDP termination | none | `nstun-netstack` (smoltcp) |
| ACL as part of the data plane | none | `nstun-acl` (port of ns `acl`) |
| Configuration by code, status events | UAPI text, no events | `Engine` API + event channel |
| tokio | sync event loop | tokio engine; the sync `device` layer is retired once the engine passes e2e |

## Proposal

### Crate layout (nstun workspace)

| Crate | Role | Depends on |
|---|---|---|
| `boringtun` | unchanged noise core (`noise`, `x25519`, `ffi`, `jni`). The `device` module is deleted at the end of Phase 1 (decided 2026-10-02); its reusable parts move to `nstun-core`/`nstun-tun`. | — |
| `nstun-packet` | IPv4/IPv6/TCP/UDP/ICMP header views (zerocopy), five-tuple, checksums, IPv4 fragment metadata, `PacketBuf` with header room for in-place sealing, a buffer pool. No I/O. | `zerocopy` |
| `nstun-core` | the sans-I/O engine: peer table, sessions, timers, filter chain, path policy queries, injection; input = datagrams and local packets, output = `Transmit`, `Deliver`, `Event`; `handle_timeout`/`poll_timeout`. No tokio, no sockets. Re-exports `boringtun::noise`. | `boringtun`, `nstun-packet` |
| `nstun` | the tokio driver: `PacketSource`/`PacketSink`/`Transport` traits and their default implementations (UDP), `PacketBatch`, the `Engine` facade and `EngineHandle` API, event channel. One task owns the core; I/O tasks feed it through bounded channels. | `nstun-core`, `tokio` |
| `nstun-tun` | `PacketSource`/`PacketSink` for OS TUNs: Linux (with virtio-net offload in Phase 5), macOS utun, Windows Wintun, and adoption of an inherited fd/handle (iOS, Android). Only crate besides `boringtun` with `unsafe`. | `nstun` |
| `nstun-netstack` | smoltcp 0.13 stack implementing `PacketSink`+`PacketSource`; yields TCP connections (`AsyncRead + AsyncWrite`) and UDP flows; dialers for the reverse direction. | `nstun`, `smoltcp` |
| `nstun-acl` | the policy engine, as a `PacketFilter` and as a connection-level `is_allowed`, plus a flow tracker filter for per-flow accounting. Ported from ns `acl`, decoupled from ns `common`. | `nstun-packet` |
| `nstun-uapi` | `wg` UAPI adapter over the engine (Unix socket / named pipe). For the dev CLI and `wg show`. | `nstun` |
| `boringtun-cli` | dev tool = `nstun` + `nstun-tun` + `nstun-uapi`. | |

Later, optional: `nstun-nat` (conntrack + DNAT/SNAT, from ns `nat`), `nstun-batch` (GSO/GRO
UDP transport on Linux through `quinn-udp`).

### Sans-I/O core (`nstun-core`)

```rust
pub struct Core { /* peers, sessions, timers, filters, policy, clock-free */ }

pub enum Input<'a> {
    /// A datagram from a transport, with the path it arrived on.
    Datagram { path: Path, data: &'a mut PacketBuf },
    /// A local packet (TUN read, netstack egress, injection) to encrypt.
    Local { packet: PacketBuf },
    /// Configuration: add/update/remove peer, set key, set paths.
    Config(ConfigChange),
}
pub enum Output {
    /// Send this datagram on this path (ECN included).
    Transmit { path: Path, data: PacketBuf },
    /// Deliver this decrypted packet to the local side.
    Deliver { from: PeerId, packet: PacketBuf },
    Event(Event),
}

impl Core {
    pub fn handle_input(&mut self, input: Input<'_>, now: Instant);
    pub fn poll_output(&mut self) -> Option<Output>;
    pub fn poll_timeout(&self) -> Option<Instant>;
    pub fn handle_timeout(&mut self, now: Instant);
}
```

`PathPolicy` and `PacketFilter` are plain trait objects owned by the core and called
synchronously; they never do I/O. Tests drive two `Core`s against each other with a fake
clock, like firezone's and `quick-runtime`'s state-machine tests.

### Driver traits (`nstun`)

```rust
/// A full IP packet with header room in front, so the engine can seal it in place.
pub struct PacketBuf { /* Vec<u8> or pooled; data at [DATA_HEADER_SZ..] */ }

pub trait PacketSource: Send + 'static {
    /// Next packet from the local side (TUN read, netstack egress, host bridge).
    fn recv(&mut self) -> impl Future<Output = io::Result<PacketBuf>> + Send;
    fn mtu(&self) -> watch::Receiver<u16>;
}
pub trait PacketSink: Send + Sync + 'static {
    /// Deliver a decrypted packet to the local side.
    fn send(&self, packet: PacketBuf, from: PeerId) -> impl Future<Output = io::Result<()>> + Send;
}

/// Where a datagram came from or goes to. The built-in transport is UDP; ns adds its own.
pub struct Path { pub transport: TransportId, pub addr: SocketAddr, pub ecn: Ecn }

pub trait Transport: Send + Sync + 'static {
    fn recv(&self, buf: &mut PacketBuf) -> impl Future<Output = io::Result<(usize, Path)>> + Send;
    fn send(&self, datagram: &[u8], to: &Path) -> impl Future<Output = io::Result<()>> + Send;
}

/// Per-peer path decisions; the engine never changes a path on its own.
pub trait PathPolicy: Send + Sync + 'static {
    /// Path for the next outgoing message of this kind (data, handshake, keepalive).
    fn select(&self, peer: PeerId, kind: MessageKind) -> Option<Path>;
    /// An authenticated message arrived from `from`. Return whether to adopt it as the
    /// peer's path (standard WireGuard roaming returns `true` for every authenticated
    /// non-cookie message; ns returns its ladder/hysteresis decision).
    fn on_authenticated(&self, peer: PeerId, from: &Path, kind: MessageKind) -> Roam;
}

pub enum Verdict { Accept, Drop { reason: &'static str }, Handled }
pub trait PacketFilter: Send + Sync + 'static {
    /// Decrypted packet from `peer`, before it reaches the sink. May rewrite in place.
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict;
    /// Local packet routed to `peer`, before encryption. May rewrite in place.
    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict;
}
```

`Handled` lets a filter consume a packet (probe replies, ICMP for the engine's own address,
netstack intercepts) the way tstun's `DropSilently` after injection does.

### Engine (`nstun::Engine`)

- Built with `EngineBuilder` generic over source/sink/transport (gotatun's shape), with
  defaults: `UdpTransport` (dual-stack socket, optional fwmark), `StandardRoaming`
  policy, no filters, `TunSource`/`TunSink` from `nstun-tun`.
- One task owns the `Core` and runs the firezone-style loop: poll I/O for input, feed
  the core, drain `Output`s to transports/sinks, sleep until `poll_timeout`. Transports and
  sources run their own tasks and feed bounded channels of `PacketBatch`. There are no
  locks on the hot path; `EngineHandle` calls are messages to the owner task.
- Programmatic API (`EngineHandle`): `set_private_key`, `add_or_update_peer(Peer)`,
  `remove_peer`, `set_allowed_ips`, `set_preshared_key`, `set_keepalive`, `peer_stats`,
  `inject_inbound(packet)`, `inject_outbound(packet)`, `force_handshake(peer, path)`,
  `suspend`/`resume`, `shutdown`. `Peer` carries a key, allowed IPs, PSK, keepalive, and an
  initial path; everything else about paths goes through `PathPolicy`.
- Events (`broadcast`/`mpsc`): `HandshakeCompleted { peer, path, rtt }`,
  `Authenticated { peer, from }`, `PathAdopted`, `SessionExpired`, periodic
  `PeerStats { rx, tx, data_rx, last_handshake }`, `Dropped { peer, reason }` counters.
  These replace `tunnel-wg`'s `GatewayStatusUpdate` fields.
- Receive demux: session index first; handshake initiations through
  `parse_handshake_anon` (no endpoint matching, so shared relay endpoints are fine).
- Backpressure: bounded channels everywhere; a full sink drops with a counted reason, a
  full transport queue holds back the source (ns's stated rule).
- Zero copy: `PacketBuf` keeps `DATA_HEADER_SZ` + 16 bytes of room; sources write
  directly into it; `encapsulate_in_place`/`decapsulate_in_place` are the only paths.

### Netstack (`nstun-netstack`)

- `NetStack::new(addresses, mtu)` implements `PacketSink` (inject) and `PacketSource`
  (egress), driven by one task around smoltcp's `poll_ingress_single`/`poll_egress`
  (ns's `VirtualDevice` approach, which keeps a single egress turn per packet).
- API: `incoming_tcp() -> impl Stream<Item = TcpConnection>`, `incoming_udp()` flows with a
  reply handle, `connect_tcp`/`bind_udp` for the reverse direction, `TUNNEL_MTU` derived
  from the engine's MTU so the advertised MSS fits the tunnel (ns's black-hole lesson).
- Hybrid mode (ns TUN mode): `nstun::Splitter` sink that routes each decrypted packet to
  one of N sinks by a user closure (`local service → TUN`, `remote → netstack`), which is
  what `nat::tun_forward_packet` decides today. NAT itself stays a filter.

### ACL (`nstun-acl`)

- Port ns `acl` (policy model, matcher, deny scope, layered merge, policy self-tests) with
  `Protocol` and the config types defined locally (no `common` dependency).
- Two entry points: `AclFilter` implementing `PacketFilter` inbound (five-tuple from
  `nstun-packet`, `SourceAssertion` derived from the decrypting peer's key through a
  user-supplied `PeerIdentity` map, fragment gate for non-first fragments), and
  `AclEngine::is_allowed(&AccessRequest)` for connection-level checks from the proxy.
- Policy reload is atomic (`ArcSwap`), fail-closed when no policy is loaded (ns rule).
- ns's existing policy tests are ported as the acceptance suite.

### What stays in ns (business layer)

Control plane and config translation (`WgConfig` → `Peer`s), pairing, relay registration
and reflexive probes (as `PacketFilter`s / separate tasks that use `inject_*`), hole punch
and the link ladder (as a `PathPolicy` plus a task issuing `force_handshake`), relay and
WSS carriers (as `Transport`s), node-L3 gate and dynamic L3 routes (as `PacketFilter`s),
service routing and the proxy (consumers of `nstun-netstack` connections), status
aggregation (consumer of engine events). `quick-runtime` keeps its sans-I/O `DataPlane`
for now; moving it onto the engine is a follow-up decision once Phase 2 shows the
`Transport`/`PathPolicy` traits cover its `TransportAdapter`.

### Phases

Each phase is one PMA task with its own tests; the engine is usable after Phase 1.

| Phase | Deliverable | Verification |
|---|---|---|
| 0 | ns pins nstun's `noise` (two `Some(src.ip())` → `Some(src)` call sites). Done in ns, on its own PMA task, after its current refactor lands. | ns `just dev-check` + targeted tests |
| 1 | `nstun-packet` (views, pool, `PacketBatch`); `nstun-core` (sans-I/O, standard roaming, programmatic config, events); `nstun` driver with TUN + UDP; `nstun-tun` (Linux, macOS, Windows, fd adoption); `nstun-uapi`; dev CLI on the engine; delete `boringtun::device`. | core-vs-core tests with a fake clock (no runtime); driver tests with in-memory source/sink/transport; `just e2e` against kernel WireGuard; `just cross`, `just test-windows`; `data_path` bench must not regress |
| 2 | `Transport` with several transports per engine, `PathPolicy`, `PacketFilter` chain with `Handled`, injection, `force_handshake`, `suspend`/`resume`. | in-memory two-transport tests (relay-like path + direct path, roam/no-roam policies); e2e unchanged |
| 3 | `nstun-netstack`; `Splitter`; netstack-only e2e (no TUN) against kernel WireGuard: TCP echo and UDP echo through the stack. | new e2e script; throughput bench TUN vs netstack |
| 4 | `nstun-acl`: filter + connection API, fragment gate, flow tracker, policy tests ported. | ported ns policy tests; filter tests on synthetic packets |
| 5 | `nstun-nat`: stateless 4↔6 translation filter (`alias4 ↔ node6` embedding, `lan4 ↔ lan6`, incremental checksums), IPv6 fragmentation and ICMPv6 Packet Too Big handled once in the engine after translation, conntrack + DNAT/SNAT for service publishing; offload: Linux TUN virtio-net GSO/GRO, UDP GSO/GRO transport, optional crypto worker pool in the driver. | translation vectors; fragmentation tests shared by TUN and netstack; iperf in the e2e containers before/after; ns TUN-mode parity tests |
| 6 | ns migration (in ns, per the NS next-architecture plan phases C and D): both `tunnel-wg` and `quick-runtime` data planes move onto the engine; ns keeps `PeerSource`s, the merged peer table, registry and relay clients, names, ladder rules, presentation and features. | ns test suite, `just qa` |

Estimated size: Phase 1 about 4.5k lines (half moved), Phase 2 about 1.5k, Phase 3 about
2k (mostly moved from ns), Phase 4 about 3k (moved), Phase 5 about 2.5k.

### Crate-to-crate contract for Phase 1 (fixed before parallel work starts)

Workstreams build against these names so they can proceed in parallel; changing them is a
scope change that goes through L1.

- `nstun_packet::PacketBuf`: a `bytes::BytesMut` with `HEADROOM = 32` bytes in front of
  the IP packet (`DATA_HEADER_SZ` 16 + 16 spare for future transports); `as_packet()`,
  `as_packet_mut()`, `with_headroom_mut()` for the sealer, `len()`, `set_len()`,
  `from_packet(&[u8])`, `into_bytes()`/`freeze()` for channel hand-off.
  `PacketPool::get(capacity)` hands out `PacketBuf`s backed by reused `BytesMut`
  allocations (plain `BytesMut::with_capacity` plus reuse; a third-party object-pool crate
  only if the `data_path` bench shows the allocator is the bottleneck). `PacketBatch`:
  `smallvec` of `PacketBuf` (cap `MAX_BATCH = 64`). Dependencies for `nstun-packet`:
  `bytes`, `zerocopy`, `smallvec`; nothing copied from other projects.
- `nstun_packet` views: `Ipv4Header`, `Ipv6Header`, `UdpHeader`, `TcpHeader`,
  `IcmpHeader` as zerocopy `Ref`s; `IpPacket::parse(&[u8]) -> Result<IpPacket, Malformed>`
  with `src()`, `dst()`, `protocol()`, `five_tuple()`, `fragment()`; checksum helpers.
- The pure value types `PeerId`, `Path`, `TransportId`, `Ecn` live in `nstun-packet`
  (so the driver crate can depend on them without `nstun-core`) and are re-exported under
  the same names from `nstun_core` (decided at gate 1, 2026-10-02).
- `nstun_core::Core` with `Input`, `Output`, `Event`, `ConfigChange`, `MessageKind`,
  `Roam`, `Verdict`, and the traits `PathPolicy` and `PacketFilter` exactly as sketched
  above. `Core::new(CoreConfig)`,
  `handle_input`, `poll_output`, `poll_timeout`, `handle_timeout`.
- `nstun` driver traits `PacketSource`, `PacketSink`, `Transport` as sketched above, plus
  `EngineBuilder`, `Engine`, `EngineHandle`, `UdpTransport`, and in-memory
  `ChannelSource`/`ChannelSink`/`ChannelTransport` for tests.
- Workspace layout stays flat: `nstun-packet/`, `nstun-core/`, `nstun/`, `nstun-tun/`,
  `nstun-uapi/` next to `boringtun/` and `boringtun-cli/`; all members inherit
  `[workspace.lints]` and `[workspace.package]`.

### Phase 1 BKD campaign partition (L1/L2 workstreams)

| L2 | Workstream | Write scope | Depends on |
|---|---|---|---|
| P | `nstun-packet` | `nstun-packet/`, `Cargo.toml` members | - |
| C | `nstun-core` (sans-I/O engine, core-vs-core tests, moved `PeerTable`, `data_path`-style bench) | `nstun-core/`, `Cargo.toml` members | P merged |
| B | platform I/O: `nstun-tun` (Linux, macOS, Windows, fd adoption; ported from `boringtun/src/device/{tun_linux,tun_darwin,windows/tun}.rs`), `nstun` driver traits, `UdpTransport`, channel transports | `nstun-tun/`, `nstun/src/{io,transport,udp,channel}.rs`, `Cargo.toml` members | P merged |
| D | engine facade: `Engine`/`EngineBuilder`/`EngineHandle`, events, `nstun-uapi`, `boringtun-cli` on the engine, delete `boringtun/src/device`, e2e and justfile updates, docs | `nstun/src/{engine,builder,handle,events}.rs`, `nstun-uapi/`, `boringtun-cli/`, `boringtun/src/{lib.rs,device/**}`, `scripts/`, `justfile`, `README.md`, `CHANGELOG.md`, `docs/` | C and B merged |
| E | `nstun-e2e`: library-level end-to-end tests (two engines over channel transports and against kernel WireGuard), added by L1 during the campaign | `nstun-e2e/`, `Cargo.toml` members, `justfile` | D merged |

Merge order P → (C, B in parallel) → D → E. Phases 2-5 are later campaigns.

## Risks

- **Scope.** This is a rewrite of nstun's device layer plus re-homing three ns crates.
  Mitigation: phases land independently; nothing in ns changes before Phase 6.
- **ns is changing underneath** (uncommitted rename/refactor by another session). The
  interface inventory above may drift; Phase 6 re-reads ns before starting.
- **Two data planes in ns.** The engine is designed against `tunnel-wg`; `quick-runtime`'s
  sans-I/O design may not want an async engine at all. Decided after Phase 2, not assumed.
- **Semantics parity.** ns has many hard-won rules (lock release before awaits, bounded
  queues, fail-closed ACL, MSS/MTU coupling, roaming exceptions). Each is carried as a
  test when its code moves; the plan lists them per phase.
- **License.** gotatun is MPL-2.0 and tailscale is BSD-3-Clause; both are used for design
  only. nstun stays BSD-3-Clause.
- **Platforms.** Windows and iOS/Android paths cannot be run here; they get clippy, wine
  unit tests, and the fd-adoption path is exercised with a socketpair on Linux.
- **Performance.** An async engine with per-peer mutexes must match the current sync loop;
  the `data_path` bench and a TUN e2e throughput number (iperf in the e2e containers) are
  the gates.
- **API churn.** Traits are `pub` from Phase 1; ns depends on them in Phase 6. Phases 2-4
  may still change them; semver-breaking until ns migrates.

## Scope

nstun only: new crates `nstun-packet`, `nstun`, `nstun-tun`, `nstun-netstack`,
`nstun-acl`, `nstun-uapi`; `boringtun::device` retired; dev CLI rebuilt on the engine;
docs, ADRs (async engine replaces the sync device; ACL ported from ns), justfile and e2e
scripts extended. ns is read-only for this plan.

## Alternatives

1. **Keep ns's `tunnel-wg` as the engine and only extract pieces into nstun** (peer table,
   demux, timers). Smaller, but leaves two data planes and the TUN/netstack split in ns;
   does not meet "upper layer is pure business".
2. **Adopt gotatun's device as the engine.** Closest existing Rust design, but MPL-2.0 and
   its transport model is single-path UDP; ns's relay/WSS/ladder would still live outside.
3. **A `conn.Bind`-style single transport trait (magicsock) instead of `Transport` +
   `PathPolicy`.** Hides paths inside one object; simpler engine, but ns's ladder needs the
   engine to report which path authenticated and to ask before roaming, which the split
   design makes explicit. Chosen: the split.
4. **Async-first engine (tasks + per-peer mutexes) instead of a sans-I/O core.** Smaller
   first step and closer to today's `tunnel-wg`, but it keeps the lock-across-await hazard,
   needs mocks for every test, and cannot be embedded by `quick-runtime` or by a host that
   owns its own loop. The survey (firezone, `quick-runtime`) tipped this to sans-I/O.
5. **gVisor-like full netstack vs smoltcp.** smoltcp is already in ns, pure Rust, and the
   ns `VirtualDevice` driver works; staying with it.

## Annotations

- 2026-10-02: the project will be renamed **nsplane** (ADR `2026-10-02-rename-nsplane`);
  crate names in this plan (`nstun-*`, `boringtun`) are the Phase 1 contract names and
  stay until the campaign merges. Later phases use `nsplane-*`.
- 2026-10-02: aligned with the NS next-architecture page (docs site `ns/next`): one
  engine per node, 4↔6 translation and fragmentation/PTB belong to the engine (Phase 5),
  Phase 6 migrates both ns data planes. L1 added workstream E (library e2e). The campaign
  runs in auto mode since round ~20. Overview: `docs/design.md`.
- 2026-10-02: gate 1 confirmed (`proceed`): four L2s P/C/B/D, value types moved to
  `nstun-packet` with re-exports so C and B run in parallel.
- 2026-10-02: no code is copied from reference projects; use mature crates (`bytes`) for
  buffers instead of a vendored or hand-written pool.
- 2026-10-02: user confirmed `boringtun::device` is deleted after Phase 1 and that the
  work is split into phases; asked for a second architecture review against comparable
  GitHub projects. Review added above; the core became sans-I/O as a result.
- 2026-10-02: renamed to nsplane; crates live under crates/
- 2026-10-02: design input for Phase 5 (and follow-up #1 of task
  `20261002-1509-phase1-followups`) from Tailscale's "We're making Tailscale faster"
  (2026-09-22, https://tailscale.com/blog/making-tailscale-faster; design only):
  1. After a large GRO read, packets stay where they landed and are tracked by offset;
     many small packets share one allocation instead of each being copied into its own
     64 KiB buffer (~5% faster). For nsplane: on receive (UDP GRO -> decrypt -> TUN),
     split the read buffer into `Bytes`/`BytesMut` slices that share the allocation and
     decrypt in place (output only shrinks, no headroom needed); on send (TUN GSO ->
     encrypt -> UDP GSO), encrypt straight into the segment offsets of the UDP GSO send
     buffer, so the encryption write is the only copy. This interacts with the fixed
     `HEADROOM` of `PacketBuf` and with the O(1) front-adjust proposed in follow-up #1;
     design them together.
  2. Queue depths were reduced after measuring that most capacity went unused, lowering
     latency and memory. For nsplane: add high-water-mark counters to the engine's
     bounded queues (`queue_capacity`, transmit backlog, sink/source channels), measure
     under e2e/iperf, then set the defaults from data.
  3. `writev` hands several pieces of packet data to the kernel in one call without
     joining them first. For nsplane: write the virtio-net header and the packet to the
     TUN with `writev` instead of reserving headroom for the header or copying.
  4. Multi-queue processing for routers/exit nodes: lanes scaled to CPU cores, per-flow
     ordering kept. For nsplane: decide together with the optional crypto worker pool
     whether to shard `Core` by peer or hash flows to workers; the single owner task is
     the current limit.
- 2026-10-03: Phases 1-5 are complete in this repository (plans 20261002-1535, 20261002-1725,
  20261002-2240; main 64131c7). Phase 6 (ns migration of tunnel-wg and quick-runtime) and Phase 0
  (ns pins nsplane) happen in ns and are not started here.
