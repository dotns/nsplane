# nsplane Design Overview

The one-page view of where nsplane is going. `docs/architecture.md` describes what is on
`main` today; `docs/plan/` holds the approved plans with their investigation notes; this
page ties them together and is updated whenever a plan is approved or a phase lands.

Last updated: 2026-10-03 (Phases 1-5 and their follow-ups merged; Phase 6 is the ns migration).

**Naming.** The project was renamed **nsplane** on 2026-10-02 (ADR
`2026-10-02-rename-nsplane`): it is the node's underlying data plane, and TUN is only one of
its local attachments.

## 1. Purpose and position

nsplane is the WireGuard data plane of dotns. It is a Rust library that owns everything
between "an IP packet exists on this machine" and "an encrypted datagram leaves on some
path": packet I/O (TUN or an in-process network stack), the WireGuard engine, the
transports, the packet filters (ACL, NAT/translation, flow accounting) and the per-peer path
decisions' *mechanics*.

In the NS target architecture nsplane is layer 1 of four; the layers above it live in ns:

| Layer | Owner | Content |
|---|---|---|
| 4 Features | ns | service publishing, reverse proxy / public ingress, subnet routing, exit, local proxies, apps (`send`, third-party) |
| 3 Presentation | ns | how the overlay is shown to this host: TUN, userspace stack listeners, DNS, DNS-VIP, SOCKS5/HTTP/PAC |
| 2 Overlay core | ns | identity, identity-derived IPv6, registry client, `PeerSource`s (NSD, quick, app sessions) and the merged peer table, policy namespaces, names, path-ladder *rules* |
| 1 Engine | **nsplane** | WireGuard, transports, path policy mechanics, filter chain, netstack, TUN, ACL, 4↔6 translation |

One engine per node. Account mode, Quick mode and applications are peer *sources* and
presentation choices on top of the same engine; "mode" never appears inside nsplane. The
CLI (`nsplane-cli`) is a Linux/macOS development tool only.

**Application mode** (decided 2026-10-02 against the docs site's `ns/next`, `ns/apps` and
`ns/rendezvous`): nsplane provides the mechanics: engine peers that come and go with a
session, in-tunnel connections through `nsplane-netstack` and `Splitter`, ACL enforcement per
source namespace with cross-namespace default deny, directed grants, outbound rules for
restricted namespaces such as `app:*`, pinholes that close with their session, and the 4↔6
translation filter. ns keeps the `/quick/v2` rendezvous client, the `app:<session>` peer
source lifecycle, `kind` dispatch, third-party app access, the pairing and transfer state
machines and the relay client carriers. An app session reuses the existing tunnel to a peer
it already has (through a pinhole the peer's source namespace must permit for that app kind)
and only installs a session-scoped peer for an unpaired one.

## 2. Non-goals

- No control plane, pairing, identity, address allocation, registry or relay *client*
  protocol: nsplane carries datagrams on paths it is told about and reports which path
  authenticated; ns decides what a path means.
- No copying or vendoring of code from reference projects (firezone, gotatun, tailscale,
  NepTUN, ...), whatever their license. Design only. Mature crates are used for building
  blocks (`bytes`, `smallvec`, `zerocopy`, `smoltcp`, `aws-lc-rs`).
- No `wg`-daemon product: UAPI exists for the dev tool and `wg show`.
- No DAITA, pcap, or alternative allocators.

## 3. Principles

1. **Sans-I/O core.** `nsplane-core` is a state machine: inputs in, outputs out, no sockets,
   no clock of its own. A driver owns it. Tests run two cores against each other with a
   fake clock; embedders (tokio driver, mobile hosts, ns's sans-I/O `quick-runtime`) drive
   it from their own loop.
2. **The engine never changes a path by itself.** `PathPolicy` answers "which path for
   this message" and "an authenticated message arrived on this path: adopt it?". The
   built-in `StandardRoaming` is plain WireGuard roaming; ns plugs in its ladder.
3. **Transports are first class.** Several `Transport`s per engine (UDP, relay, WSS
   carrier, candidates); a `Path` names the transport and address, carries ECN. No fake
   addresses to hide relayed peers.
4. **Filters, not special cases.** Everything between decrypt and deliver, or between
   local read and seal, is a `PacketFilter` returning `Accept`, `Drop`, or `Handled`:
   ACL, NAT, 4↔6 translation, flow gates, probe responders, flow accounting.
5. **Zero copy and bounded queues.** `PacketBuf` (a `BytesMut` with 32 bytes of headroom)
   is sealed and opened in place; batches are `smallvec`s; every channel is bounded, drops
   are counted, a full network queue holds back the local source.
6. **pma-rust baseline.** Edition 2024, MSRV 1.95, workspace lints deny warnings, no
   `unwrap`/`expect`/`panic` in runtime code, `unsafe` confined to platform/FFI modules
   with `SAFETY` comments, no CI: `just check`, `just cross`, `just test-windows`,
   `just e2e` are the gates (ADRs in `docs/decisions/`).

## 4. Crates

```
nsplane-noise    noise core (Tunn, in-place seal/open, RateLimiter, zerocopy wire views), x25519
nsplane-packet   IP/TCP/UDP/ICMP header views, five-tuple, fragments, checksums,
                 PacketBuf/PacketPool/PacketBatch, PeerId/Path/TransportId/Ecn
nsplane-core     sans-I/O engine: Core (single and batched input, deferred crypto jobs),
                 PeerTable, timers, PathPolicy, onion-ordered PacketFilter chain, injection,
                 events
nsplane          tokio driver: PacketSource/PacketSink/Transport traits (batched),
                 UdpTransport (GSO/GRO), channel transports, Splitter/MergeSource,
                 fragmentation stage, crypto worker pool, Engine/EngineBuilder/EngineHandle,
                 events, drop/queue/fragment/transport counters and status
nsplane-tun      TUN backends: Linux/Android (virtio-net offload), macOS/iOS utun, Windows
                 Wintun, fd/handle adoption
nsplane-uapi     `wg` UAPI over the engine (Unix socket / named pipe)
nsplane-netstack smoltcp (dotns/smoltcp fork) stack as PacketSink + PacketSource; TCP
                 connections, UDP flows, dialers
nsplane-acl      ACL engine and AclFilter: namespaces, grants, outbound rules, pinholes,
                 per-flow hook with bypass and verdict cache; fragment gate; FlowTracker
nsplane-nat      4↔6 translation filter (RFC 7915), conntrack, DNAT/SNAT port map
nsplane-cli      Linux/macOS dev tool on the engine
nsplane-e2e      library-level end-to-end tests (not published)
examples         nsplane-examples: runnable examples, single-port relay (not published)
```

Dependency direction is strictly downward: `nsplane-cli` → `nsplane-uapi` → `nsplane` →
`nsplane-core` → `nsplane-packet`; `nsplane-tun`/`nsplane-netstack`/`nsplane-acl`/
`nsplane-nat` → `nsplane-core` / `nsplane` (+ `nsplane-packet`). `nsplane-core` is the only
crate that depends on `nsplane-noise`. All of the feature crates are optional: a basic client
links `nsplane` and `nsplane-tun` only, and a feature that is not installed is not on the
data path (`docs/architecture.md`, *Optional features and defaults*). The public interfaces
of every crate are listed in `docs/architecture.md`, *Public interfaces*.

## 5. The engine

### Core (sans-I/O)

```
Input::Datagram { path, data }   ─┐                 ┌─▶ Output::Transmit { path, data }
Input::Local    { packet }        ├─▶ Core::handle_input(now) ─▶ poll_output ─┼─▶ Output::Deliver  { from, packet }
Input::Config   (ConfigChange)   ─┘                 └─▶ Output::Event (handshake, authenticated,
                                                         path adopted, session expired, stats, drops)
Core::poll_timeout / handle_timeout(now)      250 ms-class timers: rekey, keepalive,
                                              expiry, rate-limiter reset
Core::inject_inbound / inject_outbound / force_handshake / peer_stats / recycle
```

- Receive demux by session index; handshake initiations resolve the peer by decrypting
  the static key (`parse_handshake_anon`), so peers sharing a relay endpoint need no
  endpoint matching.
- Inbound order: open in place → allowed-IP source check (global longest match must be
  the sending peer) → filter chain (inbound) → `Deliver`. Outbound order: filter chain
  (outbound) → route by destination → seal in place → `Transmit` on the policy's path.
- Peers: `PeerTable` by key / session index / allowed IP; runtime updates of PSK,
  keepalive, allowed IPs and paths without rebuilding sessions.

### Driver (tokio)

One task owns the core and loops: poll sources and transports, feed inputs, drain
outputs to transports and sinks, sleep until `poll_timeout`. Each `PacketSource` and
`Transport` runs its own task and feeds a bounded channel of `PacketBatch`. There are no
locks on the hot path; `EngineHandle` calls are messages to the owner task.

```rust
// Simplified; every method of the I/O traits has a batch form with a default
// (`recv_batch`, `send_batch`), and `Transport::send_batch` reports failed datagrams.
trait PacketSource { async fn recv(&mut self) -> io::Result<PacketBuf>; fn mtu(&self) -> watch::Receiver<u16>; }
trait PacketSink   { async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()>; }
trait Transport    { async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)>;
                     async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()>; }
trait PathPolicy   { fn select(&self, peer, kind) -> Option<Path>; fn on_authenticated(&self, peer, from, kind) -> Roam; }
trait PacketFilter { fn inbound(&self, peer, &mut PacketBuf) -> Verdict; fn outbound(&self, peer, &mut PacketBuf) -> Verdict; }
```

`EngineBuilder` takes the source and sink, any number of transports (`DynTransport` for
runtime choice), a `PathPolicy` (`StandardRoaming` by default), filters, an optional
fragmentation stage and crypto worker pool; in-memory `Channel*` implementations serve
tests and embedders. The owner task feeds the core what is already queued as one batch
(never waiting to fill one), reads local packets only up to the transmit room, and keeps a
per-transport backlog so a stalled transport never holds back the others.
`EngineHandle::status` and `transport_stats` report the engine's state and per-transport
traffic in one call; rates and metric export are left to the caller.

### Presentation × transport

| Local side (PacketSink/Source) \ Transport | UDP | relay UDP | relay WSS |
|---|:-:|:-:|:-:|
| TUN (kernel stack) | ✓ | ✓ | ✓ |
| `nsplane-netstack` (no TUN, no root) | ✓ | ✓ | ✓ |
| host bridge (iOS/Android fd, channels) | ✓ | ✓ | ✓ |

Transports beyond UDP are ns implementations of `Transport`; the matrix is a property
of the design, not of individual features.

## 6. Packets, translation, MTU

- `nsplane-packet` views are `zerocopy` refs; parsing never copies. Checksums are
  incremental where a filter rewrites addresses.
- The 4↔6 translation the NS architecture requires (`alias4 ↔ node6` embedding for peers,
  `lan4 ↔ lan6` for published LANs) is a stateless `PacketFilter` in `nsplane-nat`, applied
  before encryption and after decryption, shared by TUN and netstack. Remote nodes only
  see IPv6.
- Fragmentation and Packet Too Big are handled once in the engine, by an optional stage on
  the local path before the core (the core encrypts right after its outbound filters):
  IPv6 above the MTU gets an ICMPv6 Packet Too Big, IPv4 above its ceiling gets a
  Fragmentation Needed (DF) or is split into IPv4 fragments that the translator turns into
  IPv6 fragments (RFC 7915 5.1.1); destinations translated to IPv6 get a 20-byte lower
  ceiling. TUN and netstack share the same MTU/MSS limits (`nsplane-netstack` derives its
  advertised MSS from the engine MTU).
- The filter chain is onion-ordered (installed from the wire side to the local side);
  the recommended stack is `[AclFilter, PortMap, Translator]`, so the ACL sees overlay IPv6
  in both directions.

## 7. Performance

Measured numbers and their analysis are in `docs/architecture.md`, *Performance*. In short:

- In-place seal/open, no per-packet allocation (`PacketPool`), handshake-init demux without
  endpoint scans, zero-copy GRO slices.
- `data_path` (64 B round trip): core 533 ns per packet one at a time (device-equivalent
  471 ns, +12 %), 411-416 ns per packet in batches of 32 (below the device-equivalent; the
  10 % target is met for batched input, which the engine uses whenever packets queue up).
- Offload: Linux/Android TUN virtio-net TSO/USO and UDP GSO/GRO, on by default with
  fallback; nothing waits to fill a batch.
- Optional crypto worker pool (2 or more workers, sharded by peer): up to about 1.4x on
  full-size packets; without it the data path takes no lock.
- ACL hook: bypass peer ~38 ns, established flow ~51-55 ns, unchanged verdicts.

Open: sender pacing / receiver-side sink backpressure (follow-up #21).

## 8. Security and protocol baseline

Carried from the fork baseline (plan `20261001-1859`): cookies cover IP and port;
per-source handshake rate limiting with a device-wide backstop; `Reject-After-Messages`
enforced on both directions and rekey at `Rekey-After-Messages`; 16-byte padding; 8192
anti-replay window; cookie replies never roam; source allowed-IP check by global longest
match; malformed keys rejected; keepalive/handshake timers measured from the first
unanswered packet; jittered handshake retries. Debug output redacts key material.

## 9. Roadmap and status

| Phase | Deliverable | Status (2026-10-04) |
|---|---|---|
| Baseline | aws-lc-rs backend, pma-rust lints, protocol fixes, zero-copy noise, Windows device, CLI as dev tool | done (`1fb9899`) |
| 1 | `nsplane-packet`, `nsplane-core`, `nsplane` driver, `nsplane-tun`, `nsplane-uapi`, `nsplane-e2e`, CLI on the engine, upstream `device` layer deleted | done (`1660fc2`, `8c6ad9f`, `2827a4a`, `17eb69d`, `f712711`) |
| 1b | Rename to nsplane, `crates/` layout, cleanup | done (`5578a90`) |
| 2 | multi-transport, `PathPolicy`, filter chain with `Handled`, injection, `force_handshake`, suspend/resume, engine-driven timers | done (`ce54d62`, `d3d4f50`) |
| 3+4 | per-transport backpressure, `nsplane-netstack`, `Splitter` / `MergeSource`, `nsplane-acl`, examples and the presentation × transport matrix, ACL namespaces / grants / outbound rules / pinholes | done (`7e7139c`, `0e10b0d`, `688e585`, `3a5f74c`, `c35429e`) |
| 5 | `nsplane-nat` (translation, conntrack, port map), fragmentation stage, onion filter order, TUN and UDP offload, ACL flow hook, queue high-water marks, crypto worker pool | done (`a2c0635`, `33445e0`, `f46427f`, `e60072b`, `02ff770`, `64131c7`) |
| 5 follow-ups | batched core entry, no lock without workers, exact send errors, worker/fragment stats, smoltcp fork | done (`8f01a55`, `5132f27`, `91c4943`) |
| Status | per-transport traffic counters, `EngineHandle::status` | done (task `20261003-1215-traffic-status`) |
| ns M4 hooks | `inject_outbound_on`, `PacketFilter::inbound_from`, `PathPolicy::observe_every_message`, netstack accept backpressure, `connect_tcp_from`, random ephemeral start | done (task `20261003-1300-ns-m4-requests`) |
| ns data-plane moves | `owns()`, reassembly, send progress, oversize UDP (netstack); UDP side channel, `LinkTransport`; `Nat64Lan`, `Redirect` (nsplane-nat); `force_handshake_on` | done (plan `20261003-1600-ns-dataplane-moves`) |
| Throughput and WSS | benchmark harness against kernel WireGuard and wireguard-go; engine fast path (batched handoff, inline output); netstack fixes and TCP buffers; `nsplane-wss` (datagram carrier, WsFrame stream client and server) | done (plan `20261003-1630-perf-and-wss`) |
| ACL and node L3 gate | per-source identities (now `LabelSet`s), fragment modes, bypass flags, `Ipv6Mode`, a stateless option preset (removed; its field values are in `docs/specs/acl-policy-document.md`), inbound destinations; the node L3 gate with divert (replaced by the generic flow gate `gate::FlowGate`, plan `20261007-0900-business-agnostic`; product mapping in `docs/specs/node-l3.md`); differential fixtures against ns (now `docs/specs/data/`) | done (plan `20261003-2300-acl-l3-gate`) |
| Local side | `MapSink` / `MapSource`, `pump`, `pipe`; `Masquerade`, `echo_reply_in_place`; `TunSlot`, `host_tun` | done (plan `20261003-2330-local-side`) |
| Release 0.8.0 | first nsplane release (tag `v0.8.0`) | 2026-10-04 |
| ns requests | per-path MTU and Linux path MTU discovery, padding cap, UDP builder, `send_to_async`, redirect tries, native alias; netstack abort, fragment discard, connected UDP; `nsplane-wss` plain ws, events, keepalive, timeouts; ACL source scope | done (plan `20261004-1100-ns-requests`) |
| Release 0.9.0 | the remaining ns requests (tag `v0.9.0`) | 2026-10-04 |
| Optimization | engine fast path and parallel per-peer crypto, UDP batching, TUN buffers; netstack smoltcp fork round; hygiene follow-ups | done (plan `20261004-1730-optimization`) |
| Release 0.10.0 | the optimization round (tag `v0.10.0`) | 2026-10-05 |
| 6 | ns migration: both `tunnel-wg` and `quick-runtime` data planes move onto the engine (in ns, per the NS next-architecture plan) | in ns: account mode on the engine (M4) in progress, Quick (M5) later |

Open items in this repository (`docs/task/20261002-1509-phase1-followups.md`): #5 Windows
real-host verification, #19 sending the smoltcp fixes upstream (the user's call), #21 sender
pacing / sink backpressure. Performance follow-ups: multi-stream throughput against
wireguard-go (10.1 against 8.9 Gbit/s on 4 streams), the netstack pair's 4-stream result,
sealing/pool allocation, the TSO split copy, TUN write coalescing, a smoltcp-fork round
(checksum over u64 words, SACK or partial-ACK retransmit). ns requests for Quick on the
engine (MQ-1..5) wait for M5. Phase 0 (ns pins nsplane's `noise` with the `SocketAddr` source
change) runs in ns when its current refactor lands.

## 10. Decisions

| Date | Decision | Where |
|---|---|---|
| 2026-10-01 | Fork baseline: `ring` → `aws-lc-rs`; no CI, local gates; `unsafe` only in platform/FFI modules; Wintun C library accepted | `docs/decisions/2026-10-01-*.md` |
| 2026-10-02 | CLI is a Linux/macOS dev tool; Windows `device` kept until the engine replaces it | task `20261002-1008-cli-dev-tool` |
| 2026-10-02 | Complete data plane with a sans-I/O core; `Transport` and `PathPolicy` split; smoltcp over `ipstack`; the upstream `device` layer deleted after Phase 1 | plan `20261002-1024-data-plane-core` |
| 2026-10-02 | No code copied from reference projects; buffers on `bytes` | same plan, annotations |
| 2026-10-02 | Value types (`PeerId`, `Path`, `TransportId`, `Ecn`) live in `nsplane-packet`, re-exported by `nsplane-core` | same plan, gate 1 |
| 2026-10-02 | One nsplane engine per NS node; 4↔6 translation and fragmentation live in the engine; both ns data planes migrate | NS next-architecture page (docs site, `ns/next`) |
| 2026-10-02 | Rename to **nsplane** (`nsplane-noise`, `nsplane-core`, `nsplane`, `nsplane-tun`, ...); executed after Phase 1 merges | ADR `2026-10-02-rename-nsplane` |
| 2026-10-02 | Examples package with real WebSocket over TLS; single-port relay in WireGuard's undefined message-type range, plain WireGuard peers keep working (Proposed wire contract with ns / nsgw) | ADR `2026-10-02-single-port-relay`, plan `20261002-1725` |
| 2026-10-02 | Application mode split: nsplane provides peers, in-tunnel connections, ACL namespaces, grants, outbound rules and pinholes; ns keeps rendezvous, `kind` dispatch and app state machines; app traffic to an existing peer only through a pinhole permitted by its source namespace, closed with the session | plan `20261002-1725`, annotations |
| 2026-10-02 | ACL as a per-flow hook: zero cost when not installed, per-peer bypass, verdict cache keyed by generation | plan `20261002-1725`, annotations |
| 2026-10-02 | Every optional feature (translation, port map, ACL, fragmentation, worker pool, netstack) is opt-in and off the data path when not installed; offload is on with fallback | plan `20261002-2240` |
| 2026-10-03 | Batched core entry and drain-only engine batching (no wait, no timer; local intake bounded by the transmit room); sink-full loss under saturation accepted, pacing is follow-up #21 | plan `20261003-0715` |
| 2026-10-03 | nsplane-netstack depends on the `dotns/smoltcp` fork pinned to a tag; workarounds removed | ADR `2026-10-03-smoltcp-fork` |
| 2026-10-03 | Status and traffic: nsplane reports counters (`status`, `transport_stats`); rates, metric export and direct/relay labels live in ns | task `20261003-1215-traffic-status` |
| 2026-10-03 | Every data-channel protocol (transports and stream carriers) is implemented in nsplane; ns supplies configuration and business decisions only; heavy protocol dependencies live in optional crates (`nsplane-wss`) | ADR `2026-10-03-data-channel-protocols-in-nsplane` |

## 11. References (design only)

firezone connlib (sans-I/O node, io driver, ip-packet, offload), tailscale `tstun`/
`wgengine` (filter hooks, injection, header room), mullvad/gotatun (I/O traits, builder),
NordSecurity/NepTUN (crypto workers), wireguard-go `conn.Bind` and netbird `ICEBind` (the
single-transport alternative and its cost), EasyTier (multi-transport mesh), tun2proxy/
ipstack and netstack-smoltcp (userspace stacks). See the survey in the data-plane plan.
