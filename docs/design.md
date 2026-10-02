# nstun Design Overview

The one-page view of where nstun is going. `docs/architecture.md` describes what is on
`main` today; `docs/plan/` holds the approved plans with their investigation notes; this
page ties them together and is updated whenever a plan is approved or a phase lands.

Last updated: 2026-10-02 (Phase 1 of the data-plane plan in progress).

**Naming.** The project is being renamed **nsplane** (ADR `2026-10-02-rename-nsplane`):
it is the node's underlying data plane, and TUN is only one of its local attachments. The
rename of the repository, crates (`nstun-*` → `nsplane-*`, `boringtun` → `nsplane-noise`)
and docs happens as its own task after Phase 1 merges; this page still uses the names on
`main` today.

## 1. Purpose and position

nstun is the WireGuard data plane of dotns. It is a Rust library (a fork of
cloudflare/boringtun, BSD-3-Clause) that owns everything between "an IP packet exists on
this machine" and "an encrypted datagram leaves on some path": packet I/O (TUN or an
in-process network stack), the WireGuard engine, the transports, the packet filters (ACL,
NAT/translation, flow accounting) and the per-peer path decisions' *mechanics*.

In the NS target architecture nstun is layer 1 of four; the layers above it live in ns:

| Layer | Owner | Content |
|---|---|---|
| 4 Features | ns | service publishing, reverse proxy / public ingress, subnet routing, exit, local proxies, apps (`send`, third-party) |
| 3 Presentation | ns | how the overlay is shown to this host: TUN, userspace stack listeners, DNS, DNS-VIP, SOCKS5/HTTP/PAC |
| 2 Overlay core | ns | identity, identity-derived IPv6, registry client, `PeerSource`s (NSD, quick, app sessions) and the merged peer table, policy namespaces, names, path-ladder *rules* |
| 1 Engine | **nstun** | WireGuard, transports, path policy mechanics, filter chain, netstack, TUN, ACL, 4↔6 translation |

One engine per node. Account mode, Quick mode and applications are peer *sources* and
presentation choices on top of the same engine; "mode" never appears inside nstun. The
CLI (`boringtun-cli`) is a Linux/macOS development tool only.

## 2. Non-goals

- No control plane, pairing, identity, address allocation, registry or relay *client*
  protocol: nstun carries datagrams on paths it is told about and reports which path
  authenticated; ns decides what a path means.
- No copying or vendoring of code from reference projects (firezone, gotatun, tailscale,
  NepTUN, ...), whatever their license. Design only. Mature crates are used for building
  blocks (`bytes`, `smallvec`, `zerocopy`, `smoltcp`, `aws-lc-rs`).
- No `wg`-daemon product: UAPI exists for the dev tool and `wg show`.
- No DAITA, pcap, or alternative allocators.

## 3. Principles

1. **Sans-I/O core.** `nstun-core` is a state machine: inputs in, outputs out, no sockets,
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
   ACL, NAT, 4↔6 translation, node-L3 gates, probe responders, flow accounting.
5. **Zero copy and bounded queues.** `PacketBuf` (a `BytesMut` with 32 bytes of headroom)
   is sealed and opened in place; batches are `smallvec`s; every channel is bounded, drops
   are counted, a full network queue holds back the local source.
6. **pma-rust baseline.** Edition 2024, MSRV 1.95, workspace lints deny warnings, no
   `unwrap`/`expect`/`panic` in runtime code, `unsafe` confined to platform/FFI modules
   with `SAFETY` comments, no CI: `just check`, `just cross`, `just test-windows`,
   `just e2e` are the gates (ADRs in `docs/decisions/`).

## 4. Crates

```
boringtun        noise core (Tunn, in-place seal/open, RateLimiter, zerocopy wire views),
                 x25519, ffi, jni            [exists; `device` deleted at end of Phase 1]
nstun-packet     IP/TCP/UDP/ICMP header views, five-tuple, fragments, checksums,
                 PacketBuf/PacketPool/PacketBatch, PeerId/Path/TransportId/Ecn    [merged]
nstun-core       sans-I/O engine: Core, PeerTable, timers, PathPolicy, PacketFilter,
                 injection, events                                          [in progress]
nstun            tokio driver: PacketSource/PacketSink/Transport traits, UdpTransport,
                 channel transports, Engine/EngineBuilder/EngineHandle, events  [in progress]
nstun-tun        TUN backends: Linux, macOS utun, Windows Wintun, fd/handle adoption
                 (iOS, Android)                                             [in progress]
nstun-uapi       `wg` UAPI over the engine (Unix socket / named pipe)           [planned]
nstun-e2e        library-level end-to-end tests (two engines, kernel WireGuard)  [planned]
nstun-netstack   smoltcp stack as PacketSink + PacketSource; TCP connections, UDP flows,
                 dialers; Splitter for hybrid TUN + netstack                [Phase 3]
nstun-acl        policy engine as PacketFilter and connection-level check; fragment gate;
                 flow tracker                                               [Phase 4]
nstun-nat        4↔6 translation filter, conntrack, DNAT/SNAT for service publishing
                 (optional)                                                 [Phase 5]
boringtun-cli    Linux/macOS dev tool on the engine                         [exists]
```

Dependency direction is strictly downward: `boringtun-cli` → `nstun-uapi` → `nstun` →
`nstun-core` → `nstun-packet`; `nstun-tun`/`nstun-netstack`/`nstun-acl`/`nstun-nat` →
`nstun` (+ `nstun-packet`). `nstun-core` is the only crate that depends on `boringtun`.

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
trait PacketSource { async fn recv(&mut self) -> io::Result<PacketBuf>; fn mtu(&self) -> watch::Receiver<u16>; }
trait PacketSink   { async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()>; }
trait Transport    { async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)>;
                     async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()>; }
trait PathPolicy   { fn select(&self, peer, kind) -> Option<Path>; fn on_authenticated(&self, peer, from, kind) -> Roam; }
trait PacketFilter { fn inbound(&self, peer, &mut PacketBuf) -> Verdict; fn outbound(&self, peer, &mut PacketBuf) -> Verdict; }
```

`EngineBuilder` is generic over source/sink/transport with defaults (`UdpTransport`,
`StandardRoaming`, TUN from `nstun-tun`); in-memory `Channel*` implementations serve
tests and embedders.

### Presentation × transport

| Local side (PacketSink/Source) \ Transport | UDP | relay UDP | relay WSS |
|---|:-:|:-:|:-:|
| TUN (kernel stack) | ✓ | ✓ | ✓ |
| `nstun-netstack` (no TUN, no root) | ✓ | ✓ | ✓ |
| host bridge (iOS/Android fd, channels) | ✓ | ✓ | ✓ |

Transports beyond UDP are ns implementations of `Transport`; the matrix is a property
of the design, not of individual features.

## 6. Packets, translation, MTU

- `nstun-packet` views are `zerocopy` refs; parsing never copies. Checksums are
  incremental where a filter rewrites addresses.
- The 4↔6 translation the NS architecture requires (`alias4 ↔ node6` embedding for peers,
  `lan4 ↔ lan6` for published LANs) is a stateless `PacketFilter` in `nstun-nat`, applied
  before encryption and after decryption, shared by TUN and netstack. Remote nodes only
  see IPv6.
- IPv6 fragmentation and ICMPv6 Packet Too Big are handled once in the engine after
  translation; TUN and netstack share the same MTU/MSS limits (`nstun-netstack` derives
  its advertised MSS from the engine MTU).

## 7. Performance plan

- Already: in-place seal/open, no per-packet allocation on the data path
  (`PacketPool`), handshake-init demux without endpoint scans.
- Phase 1 gate: the core must stay within 10 % of a `Tunn`-plus-routing baseline on
  64 B and 1420 B packets (`nstun-core` bench vs `boringtun/benches/data_path`).
- Phase 5: Linux TUN virtio-net GSO/GRO, UDP GSO/GRO (`quinn-udp`), optional crypto worker
  pool in the driver; measured with iperf in the e2e containers before and after.

## 8. Security and protocol baseline

Carried from the fork baseline (plan `20261001-1859`): cookies cover IP and port;
per-source handshake rate limiting with a device-wide backstop; `Reject-After-Messages`
enforced on both directions and rekey at `Rekey-After-Messages`; 16-byte padding; 8192
anti-replay window; cookie replies never roam; source allowed-IP check by global longest
match; malformed keys rejected; keepalive/handshake timers measured from the first
unanswered packet; jittered handshake retries. Debug output redacts key material.

## 9. Roadmap and status

| Phase | Deliverable | Status (2026-10-02) |
|---|---|---|
| Baseline | aws-lc-rs backend, pma-rust lints, protocol fixes, zero-copy noise, Windows device, CLI as dev tool | done, pushed (`1fb9899`) |
| 1 | `nstun-packet`, `nstun-core`, `nstun` driver, `nstun-tun`, `nstun-uapi`, `nstun-e2e`, CLI on the engine, delete `boringtun::device` | BKD campaign `nstun-dp-p1`: P, C and B merged; D and E in progress |
| 1b | Rename to nsplane (repo, crates, docs section) | after Phase 1, own task (ADR `2026-10-02-rename-nsplane`) |
| 2 | multi-transport, `PathPolicy`, filter chain with `Handled`, injection, `force_handshake`, suspend/resume | planned |
| 3 | `nstun-netstack`, `Splitter`, netstack-only e2e | planned |
| 4 | `nstun-acl` (policy filter, connection check, fragment gate, flow tracker) | planned |
| 5 | 4↔6 translation filter, fragmentation/PTB, offload (TUN virtio-net, UDP GSO/GRO), crypto workers, conntrack/DNAT | planned |
| 6 | ns migration: both `tunnel-wg` and `quick-runtime` data planes move onto the engine (in ns, per the NS next-architecture plan, its phases C and D) | after 1-5 |

Phase 0 (ns pins nstun's `noise` with the `SocketAddr` source change) is independent and
runs in ns when its current refactor lands.

## 10. Decisions

| Date | Decision | Where |
|---|---|---|
| 2026-10-01 | Fork baseline: `ring` → `aws-lc-rs`; no CI, local gates; `unsafe` only in platform/FFI modules; Wintun C library accepted | `docs/decisions/2026-10-01-*.md` |
| 2026-10-02 | CLI is a Linux/macOS dev tool; Windows `device` kept until the engine replaces it | task `20261002-1008-cli-dev-tool` |
| 2026-10-02 | Complete data plane with a sans-I/O core; `Transport` and `PathPolicy` split; smoltcp over `ipstack`; `boringtun::device` deleted after Phase 1 | plan `20261002-1024-data-plane-core` |
| 2026-10-02 | No code copied from reference projects; buffers on `bytes` | same plan, annotations |
| 2026-10-02 | Value types (`PeerId`, `Path`, `TransportId`, `Ecn`) live in `nstun-packet`, re-exported by `nstun-core` | same plan, gate 1 |
| 2026-10-02 | One nstun engine per NS node; 4↔6 translation and fragmentation live in the engine; both ns data planes migrate | NS next-architecture page (docs site, `ns/next`) |
| 2026-10-02 | Rename to **nsplane** (`nsplane-noise`, `nsplane-core`, `nsplane`, `nsplane-tun`, ...); executed after Phase 1 merges | ADR `2026-10-02-rename-nsplane` |

## 11. References (design only)

firezone connlib (sans-I/O node, io driver, ip-packet, offload), tailscale `tstun`/
`wgengine` (filter hooks, injection, header room), mullvad/gotatun (I/O traits, builder),
NordSecurity/NepTUN (crypto workers), wireguard-go `conn.Bind` and netbird `ICEBind` (the
single-transport alternative and its cost), EasyTier (multi-transport mesh), tun2proxy/
ipstack and netstack-smoltcp (userspace stacks). See the survey in the data-plane plan.
