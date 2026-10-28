# nsplane architecture

What nsplane is for, how its crates fit together and how a packet moves through them. The
behavior of each component is in its [reference](reference/) document, measured numbers are in
[performance.md](performance.md), and embedding is explained in the [usage guide](guide.md).

## Scope

nsplane is a business-agnostic WireGuard data plane, written as Rust libraries. It owns
everything between "an IP packet exists on this machine" and "an encrypted datagram leaves on
some path": packet I/O (a TUN device, an in-process network stack or host-provided
callbacks), the WireGuard engine, the transports, the packet filters (access control,
address translation and NAT, flow accounting) and the mechanics of per-peer path decisions.

Products built on nsplane compile their own models (identities, groups, services, policies)
into generic inputs: flow rules, opaque labels, address tables and narrow trait callbacks. No
product concept is part of nsplane's API (ADR
[2026-10-06-business-agnostic-scope](decisions/2026-10-06-business-agnostic-scope.md)); the
mappings of a product onto the generic APIs are in [specs](specs/).

One engine serves a node. Peer sources, rendezvous, pairing and session state machines live in
the embedding application, which adds and removes peers and policies through the engine
handle and the filter APIs.

### Non-goals

- No control plane: no pairing, identity, address allocation, registry or relay client
  protocol. nsplane carries datagrams on the paths it is told about and reports which path
  authenticated; the application decides what a path means.
- No code copied or vendored from reference projects, whatever their license. Mature crates
  provide building blocks (`bytes`, `smallvec`, `zerocopy`, `smoltcp`, `aws-lc-rs`).
- No `wg` daemon product: the UAPI exists for the development CLI and `wg show`.
- No DAITA, pcap or alternative allocators.

## Principles

1. **Sans-I/O core.** `nsplane-core` is a state machine: inputs in, outputs out, no packet
   I/O, and timers scheduled from caller-supplied time. Its Noise dependency still reads
   clocks for timestamps, cookie rotation and RTT measurements. A driver owns it; tests run
   two cores against each other with simulated timer time, and embedders may drive it from
   their own loop.
2. **The engine never changes a path by itself.** `PathPolicy` answers "which path for this
   message" and "an authenticated message arrived on this path: adopt it?". The built-in
   `StandardRoaming` is plain WireGuard roaming.
3. **Transports are first class.** An engine has any number of `Transport`s (UDP, message
   links, WebSocket over TLS); a `Path` names the transport and the address and carries ECN.
4. **Filters, not special cases.** Everything between decrypt and deliver, and between local
   read and seal, is a `PacketFilter` returning `Accept`, `Drop` or `Handled`: access
   control, NAT, translation, flow gates, flow accounting.
5. **Zero copy and bounded queues.** `PacketBuf` is sealed and opened in place; batches are
   `smallvec`s; every channel is bounded, drops are counted, and a full network queue holds
   back the local source.
6. **Optional features cost nothing when unused.** A basic client is an `EngineBuilder` on a
   TUN device and a `UdpTransport` with peers and no filters; a feature that is not installed
   is not on the data path. Each reference document lists its features with their defaults
   and their cost when off, under *Configuration and defaults*.
7. **Baseline.** Edition 2024, MSRV 1.95, workspace lints deny warnings, no
   `unwrap` / `expect` / `panic` in runtime code, `unsafe` confined to platform and FFI
   modules with `SAFETY` comments. There is no CI: `just check`, `just cross`,
   `just test-windows` and `just e2e` are the gates (ADR
   [2026-10-01-no-ci](decisions/2026-10-01-no-ci.md)).

## Crates

| Crate | Path | Role | Reference |
|---|---|---|---|
| `nsplane-noise` | `crates/nsplane-noise/` | The Noise protocol state machine (`noise`); no I/O | [nsplane-noise](reference/nsplane-noise.md) |
| `nsplane-packet` | `crates/nsplane-packet/` | Packet buffers (`PacketBuf`, `PacketPool`, `SharedPacketPool`, `PacketBatch`), IP header views, reassembly, checksums, a keyed hasher, shared value types (`PeerId`, `TransportId`, `Path`, `Ecn`) | [nsplane-packet](reference/nsplane-packet.md) |
| `nsplane-core` | `crates/nsplane-core/` | Sans-I/O engine core: peers, cryptokey routing, timers, path policy, packet filters, local identities | [nsplane-core](reference/nsplane-core.md) |
| `nsplane` | `crates/nsplane/` | Tokio driver: `Engine`, `EngineBuilder`, `EngineHandle`, events, the I/O traits, `UdpTransport`, `LinkTransport`, the fragmentation stage, the crypto worker pool, the local-side graph | [nsplane](reference/nsplane.md) |
| `nsplane-acl` | `crates/nsplane-acl/` | Label-based accept-only flow ACL (`AclEngine`), the stateful flow gate (`gate::FlowGate`), and the `AclFilter`, `GateFilter` and `FlowTracker` packet filters | [nsplane-acl](reference/nsplane-acl.md) |
| `nsplane-nat` | `crates/nsplane-nat/` | IPv4/IPv6 translation (`Translator`, `TranslationTable`), service-publishing DNAT/SNAT (`PortMap`, `Conntrack`), NAT64 to a LAN (`Nat64Lan`), `Redirect`, `Masquerade` | [nsplane-nat](reference/nsplane-nat.md) |
| `nsplane-wss` | `crates/nsplane-wss/` | WebSocket-over-TLS carriers: `WssDialer` for `LinkTransport` and its server side, `WssServerTransport` | [nsplane-wss](reference/nsplane-wss.md) |
| `nsplane-tun` | `crates/nsplane-tun/` | OS TUN devices and host-managed devices as `PacketSource` / `PacketSink` | [nsplane-tun](reference/nsplane-tun.md) |
| `nsplane-netstack` | `crates/nsplane-netstack/` | User-space TCP/IP stack on smoltcp as `PacketSource` / `PacketSink`: TCP and UDP endpoints for IPv4 and IPv6 | [nsplane-netstack](reference/nsplane-netstack.md) |
| `nsplane-ether` | `crates/nsplane-ether/` | Ethernet adapter for one guest as `PacketSource` / `PacketSink`: ARP, IPv6 neighbor discovery and router advertisements, single-lease DHCPv4; stream and TAP frame transports | [nsplane-ether](reference/nsplane-ether.md) |
| `nsplane-dns` | `crates/nsplane-dns/` | DNS serving: wire codec, async `Resolver` trait, `StaticRecords`, `FakePool`, `Forwarder`, and a UDP/TCP `Server` on sockets or netstack flows (feature `netstack`) | [nsplane-dns](reference/nsplane-dns.md) |
| `nsplane-uapi` | `crates/nsplane-uapi/` | The `wg` UAPI over an `EngineHandle`; Unix socket listener | [nsplane-uapi](reference/nsplane-uapi.md) |
| `nsplane-cli` | `crates/nsplane-cli/` | Linux/macOS development daemon: TUN + engine + UAPI | [nsplane-cli](reference/nsplane-cli.md) |
| `nsplane-e2e` | `crates/nsplane-e2e/` | Not published: library-level end-to-end tests | |
| `nsplane-examples` | `examples/` | Not published: runnable example binaries on the public APIs and their shared node code, including a single-port relay with UDP and WSS client transports | [examples](../examples/README.md) |

```text
nsplane-noise (noise) ─► nsplane-core ─► nsplane ─► nsplane-tun, nsplane-uapi ─► nsplane-cli
nsplane-packet ────────► nsplane-core, nsplane
nsplane, nsplane-packet ─► nsplane-netstack, nsplane-ether
nsplane-core, nsplane-packet ─► nsplane-acl, nsplane-nat
nsplane ─► nsplane-nat
nsplane ─► nsplane-wss
nsplane-netstack (optional) ─► nsplane-dns
```

Dependencies point downward only. `nsplane-core` is the only crate that depends on
`nsplane-noise`. The feature crates are optional: a basic client links `nsplane` and
`nsplane-tun` only.

## Data flow

The core takes inputs and produces outputs; the driver moves them between the I/O sides:

```text
Input::Datagram { path, data }  ─┐                                  ┌─► Output::Transmit  { path, data }
Input::Local    { packet }       ├─► Core::handle_input(now) ─► poll_output ─┼─► Output::Deliver   { from, packet }
Input::Config   (ConfigChange)  ─┘                                  ├─► Output::Plaintext { to, packet }
                                                                    ├─► Output::Tracked   { tag, peer, outcome }
                                                                    └─► Output::Event (handshake, authenticated,
                                                                         path adopted, session expired, drops)
Core::poll_timeout / handle_timeout(now): rekey, keepalive, expiry, rate-limiter reset
```

- Received datagrams are demultiplexed by session index; a handshake initiation resolves its
  peer by decrypting the static key, so peers that share a relay endpoint need no endpoint
  matching.
- Inbound order: open in place, allowed-IP source check (the longest match must be the
  sending peer), the inbound filters, deliver. Outbound order: route by destination (within
  the local identity the source selects), the outbound filters, seal in place, transmit on
  the path the policy selects.
- The filter chain is onion-ordered: filters are installed from the wire side to the local
  side, decrypted packets run through them in install order and local packets in reverse. The usual stack is
  `[AclFilter, PortMap, Translator]`, so the ACL sees the tunnel's IPv6 in both directions.
- Plaintext packets attributed to a peer enter the inbound order after the open step:
  `Core::receive_plaintext` (in the engine, a bounded `PlaintextIngress`) runs the allowed-IP
  source check, the inbound destinations, the inbound filters with the caller's arrival path
  and delivery, the same code as for decrypted data, without authenticating anything.
  `Core::inject_inbound` keeps bypassing the checks and the filters.
- The engine counts the packets it takes from its local source; `EngineHandle::local_barrier`
  completes once every packet taken before the call has been routed and passed or been
  dropped by the outbound filters, so a change of address ownership can wait until no older
  local packet is still ahead of routing.
- Every `PacketBuf` carries an optional opaque tag (`Option<NonZeroU64>`) and a receipt
  marker. Both belong to the consumer, and neither is ever written to the wire. nsplane moves
  them with the packet through its queues, the filters, the crypto workers and the transmit
  queues up to the transport call, and copies them where it copies a packet into another
  buffer (the core's copy of a packet without headroom, the translators' grown copies; each
  fragment of the fragmentation stage takes the tag, never the marker). It clears both where a
  buffer stops being that packet: buffers from a pool, buffers handed to
  `PacketSource::recycle` by the engine and by `pump`, and a handshake initiation the tunnel
  writes into a packet's buffer. A datagram reassembled from fragments keeps a tag only if
  every fragment carried the same one (`None` included); a mixed set is dropped and counted.
  The outbound filters see a local packet's tag, so a consumer can stamp each packet at its
  producers with the ownership epoch its destination was chosen under and drop stale packets
  in its own filter, across every queue in between.
- The receipt marker makes a tagged packet tracked: the engine honours it only on packets its
  `TrackedSender` accepted, and clears it on every other entry (source, inject calls,
  `PlaintextIngress`) and on every packet it hands out (delivery, plaintext egress,
  recycling). A clone is never tracked.
- A tracked packet (its tag is the token) gets exactly one `SendResult`: `Sent { peer, bytes }`
  once the transport call that carried its datagram succeeded, or `NotSent { reason }` with
  the drop reason wherever it ended (routing, filters, no session, fragmentation, transmit
  queue, transport, plaintext egress, engine stop). The core reports each tracked packet once
  (`Output::Tracked`: sealed, right before its datagram, or not sent); the engine ends a
  transmit batch after every tracked datagram so that the transport call's outcome attributes
  it exactly, and reports every outstanding packet `ENGINE_STOPPED` when it stops. Results are
  bounded by the sender's capacity and never dropped. Untracked packets take no receipt path.
- A peer marked for plaintext egress (`Core::set_plaintext_egress`,
  `EngineHandle::set_plaintext_egress`) gets the local packets routed to it after the mark as
  `Output::Plaintext` once they passed the outbound filters, instead of sealed datagrams; the
  engine hands them to a bounded `PlaintextEgress`. The mark is runtime state of the `PeerId`
  (kept on an update, gone with the peer); the peer starts no handshake for data and still
  answers and starts handshakes for inbound sealed traffic.
- A flow gate can decide for a caller's selection of scopes (`FlowGate::evaluate_inbound_in`
  / `evaluate_outbound_in`): on the same snapshot and state as the unscoped calls, inside the
  selection the normal decision with its scope, rule and policy generation, outside it an
  enforced `OutOfScope` denial that reads and writes no state.
- A netstack admits new connections and flows at their first input on every stack
  (`NetStackConfig::admission`). Under `Admission::Decide` the lifetime's `FlowControl` and
  its delivery receipt exist from the held input on: a revoke before the hand-out retires the
  lifetime at its stage and no handle of it is delivered, and every such lifetime ends
  delivered or not delivered with one reason.
- A packet's tag at `NetStackSink` is its netstack ingress label. Each connection or flow
  takes the label of its first input, and input with another label is dropped and counted, so
  a lifetime never takes input meant for another owner of the same tuple.
  `NetStackHandle::revoke_label` retires every lifetime of a label at every stage, handles
  already handed out included, discards the label's input still queued in the stack and its
  partial datagrams, and keeps a bounded tombstone so later input with the label opens
  nothing; `Retired` means nothing of the label is delivered from then on. A stack without
  labeled lifetimes keeps the unlabeled path.
- Fragmentation and Packet Too Big are handled once, by an optional stage on the local path
  in front of the core; TUN and netstack share the same MTU limits, and the netstack derives
  its advertised MSS from the engine MTU.
- Local sides compose: `Splitter`, `MergeSource`, `MapSink` / `MapSource`, `pipe` and `pump`
  join TUN devices, netstacks, engines and translators into one graph without packet loops in
  the application.

Any local side works with any transport:

| Local side \ Transport | UDP | message link (relay) | WebSocket over TLS |
|---|:-:|:-:|:-:|
| TUN (kernel stack) | ✓ | ✓ | ✓ |
| `nsplane-netstack` (no TUN, no root) | ✓ | ✓ | ✓ |
| host bridge (mobile fd or callbacks, channels) | ✓ | ✓ | ✓ |

## Threading

One owner task holds the `Core` and loops over handle commands, local packets, received
datagrams and the core's next timeout. Each `PacketSource`, `PacketSink` and `Transport` has
its own task connected to the owner through a bounded queue. The core is never shared,
and `EngineHandle` calls are messages to the owner task. Noise session replay validation
locks its receiving counter even without crypto workers. With
`EngineBuilder::crypto_workers(n)` (n of 2 or more) sealing and opening
move to `n` worker tasks while handshakes, timers and configuration stay on the owner; every
peer's packets keep their arrival order. The details are in the
[nsplane reference](reference/nsplane.md).

Shared state that packet paths read and control paths replace (ACL state, filter scopes, the
gate policy, translation tables, LAN routes) lives in a `SnapshotCell`
([nsplane-core](reference/nsplane-core.md#snapshot-cell)): a reader takes no lock on an
unchanged value, and a writer publishes a whole new value.

## Protocol baseline

Cookies cover the IP and port; handshakes are rate-limited per source with an engine-wide
backstop; `Reject-After-Messages` is enforced in both directions and rekeying starts at
`Rekey-After-Messages`; data is padded to 16 bytes (or capped at a path's MTU); the
anti-replay window is 8192 messages; cookie replies never roam; the source allowed-IP check
is the longest match over all peers; malformed keys are rejected; keepalive and handshake
timers run from the first unanswered packet, and handshake retries are jittered. Debug output
redacts key material.

## Unsafe code

`unsafe` lives only in `nsplane-tun`'s platform modules (`unix`, `linux`, `darwin`, and
loading Wintun in `windows`), each with `SAFETY` comments. `nsplane-packet`, `nsplane-core`,
`nsplane`, `nsplane-acl`, `nsplane-nat`, `nsplane-wss`, `nsplane-netstack`, `nsplane-uapi`,
`nsplane-cli` and `nsplane-examples` declare `#![forbid(unsafe_code)]`, and `nsplane-noise`
contains no `unsafe` block. See ADR
[2026-10-01-unsafe-code-in-boringtun](decisions/2026-10-01-unsafe-code-in-boringtun.md).

## Crypto

- ChaCha20-Poly1305 (transport data, handshake fields): `aws-lc-rs` (an `aws-lc-sys` C and
  assembly core).
- Constant-time comparisons: `subtle`.
- XChaCha20-Poly1305 (cookies), BLAKE2s, HMAC: RustCrypto.
- X25519: `x25519-dalek`.

## Testing

- `just check` runs formatting, lints (every feature combination), the unit, integration and
  doc tests of every crate, `cargo deny`, `cargo shear`, typos, the MSRV build, the example
  build, and the product-term and documentation checks. `nsplane-e2e` runs engines against each other
  over in-memory channel transports: the filters (`translate`, `port_map`, `nat64_lan`,
  `acl_*`, `flow_gate*`), the fragmentation stage, the local-side graph (`local_graph`,
  `graph_*`), the netstack (`netstack_*`), inbound destinations, local identities and the
  transports.
- `just e2e` (`scripts/e2e/linux.sh`) runs `nsplane-cli` against kernel WireGuard in two
  containers.
- `just e2e-examples` (`scripts/e2e/examples.sh`) runs the `nsplane-examples` binaries in
  containers as a matrix of local sides and transports plus relay, translation and gateway
  scenarios, against each other and against kernel WireGuard (see
  [examples/README.md](../examples/README.md)).
- `just cross` runs clippy for macOS and Windows; `just test-windows` runs the Windows
  build's unit tests under Wine (without the Wintun driver).
- Tests that need privileges (`CAP_NET_ADMIN`, a real Windows host) are `#[ignore]` and name
  the command that runs them in their module docs.
