# 20261002-1725-phase3-4-netstack-acl Phases 3 and 4: netstack, ACL, transport backpressure

- **status**: approved
- **createdAt**: 2026-10-02 17:25
- **approvedAt**: 2026-10-02 17:25 (user: run the roadmap to the end)
- **relatedTask**: 20261002-1020-data-plane-core, 20261002-1509-phase1-followups

## Context

Plan `20261002-1024-data-plane-core` sections "Netstack (`nstun-netstack`)" and
"ACL (`nstun-acl`)", Phases 3 and 4, now under the nsplane names. Phase 2 left two engine
defects (follow-ups #10 head-of-line blocking across transports, #11 uncounted drops on
transport removal) that also affect any second source/sink such as the netstack.

ns code that moves (same owner, design and code may be ported; read-only in
`/srv/dotns/ns`, never modified):
- `crates/netstack` (~3.3k lines incl. tests): smoltcp 0.13.1 stack around a
  channel-driven `VirtualDevice` (`device.rs`), `stack.rs` (TCP listener pool, half
  close), `udp.rs`, tests `stack/tests/*`, `tests/tcp_pipeline.rs`.
- `crates/acl` (~2.4k lines): `engine.rs`, `matcher.rs`, `merge.rs`, `deny_scope.rs`,
  `policy.rs` (serde model), `local.rs` (TOML file layer). Depends on ns `common` for
  `IpNet`/`Protocol`.

## Proposal

### Contract

`nsplane-netstack` (new crate, smoltcp 0.14):
- `NetStack::new(NetStackConfig { addresses, mtu, .. }) -> (NetStack, NetStackHandle)`;
  `NetStack` (or parts from `split()`) implements `nsplane::PacketSink` (packets into the
  stack) and `nsplane::PacketSource` (stack egress).
- `NetStackHandle::incoming_tcp() -> impl Stream<Item = TcpConnection>`,
  `incoming_udp() -> impl Stream<Item = UdpFlow>` (datagram + reply handle),
  `connect_tcp(SocketAddr) -> TcpConnection`, `bind_udp(SocketAddr) -> UdpSocket`;
  `TcpConnection: AsyncRead + AsyncWrite` with half close.
- MSS/window derived from the engine MTU (the "tunnel MTU" rule ns learned).
- One driver task around `poll_ingress_single`/`poll_egress` (single egress turn per
  packet), bounded channels, counted drops.

`nsplane` additions:
- `Splitter`: a `PacketSink` that routes each delivered packet to one of N sinks by a
  user closure (`Fn(PeerId, &PacketBuf) -> usize`), for hybrid TUN + netstack.
- `MergeSource`: a `PacketSource` that merges several sources fairly.
- Follow-up #10: per-transport backpressure; a transport with waiting datagrams no longer
  pauses local reads for peers on other transports (bounded per-transport backlog,
  counted `TRANSMIT_FULL` drops when that backlog is full).
- Follow-up #11: datagrams still queued for a removed transport are counted
  (`TRANSPORT_REMOVED` reason in `nsplane_core::reasons`, the only core touch, additive).

`nsplane-acl` (new crate):
- Ported policy model (`AclPolicy`, rules, hosts), matcher, deny scope, layered merge
  (`PolicyLayers`, `merge_layered`), policy self-tests; `Protocol` and `IpNet` defined
  locally (no ns `common`). serde derive on the policy model (serde, serde_json are
  already in Cargo.lock). The TOML local-file loader (`local.rs`) stays in ns.
- `AclEngine` with atomic reload (`arc-swap`), fail-closed when no policy is loaded,
  `is_allowed(&AccessRequest) -> AclDecision`.
- `AclFilter: nsplane_core::PacketFilter` (inbound): five-tuple from `nsplane-packet`,
  `SourceAssertion` from the decrypting peer through a user `PeerIdentity` map, fragment
  gate (non-first fragments follow the first fragment's verdict, bounded table).
- `FlowTracker: PacketFilter` for per-flow accounting (bounded, counted evictions).

### Workstreams (L2)

| L2 | Scope | Depends on |
|---|---|---|
| 3A netstack | `crates/nsplane-netstack/**`, `crates/nsplane/src/{splitter,merge}.rs` (+ lib.rs lines), its e2e tests and container cases, `scripts/e2e/**` additions | - |
| 3B acl | `crates/nsplane-acl/**`, its e2e tests and container cases | - |
| 3C engine | `crates/nsplane/src/{engine,handle,builder,events}.rs`, `crates/nsplane-core/src/reasons.rs` (one constant), its e2e tests | - |

All three run in parallel; merge order 3C -> 3A -> 3B (L1 resolves trivial conflicts in
workspace members, `crates/nsplane/src/lib.rs`, `Cargo.lock`, `crates/nsplane-e2e`).

### End-to-end tests (required for every feature)

- 3A: engine + `NetStack` in process (TCP echo, UDP echo, connect_tcp/bind_udp reverse
  direction, MSS fits the tunnel MTU, half close); `Splitter`/`MergeSource` hybrid case;
  container: netstack-only node (no TUN) against kernel WireGuard: kernel peer `nc` TCP
  echo and UDP echo through the stack; throughput note TUN vs netstack.
- 3B: engine with `AclFilter`: allowed vs denied flows, live reload, fail-closed before the
  first policy, fragment gate, `FlowTracker` counters; ported ns policy tests pass;
  container: kernel peer reaches an allowed port and is dropped on a denied port.
- 3C: two transports, one stalled: peers on the other transport keep full traffic; removal
  with queued datagrams counts `TRANSPORT_REMOVED`.

### Acceptance

`just check`, `just cross`, `just test-windows`, `cargo doc -D warnings`, release CLI +
`scripts/e2e/linux.sh`, `scripts/e2e/lib.sh` green on each branch and on main after each
merge; data_path bench no regression vs Phase 2 (64 B 538.5 ns, 1420 B 1351 ns).

## Risks

- smoltcp 0.13 -> 0.14 API changes in the ported driver; the ns tests are the guard.
- ACL semantics parity: the ported ns policy tests are the acceptance suite.

## Scope

nsplane repository only; `/srv/dotns/ns` read-only. New dependencies allowed: `smoltcp`
0.14 (approved), `arc-swap` (approved), crates already in Cargo.lock (serde, serde_json,
thiserror, futures-core if present, ...). Anything else is a yellow.

## Annotations
- 2026-10-02: user added workstream 3D: a root `examples/` package (`nsplane-examples`,
  publish = false) with runnable examples for every feature and `just e2e-examples`
  running them over the design's presentation x transport matrix (TUN, netstack, fd/channel
  bridge x UDP, relay UDP, relay WSS). Relay WSS is a real WebSocket over TLS; the user
  approved `tokio-tungstenite`, `tungstenite`, `tokio-rustls`/`rustls` (aws-lc-rs),
  `rustls-pki-types`, `rcgen` for the examples package only. 3D starts after 3A merges.
