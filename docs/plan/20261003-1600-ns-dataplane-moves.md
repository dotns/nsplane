# 20261003-1600-ns-dataplane-moves Move the remaining ns data-plane pieces into nsplane

- **status**: completed
- **createdAt**: 2026-10-03 16:00
- **approvedAt**: 2026-10-03 16:00 (user: D9 do, D10 a generic link transport, SNAT/DNAT
  in nsplane-nat, evaluate the ACL move)
- **relatedTask**: 20261003-1500-ns-dataplane-moves, 20261003-1300-ns-m4-requests

## Context

Owner rule (2026-10-03): ns holds business logic and the control plane only; every
per-packet piece belongs in nsplane. Task `20261003-1500-ns-dataplane-moves` lists what ns
still owns. MA-1..3 and MB-4..6 landed in `36cbe21`; MA-x1 (`force_handshake_on`) is done by
L1 before this campaign. MD (ACL and the node L3 gate, migration M6) is only evaluated in
this round (L1), not implemented.

Conventions for every item: additive API, defaults keep today's behavior, nothing costs
anything when unused, an `nsplane-e2e` test (or example scenario) per item, no new
dependency without the user's approval.

## Contract

### MB-x netstack (`crates/nsplane-netstack/**`, `crates/nsplane-packet/**` for the shared reassembler)

- MB-x1 `NetStackHandle::owns(&self, packet: &[u8]) -> Ownership`, sync (no await; lock-free
  or one short lock), `enum Ownership { Flow, Listener, None }` (`#[non_exhaustive]`):
  - `Flow`: an IPv4/IPv6 TCP or UDP packet whose exact (local, remote, proto) tuple matches a
    live connection, a connect in SYN-SENT (visible once `connect_tcp`/`connect_tcp_from`
    has queued its SYN), or a bound UDP socket or UDP flow; or an ICMP/ICMPv6 error quoting
    such a tuple.
  - `Listener`: a bare TCP SYN or a UDP datagram to a stack address that would open a new
    inbound connection or flow.
  - `None`: anything else; non-first IPv4 fragments unless MB-x2 is on.
- MB-x2 reassembly of IPv4 fragments and IPv6 Fragment-header packets on the stack's
  ingress: `NetStackConfig::reassembly: Option<ReassemblyConfig { max_datagrams (64),
  timeout (30 s), max_bytes (65 535 per datagram) }>`, default `None` (fragments dropped as
  today); counters `NetStackStats::{reassembled, reassembly_timeout, reassembly_overflow}`.
  The reassembler is a reusable module in `nsplane-packet` (`nsplane_packet::reassembly`),
  so the translator's zero-checksum reassembly can move onto it later (not in this round).
- MB-x3 `TcpConnection::unacked(&self) -> u32` (SND.NXT - SND.UNA) and
  `TcpConnection::last_ack(&self) -> Option<std::time::Instant>`; updated by the driver
  without a per-byte cost (atomics written per turn).
- MB-x4 `NetStackConfig::udp_allow_fragmentation: bool` (default `false`): with it,
  `UdpReply::send` / `UdpSocket::send_to` above `mtu - headers` emit one IPv4 datagram with
  DF clear for the engine's fragmenter to split (`EngineBuilder::fragmenter`); IPv6 keeps
  failing with `InvalidInput`.

### MC transports (`crates/nsplane/src/{udp,transport,lib}.rs`, new `crates/nsplane/src/link.rs`)

- MC-1 side channel on `UdpTransport`:
  `UdpTransport::with_side_channel(self, classify: impl Fn(&[u8]) -> bool + Send + Sync + 'static, capacity: usize) -> (UdpTransport, SideSender, mpsc::Receiver<SideDatagram>)`;
  `SideDatagram { from: SocketAddr, datagram: Bytes }`; `SideSender::send_to(&self,
  datagram: &[u8], to: SocketAddr) -> io::Result<()>` (same socket, ECN not set, best
  effort), `SideSender::local_addr()`, `SideSender::stats() -> SideStats { received,
  dropped }` (full or closed receiver). Classified datagrams are taken out of `recv` and
  `recv_batch` (GRO segments included) and never reach the engine; without a side channel
  nothing changes and nothing is classified. (Deviation from the ns proposal: the side
  counters live on `SideSender`, not in `TransportStats`, because side datagrams never reach
  the engine's transport tasks.)
- MC-2 generic message-link transport (user decision: no WebSocket or TLS dependency in
  nsplane): `LinkTransport::new(id: TransportId, peer: SocketAddr, dialer: Arc<dyn
  LinkDialer>, config: LinkConfig) -> LinkTransport`, a `Transport` where one datagram is one
  message. `trait LinkDialer: Send + Sync + 'static { fn dial(&self) -> BoxFuture<'_,
  io::Result<(Box<dyn LinkSender>, Box<dyn LinkReceiver>)>>; fn on_state(&self, state:
  LinkState) {} }`, `enum LinkState { Connected, Disconnected }` (`#[non_exhaustive]`),
  object-safe `LinkSender::send(&mut self, message: &[u8]) -> BoxFuture<'_, io::Result<()>>`
  and `LinkReceiver::recv(&mut self) -> BoxFuture<'_, io::Result<Option<Bytes>>>` (`None`
  = closed). Received messages are reported from `peer`; sends to another address are
  dropped and counted as sent. While no link is up, sends wait in a bounded queue
  (`LinkConfig::queue`, 256) and then fail (the engine counts `TRANSPORT_SEND_ERROR`). On
  link loss the transport dials again; backoff is the dialer's (it may sleep in `dial`).
  `LinkConfig::read_idle_timeout: Option<Duration>` closes an idle link. ns implements the
  dialer over its WebSocket (URL, bearer, 401/403, backoff); the wire stays the same. e2e:
  an in-memory link in `nsplane-e2e`, and the examples' relay WSS client moved onto
  `LinkTransport` with a tungstenite dialer (tungstenite is approved for the examples
  package only).

### ME nat (`crates/nsplane-nat/**`)

- ME-1 stateful NAT64-to-LAN (NAPT) `Nat64Lan`: routes `LanRoute { mapped: Ipv6Net (/96),
  real: Ipv4Net, snat_source: Ipv4Addr }` replaceable atomically; IPv6 TCP/UDP/ICMPv6 echo
  to a `mapped` address -> IPv4 to the embedded low-32 address in `real`, rejecting unsafe
  LAN targets as ns `SubnetRoute::resolve` does; source NAT to `snat_source` with a port
  (or ICMP id) reserved per flow through a caller-supplied `SnatPorts` trait (default an
  in-memory allocator; ns couples it to its host sockets), `port_tries` (32); reverse
  translation with optional TCP MSS clamp; ICMP Fragmentation Needed -> ICMPv6 Packet Too
  Big with mtu + 20 (min 1280); bounded flow table with idle timeouts (the existing
  `Conntrack` where it fits), `remove_flow`, stats. Placement: replies from the LAN are
  addressed to `snat_source`, which no peer's allowed IPs contain, so the core cannot route
  them before a filter runs; the translation therefore sits on the local side: `forward` /
  `reverse` functions on `PacketBuf` (in place, growing into headroom/tailroom like the
  translator) plus `PacketSink` / `PacketSource` wrappers (`Nat64LanSink<K>`,
  `Nat64LanSource<S>`) that apply them to delivered and local packets; packets that are not
  theirs pass unchanged.
- ME-2 local-side redirect (DNAT with reverse SNAT) replacing ns `tun_service/rewrite.rs`:
  a per-flow redirect of local IPv4 TCP/UDP packets to a caller-chosen endpoint (decision
  closure per new flow, endpoint allocator owned by the caller), reverse rewrite of the
  replies to the original destination, bounded flow table, idle expiry, `remove_flow`.
  Evaluate `PortMap` / `Conntrack` reuse first; the L2 proposes the exact API to L1 before
  coding it (a yellow gate).

### Out of this round

- MD (ACL and node L3 gate): L1 writes an assessment for the user.
- Item 7 of the M4 task (`SOURCE_NOT_ALLOWED` opt-out): conditional, as before.

## Workstreams (L2)

| L2 | Items | Scope |
|---|---|---|
| MB-x | x1-x4 | `crates/nsplane-netstack/**`, `crates/nsplane-packet/src/reassembly*`, its e2e |
| MC | 1-2 | `crates/nsplane/src/{udp,transport,link,lib}.rs`, `examples/**` (relay WSS client), its e2e |
| ME | 1-2 | `crates/nsplane-nat/**`, its e2e and examples |

Parallel, disjoint write scopes except `crates/nsplane-e2e/**` (new test files only),
`CHANGELOG.md`, `docs/architecture.md`, `Cargo.lock`; L1 merges by completion.

## Acceptance

Each branch and main after each merge: just check, just cross, just test-windows, cargo doc
-D warnings, root tests, release CLI + linux.sh, lib.sh, examples.sh green; data_path no
regression (64 B 532 ns, 1420 B 1.331 us; batched 415 ns / 1.226 us per packet).

## Annotations
- 2026-10-03: MB-x3 contract change (L1, on the MB-x yellow): `TcpConnection::unacked` is the
  bytes written and not yet acknowledged (smoltcp's send queue, including bytes the peer or
  congestion window holds back), not SND.NXT - SND.UNA: the fork exposes no SND.NXT, the
  value matches the signal ns's stall check uses today, and it costs nothing per packet.
- 2026-10-03: ME-2 API approved as `nsplane_nat::redirect::Redirect` (forward/reverse on
  PacketBuf, caller `decide` closure, Conntrack-backed, never calling `decide` under a lock);
  ME-1 `LanRoute` uses `(addr, prefix)` pairs instead of `Ipv6Net`/`Ipv4Net` (no ipnet
  crate), and nsplane-nat gains a dependency on `nsplane` for the sink/source wrappers.
- 2026-10-03: completed (campaign `nsplane-mv-202610031600`). Merges into main: MC c9008ba
  (+ 197c00c side-channel capacity 0 raised to 1), ME 55abac8, MB-x 9c9efcd. Final acceptance
  on main: just check 1048 tests, cross, test-windows, cargo doc, root nsplane-tun/nsplane
  ignored tests, linux.sh, lib.sh (7), examples.sh (all cells and scenarios incl.
  subnet_gateway) green; data_path 64 B 531 ns (batched 415 ns per packet), 1420 B 1.335 us
  (batched 1.239 us), flat against before. Left in task 20261003-1500: MB-x5, MB-x6 (already
  counted as `NetStackStats::syn_refused`), MC-3 (WSS carriers, needs the user's decision on
  dependencies), MF (engine and netstack throughput), MD (ACL, own plan).
