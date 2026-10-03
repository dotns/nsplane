# 20261003-1500-ns-dataplane-moves Data-plane pieces ns still owns, to move into nsplane

- **status**: in_progress
- **priority**: P1
- **owner**: L1 (7f5cstru), plan 20261003-1600-ns-dataplane-moves
- **createdAt**: 2026-10-03 15:00

## Description

Architecture rule (owner, 2026-10-03): ns holds only business logic and the control plane;
every per-packet piece belongs in nsplane. ns classified its remaining data-plane code (ns
campaign ns-nsplane-202610021955, T13a). Items below are what nsplane lacks. ns deletes its
own copy as each workstream lands and ns bumps its nsplane pin.

This extends `20261003-1300-ns-m4-requests` (MA-1..3 and MB-4..6 there, proposal 52c5a73)
with new MB items and three new workstreams. Priority for the first ns release, which runs
on the engine only:

| Workstream | Needed for | ns code it removes |
| --- | --- | --- |
| MA (+ MA-x1 optional) | first release (full ladder, recovery probes) | tunnel-wg per-path send, hole-punch / direct-link state machines |
| MB (+ MB-x1..x4) | first release | crates/netstack, the exit-owned smoltcp loop, smoltcp 0.13, client_stack ownership / reassembly / send-progress code |
| MC | first release | ns-engine SharedUdpTransport and WssTransport, the opaque pump loopback hop |
| ME | first release | crates/nat subnet translation and SubnetConntrack |
| MD | migration M6 (ACL moves to nsplane-acl) | crates/acl enforcement, AccountFilter, the node_l3 gate |

What stays in ns: policy and projection (node_l3 policy, DynamicL3RouteTable contents,
ServiceRouter, SubnetRoute decisions), control codecs and loops (reflexive gather,
candidate report, relay and recovery-probe messages), the PathPolicy implementation, dialers
(URL, bearer, backoff), stall decisions and status mapping.

Conventions: every hook is additive, defaults keep today's behavior, nothing costs anything when unused, and every item has an nsplane-e2e test.

## Workstream MA (core + engine), already proposed in 52c5a73
- MA-1 (proposal item 1) `EngineHandle::inject_outbound_on(peer: PeerId, path: Path, packet: PacketBuf) -> Result<(), EngineError>`.
  - Needed by: recovery-probe challenge bursts (16 x 1,168-byte, recovery_probe.rs) and the reply on the arrival path; direct-promotion bursts.
  - Replaces: tunnel-wg's per-path send in userspace_io.
- MA-2 (proposal item 2) `PacketFilter::inbound_from(&self, peer, from: &Path, packet) -> Verdict`, default delegating to `inbound`.
  - Needed by: the NSPATH01 recovery filter (consume the challenge and answer it on `from` via MA-1); PayloadCounter attribution of payload to the current path vs a candidate (removes the documented difference "data_bytes_rx also counts payload that arrives off the current path").
- MA-3 (proposal item 3) `PathPolicy::observe_every_message(&self) -> bool`.
  - Needed by: the ladder's direct-lost timer (15 s) once the direct path is the engine path.
- MA-x1 (NEW, optional) `EngineHandle::force_handshake_on(peer: PeerId, path: Path)`.
  - Semantics: send one handshake initiation on `path` without changing the peer's path (today `force_handshake(peer, Some(path))` makes `path` the peer's path).
  - Errors: EngineError when the engine is gone; unknown peer -> no-op Ok (as force_handshake).
  - Replaces: AccountPaths' one-shot initiation entry (link.rs set_initiation/clear_initiation). Not required; the PathPolicy::select workaround is correct. L1 decides (D9).

## Workstream MB (netstack), already proposed in 52c5a73, plus new items
- MB-4 (proposal item 4) `NetStackConfig::accept_backpressure: bool` (default false).
  - Needed by: account_engine::stack parity with the legacy blocking accept (stack.rs:38).
- MB-5 (proposal item 5) `NetStackHandle::connect_tcp_from(local_port: u16, remote: SocketAddr) -> io::Result<TcpConnection>`. AddrInUse when the port is taken by a connection or listener of the stack.
  - Needed by: exit-owned runtimes (HostPortReservation). UDP is already covered: `bind_udp(SocketAddr::new(stack_ip, reserved_port))` already picks the caller's port (nsplane main as of the traffic-status change), so no UDP item is needed.
- MB-6 (proposal item 6) random ephemeral start per stack.
  - Closes client_stack difference 2 (ports start at 49152).
- MB-x1 (NEW) Packet ownership query so a local side can share one decrypted stream between the stack and other consumers.
  - API: `NetStackHandle::owns(&self, packet: &[u8]) -> Ownership` (sync, no await, lock-free or one short lock) with
    `enum Ownership { Flow, Listener, None }`:
    - Flow: an IPv4/IPv6 TCP or UDP packet whose exact (local, remote, proto) tuple matches a live connection, a connect in SYN-SENT, or a bound UDP socket; or an ICMP/ICMPv6 error quoting such a tuple.
    - Listener: a TCP SYN or a UDP datagram to the stack address that would open a new inbound connection or flow.
    - None: everything else.
  - Semantics: the answer is valid for the stack state at the call; a connect becomes visible from the moment `connect_tcp`/`connect_tcp_from` has queued its SYN (before the first SYN leaves). Not-first IPv4 fragments return None unless MB-x2 is enabled.
  - Purpose: removes client_stack's SYN-key learning, the retired-tuple table and the per-destination connect serialization (client_stack differences 6 and the "abandoned connect reserves its destination 5 s" rule), and the exact-flow GatewayClassifier lookup. ns keeps the ownership POLICY (Consumer > Provider > L3) as a Splitter closure.
- MB-x2 (NEW) IPv4 (and IPv6 fragment-header) reassembly on NetStackSink.
  - Config: `NetStackConfig::reassembly: Option<ReassemblyConfig { max_datagrams: usize /*64*/, timeout: Duration /*30 s*/, max_bytes: usize /*65_535 per datagram*/ }>`, default None, so today's "fragmented UDP is dropped" is kept.
  - Counters: `NetStackStats::{reassembled, reassembly_timeout, reassembly_overflow}`.
  - Replaces: client_stack Reassembly (FRAGMENT_TTL 30 s, ASSEMBLY_LIMIT 64).
- MB-x3 (NEW) Send progress per connection.
  - API: `TcpConnection::unacked(&self) -> u32` (bytes sent and not acknowledged, i.e. SND.NXT - SND.UNA) and `TcpConnection::last_ack(&self) -> Option<Instant>`.
  - Purpose: replaces client_stack SendProgress (observe_egress/note_ack seq tracking). The stall decision (4 s without progress -> route failure) stays in ns (c).
- MB-x4 (NEW) Oversize UDP replies.
  - Semantics: `UdpReply::send` / `UdpSocket::send_to` with a payload above `mtu - headers` emit one IPv4 datagram with DF clear (to be split by the engine fragmenter, `EngineBuilder::fragmenter`) instead of failing; IPv6 keeps failing with `InvalidInput`.
  - Opt-in: `NetStackConfig::udp_allow_fragmentation: bool` (default false).
  - Replaces: stack.rs send_reply + netstack::udp::build_udp_reply.

- MB-x5 (NEW, from ns T10 throughput) Configurable TCP socket buffers.
  - Config: `NetStackConfig::tcp_rx_buffer` / `tcp_tx_buffer` (bytes; default today's 512 segments) with the advertised window and window scaling following the receive buffer.
  - Evidence: ns user-space mode single-stream TCP is 15% below the legacy stack (1 MiB buffers) on a quiet host, with lower CPU use, i.e. window-limited.
- MB-x6 (NEW, from ns T10 load) Count listener-pool overflow.
  - The listener pool size is already caller config (ns raises it); the gap is visibility: a SYN that finds the pool full is reset silently. Add `NetStackStats::tcp_listen_overflow`.
  - Evidence: with ns's pool at 32, 500 concurrent connects got 135-168 accepted and the rest reset without a counter; with the pool at 512, 500/500.

## NEW workstream MF: engine throughput (ns release gate "throughput not below the legacy baseline")

ns T10b profiling (Linux, two containers with pinned CPUs, real TUN, single-stream iperf3 TCP,
nsplane main as of the traffic-status change; full tables in ns docs/task/20261003-1300-account-mode-engine.md):

- MF-1 TUN data path is 15-21% below ns's legacy tunnel-wg loops (unloaded rounds: 4044 vs
  4748 Mbit/s; engine lower in 8 of 10 paired rounds). Nodes are not CPU-bound; per-byte CPU
  is within -4% to +11%. ns code (ChannelIo copy, AccountFilter, payload counter, UDP transport
  wrapper) is under 2% of samples. The engine spends 5-7 points more in engine/core internals
  and about 5 points more in tokio channel handoffs (mpsc, batch_semaphore) along
  read_source -> Owner -> transmit and receive -> Owner -> write_sink. Inclusive samples:
  sender engine::transmit 3.63%, Core::prepare_send 2.57%, engine::read_source 2.00%,
  Owner::drain 1.55%, Owner::transmit 0.96%; receiver engine::receive 3.70%,
  engine::write_sink 1.56%, Owner::drain 1.03%, Core::deliver_opened 0.81%. Likely cause:
  handoff latency and wakeups in the task pipeline (inferred). Ask: reduce handoffs on the
  hot path (for example run-to-completion read -> seal -> send when no crypto workers are
  configured), measured with the ns harness or an equivalent nsplane-e2e bench.
  - Harness: `just bench-wg` (`scripts/bench/wg-compare.sh`); results in docs/architecture.md, Performance, *Against WireGuard implementations*.
- MF-2 user-space mode (nsplane-netstack) is 12-14% below the legacy smoltcp stack; raising
  the TCP buffer to 1 MiB did not close it (4356 vs 4897 Mbit/s, within noise). Cause unknown;
  ask: profile nsplane-netstack under the same single-stream load. MB-x5 stays useful but is
  not the fix.

## NEW workstream MC: transports (crates/nsplane/src/udp.rs, transport.rs; e2e)
- MC-1 Side channel for non-WireGuard datagrams on a UdpTransport.
  - API: `UdpTransport::with_side_channel(self, classify: impl Fn(&[u8]) -> bool + Send + Sync + 'static, capacity: usize) -> (UdpTransport, SideSender, mpsc::Receiver<SideDatagram>)`.
    - `SideDatagram { from: SocketAddr, datagram: Bytes }`.
    - `SideSender::send_to(&self, datagram: &[u8], to: SocketAddr) -> io::Result<()>`: same socket, ECN NotEct, best effort.
    - `SideSender::local_addr()`.
  - Semantics: received datagrams for which `classify` is true are taken out of recv and recv_batch (GRO segments included) and try_sent to the receiver, dropped when it is full or closed and counted in TransportStats (new `rx_side`, `rx_side_dropped`). Everything else reaches the core unchanged; the default is no side channel.
  - ns supplies `classify = |d| d.starts_with(b"NSGWP2P1")`.
  - Replaces: ns-engine SharedUdpTransport/ControlSender.
  - Done (2026-10-03): `UdpTransport::with_side_channel`, `SideSender`, `SideDatagram`; the counters are `SideSender::stats() -> SideStats { received, dropped }`, not `TransportStats` (deviation recorded in the plan). Tests: `nsplane-e2e` `udp_side_channel`, unit tests in `crates/nsplane/src/udp.rs`.
- MC-2 WebSocket datagram transport.
  - API: `nsplane::WsTransport::new(id: TransportId, peer: SocketAddr, dialer: Arc<dyn WsDialer>)` with
    `trait WsDialer: Send + Sync { fn dial(&self) -> BoxFuture<'_, io::Result<WebSocketStream<BoxedIo>>>; fn on_state(&self, state: WsLegState) {} }` and
    `enum WsLegState { Connected, Disconnected, Rejected(u16) }`.
  - Semantics: one datagram = one binary message, raw. Received datagrams are reported from `peer`; sends to other addresses are dropped and counted as sent. While no leg is up, sends wait, bounded by a queue (default 256), then drop with DROP_TRANSPORT_SEND_ERROR. On leg loss the transport calls `dial` again after a backoff the dialer controls (the dialer may sleep). The idle watchdog (read idle timeout, default the tunnel-ws WSS_READ_IDLE_TIMEOUT) closes the leg.
  - ns keeps URL, leg, bearer, 401/403 handling and backoff in its WsDialer (c).
  - Replaces: the OpaquePump loopback UDP hop and ns-engine WssTransport. The wire stays unchanged (campaign rule).
  - Alternative (no MC-2): keep the pump as it is. It is per-datagram code in ns, so it would be a recorded exception to the rule (D10).
  - Done (2026-10-03) as the generic form (D10): `LinkTransport` with `LinkDialer`, `LinkSender`, `LinkReceiver`, `LinkState { Connected, Disconnected }` and `LinkConfig { queue: 256, read_idle_timeout: None }`; no WebSocket or TLS dependency in nsplane, so `Rejected(u16)` stays with ns's dialer. Tests: `nsplane-e2e` `link` (in-memory link); the examples' relay WSS client runs on it with a tungstenite dialer (`examples/tests/wss.rs`, `just e2e-examples` relay-wss cells).
- MC-3 (NEW, approved 2026-10-03, plan 20261003-1630-perf-and-wss PW) WSS carriers in nsplane. Owner: ns is the business layer, nsplane the data plane; without UDP, WSS is the only channel, so all of ns `tunnel-ws` moves. This revisits D10's "no WebSocket or TLS dependency in nsplane".
  - New crate `nsplane-wss` (tokio-tungstenite, rustls/aws-lc-rs); `nsplane` core stays free of WebSocket and TLS.
  - (a) Datagram carrier: `WssDialer: LinkDialer`, from ns `OpaquePump` (bearer header, 401/403, doubling backoff 2 s..60 s, read-idle watchdog, ping) and `examples/src/relay/wss/client.rs`. `LinkState` gains `Rejected(u16)`.
  - (b) Stream carrier: the WsFrame protocol (`[stream_id u32][cmd][payload]`, OPEN_V4/V6, DATA, CLOSE, CLOSE_ACK) with both legs: client (open a TCP/UDP flow to a target, today ns `proxy/wire.rs` + `wss_flow.rs`) and terminate (ns `tunnel-ws` `WsTunnel` session: per-session buffer cap, separate data/control queues, stream table). Business resolution (`OverlayResolver`, services.toml, FQID, ACL, gateway identity) stays in ns behind an embedder trait that maps an OPEN to a backend address or a denial.
  - Finding: `WsTunnel` has had no consumer in ns since the connector crate was retired (ns 0aef94a0, 2026-08-28); only `OpaquePump` and ns `proxy/` (client leg) are live.
  - ns then deletes `crates/tunnel-ws`, the opaque pump loopback hop and its own WsFrame codec, keeping listeners, route lookup, bearer source, ACL preflight and status mapping.

## NEW workstream MD: ACL and L3 gate (nsplane-acl, M6; option A holds until then)
- MD-1 Per-packet source principal.
  - API: `SourceAssertion::TerminateFromPacket` (or `PeerIdentity::assertion_for(&self, peer, src: IpAddr) -> Option<SourceAssertion>` with a default delegating to `assertion`).
  - Semantics: for peers marked "terminate by IP", the principal is `Terminate { ip: Some(src), anchor: src.to_string() }` from the packet's source address (crates/acl AccessRequest::from_ip). For relay client keys it is `WgPeerKey { pubkey }` (with_wg_peer_key).
  - Caching: per (peer, src) under the identity generation.
- MD-2 Node L3 gate as an nsplane-acl mode. It must express:
  - target-bound Node/Service/Subnet grants;
  - source binding (packet source must be the peer's projected Node address);
  - the same-owner rule;
  - stateful flows with per-protocol idle timeouts (TCP 2 h, half-close 5 min, terminal 30 s, UDP 2 min, ICMP 30 s, other 60 s);
  - per-peer (2,048) and global (16,384) state limits with a StateCapacity drop, and an orphan-fragment drop;
  - ICMP errors matched to their flow;
  - modes Legacy (not applicable: continue to the next filter step), Observe (count, do not enforce) and Enforce;
  - "enforced allow ends evaluation before the L4 ACL" (a final-accept verdict, or one filter evaluating both layers in order).
  - Reasons: map NodeL3Reason 1:1 to reason strings.
  - Input: the compiled NodeL3Config (ns still compiles it, (c)).
- MD-3 Divert verdict. AclFilter config `divert: Option<mpsc::Sender<(PeerId, Bytes)>>` plus a predicate on the drop reason: a packet denied for SourceBinding/OrphanFragment is try_sent there and reported as `Verdict::Handled` (gateway-consumer path, filters.rs:200).
- MD-4 Fragment parity with FragmentAclGate. Non-first IPv4 fragments are judged by the remembered verdict of their datagram's first fragment, keyed (src, dst, proto, id) with a TTL (FragmentAclGate's) and the fragment_capacity bound. nsplane-acl already gates on the first fragment; the requirement is equal keying, TTL and miss behavior (drop).
- MD-5 Bypass flags in AclFilterConfig, default false:
  - `accept_to_local: Option<Ipv4Addr>`: IPv4 packets to this address skip the ACL (is_local_node_packet);
  - `accept_icmp_echo_reply: bool`;
  - `stateful_replies: false` must give crates/acl semantics exactly. The flag exists today; verify that it also disables the flow verdict cache side effects.
- MD-6 Destination authorization per peer. `AllowedDestinations` per peer, checked on inbound (the IPv6 destination must be in the peer's authorized Subnet set or lease, else drop "ipv6 not authorized") and on outbound ("packet routed to a peer other than the destination's owner" = drop "route owner mismatch").
  - Alternative: nsplane-core inbound destination check per peer (new PeerConfig field `inbound_destinations: Option<Vec<AllowedIp>>`, None = unchecked).
  - Proposal item 7 (SOURCE_NOT_ALLOWED opt-out) is the source-side counterpart and stays conditional.

## NEW workstream ME: Subnet translation (nsplane-nat)
- ME-1 Stateful NAT64-to-LAN (NAPT) filter. Done: `Nat64Lan` with the `Nat64LanSink` / `Nat64LanSource` local-side wrappers, covered by `nsplane-e2e`'s `nat64_lan` tests and the `subnet_gateway` example scenario.
  - API: `Nat64Lan::new(routes: Arc<ArcSwap<Vec<LanRoute { mapped: Ipv6Net, real: Ipv4Net, snat_source: Ipv4Addr }>>>, config: Nat64LanConfig { max_tcp_mss: Option<u16>, port_tries: u8 /*32*/, ... })`, as a PacketFilter on the local side or a pure `forward(&[u8]) -> Option<BytesMut>` / `reverse(&[u8]) -> Option<BytesMut>` pair.
  - Translation: IPv6 TCP/UDP/ICMPv6 echo -> IPv4 with the embedded low-32 destination, rejecting unsafe LAN targets as SubnetRoute::resolve does; the SNAT port is reserved per (snat_source, port) for the flow lifetime; `remove_flow(proto, snat, target)` releases it.
  - Reverse path: reverse translation with TCP MSS clamp; ICMP Fragmentation Needed -> ICMPv6 Packet Too Big with mtu + 20 (min 1280).
  - Differences from nsplane_nat::Translator: stateful, a caller-owned SNAT source, port reservation coupled to host sockets.
  - Replaces: nat::subnet_route translate/SubnetConntrack.
- ME-2 done: `nsplane_nat::Redirect`, a local-side DNAT/SNAT redirect replacing tun_service/rewrite.rs (on `Conntrack`; PortMap's rewrite reused), covered by `nsplane-e2e`'s `redirect` tests.

## Acceptance

- Each item has an `nsplane-e2e` test; defaults keep current behavior and cost nothing when
  unused.
- just check, cross, test-windows, cargo doc -D warnings; data_path bench no regression.

## ActiveForm

Moving the remaining ns data-plane pieces into nsplane

## Dependencies

- **blocked by**: (none)
- **blocks**: ns first release on the engine only; ns migration M6 (MD)
- **related**: 20261003-1300-ns-m4-requests

## Notes
2026-10-03: MA-1..3 and MB-4..6 landed in 36cbe21 (task 20261003-1300-ns-m4-requests).
MA-x1 done by L1 (D9: yes): `Core::force_handshake_on` / `EngineHandle::force_handshake_on`,
covered by `nsplane-e2e`'s `path_hooks::a_handshake_can_start_on_a_candidate_without_moving_the_peer`.
User decisions: D10 a generic message-link transport (no WebSocket dependency in nsplane);
ME-1 and ME-2 (SNAT and DNAT) both in nsplane-nat; MD is evaluated, not implemented, this
round. MB-x, MC and ME run as a BKD campaign (plan 20261003-1600-ns-dataplane-moves).
2026-10-03: MC-1 and MC-2 landed (campaign nsplane-mv-202610031600). The examples' WSS
client now queues datagrams while disconnected (256 entries) instead of dropping them.
MB-x3 and MB-x4 done: `TcpConnection::{unacked, last_ack}` (smoltcp exposes no SND.NXT, so
`unacked` is the socket's send queue: in flight plus bytes held back for the peer's window)
and `NetStackConfig::udp_allow_fragmentation`, covered by `nsplane-e2e`'s
`netstack_progress`.
MB-x1 done: `NetStackHandle::owns` / `Ownership` over a tuple table kept per connection,
flow and socket (not per packet); fragments are `None` until the stack reassembles them;
covered by `nsplane-e2e`'s `netstack_owns` (a `Splitter` routing on `owns`).
MB-x2 done: `nsplane_packet::reassembly::Reassembler` wired into the stack's driver by
`NetStackConfig::reassembly` (default `None`), counted in
`NetStackStats::{reassembled, reassembly_timeout, reassembly_overflow}`; with it `owns`
reports TCP/UDP fragments to a stack address as `Flow` (first fragment, registered tuple)
or `Listener`; covered by `nsplane-e2e`'s `netstack_reassembly`.

### MD assessment (L1, 2026-10-03; not implemented this round)

What moves: ns `tunnel-wg/src/node_l3*` (about 3.2k lines plus 2.3k lines of tests:
target-bound Node/Service/Subnet grants, source binding, same-owner rule, a stateful flow
table with per-protocol idle timeouts and per-peer/global limits, orphan fragments, ICMP
errors matched to flows, Legacy/Observe/Enforce modes), the account `AccountFilter`
(340 lines, the composition and the IPv6 destination checks) and the `crates/acl` call
path (`acl_check_packet`, `FragmentAclGate`). `nsplane-acl` (9.1k lines) already has the
`crates/acl` policy model, matcher, merge, deny scope, fragment gate, reply table,
namespaces, grants, pinholes and the flow hook.

| Item | Size | Notes |
|---|---|---|
| MD-1 per-packet source principal | small-medium | `PeerIdentity` gains a per-source assertion; the flow cache key and the bypass computation must include it |
| MD-3 divert verdict | small | needs the L3 gate's gateway-consumer candidate, so it lands with MD-2 |
| MD-4 fragment parity | small-medium | keying (src, dst, proto, id), TTL and miss = drop, next to today's first-fragment gate |
| MD-5 bypass flags | small | `accept_to_local`, `accept_icmp_echo_reply`; prove `stateful_replies: false` equals `crates/acl` with a differential test |
| MD-6 destination authorization | small in the core | a per-peer `inbound_destinations` check mirrors the existing source check; the outbound "route owner" check disappears when ns expresses leases as allowed IPs |
| MD-2 Node L3 gate | large | port the gate as its own module (tests carry the semantics); an nsplane-side config model mirroring `NodeL3Config` (nsplane cannot depend on ns `control`); an ordered composition where an enforced allow skips the L4 ACL (one combined filter, since `Verdict` has no final-accept); its locks and state tables need the ACL hook treatment to stay off the hot path |

Main risks: semantic parity of the gate (mitigated by porting its tests and a differential
test against the ns implementation on recorded packets), per-packet cost of the stateful
gate, and keeping `nsplane-acl` usable without the account-specific parts (the gate stays
optional and off by default).

Recommendation: its own plan after this round, two workstreams: MD-A (MD-1, 4, 5, 6 and the
`crates/acl` parity tests) and MD-B (MD-2 with MD-3 and the composition). Until M6, ns keeps
`AccountFilter` (option A in the M4 plan).
2026-10-03: campaign nsplane-mv-202610031600 done (MB-x1..x4, MC-1, MC-2, ME-1, ME-2 in main).
MB-x6 needs no code: `NetStackStats::syn_refused` counts the bare SYNs refused (RST) for a
full listener pool, which `NetStackConfig::listener_pool` sizes. User decisions for the next
round (plan 20261003-1630-perf-and-wss): MC-3 approved as recommended (new optional crate
`nsplane-wss` with the WSS dependencies; datagram carrier complete, stream carrier client leg
first, terminate leg when a consumer exists; revised 15:35: terminate leg in scope now, PW
(c)), ADR 2026-10-03-data-channel-protocols-in-nsplane
(every data-channel protocol lives in nsplane), MF-1, MF-2 and MB-x5 after a benchmark
harness against kernel WireGuard and wireguard-go.
