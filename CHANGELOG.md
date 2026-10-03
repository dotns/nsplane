# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `nstun-packet`: packet buffers with header room (`PacketBuf`, `PacketPool`,
  `PacketBatch`), IP/TCP/UDP/ICMP header views and the shared value types (`PeerId`,
  `TransportId`, `Path`, `Ecn`). No I/O, no `unsafe`.
- `nstun-core`: sans-I/O WireGuard engine core over `boringtun::noise`. `Core` takes inputs
  (local packets, datagrams, configuration changes), exposes `poll_timeout`/`handle_timeout`
  and yields outputs (datagrams to transmit, packets to deliver, events). Peers, cryptokey
  routing, a pluggable `PathPolicy` (`StandardRoaming`) and `PacketFilter` chain.
- `nstun`: tokio driver. `EngineBuilder` builds an `Engine` on a `PacketSource`, a
  `PacketSink` and a `Transport` (`UdpTransport`: dual-stack, fwmark, ECN); one owner task
  drives the core, I/O tasks feed it through bounded queues. `EngineHandle` changes peers,
  the private key and the transport at runtime, reads stats and drop counters, and
  `subscribe`s to `Event`s on a broadcast channel. Engine-side drops are counted as
  `DROP_SINK_FULL`, `DROP_SINK_CLOSED`, `DROP_NO_TRANSPORT`, `DROP_TRANSMIT_FULL` and
  `DROP_TRANSPORT_CLOSED`. In-memory `ChannelSource`/`ChannelSink`/`ChannelTransport` for
  tests and embedders.
- `nsplane-noise`: `Tunn::update_timers_at(now, dst)`, `Tunn::time_since_last_handshake_at(now)`
  and `RateLimiter::reset_count_at(now)` run the timers on the caller's clock; the
  no-argument variants use `std::time::Instant::now()`.
- `nsplane-noise`: `Tunn::handshake_count()` counts completed handshakes (monotonic), and
  `Tunn::handle_verified_packet` is public for callers that verify mac1/mac2 with their own
  `RateLimiter`; it does no rate limiting itself.
- `nsplane-core`: `reasons` module with a constant for every `Event::Dropped` reason, the
  core's (e.g. `reasons::HANDSHAKE_REJECTED`) and the driver's; re-exported as
  `nsplane::reasons`, and the `nsplane::DROP_*` constants are aliases of it.
- `nsplane-core`: `Event::Suspended`, `Event::Resumed` and `Event::MtuChanged { mtu }`,
  emitted by the driver only.
- `nstun-tun`: TUN devices as packet sources and sinks: Linux and Android
  (`/dev/net/tun`), macOS and iOS (utun), Windows (Wintun). `Tun::create`, `Tun::from_fd`
  (Unix) and `Tun::split`.
- `nstun-uapi`: the `wg` UAPI (`get=1`/`set=1`) over an `EngineHandle`, including
  `listen_port` and `fwmark` rebinding the UDP transport; `UapiListener` binds
  `/var/run/wireguard/<iface>.sock` on Unix.
- `nsplane`: one engine runs several transports of different types at once (e.g. direct UDP
  next to a relay), keyed by the new `Transport::id`. `EngineHandle::add_transport`,
  `remove_transport` and `replace_transport` change them at runtime and fail with the typed
  `TransportError` (`Stopped`, `Duplicate`, `Unknown`). `DynTransport` (with `BoxFuture`) is
  the object-safe form of `Transport`; `Box<dyn DynTransport>` is a `Transport`. Each
  transport has its own transmit queue and waiting datagrams, so a slow transport does not
  delay another's datagrams; a datagram whose path names no installed transport is dropped
  under `DROP_NO_TRANSPORT`.
- `nsplane`: `EngineHandle::suspend` and `resume` pause the engine without tearing it down
  (e.g. while the host sleeps): no source, sink or transport I/O and no timers run, peers
  and sessions are kept, and handle calls still work. They publish `Event::Suspended` and
  `Event::Resumed`; resuming runs the core's timers once with the current time.
- `nsplane`: the engine watches `PacketSource::mtu` and publishes `Event::MtuChanged` once
  per change; `EngineHandle::mtu` returns the last observed value. Changes made while
  suspended are published once after resuming if the value differs.
- `nsplane-uapi`: `udp_transport(port)` binds the UAPI's transport for the engine builder,
  and `Uapi::with_listen_port` serves an engine built with it.
- `nsplane-tun` (Unix): `adopt_fd` and `Tun::from_raw_fd` adopt an fd passed in by number
  without `unsafe` at the call site (ownership moves to the returned value; a negative or
  closed fd is rejected), and `Tun` implements `AsFd`. The `TunSource` MTU follows the
  interface MTU: on Linux/Android and macOS/iOS `Tun::split` starts a task that polls
  `SIOCGIFMTU` every `MTU_POLL_INTERVAL` (1 s); on Windows the MTU is read once and not
  watched.
- `nsplane-uapi` (Unix): `Uapi::serve_stream` serves the UAPI on one already-connected
  `UnixStream`.
- `nsplane-uapi` (Windows): `UapiListener` listens on a named pipe,
  `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<iface>` (`pipe_path`, as
  wireguard-windows uses) or any pipe name (`bind_path`), so `Uapi::serve` works on Windows
  too. The pipe keeps the default security descriptor (see `UapiListener::bind`).
- CLI: `--tun-fd`/`WG_TUN_FD` adopts an already-open TUN fd and `--uapi-fd`/`WG_UAPI_FD`
  serves the UAPI on an already-connected Unix stream socket next to the standard socket;
  the daemon takes ownership of both fds.
- `nsplane-netstack`: a user-space TCP/IP stack on smoltcp 0.14 for IPv4 and IPv6.
  `NetStack::new(NetStackConfig)` starts it and `NetStack::split` yields a
  `NetStackSource` (`PacketSource`, the stack's egress) and a `NetStackSink` (`PacketSink`),
  which an `EngineBuilder` takes in place of a TUN device. `NetStackHandle` accepts TCP
  connections and UDP flows to any port of the stack's addresses (`incoming_tcp`,
  `incoming_udp`) and opens them (`connect_tcp`, `bind_udp`); `TcpConnection` is
  `AsyncRead + AsyncWrite` with half close, and a `UdpFlow` replies itself or through a
  `UdpReply` handle. The advertised
  MSS follows the configured MTU (`mtu - 40` over IPv4, `mtu - 60` over IPv6), so no
  emitted packet exceeds it. One driver task runs one smoltcp egress turn per ingested
  packet; every queue is bounded and every discarded packet, datagram or connection is
  counted in `NetStackHandle::stats` (`NetStackStats`).
- `nsplane`: `Splitter`, a `PacketSink` that routes each delivered packet to one of several
  sinks of any types by a closure (`Fn(PeerId, &PacketBuf) -> usize`; out-of-range indices
  are counted in `Splitter::misrouted`), and `MergeSource`, a `PacketSource` that merges
  several sources round-robin, for a hybrid local side such as a TUN device next to a
  netstack.
- `nsplane-acl`: accept-only ACL policy engine (ported policy model, layered merge with
  per-rule provenance, deny scope). `AclEngine` swaps the compiled policy atomically on
  `load` (a rejected policy keeps the previous one) and is fail-closed: with no policy
  loaded every request is denied. `AclFilter` is a `PacketFilter` that evaluates inbound
  packets against the engine with each peer's principal from a `PeerIdentity` (e.g.
  `PeerIdentityMap`), gates IPv4 fragments on their first fragment, accepts replies to
  flows the local side opened and reports drops under the `reasons` constants, with
  counters in `AclFilterStats`. `FlowTracker` is a pass-through `PacketFilter` counting
  packets and bytes per flow in a bounded table.
- `nsplane-acl`: rule namespaces per peer source (`namespace` module: `NamespaceId`,
  `NamespaceMember`, `NamespacePolicy`, `OutboundRule`). `AclEngine::store_namespace`,
  `remove_namespace`, `namespaces` and `memberships` change one namespace at a time; the
  default policy applies only to principals in no namespace. Traffic between peers of
  different namespaces is dropped as `reasons::CROSS_NAMESPACE` unless a directed `Grant`
  (`store_grant`, `remove_grant`, `grants`) accepts it. The engine state (default policy,
  namespaces, grants, pinholes) is one snapshot swapped atomically; `clear_all` removes it
  all.
- `nsplane-acl`: opt-in outbound rules (`NamespacePolicy::outbound`, union across a peer's
  namespaces); outbound packets to a restricted peer pass only by rule, outbound pinhole or
  reply allowance, else `reasons::OUTBOUND`. Reply allowances that depend on a removed
  grant or closed pinhole are revoked on their next lookup. New `AclFilterStats` counters
  `cross_namespace`, `outbound_denied`, `outbound_replies`, `reply_revoked`.
- `nsplane-acl`: source-gated app pinholes (`pinhole` module). `AclEngine::open_pinhole`
  opens one peer, direction, protocol and port in an app namespace when a source namespace
  allows the app kind (`allow_app_pinholes`), else `PinholeError::NotPermitted`; the
  `PinholeGuard` closes it on drop. Pinholes expire on the engine clock
  (`AclEngine::with_clock`, `expire_pinholes`) and are counted per close reason in
  `PinholeStats`. A `namespaces` bench (`cargo bench -p nsplane-acl --bench namespaces`).
- `nsplane-e2e`: `acl_namespaces` tests namespaces, grants, outbound rules and pinholes
  under running engines.
- `nsplane-examples`: `app_session`, a file transfer through pinholes between existing
  peers and between session-only peers (not-permitted, revoke, cross-namespace and, with
  `--tun`, TUN outbound steps); `just e2e-examples` scenarios `app_session` and
  `app_session_tun`.
- `nsplane-examples` (`examples/`, not published): runnable examples on the public APIs,
  each with `--help` — `udp_pair`, `tun_node`, `netstack_node`, `hybrid`, `acl_gateway`,
  `fd_bridge`, `events_stats` — sharing node, echo/check and status-file flags. See
  `examples/README.md`.
- `nsplane-examples`: a single-port relay (`relay_server`) that is also a WireGuard node:
  one UDP socket carries WireGuard to its own engine, WireGuard between other peers relayed
  by mac1 and receiver index, and signed control messages (`register_source`, reflexive
  address); targets come from flags and a reloaded JSON config. Every node example gains
  `--transport relay`: capability discovery, registration, the reflexive address and a
  direct-first path ladder with relay fallback; `relay_transport` shows it in one process.
  The wire format is in `docs/decisions/2026-10-02-single-port-relay.md` (Proposed).
- `nsplane-examples`: WebSocket over TLS as a relay carrier. `relay_server --wss-listen`
  accepts WSS clients with a self-signed certificate written for pinning (`--wss-cert-out`);
  `--transport wss` reaches the relay over WSS with that certificate as the only trust
  anchor, reconnecting with backoff; `relay_transport --carrier wss`.
- `just e2e-examples` (`scripts/e2e/examples.sh`): the example binaries in containers as a
  12-cell matrix (TUN, netstack, bridge by fd and by channel x UDP, relay over UDP, relay
  over WSS; kernel WireGuard peers in the UDP column) and scenarios (hybrid, ACL gateway,
  native WireGuard through the relay, the path ladder, NAT hole punching, plain WireGuard
  compatibility). The e2e image adds `socat`, `iptables` and `tcpdump`.
- `nsplane-packet`: `PacketBuf::headroom` and fallible `advance`, `reserve_front`, `from_shared`
  returning `BoundsError` instead of panicking.
- `nsplane-packet`: `PacketPool::get_len` hands out a packet of a given length without
  re-zeroing bytes a pooled buffer already initialized; pooled buffers keep their bytes.
- `nsplane-nat`: IPv4/IPv6 translation and service-publishing NAT as `PacketFilter`s. The
  address model is a validated, immutable `TranslationTable` (`TranslationTableBuilder`):
  every peer owns a /127 IPv6 group (`node6`, `node4`) presented locally as `alias4` and
  optionally `alias6`, this node as `self4 <-> node4`, and IPv4 LAN prefixes paired with IPv6
  /96 prefixes. `Translator` translates statelessly as RFC 7915 describes (`alias4 <-> node4`,
  `self4 <-> node4`, `alias6 <-> node6`, `lan4 <-> lan6`; ICMP/ICMPv6 including the packet
  quoted in errors, fragments, incremental checksums), swaps its table atomically
  (`Translator::store`) and counts in `TranslatorStats`; a fragmented IPv4 UDP datagram
  without a checksum is reassembled first, and completes only when its first fragment
  arrives first. A translated packet grows by 20 bytes (28 with a fragment header) in place
  when its buffer has the room; otherwise it is copied into a larger buffer
  (`TranslatorStats::grown_copies`) instead of being dropped, and `reasons::NO_ROOM` only
  bounds the result at the largest IPv6 packet. Each peer's allowed IPs must contain its `alias4/32`, its LAN IPv4
  prefixes, `alias6`, `node4`, `node6` and its `lan6` prefixes, since the core routes and
  checks sources before the filters run. `PortMap` publishes local services by DNAT/SNAT
  (`PortMapRule`, optionally per peer, with ICMP errors rewritten) on a bounded `Conntrack`
  (LRU eviction, per-protocol idle timeouts with TCP state, injectable clock). The
  `checksum` module has RFC 1624 incremental update helpers.
- `nsplane`: an optional fragmentation stage on the local path,
  `EngineBuilder::fragmenter(FragmentConfig)`, keeps local packets within the source MTU
  before they enter the core: oversized IPv6 is answered with an ICMPv6 Packet Too Big,
  oversized IPv4 with an ICMP Fragmentation Needed (DF set) or split into fragments (DF
  clear). The IPv4 ceiling is the MTU for native destinations and MTU - 20 (fragments
  sized for MTU - 28) for destinations `FragmentConfig::translated` marks as translated
  (e.g. `Translator::ipv4_translated_predicate`), whose zero UDP checksums are filled in
  before splitting. Errors are delivered as coming from the peer the destination routes to
  and are rate-limited (burst 10, then 5 per second).
- `nsplane-core`: `Core::route(dst)` returns the peer a packet to `dst` is routed to (the
  longest allowed-IP match), e.g. for the `peer` of `Core::inject_inbound`.
- `nsplane-examples`: `translate_node` (a TUN node with a `Translator`: `--self`, `--map`,
  `--lan`) and `port_map` (a TUN node with a `PortMap`: `--publish`, conntrack timeouts and
  `--max-flows`); `just e2e-examples` scenarios `translate_node` (an IPv4-only client
  container behind the translating node reaches an IPv6-only kernel WireGuard peer) and
  `port_map`.
- `nsplane-e2e`: `translate`, `port_map` (including the full
  `[AclFilter, PortMap, Translator]` stack) and `fragment` tests between engines.
- `nsplane`: batched I/O. `PacketSource::recv_batch(&mut PacketBatch)`,
  `PacketSink::send_batch(&mut VecDeque<(PeerId, PacketBuf)>)`,
  `Transport::recv_batch(&mut PacketBuf, &mut VecDeque<(Path, PacketBuf)>)` and
  `Transport::send_batch(&[(Path, PacketBuf)], &mut usize)` are additive default methods
  (one packet or datagram at a time) that `DynTransport` mirrors. The engine's I/O tasks
  move up to `MAX_BATCH` (64) packets or datagrams per call and keep backpressure, the
  handback of unsent datagrams on stop and buffer recycling.
- `nsplane-tun` (Linux, Android): virtio-net segmentation offload. `Tun::create` opens the
  device with `IFF_VNET_HDR` and enables checksum offload and TSO4/6 (`TUNSETOFFLOAD`), plus
  USO4/6 when the kernel accepts it, and falls back to a plain `IFF_NO_PI` device when the
  kernel supports neither; `Tun::offload` reports the outcome (`Offload { vnet_hdr, tso, uso
  }`). `Tun::create_with(name, TunOptions::new().offload(false))` opts out. The source reads
  up to 64 KiB plus the 10-byte header at once and segments TCP/UDP super-packets into
  pooled `PacketBuf`s no larger than the MTU, each with capacity for the MTU plus 28 bytes
  so an IPv4 -> IPv6 translator grows them in place; the sink coalesces runs of TCP packets (and
  of equally sized UDP datagrams with USO) of one flow into one super-packet, written with
  one `writev` of the header and the packet pieces (no join copy). An adopted fd uses vnet
  framing only if it was opened with `IFF_VNET_HDR` (segmented on read, written as
  `GSO_NONE`). macOS, iOS and Windows are unchanged. An `offload` bench (`cargo bench -p
  nsplane-tun --bench offload`): a 64 KiB TCPv4 super-packet splits into 48 segments in
  4.58 us, 48 segments coalesce into one in 6.17 us.
- `nsplane`: UDP segmentation offload through `quinn-udp` 0.6.3. `UdpTransport::bind` turns
  it on: GSO sends in `send_batch` on every platform that has it, GRO receives in
  `recv_batch` on Linux and Android, where every datagram of a GRO train is a
  `PacketBuf::from_shared` slice of the read buffer (no copy, headroom 0; the core opens it
  in place at any headroom). `UdpTransport::bind_with_offload(id, addr, false)` binds the
  Phase 3+4 socket (no `quinn-udp` setup, the OS's default fragmentation, the previous
  `cmsg` ECN path); `set_offload` and `offload` switch and report it at runtime
  (`set_offload(false)` on an offload-bound socket keeps DF, `set_offload(true)` on a
  socket bound without it fails with `Unsupported`). With offload on, outer datagrams
  above the path MTU fail with `EMSGSIZE`; the engine counts them under
  `TRANSPORT_SEND_ERROR` (`nsplane_core::reasons::TRANSPORT_SEND_ERROR`, alias
  `nsplane::DROP_TRANSPORT_SEND_ERROR`; `drop_counters`, `Event::Dropped`). Where
  `quinn-udp` cannot set the socket up (Wine), sends fall back to plain `send_to`. A
  `udp_offload` bench (`cargo bench -p nsplane --bench udp_offload`, 64 x 1420 B over
  loopback): ~8 us with offload, ~85 us without.
- `nsplane`: `UdpTransport::bind` requests 4 MiB socket buffers (`SO_RCVBUF`,
  `SO_SNDBUF`); `set_recv_buffer_size`, `set_send_buffer_size`, `recv_buffer_size` and
  `send_buffer_size` change and report them (Linux reports twice the granted size). The
  kernel clamps the request to `net.core.rmem_max` / `net.core.wmem_max`, so large bursts
  need those sysctls raised (e.g. to 4194304); `SO_RCVBUFFORCE` is not used.
- `nsplane-uapi`: `Uapi::with_external_transport(handle, port)` serves an engine whose
  transport under the UAPI's id is not a UDP transport the UAPI owns (a relay or WSS
  carrier); `bind_transport` fails there with `Unsupported`.
- `nsplane-examples`: `--no-offload` on every node example (including `hybrid` and
  `relay_server`; `node::create_tun`, `node::bind_udp`) opens a plain TUN device and binds
  UDP without GSO/GRO; the startup logs name the modes (`offload=<mode>`,
  `udp_offload=<mode>`).
- `nsplane-e2e`: `offload_batch`, `offload_udp` and `offload` tests, and
  `nsplane-tun`'s `linux_offload` tests (root), cover batching, UDP GSO/GRO and TUN
  offload. `just e2e-examples` adds the scenarios `offload_iperf` (iperf3 TCP and UDP
  between a `tun_node` and kernel WireGuard with offload on and off, medians over
  `NSPLANE_E2E_IPERF_REPS` runs at UDP rate `NSPLANE_E2E_IPERF_RATE`),
  `offload_fallback`, `offload_fallback_hybrid` and `offload_fallback_relay`; the e2e image
  adds `iperf3`. `offload_iperf` medians (3 runs, Mbit/s, offload on | off, shared host):
  at `-b 0` TCP a->k 5373 | 2911, k->a 5657 | 4228, UDP a->k 5673 (57.4 % loss) | 2725
  (83.1 %), k->a 5162 (0 %) | 4944 (1.5 %); at `-b 2G` TCP a->k 4460 | 3054, k->a 4806 |
  4297, UDP ~1999 (0 %) both ways on and off. The UDP a->k loss at `-b 0` is on the
  kernel/iperf3 side.

### Changed
- Breaking: `Engine` and `EngineHandle` (and `EngineBuilder`'s third parameter) lose their
  transport type parameter. `EngineBuilder::transport` adds a transport and may be called
  several times; `EngineBuilder::build` returns `Result<Engine, BuildError>` and fails with
  `BuildError::NoTransport` without a transport and `BuildError::DuplicateTransport` when
  two share an id. `EngineHandle::set_transport` is replaced by
  `EngineHandle::replace_transport`, which needs a transport with the same id installed.
  `UdpTransport::id` and `ChannelTransport::id` are now `Transport::id`.
- Breaking: `nsplane-uapi` installs its transport with `add_transport` the first time and
  `replace_transport` afterwards; `Uapi::handle` returns a non-generic `EngineHandle`.
- Breaking: the project is renamed **nsplane** (`github.com/dotns/nsplane`) and every crate
  lives under `crates/`: `boringtun` → `nsplane-noise`, `boringtun-cli` → `nsplane-cli`
  (binary `nsplane-cli`), `nstun` → `nsplane`, `nstun-core` → `nsplane-core`,
  `nstun-packet` → `nsplane-packet`, `nstun-tun` → `nsplane-tun`, `nstun-uapi` →
  `nsplane-uapi`, `nstun-e2e` → `nsplane-e2e`. The e2e scripts read `NSPLANE_E2E_*` and
  `NSPLANE_E2E_LIB_*`. Removed with it: the C FFI and JNI bindings (`ffi-bindings` and
  `jni-bindings` features, `wireguard_ffi.h`, the `staticlib`/`cdylib` crate types), the
  upstream crypto primitive benches, and the upstream banner and logo images. Copyright,
  origin and trademark notices live in `LICENSE.md`.
- Breaking (CLI): `boringtun-cli` runs on the async engine (`nstun`, `nstun-tun`,
  `nstun-uapi`) on a tokio multi-thread runtime with `--threads` workers; SIGTERM stops it
  as well as SIGINT. The UDP socket is bound to an ephemeral port at startup until
  `wg set ... listen-port` rebinds it. Removed flags: `--disable-connected-udp` and
  `--disable-multi-queue` (they configured the synchronous device only); `--tun-fd` and
  `--uapi-fd` are kept on top of `nsplane-tun`'s safe fd adoption. The privilege drop
  reads `SUDO_UID`/`SUDO_GID` instead of `getlogin`.
- Breaking: replace `ring` with `aws-lc-rs` for ChaCha20-Poly1305, and with `subtle` for
  constant-time comparisons. `ring` is no longer a dependency.
- Edition 2024, MSRV 1.95, workspace-wide lint policy (warnings denied, clippy pedantic and
  nursery, no `unwrap`/`expect`/`panic` in runtime code).
- Breaking: `Tunn::encapsulate` and the session code return
  `WireGuardError::DestinationBufferTooSmall` instead of panicking on short buffers.
- Breaking: `AllowedIps::insert` takes the prefix length as `u8`.
- `nsplane-core` drives every tunnel's timers (handshake retries, keepalives, rekey, session
  expiry, the rate limiter reset) and `last_handshake` with the `now` it is given instead
  of nsplane-noise's own clock.
- `nsplane-core` verifies and rate-limits each handshake message once with the shared gate,
  so `handshake_rate_limit` is the real per-source rate (it used to allow twice that).
- `nsplane-core` emits `Event::HandshakeCompleted` once per completed handshake, including
  several within one timer tick. The responder reports it when the initiator's first data
  message confirms the session.
- Breaking: `PeerStats::rx`/`tx` and `Event::PeerStats::rx`/`tx` (and with them the UAPI
  `rx_bytes`/`tx_bytes` and `wg show` transfer) count bytes on the wire, like kernel
  WireGuard: whole handshake, keepalive and data datagrams accepted from or sent to the
  peer, without cookie replies. They used to count IP payload only. The payload is in
  `data_rx` and the new `data_tx` (plaintext sealed for the peer).
- Breaking (CLI): `boringtun-cli` is a Linux/macOS development tool. It runs in the
  foreground, logs to stderr, and no longer daemonizes (`-f`/`--foreground` and `--log` are
  gone, so is the unmaintained `daemonize` dependency). Argument parsing uses clap derive;
  core dumps are disabled at startup and panics are logged.
- `nsplane`: backpressure is per transport: each transport has its own transmit queue and
  bounded backlog, and the engine stops reading local packets only while every installed
  transport's backlog is full, so a stalled transport (e.g. a relay) no longer holds back
  peers on other transports; its own local packets are dropped under `DROP_TRANSMIT_FULL`
  instead. `remove_transport` counts the datagrams still queued for the transport under the
  new `DROP_TRANSPORT_REMOVED` (`nsplane_core::reasons::TRANSPORT_REMOVED`) instead of
  dropping them silently; `replace_transport` carries them over to the new transport in
  order.
- Breaking: `nsplane-core`'s `Input::Datagram` takes the datagram by value
  (`data: PacketBuf`) and `Input` loses its lifetime parameter. The core consumes the
  datagram: a packet it carries is decrypted in place and delivered in the same buffer
  (no buffer swap, no copy), any other datagram's buffer goes to the core's pool. Callers no
  longer recycle the datagram after `handle_input`. Local packets are sealed in place with
  the data header in their headroom (copied into a pooled buffer only when the headroom is
  smaller than the data header), and the timers, queue flushes and handshake replies no
  longer zero-fill their buffers on every use.
- Behaviour change: `nsplane-core`'s `PacketFilter` chain is an onion. Filters are installed
  from the wire side to the local side; decrypted packets run through them in install order
  and local (outbound) packets in reverse install order. The recommended stack is
  `[AclFilter, PortMap, Translator]`, so the ACL and the port map see overlay IPv6 in both
  directions. Chains whose filters depend on running in install order outbound must be
  reviewed.

### Removed
- Breaking: the `boringtun::device` module and the `device` feature (TUN, epoll/kqueue and
  Windows event loops, UDP sockets, UAPI). Use `nstun`, `nstun-tun` and `nstun-uapi`.
  `boringtun` no longer depends on `socket2`, `thiserror`, `wintun-bindings`, `windows-sys`,
  `ip_network` or `ip_network_table`, nor on the `nix` `user` feature.
- `just integration` and the upstream integration tests that ran against the device.
- Breaking: the `mock-instant` features of `nsplane-noise` and `nsplane-core`; tests drive
  the timers through the `_at` methods and the core's `now` instead.

### Fixed
- `nsplane-uapi`: `listen_port=` and `fwmark=` never replace a transport the UAPI does not
  own: over `Uapi::with_external_transport` the reported value is a no-op and any other
  fails with `EADDRINUSE`. `tun_node` uses it for relay and WSS transports, which
  `wg set <if> listen-port` used to replace with plain UDP.
- e2e: `scripts/e2e/linux.sh` and `lib.sh` default to PID-derived prefixes
  (`nsplane-e2e-$$`, `nsplane-e2e-lib-$$`; the env overrides stay) and remove their
  per-prefix images at cleanup, so concurrent runs no longer remove each other's
  containers.

### Security
- Cookies (mac2) cover the source port as well as the IP, as the whitepaper requires.
- Handshake rate limiting counts per source IP, so one flooding source no longer pushes every
  peer into cookie mode; a device-wide budget (10x the per-source limit) remains as backstop.
- Enforce `Reject-After-Messages`: a sending key never wraps its nonce, and received counters
  at the limit are rejected. Keys that reach `Rekey-After-Messages` are renegotiated.
- Malformed base64 keys are rejected instead of being read as an all-zero key.
- Decapsulated packets are only accepted when the longest allowed-IP match of their source
  is the sending peer; a peer could previously use addresses inside another peer's subnet.
- Cookie replies no longer move the peer's endpoint (roaming).

### Added
- Windows support for the `device` feature: Wintun interface (`wintun.dll` next
  to the executable), one blocking thread per task (Wintun, UDP sockets, timers, UAPI), and
  the UAPI on the named pipe `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>`
  restricted to SYSTEM and Administrators, as `wg.exe` expects. Ctrl-C stops the device.
- The UAPI (`device::uapi`) and the per-packet logic are shared by the Unix and Windows
  devices.
- Zero-copy data path: `Tunn::encapsulate_in_place` seals a packet where it was read (behind
  `DATA_HEADER_SZ` bytes of header room) and `Tunn::decapsulate_in_place` decrypts transport
  data inside the receive buffer. The device reads TUN packets straight into the
  encapsulation buffer and decrypts UDP datagrams in place. `encapsulate`/`decapsulate` remain
  as copying wrappers.
- Messages are parsed and built through `zerocopy` views (`noise::wire`) instead of
  hand-written offsets.
- `data_path` benchmark (copying versus in-place round trip).
- `scripts/e2e/linux.sh` (`just e2e`): interop test against kernel WireGuard in two containers.
- `Tunn::set_preshared_key` and `Tunn::set_persistent_keepalive`. The UAPI updates existing
  peers in place (endpoint, keepalive, preshared key, allowed IPs including
  `replace_allowed_ips`) instead of panicking.

### Changed
- Breaking: `Tunn::decapsulate` and `RateLimiter::verify_packet` take the source as
  `Option<SocketAddr>`.
- Breaking: `Peer` no longer keeps its own allowed-IP table; the device routing table is the
  only source of truth. `Peer::new` lost its `allowed_ips` argument.
- Data packets are padded to a multiple of 16 bytes (when the buffer has room).
- The anti-replay window grows from 1024 to 8192 packets, like Linux and wireguard-go.
- Timers: the passive keepalive is due 10 s after the first unanswered data packet, a
  handshake 15 s after the first unanswered data packet sent; the persistent keepalive is sent
  as soon as it is enabled and is suppressed while traffic flows; handshake retries add
  0-333 ms of jitter.

### Fixed
- The deleted `device/tun_linux.rs` passed an `ifreq` of the wrong size to the TUN ioctls;
  `nstun-tun` uses the kernel's 40-byte `ifreq`.
- UAPI `set`: settings of one peer section no longer leak into the next section.
- UAPI `get` reports `last_handshake_time_*` as wall-clock Unix time, as `wg` expects, instead
  of the age of the handshake ("56 years ago").
- CLI: `WG_SUDO=1` is accepted again (any boolish value).
- Re-binding the listen port now unregisters the previous UDP sockets; the old sockets were
  leaked because their events were cleared under the wrong fd.
- The UAPI socket is bound at `/var/run/wireguard/<name>.sock` without a doubled slash.
- JNI: `x25519_key_to_hex`/`x25519_key_to_base64` no longer leak the string.
- FFI/JNI: NULL tunnel pointers and short buffers return an error instead of crashing.
- TUN devices close their fd on every error path (Linux and macOS).
- `Debug` output redacts preshared keys, chaining keys, and cookies.

## [0.7.1] - 2026-05-01

### Security
- use a 64-bit nonce counter on 32-bit platforms to avoid the possibility of nonce re-use with large REKEY_AFTER_TIME
- CLI only: remove vulnerable dependency: `atty`

### Fixed
- use portable-atomic to support targets without native 64-bit atomics

## [0.7.0] - 2026-01-09

### Changes

- Breaking: make `noise::Tunn::new` infallible
- Upgrade vulnerable dependencies: ring, x25519-dalek
- Fix a compilation error on freebsd
- Fix incorrect socket type in `device::Peer::connect_endpoint`