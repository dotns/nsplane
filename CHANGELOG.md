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
- CLI: `--crypto-workers`/`WG_CRYPTO_WORKERS` sets the engine's crypto workers and `--no-offload`/`WG_NO_OFFLOAD` opens the TUN device and binds the UDP socket without segmentation offload.
- Benchmarks: `just bench-wg` (`scripts/bench/wg-compare.sh`) compares nsplane-cli, kernel
  WireGuard and wireguard-go in pinned containers (TCP, UDP loss, latency, CPU per GB), plus
  nsplane's user-space mode through the `netstack_bench` example; results in
  `docs/architecture.md` (*Against WireGuard implementations*).
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
  without a checksum is reassembled first, in any fragment order. A translated packet grows by 20 bytes (28 with a fragment header) in place
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
  `Transport::send_batch(&[(Path, PacketBuf)], &mut usize, &mut usize)` are additive default methods
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
- `nsplane-acl`: the ACL as a per-flow hook. `AclEngine::generation` increases on every
  published change; `AclFilter` caches each peer's resolved principal and the verdict of each
  TCP/UDP flow's first packet from a namespace member in its reply table, under the policy and identity
  generations, so established flows skip the evaluation; peers whose namespaces (or the
  default policy) accept everything bypass it. `PeerIdentity::generation` (default 0: not
  cached) versions identities, and `PeerIdentityMap` bumps it on every change. Verdicts are
  the same as a full evaluation (differential test). New counters
  `AclFilterStats::pending_evictions` and `verdict_evictions`; `nsplane-e2e` `acl_hook`
  tests. The reply, pending and fragment tables evict their least recently seen (fragments:
  oldest) entry in O(1) instead of scanning the full table.
- `nsplane`: `EngineHandle::queue_stats` reports the capacity and high-water mark of every
  bounded queue of the engine (`QueueStats`, `QueueDepth`: commands, local packets,
  received datagrams, deliveries, recycled buffers, the transmit queues and backlogs, events);
  `take_queue_stats` also restarts the marks for windowed measurements. The owner task keeps
  the marks without locks or atomics. Measured defaults: the queue capacity stays at 1024
  and the command queue at 64 (see docs/architecture.md, "Queue depths").
- `nsplane`: optional crypto worker pool, `EngineBuilder::crypto_workers(n)` (off by
  default; 0 or 1 keeps the cryptography on the owner task). With 2 or more workers the
  encryption of local packets and the decryption of received transport data run on `n`
  worker tasks, sharded by peer, so each peer's packets keep their order in both directions
  while different peers are encrypted in parallel; routing, filters, handshakes, timers,
  counters and events stay on the owner task, and handle calls that read or change peers or
  counters wait for the packets with the workers (see docs/architecture.md, "Crypto worker
  pool").
- `nsplane-core`: `Core::handle_input_deferred` returns the encryption or decryption of a
  data packet as a `CryptoJob` (`Send`, locks only its peer's tunnel) to run on another
  thread with `CryptoJob::run`; `Core::complete_job` finishes it in the core.
- `nsplane-nat`: `Translator::set_mtu(u16)` and `Translator::mtu()` (default 1280, the IPv6
  minimum; applications set the tunnel MTU, as `translate_node` does) bound the size of a
  reassembled datagram, and `reasons::REASSEMBLED_TOO_BIG` reports one that is dropped as
  larger. `translate_node`'s status file adds the five new `TranslatorStats` counters under
  `extra.translate`.
- `nsplane-examples`: `translate_node` honours `--no-offload` (it opens its TUN device with
  `node::create_tun`); its e2e scenario adds a 1420-byte IPv4 ping with offload off that
  checks `grown_copies` stays 0.
- Optional features and defaults: a section in `README.md` and `docs/architecture.md` lists
  every optional feature with its switch, default and cost when off, the crates a minimal
  client needs, a minimal IPv4-only client, and that offload never waits for more packets.
- `nsplane-core`: `Core::handle_datagrams` and `Core::handle_locals` take a batch of
  received datagrams or local packets and process them exactly like feeding each to
  `Core::handle_input` in order (same outputs, events, drops and counters), sharing one
  schedule update, the output queue room and the session, route and peer lookups of
  consecutive packets; `Core::handle_datagrams_deferred` and `Core::handle_locals_deferred`
  do the same for `Core::handle_input_deferred`. A batch of 32 costs 3910 / 18980
  instructions per 64 B / 1420 B round trip, 11.8 % / 2.7 % below the device-equivalent
  baseline (see docs/architecture.md, "Performance").
- `nsplane-core`: `CoreConfig::crypto_jobs` (default `false`) decides whether
  `Core::handle_input_deferred` hands out `CryptoJob`s; the engine sets it with 2 or more
  crypto workers.
- `nsplane`: `QueueStats::crypto` (jobs with the crypto workers, capacity the bound of jobs
  in flight) and `QueueStats::crypto_done` (batches waiting for the owner task); both are
  zero without workers.
- `nsplane`: `FragmentStats` and `EngineHandle::fragment_stats` report the fragmentation
  stage's counters (packets fragmented, fragments emitted, Packet Too Big and Fragmentation
  Needed errors sent, oversized packets dropped for the rate limit, for no route or without
  an error); all zero without a stage. The drops are also counted in `drop_counters` under
  the new reasons `DROP_FRAGMENT_OVERSIZE`, `DROP_FRAGMENT_NO_ROUTE` and
  `DROP_FRAGMENT_RATE_LIMITED` (`reasons::FRAGMENT_*` in `nsplane-core`).
- `nsplane`: a side channel on `UdpTransport` for datagrams of another protocol sharing the
  port. `UdpTransport::with_side_channel(classify, capacity)` returns the transport, a
  `SideSender` and a receiver of `SideDatagram`s (`from`, `datagram`): every received
  datagram `classify` picks (GRO segments one by one) is taken out of `recv` and
  `recv_batch` and never reaches the engine; a full or closed receiver drops it.
  `SideSender::send_to` sends on the transport's socket, synchronously and best effort
  (`WouldBlock` when the socket buffer is full, no ECN mark), and `SideSender::stats`
  returns `SideStats { received, dropped }` (on the sender, not in `TransportStats`).
  Without a side channel nothing is classified and nothing changes; a capacity of 0 is raised to 1
  and a second call replaces the channel.
- `nsplane`: `LinkTransport`, an opt-in `Transport` to one peer over a message link the
  embedder dials (one datagram per message), with the `LinkDialer`, `LinkSender` and
  `LinkReceiver` traits, `LinkState` (`Connected`, `Disconnected`, reported to
  `LinkDialer::on_state`) and `LinkConfig` (`queue` 256, `read_idle_timeout` `None`). Sends
  wait in the queue, also while no link is up; on a full queue `send` fails with
  `WouldBlock` and the engine counts `DROP_TRANSPORT_SEND_ERROR`. A lost link (closed,
  failed or idle) is dialed again at once, after a failed dial too; the dialer owns the
  backoff. Received datagrams come from the peer's address, and sends to another address
  are dropped. `nsplane` has no WebSocket or TLS dependency.
- `nsplane`: `LinkState::Rejected(u16)`, the HTTP status with which the far end refused a
  link (e.g. 401 or 403). Dialers report it to their own observers; `LinkTransport` itself
  never does.
- `nsplane-wss`, a new optional crate of WebSocket-over-TLS carriers (tokio-tungstenite,
  rustls with aws-lc-rs; `nsplane` gains no dependency). All share `WssConfig` (URL,
  `connect_addr`, `server_name`, extra headers, a `BearerProvider` for
  `Authorization: Bearer`, backoff 2 s doubling to 60 s, pings every 10 s, read idle 35 s,
  connect timeout 10 s) and `WssTls` (`Roots(RootCertStore)` or `Config(Arc<ClientConfig>)`;
  no system or web PKI roots are bundled). A 401 or 403 on the upgrade is reported as
  `LinkState::Rejected`; after a 401 the next dial waits for a new bearer token.
  - `WssDialer`, a `LinkDialer` for `LinkTransport` (`into_transport`, `state`, `stats` as
    `WssStats`): one binary message per datagram, as ns `OpaquePump` and the examples' relay.
  - `frame`: the `WsFrame` codec of ns `tunnel-ws` and NSGW (`[stream_id u32][command u8]
    [payload]`; OPEN_V4/OPEN_V6, DATA, CLOSE, CLOSE_ACK), byte-identical to ns.
  - `WssStreamClient` (`open_tcp` -> `WssTcpStream`, `AsyncRead` + `AsyncWrite`;
    `open_udp` -> `WssUdpFlow`; `connect`, `state`, `stats` as `WssStreamStats`), the
    client leg of ns `proxy`: every TCP stream and UDP flow shares one session until it
    holds `WssStreamLimits::max_streams_per_session` (1024, NSGW's default per-session cap)
    live ones, then another session is dialed. `shutdown` sends CLOSE behind the written
    data and keeps reading until the peer's CLOSE or CLOSE_ACK.
  - `WssStreamServer` (`new`, `with_events`, `run`, `state`, `stats` as `WssServerStats`),
    the terminate leg ported from ns `tunnel-ws` `WsTunnel`: it dials the relay, asks the
    embedder's `WssResolver` for each OPEN's backend (`WssOpen` -> `SocketAddr` or
    `Denied`), relays TCP and UDP to it and reports `WssStreamEvent`s (`Open`, `Close`
    with a `WssCloseReason`). Bounded by `WssServerLimits` (4 MiB per stream, 32 MiB per
    session, 64-frame stream queue, control 64 / data 256 queues, 1024 streams).
  - Tests: unit tests in the crate, `crates/nsplane-wss/tests/stream.rs` (client and server
    through a TLS test relay, frames checked against the ns layouts) and `nsplane-e2e`
    `wss_datagram` (two engines over `WssDialer`).
- `nsplane-e2e`: `udp_side_channel` (side datagrams beside a WireGuard transfer, offload on
  and off, an unread receiver) and `link` (transfer, redial, the bounded queue, the read
  idle timeout over an in-memory link).
- `nsplane-nat`: `Nat64Lan`, a stateful NAT64 to an IPv4 LAN (NAPT) for subnet routing,
  ported from ns `SubnetRoute` / `SubnetConntrack`. A `LanRoute` maps an IPv6 /96
  (`mapped`) to an IPv4 prefix (`real`) with a `snat_source`; IPv6 TCP, UDP and ICMPv6 echo
  to `mapped` plus a safe LAN address become IPv4 from `snat_source` with a port (or echo
  identifier) reserved per flow through the caller's `SnatPorts` (`DefaultSnatPorts` in
  memory; `Nat64LanConfig::port_tries`, 32), and the LAN's replies (and Fragmentation
  Needed, as Packet Too Big) are translated back; optional TCP MSS clamp
  (`Nat64LanConfig::max_tcp_mss`), routes replaced through an `ArcSwap`, flows in a bounded
  `Conntrack` with idle timeouts, `Nat64Lan::remove_flow` and `Nat64LanStats` (unsafe
  targets, ambiguous routes and port exhaustion counted separately). As ns, translated
  IPv4 packets leave DF clear; `Nat64LanConfig::set_df` opts into RFC 7915 DF above 1260
  bytes (Fragmentation Needed then comes back as Packet Too Big, at the risk of a PMTU black
  hole when the LAN filters ICMP). As ns, a destination that more than one route resolves is
  dropped (`reasons::AMBIGUOUS_ROUTE`) rather than translated by the first route. The routes
  gate every forward packet; a flow keeps its SNAT address across a route replacement, and
  the flows of a removed route are revoked with `Nat64Lan::remove_flow`, as ns. `LanRoute` prefixes are
  `(Ipv6Addr, u8)` / `(Ipv4Addr, u8)` pairs validated by `LanRoute::new`, like
  `LanPrefix`, as no IP network crate is a dependency. The translation runs on the local
  side: `Nat64LanSink` and `Nat64LanSource` wrap the engine's sink and source; nothing
  runs unless they are installed. `nsplane-nat` now depends on `nsplane` (for the
  wrappers); `nsplane` and `nsplane-tun` still do not depend on `nsplane-nat`.
- `nsplane-nat`: `Conntrack::remove` removes a flow by either direction's tuple
  (`ConntrackStats::removed`), and `Conntrack::with_removal_hook` reports every flow that
  leaves the table (expired, evicted, retained out or removed).
- `nsplane-e2e`: `nat64_lan` tests: an IPv6 client engine reaches an IPv4 netstack LAN host
  behind a gateway engine with wrapped local side (TCP and UDP echo, ICMPv6 echo), with
  unsafe targets, port exhaustion and `remove_flow` checked. `nsplane-examples`:
  `subnet_gateway` (a TUN node with `--route <mapped>/96=<real>,snat=<IPv4>`) and its
  `scripts/e2e/examples.sh` scenario against kernel WireGuard.
- `nsplane-nat`: `Redirect`, a local-side redirect (DNAT with the reverse SNAT) of IPv4
  TCP/UDP flows to an endpoint a decision closure picks per new flow (`RedirectDecision`),
  ported from ns `tun_service/rewrite.rs`. `forward` / `reverse` rewrite a `PacketBuf` in
  place with incremental checksums and return a `RedirectVerdict`; flows live in a
  `Conntrack` (bounded, idle expiry) and go through `remove_flow` and `retain`;
  `original_destination` reports the service address of a flow the endpoint accepted;
  `RedirectStats` counts the outcomes. Drop reasons in `nsplane_nat::redirect::reasons`.
- `nsplane-netstack`: `TcpConnection::unacked` (bytes written and not yet acknowledged by
  the peer, including bytes the socket still holds back for the peer's or the congestion
  window, i.e. smoltcp's send queue; it is not SND.NXT - SND.UNA) and `TcpConnection::last_ack` (when the stack last saw the peer
  acknowledge new data, `None` before it did) report a connection's send progress; the
  driver writes them once per turn into atomics, and they stay readable after the
  connection closed.
- `nsplane-netstack`: `NetStackConfig::udp_allow_fragmentation` (default `false`): an IPv4
  UDP datagram above the MTU from `UdpReply::send` / `UdpSocket::send_to` leaves as one
  packet with DF clear for the engine's fragmenter (`EngineBuilder::fragmenter`) to split,
  instead of failing with `InvalidInput`; IPv6 above the MTU and IPv4 above 65 535 bytes
  still fail. Without it the bytes on the wire are unchanged (DF set).
- `nsplane-netstack`: `NetStackHandle::owns(packet) -> Ownership` tells, without waiting,
  whether an ingress packet belongs to the stack: `Flow` for a TCP connection (open, in
  SYN-SENT from the moment the connect is queued, mid handshake or half closed), a bound
  UDP socket or a UDP flow, and for ICMP errors quoting one of them; `Listener` for a bare
  SYN or a UDP datagram to a stack address that opens something new; `None` otherwise,
  including fragments. A `Splitter` closure can share one decrypted stream between the stack
  and other consumers with it. The table it reads changes only when a connection, flow or
  socket opens or closes.
- `nsplane-packet`: `reassembly::Reassembler`, a sans-I/O reassembler of IPv4 fragments and
  IPv6 Fragment-header packets on the caller's clock: `push` returns `Outcome::{Pass, Held,
  Complete, Dropped}`, fragments may arrive in any order, overlaps drop the datagram, and
  state is bounded by `ReassemblyConfig { max_datagrams (64), timeout (30 s), max_bytes
  (65 535) }`, with `expire` and `ReassemblyStats`. Nothing is allocated before the first
  fragment.
- `nsplane-netstack`: `NetStackConfig::reassembly: Option<ReassemblyConfig>` (re-exported as
  `nsplane_netstack::ReassemblyConfig`; default `None`, fragments dropped as before and no
  reassembler allocated): the driver reassembles IPv4 fragments and IPv6 Fragment-header
  packets to the stack's addresses and routes each completed datagram as if it had arrived
  whole (UDP socket or flow, or TCP); expiry runs on the driver's existing tick. Counted in
  the new `NetStackStats::{reassembled, reassembly_timeout, reassembly_overflow}` (0 when
  disabled; invalid or overlapping fragments count as `malformed`). With it, `owns` reports
  TCP and UDP fragments to a stack address as the stack's: `Flow` for a first fragment on a
  registered tuple, `Listener` for any other.
- `nsplane-netstack`: `NetStackConfig::tcp_rx_buffer` and `tcp_tx_buffer: Option<usize>`
  size every TCP socket's receive and send buffer, listener pool sockets included (default
  `None`: `(mtu - 40) * 512` as before). Values are clamped to one IPv4 MSS (`mtu - 40`) at
  least and `65535 << 14` at most; the advertised window and the window-scale option follow
  the receive buffer (smoltcp derives the shift from its capacity). A window larger than
  the queues on the path loses its tail and recovers by retransmission timeout, so the
  default stays (ns's MB-x5; MB-x6 needs no code, `NetStackStats::syn_refused` counts SYNs
  refused for a full listener pool).
- `nsplane-nat`: `Masquerade`, a local-side IPv6 source NAPT of routed LAN ingress, ported
  from ns `subnet/ingress.rs` (`SubnetLanIngressTranslator`). A decision closure gives each
  new TCP, UDP or `ICMPv6` Echo flow a source (`MasqueradeDecision { source: Ipv6Addr,
  route: u64 }`; the contract's `source: IpAddr` became `Ipv6Addr` by L1 decision, so an
  IPv4 source cannot be expressed), and the source port or Echo identifier becomes a token
  from `MasqueradeConfig::ports`. `forward` / `reverse` rewrite a `PacketBuf` in place and
  return a `MasqueradeVerdict`; `reverse` asks the closure again and drops the reply and
  its flow when the route changed. Flows live in a table of their own (bounded, a full
  table refuses new flows, per-protocol idle expiry). Drop reasons in
  `nsplane_nat::masquerade::reasons`: `tcp_not_syn`, `capacity`, `route_changed`,
  `tokens_exhausted` and `bad_checksum` (the last one beyond the contract; ns drops these
  too); `MasqueradeStats` counts the outcomes.
- `nsplane-packet`: `icmp::echo_reply_in_place(&mut [u8]) -> bool` turns an IPv4 ICMP or
  IPv6 `ICMPv6` Echo request into its Echo reply in the same buffer (addresses swapped,
  checksums recomputed, TTL / hop limit kept), ported from ns `subnet_icmp_echo_reply`;
  anything else, IPv4 fragments and buffers longer than the IP length included, returns
  `false` untouched.
- `nsplane`: `MapSink` and `MapSource`, in-place transform wrappers for the local side: a
  closure (`Fn(&mut PacketBuf, PeerId) -> MapVerdict` on the sink side,
  `FnMut(&mut PacketBuf) -> MapVerdict` on the source side) rewrites each packet or drops
  it (`MapVerdict::{Keep, Drop}`, counted in `dropped()`); the MTU passes through and batch
  methods map each packet. A Redirect is a `MapSink` plus a `MapSource`.
- `nsplane`: `pump(source, sink, from) -> io::Result<PumpStats>` moves every packet from a
  `PacketSource` into a `PacketSink` in order (`recv_batch` then `send_batch`), awaiting the
  sink's backpressure; it ends with `Ok` when either side returns `BrokenPipe` and is
  cancellation-safe at batch boundaries. `PumpStats { packets, batches }`.
- `nsplane`: `pipe(capacity, mtu) -> (PipeSink, PipeSource)`, a bounded in-memory loopback,
  so one engine's (or `Splitter`'s) output feeds another engine's input without a
  forwarding task. `PipeSink` is `Clone`; either end gone makes the other return
  `BrokenPipe` (the source after draining); `PipeSource::mtu_sender` changes the MTU it
  reports. A `local_graph` bench (`cargo bench -p nsplane --bench local_graph`).
- `nsplane-e2e`: `local_graph` tests: two engines joined only by pipes through a `Splitter`,
  a Redirect-like `MapSink`/`MapSource` and a `MergeSource` (IPv4 and IPv6, in order, with a
  Drop rule), a TUN-like channel pumped into and out of an engine, backpressure without
  loss, `BrokenPipe` from either end of a pipe, and a cancelled pump.
- `nsplane-tun` (Linux, Android, macOS, iOS): `TunSlot`, a TUN fd the host swaps while the
  engine runs (Android `VpnService`; ns's MT-1). `TunSlot::new(mtu)` returns the cloneable
  control handle with a `SlotSource` and a `SlotSink`. `replace(fd)` takes ownership of an
  `OwnedFd`, sets it non-blocking and fences the previous one: once it returns no syscall
  runs on the old fd, and a read completed on it but not yet returned is discarded and
  retried on the new one. `disable` parks I/O and `enable` resumes it; `close` (or
  dropping the last handle) makes the source, the sink and later `replace` calls fail with
  `BrokenPipe`. Reads get an MTU + 1 buffer: longer reads are dropped and counted
  (`SlotSource::oversize_drops`), a 0-byte read is `UnexpectedEof`; a short write is
  `WriteZero`. No header and no offloads; the MTU is fixed. Not built on Windows.
- `nsplane-tun`: `host_tun(mtu, capacity, write)`, a local side bridged through host
  callbacks such as iOS `NEPacketTunnelFlow` (ns's MT-2; the contract's `HostTun::new`
  ships as this free function, so no `clippy::new_ret_no_self` suppression is needed). It
  returns a `HostTunInput`, whose `push` copies a packet into the queue from any thread
  without blocking and fails with `PushError::Full` or `PushError::Closed`, a
  `HostTunSource` that drops and counts packets longer than the MTU
  (`HostTunSource::oversize_drops`, one warning per source), and a `HostTunSink` that calls
  `write` and returns `BrokenPipe` when it returns `false`. `HOST_TUN_DEFAULT_CAPACITY` is
  4096 packets. Built on every target.
- `nsplane-acl`: the node L3 gate (MD-2), a port of ns tunnel-wg `node_l3`. `NodeL3Gate`
  applies target-bound `NodeL3Config` snapshots (Node, Service and Subnet Grants, peer
  bindings, modes `disabled` / `observe` / `enforce`) and the WireGuard projection
  (`NodeL3Transport`), and judges decrypted inbound and plaintext outbound IPv4 packets:
  source binding by `(peer key, inner address)`, the same-owner rule, stateful flows with
  per-protocol idle timeouts, 2,048 flows per peer and 16,384 in all (a full table drops
  with `state_capacity`, never evicts), orphan fragments, ICMP errors matched to their flow,
  Provider listeners for Service Grants and the reserved Subnet transport admission.
  `NodeL3Reason` names every verdict (`as_str`, `drop_reason`); `NodeL3Counters` counts
  enforced and observed denials. Not installed by default; nothing is on the data path
  without it.
- `nsplane-acl`: `NodeL3Filter`, the gate and an optional `AclFilter` as one ordered
  `PacketFilter`: an enforced allow ends the decision before the ACL, an enforced denial
  drops with the gate's reason, Legacy and Observe go on to the ACL; outbound is the gate
  only unless `with_acl_outbound(true)`. Peers resolve to WireGuard keys through
  `PeerPublicKeys` (`PeerKeyMap`); `NodeL3FilterStats` counts the steps.
- `nsplane-acl`: gateway-consumer divert (MD-3): `NodeL3Filter::with_divert` hands a
  `SourceBinding` / `OrphanFragment` denial the gate captures as a gateway return
  (`GatewayConsumerPacket`) to a `GatewayConsumerSink` and reports it as
  `Verdict::Handled`; a refused candidate is dropped. Tests: `nsplane-e2e` `node_l3`; bench
  `cargo bench -p nsplane-acl --bench node_l3`.
- `nsplane-acl`: per-packet source principals. `PeerIdentity::assertion_for(peer, src)`
  (default: `assertion(peer)`) resolves a peer's principal for the packet's remote address, and
  `PeerIdentity::by_source` marks peers whose principal depends on it;
  `PeerIdentityMap::insert_by_source` makes a peer terminate by source address (each packet's
  principal is a terminate binding of its address, as `AccessRequest::from_ip` builds it), next
  to `insert` with a `SourceAssertion::WgPeerKey` for relay clients. `AclFilter` caches such a
  principal per peer and address (bounded by `reply_capacity`, least recently used
  evicted) under the identity generation.
- `nsplane-acl`: `AclFilterConfig::fragments: FragmentMode` (`#[non_exhaustive]`). `Outcome`
  (default) is today's gate; `AllowOnly { ttl, capacity }` is the ns `FragmentAclGate` (only
  accepted first fragments recorded, keyed (source, destination, protocol, identification), a
  miss drops with `reasons::FRAGMENT`); `FragmentMode::ALLOW_ONLY` has ns's 15 s and 4096.
- `nsplane-acl`: bypass flags `AclFilterConfig::accept_to_local: Option<Ipv4Addr>` (ns
  `is_local_node_packet`) and `accept_icmp_echo_reply: bool` (ns `is_icmp_echo_reply`), off by
  default; packets they accept count in the new `AclFilterStats::bypassed`.
- `nsplane-acl`: `AclFilterConfig::crates_acl(local)`, the ns `crates/acl` preset: for inbound
  IPv4 it equals ns `is_local_node_packet || is_icmp_echo_reply || acl_check_packet` (no reply
  allowances, TCP and UDP only, `FragmentMode::ALLOW_ONLY`, both bypass flags), and it passes
  IPv6 unevaluated as ns does (`ipv6: Ipv6Mode::Accept`). A differential test
  (`tests/crates_acl_parity.rs`) replays ns verdicts from a fixture; it differs only on
  malformed IPv4, which nsplane-acl drops. `nsplane-e2e` `acl_parity` tests.
- `nsplane-acl`: `AclFilterConfig::ipv6: Ipv6Mode` (`#[non_exhaustive]`). `Evaluate` (default)
  judges IPv6 like IPv4; `Accept` passes every IPv6 packet, inbound and outbound, before
  anything else without recording state, counted in the new `AclFilterStats::ipv6_accepted`
  (ns runs no ACL on IPv6; its destination check is `PeerConfig::inbound_destinations`).
- `nsplane-core`: per-peer inbound destinations. `PeerConfig::inbound_destinations:
  Option<Vec<AllowedIp>>` (`None`, the default: unchecked) restricts where a peer's decrypted
  packets may be addressed; others are dropped as the new `reasons::DESTINATION_NOT_ALLOWED`.
  `ConfigChange::SetInboundDestinations` and `EngineHandle::set_inbound_destinations` change or
  remove them at runtime (an update through `add_or_update_peer` with `None` keeps them). They
  add no routes. `nsplane-core` and `nsplane-e2e` `inbound_destinations` tests.
- `nsplane`: `Transport::try_send_batch` / `DynTransport::try_send_batch` and
  `PacketSink::try_send_batch`, the non-blocking forms of `send_batch`: they hand off what
  can go at once, in order, and return `WouldBlock` with the rest left to the caller. The
  defaults hand off nothing (`WouldBlock`), which keeps today's path through the transmit
  and sink tasks. `UdpTransport` and the Unix `TunSink` (Linux, Android, macOS, iOS)
  override them.

### Changed
- Breaking: struct literals of `PeerConfig` (`nsplane::Peer`), `AclFilterConfig` and
  `AclFilterStats` need the new fields (`inbound_destinations`; `fragments`, `accept_to_local`,
  `accept_icmp_echo_reply`, `ipv6`; `bypassed`, `ipv6_accepted`) (`..Default::default()`, `PeerConfig::new`), and
  exhaustive matches on `ConfigChange` the new `SetInboundDestinations`. Behavior with the
  defaults is unchanged.
- Breaking: `Transport::send_batch` and `DynTransport::send_batch` take a third argument,
  `failed: &mut usize`. A call adds one for every datagram it was done with that failed
  (and was dropped), never more than it advanced `sent`; `Ok` means nothing failed in the
  call, an error means at least the last datagram it was done with failed. The default
  method counts each failed `send`. Transports that override `send_batch` must count their
  failures.
- Breaking: `nsplane-nat`'s `TranslatorStats` gains `fragments_held`, `fragment_timeouts`,
  `fragment_budget_drops`, `fragment_marker_evictions` and `reassembled_too_big`, so struct
  literals of it no longer compile. `reasons::EXPIRED` is no longer emitted: a fragment
  that arrives after its datagram expired starts a new held entry, and the expiry is
  counted in `fragment_timeouts`.
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
- `nsplane`: every datagram a transport fails to send (any I/O error, e.g. `EMSGSIZE`) is
  counted under the new `DROP_TRANSPORT_SEND_ERROR`
  (`nsplane_core::reasons::TRANSPORT_SEND_ERROR`) and published as `Event::Dropped` instead
  of only being logged. The transmit tasks report failures through a shared counter and a
  wake signal to the owner task; successful sends take no extra work. A failed
  `send_batch` call counts exactly the datagrams it reports failed (for `UdpTransport`, the
  failed GSO run).
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
- `nsplane-netstack`: every TCP socket runs CUBIC congestion control (smoltcp feature
  `socket-tcp-cubic`). A bulk transfer through a hop that drops part of a window (a full
  socket buffer on a loaded host) no longer stalls on doubling retransmission timeouts:
  16 MiB through a 25 MB/s link with a 64-packet buffer finish in 14-17 s instead of not at
  all within 60 s, and at 1 % random loss in 3 s instead of 35-41 s (release, in-process).
- `nsplane-netstack`: TCP connections no longer stall for good under loss when both ends
  send. smoltcp is now the `dotns/smoltcp` fork (git dependency, tag `v0.14.0-nsplane.3`,
  v0.14.0 plus five TCP fixes; ADR `docs/decisions/2026-10-03-smoltcp-fork.md`): empty
  segments sent after a retransmission timeout carry the highest sequence number sent, so
  the peer no longer drops them as old, without undoing the rewind for retransmission;
  data lost before the peer's window closed stays under the retransmission timer instead
  of being left to the zero-window probe; a fast retransmission the device has no room
  for is sent later instead of being dropped with its timer; and duplicate ACKs no longer
  take the retransmission timer away from a lost FIN. The driver workarounds are removed:
  it no longer rewrites the sequence number of outgoing pure ACKs, reopens a stalled
  receive window past its bound or sets keep-alives on stalled connections. `deny.toml`
  allows the fork's git source only.
- `nsplane-netstack`: the driver takes its queued ingress packets in one batch per turn,
  and egress TCP segments and UDP datagrams keep 32 bytes of tail room, so the engine
  seals them in place instead of reallocating each full-size packet. One 1 GiB TCP stream
  between two netstacks over two engines takes 7-8 % less CPU time, 2.2-2.3 % fewer
  instructions and 22-24 % fewer context switches (release, in-process; throughput within
  the shared host's noise); behavior is unchanged. See docs/architecture.md, "Netstack
  throughput".
- `nsplane`: the owner task feeds the received datagrams and local packets already queued
  (up to `MAX_BATCH`, never waiting for more) to the core as one batch. It reads local
  packets only while a transport has transmit room and takes no more at once than that
  room, so a saturated transport holds back the source instead of building a backlog. Under
  a saturating flow the engine moves about 19 % more packets, and a receiving sink slower
  than the tunnel now drops at `DROP_SINK_FULL` (see docs/architecture.md, "Performance").
- `nsplane-core`: without crypto jobs every peer owns its tunnel and the data path takes no
  lock; only a core built with `CoreConfig::crypto_jobs` keeps each tunnel behind a mutex
  shared with its jobs. Breaking: `CoreConfig` struct literals need the new field (or
  `..CoreConfig::default()`), and `Core::handle_input_deferred` on a core without
  `crypto_jobs` processes every input at once and returns `None`.
- `nsplane-examples`: the relay WSS client (`--transport wss`) runs on `LinkTransport`
  with a tungstenite dialer (tungstenite and rustls stay in the examples package). While
  the connection is down, datagrams to the relay now wait in the link's 256-entry queue
  instead of being dropped: `.extra.wss.dropped.disconnected` stays 0 and
  `dropped.queue_full` counts sends that failed on a full queue. The status field names are
  unchanged.
- `nsplane-examples`: the relay WSS client dials with `nsplane_wss::WssDialer` instead of
  its own tungstenite dialer (the pinning `ClientConfig` passed as `WssTls::Config`);
  `WssTransport::connect` now returns `io::Result`.
- `nsplane`: without crypto workers the engine hands what one source or transport read
  returned to the owner task as one message (the input queues stay bounded in packets; a
  lone item goes over without an allocation). The owner delivers a drain's packets to the
  sink itself (`try_send_batch`) when the sink has nothing queued or in flight, and sends a
  drain's datagrams itself when the transport has nothing queued or in flight and no local
  packet or received datagram is waiting; under load the transmit task sends while the
  owner seals. A transport or sink whose `try_send_batch` takes nothing is skipped for 1,
  2, 4, ... up to 1024 drains, so the default implementations cost about one try per 1024
  drains. The rest falls back to the transmit and sink tasks (see docs/architecture.md,
  "Engine fast path (MF-1)"). As a result the `QueueStats` mark of `deliver` is lower (those
  of `transmit` and `recycle` under light load), and `TransportStats` may also be counted by
  the owner task.

### Removed
- Breaking: the `boringtun::device` module and the `device` feature (TUN, epoll/kqueue and
  Windows event loops, UDP sockets, UAPI). Use `nstun`, `nstun-tun` and `nstun-uapi`.
  `boringtun` no longer depends on `socket2`, `thiserror`, `wintun-bindings`, `windows-sys`,
  `ip_network` or `ip_network_table`, nor on the `nix` `user` feature.
- `just integration` and the upstream integration tests that ran against the device.
- Breaking: the `mock-instant` features of `nsplane-noise` and `nsplane-core`; tests drive
  the timers through the `_at` methods and the core's `now` instead.

### Fixed
- `nsplane`: `PipeSink` implements `PacketSink::try_send_batch` (queues while the pipe has
  room, never waits), so an engine delivers into a pipe from its owner task; `MapSink`
  keeps the default by design. `ChannelTransport::recv` no longer zero-fills the whole
  receive buffer (64 KiB in the engine) for every datagram, which slowed every in-process
  engine benchmark.
- Tests: `nsplane-cli`'s `boolean_environment_variables_accept_1` no longer hangs under
  `CAP_NET_ADMIN` (it adopts a closed descriptor so startup fails whatever the
  privileges); the WSS tests `a_foreign_certificate_is_rejected` and
  `session_budget_bounds_all_streams` wait for the server's counter and allow a loaded
  host more time.
- `nsplane`: `DROP_TRANSPORT_SEND_ERROR` is exact for batched sends. `UdpTransport` counts
  only the datagrams of a failed GSO run, not the runs it handed off before it in the same
  call; the engine counts what `Transport::send_batch` reports failed (at least one).
- `nsplane-tun`: plain TUN reads (offload off on Linux and Android, and macOS/iOS) and
  Wintun reads on Windows leave 28 bytes of room behind each packet, as offload reads do
  (a read still takes at most the MTU), so a full-MTU IPv4 packet is translated to IPv6 in
  place (`TranslatorStats::grown_copies` stays 0) with offload off.
- `nsplane-nat`: IPv4 UDP fragments that arrive before their first fragment are held
  (bounded at 256 datagrams and 1 MiB, 60 s) instead of being translated alone, so
  zero-checksum datagrams reassemble in any order. A datagram with a checksum whose later
  fragments came first is reassembled and sent unfragmented; in-order fragments of a
  checksummed datagram still pass one by one, without holding or added latency. A
  reassembled datagram larger than the translator's MTU is dropped and counted
  (`reassembled_too_big`), never sent oversize.
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