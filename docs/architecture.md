# nsplane Architecture

This page describes what is on `main`. The target design and roadmap are in
[design.md](design.md).

Scope: nsplane is a business-agnostic data plane. ns is one product built on it, and other
libraries and products may use it. Product models (identities, subjects, groups, realms,
services, grants) are compiled above nsplane into generic inputs: flow rules, opaque labels
and narrow trait callbacks. What nsplane does and does not do is listed in ADR
[2026-10-06-business-agnostic-scope](decisions/2026-10-06-business-agnostic-scope.md).

## Crates

| Crate | Path | Role |
|---|---|---|
| `nsplane-noise` | `crates/nsplane-noise/` | The Noise protocol state machine (`noise`); no I/O |
| `nsplane-packet` | `crates/nsplane-packet/` | Packet buffers (`PacketBuf`, `PacketPool`, `PacketBatch`), IP header views, shared value types (`PeerId`, `TransportId`, `Path`, `Ecn`) |
| `nsplane-core` | `crates/nsplane-core/` | Sans-I/O engine core: peers, cryptokey routing, timers, path policy, packet filters |
| `nsplane` | `crates/nsplane/` | Tokio driver: `Engine`, `EngineBuilder`, `EngineHandle`, events, the I/O traits, `UdpTransport`, the fragmentation stage (`FragmentConfig`) |
| `nsplane-acl` | `crates/nsplane-acl/` | Accept-only ACL policy engine (`AclEngine`), the `AclFilter` and `FlowTracker` packet filters |
| `nsplane-nat` | `crates/nsplane-nat/` | IPv4/IPv6 translation (`Translator`, `TranslationTable`) and service-publishing DNAT/SNAT (`PortMap`, `Conntrack`) packet filters; NAT64 to a LAN (`Nat64Lan`) on the local side |
| `nsplane-wss` | `crates/nsplane-wss/` | WebSocket-over-TLS carriers: `WssDialer` for `LinkTransport`, the `WsFrame` stream client (`WssStreamClient`) and terminate leg (`WssStreamServer`) |
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
nsplane ─► nsplane-nat
nsplane ─► nsplane-wss
```

## Public interfaces

Every public item has rustdoc (`cargo doc --workspace --no-deps --open`); that is the
reference for signatures and contracts. This table is the map: what each crate exports and
where it is described below.

| Crate | Entry points | Supporting types |
|---|---|---|
| `nsplane-noise` | `noise::Tunn` (handshake, sessions, timers; `encapsulate_in_place` / `decapsulate_in_place`, `set_pad_limit`, `remote_index`), `noise::rate_limiter::RateLimiter`, `x25519` keys | `TunnResult`, `noise::errors::WireGuardError` |
| `nsplane-packet` | `PacketBuf` (headroom, `advance` / `reserve_front`, `from_shared`, fallible bounds), `PacketPool`, `PacketBatch`, `IpPacket`, `reassembly::Reassembler` (`push`, `expire`, `stats`, `pending`), `build::udp_packet` / `build::write_udp`, `icmp::echo_reply_in_place` | `reassembly::{ReassemblyConfig, ReassemblyStats, Outcome}`; `Path`, `TransportId`, `PeerId`, `Ecn`; header views `Ipv4Header`, `Ipv6Header`, `TcpHeader`, `UdpHeader`, `IcmpHeader`, `Fragment`, `FiveTuple`; `checksum`, `protocol`; errors `Malformed`, `BoundsError`, `UdpBuildError`; `HEADROOM`, `MAX_BATCH` |
| `nsplane-core` | `Core` (`handle_input`, `handle_datagrams` / `handle_locals`, the `_deferred` forms and `complete_job`, `handle_timeout` / `poll_timeout`, `poll_output`, `inject_inbound` / `inject_outbound` / `inject_outbound_on`, `force_handshake` / `force_handshake_on`, `route`, `data_path`, `is_remote_index`, `set_peer_pad_limit`, `peer_stats`, `recycle`); traits `PathPolicy` (`select`, `on_authenticated`, `observe_every_message`) and `PacketFilter` (`inbound`, `inbound_from`, `outbound`) | `CoreConfig`, `Input`, `Output`, `ConfigChange`, `PeerConfig`, `AllowedIp`, `PeerStats`, `Event`, `Verdict`, `Roam`, `MessageKind`, `StandardRoaming`, `CryptoJob`, `reasons` |
| `nsplane` | `EngineBuilder` (`transport`, `private_key`, `policy`, `filter`, `fragmenter`, `transport_max_datagram`, `path_mtu_expiry`, `crypto_workers`, `queue_capacity`, `event_capacity`, `stats_interval`, `build`), `Engine` (`handle`, `wait`), `EngineHandle` (peers, keys, allowed IPs, PSK, keepalive, `set_path`, `set_transport_max_datagram`, `report_path_mtu`, `peer_mtu` / `peer_mtus`, `path_mtu_stats`, `add_transport` / `remove_transport` / `replace_transport`, `inject_inbound` / `inject_outbound` / `inject_outbound_on`, `force_handshake` / `force_handshake_on`, `suspend` / `resume`, `subscribe`, `peers` / `peer_stats`, `drop_counters`, `queue_stats`, `fragment_stats`, `transport_stats`, `status`, `shutdown`); traits `PacketSource`, `PacketSink`, `Transport` (each with batch methods; `Transport::path_mtu_reports`), `DynTransport`; `LinkTransport` with the traits `LinkDialer`, `LinkSender`, `LinkReceiver` | `UdpTransport` (`with_side_channel`, `set_path_mtu_discovery`, `path_mtu_reports_dropped`), `SideSender` (`send_to`, `send_to_async`), `SideDatagram`, `SideStats`, `LinkConfig`, `LinkState`, `ChannelSource` / `ChannelSink` / `ChannelTransport`, `Splitter` (`new_map`), `MergeSource`, `MapSink` (`with_after`) / `MapSource` / `MapVerdict`, `SwapSink` (`replace`, `dropped`), `AbortSink` / `SinkAbort` (`abort`, `is_aborted`), `pipe` / `PipeSink` / `PipeSource` (`mtu_sender`), `pump` / `PumpStats`, `FragmentConfig` / `FragmentStats`, `EngineStatus`, `PathMtuReport`, `PeerMtus`, `PathMtuStats`, `TransportStats`, `QueueStats` / `QueueDepth`, `Peer`, `Event`, the `DROP_*` reasons, `EngineError`, `TransportError`, `BuildError`, `BoxFuture`; re-exports of the value types |
| `nsplane-wss` | `WssDialer` (`new`, `into_transport`, `state`, `stats`, `events`), `WssStreamClient` (`new`, `connect`, `open_tcp`, `open_udp`, `state`, `stats`, `events`), `WssStreamServer` (`new`, `with_events`, `run`, `state`, `stats`); traits `BearerProvider`, `WssResolver` | `WssConfig` (`allow_plaintext` for `ws://`, `keepalive`, `reconnect_delay`), `WssTls`, `WssDialError` (`MAX_BODY`), `WssDialEvent` (`CAPACITY`), `WssStats`, `WssStreamLimits` (`open_timeout`), `WssStreamStats`, `WssTcpStream`, `WssUdpFlow`, `WssServerLimits`, `WssServerStats`, `WssOpen`, `Denied`, `WssStreamEvent` / `WssStreamEventKind`, `WssCloseReason`; `frame` (`WsFrame`, `FrameCommand`, `Protocol`, `FrameError`, the command and protocol bytes); `MAX_DATAGRAM`, `MAX_MESSAGE`, `MAX_DATA_PAYLOAD` |
| `nsplane-tun` | `Tun` (`create`, `create_with` (on Windows with the service TUN checks), `from_fd` / `from_raw_fd` on Unix, `split`, `offload`, `mtu`, `name`), `TunSlot` (`new`, `replace`, `disable`, `enable`, `close`; Linux, Android, macOS, iOS), `host_tun` | `TunOptions` (Windows: `wintun_pin`, `exclusive`, `mtu`), `WintunPin` and `WintunError` (Windows), `TunSource` (`name`), `TunSink` (`name`), `Offload`, `adopt_fd` (Unix), `MTU_POLL_INTERVAL`; `SlotSource` (`oversize_drops`), `SlotSink`; `HostTunInput` (`push`), `HostTunSource` (`oversize_drops`), `HostTunSink`, `PushError`, `HOST_TUN_DEFAULT_CAPACITY` |
| `nsplane-packet` | `PacketBuf` (headroom, `advance` / `reserve_front`, `from_shared`, fallible bounds), `PacketPool`, `PacketBatch`, `IpPacket`, `reassembly::Reassembler` (`push`, `expire`, `stats`, `pending`), `build::udp_packet` / `build::write_udp`, `icmp::echo_reply_in_place`, `icmp::is_echo_request` | `reassembly::{ReassemblyConfig, ReassemblyStats, Outcome}`; `Path`, `TransportId`, `PeerId`, `Ecn`; header views `Ipv4Header`, `Ipv6Header`, `TcpHeader`, `UdpHeader`, `IcmpHeader`, `Fragment`, `FiveTuple`; `checksum`, `protocol`; errors `Malformed`, `BoundsError`, `UdpBuildError`; `HEADROOM`, `MAX_BATCH` |
| `nsplane-core` | `Core` (`handle_input`, `handle_datagrams` / `handle_locals`, the `_deferred` forms and `complete_job`, `handle_timeout` / `poll_timeout`, `poll_output`, `inject_inbound` / `inject_outbound` / `inject_outbound_on`, `force_handshake` / `force_handshake_on`, `route`, `data_path`, `is_remote_index`, `set_peer_pad_limit`, `peer_stats`, `unanswered_handshakes` / `total_unanswered_handshakes`, `recycle`); traits `PathPolicy` (`select`, `on_authenticated`, `observe_every_message`) and `PacketFilter` (`inbound`, `inbound_from`, `outbound`) | `CoreConfig`, `Input`, `Output`, `ConfigChange`, `PeerConfig`, `AllowedIp`, `PeerStats`, `Event`, `Verdict`, `Roam`, `MessageKind`, `StandardRoaming`, `CryptoJob`, `reasons` |
| `nsplane` | `EngineBuilder` (`transport`, `private_key`, `policy`, `filter`, `fragmenter`, `transport_max_datagram`, `path_mtu_expiry`, `crypto_workers`, `queue_capacity`, `event_capacity`, `stats_interval`, `build`), `Engine` (`handle`, `wait`), `EngineHandle` (peers, keys, allowed IPs, PSK, keepalive, `set_path`, `set_transport_max_datagram`, `report_path_mtu`, `peer_mtu` / `peer_mtus`, `path_mtu_stats`, `add_transport` / `remove_transport` / `replace_transport`, `inject_inbound` / `inject_outbound` / `inject_outbound_on`, `force_handshake` / `force_handshake_on`, `suspend` / `resume`, `subscribe`, `peers` / `peer_stats`, `unanswered_handshakes` / `total_unanswered_handshakes`, `drop_counters`, `queue_stats`, `fragment_stats`, `transport_stats`, `status`, `shutdown`); traits `PacketSource`, `PacketSink`, `Transport` (each with batch methods; `Transport::path_mtu_reports`), `DynTransport`; `LinkTransport` with the traits `LinkDialer`, `LinkSender`, `LinkReceiver` | `UdpTransport` (`with_side_channel`, `set_path_mtu_discovery`, `path_mtu_reports_dropped`), `SideSender` (`send_to`, `send_to_async`), `SideDatagram`, `SideStats`, `LinkConfig`, `LinkState`, `ChannelSource` / `ChannelSink` / `ChannelTransport`, `Splitter` (`new_map`, `stats`) / `SplitterStats`, `MergeSource`, `MapSink` (`with_after`) / `MapSource` / `MapVerdict`, `SwapSink` (`replace`, `dropped`), `AbortSink` / `SinkAbort` (`abort`, `is_aborted`), `pipe` / `PipeSink` / `PipeSource` (`mtu_sender`), `pump` / `PumpStats`, `FragmentConfig` / `FragmentStats`, `EngineStatus`, `PathMtuReport`, `PeerMtus`, `PathMtuStats`, `TransportStats`, `QueueStats` / `QueueDepth`, `Peer`, `Event`, the `DROP_*` reasons, `EngineError`, `TransportError`, `BuildError`, `BoxFuture`; re-exports of the value types |
| `nsplane-wss` | `WssDialer` (`new`, `into_transport`, `state`, `stats`), `WssStreamClient` (`new`, `connect`, `open_tcp`, `open_udp`, `state`, `stats`), `WssStreamServer` (`new`, `with_events`, `run`, `state`, `stats`); traits `BearerProvider`, `WssResolver` | `WssConfig`, `WssTls`, `WssStats`, `WssStreamLimits`, `WssStreamStats`, `WssTcpStream`, `WssUdpFlow`, `WssServerLimits`, `WssServerStats`, `WssOpen`, `Denied`, `WssStreamEvent` / `WssStreamEventKind`, `WssCloseReason`; `frame` (`WsFrame`, `FrameCommand`, `Protocol`, `FrameError`, the command and protocol bytes); `MAX_DATAGRAM`, `MAX_MESSAGE`, `MAX_DATA_PAYLOAD` |
| `nsplane-tun` | `Tun` (`create`, `create_with` (on Windows with the service TUN checks), `from_fd` / `from_raw_fd` on Unix, `split`, `offload`, `mtu`, `name`), `TunSlot` (`new`, `replace`, `clear`, `disable`, `enable`, `close`; Linux, Android, macOS, iOS), `host_tun` | `TunOptions` (Windows: `wintun_pin`, `exclusive`, `mtu`), `WintunPin` and `WintunError` (Windows), `TunSource` (`name`), `TunSink` (`name`), `Offload`, `adopt_fd` (Unix), `MTU_POLL_INTERVAL`; `SlotSource` (`oversize_drops`), `SlotSink`; `HostTunInput` (`push`), `HostTunSource` (`set_mtu`, `oversize_drops`), `HostTunSink`, `PushError`, `HOST_TUN_DEFAULT_CAPACITY` |
| `nsplane-netstack` | `NetStack` (`new`, `split`), `NetStackHandle` (`incoming_tcp`, `incoming_udp`, `connect_tcp`, `connect_tcp_from`, `bind_udp`, `connect_udp`, `connect_udp_from`, `discard_fragments`, `stats`, `owns`) | `Ownership`, `NetStackConfig` (`udp_allow_fragmentation`, `reassembly`), `ReassemblyConfig` (re-export), `NetStackSource`, `NetStackSink`, `TcpConnection` (`AsyncRead` + `AsyncWrite`, `unacked`, `last_ack`, `abort`), `UdpFlow`, `UdpReply`, `UdpSocket` (`send`, `peer_addr` for a connected one), `NetStackStats`, `DEFAULT_MTU`, `MIN_MTU` |
| `nsplane-acl` | `AclEngine` (`load`, `store_namespace` / `remove_namespace`, `store_grant` / `remove_grant`, `open_pinhole`, `expire_pinholes`, `clear_all`, `is_allowed`, `generation`, `pinhole_stats`), `AclFilter` (`new`, `with_config`, `stats`), `FlowTracker` | policy model `AclPolicy`, `AclRule`, `AclAction`, `AclTest`, `Protocol`, `IpNet`; requests `AccessRequest`, `SourceAssertion`, `TerminateBinding`, `AclDecision`; identity `PeerIdentity`, `PeerIdentityMap`, `wg_peer_anchor`; namespaces `NamespaceId`, `NamespacePolicy`, `NamespaceMember`, `OutboundRule`, `Grant`, `GrantEnd`; pinholes `PinholeSpec`, `PinholeGuard`, `PinholeId`, `Direction`, `PinholeError`, `PinholeStats`; layering `PolicyLayers`, `RemotePolicy`, `merge_layered`, `MergedPolicy`, `MergeStats`, `RuleProvenance`, `apply_deny_scope`, `DenyScope`; stats `AclFilterStats`, `FlowKey`, `FlowStats`; `CompiledPolicy`, `reasons`; node L3 gate `NodeL3Gate`, `NodeL3Filter`, `PeerPublicKeys`, `PeerKeyMap`, `GatewayConsumerSink`, `GatewayConsumerPacket`, `GatewayConsumerAuthority`, `NodeL3FilterStats`, `NodeL3Config`, `NodeL3Node`, `NodeL3PeerBinding`, `NodeL3ServiceEndpoint`, `NodeL3ServiceProtocol`, `NodeL3Grant`, `NodeL3Resource`, `NodeL3Mode`, `NodeL3Transport`, `NodeL3TransportPeer`, `NodeL3PeerPolicyRequirement`, `NodeL3Decision`, `NodeL3Reason`, `NodeL3Applied`, `NodeL3Counters`, `NodeL3SubnetAuthorization`, `NodeL3PeerReadiness`, `NodeL3PeerReadinessReason`, `NodeL3ConfigError`, `NodeL3TransportError`, `NODE_L3_SCHEMA_VERSION` |
| `nsplane-netstack` | `NetStack` (`new`, `split`), `NetStackHandle` (`incoming_tcp`, `incoming_udp`, `connect_tcp`, `connect_tcp_from`, `bind_udp`, `stats`, `owns`) | `Ownership`, `NetStackConfig` (`udp_allow_fragmentation`, `reassembly`), `ReassemblyConfig` (re-export), `NetStackSource`, `NetStackSink`, `TcpConnection` (`AsyncRead` + `AsyncWrite`, `unacked`, `last_ack`), `UdpFlow`, `UdpReply`, `UdpSocket`, `NetStackStats`, `DEFAULT_MTU`, `MIN_MTU` |
| `nsplane-acl` | `AclEngine` (`load`, `store_namespace` / `remove_namespace`, `store_grant` / `remove_grant`, `open_pinhole`, `expire_pinholes`, `clear_all`, `is_allowed`, `generation`, `pinhole_stats`), `AclFilter` (`new`, `with_config`, `with_scope`, `stats`), `FlowTracker` | policy model `AclPolicy`, `AclRule`, `AclAction`, `AclTest`, `Protocol`, `IpNet`; requests `AccessRequest`, `SourceAssertion`, `TerminateBinding`, `AclDecision`; identity `PeerIdentity`, `PeerIdentityMap`, `wg_peer_anchor`; namespaces `NamespaceId`, `NamespacePolicy`, `NamespaceMember`, `OutboundRule`, `Grant`, `GrantEnd`; pinholes `PinholeSpec`, `PinholeGuard`, `PinholeId`, `Direction`, `PinholeError`, `PinholeStats`; layering `PolicyLayers`, `RemotePolicy`, `merge_layered`, `MergedPolicy`, `MergeStats`, `RuleProvenance`, `apply_deny_scope`, `DenyScope`; scopes `AclFilterScope`, `OtherProtocolRule`, `OtherProtocol`; stats `AclFilterStats`, `FlowKey`, `FlowStats`; `CompiledPolicy`, `reasons`; node L3 gate `NodeL3Gate`, `NodeL3Filter`, `PeerPublicKeys`, `PeerKeyMap`, `GatewayConsumerSink`, `GatewayConsumerPacket`, `GatewayConsumerAuthority`, `NodeL3FilterStats`, `NodeL3Config`, `NodeL3Node`, `NodeL3PeerBinding`, `NodeL3ServiceEndpoint`, `NodeL3ServiceProtocol`, `NodeL3Grant`, `NodeL3Resource`, `NodeL3Mode`, `NodeL3Transport`, `NodeL3TransportPeer`, `NodeL3PeerPolicyRequirement`, `NodeL3Decision`, `NodeL3Reason`, `NodeL3Applied`, `NodeL3Counters`, `NodeL3SubnetAuthorization`, `NodeL3PeerReadiness`, `NodeL3PeerReadinessReason`, `NodeL3ConfigError`, `NodeL3TransportError`, `NODE_L3_SCHEMA_VERSION` |
| `nsplane-nat` | `Translator` (`new`, `store`, `set_mtu`, `ipv4_translated_predicate`, `stats`), `TranslationTableBuilder` (`peer_with_native_alias4`) / `TranslationTable` (`native_alias4`, `by_native_alias4`), `PortMap` (`new`, `with_conntrack`, `set_rules`), `Conntrack` (`peek`, `remove`, `with_removal_hook`), `Nat64Lan` (`new`, `with_snat_ports`, `forward`, `reverse`, `remove_flow`, `stats`), `Nat64LanSink` / `Nat64LanSource`; trait `SnatPorts` | `PeerMapping`, `SelfMapping`, `LanPrefix`, `TableError`, `TranslatorStats`, `PortMapRule`, `PortMapProtocol`, `PortMapError`, `ConntrackConfig`, `ConntrackStats`, `ConntrackError`, `Flow`, `FlowMatch`, `FlowDirection`, `TcpState`, `LanRoute`, `Nat64LanConfig`, `Nat64LanStats`, `Nat64LanError`, `Nat64Verdict`, `DefaultSnatPorts`, `nat64_lan::reasons`, `checksum` |
| `nsplane-nat` (local side) | `Redirect` (`new`, `with_conntrack`, `forward`, `reverse`, `original_destination`, `with_endpoint_tries`, `endpoint_in_use`, `remove_flow`, `retain`, `stats`) | `RedirectDecision`, `RedirectVerdict`, `RedirectStats`, `redirect::reasons` |
| `nsplane-nat` (local side) | `Masquerade` (`new`, `with_clock`, `forward`, `reverse`, `len`, `is_empty`, `stats`, `config`) | `MasqueradeDecision`, `MasqueradeConfig` (`recheck_route_on_forward`), `MasqueradeVerdict`, `MasqueradeStats`, `masquerade::reasons` |
| `nsplane-uapi` | `Uapi` (`new`, `with_external_transport`, `with_listen_port`, `handle_request`, `serve_stream`), `UapiListener` (Unix socket; named pipe on Windows) | `udp_transport`, `TRANSPORT_ID`, `socket_path` / `pipe_path` |

Per-source ACL principals, the ns `crates/acl` mode and inbound destinations add:
`nsplane-acl` `PeerIdentity::assertion_for` / `by_source`, `PeerIdentityMap::insert_by_source`,
`AclFilterConfig::crates_acl` with the fields `fragments` (`FragmentMode`, `ALLOW_ONLY`),
`accept_to_local`, `accept_icmp_echo_reply` and `ipv6` (`Ipv6Mode`), and
`AclFilterStats::bypassed` and `ipv6_accepted`; `nsplane-core`
`PeerConfig::inbound_destinations`, `ConfigChange::SetInboundDestinations` and
`reasons::DESTINATION_NOT_ALLOWED`; `nsplane` `EngineHandle::set_inbound_destinations`.

`nsplane-packet::build` writes whole IPv4 or IPv6 UDP datagrams for packets an application
injects into the tunnel: `write_udp(buf, src, dst, payload)` into an existing `PacketBuf`
(headroom kept) and `udp_packet(src, dst, payload)` into a fresh one, both re-exported at the
crate root. Checksums are always computed (a zero UDP checksum goes out as `0xFFFF`); IPv4
gets IHL 5, DF and TTL 64, IPv6 hop limit 64 and no extension headers; the family follows
the socket addresses (an IPv4-mapped address in a `SocketAddr::V6` builds IPv6). Mixed
families and payloads beyond the length fields are a `UdpBuildError` and leave the buffer
unchanged. Ported from ns's control-message builder; nothing calls it unless the application
does.

Not public API: `nsplane-cli` (a binary), `nsplane-e2e` (test harness) and
`nsplane-examples` (example binaries, including the single-port relay and its client
transports; the relay wire format is the Proposed ADR `2026-10-02-single-port-relay`).

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
leaves as the delivery; buffers come back through `recycle`. `handle_datagrams` and
`handle_locals` take a batch of received datagrams or local packets and behave exactly like
feeding each to `handle_input` in order, but share one schedule update, the output queue's
room and the session, route and peer lookups of consecutive packets. Peers are looked up by key,
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

Hooks for a path ladder (ns account mode, quick-v2 §9), each unused by default:

- `Core::inject_outbound_on` (`EngineHandle::inject_outbound_on`) seals one packet for a
  peer in its current session and transmits it on an explicit path, bypassing routing, the
  outbound filters and `PathPolicy::select`; the peer's path is not changed. It is how probes
  reach a candidate path while the peer's traffic stays on its path. Without a current
  session the packet is dropped as `reasons::NO_SESSION` and no handshake starts.
  `force_handshake_on` likewise sends one handshake initiation on an explicit path without
  changing the peer's path (`force_handshake` with a path makes it the peer's path).
- `PacketFilter::inbound_from` is what the core calls for every decrypted datagram, with the
  path it arrived on; its default calls `inbound`. A probe responder overrides it to match a
  reply with the exact tuple it probed, or to answer on the path a request came from.
- `PathPolicy::observe_every_message` (read once when the core is built, `false` by default)
  makes the core call `on_authenticated` for every authenticated message, on the current path
  too, where the answer changes nothing; by default the core asks only about messages from
  another path, which keeps the steady-state data path free
  of the call. `Event::Authenticated` stays limited to path changes.

**Unanswered handshakes.** `Core::unanswered_handshakes(peer)` (`None` for an unknown peer)
counts the handshake initiations sent to a peer that got no response: one counts when another
initiation is sent while it is still unanswered (a retry, a `force_handshake`) or when the
attempt gives up (`Event::SessionExpired`); a completed handshake answers it. The count is
monotonic and a peer that only responds stays at 0. `Core::total_unanswered_handshakes()` sums
it over every peer, removed peers included, so a consumer with a peer registry polls one
number and looks up the peer when it grows (`EngineHandle::unanswered_handshakes` /
`total_unanswered_handshakes`); `Event` and `PeerStats` are unchanged.

**Injected packets skip the filters** (part of the contract, ns's MQ-8):
`Core::inject_inbound`, `inject_outbound` and `inject_outbound_on` hand their packet past
the filter chain, so no `PacketFilter` sees it. A stateful filter (`nsplane-acl`'s
`AclFilter`) keeps no reply state for an injected packet, so the peer's replies are judged by
the inbound rules alone, and a translating filter does not translate it; a consumer orders
its filters with that in mind (ns puts its control filter wire-side of the ACL). Pinned by
`nsplane-e2e`'s `inject_filters` tests.

**Padding and path hooks** (used by the driver's per-path MTU, below; unused otherwise):
`Core::data_path(peer)` is the path the peer's next data message leaves on (what the policy
selects for `MessageKind::Data`, else the current path), `Core::is_remote_index(peer, index)`
checks a quoted receiver index against the peer's current session, and
`Core::set_peer_pad_limit(peer, limit)` caps the padding of the peer's data at `limit` bytes
of plaintext (`noise::Tunn::set_pad_limit`), as kernel WireGuard pads to the interface MTU: a
packet is padded to the lower of the next multiple of 16 and the limit, and one of at least
the limit is not padded. `None`, the default, pads to a multiple of 16 as before; deferred
`CryptoJob`s honor the limit too.

**Inbound destinations.** `PeerConfig::inbound_destinations` (`None` by default: unchecked)
restricts where a peer's decrypted packets may be addressed. The core checks the destination
after decryption, right after the source check and before the inbound filters, on every receive
path (per packet, batched, deferred); a packet to another destination, or whose destination
cannot be read, is dropped as `reasons::DESTINATION_NOT_ALLOWED`. The networks sit in their
own per-peer table, apart from routing (they add no routes), and the last accepted
destination of the batch is remembered like the other lookups.
`ConfigChange::SetInboundDestinations` (`EngineHandle::set_inbound_destinations`) sets or removes them at runtime, and
`add_or_update_peer` with `Some` replaces them (`None` keeps them). An unchecked peer pays one
`Option` check per packet; no peer pays an allocation or a lock.

`handle_input_deferred` is the same entry point for a driver that encrypts on several
threads: the cryptography of a local packet or a received transport data message comes back
as a `CryptoJob` (everything before it, such as routing and the outbound filters, has
already run), `CryptoJob::run` seals or opens the packet under the lock of that peer's
tunnel only, and `complete_job` does the rest in the core (counters, completed handshakes,
roaming, the source check, the inbound filters, the output); `handle_datagrams_deferred`
and `handle_locals_deferred` do the same for batches. Only a core built with
`CoreConfig::crypto_jobs` hands out jobs, and only then does each peer's tunnel sit behind
its own mutex, shared with its jobs; otherwise every peer owns its tunnel and the data path
takes no lock (`handle_input_deferred` then processes every input at once).

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

Without crypto workers the owner also delivers to the sink itself when the sink task is
idle, and sends itself when the transmit task is idle and no input is waiting (inline
output, below), skipping that hop.

The core is never shared, and without the crypto worker pool the data path takes no lock;
with the pool, each peer's tunnel is behind a mutex that only the owner takes (the jobs
carry the session keys they need), so it is uncontended.

When the owner wakes for a received datagram or a local packet, it also takes the ones
already queued behind it (up to `MAX_BATCH`, 64) and feeds them to the core as one batch
(`Core::handle_datagrams`, `Core::handle_locals`). It never waits for a batch to fill and
runs no timer for it, so a lone packet goes through at once. Received datagrams are taken
up to the sink queue's room; local packets up to the transmit room (see the backpressure
list below). Without crypto workers the source and receive tasks hand over what one read
returned as one message (up to `MAX_BATCH` items, as many as the queue has room for; a
lone item goes over without an allocation); the input queues stay bounded in items (a
semaphore of `queue_capacity` permits beside the channel). With crypto workers they hand
over one item per message. The other way, the owner hands the datagrams one drain queued
for a transport to its transmit task as one message (the transmit queue stays bounded in
datagrams), and transmitted buffers go back to the source task one message per sent batch,
over a lossy bounded queue, for `PacketSource::recycle` (`TunSource` reads into them
again); a source that keeps the default no-op gets none after the first, and the buffers go
to the core's pool as before.

Inline output: without crypto workers and while not suspended, the owner sends a drain's
datagrams itself (`Transport::try_send_batch`) when nothing of that transport is in its
backlog, its transmit queue or the batch its transmit task is sending, and hands the
drain's delivered packets to the sink itself (`PacketSink::try_send_batch`) when nothing is
queued for or being delivered by the sink task. It sends itself only for a drain after
which no local packet and no received datagram is waiting (it would wait next); under load
it hands the datagrams to the transmit task, which sends them while the owner seals the
next batch. Delivery is not gated on waiting input. Whatever is not taken at once goes to
the transmit queue / backlog or the deliver queue, in order, under the usual rules below;
later traffic queues behind it until the task has drained it, so a peer's order on one
transport is kept. Inline-sent buffers return to `Core::recycle` directly. A transport or
sink whose `try_send_batch` took nothing (it keeps the default, or is full) is skipped for
1, 2, 4, ... up to 1024 drains and tried again once that wait is over; taking anything
resets the wait, so a default implementation costs about one try per 1024 drains. The
defaults of both `try_send_batch` methods take nothing, which keeps every datagram and
packet on the tasks; `UdpTransport`, the Unix `TunSink` and `PipeSink` override them.
`MapSink` keeps the default on purpose: forwarding would map the packets its inner sink
leaves behind, and the engine's later `send_batch` would map them a second time.

- `EngineHandle` sends commands to the owner (peers, keys, allowed IPs, path, transport,
  stats, injection, shutdown) and returns their replies.
- Events are published on a `broadcast` channel (`EngineHandle::subscribe`); publishing never
  blocks, and a lagging subscriber loses the oldest events.
- Drops are counted per reason (`EngineHandle::drop_counters`) and published as events.
- Unanswered handshake initiations are counted per peer and in total
  (`EngineHandle::unanswered_handshakes` / `total_unanswered_handshakes`, see nsplane-core).
- Traffic is counted per peer (`PeerStats`: wire bytes and plaintext bytes) and per transport
  (`EngineHandle::transport_stats`: datagrams and bytes each way, failed sends), the latter
  once per batch by whoever moved it (the transport's receive/transmit tasks, or the owner
  task when it sends itself), one relaxed atomic update per batch. `EngineHandle::status`
  returns the key, MTU, suspension, peers, transports, drops, queue and fragmentation stats,
  peer MTUs and path MTU counters in one owner call. Counters only grow; rates, metric export and labels such as direct vs relay
  are left to the caller (ns), which samples `status` and maps transport ids to its paths.

Backpressure:

- Local packets are never dropped by an engine with one transport: when the transmit queue
  is full, datagrams wait in the owner task (the transport's backlog). The owner reads local
  packets only while some transport has room for them and takes no more at once than the
  largest room, counting one datagram per packet; a transport's room is its free transmit
  slots while its backlog is empty, plus `min(MAX_BATCH, capacity)` minus its backlog. With
  no room it stops reading, which holds back the source, so a saturated transport keeps at
  most `MAX_BATCH` local datagrams in its backlog.
- With crypto workers, received datagrams with the workers count against the deliver
  queue's room: the owner reads received datagrams only while the deliver queue has room
  beyond them, so a sink slower than the network holds datagrams back in the transport
  (the UDP socket buffer) instead of dropping decrypted packets under `DROP_SINK_FULL`, as
  without workers.
- Datagrams caused by received datagrams or timers that find the waiting datagrams at the
  queue capacity are dropped (`DROP_TRANSMIT_FULL`).
- A full sink queue drops the decrypted packet (`DROP_SINK_FULL`); a closed sink or
  transport drops with `DROP_SINK_CLOSED` / `DROP_TRANSPORT_CLOSED`, and without a transport
  datagrams are dropped with `DROP_NO_TRANSPORT`.
- An I/O side that reports `BrokenPipe` stops its task; the engine keeps running without it.
  Inline output follows the same rules: a failed inline send counts as a failed send
  (`DROP_TRANSPORT_SEND_ERROR`), `WouldBlock` is not a drop (the rest is queued, and only
  then can `DROP_SINK_FULL` / `DROP_TRANSMIT_FULL` apply), and `BrokenPipe` marks the
  transport or sink closed.
- Known limitation: `TunSink` with TCP segmentation offload coalesces packets before a
  write; an inline TUN write that hits `EAGAIN` mid-chunk keeps the rest of that chunk and
  writes it first with the next delivery (no drop, order kept). Only a lowered
  `TUNSETSNDBUF` makes a Linux TUN write block.

### Queue depths

`EngineHandle::queue_stats` reports, for every bounded queue, its capacity and high-water
mark (the most items it held at once) since the start or the last `take_queue_stats`, which
also restarts the marks. The owner task samples each queue whenever it sends to or receives
from it (a receive sees the occupancy just before it, which is the peak since the previous
receive), with plain fields and no locks or atomics on the data path. The event channel is
sampled only for events other than `Event::Dropped`, because reading its occupancy takes the
channel's locks.

| Queue | Capacity | Producer -> consumer |
| --- | --- | --- |
| `command` | 64 | handles -> owner |
| `local` | `queue_capacity` | source task -> owner |
| `datagrams` | `queue_capacity` | every receive task -> owner |
| `deliver` | `queue_capacity` | owner -> sink task |
| `recycle` | `queue_capacity` | every transmit task -> owner (full: buffer dropped); used only when the source keeps the default `PacketSource::recycle`, the lossy queue back to the source is not counted |
| `transmit` | `queue_capacity` per transport | owner -> transmit task, in datagrams, counting the batch being sent |
| `backlog` | `queue_capacity` per transport | owner, waiting for room in `transmit` |
| `events` | `event_capacity` | owner -> subscribers |
| `crypto` | `queue_capacity` (the bound of jobs in flight) with 2 or more crypto workers, else 0 | owner -> workers -> owner (jobs not completed yet) |
| `crypto_done` | `queue_capacity` with 2 or more crypto workers, else 0 | workers -> owner (batches of finished jobs) |

Without crypto workers, the datagrams and packets the owner sends or delivers inline (see
[nsplane (driver)](#nsplane-driver)) never enter `transmit`, `deliver` or `recycle`. The
owner sends inline only when no input is waiting, so under load `transmit` (and `recycle`)
rise as before; `deliver` stays low or at 0 while the sink keeps up, and rises only once
the sink falls behind and packets fall back to the sink task. `recycle` counts only the
buffers a transmit task returns to the owner. With a source that recycles (`TunSource`,
or a `MapSource` around one) every transmitted buffer, inline-sent ones included, goes back
to the source instead and `recycle` stays at 0; otherwise inline-sent buffers go back to
the core directly.

Measured with the default capacity of 1024 on two engines linked in process (release
build, 4-thread runtime, 32-core host shared with other jobs, so throughput is noisy),
before the inline output; the highest mark of either engine over three runs:

| Load | local | datagrams | deliver | recycle | transmit | backlog | command | events | Drops |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Ping-pong, 1300 B, one packet in flight (the `data_path` pattern) | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | none |
| UDP paced, 64 x 1300 B per ms, channel link | 64 | 41 | 53 | 64 | 64 | 0 | 0 | 0 | none |
| UDP paced, 64 x 1300 B per ms, loopback `UdpTransport` | 103 | 43 | 64 | 107 | 107 | 0 | 0 | 0 | none |
| UDP flood, 100k x 1300 B, channel link | 1024 | 341 | 866 | 1023 | 1024 | 449 | 0 | 0 | none |
| UDP flood, 100k x 1300 B, loopback `UdpTransport` | 1024 | 120 | 239 | 1013 | 1024 | 280 | 0 | 0 | none (the kernel drops ~25%) |
| Netstack TCP, 1 connection, 32 MiB echoed (2.5-7.4 Gbit/s) | 668 | 642 | 212 | 247 | 665 | 0 | 0 | 0 | none |
| Netstack TCP, 4 connections, 32 MiB echoed | 1024 | 1024 | 1024 | 469 | 1024 | 1024 | 0 | 0 | `DROP_SINK_FULL` in 3 of 6 runs |
| Netstack TCP, 8-16 connections, 32 MiB echoed | 1024 | 1024 | 1024 | 896 | 1024 | 1024 | 0 | 0 | `DROP_SINK_FULL` in every run |

With capacity 2048, 8 and 16 netstack connections ran without a drop (deliver peaked at
494 and 2021); with 512 and 256, even 4 connections dropped at the deliver queue. Once the
deliver queue drops, the netstack's TCP throughput collapses (to 130-450 Mbit/s), and in
some runs the connections stalled for good with every engine queue empty, a loss recovery
problem of the netstack rather than of the queues. The stalls were fixed in the smoltcp
fork (`.3`); the collapse after sink-full drops by `.4`'s NewReno, SWS avoidance and
Limited Transmit: in process, four bulk streams at the default capacity still drop
250-580 packets at the sink per GiB but now move 1.00-1.11x the one-stream aggregate
(0.43x on `.3`), see [Netstack throughput](#netstack-throughput).

Defaults, from these numbers:

- `queue_capacity` stays at 1024. A single bulk TCP flow, the heaviest paced load, peaks at
  about 670 (1.5x headroom), and paced or request/response traffic stays far below. Floods
  and many parallel bulk flows fill every queue upstream of the bottleneck whatever the
  capacity (the in-process loop is bounded by the TCP windows, not by a link rate), so a
  larger default would only add latency and memory, and a smaller one turns the sink-full
  drops of the multi-flow case into a single-flow problem. Since queued packets are sized
  to their contents, an idle or lightly loaded queue costs little.
- The command queue stays at 64: every handle call waits for its reply, so it holds at most
  one command per concurrent caller (the marks never passed 1).
- `event_capacity` stays at 1024: without a subscriber the channel holds nothing, and a
  subscriber that stops reading fills any capacity.

Embedders that run many parallel bulk flows through a userspace netstack should raise
`queue_capacity` (2048 held 16 flows without a drop here) and watch the marks and
`DROP_SINK_FULL` with `queue_stats` and `drop_counters`. The alternative on the sending
side is `NetStackConfig::tcp_send_budget`, which keeps the stack's connections together
within one budget instead of one window each: with a budget of one default send buffer
(512 segments) four in-process streams dropped nothing at the sink and moved 648-671 MB/s
against 135-188 MB/s without it on smoltcp `.3`, and on `.4` 749-795 MB/s, the same as
without it (689-841 MB/s, load 3-6). It caps all connections together at
`budget / RTT` (one default send buffer, about 690 KiB, is about 14 MB/s at 50 ms), so it
suits stacks whose peers are near; it stays opt-in.

### Crypto worker pool

The single owner task is the limit of one engine's throughput: it seals and opens every
packet. `EngineBuilder::crypto_workers(n)` with `n` of 2 or more moves that cryptography to
`n` worker tasks; 0 or 1 (the default) keeps today's single task, which then never calls the
deferred API.

```text
local packets ─┐           ┌─► worker 0     ─┐
               ├─► owner ──┼─► worker 1     ─┼─► done queue ─► owner ─► sink, transmit tasks
datagrams     ─┘           └─► worker n - 1 ─┘
```

- One peer on every worker (OE-4, C7; until then jobs were sharded by `peer id % n`, so one
  peer used one worker). The owner feeds each local packet and received datagram to
  `Core::handle_input_deferred`, which routes it (receiver index or destination), runs the
  outbound filters and prepares a `CryptoJob` on the peer's tunnel: a local packet gets the
  session's next counter (nonce), in order (`Tunn::reserve_in_place` -> `SealTicket`), and a
  received message passes the session and replay-window check (`Tunn::open_ticket` ->
  `OpenTicket`). The job carries the session key and counter, so `CryptoJob::run` never
  touches the tunnel. Jobs go to the workers in turn, whatever their peer, and the owner
  completes them (`Core::complete_job`) in the order it handed them out, through a reorder
  buffer keyed by job sequence: a received message's counter is marked as received only
  there (`Tunn::commit_open`), so a duplicate opened on two workers at once is still
  rejected, and a datagram of a session that expired or was replaced meanwhile is dropped
  and counted. So all packets of one peer, in both directions, are emitted in arrival
  order, and one peer's cryptography spreads over every worker.
- Batches. Jobs go to a worker in batches of up to 64 (`MAX_BATCH`): a worker's batch is
  handed over when it is full, together with every other batch, or when the owner has
  nothing else ready, and a worker hands each batch back whole. A busy owner thus wakes each
  worker once per batch instead of once per packet; handing over every packet on its own
  cost as much as the cryptography it moved and gained nothing.
- Everything else stays on the owner: handshakes (the gate, the responses, flushing the
  packets queued behind a handshake), timers, configuration, events, drop counters, roaming
  and the per-peer counters. Workers never lock a tunnel, so a handshake or a timer never
  waits for a worker. The order on the wire stays the arrival order
  even when the owner seals a keepalive or flushes queued packets while newer packets of the
  peer are with a worker: those are emitted only once they come back.
- Bounds: at most `queue_capacity` jobs are with the workers. While that many are, the owner
  stops reading local packets and received datagrams (handle calls, timers and finished jobs
  are still served), which holds back the sources as a full transmit queue does. Every
  worker queue and the done queue hold that many jobs, so neither side ever waits on them.
- Handle calls that read or change peers, sessions or counters (configuration, peer stats,
  injection, forced handshakes, drop counters) first wait for every job in flight, so they
  act after every packet read before them, exactly as without workers: per-peer stats and
  drop counters stay exact, and a removed peer's packets read before the removal still go
  out while later ones are dropped as `no route` / `unknown session`.
- Parallelism needs a multi-threaded tokio runtime; on a current-thread runtime the workers
  interleave with the owner and only add overhead.
- No inline output: with 2 or more workers the owner never sends or delivers itself; every
  datagram goes through the transmit task and every packet through the sink task, and the
  source and receive tasks hand over one item per message, as before the engine fast path.

Throughput note, from `cargo bench -p nsplane --bench worker_pool` (bench profile with
LTO, multi-threaded runtime, 32-core host shared with other jobs; the range of two runs,
taken after the Phase 5 follow-ups #1 and #17: batched core input, no lock without
workers): a
hub engine with 8 peers, each its own engine without workers on an in-memory link, sends
120 packets to every peer while every peer sends 120 to the hub, so the hub seals and opens
all 1920 packets of an iteration. The pool off is the default of 0 workers; 1 worker is the
same code path.

| Packet | Pool off (0 or 1) | 2 workers | 4 workers |
| --- | --- | --- | --- |
| 64 B | 1.49-1.55 Mpps (1.29 / 1.24 ms) | 1.64-1.68 Mpps (1.14 / 1.17 ms) | 1.61-1.64 Mpps (1.19 / 1.17 ms) |
| 1420 B | 869-906 kpps (9.9-10.3 Gbit/s; 2.21 / 2.12 ms) | 0.94-1.20 Mpps (10.6-13.6 Gbit/s; 2.05 / 1.60 ms) | 1.17-1.26 Mpps (13.3-14.3 Gbit/s; 1.53 / 1.64 ms) |

Before those follow-ups, in the same session, the mean iteration times were 1.59 / 1.79 ms
(64 B, pool off), 1.48 / 1.51 ms (64 B, 2 workers), 1.53 / 1.52 ms (64 B, 4 workers),
2.84 / 2.84 ms (1420 B, pool off), 1.88 / 1.92 ms (1420 B, 2 workers) and 1.96 / 1.96 ms
(1420 B, 4 workers): every case is about 15-25 % faster now, except 1420 B with 2 workers,
which is within the run-to-run noise.

With full-size packets the pool moves the hub up to about 1.4x further; small packets gain little,
since there the cryptography is a small part of the owner's work per packet (queues,
routing, counters). Beyond 2 workers the owner task itself, which still touches every
packet twice, is the limit, so 4 workers do not add to 2. Sharding `Core` itself by peer
(one owner per shard) would lift that limit, at the cost of splitting the handshake gate,
the peer table and the allowed IPs across shards.

Since OE-4 the bench also runs a single peer (`worker_pool_one_peer`: the hub linked to a single spoke
that has as many workers, the same packets per iteration): with 1420 B packets 792 k / 1.30 M / 1.41 M packets per second with 0 /
2 / 4 workers (2026-10-05, load1 below 4.2; 0.37 M with 2 workers before OE-4, when a peer
used one worker). The hub cases did not change with it (-4.6 to +1.8 % against main).

The pool off takes no lock (follow-up #17): the core hands out crypto jobs only when built
with `CoreConfig::crypto_jobs`, which the engine sets for 2 or more workers, and otherwise
every peer owns its tunnel outright. With the pool, each peer's tunnel is behind a mutex
that only the owner takes (since OE-4 the jobs carry their keys), so it is uncontended. The lock had cost no more than the run-to-run spread when it was added
(`core_round_trip` medians 616 -> 569 ns at 64 B and 1347 -> 1362 ns at 1420 B); without it
the `data_path` core round trip measures 532 ns at 64 B (device-equivalent 474 ns, raw
`Tunn` 359 ns) and 1.348 us at 1420 B (device-equivalent 1.282 us), against 546 ns and
1.354 us on main 64131c7.

`UdpTransport` is the network side: one dual-stack UDP socket with fwmark and ECN support,
4 MiB socket buffers requested (clamped by `net.core.rmem_max` / `wmem_max`) and segmentation
offload through `quinn-udp`. Since OE-2, on Linux a segmented run is sent as one `sendmsg`
with one iovec per datagram and the `UDP_SEGMENT` / TOS control messages (no train buffer
copy; on `EIO` / `EINVAL` the run goes through `quinn-udp`, which turns segmentation off as
before); coalesced reads take turns in a ring of four 128 KiB storages instead of
allocating while slices of the last one are queued, and after four coalesced reads in a row
of one datagram each (a peer that sends no trains, e.g. kernel WireGuard) `recv_batch`
reads up to 16 datagrams per `recvmmsg` until a train arrives. With offload off, runs to one
address and ECN mark go out with `sendmmsg` and `recv_batch` reads up to 16 datagrams per
`recvmmsg`: batching, not offload, as every datagram stays its own message.
`ChannelSource`, `ChannelSink` and `ChannelTransport` are in-memory implementations for tests
and embedders.

**UDP side channel.** Another protocol can share the `UdpTransport`'s port (ns control
messages next to WireGuard, say). `UdpTransport::with_side_channel(classify, capacity)`
runs `classify` on every received datagram, each GRO segment on its own, in the receive
path of `recv` and `recv_batch`; a datagram it picks is copied into a `SideDatagram`
(`from`, unmapped as `Path::addr` reports it, and `datagram`) and `try_send`-ed to the
returned receiver of `capacity` entries, never reaching the engine; a full or closed
receiver drops it. `SideSender::stats` counts both (`SideStats { received, dropped }`);
they live on the sender, not in `TransportStats`, because side datagrams never reach the
engine's transport tasks. `SideSender::send_to` writes straight to the non-blocking socket
without an ECN mark: it never waits behind the engine's traffic and fails with
`WouldBlock` when the send buffer is full. `SideSender::send_to_async` addresses the same way
but, on a full send buffer, waits for the socket to be writable and tries again (ns's MQ-5):
it waits on the same readiness as the engine's own sends and takes no lock, so it never
delays them; it is cancel safe (a dropped future sends nothing or the whole datagram, once).
Pinned by `nsplane-e2e`'s `udp_side_channel::awaited_side_sends_beside_wireguard_offload_on`
/ `_off`. A capacity of 0 is raised to 1; a second call replaces
the channel (the old receiver closes once drained). Without a side channel nothing is
classified; the receive path checks one `Option` per datagram.

**Path MTU discovery on `UdpTransport`.** `UdpTransport::set_path_mtu_discovery(true)` (off
by default; Linux and Android, `Unsupported` elsewhere, since macOS and Windows deliver no
ICMP errors to an unconnected UDP socket) sets `IP_RECVERR` / `IPV6_RECVERR` and makes every
receive read the socket's error queue empty first: each ICMP Fragmentation Needed or ICMPv6
Packet Too Big about one of the transport's datagrams becomes a `PathMtuReport` (the
destination path, the MTU it carries, the datagram's first 8 bytes as the quote); other
errors are read and skipped, and no error fails a receive. The reports reach the engine
through `Transport::path_mtu_reports`, handed out once after the first switch-on, so it is
turned on before the transport is given to the engine; at most 64 wait, further ones are
dropped and counted (`UdpTransport::path_mtu_reports_dropped`). The kernel learns of a too
small path only for datagrams sent with DF: with offload all of them, without it only those
below the path MTU it knows. Two caveats while it is on: an ICMP error can fail one send
before a receive reads it (the engine drops and counts that datagram, `SideSender` returns
the error), and once the socket has reported an error tokio keeps its write readiness (after
`EPOLLERR`), so a send that finds the send buffer full (`send`, `send_batch`,
`SideSender::send_to_async`) retries after pauses of 1 ms doubling up to 8 ms and may go out
up to 8 ms after room appeared; sends that find room are not delayed, and with discovery off
nothing changes (`nsplane`'s `udp::tests::full_sends_back_off_after_an_icmp_error` and the
root `full_send_buffer_backs_off_after_an_icmp_error`, ignored without `CAP_NET_ADMIN`).
Pinned by the root test
`nsplane-e2e`'s `path_mtu_root::path_mtu_follows_real_icmp_errors` (ignored by default; needs
`NET_ADMIN` and `SYS_ADMIN`, its module docs give the command).

**Message links.** `LinkTransport` (opt-in; nothing runs unless one is created) carries
datagrams to one peer as messages over a link the embedder dials, so `nsplane` itself has
no WebSocket or TLS dependency. Its task asks the `LinkDialer` for a link (a `LinkSender`
and a `LinkReceiver`), drains the send queue into it and hands received messages to
`recv`, reported from `Path { transport: id, addr: peer, ecn: NotEct }`; sends to another address are
dropped and count as sent.

- `LinkConfig::queue` (256) bounds the datagrams waiting for the link, also while none is
  up; `send` never waits, and on a full queue fails with `WouldBlock`, which the engine
  counts under `DROP_TRANSPORT_SEND_ERROR`.
- A link ends when the receiver yields `None` or an error, a send fails (that datagram is
  lost; the queued ones go out on the next link) or `LinkConfig::read_idle_timeout`
  (default `None`) passes without a message. The task reports `LinkState::Disconnected`
  to `LinkDialer::on_state` and dials again at once, also after a failed dial; the dialer
  owns the backoff and may sleep in `dial`.
- The idle timeout is reset only by messages the receiver yields, so a dialer whose
  keepalive frames are consumed inside its receiver does its own idle detection. The
  examples' WSS client (`examples/src/relay/wss/client.rs`, a tokio-tungstenite dialer)
  does: it pings every 10 s and closes a connection silent for 35 s.

**Per-path MTU** (ns's MQ-1). One peer's paths (direct UDP, a relay, WSS) carry different
datagram sizes, so the engine can keep an inner MTU per peer below the source MTU:

- Two ceilings limit a path: per transport, the largest WireGuard datagram it carries
  (`EngineBuilder::transport_max_datagram(id, max)`, `EngineHandle::set_transport_max_datagram`,
  e.g. a relay's frame limit), and per path (transport and remote address), an outer IP MTU
  learned from reports (`EngineHandle::report_path_mtu(path, mtu)`, or
  `Transport::path_mtu_reports`, which `UdpTransport` feeds on Linux, above).
- A report is accepted only for a path some peer's data leaves on or a peer's stored path,
  only if it lowers what the path allows (one equal to the learned MTU confirms it), and,
  when it quotes the datagram (`PathMtuReport::with_quote`), only for a transport data message
  carrying that peer's current receiver index. `mtu` 0 takes the next RFC 1191 plateau below
  the current outer MTU; IPv6 paths take at least 1280, IPv4 at least 576. A learned MTU
  expires `EngineBuilder::path_mtu_expiry` (10 minutes) after the report that set or last
  confirmed it, which restores the transport's ceiling; the engine does not probe upwards.
- A peer's inner MTU follows the path its data leaves on (`Core::data_path`): the source MTU,
  lowered to `min(transport limit, learned MTU - IP header - 8) - 32`, never below 1280; a
  1500-byte IPv6 path gives 1420. `EngineHandle::peer_mtu(peer)` returns it,
  `EngineHandle::peer_mtus()` is a watch of `PeerMtus { min, peers }` (the peers below the
  source MTU, updated only on a change) and `path_mtu_stats` counts reports received,
  applied, ignored and expired (`PathMtuStats`, also in `EngineStatus`).
- `EngineHandle::mtu` and `Event::MtuChanged` keep meaning the source MTU. The per-peer MTU
  reaches the local kernel or stack only through the fragmentation stage (below), which holds
  packets to the destination's peer's MTU, or through ICMP the caller generates from
  `peer_mtus`; without a fragmenter it is visible only there. On macOS and Windows no Packet
  Too Big reaches the transport, so `report_path_mtu` is the only way to set a path's MTU.
- From the first ceiling or report on, the owner caps every peer's data padding at its inner
  MTU (`Core::set_peer_pad_limit`), so a packet at the inner MTU makes an outer datagram of at
  most the path MTU; before, padding to a multiple of 16 bytes could overshoot it by up to
  15. A peer without this state (a plain `nsplane-cli`, another WireGuard) still pads to 16
  and can exceed the path MTU with its replies, e.g. at a 1420 source MTU over a 1500-byte
  IPv6 path, so both ends should use the feature.
- Nothing of it exists until a ceiling is set or a report arrives: no table, no padding
  limit, no per-packet lookup, and a report forwarder task is spawned only for a transport
  whose `path_mtu_reports` returns a receiver (the default returns `None`).

Pinned by `nsplane-e2e`'s `path_mtu` tests (`the_inner_mtu_follows_the_path_and_recovers`,
`packets_at_the_inner_mtu_fit_ipv4_and_ipv6_paths`,
`packets_at_the_source_mtu_fit_once_the_feature_is_used`,
`reports_that_lower_nothing_change_nothing`, `transport_ceilings_apply_at_once`,
`an_engine_without_the_feature_keeps_no_state`) and `path_mtu_root`.

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
- With per-path MTUs, a packet to a destination routed to a peer whose inner MTU is below the
  source MTU is held to that peer's MTU instead: the errors carry it and the fragments fit
  it. Packets within the lowest MTU of all peers pay no lookup.
- `EngineHandle::fragment_stats` returns the stage's `FragmentStats` (all zero without a
  stage): IPv4 packets fragmented, fragments emitted, Packet Too Big and Fragmentation
  Needed errors sent, and oversized packets dropped without an error for the rate limit
  (`rate_limited`), for no route (`no_route`) or because no error is allowed or the packet
  cannot be split (`dropped`). The drops are counted in `drop_counters` too, under
  `DROP_FRAGMENT_RATE_LIMITED`, `DROP_FRAGMENT_NO_ROUTE` and `DROP_FRAGMENT_OVERSIZE`.

For a hybrid local side, e.g. a TUN device next to a userspace netstack, `Splitter` is a
`PacketSink` that routes each delivered packet to one of several sinks by a closure
(`Fn(PeerId, &PacketBuf) -> usize`) and `MergeSource` is a `PacketSource` that serves
several sources round-robin and reports the smallest of their MTUs. The splitter awaits
only the chosen sink, but a waiting sink still holds back the engine's next delivery;
packets routed to an index out of range are dropped and counted (`Splitter::misrouted`).
`Splitter::stats` returns a `SplitterStats` snapshot (`#[non_exhaustive]`): `misrouted`, and
`failed`, packets whose chosen sink returned an error or that found every sink gone; a
delivered packet updates no counter.

**Local-side graph.** Three more primitives join local-side endpoints (TUN devices,
netstacks, engines, translators) into a graph, so an embedder writes routing closures and
decisions, not packet loops:

- `MapSink::new(sink, f)` and `MapSource::new(source, f)` run a closure on every packet in
  place, before delivery (`Fn(&mut PacketBuf, PeerId) -> MapVerdict`) or after reception
  (`FnMut(&mut PacketBuf) -> MapVerdict`). `MapVerdict::Drop` discards the packet: the
  sink's `send` returns `Ok`, the source reads the next one, and both count it in
  `dropped()`. The MTU passes through and the batch methods map each packet. A Redirect is a
  `MapSink` running the forward translation plus a `MapSource` running the reverse one.
  `Nat64LanSink` / `Nat64LanSource` are equivalent to a `MapSink` / `MapSource` over a
  `Nat64Lan` and stay as they are.
- `pipe(capacity, mtu)` returns a `PipeSink` and a `PipeSource`: what is sent to the sink
  comes out of the source in order, so one engine's (or a `Splitter`'s) output is another
  engine's input without a forwarding task. `send` waits while the pipe is full; once the
  source is dropped it returns `BrokenPipe`, and once every `PipeSink` clone is dropped the
  source returns `BrokenPipe` after draining. The `from` peer is not carried.
  `PipeSource::mtu_sender` changes the MTU the source reports.
- `pump(source, sink, from)` moves every packet from a source into a sink in order, one
  `recv_batch` and one `send_batch` per round, and awaits the sink's backpressure instead of
  dropping. It ends with `Ok(PumpStats { packets, batches })` once either side returns
  `BrokenPipe` and returns any other error. Cancelled while it waits for the source it
  loses nothing; while it waits for the sink, at most the batch in flight.

```text
TUN source ─► pump ─► Splitter ─┬─► pipe ─► MergeSource ─► engine A
                                └─► MapSink (Redirect) ─► netstack sink
netstack source ─► MapSource (reverse) ─► MergeSource
engine A ─► Splitter ─┬─► pipe ─► engine B
                      └─► TUN sink
```

Four wrappers cover the per-packet glue left after that:

- `Splitter::new_map(route)` takes a closure `Fn(PeerId, &mut PacketBuf) -> usize` that may
  rewrite the packet in place (a Redirect or Masquerade translation) and then returns the
  sink index; the packet goes there as rewritten. The rest is `Splitter` as above: out of
  range drops the already rewritten packet as misrouted and returns `Ok`, only the chosen
  sink is awaited, and once every sink is gone the closure is not called. `Splitter::new`
  is a `new_map` whose closure only reads, so a reading splitter costs what it did.
- `MapSink::with_after(sink, f, after)` adds an after-delivery hook `Fn(&[u8])`, called with
  each packet's bytes as handed to `sink` (after `f`), once `sink` took it over: never for a
  packet `f` dropped or the one `sink` failed on, e.g. to retire a mapping only after the
  TUN writer took the packet. Kept packets are copied first into a buffer reused from call
  to call. `send_batch` calls `after` in order for exactly the packets `sink` took over:
  all of them on success, the ones before the failed packet on an error. A cancelled `send`
  or `send_batch` calls no `after` for that packet or batch, so a cancelled batch may have
  delivered packets whose hook did not run. `try_send_batch` keeps the default
  (`WouldBlock`) with or without a hook. The third type parameter defaults to `fn(&[u8])`,
  so `MapSink::new` and `MapSink<S, F>` are unchanged and pay nothing.
- `SwapSink<S>` is a sink whose inner sink is replaced, or removed, while the engine runs;
  clones share the slot and the drop counter, so the engine owns one and the embedder calls
  `replace` on another. While the slot is empty every packet is dropped, counted in
  `dropped()` and `Ok`; otherwise a call awaits the current sink. A call in flight finishes
  on the sink it started on, and `replace` does not wait for it; that is why
  `replace(Option<S>)` returns the old sink as `Option<Arc<S>>`, dropped once the last call
  holding it is done. An error from a sink replaced while the call was in flight is counted
  as dropped and returns `Ok`, so the engine does not take the local side for gone; an error
  from the current sink is returned unchanged.
- `AbortSink::new(sink)` returns the wrapped sink and a `SinkAbort` handle. Until the abort,
  each call races the inner call against it (one atomic load more when the call does not
  wait); `SinkAbort::abort` drops a pending inner `send` or `send_batch`, so nothing it
  carried arrives later, counts the packet in flight and the rest of the batch in
  `AbortSink::dropped`, and returns `Ok`. Later calls drop and count at once. It returns
  `Ok`, not `BrokenPipe`, because behind a `SwapSink` the next generation may already be
  installed: a `BrokenPipe` would make the engine (or a `pump`) tear down the whole local
  side mid-swap. Stopping whatever feeds the aborted sink stays the caller's job. Caveat:
  the packet being delivered counts as one, per the `send_batch` cancellation contract; an
  inner sink that takes several packets over at once may lose more than are counted.

A sink rebuilt per generation (ns's exit encrypt sender) composes the two: the engine gets
a `SwapSink<AbortSink<S>>`, and each new generation does `swap.replace(Some(next))` and
then `old_abort.abort()` on the previous generation's handle, so later packets go to the
new sink and a delivery stuck on the old, full one is cancelled instead of holding up the
engine or delivering after the old generation stopped.

`nsplane-e2e` covers them behind an engine: `graph_split_map` (a Redirect then route
demux, misrouted counting), `graph_after_delivery` (the hook reports every delivered packet
once and in order, none dropped or failed) and `graph_swap_sink` (an empty slot, a delivery
stuck on generation 1 aborted when generation 2 is installed, order kept, every packet
accounted for). The `local_graph` bench compares each wrapper with its baseline: `splitter`
(`new` vs `new_map`), `map_sink` (`new` vs `with_after`, `send` and `send_batch`) and
`swap_sink` (the bare sink vs `SwapSink` vs `SwapSink<AbortSink>` not aborted).

They are plain generic types and a `pump` runs only where the embedder spawns it: an engine
that does not use them is unchanged.

**Batched I/O.** The I/O tasks move up to `MAX_BATCH` (64) packets or datagrams per call
through `PacketSource::recv_batch`, `PacketSink::send_batch`, `Transport::recv_batch` and
`Transport::send_batch` (default methods that fall back to one at a time; `DynTransport`
mirrors them), with the same backpressure, stop handback and recycling as single calls:

```text
TUN read (vnet hdr + up to 64 KiB) ─► segments (<= MTU) ─► core seals ─► GSO UDP send
UDP GRO read ─► zero-copy slices ─► core opens in place ─► coalesced TUN writev
```

`Transport::send_batch` reports in its `failed` argument which of the datagrams it was done
with failed, so `TRANSPORT_SEND_ERROR` counts exactly the lost datagrams: a failed segmented
`UdpTransport` send loses its run, not the runs handed off before it in the same call.

Offload is negotiated where the device or socket is opened. `Tun::create` (Linux,
Android) asks for `IFF_VNET_HDR` with checksum offload and TSO, plus USO when the kernel
accepts it, and falls back to a plain `IFF_NO_PI` device; `Tun::offload` reports the
result. `UdpTransport::bind` sets the socket up with `quinn-udp`: GSO on send where the
platform has it, GRO on receive on Linux and Android, each GRO datagram a
`PacketBuf::from_shared` slice of the read buffer without headroom. A segmented send that
fails with `EIO`/`EINVAL` falls back to one datagram per send, and where `quinn-udp`
cannot set the socket up (Wine) the transport sends with plain `send_to`. With offload on
the socket sets DF, so outer datagrams above the path MTU fail with `EMSGSIZE`; the engine
counts them under `TRANSPORT_SEND_ERROR`. `TunOptions::offload(false)`,
`UdpTransport::bind_with_offload(.., false)` and the examples' `--no-offload` opt out. Plain
TUN reads (no virtio-net header, and Wintun reads on Windows) leave the same 28 bytes of
room behind each packet as segmented ones (a read still takes at most the MTU), so a
translator grows full-MTU IPv4 in place with offload off too.

## nsplane-wss

`nsplane-wss` carries data-plane traffic over WebSocket over TLS (ADR
`2026-10-03-data-channel-protocols-in-nsplane`: both legs of each data-channel protocol live
in nsplane). It is a separate crate on `nsplane`, so `nsplane` itself stays free of
WebSocket and TLS; only an application that adds it pulls in `tokio-tungstenite` and
`rustls` (aws-lc-rs provider). It is `#![forbid(unsafe_code)]` and publishes once
`nsplane` 0.8.0 is on crates.io (it has no unpublished dependencies).

**Connections.** Every carrier dials the same way, from one `WssConfig`:

- TCP, TLS and the WebSocket upgrade within `connect_timeout` (10 s), to `connect_addr`
  or the URL's host, with `server_name` (default the URL's host), the extra `headers` and,
  with a `BearerProvider`, `Authorization: Bearer <token>` fetched per dial.
- A `ws://` URL is accepted only with `allow_plaintext` (default `false`): TCP and the
  upgrade without TLS (port 80 by default; `server_name` and `tls` unused), everything
  else as for `wss://`. The connection's byte stream is a crate-private enum over the TLS
  stream (boxed, once per dial) and the plain `TcpStream`; one match per poll.
- An upgrade answered with any HTTP response (no 101) fails the dial with a public
  `WssDialError` inside the `io::Error` (`get_ref()` + `downcast_ref`): `status`, the
  response `headers` (non-UTF-8 values lossily) and the start of the `body`, the bytes
  that arrived with the head up to `WssDialError::MAX_BODY` (512, ns's log cut). The kind
  and message are unchanged: `PermissionDenied`, "wss upgrade rejected with HTTP {status}"
  for 401/403; `Other`, "wss connect failed: HTTP error: {status}" otherwise. Stream
  client opens waiting behind that dial get a copy with the detail.
- An upgrade answered with 401 or 403 is reported as `LinkState::Rejected(status)` on the
  carrier's `state()` watch (and counted in its stats). After a 401 the next dial waits
  until the provider yields a different token (polled every `token_poll`, 2 s, at most
  `token_wait`, 300 s); a 403, and a 401 without a provider, back off like any failure.
- Backoff: every dial but the first waits. After a link or session that came up (for the
  dialer and the server, the dial after a successful one) it waits `reconnect_delay` when
  set, and a dial failing after it waits `backoff_min` (2 s), doubled after each further
  failure up to `backoff_max` (60 s); the connector models this as a distinct
  `Retry::Reconnect` state, so the failure backoff restarts at the floor instead of
  doubling the reconnect delay. Without `reconnect_delay` (the default) the wait after a
  link is `backoff_min` as the first step of the doubling, as before. A stream client's
  capacity dial (another session while one is up) goes at once.
- Keepalive: a ping every `ping_interval` (10 s); the link ends when no frame at all
  (pongs included) arrived for `read_idle` (35 s). Every carrier reads both per dial
  (`WssConfig::keepalive`); ns sets its ping interval and a 45 s read idle. A zero
  `ping_interval` (`WssConfig::ping_interval(None)`) sends no pings: the dialer spawns no
  ping task and the session writers never wake for one; the read idle stays. No message
  above `MAX_MESSAGE` (4 x 65 535 bytes) is read.
- Events: `WssDialer::events()` and `WssStreamClient::events()` subscribe to a
  `broadcast` channel in the shared connector (`WssDialEvent::CAPACITY` = 64; a lagging
  receiver sees `RecvError::Lagged`), one `WssDialEvent` per occurrence: the connector
  sends `DialFailed`, `TimedOut` and `Rejected(status)` for each failed dial; the dialer
  sends `Connected` and `Lost` from `LinkDialer::on_state` (so a link's `Connected`, sent
  when the transport reports it up right after the dial, precedes its `Lost`), the stream
  client when a session comes up and where it ends. Without a receiver a send is a lock
  and a count check, no allocation; events are per dial, never per datagram. The counters
  and the `state()` watch are unchanged.
- TLS trust is the caller's: there are no built-in system or web PKI roots. `WssTls::Roots`
  takes a `RootCertStore` (the client configuration is built with aws-lc-rs, the safe
  default protocol versions and no client auth); `WssTls::Config` takes a complete
  `Arc<rustls::ClientConfig>` used as is (ns passes its `control::tls::client_config()`).
  Built-in roots may become an optional feature later if a consumer needs them.

**Datagram carrier.** `WssDialer` is a `LinkDialer`: `into_transport(id, peer, config)`
returns a `LinkTransport` whose links are WSS connections. Each datagram is one binary
message carrying its raw bytes (the wire of ns `OpaquePump` and the examples' relay); text
messages and messages above `MAX_DATAGRAM` (65 535) are dropped and counted in
`WssStats`, a close frame or the end of the stream ends the link.

**Stream carrier wire.** `WsFrame` (module `frame`) is ns `tunnel-ws`'s and NSGW's protocol,
byte for byte: every binary message is one frame, big-endian.

| Field / command | Bytes | Content |
|---|---|---|
| `stream_id` | 4 | the stream, per session (never 0 from the client) |
| `command` | 1 | one of the commands below |
| `OPEN_V4` (`0x01`) | 4 + 2 + 1 | IPv4 address, port, protocol (`0x00` TCP, `0x01` UDP) |
| `OPEN_V6` (`0x02`) | 16 + 2 + 1 | IPv6 address, port, protocol |
| `DATA` (`0x10`) | rest | stream bytes (at most `MAX_DATA_PAYLOAD`, 65 531, per frame), or one UDP datagram |
| `CLOSE` (`0x20`) | 0 | close the stream |
| `CLOSE_ACK` (`0x21`) | 0 | acknowledge a CLOSE |

As in ns, bytes after a complete OPEN, CLOSE or `CLOSE_ACK` are ignored and any protocol
byte but `0x01` is TCP. The protocol has no open reply and no flow control: a refused
OPEN is answered with CLOSE, and a stream whose peer outruns its receive budget is closed.

**Stream client.** `WssStreamClient` (the client leg, ns `proxy/wire.rs` and
`wss_flow.rs`) opens TCP streams (`open_tcp`, a `WssTcpStream` with `AsyncRead` and
`AsyncWrite`) and UDP flows (`open_udp`, a `WssUdpFlow` with `send` / `recv`) to targets
behind a terminate (NSGW, or `WssStreamServer`).

- Sessions: dialed lazily on the first open (or `connect`). Every TCP stream and UDP flow
  is multiplexed over one session until it holds
  `WssStreamLimits::max_streams_per_session` live ones (default 1024, NSGW's default
  `PER_SESSION_STREAM_CAP`); only then is one more session dialed. One dial runs at a time,
  in a task of its own (one per dial, not per open), and waiting opens share its outcome;
  an open dropped while it waits therefore loses neither the backoff nor the 401 token
  wait, and never starts a second dial. The wire format is ns's, unchanged. NSGW caveats: it rejects
  OPENs beyond its own per-session cap, which its operator can set below 1024 (keep
  `max_streams_per_session` at most the gateway's cap), and it writes all streams of a
  session through one shared writer queue.
- Stream ids count up from 1 per session, skipping ids still in use; an id stays in use
  until the peer's CLOSE or `CLOSE_ACK`. An open returns once its OPEN is queued.
- Half-close: `shutdown` sends CLOSE behind the data already written (the wire has no
  other half-close) and the stream keeps reading until the peer's CLOSE or `CLOSE_ACK`,
  then reads EOF; this matches the ns terminate and `WssStreamServer`, which drain the
  stream to the backend before ending it. A peer's CLOSE reads as EOF after the bytes
  before it and is answered with `CLOSE_ACK`; dropping a stream sends CLOSE.
- Queues and bounds (`WssStreamLimits`, ns's defaults): a control queue (OPEN,
  `CLOSE_ACK`, reset CLOSE, pings; 64 messages) written before the data queue (DATA and
  orderly CLOSE; 256 messages), and receive budgets of 4 MiB per stream
  (`stream_buffer`) and 32 MiB per session (`session_buffer`), each received frame
  costing its payload plus 64 bytes. Over budget, a TCP stream is reset (reads fail with
  `ConnectionReset`) and a UDP datagram is dropped while the flow stays.
- Fail-fast opens: `WssStreamLimits::open_timeout` (default `None`: an open waits as long
  as the dial, its backoff and token wait included). With `Some(t)`, `connect`, `open_tcp`
  and `open_udp` give up after `t` with a copy of the last dial failure (kind, message,
  `WssDialError`), or `TimedOut` ("wss open timed out") when no dial failed since the last
  session came up; the dial goes on and its session serves later opens. A dial that fails
  at once still fails the open at once. Without it no timer is armed.
- Reconnection: when a session ends (socket error, close, read idle) every stream and flow
  on it fails; the next open dials again after `reconnect_delay` (or the backoff). Frames
  for unknown stream ids are ignored and counted in `WssStreamStats`.

**Terminate leg.** `WssStreamServer` (ported from ns `tunnel-ws` `WsTunnel`) dials the
relay like the client and serves the protocol on the session; `run(shutdown)` drives it.

- Resolution is the embedder's: `WssResolver::resolve(WssOpen { session, stream_id,
  target, protocol })` returns the backend `SocketAddr` or `Denied` (answered with CLOSE).
  It runs on the stream's own task, so a slow answer delays only that stream. ns keeps its
  resolution (`OverlayResolver`, services.toml, FQID, ACL, gateway identity) behind it.
- An OPEN for an id in use, or beyond `max_streams` (1024), is answered with CLOSE. The
  server connects a TCP stream or a connected UDP socket (bound to the backend's address
  family) and relays: TCP bytes in DATA frames of at most `MAX_DATA_PAYLOAD`, one datagram
  per DATA frame for UDP.
- A CLOSE is always answered with `CLOSE_ACK`; the stream's queued data is still written
  to the backend, then its write side is shut. A backend EOF sends CLOSE behind the
  stream's data; a failed connect, a backend error (a failed UDP receive included) sends
  CLOSE at once.
- Queues and bounds (`WssServerLimits`, ns's defaults): 4 MiB per stream
  (`stream_buffer`), 32 MiB per session (`session_buffer`), 64 frames per stream
  (`stream_queue`), each received frame costing its payload plus 64 bytes until written;
  a frame over a bound closes its stream only (`WssCloseReason::Overflow`). Control queue
  64 messages (`CLOSE_ACK`, refusing or resetting CLOSE, pings), written before the data
  queue of 256 (DATA and the CLOSE after a backend's end).
- Events: `with_events(mpsc::Sender<WssStreamEvent>)` reports each stream's `Open` and
  `Close { reason, to_backend, from_backend }`; sending never waits, an event that does
  not fit is counted in `WssServerStats::event_drops`.
- Reconnection: one session at a time carries every stream. When it ends its streams are
  closed (`WssCloseReason::SessionEnded`) and the next session is dialed after
  `reconnect_delay` (or the backoff); a shutdown closes the open streams and the session.

ns `WsTunnel` has had no consumer since ns 0aef94a0 (2026-08-28); with the terminate leg
here, ns can delete `tunnel-ws` whole.

**Deviations from ns.** An orderly CLOSE is queued behind the stream's data on both legs.
Client: an over-budget UDP datagram is dropped and the flow kept, and the receive budgets
count payload plus 64 bytes per frame instead of ns's 64-message cap per stream. Server:
on a peer's CLOSE the queued data is drained to the backend and its write side shut (ns
dropped it), the half-close the client relies on; a failed UDP backend receive sends
CLOSE; the UDP socket binds to the backend's address family.

**Tests.** Unit tests next to the code (`frame`, `stream`, `server`, `connect`, `config`);
`crates/nsplane-wss/tests/stream.rs` runs the client and the server through a TLS test
relay (and a plain one for `ws://`) and checks the frames against the ns layouts;
`nsplane-e2e` `wss_datagram` runs two engines over `WssDialer` (401, 403, reconnect, read
idle), `wss_plain` over `ws://`, `wss_dial_error` checks the `WssDialError` of a 401
and a 503 (header, truncated body) from the dialer and the stream client,
`wss_keepalive` the ping cadence and read idle of both carriers at two settings, and
`wss_events` the event sequence (up, lost, up, 401 x 2, 403 x 2, relay down, timeout) and
the reconnect delay against the doubling backoff on both carriers, and `wss_stream_open`
the stream client's `open_timeout` (relay down, 403, relay coming up, and the default
waiting open); `examples/tests/wss.rs` and the
`relay-wss` cells of `just e2e-examples` run the examples' relay client on it.

## nsplane-tun

`Tun::create` opens a TUN device, `Tun::from_fd` (Unix) adopts one, and `Tun::split`
yields a `TunSource` and a `TunSink` registered with the tokio reactor. `Tun::name` and,
after the split, `TunSource::name` / `TunSink::name` query the created interface name from
the device (the kernel-assigned one for a `"tun%d"` or `"utun"` pattern, the adapter alias
on Windows), so a caller learns it without opening the device itself (MT-4).

- `linux`: `/dev/net/tun` (Linux, Android), raw IP packets, or with `IFF_VNET_HDR` a
  10-byte virtio-net header per read and write.
- `offload`: the virtio-net codec: GSO segmentation of read super-packets and TCP/UDP
  coalescing for writes (one `writev` of header and packet pieces per super-packet).
  Segments are appended with `PacketBuf::extend_from_slice`, without zero-filling first.
- Buffers (OE-1): `TunSource`, `SlotSource` and the Wintun reader size every read for the
  MTU, the translation slack and `TAILROOM` (padding plus AEAD tag, from `nsplane-packet`)
  behind the packet, so the core seals a full-size packet in place without reallocating.
  `TunSource` implements `PacketSource::recycle`: the engine hands transmitted buffers back
  and the source puts them into its pool up to its bound, so reads stop allocating;
  pooled buffers keep their initialized bytes, so a reused buffer is not zero-filled again.
  `TunSource::recv_batch` keeps reading without waiting after the first packet, until
  `EAGAIN`, a full batch or a split GSO read, so plain packets (no TSO: UDP, small packets,
  no offload) come in batches; a lone packet still returns at once.
- `darwin` and `utun`: the utun control socket (macOS, iOS), packets framed by a 4-byte
  address-family header.
- `unix`: non-blocking fd I/O shared by both.
- `windows`: a Wintun adapter; a reader thread feeds the source.
- Windows service TUN (MT-3, `windows` and `wintun`): `Tun::create_with(name, options)`
  adds opt-in checks; `Tun::create` keeps loading `wintun.dll` through the loader's search
  path and opening or creating the adapter. Order: the MTU is validated (below 576 is
  `InvalidInput`); with `TunOptions::wintun_pin(WintunPin)` the file at the pin's path
  (default `wintun.dll` next to the executable, made absolute) is read (at most 16 MiB) and
  its SHA-256 compared before any DLL code is loaded, then that same absolute path is loaded;
  a missing file is `NotFound` with the wintun.net remedy (`bin\<arch>\wintun.dll`, elevated
  terminal), a mismatch `WintunError::HashMismatch`. The file can still be replaced between
  check and load, so it must sit in a directory only administrators can write. With
  `exclusive(true)` an existing Wintun adapter (`Adapter::open` succeeds; that handle is
  only closed) or any interface with that alias (`ConvertInterfaceAliasToLuid`) is refused
  with `WintunError::AdapterExists` instead of opened. Once the adapter is open, a pinned
  `driver_version` is compared with the running driver (`WintunError::DriverVersionMismatch`;
  dropping the handle removes an adapter this call created), then `mtu(n)` sets the
  interface MTU (IPv4, IPv6 where the row exists) and `Tun::mtu` reports the read-back IPv4
  value. The typed errors travel inside `io::Error` (`InvalidData`, `AlreadyExists`) and are
  recovered with `downcast_ref::<WintunError>()`. Verified here: the pure logic in Linux unit
  tests, the pin-before-load path under wine (no wintun.dll); adapter creation, the
  exclusive refusal against a live adapter, MTU set/read-back and the driver version query
  need a real Windows host.
- `slot`: `TunSlot`, an fd local side the host swaps while the engine runs (Android
  `VpnService`). `TunSlot::new(mtu)` returns the control handle, a `SlotSource` and a
  `SlotSink`; built on Linux, Android, macOS and iOS (the cfg of `Tun`), not on other Unix
  targets or Windows. Every read and write runs under a shared lock and only if the fd it
  waited on is still installed (a generation counter); `replace` and `close` take the lock
  exclusively and bump the generation. So once `replace(fd)` returns no syscall runs on
  the previous fd, and a read completed on it but not yet returned is discarded and
  retried on the new one; the old fd closes when no I/O holds it. `disable` parks reads
  and writes until `enable`; `close`, or dropping the last handle, fails the source, the
  sink and later `replace` calls with `BrokenPipe`. `clear` removes the installed fd with the
  same fencing as `replace` and keeps the slot open: the fd closes once no I/O holds it, and
  reads and writes wait for the next `replace` (a no-op after `close`), so a retired Android
  generation's fd does not stay parked. Reads get an MTU + 1 buffer: a longer
  read is dropped and counted (`SlotSource::oversize_drops`), a 0-byte read is
  `UnexpectedEof`. Each packet is one write without header; a short write is `WriteZero`.
  No offloads, and the MTU watch keeps the value given to `new`. The caller keeps its own
  generation numbering, attach/activate ordering and host-claim rules.
- `host`: `host_tun(mtu, capacity, write)`, a local side for hosts that hand packets over
  through callbacks (iOS `NEPacketTunnelFlow`); platform-independent. It returns a
  `HostTunInput`, a `HostTunSource` and a `HostTunSink`. The contract named it
  `HostTun::new`; it ships as a free function so no `clippy::new_ret_no_self` suppression
  is needed. `HostTunInput::push` copies the packet once into a bounded queue
  (`capacity` packets, `HOST_TUN_DEFAULT_CAPACITY` = 4096) without blocking, from any
  thread, and fails with `PushError::Full` or `PushError::Closed` (source dropped). The
  source drops and counts packets longer than the MTU (`oversize_drops`), logging the first
  one as a warning, and returns `BrokenPipe` once every input is dropped and the queue is
  drained. `HostTunSource::set_mtu` changes the MTU, e.g. once an iOS host knows its
  configured MTU: every packet read afterwards is checked against it, those queued before
  the call included, the value is published on the `PacketSource::mtu` watch only when it
  changes, and `oversize_drops` is not reset. The sink calls `write` synchronously on the engine task; `false` drops the
  packet and returns `BrokenPipe`.

## nsplane-netstack

`NetStack::new` starts a user-space TCP/IP stack on smoltcp for the addresses in its
`NetStackConfig`, and `NetStack::split` yields a `NetStackSource` (egress) and a
`NetStackSink` (ingress) that an `EngineBuilder` takes in place of a TUN device. The
application side is `NetStackHandle`: `incoming_tcp` and `incoming_udp` accept connections
and flows to any port of the stack's addresses, `connect_tcp`, `bind_udp` and
`connect_udp` open them.

One driver task owns smoltcp. Each iteration takes a bounded batch of ingress packets,
sizes the TCP listener pool to the batch's SYNs, then ingests the packets one by one with a
single smoltcp egress turn after each (`poll_ingress_single` / `poll_egress`), moves
connection bytes between smoltcp and the applications, and flushes egress. UDP bypasses
smoltcp on its own dispatch path.

- Every queue is bounded (ingress, egress, accept and datagram capacities in
  `NetStackConfig`); the sink waits while ingress is full. One driver turn routes up to
  256 ingress packets before any application reads, so a burst to one UDP flow or socket
  beyond `datagram_capacity` loses the excess even when the application keeps up on
  average (`udp_queue_full`). In the harness's netstack pair that was 100 % of the
  receiver's UDP loss at 1 Gbit/s and 99 % at 3 Gbit/s with the former default of 128
  (per-hop accounting; the kernel, the sender and reordering lost nothing). The default
  is 256, one driver step (QN-4, see [Netstack throughput](#netstack-throughput)); the
  queue grows on demand in 32-entry blocks, so an idle flow costs one block (about
  1 KiB, 2 KiB per bound socket) at any capacity, and a full one pins up to 256 ingress
  buffers (about 512 KiB). `netstack_bench`'s server keeps 1024.
- A full accept queue closes new TCP connections (`tcp_not_accepted`) by default. With
  `NetStackConfig::accept_backpressure`, bare SYNs are left unanswered while it is full
  (`syn_deferred`; the peer retransmits) and connections that completed their handshake
  meanwhile wait in the stack, bounded by the listener pool, until the application accepts
  them.
- `connect_tcp` takes an ephemeral port; `connect_tcp_from` a caller-chosen one (`AddrInUse`
  when a connection or listener of the stack has it). Ephemeral TCP and UDP ports start at a
  random point of 49152-65535 per stack and then go up in order.
- Everything the stack discards is counted per reason in `NetStackHandle::stats`
  (`NetStackStats`): malformed, foreign or unsupported packets, refused SYNs, connections
  and flows not accepted, full UDP queues, the flow limit, and egress produced while the
  egress backlog is full.
- smoltcp sees the configured MTU as its device MTU, so it advertises an MSS of `mtu - 40`
  (IPv4) or `mtu - 60` (IPv6) and no emitted packet exceeds the MTU, which the source
  reports and never changes. Socket buffers hold 512 IPv4-sized segments, so the window
  scales with the MSS.
- `NetStackConfig::tcp_rx_buffer` / `tcp_tx_buffer` (default `None`: the 512 segments
  above) size every TCP socket's buffers, listener pool sockets included, clamped to one
  IPv4 MSS (`mtu - 40`) at least and `65535 << 14` (the largest window TCP can advertise,
  under smoltcp's 1 GiB limit) at most. The receive buffer is the window: smoltcp's
  `Socket::new` derives the window-scale shift from its capacity (its bit length minus 16,
  at least 0), so the SYN and SYN-ACK carry a scale and initial window
  matching it with no further code. A window of more segments than the queues on the path
  hold loses its tail when the peer sends it at once (see the field docs and
  [Socket buffers (MB-x5)](#socket-buffers-mb-x5)). This is ns's MB-x5 knob and not the
  fix for the throughput gap (MF-2). ns's MB-x6
  (counting SYNs refused for a full listener pool) needs no code here:
  `NetStackStats::syn_refused` counts them, for a pool sized by
  `NetStackConfig::listener_pool`.
- `NetStackConfig::tcp_send_budget` (default `None`) bounds the bytes all TCP connections
  of the stack hold in their send buffers together, split evenly between the connections
  with data to send (each at least one IPv4 MSS, at most its `tcp_tx_buffer`). Without it
  `n` bulk connections put `n` windows on the path at once: four default windows are 2048
  segments against the receiving engine's 1024-packet deliver queue, and the excess is
  dropped as `DROP_SINK_FULL`. It is opt-in because it also caps all connections together
  at `budget / RTT`, which limits parallel connections on a long path; see
  [Queue depths](#queue-depths) for when to set it. Unset, the bridge pass skips counting
  the senders and every connection's limit is `usize::MAX`.
- UDP datagrams are built with DF set over IPv4 and an application payload whose packet
  exceeds the MTU fails with `InvalidInput`. With `NetStackConfig::udp_allow_fragmentation`
  an IPv4 one instead leaves as a single oversize packet with DF clear (up to the 65 535-byte
  total length), for the engine's fragmenter (`EngineBuilder::fragmenter`) to split; the
  UDP egress bypasses smoltcp, so nothing in the stack caps it, and the source keeps
  reporting the configured MTU. IPv6 still fails.
- `TcpConnection::unacked` and `TcpConnection::last_ack` report send progress: after
  smoltcp ran, each bridge pass reads the socket's send queue (bytes taken from the
  application and not acknowledged; smoltcp exposes no SND.NXT, so bytes held back for the
  peer's window count too) and stores it in an atomic shared with the connection when it
  changed; a queue smaller than at the end of the previous pass means SND.UNA advanced
  (only an acknowledgement shrinks it, except a reset, which leaves the socket closed and
  is not counted), so the pass's time is stored as `last_ack`. No lock, no per-packet or
  per-byte work; the values stay readable after the socket is released.
- Dropping a `TcpConnection` closes it gracefully (FIN; the socket stays until the close
  completes). `TcpConnection::abort` resets it instead: the driver turn that observes the
  abort resets the socket and discards its unread and unsent bytes, the poll after the
  bridge pass sends the RST, and the connection is released (tuple out of the `owns` table,
  socket removed, `terminated` resolved) in the same turn when the device had room for the
  RST, else in the next. A connection the peer already reset or closed is released without
  an RST. A `connect_tcp_from` of a port an aborted connection still holds is deferred by
  the driver and retried once that release frees the port, so it succeeds when issued right
  after the abort. A connection without traffic for 5 minutes takes the same path, so the
  idle timeout also sends the peer an RST before the release. Unused, the abort costs one
  state compare under the connection's existing lock and two empty-`Vec` takes per driver
  turn. A reset peer reads `Ok(0)` and writes fail with `BrokenPipe`.
- `connect_udp` / `connect_udp_from` open a `UdpSocket` connected to one remote: the local
  end is the stack's address of the remote's family (an unspecified `local` stands for it,
  port 0 picks an ephemeral port), `send` goes to the remote (`NotConnected` on a bound
  socket) and `peer_addr` returns it (`None` on a bound socket). A datagram goes to the
  connected socket of its exact tuple first, then to a socket bound to its exact address,
  then to one bound to the unspecified address, then to a flow; other remotes still reach a
  bound socket or `incoming_udp`. Errors: `InvalidInput` (unspecified remote, other-family
  local), `AddrNotAvailable` (no stack address of the family, or another address),
  `AddrInUse` (a live connected socket or flow on the tuple, or no free port),
  `BrokenPipe` (stack stopped). The connected table is checked only while not empty: one
  `HashMap::is_empty` per UDP datagram when unused.
- `NetStackHandle::owns(packet)` answers `Ownership::{Flow, Listener, None}` synchronously
  for a local side that shares one decrypted stream between the stack and other consumers
  (a `Splitter` closure). It reads one table of tuples behind a mutex, keyed
  `(local, remote)`: TCP connections are registered when a connect is queued (by the handle
  for `connect_tcp_from` with a port, by the driver before the SYN is emitted for an
  ephemeral port), when a listener socket enters SYN-RECEIVED (after the poll that ingested
  the SYN, before the SYN-ACK is flushed) and when a socket is adopted as a connection;
  bound and connected UDP sockets and UDP flows when they are created. Each registration is dropped with
  what holds it (the released connection, the abandoned or failed connect, a handshake
  socket back in `Listen` or closed, the dropped `UdpSocket` or `UdpFlow`, whose
  registration goes before its queue closes so a rebind or a new flow never races it), so
  the table changes per connection, never per packet, and costs nothing per packet when
  `owns` is not called. `Flow` is an exact tuple match (any remote for a bound UDP socket,
  only its remote for a connected one) or an ICMP/ICMPv6 error quoting a packet sent on a registered tuple; `Listener` a bare SYN
  or UDP datagram to a stack address otherwise; `None` everything else, fragments (dropped
  by the stack) and every packet once the driver stopped. The answer reflects the state at
  the call. With reassembly on, TCP and UDP fragments to a stack address are the stack's:
  `Flow` for a first fragment on a registered tuple, `Listener` for any other first
  fragment. A later fragment carries no ports, so `owns` remembers each first fragment it
  classified as `Flow` by `(src, dst, protocol, id)` (the reassembler's key: `protocol`
  only for IPv4) and reports the later fragments of that datagram as `Flow`; the entry
  lives `ReassemblyConfig::timeout`, the memory holds at most `max_datagrams` entries
  (oldest dropped) and `discard_fragments` clears the datagram's entry. A later fragment
  that arrives before its first, or after the memory forgot it, is `Listener`. Only
  fragment classification takes this memory's lock; without reassembly none exists.
- `NetStackConfig::reassembly` gives the driver one `nsplane_packet::reassembly::Reassembler`
  (none is created without it). Before `classify`, every ingress packet to a stack address
  is pushed into it: a non-fragment passes unchanged, a fragment is held, and a completed
  datagram continues through the normal ingress as one packet (UDP dispatch, or smoltcp for
  TCP). Expiry runs at the start of each driver turn, which the driver's existing timer
  (at most `MAX_POLL_DELAY`, 50 ms) already wakes, and is a single emptiness check while no
  datagram is held. The reassembler's counts are added to `NetStackStats` after each push
  or expiry: `reassembled`, `reassembly_timeout`, `reassembly_overflow`, and overlapping or
  invalid fragments as `malformed`. Without it, fragments count as `unsupported`.
- `NetStackHandle::discard_fragments(src, dst, protocol, id)` is for a local side that
  revokes a flow's admission while one of its datagrams may be half reassembled. The call
  records the datagram (IPv4 16-bit id widened to `u32`, IPv6 32-bit id; `protocol` only
  narrows an IPv4 key) synchronously under one short lock, so from then on the driver drops
  every fragment of it, those already queued in the `NetStackSink` included, and counts
  them in `reassembly_overflow`; the fragments the reassembler holds never complete and
  expire at the reassembly timeout (`reassembly_timeout`). The record lives
  `ReassemblyConfig::timeout`, so a later datagram with the same id starts afresh, and at
  most `max_datagrams` records are kept (the oldest forgotten early). Without reassembly
  the call does nothing; with it and nothing discarded, the driver checks one atomic per
  ingress packet and takes no lock.
- Every TCP socket (connect and listener pool) runs CUBIC congestion control (smoltcp
  feature `socket-tcp-cubic`, no extra crate). Without it smoltcp sends the whole peer
  window at once and, after a retransmission timeout, all of it again; a hop that drops
  part of the burst (a full socket buffer on a loaded host) drops the retransmission too,
  and the timeouts (1 s minimum, doubling) add up past 30 s. CUBIC rather than Reno: both
  restart from one segment after a timeout and measured alike on the bottleneck below
  (32 MiB in 40-41 s with CUBIC, 40-50 s with Reno), CUBIC recovered faster at 1 % random
  loss (16 MiB in 1.1-4.1 s, Reno 4.1-5.1 s) and is the default of Linux, Windows and macOS;
  its `f64` arithmetic is no concern on the targets nsplane runs on.
- smoltcp is the `dotns/smoltcp` fork (tag `v0.14.0-nsplane.4`, branch
  `nsplane/v0.14-perf`, ADR `docs/decisions/2026-10-03-smoltcp-fork.md`): v0.14.0 plus
  fixes for four defects that stalled connections for good under loss when both ends send
  (an echo, request and response), and five throughput changes (ON) listed after them.
  - After a retransmission timeout smoltcp 0.14 rewound its next sequence number to the
    oldest unacknowledged byte and stamped its pure ACKs with it. If the peer had already
    received past that point (only its ACKs were lost), the peer dropped those ACKs as old,
    acknowledgement included; with both ends in that state each resent data the other had
    and the timeouts backed off to 60 s. The fork sends every empty segment with the
    highest sequence number sent (RFC 9293 `SEQ=SND.NXT`), and such a segment no longer
    moves the send position, so the rewind for retransmission stays in effect.
  - When an ACK closed the peer's window while data was in flight (window scaling rounds
    a few free bytes down to zero), the zero-window probe timer replaced the retransmission
    timer, so lost bytes were never resent, and no timer ran once the window reopened. The
    fork keeps outstanding data under the retransmission timer (RFC 6298 5.1) and probes
    from the oldest unacknowledged byte when a timeout finds the window closed.
  - The third duplicate ACK reset the retransmission timer and dropped the pending fast
    retransmission before the segment reached the device; with the egress backlog full the
    segment was never sent and no timer ran (traced: `LAST-ACK`, 360 KB in flight above
    cwnd, timer idle). The fork keeps it pending until it is emitted.
  - Three duplicate ACKs while only the FIN was outstanding replaced its retransmission
    timer by a fast retransmission, which resends data only (traced: `FIN-WAIT-1`, empty
    send buffer, FIN in flight, timer idle). The fork leaves a FIN to the retransmission
    timer.

  The throughput changes of `v0.14.0-nsplane.4` (the ON round, 5 files, +1031/-33 over
  `.3`):

  - The TCP/IP checksum sums 64-bit words into two `u128` accumulators (no `unsafe`).
    It is bit-identical to 0.14's in an equivalence test over lengths 0-2000 at 16
    offsets, and takes 38 % fewer instructions per 1400-byte call (about 22 % fewer
    checksum samples in an IBS profile of the stream).
  - The advertised right edge of the receive window never moves left. Under window
    scaling 0.14 rounded the free space down at every segment, so the edge shrank (6 -> 5
    -> 0 units) and in-flight data the sender was allowed to send was trimmed and
    retransmitted. The fork rounds up when rounding down would shrink the edge, with the
    window end capped at the buffer. `netstack_lossy` at 1 % loss: 8-15 -> 180-184 MB/s.
  - Fast recovery retransmits the next hole on a partial ACK (NewReno, RFC 6582, careful
    variant; Reno and CUBIC `on_partial_ack`), instead of waiting for a timeout of at
    least 1 s for every loss after the first of a window. The bottleneck case went from
    15-23 s to 0.8-0.9 s.
  - The sender avoids the silly window syndrome (Minshall's variant of Nagle): a sub-MSS
    segment cut by the peer's window is held while an earlier sub-MSS segment is
    unacknowledged. With nsplane's Nagle off, segments decayed to 275-800 bytes on
    average after losses with four streams (about 1080 with one).
  - Limited Transmit (RFC 3042): the first two duplicate ACKs each release one new
    segment, so small windows still reach the third duplicate ACK and fast retransmit.

  Together they lift four parallel streams to at least the one-stream aggregate with
  nsplane's defaults (no driver Nagle, `tcp_send_budget` unset); see
  [Netstack throughput](#netstack-throughput).

  Phase 5 worked around the first two in the driver (an outgoing pure-ACK sequence
  rewrite, and a stalled connection taking up to 1 KiB past its application buffer's bound
  and keeping a 1 s keep-alive in place of the persist timer); all of it is gone.

  The engine's `DROP_SINK_FULL` is ordinary loss to TCP: a decrypted segment the engine
  drops at the full sink is never acknowledged, the retransmission timer stays armed and
  smoltcp resends it; the stalls above only needed such a loss at the wrong moment.
  `parallel_echo_*` in `tests/netstack_lossy.rs` run eight 1 MiB echoes through
  256-packet engine queues, without loss and at 2 % loss. On the fork without any driver
  workaround they passed 10 consecutive runs in debug (2 % loss: 10.2-16.2 s) and in
  release (11.0-21.0 s), as they did on smoltcp 0.14 with the Phase 5 workarounds (8.3-17.3 s
  and 9.0-23.1 s).

### Netstack throughput

Release, two netstacks over two engines on an in-process `ChannelTransport` pair (no
latency), one TCP connection, MTU 1420; the link wrappers are `nsplane_e2e::LossyTransport`
(drops a deterministic fraction of the data messages in each direction) and
`nsplane_e2e::Bottleneck` (25 MB/s behind a 64-datagram drop-tail buffer, like a socket
buffer drained by a busy receiver). "After" is CUBIC with the Phase 5 stall workarounds
on smoltcp 0.14 (two runs each); "fork" is the same on `v0.14.0-nsplane.3` without any
workaround (four runs each, on a host shared with other builds, load 7-11 on 32 cores):

```text
cargo test --release -p nsplane-e2e --test netstack_lossy -- --ignored --nocapture
```

| Case | Before (no congestion control) | After | Fork |
| --- | --- | --- | --- |
| TCP, 64 MiB, no loss | 440.5 / 441.0 MB/s | 321.1 / 319.4 MB/s | 308.6 / 129.2 / 246.7 / 228.9 MB/s |
| TCP, 16 MiB, 1 % loss | 41.1 s / 35.1 s (0.4-0.5 MB/s) | 4.09 s / 2.09 s (4.1-8.0 MB/s) | 1.09 / 6.16 / 1.14 / 3.13 s (2.7-15.3 MB/s) |
| TCP, 16 MiB, 3 % loss | not done after 60 s (both) | 54.2 s / 59.2 s (0.3 MB/s) | 53.2 s once, 3 of 4 not done after 60 s |
| TCP, 16 MiB, bottleneck | not done after 60 s (both, ~2650 drops) | 20.9 s / 18.9 s (0.8-0.9 MB/s, ~330 drops) | 18.9 / 15.9 / 19.8 / 17.9 s (0.8-1.1 MB/s, 276-472 drops) |
| UDP, 50 000 x 1200 B, no loss | 902.7 / 468.4 MB/s | 587.1 / 608.7 MB/s | 303.3 / 530.1 / 644.5 / 411.1 MB/s |

Without loss the stack is not the limit (runs of the same build spread from 320 to
460 MB/s for TCP and 470 to 900 MB/s for UDP: scheduling noise) and congestion control
costs nothing. With loss, smoltcp 0.14 recovers one lost segment per window by fast
retransmit and any further one by a retransmission timeout of at least 1 s (no SACK, no
retransmission on a partial ACK), so elapsed times come in whole seconds and random loss of
2 % or more stays timeout-bound. Congestion control turns the stalls on a congested hop into
completed transfers. A smaller default window was measured and not adopted (see
`WINDOW_SEGMENTS` in `config.rs`): through the bottleneck, 64 segments lose nothing
(32 MiB in 2.9 s), but a window that small caps a connection at 1.8 MB/s over a 50 ms path,
and without loss it gains nothing. `tests/netstack_lossy.rs` asserts that 8 MiB complete
intact at 1 % loss within 15 s, next to a loss-free reference.

The fork changes nothing on the loss-free path (its fixes only touch retransmission and
empty segments, and the driver lost per-packet work); the loss-free spread above is the
shared host, as the 320-460 MB/s spread of one build was before. With loss the results
stay in the same range: 1 % loss completes in 1.1-6.2 s (before 2.1-4.1 s; whole seconds
are retransmission timeouts), the bottleneck in 15.9-19.8 s (before 18.9-20.9 s), and 3 %
loss stays timeout-bound right at the 60 s limit, as before.

`v0.14.0-nsplane.4` (ON) changes loss recovery and the sender (see
[nsplane-netstack](#nsplane-netstack)). The same test, with the step-by-step numbers of the
fork round (each on a quiet host) and the final gate's run of the merged workspace:

| Case | `.3` | `.4` step by step | `.4`, final gate (load 8.9-9.3) |
| --- | --- | --- | --- |
| TCP, 64 MiB, no loss | see above | within noise | 277.0 MB/s |
| TCP, 16 MiB, 1 % loss | 8-15 MB/s with the shrinking window edge | 180-184 MB/s (window edge); median 1.09 s with all five changes (2.09 s without SWS and Limited Transmit) | 1.14 s (14.8 MB/s, 251 drops) |
| TCP, 16 MiB, 3 % loss | stalls past 60 s; median 51.2 s with the window-edge change | median 33.1 s with NewReno, 32 s with all five (11-41 s) | 19.2 s (0.9 MB/s, 739 drops) |
| TCP, 16 MiB, bottleneck | 15-23 s | 0.8-0.9 s with NewReno | 0.82 s (20.5 MB/s, 124 drops) |
| UDP, 50 000 x 1200 B, no loss | see above | within noise | 449.4 MB/s |

The remaining 3 % loss timeouts are lost retransmissions, which only a timeout recovers
without SACK or RACK-TLP. With many parallel streams the fork removes the throughput
collapse after sink-full drops: `tests/netstack_multistream.rs` (two engines in process,
1 GiB per run split between the streams, default MTU and configuration, release) moved
one stream at 669-782 MB/s and four at 689-841 MB/s, 1.00-1.11x the single stream in 12
pairs (load 3.2-5.5), with 251-577 sink-full drops per four-stream run; on `.3` the same
run gave 629 against 269 MB/s (0.43x). Its ignored `streams_throughput` asserts at least
0.8x:

```text
cargo test --release -p nsplane-e2e --test netstack_multistream -- --ignored --nocapture
```

The harness's netstack pair (`scripts/bench`, `BENCH_PAIRS=netstack`, 30 s x 3, CPU sets
2-5 / 6-9), `main` b5e531f's `netstack_bench` against the ON branch's in one lock hold,
2026-10-05, a quiet host (1-minute load 3.53 -> 2.24 for `main`, 2.22 -> 2.58 for the
branch); medians [repetitions]:

| Build | TCP P1 Gbit/s | TCP P4 Gbit/s | UDP loss 1G / 3G % | CPU s/GB a / b |
| --- | --- | --- | --- | --- |
| `main` (smoltcp `.3`, server queue 128) | 6.21 [6.10-6.29] | 2.48 [1.92-3.21] | 2.21 / 5.56 | 1.92 / 1.59 |
| ON (smoltcp `.4`, server queue 1024) | 6.85 [6.74-6.98] | 7.29 [7.28-7.38] | 0.00 / 0.03 | 1.70 / 1.41 |

Four streams now beat one in every repetition (+6 % on the median), single-stream TCP is
10 % faster at 11 % less CPU per GB on both sides, and the UDP loss left at 3 Gbit/s is the
receiving engine's full sink, i.e. the netstack's receive throughput on four CPUs (an
inline-sink experiment that removed it regressed default-config applications and was
reverted; follow-up). Idle request/response latency is unchanged (p50 / p99 0.027 /
0.052 ms against 0.027 / 0.054), but next to a saturating stream it rose from 0.081 /
0.941 to 0.280 / 1.271 ms in this run: the stream now keeps more in flight (it is 10 %
faster and no longer backs off after losses). Not analysed further here (follow-up).

The sender alone, without engine, crypto or loss: `benches/send_stream.rs` in
`nsplane-netstack` (criterion) wires two netstacks back to back in process and sends 8 MiB per
iteration over one or four persistent connections at the default MTU and configuration, on
four runtime workers (`netstack_send`) and on one thread (`netstack_send_1cpu`, both ends'
summed cost):

```text
cargo bench -p nsplane-netstack --bench send_stream
```

`.3` against `.4` (MF-5), 15 alternating pairs pinned to CPUs 2-5, 2026-10-06, 1-minute load
1.6-9.4 (32 cores); medians in MB/s [IQR], and `.4` against `.3` per pair:

| Case | `.3` | `.4` | `.4` vs `.3` (IQR; pairs faster) |
| --- | --- | --- | --- |
| 1 stream, 4 workers | 2558 [2500-2692] | 2748 [2659-2764] | +2.1 % (+0.3..+8.9; 12/15) |
| 4 streams, 4 workers | 3620 [3303-3681] | 4063 [3995-4129] | +12.8 % (+10.0..+16.7; 14/15) |
| 1 stream, 1 thread | 2501 [2466-2521] | 2538 [2499-2546] | +1.5 % (+0.5..+1.9; 13/15) |
| 4 streams, 1 thread | 2099 [2055-2116] | 2083 [1953-2091] | -0.9 % (-2.8..-0.2; 4/15) |

One sending stream costs nothing on `.4`: it is 1.5-2 % faster, so the SWS hold and Limited
Transmit cost the loss-free single stream nothing measurable (not bisected further). The -5.3 % ns measured on a loud host
(range -28..+16 %) is inside that host's spread; the one pair here below -6 % (-31 %) ran at
load 9.

L2's queue harness (4 and 8 parallel 32 MiB-total echo connections over two engines at
queue capacity 512 and 1024, release, 3 runs per cell) completed every run after the
change (sink drops in one 8-connection run at 512, recovered in 2.2 s); before it, the
same harness stalled a connection for good in 2 of 20 runs at 8 connections and 512. The
5C-T7 re-run of these cases is in [Performance](#performance).

#### Single-stream profile (MF-2)

Method: `tests/netstack_stream.rs` streams 1 GiB over one TCP connection, MTU 1420,
release, either between two netstacks over two engines on the in-process
`ChannelTransport` pair (`stream_throughput_engines`) or between two netstacks whose egress
feeds the other's ingress directly, without engine or crypto (`stream_throughput_direct`).
Both sides run in the test process and are told apart by symbol. Profiles were taken with
`perf` 6.12 in a sibling container (frame-pointer call graphs, built with
`CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTFLAGS=-Cforce-frame-pointers=yes`). They
sample `instructions:u` as well as cycles: on the shared host (load 13-47 on 32 cores)
cycle counts of unchanged smoltcp code swung by 25 % between runs, while instruction counts
of one build stay within about 2 %. Temporary driver counters (never committed) counted
turns and packets.

```text
cargo test --release -p nsplane-e2e --test netstack_stream -- --ignored --nocapture
```

Where the instructions go on main (per GiB):

| | Over engines | Direct |
| --- | --- | --- |
| Whole process | 39.9 G | 7.6 G |
| Both netstack drivers | 7.1 G (18 %) | 6.2 G (81 %) |
| smoltcp and the device, inside the drivers | 4.9 G | 5.0 G |
| ChaCha20-Poly1305 seal + open | 14.5 G (36 %) | - |
| Driver turns, of which `yield_now` turns | 355 k, 268 k | 117 k, 42 k |

- smoltcp is the stack's cost. `process_tcp` (21 % of the direct process), the egress
  `dispatch_ip` closure (12 %) and `socket_egress` (10 %) lead, and about 15 % of all
  instructions are the TCP checksum loop (`smoltcp::wire::ip::checksum::data`) in both
  directions. The profile attributed them to the loop's `try_into().unwrap()` line, but
  0.14's loop was already auto-vectorized with no bounds check per chunk; that line
  attribution was an artefact. The fork's `.4` sums 64-bit words instead (38 % fewer
  instructions per 1400-byte call).
- The driver's own code is small: the ingress queue (0.49 G, one semaphore lock per
  `try_recv`), its turn bookkeeping (0.27 G) and copies between the sockets and the
  application buffers (0.1 G of instructions; `memmove` is about 5 % of the direct cycles).
  The byte-wise looking `shared.rx.extend(bytes.iter())` only runs for terminal sockets
  and is a slice copy (`VecDeque`'s `Extend<&u8>` from a slice iterator); it does not show
  in the profile.
- Every egress buffer is zero-filled before smoltcp writes it (`PacketPool::get` plus
  `PacketBuf::set_len`, about 4 % of the direct instructions).
- Over engines a full-size TCP segment did not fit its buffer once the engine appended the
  WireGuard trailer, so every one was reallocated and copied when sealed (`_int_malloc`
  2.5 %, `realloc` 1 % of the instructions).
- The engine side dominates the engine pairing: crypto, the engine tasks and channel
  handoffs, and `ChannelTransport::recv`, which zero-fills its 64 KiB receive buffer per
  datagram (7 % of the instructions, 9 % of the cycles; a test harness cost, not a
  netstack one).
- smoltcp sends at most one segment per socket per egress pass, so on the sender most
  turns end with more to send and yield (268 k of 355 k turns over engines).

Fixes, without behavior change:

1. Ingress is taken with `poll_recv_many` (still at most 256 packets per turn, same order),
   so the queue slots of a batch are returned in one step: -2.3 % driver instructions
   on the direct pairing.
2. Egress TCP segments and UDP datagrams keep 32 bytes of tail room (`device::TAILROOM`),
   so the engine seals them in place without reallocating: -2.0 % process instructions
   over engines, CPU time 9.6 s to 8.7 s, context switches 529 k to 403 k per GiB.

Not adopted: draining egress after a pass while it sends (up to the backlog bound) cut
the turns over engines from 355 k to 93 k and the yields to almost none, but it made the
sender fill the receive window to its edge, where smoltcp trims data (see the window-edge
item under *Known remaining costs*): 2-5 % of the segments were retransmitted without any
loss, and the direct pairing used more CPU. With that smoltcp issue fixed in a local
prototype it retransmits 0.6 % and saves another 2.6 % of instructions and 30 % of the
context switches over engines, but did not raise the throughput (median 519 MB/s against
576 MB/s), so it stays out.

Before and after: `main` against the branch, interleaved runs of the stream loads, median
[range] per GiB, CPU time, instructions and context switches from `perf stat`. "First" is
the window the fixes were measured in (five runs each, 1-minute load 13-18 on 32 cores);
"final" is a fresh run of the merged workstream against `main` (2026-10-03, five runs
each, load 20-29):

| Stream | main, first | branch, first | main, final | branch, final |
| --- | --- | --- | --- | --- |
| Over engines, MB/s | 540 [498-545] | 576 [536-610] | 306 [187-330] | 309 [134-361] |
| Over engines, CPU time | 5.99 s [5.90-6.41] | 5.50 s [5.29-6.03] | 10.08 s [9.51-11.22] | 9.34 s [8.88-10.59] |
| Over engines, instructions | 39.45 G | 38.57 G | 39.41 G [39.37-39.43] | 38.49 G [38.43-38.60] |
| Over engines, context switches | 448 k | 340 k | 555 k [480-603] | 431 k [396-473] |
| Direct, MB/s | 2022 [1534-2144] | 1906 [1182-2377] | 1002 [628-1189] | 1162 [984-1254] |
| Direct, CPU time | 0.87 s [0.86-1.32] | 1.00 s [0.82-1.71] | 1.82 s [1.61-1.88] | 1.60 s [1.54-1.74] |
| Direct, instructions | 7.72 G [7.68-9.03] | 7.85 G [7.52-8.57] | 7.72 G [7.68-7.80] | 7.54 G [7.48-7.63] |

Instruction counts are the stable measure: over engines the branch runs 2.2-2.3 % fewer
(38.5-38.6 G against 39.4 G per GiB), with 7-8 % less CPU time and 22-24 % fewer
context switches. Throughput follows the host load: at load 20-29 both builds reach about
half of what they did at 13-18, and the branch's median is ahead by 1 % (final) to 7 %
(first), inside the spread. The direct pairing has no sealing; the batched ingress saves
2.3 % of its instructions in the final window and less than the run-to-run spread in the
first.

`netstack_lossy`'s throughput rows, three interleaved runs each (load 4-22 first, 17-37
final), show no loss-recovery regression:

| Case | main, first | branch, first | main, final | branch, final |
| --- | --- | --- | --- | --- |
| TCP, 64 MiB, no loss | 399 / 457 / 120 MB/s | 406 / 232 / 453 MB/s | 77 / 258 / 248 MB/s | 383 / 289 / 107 MB/s |
| TCP, 16 MiB, 1 % loss | 1.08 / 2.08 / 0.18 s | 0.09 / 1.13 / 0.07 s | 1.28 / 1.13 / 4.19 s | 2.11 / 1.17 / 1.17 s |
| TCP, 16 MiB, 3 % loss | 52.2 / 50.2 s, once not done after 60 s | 55.2 / 58.2 / 51.2 s | 57.2 s, twice not done after 60 s | 50.2 / 51.3 / 55.2 s |
| TCP, 16 MiB, bottleneck | 14.9 / 23.9 / 21.9 s | 22.8 / 22.9 / 17.9 s | 21.8 / 17.9 / 20.9 s | 16.9 / 21.9 / 18.9 s |
| UDP, 50 000 x 1200 B | 780 / 261 / 716 MB/s | 798 / 247 / 188 MB/s | 747 / 540 / 500 MB/s | 409 / 568 / 698 MB/s |

The fixes do not touch retransmission: 3 % loss is timeout-bound right at the 60 s limit on
both builds (main missed it three times in six runs, the branch never), and the other rows
spread alike.

#### Socket buffers (MB-x5)

`NetStackConfig::tcp_rx_buffer` / `tcp_tx_buffer` (see [nsplane-netstack](#nsplane-netstack))
size the window, and the window is a trade-off: a peer may send a whole window at once, and
a window of more segments than the queues between the stacks hold loses its tail there.
In-process that queue is the receiving engine's 1024-packet sink queue: the excess is
dropped as `DROP_SINK_FULL`, and smoltcp recovers past the first lost segment of a window
only by a retransmission timeout of at least 1 s (no SACK; on `.3` also no partial-ACK
retransmission).
`tests/netstack_buffers.rs` `throughput`, the branch only (`main` has no fields), three
runs, release, load 17-31:

| Buffers on both stacks | 64 MiB, MB/s, median [range] | `DROP_SINK_FULL` per run |
| --- | --- | --- |
| Default, 512 segments (about 690 KiB) | 287 [200-336] | 0 |
| 1 MiB | 315 [298-334] | 0 |
| 4 MiB, about 3000 segments | 52 [37-53] | 101-312 |

```text
cargo test --release -p nsplane-e2e --test netstack_buffers -- --ignored --nocapture
```

When the buffers were added (PS-BUF) the same load gave about 50 MB/s at 4 MiB against
250-450 MB/s for the default and 1 MiB, and 4 MiB ran without drops once the engine and
stack queues held 8192 packets. A larger window pays only on a path whose round trip needs
it and whose queues match it, so the default stays at 512 segments. ns measured a 1 MiB
window within noise of the default, so this knob is not the MF-2 fix.

#### Known remaining costs (deferred)

Decided for later, not in this workstream:

- smoltcp fork: the checksum over 64-bit words, the non-shrinking advertised window edge
  and NewReno's partial-ACK retransmission listed here before are in `v0.14.0-nsplane.4`
  (see [nsplane-netstack](#nsplane-netstack)). What stays: a lost retransmission still
  waits for a timeout of at least 1 s, which keeps 3 % loss at 11-41 s; SACK or RACK-TLP
  is the next step.
- `nsplane-packet`: setting a pooled buffer's length without zero-filling it (smoltcp
  writes every byte of a transmitted packet) would save about 4 % of the direct
  instructions. It is a later design item: it would need `unsafe` in a
  `forbid(unsafe_code)` crate.
- `nsplane`: `ChannelTransport::recv` zero-fills its 64 KiB receive buffer per datagram
  (7 % of the instructions, 9 % of the cycles over engines), which skews every in-process
  engine benchmark, the over-engines numbers above included. It is to be fixed after the
  PF campaign merges.
- MF-2's 12-14 % gap to ns's legacy stack cannot be split in-process: it was measured on
  ns's own path, whose legacy WireGuard loop is tunnel-wg's, not the nsplane engine. The
  netstack is about 18 % of the engine pairing's instructions (and the fixes above removed
  its per-segment reallocation and per-packet queue locking), so most of the gap is likely
  the engine (MF-1). PB's netstack pair (`scripts/bench`) is not on `main` yet; MF-2 is to
  be re-measured with PB's harness.

## nsplane-uapi and the CLI

`Uapi` answers `get=1` and `set=1` over an `EngineHandle`; `listen_port` and `fwmark` bind a
new `UdpTransport` and install it with `EngineHandle::replace_transport`. Over an engine whose
transport the UAPI does not own (`Uapi::with_external_transport`, e.g. a relay or WSS
carrier) they never replace it: the reported value is a no-op, any other fails with
`EADDRINUSE`. On Unix,
`UapiListener` binds `/var/run/wireguard/<iface>.sock`. The Windows named-pipe listener
exists since Phase 2; real-host verification of its `ProtectedPrefix` path and security
descriptor is still pending.

`nsplane-cli` builds a tokio multi-thread runtime (`--threads` workers), creates the TUN,
builds an engine on it, binds an ephemeral UDP port, serves the UAPI, drops privileges to
`SUDO_UID`/`SUDO_GID`, and runs until SIGINT or SIGTERM.

## nsplane-acl

The ACL evaluates business-agnostic flows. Product policy (subjects, groups, realms) is
compiled above nsplane into rules, and new product concepts are not added here (ADR
`2026-10-06-business-agnostic-scope`). The ns-specific pieces described below
(`SourceAssertion::Terminate` / `External`, `crates_acl()`, the node L3 gate's grant model)
predate that rule and stay for ns.

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

**Outbound source scope.** `AclFilter::with_scope` takes an `AclFilterScope`, per-filter
address scopes beside `AclFilterConfig`. With `outbound_sources: Some(prefixes)` every
outbound packet (any peer, restricted or not, any protocol, every fragment) whose source
address, read from the raw IPv4 or IPv6 header, is in none of the prefixes is dropped with
`reasons::OUTBOUND_SOURCE` (`AclFilterStats::outbound_source`) before the outbound rules,
pinholes and reply allowances, and records no state; a buffer too short for the source is
dropped too, and an empty list drops every outbound packet. Only `Ipv6Mode::Accept` runs
before it. The default (`None`) costs one branch per outbound packet. ns sets it to its
`N4(self)/32` and `N6(self)/128` so a packet into the tunnel cannot carry a foreign source.

**Other-protocol rules.** `AclFilterScope::other_protocols` holds `OtherProtocolRule`s
(`OtherProtocol::IcmpEcho`, `Icmp` or `Ip(number)`, plus destination prefixes) for inbound
packets that are neither TCP nor UDP. After the reply allowances and `allow_other_protocols`
(which still accepts everything), and behind a loaded policy, a packet some rule matches by
protocol and destination address is accepted (`AclFilterStats::accepted`); anything else is
dropped with `reasons::PROTOCOL` as before. Non-first fragments follow their first fragment.
With `stateful_replies`, an accepted packet from an outbound-restricted peer (an echo request,
or a non-ICMP packet) records the outbound allowance its reply passes through
(`outbound_replies`), and an outbound ICMP echo request records the inbound allowance of its
reply as with `allow_other_protocols`. Rules match destinations only, never sources. The empty
default costs nothing on the TCP/UDP path and one branch for other protocols. ns sets an
`IcmpEcho` rule for `N4(self)/32` and `N6(self)/128` instead of `allow_other_protocols`.

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
packets are evaluated from scratch.

**ACL hook.** The filter evaluates a flow once, not every packet. `AclEngine::generation`
increases on every published change (default policy, namespaces, grants, pinholes opened,
closed, swept or revoked, `clear_all`), and a versioned `PeerIdentity`
(`PeerIdentity::generation`, bumped by `PeerIdentityMap`) on every identity change. The
filter caches per peer its resolved principal and flags, and per peer, direction and
five-tuple the verdict of a namespace member's TCP/UDP flow's first packet (the default
policy is cheaper to evaluate than to cache), in the reply table (one lock, one
capacity, cached verdicts flushed first when full), both tagged with the two generations: a
hit under other generations is evaluated again, so a change applies to the very next
packet, and a verdict accepted through a pinhole is also checked against the pinhole's
expiry. Peers whose namespaces (or the default policy) accept every destination, port and
protocol and are not outbound-restricted, as computed on every update, bypass the
evaluation. The reply table, fragments and fail-closed rules are unchanged, and verdicts and
counters equal a full evaluation (a differential test checks it). The full rules and
per-packet bench numbers (`cargo bench -p nsplane-acl --bench namespaces`) are in the crate
docs (`crates/nsplane-acl/src/lib.rs`, *Namespaces*, *Pinholes*, *ACL hook* and
*Performance*) and in [Performance](#performance).

Measured results (5C-T3 record): a bypass peer costs ~41-54 ns (937 ns before the hook); an
established flow 50-55 ns under namespaces and 62 ns under the default policy (deliberately
uncached); new flows 60-75 ns (default policy), ~200-400 ns (namespaces), 0.34-0.56 us
through a grant and 240-280 ns through a pinhole (38 us and 15-20 us before full tables
evicted in O(1)). The floor is the five-tuple parse (6-7.5 ns) plus the snapshot load
(9.5-11.5 ns), 16-19 ns; skipping the reply check would be exact only for unidirectional
traffic. Exactness was not weakened (differential test).

**Per-source principals.** `PeerIdentity::assertion_for(peer, src)` resolves a principal for
the packet's remote address (the source of an inbound packet, the destination of an outbound
one); its default ignores the address. `PeerIdentityMap::insert_by_source` makes a peer
terminate by source address, so each packet's principal is a terminate binding of its
address, as `AccessRequest::from_ip` builds it (an ns gateway, whose packets carry several
sources); `insert` with a `SourceAssertion::WgPeerKey` keeps a key principal (an ns relay
client). The filter asks `PeerIdentity::by_source` once per peer and identity generation and
caches such a peer's principal per address in a least-recently-used table bounded by
`AclFilterConfig::reply_capacity`; the bypass and the flow verdict cache work per address
too, so verdicts still equal a full evaluation (the differential test covers by-source
peers).

**Fragment modes and bypass flags.** `AclFilterConfig::fragments` selects how inbound
non-first IPv4 fragments are gated. `FragmentMode::Outcome` (default) is the gate described
above: the outcome of each first fragment, accepted or dropped, per peer and direction, the
last fragment freeing it. `FragmentMode::AllowOnly { ttl, capacity }` is ns's
`FragmentAclGate`: only accepted first fragments are recorded, keyed (source, destination,
protocol, identification) without the peer, live for `ttl` on the engine clock; a non-first
fragment is judged before anything but the bypass flags and dropped with `reasons::FRAGMENT`
without a live entry; a full table drops expired entries and otherwise records nothing
(`FragmentMode::ALLOW_ONLY`: 15 s, 4096, ns's values). `accept_to_local: Option<Ipv4Addr>` (ns
`is_local_node_packet`) and `accept_icmp_echo_reply` (ns `is_icmp_echo_reply`, read from the
raw header) accept an inbound IPv4 packet before anything else without the policy, counted in
`AclFilterStats::bypassed`. Both are off by default and cost one branch each when off.

**The ns `crates/acl` mode.** `AclFilterConfig::crates_acl(local)` sets
`stateful_replies: false` (no reply allowances in either direction, no pending dependency),
`allow_other_protocols: false`, `FragmentMode::ALLOW_ONLY`, `accept_to_local: local`,
`accept_icmp_echo_reply: true` and `ipv6: Ipv6Mode::Accept`. With a `PeerIdentityMap` holding relay clients under their
`WgPeerKey` and every other peer by source, it judges inbound IPv4 packets as ns's account
ACL step: `is_local_node_packet(pkt, tun_ip) || is_icmp_echo_reply(pkt) ||
acl_check_packet(..)`. Drop reasons are this crate's (a packet ns drops is dropped here,
possibly under another reason); outbound IPv4 packets keep this filter's handling. IPv6 is
not judged by the policy, as in ns, whose account filter runs no ACL on IPv6 and only checks
an inbound IPv6 packet's destination: `Ipv6Mode::Accept` passes every IPv6 packet in both
directions (fragments, `ICMPv6` and packets malformed beyond the version included) before
anything else, records no flow, reply or fragment state and counts it in
`AclFilterStats::ipv6_accepted`; the destination check is the core's
`PeerConfig::inbound_destinations`. The default, `Ipv6Mode::Evaluate`, judges IPv6 like IPv4,
and `Accept` costs one branch per packet when off.

**Parity with ns.** `crates/nsplane-acl/tests/crates_acl_parity.rs` replays a fixture
(`tests/fixtures/crates_acl_parity.json`, recorded and generated sequences with the verdicts
ns `acl_check_packet` and the two bypass checks gave them, and the ns commit they come from)
through one `AclFilter` per sequence in this mode on a manual clock, and requires the same
verdict for every packet. The fixture marks 30 packets as an intended deviation: ns
`parse_five_tuple` reads IHL+4 bytes; nsplane-acl drops malformed IPv4 (TCP/UDP header
truncated, total length inconsistent with the buffer) as acl malformed in every mode;
verdicts are equal on well-formed packets. (A later fragment ns admits only through such a
malformed first fragment is dropped as `reasons::FRAGMENT`.) The test requires exactly those
30, each ns-allowed and dropped with its kind's reason. `nsplane-e2e`'s `acl_parity` runs the
mode between two engines, including IPv6 TCP to a denied port, delivered in this mode and
dropped as `reasons::DENIED` under the default config.

**What ns deletes.** The account filter's ACL and destination steps become nsplane calls;
the file references are to ns `refactor/nsplane` (`crates/ns/src/account_engine/filters.rs`,
`crates/tunnel-wg`).

| ns today | nsplane |
| --- | --- |
| `tunnel_wg::acl_check_packet` (`tun_io.rs`) on the `crates/acl` `AclEngine` | `AclFilter` with `AclFilterConfig::crates_acl(Some(tun_ip))` on an `nsplane-acl` `AclEngine` (same policy model; `load` for a policy, `clear_all` for none: fail-closed, `reasons::NO_POLICY`) |
| `nat::FragmentAclGate`, one per filter | `FragmentMode::ALLOW_ONLY` inside that filter |
| `tunnel_wg::is_local_node_packet(pkt, tun_ip)` | `AclFilterConfig::accept_to_local = Some(tun_ip)` |
| `tunnel_wg::is_icmp_echo_reply` | `AclFilterConfig::accept_icmp_echo_reply = true` |
| `relay_client_keys` set and the `PeerKeys` map (engine `PeerId` to key; an unmapped peer dropped) | `PeerIdentityMap`: `insert(peer, SourceAssertion::WgPeerKey { pubkey })` for a relay client key, `insert_by_source(peer)` for every other peer, `remove` with the peer (an unknown peer is dropped as `reasons::UNKNOWN_PEER`) |
| `AccountFilter` ACL step (`inbound_ipv4` after the Node L3 step; `account: acl denied`) | that filter; the Node L3 step before it is the Node L3 gate's (MD-B) |
| `DynamicL3RouteTable` leases (`peer_key_for`) and Subnet return identities (`return_node_ip`, `enforced_subnet_return_peer_key`) in `AccountFilter::outbound_route`, and the outbound `account: route owner mismatch` drop | the lease prefixes and return identities in the owning peer's `allowed_ips`: routing picks the owner, so the outbound check disappears |
| `AccountFilter` inbound IPv6 step (`inbound_ipv6`: `allows_inbound_subnet_packet`, a lease owned by this node, or this node's `:2::<tun IPv4>` return identity from the lease's peer; `enforced_subnet_ingress_authorized`; no ACL) and the `account: ipv6 not authorized` drop | `AclFilterConfig::ipv6 = Ipv6Mode::Accept` (set by `crates_acl`: the filter does not judge IPv6) plus `PeerConfig::inbound_destinations` of each peer in the core, set from the same leases and grants (`Some` for every peer, also with no lease, since ns drops all unauthorized IPv6; with `0.0.0.0/0` because ns checks no IPv4 destination), dropped as `reasons::DESTINATION_NOT_ALLOWED`; updated with `EngineHandle::set_inbound_destinations` or `add_or_update_peer` when leases or Subnet returns change |

ns keeps the policy compilation and projection (the control-plane policy into an
`AclPolicy`, the relay-client key set, leases and Subnet returns into allowed IPs and
inbound destinations) and the conversion of each into the calls above; the Node L3 gate's
mapping is in its own section.

nsplane only enforces: the peer source lifecycle (`PeerSource`), rendezvous and the
pairing and transfer state machines stay in ns, which stores namespaces, grants and pinholes
through this API. `examples/src/bin/app_session.rs` shows a file transfer on it.

### Node L3 gate

`NodeL3Gate` (`crates/nsplane-acl/src/node_l3*`) is the port of ns tunnel-wg `node_l3`
(MD-2, plan `20261003-2300-acl-l3-gate`): an authenticated, target-bound policy on the Node
address plane, judged on decrypted inbound and plaintext outbound IPv4 packets. Its
configuration types (`NodeL3Config`, `NodeL3Node`, `NodeL3PeerBinding`,
`NodeL3ServiceEndpoint`, `NodeL3Grant`, `NodeL3Resource`, `NodeL3Transport`,
`NodeL3TransportPeer`, `NodeL3PeerPolicyRequirement`) mirror ns `control::messages`, which
nsplane cannot depend on.

- **Snapshots.** `apply` / `apply_from_source` validate a per-Network snapshot (schema,
  target machine, generation, source authority, references) and publish it atomically; a
  Network stays pinned to its first source, and its tombstone (generation, phase, content)
  outlives `disabled` and `withdraw_source`, so stale snapshots cannot resurrect access.
  `replace_transport_projection` installs the WireGuard projection (local address, peers'
  routes, gateway role, policy markers); `replace_provider_listeners` the local Service
  listeners.
- **Grants.** Nodes of one owner reach each other; otherwise a Node Grant opens the whole
  target Node, a Service Grant one exact listener (inbound only while the local Provider
  listener is installed, else `service_projection`), and Subnet Grants are exposed through
  the `enforced_subnet_*` queries and the reserved Subnet transport admission
  (`evaluate_subnet_transport_*`, `NodeL3Filter::with_subnet_transport_port`).
- **Source binding.** A packet belongs to a Network only through the exact
  `(peer key, inner Node address)` pair of a binding; anything else is `source_binding`. A
  peer carrying a policy marker fails closed (`policy_pending`) until the matching snapshot
  is applied.
- **State.** An allowed new flow creates state that admits its replies, later fragments
  and ICMP errors (matched through the quoted header): idle timeouts TCP 2 h, half-closed
  5 min, closed 30 s, UDP 2 min, ICMP 30 s, other 60 s, fragments 30 s. A reply-only packet
  without state is `reverse_new_flow`, as is a new SYN on a closing flow; a later fragment
  without its first is `orphan_fragment`. Limits: 2,048 flows per peer, 16,384 in all and
  4,096 fragments (`with_limits`); a full table sweeps expired entries and then fails
  closed with `state_capacity`, never evicting a live flow.
- **Modes.** No snapshot (or `disabled`) is `NodeL3Decision::Legacy`; `observe` reports
  the prospective verdict and counts denials (`NodeL3Counters::observed_denied`) without
  enforcing; `enforce` is authoritative. `NodeL3Reason` maps 1:1 to ns's reasons
  (`as_str`, and `drop_reason` = `node l3: <reason>` for drops).

**State and locking.** Packet paths take one lock-free load of an immutable `Snapshot`
(behind an `ArcSwap`) holding the compiled policies, keyed by interned Network ids, and the
projection, and then lock only the state shard of the remote peer: 64 shards by peer key,
each tagged with the snapshot epoch it was migrated to. Writers serialize on one mutex,
build the next snapshot, and migrate the state (revalidate or drop flows) with every shard
locked; a packet whose shard epoch differs from its snapshot retries, so it never sees a
policy together with state of another one. Expired entries are swept only when a limit is
reached (the peer's shard first, every shard for the global limit). The gate's clock is
`Instant::now` or injected (`with_clock`) for tests and benches. Every policy or transport
change that can alter the usable Subnet Grants bumps `authorization_generation` and calls
`set_on_authorization_change`.

**Composition.** `NodeL3Filter` runs the gate as one `PacketFilter`, with an optional
`AclFilter` behind it (`with_acl`), because an enforced allow must end the decision before
the L4 ACL, which an accept-means-continue chain cannot express. Inbound: an unknown peer
(no key in `PeerPublicKeys` / `PeerKeyMap`) is dropped; IPv4 goes through the Subnet
transport admission (when a port is set) and `evaluate_inbound`; an enforced allow is
`Accept` without the ACL, an enforced denial drops with the gate's reason, and Legacy,
Observe, IPv6 and non-IP go on to the ACL (or are accepted without one). Outbound is the
gate only, as in ns; `with_acl_outbound(true)` also runs the ACL's outbound for packets the
gate did not deny. `NodeL3FilterStats` counts the steps.

**Divert (MD-3).** With `with_divert(sink)`, an inbound `source_binding` or
`orphan_fragment` denial that the gate captures as a gateway return
(`gateway_consumer_packet`: an installed, non-relayed gateway carrier and an Enforce
policy) is offered to the `GatewayConsumerSink`; accepted, it is `Verdict::Handled` (no
delivery, no drop event); refused (full or closed), it is dropped with the gate's reason.
The consumer rechecks `gateway_consumer_authority_current` and its exact flow before
delivery.

**ns wiring.** ns keeps policy compilation: it converts its `NodeL3Config` and `WgConfig`
to the mirror types, applies them, and installs `NodeL3Filter::new(gate, keys).with_acl(acl)`
(plus `with_subnet_transport_port(53535)` and `with_divert`) on its engine. On an
`authorization_generation` change it recomputes `enforced_subnet_ingress_prefixes` into
nsplane-core's per-peer inbound destinations (`PeerConfig::inbound_destinations` through
`EngineHandle::set_inbound_destinations` / `ConfigChange::SetInboundDestinations`, MD-6),
which replace the gate's IPv6 Subnet ingress check. ns then deletes tunnel-wg `node_l3*`
(gate and tests) and `AccountFilter`'s gate and divert steps (with MD-A, also its ACL step:
`acl_check_packet` and the `FragmentAclGate` use). ns keeps the policy compilation, the
`NodeL3Config` / `WgConfig` conversion, the gateway consumer queue and its flow check, and
the inbound destinations push. The ns `AccountFilter` steps and their nsplane locations are
tabled in the `NodeL3Filter` rustdoc.

**Tests.** The 60 tests of ns `tunnel-wg/src/node_l3/tests` are ported
(`node_l3/tests/{grants_flow,packets_fragments,subnet,transport_policy,gateway_consumer}.rs`),
plus state-table and concurrency tests (writers publishing while packet threads evaluate,
checking the epoch invariant and the counts) and the `NodeL3Filter` tests ported from ns
`AccountFilter`. A differential fixture recorded from ns
(`crates/nsplane-acl/src/node_l3/fixtures/differential.json`) is replayed by
`node_l3/tests/differential.rs`. `nsplane-e2e` `node_l3` runs the filter on one of two
engines: Grants, source binding, state, limits and expiry (injected clock), modes, ICMP
errors, divert and outbound.

**Measured** (`cargo bench -p nsplane-acl --bench node_l3`, see [Performance](#performance)):
2026-10-04 on the shared host (1-minute load 23-32), two runs interleaved with the previous
code: an established flow costs 129 / 134 ns through `NodeL3Filter` (was 214 / 429) and
90 / 103 ns through `evaluate_inbound` alone (was 229 / 350), 128 / 81 ns outbound; new
flows 172 / 110 ns (Node Grant, was 396 / 781) and 235 / 121 ns (Service Grant, was
476 / 795); the `AclFilter` alone 50 / 34 ns, `NodeL3Filter` with a gate without snapshot
57 / 50 ns (was 114 / 170), that gate alone 2.3 ns; with a writer publishing every 1 ms /
10 ms 87 / 88 ns and 90 / 92 ns. At load 13 the established flow measured 69-73 ns through
the gate and 86-90 ns through the filter. A release-mode breakdown (load 5-20) puts
`evaluate_inbound` at 64-69 ns: the clock 18 ns (`perf`: `clock_gettime` is 46 % of the
samples), the snapshot load 9 ns, the shard lock 8 ns, the counter 4 ns, the flow and
binding lookups 4 + 3 ns, parsing 2.4 ns. A gate without snapshot or transport adds
7-17 ns over the `AclFilter`: the peer key lookup (~10 ns, needed to drop unknown peers)
and the hand-off counter.

Accepted 2026-10-04 as within the ACL hook's class: the established flow at 64-73 ns quiet
and 90-103 ns at load 23-32 through the gate, 86-90 / 129-134 ns through `NodeL3Filter`, an
inert gate 2.3 ns, writer contention 87-92 ns. The remaining gap to ~60 ns is mostly the
per-packet clock read (~18 ns, `__vdso_clock_gettime` 46 % of the `perf` samples), plus the
`ArcSwap` snapshot load (~9 ns) and the shard mutex (~8 ns). A possible follow-up, not done:
a per-batch or cached timestamp instead of a clock read per packet. It gives millisecond
expiry granularity against timeouts of 30 s and more, but differs from ns's per-packet
`Instant::now`, so it needs an owner decision.

## nsplane-nat

Packet filters for the engine's filter chain; they rewrite packets in place and keep no I/O.

**Address model.** Every peer owns a /127 IPv6 group, `node6` (native) and `node4` (its IPv4
side). This node presents a peer to local applications as an IPv4 alias (`alias4 <-> node4`)
and optionally an IPv6 alias (`alias6 <-> node6`) and a native IPv4 alias (an IPv4 address
translated to and from `node6`, quick-v2 `alias6(b)`); the node itself is `self4 <-> node4`, and
IPv4 LAN prefixes pair with IPv6 /96 prefixes holding the IPv4 address in the low 32 bits
(`lan4 <-> lan6`), behind this node or behind a peer. `TranslationTable` (built and validated
by `TranslationTableBuilder`) holds this model immutably; `Translator::store` replaces it
atomically while traffic flows.

**Translator.** A stateless RFC 7915 translator: local IPv4 to an `alias4` or a peer's LAN
leaves as IPv6 to `node4` / `lan6`, IPv6 to `alias6` is rewritten to `node6`, and the
replies are mapped back; local IPv4 to a peer's native IPv4 alias
(`TranslationTableBuilder::peer_with_native_alias4(id, mapping, alias)`; looked up with
`TranslationTable::native_alias4` / `by_native_alias4`) leaves as IPv6 to its `node6`, from
`node4` for `self4` or from the `lan6` address of a local LAN source, and IPv6 from that
`node6` comes back as IPv4 from the alias, ICMP errors and fragments included (ns's MQ-9).
The native alias coexists with `alias4` and `alias6`, must not collide with `self4`, another
peer's `alias4` or native alias, or a LAN IPv4 prefix, and is covered by
`Translator::ipv4_translated_predicate`; pinned by `nsplane-e2e`'s `translate_native_alias`
tests (UDP, TCP, ICMP Echo, coexistence with `alias4`); native IPv4 and IPv6 pass unchanged and packets spoofing a
local-view address are dropped. TTL/hop limit, ICMP/ICMPv6 (echo and errors, including the
quoted packet and the MTU of Fragmentation Needed / Packet Too Big) and fragments (with an
IPv6 Fragment header) are translated; TCP/UDP checksums are verified and updated
incrementally. A fragmented IPv4 UDP datagram without a checksum is reassembled first, in
any fragment order: only the first fragment shows the checksum, so later fragments that
arrive before it are held (at most 256 datagrams and 1 MiB, for 60 s; a fragment after the
expiry starts a new entry) in an `nsplane_packet::reassembly::Reassembler`, the one the
netstack driver uses; the translator keeps the byte budget and the markers on top of it. A datagram with a checksum whose later fragments came first is
reassembled the same way and sent unfragmented; with nothing held, in-order fragments of a
checksummed datagram are translated one by one, without holding or waiting. A reassembled
datagram larger than the translator's MTU (`Translator::set_mtu`, 1280 by default; set it
to the tunnel MTU) is dropped as `reasons::REASSEMBLED_TOO_BIG`, never sent oversize.
`TranslatorStats` counts `fragments_held` (exact duplicates, ignored, included), `fragment_timeouts`, `fragment_budget_drops`,
`fragment_marker_evictions` and `reassembled_too_big`. A translated packet grows by 20
bytes (28 with a fragment header) inside its buffer when it has the room, else it is copied
into a larger buffer (`TranslatorStats::grown_copies`); TUN reads leave that room. A
translated IPv6 packet shrinks without moving its payload: the IPv4 header is written in
front of it and the packet start moves forward (the headroom grows by 20 or 28 bytes).
Transport checksums are verified with `checksum::transport_valid` (32-bit word sums, about
four times faster than the 16-bit full recomputation) and then moved to the new
pseudo-header incrementally; the reassembly clock is read only for fragments, and the
table's address indexes hold the mapping, so a lookup is one hash. Per-packet costs are in
[nsplane-nat translator (MF-4)](#nsplane-nat-translator-mf-4). Since the core routes and checks sources before the
filters, each peer's allowed IPs must contain its `alias4/32`, its native IPv4 alias as a /32
if any, the LAN IPv4 prefixes behind it, its `alias6`, `node4`, `node6` and the `lan6` prefixes behind it.

**PortMap and Conntrack.** `PortMap` publishes local services to peers: a `PortMapRule` maps a
tunnel-facing `listen` address and port (TCP or UDP) to a local `target` of the same family,
optionally for some peers only (other peers are dropped). Inbound packets are DNATed and
their flow recorded in a `Conntrack`; replies are SNATed back to `listen` when routed to the
flow's peer, and ICMP errors quoting a flow are rewritten too. `Conntrack` is bounded (least
recently seen flow evicted), expires flows on per-protocol idle timeouts (TCP state aware)
without a background task, and takes an injectable clock. `PortMap::set_rules` swaps rules
atomically and drops the flows of changed rules.

**Nat64Lan.** A stateful NAT64 to an IPv4 LAN (NAPT) for a subnet gateway, ported from ns
`SubnetRoute`. A `LanRoute` maps an IPv6 /96 (`mapped`) to an IPv4 prefix (`real`); the
prefixes are `(Ipv6Addr, u8)` / `(Ipv4Addr, u8)` pairs validated by `LanRoute::new`, like
`LanPrefix`, since no IP network crate is a dependency. IPv6 TCP, UDP and ICMPv6 echo to
`mapped` plus a safe address of `real` (not broadcast, loopback, link-local, multicast or
unspecified; other mapped targets are dropped and counted) become IPv4 from the route's
`snat_source`, with a port (or echo identifier) reserved for the flow through the caller's
`SnatPorts` and given back when the flow expires, is evicted or is removed
(`Nat64Lan::remove_flow`, built on `Conntrack::remove` and its removal hook); a saturated
range drops the packet rather than aliasing a flow. Replies and Fragmentation Needed (as
Packet Too Big) are translated back; TCP MSS can be clamped. As in ns, translated packets
leave DF clear (`Nat64LanConfig::set_df` sets it above 1260 bytes, trading LAN
fragmentation for a PMTU black hole when the LAN filters ICMP), and a destination that more
than one route resolves is dropped and counted (`reasons::AMBIGUOUS_ROUTE`). The routes gate
every forward packet; a flow keeps its SNAT address across a route replacement, and the
caller revokes the flows of a removed route with `remove_flow`. Unlike the filters above it sits
on the **local side**: the LAN's replies are addressed to `snat_source`, which no peer's
allowed IPs contain, so the core could not route them to a peer before a filter ran.
`Nat64LanSink` runs `forward` on the packets the engine delivers and `Nat64LanSource` runs
`reverse` on local packets before the core routes them (the IPv6 result goes to the peer
owning the original source). The clients route the mapped /96 to the gateway (it is in their
allowed IPs for it), and the gateway's local side routes `snat_source` back to itself. The
wrappers make `nsplane-nat` depend on `nsplane`; `nsplane` does not depend on `nsplane-nat`.

**Redirect.** `Redirect` is not a filter: it runs on the local side, on `PacketBuf`s before
they reach a local endpoint (`forward`) and on that endpoint's replies (`reverse`). It
sends the IPv4 TCP/UDP flows a local application opens to a service address to an
endpoint a caller-supplied closure picks for each new flow (`RedirectDecision::Redirect`,
`Pass` or `Drop`), for example a `nsplane-netstack` listening on its own address, and
rewrites the replies so they come from the service address; the source is kept. Flows
live in a `Conntrack` (translated tuple: application to endpoint; `Flow::peer` unused); an
endpoint already used by a live flow from the same source is refused and the closure asked
again, up to 32 times by default (`Redirect::with_endpoint_tries(NonZeroUsize)`, ns's MQ-6).
A closure with a small endpoint pool can scan it with `Redirect::endpoint_in_use(original,
endpoint)` and offer a free endpoint first, or offer each in turn with as many tries as the
pool has endpoints. `endpoint_in_use` looks the flow up with `Conntrack::peek`, which skips a
flow past its idle timeout and neither refreshes it, advances its TCP state or eviction
order, nor counts a hit or miss, so scanning a pool keeps no idle flow alive; another thread
may still take the endpoint before the answer is recorded, which only costs a try. Pinned by
`nsplane-e2e`'s `redirect_tries::a_small_pool_is_scanned_with_endpoint_in_use`. `remove_flow` (by the endpoint's view of the flow) and `retain` end
flows; `original_destination` gives the service address of an accepted flow. The closure
never runs under a lock, so it may call back into the `Redirect`. IPv6, fragments, other
protocols and untracked replies pass unchanged.

**Masquerade.** `Masquerade` also runs on the local side: on the IPv6 packets a routed LAN
host sends towards the tunnel (`forward`) and on their replies (`reverse`). It is a source
NAPT ported from ns `SubnetLanIngressTranslator`: a caller-supplied closure gives each new
TCP, UDP or `ICMPv6` Echo flow a source (`MasqueradeDecision::source`, an `Ipv6Addr`: the
contract's `IpAddr` was narrowed by L1 decision, so an IPv4 source cannot be expressed) and
a `route` fingerprint, and the source port or Echo identifier becomes a token from
`MasqueradeConfig::ports`, unique per destination and source. `reverse` restores the LAN
host's address and port or identifier, after asking the closure again: a reply whose flow
now gets `None` or another `route` is dropped and the flow removed (`route_changed`, ns's
rule that the route fingerprint must stay current). With
`MasqueradeConfig::recheck_route_on_forward` (default `false`), forward asks the closure for
every packet of a recorded flow too and drops it the same way (`ROUTE_CHANGED`), as ns did. The transport checksum is recomputed
over the IPv6 pseudo-header. Drop reasons (`masquerade::reasons`, counted in
`MasqueradeStats`): `tcp_not_syn` (with `tcp_new_flow_requires_syn`, only a SYN opens a TCP
flow), `capacity`, `route_changed`, `tokens_exhausted` and `bad_checksum` (with
`verify_checksums`, an invalid transport checksum; beyond the contract, ns drops these
too). Forward verifies the checksum only for packets it masquerades: for a new flow after the
closure returned `Some` (a corrupt first packet records no flow), for a recorded flow before
the route recheck; a packet that passes unchanged is never dropped for its checksum. Flows live in a dedicated table instead of a `Conntrack`: a full masquerade table
refuses new flows, as the contract and ns require, while a `Conntrack` evicts its least
recently seen flow. Expiry is lazy, per protocol. IPv4, extension headers, fragments, other
protocols and replies of unknown flows pass unchanged. A local side that answers pings
itself can recognize a forwarded `ICMPv6` Echo request with the read-only
`nsplane_packet::icmp::is_echo_request` and turn it into its reply with
`nsplane_packet::icmp::echo_reply_in_place`, and `reverse` takes it back to the LAN host
(`crates/nsplane-e2e/tests/masquerade.rs`). A criterion bench
(`crates/nsplane-nat/benches/masquerade.rs`) measures both directions.

**Order.** The recommended chain is `[AclFilter, PortMap, Translator]`: the translator sits
next to the local side, so the ACL and the port map see overlay IPv6 in both directions and
ACL policies need no rules for the IPv4 aliases. With the engine's fragmentation stage and
`Translator::ipv4_translated_predicate`, oversized local IPv4 to translated destinations is
fragmented to fit the MTU after translation.

## Optional features and defaults

A basic client is an `EngineBuilder` on a TUN device and a `UdpTransport` with peers and
no filters. Every feature below is optional; one that is not installed is not on the data
path, so such a client pays no extra latency for it.

| Feature | Crate | How to enable | Default | Cost when not enabled |
|---|---|---|---|---|
| IPv4/IPv6 translation | `nsplane-nat` | `EngineBuilder::filter(Box::new(Translator::new(table)))`; `Translator::set_mtu` to the tunnel MTU | not installed | none: the core's filter chain is empty |
| Native IPv4 alias of a peer's `node6` | `nsplane-nat` | `TranslationTableBuilder::peer_with_native_alias4(id, mapping, alias)` | no native alias | negligible: without one, a lookup in an empty map where the translator already looks up `alias4` (only with a `Translator` installed) |
| Service publishing (DNAT/SNAT) | `nsplane-nat` | `EngineBuilder::filter(Box::new(PortMap::new(rules)?))`, or `PortMap::with_conntrack` for a sized `Conntrack` | not installed | none |
| NAT64 to LAN (NAPT) | `nsplane-nat` | wrap the local side: `EngineBuilder::new(Nat64LanSource::new(source, nat.clone()), Nat64LanSink::new(sink, nat))` | not installed | none |
| Local-side redirect (DNAT) | `nsplane-nat` | call `Redirect::forward` / `Redirect::reverse` on the local path | not used | none |
| Redirect endpoint tries / pool scan | `nsplane-nat` | `Redirect::with_endpoint_tries(n)`; `Redirect::endpoint_in_use` from the decision closure | 32 tries, no scan | none: the same loop with another bound; `endpoint_in_use` runs only when called |
| Local-side masquerade (IPv6 source NAPT) | `nsplane-nat` | call `Masquerade::forward` / `Masquerade::reverse` on the local path | not used | none: a plain type, only called if the embedder wires it |
| ICMP Echo reply synthesis | `nsplane-packet` | call `icmp::echo_reply_in_place` on a request for an address the local side answers | not used | none: a plain function, only called if the embedder wires it |
| UDP datagram builder | `nsplane-packet` | `build::udp_packet` / `build::write_udp` for packets to inject | not used | none: plain functions, only called if the embedder wires them |
| ACL | `nsplane-acl` | `EngineBuilder::filter(Box::new(AclFilter::new(engine, identity)))` (`AclFilter::with_config`) | not installed | none |
| ACL principal by source address | `nsplane-acl` | `PeerIdentityMap::insert_by_source(peer)` (or a `PeerIdentity` overriding `assertion_for` and `by_source`) | per peer: one principal per peer | one cached flag per peer; no per-address table is filled |
| ACL fragment mode | `nsplane-acl` | `AclFilterConfig::fragments = FragmentMode::ALLOW_ONLY` (or `AllowOnly { ttl, capacity }`) | `FragmentMode::Outcome` | none: the same gate as before |
| ACL bypass flags | `nsplane-acl` | `AclFilterConfig::accept_to_local = Some(addr)`, `accept_icmp_echo_reply = true` | off | one branch per inbound packet each |
| ACL IPv6 mode | `nsplane-acl` | `AclFilterConfig::ipv6 = Ipv6Mode::Accept` | `Ipv6Mode::Evaluate` | one branch per packet |
| ns `crates/acl` mode | `nsplane-acl` | `AclFilter::with_config(engine, identity, AclFilterConfig::crates_acl(local))` | not used | none: a preset of the options above |
| Inbound destinations | `nsplane-core` | `PeerConfig::inbound_destinations = Some(nets)`, `EngineHandle::set_inbound_destinations` | `None`: unchecked | one `Option` check per decrypted packet |
| Flow accounting | `nsplane-acl` | `EngineBuilder::filter(Box::new(FlowTracker::new(capacity)))` | not installed | none |
| Node L3 gate | `nsplane-acl` | `EngineBuilder::filter(Box::new(NodeL3Filter::new(gate, keys).with_acl(acl)))` | not installed | none |
| Fragmentation stage | `nsplane` | `EngineBuilder::fragmenter(FragmentConfig::default())`; `FragmentConfig::translated` for destinations a translator turns into IPv6 | off | one `Option` check per local packet; local packets enter the core whatever their size |
| Per-path MTU | `nsplane` | `EngineBuilder::transport_max_datagram` / `EngineHandle::set_transport_max_datagram`, `EngineHandle::report_path_mtu`, or a transport whose `path_mtu_reports` returns a receiver; `EngineBuilder::fragmenter` to make it reach the local side | off: every peer at the source MTU, padding to 16 bytes | none: no table, padding limit or report task until a ceiling is set or a report arrives; the fragmentation stage looks a peer up only for packets above the lowest MTU |
| Crypto worker pool | `nsplane` | `EngineBuilder::crypto_workers(n)`, `n` >= 2 | 0: the owner task encrypts and decrypts | one `Option` check per packet, no tasks spawned; without crypto workers each peer owns its tunnel and the data path takes no lock (with workers it is shared behind a `Mutex`) |
| User-space TCP/IP stack | `nsplane-netstack` | `NetStack::new(NetStackConfig)`, `NetStack::split` as the builder's source and sink | not used | none: the crate is not a dependency of `nsplane` or `nsplane-tun` |
| Stack reassembly | `nsplane-netstack` | `NetStackConfig::reassembly = Some(ReassemblyConfig::default())` (64 datagrams, 30 s, 65 535 bytes) | off: fragments are dropped (`unsupported`) | one `Option` check per ingress packet; no reassembler is allocated |
| TCP socket buffers | `nsplane-netstack` | `NetStackConfig::tcp_rx_buffer` / `tcp_tx_buffer = Some(bytes)`, clamped to `mtu - 40 ..= 65535 << 14` | `None`: `(mtu - 40) * 512` bytes each, as before | none: the sizes are resolved once when the stack is created |
| Oversize IPv4 UDP sends | `nsplane-netstack` | `NetStackConfig::udp_allow_fragmentation = true`, with `EngineBuilder::fragmenter` on the stack's engine | off: a packet above the MTU fails with `InvalidInput` | one length comparison per send, as before |
| TCP abort | `nsplane-netstack` | `TcpConnection::abort` instead of dropping the connection | drop closes with a FIN | one state compare under the connection's lock and two empty-`Vec` takes per driver turn |
| Fragment discard | `nsplane-netstack` | `NetStackHandle::discard_fragments(src, dst, protocol, id)` when a flow's admission is revoked; needs `NetStackConfig::reassembly` | not called | none without reassembly; with it one atomic load per ingress packet while nothing is discarded, no lock |
| Later-fragment ownership | `nsplane-netstack` | on with `NetStackConfig::reassembly`; `owns` reports a datagram's later fragments as its first fragment's `Flow` | off without reassembly (fragments are `None`) | none without reassembly; with it only fragment classification in `owns` takes the memory's lock |
| Connected UDP sockets | `nsplane-netstack` | `NetStackHandle::connect_udp(remote)` / `connect_udp_from(local, remote)` | not used: `bind_udp` sockets take any remote | one `HashMap::is_empty` per UDP datagram |
| Hybrid local side | `nsplane` | `Splitter::new(route).sink(..)` as the sink, `MergeSource::new().source(..)` as the source | not used | none: plain types, used only when passed to the builder |
| Local-side graph | `nsplane` | `MapSink::new(sink, f)` / `MapSource::new(source, f)` around a sink or source; `pipe(capacity, mtu)` to feed one engine's output into another's input; `pump(source, sink, from)` spawned between two endpoints | not used | none: plain generic types, used only when passed to the builder or spawned; nothing changes for an engine that does not use them |
| Windows service TUN checks | `nsplane-tun` | `Tun::create_with(name, TunOptions::new().wintun_pin(pin).exclusive(true).mtu(n))` (Windows) | off: `wintun.dll` from the search path, an existing adapter opened, the MTU left as it is | none: `Tun::create` takes the same path as before |
| TUN segmentation offload | `nsplane-tun` | `Tun::create` turns it on; `Tun::create_with(name, TunOptions::new().offload(false))` opts out; `Tun::offload` reports it | on where the kernel supports it (Linux, Android); macOS, iOS and Windows have none | off: one read or write system call per packet |
| UDP segmentation offload (GSO/GRO) | `nsplane` | `UdpTransport::bind` turns it on; `UdpTransport::bind_with_offload(id, addr, false)` or `set_offload(false)` opts out | on: GSO where the platform has it, GRO on Linux and Android | off: one system call per datagram |
| UDP side channel | `nsplane` | `UdpTransport::with_side_channel(classify, capacity)` | off | one `Option` check per received datagram; nothing is classified, no task or copy |
| UDP path MTU discovery | `nsplane` | `UdpTransport::set_path_mtu_discovery(true)` before handing the transport to the engine (Linux, Android) | off | none: no socket option, no error-queue read, no report queue |
| Awaiting side send | `nsplane` | `SideSender::send_to_async` instead of `send_to` | not used | none |
| Message-link transport | `nsplane` | `LinkTransport::new(id, peer, dialer, config)` as a transport | not used | none: no task is spawned and no dependency added; the dialer (WebSocket, TLS) is the embedder's |
| WSS carriers | `nsplane-wss` | `WssDialer::new(config)?.into_transport(..)`, `WssStreamClient::new`, `WssStreamServer::new` | not a dependency | none: a separate crate; `nsplane` gains no WebSocket or TLS dependency (`tokio-tungstenite`, `rustls` with aws-lc-rs come only with `nsplane-wss`) |

**Crates of a minimal client.** `nsplane` and `nsplane-tun`, which pull in `nsplane-core`,
`nsplane-packet` and `nsplane-noise`. `nsplane-acl`, `nsplane-nat` and `nsplane-netstack`
are separate crates that `nsplane` and `nsplane-tun` do not depend on (`nsplane-nat` and
`nsplane-netstack` depend on `nsplane`, not the other way round), so they are not
built or linked unless the application adds them; `nsplane-uapi` is only needed to serve
the `wg` UAPI. None of the crates has optional Cargo features.

**Address family.** IPv4-only, IPv6-only or dual stack is the caller's choice and needs no
switch: the transport's bind address (`0.0.0.0:port` for IPv4 only, an IPv6 address for
IPv6 only, `[::]:port` for a dual-stack socket), the addresses and routes configured on the
TUN device (outside nsplane, e.g. `ip addr`), and the peers' allowed IPs.

**A minimal IPv4-only client** (one TUN device, one UDP socket, one peer, no filters):

```rust
use std::error::Error;
use std::net::SocketAddr;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{Ecn, EngineBuilder, Path, Peer, TransportId, UdpTransport};
use nsplane_tun::Tun;

async fn client(
    key: StaticSecret,
    server_key: PublicKey,
    server: SocketAddr, // e.g. 198.51.100.1:51820
) -> Result<(), Box<dyn Error>> {
    const UDP: TransportId = TransportId::new(0);
    // The caller sets up the TUN device's addresses and routes, e.g.
    // `ip addr add 10.0.0.2/32 dev wg0` and `ip route add 10.0.0.0/24 dev wg0`.
    let (source, sink) = Tun::create("wg0")?.split()?;
    let udp = UdpTransport::bind(UDP, "0.0.0.0:0".parse()?)?;
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    let mut peer = Peer::new(server_key);
    peer.allowed_ips = vec!["10.0.0.0/24".parse()?];
    peer.persistent_keepalive = Some(25);
    peer.path = Some(Path { transport: UDP, addr: server, ecn: Ecn::NotEct });
    engine.handle().add_or_update_peer(peer).await?;
    engine.wait().await?;
    Ok(())
}
```

**Offload never waits for more packets.** Batching and offload only group work that is
already there; nothing holds a packet back to fill a batch:

- the engine's I/O tasks fill a batch with non-blocking `try_recv` after the first packet
  and send what they have (no timers, no linger);
- TUN GSO/GRO writes coalesce only the packets of the batch they are handed;
- UDP GSO segments only runs of datagrams within the current batch;
- a GRO or segmented TUN read returns what one receive yields;
- the crypto worker pool hands a batch to a worker when it is full or when the owner task
  runs out of other work, never on a timer.

## Performance

Phase 5 numbers: release / bench profile in the dev image, x86-64, 32-core host shared with
other jobs, criterion means. The `data_path`, worker pool and engine latency rows are from
the Phase 5 follow-ups (campaign `nsplane-fu-202610030716`, workstream FA, 2026-10-03:
follow-ups #1 batched input and #17 no lock without workers); the other rows were re-run on
the merged 5C branch (5C-T7, 2026-10-03, 1-minute load 0.8-5.1), two runs each. The
subsections linked below hold each subtask's own measurements and analysis.

```text
cargo bench -p nsplane-core --bench data_path
cargo bench -p nsplane-acl --bench namespaces
cargo bench -p nsplane --bench worker_pool
cargo bench -p nsplane --bench local_graph
cargo test --release -p nsplane-e2e --test netstack_lossy -- --ignored --nocapture
cargo test --release -p nsplane-e2e --test netstack_stream -- --ignored --nocapture
cargo test --release -p nsplane-e2e --test latency -- --ignored --nocapture
```

| Area | Case | Result (run 1 / run 2) | Reference |
| --- | --- | --- | --- |
| `data_path`, 64 B round trip | raw `Tunn` / device-equivalent / core, one packet per call | 359 ns, 472-474 ns, 530-533 ns (core vs device +12 %) | main 64131c7 core 546 ns; Phase 3+4 core 540 ns |
| `data_path`, 1420 B round trip | device-equivalent / core, one packet per call | 1.278-1.294 us, 1.331-1.351 us (core vs device +4-5 %) | main 64131c7 core 1.354 us; Phase 3+4 core 1.37 us |
| `data_path`, 64 B batched | core, 32 per call (`core_round_trip_batch32`), per packet | 13.15-13.21 us per batch = 411-413 ns (core vs device -12.5 % to -13.0 %) | |
| `data_path`, 1420 B batched | core, 32 per call, per packet | 39.24-39.31 us per batch = 1.227 us (core vs device -4.0 % to -5.2 %) | |
| `data_path`, instructions per round trip (callgrind) | raw `Tunn` / device-equivalent / core / core batched, 64 B and 1420 B | 3090 / 4435 / 5299 / 3910 (batched vs device -11.8 %); 18168 / 19513 / 20370 / 18980 (-2.7 %) | core before #1's batching 5289 / 20359 |
| `data_path`, one direction (5C) | core encapsulate / decapsulate, 64 B and 1420 B | 273 / 273 ns and 278 / 278 ns; 673 / 674 ns and 692 / 685 ns | |
| ACL hook, established flow | namespace member / default policy (not cached) | 51.2 / 51.0 ns, 54.9 / 54.6 ns | before the hook: every packet a new flow, 669 ns / 71 ns |
| ACL hook, bypass peer | new flow / established | 38.1 / 37.9 ns, 37.5 / 37.3 ns | 937 ns before the hook |
| ACL hook, new flow | default policy / namespaces / grant / pinhole | 55.4 / 55.2 ns, 184 / 184 ns, 346 / 339 ns, 216 / 205 ns | |
| ACL hook, grant established / outbound | grant / outbound (default, namespaces, restricted, bypass) | 268 / 276 ns; 76, 95, 156, 77 ns | 1.75 us grant, 580/623 ns outbound before |
| ACL hook, floor | five-tuple parse + snapshot load | 5.7 + 8.8 ns | |
| Queues | default capacities | `queue_capacity` 1024, command 64, `event_capacity` 1024 | [Queue depths](#queue-depths) |
| Worker pool, 64 B | off / 2 / 4 workers | 1.49 / 1.55 Mpps, 1.68 / 1.64 Mpps, 1.61 / 1.64 Mpps | before #1/#17: 1.21 / 1.07, 1.30 / 1.27, 1.25 / 1.26 Mpps; [Crypto worker pool](#crypto-worker-pool) |
| Worker pool, 1420 B | off / 2 / 4 workers | 869 / 906 kpps (9.9 / 10.3 Gbit/s), 0.94 / 1.20 Mpps (10.6 / 13.6 Gbit/s), 1.26 / 1.17 Mpps (14.3 / 13.3 Gbit/s) | before #1/#17: 676 / 676 kpps, 1.02 / 1.00 Mpps, 0.98 / 0.98 Mpps |
| Engine latency, idle | two engines over UDP loopback, builder defaults, 2000 pings, p50 / p99 | 11.3 / 36.0 us, 11.2 / 40.3 us | before #1's engine batching: 20.9 / 41.0 us, 11.0 / 23.7 us; [Engine batching under load](#engine-batching-under-load) |
| Engine latency, loaded | the same next to a saturating bulk flow, p50 / p99 / lost pings | 2.15 / 4.69 ms / 13, 2.13 / 5.16 ms / 18 | before: 2.71 / 6.91 ms / 2, 2.36 / 4.74 ms / 1 |
| Netstack TCP, no loss | 64 MiB, one connection | 439.0 / 430.0 MB/s | [Netstack throughput](#netstack-throughput) |
| Netstack TCP, 1 % loss | 16 MiB | 2.07 / 2.08 s (8.1 MB/s) | |
| Netstack TCP, 3 % loss | 16 MiB | not done after 60 s (833 / 715 drops) | 5C-T6: 54.2 / 59.2 s |
| Netstack TCP, bottleneck | 16 MiB, 25 MB/s, 64-datagram buffer | 12.9 / 16.8 s (1.3 / 1.0 MB/s, 320 / 341 drops) | 5C-T6: 20.9 / 18.9 s |
| Netstack UDP, no loss | 50 000 x 1200 B | 614.7 / 670.2 MB/s | |
| Netstack TCP, smoltcp `.4` (ON) | `netstack_lossy` 1 % loss / 3 % loss / bottleneck, 16 MiB (final gate, load 8.9-9.3) | 1.14 s / 19.2 s / 0.82 s | `.3`: 1.1-6.2 s / stalls past 60 s / 14.9-23.9 s; [Netstack throughput](#netstack-throughput) |
| Netstack pair (harness, ON) | TCP P1 / P4 Gbit/s, UDP loss 1G / 3G %, 30 s x 3 medians (2026-10-05, load 2.2-3.5) | 6.85 / 7.29, 0.00 / 0.03 | `main` b5e531f same window: 6.21 / 2.48, 2.21 / 5.56 |
| Engine fast path (MF-1), TUN, nsplane-cli -> nsplane-cli | iperf3 TCP -P1 / -P4, no workers, median of the 3 quiet pairs (load1 <= 12.3) | 9.90 / 10.37 Gbit/s | before: 8.43 / 8.70 Gbit/s (+17 % / +19 %); [Engine fast path (MF-1)](#engine-fast-path-mf-1) |
| Engine fast path (MF-1), TUN, kernel WireGuard -> nsplane-cli | the same | 4.85 / 4.77 Gbit/s; dedicated rerun 5.87 / 5.92 | before: 6.27 / 6.07; rerun 6.32 / 6.12 Gbit/s (-23 % / -21 %; rerun -7 % / -3 %), not reproduced outside the harness |
| Engine fast path (MF-1), worker pool hub | off / 2 / 4 workers, 64 B and 1420 B, median of 3 quiet pairs | 1.36 / 1.40 / 1.41 Mpps, 784 / 959 / 937 kpps | before: 1.40 / 1.38 / 1.41 Mpps, 788 / 938 / 960 kpps (all within -3 % to +2 %) |
| Engine fast path (MF-1), engine latency, loaded, no workers | p50 / p99 / lost pings, 3 pairs | 2.25 / 13.5 ms / 76, 2.09 / 4.89 ms / 31, 2.17 / 4.38 ms / 24 | before: 2.29 / 10.6 ms / 17, 2.42 / 16.7 ms / 25, 2.37 / 11.6 ms / 20 |
| Engine and device fast path (OE), TUN, nsplane-cli -> nsplane-cli | iperf3 TCP P1 / P4 Gbit/s, sender CPU s/GB; default / 2 workers / no offload (2026-10-05, load 2.2-6.4) | 10.33 / 11.38, 0.94; 11.67 / 12.65, 1.07; 3.45 / 3.51, 2.97 | main 20d728c same window: 9.60 / 10.39, 1.24; 8.39 / 8.58, 1.23; 3.10 / 3.35, 3.61; [Engine and device fast path (OE)](#engine-and-device-fast-path-oe) |
| Netstack TCP stream (PS) | 1 GiB, one connection, over two engines / direct, median of 5, per GiB (2026-10-03, load 20-29) | 309 MB/s, 9.34 s CPU, 38.49 G instructions / 1162 MB/s, 7.54 G instructions | `main`: 306 MB/s, 10.08 s, 39.41 G / 1002 MB/s, 7.72 G; [Single-stream profile (MF-2)](#single-stream-profile-mf-2) |
| Local-side graph, `pipe` | send + `recv_batch`, 64 B / 1420 B, per packet (1024 packets per iteration, current-thread runtime; 2026-10-03, load 9.99 21.78 29.87; at load 59: ~132 / ~151 ns) | ~68 ns / ~68 ns | |
| Local-side graph, `pump` | pipe -> pipe, 64 B / 1420 B, per packet (two spawned tasks, allocation excluded; same run; at load 59: ~263 / ~369 ns) | ~146 ns / ~170 ns | |

- Data path. Follow-up #1 (5C) removed the rx buffer swap, the `copy_within` shifts and the
  `set_len` zero-fills, leaving ~695 instructions of dispatch per 64 B round trip. The
  batched entry points (`Core::handle_datagrams`, `Core::handle_locals`) share that dispatch
  across a batch: at 32 packets per call the core is 11.8 % (64 B) and 2.7 % (1420 B) below
  the device-equivalent baseline by instruction count, and 12.5-13.0 % and 4.0-5.2 % below it
  in wall clock, so the 10 % target is met at 64 B for batched input. One packet per call
  still costs +12 % (64 B) and +4-5 % (1420 B) over the baseline; the empty lookup cache adds
  10 instructions to it. The engine feeds the core in batches of what is already queued, so
  a lone packet takes the single-packet cost and a busy one approaches the batched cost.
- No lock without workers (#17). The core round trip measures 532 ns at 64 B (device-equivalent
  474 ns, raw 359 ns) and 1.348 us at 1420 B (device-equivalent 1.282 us), against 546 ns and
  1.354 us on main 64131c7: removing the per-peer tunnel lock from the pool-off path is a
  small gain within the run-to-run spread, and the worker pool no longer costs it to
  embedders that do not use the pool.
- ACL hook. An established flow costs about the same as the default policy's three rules,
  and a bypass peer less than either: the floor every packet pays is parsing its five-tuple
  and loading the engine snapshot (5C-T3: 6-7.5 ns + 9.5-11.5 ns = 16-19 ns), and the rest is
  the flow-table lookup under its lock. Skipping the reply check would be exact only for
  unidirectional traffic, so it stays. Exactness was not weakened: a differential test
  checks verdicts and counters against a full evaluation of every packet. See
  [nsplane-acl](#nsplane-acl).
- Node L3 gate (`cargo bench -p nsplane-acl --bench node_l3`, 2026-10-04, load 23-32,
  two runs interleaved with the previous code). Established flow: 129 / 134 ns through
  `NodeL3Filter` (was 214 / 429), 90 / 103 ns through `NodeL3Gate::evaluate_inbound` (was
  229 / 350; 69-73 ns at load 13); new flow 172 / 110 ns (Node Grant), 235 / 121 ns (Service
  Grant), about half to a sixth of before; baseline `AclFilter` alone 50 / 34 ns (the
  namespaces bench's established cases ran at 82 / 52 ns namespaces, 71 / 56 ns default in
  the same run); a gate without snapshot in front of the ACL 57 / 50 ns, alone 2.3 ns;
  writer contention (a new generation every 1 / 10 ms) 87 / 88 ns and 90 / 92 ns. Keyed
  multiply hashing instead of `SipHash`, one flow lookup, no clock read before the state,
  and an inert flag checked before anything else made the difference. Not installed, the
  gate costs nothing (no filter on the chain). Accepted 2026-10-04 as within the ACL hook's
  class (gate 64-73 ns quiet / 90-103 ns at load 23-32, `NodeL3Filter` 86-90 / 129-134 ns,
  inert gate 2.3 ns, writer contention 87-92 ns); the remaining gap to ~60 ns is mostly the
  per-packet clock read (~18 ns, `__vdso_clock_gettime` 46 % of `perf` samples), plus the
  `ArcSwap` snapshot load (~9 ns) and the shard mutex (~8 ns). Possible follow-up, not
  done: a per-batch or cached timestamp (millisecond expiry granularity against timeouts of
  30 s and more, unlike ns's per-packet `Instant::now`; needs an owner decision); see
  [Node L3 gate](#node-l3-gate).
- Worker pool. The batched input and the lock-free pool-off path make every case about
  15-25 % faster than before the follow-ups (1420 B with 2 workers within the noise). The
  pool moves full-size packets up to about 1.4x further, small packets little; 4 workers do
  not add much to 2, as the owner task stays the limit.
- Netstack. Without loss the stack is not the limit (same-build spread 320-460 MB/s TCP,
  470-900 MB/s UDP). At 3 % random loss smoltcp's timeout-bound recovery lands right at the
  test's 60 s limit (5C-T6 finished in 54-59 s); the 1 % case and the bottleneck complete.
  On one 1 GiB stream the netstack is about 18 % of the engine pairing's instructions
  (crypto 36 %); the PS fixes take 2.2-2.3 % of the instructions and 7-8 % of the CPU time
  off it, and the rest of the stack's cost is smoltcp (see *Known remaining costs* under
  [Netstack throughput](#netstack-throughput)). The gap to ns's legacy stack (MF-2) is to
  be re-measured with PB's netstack pair. With smoltcp `.4` (ON) the 1 % loss and
  bottleneck cases finish in about a second, 3 % loss in 11-41 s (lost retransmissions
  still wait for a timeout), and the harness's netstack pair moves four streams faster
  than one (7.29 against 6.85 Gbit/s; `main` 2.48 against 6.21).

### Engine batching under load

Follow-up #1's engine side feeds the core what is already queued, in batches of up to
`MAX_BATCH`, with no wait and no timer, and reads local packets only up to the transmit
room (see *Backpressure* under [nsplane (driver)](#nsplane-driver)). Measured with
`crates/nsplane-e2e/tests/latency.rs` (`round_trip_latency`, `round_trip_latency_queue_256`):
two engines over UDP loopback with the builder defaults, 2000 one-packet pings, idle and
next to a saturating bulk flow between the same engines; "before" is the same branch
without the engine batching, two runs each, 1-minute load 2.8-5.9.

| Case | p50 / p99 / lost pings, after | before |
| --- | --- | --- |
| Idle, no workers | 11.3 / 36.0 us, 11.2 / 40.3 us | 20.9 / 41.0 us, 11.0 / 23.7 us |
| Loaded, no workers | 2.15 / 4.69 ms / 13, 2.13 / 5.16 ms / 18 | 2.71 / 6.91 ms / 2, 2.36 / 4.74 ms / 1 |
| Loaded, no workers, `queue_capacity` 256 | 1.75 / 12.0 ms / 100, 1.59 / 3.89 ms / 93 | 1.51 / 3.85 ms / 0, 1.52 / 3.81 ms / 0 |
| Loaded, 2 workers (for information) | 7.40 / 21.7 ms / 286, 7.25 / 11.8 ms / 387 | 3.53 / 9.96 ms / 316, 3.36 / 9.59 ms / 267 |

- Idle latency is unchanged within the run-to-run spread: a lone packet goes through at
  once. Under load, p50 is lower in both runs and the worst p99 is lower (5.16 against
  6.91 ms) than before, and the
  sender's backlog stays at 64 (`MAX_BATCH`) because local intake follows the transmit room.
  A first attempt that read local packets without that bound filled the sender's transmit
  queue and backlog to 1024 each, and its loaded p99 rose to 7.8-19 ms.
- The extra loss under a saturating flow happens only at the receiver's full sink. A
  diagnostic run moved 1093 packets per ms of bulk traffic after the change against 919
  before (about 19 % more), and the receiver dropped 486 251 packets under `DROP_SINK_FULL`
  against 717 before; the sender dropped nothing. Batching raises the tunnel's throughput
  until it outruns the receiving application. High-water marks, loaded without workers:
  after, sender `local` 1024, `transmit` 1024, `backlog` 64, receiver `datagrams` 1024,
  `deliver` 1024; before, sender `transmit` 284-640, `backlog` 0, receiver `deliver`
  363-372. The lost pings are these sink drops, which a smaller `queue_capacity` makes more
  frequent.
- A sink slower than the tunnel must therefore size `queue_capacity` for its bursts or apply
  its own flow control (e.g. TCP through the netstack); the engine does not pace the sender
  to the receiver's sink. Sender pacing and receiver-side backpressure are an open design
  item (`docs/task/20261002-1509-phase1-followups.md` item 21).
- With 2 workers the loaded latency is higher in both builds, as the jobs in flight sit at
  their bound (`QueueStats::crypto` at `queue_capacity`) with the queueing delay that adds;
  these rows are for information only.

### Against WireGuard implementations

Latest run, the OE branch (bkd/smvobr6t, the final A/B of
[Engine and device fast path (OE)](#engine-and-device-fast-path-oe)), 2026-10-05
15:51-16:57Z, 1-minute load 2.2-5.9, same harness, CPU sets 2-5 / 6-9, 30 s x 3
repetitions, medians; kernel-kernel and the netstack pair were not part of this run. The
last column is main 20d728c in the adjacent half (17:28-18:34Z, load 2.2-6.4):

| Pair (a -> b) | TCP P1 Gbit/s | TCP P4 Gbit/s | UDP loss 1G / 3G % | ping p50 / p99 idle ms | ping p50 / p99 loaded ms | CPU s/GB a / b | main 20d728c: P1 / P4, CPU a / b |
| --- | --- | --- | --- | --- | --- | --- | --- |
| nsplane-nsplane | 10.33 | 11.38 | 0.06 / 0.10 | 0.686 / 1.390 | 2.470 / 5.220 | 0.94 / 0.89 | 9.60 / 10.39, 1.24 / 0.91 |
| nsplane-nsplane (w2) | 11.67 | 12.65 | 0.09 / 0.26 | 0.882 / 1.770 | 2.160 / 4.690 | 1.07 / 1.09 | 8.39 / 8.58, 1.23 / 1.10 |
| nsplane-nsplane (w4) | 11.61 | 12.49 | 0.08 / 0.25 | 0.652 / 1.090 | 2.290 / 4.770 | 1.08 / 1.12 | 8.42 / 8.60, 1.23 / 1.08 |
| nsplane-nsplane (nooffload) | 3.45 | 3.51 | 0.01 / 0.06 | 0.544 / 1.010 | 1.030 / 2.430 | 2.97 / 2.80 | 3.10 / 3.35, 3.61 / 3.08 |
| nsplane-nsplane (nooffload-w2) | 4.53 | 4.98 | 0.05 / 0.21 | 0.627 / 0.826 | 1.140 / 2.520 | 3.17 / 3.05 | 3.65 / 4.17, 3.64 / 3.49 |
| nsplane-kernel | 7.85 | 7.52 | 0.03 / 0.06 | 0.695 / 1.660 | 3.320 / 5.050 | 1.92 / 0.31 † | 7.44 / 7.23, 2.13 / 0.32 † |
| kernel-nsplane | 7.08 | 7.02 | 0.02 / 0.04 | 0.759 / 1.640 | 1.910 / 4.940 | 0.07 † / 1.65 | 6.97 / 6.80, 0.10 † / 1.70 |
| wggo-wggo | 8.50 | 10.50 | 0.09 / 0.83 | 0.604 / 0.815 | 2.400 / 6.090 | 1.32 / 1.67 | 8.41 / 9.82, 1.36 / 1.71 (same binary) |

† kernel WireGuard encrypts in kernel threads outside the container cgroup (undercount).
nsplane-cli now leads wireguard-go on this host at one stream with any configuration that
has offload (10.33-11.67 against 8.50) and, with 2 or 4 crypto workers, also at four
streams (12.49-12.65 against 10.50), at lower CPU per GB on the receiver (0.89-1.12 against
1.67) and a lower loaded p99 (4.69-5.22 against 6.09 ms). wireguard-go's own runs spread
8.41-9.66 (P1) over the four halves of that A/B.

The run before, main `92652cb` (after the engine fast path, the netstack fixes and the
`ChannelTransport` fix), 2026-10-04, a quiet host (1-minute load 2-11), same harness, CPU
sets 2-5 / 6-9, 30 s x 3 repetitions, medians:

| Pair (a -> b) | TCP P1 Gbit/s | TCP P4 Gbit/s | UDP loss 1G / 3G % | ping p50 / p99 idle ms | ping p50 / p99 loaded ms | CPU s/GB a / b |
| --- | --- | --- | --- | --- | --- | --- |
| kernel-kernel | 4.04 | 4.10 | 0.01 / 0.03 | 0.780 / 1.690 | 1.300 / 1.590 | 0.09 † / 0.82 † |
| nsplane-nsplane | 8.12 | 8.93 | 0.04 / 0.44 | 0.241 / 0.728 | 3.010 / 8.270 | 1.26 / 1.10 |
| nsplane-nsplane (w2) | 8.52 | 8.71 | 0.00 / 0.01 | 0.737 / 0.810 | 1.230 / 2.560 | 1.22 / 1.07 |
| nsplane-nsplane (nooffload) | 3.13 | 3.41 | 0.00 / 0.05 | 0.561 / 0.603 | 1.300 / 2.640 | 3.63 / 3.08 |
| nsplane-nsplane (nooffload-w2) | 3.71 | 4.28 | 0.00 / 0.12 | 0.708 / 0.789 | 1.210 / 2.650 | 3.60 / 3.41 |
| nsplane-kernel | 7.71 | 7.57 | 0.00 / 0.01 | 0.750 / 1.580 | 3.360 / 5.720 | 2.14 / 0.31 † |
| kernel-nsplane | 7.00 | 6.92 | 0.00 / 0.02 | 0.804 / 1.760 | 1.950 / 5.430 | 0.09 † / 1.67 |
| wggo-wggo | 9.99 | 10.14 | 0.02 / 0.41 | 0.690 / 0.779 | 2.300 / 5.980 | 1.29 / 1.44 |
| netstack (user-space) | 6.21 | 2.02 | 1.93 / 6.20 | 0.027 / 0.041 | 0.137 / 0.916 | 1.90 / 1.56 |
| netstack (user-space), ON branch ‡ | 6.85 | 7.29 | 0.00 / 0.03 | 0.027 / 0.052 | 0.280 / 1.271 | 1.70 / 1.41 |

† kernel WireGuard encrypts in kernel threads outside the container cgroup (undercount).
‡ A separate run, 2026-10-05 (load 2.2-3.5), with smoltcp `v0.14.0-nsplane.4` and
`netstack_bench`'s 1024-datagram server queue; `main` b5e531f in the same window measured
6.21 / 2.48 Gbit/s and 2.21 / 5.56 % (see [Netstack throughput](#netstack-throughput)).
Repetitions were tight for the mixed pairs (kernel -> nsplane 7.02 / 7.00 / 6.99, nsplane ->
kernel 7.72 / 7.70 / 7.71) and wider for nsplane-nsplane (7.85 / 8.12 / 9.33) and
wireguard-go (7.75 / 9.99 / 10.79). Kernel WireGuard -> nsplane-cli, left open after the MF-1
A/B, measures 7.00 Gbit/s here against 3.67 in the first (loaded) run and 6.3 in the MF-1
"before" reruns: no regression on a quiet host, so the open item is closed. What stays:
wireguard-go leads on 4 streams (10.1 against 8.9), kernel WireGuard is CPU-pinned by the
harness (its crypto threads do not run on the pinned sets). The netstack pair's 4-stream
result, below its single stream here, is above it with the ON changes (‡).

The earlier, loaded run below is kept for its notes.


`scripts/bench/wg-compare.sh` (see `scripts/bench/README.md`) runs every pair in two fresh
containers on one docker network: side a (sender) pinned to CPUs 2-5, side b (receiver) to
6-9, real TUN devices, MTU 1420, every implementation configured over the UAPI with `wg`
and `ip`. Measured 2026-10-03 at f42b01e (main 3cc35ac plus the additive
nsplane-cli flags `--crypto-workers` and `--no-offload`; nsplane code otherwise identical),
image `ai-agent/nsplane-bench` (debian trixie-slim, iperf 3.18), wireguard-go 0.0.20250522
(f333402), host AMD Ryzen AI MAX+ 395 with 32 CPUs shared with other jobs, kernel
7.1.8+deb13-amd64. 30 s per run, 3 repetitions, medians. The 1-minute load was 20.5 at the
start, 30 after `kernel-nsplane` and about 33 sampled during it, so these are loaded-host
numbers.

```text
just bench-wg
BENCH_PAIRS=nsplane-nsplane BENCH_NSPLANE_VARIANTS='default;w2:WG_CRYPTO_WORKERS=2' \
  NSPLANE_CLI_BIN=../other-worktree/target/release/nsplane-cli scripts/bench/wg-compare.sh
```

Knobs: `BENCH_PAIRS`, `BENCH_DURATION`, `BENCH_REPS`, `BENCH_UDP_RATES`, `BENCH_CPUS_A`/`_B`,
`BENCH_NSPLANE_VARIANTS`; `NSPLANE_CLI_BIN` measures a binary built on another branch.

| Pair (a -> b) | TCP P1 Gbit/s | TCP P4 Gbit/s | UDP rate: loss % | ping p50 / p99 idle ms | ping p50 / p99 loaded ms | CPU s/GB a | CPU s/GB b | 1-min load before / after |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| kernel-kernel | 3.68 | 3.69 | 1G: 0.77, 3G: 3.50 | 0.434 / 4.190 | 2.070 / 4.220 | 0.12 † | 0.93 † | 20.47 / 18.63 |
| nsplane-nsplane | 6.65 | 6.36 | 1G: 0.14, 3G: 2.14 | 0.383 / 2.780 | 1.680 / 5.700 | 1.33 | 1.34 | 18.63 / 21.90 |
| nsplane-nsplane (w2) | 4.14 | 6.06 | 1G: 1.88, 3G: 1.46 | 0.228 / 1.830 | 1.280 / 3.620 | 1.96 | 1.96 | 21.42 / 7.78 |
| nsplane-nsplane (nooffload) | 2.03 | 3.01 | 1G: 2.71, 3G: 28.37 | 0.254 / 1.760 | 1.910 / 7.030 | 4.78 | 4.82 | 10.04 / 16.68 |
| nsplane-nsplane (nooffload-w2) | 2.87 | 3.39 | 1G: 0.25, 3G: 5.07 | 0.532 / 2.370 | 1.400 / 3.790 | 3.87 | 4.32 | 18.47 / 9.69 |
| nsplane-kernel | 5.30 | 4.23 | 1G: 4.04, 3G: 4.66 | 0.260 / 4.050 | 3.770 / 7.670 | 2.81 | 0.36 † | 9.69 / 21.38 |
| kernel-nsplane | 3.67 | 3.13 | 1G: 2.76, 3G: 9.39 | 0.324 / 3.120 | 2.770 / 8.390 | 0.18 † | 2.66 | 21.38 / 30.04 |
| wggo-wggo | 6.14 | 8.51 | 1G: 0.57, 3G: 42.51 | 0.361 / 3.100 | 3.870 / 8.140 | 1.58 | 2.17 | 29.64 / 11.36 |
| netstack (user-space) | 3.06 | 1.61 | 1G: 0.25, 3G: 1.96 | 0.030 / 0.050 | 0.137 / 1.080 | 3.21 | 2.58 | 11.36 / 10.75 |

Variants: `w2` = 2 crypto workers, `nooffload` = no TUN offload and no UDP GSO/GRO, on both
sides; the mixed pairs run the default configuration. Throughput is the receiver-side sum;
the loaded ping runs next to one saturating TCP stream; CPU s/GB is the container's cgroup
CPU over the TCP P1 run divided by the GB received, iperf3's own CPU included.

- Caveats. The host is shared and the 1-minute load moved between 7.8 and about 33 during
  the run; the repetitions spread widely (e.g. nsplane-nsplane default TCP P1 6.46 / 8.86 / 6.65,
  netstack 2.26 / 3.06 / 5.74), so only large differences are meaningful. † Kernel
  WireGuard encrypts in kernel workqueue threads outside the container cgroup, so its CPU
  per GB is an undercount. The `netstack` pair runs `netstack_bench` (engine, netstack and
  load generator in one process per side, no TUN) instead of iperf3 and ping; its latency
  columns are 1-byte TCP request/response round trips. nsplane-cli sides keep their
  startup UDP port (a `listen-port` set over the UAPI now keeps `WG_NO_OFFLOAD`; when these
  rows were measured it rebound with offload on).
- Offload carries nsplane-cli's single-stream throughput: the default is 3.3x `nooffload`
  at P1 (6.65 against 2.03 Gbit/s) at a quarter of the CPU per GB (1.33 against 4.78 s).
  2 crypto workers lower P1 (4.14) and cost more CPU per GB (1.96), with P4 about the same
  as the default.
- Against the other implementations on this host and run: nsplane-nsplane default is above
  kernel-kernel (3.68) and wireguard-go (6.14) at P1, below wireguard-go at P4 (6.36 against
  8.51), and loses less UDP at 3G (2.14 % against 3.50 % and 42.51 %).
- netstack: TCP P4 is below P1 in all three repetitions (1.55-2.50 against 2.26-5.74
  Gbit/s), and also in a 5 s smoke run at a 1-minute load of 7 (1.08 against 1.83).
- ns T10b (MF-1, MF-2 in `docs/task/20261003-1500-ns-dataplane-moves.md`) measured
  single-stream TCP over TUN with a different harness and host, unloaded: engine 4044
  against legacy tunnel-wg 4748 Mbit/s, and nsplane-netstack 4356 against legacy smoltcp
  4897 Mbit/s. Here nsplane-nsplane default TCP P1 is 6.65 Gbit/s and netstack 3.06
  Gbit/s; the setups differ, so these are not a like-for-like comparison.

### Engine fast path (MF-1)

The engine fast path without crypto workers (batched input handoff, inline output with
the waiting-input rule for sends and the backoff, see [nsplane (driver)](#nsplane-driver))
was measured A/B on 2026-10-04 (campaign `nsplane-pf-202610031630`, PF3 round 2): A is
main at 7196ab9, B the same plus the fast path, both release builds in the dev image;
32-thread Ryzen AI MAX+ 395, shared with other jobs. Every half of a pair (A, then B)
started at a 1-minute load below 8; load1 was sampled every 10 s, and a pair was kept when
the highest load of both halves was at most 25 and the two differed by at most 10. The
first round of the fast path, which also sent inline while input was waiting, cost
nsplane-cli -> kernel WireGuard 31-37 % (the owner ran the GSO `sendmsg` itself and
saturated); hence the waiting-input rule.

Throughput with `scripts/bench/wg-compare.sh` (the harness on main; real TUN with offload,
`UdpTransport` with GSO/GRO, MTU 1420, nsplane-cli builder defaults): side a (sender) on
CPUs 10-13, side b (receiver) on CPUs 14-17, 20 s per iperf3 run, one repetition per half;
`default` has no crypto workers, `w2` 2 workers. Five pairs were kept (pair 3 was
interrupted); pairs 4-6 are the quiet ones. -P1 / -P4 Gbit/s, receiver-side sum:

| Pair (a -> b) | A, 5 pairs | B, 5 pairs | A, pairs 4-6 | B, pairs 4-6 | B vs A, pairs 4-6 |
| --- | --- | --- | --- | --- | --- |
| nsplane-cli -> nsplane-cli, `default` | 8.38 / 7.31 | 9.82 / 10.25 | 8.43 / 8.70 | 9.90 / 10.37 | +17 % / +19 % |
| nsplane-cli -> nsplane-cli, `w2` | 7.32 / 8.02 | 8.08 / 7.43 | 8.26 / 8.35 | 8.30 / 8.08 | +0.5 % / -3 % |
| nsplane-cli -> kernel WireGuard | 6.87 / 6.45 | 6.63 / 6.33 | 6.88 / 6.74 | 6.83 / 6.40 | -1 % / -5 % |
| kernel WireGuard -> nsplane-cli | 3.94 / 5.54 | 5.22 / 4.79 | 6.27 / 6.07 | 4.85 / 4.77 | -23 % / -21 % |

Per pair, -P1 Gbit/s A / B and the highest 1-minute load of the A / B half:

| Pair | `default` | `w2` | nsplane -> kernel | kernel -> nsplane | max load A / B |
| --- | --- | --- | --- | --- | --- |
| 1 | 5.37 / 5.06 | 5.83 / 5.69 | 5.35 / 6.30 | 3.85 / 5.22 | 23.9 / 23.3 |
| 2 | 7.05 / 7.65 | 5.60 / 5.98 | 6.11 / 4.16 | 2.97 / 5.66 | 15.6 / 20.8 |
| 4 | 8.43 / 9.82 | 8.26 / 8.30 | 6.87 / 6.83 | 6.79 / 5.30 | 12.3 / 8.6 |
| 5 | 9.04 / 9.90 | 8.37 / 8.08 | 6.89 / 6.63 | 6.27 / 4.85 | 6.5 / 7.3 |
| 6 | 8.38 / 9.95 | 7.32 / 8.39 | 6.88 / 6.83 | 3.94 / 4.79 | 7.9 / 11.2 |

CPU seconds per GB (cgroup, iperf3 included), `default`, median of pairs 4-6, sender /
receiver: 1.24 / 0.98 before, 1.27 / 0.88 after (receiver -10 %).

kernel WireGuard -> nsplane-cli was slower in B in all three quiet pairs. A dedicated rerun
of that pair alone (3 pairs, load 2.9-5.9) gave A 6.32 / 6.28 / 6.32 and B 3.74 / 5.87 /
5.90 Gbit/s -P1 (-P4 6.15 / 6.12 / 6.08 against 5.18 / 5.92 / 6.15): A was steady, B about
7 % lower with one slow run. Outside the harness it did not reproduce: the same pair in
the profiling containers (frame-pointer build, 25 s, nsplane-cli keeping its startup port
as in the harness, or with `listen-port` set) gave B 6.04 / 6.15 and A 5.82 / 5.67 Gbit/s
(startup port), B 6.93 / 6.90 / 6.84 and A 7.06 / 6.91 / 7.07 / 6.22 Gbit/s (`listen-port`).
In the profile the receiver is not saturated in either build (1.07 / 1.13 cores; the
receive task with GRO is 31-32 %, crypto 30-32 %, the owner 8 % plus the sink task 12 %
before, 20 % with inline delivery after). The cause of the harness gap is open.

Where the time goes on nsplane-cli -> nsplane-cli `default`: a 15 s `perf record` (frame
pointers, 1999 Hz) and `pidstat -t` of both sides, same CPU sets, load 2.4-5.0, A 8.93 and
B 9.78 / 9.67 Gbit/s. Shares of each process's samples; the crypto assembly loses its
callers (it runs in the owner task):

| | sender A | sender B | receiver A | receiver B |
| --- | --- | --- | --- | --- |
| nsplane-cli CPU (cores of 4) | 1.32 | 1.48 | 1.05 | 1.02 |
| crypto (seal / open) | 38.7 % | 39.0 % | 47.2 % | 50.8 % |
| owner task, without crypto | 10.5 % | 11.8 % | 12.2 % | 26.7 % |
| of which inline delivery (TUN coalescing and write) | - | - | - | 16.8 % |
| transmit task (UDP `sendmsg` with GSO) | 16.0 % | 18.1 % (10.3 % syscalls) | 3.4 % | 0.7 % |
| source task (TUN read, TSO split) | 12.3 % (6.6 % split) | 10.6 % (7.0 % split) | 0.9 % | 0.8 % |
| receive task (`recvmmsg` with GRO) | 0.9 % | 0.3 % | 12.9 % | 14.7 % |
| sink task (TUN write) | 3.2 % | 0 | 16.8 % | 0 |
| handoffs (mpsc, semaphore, wake, futex) | 12.4 % | 10.3 % | 4.9 % | 1.0 % |
| malloc / free | 6.4 % | 7.3 % | 3.6 % | 5.4 % |

Engine latency, `cargo test --release -p nsplane-e2e --test latency -- --ignored --nocapture
--exact <test>`, each test alone, CPUs 20-27, three kept pairs each; p50 / p99 / lost pings
of 2000 and the receiver's `DROP_SINK_FULL` count. `round_trip_latency` pairs had a highest
load of 16.5 / 12.2, 14.1 / 22.3 and 11.1 / 7.1; `round_trip_latency_queue_256` pairs 13.0 /
15.5, 4.0 / 4.0 and 3.4 / 3.1 (one more pair, 8.5 / 21.1, was discarded):

| Case | A (before) | B (after) |
| --- | --- | --- |
| Idle, no workers | 11.1 / 27.3, 17.9 / 31.5, 18.6 / 28.1 us | 18.1 / 28.8, 16.7 / 37.3, 21.9 / 28.9 us |
| Loaded, no workers | 2.29 / 10.6 ms / 17, 2.42 / 16.7 ms / 25, 2.37 / 11.6 ms / 20 | 2.25 / 13.5 ms / 76, 2.09 / 4.89 ms / 31, 2.17 / 4.38 ms / 24 |
| sink-full drops | 345 273, 691 647, 442 851 | 6 900 418, 364 006, 270 626 |
| Idle, no workers, `queue_capacity` 256 | 16.8 / 40.5, 17.9 / 28.4, 17.3 / 31.2 us | 34.1 / 51.3, 15.4 / 22.5, 11.3 / 30.5 us |
| Loaded, no workers, `queue_capacity` 256 | 1.79 / 10.4 ms / 88, 1.64 / 9.09 ms / 104, 1.48 / 3.09 ms / 56 | 1.70 / 5.01 ms / 103, 1.42 / 2.47 ms / 62, 1.42 / 1.74 ms / 74 |
| sink-full drops | 3 308 003, 4 398 958, 1 465 383 | 11 518 579, 893 414, 1 400 144 |
| Idle, 2 workers | 13.9 / 15.9, 24.6 / 44.7, 20.4 / 39.4 us | 14.2 / 28.9, 13.9 / 16.0, 21.7 / 37.2 us |
| Loaded, 2 workers | 8.17 / 32.5 ms / 332, 7.62 / 23.8 ms / 288, 8.05 / 25.8 ms / 327 | 8.31 / 32.3 ms / 233, 8.81 / 35.4 ms / 298, 7.42 / 19.0 ms / 346 |

Lost pings are higher in B only in the loaded first pair of each test (76 against 17;
103 against 88); in the quiet pairs they are within each other's spread, and the loaded
p99 is lower in B. The lost pings are the receiver's `DROP_SINK_FULL` at the test's channel
sink, as in [Engine batching under load](#engine-batching-under-load).

Worker pool hub, `cargo bench -p nsplane --bench worker_pool` (8-peer hub on in-memory
`ChannelTransport` links, which keep the default `try_send_batch`), CPUs 20-27; criterion
means as packets per second, median of the three quiet pairs (highest load 5.2-5.8):

| Packet | Pool off, A / B | 2 workers, A / B | 4 workers, A / B |
| --- | --- | --- | --- |
| 64 B | 1.40 / 1.36 Mpps (-3 %) | 1.38 / 1.40 Mpps (+1 %) | 1.41 / 1.41 Mpps (0 %) |
| 1420 B | 788 / 784 kpps (-0.5 %) | 938 / 959 kpps (+2 %) | 960 / 937 kpps (-2 %) |

A's own run-to-run spread is up to 7 %, so every case is within noise. Three earlier pairs
at loads up to 16 had B's pool-off 64 B at 2.53-4.77 ms per iteration (A 1.69-2.13 ms); the
quiet pairs do not repeat it.

`cargo bench -p nsplane-core --bench data_path` (the core and its bench binary are the
same in A and B): core round trip 64 B 529.1 / 527.6 ns, 1420 B 1.345 / 1.346 us; batched
32 per call 413.8 / 413.0 ns and 1.231 / 1.220 us per packet (A / B). No regression.

Verdict against the target of +18 % single-stream nsplane-cli <-> nsplane-cli without
workers: just short. The quiet pairs give +17 % at -P1 (8.43 -> 9.90 Gbit/s) and +19 % at
-P4, at 10 % less receiver CPU per GB; with crypto workers and towards kernel WireGuard
nothing changes beyond noise; the worker pool hub and the core are unchanged. Open:
kernel WireGuard -> nsplane-cli is 7-23 % slower in B in the harness but not in the
profiling containers.

What is left: on nsplane-cli -> nsplane-cli the receiver's owner task is the busy side,
about 0.8 core in one task: opening (51 %) plus the inline delivery it now does itself
(17 %: coalescing TSO chunks and the TUN write). Gating inline delivery on waiting input
too, so that the sink task delivers under load, made the pair 25 % slower than before in
PF2's experiments, so the next step there is cheaper
delivery (TUN write coalescing) or parallel opening that keeps per-peer order. The sender
spreads over 1.5 cores: sealing 39 %, the transmit task 18 % (GSO `sendmsg` 10 %), the TSO
split copy 7 % (`VnetReader::segment`), allocation 7 % and handoffs 10 % (mostly the
transmit task's queue and futex wakes). The cryptography itself (39-51 %) is the floor.
See also `docs/task/20261003-1500-ns-dataplane-moves.md`, MF-1.

### Engine and device fast path (OE)

Workstream OE (campaign `nsplane-op-202610041900`, 2026-10-04/05) took the five targets of a
quiet re-baseline of main b5e531f and a profile of each, and changed the engine, the UDP
transport, the TUN device and the cryptography's split between the owner and the workers.
Defaults are unchanged except where a change is a pure speedup.

Method. Throughput with `scripts/bench/wg-compare.sh` (CPU sets 2-5 / 6-9, MTU 1420, 30 s x 3
repetitions, medians; release nsplane-cli built in the dev image); A/B halves alternate, each
half is one acquisition of the host's bench lock, starts at a 1-minute load below 8 and is
kept when its load stays at or below 12. Micro benches with criterion, one bench per lock
acquisition. The profile: `perf record` from a privileged sibling container on each side
(`--pid=container:<side>`, cycles and `instructions:u`, 1999 Hz, 15 s) of a frame-pointer
build, plus `pidstat -t`, 2026-10-04 21:55-22:04Z (load 0.9-11).

Targets and the re-baseline (main b5e531f, 2026-10-04 19:18-20:17Z, load1 2.7-6.6):

| Target | Re-baseline | What limited it (profile) |
| --- | --- | --- |
| T1 crypto workers | w2 P1 / P4 8.01 / 7.09 Gbit/s, UDP 3G loss 4.03 % | one peer = one worker; the receiver dropped at its own deliver queue (`DROP_SINK_FULL` 2 610 in a P1 run = iperf3's 2 632 retransmits) |
| T2 no offload | 2.59 / 2.96 Gbit/s, 3.76 / 3.63 s/GB | one system call per packet on each of TUN read, UDP send, UDP receive, TUN write (syscalls 56-66 %) |
| T3 mixed directions | nsplane -> kernel 7.65, kernel -> nsplane 5.80 Gbit/s | kernel WireGuard's receiver; on our receiver ~0.8 datagram per `recvmmsg` |
| T4 loaded latency | ping p50 / p99 2.84 / 5.40 ms (wireguard-go 2.56 / 6.09) | queue depth: sender `local` ~830 + `transmit` 1024, receiver `datagrams` ~360 |
| T5 default P4, CPU per GB | 9.91 / 9.87 Gbit/s, 1.21 / 0.84 s/GB | both owner tasks 82-85 % busy at ~0.95 us per packet, crypto 35 % / 49 % |

Where the cycles went (share of the nsplane-cli process; T5 default pair, T4 loaded ping
next to one stream, T1 2 workers):

| Case / side | crypto | owner: core w/o crypto | owner: inline delivery | owner: inline send | owner: other | transmit task | source: TSO split | source: other | receive task | sink task | workers w/o crypto | handoffs | malloc / free | libc unresolved (memcpy etc.) | other | syscalls |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T5 P1 sender | 35.1 | 5.9 | 1.7 | 0.0 | 3.9 | 11.9 | 5.4 | 4.0 | 0.2 | 0 | 0 | 15.6 | 8.3 | 6.9 | 1.1 | 22.4 |
| T5 P1 receiver | 49.4 | 6.8 | 16.8 | 0.6 | 1.6 | 0.6 | 0 | 0.8 | 15.4 | 0 | 0 | 5.0 | 0.8 | 0.6 | 1.6 | 26.6 |
| T5 P4 sender | 32.8 | 5.5 | 3.1 | 0.0 | 3.6 | 11.2 | 5.0 | 4.7 | 0.3 | 0 | 0 | 17.6 | 8.2 | 7.1 | 0.8 | 26.1 |
| T5 P4 receiver | 50.4 | 7.1 | 17.6 | 0.7 | 1.6 | 0.7 | 0 | 1.1 | 11.9 | 0 | 0 | 6.6 | 0.7 | 0.6 | 0.9 | 24.8 |
| T4 loaded sender | 35.4 | 6.4 | 1.7 | 0.0 | 3.8 | 11.6 | 5.6 | 4.1 | 0.2 | 0 | 0 | 14.9 | 8.4 | 6.9 | 1.0 | 21.5 |
| T4 loaded receiver | 49.6 | 7.2 | 18.2 | 0.5 | 1.6 | 0.7 | 0 | 0.9 | 13.3 | 0 | 0 | 5.2 | 0.8 | 0.6 | 1.2 | 25.3 |
| T1 w2 P1 sender | 34.2 | 2.6 | 0 | 0 | 7.8 | 11.4 | 4.8 | 5.1 | 0.9 | 3.1 | 3.3 | 14.7 | 6.2 | 5.3 | 0.7 | 21.4 |
| T1 w2 P1 receiver | 40.6 | 6.5 | 0 | 0 | 6.3 | 2.9 | 0 | 0.8 | 11.3 | 14.3 | 4.5 | 10.4 | 0.6 | 0.7 | 0.9 | 22.3 |
| T1 w2 P4 sender | 33.1 | 2.6 | 0 | 0 | 7.5 | 11.6 | 4.5 | 6.1 | 1.1 | 3.7 | 2.9 | 14.4 | 6.3 | 5.3 | 0.7 | 23.5 |
| T1 w2 P4 receiver | 39.9 | 6.2 | 0 | 0 | 6.1 | 3.2 | 0 | 1.0 | 11.6 | 14.3 | 4.3 | 11.2 | 0.7 | 0.8 | 0.8 | 23.6 |

The "syscalls" column overlaps the task columns (a task's system calls are also in its
share). On the sender, the full-size TSO segments were reallocated when sealed (`realloc`
4.5 %: the source buffer was 3 bytes short of the tail room) and allocated anew (`malloc`
3.3 %), since sent buffers never went back to the source; handoffs were one message per
datagram (369 k futex/s at P1).

The changes:

| Subtask | Change |
| --- | --- |
| OE-1 buffers and TUN | `TAILROOM` in `nsplane-packet` (padding + tag) behind every TUN / slot / Wintun read, so sealing never reallocates; `PacketSource::recycle` (default no-op) and `TunSource`'s pool fed from it; batched plain TUN reads (keep reading until `EAGAIN`); `PacketBuf::extend_from_slice` for the TSO split and pooled buffers that keep their initialized bytes (no zero-fill, no `unsafe`) |
| OE-2 UDP transport | GSO send from the datagram buffers (one iovec each, `nix`), `sendmmsg` / `recvmmsg` without offload, a ring of four GRO storages, `recvmmsg` of up to 16 when no GRO trains arrive |
| OE-3 engine handoffs | one transmit message per drain and transport, sent buffers back to the source one message per batch (C3, C1); with workers, received datagrams with the workers count against the deliver room (C2) |
| OE-4 parallel crypto (C7) | one peer's packets on every worker: counter reserved and replay checked on the owner, the job carries the session key, completion in hand-out order (see [Crypto worker pool](#crypto-worker-pool)); 0 workers unchanged |
| OE-5 | `MapSource` forwards `recycle` to its inner source |

Per change, each A/B against the main of its day (pair kept by the load rule):

- OE-1 (A main b5e531f, pair 2, load1 <= 5.8): default P1 / P4 9.76 / 10.40 -> 9.77 / 11.16
  Gbit/s, sender CPU 1.24 -> 1.08 s/GB; w2 8.42 / 8.63 -> 9.00 / 9.17; nooffload 3.12 / 3.32
  -> 3.49 / 3.87, CPU 3.57 / 3.06 -> 3.24 / 2.80; nsplane -> kernel 7.53 / 7.39 -> 7.66 /
  7.55, CPU 2.23 -> 1.96. TSO split bench -2.8 %, `data_path` within -1.4 to +0.9 %. Its one
  open item, nooffload UDP 3G loss 0.31 -> 0.88 %, is gone in the final A/B (below).
- OE-2 (A main b5e531f): without offload the sender makes about 57 datagrams per `sendmmsg`
  (58x fewer send calls) and the receiver 1.6 per `recvmmsg` (-39 % calls); system calls
  per GB -33 % (sender) / -22 % (receiver); against the re-baseline nooffload 2.59 / 2.96 ->
  3.29 / 3.19 Gbit/s at 3.38 / 2.81 s/GB, nooffload-w2 3.67 / 4.22 -> 4.38 / 4.62.
  `udp_offload` offload off 84.5 -> 51-76 us. kernel -> nsplane par over three kept
  alternating pairs (A 5.50-6.93, B 5.69-5.83 Gbit/s). The adaptive receive holds 16 slots
  of 64 KiB (16 x the caller's buffer without offload) per transport, allocated once on the
  first batched read; the GRO ring at most 4 x 128 KiB. UDP 3G loss, traced with counters
  around a 30 s run: iperf3's lost datagrams equal the sender's `wg0` `tx_dropped` (the
  sender's TUN queue, when its engine reads too slowly) plus the receiver's
  `UdpRcvbufErrors` of the iperf3 socket, exactly, in every run (A and B); the tunnel, the
  engine and both nsplane UDP sockets lose nothing.
- OE-3 (A main b5e531f, B with OE-1 and OE-2, so cumulative; halves at load1 <= 9.5):
  default 9.47 / 10.27 -> 10.46 / 11.49 Gbit/s, sender CPU 1.25 -> 0.95 s/GB, loaded ping
  2.95 / 5.91 -> 2.39 / 5.02 ms; w2 7.81 / 7.82 -> 9.99 / 10.49 (C2: no receiver
  `DROP_SINK_FULL`, so no retransmits); nooffload-w2 2.89 / 3.46 -> 4.54 / 4.86, UDP 3G loss
  3.63 -> 0.22 %; nsplane -> kernel 7.18 -> 7.94, CPU 2.38 -> 1.94. The w2 loaded ping rose
  from 1.2 / 2.6 to 2.7 / 5.4 ms: without the sink-full drops TCP no longer backs off and
  fills the queues as on the default pair (the same ~2.5 ms), a consequence of C2 and not a
  queue regression. Engine latency e2e (`latency.rs`, loaded, 2 pairs): with 2 workers lost
  pings 327 / 363 -> 47 / 52 (no sink-full drops in B); without workers 344 / 256 -> 703 /
  736, reproducibly: the test's ponger sink is slower than the link in both builds, every
  lost ping is a sink-full drop at the receiver, and the faster sender pushes more into the
  already overloaded pool-off receiver (bulk delivered 727-872 -> 554-579 packets/ms). The
  pool-off owner still takes at least one datagram per wake; C2 applies only with workers.
  The futex and context-switch counts of C3 were not measured.
- OE-4 (C7 alone, A = the OE-3 merge 86c6b75, load1 <= 9): w2 10.03 / 10.50 -> 11.66 / 12.67
  Gbit/s, w4 9.99 / 10.50 -> 11.47 / 12.49, default 10.15 / 11.48 -> 10.20 / 11.30 (noise);
  `worker_pool` one peer, 1420 B, 2 workers 0.37 -> 1.30 Melem/s.

Final A/B, 2026-10-05: A = main 20d728c, B = the OE branch (all of the above), both release
builds. Halves A1 12:53-13:59Z (load1 3.1, highest 7.6), B1 14:31-15:37Z (0.5, highest 13.1:
discarded), B2 15:51-16:57Z (2.6, highest 5.9), A2 17:28-18:34Z (3.0, highest 6.4); the table
is the adjacent pair B2 / A2, with A1 in brackets. P1 / P4 Gbit/s, UDP loss %, ping ms, CPU
s/GB:

| Pair (a -> b) | P1 A -> B | P4 A -> B | UDP 1G / 3G A -> B | loaded ping p50 / p99 A -> B | CPU s/GB a, A -> B | CPU s/GB b, A -> B |
| --- | --- | --- | --- | --- | --- | --- |
| nsplane-nsplane | 9.60 [9.49] -> 10.33 (+8 %) | 10.39 [10.27] -> 11.38 (+10 %) | 0.03 / 0.08 -> 0.06 / 0.10 | 2.89 / 5.89 [3.18 / 5.88] -> 2.47 / 5.22 | 1.24 -> 0.94 (-24 %) | 0.91 -> 0.89 |
| nsplane-nsplane (w2) | 8.39 [7.31] -> 11.67 (+39 %) | 8.58 [7.35] -> 12.65 (+47 %) | 0.02 / 0.09 -> 0.09 / 0.26 | 1.21 / 2.60 -> 2.16 / 4.69 | 1.23 -> 1.07 | 1.10 -> 1.09 |
| nsplane-nsplane (w4) | 8.42 [7.99] -> 11.61 (+38 %) | 8.60 [7.17] -> 12.49 (+45 %) | 0.04 / 0.11 -> 0.08 / 0.25 | 1.23 / 2.50 -> 2.29 / 4.77 | 1.23 -> 1.08 | 1.08 -> 1.12 |
| nsplane-nsplane (nooffload) | 3.10 [2.26] -> 3.45 (+11 %) | 3.35 [2.58] -> 3.51 (+5 %) | 0.02 / 0.37 [0.06 / 8.88] -> 0.01 / 0.06 | 1.33 / 2.86 -> 1.03 / 2.43 | 3.61 -> 2.97 (-18 %) | 3.08 -> 2.80 (-9 %) |
| nsplane-nsplane (nooffload-w2) | 3.65 [3.37] -> 4.53 (+24 %) | 4.17 [3.97] -> 4.98 (+19 %) | 0.02 / 0.42 [0.44 / 14.21] -> 0.05 / 0.21 | 1.25 / 2.86 -> 1.14 / 2.52 | 3.64 -> 3.17 (-13 %) | 3.49 -> 3.05 (-13 %) |
| nsplane-kernel | 7.44 [6.53] -> 7.85 (+6 %) | 7.23 [6.32] -> 7.52 (+4 %) | 0.03 / 0.09 -> 0.03 / 0.06 | 3.49 / 6.77 -> 3.32 / 5.05 | 2.13 -> 1.92 (-10 %) | 0.32 † -> 0.31 † |
| kernel-nsplane | 6.97 [7.01] -> 7.08 (+2 %) | 6.80 [6.83] -> 7.02 (+3 %) | 0.01 / 0.05 -> 0.02 / 0.04 | 1.96 / 5.50 -> 1.91 / 4.94 | 0.10 † -> 0.07 † | 1.70 -> 1.65 |
| wggo-wggo (same binary: spread) | 8.41 [9.66] -> 8.50 | 9.82 [10.14] -> 10.50 | 0.06 / 0.75 -> 0.09 / 0.83 | 2.56 / 6.40 -> 2.40 / 6.09 | 1.36 -> 1.32 | 1.71 -> 1.67 |

† kernel WireGuard encrypts outside the container cgroup (undercount). The discarded B1
agrees with B2 within 1-4 % (default 10.27 / 10.89, w2 11.58 / 12.49, nooffload 3.45 / 3.47).
wireguard-go, the same binary in every half, moves up to 15 % (P1) between halves, so
differences below that on a single pair are not meaningful; the w2 / w4 and no-offload
gains are well above it and agree in both B halves. Idle ping is 0.5-0.9 ms p50 on every
nsplane row in both builds. The nooffload UDP 3G loss that OE-1 had raised (0.31 -> 0.88 %)
is 0.06-0.08 % in B against 0.37-8.88 % in A (nooffload-w2 0.21-0.27 against 0.42-14.21 %):
not worse than main in any half.

Micro, same day, one bench per lock acquisition, every half at load1 <= 4.2 (A / B):
`nsplane-core` `data_path` within -1.5 to +0.8 % on all 16 cases (core round trip 530.2 /
532.1 ns at 64 B, 1.3305 / 1.3346 us at 1420 B; batched 32 at 1420 B 39.36 / 39.07 us);
`nsplane-noise` `data_path` within 0.3 %; `worker_pool` hub within -4.6 to +1.8 %; one peer
(B only, the case is new) 1420 B 792 k / 1.30 M / 1.41 M packets/s with 0 / 2 / 4 workers;
`local_graph` -0.3 to -1.8 %; `udp_offload` offload off 83.9 -> 51.0 us (-39 %), on 7.18 ->
7.29 us; `nsplane-tun` `offload` TSO split 4.48 -> 4.32 us (-3.8 %), coalescing (unchanged
code) 4.30 -> 4.47 us with overlapping intervals. No regression.

Where the targets ended (final B2; re-baseline in brackets):

- T1 crypto workers: w2 11.67 / 12.65 Gbit/s, w4 11.61 / 12.49, UDP 3G loss 0.25-0.26 %
  [8.01 / 7.09, 4.03 %]. Workers are now faster than the default (10.33 / 11.38), and four
  streams beat one.
- T2 no offload: 3.45 / 3.51 Gbit/s at 2.97 / 2.80 s/GB [2.59 / 2.96 at 3.76 / 3.63];
  nooffload-w2 4.53 / 4.98 [3.67 / 4.22]. The UDP side is batched; what is left is one TUN
  read and one TUN write per packet.
- T3 mixed directions: nsplane -> kernel 7.85 Gbit/s, sender CPU 1.92 s/GB [7.65, 2.22];
  kernel -> nsplane 7.08 [5.80; main in the same window 6.97]. nsplane -> kernel is bounded
  by kernel WireGuard's receiver, not by our sender: kernel WireGuard -> kernel WireGuard
  moves 4.04-4.88 Gbit/s on this host and harness (4.04 in the run below, 4.88 in the OE
  re-baseline), below the 7.85 nsplane-cli sends into it, and in the profile the kernel
  receiver's own cryptography is the limit, outside our reach. Sending without GSO to such
  peers (`skb_segment` 6.2 % in that profile) was ruled out: the peer type is unknown and
  the kernel receiver stays the limit. Our side can only lower its CPU per GB, which it did
  (-10 %).
- T4 loaded latency: default 2.47 / 5.22 ms [2.84 / 5.40; main same window 2.89 / 5.89],
  wireguard-go 2.40 / 6.09 in the same half. The sender intake bound proposed for it (C8, a
  smaller bound on local packets queued for transmission) was tried as an opt-in and
  dropped: at the bound with an empty backlog nothing woke the owner when the transmit
  queue drained (loaded p50 / p99 ~750 ms), and the ping only moved from the transmit queue
  into the local queue (`local` 1024 / 1024). A shallower `queue_capacity` already lowers
  loaded latency (256: p50 2.1-2.4 -> 1.4-1.6 ms in the latency e2e); C8 is deferred.
- T5 default: P1 / P4 10.33 / 11.38 Gbit/s, CPU 0.94 / 0.89 s/GB [9.91 / 9.87, 1.21 / 0.84].
  Sender CPU per GB -24 % against main in the same window.

ns MF-3 (per-peer parallelism, `docs/task/20261003-2200-ns-local-side.md`): one peer's
throughput was capped by one serial task doing all of that peer's cryptography. Without
workers that is the owner task, 82-85 % busy at about 0.95 us per packet with crypto 35 %
(sender) / 49 % (receiver) of its cycles, so iperf3 `-P 4` cannot scale past one stream: the
streams share the peer. With `crypto_workers` before OE-4, jobs went to worker `peer id % n`,
so one peer still used one worker (w2 8.01 / 7.09 Gbit/s, below the default). It was not a
per-peer queue or a lock: without workers the data path takes no lock. C7 spreads one peer's
cryptography over every worker, with the counters reserved and the replay window checked
in order on the owner and completion in order: with `crypto_workers` >= 2 the same pair
moves 11.67 / 12.65 Gbit/s at w2 (main in the same window 8.39 / 8.58: +39 % / +47 %) and
11.61 / 12.49 at w4, and P4 is now above P1; in process one peer with 1420 B packets goes
from 792 k to 1.30 M (2 workers) and 1.41 M (4) packets per second. ns should set
`crypto_workers` to 2 or more for a single busy peer on a multi-threaded runtime.

What is left (from the profile and the design): with the cryptography on the workers the
owner's work per packet drops to an estimated 0.35-0.45 us (not measured), so the next
limits are the receiver's TUN delivery (coalescing and the TUN
write, 17-18 % of the receiver on its owner without workers, the sink task with workers) and
the sender's TSO split copy (`VnetReader::segment`, 5 % of the sender; splitting in place is
not possible, each segment needs its own header and headroom). Without workers, a receiver
whose sink is slower than the network still drops at `DROP_SINK_FULL` (the pool-off owner
takes at least one datagram per wake); applying C2's deliver-room gate without workers would
change the default path and is left for a later round. Without offload, one TUN read and one
TUN write per packet remain. UDP loss at 3 Gbit/s is at the iperf3 socket and the sender's
TUN queue, not in the tunnel.

### nsplane-nat translator (MF-4)

ns measured direct traffic through `alias4` at about 3.4 Gbit/s against 5.0 Gbit/s for N6
(MF-4). `cargo bench -p nsplane-nat --bench translate` measures `Translator::outbound` of
IPv4 TCP / UDP from `self4` to a peer's `alias4` (to IPv6 `node4`) and `inbound` of the
IPv6 reply, 64 B and 1400 B (TCP) / 1420 B (UDP) payloads, with 1 and 1000 peers in the
table, in a buffer with the TUN reader's room (no grown copy). A/B on 2026-10-06 against
the translator of main (e381bcf; the bench commit 8af9712), three interleaved rounds in one
bench-lock acquisition, 1-minute load 2.3-5.2; criterion means, the range over the rounds
(the third "after" round was cut short):

| Case | Before | After | Change |
| --- | --- | --- | --- |
| out, TCP / UDP 64 B | 72-86 ns | 42-43 ns | -42 % |
| out, TCP 1400 B / UDP 1420 B | 197-228 ns | 79-93 ns | -60 % |
| in, TCP / UDP 64 B | 69-74 ns | 62-73 ns | -11 % |
| in, TCP 1400 B / UDP 1420 B | 191-210 ns | 88-102 ns | -54 % |

1 and 1000 peers cost the same. Where the time went (variants measured in a scratch bench
under the same lock, load 77-94, so about twice the quiet values): the full transport
checksum verification was most of it (`internet_checksum` over 1428 B 282 ns, a 64-bit sum
of 32-bit words 80 ns, a 1428 B `copy_within` 67 ns), then `SipHash` lookups (16 ns for an
IPv4 key, 22 ns for an IPv6 key, two per packet) and `Instant::now()` for the reassembly
clock on every outbound packet. Changes: verification with the word-wise sum
(`checksum::transport_valid`; `checksum::sum` and `valid` use it too), the clock read only
for fragments, IPv6 to IPv4 without moving the payload, one hash per table lookup. The
output is byte-identical (the translator's unit and RFC 7915 vector tests, the
`nsplane-e2e` translate tests and property tests of the new sums against the full ones).
`perf` is not in the dev image; the attribution comes from those variants.

End-to-end effect. Per full-size packet the translator now costs about 0.08 us on the
sender (was 0.20) and 0.09 us on the receiver (was 0.19), plus 0.04-0.06 us (was 0.07) per
ACK. Against the engine's own per-packet cost (`data_path` core round trip 0.10.0: 1.334 us
at 1420 B, about 0.67 us per side) the translator added about 30 % per side and now adds
about 12-13 %; that bounds the gain at about +15 % (3.4 to about 3.9 Gbit/s) when the
thread that runs the filters is the limit. At ns's measured 5.0 Gbit/s the bottleneck
spends about 2.3 us per 1448 B packet, and the alias4 path 3.4 us: the old translator's
0.2-0.27 us per side explains only a fifth to a quarter of that 1.1 us gap if the rest of
the path costs the same, and the change gains about +4 % there. So the translator was not
the whole 30 %: the rest is outside `nsplane-nat` and was not measured here. To check on
the ns side: `TranslatorStats::grown_copies` (each one is a fresh allocation and a copy:
the packet source left less than 20 bytes of room), engine fragmentation of translated
IPv4 (the IPv4 MTU must leave the 20 bytes the header grows by), and TCP segmentation
offload for IPv4 on the TUN.

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

`nsplane-e2e`'s `nat64_lan` test runs `Nat64Lan` around a gateway engine's local side, with an
IPv6 client engine reaching an IPv4 netstack LAN host over channel transports.
The `subnet_gateway` example scenario runs it in containers: a kernel WireGuard peer reaches
an IPv4 LAN host through the mapped /96.

`nsplane-e2e`'s `local_graph` test joins two engines over channel transports only by pipes,
through a `Splitter`, a Redirect-like `MapSink` / `MapSource` and a `MergeSource`, and checks
`pump` for order, backpressure without loss, `BrokenPipe` from either end and cancellation.

`nsplane-acl`'s `crates_acl_parity` test replays the ns ACL verdicts of its fixture
(`tests/fixtures/crates_acl_parity.json`) against the `crates/acl` mode (see
[nsplane-acl](#nsplane-acl)), and `nsplane-e2e`'s `acl_parity` runs that mode between two
engines (by-source and relay-key principals, the fragment gate, the bypass flags, policy
reloads). `nsplane-core`'s and `nsplane-e2e`'s `inbound_destinations` tests cover the
destination check on every receive path and its runtime changes.
