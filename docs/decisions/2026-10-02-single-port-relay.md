# ADR: Single-port relay wire format

Status   : Proposed (the wire contract is shared with ns and nsgw and is not decided by this
           repository)
Date     : 2026-10-02
Sunset   : when ns and nsgw adopt or reject the framing below

## Context

nsgw runs its WireGuard relay on a UDP socket separate from its WireGuard listen socket and
tells relay control datagrams apart by an 8-byte ASCII magic (`NSGWGRS1`, `NSGWP2P1`). The
examples in this repository (workstream 3D) need a relay that is also a WireGuard node, on
one port: a peer behind NAT reaches the relay's own engine, other peers through the relay,
and the relay's control messages without a second port to open or discover. Plain WireGuard
clients (kernel, wireguard-go, mobile apps) must keep working against that port unchanged.

The control messages are ns's: the Ed25519-signed CBOR `ControlEnvelope`
(`wg_relay.register_source`, `gateway.reflexive`) and nsgw's unsigned reflexive reply. This
repository mirrors them; only the framing on the shared port is new. The implementation is
`nsplane_examples::relay` (`examples/src/relay/`): pure functions and types, no sockets.

## Decision

One UDP port carries three kinds of traffic:

- (a) native WireGuard to the relay's own engine;
- (b) blind relaying of WireGuard between two other peers, without decryption: the relay
  only reads the type, the indices and mac1;
- (c) control messages: `[type u8][0u8; 3][version u8 = 1][payload]`, where the payload is
  the ns encoding unchanged and the header replaces ns's 8-byte magic.

### Demux rules

The first four bytes are read as a little-endian `u32`, as WireGuard and the Linux kernel
read the message type (`relay::wire::classify`).

1. Value 1-4 (so the three reserved bytes are zero) with at least the WireGuard length of
   that type (initiation 148, response 92, cookie reply 64, transport data 32) is
   WireGuard. Shorter is invalid.
2. Handshake initiation: mac1 computed with the relay's own static public key goes to the
   own engine; mac1 matching a registered target's public key is relayed to that target's
   learned source. Neither: drop.
3. Handshake response, cookie reply and transport data: the relay's route table keyed by
   `(receiver_index, source)` first (filled from relayed initiations and responses); no
   route: the own engine.
4. A packet that matches more than one destination (mac1 of the own key and of a target's,
   two targets with one key, a route colliding with the own engine's index) is ambiguous:
   drop it and count it.
5. First byte in `0xF0..=0xFF`, bytes 1-3 zero, at least five bytes: control. The fifth
   byte is the version; an unknown version or a reserved type is dropped. Non-zero reserved
   bytes after a type of 1-4 never select a control message.
6. Everything else is dropped.

### Message types

| Type   | Message                             | Direction    | Payload (unchanged from ns/nsgw)                 |
|--------|-------------------------------------|--------------|--------------------------------------------------|
| `0xF0` | `wg_relay.register_source`          | peer → relay | CBOR `ControlEnvelope`, request domain, payload CBOR `WgRelayRegistrationRequest { nsn_pubkey }` |
| `0xF1` | reserved (ns has no registration ack) | -          | -                                                |
| `0xF2` | `gateway.reflexive` request         | peer → relay | CBOR `ControlEnvelope`, request domain, payload CBOR `GatewayReflexiveRequest { peer_key_pub, nonce }` |
| `0xF3` | `gateway.reflexive` response        | relay → peer | CBOR `GatewayReflexiveResponse { nonce, observed_addr, gateway_id, relay_socket_addr, timestamp_unix_ms }`, unsigned |
| `0xF4`-`0xFF` | reserved                     | -            | -                                                |

Timing, as ns and nsgw: registration every 30 s, learned source kept 90 s, relay routes
180 s, reflexive request every 20 s, reflexive nonce outstanding 30 s, envelope clock skew
60 s, replay window 120 s.

### Authentication

- Requests ride in the ns signed envelope: Ed25519 over the machine key, signing input
  `"nsio-ctrl-v1\0" || v || len-prefixed api || ts || nonce || machine_id || machine_key_pub
  || sha256(payload)`, fresh 16-byte nonce, clock skew 60 s, replay window 120 s.
- The relay pins each machine: its configuration maps the WireGuard public key in the
  payload to the machine id and Ed25519 machine key it expects, as NSD projects
  `GatewayWgRelayPair` (`nsn_machine_key_pub`, `nsc_machine_key_pub`) to nsgw. A valid
  signature by any other key is rejected. The replay check runs after the pin, so a foreign
  machine cannot burn another's nonce (`Authenticated::admit`).
- The reflexive response is unsigned, as in nsgw, and is bound to its request by the echoed
  nonce: the peer accepts it once, only while the nonce is outstanding, and never for an
  all-zero nonce (`PendingNonces`).
- The relay never sends a control message to a peer that did not send one first: the only
  relay-originated control message is the reflexive response to an admitted request.

### ns/nsgw mapping

| Item here (`relay::…`)                         | ns/nsgw source                                                                 |
|-----------------------------------------------|--------------------------------------------------------------------------------|
| `envelope::ControlEnvelope`, `sign_request`, `sign_response`, `verify_request`, `verify_response`, `to_cbor`, `from_cbor` | ns `crates/control/src/envelope.rs` `ControlEnvelope` |
| signing input, `DOMAIN_REQUEST`, `DOMAIN_RESPONSE`, `ENVELOPE_VERSION`, `MAX_CLOCK_SKEW_SECS`, `REPLAY_WINDOW_SECS` | ns `envelope.rs` `build_sig_input` and constants |
| `envelope::ReplayGuard`                        | ns `envelope.rs` `ReplayGuard`                                                 |
| `envelope::MachineKey`                         | ns `crates/common/src/state/storage/machine.rs` signing key (see deviations)   |
| `messages::WG_RELAY_REGISTER_SOURCE`, `GATEWAY_REFLEXIVE` | ns `envelope.rs` `api::WG_RELAY_REGISTER_SOURCE`, `api::GATEWAY_REFLEXIVE` |
| `messages::WgRelayRegistrationRequest`, `build_register_source` | ns `crates/control/src/api.rs` `WgRelayRegistrationRequest`, `build_register_source_datagram` |
| `messages::GatewayReflexiveRequest`, `build_reflexive_request` | ns `api.rs` `GatewayReflexiveRequest`, `build_gateway_reflexive_datagram` |
| `messages::GatewayReflexiveResponse`, `build_reflexive_response` | ns `api.rs` `GatewayReflexiveResponse`; nsgw `crates/nsgw-wg/src/relay.rs` `handle_reflexive_request` |
| `messages::open_register_source`, `Authenticated::admit` | nsgw `relay.rs` `decode_registration`, `register_source` |
| `messages::open_reflexive_request`             | nsgw `relay.rs` `decode_reflexive_request`                                     |
| `messages::PendingNonces`, `REFLEXIVE_NONCE_TTL` | ns `crates/tunnel-wg/src/p2p/reflexive.rs` `ReflexiveGatherer` (`issue_nonce`, `ingest_response`, `gc`), `p2p.rs` `NONCE_TTL` |
| `messages::RELAY_REGISTER_INTERVAL`, `REFLEXIVE_GATHER_INTERVAL` | ns `crates/tunnel-wg/src/lib.rs` `RELAY_REGISTER_INTERVAL`, `p2p/reflexive.rs` `REFLEXIVE_GATHER_INTERVAL` |
| `messages::LEARNED_SOURCE_TTL`, `SESSION_TTL`  | nsgw `relay.rs` constants                                                      |
| `wire::classify`, `sender_index`, `receiver_index`, length constants | nsgw `relay.rs` `parse_packet`, `*_MIN_LEN`, index offsets |
| `mac1::Mac1Key`, `mac1_matches`                | nsgw `relay.rs` `mac1_key`, `mac1_for_packet`                                  |
| `wire::encode_control`, `decode_control`, `ControlType` | ns/nsgw `WG_RELAY_REGISTRATION_MAGIC`, `GATEWAY_REFLEXIVE_MAGIC` prefixes |

Deviations:

- Framing (intended): the 5-byte control header replaces the 8-byte magic. The bytes after
  the header equal the bytes after ns's magic. The reflexive request and response share
  one magic in ns and get two types here, because one port now carries both directions.
- Transport data minimum: 32 bytes (header and tag of a keepalive) instead of nsgw's 16.
  A 16-31 byte type-4 datagram cannot authenticate at any receiver; nsgw relays it, this
  relay drops it.
- mac1 of a handshake response is checked as well (against the initiator's key); nsgw
  only uses mac1 on initiations. The demux above still routes responses by index.
- `PendingNonces` keeps only the nonce binding of ns's `ReflexiveGatherer`, not its
  candidate set, RTT accounting or epochs, which belong to ns's P2P layer.
- `MachineKey` stores the Ed25519 secret seed as one line of base64. ns derives the
  signing key from an identity seed and the machine id (SHA-512 split) and persists it in
  its state file; neither is part of the wire contract.
- `serde_bytes` is not a dependency here; fixed arrays and the payload are serialized as
  CBOR byte strings by local helpers, which is what `serde_bytes` produces. Decoding also
  accepts arrays of integers, as `serde_bytes::ByteBuf` does.

## Compatibility

- Capability discovery: a peer or endpoint counts as extension-capable only after an
  authenticated, nonce-bound reply (a `0xF3` that echoes an outstanding nonce). Until then
  it is plain WireGuard and nothing else is sent to it.
- A peer that gets no reply backs off exponentially, bounded, and then stops until it is
  reconfigured or the endpoint changes. Control messages are rate-limited per endpoint on
  both sides (nsgw already limits reflexive requests per source before verifying).
- Extension traffic is never required: WireGuard between two peers and to the relay's own
  engine works without it. It never uses types 1-4 and never delays a handshake or data.
- Native clients: a native WireGuard client can talk to the relay's own engine on the same
  port and can be a consumer through the relay (its initiation's mac1 names a registered
  target). It cannot register a NAT source or learn its reflexive address, and so cannot
  be a relayed target behind NAT or hole-punch, because it never sends control messages.

## Implementation in the examples

`relay::router` (sans-I/O demux), `relay::server` (the relay's wrapping transport and
configuration), `relay::client` (discovery, registration, the node's extension-aware
transport) and `relay::ladder` (the path policy); binaries `relay_server` and
`relay_transport`. Choices within the rules above:

- Configuration: `{"machine_keys": [{"machine_key": b64, "wg_public_key": b64}],
  "static_targets": [{"wg_public_key": b64, "endpoint": "ip:port"}]}`, re-read on change
  (polled every second). A `machine_keys` entry pins the machine allowed to register the
  WireGuard key; its machine id is the standard base64 of the Ed25519 public key, and
  nodes sign with that id. A `static_targets` entry relays to a fixed endpoint, for native
  WireGuard peers that cannot register. A reflexive request is answered only for a pinned
  machine's WireGuard key.
- Discovery: ns has no registration ack, so the discovery probe is a reflexive request;
  an endpoint becomes capable with the first accepted `0xF3`. `register_source` is sent
  only after that (right away, then every 30 s), so an endpoint that is not known to be
  capable never receives a registration. Probes back off 1, 2, 4, 8, 16 s; after five
  unanswered ones the endpoint is stopped until it is reconfigured. At most four control
  messages per endpoint and second.
- Own-engine indices: the relay notes the sender index of every handshake its own engine
  sends; a relay route on such an index is ambiguous (rule 4).
- Bounds, as nsgw: 4096 routes and 1024 routes of unanswered initiations (least recently
  used evicted, counted), 128 relayed initiations and 16 control messages per source and
  second (the control limit applies before verification). Routes expire after 180 s
  without traffic, learned sources after 90 s without a registration or traffic from them.
- Control failures map to counters: bad or foreign signature and a machine id other than
  the pinned one count as `bad_signature`, a seen nonce or a stale timestamp as `replay`,
  no pinned target as `unknown_target`, anything malformed as `invalid`.

## WebSocket carrier

Where UDP is blocked, the same datagrams travel over WebSocket over TLS (WSS) to a TCP
listener of the relay (`relay_server --wss-listen`; `relay::wss`).

- Framing: one binary WebSocket message carries exactly one datagram, the bytes it would
  have on UDP (WireGuard or a framed control message). Text messages, messages over
  65535 bytes and payloads that classify as neither are dropped and counted; pings are
  answered.
- Routing: each connection is a source of the same router as the UDP socket, so UDP and
  WSS clients relay to each other and reach the own engine, under the rules above. A
  `register_source` received on a connection binds the WireGuard key to that connection; a
  reflexive request on it observes the connection's TCP peer address. Closing a connection
  forgets the sources learned on it and its routes. The own engine sees a connection as a
  path whose address is the TCP peer address.
- TLS: rustls with the aws-lc-rs provider. The examples' relay self-signs a certificate at
  start for a DNS name plus the listen address; clients pin that certificate and trust
  nothing else, with SNI from the URL host.
- Client: the node's transport sends datagrams for the relay's address over the
  connection and everything else over its UDP socket, so discovery, registration and the
  direct-first ladder are unchanged, with WSS as the relay carrier. It reconnects with
  bounded exponential backoff, drops (and counts) what is sent while disconnected, and
  restarts discovery after every connect, so a restarted relay learns the node at once.

## Consequences

- One port to open and advertise per relay; the relay is a WireGuard node and a relay at
  once.
- ns and nsgw payload code ports unchanged; a bridge between this relay and nsgw only swaps
  the header for the magic. Changing the framing in ns/nsgw is their decision; until then
  this format is used only by this repository's examples.
- The relay depends on mac1 and receiver indices staying unencrypted, which they are in
  WireGuard by design; a relay never holds keys of the peers it relays.
- Every WireGuard key the relay serves (its own and each target's) must be unique among
  them; collisions are ambiguous and dropped.
