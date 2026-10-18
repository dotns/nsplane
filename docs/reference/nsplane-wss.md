# nsplane-wss

WebSocket over TLS carriers: `WssDialer`, a datagram link for `LinkTransport`, and
`WssServerTransport`, its server side over sessions the embedder accepts. The deprecated
stream carrier (`WssStreamClient`, `WssStreamServer`) multiplexes TCP streams and UDP flows.
Builds on `nsplane`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `WssDialer` (`new`, `into_transport`, `state`, `stats`, `events`), `WssStreamClient` (`new`, `connect`, `open_tcp`, `open_udp`, `state`, `stats`, `events`), `WssStreamServer` (`new`, `with_events`, `run`, `state`, `stats`); traits `BearerProvider`, `WssResolver` | `WssConfig` (`allow_plaintext` for `ws://`, `keepalive`, `reconnect_delay`), `WssTls`, `WssDialError` (`MAX_BODY`), `WssDialEvent` (`CAPACITY`), `WssStats`, `WssStreamLimits` (`open_timeout`), `WssStreamStats`, `WssTcpStream`, `WssUdpFlow`, `WssServerLimits`, `WssServerStats`, `WssOpen`, `Denied`, `WssStreamEvent` / `WssStreamEventKind`, `WssCloseReason`; `frame` (`WsFrame`, `FrameCommand`, `Protocol`, `FrameError`, the command and protocol bytes); `MAX_DATAGRAM`, `MAX_MESSAGE`, `MAX_DATA_PAYLOAD` |
| server transport | `WssServerTransport` (`new`, `stats`; a `Transport`), `WssAcceptor` (`accept`, `ws_config`), `WssSession` (`addr`, `close`, `stats`) | `WssServerConfig` (`queue`, `inbound_queue`, `ping_interval`, `read_idle`, `max_sessions`), `WssServerTransportStats`, `WssSessionStats` |

## Behavior

Both legs of each data-channel protocol live in nsplane (ADR
`2026-10-03-data-channel-protocols-in-nsplane`). This is a separate crate on `nsplane`, so
`nsplane` itself has no WebSocket or TLS dependency; only an application that adds it pulls
in `tokio-tungstenite` and `rustls` (aws-lc-rs provider). It is `#![forbid(unsafe_code)]`.

### Connections

Every carrier dials the same way, from one `WssConfig`:

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
  that arrived with the head up to `WssDialError::MAX_BODY` (512). The kind
  and message: `PermissionDenied`, "wss upgrade rejected with HTTP {status}"
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
  link is `backoff_min` as the first step of the doubling. A stream client's
  capacity dial (another session while one is up) goes at once.
- Keepalive: a ping every `ping_interval` (10 s); the link ends when no frame at all
  (pongs included) arrived for `read_idle` (35 s). Every carrier reads both per dial
  (`WssConfig::keepalive`). A zero
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
  and a count check, no allocation; events are per dial, never per datagram.
- TLS trust is the caller's: there are no built-in system or web PKI roots. `WssTls::Roots`
  takes a `RootCertStore` (the client configuration is built with aws-lc-rs, the safe
  default protocol versions and no client auth); `WssTls::Config` takes a complete
  `Arc<rustls::ClientConfig>` used as is (an application with its own TLS setup passes it).

### Datagram carrier

`WssDialer` is a `LinkDialer`: `into_transport(id, peer, config)`
returns a `LinkTransport` whose links are WSS connections. Each datagram is one binary
message carrying its raw bytes (the wire of the examples' relay); text
messages and messages above `MAX_DATAGRAM` (65 535) are dropped and counted in
`WssStats`, a close frame or the end of the stream ends the link.

### Stream carrier (deprecated)

The stream carrier is deprecated; a WireGuard peer over `WssDialer` replaces it.

Wire: `WsFrame` (module `frame`) is byte-compatible with an existing stream relay protocol:
every binary message is one frame, big-endian.

| Field / command | Bytes | Content |
|---|---|---|
| `stream_id` | 4 | the stream, per session (never 0 from the client) |
| `command` | 1 | one of the commands below |
| `OPEN_V4` (`0x01`) | 4 + 2 + 1 | IPv4 address, port, protocol (`0x00` TCP, `0x01` UDP) |
| `OPEN_V6` (`0x02`) | 16 + 2 + 1 | IPv6 address, port, protocol |
| `DATA` (`0x10`) | rest | stream bytes (at most `MAX_DATA_PAYLOAD`, 65 531, per frame), or one UDP datagram |
| `CLOSE` (`0x20`) | 0 | close the stream |
| `CLOSE_ACK` (`0x21`) | 0 | acknowledge a CLOSE |

As in that protocol, bytes after a complete OPEN, CLOSE or `CLOSE_ACK` are ignored and any protocol
byte but `0x01` is TCP. The protocol has no open reply and no flow control: a refused
OPEN is answered with CLOSE, and a stream whose peer outruns its receive budget is closed.

Stream client: `WssStreamClient` (the client leg) opens TCP streams (`open_tcp`, a `WssTcpStream` with `AsyncRead` and
`AsyncWrite`) and UDP flows (`open_udp`, a `WssUdpFlow` with `send` / `recv`) to targets
behind a stream server (`WssStreamServer`, or any other server of the protocol).

- Sessions: dialed lazily on the first open (or `connect`). Every TCP stream and UDP flow
  is multiplexed over one session until it holds
  `WssStreamLimits::max_streams_per_session` live ones (default 1024); only then is one more session dialed. One dial runs at a time,
  in a task of its own (one per dial, not per open), and waiting opens share its outcome;
  an open dropped while it waits therefore loses neither the backoff nor the 401 token
  wait, and never starts a second dial. Server caveats: a server may reject
  OPENs beyond its own per-session cap, which can be below 1024 (keep
  `max_streams_per_session` at most the server's cap), and may write all streams of a
  session through one shared writer queue.
- Stream ids count up from 1 per session, skipping ids still in use; an id stays in use
  until the peer's CLOSE or `CLOSE_ACK`. An open returns once its OPEN is queued.
- Half-close: `shutdown` sends CLOSE behind the data already written (the wire has no
  other half-close) and the stream keeps reading until the peer's CLOSE or `CLOSE_ACK`,
  then reads EOF; this matches `WssStreamServer`, which drains the
  stream to the backend before ending it. A peer's CLOSE reads as EOF after the bytes
  before it and is answered with `CLOSE_ACK`; dropping a stream sends CLOSE.
- Queues and bounds (`WssStreamLimits`): a control queue (OPEN,
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

Server leg: `WssStreamServer` dials the
relay like the client and serves the protocol on the session; `run(shutdown)` drives it.

- Resolution is the embedder's: `WssResolver::resolve(WssOpen { session, stream_id,
  target, protocol })` returns the backend `SocketAddr` or `Denied` (answered with CLOSE).
  It runs on the stream's own task, so a slow answer delays only that stream. Name
  resolution, access control and identity checks stay the embedder's, behind it.
- An OPEN for an id in use, or beyond `max_streams` (1024), is answered with CLOSE. The
  server connects a TCP stream or a connected UDP socket (bound to the backend's address
  family) and relays: TCP bytes in DATA frames of at most `MAX_DATA_PAYLOAD`, one datagram
  per DATA frame for UDP.
- A CLOSE is always answered with `CLOSE_ACK`; the stream's queued data is still written
  to the backend, then its write side is shut. A backend EOF sends CLOSE behind the
  stream's data; a failed connect, a backend error (a failed UDP receive included) sends
  CLOSE at once.
- Queues and bounds (`WssServerLimits`): 4 MiB per stream
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

### Tests

Unit tests next to the code (`frame`, `stream`, `server`, `connect`, `config`);
`crates/nsplane-wss/tests/stream.rs` runs the client and the server through a TLS test
relay (and a plain one for `ws://`) and checks the frames against the reference layouts;
`nsplane-e2e` `wss_datagram` runs two engines over `WssDialer` (401, 403, reconnect, read
idle), `wss_plain` over `ws://`, `wss_dial_error` checks the `WssDialError` of a 401
and a 503 (header, truncated body) from the dialer and the stream client,
`wss_keepalive` the ping cadence and read idle of both carriers at two settings, and
`wss_events` the event sequence (up, lost, up, 401 x 2, 403 x 2, relay down, timeout) and
the reconnect delay against the doubling backoff on both carriers, and `wss_stream_open`
the stream client's `open_timeout` (relay down, 403, relay coming up, and the default
waiting open); `examples/tests/wss.rs` and the
`relay-wss` cells of `just e2e-examples` run the examples' relay client on it.

### Server transport

`WssServerTransport` (module `accept`) is the server side of `WssDialer`'s links: a
`Transport` over WebSocket sessions the embedder accepts. `WssServerTransport::new(id,
WssServerConfig)` returns the transport and a `WssAcceptor` (`Clone`); the embedder runs
the listener, TLS, its own request checks (path, token) and the upgrade with
`WssAcceptor::ws_config()` (messages and frames up to `MAX_MESSAGE`), then calls
`accept(ws)`. The crate does no authentication. The wire is the datagram carrier's: one
binary message per datagram, text and messages above `MAX_DATAGRAM` dropped and counted.

- **Endpoints.** Each accepted session gets `[100::n]:0`: IPv6 in 100::/64 (RFC 6666
  discard-only), `n` a 64-bit count of the sessions accepted, so an address is never
  reused while the transport lives. Received datagrams carry `Path { transport: id,
  addr, ecn: NotEct }`. A peer's endpoint in the engine's status and in UAPI shows such an
  address; it names a session, not a host.
- **Routing.** Replies go to the engine's path, which roams on
  authenticated messages (`StandardRoaming`), so they reach the session the peer last
  authenticated on. A send to an address without a live session fails at once with
  `NotConnected` (the engine counts `DROP_TRANSPORT_SEND_ERROR`, the transport
  `sent_to_closed`). Between a session closing and the peer's redial, datagrams to that
  peer are lost by design; WireGuard retransmits handshakes, and the peer's next
  authenticated datagram on the new session moves its path.
- **Tasks and queues.** One task per session reads, writes and pings. Outbound: a bounded
  queue per session (`queue`, 256; 0 taken as 1) drained by that task; a full queue fails
  `send` at once with `WouldBlock`, as `LinkTransport` does, counted in
  `dropped_queue_full`. Inbound: one shared bounded channel (`inbound_queue`, 1024) feeds
  `recv`; a session's reader waits for room, so a slow engine pushes back per session onto
  TCP. Batch methods are the trait defaults.
- **Lifecycle.** A close frame or end of stream (peer close), a read or write error, no
  frame for `read_idle` (35 s; pongs count) or `WssSession::close` / dropping the transport
  (local close) ends a session; except after an error it then tries a close frame for at
  most 1 s. Pings go out every `ping_interval` (10 s; `None` sends none). Dropping the
  `WssSession` handle does not close it. `max_sessions` (4096) bounds the open sessions:
  `accept` beyond it fails with `ConnectionRefused` before any task starts, and after the
  transport is dropped with `BrokenPipe`. Worst-case buffered memory is `max_sessions` x
  `queue` x `MAX_DATAGRAM` plus `inbound_queue` x `MAX_DATAGRAM` (64 GiB + 64 MiB at the
  defaults; about 1.5 GiB with WireGuard-sized datagrams).
- **Counters.** `WssServerTransportStats`: active, accepted, refused (limit, closed),
  closed by reason (idle, error, peer, local), rx/tx datagrams and bytes, dropped text,
  oversized and queue-full, `sent_to_closed`; `WssSessionStats` per session (rx/tx,
  drops).
- **Tests.** `crates/nsplane-wss/src/accept/tests.rs`: a `WssDialer` link against the
  transport over loopback `ws://`, and sessions over in-memory streams (distinct
  addresses, sends to closed sessions, queue full, read idle and pings, dropped messages,
  the session limit and dropping the transport). `nsplane-e2e` `wss_server` runs engines on
  `WssDialer`s against one engine on the transport: several nodes on distinct session
  addresses, a server-side close and redial moving the endpoint, the transport next to a
  `UdpTransport`, no endpoint takeover by garbage or an unknown key on another session,
  and a session that stops reading without holding up the others.


## Configuration and defaults

| Feature | How to enable | Default | Cost when not enabled |
|---|---|---|---|
| WSS carriers | `WssDialer::new(config)?.into_transport(..)`, `WssServerTransport::new`, the deprecated `WssStreamClient::new` / `WssStreamServer::new` | not a dependency | none: a separate crate; `nsplane` gains no WebSocket or TLS dependency (`tokio-tungstenite`, `rustls` with aws-lc-rs come only with `nsplane-wss`) |

## See also

- [nsplane](nsplane.md): `LinkTransport`, `LinkDialer` and `LinkState`.
- [Usage guide: WebSocket over TLS](../guide.md#websocket-over-tls-nsplane-wss)

