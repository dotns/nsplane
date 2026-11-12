# nsplane-wss

WebSocket over TLS carriers: `WssDialer`, a datagram link for `LinkTransport`, and
`WssServerTransport`, its server side over sessions the embedder accepts. Builds on
`nsplane`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `WssDialer` (`new`, `into_transport`, `state`, `stats`, `events`); trait `BearerProvider` | `WssConfig` (`allow_plaintext` for `ws://`, `keepalive`, `ping_interval`, `reconnect_delay`), `WssTls`, `WssDialError` (`MAX_BODY`), `WssDialEvent` (`CAPACITY`), `WssStats`; `MAX_DATAGRAM`, `MAX_MESSAGE` |
| server transport | `WssServerTransport` (`new`, `stats`; a `Transport`), `WssAcceptor` (`accept`, `ws_config`), `WssSession` (`addr`, `close`, `stats`) | `WssServerConfig` (`queue`, `inbound_queue`, `ping_interval`, `read_idle`, `max_sessions`), `WssServerTransportStats`, `WssSessionStats` |

## Behavior

Both legs of each data-channel protocol live in nsplane (ADR
`2026-10-03-data-channel-protocols-in-nsplane`). This is a separate crate on `nsplane`, so
`nsplane` itself has no WebSocket or TLS dependency; only an application that adds it pulls
in `tokio-tungstenite` and `rustls` (aws-lc-rs provider). It is `#![forbid(unsafe_code)]`.

### Connections

`WssDialer` dials from one `WssConfig`:

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
  for 401/403; `Other`, "wss connect failed: HTTP error: {status}" otherwise.
- An upgrade answered with 401 or 403 is reported as `LinkState::Rejected(status)` on the
  dialer's `state()` watch (and counted in its stats). After a 401 the next dial waits
  until the provider yields a different token (polled every `token_poll`, 2 s, at most
  `token_wait`, 300 s); a 403, and a 401 without a provider, back off like any failure.
- Backoff: every dial but the first waits. After a link that came up (the dial after a
  successful one) it waits `reconnect_delay` when set, and a dial failing after it waits
  `backoff_min` (2 s), doubled after each further failure up to `backoff_max` (60 s); the
  connector models this as a distinct `Retry::Reconnect` state, so the failure backoff
  restarts at the floor instead of doubling the reconnect delay. Without
  `reconnect_delay` (the default) the wait after a link is `backoff_min` as the first step
  of the doubling. Each of these waits is jittered: the delay is an upper bound, and a
  dial waits a random time between half of it and all of it (1 to 2 s, then 2 to 4 s, at
  most 30 to 60 s by default), so the dialers a restarted server lost together do not
  come back in waves. The doubling goes by the delay, not by the time waited.
- Keepalive: a ping every `ping_interval` (10 s); the link ends when no frame at all
  (pongs included) arrived for `read_idle` (35 s). The dialer reads both per dial
  (`WssConfig::keepalive`). A zero `ping_interval` (`WssConfig::ping_interval(None)`)
  sends no pings: the dialer spawns no ping task; the read idle stays. No message above
  `MAX_MESSAGE` (4 x 65 535 bytes) is read.
- Events: `WssDialer::events()` subscribes to a `broadcast` channel in the connector
  (`WssDialEvent::CAPACITY` = 64; a lagging receiver sees `RecvError::Lagged`), one
  `WssDialEvent` per occurrence: the connector sends `DialFailed`, `TimedOut` and
  `Rejected(status)` for each failed dial; the dialer sends `Connected` and `Lost` from
  `LinkDialer::on_state` (so a link's `Connected`, sent when the transport reports it up
  right after the dial, precedes its `Lost`). Without a receiver a send is a lock and a
  count check, no allocation; events are per dial, never per datagram.
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

The link's sender implements `LinkSender::send_batch`: the datagrams `LinkTransport` hands
it together (those queued at that moment, at most `LinkTransport::SEND_BATCH` = 64) are
fed to the WebSocket as they are, without a copy, and flushed once, so a burst shares its
TLS records and write calls while a datagram alone is flushed at once. There is no timer
and no waiting for more. The order is the queue's; tungstenite writes its buffer out by
itself above 128 KiB, which bounds what a batch holds in memory. A failed write ends the
link and loses the batch.

### Tests

Unit tests next to the code (`connect`, `config`, `dialer`); `nsplane-e2e` `wss_datagram`
runs two engines over `WssDialer` (401, 403, reconnect, read idle), `wss_plain` over
`ws://`, `wss_dial_error` checks the `WssDialError` of a 401 and a 503 (header, truncated
body), `wss_keepalive` the ping cadence and read idle at two settings, `wss_ping_off` a
link without pings (data flows, no ping sent, the read idle still ends it), and
`wss_events` the event sequence (up, lost, up, 401 x 2, 403 x 2, relay down, timeout) and
the reconnect delay against the doubling backoff; `examples/tests/wss.rs` and the
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
  `dropped_queue_full`. The writer takes what is queued (`recv_many`, at most 64
  datagrams, never waiting for more), feeds it and flushes once: a datagram alone leaves
  at once, a burst shares its writes, the order is the queue's. Inbound: one shared
  bounded channel (`inbound_queue`, 1024) feeds `recv`; a session's reader waits for
  room, so a slow engine pushes back per session onto TCP. Batch methods are the trait defaults.
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
  queued datagrams written together, the session limit and dropping the transport). `nsplane-e2e` `wss_server` runs engines on
  `WssDialer`s against one engine on the transport: several nodes on distinct session
  addresses, a server-side close and redial moving the endpoint, the transport next to a
  `UdpTransport`, no endpoint takeover by garbage or an unknown key on another session,
  and a session that stops reading without holding up the others.


### Benchmark

`cargo bench -p nsplane-wss --bench throughput` carries a million datagrams of 1200 bytes
each way between a `WssDialer` link and the server transport over loopback `ws://`, at most
128 in flight, and prints datagrams per second and CPU time per datagram (whole process).
On the development host (7 cores of one CCD, three runs each): with one flush per datagram
0.47 to 0.51 M/s at 4.6 us from the link to the server and 0.51 to 0.55 M/s at 4.5 to
4.7 us back; with the batched writes 2.3 to 2.5 M/s at 1.1 to 1.3 us and 1.3 to 1.4 M/s at
2.1 to 2.3 us.

## Configuration and defaults

| Feature | How to enable | Default | Cost when not enabled |
|---|---|---|---|
| WSS carriers | `WssDialer::new(config)?.into_transport(..)`, `WssServerTransport::new` | not a dependency | none: a separate crate; `nsplane` gains no WebSocket or TLS dependency (`tokio-tungstenite`, `rustls` with aws-lc-rs come only with `nsplane-wss`) |

## See also

- [nsplane](nsplane.md): `LinkTransport`, `LinkDialer` and `LinkState`.
- [Usage guide: WebSocket over TLS](../guide.md#websocket-over-tls-nsplane-wss)

