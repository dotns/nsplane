# ADR: every data-channel protocol is implemented in nsplane

Status   : Accepted
Date     : 2026-10-03

## Context

ns is the business and control layer; nsplane is the data plane. While moving ns's
per-packet code into nsplane (task `20261003-1500-ns-dataplane-moves`), the WSS carriers
came up: decision D10 had kept WebSocket and TLS out of nsplane and left a WebSocket dialer
to ns behind the generic `LinkTransport`. Without UDP, WSS is the only channel a node has,
and every protocol implemented in ns duplicates framing, reconnection, backpressure and
their tests next to the engine.

## Decision

A data-channel protocol (a transport carrying WireGuard datagrams, or a carrier of
streams/flows such as the WsFrame protocol) is implemented in nsplane, completely: wire
format, connection setup, authentication handshake on the wire (headers, status codes),
reconnection and backoff, keepalive and idle detection, queues and counters. ns supplies only
configuration and business decisions through narrow traits (where to connect, which bearer
token, whether an incoming open is allowed and where it goes) and maps status to its own
model. Adding a protocol to ns means writing that glue, not a protocol implementation.

Protocol crates that need heavy dependencies are separate, optional crates (the first is
`nsplane-wss`: tokio-tungstenite, tungstenite, tokio-rustls, rustls with aws-lc-rs,
rustls-pki-types, approved 2026-10-03), so `nsplane` itself and a basic client stay free of
them. This supersedes the "no WebSocket or TLS dependency in nsplane" part of D10;
`LinkTransport` stays the generic, dependency-free base the protocol crates build on.

## Consequences

- ns deletes its protocol code as each carrier lands (`tunnel-ws`, the opaque pump hop, its
  WsFrame codec) and keeps listeners, route lookup, bearer source, ACL preflight and status
  mapping.
- Both legs of a protocol move, including a leg ns does not run today (the WsFrame terminate
  leg, user decision 2026-10-03), so ns keeps no protocol code at all.
