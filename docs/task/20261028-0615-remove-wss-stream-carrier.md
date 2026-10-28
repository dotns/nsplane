# 20261028-0615-remove-wss-stream-carrier Remove the deprecated WsFrame stream carrier from nsplane-wss

- **status**: completed (released in 0.21.0 on 2026-10-28)
- **priority**: P2
- **owner**: pdev (oitcozuh)
- **createdAt**: 2026-10-28 06:15
- **plan**: 20261027-0433-post-freeze-schedule

## Description

The WebSocket stream carrier of `nsplane-wss` (the `WsFrame` codec) is deprecated since 0.11.0
and has no remaining consumer; its replacement is a WireGuard peer over `WssDialer`, served by
`WssServerTransport`. Plan `20261027-0433-post-freeze-schedule` schedules its removal for
0.21.0 with release C; the owner confirmed it on 2026-10-28 (ADR
`2026-10-27-normal-maintenance`: breaking, called out in the CHANGELOG with a migration
example, in a minor release).

Remove `WssStreamClient`, `WssTcpStream`, `WssUdpFlow`, `WssStreamLimits`, `WssStreamStats`,
`MAX_DATA_PAYLOAD`, `WssStreamServer`, `WssServerLimits`, `WssServerStats`, `WssResolver`,
`WssOpen`, `Denied`, `WssStreamEvent`, `WssStreamEventKind`, `WssCloseReason` and the `frame`
module, and everything that exists only for them.

## Acceptance

- The items are gone; the dialer, its configuration and the server transport are unchanged.
- Shared dialer behaviour the stream tests covered stays covered by `WssDialer` tests.
- Reference, README, guides and CHANGELOG `[0.21.0]` `#### Breaking` updated.
- Gate: `just check`, rustdoc `-D warnings`, `cargo semver-checks` lists the removals.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- Removed on `feat/0.21.0-m3-removals`: `src/stream.rs`, `src/server.rs`, `src/frame.rs` with
  their unit tests, `tests/stream.rs`, and the crate-private `WssConfig::pings`,
  `Connector::retry_now` and `Connector::lost` that only they used; `thiserror` and the
  `rcgen` dev-dependency. `WssConfig` keeps every field and method (none was stream-only).
- `connect.rs` unit tests: `loss_waits_at_least_the_floor` became
  `without_a_reconnect_delay_a_redial_waits_the_floor`; the backoff test sets the post-success
  state through `reconnect()`.
- e2e: `wss_stream_open.rs` deleted (only `open_timeout`, stream-only); the stream-client tests
  in `wss_dial_error`, `wss_events`, `wss_keepalive` and `wss_ping_off` deleted, each with a
  `WssDialer` test covering the shared behaviour. Coverage note: the deleted events test
  checked exact connect-failure counters (7, and 2/2 rejections); the dialer test checks the
  same event sequence one to one with looser counter bounds.
- `cargo semver-checks` against v0.20.2 lists exactly the removed items (enum, struct, trait,
  function, module and constant missing in `nsplane-wss`).
