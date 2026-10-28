# 20261028-0615-remove-wss-stream-carrier Remove the deprecated WsFrame stream carrier from nsplane-wss

- **status**: in_progress
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
