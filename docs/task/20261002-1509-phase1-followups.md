# 20261002-1509-phase1-followups Phase 1 follow-up fixes (data plane core campaign)

- **status**: in_progress
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-10-02 15:09

## Description

Defects, gaps and limitations found while delivering Phase 1 of plan
`20261002-1024-data-plane-core` (campaign `nstun-dp-p1-202610021055`). Each was accepted
for Phase 1 and must be fixed in a later task. Items 1-4 change `boringtun`,
`nstun-packet`, `nstun-core` or `nstun-tun` and need their own plan before work starts.

1. **Data-path overhead at small packets.** `nstun-core/benches/data_path`: the core round
   trip is +14.5% vs the device-equivalent baseline at 64 B (+6.4% at 1420 B, within the
   10% target), +52% vs raw `Tunn::round_trip_in_place`. The remaining cost is spread over
   the engine structure; the candidate fixes change `nstun-packet` or the `Input` contract:
   an O(1) `PacketBuf` front-adjust (removes the two 16-byte `copy_within` shifts), dropping
   the rx buffer swap, keeping lengths in the pool (no `set_len` zero-fill). Fit with the
   Phase 5 batching/GSO work.
   Design input: plan `20261002-1024-data-plane-core`, annotation of 2026-10-02 on
   Tailscale's zero-copy receive path (slices sharing one GRO read, encrypting straight
   into the UDP GSO buffer, `writev` for the virtio-net header, measured queue depths).
2. **boringtun handshake API.** `nstun-core` gates handshakes with its own `RateLimiter`
   (shared with every `Tunn`, built with `handshake_rate_limit * 2` to offset the double
   count) because `Tunn::handle_verified_packet` is `pub(crate)`. Expose a
   verified-handshake entry point and a handshake counter or session id, then:
   remove the double count, and report `Event::HandshakeCompleted` for a re-handshake that
   completes within the same 250 ms timer tick (today it is missed; detection relies on
   `time_since_last_handshake` shrinking).
3. **Engine-level timers.** `Tunn` timers read boringtun's own clock and `nstun-core`
   calls `update_timers` without a time, so the engine's `now` does not drive persistent
   keepalive, rekey (120 s) or session expiry (540 s). Pass the engine's time in (e.g.
   `update_timers_at(now)`), then add engine-level timer tests in `nstun-e2e`. Related: the
   workspace test run uses `--all-features`, which enables `nstun-core/mock-instant` and
   freezes boringtun's clock for every crate; under it a re-handshake on an established
   session is rejected (TAI64N timestamp does not advance), so `force_handshake` is only
   tested as a first handshake. Core-level coverage exists (nstun-core tests, C3a).
4. **fd adoption from the CLI.** `--tun-fd`/`WG_TUN_FD` and `--uapi-fd`/`WG_UAPI_FD` were
   removed from `boringtun-cli` because adopting a raw fd needs `unsafe` and the CLI
   forbids it. Add a safe raw-fd constructor in `nstun-tun` (the unsafe-owning crate) if
   the flags are wanted back.
5. **Windows.** The Wintun device itself is untested (needs a Windows host with
   `wintun.dll`); `nstun-uapi` has no named-pipe listener; in `nstun/src/udp.rs` a
   truncated datagram may be attributed to the wrong sender when several tasks receive
   concurrently.
6. **MTU.** No MTU watcher in Phase 1: `TunSource::mtu()` never changes.
7. **Event semantics to document or change.** `Event::Authenticated` fires only when the
   source differs from the peer's current path; `HandshakeCompleted.rtt` is reported on
   the initiator only; a roamed path is compared on transport + addr and stored with
   `Ecn::NotEct`.
8. **Traffic counters.** `PeerStats` `rx`/`tx` (and therefore UAPI `rx_bytes`/`tx_bytes`
   and the `transfer` line of `wg show`) count only IP payload bytes from boringtun's
   `Tunn` counters; keepalives and handshakes are not counted, although `nstun-core`
   documents the fields as bytes on the wire and kernel WireGuard counts wire bytes.
   Count wire bytes in the core.
9. **Drop reason constants.** The drop reason `"handshake rejected"` has no public
   constant, unlike the other reasons; export one.

Status after Phase 2 (plan `20261002-1535-phase2-engine`, merged 2026-10-02 as d3d4f50):
items 2, 3, 4, 6, 7, 8 and 9 are fixed; item 5 is partly fixed (Windows UAPI named pipe
added); item 1 is open. Still open:

- item 1 (small-packet data-path overhead), scheduled after Phase 2 with the Phase 5
  design input in the plan;
- item 5: the Wintun device and the named pipe's `ProtectedPrefix` path and security
  descriptor are unverified on a real Windows host; the pipe uses the default descriptor
  (full control for LocalSystem/Administrators/creator, read for everyone else), so a
  non-elevated local process can occupy the waiting instance and delay clients;
  wireguard-windows restricts it to LocalSystem and Administrators (needs Win32 `unsafe`
  in an unsafe-owning crate); the UDP truncated-datagram sender attribution note stands;
10. **Head-of-line blocking across transports** (found in Phase 2): local reads pause
    while any transport has datagrams waiting, so one slow transport (e.g. a relay) holds
    back traffic for peers on other transports. Needs per-transport backpressure.
11. **Silent drop on transport removal** (found in Phase 2): datagrams already in a
    removed transport's transmit queue are dropped without a counted reason; count them.

Status after Phase 3 (plan `20261002-1725-phase3-4-netstack-acl`): items 10 and 11 are
fixed by workstream 3C (per-transport backpressure, `DROP_TRANSPORT_REMOVED`).

Out of this task: the rename to `nsplane` (ADR `docs/decisions/2026-10-02-rename-nsplane.md`,
its own task after the campaign) and Phase 2-6 scope of the plan.

## ActiveForm

Fixing Phase 1 data plane follow-ups

## Dependencies

- **blocked by**: 20261002-1020-data-plane-core (Phase 1 merged)
- **blocks**: (none)

## Notes

Item 1 numbers, item 2 and item 3 analysis come from the campaign's L2 reports for
workstreams C (nstun-core) and E (nstun-e2e); item 4 and 6 from D and B; items 8-9 from E.
