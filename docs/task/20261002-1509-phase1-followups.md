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

12. **UAPI listen-port rebinding** (found in 3D): on `tun_node`, `wg set <if> listen-port`
    makes nsplane-uapi replace the transport it manages with plain UDP, which drops a
    relay/WSS transport configured for that id; UAPI should rebind only a UDP transport it
    owns and leave other transports alone.
13. **Fixed e2e container prefixes** (found in Phase 3+4): `scripts/e2e/linux.sh` and
    `lib.sh` default to fixed prefixes, so concurrent runs remove each other's containers;
    derive the default from the PID as `examples.sh` does.

Status after Phase 5 (5B, branch `bkd/qni0z073`): item 12 is fixed by
`Uapi::with_external_transport` (`listen_port=`/`fwmark=` leave a transport the UAPI does
not own alone; covered by the `nsplane-uapi` unit tests and `nsplane-e2e`'s
`uapi::listen_port_leaves_an_external_transport_alone` and
`uapi::listen_port_rebinds_an_owned_udp_transport`); item 13 is fixed by PID-derived
default prefixes in `linux.sh` and `lib.sh` (`nsplane-e2e-$$`, `nsplane-e2e-lib-$$`),
verified by two concurrent default-prefix runs of each script.

Status of item 1 after Phase 5 workstream 5C (follow-up #1, 2026-10-02): the rx buffer swap,
both `copy_within` shifts and the `set_len(BUF_SIZE)` zero-fills on the timer, queue-flush
and handshake-reply paths are gone. `Input::Datagram` takes the datagram by value and the
core delivers the plaintext in the same buffer (`advance` past the data header); local
packets are sealed in place with the data header in their headroom (pooled copy only when
the headroom is smaller than the data header); `PacketPool::get_len` reuses pooled bytes
without re-zeroing them. Measured with `cargo bench -p nsplane-core --bench data_path`
(release, criterion mean; shared 32-core host, so the absolute numbers move between runs):

| run | size | raw `Tunn` | device-equivalent | core | core vs device |
| --- | --- | --- | --- | --- | --- |
| before, run 1 | 64 B | 486 ns | 561 ns | 562 ns | +0.1 % (noisy) |
| before, run 2 | 64 B | 365 ns | 471 ns | 550 ns | +16.8 % |
| before, run 1 | 1420 B | 1.22 us | 1.29 us | 1.37 us | +5.8 % |
| before, run 2 | 1420 B | 1.17 us | 1.32 us | 1.39 us | +5.2 % |
| after, run 1 | 64 B | 359 ns | 471 ns | 535 ns | +13.6 % |
| after, run 2 | 64 B | 409 ns | 476 ns | 530 ns | +11.4 % |
| after, run 1 | 1420 B | 1.16 us | 1.27 us | 1.33 us | +5.1 % |
| after, run 2 | 1420 B | 1.19 us | 1.73 us | 1.83 us | (host load) |

Instruction counts per round trip (callgrind, independent of the host load): 64 B core
5404 -> 5207 (device-equivalent 4431, raw 3078: core vs device +22.0 % -> +17.5 %);
1420 B core 20795 -> 20225 (device-equivalent 19476: +6.8 % -> +3.8 %). The 1420 B target
holds; the 10 % target at 64 B is not reached. The remaining ~780 instructions per round
trip are the core's own dispatch rather than buffer handling: `handle_input` (~460: input
dispatch, data-header parsing, session-index and peer lookups, the output queue),
`transmit` (~85), `authenticated` (~60) and the extra allowed-IP wrapper (~45). Skipping
the roaming check in steady state and the duplicate peer lookup on send made no
measurable difference. Further gains need a leaner dispatch (e.g. a batched data-path
entry point), which belongs with the Phase 5 batching work.

Dispatch trim (same follow-up, second pass): the roaming check is skipped for a data
message that completes no handshake and comes from the current path, `send` reuses its peer
borrow for `transmit`, and handshake and configuration handling stay out of line so
`handle_input` keeps a small frame. Instructions per round trip: 64 B core 5208 -> 5126
(device-equivalent 4431: +17.5 % -> +15.7 %); 1420 B 20222 -> 20146 (+3.8 % -> +3.4 %).
Wall clock on a host at load ~85 (absolute numbers about twice the quiet ones): 64 B core
1219 / 1113 ns vs device-equivalent 1083 / 1010 ns (+12.6 % / +10.2 %); 1420 B 3.15 / 3.02 us
vs 3.15 / 2.90 us (+0.0 % / +4.3 %). The 64 B target is still not met.

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
