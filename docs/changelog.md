# nstun - Development Changelog

Project-level history for PMA task and plan tracking. Release notes for the crates live in
the root `CHANGELOG.md`.

## 2026-10-01 19:05 [decision]

Forked cloudflare/boringtun `6dcc889` as `dotns/nstun`. Approved plan
`20261001-1859-fork-baseline`: remove upstream CI, adopt the pma-rust baseline, switch the
crypto backend from `ring` to `aws-lc-rs`, re-implement gotatun fixes F1-F10, add a
zero-copy data path and Windows support. gotatun code is not copied (MPL-2.0).

## 2026-10-01 19:34 [progress]

Phase B (pma-rust baseline) done: edition 2024, MSRV 1.95, toolchain 1.99.0,
`[workspace.lints]`, `missing_docs` on the library, `unsafe` confined to platform/FFI
modules with SAFETY comments (ADR `2026-10-01-unsafe-code-in-boringtun`), no CI
(ADR `2026-10-01-no-ci`), `daemonize` advisory waived (ADR `2026-10-01-daemonize-advisory`).
`just check` and `just cross` (macOS via zig, Windows via mingw-w64 + nasm) pass.

## 2026-10-01 19:34 [pitfall]

- `cargo clippy --fix` rewrote `Duration` subtraction into `checked_sub(..).unwrap()`;
  replaced with `saturating_sub`.
- Building `aws-lc-sys` for `x86_64-pc-windows-*` requires NASM on the build host.
- `kqueue.rs`/`tun_darwin.rs` are invisible to Linux builds; use `just cross`.

## 2026-10-01 19:48 [progress]

Phase D done: F1-F10 re-implemented with failing tests first (no gotatun code copied).
`device::PeerTable` extracted to make peer updates testable. `just check` and `just cross` pass.

## 2026-10-01 19:48 [pitfall]

- With `mock-instant`, timer ticks use the time of the last `update_timers` call; tests must
  call `update_timers` after advancing the clock, as the device does every 250 ms.
- Re-handshake tests need the mock clock to advance, or the responder rejects the initiation
  timestamp as a replay.

## 2026-10-01 20:19 [progress]

Phase F done (Windows). Plan `20261001-1859-fork-baseline` completed: all phases A-F landed,
`just check`, `just cross`, `just test-windows` and `just e2e` pass. Not verified on a real
Windows host with the Wintun driver.

## 2026-10-01 20:19 [pitfall]

- A clap derive `bool` flag only accepts `true`/`false` from its env var; use
  `BoolishValueParser` to keep `WG_SUDO=1` working.
- Under wine, `wintun.dll` cannot load, so the Windows device stops at adapter creation.

## 2026-10-02 10:20 [decision]

ns consumes nstun as a library; the CLI is a Linux/macOS development tool. Task
`20261002-1008-cli-dev-tool`: the CLI runs in the foreground only and no longer builds on
other targets; `daemonize` and its advisory waiver are gone (ADR superseded). The Windows
`device` layer stays in the library as a fallback.

## 2026-10-02 10:50 [decision]

Plan `20261002-1024-data-plane-core` approved: nstun becomes the complete data plane with
a sans-I/O core (`nstun-core`), a tokio driver (`nstun`), platform I/O (`nstun-tun`), an
in-process netstack, and the ACL; `boringtun::device` is deleted after Phase 1. Architecture
reviewed against firezone connlib, tailscale tstun/wgengine, gotatun, NepTUN, wireguard-go,
netbird, EasyTier and the userspace-stack crates. Phase 1 is executed as a BKD campaign.

## 2026-10-02 13:10 [progress]

Added `docs/design.md`, the one-page design overview (position in the NS architecture,
non-goals, principles, crate map, engine model, roadmap, decisions). Plan
`20261002-1024-data-plane-core` aligned with the NS next-architecture page: 4↔6
translation and fragmentation in Phase 5, both ns data planes in Phase 6, workstream E.

## 2026-10-02 14:40 [decision]

The project is renamed **nsplane**: it is the node's underlying data plane, not a TUN.
ADR `2026-10-02-rename-nsplane` records the candidates checked, the crate scheme
(`nsplane-noise`, `nsplane-core`, `nsplane`, `nsplane-tun`, ...) and the timing: executed
as its own task after the Phase 1 BKD campaign merges D and E. The docs-site nstun pages
were rewritten from `docs/design.md`.

## 2026-10-02 14:50 [progress]

Phase 1 workstream D done: the `nstun` Engine facade (`EngineBuilder`, `Engine`,
`EngineHandle`, broadcast events, bounded transmit backlog and engine drop counters),
`nstun-uapi` (the `wg` UAPI over an engine, Unix socket listener), `boringtun-cli` on the
engine (tokio runtime, `--tun-fd`, `--uapi-fd`, `--disable-connected-udp` and
`--disable-multi-queue` removed, privilege drop via `SUDO_UID`/`SUDO_GID`), and the deletion
of `boringtun::device`, the `device` feature, its dependencies and `just integration`.
`just e2e` passes unchanged against kernel WireGuard. README, CHANGELOG, architecture and
the unsafe/Wintun ADRs updated; ADR `2026-10-02-async-engine-replaces-sync-device` added.

## 2026-10-02 15:36 [progress]

Task `20261002-1529-repo-cleanup-layout` done together with the rename (ADR
`2026-10-02-rename-nsplane`): the crates moved under `crates/` with their nsplane names
(`nsplane-noise`, `nsplane-cli`, `nsplane`, `nsplane-core`, `nsplane-packet`,
`nsplane-tun`, `nsplane-uapi`, `nsplane-e2e`), identifiers, test interface names, e2e env
vars and container prefixes follow. The FFI/JNI bindings, the upstream crypto benches and
the banner/logo images are deleted. Attribution (Cloudflare copyright, dotns copyright,
origin, WireGuard trademark) lives only in `LICENSE.md`; README and the living docs use the
new names.

## 2026-10-03 15:35 [decision]

Plan `20261003-1630-perf-and-wss` PW widened by the user: the WsFrame terminate leg (ns
`tunnel-ws` `WsTunnel`) moves into `nsplane-wss` now as PW (c), with OPEN resolution behind an
embedder trait, so ns can delete `tunnel-ws` whole. ADR
`2026-10-03-data-channel-protocols-in-nsplane` consequence updated (both legs move).

## 2026-10-04 06:00 [progress]

Campaigns since the Phase 5 follow-ups, all merged into `main` with their final gates and
the full e2e suites green: traffic counters and `EngineHandle::status`; the ns M4 engine hooks
(`inject_outbound_on`, `PacketFilter::inbound_from`, `observe_every_message`,
`force_handshake_on`, netstack accept backpressure and ports); the ns data-plane moves (plan
`20261003-1600`: netstack ownership, reassembly, send progress; UDP side channel and
`LinkTransport`; `Nat64Lan` and `Redirect`); throughput and WSS (plan `20261003-1630`:
benchmark harness, engine fast path +17 % / +19 %, netstack fixes, `nsplane-wss`); the ACL and
node L3 gate (plan `20261003-2300`, differential fixtures against ns); the local side (plan
`20261003-2330`: graph primitives, `Masquerade`, Echo reply, `TunSlot`, `host_tun`). ADR
`2026-10-03-data-channel-protocols-in-nsplane`: every data-channel protocol lives in nsplane.

## 2026-10-04 11:00 [release]

Release 0.8.0 (tag `v0.8.0`), the first release under the nsplane name. Quiet-host comparison
on main: nsplane <-> nsplane 8.1 / 8.9 Gbit/s (1 / 4 TCP streams), kernel WireGuard ->
nsplane 7.0, nsplane -> kernel 7.7, wireguard-go 10.0 / 10.1.

## 2026-10-04 15:30 [release]

Release 0.9.0 (tag `v0.9.0`): the remaining ns requests (plan `20261004-1100-ns-requests`,
campaigns RN, RW, RA, RS, RX), all additive. Next: the optimization round (quiet-host
re-measure, multi-stream throughput against wireguard-go, netstack 4-stream anomaly).
