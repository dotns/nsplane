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
