# ADR: An async engine replaces the synchronous `boringtun::device`

Status   : Accepted
Date     : 2026-10-02
Sunset   : none (structural)

## Context

The inherited `boringtun::device` layer was a synchronous device: an epoll (Linux) or
kqueue (macOS) event loop with N threads around a shared, locked peer state, and on Windows
a separate model of one blocking thread per task (Wintun reader, UDP readers, timers, UAPI
pipe). The two platforms shared only the per-packet functions and the UAPI parser. ns, the
main consumer, is a tokio application and needs the data plane as a library it can drive
with its own packet sources (TUN, netstack, host bridges), transports and events, which the
device could not offer without its own threads and locks.

## Decision

- Split the data plane into a sans-I/O core and a driver (plan
  `20261002-1024-data-plane-core`, Phase 1):
  - `nstun-packet`: buffers and value types; `nstun-core`: the sans-I/O engine core over
    `boringtun::noise`, with no I/O and no clock of its own;
  - `nstun`: the tokio driver, one owner task per engine and I/O tasks connected through
    bounded queues, configured through `EngineHandle`, reporting `Event`s;
  - `nstun-tun`: TUN devices for Linux, Android, macOS, iOS and Windows (Wintun);
  - `nstun-uapi`: the `wg` UAPI over an `EngineHandle`.
- Once the engine and the CLI on it pass the e2e, delete `boringtun::device`, the `device`
  feature and the dependencies only it used. `boringtun` keeps `noise`, `ffi` and `jni`.

## Consequences

- `boringtun-cli` runs on the engine. Flags that configured the synchronous device are
  gone (`--disable-connected-udp`, `--disable-multi-queue`), and so are `--tun-fd`/`WG_TUN_FD`
  and `--uapi-fd`/`WG_UAPI_FD`: adopting a raw fd needs `unsafe`, which the CLI forbids. The
  library keeps `nstun_tun::Tun::from_fd`. The privilege drop uses `SUDO_UID`/`SUDO_GID`.
- One thread model on every platform: the tokio runtime. Windows differs only in the TUN
  backend; it has no UAPI listener (named pipe) yet.
- `unsafe` is confined to `boringtun`'s FFI/JNI and `nstun-tun`'s platform modules; the new
  crates and the CLI forbid it (ADR `2026-10-01-unsafe-code-in-boringtun`).
- The upstream integration tests (`just integration`) went with the device. The e2e against
  kernel WireGuard (`scripts/e2e/linux.sh`, `just e2e`) is unchanged and passes on the
  engine-based CLI.
- Upstream changes to `boringtun::device` no longer apply; only `noise` changes can be ported.
