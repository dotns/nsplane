# ADR: `unsafe` code in the `boringtun` library crate

- **Status**: Accepted
- **Date**: 2026-10-01
- **Review**: none (structural; reassess if the platform layers move to safe wrappers)

## Context

pma-rust Lock 3 requires `#![forbid(unsafe_code)]` at every crate root. The data plane owns
the platform layer of a VPN: TUN devices (`ioctl`, `/dev/net/tun`, utun control sockets,
Wintun), the C ABI (`ffi`) and the JNI bindings. None of these have safe wrappers that fit
the design.

Until 2026-10-02 the TUN devices and the epoll/kqueue event loops lived in
`boringtun::device`; they were deleted with it (ADR
`2026-10-02-async-engine-replaces-sync-device`).

## Decision

- The workspace sets `unsafe_code = "deny"` and `unsafe_op_in_unsafe_fn = "deny"`.
- `nstun-packet`, `nstun-core`, `nstun`, `nstun-uapi` and `boringtun-cli` declare
  `#![forbid(unsafe_code)]`.
- In `boringtun`, only `ffi` and `jni` opt out with a module-level
  `#![allow(unsafe_code, reason = "...")]`; `noise` has no `unsafe`.
  ffi/jni removed 2026-10-02: the library crate has no `unsafe` left.
- In `nstun-tun`, the platform modules `unix`, `linux` and `darwin` opt out at module level;
  `windows` allows a single statement (loading the Wintun library).
- Safe public functions do not take ownership of a descriptor number: the library accepts
  `OwnedFd` (`Tun::from_fd`). `nsplane-cli` gets descriptor numbers from its invoker
  (`--tun-fd`, `--uapi-fd`), so it declares `#![deny(unsafe_code)]` and allows one block, in
  a private helper that runs before the process opens any descriptor and refuses the
  standard streams, closed numbers and repeated numbers.
- Every `unsafe` block carries a `// SAFETY:` comment.
- Where a safe API exists it is preferred: `nix` for `setuid`/`setgid`, `OwnedFd` for fd
  ownership, `socket2` and `std::net` for sockets.

## Consequences

The `unsafe` surface is confined to the FFI and TUN platform modules and is greppable via
`allow(unsafe_code`.

## Status history

- 2026-10-02: updated; the device layer moved to `nstun-tun`.
- 2026-11-11: updated; `adopt_fd` and `Tun::from_raw_fd` left the public API of the TUN
  crate, and the conversion from a descriptor number moved into `nsplane-cli`.
