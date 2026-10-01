# ADR: `unsafe` code in the `boringtun` library crate

Status   : Accepted
Date     : 2026-10-01
Sunset   : none (structural; reassess if the platform layers move to safe wrappers)

## Context

pma-rust Lock 3 requires `#![forbid(unsafe_code)]` at every crate root. The `boringtun`
library owns the platform layer of a VPN: TUN devices (`ioctl`, `/dev/net/tun`, utun
control sockets), the epoll/kqueue event loops, the C ABI (`ffi`) and the JNI bindings.
None of these have safe wrappers that fit the existing design.

## Decision

- The workspace sets `unsafe_code = "deny"` and `unsafe_op_in_unsafe_fn = "deny"`.
- `boringtun-cli` declares `#![forbid(unsafe_code)]`.
- In `boringtun`, only these modules opt out with a module-level
  `#![allow(unsafe_code, reason = "...")]`: `device/epoll.rs`, `device/kqueue.rs`,
  `device/tun_linux.rs`, `device/tun_darwin.rs`, `ffi`, `jni`. Single statements elsewhere
  (adopting an inherited fd, `getlogin`, clearing an event under the device write lock) use
  a statement-level `#[allow]`.
- Every `unsafe` block carries a `// SAFETY:` comment.
- Where a safe API exists it is preferred: `nix` for `setuid`/`setgid`, `OwnedFd` for fd
  ownership, `std::net::UdpSocket` instead of `MaybeUninit` buffers, `std::os::unix::fs::chown`.

## Consequences

The `unsafe` surface is confined to the platform and FFI modules and is greppable via
`allow(unsafe_code`.
