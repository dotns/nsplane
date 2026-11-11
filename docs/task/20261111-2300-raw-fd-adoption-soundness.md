# 20261111-2300-raw-fd-adoption-soundness Safe functions took ownership of a descriptor number

- **status**: completed
- **priority**: P2
- **owner**: audit-fix
- **createdAt**: 2026-11-11 23:00

## Description

Audit finding: `nsplane_tun::adopt_fd(fd: RawFd)` and `Tun::from_raw_fd(fd: RawFd, mtu)` were
safe `pub fn`s around `OwnedFd::from_raw_fd`. Safe code could hand them any number and close a
descriptor owned by something else, or close one twice (an I/O-safety violation).

Acceptance: the library takes `OwnedFd` only (`Tun::from_fd`); the two functions are gone
from the public API. `nsplane-cli` keeps `--tun-fd` / `--uapi-fd` and converts the numbers in
one private, documented `unsafe` block that runs before the process opens any descriptor and
refuses the standard streams, closed numbers and the same number twice. The `fd_bridge`
example needs no `unsafe`.

## ActiveForm

Removing the raw descriptor adoption from the TUN crate and hardening it in the CLI.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Breaking change for the next 0.x release: `nsplane_tun::adopt_fd` and `Tun::from_raw_fd` are
removed; callers build the `OwnedFd` themselves and call `Tun::from_fd`.

CLI: `#![forbid(unsafe_code)]` became `#![deny(unsafe_code)]` with one `allow` in `adopt_fd`.
`main` adopts the descriptors right after argument parsing (`Inherited::adopt`), before the
logger and the tokio runtime; adopted descriptors get `FD_CLOEXEC`. `nix` 0.31 `fcntl` takes
`AsFd`, so the number cannot be probed with `F_GETFD` before an owned or borrowed handle
exists: the helper builds the `OwnedFd` first, probes through it, and on `EBADF` releases the
number with `into_raw_fd` instead of closing it. No safe conversion exists that keeps the same
open file description for an arbitrary number.

`fd_bridge --mode fd` now passes the TUN as the child's standard input (`Stdio::from(OwnedFd)`)
and the child duplicates it with `try_clone_to_owned`; the internal `--child-fd <N>` flag
became `--child`.

## Validation

Unit tests in `crates/nsplane-cli/src/main.rs` cover adoption of open descriptors (same
number, `FD_CLOEXEC` set, same socket), and refusal of 0-2 and negative numbers, of a closed
number and of the same number twice; `crates/nsplane-cli/tests/cli.rs` still sees a closed
`--tun-fd` / `--uapi-fd` fail startup. `crates/nsplane-tun/tests/fd.rs` uses `Tun::from_fd`.

Smoke on a real TUN device (container with `NET_ADMIN`): `nsplane-cli --tun-fd 3 --uapi-fd 4`
serves the UAPI on both sockets with both descriptors close-on-exec, and `fd_bridge --mode fd`
starts its engine on the TUN inherited as standard input. The workspace gates pass (fmt,
clippy per feature and for `aarch64-apple-darwin`, 209 tests, deny, shear, typos, docs and
product-term checks).
