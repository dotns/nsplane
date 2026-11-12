# 20261112-0202-sys-wrapper-crate A crate for `unsafe` OS calls behind safe functions, and the two gaps it closes

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 02:02

## Description

Two gaps stayed open because closing them needs an `unsafe` call and the crates concerned
forbid `unsafe` code:

1. Windows (`20261112-0104-windows-udp-port-ownership.md`): a process of the transport's own
   user binds one local address of a `UdpTransport`'s port (`127.0.0.1:port`, `[::1]:port`)
   and takes the datagrams sent to it. Only `SO_EXCLUSIVEADDRUSE` refuses that bind, and
   `socket2` has no setter for it.
2. macOS (`20261112-0103-sink-contract-outside-the-engine.md`, item 3): `nsplane-cli` keeps
   root's supplementary GIDs after the privilege drop, as `nix` has no `setgroups` on Apple
   targets.

The owner decided that one dedicated crate may hold `unsafe` calls behind a safe API.

Acceptance: `crates/nsplane-sys` with exactly the two functions needed, each safe for every
argument; `nsplane` stays `#![forbid(unsafe_code)]` and `nsplane-cli` keeps its single
allowed block; on Windows every socket of the UDP transport is bound for exclusive use, with
a test seen failing first on a Windows host; on macOS the drop leaves no GID of root, seen on
a macOS host before and after; no new crate version in `Cargo.lock`.

## ActiveForm

Adding `nsplane-sys` and using it for `SO_EXCLUSIVEADDRUSE` on Windows and `setgroups` on
macOS.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

### The crate

`nsplane-sys` has no dependency on any platform but two: `windows-sys` 0.61.2 on Windows
(the version `tokio`, `socket2`, `mio` and `quinn-udp` already resolve to, feature
`Win32_Networking_WinSock` only) and `libc` 0.2 on Apple targets. `Cargo.lock` gains the
workspace member and nothing else. On Linux the crate is empty. One `unsafe` block per
function, each allowed on its statement as in `nsplane-tun::windows`.

- `set_exclusive_address_use(socket: &impl AsSocket, exclusive: bool)` (Windows):
  `setsockopt(SOL_SOCKET, SO_EXCLUSIVEADDRUSE)` with a 4-byte `BOOL`. The handle comes from
  the borrowed socket, so it is open for the call.
- `set_supplementary_groups(gids: &[u32])` (Apple): `setgroups`. `gid_t` is `u32` there, so
  the slice is passed as it is. Not offered on other Unix targets, where `nix` has the safe
  call and the ADR prefers it. Measured on macOS 26.5: the first GID becomes the effective
  GID as well; more than 16 GIDs fail with `EINVAL` for every caller, before the privilege
  check; and an empty list does not empty anything: for a root process it left GID 0 as the
  only entry and as the effective GID. The wrapper therefore refuses an empty list with
  `InvalidInput` before the call.

The name contains a word the product-term scan looks for (`group`); the two lines are
allowlisted as OS vocabulary, like the existing entries for the CLI and the TAP module.

Not moved into the crate: the platform modules of `nsplane-tun` and the descriptor adoption
of `nsplane-cli`. The TUN modules are `unsafe` throughout and tied to the crate's own types
(reactor registration, ioctl structs, Wintun), so moving them would move the crate. The
CLI's `OwnedFd::from_raw_fd` cannot be a safe function at all: its soundness is the caller's
argument (who passed the number, and that nothing else uses it), which is exactly what the
new crate's functions must not depend on.

### 1. Windows

`udp/socket.rs`: `bind_socket` and `bind_v6_only` set the option between creating the socket
and binding it, on Windows only. That covers both sockets of `bind_pair`, its `0.0.0.0`
fallback, and every exact-address bind. The two-socket design is unchanged. A failure to set
the option fails the bind. Nothing in the workspace sets `SO_REUSEADDR` on these sockets
(`socket2`, `tokio`, `mio` and `quinn-udp` do not set it on Windows either), which the option
would refuse with `WSAEINVAL`.

Measured on Windows 11 (build 26100), one process, an elevated administrator, UDP, first
socket bound then a second one on the same port; identical for IPv4 and IPv6-only sockets:

| first socket | second: wildcard, plain / reuse / exclusive | second: loopback, plain / reuse / exclusive |
| --- | --- | --- |
| wildcard, plain | `10048` / `10013` / `10048` | bound / bound / bound |
| wildcard, exclusive | `10048` / `10013` / `10048` | `10013` / `10013` / `10013` |
| loopback, plain | bound / bound / `10048` | `10048` / `10013` / `10048` |
| loopback, exclusive | bound / bound / `10048` | `10048` / `10013` / `10048` |
| wildcard, `SO_REUSEADDR` | `10048` / bound / `10048` | bound / bound / bound |
| loopback, `SO_REUSEADDR` | bound / bound / `10048` | `10048` / bound / `10048` |

(`10048` is `WSAEADDRINUSE`, `10013` `WSAEACCES`.) An exclusive IPv6-only socket on `[::]`
leaves every IPv4 bind of the port alone, so the two sockets of a pair do not get in each
other's way. What follows for the transport:

- The hole is closed: next to a transport on a wildcard address every bind of a local
  address of the port fails (row 2).
- New refusals: a transport does not bind a wildcard address while any socket holds a local
  address of the port (rows 3, 4 and 6, last column of the wildcard group), where the plain bind
  went through. The error is `AddrInUse` in every case, so `bind_pair`'s retry and fallback
  rules did not need a change.
- Two transports no longer share a port by binding different addresses of it: after
  `[::]:port`, a transport on `127.0.0.1:port` fails with `PermissionDenied`.
- An exact-address transport gains nothing measurable from the option (rows 3 and 4 are the
  same) and still does not keep others from the wildcard address of its port.
- Setting the option on a bound socket does not fail on Windows 11; the wrapper documents
  that it is set before `bind`.

Wine accepts the option and refuses every second bind of a port with or without it
(`10048`, with `SO_REUSEADDR` `10013`), so it cannot show the difference. The `nsplane` tests
assert a failed bind, which holds on every platform; the one `nsplane-sys` test that needs
the plain bind to succeed is ignored by default, like the pipe test of `nsplane-uapi`, and
runs on a Windows host with `--include-ignored`.

Left as they are:

- `nsplane-uapi`: binds through `UdpTransport`, so it is covered; its listener is a named
  pipe.
- `nsplane-wss` and the `nsplane-dns` server take listeners and sockets the embedder bound;
  the option is the embedder's to set, and `nsplane-sys` is there for it.
- `nsplane-dns::Forwarder` binds one UDP socket per upstream attempt on a wildcard address
  and an OS-chosen port, connects it and drops it within the timeout. Whether a same-user
  socket on one local address of that port could take a response was not measured. Left: a
  short-lived client socket on a random port, with the response checked against a random
  transaction id and the question.
- The example binaries and the tests bind plain sockets.
- Not measured with the option: binds by another user (refused already without it), service
  accounts, TCP.

### 2. macOS

`drop_privileges` has one sequence for every platform again: for a root process `setgroups`
with the target GID (through `nix`, or through `nsplane-sys` on Apple targets, one line
each), then `setgid`, then `setuid`. The target GID is the only entry, so the effective GID
the call sets on macOS is the one `setgid` sets next.

Not measured: which GIDs the kernel resolves for the new UID on its own after `setuid`
(directory service memberships of the target user); the list the kernel holds for the
process is the one entry.

## Validation

Windows 11 host (test executables cross-built for `x86_64-pc-windows-gnu`, copied over and
run there):

- Before the change, `udp::tests::wildcard_bind_owns_the_local_addresses_of_the_port` fails:
  `called Result::unwrap_err() on an Ok value: UdpSocket { addr: 127.0.0.1:53899 }`. That a
  socket bound this way gets the datagrams was measured in
  `20261112-0104-windows-udp-port-ownership.md` (4 of 4) and not repeated.
- After: `nsplane` unit tests 196 of 196 (with the new test and
  `unspecified_bind_fails_on_a_port_with_a_taken_local_address`), `tests/engine.rs` 49,
  `plaintext_egress` 7, `tags` 5, `tracked` 21, `nsplane-uapi` 19 (1 ignored) and
  `tests/uapi.rs` 9, `nsplane-sys` 3 of 3 with `--include-ignored`. No failure.

macOS 26.5 host (arm64), native `cargo test -p nsplane-sys -p nsplane-cli --all-features
--locked`: 7 + 3 CLI tests and 2 `nsplane-sys` tests pass, 1 ignored;
`apple::tests::root_replaces_the_list` passes under `sudo` (root's 16 GIDs replaced by one,
read back with `getgroups`). The five bind tests of `nsplane` pass there as well.

End to end on that host: the built `nsplane-cli utun` started with `sudo` and `SUDO_UID` /
`SUDO_GID` of `nobody`, then the credentials the kernel holds for the process read from
outside with `sysctl` (`KERN_PROC_PID`, `kinfo_proc.kp_eproc.e_ucred`):

- Before: `euid=4294967294 ... ngroups=16 groups=4294967294,1,2,3,4,5,8,9,12,20,29,61,80,33,98,100`
  (`daemon`, `kmem`, `sys`, `tty`, `operator`, `procview`, `procmod`, `staff`, `admin` and
  others of root).
- After: `euid=4294967294 ruid=4294967294 svuid=4294967294 rgid=4294967294
  svgid=4294967294 ngroups=1 groups=4294967294`.

In the container: `cargo fmt --all --check`; `cargo hack clippy --each-feature --all-targets`
for `nsplane-sys`, `nsplane` and `nsplane-cli` on Linux, and for `nsplane-sys`, `nsplane` and
`nsplane-uapi` on `x86_64-pc-windows-gnu`; `cargo-zigbuild clippy` for
`aarch64-apple-darwin`; `cargo nextest run` for the three crates, `nsplane-uapi` and
`nsplane-e2e` (719 passed, 23 skipped); doc tests; `cargo hack check --workspace
--rust-version`; `cargo deny check`; `cargo shear`; `typos`; `scripts/check-docs.sh`;
`scripts/check-product-terms.sh`; and the wine run of the `nsplane-sys`, `nsplane` and
`nsplane-uapi` tests. All pass.
