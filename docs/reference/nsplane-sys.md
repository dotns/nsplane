# nsplane-sys

Safe wrappers over the few OS calls the nsplane crates need and no safe dependency provides.
The crates that use them forbid `unsafe` code, so the `unsafe` blocks live here, one per
call. It builds on `windows-sys` (Windows) and `libc` (Apple platforms) and on no nsplane
crate; `nsplane` uses it on Windows and `nsplane-cli` on macOS. An embedder that binds its
own listening sockets on Windows, such as the ones it hands to `nsplane-dns`, can call it for
the same purpose.

## Public API

| Item | Role |
|---|---|
| `set_exclusive_address_use(socket: &impl AsSocket, exclusive: bool) -> io::Result<()>` (Windows) | `setsockopt` with `SO_EXCLUSIVEADDRUSE` |
| `set_supplementary_groups(gids: &[u32]) -> io::Result<()>` (Apple platforms) | `setgroups` |

A function exists only on the platform its call belongs to; on every other target the crate
is empty.

## Behavior

Every function is safe for every argument. It takes typed handles and slices (`AsSocket`,
`&[u32]`), never a descriptor number or a pointer, checks the lengths the call takes, and
returns the error of the call as an `io::Error`. No function keeps state, and none takes
ownership of what it is given.

### `set_exclusive_address_use`

Turns `SO_EXCLUSIVEADDRUSE` on or off for a socket. The option is set before `bind` (the
call does not fail on a bound socket, so the order is the caller's to keep), and it excludes
`SO_REUSEADDR` on the same socket. With it on, a socket bound to a wildcard address owns
every local address of its port in its address family: a later bind of the wildcard address
or of one local address fails, whatever options that socket sets, and the socket's own bind
fails with `WSAEADDRINUSE` while another socket holds any address of the port. The results
per combination are in [nsplane](nsplane.md#udp-transport), whose `UdpTransport` sets the
option on every socket it binds on Windows.

### `set_supplementary_groups`

Replaces the supplementary GIDs of the process. `nix` provides `setgroups` on every Unix
target except the Apple ones, which is why the function exists for those only. The kernel
keeps the effective GID as the first entry of the list, so `gids[0]` becomes the effective
GID as well; a caller that goes on to `setgid`, as the privilege drop of
[nsplane-cli](nsplane-cli.md) does, passes that GID first.

## Errors and drop reasons

| Function | Error | When |
|---|---|---|
| `set_exclusive_address_use` | `InvalidInput` (`WSAEINVAL`) | the socket has `SO_REUSEADDR` set |
| `set_supplementary_groups` | `InvalidInput` | an empty list (refused before the call: the kernel would make GID 0 the only entry and the effective GID), or more than 16 GIDs (`EINVAL`) |
| `set_supplementary_groups` | `PermissionDenied` (`EPERM`) | the process is not root |

A failed call changes nothing.

## Platform notes

- `unsafe` code: one block per function, each a single FFI call with a `SAFETY` comment. The
  soundness of a block does not depend on the caller: the socket handle is borrowed for the
  call, and the option value and the GID list are borrowed memory the call copies.
- Wine accepts `SO_EXCLUSIVEADDRUSE` and keeps one port space for all local addresses with
  or without it, so there the option changes no bind result.
- `set_supplementary_groups` has two unit tests for an unprivileged process and one for
  root, which changes the credentials of the test process and is ignored by default
  (`sudo <test executable> --ignored --exact apple::tests::root_replaces_the_list`).

## See also

- [nsplane](nsplane.md): the UDP transport that sets `SO_EXCLUSIVEADDRUSE`.
- [nsplane-cli](nsplane-cli.md): the privilege drop.
- [Architecture](../architecture.md#unsafe-code): where the workspace allows `unsafe` code.
