# 20261111-2304-uapi-socket-and-jitter UAPI socket hardening, reconnect and router advertisement jitter

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-11 23:04

## Description

Six audited hardening items in `nsplane-uapi`, `nsplane-wss`, `nsplane-ether` and the
architecture document:

1. The UAPI Unix socket took its mode from the process umask, although `get=1` answers with
   the private key.
2. `UapiListener::bind_path` removed whatever was at the socket path, a regular file or a
   symlink included.
3. `Uapi::serve` spawned one task per accepted connection without a limit.
4. The WSS dialer waited exact delays, so the dialers of a restarted server came back in
   synchronized waves.
5. The periodic router advertisement of `spawn_port` went out at a fixed interval; RFC 4861
   6.2.4 asks for a random one.
6. `docs/architecture.md` claimed that `unsafe` lives only in `nsplane-tun`.

Acceptance: a test per behavior change, the gates of the three crates and of `nsplane-cli`
pass on Linux, and the lints for Windows and macOS targets. No push, tag or release.

## ActiveForm

Hardening the UAPI socket and adding jitter to the WSS backoff and the router advertisements.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

1. `bind_path` binds through `tokio::net::UnixSocket`, sets mode `0600` on the socket file
   and only then listens. A bound socket that does not listen refuses connections
   (`ECONNREFUSED` on Linux and macOS), so no client connects under the umask mode: there is
   no window to document, and neither a process-wide `umask` change nor a private directory
   with a rename is needed. The backlog is 1024, capped by the kernel.

   The socket is not handed to `SUDO_UID` the way `/var/run/wireguard` is. Connecting to a
   Unix socket needs write permission on it, so under the usual umask 022 a root-owned socket
   already took root to connect; wireguard-go behaves the same (umask 077 around the bind),
   and boringtun only hands over the directory. The visible change is for a daemon started
   with `sudo` under a umask without the write bits masked (002, 000): the invoking user or
   other users could connect and read the private key, and now need `sudo wg`. A daemon
   started unprivileged (`setcap`, the README workflow) owns its socket, and `wg` run by the
   same user works as before.
2. Only a socket is removed (`symlink_metadata`, so a symlink to a socket is not one).
   Anything else fails with `AlreadyExists` and is left alone. No liveness detection: a
   socket with an active listener is still replaced. The integration test that planted a
   regular file as the stale socket now leaves a real stale socket.
3. The limit is an internal constant (64) in the shared accept loop, so it covers the Unix
   socket and the Windows named pipe; a connection over it is dropped right after the
   accept, logged at debug level. The stream of `serve_stream` (`--uapi-fd`) is not counted.
   The Windows path is compiled and linted, not run.
4. Each wait (`reconnect_delay`, and every step of the backoff) is a random time between
   half of its delay and the delay. The stored delay stays exact, so the doubling and its
   cap go by the configured values and `backoff_max` remains the upper bound. The random
   value comes from the standard library (`RandomState`), as `nsplane-netstack` does for its
   first ephemeral port: no new dependency. `nsplane-e2e` `wss_events` asserted the delays as
   lower bounds; it now asserts half of them.
5. `spawn_port` waits a random time between three quarters of `RA_INTERVAL` and
   `RA_INTERVAL` (450 to 600 s) before each periodic advertisement, with the same source of
   randomness. `RA_INTERVAL` is unchanged and documented as the upper bound; the adapter
   stays without a clock. The paused-time test takes six repeats instead of four so that it
   still passes the router lifetime with the shortest waits.
6. The section now names both crates with `unsafe` (`nsplane-tun`, `nsplane-ether`), lists
   the crates that forbid it at the root, and describes binaries and tests by the workspace
   lint (an explicit `allow` per statement) instead of claiming that they have none.

## Validation

New tests: `listener::tests::{the_socket_is_owner_only, a_stale_socket_is_replaced,
a_path_that_is_not_a_socket_is_kept}`, `connections_above_the_cap_are_closed`
(`nsplane-uapi` integration, 30 of 30 under `--stress-count`), `connect::tests::{
jitter_spreads_a_wait_over_its_upper_half, jittered_waits_differ}`,
`port::tests::the_wait_is_in_the_last_quarter_of_the_interval`, and the extended
`port::tests::router_advertisements_repeat_once_the_guest_is_known`. The mode test failed
with `0755`, the path test and the cap test failed before their fixes.

Gates: `cargo fmt --all --check`; `cargo hack clippy` over the three crates with each
feature, for Linux and for `x86_64-pc-windows-gnu` (`nsplane-uapi`, `nsplane-ether`);
`cargo-zigbuild clippy` for `aarch64-apple-darwin`; `cargo nextest run` over the three crates
and `nsplane-cli`; `cargo deny check`; `cargo shear`; `typos`; `scripts/check-docs.sh`;
`scripts/check-product-terms.sh`. The `nsplane-e2e` tests `wss_events`, `wss_datagram` and
`wss_plain` pass with the jitter.
