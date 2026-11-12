# 20261112-0104-windows-udp-port-ownership A transport on `[::]:port` does not own the IPv4 side of its port on Windows

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 01:04

## Description

Found on a Windows 11 host (build 26100). `UdpTransport::bind` of `[::]:port` bound one
dual-stack IPv6 socket. On Windows that socket does not own the IPv4 side of the port: a plain
bind of `0.0.0.0:port` by another socket still succeeds, and from then on every IPv4 datagram
to the port goes to that socket and none to the transport, whichever was bound first. The
mirror image: with an IPv4 listener already on the port the transport's bind succeeded, so
`nsplane-uapi` answered `listen_port=` with errno 0 for a port that was in use.
`nsplane-uapi`'s `listen_port_rebinds_the_transport` asserts the first half and failed on the
host; wine shares one port space between the families and hid it.

Acceptance: on Windows nobody else binds `0.0.0.0:port` while the transport holds `[::]:port`,
and a port whose IPv4 side is taken is reported in use; IPv4 and IPv6 datagrams are both
received and sent by one transport; other platforms behave as before; no unsafe code, no new
dependency, no change of the public API.

## ActiveForm

Binding two sockets for `[::]:port` on Windows and measuring what they leave open.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

`SO_EXCLUSIVEADDRUSE` on the dual-stack socket refuses the IPv4 bind, but `socket2` 0.6 has no
safe setter for it and `nsplane` forbids unsafe code, so that route stays closed.

Decision: on Windows only, `[::]:port` is two sockets on one port, an IPv6-only one and an
IPv4 one (`udp/socket.rs::bind_pair`).

- Bind: the IPv6-only socket first, then `0.0.0.0` on the port it got. For port 0 an
  ephemeral port that is taken for IPv4 (`AddrInUse`, or `PermissionDenied` from a holder with
  `SO_EXCLUSIVEADDRUSE`) is given up for another, up to 16 more tries. For a given port the
  IPv4 error is returned and the IPv6 socket dropped, so nothing stays bound. If the IPv6
  socket cannot be had for another reason than a port in use, `0.0.0.0:port` is bound alone,
  as before. An IPv4 socket that cannot be created fails the bind: a host without IPv4 was not
  worth a second fallback.
- Structure: `UdpTransport` keeps its `socket` and `state` (the IPv6-only socket on Windows)
  and gets one `cfg(windows)` field, `v4: Option<windows::V4>` (socket, its own `quinn-udp`
  state, the turn flag). The states are separate because `quinn-udp` sets each socket up for
  its family and may fail for one only (wine lacks some IPv4 options). All sends go
  through one new lookup, `UdpTransport::out(addr)`: the socket, its state and the destination
  in its family. On other platforms it returns the one socket and what `target` returned
  before, so their sends are the same calls on the same socket; the Linux-only paths
  (`linux/*`, `sendmmsg`) are untouched. `send_batch` takes the segment limit from the state
  of the socket the run leaves from; when the lookup fails (an IPv6 destination on an IPv4
  socket) it uses the transport's own state as before, so such a run still fails and is
  counted as a whole. `SideSender` holds the IPv4 socket as well and chooses the same way.
- Addresses: the IPv4 socket reports IPv4 senders, which is what `unmap` produced before, so
  `Path::addr` and `SideDatagram::from` keep their form and endpoints stored before the change
  keep matching. IPv4 destinations and IPv4-mapped ones (`::ffff:a.b.c.d`, which the
  dual-stack socket accepted) leave the IPv4 socket as plain IPv4 addresses
  (`socket.rs::ipv4_destination`); everything else leaves the IPv6-only socket.
- Receive: `windows.rs::readable` waits on both sockets' `readable()` in one `poll_fn` (no
  `select!`: tokio's `macros` feature is not a dependency of the crate) and returns the one
  that is ready, looking first at the socket that was not looked at first the last time. No
  busy wait: a socket that turns out empty clears tokio's readiness as before. With both
  sockets holding datagrams they alternate, so a backlog of one family delays a datagram of
  the other by one receive; the order of arrival across the two families is no longer kept
  (within a family it is).
- `local_addr` reports the IPv6 socket's address, `[::]:port`. The buffer setters size both
  sockets, the getters report the IPv6 one; the 4 MiB default is requested for each.
- `bind_pair` and `ipv4_destination` are compiled for tests on every platform and tested on
  Linux, where the same two binds work (`pair_binds_both_families_on_one_port`,
  `pair_sends_ipv4_and_mapped_destinations_on_the_ipv4_socket`).

What two sockets leave open, measured on the host against a transport on `[::]:port` (second
socket bound through .NET; four datagrams sent to the address it bound):

| second socket | same user (elevated administrator) | another, standard user |
| --- | --- | --- |
| `0.0.0.0:port`, `[::]:port` | `WSAEADDRINUSE`; with `SO_REUSEADDR` `WSAEACCES` | `WSAEADDRINUSE`; with `SO_REUSEADDR` `WSAEACCES` |
| `127.0.0.1:port`, `[::1]:port` | bound with or without `SO_REUSEADDR`; it got 4 of 4, the transport 0 | `WSAEACCES` with or without `SO_REUSEADDR` |

So `SO_REUSEADDR` does not reopen the wildcard addresses, and another user gets nothing. A
process of the same user can bind one local address of the port, without any option, and
takes that address's datagrams; a transport on `0.0.0.0:port` measured the same. Only
`SO_EXCLUSIVEADDRUSE` closes that, so it stays open and is documented in
`docs/reference/nsplane.md`. Not measured: an administrator against a standard user's
transport, service accounts.

Left undone:

- The ephemeral-port retry of `bind_pair` has no test: it needs another process to take the
  IPv4 side of a port between two binds.
- Seen on the host and not part of this item: with offload, a send marked `Ecn::Ce` fails
  with `WSAEINVAL` (10022) for every destination tried (loopback, the host's own address, the
  default router, `192.0.2.1`, `::1`), while `NotEct`, `Ect0` and `Ect1` are sent. Windows
  does not let an application send CE through `IP_ECN` / `IPV6_ECN`. The engine drops such a
  datagram and counts it under `DROP_TRANSPORT_SEND_ERROR`. `udp::tests::ecn_ipv4`, `ecn_ipv6`,
  `ecn_dual_stack`, `offload::mixed_batch_reaches_each_receiver_in_order` and
  `offload::offload_off_batches_without_coalescing` fail on the host for that reason, before
  and after this change; wine has no ECN support at all and passes them. Which mark replaces
  CE there is a decision for the owner.

## Validation

On the Windows 11 host (test executables cross-built for `x86_64-pc-windows-gnu`, copied over
and run there):

- Before the change: `nsplane-uapi`'s `listen_port_rebinds_the_transport` fails at the
  `0.0.0.0` bind assertion, the new `listen_port_taken_for_ipv4_is_reported` answers
  `errno=0` instead of `errno=98`, and `udp::tests::unspecified_bind_owns_the_ipv4_port`
  fails (`UdpSocket { addr: 0.0.0.0:65069 }` bound). The other new `nsplane` tests were not
  run on their own against the old code; the UAPI test covers the listener case.
- After: `tests/uapi.rs` 9 of 9, `nsplane-uapi` unit tests 16 of 16 (1 ignored),
  `tests/engine.rs` 49, `plaintext_egress` 7, `tags` 5, `tracked` 21. `nsplane` unit tests
  185 of 190: the five that fail are the CE sends described above, the same five as before the
  change. Green there: `unspecified_bind_owns_the_ipv4_port`,
  `unspecified_bind_fails_on_a_port_taken_for_ipv4`, `dual_stack_unmaps_ipv4_peers` (IPv4 and
  IPv6 round trips both ways through one transport), `dual_stack_sends_to_mapped_destinations`,
  `dual_stack_serves_both_families_at_once` (a single datagram of one family is served within
  the first half of a backlog of 64 of the other, both ways; one batch to both families), the
  side channel tests and the socket buffer tests.

In the container: `cargo fmt --all --check`; `cargo hack clippy --each-feature --all-targets`
for `nsplane` and `nsplane-uapi` on Linux and `x86_64-pc-windows-gnu`; `cargo-zigbuild clippy`
for `aarch64-apple-darwin`; `cargo nextest run -p nsplane -p nsplane-uapi -p nsplane-e2e
--all-features` (700 passed, 23 skipped); doc tests; `cargo deny check`; `cargo shear`;
`typos`; `scripts/check-docs.sh`; `scripts/check-product-terms.sh`; and the wine run of the
`nsplane` and `nsplane-uapi` tests (190, 49, 7, 5, 21, 16, 9 passed). All pass.
