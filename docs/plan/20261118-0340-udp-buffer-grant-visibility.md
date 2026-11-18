# 20261118-0340-udp-buffer-grant-visibility Make the granted UDP socket buffer size visible and reachable

- **status**: draft
- **createdAt**: 2026-11-18 03:40
- **approvedAt**: (pending review; plan only, no implementation is proposed in this change)
- **relatedTask**: (none until approved)

## Context

`UdpTransport::prepare` requests `DEFAULT_SOCKET_BUFFER` (4 MiB) for `SO_RCVBUF` and
`SO_SNDBUF`. Linux clamps both to `net.core.rmem_max` / `wmem_max` without an error;
the stock limit on common distributions is 212992 bytes. The grant is never compared
with the request, and only a failed `setsockopt` is logged, at `debug`. An embedder
on a stock host therefore runs every carrier with the 208 KiB default this code was
written to avoid, and neither its logs nor its status can tell. `docs/guide.md`
asks embedders to raise the sysctls, but nothing reports when they did not.

Embedders such as `ns` commonly hold `CAP_NET_ADMIN` (they create TUN devices), so
`SO_RCVBUFFORCE` / `SO_SNDBUFFORCE` would usually obtain the full size without a
host-global sysctl change.

## Proposal

1. After the existing requests, read back the granted sizes. If a grant is below the
   request (accounting for Linux's doubling), log once per transport at `info` with
   the requested and granted sizes and the limiting sysctl, instead of only logging
   failures at `debug`.
2. On Linux and Android, when the plain request was clamped, attempt
   `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE` with the same size; `EPERM` falls back to the
   clamped grant silently. Exposed as a `bind` option defaulting to the current
   behavior until reviewers decide the default.
3. Document the grant check and the FORCE fallback in `docs/guide.md` and
   `docs/reference/nsplane.md`.

## Risks

FORCE bypasses an operator-set ceiling; keeping it opt-in (or reviewer-chosen
default) preserves operator intent. Larger buffers add queueing delay under
overload; the size and the measurements in `docs/performance.md` are unchanged.

## Scope

`crates/nsplane/src/udp.rs`, its tests and the two documents. No change to the
requested size, batching, offload or any other transport behavior.

## Alternatives

Leaving detection to every embedder duplicates the read-back and still cannot use
FORCE, because the socket is not exposed.

## Annotations

Submitted from the `ns` investigation `20261118-0326-udp-socket-buffer-headroom`.
This change adds the plan only; implementation and merge are left to the
repository's owners.
