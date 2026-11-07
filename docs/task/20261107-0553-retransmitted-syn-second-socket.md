# 20261107-0553-retransmitted-syn-second-socket Retransmitted SYN opens a second socket for one tuple

- **status**: completed
- **priority**: P1
- **owner**: L3/nyobdsjx
- **createdAt**: 2026-11-07 05:53

## Description

Reported from netseed-ns (L1 elcock9k). A lost SYN-ACK makes the client retransmit its SYN.
The stack lets it through and provides a free `Listen` socket, and smoltcp hands the packet to
the first accepting socket in slot order. The tuple then has two sockets with different ISNs, an
ACK reaches the wrong one, its RST ends the connection on the client. No `NetStackConfig`
prevents it; seen at `Admission::Decide` and `Immediate`.

Acceptance: a regression test ported from `crates/libns-net/tests/concurrent.rs` on the ns
`mini-ns` branch fails before the fix and passes after, under loss, across many seeds; a client
that reuses a port against a stale connection does not hang; `just check` passes. No push, tag
or release: the owner decides.

## ActiveForm

Fixing the retransmitted SYN path of the netstack.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Approval given up front in the issue. The smoltcp fork route (tuple-first dispatch) needs a
pushed tag, which the issue forbids, so the fix stays in `nsplane-netstack`.

`screen_syn` in `stack/ingress.rs` runs for every bare SYN of a registered tuple: dropped in
SYN-RECEIVED, challenged on a synchronized socket, passed in SYN-SENT. smoltcp ignores a bare SYN
on a synchronized socket (`(_, _, None)`) and exposes no sequence numbers, so the challenge is
four rewritten SYN|ACK copies; a free listener refuses them.

## Validation

`tests/lossy_link.rs` (ported, 64 runs at each admission) and the `repeated_syn` tests fail without
`screen_syn` and pass with it, 20 of 20 repeats. `just check` passes (2504 tests, 34 skipped).
`just cross` was not run.

Left open: a free listener in a lower slot can still take the SYN of a simultaneous open. The
four-copy challenge can go if the fork answers a bare SYN itself and prefers tuple-bound sockets.
