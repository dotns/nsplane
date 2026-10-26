# 20261026-0838-first-input-flow-control Netstack flow control from the first input

- **status**: in_progress
- **priority**: P1
- **owner**: w1/first-input-flow-control
- **createdAt**: 2026-10-26 08:38
- **plan**: 20261026-0822-node-gateway-requests (W1, request R1)

## Description

Under `Admission::Decide` the consumer gets a `FlowControl` for one connection or flow
lifetime at its first input (bare SYN, first UDP datagram), through `PendingFlow::control`.
Revoking it at any stage (held, accepted before the next driver turn, SYN-received,
established and waiting for `incoming_tcp`, in the accept channel) retires the lifetime and
no handle of it is delivered afterwards; the delivered handle carries the same control.
Every lifetime ends with exactly one `DeliveryOutcome` (delivered, or not delivered with an
`Undelivered` reason) on a `DeliveryReceipt`. `RetirementOutcome` keeps its meaning.
Admission moves to a top-level `NetStackConfig::admission` that also applies to ordinary
stacks; `TransparentConfig::admission` is deprecated and still honoured.

Owner decisions: O1 top-level admission with the transparent field deprecated; O2 a revoke
before the hand-out sends nothing; O3 the delivery receipt covers `Decide` lifetimes, other
handles report `Delivered` at once.

Acceptance criteria:

- Unit tests for every stage x revoke, every `Undelivered` reason, the hand-out race
  (multi-thread runtime), same tuple after a revoke, an ordinary stack with `Decide`
  (TCP and UDP) and a context bound on the pending control seen on the handle.
- An `nsplane-e2e` test through two engines: revoke at each stage, no handle and no packet
  of a revoked lifetime leaves the stack.
- `Immediate` stacks unchanged; slot A/B of `send_stream` (`netstack_send`,
  `netstack_udp_send` including `flows_4`) within noise.
- Reference page, `CHANGELOG.md` `Added`; full gate green.

## ActiveForm

Implementing netstack flow control from the first input

## Dependencies

- **blocked by**: (none; approved 2026-10-26 as part of release B)
- **blocks**: (none)

## Notes

- Lifetime state: `FlowState` is created at the hold (`FlowState::held`), its target bound
  once by the driver (the listener socket at SYN-RECEIVED, the flow entry at accept); the
  delivery stage is one `AtomicU8` fixed by compare-and-swap (`deliver` at the stream,
  `undeliver(reason)` at the first terminal event, the revoke included). Rejection, timeout
  and connection-limit answers are sent only when the driver wins that swap, so a
  concurrent revoke never ends `Revoked` with an answer sent.
- Retirement per stage: held entry removed; accepted SYN dropped in `take_decisions` when
  revoked; SYN-RECEIVED socket removed without RST plus TCP fence from the socket's start
  mark; connection removed from `waiting`; the flow entry; a reassembly barrier from the
  held tuple. A SYN refused by the pool after a concurrent revoke has smoltcp's RST purged.
- `tcp_egress_drained` rejects a lifetime without a connection (adopted flag), as the plan
  states.
- An accepted UDP lifetime opens in the flow table directly (no socket precedence), so the
  lifetime always maps to one `UdpFlow`.
- Stop: `Pending` keeps weak references to open lifetimes, pruned on doubling; the driver's
  drop ends them `Stopped` before its fields drop.
- Out-of-scope files touched only to migrate off the deprecated field: the
  `dns_netstack` example, `nsplane-e2e` `netstack_transparent.rs` and the guide snippets
  (English and Chinese).
