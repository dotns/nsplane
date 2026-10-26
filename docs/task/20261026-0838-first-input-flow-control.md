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

(none yet)
