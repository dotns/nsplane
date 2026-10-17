# 20261017-1800-flow-retirement Per-flow control, retirement receipts and flow context in the netstack

- **status**: in_progress
- **createdAt**: 2026-10-17 18:00
- **approvedAt**: 2026-10-17 (owner: "可以先做r1和r2，先不做r3", the sixth exception to the freeze)
- **relatedTask**: 20261017-1700-flow-lifecycle-request (R1, R2; R3 deferred)

## Context

ns runs one NetStack per service flow so that revoking one flow can be proven by closing a whole
stack; that does not scale (memory per stack, mobile process limits, gateways with many clients).
The request (task `20261017-1700-flow-lifecycle-request`) asks for generic per-flow retirement in
a shared stack (R1), a flow context the stack keeps through its own queues (R2) and delivery gates
in the engine and transports (R3). The owner approved R1 and R2; R3 is deferred.

Today: `TcpConnection::abort(self)` consumes the connection, sends an RST and releases the socket
in the next driver turn; `terminated()` waits for the release. `UdpFlow` / `UdpReply` share an
output path; there is no per-flow control object and no receipt type.

## Scope decision (L1)

R2 stops at the stack boundary: the context lives on the stack's own state and queues (sockets,
TCP output and retransmission, UDP replies, the device output queue, reassembly and correlation
the stack owns), and a retired flow's packets still inside the stack are dropped. Carrying the
context into the engine, the crypto workers and the transports, and gating real delivery there,
is R3 and out of scope. The receipt states that boundary.

## Requirements

| Item | Requirement |
|---|---|
| R1-1 | A control object per TCP connection and UDP flow, independent of the data handles, cloneable, that stays valid after the data handles move to tasks or reply handles are cloned |
| R1-2 | `revoke` is idempotent and irreversible, wakes blocked reads, writes and sends, and makes every old data and reply handle fail; distinct from FIN / half-close and from drop |
| R1-3 | Only the target flow is cleaned (socket, its buffers, retransmissions, UDP replies, its queued output); the stack, other flows and peers are untouched |
| R1-4 | A receipt with three outcomes: retired, failed, unknown (driver gone, stack stopped mid-way). Waiting is cancellation-safe and can be repeated; the outcome stays queryable; state is bounded |
| R1-5 | Retirement does not depend on an RST being sent, the peer, TIME-WAIT or backpressure; it completes within one driver turn after the revoke is observed, bounded and measured |
| R2-1 | An opaque flow context (isolation domain + instance) set by the caller when a flow is accepted or opened; the stack never interprets it |
| R2-2 | Every queued output of a flow inside the stack carries its instance; after revoke none of it leaves the stack. A new flow on the same 5-tuple never takes over an old flow's queues or replies |
| R2-3 | Instances are never reused or revived (wrap-around and exhaustion refuse); flows of different isolation domains with the same 5-tuple never mix |
| R2-4 | Fragments and reassembly in the stack keep the instance or drop on ambiguity, with bounded state |

## Constraints

- Additive public API in `nsplane-netstack` (0.16.0); existing `abort`, `terminated`, `UdpFlow`,
  `UdpReply` keep their behaviour.
- No new crate, no unsafe; no cost on the engine data path (the stack only); netstack benches at
  par for flows without a context.
- Unit tests per item and nsplane-e2e tests: two TCP and two UDP flows in one stack, revoke one
  under traffic with full queues, the other continues; same 5-tuple re-open after revoke;
  receipts under a stopped driver.

## Items

- **FL-A** design note to L1 (yellow): API shape (control object, receipt, context), queue
  inventory of the stack with where the instance is checked, receipt state machine, bounds.
- **FL-B** R1 implementation (TDD).
- **FL-C** R2 implementation (TDD).
- **FL-D** e2e tests, benches A/B against 0.15.0, docs (architecture.md, CHANGELOG Added).

## Acceptance

R1-1..5 and R2-1..4 met with tests, full gate green, netstack benches at par, released as 0.16.0
after the owner confirms.

## Annotations
