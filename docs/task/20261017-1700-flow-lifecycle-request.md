# 20261017-1700-flow-lifecycle-request Per-flow retirement, flow context and delivery gates (request, draft)

- **status**: in_progress (R1, R2 merged 2026-10-17, plan `20261017-1800-flow-retirement`, pending release 0.16.0; R3 deferred by the owner)
- **priority**: P3
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-17 17:00
- **source**: ns draft `20261017-0538-nsplane-flow-lifecycle` (Chinese, received as an archive on
  2026-10-17 and summarized here; reviewed against nsplane v0.14.2 `64109b0`)

## Description

ns runs one NetStack per service flow, private `Path` markers and its own send wrappers so that a
revoked service flow stops delivering at once and its resources can be proven released. The draft
asks nsplane for three generic, in-process mechanisms so ns could share stacks and drop those
adapters. It is explicitly a long-term candidate: not a prerequisite of ns M6, which stays on
0.14.x without nsplane changes.

Terms: a flow instance is one admitted runtime flow with an opaque isolation domain (a 5-tuple is
not an identity); closing a gate is an irreversible cut after which no new protected delivery
starts; retirement is the release of the resources a named component owns for that flow.

### R1: per-flow control and scoped retirement receipts (`nsplane-netstack`)

- A control object per TCP and UDP flow, independent of the data handles, that survives handing
  the flow to tasks or cloning reply handles. Today `TcpConnection::abort(self)` consumes the
  connection and `terminated()` waits for the socket release.
- Revocation is idempotent and irreversible, wakes blocked operations, invalidates old data and
  reply handles, and differs from FIN / half-close.
- Only the target flow's socket, queues, retransmissions and UDP replies are cleaned; the shared
  stack and peers stay.
- The receipt distinguishes retired, failed and unknown; timeouts, cancelled waiters or a lost
  driver are never success; a cancelled waiter can wait again; state is bounded.
- The receipt covers the stack only; packets already handed to the engine carry their context
  (R2/R3). No dependence on an RST being sent or TIME-WAIT.

### R2: flow context through every queue (`nsplane-netstack`, `nsplane-core`, `nsplane`)

- The caller attaches an opaque context at admission; nsplane carries it through stack buffers,
  TCP output and retransmission, UDP replies, engine commands, crypto queues, batches, writable
  waits and transport retries. It never crosses the wire and has no business meaning.
- Bound to its isolation domain and generation; never reused or revived (wrap-around and
  exhaustion refuse); a new flow on the same 5-tuple never takes over old queues.
- Fragments, reassembly, NAT and ICMP correlation keep it or drop on ambiguity, with bounded
  state.

### R3: gates at the real delivery points (`nsplane`, transports)

- A caller-driven gate checked at the actual delivery to the application or host and at the
  actual transport send, again after every writable wait, partial send or batch remainder; no
  unprotected queue after the check; no lock across await.
- Revocation is linearized against delivery; the caller supplies its clock and deadline.
- The context travels the normal filter path (today `inject_*` skips the filter chain by design;
  that stays, but must not bypass a bound context's gate).
- No session: refuse, or wait in a bounded, context-carrying handshake queue.
- A transport that queues in memory must carry the gate to its real carrier write; enqueued is
  not delivered. Relays and remote queues are out of scope (three separate control domains).

### What ns could remove once it lands (ns side, for reference)

Per-flow NetStacks, private Path markers, the dedicated service send wrapper, per-queue permit
wrappers, compensating abort cleanup. Business permits, clocks and endpoint rules stay in ns.

### Acceptance in the draft

Unit: U01-U08 (two flows on one stack, revoke one; half-close and full queues; idempotent and
re-waitable receipts; paused queues then same 5-tuple; isolation domains and wrap-around;
fragments and ICMP; deadline without the timer; partial receipts). Transport: T01-T06 (real UDP
writable waits and batches; relay and custom transport queues; no session and inject paths;
shared WSS with partial frames and TLS buffers; remote relay queues; re-registration and
carrier switch). Integration in ns: N01-N04, P01 (capacity against the per-flow-stack design).

## L1 assessment (2026-10-17)

- Scope: a feature across `nsplane-netstack`, `nsplane-core`, `nsplane` and every `Transport`.
  It needs an owner exemption from the freeze and its own plan.
- R1 alone is contained: a cloneable control handle and a scoped receipt in `nsplane-netstack`,
  additive, no data-path cost outside the stack. It does not by itself let ns drop per-flow
  stacks (the draft says so too).
- R2/R3 change the data path: a context per packet through the core, the crypto workers and
  batching, and a gate inside `Transport::send` / `send_batch` / `try_send_batch`, which are
  public traits today. That is a breaking API change (0.x minor) and a per-packet cost that
  needs a slot A/B against the current `data_path` (417 ns at 64 B); untagged traffic must pay
  nothing.
- Suggested order if approved: R1 first (additive, small release), then a design note for
  R2/R3 with the Transport API shape, the per-packet cost budget and a migration path for
  existing transports, reviewed with ns before implementation.

## Dependencies

- **blocked by**: owner approval (freeze exception); ns confirming it wants this beyond M6
- **blocks**: (none)
