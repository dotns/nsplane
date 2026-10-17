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

## Results

### FL-D benches: v0.15.0 (A) against the branch (B)

2026-10-17, `scripts/bench/slot.sh`, every invocation in slot 0 (criterion container
`--cpuset-cpus 1-7`), one A/B per invocation (A then B), 120 s between invocations, three
rounds each for the netstack benches and `data_path`, interleaved netstack, `data_path`,
netstack, ... A is `git archive v0.15.0` with the branch's `benches/send_stream.rs` copied in
(the UDP case uses only 0.15.0 API). Criterion medians per round, then the median of the three
rounds; lower is better. Branch at `6f940e2`.

`send_stream` (TCP: 8 MiB per iteration; UDP: 1024 x 1200 B datagrams per iteration):

| Case | A rounds | B rounds | A median | B median | B vs A |
| --- | --- | --- | --- | --- | --- |
| `netstack_send/streams_1` | 3.137 / 3.145 / 3.099 ms | 3.089 / 3.139 / 3.151 ms | 3.137 ms | 3.139 ms | +0.1 % |
| `netstack_send/streams_4` | 2.020 / 2.028 / 2.006 ms | 2.006 / 1.999 / 1.994 ms | 2.020 ms | 1.999 ms | -1.0 % |
| `netstack_send_1cpu/streams_1` | 3.352 / 3.360 / 3.348 ms | 3.313 / 3.308 / 3.357 ms | 3.352 ms | 3.313 ms | -1.2 % |
| `netstack_send_1cpu/streams_4` | 4.055 / 4.122 / 4.064 ms | 4.079 / 4.067 / 4.100 ms | 4.064 ms | 4.079 ms | +0.4 % |
| `netstack_udp_send/flows_1` | 575.1 / 574.8 / 577.9 us | 566.6 / 580.0 / 582.3 us | 575.1 us | 580.0 us | +0.8 % |
| `netstack_udp_send/flows_4` | 461.9 / 456.8 / 468.5 us | 480.7 / 478.7 / 481.7 us | 461.9 us | 480.7 us | **+4.1 %** |
| `netstack_udp_send_1cpu/flows_1` | 425.9 / 425.8 / 423.2 us | 420.2 / 419.9 / 417.7 us | 425.8 us | 419.9 us | -1.4 % |
| `netstack_udp_send_1cpu/flows_4` | 420.8 / 421.1 / 425.0 us | 425.6 / 421.5 / 422.4 us | 421.1 us | 422.4 us | +0.3 % |

`nsplane-core` `data_path` (no code difference between A and B in `nsplane-core`, so this row
is the A/B noise floor):

| Case | A rounds | B rounds | A median | B median | B vs A |
| --- | --- | --- | --- | --- | --- |
| `core_round_trip/64` | 416.3 / 415.9 / 418.1 ns | 417.4 / 415.5 / 421.3 ns | 416.3 ns | 417.4 ns | +0.3 % |
| `core_round_trip/1420` | 1.224 / 1.221 / 1.221 us | 1.240 / 1.222 / 1.233 us | 1.221 us | 1.233 us | +1.0 % |

Load (`/proc/loadavg`, 1-minute, 32 CPUs) before / after each run:

| Invocation | A | B |
| --- | --- | --- |
| netstack round 1 | 2.22 / 1.72 | 1.72 / 1.53 |
| `data_path` round 1 | 0.76 / 0.97 | 0.97 / 0.98 |
| netstack round 2 | 0.81 / 1.44 | 1.44 / 1.84 |
| `data_path` round 2 | 0.75 / 0.98 | 0.98 / 1.07 |
| netstack round 3 | 0.66 / 1.32 | 1.32 / 1.72 |
| `data_path` round 3 | 0.69 / 0.98 | 0.98 / 1.21 |

- TCP `send_stream` and `data_path`: at par (within -1.2..+1.0 %, the spread of the identical
  `data_path` code).
- UDP on one thread and with one flow on four workers: at par.
- **UDP, four flows on four workers: +4.1 % per iteration, beyond noise.** All three B rounds
  (478.7-481.7 us) are slower than every A round (456.8-468.5 us) on a quiet host, while the same
  case on one thread is at par. The per-datagram cost added in FL-B is one `Arc<FlowState>`
  clone in `UdpSocket::send`, one atomic load in the driver, and a push and a prune of the
  driver's mark list; with four sender tasks on other workers the clone and the later drop of
  that `Arc` in the driver touch a reference count shared across threads, the likely cause (not
  profiled). Not fixed in FL-D (outside its scope); reported to L2.

## Annotations

### FL-A design note (2026-10-17)

Read against `067e9eb` (0.15.0). The ns adapter paths named in the brief
(`crates/ns/src/service_control/*`) do not exist on `refactor/nsplane` (`3aa543fd`); the ns
side today uses one `NetStack` per flow in `account_engine/stack.rs` and waits on
`TcpConnection::terminated()`. The note relies on the request, not on those adapters.

#### 1. Public API (additive; new module `flow.rs`, re-exported from `lib.rs`)

```rust
/// Per-flow control, independent of the data handles. Clone + Send + Sync + Debug.
#[derive(Clone, Debug)] pub struct FlowControl { /* Arc<FlowState> */ }
impl FlowControl {
    pub fn revoke(&self) -> RetirementReceipt;            // idempotent, irreversible
    pub fn is_revoked(&self) -> bool;
    pub fn bind_context(&self, domain: u64) -> io::Result<FlowContext>;
    pub fn context(&self) -> Option<FlowContext>;
}
/// Opaque label: the caller's isolation domain plus a stack-allocated instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct FlowContext { /* u64, NonZeroU64 */ }
impl FlowContext { pub const fn domain(&self) -> u64; pub const fn instance(&self) -> NonZeroU64; }
/// The receipt of one revoke. Clone; every clone and every later revoke share one outcome.
#[derive(Clone, Debug)] pub struct RetirementReceipt { /* Arc<FlowState> */ }
impl RetirementReceipt {
    pub fn outcome(&self) -> Option<RetirementOutcome>;  // None while pending
    pub async fn wait(&self) -> RetirementOutcome;       // cancellation-safe, repeatable
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetirementOutcome { Retired, Failed, Unknown }

impl TcpConnection { pub fn control(&self) -> FlowControl; }
impl UdpFlow       { pub fn control(&self) -> FlowControl; }
impl UdpReply      { pub fn control(&self) -> FlowControl; }  // same flow, same control
impl UdpSocket     { pub fn control(&self) -> FlowControl; }  // bind_udp and connect_udp
impl NetStackStats { pub retired: u64 }  // new counter, see Q4
```

- **One control per flow (R1-1).** Every `TcpConnection`, `UdpFlow` (shared with all its
  `UdpReply` clones) and `UdpSocket` gets an `Arc<FlowState>` when the driver creates it
  (`adopt`, `dispatch_flow`, `bind`, `connect_udp`): one allocation per flow, none per packet.
  `control()` clones that `Arc`, so it works at any time, after the data handle moved to a
  task, after `abort(self)`, after the flow was dropped or released. No existing signature
  changes. A bound `UdpSocket` is one flow for this purpose (all its remotes).
- **`revoke` (R1-2).** The first call flips `revoked` (`swap`, `SeqCst`) and queues the state
  for the driver; later calls only return a receipt of the same outcome. It never sends a
  FIN or an RST and never waits. It differs from:
  - FIN / `shutdown`: no FIN; reads and writes fail at once, buffered bytes are discarded.
  - drop: drop closes gracefully and keeps the socket until the close completes; dropping a
    `FlowControl` or a receipt does nothing.
  - `abort`: abort sends an RST and releases only once it left (the `aborting` list waits
    for the device); revoke releases in the observing turn whatever the device does.
  On the handle side, at the call: TCP sets `Shared::revoked`, clears `rx`/`tx`, wakes reader
  and writer (under the existing `Shared` lock); UDP wakes senders parked on a full queue
  (`FlowState::wake`, a `Notify`). After it, every old handle fails with
  `io::ErrorKind::ConnectionAborted` (distinct from `BrokenPipe` for stopped / closed):
  `poll_read`, `poll_write`, `poll_flush`, `poll_shutdown`, `UdpFlow::send`, `UdpReply::send`,
  `UdpSocket::send` / `send_to` / `recv_from`. `UdpFlow::recv` returns `None` (its signature
  has no error); buffered datagrams are never returned. `terminated()` resolves once the
  driver released the flow, as today.
- **Receipt (R1-4).** Outcomes: `Retired` (the driver removed the flow's state and nothing
  of it can leave the stack, see 2), `Failed` (the driver observed the revoke but a bound of
  section 2 was full, so that cannot be promised), `Unknown` (the driver stopped before it
  finished, see 4). The boundary is the stack: a packet `NetStackSource::recv` already
  returned belongs to the engine and is outside the receipt (L1 scope decision; R3).
- **Context (R2-1).** `bind_context(domain)` sets the context once: a second call fails with
  `AlreadyExists`, a call after revoke with `ConnectionAborted`, exhaustion with
  `QuotaExceeded` (5). The caller binds it right after it gets the flow: after
  `incoming_tcp` / `incoming_udp` yields it, after `connect_tcp[_from]`, `connect_udp[_from]`
  or `bind_udp` returns. Binding late loses nothing: the stack's cleanup is keyed on the
  `FlowState`, which exists from creation; the context is the caller's label on it and is
  never read by the stack (no branch, no hash, no log on its value). No new `NetStackHandle`
  method; `connect_tcp_in(domain, ..)`-style variants can be added later if R3 needs the
  context on the SYN. Names avoid every term of `scripts/check-product-terms.sh`.

#### 2. Inventory: every place a flow's data or output lives, and its cleanup

Positions: the driver counts packets it moves into the `egress` channel (`sent: u64`, a
plain field); `NetStackSource` counts packets it takes (`received: u64`). The channel is
FIFO with one producer, so the k-th packet received is the k-th sent. For each TCP flow the
driver keeps `start` (= `sent + tx_queue.len()` at the turn its socket was created or took
the SYN) and sets `end` the same way when it drops the socket (release or revoke). All of
the flow's packets have a position in `[start, end)`; a later holder of the tuple starts at
or after `end`, because smoltcp hands a SYN to the existing socket of a tuple, so a listener
only takes it once the old socket is gone.

| State / queue | Holds | On revoke (R1-3) | Instance check (R2-2) |
|---|---|---|---|
| smoltcp socket: rx/tx buffers, retransmission, timers | TCP | `sockets.remove(handle)` in the observing turn, no `abort()`, no RST; also removed from `aborting` | the socket is per flow; gone means no emission |
| `Conn` / `Shared` rx, tx, wakers, registration | TCP | handle side clears at the call; driver removes `Conn` (drops the `owns` registration), sends `terminal`, sets `released` | per flow |
| `connecting`, `deferred` | TCP connect | n/a: a control exists only after `connect` returned; a deferred connect waiting for a revoked port proceeds (port freed) | n/a |
| listener pool, `inbound` (SynReceived), `waiting`, accept channel | TCP not yet handed out | untouched; no control exists before the application holds the connection | a new SYN on the tuple is a new flow |
| `flows` / `connected` / `bound` entries and the per-flow datagram channel | UDP in | entry removed if it is this flow's (`FlowState` pointer); the `Sender` drop wakes a blocked `recv`; buffered datagrams are freed with the handle | `recv` checks `revoked` after every receive |
| `UdpOut` channel `udp_rx` | UDP out | elements are `(PacketBuf, Arc<FlowState>)`; dropped in `take_udp_sends` | `revoked` checked after `reserve` in `send` and in `take_udp_sends` |
| device `tx_queue` (EGRESS_BACKLOG, 256) | TCP + UDP out | `retain`: drop UDP elements of the state and TCP packets of the tuple whose position is in `[start, end)` (≤ 256 parses, only on revoke) | element `(PacketBuf, Option<Arc<FlowState>>)`, `None` for smoltcp output |
| `egress` channel up to `NetStackSource::recv` (`egress_capacity`) | TCP + UDP out | not reachable by the driver: TCP gets a fence `(tuple, start, end)` if `end` > the oldest position possibly queued (`sent - len`); UDP is tagged | `recv` drops tagged revoked packets, and while a fence exists, TCP packets of a fenced tuple whose `received` position is in the window; fences with `end <= received` are pruned |
| reassembler (`nsplane-packet`, in) | fragments of either | if `pending() > 0`: a barrier `(remote ip, local ip, protocol, ports, until = now + timeout)` | a datagram completed before `until` whose tuple matches is dropped (6) |
| `Owners` fragment memory (`owns`) | classification only | expires with the timeout; not output | n/a |
| PMTU | none per flow | n/a: an ICMP quoting the tuple finds no socket, counted in `icmp_ignored` | n/a |
| ingress channel | peer packets for the tuple | untouched; after revoke they are new traffic: TCP gets smoltcp's stateless RST, UDP opens a new `UdpFlow` the caller admits or not | new `FlowState` |

Every drop counts in `NetStackStats::retired` (Q4). Same 5-tuple re-open: a new flow gets a
new `FlowState` and a window starting at or after the old `end`; it never sees the old
datagram channel, socket or reply handles (old `UdpReply` clones carry the old state and
keep failing).

#### 3. Receipt state machine and bounds (R1-4, R1-5)

`Pending` (revoke called) → `Retired` | `Failed` | `Unknown`; terminal states never change.
`FlowState::outcome` is an `AtomicU8` written once (compare-exchange from `Pending`), then
`done.notify_waiters()`.

- The handle side: `revoke` flips the bit and pushes the state onto `Revocations` (shared,
  `Mutex<Vec<Arc<FlowState>>>` plus an `AtomicBool` hint), then `notify_one` on the
  driver's `Notify`. Only the winner of the swap pushes: one entry per flow at most.
- The driver: at the start of every turn (before ingest and poll) one hint load; if set,
  takes the list into `retiring`, applies section 2 per flow, writes `Retired` (or `Failed`)
  and clears `retiring`. Revoke is "observed" in that turn and completed in it: no step
  waits for the peer, an RST, TIME-WAIT, egress room or the engine.
- `wait`: `loop { let n = done.notified(); pin + enable; if let Some(o) = outcome() { return
  o } n.await }`; cancellation drops only the `Notified`; any number of waiters, any time.
- Bounds: `FlowState` is fixed size (about 128 B) and lives as long as a handle, control or
  receipt; `Revocations` holds at most one entry per live flow; fences at most
  `MAX_FENCES` (1024) at 64 B, barriers at most `ReassemblyConfig::max_datagrams`. A full
  fence or barrier table gives `Failed` for that flow; nothing grows past its bound.
- Measured: a `#[cfg(test)]` turn counter on the driver, recorded in `FlowState` when the
  revoke is taken and when the outcome is written; tests assert the two are equal under a
  silent peer, a full `egress` (source not drained), a socket in TIME-WAIT, an aborted
  connection waiting for its RST, and a full send queue.

#### 4. Stopped driver → `Unknown`

`Driver::drop` (normal stop, panic unwind, runtime shutdown) locks `Revocations`, sets
`closed`, and writes `Unknown` to every state still in the list or in `retiring`. `revoke`
pushes under the same lock and, if `closed`, writes `Unknown` itself, so no revoke falls in
between. A stopped stack cannot run the egress-side cleanup either, so `Unknown` is also the
answer after `NetStackSource`/`NetStackSink` dropped, even while the engine drains the
remaining channel. `wait` has no internal timeout; a caller's timeout or a cancelled waiter
leaves `outcome()` at `None`, never `Retired`.

#### 5. Instance allocation (R2-3)

A process-wide `static NEXT_INSTANCE: AtomicU64` (starts at 1), taken by `bind_context` with
`fetch_update(checked_add(1))`: never reused, never revived, unique across stacks; at
`u64::MAX` every later call fails with `io::ErrorKind::QuotaExceeded` (no wrap). The domain is
stored as given. Domains never mix because a tuple has at most one live holder in a stack and
cleanup is per `FlowState`, not per tuple or domain: two domains on the same 5-tuple are two
holders in sequence with disjoint windows and distinct tags. The allocator is a function over
`&AtomicU64`, so the exhaustion test runs on a local counter.

#### 6. Fragments (R2-4)

Ingress only: the stack sends no fragments itself (IPv4 UDP with DF clear is one packet for
the engine's fragmenter, outside the stack). Later fragments carry no ports, so a held
datagram cannot be tied to an instance; on revoke with `pending() > 0` the driver adds a
barrier and drops (counted in `retired`) every datagram completed before `until` whose tuple
is the revoked flow's: held fragments of the old flow never reach a new flow on the tuple,
and a new flow's fragmented datagrams in that one timeout are dropped as ambiguous.
`discard_fragments` keeps working unchanged. The netstack keeps the barriers; no change in
`nsplane-packet`.

#### 7. Cost

The context is never on a per-packet path: zero. The R1 machinery applies to every flow:

- driver turn: one `Relaxed` load of the revocation hint;
- `flush_egress` / `wait` egress permit: `sent += 1`; elements 8 bytes larger (`Option<Arc>`
  niche);
- `NetStackSource::recv`: `received += 1`, a `None` branch, one `Relaxed` load of the fence
  hint; parsing only while a fence exists;
- TCP bridge: nothing (revocation is pull-queued, not checked per connection);
- UDP send: one `Arc` clone and one atomic load per datagram (next to a `PacketBuf`
  allocation and a channel send); `take_udp_sends`: one load;
- creation: one `Arc<FlowState>` per connection or flow.

`send_stream` (TCP, persistent connections) touches only the first three: expected at par.
FL-D runs the slot A/B against 0.15.0 (`scripts/bench/slot.sh`), `netstack_send` and
`netstack_send_1cpu`, streams 1 and 4. There is no UDP netstack bench (Q5).

#### 8. Existing behaviour

Without a revoke nothing changes: `abort`, `terminated`, drop, FIN / half close, idle
timeout, `UdpFlow` / `UdpReply` (a dropped flow's reply clones keep sending), `owns`,
`discard_fragments`, stats. `ConnectionAborted` appears only on revoked flows. Every existing
test in `src/**` and `tests/*.rs` passes untouched; no existing test is edited.

#### 9. Split of work

**FL-B (R1)**: `src/flow.rs` (new: `FlowControl`, `RetirementReceipt`, `RetirementOutcome`,
`FlowState`, `Revocations`), `lib.rs` (re-exports), `tcp.rs` (`control`, `Shared::revoked`,
`ConnectionAborted`), `udp.rs` (`control` on the three types, `revoked` checks, woken wait on
a full queue, tagged `udp_rx` elements), `stack.rs` (states at creation, revocation drain,
socket / entry removal, `tx_queue` retain, positions and fences, `Driver::drop`),
`device.rs` (tagged `tx_queue` element), `stats.rs` (`retired`). Tests in
`src/stack/tests/flow_control.rs` (new) and `src/flow.rs`:
`control_survives_moved_and_cloned_handles` (R1-1),
`revoke_is_idempotent_and_wakes_blocked_read_write_send` (R1-2),
`revoked_handles_fail_with_connection_aborted` (R1-2),
`revoke_sends_no_fin_and_no_rst` (R1-2),
`revoke_cleans_only_its_flow_two_tcp_two_udp` (R1-3),
`revoke_purges_backlog_and_fences_egress` (R1-3),
`receipt_wait_is_cancellation_safe_and_repeatable` (R1-4),
`receipt_is_unknown_when_driver_stops` and `revoke_after_stop_is_unknown` (R1-4),
`receipt_fails_when_fence_table_is_full` (R1-4),
`retires_in_one_turn_with_silent_peer_full_egress_time_wait` (R1-5),
`revoke_after_abort_or_release_retires` (R1-5).

**FL-C (R2)**: `src/flow.rs` (`FlowContext`, `bind_context`, `context`, the allocator),
`stack.rs` (reassembly barriers), docs on the context in `lib.rs`. Tests:
`bind_context_once_and_not_after_revoke` (R2-1),
`stack_never_reads_the_context` (R2-1: two flows differing only in context behave
identically), `same_tuple_reopen_gets_new_queues_and_replies` (R2-2, TCP and UDP),
`old_reply_clone_never_sends_after_revoke` (R2-2),
`instances_are_unique_and_exhaustion_refuses` (R2-3),
`two_domains_same_tuple_never_mix` (R2-3), `held_fragments_never_reach_a_new_flow` (R2-4),
`fragment_barriers_are_bounded_and_expire` (R2-4).

FL-B lands first; FL-C rebases on it (it only adds to `flow.rs` and the reassembly path).

#### 10. Open questions (yellow; none needs a change outside `crates/nsplane-netstack`)

- **Q1 — who allocates the instance.** Proposed: the stack (process-wide counter), caller
  gives the domain. Alternative: the caller gives both and the stack refuses an instance not
  above a stack-wide high-water mark; that matches "set by the caller" literally but refuses
  legitimate opens that race across tasks. L1 to choose.
- **Q2 — TCP output is identified by tuple and position, not by a per-packet tag.** smoltcp's
  `TxToken` does not say which socket emits, so tagging TCP would need a tuple lookup per
  segment (cost on `send_stream`) or a change in the smoltcp fork (outside the crate). The
  `[start, end)` window identifies exactly one holder, which is what R2-2 asks; L1 to accept
  this as "carries its instance".
- **Q3 — no RST on revoke.** Revoke is silent; the peer learns from smoltcp's stateless RST
  on its next segment, or by its own timeout. A best-effort RST would be a packet of the
  retired flow leaving after the revoke.
- **Q4 — `NetStackStats::retired`.** `NetStackStats` is not `#[non_exhaustive]`, so a new
  field breaks struct literals; earlier 0.x minors added counters the same way
  (`icmp_ignored`, the reassembly counters). Without it the drops go uncounted, against
  "everything the stack discards is counted".
- **Q5 — UDP cost.** The per-datagram `Arc` clone is not covered by any bench; FL-D could add
  a UDP case to the netstack benches or L1 accepts the argument above.
- **Q6 — `Unknown` after stop.** A stack whose driver stopped answers `Unknown` even if the
  application only wanted the egress channel scrubbed; scrubbing it from `NetStackSource`
  after the driver is gone would need the fence logic without the driver.
- No new dependency, no `unsafe`, no `#[allow]` / `#[expect]`.

### L1 decision on the FL-A note (2026-10-17)

Approved as written, amended as follows (binding for FL-B..FL-D):

- **Q1**: the stack allocates the instance, the caller gives the domain (FL-C).
- **Q2**: TCP output is identified by tuple + `[start, end)` window (accepted).
- **Q3**: no RST on revoke; `abort()` keeps its RST. `revoke`'s rustdoc says the peer is not
  told and times out on its own (or learns from the stateless RST on its next segment).
- **Q4**: strictly additive: no new field in `NetStackStats`. Retirement drops are counted
  by `NetStackHandle::retired_drops(&self) -> u64` (everything the stack discarded because
  its flow was revoked).
- **Q5**: FL-D adds a UDP netstack bench case.
- **Q6**: `Unknown` after the driver stopped, never a false success.
- **Condition 1**: the rustdoc of `FlowControl` and `RetirementReceipt` states the proof
  boundary: the stack only; packets already taken from `NetStackSource` are not covered (R3).
- **Condition 2**: `bind_context` binds once and late binding labels the existing
  `FlowState` (FL-C implements it and its test); FL-B keeps queue tags referencing the
  `FlowState`, not a copy of the context.
- **Condition 3**: this subsection records the decision.
