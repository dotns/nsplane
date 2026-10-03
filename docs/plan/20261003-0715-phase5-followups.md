# 20261003-0715-phase5-followups Fix the open Phase 1-5 follow-ups

- **status**: approved
- **createdAt**: 2026-10-03 07:15
- **approvedAt**: 2026-10-03 07:15 (user: "开始修复")
- **relatedTask**: 20261002-1509-phase1-followups

## Context

Open items in task `20261002-1509-phase1-followups` that can be fixed in this repository:
#1 (64 B core overhead, deferred to a batched data-path entry point), #14 (send errors of a
batched UDP send are over-counted), #15 (QueueStats misses the worker-pool queues), #16
(Fragmenter counters only traced), #17 (per-peer `Mutex<Tunn>` on the pool-off path), #18
(plain TUN read capacity is MTU, translation takes the grown-copy path), #20 (zero-checksum
fragmented IPv4 UDP out of order cannot be translated). Not in scope: #5 (needs a Windows
host), #19 (upstream smoltcp report, outward-facing, needs the user's go).

## Proposal

### Contract

- `nsplane-core` (FA): a batched data-path entry point, e.g.
  `Core::handle_datagrams(&mut self, batch: impl IntoIterator<Item = (Path, PacketBuf)>, now)`
  and `Core::handle_locals(...)`, sharing one dispatch setup per batch (output queue reserve,
  one clock read, peer lookup cache for consecutive packets of the same session/peer); the
  per-packet `handle_input` stays. The engine feeds received/local batches through it. With
  `crypto_workers == 0` the peer tunnel is not behind a `Mutex` (an enum or generic storage
  chosen by the core at construction; no lock on that path).
- `nsplane` (FA): `QueueStats` gains the worker-pool queues; Fragmenter counters (PTB sent,
  frag-needed sent, fragments made, no-route ICMP, oversize drops) appear in `drop_counters`
  (drops) and a new `FragmentStats` via `EngineHandle` (non-drop counters).
- `nsplane` `Transport` (FB, breaking for implementers): `send_batch` reports how many
  datagrams of the call failed (or a per-datagram result) so the engine counts exactly;
  default method and `UdpTransport` (GSO runs) implement it; the engine's transmit task uses
  it.
- `nsplane-tun` (FB): the plain (non-offload) read path allocates MTU + 28 capacity.
- `nsplane-nat` (FB): the Translator keeps a bounded, time-limited hold of non-first fragments
  of zero-checksum IPv4 UDP datagrams until the first fragment arrives (then computes the
  checksum and translates all), counted evictions/timeouts.

### Workstreams (L2)

| L2 | Items | Scope |
|---|---|---|
| FA core + engine | #1, #15, #16, #17 | `crates/nsplane-core/**`, `crates/nsplane/src/{engine,builder,handle,events,fragment,lib}.rs` except the transmit-task body, benches, e2e |
| FB I/O + nat | #14, #18, #20 | `crates/nsplane/src/{transport,udp,io}.rs` and the engine transmit-task body, `crates/nsplane-tun/**`, `crates/nsplane-nat/**`, e2e |

Parallel; merge order by completion; L1 resolves `engine.rs` conflicts.

### Acceptance

- #1: `data_path` gains a batched case (e.g. 32 datagrams per call); the per-packet cost of
  the batched core path vs the device-equivalent is <= 10 % at 64 B (target), reported with
  callgrind and wall clock; single-packet numbers do not regress.
- #17: pool-off path has no lock (code + a test/bench note); pool-on unchanged.
- #15/#16/#14: e2e assertions on the new counters (worker queues visible; fragmenter counters
  after PTB/fragmentation; exact send-error count with a partially failing GSO batch).
- #18/#20: unit + e2e (translate_node with offload off and full-MTU IPv4 takes the in-place
  path, `grown_copies` 0; out-of-order zero-checksum fragments translated).
- Each branch and main after each merge: just check, just cross, just test-windows, cargo doc
  -D warnings, root tests, release CLI + linux.sh, lib.sh, examples.sh green; data_path no
  regression vs main 64131c7 (64 B 546 ns, 1420 B 1.354 us).

## Scope

nsplane repository only; no new dependencies; no lint changes.

## Annotations
- 2026-10-03: user decision: nsplane depends on its own smoltcp fork `dotns/smoltcp` (forked from
  smoltcp-rs/smoltcp, branch `nsplane/v0.14-fixes` from v0.14.0) carrying fixes for the two
  0.14 defects (pure-ACK SEQ after a retransmission-timeout rewind; zero-window probe replacing the retransmit
  timer). After the fork is fixed and pushed, nsplane-netstack switches to a git dependency
  pinned to a tag on the fork, `deny.toml` allows that git source only, and the netstack
  workarounds (pure-ACK SEQ rewrite, `nudge_stalled`) are removed when the lossy e2e passes
  without them. Follow-up #19 becomes "send the fixes upstream" (still the user's call).
