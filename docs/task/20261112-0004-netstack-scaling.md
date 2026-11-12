# 20261112-0004-netstack-scaling Netstack scaling and resource items from the audit

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 00:04

## Description

Five scaling and resource items of the audit in `nsplane-netstack`:

1. A driver turn is linear in the connections: `preserve_all` (up to twice) and `bridge_all`
   take one lock per connection, on every ingress wake, every application write and at least
   every 50 ms. One busy flow next to N idle connections pays for all of them.
2. The driver wakes every 50 ms (`MAX_POLL_DELAY`) also when smoltcp has no timer and nothing
   is connected.
3. Each TCP connection holds two socket buffers of `(mtu - 40) * 512` bytes plus its stream
   buffers, and only a transparent stack can bound its connections.
4. The listener pool (32) bounds the half-open handshakes of all sources together.
5. `connect_tcp` builds a set of all local ports per call, `connect_udp` sweeps the connected
   sockets.

Acceptance: measure first; change what can be shown correct, with a test seen failing first
where one is feasible; leave the rest with the reason recorded. The public API changes only by
additions, new limits default to off, and the gates pass.

## ActiveForm

Fixing the audited scaling items in the netstack.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

### Measurement

`examples/src/bin/netstack_bench.rs` and `scripts/bench/wg-compare.sh` measure one or four
streams through engines in containers; they have no idle connections and no view of a driver
turn. The numbers below are from a measurement written for this task and not committed: two
stacks back to back in one process (release build, 4 worker threads, 64 KiB socket buffers),
N idle connections and one busy one, with a timer around each phase of `Driver::turn` in a
copy of the source. It ran through `scripts/bench/slot.sh`, before and after interleaved in
one invocation, two repetitions each (both shown). The host was loaded (load average 10 to 12
for the rows with idle connections, 26 for the rows with N = 1, taken in an earlier
invocation), so the times scatter; the split between the phases is what the tables show.
Times are per turn, averaged over the turns of both drivers.

Request/response, 2000 round trips of one byte:

| N idle | variant | preserve + bridge | smoltcp poll | `poll_delay` | turn | wall |
|---|---|---|---|---|---|---|
| 1 | before | 0.4 / 0.7 us | 0.4 / 0.5 us | 0.1 us | 1.7 / 2.0 us | 43 / 144 ms |
| 1 | after | 0.3 / 0.4 us | 0.4 / 0.5 us | 0.1 us | 1.3 / 1.8 us | 33 / 45 ms |
| 1 000 | before | 36 / 61 us | 23 / 39 us | 15 / 24 us | 61 / 102 us | 0.62 / 1.03 s |
| 1 000 | after | 0.6 / 0.6 us | 24 / 23 us | 15 / 13 us | 25 / 24 us | 0.33 / 0.30 s |
| 10 000 | before | 436 / 427 us | 236 / 231 us | 134 / 133 us | 675 / 660 us | 6.50 / 6.47 s |
| 10 000 | after | 11 / 10 us | 208 / 207 us | 110 / 109 us | 220 / 217 us | 2.65 / 2.62 s |

Bulk, 32 MiB one way:

| N idle | variant | preserve + bridge | smoltcp poll | turn | wall |
|---|---|---|---|---|---|
| 1 | before | 1.1 / 0.8 us | 3.4 / 2.3 us | 6.1 / 4.5 us | 39 / 88 ms |
| 1 | after | 0.8 / 1.2 us | 3.0 / 3.6 us | 5.1 / 6.4 us | 31 / 40 ms |
| 1 000 | before | 27 / 30 us | 137 / 151 us | 165 / 182 us | 0.69 / 0.76 s |
| 1 000 | after | 1.1 / 1.4 us | 144 / 145 us | 146 / 148 us | 0.64 / 0.63 s |
| 10 000 | before | 387 / 378 us | 1695 / 1584 us | 2084 / 1965 us | 7.9 / 7.5 s |
| 10 000 | after | 50 / 49 us | 1339 / 1351 us | 1391 / 1401 us | 6.4 / 6.3 s |

The first invocation (load average 20 to 27) gave the same split with more scatter: 10 000
idle, request/response 8.3 / 6.5 s before and 3.1 / 7.1 s after, bulk 9.3 / 9.8 s before and
7.5 / 7.7 s after. The "after" bridge time includes the periodic pass over every connection,
20 times a second.

An idle stack takes the same 20 turns a second before and after, each a pass over every
connection. With 10 000 connections that pass costs 1.16 / 1.12 ms before and 1.43 / 1.24 ms
after: it now also takes each connection's request flag and checks its two waker
registrations. That is 5 ms more per second and driver at 10 000 idle connections, against
the per-turn saving above.

What is left is smoltcp. It offers each ingress packet to the sockets in slot order
(`process_tcp`), walks every socket in each egress turn (`socket_egress`, once per ingress
packet in `VirtualDevice::poll_interface`) and again for `poll_delay`. That is linear in the
sockets per packet, not per turn, and it is in the fork: a tuple index and a list of sockets
with something to send would have to be added there. Not done here: it needs a tagged fork
release.

### Item 1

A turn bridges only the connections that were signalled since their last bridge pass.

- The application signals through its `TcpConnection`, at the places that already woke the
  driver: a write, a read that empties the stream buffer or takes it out of the full state, a
  shutdown, a drop, an abort.
- smoltcp signals through the socket's receive and send wakers (the fork's `async` feature, a
  feature flag without a new crate). They fire in `set_state` (every state change), `reset`,
  when received bytes are enqueued, when acknowledged bytes are dequeued, and when the RST of
  an abort left. These are all the socket reads `Conn::bridge` depends on: the state, the
  receive queue, the send queue and its room, and the endpoints. smoltcp wakes a registration
  once, so `bridge` registers both wakers first thing in every pass.
- The flag in `tcp::Mark` is the request: set with the queue entry, taken right before the
  connection is bridged. A signal after that queues the connection again; a signal before it
  is seen by the pass, because the application changes its state under the connection's lock
  before it signals.
- A pass over every connection still runs once 50 ms passed since the last one
  (`FULL_PASS_INTERVAL`). The idle timeout and the release of a closed socket with unread
  bytes after the timeout have no signal and need it. It also bounds what a signal the
  tracking missed could cost: 50 ms, the same bound the periodic turn gave before.
- With `tcp_send_budget` every turn bridges every connection: a connection's share of the
  budget changes when another connection starts or stops sending. Left as it was.
- `preserve_all` became `preserve_signalled`. A socket turns terminal with a state change,
  which signals it, and the pass that takes the signal moves every byte of a terminal socket,
  so a connection without a signal has nothing to preserve.
- `promote` walks the listener pool, at most `listener_pool` sockets: not linear in the
  connections, left alone (30 to 90 ns per turn in the measurement).

Proof beyond the reading above: `Driver::assert_bridged` runs after every bridge pass in the
crate's tests (where the application runs on the driver's thread) and fails when a
connection without a request has anything a bridge pass would do. It fired in both red runs
below. `stack/tests/signalled.rs` switches the periodic pass off, so each step moves only by
its own signal: an application write on an idle connection, peer data on an idle connection,
close and abort from either side, the release after each, a read that reopens the stack's
closed window, and acknowledgements that refill a full send buffer.

### Item 2

The cap has been in the crate since its first commit, without a stated reason. It is the only
wake-up for the work that has none of its own: the idle timeout and the release of
connections, a `connect_tcp` whose caller gave up, a handshake that ended (`release_inbound`
runs at the start of the next turn), listener sockets to reclaim, the expiry of fragments and
discard records (the reference documents that it rides on this timer), and the pruning of UDP
marks. So it is a guard and it stays, wherever one of those can exist: `Driver::timed` is
true while the socket set holds a socket, the stack has a reassembler, a UDP mark is held or
the egress backlog is not empty. A stack with none of them sets no timer; everything that
can give it work arrives through a queue or the notification `wait` already selects on.

A stack with `reassembly` configured keeps the timer also while it is empty. Checking the
reassembler and the discard records for emptiness would let it sleep too; left out, as the
records are written from other threads without waking the driver.

### Item 3

(a) `NetStackConfig::max_connections`, default `None`. It counts what
`TransparentConfig::max_connections` counts (connections, handshakes, connects, the SYNs of
the batch) and refuses the same way (RST, `rejected_connection_limit`); with both set the
lower applies. `connect_tcp` counts towards it and is never refused, as in transparent mode.

(b) Documented in the field's rustdoc and in the reference. Measured with the same harness
and the default buffers (glibc): 1000 idle connection pairs add 21.5 MiB of resident memory,
11 KiB per connection end, although each end has 1.35 MiB of socket buffers: `vec![0; n]` of
this size is a fresh zero mapping, resident only where written. With 64 KiB buffers the same
1000 pairs take 39 MiB (the allocator serves those from its heap). A connection that carried
1 MiB one way added about 1.8 MiB (the sender's send buffer, the receiver's receive buffer,
the stream buffers). smoltcp's ring buffer starts over at offset 0 when it runs empty, so
only a transfer that keeps the buffer non-empty wraps through all of it. The sizing rule
documented is the full size.

(c) Nothing is allocated for idle listeners. The pool is sized per turn from the SYNs of the
batch: a socket is created in the turn that takes its SYN, and one left in `Listen` is
removed by the next turn. A stack without connections holds no smoltcp socket; the new idle
test shows it (the driver sleeps only with an empty socket set). No change.

### Item 4

The source is known at SYN admission: the tag of the packet (the ingress label) where the
consumer sets one, and the source address in any case.
`NetStackConfig::listener_pool_per_source` bounds the sockets one source holds in
SYN-RECEIVED; the driver counts the handshakes in progress (`inbound`, at most the pool) and
the SYNs recorded in the current turn (`Labels::syns`), so no state was added. Refusals get a
RST and are counted in the new `NetStackStats::syn_refused_source`.

The default is `None`, not half the pool as the audit suggested. A stack with one source
(one peer behind the tunnel) accepts 32 simultaneous handshakes today; a default share of 16
would refuse the 17th of a legitimate burst. The reference recommends half the pool for
stacks with several sources.

Not applied under `Admission::Decide`: a held SYN is not in the pool, and the application
decides each connection with the peer address and the label in hand.

Found on the way and fixed in its own commit: a listener socket had no timeout, and smoltcp
retransmits a SYN-ACK without an end. A peer that sent a SYN and never answered again held
its pool socket for good, so 32 such SYNs ended every inbound TCP connection of a default
stack until restart, with or without a share. An inbound handshake without a segment from
its peer for 60 s (`HANDSHAKE_TIMEOUT`, about the 63 s Linux gives a SYN-ACK) is now reset
and counted in `handshake_failed`; the timeout is lifted at promotion.

### Item 5

Left as is; the earlier conclusion holds. A port is occupied while a socket in `conns` or
`connecting` has a local endpoint, and a socket loses it inside smoltcp's poll (a RST
received, the last ACK of a close, the RST of an abort sent, a timeout). The wakers of item 1
now report those moments for connections, but only as a request for the next bridge pass,
while commands run at three other points of a turn (`take_commands` before the poll,
`release_aborted` after the second poll, the command branch of `wait`). A count kept by hand
would still hold the port between the poll that cleared the endpoint and the pass that
notices, which the set read from the sockets does not: `connect_tcp_from` would fail with
`AddrInUse` in that window, and the deferred connects after an abort rely on the port being
free in exactly that turn. Reconciling the queue before every command, for `connecting`
sockets as well (they have no waker), plus the listener ports changed in four places, is more
machinery than the cost justifies: the set costs one hash insert per socket per connect, and
smoltcp's own per-packet walk over the sockets is of the same order for each handshake
packet. The same holds for `connect_udp`: whether a connected socket is live is read from its
channel (`is_closed`), which has no hook either.

## Validation

Tests seen failing first:

- `stack::tests::signalled` (9 tests): with the application's signal not queueing the
  connection, 6 fail; with smoltcp's wakers not queueing it, 6 fail (together all but the
  periodic pass test); `assert_bridged` names the missed work in each.
- `stack::tests::idle`: `a_stack_without_tcp_sockets_takes_no_turn_until_woken` and
  `the_periodic_turn_runs_while_a_connection_exists_and_stops_after_it` fail before item 2
  (10 turns against 2); `a_stack_with_reassembly_keeps_its_periodic_turn` passes before and
  after, it holds the guard.
- `stack::tests::connection_limit`: the SYN beyond the limit gets a SYN-ACK without the check
  in `ingest`.
- `stack::tests::half_open`: `a_handshake_that_never_completes_gives_its_socket_back` fails
  without the timeout (`handshake_failed` 0 after 65 s),
  `an_established_connection_outlives_the_handshake_timeout` fails with the timeout not
  lifted at promotion, and the three share tests fail with the share not consulted.

Gates, all passing: `cargo fmt --all --check`, `cargo hack clippy -p nsplane-netstack
--each-feature --all-targets --locked`, `cargo nextest run -p nsplane-netstack -p nsplane-e2e
--all-features --locked` (647 passed, 18 skipped), the doc tests, `cargo deny check`,
`cargo shear`, `typos`, `scripts/check-docs.sh`, `scripts/check-product-terms.sh`, the
examples build, the minimum Rust version check, and clippy for `aarch64-apple-darwin`.

Left undone: the smoltcp side of item 1 (per-packet walk over the sockets), item 5, the
share under `Admission::Decide`, and sleeping on an empty stack that has a reassembler.
