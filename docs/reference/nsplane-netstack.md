# nsplane-netstack

A user-space TCP/IP stack on smoltcp that an engine uses in place of a TUN device: TCP
connections and UDP flows and sockets for the application, transparent termination of
traffic to any destination in configured prefixes with admission events, optional
per-flow admission on every stack with control of each connection or flow from its first
input, per-flow revocation, optional reassembly, and an ownership query for local sides that share one decrypted stream. Builds on
`nsplane`, `nsplane-core` and `nsplane-packet`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `NetStack` (`new`, `split`), `NetStackHandle` (`incoming_tcp`, `incoming_udp`, `incoming_pending`, `flow_events`, `connect_tcp`, `connect_tcp_from`, `bind_udp`, `connect_udp`, `connect_udp_from`, `discard_fragments`, `stats`, `retired_drops`, `owns`) | `Ownership`, `NetStackConfig` (`udp_allow_fragmentation`, `reassembly`), `ReassemblyConfig` (re-export), `NetStackSource` (`tcp_egress_drained`), `NetStackSink`, `TcpConnection` (`AsyncRead` + `AsyncWrite`, `unacked`, `last_ack`, `abort`, `control`), `UdpFlow`, `UdpReply`, `UdpSocket` (`send`, `peer_addr` for a connected one; each with `control`), `FlowControl` (`revoke`, `is_revoked`, `delivery`, `bind_context`, `context`), `RetirementReceipt` (`outcome`, `wait`), `RetirementOutcome` (`Retired`, `Failed`, `Unknown`), `DeliveryReceipt` (`outcome`, `wait`), `DeliveryOutcome` (`Delivered`, `NotDelivered`), `Undelivered` (`Rejected`, `TimedOut`, `ConnectionLimit`, `NoListener`, `HandshakeFailed`, `AcceptQueueFull`, `AcceptQueueGone`, `FlowLimit`, `Revoked`, `Stopped`), `FlowContext` (`domain`, `instance`), `NetStackStats`, `DEFAULT_MTU`, `MIN_MTU` |
| admission | `NetStackConfig::admission`, `NetStackHandle::incoming_pending` | `Admission` (`Immediate`, `Decide { timeout, max_pending }`), `PendingFlow` (`protocol`, `peer_addr`, `local_addr`, `control`, `accept`, `reject`), `PendingProtocol` (`Tcp`, `Udp`) |
| transparent mode | `NetStackConfig::transparent`, `NetStackHandle::flow_events` | `TransparentConfig` (`prefixes`, `max_connections`, `events`; `admission` deprecated, replaced by `NetStackConfig::admission`), `FlowEventsConfig` (`capacity`, `rate`, `burst`), `FlowEvent` (`at`, `protocol`, `src`, `dst`, `allow`, `reason`), `FlowEventReason` (`Admitted`, `Hook`, `Timeout`, `TableFull`, `ConnectionLimit`, `Prefix`) |

## Behavior

### Stack and driver

`NetStack::new` starts a user-space TCP/IP stack on smoltcp for the addresses in its
`NetStackConfig`, and `NetStack::split` yields a `NetStackSource` (egress) and a
`NetStackSink` (ingress) that an `EngineBuilder` takes in place of a TUN device. The
application side is `NetStackHandle`: `incoming_tcp` and `incoming_udp` accept connections
and flows to any port of the stack's addresses, `connect_tcp`, `bind_udp` and
`connect_udp` open them.

One driver task owns smoltcp. Each iteration takes a bounded batch of ingress packets,
sizes the TCP listener pool to the batch's SYNs, then ingests the packets one by one with a
single smoltcp egress turn after each (`poll_ingress_single` / `poll_egress`), moves
connection bytes between smoltcp and the applications, and flushes egress. UDP bypasses
smoltcp on its own dispatch path. Ingress is taken with `poll_recv_many` (at most 256 packets
per turn, in order), and egress TCP segments and UDP datagrams keep 32 bytes of tail room
(`device::TAILROOM`), so the engine seals them in place without reallocating.

### Queues, ports and counters

- Every queue is bounded (ingress, egress, accept and datagram capacities in
  `NetStackConfig`); the sink waits while ingress is full. One driver turn routes up to
  256 ingress packets before any application reads, so a burst to one UDP flow or socket
  beyond `datagram_capacity` loses the excess even when the application keeps up on
  average (`udp_queue_full`). The default is 256, one driver step (the measured loss per
  capacity is in [Performance](../performance.md#netstack)); the queue grows on demand in 32-entry blocks, so an idle flow costs one block (about
  1 KiB, 2 KiB per bound socket) at any capacity, and a full one pins up to 256 ingress
  buffers (about 512 KiB). `netstack_bench`'s server keeps 1024.
- A full accept queue closes new TCP connections (`tcp_not_accepted`) by default. With
  `NetStackConfig::accept_backpressure`, bare SYNs are left unanswered while it is full
  (`syn_deferred`; the peer retransmits) and connections that completed their handshake
  meanwhile wait in the stack, bounded by the listener pool, until the application accepts
  them.
- `connect_tcp` takes an ephemeral port; `connect_tcp_from` a caller-chosen one (`AddrInUse`
  when a connection or listener of the stack has it). Ephemeral TCP and UDP ports start at a
  random point of 49152-65535 per stack and then go up in order.
- Everything the stack discards is counted per reason in `NetStackHandle::stats`
  (`NetStackStats`): malformed, foreign or unsupported packets, refused SYNs, connections
  and flows not accepted, full UDP queues, the flow limit, and egress produced while the
  egress backlog is full.
### TCP segments, path MTU and buffers

- smoltcp sees the configured MTU as its device MTU, so it advertises an MSS of `mtu - 40`
  (IPv4) or `mtu - 60` (IPv6) and no emitted packet exceeds the MTU, which the source
  reports and never changes. Socket buffers hold 512 IPv4-sized segments, so the window
  scales with the MSS.
- Path MTU discovery for the stack's own TCP (RFC 1191 / RFC 8201): an ICMP
  Destination Unreachable / Fragmentation Needed (type 3 code 4, next-hop MTU in bytes 6-7)
  or an `ICMPv6` Packet Too Big (type 2, MTU in bytes 4-7) to a stack address lowers the
  MSS of the connection whose segment it quotes to `mtu - 40` (IPv4) or `mtu - 60` (IPv6),
  so a stack at 1420 over a path whose inner MTU is smaller (a 1376 relay path) does not
  stall on segments the path drops. The quote must be a TCP segment (IP header and at
  least 8 bytes: ports and sequence number) of the message's family from the stack's
  address, on the `(local, remote)` tuple of a live connection (SYN-RECEIVED or later),
  with its sequence number within `SND.UNA..SND.NXT`; the MTU must be at least 576 (IPv4,
  the stack's `MIN_MTU`) or 1280 (IPv6), below the configured MTU and below the
  connection's current path MTU (it never goes up). An IPv4 message with MTU 0 (pre-RFC
  1191 routers) is ignored, with no plateau guess. Anything else of those two types is
  dropped and counted in `NetStackStats::icmp_ignored`; other ICMP messages count as
  `unsupported`. Checksums are not verified, as for the rest of the ingress.
  Applying a message calls the fork's `tcp::Socket::reduce_mss`, which resends the data in
  flight at once from `SND.UNA` in segments of the new size, without a congestion window
  or timer back-off (the drop was not congestion). The connection is found by a scan of
  the socket set per message, so nothing is stored and the TCP path pays nothing: ICMP is
  classified after TCP and UDP. The lowered MSS lasts for the connection (no
  increase probing, RFC 1191's 10-minute timer is not implemented). UDP is out of scope:
  datagrams are sent with DF and an oversize one fails with `InvalidInput` at the
  configured MTU.
- `NetStackConfig::tcp_rx_buffer` / `tcp_tx_buffer` (default `None`: the 512 segments
  above) size every TCP socket's buffers, listener pool sockets included, clamped to one
  IPv4 MSS (`mtu - 40`) at least and `65535 << 14` (the largest window TCP can advertise,
  under smoltcp's 1 GiB limit) at most. The receive buffer is the window: smoltcp's
  `Socket::new` derives the window-scale shift from its capacity (its bit length minus 16,
  at least 0), so the SYN and SYN-ACK carry a scale and initial window
  matching it with no further code. A window of more segments than the queues on the path
  hold loses its tail when the peer sends it at once (see the field docs and
  [Performance](../performance.md#socket-buffers)). SYNs refused for a full listener pool
  (sized by `NetStackConfig::listener_pool`) are counted in `NetStackStats::syn_refused`.
- `NetStackConfig::tcp_send_budget` (default `None`) bounds the bytes all TCP connections
  of the stack hold in their send buffers together, split evenly between the connections
  with data to send (each at least one IPv4 MSS, at most its `tcp_tx_buffer`). Without it
  `n` bulk connections put `n` windows on the path at once: four default windows are 2048
  segments against the receiving engine's 1024-packet deliver queue, and the excess is
  dropped as `DROP_SINK_FULL`. It is opt-in because it also caps all connections together
  at `budget / RTT`, which limits parallel connections on a long path; see
  [Queue depths](nsplane.md#queue-depths) for when to set it. Unset, the bridge pass skips counting
  the senders and every connection's limit is `usize::MAX`.
- `NetStackConfig::tcp_min_rto` and `tcp_initial_rto` (default 1 s each, smoltcp's
  defaults, RFC 6298 2.4 and 2.1) are applied to every TCP socket, listener pool sockets
  included, through smoltcp's `set_min_rto` / `set_initial_rto`. Both are taken in whole
  milliseconds and clamped to 1 ms..=60 s, as smoltcp does; the largest RTO after
  exponential back-off stays smoltcp's 60 s. smoltcp samples RTTs in whole milliseconds, so
  on a path whose round trip is far below the minimum, the minimum alone sets the RTO and
  every loss that neither fast retransmit nor the tail loss probe recovers costs at least
  that long (see [Performance](../performance.md#netstack) for a run with 20 ms). A
  minimum below the peer's delayed-ACK time turns its delayed ACKs into spurious
  retransmissions; the stack's own sockets do not delay ACKs. A lowered minimum applies
  from a connection's first RTT measurement; the initial RTO times the SYN, the SYN-ACK
  and data sent before a round trip was measured.
### Oversize UDP

- UDP datagrams are built with DF set over IPv4 and an application payload whose packet
  exceeds the MTU fails with `InvalidInput`. With `NetStackConfig::udp_allow_fragmentation`
  an IPv4 one instead leaves as a single oversize packet with DF clear (up to the 65 535-byte
  total length), for the engine's fragmenter (`EngineBuilder::fragmenter`) to split; the
  UDP egress bypasses smoltcp, so nothing in the stack caps it, and the source keeps
  reporting the configured MTU. IPv6 fails.
### TCP progress and abort

- `TcpConnection::unacked` and `TcpConnection::last_ack` report send progress: after
  smoltcp ran, each bridge pass reads the socket's send queue (bytes taken from the
  application and not acknowledged; smoltcp exposes no SND.NXT, so bytes held back for the
  peer's window count too) and stores it in an atomic shared with the connection when it
  changed; a queue smaller than at the end of the previous pass means SND.UNA advanced
  (only an acknowledgement shrinks it, except a reset, which leaves the socket closed and
  is not counted), so the pass's time is stored as `last_ack`. No lock, no per-packet or
  per-byte work; the values stay readable after the socket is released.
- Dropping a `TcpConnection` closes it gracefully (FIN; the socket stays until the close
  completes). `TcpConnection::abort` resets it instead: the driver turn that observes the
  abort resets the socket and discards its unread and unsent bytes, the poll after the
  bridge pass sends the RST, and the connection is released (tuple out of the `owns` table,
  socket removed, `terminated` resolved) in the same turn when the device had room for the
  RST, else in the next. A connection the peer already reset or closed is released without
  an RST. A `connect_tcp_from` of a port an aborted connection still holds is deferred by
  the driver and retried once that release frees the port, so it succeeds when issued right
  after the abort. A connection without traffic for 5 minutes takes the same path, so the
  idle timeout also sends the peer an RST before the release. Unused, the abort costs one
  state compare under the connection's existing lock and two empty-`Vec` takes per driver
  turn. A reset peer reads `Ok(0)` and writes fail with `BrokenPipe`.
### Connected UDP sockets

- `connect_udp` / `connect_udp_from` open a `UdpSocket` connected to one remote: the local
  end is the stack's address of the remote's family (an unspecified `local` stands for it,
  port 0 picks an ephemeral port), `send` goes to the remote (`NotConnected` on a bound
  socket) and `peer_addr` returns it (`None` on a bound socket). A datagram goes to the
  connected socket of its exact tuple first, then to a socket bound to its exact address,
  then to one bound to the unspecified address, then to a flow; other remotes still reach a
  bound socket or `incoming_udp`. Errors: `InvalidInput` (unspecified remote, other-family
  local), `AddrNotAvailable` (no stack address of the family, or another address),
  `AddrInUse` (a live connected socket or flow on the tuple, or no free port),
  `BrokenPipe` (stack stopped). The connected table is checked only while not empty: one
  `HashMap::is_empty` per UDP datagram when unused.
### Ownership

- `NetStackHandle::owns(packet)` answers `Ownership::{Flow, Listener, None}` synchronously
  for a local side that shares one decrypted stream between the stack and other consumers
  (a `Splitter` closure). It reads one table of tuples behind a mutex, keyed
  `(local, remote)`: TCP connections are registered when a connect is queued (by the handle
  for `connect_tcp_from` with a port, by the driver before the SYN is emitted for an
  ephemeral port), when a listener socket enters SYN-RECEIVED (after the poll that ingested
  the SYN, before the SYN-ACK is flushed) and when a socket is adopted as a connection;
  bound and connected UDP sockets and UDP flows when they are created. Each registration is dropped with
  what holds it (the released connection, the abandoned or failed connect, a handshake
  socket back in `Listen` or closed, the dropped `UdpSocket` or `UdpFlow`, whose
  registration goes before its queue closes so a rebind or a new flow never races it), so
  the table changes per connection, never per packet, and costs nothing per packet when
  `owns` is not called. `Flow` is an exact tuple match (any remote for a bound UDP socket,
  only its remote for a connected one) or an ICMP/ICMPv6 error quoting a packet sent on a registered tuple; `Listener` a bare SYN
  or UDP datagram to a stack address otherwise; `None` everything else, fragments (dropped
  by the stack) and every packet once the driver stopped. The answer reflects the state at
  the call. With reassembly on, TCP and UDP fragments to a stack address are the stack's:
  `Flow` for a first fragment on a registered tuple, `Listener` for any other first
  fragment. A later fragment carries no ports, so `owns` remembers each first fragment it
  classified as `Flow` by `(src, dst, protocol, id)` (the reassembler's key: `protocol`
  only for IPv4) and reports the later fragments of that datagram as `Flow`; the entry
  lives `ReassemblyConfig::timeout`, the memory holds at most `max_datagrams` entries
  (oldest dropped) and `discard_fragments` clears the datagram's entry. A later fragment
  that arrives before its first, or after the memory forgot it, is `Listener`. Only
  fragment classification takes this memory's lock; without reassembly none exists.
### Reassembly

- `NetStackConfig::reassembly` gives the driver one `nsplane_packet::reassembly::Reassembler`
  (none is created without it). Before `classify`, every ingress packet to a stack address
  is pushed into it: a non-fragment passes unchanged, a fragment is held, and a completed
  datagram continues through the normal ingress as one packet (UDP dispatch, or smoltcp for
  TCP). Expiry runs at the start of each driver turn, which the driver's existing timer
  (at most `MAX_POLL_DELAY`, 50 ms) already wakes, and is a single emptiness check while no
  datagram is held. The reassembler's counts are added to `NetStackStats` after each push
  or expiry: `reassembled`, `reassembly_timeout`, `reassembly_overflow`, and overlapping or
  invalid fragments as `malformed`. Without it, fragments count as `unsupported`.
- `NetStackHandle::discard_fragments(src, dst, protocol, id)` is for a local side that
  revokes a flow's admission while one of its datagrams may be half reassembled. The call
  records the datagram (IPv4 16-bit id widened to `u32`, IPv6 32-bit id; `protocol` only
  narrows an IPv4 key) synchronously under one short lock, so from then on the driver drops
  every fragment of it, those already queued in the `NetStackSink` included, and counts
  them in `reassembly_overflow`; the fragments the reassembler holds never complete and
  expire at the reassembly timeout (`reassembly_timeout`). The record lives
  `ReassemblyConfig::timeout`, so a later datagram with the same id starts afresh, and at
  most `max_datagrams` records are kept (the oldest forgotten early). Without reassembly
  the call does nothing; with it and nothing discarded, the driver checks one atomic per
  ingress packet and takes no lock.
### Congestion control

- Every TCP socket (connect and listener pool) runs CUBIC congestion control (smoltcp
  feature `socket-tcp-cubic`, no extra crate). Without it smoltcp sends the whole peer
  window at once and, after a retransmission timeout, all of it again; a hop that drops
  part of the burst (a full socket buffer on a loaded host) drops the retransmission too,
  and the timeouts (at least `tcp_min_rto`, doubling) add up. CUBIC rather than Reno: both restart
  from one segment after a timeout, CUBIC recovers faster under random loss and is the
  default of Linux, Windows and macOS; its `f64` arithmetic is no concern on the targets
  nsplane runs on.

### smoltcp fork

smoltcp is the `dotns/smoltcp` fork (tag `v0.14.0-nsplane.7`, ADR
[2026-10-03-smoltcp-fork](../decisions/2026-10-03-smoltcp-fork.md)): upstream smoltcp `main`
at `24bda3b` plus the changes below. Upstream smoltcp itself keeps outstanding data under the
retransmission timer when the peer's window closes (RFC 6298 5.1) and arms the zero-window
probe timer when a timeout finds the window closed; it keeps a fast retransmission pending
until its segment is emitted, also while the egress backlog is full; and it has the
per-socket RTO bounds behind `tcp_min_rto` and `tcp_initial_rto`.

Recovery when both ends send under loss:

- Every empty segment carries the highest sequence number sent (RFC 9293 `SEQ=SND.NXT`)
  and does not move the send position, so a peer that already received past a
  retransmission point still accepts the acknowledgements.
- A FIN in flight is left to the retransmission timer; duplicate ACKs do not replace it by a
  fast retransmission.

Throughput:

- The TCP/IP checksum sums 64-bit words into two `u128` accumulators (no `unsafe`),
  bit-identical to 0.14's (an equivalence test over lengths 0-2000 at 16 offsets).
- The advertised right edge of the receive window never moves left: under window scaling
  the free space is rounded up when rounding down would shrink the edge, with the window end
  capped at the buffer.
- Fast recovery retransmits the next hole on a partial ACK (NewReno, RFC 6582, careful
  variant; Reno and CUBIC `on_partial_ack`).
- The sender avoids the silly window syndrome (Minshall's variant of Nagle): a sub-MSS
  segment cut by the peer's window is held while an earlier sub-MSS segment is
  unacknowledged.
- Limited Transmit (RFC 3042): the first two duplicate ACKs each release one new segment, so
  small windows still reach the third duplicate ACK and fast retransmit.

Path MTU: `tcp::Socket::reduce_mss` (above).

Tail loss probe, in the manner of RFC 8985 section 7. Next to the retransmission timer runs a probe timeout of two smoothed RTTs plus 10 ms
(plus 200 ms for a delayed ACK when one segment is in flight), restarted by every
segment sent and every ACK of new data. When it expires, the first unacknowledged
segment is resent once, and fast recovery starts unless a recovery is already running;
the retransmission timer keeps running for a lost probe. The probe is armed only when it
expires before the retransmission timeout, so with a `tcp_min_rto` below the probe timeout
the retransmission timer recovers the loss alone. Unlike RFC 8985 the probe
resends the first unacknowledged segment rather than the last (smoltcp keeps no SACK
scoreboard, so that is where the loss must be) and also runs in fast recovery and after
a timeout, where it resends a lost retransmission: the role RACK has in RFC 8985. SACK is not used:
smoltcp's receiver reports a single SACK block, so a sender scoreboard would see little of
the holes; the probe needs no state beyond one flag and one timer field and no receiver
change. A lost probe waits for a retransmission timeout of at least `tcp_min_rto`.

The engine's `DROP_SINK_FULL` is ordinary loss to TCP: a decrypted segment the engine drops
at the full sink is never acknowledged, the retransmission timer stays armed and smoltcp
resends it.

### Transparent mode

With `NetStackConfig::transparent: Some(TransparentConfig)` the stack is the endpoint for TCP
and UDP addressed to any destination inside `TransparentConfig::prefixes`, not only to its
own `addresses`.

- **Destinations.** `prefixes` lists addresses with prefix lengths of either family; an
  empty list means every address of both families. A prefix length longer than the family
  allows is clamped to 32 or 128 and host bits are ignored. A packet to a destination that
  is neither one of the stack's addresses nor inside a prefix is dropped and counted in
  `no_address`, as without transparent mode, and also in `rejected_prefix`. Which
  destinations reach the stack at all is decided in front of it: the peers' allowed IPs,
  `PeerConfig::inbound_destinations`, the ACL or a `Splitter`. The stack only terminates
  what the engine delivers.
- **Addresses of a connection.** On an accepted `TcpConnection` or `UdpFlow`,
  `local_addr()` is the original destination (the address the peer dialed) and
  `peer_addr()` the source. The stack sources SYN-ACKs, data, RSTs and UDP replies from the
  original destination, so the peer sees answers from the address it dialed.
- **Shared bounds.** Every bound of the stack applies to all addresses together: the
  listener pool (per destination port and in total), `max_udp_flows`, the accept queue and
  every other queue. Fragments to in-prefix destinations are reassembled within the same
  `reassembly` bounds, ICMP Fragmentation Needed / Packet Too Big is matched by the quoted
  tuple alone, and `owns` treats in-prefix destinations as the stack's (`Listener` for a bare
  SYN or datagram). `connect_tcp`, `connect_udp` and `bind_udp` still require one of the
  stack's own `addresses`.

#### Connection limit and counters

`TransparentConfig::max_connections` bounds the TCP connections the stack holds at once
(accepted, mid handshake, or opened with `connect_tcp`, until released). At the limit, the
bare SYN of a new connection is answered with a RST from its original destination and
counted in `rejected_connection_limit`; a retransmitted SYN of a handshake in progress is not
a new connection. Under `Admission::Decide` the limit is checked when the SYN arrives and
again when the connection is accepted. Default `None`: no limit beyond the listener pool and
the accept queue.

Under `Admission::Immediate` a transparent stack counts every new connection and flow in
`accepted`; `rejected_prefix` counts per packet (also in `no_address`). The other admission
counters are under [Admission](#admission).

#### Flow events

`TransparentConfig::events: Some(FlowEventsConfig)` opts in to admission events: one
`FlowEvent` per increment of `accepted` or of a `rejected_` counter, on
`NetStackHandle::flow_events`. An event carries `at` (read from the tokio clock), the IP
`protocol`, `src` (the peer), `dst` (the original destination; ports are 0 for a packet
without readable ports), `allow` and a `FlowEventReason` (`Admitted`, `Hook`, `Timeout`,
`TableFull`, `ConnectionLimit`, `Prefix`). Prefix rejections emit per packet.

- **Bounded.** `capacity` events are buffered for the receiver (default 1024; 0 is taken
  as 1).
- **Rate limited.** A token bucket of `burst` tokens (default 1000) refilled at `rate`
  events per second (default 1000) limits emission; the bucket starts full, `rate` 0 never
  refills it and `burst` 0 emits nothing.
- **Lossy.** The driver never waits on the channel: an event beyond the bucket, finding the
  buffer full or the receiver gone is dropped and counted in `events_dropped`; delivered
  events are counted in `events_emitted`.
- `flow_events` hands its events to the first call only; later calls, and every call
  without events configured, return a stream that ends at once. The stream ends when the
  stack stops; once it is dropped every event is counted as dropped.

Off (`events: None`, the default) there is no channel and the cost is one `Option` check on
the admission and rejection paths; established traffic pays nothing.

#### Cost

Without transparent mode (the default) a bare SYN, a new UDP flow and a packet to a foreign
address each take one `Option` check; established connections and flows pay nothing. In
transparent mode, the prefix check is a scan of the configured prefixes for packets not
addressed to the stack's own addresses. A pending entry costs the held packet and a few
words; expiry rides on the driver's timer, with no task per entry. `nsplane-e2e`
`netstack_transparent` covers Immediate admission for both families, Decide accept and
reject (RST and ICMP / `ICMPv6` port unreachable observed at the client) and the
`no_address` drops without transparent mode.

### Admission

`NetStackConfig::admission` decides how a new TCP connection (a bare SYN) or UDP flow (its
first datagram) is admitted, on every stack: to the stack's own addresses, and on a
transparent stack to every in-prefix destination too. A transparent stack also honours the
deprecated `TransparentConfig::admission` while the top-level field is `Immediate`; a
`Decide` at the top level takes precedence.

- `Admission::Immediate` (default): accepted on arrival.
- `Admission::Decide { timeout, max_pending }`: the SYN or first datagram is held in a
  pending table and offered on `NetStackHandle::incoming_pending` as a `PendingFlow` with
  its `protocol()`, `peer_addr()` (the source), `local_addr()` (the destination the peer
  dialed) and `control()` (see [Control from the first input](#control-from-the-first-input)).
  `accept()` admits it: the stack answers the held SYN with SYN-ACK (the connection arrives
  on `incoming_tcp` once established) or opens the flow with the held datagram on
  `incoming_udp`, and counts it in `accepted`. `reject()`, or dropping the item, rejects it
  (`rejected_hook`). Decisions take effect on the next driver turn and never wait; a
  decision after the timeout, after a revoke or after the stack stopped does nothing.
  - No decision within `timeout`: rejected, counted in `rejected_timeout`.
  - `max_pending` entries held, or `max_pending` items not taken from `incoming_pending`:
    a new connection or flow is rejected at once, counted in `rejected_table_full`.
  - While a connection is held, its retransmitted SYNs are absorbed. While a flow is held,
    its further datagrams are dropped and counted in `udp_queue_full`: a held flow queues
    its first datagram only. An accepted flow opens in the flow table with its held
    datagram.
  - `incoming_pending` hands its items to the first call only (on any clone of the handle);
    later calls, and every call without `Decide`, return a stream that ends at once. The
    stream ends when the stack stops.

A rejected TCP connection is answered with a RST and a rejected UDP flow with an ICMP port
unreachable (type 3 code 3) or `ICMPv6` port unreachable (type 1 code 4) quoting the
datagram, both sourced from the destination the peer dialed (on a stack without
`transparent`, one of its own addresses), so the peer sees a refused connection or an
unreachable port at the address it dialed. Without `transparent` there is no connection
limit beyond the listener pool and the accept queue.

`NetStackStats` carries the outcome: `pending` (a gauge: connections and flows held now),
`accepted`, `rejected_hook`, `rejected_timeout`, `rejected_table_full` and, on a transparent
stack, `rejected_connection_limit`. Each held connection or flow leaves `pending` accepted,
counted in exactly one `rejected_` field, or revoked (counted nowhere). An accepted SYN may
still be refused by the listener pool (`syn_refused`) or fail its handshake
(`handshake_failed`), and an accepted datagram may meet the flow limit or a full accept
queue.

### Per-flow control and retirement

Every `TcpConnection`, `UdpFlow` (shared with its `UdpReply` clones) and `UdpSocket` gets
one `FlowState` when the driver creates it, and `control()` hands out a `FlowControl` on
it: valid after the data handles moved, were aborted, dropped or released.

- `FlowControl::revoke` flips the flow's revoked bit, clears its TCP stream buffers, wakes
  its blocked reads, writes and sends, and queues the flow for the driver; it never waits
  and sends nothing (no FIN, no RST: the peer times out or gets the stateless RST on its
  next segment). From then on every data handle fails with `ConnectionAborted`
  (`UdpFlow::recv` returns `None`). Repeated calls share the first call's outcome.
- The driver takes the revocations at the start of its next turn and in that turn removes
  the flow's socket (without an RST, also from the aborting list) or its queue entry,
  replaces the flow's packets in the egress backlog by empty placeholders, fences those
  possibly in the egress queue, and bars the flow's tuple in the reassembler if it holds
  fragments. Nothing in it waits for the peer, TIME-WAIT, an RST or egress room.
- Egress positions identify output without a per-packet tag for TCP: the driver counts
  packets it moves into the egress queue, `NetStackSource` counts packets it takes, and a
  TCP flow owns the tuple's packets in `[start, end)`. UDP datagrams are marked with their
  flow. The source drops placeholders (they keep later positions intact), packets of a
  fenced TCP window and fenced UDP positions; none of them reaches the engine, none counts
  in `NetStackStats`. Everything dropped for a revoked flow counts in
  `NetStackHandle::retired_drops`.
- `RetirementReceipt` reports `Retired` (state removed, queued output dropped), `Failed`
  (state removed, but a bound below was full, so output in the egress queue or a held
  fragment may still leave) or `Unknown` (the driver stopped first, or had stopped: a stopped
  stack never claims a retirement). `wait` is cancellation-safe and repeatable.
- Proof boundary: the stack only. A packet `NetStackSource::recv` already returned belongs
  to the engine and is not covered.
- `FlowControl::bind_context(domain)` labels the flow once with an opaque `FlowContext`:
  the caller's domain and an instance from a process-wide counter that never repeats (and
  refuses with `QuotaExceeded` when used up). The stack never reads it; a same-tuple
  re-open is a new flow with a new state, new queues and a new instance.

Bounds of the retirement state; a full table fails the revoke (`Failed`) after the flow's
own state is removed, it never grows past its bound:

| State | Bound | When full |
| --- | --- | --- |
| UDP marks (flow of each queued datagram) | the backlog (256) plus `egress_capacity`, pruned every turn | cannot fill: a mark exists only with its datagram's queue slot |
| UDP fence positions | `egress_capacity` per fence (positions in the egress queue only) | n/a |
| Fences (TCP windows and UDP position lists) | 1024 per stack, dropped once the source passed them | `Failed` |
| Reassembly barriers | `ReassemblyConfig::max_datagrams`, each for one reassembly timeout | `Failed` |

Without a revoke the per-packet cost is one relaxed load per driver turn, a position
counter on each side of the egress queue, one atomic load per packet in the source while
no fence exists, and an `Arc` clone per UDP datagram sent (measured by the `send_stream`
and `netstack_udp_send` benches, see [Performance](../performance.md#netstack)).
The unit tests `src/stack/tests/flow_control.rs`, `flow_context.rs` and `flow_bounds.rs`
and `nsplane-e2e`'s `tests/netstack_flow_retirement.rs` cover the outcomes, the bounds and
same-tuple re-opens.

### Control from the first input

Under `Admission::Decide` a connection's or flow's lifetime gets its `FlowState` when the
driver holds its first input, not when the handle is created. `PendingFlow::control`
returns its `FlowControl`, and the `TcpConnection` or `UdpFlow` handed out later carries the
same control: a `FlowContext` bound on the pending control stays on the handle, and a
revoke through either is one revoke. The driver binds the lifetime's target once: held (the
tuple), then the listener socket that takes the accepted SYN, or the flow entry.

- **Delivery receipt.** `FlowControl::delivery` returns a `DeliveryReceipt` (`outcome`, a
  cancellation-safe `wait`). Each lifetime has exactly one `DeliveryOutcome`, fixed by one
  compare-and-swap: `Delivered` when the `incoming_tcp` / `incoming_udp` stream takes the
  handle, or `NotDelivered(Undelivered)` at the first event that ends the lifetime before.
  A stream that finds a handle whose lifetime ended skips it, so it never returns it.
  Handles admitted with `Immediate` and those the application opens (`connect_tcp`,
  `bind_udp`, `connect_udp`) report `Delivered` from the start.

| `Undelivered` | When | Counter |
| --- | --- | --- |
| `Rejected` | `reject()`, or the item dropped | `rejected_hook` |
| `TimedOut` | no decision within `timeout` | `rejected_timeout` |
| `ConnectionLimit` | `max_connections` reached at the accept | `rejected_connection_limit` |
| `NoListener` | the accepted SYN found no listener socket (`listener_pool`) | `syn_refused` |
| `HandshakeFailed` | the socket in SYN-RECEIVED was reset, or the connection closed before the stack took it | `handshake_failed` |
| `AcceptQueueFull` | `incoming_tcp` / `incoming_udp` full (without `accept_backpressure` for TCP) | `tcp_not_accepted` / `udp_not_accepted` |
| `AcceptQueueGone` | the stream was dropped: before the hand-out, or with the handle in its queue | `tcp_not_accepted` / `udp_not_accepted` before the hand-out |
| `FlowLimit` | `max_udp_flows` reached at the accept | `udp_flow_limit` |
| `Revoked` | `FlowControl::revoke` before the hand-out | none |
| `Stopped` | the stack stopped first | none |

- **Revoke before the hand-out.** The driver turn that observes the revoke retires the
  lifetime at its stage and sends nothing: the pending entry (no RST or port unreachable; a
  decision on the item afterwards does nothing); an accepted SYN not in smoltcp yet; the
  listener socket in SYN-RECEIVED, released without an RST, with its SYN-ACK dropped from
  the backlog or fenced in the egress queue from the egress position the socket took the
  SYN at; the established connection waiting for `incoming_tcp`; the flow entry with its
  queued datagrams; and a reassembly barrier as for any revoke. `RetirementOutcome` keeps
  its meaning: `Retired` when the stack holds nothing of the lifetime, `Failed` when a
  bounded table is full, `Unknown` when the stack stopped. A lifetime that already ended
  undelivered holds nothing and retires at once; an answer already sent (the RST or port
  unreachable of a rejection) is not withdrawn. A later SYN or datagram on the tuple is a
  new lifetime.
- **Refusals** are those of every control: `bind_context` on a revoked lifetime, a second
  bind, exhausted instances. `NetStackSource::tcp_egress_drained` rejects a lifetime that
  has no connection yet (`InvalidInput`).
- **Bounds.** The stack tracks the lifetimes whose delivery is open to end them when it
  stops: a list pruned of decided ones whenever it doubles, so at most twice the open ones
  (the pending table, the listener pool, the waiting connections and the accept queues
  bound those).
- **Cost.** `Immediate` keeps its path: no state before the hand-out, one load per handle
  taken from a stream. Under `Decide` the `FlowState` is allocated at the hold instead of
  at adoption, plus one compare-and-swap per hand-out and one stage check per item the
  streams take.

The unit tests `src/stack/tests/first_input.rs` cover a revoke at every stage, every
`Undelivered` reason, a revoke racing the hand-out on a multi-thread runtime, ordinary stacks
deciding, and same-tuple lifetimes; `nsplane-e2e`'s `tests/netstack_first_input.rs` revokes
TCP and UDP lifetimes at each stage between two engines while an accepted one echoes.

### Graceful TCP egress drain

`TcpConnection::terminated` reports socket release. The final TCP ACK can still be
queued in the driver or `NetStackSource` at that point. Before revoking a gracefully
closed flow, keep receiving and forwarding packets until
`NetStackSource::tcp_egress_drained(&control)` returns true. Finish each external send
before checking the barrier; it does not cover a packet already returned by `recv`.
The query rejects another stack's control, non-TCP flows, revoked flows and lifetimes held
under `Admission::Decide` that have no connection yet. It does
not establish peer application completion or remote cleanup.

### Tests

- `tests/netstack_lossy.rs` (`nsplane-e2e`): 8 MiB complete intact at 1 % loss within 15 s
  next to a loss-free reference; `bulk_tcp_with_heavy_loss`, 8 MiB at 3 % loss within 5 s;
  `parallel_echo_*`, eight 1 MiB echoes through 256-packet engine queues, without loss and
  at 2 % loss. Its ignored `throughput` prints the lossy-link table of
  [Performance](../performance.md#netstack).
- `tests/netstack_multistream.rs`: its ignored `streams_throughput` asserts that four
  parallel streams move at least 0.8x the one-stream aggregate.
- `tests/netstack_buffers.rs` and `tests/netstack_stream.rs`: socket-buffer and
  single-stream throughput runs (ignored by default).
- `benches/send_stream.rs` (`nsplane-netstack`): the sender alone, two stacks back to back in
  process, TCP (`netstack_send`, `netstack_send_1cpu`) and connected UDP
  (`netstack_udp_send`, `netstack_udp_send_1cpu`).

## Configuration and defaults

| Feature | How to enable | Default | Cost when not enabled |
|---|---|---|---|
| User-space TCP/IP stack | `NetStack::new(NetStackConfig)`, `NetStack::split` as the builder's source and sink | not used | none: the crate is not a dependency of `nsplane` or `nsplane-tun` |
| Stack reassembly | `NetStackConfig::reassembly = Some(ReassemblyConfig::default())` (64 datagrams, 30 s, 65 535 bytes) | off: fragments are dropped (`unsupported`) | one `Option` check per ingress packet; no reassembler is allocated |
| TCP socket buffers | `NetStackConfig::tcp_rx_buffer` / `tcp_tx_buffer = Some(bytes)`, clamped to `mtu - 40 ..= 65535 << 14` | `None`: `(mtu - 40) * 512` bytes each | none: the sizes are resolved once when the stack is created |
| TCP RTO bounds | `NetStackConfig::tcp_min_rto` / `tcp_initial_rto = Duration`, whole milliseconds clamped to `1 ms ..= 60 s` | 1 s each (smoltcp's) | none: two setter calls per socket created |
| Oversize IPv4 UDP sends | `NetStackConfig::udp_allow_fragmentation = true`, with `EngineBuilder::fragmenter` on the stack's engine | off: a packet above the MTU fails with `InvalidInput` | one length comparison per send |
| TCP abort | `TcpConnection::abort` instead of dropping the connection | drop closes with a FIN | one state compare under the connection's lock and two empty-`Vec` takes per driver turn |
| Fragment discard | `NetStackHandle::discard_fragments(src, dst, protocol, id)` when a flow's admission is revoked; needs `NetStackConfig::reassembly` | not called | none without reassembly; with it one atomic load per ingress packet while nothing is discarded, no lock |
| Later-fragment ownership | on with `NetStackConfig::reassembly`; `owns` reports a datagram's later fragments as its first fragment's `Flow` | off without reassembly (fragments are `None`) | none without reassembly; with it only fragment classification in `owns` takes the memory's lock |
| Transparent termination | `NetStackConfig::transparent = Some(TransparentConfig { prefixes, ..Default::default() })` | `None`: the stack terminates its own addresses only | one `Option` check per bare SYN, new UDP flow and packet to a foreign address |
| Per-flow admission | `NetStackConfig::admission = Admission::Decide { timeout, max_pending }` (every stack), decisions and controls on `NetStackHandle::incoming_pending` | `Admission::Immediate` | none: one `Option` check per bare SYN |
| TCP connection limit | `TransparentConfig::max_connections = Some(n)` | `None`: listener pool and accept queue only | one `Option` check per bare SYN in transparent mode |
| Flow events | `TransparentConfig::events = Some(FlowEventsConfig::default())` (1024 buffered, 1000/s, burst 1000), events on `NetStackHandle::flow_events` | `None`: no channel | one `Option` check on the admission and rejection paths |
| Connected UDP sockets | `NetStackHandle::connect_udp(remote)` / `connect_udp_from(local, remote)` | not used: `bind_udp` sockets take any remote | one `HashMap::is_empty` per UDP datagram |

## Errors and drop reasons

Everything the stack discards is counted per reason in `NetStackStats` (malformed, foreign
and unsupported packets, refused and deferred SYNs, connections and flows not accepted, full
UDP queues, the flow limit, egress over the backlog, ignored ICMP, reassembly timeouts and
overflows, failed inbound handshakes (`handshake_failed`), the admission outcome: `accepted`
and `rejected_hook`, `rejected_timeout`, `rejected_table_full`, and in transparent mode
`rejected_connection_limit`, `rejected_prefix`); a lifetime held under `Admission::Decide`
also ends with one `DeliveryOutcome` on its `DeliveryReceipt`;
packets dropped for a revoked flow are counted in `NetStackHandle::retired_drops`. A
connection rejected under `Admission::Decide` reaches the peer as a RST (`connect_tcp` on a peer
stack fails with `ConnectionRefused`), a rejected UDP flow as an ICMP or `ICMPv6` port
unreachable from the original destination. Flow events lost to the token bucket, a full
buffer or a dropped receiver are counted in `events_dropped`. Handle calls fail with `std::io::Error` kinds:
`InvalidInput`, `AddrNotAvailable`, `AddrInUse`, `NotConnected`, `ConnectionAborted` (a
revoked flow) and `BrokenPipe` (the stack stopped).

## Limits and bounds

- Ingress, egress, accept and datagram queues: `NetStackConfig` capacities; `datagram_capacity`
  defaults to 256.
- One driver turn routes up to 256 ingress packets.
- TCP socket buffers: 512 IPv4-sized segments by default, clamped to `mtu - 40 ..= 65535 << 14`.
- Idle TCP connections are reset after 5 minutes.
- Reassembly and the fragment memories: `ReassemblyConfig` (64 datagrams, 30 s, 65 535 bytes
  by default).
- Pending table of `Admission::Decide`: `max_pending` entries (0 is taken as 1), each held
  for at most `timeout` (at most one day); a held flow queues one datagram. Lifetimes with
  an open delivery: at most twice those the pending table, listener pool, waiting
  connections and accept queues hold.
- TCP connections in transparent mode: `TransparentConfig::max_connections`, otherwise the
  listener pool and the accept queue.
- Flow events: `FlowEventsConfig::capacity` buffered events (0 is taken as 1) and a token
  bucket of `burst` tokens refilled at `rate` per second.
- Retirement state: the table under [Per-flow control and retirement](#per-flow-control-and-retirement).

## See also

- [Usage guide: a userspace node](../guide.md#8-a-userspace-node-nsplane-netstack) and
  [transparent termination](../guide.md#transparent-termination)
- [nsplane](nsplane.md): the engine and its local-side graph.
- [Performance: netstack](../performance.md#netstack)
