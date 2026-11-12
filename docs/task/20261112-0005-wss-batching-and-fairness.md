# 20261112-0005-wss-batching-and-fairness WSS write batching, session fairness and idle sessions

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 00:05

## Description

Four audited P3 items in `nsplane-wss` and the examples' relay WSS server:

1. One flush (a TLS record and a write call) and one copy per datagram, on the dialer's link and
   on the server's sessions.
2. All sessions share one inbound queue and a session's reader awaits its room: can a flooding
   session delay the others?
3. A session that keeps sending junk never idles out, so unauthenticated clients can hold all
   of `max_sessions`.
4. The examples' relay WSS server has no connection cap, no idle timeout after the handshake and
   awaits `ws.send` without a timeout.

## ActiveForm

Batching the WSS writes, pinning the inbound fairness, tightening the read idle and bounding the
example relay.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

### 1. Batched writes

- The send queue of `LinkTransport` carries `Bytes` and tungstenite's `Message::Binary` takes
  `Bytes`, but `LinkSender::send(&[u8])` sat between them and forced a second copy, and gave the
  sender no way to know that more was queued. The fix needs the trait: `LinkSender::send_batch(&mut
  Vec<Bytes>)` is a new provided method (default: one `send` per message, so other senders are
  unchanged) and the transport's task takes the queue with `recv_many` (at most
  `LinkTransport::SEND_BATCH` = 64, which waits only for the first datagram). Additive public API
  in `nsplane`: one trait method with a default, one associated constant.
- `WssSender::send_batch` feeds the messages as they are and flushes once; the server's writer
  does the same with `recv_many` on the session queue. No timer, no waiting: a datagram alone is
  flushed at once.
- The server keeps its one copy in `Transport::send(&[u8])` (the queue needs ownership); the
  dialer's second copy is gone.
- Bytes are bounded by tungstenite, which writes its buffer out above `write_buffer_size`
  (128 KiB); no byte bound of our own.
- Contract change: a failed write loses the batch (up to 64 datagrams) instead of one datagram.
  The data in the socket buffers of a lost link was lost already; documented in
  `LinkSender::send_batch`, `LinkTransport` and both reference pages.
- Order and backpressure (`WouldBlock` on a full queue, readers waiting on the inbound queue) are
  unchanged.

Benchmark `cargo bench -p nsplane-wss --bench throughput` (new, plain `main`, no dependency
added): loopback `ws://`, 1 000 000 datagrams of 1200 bytes each way, at most 128 in flight,
release profile, 7 cores of one CCD through `scripts/bench/slot.sh`, before and after interleaved
three times in one slot:

| Direction | Before, datagrams/s | After, datagrams/s | Before, CPU us/datagram | After, CPU us/datagram |
|---|---|---|---|---|
| link to server | 467 079, 506 738, 481 848 | 2 331 271, 2 538 914, 2 502 590 | 4.66, 4.60, 4.59 | 1.25, 1.11, 1.13 |
| server to link | 505 312, 517 680, 548 639 | 1 314 285, 1 411 873, 1 297 147 | 4.67, 4.60, 4.50 | 2.23, 2.07, 2.28 |

CPU is user plus system time of the whole process (both ends, and the kernel's loopback TCP).
No TLS in the benchmark: with TLS each flush is also a record, so the gain there is not smaller.

### 2. Fairness: no code change

The audited claim does not hold as stated. The inbound queue is a tokio bounded channel; its
room is handed to the waiting senders first in, first out, one datagram each, and a reader asks
again only after its datagram is in. A flooding session therefore holds one place in the line
like every other session and cannot stall them. What it can do is delay them: a datagram of
another session waits for the datagrams queued when it arrived plus what the flooding reader adds
in the one turn it runs before the other reader, about two queues at most.

The suggested `try_send` with drop was not taken: when room is freed, the session whose reader
spins is nearly always the first to try, so the quiet sessions would lose their datagrams instead
of waiting one turn, and the documented contract (nothing received is dropped, a slow engine
pushes back onto TCP) would go. A per-session share of the queue would tighten the delay but
needs a new setting and its default; not done, not justified by the code.

Added: the test `a_flooding_session_takes_turns` (inbound queue of 8, a flood of 500, the other
session's datagram arrives after fewer than 16), and the fairness paragraph in the reference and
in the rustdoc of `WssServerTransport`.

### 3. Idle sessions

- The read idle of a server session restarted on every frame, dropped ones included. It now
  restarts only on a datagram of valid size, a ping or a pong. A session that only sends text or
  oversized messages closes after `read_idle` (counted in `closed_idle`).
- Pongs still count: the keepalive design depends on it (an idle peer keeps its session by
  answering pings). So a client that answers pings, or sends datagrams the engine rejects, still
  holds a session: the crate cannot verify WireGuard authentication. This limit and the
  embedder's control are documented (reference, rustdoc): authenticate the upgrade, keep the
  `WssSession` handles, close those whose address never became a peer's endpoint. The session
  address is already the `Path` of every datagram and `WssSession::close` existed.
- Added `WssSession::is_closed` so an embedder keeping handles can forget the closed ones.
- The dialer's read idle is unchanged (the client side is not exposed to this).

### 4. Example relay

`examples/src/relay/wss/server.rs`: `MAX_CONNECTIONS` = 256 (handshakes included; above it the
accepted stream is dropped, counted in `refused`), `IDLE_TIMEOUT` = 35 s without a valid frame
(a datagram the router takes, a ping or a pong; counted in `closed_idle`; the clients ping every
10 s), `SEND_TIMEOUT` = 10 s on each send and on the closing frame. 256 rather than 1024 because
each connection takes a descriptor and the usual limit is 1024. Constants, not settings: it is
example code. The send timeout has no test (it needs a peer that stops reading with full socket
buffers).

## Validation

Seen red before the fixes: `accept::tests::queued_datagrams_are_written_together` (100 writes
for 100 datagrams), `accept::tests::dropped_messages_do_not_keep_a_session_open` (the session
stayed open), examples `wss::a_connection_without_valid_frames_is_closed` and
`wss::connections_over_the_cap_are_closed` (both timed out). `a_flooding_session_takes_turns`
passes before and after (it pins existing behavior; its first bound of 10 was wrong, see above).
`link::tests::queued_datagrams_are_sent_in_batches` and `dialer::tests::a_batch_is_sent_in_order`
use the new method and could not be run before it existed.
