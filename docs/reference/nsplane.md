# nsplane

The tokio driver around `nsplane-core`: the engine task and its I/O tasks, the handle, the
UDP and message-link transports, path MTU, fragmentation, the crypto worker pool and the
local-side graph primitives (pipes, pumps, splitters and sink wrappers). Builds on
`nsplane-core`, `nsplane-packet` and `nsplane-noise`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `EngineBuilder` (`transport`, `private_key`, `policy`, `filter`, `fragmenter`, `transport_max_datagram`, `path_mtu_expiry`, `crypto_workers`, `queue_capacity`, `event_capacity`, `stats_interval`, `plaintext_ingress`, `build`), `Engine` (`handle`, `wait`), `EngineHandle` (peers, keys, allowed IPs, PSK, keepalive, `set_path`, `set_transport_max_datagram`, `report_path_mtu`, `peer_mtu` / `peer_mtus`, `path_mtu_stats`, `add_transport` / `remove_transport` / `replace_transport`, `inject_inbound` / `inject_outbound` / `inject_outbound_on`, `force_handshake` / `force_handshake_on`, `suspend` / `resume`, `local_barrier`, `subscribe`, `peers` / `peer_stats` / `peer_has_session`, `unanswered_handshakes` / `total_unanswered_handshakes`, `drop_counters`, `queue_stats`, `fragment_stats`, `transport_stats`, `status`, `shutdown`, `add_local_identity` / `add_local_identity_on` / `remove_local_identity` / `local_identities`, `peer_id_in`, `set_local_sources`, `remove_peer_in`, `set_inbound_destinations_in` / `set_inbound_destination_source_in`); traits `PacketSource`, `PacketSink` (`send_batch_spent`), `Transport` (each with batch methods; `Transport::path_mtu_reports`), `DynTransport`; `LinkTransport` with the traits `LinkDialer`, `LinkSender`, `LinkReceiver` | `UdpTransport` (`with_side_channel`, `set_path_mtu_discovery`, `path_mtu_reports_dropped`), `SideSender` (`send_to`, `send_to_async`), `SideDatagram`, `SideStats`, `LinkConfig`, `LinkState`, `ChannelSource` (`pool`) / `ChannelSink` / `ChannelTransport`, `Splitter` (`new_map`, `stats`) / `SplitterStats`, `MergeSource` (`recycle`), `MapSink` (`with_after`) / `MapSource` / `MapVerdict`, `SwapSink` (`replace`, `dropped`), `AbortSink` / `SinkAbort` (`abort`, `is_aborted`), `pipe` / `PipeSink` (`alloc`, `recycle`) / `PipeSource` (`mtu_sender`), `pump` / `PumpStats`, `FragmentConfig` / `FragmentStats`, `EngineStatus`, `PathMtuReport`, `PeerMtus`, `PathMtuStats`, `TransportStats`, `QueueStats` / `QueueDepth`, `Peer`, `LocalIdentity`, `PlaintextIngress` (`send`, `try_send`) / `PlaintextRefused`, `Event`, the `DROP_*` reasons, `EngineError`, `TransportError`, `BuildError`, `BoxFuture`; re-exports of the value types and `SharedPacketPool` |

## Behavior

### Owner task and I/O tasks

One owner task owns the `Core` and loops: it waits for a handle command, a local packet, a
received datagram or the core's next timeout, feeds the core and drains its outputs. Four
I/O tasks surround it, each connected through a bounded queue (1024 packets by default):

```text
PacketSource ─► source task ─┐                       ┌─► transmit task ─► Transport::send
                             ├─► owner task (Core) ──┤
Transport::recv ─► recv task ┘          ▲            └─► sink task ─► PacketSink
                                        │
                          EngineHandle commands (64)
```

Without crypto workers the owner also delivers to the sink itself when the sink task is
idle, and sends itself when the transmit task is idle and no input is waiting (inline
output, below), skipping that hop.

The core is never shared, and without the crypto worker pool the data path takes no lock;
with the pool, each peer's tunnel is behind a mutex that only the owner takes (the jobs
carry the session keys they need), so it is uncontended.

When the owner wakes for a received datagram or a local packet, it also takes the ones
already queued behind it (up to `MAX_BATCH`, 64) and feeds them to the core as one batch
(`Core::handle_datagrams`, `Core::handle_locals`). It never waits for a batch to fill and
runs no timer for it, so a lone packet goes through at once. Received datagrams are taken
up to the sink queue's room; local packets up to the transmit room (see the backpressure
list below). Without crypto workers the source and receive tasks hand over what one read
returned as one message (up to `MAX_BATCH` items, as many as the queue has room for; a
lone item goes over without an allocation); the input queues stay bounded in items (a
semaphore of `queue_capacity` permits beside the channel). With crypto workers they hand
over one item per message. The other way, the owner hands the datagrams one drain queued
for a transport to its transmit task as one message (the transmit queue stays bounded in
datagrams), and transmitted buffers go back to the source task one message per sent batch,
over a lossy bounded queue, for `PacketSource::recycle` (`TunSource` reads into them
again); a source that keeps the default no-op gets none after the first, and the buffers go
to the core's pool. Sources that recycle: `TunSource` (Wintun too), `SlotSource`,
`HostTunSource`, `PipeSource` and `ChannelSource` (once pooled, see below), and the wrappers
`MapSource`, `MergeSource` and `Nat64LanSource` around them.

### Inline output

Without crypto workers and while not suspended, the owner sends a drain's
datagrams itself (`Transport::try_send_batch`) when nothing of that transport is in its
backlog, its transmit queue or the batch its transmit task is sending, and hands the
drain's delivered packets to the sink itself (`PacketSink::try_send_batch`) when nothing is
queued for or being delivered by the sink task. It sends itself only for a drain after
which no local packet and no received datagram is waiting (it would wait next); under load
it hands the datagrams to the transmit task, which sends them while the owner seals the
next batch. Delivery is not gated on waiting input. Whatever is not taken at once goes to
the transmit queue / backlog or the deliver queue, in order, under the usual rules below;
later traffic queues behind it until the task has drained it, so a peer's order on one
transport is kept. Inline-sent buffers return to `Core::recycle` directly. A transport or
sink whose `try_send_batch` took nothing (it keeps the default, or is full) is skipped for
1, 2, 4, ... up to 1024 drains and tried again once that wait is over; taking anything
resets the wait, so a default implementation costs about one try per 1024 drains. The
defaults of both `try_send_batch` methods take nothing, which keeps every datagram and
packet on the tasks; `UdpTransport`, the Unix `TunSink` and `PipeSink` override them.
`MapSink` keeps the default on purpose: forwarding would map the packets its inner sink
leaves behind, and the engine's later `send_batch` would map them a second time.

### Handle, events and counters

- `EngineHandle` sends commands to the owner (peers, keys, allowed IPs, path, transport,
  stats, injection, shutdown) and returns their replies.
- Events are published on a `broadcast` channel (`EngineHandle::subscribe`); publishing never
  blocks, and a lagging subscriber loses the oldest events.
- Drops are counted per reason (`EngineHandle::drop_counters`) and published as events.
- Local identities are handle commands to the owner (`add_local_identity`,
  `add_local_identity_on`, `remove_local_identity`, `local_identities`, `peer_id_in`,
  `set_local_sources`, and the
  `_in` forms `remove_peer_in`, `set_inbound_destinations_in`,
  `set_inbound_destination_source_in`); `add_or_update_peer` binds a peer with
  `Peer::local_identity`, and the key-addressed methods mean the default identity.
  `EngineStatus::local_identities` lists every identity (id, public key, peer count,
  transports, source set). `set_local_sources` gives an identity its source set (see
  [per-identity routing](nsplane-core.md#per-identity-routing)); the fragmentation stage looks up a local packet's peer by its
  source and destination too (`Core::route_from`), so path-MTU state and the ICMP errors
  about a too-big packet follow the identity the source selects. Transports, filters, path policy, fragmenter, crypto workers and the local side
  are shared by all identities; the UAPI and the CLI use the default identity only.
- Unanswered handshake initiations are counted per peer and in total
  (`EngineHandle::unanswered_handshakes` / `total_unanswered_handshakes`, see nsplane-core).
- Traffic is counted per peer (`PeerStats`: wire bytes and plaintext bytes) and per transport
  (`EngineHandle::transport_stats`: datagrams and bytes each way, failed sends), the latter
  once per batch by whoever moved it (the transport's receive/transmit tasks, or the owner
  task when it sends itself), one relaxed atomic update per batch. `EngineHandle::status`
  returns the key, MTU, suspension, peers, transports, drops, queue and fragmentation stats,
  peer MTUs and path MTU counters in one owner call. Counters only grow; rates, metric export and labels such as direct vs relay
  are left to the caller, which samples `status` and maps transport ids to its paths.

`EngineHandle::peer_has_session(peer)` reads the current sending-session state
through the engine command queue after preceding crypto work settles. An unknown
peer returns `None`; an installed peer without a current usable sending key
returns `Some(false)`. Check transport reachability separately: a current session
alone is not a live path.

### Local barrier

`EngineHandle::local_barrier` returns once every packet the engine took from its
`PacketSource` before the call has been routed and passed or been dropped by the outbound
filters (or dropped for no route, by the fragmentation stage or by the tunnel's queue). A
caller that moves the ownership of an address uses it to know that no local packet admitted
before the move meets the outbound filters afterwards.

- A packet counts as taken once `recv_batch` took it from the source, also while that read
  is still in progress: packets in the engine's local queue, the packets the source task
  holds while that queue is full and a packet the source is handing out at the time of the
  call are covered. Packets the source has not handed out (a kernel TUN queue, the caller's
  own queue) are not; the caller stops its source from handing out packets admitted before
  the change, then takes the barrier.
- The source task publishes its count in one word shared with the handles: twice the
  packets taken, plus one while it polls `recv_batch`. It counts what a read took in the
  poll that ends the read, so the call waits (yielding) while a read is in progress, then
  takes the count as the barrier's position; the owner replies once it has taken that many
  local packets through the fragmentation stage and the core. Routing and the outbound
  filters run on the owner in that call, also with crypto workers, so the barrier never
  waits for sealing.
- The barrier passes at once when nothing taken is waiting, or once the source has closed
  and every packet it returned was taken. While the engine is suspended it passes only after
  `resume`. A stopped engine returns `EngineError` and never reports a barrier it did not
  pass.
- Cost: two plain atomic stores per poll of the source and one counter add per batch of
  local packets.

### Plaintext ingress

`EngineBuilder::plaintext_ingress(capacity)` returns a `PlaintextIngress`: a bounded entry
for plaintext IP packets attributed to a peer, checked like decrypted data. Its
`send(peer, from, packet)` waits while the queue is full; `try_send` refuses at once with
`PlaintextRefused::Full(packet)`. Once the engine stopped, `send` returns `EngineError` and
`try_send` returns `PlaintextRefused::Stopped(packet)`.

- The owner polls the queue next to the received datagrams (alternating which comes first),
  only while the deliver queue has room, and takes at most `MAX_BATCH` packets per turn, each
  through `Core::receive_plaintext`: the peer's allowed-IP source check, its inbound
  destinations, the inbound filters in install order (`inbound_from` with `from`) and
  delivery to the sink (see
  [nsplane-core, validated plaintext](nsplane-core.md#validated-plaintext)).
- Nothing is authenticated: no handshake accounting, no path policy, no roaming and no
  `Event::Authenticated`. A filter that answers on the arrival path answers on `from`, the
  path the caller names. Delivered bytes count in the peer's `data_rx`, not in `rx`.
- `EngineHandle::inject_inbound` keeps its bypass: it delivers without the checks and the
  filters.
- While the engine is suspended the queue is not read. Without `plaintext_ingress` the engine
  has no such queue; a second call replaces the first entry, whose calls then fail like
  those of a stopped engine.

### Packet tags

The engine carries the packet tag and the receipt marker of
[nsplane-packet](nsplane-packet.md#packet-tag-and-receipt-marker) with the `PacketBuf` and
never writes either to the wire:

- A local packet keeps its tag from `PacketSource::recv_batch` through the local queue, the
  fragmentation stage (each fragment), the outbound filters (`PacketFilter::outbound` reads
  and may set it), sealing (inline and on the crypto workers) and the transmit path up to the
  `Transport::send_batch` / `try_send_batch` call, whose datagram carries it. So do
  `inject_outbound` and `inject_outbound_on`. A packet queued in the tunnel while its peer has
  no session goes out untagged: the tunnel's queue keeps bytes, and the handshake initiation
  written into the packet's buffer carries no tag.
- Received packets are untagged; an inbound filter may tag one, and the sink gets the tag.
  `inject_inbound` and `PlaintextIngress` keep the tag of the packet they are given.
- The receipt marker is cleared on every packet the engine takes in (from its source, the
  inject calls and `PlaintextIngress`) and on every packet it delivers to the sink.
- The buffers handed back to `PacketSource::recycle`, by the engine and by `pump`, are
  untagged and unmarked, so a source that reuses one (with `set_len` instead of a pool) never
  sees a stale tag. Clearing costs one store per recycled buffer, off the packet path.

### Backpressure

- Local packets are never dropped by an engine with one transport: when the transmit queue
  is full, datagrams wait in the owner task (the transport's backlog). The owner reads local
  packets only while some transport has room for them and takes no more at once than the
  largest room, counting one datagram per packet; a transport's room is its free transmit
  slots while its backlog is empty, plus `min(MAX_BATCH, capacity)` minus its backlog. With
  no room it stops reading, which holds back the source, so a saturated transport keeps at
  most `MAX_BATCH` local datagrams in its backlog.
- Each received datagram may deliver a packet, so the owner reads received datagrams only
  while the deliver queue has room for them, beyond the received datagrams with the crypto
  workers if any, and takes no more at once than that room (at least one once there is
  room). A sink slower than the network so holds datagrams back in the transport (the UDP
  socket buffer) instead of dropping decrypted packets under `DROP_SINK_FULL`, with or
  without workers. Packets the owner delivers inline take no room, and those the sink
  does not take at once fit in the queue. Handshakes and keepalives arrive on the same
  queue, so a stalled sink also delays them; a closed sink holds nothing back.
- Datagrams caused by received datagrams or timers that find the waiting datagrams at the
  queue capacity are dropped (`DROP_TRANSMIT_FULL`).
- A packet that still finds the sink queue full (one injected with a handle call) is
  dropped (`DROP_SINK_FULL`); a closed sink or
  transport drops with `DROP_SINK_CLOSED` / `DROP_TRANSPORT_CLOSED`, and without a transport
  datagrams are dropped with `DROP_NO_TRANSPORT`.
- An I/O side that reports `BrokenPipe` stops its task; the engine keeps running without it.
  Inline output follows the same rules: a failed inline send counts as a failed send
  (`DROP_TRANSPORT_SEND_ERROR`), `WouldBlock` is not a drop (the rest is queued, and only
  then can `DROP_SINK_FULL` / `DROP_TRANSMIT_FULL` apply), and `BrokenPipe` marks the
  transport or sink closed.
- `TunSink` with TCP segmentation offload coalesces packets before a
  write; an inline TUN write that hits `EAGAIN` mid-chunk keeps the rest of that chunk and
  writes it first with the next delivery (no drop, order kept). Only a lowered
  `TUNSETSNDBUF` makes a Linux TUN write block.

### Queue depths

`EngineHandle::queue_stats` reports, for every bounded queue, its capacity and high-water
mark (the most items it held at once) since the start or the last `take_queue_stats`, which
also restarts the marks. The owner task samples each queue whenever it sends to or receives
from it (a receive sees the occupancy just before it, which is the peak since the previous
receive), with plain fields and no locks or atomics on the data path. The event channel is
sampled only for events other than `Event::Dropped`, because reading its occupancy takes the
channel's locks.

| Queue | Capacity | Producer -> consumer |
| --- | --- | --- |
| `command` | 64 | handles -> owner |
| `local` | `queue_capacity` | source task -> owner |
| `datagrams` | `queue_capacity` | every receive task -> owner |
| `deliver` | `queue_capacity` | owner -> sink task |
| `recycle` | `queue_capacity` | every transmit task -> owner (full: buffer dropped); used only when the source keeps the default `PacketSource::recycle`, the lossy queue back to the source is not counted |
| `transmit` | `queue_capacity` per transport | owner -> transmit task, in datagrams, counting the batch being sent |
| `backlog` | `queue_capacity` per transport | owner, waiting for room in `transmit` |
| `events` | `event_capacity` | owner -> subscribers |
| `crypto` | `queue_capacity` (the bound of jobs in flight) with 2 or more crypto workers, else 0 | owner -> workers -> owner (jobs not completed yet) |
| `crypto_done` | `queue_capacity` with 2 or more crypto workers, else 0 | workers -> owner (batches of finished jobs) |

Without crypto workers, the datagrams and packets the owner sends or delivers inline (see
[Inline output](#inline-output)) never enter `transmit`, `deliver` or `recycle`. The
owner sends inline only when no input is waiting, so under load `transmit` (and `recycle`)
rise; `deliver` stays low or at 0 while the sink keeps up, and rises only once
the sink falls behind and packets fall back to the sink task. `recycle` counts only the
buffers a transmit task returns to the owner. With a source that recycles (`TunSource`,
or a `MapSource` around one; the list is above) every transmitted buffer, inline-sent ones included, goes back
to the source instead and `recycle` stays at 0; otherwise inline-sent buffers go back to
the core directly.

Defaults: `queue_capacity` 1024, the command queue 64 (every handle call waits for its
reply, so it holds at most one command per concurrent caller) and `event_capacity` 1024
(without a subscriber the channel holds nothing, and a subscriber that stops reading fills
any capacity). Since queued packets are sized to their contents, an idle or lightly loaded
queue costs little. The high-water marks measured under load are in
[Performance](../performance.md#queue-depths).

Floods and many parallel bulk flows fill every queue upstream of the bottleneck whatever the
capacity. Embedders that run many parallel bulk flows through a userspace netstack raise
`queue_capacity` and watch the marks and `DROP_SINK_FULL` with `queue_stats` and
`drop_counters`. On the sending side, `NetStackConfig::tcp_send_budget` keeps the stack's
connections together within one budget instead of one window each; it caps all connections
together at `budget / RTT` (one default send buffer, about 690 KiB, is about 14 MB/s at
50 ms), so it suits stacks whose peers are near, and it is opt-in.

### Crypto worker pool

The single owner task is the limit of one engine's throughput: it seals and opens every
packet. `EngineBuilder::crypto_workers(n)` with `n` of 2 or more moves that cryptography to
`n` worker tasks; 0 or 1 (the default) keeps the single owner task, which then never calls the
deferred API.

```text
local packets ─┐           ┌─► worker 0     ─┐
               ├─► owner ──┼─► worker 1     ─┼─► done queue ─► owner ─► sink, transmit tasks
datagrams     ─┘           └─► worker n - 1 ─┘
```

- One peer on every worker. The owner feeds each local packet and received datagram to
  `Core::handle_input_deferred`, which routes it (receiver index or destination), runs the
  outbound filters and prepares a `CryptoJob` on the peer's tunnel: a local packet gets the
  session's next counter (nonce), in order (`Tunn::reserve_in_place` -> `SealTicket`), and a
  received message passes the session and replay-window check (`Tunn::open_ticket` ->
  `OpenTicket`). The job carries the session key and counter, so `CryptoJob::run` never
  touches the tunnel. Jobs go to the workers in turn, whatever their peer, and the owner
  completes them (`Core::complete_job`) in the order it handed them out, through a reorder
  buffer keyed by job sequence: a received message's counter is marked as received only
  there (`Tunn::commit_open`), so a duplicate opened on two workers at once is still
  rejected, and a datagram of a session that expired or was replaced meanwhile is dropped
  and counted. So all packets of one peer, in both directions, are emitted in arrival
  order, and one peer's cryptography spreads over every worker.
- Batches. Jobs go to a worker in batches of up to 64 (`MAX_BATCH`): a worker's batch is
  handed over when it is full, together with every other batch, or when the owner has
  nothing else ready, and a worker hands each batch back whole. A busy owner thus wakes each
  worker once per batch instead of once per packet; handing over every packet on its own
  cost as much as the cryptography it moved and gained nothing.
- Everything else stays on the owner: handshakes (the gate, the responses, flushing the
  packets queued behind a handshake), timers, configuration, events, drop counters, roaming
  and the per-peer counters. Workers never lock a tunnel, so a handshake or a timer never
  waits for a worker. The order on the wire stays the arrival order
  even when the owner seals a keepalive or flushes queued packets while newer packets of the
  peer are with a worker: those are emitted only once they come back.
- Bounds: at most `queue_capacity` jobs are with the workers. While that many are, the owner
  stops reading local packets and received datagrams (handle calls, timers and finished jobs
  are still served), which holds back the sources as a full transmit queue does. Every
  worker queue and the done queue hold that many jobs, so neither side ever waits on them.
- Handle calls that read or change peers, sessions or counters (configuration, peer stats,
  injection, forced handshakes, drop counters) first wait for every job in flight, so they
  act after every packet read before them, exactly as without workers: per-peer stats and
  drop counters stay exact, and a removed peer's packets read before the removal still go
  out while later ones are dropped as `no route` / `unknown session`.
- Parallelism needs a multi-threaded tokio runtime; on a current-thread runtime the workers
  interleave with the owner and only add overhead.
- No inline output: with 2 or more workers the owner never sends or delivers itself; every
  datagram goes through the transmit task and every packet through the sink task, and the
  source and receive tasks hand over one item per message.

Without the pool the core hands out no crypto jobs: they exist only when the core is built
with `CoreConfig::crypto_jobs`, which the engine sets for 2 or more workers, and otherwise
every peer owns its tunnel outright. With full-size packets the pool moves a hub engine
further; small packets gain little, since there the cryptography is a small part of the
owner's work per packet (queues, routing, counters). Beyond 2 workers the owner task, which
still touches every packet twice, is the limit. The numbers are in
[Performance](../performance.md#crypto-worker-pool).

### UDP transport

`UdpTransport` is the network side: one dual-stack UDP socket with fwmark and ECN support,
4 MiB socket buffers requested (clamped by `net.core.rmem_max` / `wmem_max`) and segmentation
offload through `quinn-udp`. On Linux a segmented run is sent as one `sendmsg`
with one iovec per datagram and the `UDP_SEGMENT` / TOS control messages (no train buffer
copy; on `EIO` / `EINVAL` the run goes through `quinn-udp`, which turns segmentation off); coalesced reads take turns in a ring of four 128 KiB storages instead of
allocating while slices of the last one are queued, and after four coalesced reads in a row
of one datagram each (a peer that sends no trains, e.g. kernel WireGuard) `recv_batch`
reads up to 16 datagrams per `recvmmsg` until a train arrives. With offload off, runs to one
address and ECN mark go out with `sendmmsg` and `recv_batch` reads up to 16 datagrams per
`recvmmsg`: batching, not offload, as every datagram stays its own message.
### In-memory channels

`ChannelSource`, `ChannelSink` and `ChannelTransport` are in-memory implementations for tests
and embedders. `ChannelSource::new` returns a raw `mpsc::Sender`, so pooled allocation goes
through `ChannelSource::pool() -> SharedPacketPool` (`max_free` = `capacity`): the
producers holding the sender `alloc` from it and consumers may `recycle` into it, and
`ChannelSource::recycle` refills it with the engine's transmitted buffers once `pool()` was
called (take the pool before moving the source into an engine); before that the source
declines them.

### UDP side channel

Another protocol can share the `UdpTransport`'s port (control messages next to WireGuard,
say). `UdpTransport::with_side_channel(classify, capacity)`
runs `classify` on every received datagram, each GRO segment on its own, in the receive
path of `recv` and `recv_batch`; a datagram it picks is copied into a `SideDatagram`
(`from`, unmapped as `Path::addr` reports it, and `datagram`) and `try_send`-ed to the
returned receiver of `capacity` entries, never reaching the engine; a full or closed
receiver drops it. `SideSender::stats` counts both (`SideStats { received, dropped }`);
they live on the sender, not in `TransportStats`, because side datagrams never reach the
engine's transport tasks. `SideSender::send_to` writes straight to the non-blocking socket
without an ECN mark: it never waits behind the engine's traffic and fails with
`WouldBlock` when the send buffer is full. `SideSender::send_to_async` addresses the same way
but, on a full send buffer, waits for the socket to be writable and tries again:
it waits on the same readiness as the engine's own sends and takes no lock, so it never
delays them; it is cancel safe (a dropped future sends nothing or the whole datagram, once).
Pinned by `nsplane-e2e`'s `udp_side_channel::awaited_side_sends_beside_wireguard_offload_on`
/ `_off`. A capacity of 0 is raised to 1; a second call replaces
the channel (the old receiver closes once drained). Without a side channel nothing is
classified; the receive path checks one `Option` per datagram.

### Path MTU discovery on UdpTransport

`UdpTransport::set_path_mtu_discovery(true)` (off
by default; Linux and Android, `Unsupported` elsewhere, since macOS and Windows deliver no
ICMP errors to an unconnected UDP socket) sets `IP_RECVERR` / `IPV6_RECVERR` and makes every
receive read the socket's error queue empty first: each ICMP Fragmentation Needed or ICMPv6
Packet Too Big about one of the transport's datagrams becomes a `PathMtuReport` (the
destination path, the MTU it carries, the datagram's first 8 bytes as the quote); other
errors are read and skipped, and no error fails a receive. The reports reach the engine
through `Transport::path_mtu_reports`, handed out once after the first switch-on, so it is
turned on before the transport is given to the engine; at most 64 wait, further ones are
dropped and counted (`UdpTransport::path_mtu_reports_dropped`). The kernel learns of a too
small path only for datagrams sent with DF: with offload all of them, without it only those
below the path MTU it knows.

A failed send reads up to 64 queued errors, preserving Packet Too Big reports in the same
report queue, then retries only the unaccepted operation. The first retry also covers a
concurrent receiver having already read the error; further retries require a queued
asynchronous ICMP error. There are at most seven retries. Successful batch prefixes are
not repeated, and genuine persistent errors still fail and are counted. This applies to
single, batched and nonblocking batched transport sends, and synchronous/asynchronous side
sends.

Once the socket has reported an error tokio keeps its write readiness (after
`EPOLLERR`), so a send that finds the send buffer full (`send`, `send_batch`,
`SideSender::send_to_async`) retries after pauses of 1 ms doubling up to 8 ms and may go out
up to 8 ms after room appeared; sends that find room are not delayed, and with discovery off
nothing changes (`nsplane`'s `udp::tests::full_sends_back_off_after_an_icmp_error` and the
root `full_send_buffer_backs_off_after_an_icmp_error`, ignored without `CAP_NET_ADMIN`).
Pinned by the root test
`nsplane-e2e`'s `path_mtu_root::path_mtu_follows_real_icmp_errors` (ignored by default; needs
`NET_ADMIN` and `SYS_ADMIN`, its module docs give the command).

### Message links

`LinkTransport` (opt-in; nothing runs unless one is created) carries
datagrams to one peer as messages over a link the embedder dials, so `nsplane` itself has
no WebSocket or TLS dependency. Its task asks the `LinkDialer` for a link (a `LinkSender`
and a `LinkReceiver`), drains the send queue into it and hands received messages to
`recv`, reported from `Path { transport: id, addr: peer, ecn: NotEct }`; sends to another address are
dropped and count as sent.

- `LinkConfig::queue` (256) bounds the datagrams waiting for the link, also while none is
  up; `send` never waits, and on a full queue fails with `WouldBlock`, which the engine
  counts under `DROP_TRANSPORT_SEND_ERROR`.
- A link ends when the receiver yields `None` or an error, a send fails (that datagram is
  lost; the queued ones go out on the next link) or `LinkConfig::read_idle_timeout`
  (default `None`) passes without a message. The task reports `LinkState::Disconnected`
  to `LinkDialer::on_state` and dials again at once, also after a failed dial; the dialer
  owns the backoff and may sleep in `dial`.
- The idle timeout is reset only by messages the receiver yields, so a dialer whose
  keepalive frames are consumed inside its receiver does its own idle detection. The
  examples' WSS client (`examples/src/relay/wss/client.rs`, a tokio-tungstenite dialer)
  does: it pings every 10 s and closes a connection silent for 35 s.

### Per-path MTU

One peer's paths (direct UDP, a relay, WSS) carry different
datagram sizes, so the engine can keep an inner MTU per peer below the source MTU:

- Two ceilings limit a path: per transport, the largest WireGuard datagram it carries
  (`EngineBuilder::transport_max_datagram(id, max)`, `EngineHandle::set_transport_max_datagram`,
  e.g. a relay's frame limit), and per path (transport and remote address), an outer IP MTU
  learned from reports (`EngineHandle::report_path_mtu(path, mtu)`, or
  `Transport::path_mtu_reports`, which `UdpTransport` feeds on Linux, above).
- A report is accepted only for a path some peer's data leaves on or a peer's stored path,
  only if it lowers what the path allows (one equal to the learned MTU confirms it), and,
  when it quotes the datagram (`PathMtuReport::with_quote`), only for a transport data message
  carrying that peer's current receiver index. `mtu` 0 takes the next RFC 1191 plateau below
  the current outer MTU; IPv6 paths take at least 1280, IPv4 at least 576. A learned MTU
  expires `EngineBuilder::path_mtu_expiry` (10 minutes) after the report that set or last
  confirmed it, which restores the transport's ceiling; the engine does not probe upwards.
- A peer's inner MTU follows the path its data leaves on (`Core::data_path`): the source MTU,
  lowered to `min(transport limit, learned MTU - IP header - 8) - 32`, never below 1280; a
  1500-byte IPv6 path gives 1420. `EngineHandle::peer_mtu(peer)` returns it,
  `EngineHandle::peer_mtus()` is a watch of `PeerMtus { min, peers }` (the peers below the
  source MTU, updated only on a change) and `path_mtu_stats` counts reports received,
  applied, ignored and expired (`PathMtuStats`, also in `EngineStatus`).
- `EngineHandle::mtu` and `Event::MtuChanged` keep meaning the source MTU. The per-peer MTU
  reaches the local kernel or stack only through the fragmentation stage (below), which holds
  packets to the destination's peer's MTU, or through ICMP the caller generates from
  `peer_mtus`; without a fragmenter it is visible only there. On macOS and Windows no Packet
  Too Big reaches the transport, so `report_path_mtu` is the only way to set a path's MTU.
- From the first ceiling or report on, the owner caps every peer's data padding at its inner
  MTU (`Core::set_peer_pad_limit`), so a packet at the inner MTU makes an outer datagram of at
  most the path MTU; padding to a multiple of 16 bytes alone could overshoot it by up to
  15. A peer without this state (a plain `nsplane-cli`, another WireGuard) still pads to 16
  and can exceed the path MTU with its replies, e.g. at a 1420 source MTU over a 1500-byte
  IPv6 path, so both ends should use the feature.
- Nothing of it exists until a ceiling is set or a report arrives: no table, no padding
  limit, no per-packet lookup, and a report forwarder task is spawned only for a transport
  whose `path_mtu_reports` returns a receiver (the default returns `None`).

Pinned by `nsplane-e2e`'s `path_mtu` tests (`the_inner_mtu_follows_the_path_and_recovers`,
`packets_at_the_inner_mtu_fit_ipv4_and_ipv6_paths`,
`packets_at_the_source_mtu_fit_once_the_feature_is_used`,
`reports_that_lower_nothing_change_nothing`, `transport_ceilings_apply_at_once`,
`an_engine_without_the_feature_keeps_no_state`) and `path_mtu_root`.

### Fragmentation stage

`EngineBuilder::fragmenter(FragmentConfig)` installs a stage on the local
path, in the owner task before the core, that keeps every local packet within the source's
MTU (`PacketSource::mtu`, so it follows MTU changes); without it local packets enter the
core whatever their size.

- An IPv6 packet above the MTU is answered with an ICMPv6 Packet Too Big carrying the MTU.
- An IPv4 packet above its ceiling is answered with an ICMP Fragmentation Needed carrying
  the ceiling when DF is set, and is otherwise split into IPv4 fragments that enter the core
  one by one. The ceiling is the MTU for native IPv4 and 20 bytes lower for destinations
  that `FragmentConfig::translated` (e.g. `Translator::ipv4_translated_predicate`) reports
  as translated to IPv6, whose fragments are sized to fit the MTU once translated with an
  IPv6 Fragment header (MTU - 28). A UDP datagram without a checksum toward a translated
  destination gets one before it is split, so each fragment translates on its own. Every
  fragment carries the packet's tag, none its receipt marker; the errors carry neither.
- The errors look as if the packet's destination had sent them: they are delivered to the
  local side as coming from the peer `Core::route` picks for that destination (no route: no
  error) through `Core::inject_inbound`. They are rate-limited (a burst of 10, then 5 per
  second) and never sent about ICMP errors, multicast or broadcast packets, or non-first
  fragments.
- With per-path MTUs, a packet to a destination routed to a peer whose inner MTU is below the
  source MTU is held to that peer's MTU instead: the errors carry it and the fragments fit
  it. Packets within the lowest MTU of all peers pay no lookup.
- `EngineHandle::fragment_stats` returns the stage's `FragmentStats` (all zero without a
  stage): IPv4 packets fragmented, fragments emitted, Packet Too Big and Fragmentation
  Needed errors sent, and oversized packets dropped without an error for the rate limit
  (`rate_limited`), for no route (`no_route`) or because no error is allowed or the packet
  cannot be split (`dropped`). The drops are counted in `drop_counters` too, under
  `DROP_FRAGMENT_RATE_LIMITED`, `DROP_FRAGMENT_NO_ROUTE` and `DROP_FRAGMENT_OVERSIZE`.

### Hybrid local side

For a hybrid local side, e.g. a TUN device next to a userspace netstack, `Splitter` is a
`PacketSink` that routes each delivered packet to one of several sinks by a closure
(`Fn(PeerId, &PacketBuf) -> usize`) and `MergeSource` is a `PacketSource` that serves
several sources round-robin and reports the smallest of their MTUs. `MergeSource::recycle`
holds up to 64 buffers (no allocation until the first) and hands them to the next input
whose `recv` completes, before re-arming it; that input takes what its pool allows and the
rest are dropped, ended inputs get none; unused it costs one `is_empty` check per packet.
The splitter awaits
only the chosen sink, but a waiting sink still holds back the engine's next delivery;
packets routed to an index out of range are dropped and counted (`Splitter::misrouted`).
`Splitter::stats` returns a `SplitterStats` snapshot (`#[non_exhaustive]`): `misrouted`, and
`failed`, packets whose chosen sink returned an error or that found every sink gone; a
delivered packet updates no counter.

### Local-side graph

Three more primitives join local-side endpoints (TUN devices,
netstacks, engines, translators) into a graph, so an embedder writes routing closures and
decisions, not packet loops:

- `MapSink::new(sink, f)` and `MapSource::new(source, f)` run a closure on every packet in
  place, before delivery (`Fn(&mut PacketBuf, PeerId) -> MapVerdict`) or after reception
  (`FnMut(&mut PacketBuf) -> MapVerdict`). `MapVerdict::Drop` discards the packet: the
  sink's `send` returns `Ok`, the source reads the next one, and both count it in
  `dropped()`. The MTU passes through and the batch methods map each packet. A Redirect is a
  `MapSink` running the forward translation plus a `MapSource` running the reverse one.
  `Nat64LanSink` / `Nat64LanSource` are equivalent to a `MapSink` / `MapSource` over a
  `Nat64Lan`.
- `pipe(capacity, mtu)` returns a `PipeSink` and a `PipeSource`: what is sent to the sink
  comes out of the source in order, so one engine's (or a `Splitter`'s) output is another
  engine's input without a forwarding task. `send` waits while the pipe is full; once the
  source is dropped it returns `BrokenPipe`, and once every `PipeSink` clone is dropped the
  source returns `BrokenPipe` after draining. The `from` peer is not carried.
  `PipeSource::mtu_sender` changes the MTU the source reports. Pooled allocation:
  `PipeSink::alloc(len) -> PacketBuf` takes a packet from the pipe's `SharedPacketPool`
  (`max_free` = `capacity`; contract as `SharedPacketPool::alloc`), and
  `PipeSink::recycle(&mut Vec<PacketBuf>)` hands buffers back to it, e.g. a consumer
  returning what a `ChannelSink` delivered. `PipeSource::recycle` puts the engine's
  transmitted buffers into that pool once some producer called `alloc`; before that it
  declines the first offer and the engine stops offering. A producer that starts
  allocating after traffic began therefore gets only what consumers return. Unused, `send`
  and `recv` are unchanged.
- `pump(source, sink, from)` moves every packet from a source into a sink in order, one
  `recv_batch` and one `send_batch` per round, and awaits the sink's backpressure instead of
  dropping. It ends with `Ok(PumpStats { packets, batches })` once either side returns
  `BrokenPipe` and returns any other error. Cancelled while it waits for the source it
  loses nothing; while it waits for the sink, at most the batch in flight.
  Sink-side return: `pump` delivers with `PacketSink::send_batch_spent(&self,
  packets: &mut VecDeque<(PeerId, PacketBuf)>, spent: &mut Vec<PacketBuf>)`, a default
  method that delivers like `send_batch` and appends the buffers the sink no longer
  references (written out or dropped); order, backpressure, errors and cancellation are
  those of `send_batch`, and `spent` may stay empty (the default calls `send_batch` and
  appends nothing). `TunSink` overrides it: plain, vnet and Wintun writes append every taken
  buffer after its write, the TSO writer a coalesced chunk's buffers once the chunk is
  written, a non-IP packet is dropped without being appended. `pump` hands `spent` to
  `PacketSource::recycle`, untagged and unmarked, before its next `recv_batch`; if the source takes none of the
  first non-empty offer, it uses plain `send_batch` for the rest of its run (later offers
  that take nothing do not switch it off). A cancel also drops spent buffers not yet
  recycled (buffers, never packets); `PumpStats` are unchanged; a default sink costs one
  `is_empty` branch per batch. The wrappers forward it under the contract of their own
  `send_batch`, so the loop also closes behind them: `MapSink` appends the buffers of the
  packets its closure dropped, in order, then the inner sink's (its `after` hook reads its
  copies); `AbortSink` races the inner `send_batch_spent` and, aborted, appends the buffers
  of the packets it drops except the one being delivered; `SwapSink` forwards to the
  current sink and appends the buffers it drops (empty slot, or left by a replaced sink that
  failed); `Splitter` hands each packet to the chosen sink's `send_batch_spent` as a batch
  of one (a packet goes to one sink only) and appends the buffers of misrouted packets and
  of a packet failed because every sink is gone.

```text
TUN source ─► pump ─► Splitter ─┬─► pipe ─► MergeSource ─► engine A
                                └─► MapSink (Redirect) ─► netstack sink
netstack source ─► MapSource (reverse) ─► MergeSource
engine A ─► Splitter ─┬─► pipe ─► engine B
                      └─► TUN sink
```

Four wrappers cover the per-packet glue left after that:

- `Splitter::new_map(route)` takes a closure `Fn(PeerId, &mut PacketBuf) -> usize` that may
  rewrite the packet in place (a Redirect or Masquerade translation) and then returns the
  sink index; the packet goes there as rewritten. The rest is `Splitter` as above: out of
  range drops the already rewritten packet as misrouted and returns `Ok`, only the chosen
  sink is awaited, and once every sink is gone the closure is not called. `Splitter::new`
  is a `new_map` whose closure only reads, so a reading splitter pays nothing for the write access.
- `MapSink::with_after(sink, f, after)` adds an after-delivery hook `Fn(&[u8])`, called with
  each packet's bytes as handed to `sink` (after `f`), once `sink` took it over: never for a
  packet `f` dropped or the one `sink` failed on, e.g. to retire a mapping only after the
  TUN writer took the packet. Kept packets are copied first into a buffer reused from call
  to call. `send_batch` calls `after` in order for exactly the packets `sink` took over:
  all of them on success, the ones before the failed packet on an error. A cancelled `send`
  or `send_batch` calls no `after` for that packet or batch, so a cancelled batch may have
  delivered packets whose hook did not run. `try_send_batch` keeps the default
  (`WouldBlock`) with or without a hook. The third type parameter defaults to `fn(&[u8])`,
  so `MapSink::new` and `MapSink<S, F>` pay nothing for the hook.
- `SwapSink<S>` is a sink whose inner sink is replaced, or removed, while the engine runs;
  clones share the slot and the drop counter, so the engine owns one and the embedder calls
  `replace` on another. While the slot is empty every packet is dropped, counted in
  `dropped()` and `Ok`; otherwise a call awaits the current sink. A call in flight finishes
  on the sink it started on, and `replace` does not wait for it; that is why
  `replace(Option<S>)` returns the old sink as `Option<Arc<S>>`, dropped once the last call
  holding it is done. An error from a sink replaced while the call was in flight is counted
  as dropped and returns `Ok`, so the engine does not take the local side for gone; an error
  from the current sink is returned unchanged.
- `AbortSink::new(sink)` returns the wrapped sink and a `SinkAbort` handle. Until the abort,
  each call races the inner call against it (one atomic load more when the call does not
  wait); `SinkAbort::abort` drops a pending inner `send` or `send_batch`, so nothing it
  carried arrives later, counts the packet in flight and the rest of the batch in
  `AbortSink::dropped`, and returns `Ok`. Later calls drop and count at once. It returns
  `Ok`, not `BrokenPipe`, because behind a `SwapSink` the next generation may already be
  installed: a `BrokenPipe` would make the engine (or a `pump`) tear down the whole local
  side mid-swap. Stopping whatever feeds the aborted sink stays the caller's job. Caveat:
  the packet being delivered counts as one, per the `send_batch` cancellation contract; an
  inner sink that takes several packets over at once may lose more than are counted.

A sink rebuilt per generation composes the two: the engine gets
a `SwapSink<AbortSink<S>>`, and each new generation does `swap.replace(Some(next))` and
then `old_abort.abort()` on the previous generation's handle, so later packets go to the
new sink and a delivery stuck on the old, full one is cancelled instead of holding up the
engine or delivering after the old generation stopped.

`nsplane-e2e` covers them behind an engine: `graph_split_map` (a Redirect then route
demux, misrouted counting), `graph_after_delivery` (the hook reports every delivered packet
once and in order, none dropped or failed) and `graph_swap_sink` (an empty slot, a delivery
stuck on generation 1 aborted when generation 2 is installed, order kept, every packet
accounted for). The `local_graph` bench compares each wrapper with its baseline: `splitter`
(`new` vs `new_map`), `map_sink` (`new` vs `with_after`, `send` and `send_batch`) and
`swap_sink` (the bare sink vs `SwapSink` vs `SwapSink<AbortSink>` not aborted).

They are plain generic types and a `pump` runs only where the embedder spawns it: an engine
that does not use them pays nothing.

### Batched I/O

The I/O tasks move up to `MAX_BATCH` (64) packets or datagrams per call
through `PacketSource::recv_batch`, `PacketSink::send_batch`, `Transport::recv_batch` and
`Transport::send_batch` (default methods that fall back to one at a time; `DynTransport`
mirrors them), with the same backpressure, stop handback and recycling as single calls:

```text
TUN read (vnet hdr + up to 64 KiB) ─► segments (<= MTU) ─► core seals ─► GSO UDP send
UDP GRO read ─► zero-copy slices ─► core opens in place ─► coalesced TUN writev
```

`Transport::send_batch` reports in its `failed` argument which of the datagrams it was done
with failed, so `TRANSPORT_SEND_ERROR` counts exactly the lost datagrams: a failed segmented
`UdpTransport` send loses its run, not the runs handed off before it in the same call.

Offload is negotiated where the device or socket is opened. `Tun::create` (Linux,
Android) asks for `IFF_VNET_HDR` with checksum offload and TSO, plus USO when the kernel
accepts it, and falls back to a plain `IFF_NO_PI` device; `Tun::offload` reports the
result. `UdpTransport::bind` sets the socket up with `quinn-udp`: GSO on send where the
platform has it, GRO on receive on Linux and Android, each GRO datagram a
`PacketBuf::from_shared` slice of the read buffer without headroom. A segmented send that
fails with `EIO`/`EINVAL` falls back to one datagram per send, and where `quinn-udp`
cannot set the socket up (Wine) the transport sends with plain `send_to`. With offload on
the socket sets DF, so outer datagrams above the path MTU fail with `EMSGSIZE`; the engine
counts them under `TRANSPORT_SEND_ERROR`. `TunOptions::offload(false)`,
`UdpTransport::bind_with_offload(.., false)` and the examples' `--no-offload` opt out. Plain
TUN reads (no virtio-net header, and Wintun reads on Windows) leave the same 28 bytes of
room behind each packet as segmented ones (a read still takes at most the MTU), so a
translator grows full-MTU IPv4 in place with offload off too.

## Configuration and defaults

| Feature | How to enable | Default | Cost when not enabled |
|---|---|---|---|
| Fragmentation stage | `EngineBuilder::fragmenter(FragmentConfig::default())`; `FragmentConfig::translated` for destinations a translator turns into IPv6 | off | one `Option` check per local packet; local packets enter the core whatever their size |
| Per-path MTU | `EngineBuilder::transport_max_datagram` / `EngineHandle::set_transport_max_datagram`, `EngineHandle::report_path_mtu`, or a transport whose `path_mtu_reports` returns a receiver; `EngineBuilder::fragmenter` to make it reach the local side | off: every peer at the source MTU, padding to 16 bytes | none: no table, padding limit or report task until a ceiling is set or a report arrives; the fragmentation stage looks a peer up only for packets above the lowest MTU |
| Crypto worker pool | `EngineBuilder::crypto_workers(n)`, `n` >= 2 | 0: the owner task encrypts and decrypts | one `Option` check per packet, no tasks spawned; without crypto workers each peer owns its tunnel and the data path takes no lock (with workers it is shared behind a `Mutex`) |
| Hybrid local side | `Splitter::new(route).sink(..)` as the sink, `MergeSource::new().source(..)` as the source | not used | none: plain types, used only when passed to the builder |
| Local-side graph | `MapSink::new(sink, f)` / `MapSource::new(source, f)` around a sink or source; `pipe(capacity, mtu)` to feed one engine's output into another's input; `pump(source, sink, from)` spawned between two endpoints | not used | none: plain generic types, used only when passed to the builder or spawned; nothing changes for an engine that does not use them |
| Pooled producer allocation | `PipeSink::alloc(len)` / `ChannelSource::pool()` for the producers, `recycle` from consumers | off: the source declines recycled buffers | none per packet: one `Arc` per pipe or channel source; the source declines the engine's first offer |
| UDP segmentation offload (GSO/GRO) | `UdpTransport::bind` turns it on; `UdpTransport::bind_with_offload(id, addr, false)` or `set_offload(false)` opts out | on: GSO where the platform has it, GRO on Linux and Android | off: one system call per datagram |
| UDP side channel | `UdpTransport::with_side_channel(classify, capacity)` | off | one `Option` check per received datagram; nothing is classified, no task or copy |
| UDP path MTU discovery | `UdpTransport::set_path_mtu_discovery(true)` before handing the transport to the engine (Linux, Android) | off | none: no socket option, no error-queue read, no report queue |
| Awaiting side send | `SideSender::send_to_async` instead of `send_to` | not used | none |
| Plaintext ingress | `EngineBuilder::plaintext_ingress(capacity)` | off | one `Option` check per poll of the received datagrams; no queue |
| Message-link transport | `LinkTransport::new(id, peer, dialer, config)` as a transport | not used | none: no task is spawned and no dependency added; the dialer (WebSocket, TLS) is the embedder's |

## Errors and drop reasons

The engine counts every dropped packet under a reason (`EngineHandle::drop_counters`) and
publishes it as `Event::Dropped`: the core's and the filters' reasons plus the engine's own,
among them `DROP_SINK_FULL`, `DROP_SINK_CLOSED`, `DROP_TRANSMIT_FULL`,
`DROP_TRANSPORT_CLOSED`, `DROP_TRANSPORT_SEND_ERROR`, `DROP_NO_TRANSPORT`,
`DROP_FRAGMENT_RATE_LIMITED`, `DROP_FRAGMENT_NO_ROUTE` and `DROP_FRAGMENT_OVERSIZE`.
Plaintext ingress drops count under the core's reasons (`SOURCE_NOT_ALLOWED`,
`DESTINATION_NOT_ALLOWED`, `UNKNOWN_PLAINTEXT_PEER`) and the filters'. An I/O side that
reports `BrokenPipe` stops its task; the engine keeps running without it.

## Limits and bounds

- Every queue between the tasks is bounded (`queue_capacity`, default 1024; commands 64;
  `event_capacity`, default 1024); batches are at most `MAX_BATCH` (64).
- With crypto workers at most `queue_capacity` jobs are in flight.
- The plaintext ingress queue holds its `capacity` (at least 1) packets.
- `LinkConfig::queue` (256) datagrams wait for a link.
- At most 64 path MTU reports wait; further ones are counted and dropped.
- Fragmentation errors: a burst of 10, then 5 per second.
- `MergeSource::recycle` holds up to 64 buffers.

## Platform notes

- GRO, path MTU discovery and the vnet-header offload are Linux and Android only; GSO is used
  where the platform has it.
- macOS and Windows deliver no ICMP errors to an unconnected UDP socket, so
  `report_path_mtu` is the only way to set a path's MTU there.

## See also

- [nsplane-core](nsplane-core.md): the sans-I/O core the engine drives.
- [nsplane-tun](nsplane-tun.md): TUN sources and sinks.
- [Usage guide](../guide.md)
- [Performance](../performance.md)
