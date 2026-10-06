# QR-4: MR-1 pooled producer allocation and MR-3 sink-side return path

Design note, no code. Contract: `docs/task/20261003-2200-ns-local-side.md`, section "Buffer
recycling items from ns on v0.10.0 (MR)"; plan row QR in `docs/plan/20261006-0900-ns-requests-2.md`.

## Where buffers leak today

- ns producers feeding a `PipeSink` or a `ChannelSource` sender allocate every packet
  (`PacketBuf::with_capacity(len + TAILROOM)`). The engine hands transmitted buffers to
  `PacketSource::recycle` before its next read, but `PipeSource` and `ChannelSource` keep the
  default, so the engine marks the source as declined and puts them into the core's pool.
- `pump` drops every buffer the sink wrote: `PacketSink::send` and `send_batch` take packets by
  value and no sink (`TunSink` included, TSO path too) gives them back. ns runs
  `pump(PipeSource, OsTunPacketSend)` for the TUN output, so every packet written to the TUN is
  freed there.
- Packets delivered to `ChannelSink` / `PipeSink` consumers (ns's netstack `stack::poll`, the
  mobile DNS stack) are dropped by the consumer, outside every pool.

## MR-1: pooled producer allocation

### API

One new public type in `nsplane-packet` (next to `PacketPool`, re-exported by `nsplane`), plus
additive methods on the existing local-side types:

```rust
/// A bounded free list of packet buffers shared by producers and a source: lossy, never waits.
#[derive(Debug, Clone)]
pub struct SharedPacketPool { /* Arc<FreeList> */ }

impl SharedPacketPool {
    pub fn new(max_free: usize) -> Self;
    /// A packet of `len` bytes behind HEADROOM, capacity() >= len + TAILROOM; bytes unspecified.
    pub fn alloc(&self, len: usize) -> PacketBuf;
    /// Takes buffers out of `bufs` up to `max_free` idle ones; takes none while busy.
    pub fn recycle(&self, bufs: &mut Vec<PacketBuf>);
    pub fn free_len(&self) -> usize;
    /// Buffers `alloc` allocated because none was idle (or the list was busy).
    pub fn allocated(&self) -> u64;
}

impl PipeSink {
    pub fn alloc(&self, len: usize) -> PacketBuf;          // the pipe's pool
    pub fn recycle(&self, bufs: &mut Vec<PacketBuf>);      // MR-3 (c), see below
}

impl ChannelSource {
    /// The pool behind this source's `recycle`, for the producers holding its sender.
    pub fn pool(&self) -> SharedPacketPool;
}
```

`pipe(capacity, mtu)` and `ChannelSource::new(capacity, mtu)` keep their signatures and create
the pool with `max_free = capacity`. `ChannelSource::new` returns a raw `mpsc::Sender`, which
cannot grow an `alloc`, hence `pool()`; a separate pooled sender type would be a second new type
for no gain.

### Semantics

- `alloc(len)`: a packet of `len` bytes, `headroom() == HEADROOM`, `capacity() >= len + TAILROOM`,
  packet bytes unspecified. Warm path: `PacketPool::get(len + TAILROOM)` then `set_len(len)`,
  which writes nothing when the recycled buffer already initialized those bytes and grows a
  too-small one (it keeps the larger capacity, so mixed sizes converge). Cold path: a fresh
  `with_capacity(len + TAILROOM)` zero-filled to `len`.
- Free list: the `host.rs` `FreeList` generalized, i.e. `Mutex<PacketPool>` taken only with
  `try_lock`, plus an `AtomicBool` "stocked" hint so `alloc` skips the lock while the list is
  empty. Bounded by `max_free`, lossy (a busy or full list drops what it is given; a busy or empty
  one makes `alloc` allocate), never waits, no `unsafe`, no new crate. `nsplane-tun`'s `host_tun`
  replaces its private `FreeList` with a `SharedPacketPool` (push becomes `alloc(len)` +
  `copy_from_slice`; a fresh buffer gains TAILROOM and a zero-fill of `len` before the copy).
- Refill: `PipeSource::recycle` and `ChannelSource::recycle` override the default and call
  `pool.recycle(bufs)`, so transmitted buffers flow engine -> source task -> pool -> producer.
- Activation gate: the source takes buffers only once some producer called `alloc` (an
  `AtomicBool` set on the first `alloc`, read `Relaxed` in `recycle`). Without it a pipe whose
  producers never allocate would park up to `capacity` buffers that only the core's pool could
  reuse. With it the first offer is declined, the engine sets `declined` and never offers again:
  exactly today's behaviour. A producer that uses `alloc` does so for its first packet, so the
  flag is set before that packet is read (the channel orders it) and before the first offer.
  Documented limit: a producer that switches to `alloc` after traffic started gets no engine
  refill, only what consumers return through `recycle`.

### Cost when unused

Per pipe or channel source: one `Arc` allocation at construction and one pointer in
`PipeSink`/`PipeSource` (cloning a `PipeSink` bumps one more refcount). Per packet: nothing;
`send`, `try_send_batch`, `recv` and `recv_batch` are unchanged. `recycle` runs once, does one
`Relaxed` load and declines. To be confirmed by the A/B below (the `pump` rows build their pipes
inside the measured loop, so they also show the constructor cost).

## MR-3: sink-side return path

| Option | API change | Class | Closes |
|---|---|---|---|
| (a) `pump` hands spent buffers to `source.recycle` | default method on `PacketSink` + `TunSink` override + pump | more than additive: trait change (non-breaking default) | TUN write loop |
| (b) `EngineHandle::recycle(Vec<PacketBuf>)` | additive method on `EngineHandle` | additive method; waits for QE in main | consumer -> engine's source |
| (c) consumer returns to the producer pool | `PipeSink::recycle`, `SharedPacketPool::recycle` | additive method (with MR-1's type) | ChannelSink/PipeSink consumer -> pool |

(a) There is no way to get buffers back without a trait change: the sink owns each packet once it
pops it. Proposed additive default method:

```rust
/// Like `send_batch`, and appends the buffers of packets it wrote to `spent`.
/// The default calls `send_batch` and appends nothing.
fn send_batch_spent(
    &self,
    packets: &mut VecDeque<(PeerId, PacketBuf)>,
    spent: &mut Vec<PacketBuf>,
) -> impl Future<Output = io::Result<()>> + Send { async move { self.send_batch(packets).await } }
```

`TunSink` (unix send loop and TSO `VnetWriter` path, Windows) overrides it: a written packet's
buffer goes to `spent` instead of being dropped. `pump` calls it with a reusable `Vec` and hands
`spent` to `source.recycle` before its next `recv_batch`, like the engine's source task. Same
first-offer rule as the engine: if the source takes none of the first non-empty `spent`, pump
switches to plain `send_batch` for good, so a default-`recycle` source costs nothing per packet.
A default sink costs one `is_empty` branch per batch. Guarantees: order, backpressure and the
`send_batch` error contract are unchanged (`spent` only holds packets already taken over);
cancellation drops `spent` with the pump, i.e. buffers, never packets; no drop counters change.
The wrappers (`MapSink`, `SwapSink`, `AbortSink`, `Splitter`) do not forward it in the first
step, so the loop is closed only for a bare sink; ns's `OsTunPacketSend` forwards it to its
`TunSink`. In ns the spent buffers land in the TUN-output `PipeSource`'s pool, from which ns's
producers into `tun_out_tx` allocate. Back to a `TunSource` literally is not reachable: ns's TUN
reader feeds `RuntimeIngressSink`, which freezes packets into `Bytes`.

(b) Feeds the engine's bounded, lossy source-recycle queue (`try_send`, never waits, ordered
nowhere). Useful only to a consumer that holds the handle and does not produce itself; ns's
consumers do produce, so (c) is shorter (no trip through the engine) and needs no QE. Deferred.

(c) `PipeSink::recycle` / `SharedPacketPool::recycle`: synchronous, `try_lock`, lossy, so it
cannot block a consumer or affect any queue, order or backpressure; it also sets nothing in the
activation gate (only `alloc` does). ns's netstack consumes from a `ChannelSink` receiver and
produces into a `ChannelSource` sender or a `PipeSink`, so it returns consumed buffers to the
pool it allocates from. `ChannelSink`'s receiver is a raw `mpsc::Receiver`, so no method goes
there.

## Recommendation

Ship MR-1 as above, MR-3 (c) (it comes with MR-1's pool) and MR-3 (a); defer (b) until a
consumer without a producer asks. Loops closed for ns:

1. Engine input: `PipeSink::alloc` / `pool().alloc` -> pipe -> engine -> transmit ->
   `PipeSource::recycle` / `ChannelSource::recycle` -> pool.
2. Consumer: engine -> `ChannelSink` / `PipeSink` -> ns netstack -> `recycle` into its producer
   pool -> loop 1.
3. TUN output: producers `alloc` from `tun_out_tx` -> `pump` -> `TunSink::send_batch_spent` ->
   `PipeSource::recycle` -> pool.

Classification: additive methods/constructors: `PipeSink::alloc`, `PipeSink::recycle`,
`ChannelSource::pool`, the `recycle` overrides on `PipeSource`/`ChannelSource`/`TunSink`
(behaviour, no signature). More than that: the new public type `SharedPacketPool`, and the new
default method `PacketSink::send_batch_spent` (trait change, non-breaking). If L2 rules the new
type out, the fallback is `PipeSink::alloc`/`recycle` only, ns moving its `ChannelSource`
producers to `pipe()`, and `host.rs` keeping its own `FreeList`.

## Test plan

- `nsplane-packet` unit: `alloc` invariants (len, headroom, capacity >= len + TAILROOM), reuse
  after `recycle` (`free_len`, `allocated` stays), bound `max_free`, too-small buffer grows,
  `from_shared` buffers dropped, busy lock (held inside the module): `alloc` allocates and
  `recycle` takes none.
- `nsplane` unit: `pipe.rs`: `alloc` + send + recv + `recycle` round trip reuses; source declines
  before any `alloc`; clones share the pool; `PipeSink::recycle` refills. `channel.rs`: same
  through `pool()`. `pump.rs`: a counting source and a sink that fills `spent`: spent buffers
  reach `recycle` before the next read; a declining source stops the offers; a default sink offers
  nothing; abort mid-batch loses no packet.
- `nsplane-tun`: `TunSink::send_batch_spent` returns written buffers (non-root fd tests, TSO and
  plain); `host_tun` tests unchanged; root TUN test adds a pump round.
- `nsplane-e2e` `recycle_loop.rs`: producer `PipeSink::alloc` -> engine A -> `ChannelTransport`
  -> engine B -> `ChannelSink` consumer that `recycle`s into the producer pool, and a
  `pump(PipeSource, spent-returning sink)`; after a warm-up of a few batches, 10k packets leave
  `allocated()` of both pools unchanged. A counting `#[global_allocator]` needs
  `unsafe impl GlobalAlloc`, which the workspace `unsafe_code = "deny"` rules out, hence the pool
  stats.
- Bench A/B vs main (`local_graph`): `pipe/send_recv_{64,1420}` and
  `pump/pipe_to_pipe_{64,1420}` must not regress (unused path). New rows, compared in-run with
  their baseline: `pipe/alloc_send_recv_*` (alloc + recycle vs `PacketBuf::with_capacity`) and
  `pump/pipe_to_pipe_spent_*`. The `host_tun` push+recv measurement from MR-2 is rerun for the
  `FreeList` swap.
