# Release C: one carrier, the packet tag

Design note, no code. Status: for owner and consumer review. Plan:
[20261026-0822-node-gateway-requests](../20261026-0822-node-gateway-requests.md) (W4-W6,
release C, open questions O8-O12); task:
[20261026-0819-node-gateway-requests](../../task/20261026-0819-node-gateway-requests.md) (R2,
R4 proposal A, R5 part 2, R6). All code references are at `main` `52eb983` (v0.19.2). The
review record is at the end.

## The carrier

R2, R4 proposal A, R5 part 2 and R6 all need a per-packet property that survives the queues
between a consumer and the point where nsplane decides. One opaque word on the packet buffer
carries it, instead of a side channel per request.

```rust
impl PacketBuf {
    /// The caller's tag, or `None`. nsplane never interprets it and never writes it to the wire.
    pub const fn tag(&self) -> Option<NonZeroU64>;
    /// Sets or clears the tag.
    pub const fn set_tag(&mut self, tag: Option<NonZeroU64>);
    /// Returns the tag and clears it.
    pub const fn take_tag(&mut self) -> Option<NonZeroU64>;
}
```

Semantics:

- A new buffer has no tag: `with_capacity`, `from_packet`, `from_shared`, and every buffer a
  `PacketPool` or `SharedPacketPool` hands out. The pools store the `BytesMut`, not the
  `PacketBuf` (`PacketPool::put` keeps `buf.buf`, `PacketPool::get` and `get_len` build a new
  `PacketBuf`), so a pooled buffer comes back untagged at no cost; no clear is needed there.
- `Clone` copies the tag. `into_bytes` and `freeze` drop it (the result is bytes, not a packet).
  No nsplane runtime path clones a `PacketBuf`: with `Clone` removed from `PacketBuf`, every
  library and binary of the workspace at `52eb983` still compiles (`cargo check --workspace
  --all-features --lib --bins`); only tests and benches clone. `Clone` stays for consumers and
  tests; the receipt marker's rule for clones is under W6 below.
- nsplane preserves the tag wherever it moves a packet into another buffer (carrier sites below)
  and clears it where a buffer stops being that packet (a handshake initiation written into it,
  a buffer handed back to a source for reuse).
- Transports and sinks never see it on the wire: they write `as_packet()` bytes only.
- The value space belongs to the consumer. One packet has one tag; a consumer that needs two
  meanings on the same packet (an ownership epoch for R4 and a receipt token for R6, say) packs
  both into the 64 bits. Packets that cross between two consumers over the wire are untagged,
  so two consumers' packings never meet.
- Where tags are in use, `None` is a value of its own, never a wildcard: a consumer that tags
  packets treats an untagged packet at a check of its own (an R4 epoch filter, say) as not
  current, and nsplane's own checks (netstack labels, merges of fragments) treat `None` as a
  label distinct from every tag. The one exception is an ICMP error at a labeled netstack (W5).

### Layout

`PacketBuf` today (`crates/nsplane-packet/src/buf.rs`): `buf: BytesMut` (32 bytes), `start:
usize`, `end: usize` (16), `shared: bool` (1), padded to 56 bytes on 64-bit targets. With
`tag: Option<NonZeroU64>` (8, the niche keeps `None` free):

| Variant | Fields | Size | Notes |
| --- | --- | --- | --- |
| A | as today plus `tag` | 64 | no other change |
| B | `start`, `end` as `u32`, plus `tag` | 56 | `len`, `headroom`, `capacity`, `set_len`, `advance`, `reserve_front` convert; `set_len` / `extend_from_slice` need a bound past `u32::MAX` that cannot panic |

The receipt marker of W6 (a `bool`) fits the padding of either variant. Every `PacketBuf`
moves by value through bounded queues and `PacketBatch`, whose inline
`SmallVec<[PacketBuf; MAX_BATCH]>` grows from 3584 to 4096 bytes under A. Recommendation:
implement A, measure it against B on the slot A/B (budget below), and take B only if A is
outside the noise. B's conversions sit on the hottest accessors, so it is not free either.

## Carrier sites

"Move" means the `PacketBuf` itself travels: the tag survives with no code. "Copy" means a new
buffer is filled from the old one: the site must copy the tag. Every site gets a test.

### nsplane-packet

| Site | Kind | Rule | Test |
| --- | --- | --- | --- |
| `PacketPool::get` / `get_len` / `put` | rebuild from `BytesMut` | untagged, unmarked | a tagged, marked buffer put and got again has neither |
| `SharedPacketPool::alloc` / `alloc_from` / `recycle` | via `PacketPool` | untagged, unmarked | same, through `recycle` |
| `PacketBatch::push` / `drain` / `IntoIterator` | move | preserve | tag round trip through a batch |
| `reassembly::Reassembler::push` | copy (`Outcome::Complete(Vec<u8>)`) | merge: the datagram carries a tag only if every fragment carried the same one (`None` included); a set with different tags is reported | new tagged entry, below |

`Reassembler::push(&[u8], Instant) -> Outcome` takes bytes and `Outcome` is an exhaustive enum
whose `Complete` holds a `Vec<u8>`, so the tag cannot be added to it without a break. Additive
entry:

```rust
/// The tags of a completed datagram's fragments.
#[non_exhaustive]
pub enum FragmentTags { Same(Option<NonZeroU64>), Mixed }

impl Reassembler {
    /// Like `push`, recording `tag` with the fragment; a completed datagram reports its fragments' tags.
    pub fn push_tagged(&mut self, packet: &[u8], tag: Option<NonZeroU64>, now: Instant) -> (Outcome, FragmentTags);
    /// Discards the incomplete datagrams holding a fragment with `tag`; returns how many.
    pub fn discard_tagged(&mut self, tag: NonZeroU64) -> usize;
}
```

`Datagram` keeps one `FragmentTags` (16 bytes per held datagram); `push` is `push_tagged` with
`None`. `Mixed` covers a set where some fragments carry a tag and others none. Every caller
drops a `Mixed` datagram and counts it (netstack and translator below), so a merge never yields
an untagged datagram from tagged input. `ReassemblyStats` is `#[non_exhaustive]`, so a
`mixed_tags` counter is additive.

### nsplane-core

| Site | Kind | Rule | Test |
| --- | --- | --- | --- |
| `Core::handle_locals`, `handle_locals_deferred`, `Input::Local` | move | preserve | |
| `Core::prepare_send` filter loop (`PacketFilter::outbound(id, &mut packet)`) | move | preserve; a filter may read or set the tag | recording filter sees the tag (R4 A) |
| `Core::layout_for_sealing`, the copy when `reserve_front` fails (shared slices) | copy | copy the tag and the marker | tagged, marked `from_shared` packet keeps both after layout |
| `job::seal` / `CryptoJob::seal` / `Core::complete_job` | move (`CryptoJob::buf`) | preserve | tag on the `Output::Transmit` datagram, with crypto jobs |
| `sealed` -> `transmit` -> `Output::Transmit { data }` | move | preserve for `MessageKind::Data`; **clear** otherwise | see below |
| `Tunn::encapsulate_in_place` / `reserve_in_place` without a session | the packet's bytes are copied into the tunnel queue (`queue_packet`, `Vec<u8>`) and a handshake initiation is written into the same buffer | the initiation must not carry the packet's tag or marker: `sealed` clears both when the kind is not data | no-session send: the initiation datagram is untagged |
| `Core::flush_queue` | new buffer (`pool.get_len`) | untagged (the queue keeps no tag, O9) | |
| `Core::opened` / `deliver_opened` -> `Output::Deliver` | move, opened in place | wire packets are untagged; an inbound filter may set a tag, which reaches the sink | inbound filter sets a tag, sink sees it |
| `Core::receive_plaintext` (release B), `Core::inject_inbound`, `inject_outbound`, `inject_outbound_on` | move | preserve the tag | one per entry |
| handshake, cookie and response buffers (`pool.get_len` in `handle_*`) | new | untagged | |

### nsplane (engine)

| Site | Kind | Rule | Test |
| --- | --- | --- | --- |
| `read_source`: `PacketSource::recv_batch` -> `PacketBatch` -> `BatchSender` local queue | move | preserve the tag; clear the marker (W6) | tag at the outbound filter through a `ChannelSource`; a marked packet from a source is untracked |
| `Owner::input_locals` -> `local_batch` -> `handle_locals(_deferred)` | move | preserve | |
| `fragment.rs` `Fragmenter::process`: `Action::Send` | move | preserve | |
| `split_ipv4` (`Action::Fragments`) | copy, one new buffer per fragment | copy the tag to every fragment; never the marker (O10) | each fragment carries the tag |
| `packet_too_big`, `fragmentation_needed` (`Action::Reply`) | new, delivered inbound | untagged | |
| `Output::Transmit` -> `TransportSlot` (`staged`, `pending`, `Handoff`, `send_now`, transmit task) | move (`Datagram = (Path, PacketBuf)`) | preserve up to the transport call | tag visible at `send_now` (R6) |
| `Output::Deliver` -> `write_sink` / inline delivery -> `PacketSink::send_batch` | move | preserve | tag reaches `NetStackSink` |
| `read_source` recycle: `recycled` -> `PacketSource::recycle(&mut bufs)` | move of whole `PacketBuf`s to the source | **clear** tag and marker before the call | a source reusing a recycled buffer gets neither |
| `pump`: `PacketSink::send_batch_spent` `spent` -> `PacketSource::recycle` | move | **clear** before the call | same, through `pump` |
| `PipeSink` / `PipeSource`, `ChannelSink` / `ChannelSource`, `MapSource`, `MergeSource`, `Splitter` | move (mpsc of `PacketBuf`) | preserve; a map closure that builds a new buffer owns its tag | pipe and channel round trip |

The recycle hand-offs matter because `PacketSource::recycle` takes `PacketBuf`s, not storage:
`MergeSource::recycle` keeps them as they are, and a consumer's source may reuse one with
`set_len` instead of a pool. Clearing costs one store per recycled buffer, off the packet path.
`PacketSource::recycle`'s docs then state that the buffers arrive untagged and unmarked.

### nsplane-nat (filters in the outbound and inbound chains)

The plan's list missed these; a filter installed after them reads the tag (R4 A), and a tracked
packet keeps its token through them (R6).

| Site | Kind | Rule |
| --- | --- | --- |
| `translate/rfc7915.rs` `make_room` (`*packet = grown`) | copy | copy the tag and the marker |
| `nat64_lan/packet.rs` `to_ipv6` (`*packet = PacketBuf::from_packet(..)`) | copy | copy the tag and the marker |
| `translate/fragment.rs` reassembly (via `Reassembler`) | the completing fragment's buffer becomes the datagram | merge rule via `push_tagged`; `Mixed` is dropped and counted, like the netstack |

Dropping a `Mixed` set (rather than passing it untagged) keeps the rule of the carrier: a merge
never turns tagged input into an untagged packet that a consumer's epoch filter might pass.
`TranslatorStats` is an exhaustive struct, so its new counter (`fragment_mixed_tags`) is a
breaking change; see the breaking-change list.

### nsplane-netstack (R2)

| Site | Kind | Rule |
| --- | --- | --- |
| `NetStackSink::send` -> `mpsc::Sender<PacketBuf>` -> `ingest_batch` (`poll_recv_many`, `batch`, `carried`) | move | preserve |
| `Driver::reassemble` (`Outcome::Complete` -> `PacketBuf::from_packet`) | copy | `push_tagged`; `Mixed` is discarded and counted (`label_mismatch`) |
| `classify` | borrow | |
| bare SYN, any stack (`Driver::ingest` before `device.inject`) | move, then consumed | the label is recorded per tuple **before** `inject`; smoltcp never sees it (W5) |
| `admit_syn` -> `Pending` (`Decision::Tcp(PacketBuf)`), `Admission::Decide` | move | the held SYN keeps its label |
| established TCP segment (`device.inject`) | move, then consumed | checked against its lifetime's label before `inject` while the stack holds a labeled lifetime |
| `udp::parse_udp` / `parse_udp_whole` (`packet.freeze()`) | the `PacketBuf` ends | the crate-private `udp::Datagram` gains the tag; `hold_udp` keeps it with the held datagram |
| `dispatch_flow` -> flow table entry and flow queue (`mpsc` of `Bytes`) | | the label is stored with the flow entry and compared on the lookup `dispatch_flow` already makes; the queue item gains nothing |
| `dispatch_udp` -> connected / bound socket queues (`mpsc` of `(SocketAddr, Bytes)`) | | unchanged: no `recv_labeled` in release C (open item for the gateway) |
| `icmp` (`pmtu::parse`, `reduce_mss`) | borrow | an unlabeled ICMP error is accepted for a labeled connection; one with another label than the connection it quotes is ignored and counted |
| egress (`VirtualDevice` tx tokens from the device pool, `UdpReply`, rejections from `pending.rs`) | new | untagged; labeling egress is not requested and not proposed |

## Per-packet budget

What an untagged packet pays: 8 more bytes per `PacketBuf` (variant A) in every queue and
batch it sits in; one word copied at the copy sites above (`layout_for_sealing`'s slow path,
`split_ipv4`, the translator's slow paths, netstack reassembly); one store per packet at the
engine's entries (the receipt marker cleared in the batch `read_source` already walks); one
store per recycled buffer; one compare in `sealed` (data vs. other kinds, already computed).
The netstack's label checks run only while the stack holds a labeled lifetime or a tombstone
(a counter), so an unlabeled stack keeps today's path; receipts cost only for tracked packets.

Acceptance bar for untagged traffic: within the slot A/B noise against `main` on

- `nsplane-core` `data_path`: `core_round_trip/64` (417 ns at 0.19.2) and
  `core_round_trip_batch32`;
- `nsplane-netstack` `send_stream`: `netstack_send/*`, `netstack_udp_send/*` including `flows_4`
  (the case that showed +4.1 % when flow state was added);
- `nsplane` `local_graph` (`pipe/send_recv_*`, `pipe/alloc_send_recv_*`) and `udp_offload`
  (`udp_loopback/batch_64x*`);
- `nsplane-packet` `vnet` and `nsplane-nat` `translate` for the copy sites.

Acceptance bar for the labeled path (a stack that runs labeled all the time, as the node's
shared stack will): in `send_stream`, the receiving stack's input labeled versus the same run
unlabeled, on the same build, interleaved, within the noise bar plus an allowance the owner
names (proposed: 3 %):

- TCP: `netstack_send/streams_{1,4}` and `netstack_send_1cpu/*` (the receiver's per-segment
  label check sits on every data segment);
- UDP: today's `netstack_udp_send` delivers to bound sockets, which carry no labels; a new
  `netstack_udp_flow_send` group sends the same load to flows the receiver takes from
  `incoming_udp` (`flows_1`, `flows_4`), labeled and unlabeled.

If TCP misses the bar, the alternative to measure is a per-socket label: stored next to the
socket handle and checked after smoltcp's demultiplexing (in the driver's poll of the socket
that took the segment) instead of a tuple lookup before `inject`. It saves the lookup but sees a
mismatch only after smoltcp has processed the segment, so it needs a way to undo that segment's
effect, which is why it is the fallback, not the default.

Variant A and B are both measured; `docs/performance.md` records the results, labeled and
unlabeled.

## How the workstreams use it

### W5, netstack ingress labels (R2)

The tag of a packet sent into `NetStackSink` is its ingress label. The consumer sets it on its
side of the sink, after its own classification of the packet (a consumer that decides a
packet's owner after the engine's filters cannot do it in an inbound `PacketFilter`); setting it
in an inbound filter remains possible for consumers that decide there. The tag then moves
through the consumer's own queue (it is part of the `PacketBuf`) and `NetStackSink` into the
stack.

Rules:

- A lifetime takes the label of its first input; `None` is a label of its own. Input whose
  label differs from its lifetime's is dropped and counted (`label_mismatch`): a TCP segment, a
  retransmitted SYN, a handshake ACK, a datagram for a labeled flow, and a fragment set whose
  labels differ. An unlabeled stack (no labeled lifetime and no tombstone) keeps today's path.
- Labels apply to every stack, with or without `Admission`:
  - TCP: a bare SYN's label is recorded in a per-tuple table of pending labels before
    `device.inject` consumes the packet (on an ordinary stack `Driver::ingest` passes the SYN
    straight to `inject`, `stack.rs:1150-1159`; `admit_syn` runs only for transparent stacks).
    `Driver::track_inbound`, which runs on every stack after smoltcp's poll
    (`stack.rs:1078`, `:2389-2418`), moves it to the `Driver::inbound` entry of the listener
    socket that took the SYN; adoption moves it to the lifetime's `FlowState` and its entry in
    the label table that established segments are checked against. A pending label that no
    socket took (no listener, `syn_refused`) expires with the next poll. Under
    `Admission::Decide` the held SYN's first-input state (release B) records it instead.
  - UDP: `dispatch_flow` stores the label with the flow entry when it opens the flow
    (`stack.rs:1655-1700`, on every stack) and compares it on the `(remote, local)` lookup it
    already makes for every datagram; under `Decide` the held datagram's first-input state
    records it.
- ICMP errors: an unlabeled ICMP error is accepted for a labeled connection (routers on the path
  send them and a consumer cannot attribute them without the inner tuple); an ICMP error with
  another label than the connection it quotes is ignored and counted.
- `NetStackHandle::revoke_label(label) -> RetirementReceipt` retires every lifetime with that
  label at every stage, including those already handed out: the held input (`Pending`), the
  pending SYN labels and `SynReceived` listener sockets, adopted `FlowState`s with their
  sockets and flow entries, `Driver::waiting`, the accept channels (release B's stage check
  skips them at the hand-out), and handles in the application's hands (their control is
  revoked: reads fail with `ConnectionAborted`, `UdpFlow::recv` returns `None`, as for
  `FlowControl::revoke`). It drops reassembly entries with the label
  (`Reassembler::discard_tagged`) and drops input with the label that is still in the ingress
  queue, until the queue has passed every packet sent before the call (a bounded table of
  ingress positions, like the egress fences).
- Outcomes, with the meanings `RetirementOutcome` has today: `Retired`: nothing of the label is
  delivered from then on. `Failed`: a bounded table was full (ingress positions, egress fences,
  reassembly barriers). Every lifetime found was still retired and its handles revoked, as a
  `FlowControl::revoke` that reports `Failed` has already released its flow (`Driver::retire`);
  what failed is a fence, so input or output queued before the call may still pass. The call is
  idempotent: the consumer may call again; a later call re-scans, records the missing fences and
  reports `Retired` once they fit. A consumer keeps the lifetime's owner withdrawn (fails
  closed) until a call reports `Retired`. `Unknown`: the stack stopped.
- A label used after its `revoke_label` (input that reaches `NetStackSink::send` after the call)
  is a consumer error: it is dropped and counted (`label_revoked`) and never becomes the first
  input of a new lifetime, as long as nsplane holds the label's tombstone (O14). The consumer
  cancels its own queued input of the label before it calls `revoke_label` (adoption path,
  step 3), so the tombstone is a safety net, not the mechanism.
- After `Retired` the label's state is gone, so the same tuple opens a fresh lifetime with
  another label: a UDP datagram on the tuple of a retired flow opens a new flow (the retired
  entry was removed from `flows`, as `FlowControl::revoke` does today); a TCP SYN on the tuple
  of a retired connection opens a new connection through the listener pool (the retired socket
  was released; the peer's segments of the old connection get the stack's stateless RST, as
  after a revoke today).
- Release B makes `NetStackStats` (with `NetStackConfig`, `TransparentConfig`,
  `FlowEventsConfig` and `PendingProtocol`) `#[non_exhaustive]`, so `label_mismatch`,
  `label_revoked` and `max_revoked_labels` are additive in release C.

Cost: the UDP compare rides on the flow lookup `dispatch_flow` makes anyway. TCP pays one tuple
lookup per segment while the stack holds a labeled lifetime: an established segment goes to
`device.inject` without a lookup today. This is the main cost of W5 and has its own bar (budget
above).

### R4 proposal A

`PacketFilter::outbound` sees the tag of the packet `read_source` took, through the fragmenter
(`split_ipv4` copies it) and the translators (they copy it). No trait change. The consumer drops
packets whose tag names a superseded ownership epoch, and untagged packets where it tags (rule
of the carrier); with release B's barrier it can use either.

### W6, plaintext egress (R5 part 2)

`Output::Plaintext { to, packet }` moves the filtered packet, tag included, to the
`PlaintextEgress` receiver. The opt-in is runtime state of the peer (O8).

### W6, send receipts (R6)

- Token = tag. `TrackedSender::send(packet)` requires a tag and reports `SendResult { tag,
  outcome }`; a separate token parameter would need a second carrier and would collide with an
  R4 tag on the same packet. Consumers pack both into the 64 bits.
- The receipt marker (O13): a tracked packet is told apart from a merely tagged one by a
  documented public marker on `PacketBuf`, separate from the tag:

  ```rust
  impl PacketBuf {
      /// Whether the packet is tracked: the engine reports exactly one `SendResult` for a
      /// tracked packet it accepted through `TrackedSender`. Clones, pooled and recycled
      /// buffers are never tracked.
      pub const fn is_tracked(&self) -> bool;
      /// Marks or unmarks the packet. The engine honours the mark only on packets
      /// `TrackedSender` accepted; it clears it on packets entering any other way.
      pub const fn set_tracked(&mut self, tracked: bool);
  }
  ```

  It takes no bits from the tag, and `tag`, `set_tag`, `take_tag` and `Clone` keep their
  meaning for untracked packets. The setter is public because the marker is set in `nsplane`
  and lives in `nsplane-packet`; a hidden setter would be an undocumented semver surface. The
  engine sets it when `TrackedSender` accepts a packet and clears it on every other entry
  (`read_source`, the inject calls, `PlaintextIngress`), so a mark set elsewhere never produces a
  result. The core reports drops of tracked packets per packet (an `Output` carrying the tag and
  the reason), the engine at the transport call.
- Clones: `Clone` copies the tag and clears the marker, so a clone is never tracked and the
  original keeps the one result. No nsplane path clones a packet (see the carrier), so inside
  nsplane a tracked packet has one buffer from `TrackedSender` to its result; copy sites that
  build a new buffer for the same packet (`layout_for_sealing`, the translators) move the
  marker, and `split_ipv4` never copies it (O10). Tests: a clone of a tracked packet is
  untracked with the same tag; one tracked packet yields exactly one result through every copy
  site.
- `Transport::send_batch` / `try_send_batch` promise that on an error at least the last datagram
  the call was done with failed. A tracked datagram that ends its call is therefore attributed
  exactly: `Ok` means sent, an error with `*sent` past it means failed, `WouldBlock` before it
  means not yet. `TransportSlot` ends `staged` / `Handoff` batches and the transmit task's
  calls after a tracked datagram.

## Open questions

- O8 (R5 part 2) Opt-in per peer through `Core::set_plaintext_egress(peer, bool)` and the engine
  equivalent (recommended: runtime, no `PeerConfig` change, reverts with the call), or a
  `PeerConfig` field. Across peer changes the runtime flag follows the `PeerId`, like
  `Core::set_peer_pad_limit` today: `AddOrUpdatePeer` for a known identity and key updates the
  peer in place and keeps its `PeerId` (`peer_table.rs` `apply`), so the flag stays; a peer
  removed and added again gets a new `PeerId` (ids are never reused) and starts without it, so
  the consumer sets it again. Tests: flag kept across an update, absent after remove and re-add,
  and no packet of the removed peer reaches the egress queue under the new id. Such a peer
  starts no handshake for data. Recommended: it may still answer and start handshakes for
  inbound sealed traffic, unchanged, so a peer moves between plaintext and sealed egress without
  a gap. For the gateway's review.
- O9 (R6) Without a session. `encapsulate_in_place` / `reserve_in_place` copy the packet into
  `Tunn::packet_queue` (`VecDeque<Vec<u8>>`, `MAX_QUEUE_DEPTH` 256, silently not queued beyond,
  cleared by `clear_all` in the timers) and write an initiation into the buffer. Recommended:
  `NotSent { no session }` at once; the tracked path checks `Tunn::has_session` (public, the same
  test `encapsulate_in_place` makes) and on `false` formats an initiation with
  `Tunn::format_handshake_initiation` without queueing the packet, so the handshake starts as for
  an untracked packet and the packet is never sent after its result. This needs no
  `nsplane-noise` change. Consequence for the consumer: a tracked packet right after a session
  expiry fails and the consumer retries once the session is up. The alternative keeps the tag in
  the queue and reports overflow, `clear_all` and the later flush, which changes
  `nsplane-noise`'s queue and `Core::flush_queue`. For the gateway's review.
- O10 (R6) A tracked packet above the MTU: `NotSent { oversize }` (recommended; `split_ipv4`
  copies the tag, so one packet would become several datagrams with one token and the result
  would wait for all of them, through possibly different calls), or one result after the last
  fragment's call (a per-token fragment count in the engine). An IPv6 or DF packet answered with
  an ICMP error is `NotSent` with `FRAGMENT_OVERSIZE` either way. For the gateway's review.
- O11 (C) The tag on `PacketBuf` (recommended: every queue and the filters see it with no new
  item type; untagged traffic pays one word; a consumer's own queue of `PacketBuf`s carries it
  unchanged) or per-queue side fields (`(PacketBuf, Tag)` in the local queue, `CryptoJob`,
  `Datagram`, the netstack ingress: no size change for untagged queues, but every queue, trait
  (`PacketSource::recv_batch`, `PacketSink::send_batch`, `PacketFilter`) and adapter changes,
  consumers carry the label beside every packet through their own queues, and a forgotten site
  loses the tag at compile time only if its type changes). `Output` becomes `#[non_exhaustive]`
  together with `Output::Plaintext`. The node agrees (variant A first).
- O12 (R2) Labels (recommended: they compose with release B's first-input control, attribute
  every handle without timing, separate an identical reinstall by a fresh label, and use the
  same carrier) or a barrier with ingress sequence numbers on handles (completion waits on
  handshakes that may never finish; every handle needs the sequence anyway, and the consumer
  maps sequence ranges to its own lifetimes). The node agrees (labels).
- O13 (R6) How a tracked packet is marked. Recommended: the documented public marker above
  (`is_tracked` / `set_tracked`, honoured only on the engine's `TrackedSender` path, separate
  from the tag, cleared by `Clone`, pools, recycling and the engine's other entries).
  Alternatives: every tagged packet tracked while a `SendResults` receiver exists (costs a
  result per R4-tagged packet), or a field in the engine's queue items (`Datagram` grows, and
  the core cannot see it for its own drops). The node's condition (no tag bits, no change for
  untracked packets) and the planning review's (documented, not hidden) are met. For the
  gateway's review.
- O14 (R2, new) How long nsplane remembers a revoked label. Recommended: a tombstone table per
  stack (`NetStackConfig::max_revoked_labels`, proposed default 65,536 labels, about 1 MiB),
  oldest entry replaced when full, so a label used after its revoke is dropped and counted for at
  least the next 65,536 revocations, far past the time input can sit in a consumer's queue.
  Alternatives: tombstones for the stack's lifetime (exact, grows with every revocation), or none
  (a reused label opens a new lifetime; the consumer contract alone protects). Either way the
  consumer contract stands: labels of revoked lifetimes are never reused, and queued input of a
  label is cancelled before its revoke.

## Consumers' adoption path

Both consumers keep working without setting a tag: untagged packets take today's paths, and the
only source changes are the breaking items below.

The node, from the release C tag (its provider stack is an ordinary stack; labels need no
`Admission` there):

1. Bump; add the `_ =>` arm for `Output` if it drives `Core` directly (the netstack structs are
   already `#[non_exhaustive]` since release B), and `..` in `TranslatorStats` literals if any.
2. Mint an immutable label per listener incarnation, fresh on every install, an identical
   reinstall included. Set it on the sink side of the stack, where the node's own classification
   decides that a packet belongs to the incarnation, before the node's own queue toward
   `NetStackSink`; a non-first fragment takes the label of its datagram's first fragment. Look the
   listener up after accept by `TcpConnection::ingress_label` / `UdpFlow::ingress_label`
   instead of by port.
3. On listener replacement or withdrawal: cancel the incarnation in the node's own queue (its
   ingress loop drops input whose label belongs to a cancelled incarnation before
   `NetStackSink::send`), then call `revoke_label`, await the receipt, and install the new
   incarnation only after `Retired`; on `Failed` keep the listener withdrawn and call again. An
   incarnation whose projection is unchanged keeps its label and is not revoked.
4. Replace the stack-side workarounds the labels cover: the port lookups after accept and the
   port-based "withdrawn before delivery or accept" drops become label checks, and the
   fragment-owner time-to-live stops being an isolation mechanism (it can stay as a memory
   bound). The guards after the hand-out stay with the node: revoking handed-out handles through
   their control and the admission it holds past the stack (its own bridges, reopen paths and
   writes). Labels do not reach past the stack.

The gateway, from the release C tag (pending its review):

1. Bump as above.
2. R4: tag local packets with the ownership epoch in its `PacketSource` and check it in its
   outbound filter, treating untagged packets as not current (optional if release B's barrier
   already suffices).
3. R5 part 2: mark the reference peers with `set_plaintext_egress` (again after a peer is
   removed and re-added), read `PlaintextEgress`; release B's `PlaintextIngress` carries the
   other direction.
4. R6: send its echo replies through `TrackedSender` with a tag that packs its token, retry a
   `NotSent { no session }`, and drop its accounting from `PeerStats::data_tx` deltas and
   `Event::Dropped`.

## Breaking changes and migration

| Change | Who breaks | Migration |
| --- | --- | --- |
| `Output` `#[non_exhaustive]` plus `Output::Plaintext` | code matching `Core::poll_output` exhaustively (the engine, consumers driving `Core` themselves) | add a wildcard arm; handle `Plaintext` only if `set_plaintext_egress` is used |
| `TranslatorStats` `#[non_exhaustive]`, new `fragment_mixed_tags` | struct literals and exhaustive patterns of the translator's counters | `..Default::default()` / `..` |
| `PacketBuf` 56 -> 64 bytes (variant A) | nobody at the source level (fields are private, no literal outside `buf.rs`); stack size of `PacketBatch` (+512 bytes) and of queues | none; `size_of` assumptions in consumer code, if any |
| `Clone` of `PacketBuf` clears the receipt marker | none (the marker is new) | none |
| `PacketSource::recycle` receives untagged, unmarked buffers | none (documented behaviour) | none |
| additive: `PacketBuf::{tag, set_tag, take_tag, is_tracked, set_tracked}`, `Reassembler::{push_tagged, discard_tagged}`, `FragmentTags`, netstack labels (`revoke_label`, `ingress_label`, `NetStackConfig::max_revoked_labels`), `NetStackStats::{label_mismatch, label_revoked}` (both structs are `#[non_exhaustive]` since release B), `TrackedSender`, `PlaintextEgress` | none | |

`Input` and `Event` stay as they are (exhaustive); the receipt output is a new `Output` variant
behind the same `#[non_exhaustive]`. The changelog lists the breaking items under their own
heading; the reference pages (`nsplane-packet.md`, `nsplane-netstack.md`, `nsplane.md`,
`nsplane-core.md`, `nsplane-nat.md`) and `docs/architecture.md` (contracts: the tag) are updated.

## Tests

- Tag unit tests in `nsplane-packet`: new buffers untagged; `Clone` copies the tag and clears the
  marker; both pools return untagged, unmarked buffers; `PacketBatch` preserves; `push_tagged`
  same, mixed (tag and `None` included), untagged, expiry, `discard_tagged`.
- `nsplane-core`: the tag at a recording outbound filter, on the `Output::Transmit` datagram
  (inline and with crypto jobs), after the shared-slice copy in `layout_for_sealing`; the
  no-session initiation is untagged and unmarked; `inject_*` and `receive_plaintext` preserve;
  an inbound filter's tag reaches `Output::Deliver`; plaintext-egress flag kept across an
  update, absent after remove and re-add.
- `nsplane`: the tag through `ChannelSource` and `PipeSource` to the outbound filter and the
  transport; a marked packet from a source or an inject call is untracked; every `split_ipv4`
  fragment; recycled buffers reach `PacketSource::recycle` untagged and unmarked (engine and
  `pump`).
- `nsplane-nat`: `make_room`, `to_ipv6`, translator reassembly (same tags pass, mixed dropped and
  counted).
- W5, on an ordinary stack and on a transparent one with `Immediate` and `Decide`: the node's two
  reproduced cases as netstack tests with labels (a partial datagram completed after a listener
  replacement, with the middle fragment carrying the old and the new label; queued complete
  input, new resource and identical reinstall); mixed-label fragments; a labeled SYN, its
  retransmission with another label, and the handshake ACK; established segments with another
  label and with `None`; unlabeled and differently labeled ICMP errors for a labeled connection;
  each stage of `revoke_label`, handles already handed out included; `Failed` with a full table,
  then a second call reporting `Retired`; a label used after its revoke dropped and counted, not
  opening a lifetime; the same tuple after `Retired` opening a fresh lifetime with a new label,
  for UDP and for TCP.
- W6: exactly one result per tracked packet under every drop site (no route, filter drop,
  handled, no session, oversize, transmit full, transport closed, peer removed, send error,
  engine stopped) and through every copy site, a clone of a tracked packet untracked, a
  transport failure in the middle of a batch, stop with results outstanding; plaintext egress
  full, closed, peer removed and re-added.
- Benchmarks as in the budget: variant A and B, untagged against `main`, labeled against
  unlabeled.

## Risks

- A copy site that forgets the tag loses attribution silently. The inventory above is the
  checklist and each site has a test; a new copy site in a later change has to add one.
- The no-session initiation and the recycle hand-offs are the two places where a stale tag would
  leak onto an unrelated buffer; both clear explicitly and are tested.
- The per-segment label lookup on labeled stacks is new cost on the TCP ingress path; it has its
  own bar and a fallback design to measure, and stays off for unlabeled stacks.
- Pending SYN labels on an ordinary stack are a new table; it is bounded by the SYNs a poll
  takes and emptied at every poll.
- The receipt marker is a second property on `PacketBuf`; it is documented, and the engine
  honours it only on its own tracked path.

## Open items for review

- Owner: O8-O14, the variant A / B decision rule (A unless it is outside the noise), the
  labeled-path allowance (proposed 3 %), and the twelfth freeze exception.
- The gateway: O8-O10 and O13; token = tag with packing; whether release B's barrier makes R4
  proposal A unnecessary; whether it needs `recv_labeled` on bound sockets (dropped from release
  C unless it asks: it costs a word per queued bound datagram and the node does not need it).

## Review record

- Node-side consumer review (of `42ef4fe`): agreed with O11 (variant A first) and O12 (labels);
  asked for labels on ordinary stacks without `Admission`, a defined outcome for a label used
  after its revoke, a fresh lifetime on the same tuple after `Retired`, `None` as its own label
  with unlabeled ICMP errors accepted, the meaning of `Failed` and whether to retry, an explicit
  statement that handed-out lifetimes are retired, a labeled-path acceptance bar with a
  per-socket fallback, a documented receipt marker that takes no tag bits, and an adoption path
  that sets the label on the sink side after the node's classification, cancels the node's own
  queue before the revoke, and keeps the node's guards after the hand-out; `recv_labeled` is not
  needed by the node. Its statements about nsplane's code were checked at `52eb983` and hold.
- Planning review (of `42ef4fe`): asked for the rule for clones of tracked packets, the
  untagged-after-merge rule in nsplane-nat, a documented instead of a hidden receipt marker, the
  labeled-path bar, the consumer's retry under O9, the plaintext-egress flag across peer removal
  and re-add, and explicit owner answers.
- Gateway review: pending.
- Changes in this revision: the carrier's `None` rule and the clone statement (checked by
  building without `Clone`); the receipt marker made a documented public property with a clone
  rule and cleared at the engine's other entries; `Mixed` dropped and counted in nsplane-nat too
  (`TranslatorStats` becomes `#[non_exhaustive]`, added to the breaking changes); W5 rewritten
  for every stack (pending SYN labels before `inject`, the flow-entry label), with ICMP,
  `revoke_label` scope, outcomes and retries, labels used after a revoke (new O14) and the same
  tuple after `Retired`; a labeled-path bar and the per-socket fallback; `recv_labeled` dropped
  pending the gateway; O8's flag across peer changes; the node's adoption path rewritten; tests
  extended for each.
