# Release C: one carrier, the packet tag

Design note, no code. Status: for owner and consumer review. Plan:
[20261026-0822-node-gateway-requests](../20261026-0822-node-gateway-requests.md) (W4-W6,
release C, open questions O8-O12); task:
[20261026-0819-node-gateway-requests](../../task/20261026-0819-node-gateway-requests.md) (R2,
R4 proposal A, R5 part 2, R6).
All code references are at `main` `52eb983` (v0.19.2).

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
- nsplane preserves the tag wherever it moves a packet into another buffer (carrier sites below)
  and clears it where a buffer stops being that packet (a handshake initiation written into it,
  a buffer handed back to a source for reuse).
- Transports and sinks never see it on the wire: they write `as_packet()` bytes only.
- The value space belongs to the consumer. One packet has one tag; a consumer that needs two
  meanings on the same packet (an ownership epoch for R4 and a receipt token for R6, say) packs
  both into the 64 bits.

### Layout

`PacketBuf` today (`crates/nsplane-packet/src/buf.rs`): `buf: BytesMut` (32 bytes), `start:
usize`, `end: usize` (16), `shared: bool` (1), padded to 56 bytes on 64-bit targets. With
`tag: Option<NonZeroU64>` (8, the niche keeps `None` free):

| Variant | Fields | Size | Notes |
| --- | --- | --- | --- |
| A | as today plus `tag` | 64 | no other change |
| B | `start`, `end` as `u32`, plus `tag` | 56 | `len`, `headroom`, `capacity`, `set_len`, `advance`, `reserve_front` convert; `set_len` / `extend_from_slice` need a bound past `u32::MAX` that cannot panic |

Every `PacketBuf` moves by value through bounded queues and `PacketBatch`, whose inline
`SmallVec<[PacketBuf; MAX_BATCH]>` grows from 3584 to 4096 bytes under A. Recommendation:
implement A, measure it against B on the slot A/B (budget below), and take B only if A is
outside the noise. B's conversions sit on the hottest accessors, so it is not free either.

## Carrier sites

"Move" means the `PacketBuf` itself travels: the tag survives with no code. "Copy" means a new
buffer is filled from the old one: the site must copy the tag. Every site gets a test.

### nsplane-packet

| Site | Kind | Rule | Test |
| --- | --- | --- | --- |
| `PacketPool::get` / `get_len` / `put` | rebuild from `BytesMut` | untagged | a tagged buffer put and got again has no tag |
| `SharedPacketPool::alloc` / `alloc_from` / `recycle` | via `PacketPool` | untagged | same, through `recycle` |
| `PacketBatch::push` / `drain` / `IntoIterator` | move | preserve | tag round trip through a batch |
| `reassembly::Reassembler::push` | copy (`Outcome::Complete(Vec<u8>)`) | merge: the datagram carries a tag only if every fragment carried the same one; a set with different tags is reported | new tagged entry, below |

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
`None`. `ReassemblyStats` is `#[non_exhaustive]`, so a `mixed_tags` counter is additive.

### nsplane-core

| Site | Kind | Rule | Test |
| --- | --- | --- | --- |
| `Core::handle_locals`, `handle_locals_deferred`, `Input::Local` | move | preserve | |
| `Core::prepare_send` filter loop (`PacketFilter::outbound(id, &mut packet)`) | move | preserve; a filter may read or set the tag | recording filter sees the tag (R4 A) |
| `Core::layout_for_sealing`, the copy when `reserve_front` fails (shared slices) | copy | copy the tag | tagged `from_shared` packet keeps its tag after layout |
| `job::seal` / `CryptoJob::seal` / `Core::complete_job` | move (`CryptoJob::buf`) | preserve | tag on the `Output::Transmit` datagram, with crypto jobs |
| `sealed` -> `transmit` -> `Output::Transmit { data }` | move | preserve for `MessageKind::Data`; **clear** otherwise | see below |
| `Tunn::encapsulate_in_place` / `reserve_in_place` without a session | the packet's bytes are copied into the tunnel queue (`queue_packet`, `Vec<u8>`) and a handshake initiation is written into the same buffer | the initiation must not carry the packet's tag: `sealed` clears it when the kind is not data | no-session send: the initiation datagram is untagged |
| `Core::flush_queue` | new buffer (`pool.get_len`) | untagged (the queue keeps no tag, O9) | |
| `Core::opened` / `deliver_opened` -> `Output::Deliver` | move, opened in place | wire packets are untagged; an inbound filter may set a tag, which reaches the sink | inbound filter sets a tag, sink sees it |
| `Core::receive_plaintext` (release B), `Core::inject_inbound`, `inject_outbound`, `inject_outbound_on` | move | preserve | one per entry |
| handshake, cookie and response buffers (`pool.get_len` in `handle_*`) | new | untagged | |

### nsplane (engine)

| Site | Kind | Rule | Test |
| --- | --- | --- | --- |
| `read_source`: `PacketSource::recv_batch` -> `PacketBatch` -> `BatchSender` local queue | move | preserve | tag at the outbound filter through a `ChannelSource` |
| `Owner::input_locals` -> `local_batch` -> `handle_locals(_deferred)` | move | preserve | |
| `fragment.rs` `Fragmenter::process`: `Action::Send` | move | preserve | |
| `split_ipv4` (`Action::Fragments`) | copy, one new buffer per fragment | copy the tag to every fragment | each fragment carries the tag |
| `packet_too_big`, `fragmentation_needed` (`Action::Reply`) | new, delivered inbound | untagged | |
| `Output::Transmit` -> `TransportSlot` (`staged`, `pending`, `Handoff`, `send_now`, transmit task) | move (`Datagram = (Path, PacketBuf)`) | preserve up to the transport call | tag visible at `send_now` (R6) |
| `Output::Deliver` -> `write_sink` / inline delivery -> `PacketSink::send_batch` | move | preserve | tag reaches `NetStackSink` |
| `read_source` recycle: `recycled` -> `PacketSource::recycle(&mut bufs)` | move of whole `PacketBuf`s to the source | **clear** before the call | a source reusing a recycled buffer gets no tag |
| `pump`: `PacketSink::send_batch_spent` `spent` -> `PacketSource::recycle` | move | **clear** before the call | same, through `pump` |
| `PipeSink` / `PipeSource`, `ChannelSink` / `ChannelSource`, `MapSource`, `MergeSource`, `Splitter` | move (mpsc of `PacketBuf`) | preserve; a map closure that builds a new buffer owns its tag | pipe and channel round trip |

The recycle hand-offs matter because `PacketSource::recycle` takes `PacketBuf`s, not storage:
`MergeSource::recycle` keeps them as they are, and a consumer's source may reuse one with
`set_len` instead of a pool. Clearing costs one store per recycled buffer, off the packet path.
`PacketSource::recycle`'s docs then state that the buffers arrive untagged.

### nsplane-nat (filters in the outbound and inbound chains)

The plan's list missed these; a filter installed after them reads the tag (R4 A), and a tracked
packet keeps its token through them (R6).

| Site | Kind | Rule |
| --- | --- | --- |
| `translate/rfc7915.rs` `make_room` (`*packet = grown`) | copy | copy the tag |
| `nat64_lan/packet.rs` `to_ipv6` (`*packet = PacketBuf::from_packet(..)`) | copy | copy the tag |
| `translate/fragment.rs` reassembly (via `Reassembler`) | the completing fragment's buffer becomes the datagram | merge rule via `push_tagged`; `Mixed` leaves the datagram untagged |

### nsplane-netstack (R2)

| Site | Kind | Rule |
| --- | --- | --- |
| `NetStackSink::send` -> `mpsc::Sender<PacketBuf>` -> `ingest_batch` (`poll_recv_many`, `batch`, `carried`) | move | preserve |
| `Driver::reassemble` (`Outcome::Complete` -> `PacketBuf::from_packet`) | copy | `push_tagged`; `Mixed` is discarded and counted (`label_mismatch`) |
| `classify` | borrow | |
| `admit_syn` -> `Pending` (`Decision::Tcp(PacketBuf)`) | move | the held SYN keeps its label |
| `device.inject` -> `VirtualDevice::rx_queue` -> smoltcp | move, then consumed | the label is checked **before** `inject`; smoltcp never sees it |
| `udp::parse_udp` / `parse_udp_whole` (`packet.freeze()`) | the `PacketBuf` ends | the crate-private `udp::Datagram` gains the tag; `hold_udp` keeps it with the held datagram |
| `dispatch_udp` -> connected / bound socket queues (`mpsc` of `(SocketAddr, Bytes)`) | new queue item | the item gains the tag for `UdpSocket::recv_labeled` (one word per queued datagram, only those queues) |
| `dispatch_flow` -> flow queue (`mpsc` of `Bytes`) | | no tag: a flow's label is fixed, mismatches are dropped before the queue |
| `icmp` (`pmtu::parse`, `reduce_mss`) | borrow | an ICMP error with another label than the connection it quotes is ignored and counted |
| egress (`VirtualDevice` tx tokens from the device pool, `UdpReply`, rejections from `pending.rs`) | new | untagged; labeling egress is not requested and not proposed |

## Per-packet budget

What an untagged packet pays: 8 more bytes per `PacketBuf` (variant A) in every queue and
batch it sits in; one word copied at the copy sites above (`layout_for_sealing`'s slow path,
`split_ipv4`, the translator's slow paths, netstack reassembly); one store per recycled buffer;
one compare in `sealed` (data vs. other kinds, already computed). The netstack's label checks run
only while the stack holds a labeled lifetime (a counter), so an unlabeled stack keeps today's
path; receipts cost only for tracked packets.

Acceptance bar: within the slot A/B noise against `main` on

- `nsplane-core` `data_path`: `core_round_trip/64` (417 ns at 0.19.2) and
  `core_round_trip_batch32`;
- `nsplane-netstack` `send_stream`: `netstack_send/*`, `netstack_udp_send/*` including `flows_4`
  (the case that showed +4.1 % when flow state was added);
- `nsplane` `local_graph` (`pipe/send_recv_*`, `pipe/alloc_send_recv_*`) and `udp_offload`
  (`udp_loopback/batch_64x*`);
- `nsplane-packet` `vnet` and `nsplane-nat` `translate` for the copy sites.

Variant A and B are both measured; `docs/performance.md` records the result.

## How the workstreams use it

W5, netstack ingress labels (R2): the tag of a packet sent into `NetStackSink` is its ingress
label. The consumer sets it on its side of the sink, or in an inbound `PacketFilter`, which gets
`&mut PacketBuf` at the decision point; the tag then moves through `write_sink` into the stack.
The plan's rules hold (a lifetime takes its first input's label; mismatched input is dropped and
counted; `NetStackHandle::revoke_label(label) -> RetirementReceipt` retires every stage and
fences the ingress queue). Refinements from the code:

- Under `Admission::Immediate` there is no `FlowState` before adoption (O3 keeps release B's
  first-input state to `Decide`). The label of a labeled SYN is recorded where
  `Driver::track_inbound` already records the tuple and egress mark of a `SynReceived` socket
  (`Driver::inbound`), and moves to the `FlowState` in `Driver::adopt`.
- An established TCP segment goes to `device.inject` without a tuple lookup today. A labeled
  stack checks it against its lifetime's label (one hash lookup per segment while any labeled
  lifetime exists); this is the main cost of W5 and is measured with labels on.
- `revoke_label` also calls `Reassembler::discard_tagged`.
- Release B makes `NetStackStats` (with `NetStackConfig`, `TransparentConfig`,
  `FlowEventsConfig` and `PendingProtocol`) `#[non_exhaustive]`, so the `label_mismatch` counter
  is additive in release C.

R4 proposal A: `PacketFilter::outbound` sees the tag of the packet `read_source` took, through
the fragmenter (`split_ipv4` copies it) and the translators (they copy it). No trait change. The
consumer drops packets whose tag names a superseded ownership epoch; with release B's barrier
it can use either.

W6, plaintext egress (R5 part 2): `Output::Plaintext { to, packet }` moves the filtered packet,
tag included, to the `PlaintextEgress` receiver.

W6, send receipts (R6). Refinements:

- Token = tag. `TrackedSender::send(packet)` requires a tag and reports `SendResult { tag,
  outcome }`; a separate token parameter would need a second carrier and would collide with an
  R4 tag on the same packet. Consumers pack both into the 64 bits.
- A tracked packet must be told apart from a tagged one (R4 and R2 tags need no results). The
  tag cannot say so without reserving values. Proposed: a `receipt` bit in `PacketBuf`'s
  existing padding (no size change), set only by `TrackedSender` and hidden from the public
  docs; the core then reports drops of such packets per packet (an `Output` carrying the tag and
  the reason), the engine at the transport call. See O13.
- `Transport::send_batch` / `try_send_batch` promise that on an error at least the last datagram
  the call was done with failed. A tracked datagram that ends its call is therefore attributed
  exactly: `Ok` means sent, an error with `*sent` past it means failed, `WouldBlock` before it
  means not yet. `TransportSlot` ends `staged` / `Handoff` batches and the transmit task's
  calls after a tracked datagram.

## Open questions

- O8 (R5 part 2) Opt-in per peer through `Core::set_plaintext_egress(peer, bool)` and the engine
  equivalent (recommended: runtime, no `PeerConfig` change, reverts with the call), or a
  `PeerConfig` field (survives reconfiguration, but `PeerConfig` changes are applied by
  replacement). Such a peer starts no handshake for data. Recommended: it may still answer and
  start handshakes for inbound sealed traffic, unchanged, so a peer moves between plaintext and
  sealed egress without a gap.
- O9 (R6) Without a session. `encapsulate_in_place` / `reserve_in_place` copy the packet into
  `Tunn::packet_queue` (`VecDeque<Vec<u8>>`, `MAX_QUEUE_DEPTH` 256, silently not queued beyond,
  cleared by `clear_all` in the timers) and write an initiation into the buffer. Recommended:
  `NotSent { no session }` at once; the tracked path checks `Tunn::has_session` (public, the same
  test `encapsulate_in_place` makes) and on `false` formats an initiation with
  `Tunn::format_handshake_initiation` without queueing the packet, so the handshake starts as for
  an untracked packet and the packet is never sent after its result. This needs no
  `nsplane-noise` change. The alternative keeps the tag in the queue and reports overflow,
  `clear_all` and the later flush, which changes `nsplane-noise`'s queue and `Core::flush_queue`.
- O10 (R6) A tracked packet above the MTU: `NotSent { oversize }` (recommended; `split_ipv4`
  copies the tag, so one packet would become several datagrams with one token and the result
  would wait for all of them, through possibly different calls), or one result after the last
  fragment's call (a per-token fragment count in the engine). An IPv6 or DF packet answered with
  an ICMP error is `NotSent` with `FRAGMENT_OVERSIZE` either way.
- O11 (C) The tag on `PacketBuf` (recommended: every queue and the filters see it with no new
  item type; untagged traffic pays one word) or per-queue side fields (`(PacketBuf, Tag)` in the
  local queue, `CryptoJob`, `Datagram`, the netstack ingress: no size change for untagged
  queues, but every queue, trait (`PacketSource::recv_batch`, `PacketSink::send_batch`,
  `PacketFilter`) and adapter changes, and a forgotten site loses the tag at compile time only if
  its type changes). `Output` becomes `#[non_exhaustive]` together with `Output::Plaintext`.
- O12 (R2) Labels (recommended: they compose with release B's first-input control, attribute
  every handle without timing, and use the same carrier) or a barrier with ingress sequence
  numbers on handles (completion waits on handshakes that may never finish; every handle needs
  the sequence anyway).
- O13 (R6, new) How a tracked packet is marked: the hidden `receipt` bit in the padding
  (recommended), every tagged packet tracked while a `SendResults` receiver exists (costs a
  result per R4-tagged packet), or a field in the engine's queue items (`Datagram` grows).

## Consumers' adoption path

Both consumers keep working without setting a tag: untagged packets take today's paths, and the
only source changes are the breaking items below.

The node, from the release C tag:

1. Bump; add the `_ =>` arm for `Output` if it drives `Core` directly (the netstack structs
   are already `#[non_exhaustive]` since release B).
2. Set the tag to the listener incarnation's label where it admits input for the shared stack
   (its inbound filter or the sink in front of `NetStackSink`), and read
   `TcpConnection::ingress_label` / `UdpFlow::ingress_label` / `recv_labeled`.
3. On listener replacement or withdrawal: stop sending the old label, call `revoke_label`,
   await the receipt (`Retired`), then install the new incarnation.
4. Drop its own replacement workarounds for partial datagrams and queued input.

The gateway, from the release C tag:

1. Bump as above.
2. R4: tag local packets with the ownership epoch in its `PacketSource` and check it in its
   outbound filter (optional if release B's barrier already suffices).
3. R5 part 2: mark the reference peers with `set_plaintext_egress`, read `PlaintextEgress`;
   release B's `PlaintextIngress` carries the other direction.
4. R6: send its echo replies through `TrackedSender` with a tag that packs its token, and drop
   its accounting from `PeerStats::data_tx` deltas and `Event::Dropped`.

## Breaking changes and migration

| Change | Who breaks | Migration |
| --- | --- | --- |
| `Output` `#[non_exhaustive]` plus `Output::Plaintext` | code matching `Core::poll_output` exhaustively (the engine, consumers driving `Core` themselves) | add a wildcard arm; handle `Plaintext` only if `set_plaintext_egress` is used |
| `PacketBuf` 56 -> 64 bytes (variant A) | nobody at the source level (fields are private, no literal outside `buf.rs`); stack size of `PacketBatch` (+512 bytes) and of queues | none; `size_of` assumptions in consumer code, if any |
| `PacketSource::recycle` receives untagged buffers | none (documented behaviour) | none |
| additive: `PacketBuf::{tag, set_tag, take_tag}`, `Reassembler::{push_tagged, discard_tagged}`, `FragmentTags`, netstack labels, `NetStackStats::label_mismatch` (the struct is `#[non_exhaustive]` since release B), `TrackedSender`, `PlaintextEgress` | none | |

`Input` and `Event` stay as they are (exhaustive); the receipt output is a new `Output` variant
behind the same `#[non_exhaustive]`. The changelog lists the breaking items under their own
heading; the reference pages (`nsplane-packet.md`, `nsplane-netstack.md`, `nsplane.md`,
`nsplane-core.md`, `nsplane-nat.md`) and `docs/architecture.md` (contracts: the tag) are updated.

## Tests

- Tag unit tests in `nsplane-packet`: new buffers untagged; `Clone` copies; both pools return
  untagged buffers; `PacketBatch` preserves; `push_tagged` same, mixed, untagged, expiry,
  `discard_tagged`.
- `nsplane-core`: the tag at a recording outbound filter, on the `Output::Transmit` datagram
  (inline and with crypto jobs), after the shared-slice copy in `layout_for_sealing`; the
  no-session initiation is untagged; `inject_*` and `receive_plaintext` preserve; an inbound
  filter's tag reaches `Output::Deliver`.
- `nsplane`: the tag through `ChannelSource` and `PipeSource` to the outbound filter and the
  transport; every `split_ipv4` fragment; recycled buffers reach `PacketSource::recycle` untagged
  (engine and `pump`).
- `nsplane-nat`: `make_room`, `to_ipv6`, translator reassembly (same and mixed).
- W5: the node's two reproduced cases as netstack tests with labels (a partial datagram
  completed after a listener replacement; queued complete input), mixed-label fragments, labeled
  SYN under `Immediate` and `Decide`, each stage of `revoke_label`, `recv_labeled`.
- W6: exactly one result per tracked packet under every drop site (no route, filter drop,
  handled, no session, oversize, transmit full, transport closed, peer removed, send error,
  engine stopped), a transport failure in the middle of a batch, stop with results outstanding;
  plaintext egress full, closed, peer removed and re-added.
- Benchmarks as in the budget, variant A and B.

## Risks

- A copy site that forgets the tag loses attribution silently. The inventory above is the
  checklist and each site has a test; a new copy site in a later change has to add one.
- The no-session initiation and the recycle hand-offs are the two places where a stale tag would
  leak onto an unrelated buffer; both clear explicitly and are tested.
- The per-segment label lookup on labeled stacks is new cost on the TCP ingress path; it is
  measured separately and stays off for unlabeled stacks.
- The hidden `receipt` bit (O13) is a second meaning in `PacketBuf`; if the owner prefers no
  hidden API, the queue-field alternative costs one word per datagram.

## Open items for review

- Owner: O8-O13, the variant A / B decision rule, and the twelfth freeze exception.
- The node: labels set in an inbound filter or in front of the sink; whether `recv_labeled` on
  bound sockets is needed or labeled lifetimes suffice.
- The gateway: token = tag with packing; `NotSent` for no session and oversize; whether release
  B's barrier makes R4 proposal A unnecessary.
