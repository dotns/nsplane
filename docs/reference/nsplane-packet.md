# nsplane-packet

Packet buffers, IP header views, checksums, a keyed hasher and the value types every other
crate shares (`PeerId`, `TransportId`, `Path`, `Ecn`). No I/O.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `PacketBuf` (headroom, `advance` / `reserve_front`, `from_shared`, fallible bounds), `PacketPool`, `SharedPacketPool` (`new`, `alloc`, `alloc_from`, `recycle`, `free_len`, `allocated`), `PacketBatch`, `IpPacket`, `reassembly::Reassembler` (`push`, `expire`, `stats`, `pending`), `build::udp_packet` / `build::write_udp`, `icmp::echo_reply_in_place`, `icmp::is_echo_request` | `reassembly::{ReassemblyConfig, ReassemblyStats, Outcome}`; `Path`, `TransportId`, `PeerId`, `Ecn`; header views `Ipv4Header`, `Ipv6Header`, `TcpHeader`, `UdpHeader`, `IcmpHeader`, `Fragment`, `FiveTuple`; `checksum` (`sum_words`, `fold`), `hash::KeyedState` / `hash::KeyedHasher`, `protocol`; `vnet::VirtioNetHdr` (`parse`, `encode`), `vnet::segment`, `vnet::OffloadError`; errors `Malformed`, `BoundsError`, `UdpBuildError`; `HEADROOM`, `MAX_BATCH` |

## Behavior

### Buffers

`PacketBuf` holds one IP packet with `HEADROOM` bytes in front (room for the WireGuard
header, so sealing never moves the payload) and `TAILROOM` behind it (padding and the AEAD
tag). `advance` / `reserve_front` move the start, every bounds change is fallible
(`BoundsError`), and `from_shared` adopts a buffer of a pool. `PacketPool` is a plain free
list; `PacketBatch` carries up to `MAX_BATCH` packets between the engine's tasks.

### Shared pool

`nsplane-packet::pool::SharedPacketPool` (re-exported at the crate root and by `nsplane`) is a
bounded free list of packet buffers shared by producers and a source, for the local side's
pooled allocation: `new(max_free)`; `alloc(len) -> PacketBuf` returns `len` bytes
behind `HEADROOM` with `capacity() >= len + TAILROOM`, bytes unspecified (a reused buffer
that is too small grows; a fresh one is zero-filled to `len`); `alloc_from(&[u8]) ->
PacketBuf` copies a packet without zero-filling first; `recycle(&mut Vec<PacketBuf>)` takes
buffers until `max_free` are idle and leaves the rest; `free_len()`; `allocated() -> u64`
counts the fresh allocations. It is a `Mutex<PacketPool>` that is only ever `try_lock`ed plus
an `AtomicBool` hint, so `alloc` skips the lock while the list is empty: lossy (a busy or full
list takes nothing, a busy or empty one makes `alloc` allocate), never waits, callable from
any thread; clones share the list. No `unsafe`.

### Header views

`IpPacket::parse` validates the IPv4 or IPv6 header and gives the addresses, protocol and
payload without copying; `Ipv4Header`, `Ipv6Header`, `TcpHeader`, `UdpHeader`,
`IcmpHeader` and `Fragment` are typed views, `FiveTuple` the flow key. A packet that does not
parse is `Malformed`.

### Reassembly

`reassembly::Reassembler` takes whole IP packets and the caller's clock. Packets that are
not fragments pass through untouched; fragments are held until their datagram is complete,
which then comes back as one valid IP packet. State is bounded in datagrams and bytes
(`ReassemblyConfig`), expires after a timeout (`expire`), and costs nothing until the first
fragment arrives. Datagrams are keyed by (source, destination, protocol, identification) for
IPv4 and (source, destination, identification) for IPv6; fragments may arrive in any order,
an identical retransmitted fragment is ignored, and fragments that overlap with different
coverage drop the whole datagram (RFC 5722, for both families). `stats` and `pending` report
the state.

### UDP builder

`nsplane-packet::build` writes whole IPv4 or IPv6 UDP datagrams for packets an application
injects into the tunnel: `write_udp(buf, src, dst, payload)` into an existing `PacketBuf`
(headroom kept) and `udp_packet(src, dst, payload)` into a fresh one, both re-exported at the
crate root. Checksums are always computed (a zero UDP checksum goes out as `0xFFFF`); IPv4
gets IHL 5, DF and TTL 64, IPv6 hop limit 64 and no extension headers; the family follows
the socket addresses (an IPv4-mapped address in a `SocketAddr::V6` builds IPv6). Mixed
families and payloads beyond the length fields are a `UdpBuildError` and leave the buffer
unchanged. Nothing calls it unless the application does.

### ICMP Echo

`icmp::is_echo_request` tells whether a packet is an ICMP or ICMPv6 Echo request without
touching it; `icmp::echo_reply_in_place` turns such a request into its Echo reply in the same
buffer (addresses swapped, type changed, checksum updated), for a local side that answers
pings for an address it owns.

### Checksums

`nsplane-packet::checksum::sum_words(acc: u64, data: &[u8]) -> u64` adds `data` as
big-endian 16-bit words without folding (an odd trailing byte is padded with a zero low byte;
only the last slice of a chain may be odd); the result is congruent modulo `0xFFFF` to the
16-bit sum and each call adds less than 2^18, so a chained `u64` does not overflow.
`checksum::fold(acc: u64) -> u16` (`const`) folds it, not complemented. The bulk is summed as
native-order 32-bit words (RFC 1071 section 2); `internet_checksum`, the IPv4 header and
transport checksums and `nsplane-nat`'s `checksum::sum` all use this one implementation.

### Virtio-net segmentation

`nsplane-packet::vnet` is the pure codec for the virtio-net header that a Linux TUN or TAP
device with `IFF_VNET_HDR`, or a packet socket with `PACKET_VNET_HDR`, puts in front of
every packet. `VirtioNetHdr` is the legacy 10-byte `struct virtio_net_hdr` (16-bit fields in
host byte order; `parse` and `encode`; `LEN`, `F_NEEDS_CSUM`, `GSO_NONE`, `GSO_TCPV4`,
`GSO_TCPV6`, `GSO_UDP_L4`, `GSO_ECN`).

`segment(hdr, packet, first, capacity, pool, out)` splits one IP packet read behind `hdr`:

- `GSO_NONE` yields the packet itself, its partial checksum completed when `F_NEEDS_CSUM`
  is set (a UDP checksum of 0 written as `0xFFFF`).
- A TCP over IPv4 or IPv6 or a UDP super-packet yields one packet per `gso_size` payload
  bytes (the last may be shorter), each with its own IP length, IPv4 identification (+1 per
  segment) and header checksum, UDP length, TCP sequence number and flags (FIN and PSH only
  on the last segment, CWR only on the first) and a complete transport checksum. The header
  length comes from the packet (IP header plus TCP data offset or UDP header), not from
  `hdr_len` or `csum_start`.
- Packets come from `pool` behind `HEADROOM`, with a capacity of at least `capacity` (or the
  length plus `TAILROOM`), and are appended to `out` from segment index `first` on. When
  `out` fills up (`MAX_BATCH`), the call returns `Ok(Some(next))` and the caller continues
  with `first = next`; `Ok(None)` means done.
- A malformed input produces nothing and returns an `OffloadError` (`#[non_exhaustive]`):
  `Truncated`, `UnsupportedGso` (UFO, ECN on UDP or on `GSO_NONE`, unknown types),
  `ZeroGsoSize`, `BadHeaders` (version or protocol not matching the GSO type, bad IHL or
  data offset, IPv6 extension headers, a fragment), `BadChecksumOffset`, `TooLong` (a
  segment above 65 535 bytes).

`nsplane-tun` splits its offload reads with it and `nsplane-ether`'s packet socket its GSO
frames.

### Keyed hasher

`nsplane-packet::hash::KeyedState` is a `BuildHasher` (`Default` draws two fresh random keys
from std's `RandomState`; a clone keeps them; `Debug` does not show them) building
`hash::KeyedHasher`s: one 64x64->128-bit multiply-fold per word, fast paths for `u8` to
`u128`, a length-tagged generic `write`. The secret per-instance keys resist hash flooding
for maps whose contents are not chosen by the party that drives the lookups; it is not a
cryptographic hash. `nsplane-nat`'s `TranslationTable` IPv6 indexes (`u128` keys) and
`nsplane-acl`'s flow gate use it.

## Configuration and defaults

| Feature | How to enable | Default | Cost when not enabled |
|---|---|---|---|
| ICMP Echo reply synthesis | call `icmp::echo_reply_in_place` on a request for an address the local side answers | not used | none: a plain function, only called if the embedder wires it |
| UDP datagram builder | `build::udp_packet` / `build::write_udp` for packets to inject | not used | none: plain functions, only called if the embedder wires them |
| Virtio-net segmentation | `vnet::segment` on packets read behind a virtio-net header | not used | none: a plain function |

## See also

- [nsplane](nsplane.md): the engine that moves these buffers.
