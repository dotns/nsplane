# nsplane-nat

Address translation and NAT for the engine: the RFC 7915 translator (`Translator`), service
publishing by DNAT/SNAT (`PortMap`, `Conntrack`), stateful NAT64 to an IPv4 LAN (`Nat64Lan`),
and two local-side building blocks (`Redirect`, `Masquerade`). Builds on `nsplane-core`,
`nsplane-packet` and, for the local-side wrappers, `nsplane`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `Translator` (`new`, `store`, `set_mtu`, `ipv4_translated_predicate`, `stats`), `TranslationTableBuilder` (`peer_with_peer6_eam4`, `nested_lans`) / `TranslationTable` (`peer6_eam4`, `by_peer6_eam4`, `nested_lans`), `PortMap` (`new`, `with_conntrack`, `set_rules`), `Conntrack` (`peek`, `remove`, `with_removal_hook`), `Nat64Lan` (`new`, `with_snat_ports`, `forward`, `reverse`, `remove_flow`, `stats`), `Nat64LanSink` / `Nat64LanSource`; trait `SnatPorts` | `PeerMapping`, `SelfMapping`, `LanPrefix`, `TableError`, `TranslatorStats`, `PortMapRule`, `PortMapProtocol`, `PortMapError`, `ConntrackConfig`, `ConntrackStats`, `ConntrackError`, `Flow`, `FlowMatch`, `FlowDirection`, `TcpState`, `LanRoute`, `LanRoutes`, `Nat64LanConfig` (`nested_routes`), `Nat64LanStats`, `Nat64LanError`, `Nat64Verdict`, `DefaultSnatPorts`, `nat64_lan::reasons`, `checksum` |
| local side | `Redirect` (`new`, `with_conntrack`, `forward`, `reverse`, `original_destination`, `with_endpoint_tries`, `endpoint_in_use`, `remove_flow`, `retain`, `stats`) | `RedirectDecision`, `RedirectVerdict`, `RedirectStats`, `redirect::reasons` |
| local side | `Masquerade` (`new`, `with_clock`, `forward`, `reverse`, `len`, `is_empty`, `stats`, `config`) | `MasqueradeDecision`, `MasqueradeConfig` (`recheck_route_on_forward`), `MasqueradeVerdict`, `MasqueradeStats`, `masquerade::reasons` |

## Behavior

The filters rewrite packets in place and do no I/O.

### Address model

The translator's addresses are explicit address mappings (EAM, RFC 7757).
Every peer has its own IPv6 address on the tunnel, `peer6`, and an EAM `eam4 <-> eam6`: a
local IPv4 address translated to and from the IPv6 side of the mapping. Optionally it also has
a second EAM `peer6_eam4 <-> peer6` (a local IPv4 address translated to and from `peer6`) and
a local IPv6 rewrite `local6 <-> peer6` (rewritten, not translated). The node's own EAM is
`SelfMapping` `eam4 <-> eam6`. IPv4 LAN prefixes pair with IPv6 prefixes (`lan4 <-> lan6`),
behind this node or behind a peer: a /96 prefix embeds the full IPv4 address, while a
/(96 + `lan4` length) prefix maps the network bits and copies only the host bits (see
[LAN prefixes](#lan-prefixes)). `TranslationTable` (built and validated by
`TranslationTableBuilder`) holds this model immutably; `Translator::store` replaces it
atomically while traffic flows.

### LAN prefixes

A `LanPrefix` has one of two forms. With a /96 `lan6`, the IPv4 address
itself fills the low 32 bits: `lan4` 192.168.1.0/24 and `fd64:b::/96` map 192.168.1.5 to
`fd64:b::c0a8:105`. With a /(96 + `lan4` length) `lan6` (RFC 7757 style), the low bits carry
an embedded IPv4 network other than `lan4` and only the host part is copied: `lan4`
10.9.1.0/24 and `fd64:c::c0a8:100/120` map 10.9.1.5 to `fd64:c::c0a8:105`, so two remote LANs
with the same range are told apart by giving one of them a local range. IPv6 addresses under
the /96 base but outside the embedded network are unmapped; ICMP inner packets map the same
way. One LAN prefix per /96 base, and the `lan4` ranges must not overlap. A `LanRoute` on the
gateway resolves the embedded address and needs no change.

### Nested LAN prefixes

With `TranslationTableBuilder::nested_lans` (opt-in, reported by
`TranslationTable::nested_lans`) the `lan4` ranges may nest, say a default 0.0.0.0/0 behind one
peer and 10.1.0.0/16 behind another: the longest prefix containing an address owns it. The
exact addresses (the self `eam4`, every `eam4` and `peer6_eam4`) always win and are never LAN
addresses, even inside a prefix. The reverse (`lan6_to_lan4`) is accepted only when the IPv4
address resolves back to the prefix of its /96 base, so a reply under the shorter prefix's base
that claims an address of a more specific prefix or an exact address is dropped
(`reasons::UNMAPPED`, counted in `TranslatorStats::dropped_in`), not translated. The build
flattens the nested prefixes into disjoint segments, each owned by its innermost prefix with the
exact addresses cut out, so a lookup stays one binary search. The same prefix twice and a /32
equal to an exact address are still rejected (`Lan4Overlap`). Without the option the strict
rules above apply. Pinned by `nsplane-e2e`'s `translate_nested_lans` tests.

### Translator

A stateless RFC 7915 translator: local IPv4 to an `eam4` or a peer's LAN
leaves as IPv6 to `eam6` / `lan6`, IPv6 to `local6` is rewritten to `peer6`, and the
replies are mapped back; local IPv4 to a peer's `peer6_eam4`
(`TranslationTableBuilder::peer_with_peer6_eam4(id, mapping, peer6_eam4)`; looked up with
`TranslationTable::peer6_eam4` / `by_peer6_eam4`) leaves as IPv6 to its `peer6`, from the
self `eam6` for the self `eam4` or from the `lan6` address of a local LAN source, and IPv6
from that `peer6` comes back as IPv4 from the `peer6_eam4`, ICMP errors and fragments
included. The `peer6_eam4` coexists with `eam4` and `local6`, must not collide with the self
`eam4`, another peer's `eam4` or `peer6_eam4`, or a LAN IPv4 prefix
(`TableError::Eam4IsSelf`, `DuplicateAddress`, `Lan4Overlap`), and is covered by
`Translator::ipv4_translated_predicate`; pinned by `nsplane-e2e`'s `translate_peer6_eam4`
tests (UDP, TCP, ICMP Echo, coexistence with `eam4`); native IPv4 and IPv6 pass unchanged and packets spoofing a
local-view address are dropped. TTL/hop limit, ICMP/ICMPv6 (echo and errors, including the
quoted packet and the MTU of Fragmentation Needed / Packet Too Big) and fragments (with an
IPv6 Fragment header) are translated; TCP/UDP checksums are verified and updated
incrementally. A fragmented IPv4 UDP datagram without a checksum is reassembled first, in
any fragment order: only the first fragment shows the checksum, so later fragments that
arrive before it are held (at most 256 datagrams and 1 MiB, for 60 s; a fragment after the
expiry starts a new entry) in an `nsplane_packet::reassembly::Reassembler`, the one the
netstack driver uses; the translator keeps the byte budget and the markers on top of it. A datagram with a checksum whose later fragments came first is
reassembled the same way and sent unfragmented; with nothing held, in-order fragments of a
checksummed datagram are translated one by one, without holding or waiting. A reassembled
datagram larger than the translator's MTU (`Translator::set_mtu`, 1280 by default; set it
to the tunnel MTU) is dropped as `reasons::REASSEMBLED_TOO_BIG`, never sent oversize. A
reassembled datagram keeps the packet tag its fragments share (no tag counting as a value of
its own, see [nsplane-packet](nsplane-packet.md#packet-tag-and-receipt-marker)); one whose
fragments carried different tags, or some a tag and others none, is dropped as
`reasons::FRAGMENT_MIXED_TAGS` (counted in `dropped_out`), so a merge never passes tagged input
untagged to a filter installed after the translator. `TranslatorStats` counts `fragments_held` (exact duplicates, ignored, included), `fragment_timeouts`, `fragment_budget_drops`,
`fragment_marker_evictions` and `reassembled_too_big`. A translated packet grows by 20
bytes (28 with a fragment header) inside its buffer when it has the room, else it is copied,
with its tag and receipt marker, into a larger buffer (`TranslatorStats::grown_copies`); TUN
reads leave that room. A
translated IPv6 packet shrinks without moving its payload: the IPv4 header is written in
front of it and the packet start moves forward (the headroom grows by 20 or 28 bytes).
Transport checksums are verified with `checksum::transport_valid` (32-bit word sums) and
then moved to the new pseudo-header incrementally; the reassembly clock is read only for
fragments, and the table's address indexes hold the mapping, so a lookup is one hash.
Per-packet costs are in [Performance](../performance.md#translator). Since the core routes and checks sources before the
filters, each peer's allowed IPs must contain its `eam4/32`, its `peer6_eam4/32`
if any, the LAN IPv4 prefixes behind it, its `local6`, `eam6`, `peer6` and the `lan6` prefixes behind it.

### PortMap and Conntrack

`PortMap` publishes local services to peers: a `PortMapRule` maps a
tunnel-facing `listen` address and port (TCP or UDP) to a local `target` of the same family,
optionally for some peers only (other peers are dropped). Inbound packets are DNATed and
their flow recorded in a `Conntrack`; replies are SNATed back to `listen` when routed to the
flow's peer, and ICMP errors quoting a flow are rewritten too. `Conntrack` is bounded (least
recently seen flow evicted), expires flows on per-protocol idle timeouts (TCP state aware)
without a background task, and takes an injectable clock. `PortMap::set_rules` swaps rules
atomically and drops the flows of changed rules.

### Nat64Lan

A stateful NAT64 to an IPv4 LAN (NAPT) for a subnet gateway. A
`LanRoute` maps an IPv6 /96 (`mapped`) to an IPv4 prefix (`real`); the
prefixes are `(Ipv6Addr, u8)` / `(Ipv4Addr, u8)` pairs validated by `LanRoute::new`, like
`LanPrefix`, since no IP network crate is a dependency. IPv6 TCP, UDP and ICMPv6 echo to
`mapped` plus a safe address of `real` (not broadcast, loopback, link-local, multicast or
unspecified; other mapped targets are dropped and counted) become IPv4 from the route's
`snat_source`, with a port (or echo identifier) reserved for the flow through the caller's
`SnatPorts` and given back when the flow expires, is evicted or is removed
(`Nat64Lan::remove_flow`, built on `Conntrack::remove` and its removal hook); a saturated
range drops the packet rather than aliasing a flow. Replies and Fragmentation Needed (as
Packet Too Big) are translated back; TCP MSS can be clamped. Translated packets
leave DF clear by default (`Nat64LanConfig::set_df` sets it above 1260 bytes, trading LAN
fragmentation for a PMTU black hole when the LAN filters ICMP), and a destination that more
than one route resolves is dropped and counted (`reasons::AMBIGUOUS_ROUTE`), unless
`Nat64LanConfig::nested_routes` lets routes of one `mapped` prefix nest their `real` prefixes,
where the longest `real` prefix containing the embedded address decides. The routes are a
`LanRoutes` handle passed to `Nat64Lan::new` / `with_snat_ports`: its clones share one
`SnapshotCell`, and `LanRoutes::replace` on the caller's clone applies to the next packet. The
routes gate every forward packet; a flow keeps its SNAT address across a route replacement, and the
caller revokes the flows of a removed route with `remove_flow`. Unlike the filters above it sits
on the **local side**: the LAN's replies are addressed to `snat_source`, which no peer's
allowed IPs contain, so the core could not route them to a peer before a filter ran.
`Nat64LanSink` runs `forward` on the packets the engine delivers and `Nat64LanSource` runs
`reverse` on local packets before the core routes them (the IPv6 result goes to the peer
owning the original source). Both keep the packet's tag and receipt marker; a reply without
the 20 bytes of headroom `reverse` grows into is copied once, with both.
`Nat64LanSink::send_batch_spent` appends the buffers of the packets `forward` dropped, in
order, then forwards to the inner sink's `send_batch_spent`. The clients route the mapped /96
to the gateway (it is in their allowed IPs for it), and the gateway's local side routes
`snat_source` back to itself. The
wrappers make `nsplane-nat` depend on `nsplane`; `nsplane` does not depend on `nsplane-nat`.

### Redirect

`Redirect` is not a filter: it runs on the local side, on `PacketBuf`s before
they reach a local endpoint (`forward`) and on that endpoint's replies (`reverse`). It
sends the IPv4 TCP/UDP flows a local application opens to a service address to an
endpoint a caller-supplied closure picks for each new flow (`RedirectDecision::Redirect`,
`Pass` or `Drop`), for example a `nsplane-netstack` listening on its own address, and
rewrites the replies so they come from the service address; the source is kept. Flows
live in a `Conntrack` (translated tuple: application to endpoint; `Flow::peer` unused); an
endpoint already used by a live flow from the same source is refused and the closure asked
again, up to 32 times by default (`Redirect::with_endpoint_tries(NonZeroUsize)`).
A closure with a small endpoint pool can scan it with `Redirect::endpoint_in_use(original,
endpoint)` and offer a free endpoint first, or offer each in turn with as many tries as the
pool has endpoints. `endpoint_in_use` looks the flow up with `Conntrack::peek`, which skips a
flow past its idle timeout and neither refreshes it, advances its TCP state or eviction
order, nor counts a hit or miss, so scanning a pool keeps no idle flow alive; another thread
may still take the endpoint before the answer is recorded, which only costs a try. Pinned by
`nsplane-e2e`'s `redirect_tries::a_small_pool_is_scanned_with_endpoint_in_use`. `remove_flow` (by the endpoint's view of the flow) and `retain` end
flows; `original_destination` gives the service address of an accepted flow. The closure
never runs under a lock, so it may call back into the `Redirect`. IPv6, fragments, other
protocols and untracked replies pass unchanged.

### Masquerade

`Masquerade` also runs on the local side: on the IPv6 packets a routed LAN
host sends towards the tunnel (`forward`) and on their replies (`reverse`). It is a source
NAPT: a caller-supplied closure gives each new
TCP, UDP or `ICMPv6` Echo flow a source (`MasqueradeDecision::source`, an `Ipv6Addr`, so an IPv4 source cannot be expressed) and
a `route` fingerprint, and the source port or Echo identifier becomes a token from
`MasqueradeConfig::ports`, unique per destination and source. `reverse` restores the LAN
host's address and port or identifier, after asking the closure again: a reply whose flow
now gets `None` or another `route` is dropped and the flow removed (`route_changed`: the
route fingerprint must stay current). With
`MasqueradeConfig::recheck_route_on_forward` (default `false`), forward asks the closure for
every packet of a recorded flow too and drops it the same way (`ROUTE_CHANGED`). The transport checksum is recomputed
over the IPv6 pseudo-header. Drop reasons (`masquerade::reasons`, counted in
`MasqueradeStats`): `tcp_not_syn` (with `tcp_new_flow_requires_syn`, only a SYN opens a TCP
flow), `capacity`, `route_changed`, `tokens_exhausted` and `bad_checksum` (with
`verify_checksums`, an invalid transport checksum). Forward verifies the checksum only for packets it masquerades: for a new flow after the
closure returned `Some` (a corrupt first packet records no flow), for a recorded flow before
the route recheck; a packet that passes unchanged is never dropped for its checksum. Flows live in a dedicated table instead of a `Conntrack`: a full masquerade table
refuses new flows, while a `Conntrack` evicts its least
recently seen flow. Expiry is lazy, per protocol. IPv4, extension headers, fragments, other
protocols and replies of unknown flows pass unchanged. A local side that answers pings
itself can recognize a forwarded `ICMPv6` Echo request with the read-only
`nsplane_packet::icmp::is_echo_request` and turn it into its reply with
`nsplane_packet::icmp::echo_reply_in_place`, and `reverse` takes it back to the LAN host
(`crates/nsplane-e2e/tests/masquerade.rs`). A criterion bench
(`crates/nsplane-nat/benches/masquerade.rs`) measures both directions.

### Filter order

The recommended chain is `[AclFilter, PortMap, Translator]`: the translator sits
next to the local side, so the ACL and the port map see overlay IPv6 in both directions and
ACL policies need no rules for the local IPv4 EAM addresses. With the engine's fragmentation stage and
`Translator::ipv4_translated_predicate`, oversized local IPv4 to translated destinations is
fragmented to fit the MTU after translation.


## Configuration and defaults

| Feature | How to enable | Default | Cost when not enabled |
|---|---|---|---|
| IPv4/IPv6 translation | `EngineBuilder::filter(Box::new(Translator::new(table)))`; `Translator::set_mtu` to the tunnel MTU | not installed | none: the core's filter chain is empty |
| IPv4 address of a peer's `peer6` | `TranslationTableBuilder::peer_with_peer6_eam4(id, mapping, peer6_eam4)` | none | negligible: without one, a lookup in an empty map next to the `eam4` lookup (only with a `Translator` installed) |
| Service publishing (DNAT/SNAT) | `EngineBuilder::filter(Box::new(PortMap::new(rules)?))`, or `PortMap::with_conntrack` for a sized `Conntrack` | not installed | none |
| NAT64 to LAN (NAPT) | wrap the local side: `EngineBuilder::new(Nat64LanSource::new(source, nat.clone()), Nat64LanSink::new(sink, nat))` | not installed | none |
| Local-side redirect (DNAT) | call `Redirect::forward` / `Redirect::reverse` on the local path | not used | none |
| Redirect endpoint tries / pool scan | `Redirect::with_endpoint_tries(n)`; `Redirect::endpoint_in_use` from the decision closure | 32 tries, no scan | none: the same loop with another bound; `endpoint_in_use` runs only when called |
| Local-side masquerade (IPv6 source NAPT) | call `Masquerade::forward` / `Masquerade::reverse` on the local path | not used | none: a plain type, only called if the embedder wires it |

## Errors and drop reasons

Each filter drops with its own reasons (`nsplane_nat::reasons`, `nat64_lan::reasons`,
`redirect::reasons`, `masquerade::reasons`) and counts them in its stats
(`TranslatorStats`, `ConntrackStats`, `Nat64LanStats`, `RedirectStats`, `MasqueradeStats`).

## Limits and bounds

- Translator fragment state: at most 256 datagrams and 1 MiB, for 60 s.
- `Conntrack`: bounded by `ConntrackConfig`; the least recently seen flow is evicted.
- `Masquerade`: a bounded table that refuses new flows when full.
- `Nat64Lan`: one SNAT port or Echo identifier per flow from `SnatPorts`; a saturated range
  drops the packet.

## See also

- [Usage guide: address translation and NAT](../guide.md#11-address-translation-and-nat-nsplane-nat)
- [Spec: translator address plan](../specs/translator-address-plan.md)
- [Performance: translator](../performance.md#translator)

