# Spec: the Quick v2 address plan on the generic translator model

Status   : Current
Since    : nsplane 0.11.0
Source   : ADR `docs/decisions/2026-10-06-business-agnostic-scope.md`, task
           `docs/task/20261006-1500-business-agnostic-cleanup.md` item AG-5

## 1. Purpose and status

`nsplane-nat` exposes per-peer explicit address mappings (EAM, RFC 7757) to its stateless
IPv4 <-> IPv6 translator (RFC 7915). It does not know any product's address plan. A
product builds its plan on top of the generic model.

Before 0.11.0 the model used the names of the Quick v2 address plan of ns (`node6`,
`node4`, `alias4`, `alias6`, `self4`, native alias). 0.11.0 renames them to generic EAM
names. The change is breaking and has no compatibility layer. Behaviour, validation order,
errors, reason strings and memory layout are unchanged.

This document maps the Quick v2 plan onto the generic model. A product that used the former
names reads it to port its code and to keep the plan's rules that nsplane no longer encodes.

## 2. The generic model

Source: the rustdoc of `crates/nsplane-nat/src/table.rs` and `crates/nsplane-nat/src/translate.rs`.

### Types

| Type | Field | Meaning |
| --- | --- | --- |
| `PeerMapping` | `peer6: Ipv6Addr` | The peer's own IPv6 address on the tunnel. |
| | `eam6: Ipv6Addr` | The IPv6 side of the peer's EAM. |
| | `local6: Option<Ipv6Addr>` | A local IPv6 address for the peer, rewritten (not translated) to and from `peer6`. |
| | `eam4: Option<Ipv4Addr>` | The local IPv4 side of the peer's EAM, translated to and from `eam6`. |
| `SelfMapping` | `eam4: Ipv4Addr` | This node's local IPv4 address. |
| | `eam6: Ipv6Addr` | This node's IPv6 address that `eam4` translates to and from. |
| `LanPrefix` | `lan4: (Ipv4Addr, u8)` | IPv4 prefix and its length. |
| | `lan6: (Ipv6Addr, u8)` | IPv6 prefix; the length must be `LAN6_PREFIX_LEN` (96). |
| | `peer: Option<PeerId>` | `None` for the LAN behind this node, `Some(peer)` for a LAN behind that peer. |

An IPv4 address `a` inside `lan4` maps to `lan6` with `a` in the low 32 bits.

A peer can have a second IPv4 EAM, `peer6_eam4 <-> peer6`. It is not a `PeerMapping`
field: `TranslationTableBuilder::peer_with_peer6_eam4(id, mapping, peer6_eam4)` adds it.
It lets IPv4 applications reach the peer's own IPv6 address. `eam4`, `peer6_eam4` and
`local6` may all be set for one peer.

### Builder and lookups

`TranslationTable::builder()` returns a `TranslationTableBuilder`:

| Method | Effect |
| --- | --- |
| `peer(id, mapping)` | Adds the mapping of `id`. |
| `peer_with_peer6_eam4(id, mapping, peer6_eam4)` | As `peer`, plus the IPv4 EAM to `peer6`. |
| `self_mapping(mapping)` | Sets the self mapping. |
| `lan(lan)` | Adds a LAN prefix pair. |
| `build()` | Validates everything at once; returns `Result<TranslationTable, TableError>`. |

A `TranslationTable` is immutable data with lookups. It never rewrites packets.

| Lookup | Returns |
| --- | --- |
| `peer(peer)` | The `PeerMapping` of `peer`. |
| `by_peer6(addr)` | The peer whose `peer6` is `addr`. |
| `by_eam6(addr)` | The peer whose `eam6` is `addr` (not the self mapping). |
| `by_eam4(addr)` | The peer whose `eam4` is `addr`. |
| `by_local6(addr)` | The peer whose `local6` is `addr`. |
| `by_peer6_eam4(addr)` | The peer whose `peer6_eam4` is `addr`. |
| `peer6_eam4(peer)` | The `peer6_eam4` of `peer`, if any. |
| `self_mapping()` | The `SelfMapping`, if set. |
| `lan4_to_lan6(addr)` | The `lan6` address and the LAN's peer for an IPv4 address inside a `lan4`. |
| `lan6_to_lan4(addr)` | The `lan4` address and the LAN's peer, if the embedded IPv4 address is inside the paired `lan4`. |

`Translator::new(table)` runs a table as a `PacketFilter`; `Translator::store(table)`
replaces it atomically while traffic flows.

### Validation (`TableError`)

| Variant | Rejected when |
| --- | --- |
| `DuplicatePeer(PeerId)` | The same peer is given more than one mapping. |
| `DuplicateAddress(IpAddr)` | An IPv6 address (`peer6`, `eam6`, `local6`, self `eam6`) is used twice, in any role; or an IPv4 EAM address (`eam4`, `peer6_eam4`) is used twice. |
| `Eam4IsSelf(Ipv4Addr)` | A peer's `eam4` or `peer6_eam4` equals the self `eam4`. |
| `InvalidLan4(Ipv4Addr, u8)` | A `lan4` is longer than 32 bits or has host bits set. |
| `InvalidLan6(Ipv6Addr, u8)` | A `lan6` is not a /96 or has low 32 bits set. |
| `Lan4Overlap(Ipv4Addr, u8)` | A `lan4` overlaps another `lan4`, an `eam4`, a `peer6_eam4` or the self `eam4`. |
| `Lan6Overlap(Ipv6Addr)` | A `lan6` equals another `lan6` or contains a `peer6`, `eam6`, `local6` or the self `eam6`. |

### Translate or rewrite

Translated means IPv4 <-> IPv6 (RFC 7915). Rewritten means the packet stays IPv6 and only
an address changes.

| Direction | Packet | Result | Kind |
| --- | --- | --- | --- |
| Outbound | IPv4 to a peer's `eam4` | IPv6 to its `eam6` | translate |
| Outbound | IPv4 into a `lan4` behind a peer | IPv6 to the paired `lan6` address | translate |
| Outbound | IPv4 to a peer's `peer6_eam4` | IPv6 to its `peer6` | translate |
| Outbound | IPv6 to a peer's `local6` | destination rewritten to its `peer6` | rewrite |
| Inbound | IPv6 to the self `eam6` or into a local `lan6` | IPv4 to the self `eam4` or the paired `lan4` address | translate |
| Inbound | IPv6 from a peer's `peer6` to anything else, when it has a `local6` | source rewritten to the `local6` | rewrite |

Rules that apply to these rows:

- Outbound translation needs a source that is the self `eam4` (-> the self `eam6`) or inside
  a local `lan4` (-> its `lan6` address). The destination mapping must belong to the peer
  the core routed the packet to. Otherwise the packet is dropped.
- Inbound translation needs a source that is the peer's `eam6` (-> its `eam4`), inside a
  `lan6` behind the peer (-> `lan4`), or the peer's `peer6` when the peer has a
  `peer6_eam4` (-> that address).
- An inbound packet whose source is one of this node's local-view addresses (an `eam4`, a
  `peer6_eam4`, an address inside a `lan4`, a `local6`) is a spoof and is dropped.
- Everything else passes unchanged, so native IPv4 and IPv6 traffic keeps working.

`TranslatorStats` counts `translated_out` / `translated_in` and `rewritten_out` /
`rewritten_in` separately.

## 3. Mapping table: Quick v2 -> generic

### Addresses

| Quick v2 name | Former nsplane name | Generic name |
| --- | --- | --- |
| `node6`, `N6` (native IPv6 of a peer) | `PeerMapping::node6` | `PeerMapping::peer6` |
| `node4`, `N4` (IPv4 service address of a peer) | `PeerMapping::node4` | `PeerMapping::eam6` |
| `alias4` (local IPv4 alias of `N4`) | `PeerMapping::alias4` | `PeerMapping::eam4` |
| IPv6 alias of `N6` | `PeerMapping::alias6` | `PeerMapping::local6` |
| `alias6(b)`, native alias (local IPv4 alias of `N6`) | `native_alias4` argument | `peer6_eam4` argument of `peer_with_peer6_eam4` |
| `self4` | `SelfMapping::self4` | `SelfMapping::eam4` |
| `N4(self)`, the node's own `node4` | `SelfMapping::node4` | `SelfMapping::eam6` |
| `lan4` / `lan6` | `LanPrefix::lan4` / `lan6` | unchanged |

Two things were called `alias6`. The former `PeerMapping::alias6` was an IPv6 alias,
rewritten to and from `N6`; it is now `local6`. The `alias6` of the Quick CLI and DNS is an
IPv4 alias translated to `N6(b)`; it is now `peer6_eam4`. Port each by its meaning, not by
its name.

### Methods and errors

| Former | Generic |
| --- | --- |
| `TranslationTableBuilder::peer_with_native_alias4` | `TranslationTableBuilder::peer_with_peer6_eam4` |
| `TranslationTable::native_alias4` | `TranslationTable::peer6_eam4` |
| `TranslationTable::by_native_alias4` | `TranslationTable::by_peer6_eam4` |
| `TranslationTable::by_alias4` | `TranslationTable::by_eam4` |
| `TranslationTable::by_alias6` | `TranslationTable::by_local6` |
| `TranslationTable::by_node4` | `TranslationTable::by_eam6` |
| `TranslationTable::by_node6` | `TranslationTable::by_peer6` |
| `TableError::Alias4IsSelf4` | `TableError::Eam4IsSelf` (message "IPv4 EAM address {0} equals the self address") |

The `translate_node` example's `--map` keys are `peer6=`, `eam6=`, `eam4=`, `local6=`, and
`--self` takes `<EAM4>=<EAM6>`.

## 4. The Quick v2 address plan as product semantics

nsplane no longer encodes any of this. The product derives and checks it.

### The /127 group

The Quick v2 protocol decision (2026-10-02) defines it as:

> Keep two addresses per node: a /127 group from a 119-bit hash of `I`, mode bit 0 =
> native IPv6 (`N6`), 1 = IPv4 service (`N4`).

So `N6` is the even address of the group and `N4` is `N6` with the last bit set. Both come
from the node identity `I` (in ns: from `nsshared-proto` through `overlay::identity`).

### Deriving each field

| Field | Quick v2 source |
| --- | --- |
| `PeerMapping::peer6` | `N6(b)`, mode bit 0 of the peer's /127 group. |
| `PeerMapping::eam6` | `N4(b)`, mode bit 1 of the same group. |
| `PeerMapping::eam4` | The peer's `alias4`: the first `ns-alias4-v2` candidate that is not `self4`, not in the alias table and not covered by observed host routes, interface addresses or firewall rules. |
| `peer6_eam4` | The peer's `alias6` (IPv4 alias of `N6(b)`), allocated from the same alias table. |
| `PeerMapping::local6` | Not allocated by Quick v2; `None`. |
| `SelfMapping::eam4` | `self4`, this node's own IPv4 address. |
| `SelfMapping::eam6` | `N4(self)`. |
| `LanPrefix::lan6` | The `ns-lan-addr-v2` derivation. |
| `LanPrefix::lan4` | The LAN's IPv4 prefix. |

Traffic flows in Quick v2 terms:

- An IPv4 application talks to `alias4`. The tunnel carries `N4(self) <-> N4(b)`.
- An IPv4 application talks to `alias6`. The tunnel carries `N4(self) <-> N6(b)`.
- IPv6 applications use `N6` directly; nothing is translated.

### Invariants the product keeps

nsplane validates only what section 2 lists. The product must keep these itself:

| Invariant | Why nsplane does not check it |
| --- | --- |
| `peer6` and `eam6` of one peer are the two halves of one /127 group (`eam6 = peer6` with bit 0 set). | Any two distinct IPv6 addresses are a valid mapping. |
| The self `eam6` is `N4(self)`, and `N6(self)` is the interface address. | The self mapping is any IPv4/IPv6 pair. |
| `N6` and `N4` are the ones derived from the peer's identity. | nsplane binds addresses to a peer only through its allowed IPs. |
| An alias never moves while the peer stays allowed; a removed peer leaves a tombstone that only the same identity reuses. | Each table is built from scratch; `store` replaces it whole. |
| An alias is not covered by host routes, interface addresses or firewall rules; a conflict suspends it (fail closed). | nsplane sees no host state. |
| `alias4` and `alias6` come from the alias candidates and never collide with `self4`. | `build` rejects collisions (`DuplicateAddress`, `Eam4IsSelf`) but does not allocate. |
| The ACL's outbound sources are `N6(self)` and `N4(self)`. | The ACL is configured separately (`AclFilterScope::outbound_sources`). |

## 5. Building it

One peer with all mappings, the self mapping and a local LAN. The names and signatures are
those of `table.rs`; the style follows `examples/src/bin/translate_node.rs`.

```rust
use std::net::{Ipv4Addr, Ipv6Addr};

use nsplane_nat::{LanPrefix, PeerMapping, SelfMapping, TableError, TranslationTable};
use nsplane_packet::PeerId;

/// The table of a node with `self4` and `N4(self)`, one peer `b` and the LAN behind this node.
fn table(
    b: PeerId,
    self4: Ipv4Addr,
    self_n4: Ipv6Addr,
    n6: Ipv6Addr,
    n4: Ipv6Addr,
    alias4: Ipv4Addr,
    alias6: Ipv4Addr,
    lan: ((Ipv4Addr, u8), Ipv6Addr),
) -> Result<TranslationTable, TableError> {
    TranslationTable::builder()
        .self_mapping(SelfMapping {
            eam4: self4,
            eam6: self_n4,
        })
        .peer_with_peer6_eam4(
            b,
            PeerMapping {
                peer6: n6,
                eam6: n4,
                local6: None,
                eam4: Some(alias4),
            },
            alias6,
        )
        .lan(LanPrefix {
            lan4: lan.0,
            lan6: (lan.1, 96),
            peer: None,
        })
        .build()
}
```

The peer ids are the engine's: build the table after the peers are added (e.g. from
`EngineHandle::peer_id`), then `Translator::store` it. A translator created with
`Translator::new(TranslationTable::default())` passes everything until then.

### Routing and allowed IPs

The core routes a local packet by its destination before the filters run, and checks a
decrypted packet's source against the peer's allowed IPs before them. So each peer's
allowed IPs must contain:

| Address | Needed for |
| --- | --- |
| `eam4/32` | outbound routing |
| `peer6_eam4/32`, if any | outbound routing |
| `local6/128`, if any | outbound routing |
| the `lan4` prefixes behind the peer | outbound routing |
| `eam6/128` | inbound source check |
| `peer6/128` | inbound source check |
| the `lan6` prefixes behind the peer | inbound source check |

The host must also route these local addresses to the tunnel interface, and the self `eam4`
must be an interface address. Hosts of a local LAN route the peers' local addresses through
this node, with IP forwarding on.

### Filter order

The filter chain is an onion: decrypted packets run through the filters in install order,
local packets in reverse. Install the translator last, next to the local side; the
recommended stack is `[AclFilter, PortMap, Translator]`. The ACL and the `PortMap` then see
tunnel-side IPv6 both ways (`eam6`, `peer6`, `lan6`), so policies need no rules for the
local IPv4 EAM addresses, and stateful replies of translated flows match.

## 6. Parity cases

These tests pin the behaviour. They stay in nsplane as generic tests; a product can replay
the same cases against its own plan.

| File | Tests | Covers |
| --- | --- | --- |
| `crates/nsplane-nat/src/table.rs` (`mod tests`) | `peer_lookups`, `self_mapping_lookup`, `lan_lookups`, `lan_round_trip`, `single_address_and_whole_space_lan4`, `peer6_eam4_lookups` | Lookups of every role. |
| same | `rejects_duplicate_peer`, `rejects_duplicate_eam4`, `rejects_duplicate_ipv6_addresses`, `rejects_eam4_equal_to_self_eam4`, `rejects_invalid_lan4`, `rejects_invalid_lan6`, `rejects_overlapping_lan4`, `rejects_lan4_covering_eam4_or_self_eam4`, `rejects_overlapping_lan6`, `rejects_lan6_covering_a_peer_eam_or_local_address`, `rejects_a_peer6_eam4_in_use`, `rejects_lan4_covering_a_peer6_eam4`, `errors_display` | Every `TableError`. |
| `crates/nsplane-nat/src/translate/tests.rs` | `outbound_eam4_from_self_eam4_becomes_ipv6_to_eam6`, `outbound_lan4_becomes_lan6_on_both_sides`, `outbound_mapping_of_another_peer_is_dropped`, `outbound_unmapped_source_is_dropped`, `native_packets_pass_unchanged`, `outbound_local6_is_rewritten_to_peer6` | Outbound rows of section 2. |
| same | `inbound_eam6_to_self_becomes_ipv4_from_eam4`, `inbound_lan6_becomes_lan4_on_both_sides`, `inbound_source_must_belong_to_the_peer`, `inbound_peer6_is_rewritten_to_local6`, `inbound_spoofed_local_view_sources_are_dropped` | Inbound rows and the spoof rule. |
| same | `store_swaps_the_table_atomically`, `predicate_follows_the_current_table`, `stats_count_each_outcome` | Table replacement, the IPv4 predicate, counters. |
| `crates/nsplane-nat/src/translate/tests/peer6_eam4.rs` | `outbound_peer6_eam4_becomes_ipv6_to_peer6`, `inbound_peer6_to_self_eam6_becomes_ipv4_from_the_peer6_eam4`, `icmp_errors_quoting_peer6_eam4_packets_are_translated`, `peer6_eam4_fragments_are_translated_both_ways`, `a_peer6_eam4_source_is_a_spoof`, `a_peer6_eam4_of_another_peer_is_dropped`, `peer6_eam4_coexists_with_eam4_and_local6`, `the_predicate_covers_peer6_eam4s` | The IPv4 EAM to `peer6` (Quick v2 `alias6`). |
| `crates/nsplane-nat/src/translate/tests/vectors.rs` | `tcp_vector_v4_to_v6`, `tcp_and_udp_round_trip_with_valid_checksums`, `echo_both_directions_preserves_odd_payload`, `every_supported_icmpv4_error_and_its_quote`, `every_supported_icmpv6_error_and_its_quote`, `icmpv6_errors_through_local6_rewrite_their_quote`, and the other tests of the file | RFC 7915 vectors on the `eam4 <-> eam6` path. |
| `crates/nsplane-e2e/tests/translate.rs` | `ipv4_app_reaches_ipv6_only_peer_over_udp`, `ipv4_app_reaches_ipv6_only_peer_over_tcp`, `local6_and_peer6_are_rewritten_both_ways`, `lan4_reaches_lan6_and_back`, `icmp_echo_is_translated_both_ways`, `icmpv6_errors_about_translated_packets_arrive_as_icmp`, `table_replacement_takes_effect_while_traffic_flows` | Two engines, with allowed IPs as in section 5. |
| `crates/nsplane-e2e/tests/translate_peer6_eam4.rs` | `ipv4_app_reaches_native_ipv6_over_udp`, `ipv4_app_reaches_native_ipv6_over_tcp`, `icmp_echo_to_the_peer6_eam4_is_translated_both_ways`, `the_peer6_eam4_coexists_with_eam4` | Two engines, `peer6_eam4` next to `eam4` and `local6`. |
| `examples/src/bin/translate_node.rs` (`mod tests`) | `map_spec`, `lan_spec`, `mapped_addresses_are_allowed_and_the_self_eam4_is_an_address`, `map_of_unknown_peer` | CLI parsing and the allowed IPs a node adds. |
| `scripts/e2e/examples.sh` | `scenario_translate_node` | A TUN node between an IPv4-only LAN client and a kernel WireGuard peer with an IPv6-only overlay, using a /127 pair (`peer6 fd00:a::2:0`, `eam6 fd00:a::2:1`). |

The fixtures use generic names (`SELF_EAM4`, `EAM4`, `peer_mapping()`, `PEER6_EAM4`). To
replay a case in Quick v2 terms, read them through the table in section 3.
