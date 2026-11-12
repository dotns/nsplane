# 20261112-0101-ipv6-extension-walker One shared walker for the IPv6 extension header chain

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 01:01

## Description

Audit item: several crates carry their own loop over the IPv6 extension headers (Hop-by-Hop 0,
Routing 43, Fragment 44, Destination Options 60, sometimes AH 51) to find the upper-layer
protocol and its offset. The copies are not identical, and some differences are policy.

Acceptance: one walker in `nsplane-packet` (additive API, documented, tested, no new
dependency, no `unsafe`), used by the copies where that is a simplification and changes no
observable behaviour; every touched copy pinned by characterization tests that pass before and
after; no measurable regression in the criterion benches of the touched hot paths.

## ActiveForm

Replacing the per-crate IPv6 extension header loops with one walker in `nsplane-packet`.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

### Inventory

Loops over the chain:

| Copy | Skips | Fragment header | AH / ESP / 59 | Bound | Cut chain | Result |
|---|---|---|---|---|---|---|
| `nsplane-acl` `gate/packet.rs` `walk_v6` (also both walks of `quote_v6`) | 0, 43, 60 by `(len + 1) * 8`; 51 by `(len + 2) * 4` | one, 8 bytes; a later fragment (offset != 0) ends the walk at its data; behind a first fragment the walk goes on; a second one is malformed | AH skipped; ESP, 59 and every other value are the upper layer | 8 headers, the Fragment header included | `None` (`GateReason::Malformed`); the packet is cut at the payload length first; every header must lie whole within it | replaced |
| `nsplane-netstack` `ownership.rs` `fragment_transport` | 0, 43, 60 | the target: fragmented protocol, identification and, for a first fragment, the bytes behind it | not walked: a Fragment header behind AH is not found | none (the payload length bounds it) | `None`: not a fragment | replaced |
| `nsplane-nat` `translate/parse.rs` `walk_extensions` | 0, 43, 60; a Routing header with segments left is `ACTIVE_ROUTING_HEADER` | ends the chain, first or later; reserved bits are `MALFORMED`; an extension header (0, 43, 44, 51, 60) behind it is `UNSUPPORTED_EXTENSION` | `UNSUPPORTED_PROTOCOL` before a byte of them is read; ESP and 59 behind a Fragment header are the fragmented protocol | 15 headers (16 loop turns, the upper layer counts as one) | `TRUNCATED`; headers are read from the whole buffer and then checked against the end of the (possibly quoted) packet, so an active Routing header or a refused header behind a Fragment header past that end keeps its own reason | kept |
| `nsplane-packet` `reassembly.rs` `parse_v6` | 0, 43, 60, reading only the first two bytes of each | the target; also remembers where the next-header byte naming it lies | not walked | none | first two bytes missing: `Pass`; a header running past the payload: `Pass`, unless it names a Fragment header, then `Dropped` (`malformed`); a cut Fragment header: `Dropped` | kept |

Not walkers (first next header only, by design; untouched): `IpPacket::five_tuple` and
`protocol`, `icmp` and `vnet` in `nsplane-packet`, `nsplane-ether` `vnet.rs`, `nsplane-nat`
`nat64_lan/packet.rs` (`request`, `untranslatable`), masquerade and port map, `nsplane`
`fragment.rs` `may_answer_v6` (a Fragment header as the first header only), the quoted tuple of
`nsplane-netstack` `ownership.rs`, and `nsplane-netstack` `stack/wire.rs` `tcp_segment` (exactly
one Hop-by-Hop header through smoltcp's own types, to match smoltcp's receiver).

### The walker

`nsplane_packet::ExtensionWalker` (`extension.rs`) is a cursor: `new(bytes, next_header,
offset)`, `step() -> Result<Option<ExtensionHeader>, Malformed>`, `next_header()`, `offset()`,
`at_extension()`. `step` moves past 0/43/60, AH and Fragment by their lengths, requires the
whole header within `bytes`, and returns `Ok(None)` at anything else. It has no limit and no
policy: a caller counts its steps and tests `next_header()` before a step to refuse a kind or
take it as the upper layer. `ExtensionHeader::fragment` gives `Ipv6Fragment { id, offset, more }`.
`protocol` gained `IPV6_HOP_BY_HOP`, `IPV6_ROUTING`, `IPV6_FRAGMENT`, `ESP`, `AH`,
`IPV6_NO_NEXT_HEADER`, `IPV6_DESTINATION_OPTIONS`. Documented in
`docs/reference/nsplane-packet.md` (IPv6 extension headers).

### Decisions

- ACL: replaced. `walk_v6` returns at once for a packet without extension headers and calls
  `walk_chain` otherwise. Without that split `icmp_error/v6` (three walks per packet) measured
  48.1 -> 52.4..53.0 ns; with it the numbers below.
- Netstack `fragment_transport`: replaced; every cut chain was `None` before and is now.
- NAT `walk_extensions`: written on the walker (same refusals in the same order, all
  characterization tests green), then put back. `eam4_in` with 64-byte packets measured the same,
  but the two large-packet cases measured slower in every quiet round: 5 interleaved rounds,
  `eam4_in/tcp/1400B/1` 74.7..76.6 -> 78.0..79.9 ns and `eam4_in/udp/1420B/1` 74.9..76.2 ->
  78.1..82.3 ns; with the same early return as in the ACL 75.9..78.1 and 77.2..79.0 ns. The
  no-extension path does the same work in both versions, so this may be code placement around
  cold packet memory rather than the walk, but that was not shown, and a measured regression
  is not accepted. The characterization tests stay.
- Reassembly `parse_v6`: kept. The walker requires whole headers; this loop does not, and the
  difference is observable (next item). Keeping the behaviour on the walker needs a second read
  of the cut header, which is no simplification.

### Disagreement reported, not unified

An options header that runs past the payload and names a Fragment header as next: the
reassembler drops the packet as a malformed fragment (`Outcome::Dropped`, `malformed`), while
the same header naming anything else passes (`Outcome::Pass`), and the netstack's ownership
says "not a fragment" in both cases. It is an accident of the reassembler's loop reading two
bytes per header, not a policy: no fragment header was ever seen. The packet is broken either
way and is delivered nowhere, so nothing was changed. Pinned by
`reassembly::tests::ipv6_chains_that_do_not_reach_a_whole_fragment_header` (the case
"an overlong options header before a Fragment header" against the `Pass` cases next to it) and
by `ownership::tests::ipv6_chains_without_a_whole_fragment_header_are_not_fragments`.

Deliberate differences, left alone: AH is skipped by the ACL (it filters on the ports behind
it), refused by the translator (RFC 7915 has no AH translation) and not walked in front of a
Fragment header by the reassembler and the netstack; the ACL bounds the chain at 8 headers, the
translator at 15, the other two not at all; the ACL walks on behind a first fragment, the
translator refuses any extension header behind a Fragment header.

### Not done

- No criterion bench covers `NetStackHandle::owns`; the replaced branch does the same reads
  (one comparison for a packet without extension headers) and was not measured.
- The local next-header constants of `nsplane-nat` and of `reassembly.rs` stay; they belong to
  the two copies that were kept.

## Validation

Characterization tests, written first and green on the unchanged code (20 tests), green after:
`gate::tests::ipv6_packets` (AH lengths 0/2/255 and overlong, 2048-byte options headers, every
header kind cut short, nothing walked behind a later fragment, unknown next headers), the new
`translate::tests::extension_chain` (10 tests on `Ipv6::parse`: skipped kinds, the 15-header
bound, AH/ESP/59, active Routing, first/middle/last/atomic fragments, headers behind a Fragment
header, reserved bits, every cut, quoted packets), `reassembly::tests` (a three-header chain,
cut chains, 100 headers) and `ownership::tests` (2 tests on `fragment_transport`). No test was
seen red: the item changes no behaviour. `extension::tests` (7 tests) cover the walker.

Benches: release profile, `scripts/bench/slot.sh` slot 0 (CPUs 1-7), before and after binaries
interleaved in one container, criterion medians in ns, three rounds.

| `nsplane-acl` `gate` | before | after |
|---|---|---|
| `established/gate_v6` | 50.28 / 50.62 / 50.15 | 48.96 / 49.42 / 49.12 |
| `established/outbound_v6` | 49.68 / 49.87 / 50.97 | 48.21 / 49.16 / 48.73 |
| `established/extension_chain_v6` (8 headers) | 54.66 / 53.99 / 54.68 | 53.37 / 54.53 / 54.30 |
| `new_flow/any_grant_v6` | 113.17 / 113.42 / 113.36 | 113.14 / 114.82 / 120.52 |
| `fragment/later_v6` | 45.95 / 45.40 / 45.99 | 44.78 / 44.48 / 45.24 |
| `icmp_error/v6` | 48.22 / 48.36 / 48.30 | 48.38 / 47.34 / 47.65 |

`new_flow/any_grant_v6` round 3 ran next to another load. A later run of that bench on a busy
host had quiet rounds at 112.0 (before) and 114.6 (after) while `new_flow/any_grant`, the IPv4
bench whose code did not change, read 103.8..105.4 (before) and 99.6..101.4 (after): the two
binaries differ by a few percent in either direction on untouched code there.

`nsplane-nat` `translate` with the walker (not merged, see Decisions), three rounds:
`eam4_in/tcp/64B/1` 53.11 / 52.89 / 52.79 -> 52.79 / 53.19 / 53.26, `eam4_in/udp/64B/1`
52.24 / 52.41 / 52.25 -> 52.58 / 52.88 / 52.86, `lan_in/tcp/64B/1` 54.59 / 54.14 / 53.93 ->
53.70 / 54.41 / 54.35, `eam4_in/tcp/1400B/1` 74.91 / 75.63 / 74.66 -> 78.20 / 79.91 / 79.35,
`eam4_in/udp/1420B/1` 75.23 / 76.05 / 74.55 -> 81.68 / 78.97 / 79.17. The bench binary of the
merged tree is byte-identical to the one before.

Gates in the container for `nsplane-packet`, `nsplane-acl`, `nsplane-nat`, `nsplane-netstack`:
`cargo fmt --all --check`, `cargo hack clippy --each-feature --all-targets --locked`,
`cargo nextest run --all-features --locked` (with `-p nsplane-e2e`), doc tests, `cargo deny
check`, `cargo shear`, `typos`, `scripts/check-docs.sh`, `scripts/check-product-terms.sh`,
`cargo-zigbuild clippy --target aarch64-apple-darwin`.
