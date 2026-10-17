# 20261017-1300-nested-lan-prefixes Nested LAN prefixes with longest-prefix match

- **status**: in_progress
- **createdAt**: 2026-10-17 13:00
- **approvedAt**: 2026-10-17 (owner: "2，需要，开始修改然后发布0.15.0", the fifth exception to the
  freeze, released as 0.15.0)
- **relatedTask**: ns plan `20261017-0422-gateway-as-node` (read only, in /srv/dotns/ns)

## Context

ns treats a gateway as an ordinary Node. A default IPv4 exit is then a LAN prefix `0.0.0.0/0` on
the gateway Node: local IPv4 destinations map into a /96 the gateway owns, and the gateway does
6->4. Today `TranslationTableBuilder::build` rejects a LAN IPv4 prefix that overlaps another
one, the self `eam4`, a peer's `eam4` or a `peer6_eam4` (`TableError::Lan4Overlap`), so
`0.0.0.0/0` cannot coexist with any other mapping. Lookups keep the LAN prefixes sorted and
disjoint (`TranslationTable::lan4`, one binary search).

Generic form, no product concepts: an operator may install LAN prefixes that nest, and the most
specific mapping wins.

## Requirements

| Item | Requirement | Crate |
|---|---|---|
| NL-1 | LAN IPv4 prefixes may nest (CIDR prefixes either nest or are disjoint). `lan4_to_lan6` returns the longest LAN prefix that contains the address. Two LAN prefixes with the same IPv4 network stay an error | `nsplane-nat` |
| NL-2 | Exact IPv4 addresses (self `eam4`, a peer's `eam4`, `peer6_eam4`) may lie inside a LAN prefix and always win over it, in every lookup: outbound destination and source, ICMP inner packets, `map4to6`/`map6to4` | `nsplane-nat` |
| NL-3 | Reverse consistency: `lan6_to_lan4` accepts an address under a LAN's /96 only if the IPv4 address it maps to resolves to that same LAN through NL-1/NL-2. A reply under the default prefix that claims an address of a more specific LAN or an exact mapping is not translated | `nsplane-nat` |
| NL-4 | `Nat64Lan` / `LanRoute::resolve` follow the same longest-prefix rule where routes nest | `nsplane-nat` |
| NL-5 | Opt-in: the current strict check stays the default, so existing callers keep their conflict detection. A builder option enables nesting; the public API only grows | `nsplane-nat` |

## Constraints

- Lookup cost: one binary search per lookup, as today (nested prefixes flattened into disjoint
  intervals when the table is built); slot A/B of the `translate` bench against 0.14.2.
- Bounded build cost, measured for 10 k LAN prefixes.
- std only, no new crate, no unsafe; existing behaviour unchanged without the option.
- Every item has unit tests, and an nsplane-e2e test covers a default prefix next to a more
  specific LAN, an exact peer mapping inside it, and a spoofed reply (NL-3) that is dropped.

## Items

- **NL-A** design note to L1 (yellow): API shape of the option, flattening, the lookup order
  in `translate.rs` (today `by_peer6_eam4` is checked after the LAN lookup and must move before
  it), NL-3 check, `Nat64Lan`.
- **NL-B** implementation with tests (TDD).
- **NL-C** e2e test, slot A/B, docs (docs/architecture.md, CHANGELOG [Unreleased] Added).

## Acceptance

- NL-1..5 met, full gate green (just check, cross, test-windows, cargo doc, release CLI +
  linux.sh, lib.sh, examples.sh), `translate` rows at par with 0.14.2.
- Released as 0.15.0 after the owner confirms.

## Annotations
