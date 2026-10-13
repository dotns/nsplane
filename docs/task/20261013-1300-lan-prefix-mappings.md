# 20261013-1300-lan-prefix-mappings Prefix address mappings for LAN prefixes

- **status**: pending (a new feature; the owner decides whether to lift the 0.13 freeze for it)
- **priority**: P1
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-13 13:00

## Description

Requested by ns (ns plan `20261010-1542-concurrent-nsd-connections`, section "nsplane request:
prefix address mappings for LAN prefixes", ns commit `ba62735f`).

Today (`nsplane-nat` 0.13), a `LanPrefix {lan4, lan6, peer}`:
- requires `lan6` to be a /96 that embeds the whole IPv4 address (`lan6 | a`);
- has `LanRoute::resolve` require the embedded address to lie inside the route's real CIDR.

As a result, a consumer reaching two remote LANs with the same IPv4 range through different peers
cannot give one of them a local IPv4 range of its own. Replies then fail `lan6_to_lan4`.
`PeerMapping` is /32 to /128 only, and `Redirect` cannot tell the peers apart.

Request: LAN prefixes map by prefix, RFC 7757 style, so the IPv4 side may be a range other than
the one embedded on the IPv6 side.

| Item | What | Crate |
| --- | --- | --- |
| LP-1 | `TranslationTableBuilder::lan` accepts `lan6` of length `96 + len4` whose low bits carry an IPv4 network part, and copies the host suffix: `lan4_to_lan6(a) = lan6 \| (a & host_mask(len4))`, `lan6_to_lan4(x) = lan4_network \| (x & host_mask(len4))`. The /96 form is the special case | `nsplane-nat` |
| LP-2 | The same mapping in `map4to6` / `map6to4` for ICMP and ICMPv6 inner packets, and in `LanRoute::resolve`: the embedded network, not the local range, must lie inside the real CIDR | `nsplane-nat` |

Conventions:
- Additive: /96 prefixes behave and cost as today.
- e2e tests:
  - two peers with the same remote LAN range, one of them reached through a different local IPv4
    range, both answering;
  - an ICMP error from the remapped LAN.

## Assessment (L1, 2026-10-13)

- Generic (RFC 7757 explicit address mappings) and business-agnostic.
- Size: small to medium, confined to `nsplane-nat` (translate, nat64_lan). No public breaking
  change is expected. A patch-compatible minor (0.14.0) or 0.13.x if the owner accepts it as an
  extension.
- Disjoint from LR (`nsplane-core`), so the two can run in parallel.
