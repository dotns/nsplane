# 20261013-1300-lan-prefix-mappings Prefix address mappings for LAN prefixes

- **status**: in_progress (owner lifted the freeze, 2026-10-13; plan 20261013-1310)
- **priority**: P1
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-13 13:00

## Description

Requested by ns (ns plan `20261010-1542-concurrent-nsd-connections`, section "nsplane request:
prefix address mappings for LAN prefixes").

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

## Consumer note

A consumer that reaches two remote LANs with the same IPv4 range through different peers keeps
one of them at its real range and gives the other a local IPv4 range of its own:

- LAN via peer `b`: `lan4` 192.168.1.0/24, `lan6` `<b-base>::/96` (the /96 form, unchanged);
- LAN via peer `c`: `lan4` 10.9.1.0/24 (a local range), `lan6` `<c-base>::c0a8:100/120` (the
  remote network 192.168.1.0/24 embedded under the /96 base).

Local applications address 10.9.1.5 for the host 192.168.1.5 behind `c`; it leaves as
`<c-base>::c0a8:105`, replies and ICMP errors (with their quoted packets) come back as
10.9.1.x. The consumer routes `<b-base>::/96` to `b` and `<c-base>::/96` to `c`, plus each
`lan4` range to its peer.

Validation (`TranslationTableBuilder::build`):
- `lan6` length is 96, or 96 + the `lan4` length;
- neither prefix has host bits set (a /96 has zero low 32 bits);
- at most one LAN prefix per /96 base (`Lan6Overlap`); different bases may embed the same
  IPv4 network;
- `lan4` ranges must not overlap each other or an IPv4 EAM/self address (`Lan4Overlap`).

IPv6 sources under a base but outside its embedded network (`<c-base>::c0a8:205`) are dropped
as unmapped, not read as 10.9.2.5.

The gateway side needs no change: its `LanRoute` maps `<c-base>::/96` to the real
192.168.1.0/24 and resolves the embedded address; it never sees the consumer's local range.
Pinned by `nsplane-e2e`'s `translate_lan_prefix` tests.
