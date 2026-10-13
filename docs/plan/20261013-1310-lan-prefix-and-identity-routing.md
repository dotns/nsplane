# 20261013-1310-lan-prefix-and-identity-routing LAN prefix mappings and per-identity routing

- **status**: approved
- **createdAt**: 2026-10-13 13:10
- **approvedAt**: 2026-10-13 (owner: "开始处理"; freeze lifted for these two items; auto mode, no round
  cap, automatic merges, watchdog with stuck-process checks)
- **relatedTask**: 20261013-1300-lan-prefix-mappings, 20261013-1301-per-identity-routing

## Work (two parallel L2s, disjoint crates)

LP (`nsplane-nat`), LP-1..2:
1. Design note: the prefix form (`lan6` of length 96 + len4, the IPv4 network part in its low
   bits), validation and overlap rules, the mapping in both directions, ICMP inner packets,
   `LanRoute::resolve`, and how the /96 path keeps its cost.
2. Implementation with unit tests (RFC 7757-style vectors), e2e tests (two peers with the same
   remote LAN range, one reached through a different local range, both answering; an ICMP error
   from the remapped LAN), and a translate A/B for /96.

LR (`nsplane-core`, `nsplane`), LR-1..2:
1. Design note covering:
   - the per-identity allowed-IP tries;
   - the LR-1 inbound check (the receiving peer's own allowed IPs);
   - how LR-2 selects the outbound identity. L1 prefers selection by source address: a
     per-identity source set, set through the handle, with the default identity as fallback.
     A filter-verdict alternative must be argued;
   - removal under traffic;
   - the one-identity fast path: a single trie and no selection step;
   - events and status.
2. Implementation with core unit tests and e2e tests (the same remote key and addresses under two
   identities exchanging traffic at once; either removed under traffic), and a data_path A/B with
   one identity.

Then docs (architecture, CHANGELOG, consumer notes in both task docs), and release 0.14.0 on the
owner's go.

## Acceptance

- /96 LAN prefixes and single-identity engines behave as before. A slot A/B shows the cost within
  noise.
- Every item is covered by unit and e2e tests.
- The full gate is green (just check with the term scan, cross, test-windows, cargo doc, release
  CLI + linux.sh, lib.sh, examples.sh).

## Annotations
- 2026-10-13: dispatched, LP `affo3r15` (campaign `nsplane-lp-202610131330`) and LR `j3miawgn` (campaign `nsplane-lr-202610131330`), in parallel with OP (plan 20261013-1330). Auto mode, watchdog every 30 min.
- 2026-10-13: LR design note approved.
  - Allowed IPs: one allowed-IP trie per identity, plus an engine-wide merged trie as the fallback.
    The merged trie is built only while a non-default identity holds allowed IPs, and is re-filled
    from the other identities on removal.
  - LR-1 checks the receiving peer's identity trie.
  - LR-2 selects the identity by the packet's source, through `set_local_sources`
    (most-specific-wins; an identical prefix is rejected). A source that matches no identity routes
    through the merged trie. This deviates from L1's default-identity fallback: it is accepted
    because adding a set changes routing only for the sources it claims.
  - New `Core::route_from(src, dst)`, used by the fragmenter.
  - The fast path is unchanged with one identity or without source sets.
  - No new events. `LocalIdentityInfo::sources` is added.
