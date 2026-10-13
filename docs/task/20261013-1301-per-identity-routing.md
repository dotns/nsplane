# 20261013-1301-per-identity-routing Cryptokey routing per local identity

- **status**: in_progress (owner lifted the freeze, 2026-10-13; plan 20261013-1310)
- **priority**: P1
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-13 13:01

## Description

Requested by ns (ns plan `20261010-1542-concurrent-nsd-connections`, section "nsplane request:
cryptokey routing per local identity", ns commit `1da85d1f`).

Today (`nsplane-core` 0.13) an engine keeps one allowed-IP trie (`PeerTable::by_ip`) for all
local identities. Two peers with the same remote key under two identities, both allowing the same
addresses, cannot coexist: the last insert owns the addresses. Outbound routing
(`by_destination`) and the inbound source check (`routes_to`, in `Core::open_data`) then see only
that peer, and the other identity's peer neither receives nor sends for them.

The 0.12 consumer note asks consumers to keep identities' address spaces disjoint. A consumer
cannot guarantee that when remote addresses derive from the remote key and are announced by
independent parties.

Request: allowed IPs are scoped to the peer's local identity.

| Item | What | Crate |
| --- | --- | --- |
| LR-1 | Inbound source check within the receiving peer's local identity: a packet from a peer is accepted when its source is in that peer's allowed IPs, whatever other identities' peers allow | `nsplane-core` |
| LR-2 | Outbound routing within one local identity: a local packet is resolved against the allowed IPs of one identity's peers. The identity is chosen by the packet's source address (a per-identity source set) or by a filter verdict, instead of the engine-wide trie | `nsplane-core`, `nsplane` |

Conventions:
- Additive: one identity, or disjoint address spaces, behave and cost as today.
- e2e tests:
  - the same remote key and addresses under two identities, both exchanging traffic at once;
  - either identity removed under traffic without disturbing the other.

## Assessment (L1, 2026-10-13)

- Generic and business-agnostic. It completes local identities (0.12): today they share one
  routing table.
- Size: medium. It touches the core's per-packet routing (`by_destination`, `routes_to`):
  - LR-1 is small: check the receiving peer's own allowed IPs within its identity.
  - LR-2 needs one trie per identity and a selection step on the outbound path. The design note
    must choose between:
    - selection by source address: a per-identity source set, cheap, and a natural fit for
      ns's per-membership alias4;
    - selection by a filter verdict: more general, but it adds a filter-to-core hop.
  - With one identity the cost must stay identical: one trie and no selection step.
- Data-path change, so a data_path A/B is required. Disjoint from LP (`nsplane-nat`), so the two
  can run in parallel.
