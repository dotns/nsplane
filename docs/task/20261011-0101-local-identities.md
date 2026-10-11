# 20261011-0101-local-identities Several local identities per engine

- **status**: in_progress
- **priority**: P1
- **owner**: L1 (7f5cstru), plan 20261011-0900-local-identities; the owner lifted the 0.11 freeze for
  this feature (2026-10-11)
- **createdAt**: 2026-10-11 01:01

## Description

Requested by ns as a major feature (ns plan `20261010-1542-concurrent-nsd-connections`).
An ns node takes part in several independent overlays at once and uses a different static
key in each, so the operators of those overlays cannot link the node by comparing keys.
Today one engine holds exactly one static key (`PeerTable::set_private_key`,
`EngineHandle::set_private_key`), so ns would have to run one engine per key, each with its
own socket, filters, queues and timers, behind one local side.

Request (generic form, no product concepts): **an engine holds several local static keys
("local identities") and every peer is bound to one of them.**

| Item | What | Crate |
| --- | --- | --- |
| LI-1 | Local identity table: add, remove and list local static keys on a running engine (`EngineHandle::{add_local_identity, remove_local_identity, local_identities}`), each with a `LocalIdentityId`. The existing single key becomes the default identity, so `set_private_key` and every current caller keep working unchanged | `nsplane-core`, `nsplane` |
| LI-2 | Peers bound to an identity: `PeerConfig::local_identity: Option<LocalIdentityId>` (`None` = default). A peer's handshakes, rekeys, cookies and keepalives use that identity's key. The peer table is keyed by `(local identity, remote public key)`, so one remote key may be a peer under two identities | `nsplane-core` |
| LI-3 | Inbound initiation dispatch: select the local identity by checking `mac1` against each identity's `mac1` key (keyed by the local public key, so no DH per identity), then decrypt with that identity only. An initiation matching no identity is dropped and counted. Cookie replies and the handshake rate limiter per identity | `nsplane-noise`, `nsplane-core` |
| LI-4 | Removing an identity removes its peers (as `remove_peer`). A peer's identity cannot change in place (remove and add) | `nsplane-core` |
| LI-5 | Events, stats and `PeerId`s carry the peer's identity. Transports, filters, path policy and the local side are shared by all identities | `nsplane`, `nsplane-core` |

Conventions as in 20261003-1500:
- Additive: an engine with one identity behaves and costs exactly as today.
- Nothing costs anything when unused: initiation dispatch with one identity is the current
  single `mac1` check.
- Every item has an nsplane-e2e test, including:
  - two identities with the same remote key;
  - removal of an identity under traffic;
  - an initiation for an unknown identity.

## Not requested

- Routing between identities: overlapping allowed IPs across identities follow the existing
  allowed-IP rules, and the consumer keeps its identities' address spaces disjoint.
- Per-identity transports or sockets: a consumer that wants separate sockets adds transports
  and binds peers to them as today.

## Notes

- Consumer fallback until this lands: one engine per local identity, with the local side split
  by destination with `Splitter::new_map` and inbound merged.
- 2026-10-11: the request file was removed from the working tree by its author after L1 had
  read it; restored verbatim by L1 on the owner's go ("需要做这个需求").
