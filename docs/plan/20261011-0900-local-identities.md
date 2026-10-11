# 20261011-0900-local-identities Several local identities per engine

- **status**: completed
- **approvedAt**: 2026-10-11 (user: "需要做这个需求"; the 0.11 freeze is lifted for this feature only; auto mode, no round cap, automatic merges, watchdog with stuck-process checks)
- **createdAt**: 2026-10-11 09:00
- **relatedTask**: 20261011-0101-local-identities

## Context

ns wants a node to join several independent overlays (several NSDs) at once, with a different
static key in each so their operators cannot link the node by key (ns plan
`20261010-1542-concurrent-nsd-connections`, draft). Today an engine has exactly one static
key. ns's fallback is one engine per key, which multiplies sockets, timers, queues, crypto
workers and buffer pools, and breaks ns's "one engine per process" rule. The request is
generic, not a product concept: several local static keys, each peer bound to one. That fits
ADR `2026-10-06-business-agnostic-scope`.

The feature is additive but deep: it touches the peer table key, handshake dispatch, cookies
and rate limiting. The 0.11 freeze (ADR `2026-10-08-feature-freeze-0-11`) has to be lifted for
it. It ships as 0.12.0, and 0.11.x keeps receiving fixes.

## Design (to confirm in the L2's design note)

| Topic | Proposal |
|---|---|
| Identity table | `LocalIdentityId` (opaque, never reused). Identity 0 is the default and holds today's key, so `set_private_key` sets the default identity's key and every caller is unchanged. `EngineHandle::{add_local_identity(StaticSecret) -> LocalIdentityId, remove_local_identity, local_identities}` |
| Peer binding | `PeerConfig::local_identity: Option<LocalIdentityId>` (`None` = default). Peers are keyed internally by `(identity, remote key)`; `PeerId` stays unique per engine. `peer_id(key)` keeps meaning the default identity; a new `peer_id_in(identity, key)` covers the rest. A peer's identity is fixed at creation |
| Inbound initiation | Check `mac1` against each identity's `mac1` key (a BLAKE2s MAC per identity, no DH), then run the Noise responder with the matching identity only. No match: drop, counted as a new reason. One identity costs the same single check as today; N identities cost N MACs per initiation |
| Other messages | Handshake responses, cookie replies and data are dispatched by receiver index, as today. Indexes are already unique per engine, so the identity follows from the peer |
| Cookies and DoS | Cookie and `mac2` keys per identity. One global handshake budget per engine, so N identities cannot multiply the CPU an attacker can consume |
| Removal | `remove_local_identity` removes its peers as `remove_peer` does, and is refused for the default identity |
| Events and stats | Peer events and `PeerStats` carry the identity; an `EngineStatus` entry per identity (public key, peer count) |
| Shared | Transports, filters, path policy, fragmenter, crypto workers and the local side are shared. Routing stays global longest prefix, and consumers keep identity address spaces disjoint (not checked) |
| UAPI and CLI | Default identity only (dev tool), documented |

Caveat for the consumer (documented, not solved here): separate keys stop key-based linking
only. With a shared transport, every overlay sees the same source address and port. A consumer
that needs unlinkability at that level gives each identity its own transport and binds its
peers' paths to it. That already works today.

## Work (one L2, sequential in nsplane-noise / nsplane-core)

1. Design note to L1 (yellow gate): API, internal key change, `mac1` dispatch, cookie/limiter
   split, the event/stats shape, and the cost model.
2. nsplane-noise: `mac1`/cookie checks against a set of responder keys, with unit tests
   against the WireGuard test vectors.
3. nsplane-core: identity table, peer key `(identity, remote)`, initiation dispatch,
   removal, events/stats; core unit tests; `data_path` A/B with one identity (no
   regression).
4. nsplane: `EngineHandle` methods, status; e2e:
   - two identities with the same remote key;
   - removal of an identity under traffic;
   - an initiation for an unknown identity;
   - kernel WireGuard peers on two identities.
5. Docs (architecture, CHANGELOG, migration note for ns), then release 0.12.0.

## Acceptance

- One identity: byte-identical wire behavior, and data_path and handshake benches within noise
  (slot A/B).
- N identities: the initiation cost is measured and documented for N = 1, 4, 16.
- Full gate (check with the term scan, cross, test-windows, doc, e2e scripts).
- Interop with kernel WireGuard per identity.

## Annotations
- 2026-10-11: dispatched (campaign `nsplane-li-202610110900`): LI `eos2286z`. Auto mode, watchdog every
  30 min with stuck-process checks. The release (0.12.0) is asked of the owner at the end.
- 2026-10-11: LI design note approved:
  - `LocalIdentityId` with DEFAULT = 0, `PeerConfig::local_identity`, `ConfigChange::InLocalIdentity`
    and `_in` handle methods;
  - peers keyed by (identity, key) with one index allocator;
  - mac1 dispatch only for N >= 2;
  - a shared `HandshakeBudget` with per-identity cookie secrets;
  - events unchanged, the identity resolvable from the PeerId (accepted reading of LI-5);
  - a golden mac1/mac2/cookie test.
  Added LI-6: an identity may be restricted to a set of transports, and initiations on other
  transports skip it, so a known key from another overlay cannot be probed via cookie replies.
- 2026-10-12: completed (campaign `nsplane-li-202610110900`), merged into main. LI-A..F: noise shared
  budget and `mac1_matches`, core identity table with (identity, key) peers and mac1 dispatch,
  handle methods and status, e2e incl. kernel WireGuard per identity, benches and docs, UAPI on
  the default identity only. Main: just check 1752 tests with a clean term scan, cargo doc green.
  data_path +0.4 % / -0.1 % and single-identity initiation +0.1 % (noise). Initiation 129 / 130
  / 132 us at N = 1 / 4 / 16, and a no-match drop 3.1 us at N = 16. Next: release 0.12.0 on the
  owner's go; the freeze is back in force afterwards.
