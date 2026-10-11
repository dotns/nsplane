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

## Consumer note

- Add an identity with `EngineHandle::add_local_identity(key)` (or `add_local_identity_on`,
  below) and keep the returned `LocalIdentityId`. Bind a peer to it with
  `add_or_update_peer(Peer { local_identity: Some(id), ..Peer::new(remote_key) })`; the same
  call with the same identity and key updates the peer. The identity is fixed at creation: to
  move a peer, remove it (`remove_peer_in`) and add it again. The key-addressed methods
  (`remove_peer`, `set_inbound_destinations`, ...) mean the default identity; the `_in` forms
  and `peer_id_in` address the others.
- Ids are never reused, so a stale id can never name a later identity. Removing an identity
  (`remove_local_identity`) removes all its peers, as `remove_peer` would for each.
- Separate keys stop key-based linking only. With a shared transport, every overlay sees the
  same source address and port.
- For unlinkability at the key and endpoint level, give each identity its own key and its own
  transport, add it with `add_local_identity_on(key, [transport])` and set its peers' paths on
  that transport. The identity then answers initiations only there (an initiation for its key
  on another transport gets no response and no cookie reply), and its peers' responses, cookie
  replies and data are accepted only there.
- Outbound traffic is not enforced: the engine sends a peer's messages on whatever path the
  peer has or the path policy selects. Keeping each identity's paths on its own transport is
  the consumer's job.

## Measurements

LI-E, 2026-10-11, criterion benches of `nsplane-core` run through `scripts/bench/slot.sh`,
each binary in the dev image with `--cpuset-cpus "$BENCH_CPUS"` (3 s warm-up, 8 s
measurement). A = `main` (db30059), B = the branch with LI-A..C merged (08abfdd). Each A/B invocation
ran A and B interleaved, four rounds each, 120 s between invocations; numbers are the medians
of the four criterion point estimates. Threshold: |delta| <= max(2 %, run-to-run spread of A).

| Case | Slot | Load avg before -> after | A | B | Delta | Spread of A |
|---|---|---|---|---|---|---|
| `data_path/core_round_trip/64` | 0 (1-7) | 1.50 1.35 1.62 -> 1.66 1.54 1.64 | 530.0 ns | 532.3 ns | +0.4 % | 0.3 % |
| `data_path/core_round_trip/1420` | 0 (1-7) | same invocation | 1.3368 us | 1.3351 us | -0.1 % | 1.0 % |
| `handshake/initiation/1` | 0 (1-7) | 5.88 3.55 2.38 -> 1.98 2.85 2.26 | 128.70 us | 128.83 us | +0.1 % | 0.6 % |

All within noise. 0.10.0 reference for `core_round_trip`: 64 B 530 ns, 1420 B 1.334 us. The
data path rows cover the one extra per-peer transport branch an unrestricted peer pays per
received message. One B run of 64 B (564.7 ns, wide interval) is an outlier; the median is
unaffected. `main` has no `handshake` bench: the A side ran the branch's bench file copied into
a detached `main` worktree (not committed) with its N = 1 case only, identical apart from
dropping the identity setup loop and the `no_match` case (main lacks the API), so both sides
time the same default-identity path.

Cost model, branch only, one invocation (slot 0, load 0.50 1.99 2.01 -> 0.80 1.82 1.95):

| Case | Time |
|---|---|
| `handshake/initiation/1` (default identity only, no dispatch) | 129.11 us |
| `handshake/initiation/4` (peer on the 4th identity) | 130.14 us |
| `handshake/initiation/16` (peer on the 16th identity) | 132.25 us |
| `handshake/no_match/16` (dropped, 16 mac1 checks) | 3.10 us |

Each identity tried before the matching one costs about 0.2 us (one keyed BLAKE2s over the
initiation: (132.25 - 129.11) / 15 = 0.21 us; no_match 3.10 us / 16 = 0.19 us), so 16
identities add 2.4 % to an initiation. A forged initiation costs the responder 16 mac1 checks
(3.1 us) and no budget or DH.

## Notes

- Consumer fallback until this lands: one engine per local identity, with the local side split
  by destination with `Splitter::new_map` and inbound merged.
- 2026-10-11: the request file was removed from the working tree by its author after L1 had
  read it; restored verbatim by L1 on the owner's go ("需要做这个需求").
