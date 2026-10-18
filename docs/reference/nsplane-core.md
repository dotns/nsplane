# nsplane-core

The sans-I/O WireGuard engine core: peers, cryptokey routing, timers, path policy and the
packet filter chain. It does no I/O and keeps no clock; `nsplane` drives it. Builds on
`nsplane-noise` and `nsplane-packet`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `Core` (`handle_input`, `handle_datagrams` / `handle_locals`, the `_deferred` forms and `complete_job`, `handle_timeout` / `poll_timeout`, `poll_output`, `inject_inbound` / `inject_outbound` / `inject_outbound_on`, `force_handshake` / `force_handshake_on`, `route`, `data_path`, `is_remote_index`, `set_peer_pad_limit`, `peer_stats`, `unanswered_handshakes` / `total_unanswered_handshakes`, `recycle`, `add_local_identity` / `add_local_identity_on` / `remove_local_identity` / `local_identities`, `peer_id_in`, `set_local_sources`, `route_from`); traits `PathPolicy` (`select`, `on_authenticated`, `observe_every_message`) and `PacketFilter` (`inbound`, `inbound_from`, `outbound`) | `CoreConfig`, `Input`, `Output`, `ConfigChange`, `PeerConfig`, `AllowedIp`, `PeerStats`, `Event`, `Verdict`, `Roam`, `MessageKind`, `StandardRoaming`, `CryptoJob`, `LocalIdentityId`, `LocalIdentityInfo`, `reasons` |

## Behavior

### Driving the core

`Core` performs no I/O and keeps no clock of its own. A driver feeds it `Input`s (local
packets, received datagrams, configuration changes) with `handle_input`, calls
`handle_timeout` when `poll_timeout` is due, and drains `poll_output`: datagrams to
transmit, packets to deliver, and events. Packets go through in place: a local packet is
sealed in its own buffer and leaves as the transmit, a datagram is opened in its buffer and
leaves as the delivery; buffers come back through `recycle`. `handle_datagrams` and
`handle_locals` take a batch of received datagrams or local packets and behave exactly like
feeding each to `handle_input` in order, but share one schedule update, the output queue's
room and the session, route and peer lookups of consecutive packets; the route and source
lookups also hold across calls, in the core's route cache (see [Lookup structure](#lookup-structure)). Peers are looked up by key,
session index and allowed IP (cryptokey routing). Path selection and roaming are delegated
to a `PathPolicy` (`StandardRoaming` by default), local packet rewriting and interception to
`PacketFilter`s.

### Filter chain and routing

The filter chain is an onion: filters are installed from the wire side to the local side,
decrypted packets run through them in install order and local packets in reverse. A local
packet is routed by its destination (longest allowed-IP match; with source sets, within the
identity its source selects, see [Local identities](#local-identities)) before the filters run, and a
decrypted packet's source is checked against the peer's allowed IPs before them, so filters
that rewrite addresses need those addresses in the peers' allowed IPs. `Core::route_from`
exposes the routing decision and `Core::route` the decision for a source in no source set,
e.g. to pick the peer `Core::inject_inbound` delivers a locally generated reply as.

### Path hooks

Hooks for a caller-driven path ladder, each unused by default:

- `Core::inject_outbound_on` (`EngineHandle::inject_outbound_on`) seals one packet for a
  peer in its current session and transmits it on an explicit path, bypassing routing, the
  outbound filters and `PathPolicy::select`; the peer's path is not changed. It is how probes
  reach a candidate path while the peer's traffic stays on its path. Without a current
  session the packet is dropped as `reasons::NO_SESSION` and no handshake starts.
  `force_handshake_on` likewise sends one handshake initiation on an explicit path without
  changing the peer's path (`force_handshake` with a path makes it the peer's path).
- `PacketFilter::inbound_from` is what the core calls for every decrypted datagram, with the
  path it arrived on; its default calls `inbound`. A probe responder overrides it to match a
  reply with the exact tuple it probed, or to answer on the path a request came from.
- `PathPolicy::observe_every_message` (read once when the core is built, `false` by default)
  makes the core call `on_authenticated` for every authenticated message, on the current path
  too, where the answer changes nothing; by default the core asks only about messages from
  another path, which keeps the steady-state data path free
  of the call. `Event::Authenticated` stays limited to off-path sources, once per change of
  source: a peer kept on its path by the policy reports a source again only after its path is
  set (configuration, `force_handshake`, adoption) or a handshake completes.

### Unanswered handshakes

`Core::unanswered_handshakes(peer)` (`None` for an unknown peer)
counts the handshake initiations sent to a peer that got no response: one counts when another
initiation is sent while it is still unanswered (a retry, a `force_handshake`) or when the
attempt gives up (`Event::SessionExpired`); a completed handshake answers it. The count is
monotonic and a peer that only responds stays at 0. `Core::total_unanswered_handshakes()` sums
it over every peer, removed peers included, so a consumer with a peer registry polls one
number and looks up the peer when it grows (`EngineHandle::unanswered_handshakes` /
`total_unanswered_handshakes`); `Event` and `PeerStats` are unchanged.

### Injected packets

Injected packets skip the filters (part of the contract): `Core::inject_inbound`, `inject_outbound` and `inject_outbound_on` hand their packet past
the filter chain, so no `PacketFilter` sees it. A stateful filter (`nsplane-acl`'s
`AclFilter`) keeps no reply state for an injected packet, so the peer's replies are judged by
the inbound rules alone, and a translating filter does not translate it; a consumer orders
its filters with that in mind. Pinned by `nsplane-e2e`'s `inject_filters` tests.

### Padding

Used by the driver's per-path MTU (see [nsplane](nsplane.md)); unused otherwise: `Core::data_path(peer)` is the path the peer's next data message leaves on (what the policy
selects for `MessageKind::Data`, else the current path), `Core::is_remote_index(peer, index)`
checks a quoted receiver index against the peer's current session, and
`Core::set_peer_pad_limit(peer, limit)` caps the padding of the peer's data at `limit` bytes
of plaintext (`noise::Tunn::set_pad_limit`), as kernel WireGuard pads to the interface MTU: a
packet is padded to the lower of the next multiple of 16 and the limit, and one of at least
the limit is not padded. `None`, the default, pads to a multiple of 16; deferred
`CryptoJob`s honor the limit too.

### Inbound destinations

`PeerConfig::inbound_destinations` (`None` by default: unchecked)
restricts where a peer's decrypted packets may be addressed. The core checks the destination
after decryption, right after the source check and before the inbound filters, on every receive
path (per packet, batched, deferred); a packet to another destination, or whose destination
cannot be read, is dropped as `reasons::DESTINATION_NOT_ALLOWED`. The networks sit in their
own per-peer table, apart from routing (they add no routes), and the last accepted
destination of the batch is remembered like the session lookup.
`ConfigChange::SetInboundDestinations` (`EngineHandle::set_inbound_destinations`) sets or removes them at runtime, and
`add_or_update_peer` with `Some` replaces them (`None` keeps them). An unchecked peer pays one
`Option` check per packet; no peer pays an allocation or a lock.
Instead of an owned list, `ConfigChange::SetInboundDestinationSource`
(`EngineHandle::set_inbound_destination_source`) gives a peer a caller-updated
`Arc<dyn InboundDestinations>` (closures implement it): its `allows(dst)` is called once per
decrypted data packet wherever the owned list is checked (also when a deferred job
completes), never cached across packets, so a grant the caller revokes or adds in its own
lock-free snapshot applies to the next packet without a command. A source and an owned list
replace each other; `None` leaves the peer unchecked. Owned lists keep their cost and cache.

### Deferred cryptography

`handle_input_deferred` is the same entry point for a driver that encrypts on several
threads: the cryptography of a local packet or a received transport data message comes back
as a `CryptoJob` (everything before it, such as routing and the outbound filters, has
already run), `CryptoJob::run` seals or opens the packet under the lock of that peer's
tunnel only, and `complete_job` does the rest in the core (counters, completed handshakes,
roaming, the source check, the inbound filters, the output); `handle_datagrams_deferred`
and `handle_locals_deferred` do the same for batches. Only a core built with
`CoreConfig::crypto_jobs` hands out jobs, and only then does each peer's tunnel sit behind
its own mutex, shared with its jobs; otherwise every peer owns its tunnel and the data path
takes no lock (`handle_input_deferred` then processes every input at once).

### Local identities

A core holds several static keys. The one in `CoreConfig::private_key`
(`set_private_key`) is the default identity, `LocalIdentityId::DEFAULT`;
`Core::add_local_identity(key)` adds another and returns its id (`None` if an identity
already holds the key). Ids are never reused. The identity table sits in the peer table,
which keys peers by (identity, remote key) with one session index allocator, so one remote
key can be a peer under two identities and `PeerId`s and indexes stay unique per core.
`PeerConfig::local_identity` (`None` = default) binds a peer at creation and cannot change
in place; `ConfigChange::InLocalIdentity { identity, change }` addresses the key-addressed
changes to another identity's peer; `peer_id(key)` means the default identity and
`peer_id_in(identity, key)` any. `remove_local_identity` removes the identity's peers as
`ConfigChange::RemovePeer` would, and is refused for the default identity. A peer's
handshakes, rekeys, cookies and keepalives use its identity's key; `PeerStats::local_identity`
reports it, and events are unchanged (the identity follows from the `PeerId`).

### Per-identity routing

Allowed IPs are scoped to the peer's identity, each identity having its own trie,
so the same remote key with the same allowed IPs can be a peer of two identities. A
decrypted packet's source is checked in the trie of the receiving peer's identity only.
Outbound, `Core::set_local_sources(identity, sources)` gives an identity a source set (the
default identity too; empty clears it). A local packet whose source lies in a set is routed
in the trie of that set's identity only, the most specific network of all sets winning;
without a match there it is dropped as `reasons::NO_ROUTE`, whatever other identities' peers
allow. A set is refused (`false`) for an unknown identity or when another identity's set
holds an identical network. A packet whose source lies in no set is routed in the
engine-wide fallback (`Core::route`): the default identity's trie while it is the only one
with allowed IPs, otherwise a merged trie of all identities, which exists only while a
non-default identity's peers hold allowed IPs. In the merged trie the last insert across
identities owns a prefix; when its owner loses it (peer or identity removed, allowed IPs
replaced), the prefix is re-filled from the lowest-id identity still holding that exact
prefix. `Core::route_from(src, dst)` is the send path's decision. Fast path: while no
identity has a source set, the source is not looked at and a local packet takes one trie
lookup; with one identity there is one trie and no selection step.
`remove_local_identity` drops the identity's trie and source set and re-fills what it owned
in the merged trie; `ConfigChange::RemoveAllPeers` keeps the sets.

### Lookup structure

Every trie (an identity's, the merged one, the source sets, a peer's inbound
destinations) runs, per address family, a binary search on the prefix lengths in use
(Waldvogel et al.): one hash table per length holds that length's networks and markers for the
longer networks whose search passes it, each entry with its best match. A lookup takes at most
`ceil(log2(L + 1))` hash probes for L lengths in use, so 6 for IPv4 and 8 for IPv6 whatever the
number of networks. The hash tables use nsplane-packet's `KeyedState`: their keys are random,
per table, and drawn anew at each rebuild. Memory per network is bounded by an ordered-map
entry (<= 100 B), a value slot (<= 24 B) and up to 6 (IPv4) / 8 (IPv6) hash entries, the
network and its markers, of <= 76 B each at the lowest load: <= 0.6 KB per IPv4 and <= 0.75 KB
per IPv6 network, <= 5.8 / 7.3 MB for 10 k; networks with common leading bits share markers.
A write at a prefix length already in use updates the structure in place: the network, its
reference-counted markers and the best match of the markers below it. Removing one value's
networks (a removed peer, or the old list a `SetAllowedIps` replacement drops) is in place too
while every length stays in use; its cost is mostly the scan for the value. Only the first
network of a new length or the last one of a length, also through a remove by value, changes
the search: it marks the family for one rebuild (O(n log L)) at the end of the change, so a
change rebuilds each family at most once, and loading networks one change at a time rebuilds
only as lengths first appear. The core thread pays the writes: a change at lengths in use
pauses that core's data path for microseconds, one that adds or empties a length for one
rebuild per family (the timings are in [Performance](../performance.md#allowed-ip-writes)).
Every configuration entry point commits before it returns, so the data
path never meets a pending rebuild; a lookup during one would stay exact, probing every length.
### Route cache

On top of the tries, each core keeps a route cache of 64 direct-mapped entries for each of
the routes of destinations, the routes of (source, destination) pairs with source sets (so a
known flow skips the source-set lookup) and the sources accepted from peers: about 6.7 KB,
boxed and fixed; a new entry replaces the one in its place, nothing grows and no packet
allocates. It keeps positive answers only, and every routing change (peers, allowed IPs,
identities, source sets) moves the peer table's generation, which drops all entries at the
next lookup, so the cache always answers like the tries.

### Handshake dispatch

With the default identity alone, an initiation takes the single mac1 check. With two or more keyed identities, or a restricted one, an initiation
goes to the first identity, in id order, that serves the arrival transport and whose mac1 key
(derived from its public key, no DH) it matches: one keyed BLAKE2s per identity tried. An
initiation matching none is dropped as `reasons::UNKNOWN_LOCAL_IDENTITY` before any budget is
counted, with no reply. Responses, cookie replies and transport data are dispatched by
receiver index, the identity following from the peer. Each identity has its own
mac1 and cookie keys and cookie secret, while one `HandshakeBudget`
(`CoreConfig::handshake_rate_limit`) is shared by all of them, so several identities do not
multiply the handshake work a sender can cause.

### Restricted identities

`add_local_identity_on(key, transports)` limits an identity to a set of
transports. On another transport an initiation skips it as if the key did not exist (no
response, no cookie reply), so a key known from elsewhere cannot be probed there; its peers'
handshake responses and cookie replies are dropped as `reasons::UNKNOWN_PEER`, and their
transport data as `reasons::UNKNOWN_SESSION` before decryption (no `Event::Authenticated`, no
roaming). Roaming between transports of the set works. What is sent is not restricted: a
peer's path may name any transport. An unrestricted peer pays one branch per received
message for the check. The `handshake` bench measures the dispatch.


### Snapshot cell

`cell::SnapshotCell` (std only) holds a value that packet paths read and control writers
replace: the ACL state, the filter scopes, the gate policy, the translation table and the
NAT64 LAN routes use it. It has 16 cache-line-padded `RwLock` shards, each with its own `Arc`;
a load read-locks its thread's shard only to clone that `Arc` (no lock is held after it
returns) and a writer locks every shard to replace them. `store` is safe to call
concurrently (stores serialize on a writer mutex inside the cell); each store gives the value
the next generation of its cell and publishes that generation while it still holds every
shard write lock.

The packet paths use `read(|value| ..)`: each thread caches up to 8 values keyed by a
never-reused cell id and the generation, so a read of an unchanged value takes no lock and no
atomic reference count (one thread-local, non-atomic count), and a miss is one shard load plus
a cache insert. The closure is called from one site, after the hit and miss paths join, and
the cache is not borrowed while it runs, so a nested read uses and fills the cache. Neither a
load nor a read returns a value older than one a returned store, or an earlier load or read on
its thread, saw. Retention: at most 8 cached values per thread, plus one per read in progress
on the stack, so at most one replaced value per cell per thread between reads; a thread that
stops reading keeps up to 8 old values until it exits.

## Configuration and defaults

| Feature | How to enable | Default | Cost when not enabled |
|---|---|---|---|
| Inbound destinations | `PeerConfig::inbound_destinations = Some(nets)`, `EngineHandle::set_inbound_destinations`, or a caller-updated `EngineHandle::set_inbound_destination_source` | `None`: unchecked | one `Option` check per decrypted packet; a source adds one `allows` call |

## Errors and drop reasons

Every packet the core drops is counted under a reason from `reasons` (for example
`NO_ROUTE`, `NO_SESSION`, `UNKNOWN_PEER`, `UNKNOWN_SESSION`, `UNKNOWN_LOCAL_IDENTITY`,
`DESTINATION_NOT_ALLOWED`) and published as `Event::Dropped`; filters add their own reasons.
The engine reports the counts with `EngineHandle::drop_counters`.

## See also

- [nsplane](nsplane.md): the tokio driver around `Core`.
- [Performance](../performance.md): `data_path`, handshake dispatch and allowed-IP writes.

