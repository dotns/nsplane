# 20261111-2302-peer-listing-quadratic Listing all peers is quadratic in the number of peers

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-11 23:02

## Description

Audit finding. `PeerTable::allowed_ips(peer)` went through `AllowedIps::iter`, which collects and
sorts every network of the peer's local identity, and then kept the networks of that one peer.
The engine's all-peers listing (`EngineHandle::peers()`, `EngineHandle::status()`, and through
them the UAPI `get=1` of every `wg show`) called `Core::peer_stats` once per peer, so listing N
peers with about one network each cost O(N^2 log N) on the engine's owner task.

Acceptance: the all-peers listing reads the allowed IPs in one pass; a single-peer query does not
sort the networks of other peers; the per-peer order of the allowed IPs is unchanged and pinned
by a test; before and after timings are recorded here.

## ActiveForm

Making the all-peers listing one pass over the allowed IPs.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- `AllowedIps::iter_where(keep)` filters by value before sorting, so the order of the kept
  entries is the order `iter` gives them (same comparator on a subset). `PeerTable::allowed_ips`
  and `PeerTable::remove_allowed_ips` (the merged-table branch) use it.
- `PeerTable::all_allowed_ips` walks each identity's table once (one sort per identity) and
  groups the networks by peer slot; `Core::all_peer_stats` (new, additive public method) builds
  every `PeerStats` from it, and the engine's listing calls it instead of `peer_stats` per peer.
- A single `Core::peer_stats` still scans the networks of the peer's identity (O(N), without the
  sort and without the allocation for the other peers' networks). Callers that query every peer
  one by one stay quadratic with a smaller constant; `all_peer_stats` is the linear form.
- Not changed: removing a peer's allowed IPs still scans the identity's networks once
  (`AllowedIps::remove` by predicate). Avoiding that needs a per-peer index of networks kept in
  step with every insert, move and removal, which is not a change of the same size.
- Not changed: `Peer::data_tx` reads the tunnel's sent-bytes counter through `Tunn::stats()`,
  which also runs the loss estimate. `Tunn` has no accessor for that counter alone, and adding
  one changes the public API of `nsplane-noise`.

## Validation

Measurement (a temporary `#[ignore]`d test in `crates/nsplane-core/src/core/tests.rs`, not kept:
the crate has no measurement tests): N peers of the default identity with one /32 each, and every
1000th peer with 8 more /24 and 8 /64 networks; time of one listing of all peers, best of 3,
`cargo test --release -p nsplane-core --lib measure_peer_listing -- --ignored --nocapture` in the
dev container.

| peers | networks | before (`peer_stats` per peer) | after (`all_peer_stats`) | after, `peer_stats` per peer |
| ---: | ---: | ---: | ---: | ---: |
| 1 000 | 1 016 | 8.59 ms | 0.067 ms | 0.77 ms |
| 5 000 | 5 080 | 208 ms | 0.35 ms | 22.4 ms |
| 20 000 | 20 320 | 3 460 ms | 3.08 ms | 576 ms |

The listing now grows roughly linearly (5x the peers: 5.2x; 4x more: 8.9x, one sort of all
networks and the memory of 20 000 result vectors included).

`core::tests::allowed_ips_are_listed_in_trie_order_per_peer` pins the order for two peers with
interleaved IPv4 and IPv6 networks of several prefix lengths and was committed, passing, before
the change; it also holds `all_peer_stats` equal to the single-peer queries.
`allowed_ips::tests::matches_the_trie_on_random_tables` compares `iter_where` with the filtered
reference trie at every step.
