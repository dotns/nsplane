# 20261112-0001-acl-fairness-and-scans Fairness between peers and full-table scans in nsplane-acl

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 00:01

## Description

Five items of the audit in `nsplane-acl`. The peers are authenticated; the concern is one peer
degrading the service of the others.

1. The flow gate's fragment table (4,096 slots, 30 s) was one budget for all peers: a bound
   peer sending first fragments with new identifications on one flow took every slot, and the
   fragmented packets of every other peer failed with `StateCapacity`.
2. At a full flow or fragment table every further new-flow packet swept all 64 shards, and at
   a full per-peer quota every one swept the peer's shard.
3. `FlowGate::find_flow` locked all shards and walked every flow per call.
4. `FlowTracker` scanned its whole table under its mutex for every new flow once it was full.
5. The hasher of the filter's tables (`lru::FlowHasher`, multiply and rotate) was reported to
   have collisions that do not depend on its seed.

Acceptance: each item is fixed with a test seen failing first where one is feasible, measured
before and after where it is about cost, or left alone with the reason recorded; the public
API only grows; the gates pass.

## ActiveForm

Fixing the audited fairness and scan items in the ACL crate.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Item 1. A peer now holds at most half of the fragment table, rounded up (2,048 by default),
counted per shard over both families like the per-peer flow count. At its share the peer's
shard is swept for expired entries, then the first fragment is denied `StateCapacity` and
counted. Half keeps a lone peer at today's behaviour up to 2,048 fragmented packets per 30 s
(68 per second sustained instead of 136) and guarantees the other peers the other half; two
flooding peers together can still fill the table, which the limit of the whole table answers
as before. `GateLimits`, `GateConfig` and `GateCounters` are plain structs with public
fields and not `#[non_exhaustive]`, so a new field in any of them breaks callers that build or
destructure them. The share is therefore set with `FlowGate::set_fragments_per_peer` (read
with `fragments_per_peer`), at any time, and the refusals are read with
`FlowGate::fragments_per_peer_denied`; a value of at least `GateLimits::fragments` restores
the former behaviour. Moving both into `GateLimits` and `GateCounters` is for the next release
that breaks the API. The reference model of the gate tests (`gate/tests/model.rs`) describes
the specification and got the same rule.

Item 2. A sweep that reclaimed nothing keeps the next sweep of its kind from running for
100 ms (`state::SWEEP_PAUSE`): one mark per shard for the sweeps a per-peer limit asks for,
one for the sweep of every shard, whose mutex is held for the whole sweep so that concurrent
callers wait for one sweep instead of each running one. A sweep that reclaimed something does
not hold the next one back. The bound: an entry that expires makes room at a limit at most
100 ms after its expiry, since only a fruitless sweep from before the expiry can delay the
next. A capacity verdict can thus be given while an entry expired less than 100 ms ago is
still counted; before, it was given only after every expired entry was reclaimed. Release
profile, one thread, time per denied new-flow packet: full table of 16,384 flows 25,238 ns
before and 178 ns after; full per-peer quota of 2,048 flows 2,811 ns before and 100 ns after.

Item 3. Callers: the tests, and by `docs/specs/node-l3.md` 3.10 a product's authorization of
an accepted service connection, which a remote peer drives at its connection rate. The key of
a flow holds the peer and the scope, neither of which the caller gives, so a lookup by key is
not possible; an index by five-tuple would be a second map kept on every flow insert and
removal of the packet path, and was not added. The walk stays O(flows) and now locks one shard
at a time, checking each shard's generation against the snapshot and starting over when a
`replace` landed in between (as the packet path does). The result is no longer one instant
across shards, which no caller can observe: a flow lives in one shard. Release profile, 16,384
flows: one call 19.6 us before and 17.5 us after; an established packet on each of four
threads while a fifth loops `find_flow`: mean 14,323 ns and worst 140 ms before, mean 244 ns
and worst 40 us after (171 to 338 ns without the fifth thread).

Item 4. The table is now the crate's `LruMap`, whose list order is the order of last use, so
the flow evicted is the same one as before (`evictions_follow_the_order_of_last_use` passes on
the old and the new table). `LruMap::touch` now says whether the key was there and
`LruMap::iter` was added. `clear` now also releases the table's memory. Release profile, new
flow on a full table: 11,246 ns before and 104 ns after at 4,096 flows, 174,325 ns before and
80 ns after at 65,536. A packet of a tracked flow went from about 300 ns to about 45 ns, mostly
because the table moved from `SipHash` to the crate's table hasher.

Item 5. Confirmed. `state = rotl((state ^ word) * odd, 29)`: a flip of bit 63 of a word
reaches the product in bit 63 alone, the rotation moves it to bit 28, and the next word
cancels it. The test showed, for every seed tried: equal hashes for such pairs of two-word
keys; equal hashes for two IPv6 addresses that differ in bit 7 of octet 7 and bit 4 of octet
11; and only 16 distinct hashes for the 256 keys made of the top four bits of one word and
bits 25 to 28 of the next (sets of `2^n` equal hashes from `2^2n` keys in general). The
tables (`LruMap`, the engine's host index, the filter's peer and identity maps) now use
`nsplane_packet::hash::KeyedState`, which the gate's maps already used; `FlowHash` and
`FlowHasher` are removed (crate-private). Cost: see Validation.

## Validation

Seen failing before the fix: `gate::tests::state_table::one_peer_holds_at_most_its_share_of_the_fragment_table`
and `the_per_peer_fragment_limit_is_configurable` (with the limit disabled; the model tests
fail then too); `a_sweep_of_a_shard_that_freed_nothing_is_not_repeated_at_once` and
`a_sweep_of_every_shard_that_freed_nothing_is_not_repeated_at_once` (with the pause disabled);
`gate::tests::concurrency::find_flow_holds_one_shard_at_a_time` (timed out on the old
locking); `lru::tests::the_table_hasher_has_no_seed_independent_collisions` (all three
assertions, on the old hasher). `a_sweep_that_freed_something_does_not_hold_the_next_one_back`
and the flow tracker tests pass before and after.

The measurements of items 2 to 4 came from a throwaway test of the public API in the release
profile, not kept in the tree. The machine was shared with other builds, so the numbers carry
some noise; the changes measured are of two or three orders of magnitude.

Cost of the keyed hasher (item 5), the crate's criterion benches (`benches/namespaces.rs`,
`benches/gate.rs`) in three runs in a row, keyed, old, keyed; the lower of the two keyed runs
against the old one, in ns per packet:

| Bench | Old hasher | Keyed hasher |
| --- | --- | --- |
| `baseline/acl_established` | 30.6 | 34.4 (31.4 in an earlier full run) |
| `default/inbound` | 47.9 | 48.8 |
| `default/inbound_established` | 45.3 | 45.8 |
| `default/outbound` | 69.8 | 67.7 |
| `namespaces/inbound` | 178.4 | 169.0 |
| `namespaces/inbound_established` | 48.3 | 47.6 |
| `bypass/inbound_established` | 35.7 | 35.7 |
| `by_source/inbound_established` | 70.3 | 69.6 |
| `stateless/inbound_established` | 47.5 | 47.6 |
| `stateless/inbound_fragment` | 27.0 | 26.8 |

The two keyed runs differ from each other by more than either differs from the old hasher
(the machine was shared), so the cost is at most about 1 ns per packet and not separable from
the noise.

The gates of the crate pass: fmt, `cargo hack clippy --each-feature`, nextest (also
`nsplane-e2e`), doc tests, `cargo deny check`, `cargo shear`, `typos`, `scripts/check-docs.sh`,
`scripts/check-product-terms.sh`.
