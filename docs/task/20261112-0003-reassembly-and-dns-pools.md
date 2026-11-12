# 20261112-0003-reassembly-and-dns-pools Reassembly table and DNS pool fairness

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 00:03

## Description

Audited P3 items in `nsplane-packet` (`reassembly.rs` only) and `nsplane-dns`:

1. A full reassembly table dropped the fragments of every new datagram until an entry timed
   out: 64 junk first fragments stopped reassembly for 30 s, and no source had a share.
2. `FakePool`: one client asking for random names bound every address, and `lookup` (the data
   path) did not refresh a binding, so an address in use was reassigned after its DNS TTL.
3. `Forwarder`: every query started at the first upstream, and with fewer attempts than
   upstreams the later ones were never asked.
4. `Server::pass`: an oversized passed response was cut to the bare header, without the
   question.
5. `build_reply` sets `AA` on every locally built reply: check for a non-authoritative path.

## ActiveForm

Bounding the reassembly table and the fake pool per source, and fixing the forwarder order.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Item 1. `ReassemblyConfig` is not `#[non_exhaustive]`, so the share is derived, not a field:
`max_datagrams / 2`, at least 1. It applies only to a full table: a new datagram replaces the
oldest one of its own source when that source holds the share or more, else the oldest of a
source holding more than half, else the oldest of all. A hard cap per source was rejected: it
would halve the table of a deployment with one source, and it would evict below the bound that
`nsplane-nat` mirrors (`translate/fragment.rs` keeps its own `held` map in step with the
reassembler and refuses a new datagram at `max_entries` before it pushes, so the reassembler
there is never full and never evicts). "Oldest" is the order the datagrams were opened in (a
counter), so equal timestamps do not make it depend on the hash order. The eviction scan is
one pass over the table plus a temporary per-source count, only for a new datagram on a full
table. An evicted datagram disappears like an expired one: its tags go with it
(`discard_tagged` no longer finds it), and its later fragments open a new datagram that
expires. `nsplane-netstack` holds no state per held datagram (its barriers and the `owns`
memory expire on their own), and it maps `overflow` to `reassembly_overflow`: an eviction
counts in the new `ReassemblyStats::evicted` and still in `overflow`, so that counter keeps
showing table pressure without a change outside this crate. `max_datagrams: 0` drops every
fragment as before.

Item 2. `FakePoolConfig` and `FakePoolStats` are exhaustive structs with public fields, so the
limit is a builder (`FakePool::with_client_limit`, getter `client_limit`) and the counter a
method (`FakePool::client_limited`). The default is half of the capacity, rounded up. Only
bindings within their TTL count in effect: at the limit a new name takes the client's own least
recently used binding if that one is unused for `ttl`, so a client that collects names over
days is not refused. A limit of the capacity or more is no limit and keeps the earlier
behaviour and counters exactly. Clients are keyed by IP (IPv4-mapped addresses as IPv4); a
name is owned by the client that created the binding and shared with later askers. `lookup`
now refreshes the binding; `lookup_name` still does not. Four existing tests fill a two-address
pool from one client and now set `with_client_limit(2)`; the assertion that `lookup` does not
refresh was the defect and is gone.

Item 3. `attempts` stays "tries per query in total" and is documented so. The forwarder keeps
the index of the upstream to ask first: the one that answered last, or, after a query whose
attempts all failed, the one after the last it tried (this is what lets later upstreams be
reached with fewer attempts than upstreams). It does not return to an earlier upstream on its
own while the current one answers.

Item 4. The truncated form keeps the original header bytes (plus `TC`, record counts zero) and
appends the response's questions, encoded again without compression; the header alone remains
when the response does not parse or the questions do not fit the limit.

Item 5 is not a defect; nothing changed. No resolver of the crate turns upstream data into
`Answer::Records`: `Forwarder` answers `Answer::Raw` (the upstream's own flags) or
`Code(SERVFAIL)`; `StaticRecords`, `Hosts`, `FakePool`, `NoData` and the policy actions
(records, sinkhole, block, no data, CNAME) answer from local data. The CNAME chain of
`PolicyResolver` puts local CNAME records in front of an upstream response by re-encoding the
parsed upstream packet (`spliced`), which keeps the upstream's flags; only when the answer for
the target is local, or the splice fails and the chain alone is sent, is the reply built with
`AA`. `AA` on local error codes (`SERVFAIL` after a failed forward or a resolve timeout,
`REFUSED`) and `RA` on every local reply are the documented contract of `encode_response`
(`Answer::Records` and `Answer::Code` are local answers) and are pinned by `tests/codec.rs`.

Left undone:

- `nsplane-nat` refuses a new zero-checksum datagram at `max_entries` in its own table, the
  same full-table policy item 1 removed from the reassembler. It is outside this task's files.
- `NetStackStats` has no counter of its own for evictions (they show in
  `reassembly_overflow`).
- The fake pool limit cannot be a `FakePoolConfig` field, nor the counter a `FakePoolStats`
  field, without a breaking change.

## Validation

Seen failing before the fix, passing after:

- `reassembly::tests::full_table_evicts_the_oldest_datagram`,
  `full_table_evicts_from_the_source_over_its_share`,
  `eviction_drops_the_tags_with_the_datagram` (`Dropped` instead of `Held`).
- `fake::one_client_takes_at_most_half_of_the_pool` (third name answered),
  `fake::a_binding_in_use_by_lookup_is_not_the_one_reused` (the busy address was reused).
- `forward::starts_with_the_upstream_that_answered_last` (5 timeouts instead of 1),
  `forward::fewer_attempts_than_upstreams_reach_the_later_ones` (`SERVFAIL` again).
- `passthrough::truncated_passed_responses_keep_the_question` (question count 0).

Written with the fix (they need the new methods or guard the unchanged cases):
`one_source_may_fill_the_table`, `zero_max_datagrams_drops_every_fragment`,
`client_limit_is_configurable_and_counted`, `an_ipv4_mapped_client_is_its_ipv4_address`,
`returns_to_an_earlier_upstream_when_the_last_one_stops_answering`,
`truncated_passed_responses_without_a_readable_question_are_a_header`.

The tests of the reassembler's consumers (`nsplane-netstack`, `nsplane-nat`, `nsplane-e2e`)
pass unchanged.
