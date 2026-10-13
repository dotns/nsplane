# 20261013-1330-snapshot-cell-read-cost Restore 0.12 read cost after the arc-swap removal

- **status**: approved
- **createdAt**: 2026-10-13 13:30
- **approvedAt**: 2026-10-13 (owner: optimize now that the host is quiet; a fix of a 0.13.0 regression, so
  allowed under the freeze)
- **relatedTask**: 20261012-1830-no-arc-swap (performance pass)

## Context

The quiet performance pass of 0.13.0 ran on 2026-10-13. A = v0.12.0, B = v0.13.0, interleaved, 3
rounds, slots 0/1, load 0.6-2.7 during gate/translate/data_path, up to 10.9 at the end of
namespaces. Logs are in `.tmp/perf-*.log`.

| Case | 0.12.0 | 0.13.0 | Delta |
|---|---|---|---|
| namespaces `floor/snapshot` (one engine snapshot load) | 9.0 ns | 16.2 ns | +7.2 ns |
| gate `established/gate` | 50.1 ns | 55.2 ns | +10.2 % |
| gate `established/filter` | 52.8 ns | 60.7 ns | +15.0 % |
| gate `baseline/acl_established` | 36.7 ns | 44.5 ns | +21.3 % |
| translate `eam4_out/udp/64B/1` | 43.3 ns | 49.4 ns | +14.0 % |
| translate `eam4_in/udp/64B/1` | 58.0 ns | 64.6 ns | +11.5 % |
| namespaces `other/icmp_echo_scope` | 39.6 ns | 51.1 ns | +29.1 % |
| data_path (core; no cell) | 532.5 ns | 535.7 ns | +0.6 % (par) |

Every `SnapshotCell::load` (a shard read lock, an `Arc` clone, an unlock and a drop) costs about
7 ns more than arc-swap's load, and a packet loads one to three cells. The A spread is 0.2-1.9 %
on these rows. The IPv6 gate numbers (B only) are 53.6-109.0 ns.

## Work (one L2)

1. Design note to L1. A cheaper read path in `nsplane_core::cell`, safe and std-only. The
   candidate is GF-4's `ScopeCell` pattern generalized:
   - a published generation (Acquire);
   - a small fixed-size per-thread cache keyed by a never-reused cell id;
   - a closure read that lends `&T` without a refcount or lock on a hit;
   - a fall back to the shard load on a miss or a nested borrow.
   The note covers:
   - the cache size, given that a packet touches several cells, and its eviction;
   - the bounded retention of old values per thread;
   - correctness ordering, which must not regress the guarantees of AS;
   - which call sites move to the closure read;
   - whether `ScopeCell` folds into it.
2. Implementation, unit tests (the existing cell tests plus several cells interleaved on one
   thread, nested reads, replace under load) and moving the hot call sites:
   - acl: engine snapshot, gate snapshot, filter scopes;
   - nat: translate, LAN routes.
3. Slot A/B against v0.12.0 and v0.13.0 of the rows above. The target is 0.12.0 par within
   max(2 %, spread).

## Annotations
- 2026-10-13: dispatched OP `gcxn1i1c` (campaign `nsplane-op-202610131330`).
- 2026-10-13: OP design note approved.
  - `SnapshotCell::read(|&T| ..)`: a published generation (Acquire), and a per-thread cache of
    4-8 entries keyed by a never-reused cell id that holds an `Arc<dyn Any>`. A hit costs no
    refcount and no lock; a miss loads the shard until the generation matches.
  - A writer mutex inside the cell makes concurrent stores safe.
  - Retention is bounded (at most 8 values per thread).
  - `ScopeCell` folds in.
  - The hot call sites in acl and nat move to `read`.
  - An e2e test checks replaces under traffic.
- 2026-10-13: OP A/B, invocations 1-4. B = f33360d.
  - Improvements:
    - `floor/snapshot` 8.8 -> 2.9 ns (0.12.0) and 15.8 -> 2.9 ns (main);
    - `icmp_echo_scope` -6.4 % against 0.12.0;
    - most filter and namespaces rows 5-15 % faster than 0.12.0.
  - Residuals:
    - `stateless/inbound_fragment` +2.7 ns against main. OP-4 fixes it (filter.rs, fragment early
      return).
    - Gate `established/*` +3.4..6.7 % against 0.12.0, but 4-10 % better than main. Accepted and
      attributed to the 0.13.0 peer-keyed gate (probable, not isolated).
