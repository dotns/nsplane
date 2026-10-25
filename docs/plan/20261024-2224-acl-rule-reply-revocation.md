# 20261024-2224-acl-rule-reply-revocation Revoke reply allowances of rule-accepted flows when their authority is gone

- **status**: completed
- **createdAt**: 2026-10-24 22:24
- **approvedAt**: 2026-10-24 22:40
- **relatedTask**: 20261024-2224-acl-rule-reply-revocation

## Context

GitHub issue #8; reproduction table in the task.

- `ReplyDependency` (`crates/nsplane-acl/src/engine.rs`) has two variants, `Grant` and
  `Pinhole`. `Evaluation::dependency` returns `None` for `Rule` and `NotInstalled`, and the
  bypass path accepts without any evaluation.
- Allowances are recorded in two places (`filter.rs`):
  - outbound allowances of an outbound-restricted peer, by accepted inbound packets
    (`replay`, `allow_restricted_reply`, `evaluate_other_rules`), with the verdict's
    dependency;
  - inbound allowances, by outbound packets (`track_outbound` -> `record_reply`), which
    inherit the dependency of the `pending` entry of the same or reversed tuple. `pending` is
    only filled for grant and pinhole flows.
- `lookup` revokes an allowance only when its dependency is not live in the snapshot; an
  allowance with no dependency is checked against the idle timeout only. Cached verdicts, by
  contrast, carry the policy and identity generations and are re-evaluated on any change,
  which is why the "no response" control is denied.
- `record_reply` rebuilds the entry on every outbound packet, so the allowance's dependency is
  whatever `pending` holds at that moment.
- The crate docs (`lib.rs`, "Other outbound packets to unrestricted peers record allowances
  without a dependency, as they always have") and `docs/reference/nsplane-acl.md` describe the
  current behavior, so the fix is a documented semantic change, not an API change.

## Proposal

Make an allowance created for an inbound flow accepted by the rules depend on that flow, and
re-check the flow when the policy or identity generation it was accepted under changes.

1. `ReplyDependency::Flow(FlowOrigin)` (crate-private). `FlowOrigin` holds the origin peer, the
   inbound `Flow` that was evaluated, and the policy and identity generations it was accepted
   under.
2. Recording: an inbound flow accepted by a rule, by `NotInstalled::Accept` or through bypass
   gets `Flow(origin)` as its dependency, through the existing paths: the `pending` entry of
   its tuple (so the inbound allowance recorded by the local reply, or by forwarding to another
   peer, inherits it) and the outbound allowance of a restricted peer. To bound the cost,
   `pending` is written for such flows only while no allowance exists for the key (the
   packets before the first reply, and one-way flows), and an allowance hit does not rewrite
   `pending` for a `Flow` dependency.
3. `record_reply`: refreshing an existing allowance keeps its dependency when the newly
   computed one is `None`, so a `Flow` (or grant) dependency is not lost when `pending` idles
   out on a long flow.
4. `lookup`: an allowance with a `Flow` dependency whose generations equal the current ones is
   live (two integer compares on the hit path). Otherwise the origin flow is evaluated again
   from its peer under the current snapshot, without side effects: accepted by a rule ->
   generations refreshed; accepted through a grant or pinhole -> dependency replaced by that
   one; denied -> allowance removed and counted in `AclFilterStats::reply_revoked`. With an
   unversioned identity (generation 0) the origin is evaluated on every hit, as every packet
   is already evaluated in that mode.
5. Unchanged: allowances of flows the local node opened (no `pending` entry, so no
   dependency) still pass the replies of local connections; grant and pinhole revocation;
   scope-accepted and `allow_other_protocols` packets.
6. Docs: `lib.rs` revocation section and "Flow verdict cache" bullet,
   `docs/reference/nsplane-acl.md`, `CHANGELOG.md` (Fixed), `docs/changelog.md`.

Tests (RED first, in `filter.rs`):

- the five cases of the task table, plus: forwarded flow `A -> C` under a namespace rule stops
  passing `C`'s replies to `A` after the rule is removed; an unrelated policy change (another
  namespace) keeps the flow; a local-originated flow to an unrestricted peer keeps its replies
  across a policy change; a flow whose rule is replaced by a grant keeps working and becomes
  grant-dependent; idle `pending` does not drop the dependency on a long flow.
- `differential.rs` keeps verdicts equal to a full evaluation (existing property test, plus a
  policy change mid-sequence if it does not already do so).
- Bench gate: `crates/nsplane-acl/benches` established-flow and new-flow cases, A/B against
  main through the bench slot script; an established-flow regression beyond noise is reported
  before merging.

## Risks

- Data-path cost: one generation compare per allowance hit, and `pending` writes for
  rule-accepted flows before their first reply. Measured by the bench gate.
- After any policy change, each live allowance is re-evaluated once on its next hit (a burst of
  evaluations proportional to active flows, spread over traffic, under the flow-table lock as
  today's re-evaluation of cached verdicts).
- Behavior change: deployments relying on established flows surviving a policy that no longer
  accepts them will see those flows cut. This is the requested semantics; noted under Fixed in
  the changelog.
- A local-originated flow whose reverse direction the inbound rules also accept when its first
  packet leaves can pick up a `Flow` dependency through `pending` only if an inbound packet of
  that tuple was evaluated first; otherwise it stays dependency-free. No false revocation of a
  local connection is expected; covered by a test.

## Scope

`crates/nsplane-acl/src/engine.rs`, `crates/nsplane-acl/src/filter.rs` (logic and tests),
`crates/nsplane-acl/src/lib.rs` (docs), `docs/reference/nsplane-acl.md`, `CHANGELOG.md`,
`docs/changelog.md`. No public API change; ships in a minor release. Estimated 150-250 lines
of code plus tests.

## Alternatives

- **Flush all dependency-free allowances on any generation change.** Simple, but cuts every
  established flow (including local connections and flows still authorized) on each policy or
  identity update; rejected by the issue's criteria.
- **Explicit invalidation API** (e.g. `AclFilter::revoke_peer(peer)`): no data-path cost and no
  semantic change, but every caller must know what to revoke and when, and it is coarse
  (per peer). Could be added later on top of this fix if a caller needs immediate cleanup
  instead of lazy revocation.
- **Document as caller-managed** (rebuild the filter): no code change; does not meet the
  acceptance criteria.

## Annotations

- Implementation deviates from Proposal step 2: recording the flow dependency in `pending` on
  every inbound packet cost up to +50 ns per packet (bench A/B), so a flow to the local node
  keeps its dependency in the verdict cache and the restricted peer's outbound allowance only,
  and a new inbound allowance without a pending dependency derives it once from the inbound
  policy (`inbound_origin`). `pending` carries the flow dependency only for flows forwarded to
  another namespace member (also through bypass), symmetric between an allowance hit and an
  evaluation so the cached and uncached filters stay equal. Limitation: under the default rules
  the replies of a flow forwarded between two peers are not tied to it.
- `Snapshot::hosts` uses `FlowHash` to keep the member lookup of bypass packets cheap.
