# 20261026-0837-scoped-flowgate nsplane-acl: scope-qualified flow gate decisions

- **status**: completed (integrated into 0.20.0)
- **priority**: P1
- **owner**: feat/scoped-flowgate
- **createdAt**: 2026-10-26 08:37
- **relatedPlan**: 20261026-0822-node-gateway-requests

## Description

Request R3 of task `20261026-0819-node-gateway-requests`, workstream W2 of plan
`20261026-0822-node-gateway-requests` (release 0.20.0). A consumer needs a `FlowGate` decision
that is valid only for a scope or set of scopes it selects: inside the selection the normal
decision, outside a distinct enforced denial that creates, refreshes or migrates no state; an
empty selection is refused; the result names the deciding `ScopeId`, the `RuleId` (also for
`ValidState`) and the policy generation.

Owner decisions: O4, a later fragment's scoped decision reports `rule: None`; O5, `OutOfScope`
denials count as enforced denials and emit decision events, without a new `GateCounters` field.

Acceptance criteria:

- `ScopeSelection` (`one`, `any_of` refusing an empty set with `EmptySelection`),
  `ScopedDecision` (`decision`, `scope`, `rule`, `generation`),
  `FlowGate::evaluate_inbound_in` / `evaluate_outbound_in` and `GateReason::OutOfScope`, as
  the plan specifies.
- The decision table of the plan: resolved scope in the selection, outside it, no scope
  (unbound, unbound pass rules, inert gate, other IP version), held, ambiguous, malformed.
- A scoped call never reads or writes state of a scope outside the selection.
- `evaluate_inbound` / `evaluate_outbound`, `GateFilter` and `find_flow` unchanged; the
  existing suite passes unmodified.
- Slot A/B of the `gate` bench (`established/gate`, `established/outbound`,
  `established/filter`, `baseline/pass_gate`) within noise; new `scoped/established` and
  `scoped/out_of_scope` cases.
- `docs/reference/nsplane-acl.md` and `CHANGELOG.md` updated.

## ActiveForm

Adding scope-qualified flow gate decisions

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- Design: a new `gate/scoped.rs` holds `ScopeSelection`, `EmptySelection`, `ScopedDecision`
  and the `evaluate_*_in` entries. The selection reaches `evaluate_once` as an `Option` in
  `PacketInput`; the check sits after the scope is resolved (`bound_scope`, step 4) and before
  any state is read. The flow's grant of a `ValidState` packet or a quoted flow is reported
  from the same state lookup; later fragments report no grant (O4). `OutOfScope` denials go
  through `record_decision` and `emit_event` like every denial (O5).
- A const-generic variant (a separate scoped monomorphization of the evaluation) was measured
  and rejected: with LTO and one codegen unit the second caller made LLVM outline the shared
  helpers (`GateAddr::quote`, `related_flow_key`, `malformed_decision`), costing about +6 ns
  on `icmp_error/v6`, and `#[inline]` hints only moved the outlining down the call chain. A
  first runtime variant with a generic family loop had `evaluate_once` called from two
  instantiations and measured +10 to +13 ns on `established/gate`. The shipped variant keeps
  one evaluation body (`evaluate_with`, out of line as on main).
- Bench (slot 0, CPUs 1-3, interleaved A/B, two rounds, main 52eb983 against the branch, load
  4.2-5.5), `cargo bench -p nsplane-acl --bench gate`, means in ns:
  `established/gate` 41.74 / 41.94 -> 42.71 / 42.29; `established/outbound` 41.86 / 41.93
  -> 42.76 / 42.47; `established/filter` 46.72 / 46.53 -> 47.01 / 47.16;
  `baseline/pass_gate` 0.67 / 0.64 -> 0.63 / 0.64; `established/gate_v6` 51.36 / 50.30 ->
  51.85 / 51.47; `established/outbound_v6` 51.18 / 50.09 -> 52.21 / 51.57;
  `new_flow/any_grant` 87.83 / 86.45 -> 89.67 / 89.25; `fragment/later_v6` 44.67 / 44.96 ->
  46.50 / 47.28; `icmp_error/v6` 48.63 / 49.14 -> 50.77 / 50.53. New: `scoped/established`
  59.87 / 59.49, `scoped/out_of_scope` 26.29 / 26.55. Established flows +0.5 to +1 ns
  (1-2 %), new flows, later fragments and ICMP errors +1.5 to +2.5 ns, the inert gate
  unchanged.
- Gate: `just check` stopped at `test` with 5 of 2364 failing outside nsplane-acl: two
  nsplane-dns tests on `AddrInUse` (pass on rerun) and `nsplane` `burst_fits_default_buffer`
  and `nsplane-e2e` `offload_udp` `bulk_transfer_ipv{4,6}_offload_on_on_workers` on 5 s
  timeouts at a host load near 20; main 52eb983 fails the same tests on the same host. The
  remaining recipes (doc-test, deny, shear, typos, msrv, examples, product-terms, docs) pass;
  fmt and clippy passed before `test`.
