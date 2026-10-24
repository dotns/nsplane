# 20261024-1453-smoltcp-upstream-fixes smoltcp fork: rebase onto upstream main and reapply the fork patches

- **status**: proposed
- **createdAt**: 2026-10-24 14:53
- **relatedTask**: 20261024-1453-smoltcp-upstream-fixes

## Work

| Step | Work | Verify |
| --- | --- | --- |
| F1 | In a local clone of `github.com/dotns/smoltcp`: branch `nsplane/upstream-24bda3b` from upstream `main` `24bda3b`; reapply the fork's patches of `v0.14.0-nsplane.1` to `.6` in order. A patch upstream now covers (`8c74844` vs `bd424c8`, `998d9f9` vs `bfe5f95`, window edge vs `336a1dd`) is dropped or reduced to what upstream lacks, with the reason in the report; conflicts with the RTO bounds (RTT estimator, tail loss probe timer) are resolved so both work. Every remaining patch keeps its regression test | smoltcp's own test suite (features nsplane uses and default features) |
| F2 | `nsplane-netstack` against the branch through a temporary `[patch]`: adapt to the API changes; `NetStackConfig` gains the TCP RTO bounds (minimum, maximum, initial), applied to every TCP socket, validated, defaults equal to smoltcp's (behavior unchanged unless set); full gate, `tests/netstack_lossy.rs` | gate green; unit test that the bounds reach the socket |
| F3 | Performance: A = `v0.14.0-nsplane.6`, B = the branch with default RTO bounds, interleaved A/B per invocation on one slot of `scripts/bench/slot.sh` (120 s between invocations): netstack throughput rows of `docs/architecture.md` (loss-free, bottleneck, lossy), `nsplane-netstack` criterion benches, `netstack_lossy` timings; plus one lossy run of B with a low minimum RTO to show the effect of the bounds | numbers in the report; a regression beyond noise is reported to L1 before any workaround |
| F4 | After L1 has pushed the branch and tag `v0.14.0-nsplane.7`: dependency and lock on the tag, `[patch]` removed, ADR `2026-10-03-smoltcp-fork` section for `.7` (new base, patches kept / dropped), reference `nsplane-netstack` (RTO bounds), CHANGELOG `[Unreleased]` | full gate, `just docs` |

## Constraints

- The RTO bounds are a feature by owner exception (freeze amendment 10); the rest are fixes.
- The issue does not push to `github.com/dotns/smoltcp`; L1 reviews the branch and pushes it
  and the tag.
- No new dependency. Gate: `just check`, `cargo doc -D warnings`, `just cross`,
  `just test-windows`.
