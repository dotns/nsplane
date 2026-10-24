# 20261024-1453-smoltcp-upstream-fixes smoltcp fork: upstream TCP fixes since v0.14.0

- **status**: proposed
- **createdAt**: 2026-10-24 14:53
- **relatedTask**: 20261024-1453-smoltcp-upstream-fixes

## Work

| Step | Work | Verify |
| --- | --- | --- |
| F1 | Branch `nsplane/v0.14-upstream` from tag `v0.14.0-nsplane.6` in a local clone of `github.com/dotns/smoltcp`: cherry-pick `336a1dd` with its test; compare `bd424c8` with the fork's `8c74844` and `bfe5f95` with `998d9f9` (and the tail loss probe of `.6`), take only what the fork lacks, adapted to the fork's timers, each with upstream's regression test or an equivalent | smoltcp's own test suite (`cargo test` with the features nsplane uses and the default features) |
| F2 | nsplane-netstack against the branch through a temporary `[patch]` to the local clone: full gate, `tests/netstack_lossy.rs` | gate green |
| F3 | Performance: A = `v0.14.0-nsplane.6`, B = the branch, interleaved A/B per invocation on one slot of `scripts/bench/slot.sh` (120 s between invocations): the netstack throughput measurement of `docs/architecture.md` (loss-free, bottleneck and lossy rows), the `nsplane-netstack` criterion benches and `netstack_lossy` timings | numbers in the report; a regression beyond noise is reported to L1 before any workaround |
| F4 | After L1 has pushed the branch and tag `v0.14.0-nsplane.7`: dependency and lock moved to the tag, the `[patch]` removed, ADR `2026-10-03-smoltcp-fork` section for `.7`, CHANGELOG `[Unreleased]` Fixed | full gate, `just docs` |

## Constraints

- Bug fixes only (feature freeze); the per-socket RTO bounds stay out.
- The issue does not push to `github.com/dotns/smoltcp`; L1 reviews the branch and pushes it
  and the tag.
- No new dependency. Gate: `just check`, `cargo doc -D warnings`, `just cross`,
  `just test-windows`.
