# 20261026-1848-split-large-modules Split the largest modules by responsibility and share e2e scenario setup

- **status**: completed (all four steps merged 2026-10-26)
- **priority**: P3
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-26 18:48
- **plan**: 20261026-1848-split-large-modules

## Description

A pma-rust audit found 25 source files above the baseline's ~600-line module guideline. Five
hold several responsibilities each: `nsplane/src/engine.rs` (2769 non-test lines),
`nsplane-netstack/src/stack.rs` (2685), `nsplane-acl/src/filter.rs` (2608, plus about 3900
lines of inline tests), `nsplane/src/udp.rs` (1954) and `nsplane-core/src/core.rs` (1657).
Duplicate code is small; only the e2e scenario setup (40-57 line blocks repeated across
`redirect*`, `translate*` and `acl_*` tests) is worth sharing. The owner asked to do both.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
