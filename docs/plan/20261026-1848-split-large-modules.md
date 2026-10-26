# 20261026-1848-split-large-modules Split the largest modules by responsibility and share e2e scenario setup

- **status**: proposed
- **createdAt**: 2026-10-26 18:48
- **relatedTask**: 20261026-1848-split-large-modules

## Goal

Each of the five modules becomes a directory module whose files hold one responsibility each,
none of them far above ~600 non-test lines, with inline tests moved next to the code they test
(`<module>/tests.rs` or per-submodule test files). Pure moves: no behavior, public API,
visibility widening beyond `pub(crate)` / `pub(super)`, or algorithm change. The e2e tests
share their repeated scenario setup through helpers in the e2e crate.

## Work

| Step | Work | Verify |
| --- | --- | --- |
| S1 | `nsplane/src/engine.rs` and `nsplane/src/udp.rs` split (e.g. `engine/{mod,run,inbound,outbound,timers,...}.rs`, `udp/{mod,send,recv,offload,icmp,...}.rs`; the issue proposes the cut) | full gate; send/receive benches A/B |
| S2 | `nsplane-netstack/src/stack.rs` split (it already has a `stack/` directory for tests) | full gate; `send_stream` bench A/B |
| S3 | `nsplane-acl/src/filter.rs` split, inline tests moved to test files | full gate; `gate` / `namespaces` bench A/B |
| S4 | `nsplane-core/src/core.rs` split; e2e: shared scenario helpers for the repeated `redirect*`, `translate*`, `acl_*` setup (and `netstack_buffers` / `netstack_lossy`) | full gate; `data_path` / `handshake` bench A/B |

Per step, before code moves: the proposed file layout (file, responsibility, approximate
lines) goes to L1 for review. After: `git diff --stat` shows moves (`git log --follow` /
`git diff -M` detect them), the public API is unchanged (a
reviewer check of the `pub` items), and hot-path benches are compared interleaved against `main` through
`scripts/bench/slot.sh`. A delta beyond noise is a blocker (inlining across module
boundaries is the usual cause; `#[inline]` where the old code relied on it).

## Constraints

- Refactor only; no new dependency; docs under `docs/` updated only where they name a moved
  file path.
- Gate: `just check`, `cargo doc -D warnings`, `just cross`, `just test-windows`.
