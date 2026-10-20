# 20261020-1000-macos-quality-gates Make native macOS quality gates executable

- **status**: completed
- **priority**: P2
- **owner**: a/macos-gates-20261020
- **createdAt**: 2026-10-20 10:00 UTC

## Description

The native macOS quality gate has platform-specific failures reproduced while validating the UDP error recovery repair. The user approved this follow-up after reviewing the UDP repair. See [the implementation plan](../plan/20261020-1154-macos-quality-gates.md).

## Evidence

- On unmodified 82cbece, `boolean_environment_variables_accept_1` and `a_closed_fd_fails_startup` fail because `nsplane-clitest` is not a valid macOS TUN name; argument validation occurs before the behavior under test.
- On the same base, `oversize_reads_are_dropped_and_counted` fails at the fixture's Unix datagram send with `Message too long`, before the read/drop assertion.
- The unchanged `scripts/check-docs.sh` fails with the native macOS awk parser at the conditional expression passed to `printf`.
- The WSS fixture failure was reproduced and repaired separately in [20261020-1026-synchronize-regression-fixtures](20261020-1026-synchronize-regression-fixtures.md); it is not part of this portability follow-up.

## Acceptance

- [x] Native macOS fixtures reach and verify their intended behavior without relaxing product validation.
- [x] The documentation check runs with the supported native macOS tools or documents an explicit portable tool prerequisite.
- [x] Native `just check` passes, with unrelated transient failures retained as evidence.

## ActiveForm

Completed: native macOS quality gates pass; runtime behavior and existing assertions are preserved.

- complete: Native macOS just check passed: 1909 tests passed, 8 configured skips; focused CLI/TUN suites passed 85 tests; documentation self-tests passed on macOS and Linux.

## Validation

- Native aarch64 macOS, pinned Rust 1.99.0: `just check` exited 0.
- Workspace tests: 1909 passed, 8 configured skips; no additional tests skipped.
- All feature-combination Clippy checks, doctests, dependency checks, spelling, Rust 1.95 MSRV, examples, product terms and documentation gates passed.
- CLI and TUN focused suites: 85 passed.
- Documentation self-tests: macOS system Bash 3.2/native awk, installed Bash, and Linux Bash/awk passed, including empty source and decision-document lists.
- Documentation gate and report mode also passed with system Bash.
- Local review found no additional defects; no runtime or dependency files changed.
