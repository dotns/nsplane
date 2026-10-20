# 20261020-1000-macos-quality-gates Make native macOS quality gates executable

- **status**: pending
- **priority**: P2
- **owner**: (unassigned)
- **createdAt**: 2026-10-20 10:00 UTC

## Description

The native macOS quality gate has platform-specific failures reproduced while validating the UDP error recovery repair. These are outside that repair's implementation scope. No product or fixture changes are included for this follow-up.

## Evidence

- On unmodified 82cbece, `boolean_environment_variables_accept_1` and `a_closed_fd_fails_startup` fail because `nsplane-clitest` is not a valid macOS TUN name; argument validation occurs before the behavior under test.
- On the same base, `oversize_reads_are_dropped_and_counted` fails at the fixture's Unix datagram send with `Message too long`, before the read/drop assertion.
- The unchanged `scripts/check-docs.sh` fails with the native macOS awk parser at the conditional expression passed to `printf`.
- The WSS fixture failure was reproduced and repaired separately in [20261020-1026-synchronize-regression-fixtures](20261020-1026-synchronize-regression-fixtures.md); it is not part of this portability follow-up.

## Acceptance

- [ ] Native macOS fixtures reach and verify their intended behavior without relaxing product validation.
- [ ] The documentation check runs with the supported native macOS tools or documents an explicit portable tool prerequisite.
- [ ] Native `just check` passes, with unrelated transient failures retained as evidence.

## ActiveForm

Awaiting scope approval for native macOS gate portability.
