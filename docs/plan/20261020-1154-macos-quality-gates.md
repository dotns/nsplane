# 20261020-1154-macos-quality-gates Restore native macOS quality gates

- **status**: completed
- **createdAt**: 2026-10-20 11:54 UTC
- **approvedAt**: 2026-10-20 11:54 UTC
- **relatedTask**: 20261020-1000-macos-quality-gates

## Context

On the repair branch, both CLI integration failures stop at interface-name parsing
instead of descriptor validation. The slot test sends a 5000-byte Unix datagram that
exceeds the native macOS socket limit before its oversize-drop assertions run.
The documentation checker fails to parse a conditional printf argument in native awk
and uses mapfile, which is unavailable in the system Bash 3.2.

## Proposal

Use a valid platform-specific interface name and require the boolean environment
tests to reach descriptor validation. Keep both slot oversize cases: exactly MTU + 1
and larger than the read buffer, with portable datagram sizes. Parenthesize the awk
conditional and collect file arrays using Bash 3.2-compatible loops.

## Scope

One native macOS gate repair block covering the two test fixtures and documentation
script, with task records. No runtime, dependency, public API, merge or release changes.
The user approved implementation, verification, commits and branch pushes.

## Risks

Fixture changes must retain the tested failure boundary, packet truncation behavior,
drop counts and surviving packet contents. Script changes must retain finding,
malformed-input and clean-tree exit codes, including empty file arrays.

## Alternatives

Skipping platform tests, weakening product validation, changing host socket limits,
or requiring GNU awk would conceal or work around the failures instead of repairing
the fixtures and native tooling support.

## Validation

- [x] Reproduce all three native Rust test failures and documentation self-test failure.
- [x] Pass the affected crate suites and documentation self-tests with system tools.
- [x] Pass native macOS just check.
- [x] Review the complete diff; no additional findings.

Evidence: the affected CLI and TUN suites pass all 85 tests. The documentation self-test
passes with macOS system Bash 3.2/native awk, the installed Bash, and Linux Bash/awk.
The native documentation gate and report mode both pass.

The native full gate exited 0: 1909 tests passed with 8 configured skips, all Clippy
feature combinations, doctests, dependency checks, spelling, Rust 1.95 MSRV, example
builds, product terms and documentation checks passed. No runtime or dependency
changes were needed. Delivery remains limited to committing and pushing the repair
branch; merging and releasing are not authorized.
