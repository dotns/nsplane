# 20261028-1630-plaintext-ipv4-validation Validate plaintext IPv4 and correct metadata

- **status**: completed
- **priority**: P2
- **owner**: plaintext-validation/748
- **createdAt**: 2026-10-28 16:30

## Description

Resolve tk #748 and #749: validate IPv4 header bounds before plaintext ingress checks,
verify IPv6 bounds, correct repository metadata and document the inner MTU floor.
Acceptance: RED regression tests, GREEN focused tests, `just check`, branch and PR into main.

## ActiveForm

Validating plaintext ingress and repository metadata.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Full tier. The owner approved this scope and the proposal gate in the task request.
Base: b7ca03a (0.21.0). Independent clone; build concurrency capped at six.

- RED: `cargo test -p nsplane-core --lib plaintext_ --locked` failed on zero IHL;
  three other selected tests passed. GREEN: all eight `core::tests::plaintext` tests pass.
- Added three table-driven tests: malformed IPv4 IHL/total/header bounds (also no filter,
  delivery or data accounting); valid base/options-only IPv4 and padding; IPv6 short header,
  oversized payload, zero payload and padding.
- Encrypted `Tunn::validate_decapsulated_packet` has the same IPv4 bounds gap; tracked as
  tk #754, outside this plaintext contract. No other plaintext ingress parser needs a fix.
- Baseline follow-ups tk #743/#744 carry alignment notes for after integration.

- `just check`: passed with `CARGO_BUILD_JOBS=6`; 2,458 tests passed, 34 skipped;
  doctests, feature clippy, dependency checks, typos, MSRV, examples, product terms and docs
  passed. Initial clippy reported two empty-vector assertions in the new tests; corrected
  to equality assertions before the successful full run.
- Local diff review: all changed code, tests and documentation inspected against b7ca03a;
  no remaining findings. IPv4 header bounds compose with the final total-length bound;
  valid options and IPv6 behavior are unchanged. Cargo metadata confirms the repository URL.

- complete: RED/GREEN verified; full just check and local review passed.
