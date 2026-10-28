# 20261028-1644-decapsulated-ipv4-validation Validate decapsulated IPv4 header bounds

- **status**: completed
- **priority**: P2
- **owner**: encrypted-ipv4-validation/754
- **createdAt**: 2026-10-28 16:44

## Description

Resolve tk #754: require IHL >= 5 and header length <= total length <= buffer on encrypted IPv4 ingress. Preserve keepalive, IPv6 and existing InvalidPacket accounting semantics. Add failing tests first, align documentation and run `just check` with at most six build jobs.

## ActiveForm

Validating encrypted IPv4 header bounds.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Owner approved the scope and proposal gate in the task request. Base: main b91e00a8.

RED: `cargo test -p nsplane-noise decapsulated_ -j 6` failed on IHL=0,
total=20 being delivered (two positive/unchanged-contract tests passed).
GREEN: `cargo test -p nsplane-noise -j 6` passed all 58 tests. The rejection
matrix covers copying, in-place and deferred ticket receive APIs; asserts no
plaintext byte or data-timer increment and preserves the authenticated-packet timer.

Audit: `job::opened_outcome` maps InvalidPacket to Failed; `Core::opened` logs
`Decapsulate error` and emits DECAPSULATE_ERROR before peer wire-byte accounting,
authenticated-message notifications, filters and delivery/data-byte accounting.
`Tunn::dst_address` only extracts a fixed-offset address; its encrypted receive
caller runs after validation, so it needs no extra validation. The independent
`nsplane_packet::Ipv4Header::parse` already enforces the bounds. IPv6 includes
its fixed header in computed length, so no analogous change is required.
No other parser was changed. Baseline follow-up noted on existing tk #743,
to be re-verified against integrated code rather than an unmerged branch.

- complete: RED reproduced; all 58 noise tests and just check passed with six build jobs (2,461 workspace tests passed, 34 skipped). Local diff review: PASS, no findings.
