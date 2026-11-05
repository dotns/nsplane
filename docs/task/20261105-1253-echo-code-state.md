# 20261105-1253-echo-code-state Enforce Echo code and state correlation

- **status**: completed
- **priority**: P1
- **owner**: repository-maintainers
- **createdAt**: 2026-11-05 12:53

## Description

Require code zero for IPv4 and IPv6 Echo requests and replies before flow admission or
state reuse. Reject incorrect types and directions when reusing Echo state. Preserve
TCP/UDP behavior, unrelated ICMP errors, PMTU and existing fragment correlation.

## ActiveForm

Validating Echo authorization and state reuse.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Validation

Prior validation of the implementation reproduced three failures: nonzero-code request
admission, nonzero-code state reuse and incorrect-direction Echo reuse. The corrected
implementation passed all seven focused regressions and all 330 ACL tests. The reference
model retains its seeds, test populations and assertions with the corrected direction rule.

The workspace checks passed, including 2496 tests with 34 existing ignored tests, formatting,
per-feature clippy, doctests, dependency checks, spelling, MSRV, examples and documentation.
Public APIs, protocol encodings and dependencies are unchanged.
