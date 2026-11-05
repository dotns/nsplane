# 20261105-1253-echo-code-state Enforce Echo code and state correlation

- **status**: completed
- **createdAt**: 2026-11-05 12:53
- **approvedAt**: 2026-11-05 12:53
- **relatedTask**: 20261105-1253-echo-code-state

## Context

The Gate parser omitted ICMP code validation. Existing flow lookup could accept an Echo
packet with a nonzero code or reuse an identifier with the wrong type or direction.
The packet Echo helper does not enforce the Gate's stateful authorization path.

## Design

Reject nonzero codes for IPv4 Echo types 8/0 and IPv6 Echo types 128/129 in Gate parsing,
before authorization or state access. Apply the same check behind IPv6 extension headers
and in first fragments. Keep other ICMP codes unchanged.

Before refreshing existing Echo state, require the original request type in its initiating
direction or the matching reply type in the reverse direction. Retain the existing scope,
peer, address, family and identifier correlation. Related errors continue through their
quoted-flow path; later fragments retain first-fragment correlation.

## Compatibility

No public API, policy encoding, dependency or version change is required by the repair.
Malformed Echo is rejected even under a broad grant. Other ICMP codes and error/PMTU
handling retain their existing behavior. Observe and pass behavior remain governed by
existing scope modes; Enforce or explicit scoping is required for authoritative denial.

## Scope

Gate parsing and established-state checks, focused regression tests, the independent
reference model and public Gate documentation. No reassembly redesign or TCP/UDP change.

## Alternatives

A new public code matcher would require an API change and still need a state-reuse guard.
Checking only the packet Echo helper would miss Gate authority and IPv6 extension chains.
Rejecting every nonzero ICMP code would break unrelated errors.

## Validation

Prior validation reproduced three failures before the repair and passed all seven focused
regressions afterward. Cases cover both IP families and initiating directions, all nonzero
codes, truncated headers, state reuse and expiry, mismatched identifiers and peers, wrong
types and directions, IPv6 extensions, fragments, scope refusal and unrelated ICMP errors.

All 330 ACL tests passed with none skipped. The full workspace checks passed with 2496
tests and 34 existing ignored tests. The reference-model update preserves its seeds,
population sizes and assertions. No test ignores or quality gates were changed.
