# 20261106-2327-tcp-zero-checksum Accept zero TCP and ICMP checksums

- **status**: completed
- **createdAt**: 2026-11-06 23:27
- **approvedAt**: 2026-11-06 23:27
- **relatedTask**: 20261106-2327-tcp-zero-checksum

## Context

The RFC 7915 translator rejects zero TCP fields in both directions. ICMP quotation translation has the same check. Masquerade rejects zero TCP/ICMPv6 fields and normalizes their computed zero to 0xffff. RFC 1624 helpers and protocol-specific finish helpers already preserve zero correctly.

## Proposal

Limit absent/invalid zero-field tests and zero-to-0xffff mapping to UDP. Preserve sum verification. Establish RED with valid zero fields, corrupt controls, incremental zero outputs accepted at the next hop, ICMP quotations, UDP controls and a real user-space TCP transfer with a calculated zero-producing payload.

## Risks

UDP zero has distinct family-dependent semantics; retain and test these. Partial TCP fragments and quoted headers cannot be fully verified and retain their existing incremental translation behavior.

## Scope

NAT translator, ICMP quotation translation, masquerade, regression tests, reference documentation and tracking. Audit packet, netstack and engine checksum paths. No dependency changes or disabled verification.

## Alternatives

Normalizing TCP to 0xffff or disabling checksum verification is excluded by the task contract.

## Annotations

The task request approves implementation and opening a PR against main. Downstream revision updates require confirmation that this PR merged.

Verification: RED captured five failing NAT regressions and both user-space TCP failures. The complete `just check` gate passed after an unrelated DNS port collision was reproduced on the unchanged base. Final-commit acceptance is recorded with the PR.
