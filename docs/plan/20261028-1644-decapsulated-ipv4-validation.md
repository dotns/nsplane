# 20261028-1644-decapsulated-ipv4-validation Validate decapsulated IPv4 header bounds

- **status**: completed
- **createdAt**: 2026-10-28 16:44
- **approvedAt**: 2026-10-28 16:44
- **relatedTask**: 20261028-1644-decapsulated-ipv4-validation

## Context

Copying, in-place and ticket-based receives converge on Tunn::validate_decapsulated_packet. IPv4 lacks IHL and minimum total-length checks. IPv6 already adds the fixed 40-byte header to its payload length. The validator increments plaintext rx_bytes and the data-received timer only after validation. Authenticated packet timers, session confirmation and replay state precede validation, including existing InvalidPacket paths. Core maps errors through opened_outcome to Outcome::Failed before wire-byte accounting, authenticated events and delivery.

## Proposal

Match plaintext ip_source: require header length >= 20 and <= declared total length, retaining the existing total <= buffer check. Exercise malformed IHL/lengths through all three receive APIs, valid options, keepalive and IPv6. Update rustdoc, reference and changelog.

## Risks

Only malformed IPv4 becomes rejected. Preserve authenticated transport state semantics rather than changing replay or session behavior.

## Scope

Noise validator and tests, reference documentation, release notes and PMA records. Audit downstream parse sites; baseline remains pinned to integrated code until this PR merges.

## Alternatives

No shared parser abstraction is needed for the independent plaintext and noise contracts.

## Annotations

Approved by the owner in the task request.
