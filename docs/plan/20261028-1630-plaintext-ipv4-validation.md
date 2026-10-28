# 20261028-1630-plaintext-ipv4-validation Validate plaintext IPv4 and correct metadata

- **status**: completed
- **createdAt**: 2026-10-28 16:30
- **approvedAt**: 2026-10-28 16:30
- **relatedTask**: 20261028-1630-plaintext-ipv4-validation

## Context

`receive_plaintext` alone uses `ip_source`; engine single and batched ingress both call it.
IPv4 misses IHL and minimum total-length validation. IPv6 already requires 40 bytes and
bounds the declared payload. `Tunn::dst_address` is an address extractor used after this
validation; `src_address` is outbound routing only. The encrypted tunnel's
`validate_decapsulated_packet` also lacks IPv4 IHL checks, but is outside plaintext ingress.

No release automation in this checkout consumes the repository field; workspace crates
inherit it as Cargo package metadata. Scripts build release profiles or run gates; releases
are recorded as manual tags and merges in the changelog. Use the public repository's HTTPS URL.

## Proposal

Add ingress regression fixtures first, then require 20 <= IHL*4 <= total length <= buffer.
Cover IPv6 header/payload bounds and valid IPv4 options and trailing padding. Clarify rustdoc.
Correct Cargo repository metadata and the padding comment; no runtime MTU change.

## Risks

Malformed IPv4 previously delivered will now drop before filters. Preserve valid options,
padding truncation, IPv6 zero payload and existing source/destination authorization.

## Scope

Core validation/tests, Cargo metadata, private padding prose, release notes and PMA records.
Baseline follow-ups #743/#744 remain for alignment after integration; do not repin to a PR.

## Alternatives

Weakening the public contract would leave malformed packets reaching filters; rejected by
the approved task. Do not change the encrypted tunnel's separate contract in this patch.

## Annotations

Proposal approved in the task request. No merge, tag or release authorized.
