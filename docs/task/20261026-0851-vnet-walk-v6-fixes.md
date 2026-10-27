# 20261026-0851-vnet-walk-v6-fixes Fix vnet IPv4 IHL 10 segmentation and the walk_v6 later-fragment header limit

- **status**: completed (release 0.19.4 prepared, not tagged; integrated into 0.20.0)
- **priority**: P1
- **owner**: fix/0.19.4-vnet-walk-v6
- **createdAt**: 2026-10-26 08:51
- **relatedPlan**: 20261026-0822-node-gateway-requests (W0, release A)

## Description

Release A (0.19.4) of plan `20261026-0822-node-gateway-requests`, approved by the owner on
2026-10-26 as a bug-fix release, including the D2 behaviour change. Defects D1 and D2 of task
`20261026-0819-node-gateway-requests`.

- D1, `nsplane-packet` `vnet`: an IPv4 GSO super-packet with IHL 10 (40-byte header) was
  segmented as IPv6, because `fix_segment` and `pseudo_sum` chose the branch by header length.
  They now take the IP version `segment` already knows. `nsplane-tun` `offload.rs`
  (`Coalescer::finish`, `checksum_valid`, `pseudo_sum`) gets the same change for consistency:
  the group keeps the version `classify` computed.
- D2, `nsplane-acl` `walk_v6`: the loop ran nine iterations and returned on a later Fragment
  header, so a ninth header passed. It now consumes at most eight headers, the Fragment header
  included, and reads the upper layer after the loop.

Acceptance criteria:

- Regression tests from the reproductions fail before the change and pass after it:
  `vnet::tests::segments_ipv4_with_twenty_option_bytes` (TCP and UDP),
  `offload::tests::ipv4_with_twenty_option_bytes_is_not_merged` (not merged, checksum
  validated as IPv4), `ipv6_packets::a_later_fragment_as_ninth_header_is_malformed` and the
  later-fragment row in `at_most_eight_extension_headers_are_walked`.
- No public API change; slot A/B of the `vnet`, `offload` and `gate` benches within noise.
- Full gate (`just check`) green; `CHANGELOG.md` 0.19.4 section prepared, not tagged.

## ActiveForm

Fixing vnet IPv4 IHL 10 segmentation and the walk_v6 later-fragment header limit

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- Tests: the four regression tests failed before the change (D1: TCP segment 0 total length
  2560 instead of 1060; offload: the IPv4 checksum read as IPv6; D2: `ValidState` and
  `OrphanFragment` instead of `Malformed`) and pass after it; `nsplane-packet`, `nsplane-tun`
  and `nsplane-acl` suites pass.
- Slot A/B against `main` (interleaved, slot 1): `vnet/segment_tcpv4_64k` 3.185 vs 3.183 us
  (mean of 3 rounds); `offload/coalesce_tcpv4_48` B at or below A in all 5 rounds (wide spread);
  gate `established/gate` 42.55 / 41.59 vs 41.55 / 41.93 ns, `established/outbound` 42.02 /
  41.51 vs 41.48 / 41.72 ns, `established/filter` 47.22 / 46.50 vs 46.59 / 46.41 ns,
  `baseline/pass_gate` 0.63 ns both, `icmp_error/v6` 48.92 / 47.90 vs 48.04 / 48.31 ns,
  `established/extension_chain_v6` 58.80 / 57.04 vs 57.25 / 57.01 ns, `fragment/later_v6` 45.16
  / 47.69 vs 45.35 / 47.03 ns. A first `walk_v6` that left the loop with `break` cost
  `icmp_error/v6` about +4 ns and was replaced by one bound check per header in the original
  loop.
- Gate: `just check` fails only in `test` on `nsplane` `udp::tests::burst_fits_default_buffer`
  and `nsplane-e2e` `offload_udp::bulk_transfer_ipv{4,6}_offload_on_on_workers` (2347 of 2350
  pass). The three fail identically on `main` `52eb983` (three runs each), most likely because
  the host's `net.core.rmem_max` / `wmem_max` are at the kernel default (212992, socket buffers
  425984), which a 512-datagram loopback burst does not fit.
  The remaining recipes (doc-test, deny, shear, typos, msrv, examples, product-terms, docs) and
  `cargo doc` pass; the Windows clippy of `nsplane-tun` and `nsplane-packet` passes. The macOS
  half of `just cross` and `just test-windows` were not run (no `cargo-zigbuild` or `wine` on
  the host).
- 2026-10-27: release A is numbered 0.19.4 (0.19.3 was released meanwhile with a musl build
  fix) and rebased onto `fb67db9`, where the module split left the four changed files where they
  were; the conflicts were the changelogs and the task index only.
