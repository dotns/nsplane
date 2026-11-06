# 20261106-2327-tcp-zero-checksum Accept zero TCP and ICMP checksums

- **status**: completed
- **priority**: P0
- **owner**: f2-checksum
- **createdAt**: 2026-11-06 23:27

## Description

Accept valid zero TCP/ICMP checksum fields throughout NAT. Keep IPv4 UDP absent-checksum computation and IPv6 UDP zero rejection. Add failing translation, masquerade, quotation and user-space TCP regressions before fixing; run `just check`.

## ActiveForm

Correcting protocol-specific zero checksum handling.

## Dependencies

- **blocked by**: (none)
- **blocks**: downstream revision updates after merge

## Notes

Implementation and Gitea PR submission approved in the task request. Base: bf2d4e26bb98665f81f90538a088b8d99871d9e4.

- complete: RED: five NAT and two user-space TCP regressions. GREEN: complete just check passed (2508 tests, 34 existing skips). Audited helpers, netstack, engine and offload; only three NAT runtime files needed changes. Unrelated DNS fixture AddrInUse reproduced on unchanged bf2d4e26 and deferred as tk #1001. Baseline alignment follows merge (tk #1000).
