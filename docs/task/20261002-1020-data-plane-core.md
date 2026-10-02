# 20261002-1020-data-plane-core Complete data plane: transport, netstack and ACL inside nstun

- **status**: in_progress
- **priority**: P1
- **owner**: agent/nstun-20261002
- **createdAt**: 2026-10-02 10:20

## Description

Turn nstun into the complete data plane for ns: pluggable packet I/O (TUN or an in-process
smoltcp netstack, no TUN required), pluggable transports (UDP, relay, WSS), the WireGuard
peer/session machinery, and the ACL, so that ns only keeps business logic. Reference designs:
Tailscale's tstun/wgengine and mullvad/gotatun (design only; no MPL code copied).

Phase 1 of this task is the investigation and the plan in `docs/plan/`; implementation waits
for approval.

## ActiveForm

Investigating and planning the nstun data plane core

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- 2026-10-02 10:50: plan approved (sans-I/O core accepted); Phase 1 runs as a BKD
  three-tier campaign (L1 issue in BKD project `nstun`); this session works in the nstun
  repo and relays user decisions.
- 2026-10-02: investigation done, plan `20261002-1024-data-plane-core` written; waiting
  for approval. ns was read at a05b6f55 plus uncommitted changes (keynet -> quick rename in
  progress by another session).
