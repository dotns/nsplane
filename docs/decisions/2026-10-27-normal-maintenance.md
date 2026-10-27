# ADR: normal maintenance after the 0.11 feature freeze

- **Status**: Accepted
- **Date**: 2026-10-27
- **Supersedes**: [2026-10-08-feature-freeze-0-11](2026-10-08-feature-freeze-0-11.md)
- **Review**: none

## Context

The 0.11 feature freeze kept nsplane to bug fixes while the consumers integrated, and every
feature since then needed a recorded owner exception (eleven, the last one shipped as 0.20.0).
The owner lifted the freeze on 2026-10-27: "后续走正常维护，解除冻结，只是提示api兼容性".

## Decision

nsplane returns to normal maintenance. Features, optimizations and refactors land through the
usual plan, approval and gate workflow; they need no freeze exception.

API compatibility is the remaining duty, and it is a notice, not a gate:

- A change that breaks the public API of a published crate is called out in its plan and in
  the proposal to the owner before implementation.
- The CHANGELOG lists it under `### Changed` / `#### Breaking` with a before/after migration
  example, as 0.20.0 does, and the release that carries it bumps the minor version (0.x).
- Additive changes and fixes ship as minor or patch releases as before. Deprecation before
  removal is preferred where it is cheap.

The rest of the bug fix rules stay: regression test, full gate, slot A/B for data-path changes.

## Consequences

- The open follow-ups the freeze left unscheduled (deferred optimizations, NG-6, wrapper
  `send_batch_spent` forwarding, `EngineHandle::recycle`, netstack SACK, release C of plan
  `20261026-0822-node-gateway-requests`, the peer-level expiry signal) can be planned again.
- The deprecated `WsFrame` stream carrier and `TransparentConfig::admission` may be removed in a
  later minor release, with a breaking notice.
