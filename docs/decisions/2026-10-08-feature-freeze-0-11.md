# ADR: feature freeze at 0.11.x

Status   : Accepted
Date     : 2026-10-08

## Context

0.11.0 completed the ns requests, the optimization rounds and the business-agnostic cleanup.
The owner's priority is now the integration of the consumers: ns moving to 0.11 from its
v0.10.0 pin, and the nsgw rebuild on the engine.

## Decision

nsplane is frozen at the 0.11 line. Only bug fixes land, released as 0.11.x patch versions
from main. No new features, optimizations, refactors or API changes are made unless the
owner lifts the freeze. A consumer request that needs a new API is recorded in its task
document and waits.

A bug fix keeps the existing API, has a regression test, and passes the full gate (just
check including the term scan, cross, test-windows, cargo doc, the e2e scripts). It needs a
slot A/B when it touches the data path.

## Consequences

- The open follow-ups (deferred optimizations, NG-6, wrapper `send_batch_spent` forwarding,
  `EngineHandle::recycle`, netstack SACK) stay open, unscheduled.
- The deprecated `WsFrame` stream carrier is removed only after the freeze is lifted. The
  removal is breaking.

## Amendments

- 2026-10-11: the owner lifted the freeze for one feature, local identities (task
  `20261011-0101`, plan `20261011-0900-local-identities`). It is additive and ships as 0.12.0.
  Everything else stays frozen. 0.11.x fixes continue on `release/0.11.x` if needed.
- 2026-10-12: second exception (owner: "这个是底层逻辑问题，需要处理"): a peer-keyed,
  address-family-agnostic flow gate and runtime per-identity `AclFilterScope` (task
  `20261012-1700`, plan `20261012-1800-peer-keyed-gate`). It ships as 0.13.0.
- 2026-10-13: third exception (owner: "开始处理"): prefix address mappings for LAN prefixes (task
  `20261013-1300`) and cryptokey routing per local identity (task `20261013-1301`), both from ns.
  They ship as 0.14.0.
- 2026-10-16: fourth exception (owner: "用大改的方式，保持api不变即可"): faster allowed-IP
  lookups on the data path with the public API unchanged (plan `20261016-1800-route-lookup`,
  task `20261013-1600` PR-3). It ships as a 0.14.x patch release.
- 2026-10-17: fifth exception (owner: "2，需要，开始修改然后发布0.15.0"): nested LAN prefixes
  with longest-prefix match in nsplane-nat, opt-in and additive (plan
  `20261017-1300-nested-lan-prefixes`, from the ns plan `20261017-0422-gateway-as-node`). It
  ships as 0.15.0.
- 2026-10-17: sixth exception (owner: "可以先做r1和r2，先不做r3"): per-flow control,
  retirement receipts and a flow context inside `nsplane-netstack` (plan
  `20261017-1800-flow-retirement`, task `20261017-1700-flow-lifecycle-request` R1 and R2). R3,
  delivery gates in the engine and transports, stays deferred. It ships as 0.16.0.
