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
