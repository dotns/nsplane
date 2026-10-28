# ADR: feature freeze at 0.11.x

- **Status**: Superseded by [2026-10-27-normal-maintenance](2026-10-27-normal-maintenance.md)
- **Date**: 2026-10-08
- **Review**: none

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
- 2026-10-24: seventh exception (owner: "1，发0.17 2，合并到一起0.17 ... 4，做"; "可以做dns，同步放在0.17"):
  the gino-agent egress requests R1 (transparent netstack), R3 (ethernet adapter) and R4 (flow
  decision events), plus a generic DNS crate (plan `20261024-1600-egress-0-17`, task
  `20261024-1500-gino-egress-requests`). The DNS crate carries protocol, serving and a
  fake-address pool only; resolution policy stays with the consumer. R5 and R6 are not done.
  It ships as 0.17.0.
- 2026-10-24: eighth exception (owner: "可以 开始处理"): transparent forwarding in nsplane-dns for
  messages it does not handle (plan `20261024-1304-dns-passthrough`), extended the same day
  (owner: "可以，cname也可以一起放进去") by DNS policy routing with CNAME rewriting (plan
  `20261024-1313-dns-policy`), and an example of a virtual machine reaching a remote
  WireGuard peer (owner: "可以把vm路径的examples也放进0.18"; plan
  `20261024-1329-vm-wireguard-example`), and an `AF_PACKET` frame transport for guests whose
  TAP another process holds, such as Firecracker (owner: "用C方式最合理、不引入额外管理"; plan
  `20261024-1338-af-packet-transport`). All ship as 0.18.0.
- 2026-10-24: ninth exception (owner: "网关做arp代理"): `nsplane-ether` answers ARP and NDP
  for every address of the guest's link but its own (plan `20261024-1454-ether-proxy-arp`).
- 2026-10-24: tenth exception (owner: "需要同步到完整上游再更新我们的补丁，包括每个 socket 单独调重传超时"):
  the smoltcp fork moves to upstream `main` and `nsplane-netstack` exposes the per-socket TCP
  RTO bounds (plan `20261024-1453-smoltcp-upstream-fixes`).
- 2026-10-26: eleventh exception (owner decision on plan
  `20261026-0822-node-gateway-requests`, release B): netstack control of a lifetime from its
  first input with admission on every stack, scope-qualified flow gate decisions, the engine's
  local barrier and a validated plaintext ingress, with the recommended answers to O1-O7; five
  netstack configuration and statistics types become `#[non_exhaustive]` (owner decision, the
  one breaking change). It ships as 0.20.0, together with the fixes of 0.19.4. Release C of the
  same plan (ingress labels, plaintext egress, send receipts) is in design and needs its own
  exception.
- 2026-10-27: twelfth exception (owner decision on plan
  `20261026-0822-node-gateway-requests`, release C): one opaque packet tag on `PacketBuf` as the
  carrier (with a documented receipt marker), netstack ingress labels with label revocation,
  plaintext egress per peer and per-packet send receipts, with the answers to O8-O14 recorded in
  the design note `docs/plan/notes/20261026-0834-packet-tag-carrier.md`. It is breaking
  (`Output` and `TranslatorStats` become `#[non_exhaustive]`, `PacketBuf` grows by one word) and
  ships as 0.21.0. As integrated: `Output` becomes `#[non_exhaustive]` with `Plaintext` and
  `Tracked`; `TranslatorStats` stays exhaustive (the mixed-tag drop is a drop reason) and
  `PacketBuf` keeps 56 bytes with `u32` packet offsets (layout B of the note, the one-word
  layout was outside the noise).
- 2026-10-27: the owner lifted the freeze ("后续走正常维护，解除冻结，只是提示api兼容性"); see
  [2026-10-27-normal-maintenance](2026-10-27-normal-maintenance.md).
