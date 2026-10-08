# 20261008-0800-consumer-integration ns and nsgw on nsplane 0.11

- **status**: in_progress
- **priority**: P1
- **owner**: L1 (7f5cstru); the code changes are made in ns and nsgw by their owners
- **createdAt**: 2026-10-08 08:00

## Description

nsplane is frozen at 0.11.x (ADR `2026-10-08-feature-freeze-0-11`). The priority is the consumers:
- ns moves from its `v0.10.0` pin to `v0.11.0`.
- The nsgw rebuild starts on the engine.

nsplane supports both with probes, migration notes and 0.11.x bug fixes. It does not edit ns or
nsgw. The migration guide for both is the docs site page `nsplane/migration-0-11`; the specs are
under `docs/specs/`.

## ns probe (2026-10-08)

ns `refactor/nsplane` at `a9c6a090`, pinned to `v0.10.0` (not `v0.10.1`). Method: a copy with all
nine nsplane pins set to `v0.11.0`, `cargo update -p nsplane*` (smoltcp `.4` -> `.6`), then
`cargo check --workspace --all-targets` in the nsplane dev image.

Result:
- The build stops in `crates/overlay`: 11 errors in the library and 32 with its tests.
- The crates downstream of `overlay`, `crates/ns` among them, are not checked until it compiles.
- A source scan of the removed and renamed items gives the full surface below.

| Area (nsplane item) | ns files | What to do (spec / guide section) |
| --- | --- | --- |
| ACL namespaces, grants and outbound rules (`NamespacePolicy::policy`, `NamespaceMember::principal`, `GrantEnd::Peer`, `Grant::{proto, ports}`, `OutboundRule`, `AclPolicy` in sources, `Decision` fields, `RuleId` instead of `String` grant ids) | `crates/overlay/src/{policy,source}.rs` (all compile errors so far) | Typed rules and labels: compile each source's document into `Vec<Rule>` (`acl-policy-document.md`), members, grant ends and pinholes keyed by `Label` (guide §2.1) |
| Source identity (`SourceAssertion`, `AccessRequest`, `wg_peer_anchor`, `PeerIdentityMap`) | `crates/overlay/src/policy.rs`, `crates/ns/src/account_engine/{filters,tunnel}.rs`, `crates/ns/src/node_engine/{node,peers}.rs` | `PeerLabelMap` / `PeerIdentity::labels`; label text per `acl-source-identity.md` |
| Account filter (`AclEngine::load`, `AclPolicy` / `AclRule` / `AclAction`, `crates_acl()`, `CompiledPolicy`) | `crates/ns/src/account_engine/filters.rs`, `crates/ns/src/node_engine/node.rs` | `RuleSet::new` + `AclEngine::install`; explicit `AclFilterConfig` fields instead of `crates_acl()`; the ns account-filter mapping in `acl-policy-document.md` §6.3; parity data `acl-crates-acl-parity.json` |
| Node L3 gate (`NodeL3Config`, `NodeL3Node`, `NodeL3Grant`, `NodeL3Resource`, `NodeL3PeerBinding`, `NodeL3Transport*`, `NodeL3Mode`, `NodeL3Decision`, `NodeL3Reason`, `NodeL3Filter`, `PeerKeyMap`) | `crates/ns/src/account_engine/wg/node_l3.rs` (+ tests), `crates/ns/src/node_engine/status.rs`, `crates/ns/src/quick/v2/state.rs` | Compile to `gate::GatePolicy` and install with `FlowGate::replace`, wired with `GateFilter`. Fill `GateScope::unbound_addresses`. Map `GateReason` back to ns reasons. See `node-l3.md`, which holds the 24-row procedure and the accepted deviations; parity data `node-l3-differential.json` |
| Translator names (`PeerMapping` / `SelfMapping` fields, `peer_with_native_alias4`, `by_*`) | `crates/ns/src/node_engine/node/translate.rs` (~69 field uses) | Rename only, byte-identical: `node6`/`node4`/`alias4`/`alias6`/`self4` -> `peer6`/`eam6`/`eam4`/`local6`/`eam4` (`translator-address-plan.md`) |
| `WsFrame` stream carrier (`WssStreamClient`, `WssStreamServer`, `frame`) | `crates/ns/src/proxy/{mod,wire,wss_flow,relay}.rs`, `crates/ns/src/router.rs`, `tests/engine-smoke/harness` | Deprecated, still compiles (warnings). Keep until M6, then switch to a WireGuard peer over `WssDialer` and drop the proxy stream path |
| Stats structs (`AclFilterStats`, `NetStackStats`) | wherever built with a struct literal | Add the new fields (`internal`, `policy_failed`, `policy_state`, `icmp_ignored`) or use `..Default::default()` |
| nsplane-nat `Masquerade`, `Redirect`, `Nat64Lan` (`LanRoute`) | `crates/ns` | Unchanged in 0.11 |

Behaviour changes ns should re-test (guide §3):
- Sink-full backpressure without crypto workers.
- `Event::Authenticated` once per source change.
- netstack `datagram_capacity` 256, PMTU and tail loss probe.
- `clear_all` -> `Failed`.
- Typed evaluation of non-TCP/UDP packets.

Suggested order for ns:
1. Bump to `v0.10.1`. This is the bug fix only and needs no code change.
2. Port `crates/overlay` (labels + typed rules) and the account filter.
3. Port node L3 to the gate, checked against the differential data.
4. Rename the translator fields.
5. Fill in the stats fields.
6. Move to `v0.11.0` and run ns's engine smoke and the Windows smoke (`20261006-1700`).

## nsgw (2026-10-08)

nsgw has no nsplane dependency yet. The `next` line (R0) has not started; `main` is `aa94aa5`.

Everything its R2 plan lists as "used directly" exists in 0.11:
- the engine;
- `UdpTransport`;
- `nsplane-tun` (Linux TUN with offload);
- peer and transport counters;
- the path MTU ceiling.

NG-7, the WebSocket endpoint as `WssServerTransport` + `WssAcceptor`, is also in 0.11.

Open, and blocked by the freeze if nsgw raises them (task `20261006-1300`, Possible requests):
- an atomic replace of the whole peer set with per-peer results (G19);
- a final counter snapshot at peer removal.

The R3 IPv6/NAT64 questions come later.

## Notes

- The probe copy lives in `.tmp/ns-probe` (gitignored). Rerun the probe after each ns port step to
  see the next crate's errors.
