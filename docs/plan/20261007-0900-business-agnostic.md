# 20261007-0900-business-agnostic Remove product concepts from nsplane; WSS server transport

- **status**: approved
- **createdAt**: 2026-10-07 09:00
- **approvedAt**: 2026-10-07 09:00 (user: "开始处理"; the scope and owner decisions are in ADR
  `2026-10-06-business-agnostic-scope` and tasks `20261006-1500` / `20261006-1300`; auto mode,
  no round cap, automatic merges, watchdog with stuck-process checks as before)
- **relatedTask**: 20261006-1500-business-agnostic-cleanup, 20261006-1300-nsgw-requests

## Context

The ADR fixes nsplane as a business-agnostic data plane. The audit of 2026-10-06 found product
concepts in nsplane-acl (source identity, policy document, node L3 gate) and in the nsplane-nat
translator (Quick v2 address names). The owner decided:
- The removed parts become specification documents, and the products implement them themselves.
- There is no compatibility layer.
- The work runs as its own round.

The gateway is a fixed WireGuard server over UDP and WebSocket. Its only remaining request is
the generic WSS datagram server transport (NG-7). With no consumer left after ns's M6, the
WsFrame stream carrier is deprecated (AG-7).

Conventions:
- No product term in any public API or rustdoc.
- Each removed concept gets a specification under `docs/specs/` that tells a product how to
  rebuild it on the generic API, with the parity data (fixtures) it needs.
- Breaking changes are allowed and listed in the CHANGELOG with their generic replacement.
  The round ends in 0.11.0.
- Data-path cost must not regress (data_path, ACL and node L3 benches, translator bench).

## Workstreams (L2)

| L2 | Items | Scope |
|---|---|---|
| AC acl | AG-1 generic ACL core (label sets, explicit policy states, rule IDs, packet-independent evaluation), AG-2 source identity to labels, AG-3 policy document and `crates_acl()` out, AG-4 node L3 gate to a generic stateful flow gate; specs for AG-2..4 | `crates/nsplane-acl/**`, its benches and e2e, `docs/specs/` (acl files) |
| AN nat | AG-5 translator names to generic per-peer explicit address mappings (RFC 7757 EAM); spec of the Quick v2 address plan on the generic fields; the term-scan gate script | `crates/nsplane-nat/**`, its e2e, `docs/specs/` (nat file), `scripts/` (term scan), the `justfile` line that runs it |
| AW wss | NG-7 WSS datagram server transport; AG-7 deprecate the WsFrame stream carrier; AG-6 rustdoc wording in nsplane, nsplane-packet, nsplane-wss, nsplane-core, nsplane-tun, nsplane-netstack; dedupe the Public interfaces table in architecture.md | `crates/nsplane-wss/**`, `crates/nsplane/src/{transport,lib}.rs` only if the transport needs a hook, rustdoc in the listed crates, new e2e |

AG-6 for nsplane-acl and nsplane-nat is done by AC and AN in their own crates. Shared files:
`CHANGELOG.md`, `docs/architecture.md`, `Cargo.lock`, new e2e test files, `docs/specs/`
(separate files per L2).

## Acceptance

Each branch and main after each merge:
- just check, just cross, just test-windows, cargo doc -D warnings, release CLI + linux.sh,
  lib.sh, examples.sh green.
- The term scan is green on main once AN lands.
- Bench A/B through `scripts/bench/slot.sh` shows no regression: data_path for all; ACL
  namespaces and node_l3 for AC; translate for AN.
- One spec per removed concept.
- The CHANGELOG lists every removal with its replacement.

After the round: release 0.11.0 (owner's go). Its table is taken on an idle host and re-checks
nsplane-kernel for F1.

## Annotations
- 2026-10-07: dispatched (campaign `nsplane-ba-202610070900`): AC `sot3v70g`, AN `b4d7qyct`, AW
  `bckqkh2q`; watchdog every 30 min with stuck-process checks.
- 2026-10-07: AW NG-7 design approved. `WssServerTransport` + `WssAcceptor` take caller-upgraded
  WebSockets. Each session is a synthetic, never-reused endpoint in 100::/64 (RFC 6666). Replies
  follow the engine's existing roaming on authenticated messages (no nsplane hook). Queues are
  bounded per session, and `max_sessions` has a finite default.
- 2026-10-07: AC design note `docs/specs/acl-generic-api.md` approved. It adds labels, rule IDs,
  `RuleSet`, `PolicyState`/`NotInstalled` and `Flow`-based evaluation, and the generic `gate`
  (scopes, bindings by PeerId, label grants, unbound pass/divert, holds; IPv4-only), with a
  22-row ns compile table. Q1-Q8 go as recommended. Two deviations are accepted and documented in
  node-l3.md: divert currency within one gate generation, and no unknown-peer drop in the gate.
- 2026-10-07: AC C5 deviations: 1 (counter once), 2 (Subnet flows follow the current grant), 3
  (fragment/pass state kept up to 30 s across a no-op recompile) and 5 (reason granularity)
  accepted. 4 (outbound to addresses without a PeerId binding fell open) reworked fail-closed: a
  per-scope list of such addresses is governed under the scope's mode and is never a divert
  candidate. The default is empty.
