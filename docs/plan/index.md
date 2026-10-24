# nstun - Plan Index

> Updated: 2026-10-20

## Usage

Each plan is a single line linking to its detail file. All detailed information lives in `docs/plan/<timestamp>-<feature-slug>.md`.

### Format

- [ ] [**20260907-1440-add-endpoint Add endpoint**](20260907-1440-add-endpoint.md) `YYYY-MM-DD`

### Status Markers

| Marker | Meaning |
|--------|---------|
| `[ ]`  | Draft / Pending review |
| `[-]`  | Approved / Implementing |
| `[x]`  | Completed |
| `[~]`  | Rejected / Abandoned |
| `[d]`  | Deleted detail file; index entry retained |

### Rules

- Only update the checkbox marker; never delete the line or change its other content. If the detail file is deleted, mark the entry `[d]`.
- Record change history and deletion reasons in `docs/changelog.md`; update affected task and plan references.
- New plans append to the end.
- See each `<timestamp>-<feature-slug>.md` for full details, except `[d]` entries whose files have been deleted; consult `docs/changelog.md` for their history.

---

## Plans

- [x] [**20261001-1859-fork-baseline Fork baseline: pma-rust, aws-lc-rs, gotatun-inspired fixes**](20261001-1859-fork-baseline.md) `2026-10-01`
- [-] [**20261002-1024-data-plane-core Complete data plane: transport, netstack and ACL inside nstun**](20261002-1024-data-plane-core.md) `2026-10-02`
- [x] [**20261002-1535-phase2-engine Phase 2: multi-transport engine, engine-driven timers, follow-up fixes**](20261002-1535-phase2-engine.md) `2026-10-02`
- [x] [**20261002-1725-phase3-4-netstack-acl Phases 3 and 4: netstack, ACL, transport backpressure**](20261002-1725-phase3-4-netstack-acl.md) `2026-10-02`
- [x] [**20261002-2240-phase5-nat-offload-perf Phase 5: translation and NAT, offload, performance**](20261002-2240-phase5-nat-offload-perf.md) `2026-10-02`
- [x] [**20261003-0715-phase5-followups Fix the open Phase 1-5 follow-ups**](20261003-0715-phase5-followups.md) `2026-10-03`
- [x] [**20261003-1600-ns-dataplane-moves Move the remaining ns data-plane pieces into nsplane**](20261003-1600-ns-dataplane-moves.md) `2026-10-03`
- [x] [**20261003-1630-perf-and-wss Throughput against WireGuard baselines, and the WSS carriers**](20261003-1630-perf-and-wss.md) `2026-10-03`
- [x] [**20261003-2300-acl-l3-gate Move the account ACL and the node L3 gate into nsplane (MD)**](20261003-2300-acl-l3-gate.md) `2026-10-03`
- [x] [**20261003-2330-local-side Local-side graph primitives, masquerade, Echo reply, host TUNs**](20261003-2330-local-side.md) `2026-10-03`
- [-] [**20261004-1100-ns-requests The remaining ns requests: WSS legs, netstack, ACL, MTU, nat**](20261004-1100-ns-requests.md) `2026-10-04`
- [x] [**20261018-1000-doc-system One documentation standard: behavior-only product docs and comments**](20261018-1000-doc-system.md) `2026-10-18`
- [x] [**20261020-0854-udp-icmp-isolation Isolate asynchronous errors on shared UDP sockets**](20261020-0854-udp-icmp-isolation.md) `2026-10-20`
- [x] [**20261020-1026-synchronize-regression-fixtures Synchronize concurrent regression fixtures**](20261020-1026-synchronize-regression-fixtures.md) `2026-10-20`
- [x] [**20261020-1154-macos-quality-gates Restore native macOS quality gates**](20261020-1154-macos-quality-gates.md) `2026-10-20`

- [x] [**20261020-1224-darwin-utun-name Validate Darwin utun descriptors before name queries**](20261020-1224-darwin-utun-name.md) `2026-10-20`
- [x] [**20261024-1430-netstack-any-destination Netstack mode that accepts any destination address**](20261024-1430-netstack-any-destination.md) `2026-10-24`
- [x] [**20261024-1600-egress-0-17 Release 0.17.0: transparent netstack, flow events, ethernet adapter, DNS crate**](20261024-1600-egress-0-17.md) `2026-10-24`
- [-] [**20261024-1304-dns-passthrough DNS transparent forwarding for messages nsplane-dns does not handle**](20261024-1304-dns-passthrough.md) `2026-10-24`
- [-] [**20261024-1313-dns-policy DNS policy routing: per-name rules choose the resolver or a local action**](20261024-1313-dns-policy.md) `2026-10-24`
