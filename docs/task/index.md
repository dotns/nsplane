# nstun - Task List

> Updated: 2026-10-02

## Usage

Each task is a single line linking to its detail file. All detailed information lives in `docs/task/<timestamp>-<feature-slug>.md`.

### Format

- [ ] [**20260907-1428-add-endpoint Add endpoint**](20260907-1428-add-endpoint.md) `P1`

### Status Markers

| Marker | Meaning |
|--------|---------|
| `[ ]`  | Pending |
| `[-]`  | In progress |
| `[x]`  | Completed |
| `[~]`  | Closed / Won't do |
| `[d]`  | Deleted detail file; index entry retained |

### Priority: P0 (blocking) > P1 (high) > P2 (medium) > P3 (low)

### Rules

- Only update the checkbox marker; never delete the line or change its other content. If the detail file is deleted, mark the entry `[d]`.
- Record change history and deletion reasons in `docs/changelog.md`; update affected dependency and plan references.
- New tasks append to the end.
- See each `<timestamp>-<feature-slug>.md` for full details, except `[d]` entries whose files have been deleted; consult `docs/changelog.md` for their history.

---

## Tasks

- [x] [**20261001-1859-fork-baseline Fork baseline: pma-rust, aws-lc-rs, gotatun-inspired fixes**](20261001-1859-fork-baseline.md) `P1`
- [x] [**20261002-1008-cli-dev-tool Reduce the CLI to a Linux/macOS development tool**](20261002-1008-cli-dev-tool.md) `P2`
- [-] [**20261002-1020-data-plane-core Complete data plane: transport, netstack and ACL inside nstun**](20261002-1020-data-plane-core.md) `P1`
- [-] [**20261002-1509-phase1-followups Phase 1 follow-up fixes (data plane core campaign)**](20261002-1509-phase1-followups.md) `P1`
- [x] [**20261003-1215-traffic-status Engine status snapshot and per-transport traffic counters**](20261003-1215-traffic-status.md) `P2`
- [x] [**20261002-1529-repo-cleanup-layout Remove unused files and move crates under `crates/`**](20261002-1529-repo-cleanup-layout.md) `P2`
- [x] [**20261003-1300-ns-m4-requests Engine hooks requested by ns account mode (M4)**](20261003-1300-ns-m4-requests.md) `P1`
- [-] [**20261003-1500-ns-dataplane-moves Data-plane pieces ns still owns, to move into nsplane**](20261003-1500-ns-dataplane-moves.md) `P1`
- [-] [**20261003-2200-ns-local-side Local-side graph, masquerade, Echo reply, host TUNs and the ACL gate for ns**](20261003-2200-ns-local-side.md) `P1`
- [ ] [**20261006-1300-nsgw-requests Data-plane items for the nsgw rebuild, in generic form**](20261006-1300-nsgw-requests.md) `P1`
- [x] [**20261006-1500-business-agnostic-cleanup Remove product concepts from nsplane**](20261006-1500-business-agnostic-cleanup.md) `P1`
- [ ] [**20261006-1700-windows-smoke-for-ns Windows TUN smoke scenario for ns (MT-3 addendum)**](20261006-1700-windows-smoke-for-ns.md) `P1`
