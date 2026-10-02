# nstun - Plan Index

> Updated: 2026-10-02

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
