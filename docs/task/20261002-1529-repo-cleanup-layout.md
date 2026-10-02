# 20261002-1529-repo-cleanup-layout Remove unused files and move crates under `crates/`

- **status**: pending
- **priority**: P2
- **owner**: (unassigned)
- **createdAt**: 2026-10-02 15:29

## Description

Clean up the repository after the Phase 1 data plane merge:

1. **Remove unused files**, including those inherited from upstream boringtun. Candidates
   (verify each is unreferenced before deleting):
   - `banner.png`, `logo.png` (upstream branding; not referenced by README);
   - `boringtun/benches/crypto_benches/**` (upstream primitive benches; keep only if the
     crypto backend is still benchmarked here);
   - `boringtun/src/sleepyinstant/**`, `boringtun/src/serialization.rs`,
     `boringtun/src/wireguard_ffi.h`, `boringtun/src/ffi/**`, `boringtun/src/jni.rs` and the
     `ffi-bindings` / `jni-bindings` features, if no consumer needs the C ABI or JNI
     (open question: ns uses `noise` only; mobile hosts may want the FFI);
   - README sections that only describe upstream (upstream feature list, upstream
     remote workflow) once the upstream merge path is no longer wanted.
2. **Move crates under `crates/`**: `boringtun`, `boringtun-cli`, `nstun`, `nstun-core`,
   `nstun-packet`, `nstun-tun`, `nstun-uapi`, `nstun-e2e` become `crates/<name>/`; update
   workspace `members`, path dependencies, `justfile`, `scripts/e2e/*`, `.config/nextest.toml`
   if it names paths, README and `docs/architecture.md`. The root keeps only workspace and
   tooling files (`Cargo.toml`, `Cargo.lock`, `justfile`, lint/format/deny configs,
   `README.md`, `CHANGELOG.md`, `LICENSE.md`, `docs/`, `scripts/`).
3. **Attribution only in the license**: WireGuard and boringtun origin and trademark
   information lives in `LICENSE.md` (the Cloudflare BSD-3-Clause copyright notice must be
   kept as the license requires; add the dotns copyright line and the WireGuard trademark
   notice there). Remove the origin and trademark paragraphs from README and other docs,
   leaving at most a one-line pointer to `LICENSE.md`.

Acceptance: `just check`, `just cross`, `just test-windows`, `just e2e`, `just e2e-lib`
green after the move; no file left that nothing references; `cargo deny` license check
still passes.

## ActiveForm

Cleaning up the repository layout

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
- **related**: the rename to `nsplane` (ADR `docs/decisions/2026-10-02-rename-nsplane.md`)
  also touches every crate path and README; do both in one change (rename while moving
  into `crates/`) or this task first, to avoid editing every path twice.

## Notes

Recorded at the end of the Phase 1 campaign `nstun-dp-p1-202610021055`; needs a proposal
(PMA) before work starts, mainly to settle the FFI/JNI question in item 1.
