# ADR: Rename the project from nstun to nsplane

Status   : Accepted (execution deferred)
Date     : 2026-10-02
Sunset   : none

## Context

The project started as a boringtun fork whose job was to be ns's WireGuard core, and
"nstun" described that: a userspace TUN device. Plan `20261002-1024-data-plane-core` turns
it into the complete data plane of an NS node: WireGuard engine, transports, path policy
mechanics, filter chain, in-process netstack, ACL and 4↔6 translation. TUN is now one
`PacketSource`/`PacketSink` among several (netstack, host fd bridges), so the name no
longer describes the thing.

Candidates were checked against GitHub repository names and crates.io on 2026-10-02:

| Name | Result |
|---|---|
| `nsplane` | free on both; matches "data plane", the layer-1 name in the NS architecture |
| `nsconduit`, `nsduct`, `nsfabric` | free; longer, or imply mesh routing the engine does not do |
| `nswire` | free, but ns already has a `quick-wire` crate (wire protocol definitions) |
| `nslink`, `nsdata` | existing third-party projects with the same name |

## Decision

- The project is renamed **nsplane**. Crates follow the same scheme: `nstun-packet` →
  `nsplane-packet`, `nstun-core` → `nsplane-core`, `nstun` → `nsplane`, `nstun-tun` →
  `nsplane-tun`, and future `nsplane-netstack`, `nsplane-acl`, `nsplane-nat`,
  `nsplane-uapi`, `nsplane-e2e`.
- `boringtun` becomes `nsplane-noise` and `boringtun-cli` becomes `nsplane-cli`. The
  upstream crate name was kept to make upstream merges cheap; the fork has diverged far
  enough that fixes are ported by hand, so that reason no longer holds. The BSD-3-Clause
  license and the upstream copyright notices are unaffected by the crate name.
- The GitHub repository moves to `dotns/nsplane` (GitHub redirects the old name); the
  working directory becomes `/srv/dotns/nsplane`; the docs site section moves from
  `/nstun/` to `/nsplane/`.
- **Timing**: the rename is executed as its own PMA task after the Phase 1 BKD campaign
  (`nstun-dp-p1`) has merged workstreams D and E and `main` is green. The campaign's
  worktrees and the Phase 1 crate contract are bound to the current names; renaming
  underneath them would break every open L2/L3 branch. Until then, new documents use
  "nsplane" when they talk about the target and the current crate names when they talk
  about code on `main`.

## Consequences

- One rename commit (`git mv` plus path/name substitution) touching every `Cargo.toml`,
  `use` path, doc page and script, followed by `just check`, `just cross`, `just e2e`.
- ns pins the engine by git URL; its Phase 0 pin (`noise` only) must point at the new
  repository name and crate name once the rename lands, so Phase 0 is scheduled after it.
- BKD project directory and any later campaign contracts use the new names.
