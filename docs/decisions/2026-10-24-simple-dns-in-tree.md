# ADR: simple-dns is kept in this repository

- **Status**: Accepted
- **Date**: 2026-10-24
- **Supersedes**: [2026-10-24-simple-dns-fork](2026-10-24-simple-dns-fork.md)
- **Review**: when upstream carries every change the in-tree copy has

## Context

`nsplane-dns` uses the `simple-dns` protocol crate as its message codec. It was first a
standalone repository, `github.com/dotns/simple-dns`, pinned by tag as a git dependency. Every
codec change then needed a commit and a tag in that repository, an update of the pin and of
the `deny.toml` git allowlist. The crate is small (about 8.7k lines, no `unsafe`, one
dependency, `bitflags`, already in the lock file) and MIT licensed. The owner asked to keep
it in this repository instead.

## Decision

The crate lives in `third_party/simple-dns` as a workspace member under its own name, with
`publish = false`, its MIT `LICENSE` and its own formatting configuration. `nsplane-dns`
depends on it by path. The content is tag `v0.12.0-nsplane.4` of the standalone repository
(`c276b6f`) without the fuzz crate; `third_party/simple-dns/UPSTREAM.md` records the upstream
base (`simple-dns 0.12.0`, `5c7ec98`) and the changes on top of it.

- Upstream changes are reviewed by hand and applied as ordinary commits; the upstream history
  is not imported.
- The code keeps its upstream style. It does not opt into the workspace lints and is outside
  the `typos`, product-term and documentation checks; `cargo fmt`, clippy (default features
  only: without `std` its tests do not build), the MSRV check, its tests and `cargo deny` still
  cover it.
- `deny.toml` no longer allows `github.com/dotns/simple-dns`. The standalone repository is
  archived.

## Consequences

- A codec fix is one commit here, reviewed and gated with the code that needs it.
- About 9k lines of third-party code in the repository.
- A crates.io release of `nsplane-dns` would need the crate published under another name or
  its changes upstreamed.
