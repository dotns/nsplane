# 20261024-1437-simple-dns-in-tree Keep the simple-dns protocol crate in this repository

- **status**: proposed
- **createdAt**: 2026-10-24 14:37
- **relatedTask**: 20261024-1437-simple-dns-in-tree

## Goal

`simple-dns` builds from `third_party/simple-dns` as a workspace member and `nsplane-dns`
uses it by path; no git dependency on `dotns/simple-dns` remains. ADR
`2026-10-24-simple-dns-in-tree` records the decision.

## Work

| Step | Work | Verify |
| --- | --- | --- |
| S1 | Copy the crate of tag `v0.12.0-nsplane.4` (`c276b6f`) without the fuzz crate to `third_party/simple-dns`, with `LICENSE`, `rustfmt.toml` and `UPSTREAM.md`; `publish = false`; workspace member; path dependency in `nsplane-dns`; `deny.toml` git allowlist entry removed; `third_party/` excluded from `typos` | full gate |
| S2 | New ADR superseding `2026-10-24-simple-dns-fork`; README, reference `nsplane-dns`, CHANGELOG | `just docs` |
| S3 | Archive `github.com/dotns/simple-dns` after the release is pushed | repository shows archived |
