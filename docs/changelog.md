# nstun - Development Changelog

Project-level history for PMA task and plan tracking. Release notes for the crates live in
the root `CHANGELOG.md`.

## 2026-10-01 19:40 [decision]

Forked cloudflare/boringtun `6dcc889` as `dotns/nstun`. Approved plan
`20261001-1859-fork-baseline`: remove upstream CI, adopt the pma-rust baseline, switch the
crypto backend from `ring` to `aws-lc-rs`, re-implement gotatun fixes F1-F10, add a
zero-copy data path and Windows support. gotatun code is not copied (MPL-2.0).
