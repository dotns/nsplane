# Upstream

The `simple-dns` protocol crate, kept in this repository and maintained here; it is not
published.

- Upstream: <https://github.com/balliegojr/simple-dns>, release `simple-dns 0.12.0`
  (commit `5c7ec98`).
- Imported from the former standalone copy `github.com/dotns/simple-dns`, tag
  `v0.12.0-nsplane.4` (commit `c276b6f`): the bind9 submodule, its test crate and the fuzz
  crate removed, unknown QTYPEs accepted, `PacketView` added.
- In this repository, `Cargo.toml` gains `publish = false` and `rust-version` (the workspace
  MSRV, checked by `just msrv`), and `repository` points at upstream.
- License: MIT (`LICENSE`), unchanged.

Upstream changes are reviewed by hand and applied as ordinary commits; the upstream history
is not imported. On import the code was formatted with `cargo fmt` (its own `rustfmt.toml`);
otherwise it keeps its upstream style and is excluded from this repository's `typos`,
product-term and documentation checks.
