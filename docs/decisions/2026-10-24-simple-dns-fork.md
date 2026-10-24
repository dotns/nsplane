# ADR: nsplane-dns depends on the dotns/simple-dns fork

- **Status**: Accepted
- **Date**: 2026-10-24
- **Review**: when the fork carries no change that upstream lacks

## Context

`nsplane-dns` answers DNS clients specially: static records, addresses from a fake-address
pool, forwarding of other names. It is not a full DNS implementation, so it needs a small
message codec rather than a resolver library. `simple-dns` parses and writes DNS messages
with one dependency (`bitflags`). Changes the crate needs (for example EDNS handling) should
not wait for upstream releases, the same situation as smoltcp.

## Decision

`nsplane-dns` depends on `github.com/dotns/simple-dns`, pinned to a tag. `deny.toml` allows
that git source; `unknown-git` stays `deny`.

The fork is branch `nsplane/v0.12`, cut from upstream tag `simple-dns/0.12.0` (`5c7ec98`).
Tag `v0.12.0-nsplane.1` (`f92badd1a2472bb50348f46f0923ca7a37c9adae`) carries one commit on
top of it: the `bind9` submodule and the `bind9-tests` crate are removed, because Cargo
clones the submodules of a git dependency.

Fork changes are made on the fork branch, tagged `v0.12.0-nsplane.N` and recorded here.

## Consequences

- The fork is rebased onto a new upstream release when one is needed; the commits above are
  re-applied and a new tag is cut.
- A crates.io release of `nsplane-dns` would need the fork published or its changes
  upstreamed.

## Status history

- 2026-10-24: Accepted.
