# ADR: nsplane-dns depends on the dotns/simple-dns fork

- **Status**: Superseded by [2026-10-24-simple-dns-in-tree](2026-10-24-simple-dns-in-tree.md)
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

`github.com/dotns/simple-dns` is an independent repository, not a GitHub fork: dotns
maintains it, upstream changes are applied by hand after review, and only the DNS protocol
crate is kept. Its branch `main` starts at upstream tag `simple-dns/0.12.0` (`5c7ec98`).
Tag `v0.12.0-nsplane.1` (`f92badd1a2472bb50348f46f0923ca7a37c9adae`) carries one commit on
top of it: the `bind9` submodule and the `bind9-tests` crate are removed, because Cargo
clones the submodules of a git dependency.

Tag `v0.12.0-nsplane.2` (`58b0bd8a11b861c1ffb86d9594f3676b473d7ae4`) adds one commit: a
question whose QTYPE has no RDATA support (TLSA, SSHFP, URI and other codes) parses as
`QTYPE::TYPE(TYPE::Unknown(n))` instead of failing (RFC 3597), so such queries get an answer
instead of FORMERR.

Tag `v0.12.0-nsplane.3` (`e17b0c7bfec7e6378bcaefda7ee782bdd1117993`) removes everything
outside the protocol crate: the mDNS crate, the benchmarks, the Docker files and the upstream
CI and release tooling. The crate and its fuzz targets remain.

Tag `v0.12.0-nsplane.4` (`c276b6f0fec493bf3ff56a2149126366779590c0`) adds `PacketView`, a
lenient view of a message: the header and questions are decoded, the other sections are
skipped by RDLENGTH without decoding names or RDATA, and the first OPT record of the
additional section is decoded with its TTL laid out as in RFC 6891 (upstream `Packet` reads
the extended RCODE and version from swapped bytes and is left unchanged).

Changes are made on `main`, tagged `v<upstream version>-nsplane.N` and recorded here.

## Consequences

- Upstream fixes are ported by hand when they touch the protocol crate; there is no
  automatic sync, and upstream releases are not followed by default.
- A crates.io release of `nsplane-dns` would need the fork published or its changes
  upstreamed.

## Status history

- 2026-10-24: Accepted as a GitHub fork; the same day the owner made it an independent
  repository maintained by dotns, without the parts outside the protocol.
- 2026-10-24: Superseded the same day: the crate moved into this repository
  (`third_party/simple-dns`) and the standalone repository is archived.
