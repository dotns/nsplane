# 20261024-1304-dns-passthrough DNS transparent forwarding for messages nsplane-dns does not handle

- **status**: completed (released as 0.18.0)
- **createdAt**: 2026-10-24 13:04
- **relatedTask**: 20261024-1304-dns-passthrough

## Goal

`nsplane-dns` stops answering FORMERR / NOTIMP for messages it merely does not understand.
A query whose other sections it cannot parse is still decoded; a message it cannot decode
at all can be passed to an upstream byte for byte, under a policy hook. With the
passthrough off, every answer that is correct today stays the same.

## Changes

| Step | Repository | Work |
| --- | --- | --- |
| P1 | `dotns/simple-dns` | A lenient view of a message: header, questions, and the OPT record (UDP size, flags) found by walking the answer, authority and additional sections by RDLENGTH without decoding other RDATA. Unit tests: unknown RR types and unknown EDNS options in every section, compression pointers, truncated records. Tagged `v0.12.0-nsplane.4` by L1 |
| P2 | `nsplane-dns` | `Query::decode` on the lenient view: only header, the one question and OPT are required; an unparsable record elsewhere no longer gives FORMERR. Raw bytes kept as today |
| P3 | `nsplane-dns` | Opt-in passthrough on `Server`: a message that does not decode as a `Query` but has a readable header (opcode other than `QUERY`, a question count other than one, a malformed question) goes to a passthrough target and its response is returned with the client's ID. Target: `Forwarder` (a raw-message entry point next to `Resolver`). Policy hook: the embedder decides per message (client address, opcode, question count) to pass or to answer locally (today's error); default without a hook is pass when passthrough is on. Counters for passed, refused and failed messages |
| P4 | `nsplane-dns` | Tests: NOTIFY / UPDATE / IQUERY passed through to a stub upstream and refused by the hook; two-question message; query with an unknown RR type and an unknown EDNS option in the additional section answered normally (with and without passthrough); passthrough off gives today's responses; UDP truncation and TCP for passed messages. Rustdoc, `docs/reference/nsplane-dns.md`, CHANGELOG `[Unreleased]` |

## Constraints

- No new dependency; protocol parsing goes into `dotns/simple-dns`, not into workarounds in
  `nsplane-dns`.
- Additive API (new types and methods); `Answer`, `Resolver` and existing constructors keep
  their signatures.
- Gate: `just check`, `cargo doc -D warnings`, `just cross`, `just test-windows`.

Release as 0.18.0 after the owner's go-ahead.

## Out of scope

- Caching, DoT / DoH, DNSSEC validation.
- Passing through responses (`QR` = 1) or messages with an unreadable header.
