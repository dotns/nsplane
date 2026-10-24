# 20261024-1304-dns-passthrough DNS transparent forwarding for messages nsplane-dns does not handle

- **status**: completed (released as 0.18.0)
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-24 13:04
- **plan**: 20261024-1304-dns-passthrough

## Description

`Forwarder` already relays queries and responses byte for byte, but messages that fail
`Query::decode` never reach it: opcodes other than `QUERY` get NOTIMP, a question count
other than one gets FORMERR, and any record simple-dns cannot parse anywhere in the message
gets FORMERR although only the header, the question and OPT are needed. The owner asked for
transparent forwarding of what the crate does not support.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Follow-up

- Upstream simple-dns `Header` / `OPT` encode and decode the OPT TTL with a non-RFC 6891
  layout (extended RCODE and version swapped). `PacketView` decodes it correctly; responses
  built from `Packet` still use the upstream encoding, harmless while nsplane-dns writes
  version 0 and RCODEs below 16. Fix in the simple-dns repository later.
