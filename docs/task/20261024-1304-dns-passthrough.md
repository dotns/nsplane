# 20261024-1304-dns-passthrough DNS transparent forwarding for messages nsplane-dns does not handle

- **status**: in progress (owner approved 2026-10-24: "可以 开始处理")
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
