# 20261024-1329-vm-wireguard-example Example: a virtual machine reaching a remote WireGuard peer through nsplane

- **status**: in progress (owner approved 2026-10-24: "可以把vm路径的examples也放进0.18")
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-24 13:29
- **plan**: 20261024-1329-vm-wireguard-example

## Description

The owner asked whether a virtual machine (libkrun-like) can reach a remote WireGuard peer
directly through nsplane. The pieces exist (`nsplane-ether` gives a `PacketSource` /
`PacketSink` that `EngineBuilder::new` accepts in place of a TUN device), but the path is not
verified end to end and there is no example. The owner put the example and its
verification into 0.18.0.

Not in this task: a unixgram frame transport, several guests on one engine, DNS split to a
local `nsplane-dns`.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
