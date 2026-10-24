# 20261024-1329-vm-wireguard-example Example: a virtual machine reaching a remote WireGuard peer through nsplane

- **status**: in progress (merged into main 066cc12; ships with 0.18.0)
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-24 13:29
- **plan**: 20261024-1329-vm-wireguard-example

## Description

The owner asked whether a virtual machine (libkrun-like) can reach a remote WireGuard peer
directly through nsplane. The pieces exist (`nsplane-ether` gives a `PacketSource` /
`PacketSink` that `EngineBuilder::new` accepts in place of a TUN device), but the path is not
verified end to end and there is no example. The owner put the example and its
verification into 0.18.0, and asked to verify the ACL on that path too.

Not in this task: a unixgram frame transport, several guests on one engine, DNS split to a
local `nsplane-dns`.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Follow-up

- The real-guest run found that an accepted outbound echo request did not allow its echo
  reply unless other-protocol settings were present; fixed in `nsplane-acl` with this task.
- `nsplane-ether` answers ARP / NDP only for the gateway address, so other hosts of the
  leased prefix are out of the guest's reach (documented as current behavior). An option to
  answer every address but the guest's own would lift it; separate work.
- With `--masquerade`, an `ICMPv6` Packet Too Big from the fragmenter is not restored by
  `Masquerade::reverse` (TCP, UDP and echo only); the advertised MTU keeps a conforming
  guest below it.
