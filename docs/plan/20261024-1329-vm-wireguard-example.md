# 20261024-1329-vm-wireguard-example Example: a virtual machine reaching a remote WireGuard peer through nsplane

- **status**: proposed
- **createdAt**: 2026-10-24 13:29
- **relatedTask**: 20261024-1329-vm-wireguard-example

## Goal

A runnable example and tests show the path virtual machine (virtio-net over a
length-prefixed Unix stream, as libkrun and QEMU use it) -> `nsplane-ether` -> WireGuard
`Engine` -> `UdpTransport` -> a standard WireGuard peer, in both directions, with the MTU
set correctly. No library change is expected; a gap found on the way is reported, not
worked around silently.

## Work

| Step | Work | Verify |
| --- | --- | --- |
| V1 | `examples/src/bin/vm_wireguard.rs`: listens on a Unix socket for one guest, runs `nsplane-ether` (DHCP lease with the tunnel address, gateway, DNS and an MTU that fits the tunnel; IPv6 RA when configured) and an `Engine` built on `EtherSource` / `EtherSink` with a `UdpTransport`, a private key and one peer from the command line or a small config; optional `Masquerade` filter for a guest address outside the tunnel network; an ACL on the engine (`AclFilter` with a policy from a file or flags, as in `examples/src/bin/acl_gateway.rs`) that decides which flows the guest may open and which the remote side may open to the guest | builds on every target the examples build on (non-Unix: a stub `main` that says it needs Unix) |
| V2 | In-process test (`examples/tests/`): a scripted guest over a socketpair (DHCP, ARP, then TCP and UDP) through the example's wiring to a second nsplane engine with a `NetStack` as the remote side; traffic in both directions, the remote side opens a connection to the guest too; payloads above the tunnel MTU are refused or fragmented as configured; with an ACL installed, an allowed flow passes in each direction and a denied flow (another port or destination) is dropped and counted in `AclFilterStats`, and a policy reload takes effect without restarting | runs in `just check` |
| V3 | Real guest against a standard peer: a script next to the existing `crates/nsplane-ether/scripts/vm-guest.sh` starts wireguard-go (the image under `scripts/bench/wireguard-go`) in one labelled sibling container and QEMU with KVM plus the example in another, on a labelled network; the guest gets its lease, pings and opens TCP to an address behind the peer, and the peer reaches the guest; with an ACL allowing one port, a second port is blocked in each direction | run once, result in the report; ignored by `just check` |
| V4 | `examples/README.md` row and section; a section in both guide languages (VM to WireGuard: wiring, address plan, MTU = tunnel MTU, masquerade option); CHANGELOG `[Unreleased]` | `just docs` |

## Constraints

- No new dependency; examples crate only, plus test scripts. A library change, if one turns
  out to be needed, is escalated to L1 first.
- Every container and network the scripts start carries `--label ai-agent=true` and is
  removed at the end.
- Gate: `just check`, `cargo doc -D warnings`, `just cross`, `just test-windows`.

Ships with the DNS passthrough and DNS policy routing as 0.18.0.

## Out of scope

- A `SOCK_DGRAM` (unixgram) frame transport, several guests on one engine, DNS split to a
  local `nsplane-dns` for the guest: separate work.
