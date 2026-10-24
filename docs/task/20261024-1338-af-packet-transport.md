# 20261024-1338-af-packet-transport Ethernet frame transport over an AF_PACKET socket bound to an existing interface

- **status**: completed (released as 0.18.0)
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-24 13:38
- **plan**: 20261024-1338-af-packet-transport

## Description

Firecracker attaches a guest only to a host TAP device and keeps that TAP's file descriptor
itself, so `nsplane-ether` cannot open the same TAP. The owner chose a frame transport that
sends and receives the guest's frames on the TAP's host side through a raw `AF_PACKET`
socket, with no bridge and no second TAP, and asked who is responsible for creating the TAP.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Follow-up

- Frames sent to the guest right after the virtual machine attaches can be dropped by the
  kernel until the TAP's queue is active; guests retransmit.
- `ensure_tap` does not set an MTU: the tunnel MTU in the lease must stay at or below the
  TAP's MTU (default 1500).
- In packet mode `vm_wireguard` logs "guest connected" at startup (cosmetic).
