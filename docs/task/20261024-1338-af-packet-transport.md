# 20261024-1338-af-packet-transport Ethernet frame transport over an AF_PACKET socket bound to an existing interface

- **status**: in progress (owner approved 2026-10-24: "用C方式最合理、不引入额外管理"; "可以")
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
