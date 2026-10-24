# 20261024-1500-gino-egress-requests Sandboxed agent egress requests from gino-agent

- **status**: pending (owner decision 2026-10-24: R1, R3, R4 and a generic DNS crate ship in 0.17.0; R5 and R6 not done)
- **plan**: 20261024-1600-egress-0-17
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-24 15:00

## Description

gino-agent wants nsplane in the egress path of sandboxed engine runs (bubblewrap TUN fds now,
libkrun virtio-net guests later). Revision 2 of the request (2026-10-24) makes the agent its
own exit: one transparent netstack per run terminates every guest flow and gino re-originates
allowed ones from host sockets; the WireGuard engine is only an optional remote-exit extension.

| Id | Prio | Request | Assessment |
|---|---|---|---|
| R1 | P0 | Transparent netstack: any destination or listed prefixes; original destination and source on `TcpConnection` / `UdpFlow`; accept hook before the SYN-ACK / first delivery (TCP RST, UDP ICMP unreachable on reject); replies and stack-emitted ICMP sourced from the original destination; optional ICMP echo hook; per-stack bounds and reject counters | Extends plan `20261024-1430-netstack-any-destination`. A mode of `nsplane-netstack`, not a separate stack type: the difference is the address checks and the hook, the driver is shared. Async hook: a bare SYN (or a UDP flow's first datagram) is held in a bounded pending table until the decision or a timeout, then fed to smoltcp or answered with RST / ICMP; retransmitted SYNs are dropped while pending. The ICMP echo hook is a later step |
| R2 | P1 | DNS responder helper with a fake-address pool | Reworked: generic crate `nsplane-dns` (codec on `simple-dns`, `Resolver` trait, UDP / TCP server, fake-address pool with reverse lookup); policy stays with the consumer, usable by ns too |
| R3 | P1 | Ethernet adapter (framed Unix stream / TAP, ARP, IPv6 ND/RA, optional DHCPv4) | New crate `nsplane-ether`, no new dependency; largest item. Accepted here with a real libkrun guest (`/dev/kvm` is available) |
| R4 | P1 | Opt-in, rate-limited flow decision events from the transparent stack (and `FlowGate`) | Additive; lossy channel beside the stack's stats |
| R5 | P2 | Dynamic local-side membership for one long-lived engine (remote exit only) | Additive new type in `nsplane`. The intended model is one engine with one local identity per run; engines cannot share a `UdpTransport` port |
| R6 | P2 | Incremental address sets for `FlowGate` (remote exit only) | `GateGrant` is an exhaustive struct; a new field breaks ns's literal in `node_l3/compile.rs`, a separate registration keeps the API |

Memory per transparent netstack (asked by gino; measured 2026-10-24 on 0.16.2, release,
glibc malloc, 4-worker runtime, stacks paired through `pump`, VmRSS deltas per stack):

| State | Default buffers (690 KiB rx + tx) | `tcp_rx_buffer` / `tcp_tx_buffer` = 128 KiB |
|---|---|---|
| Idle stack (driver task, queues, pools) | about 42-48 KiB | same |
| 8 established TCP connections, no data yet | about 130 KiB | same |
| 8 connections after 4 MiB each (buffers touched) | about 7.7-8.2 MiB (about 950 KiB per connection) | about 2.7 MiB (about 330 KiB per connection) |

Buffers are allocated zeroed and become resident as data flows; freed memory stays with glibc
until `malloc_trim`. Bounds today: listener pool 32 half-open sockets, accept queue 128, UDP
flows 65,536 with 256 queued datagrams each, ingress and egress 1024 packets. Established TCP
connections have no count limit: the worst case is connections x (rx + tx buffer + 2 x
`stream_buffer`). R1 should add a per-stack connection limit (or the accept hook enforces it).

VM testing: `/dev/kvm` is available on the development host, directly and in sibling
containers (verified 2026-10-24), so R3 can be accepted here with a real libkrun guest.

Dependency subset: `nsplane-netstack` and `nsplane-tun` depend on `nsplane` for the I/O traits,
which pulls `nsplane-core` and `nsplane-noise`. Splitting the traits into a light crate
(re-exported from `nsplane`) is possible but a structural change; not required by gino.

Packaging: releases are git tags; the smoltcp fork is a git dependency. Publishing to
crates.io is an owner decision.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)
