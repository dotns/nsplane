# 20261024-1338-af-packet-transport Ethernet frame transport over an AF_PACKET socket bound to an existing interface

- **status**: completed (released as 0.18.0)
- **createdAt**: 2026-10-24 13:38
- **relatedTask**: 20261024-1338-af-packet-transport

## Goal

`nsplane-ether` serves a guest whose virtio-net is backed by a host TAP that another
process (Firecracker) holds: frames go in and out through an `AF_PACKET` socket bound to
that interface, so DHCP, ARP, NDP, the engine and the ACL work as on the Unix stream and TAP
transports. nsplane can create and remove the TAP itself, so the embedder needs no network
setup beyond starting nsplane before the virtual machine.

## Work

| Step | Work | Verify |
| --- | --- | --- |
| P1 | Linux module `packet`: `PacketSocket::bind(ifname)` opens `AF_PACKET` / `SOCK_RAW` / `ETH_P_ALL`, binds to the interface index, sets `PACKET_IGNORE_OUTGOING` (its own writes are not read back) and non-blocking, registers with tokio; `split()` gives a reader and a writer implementing `FrameRead` / `FrameWrite`. Only frames the guest sent are delivered (`PACKET_OUTGOING` skipped as a fallback for kernels without the option) | unit tests on a veth pair or a TAP in a network namespace where the test has `CAP_NET_ADMIN`, skipped otherwise |
| P2 | Offloads: Firecracker negotiates checksum and segmentation offload with the guest, so a frame can arrive with a partial checksum or as one large GSO frame. The socket enables `PACKET_VNET_HDR`; the reader completes partial checksums and segments GSO frames (TCP v4/v6, UDP) before handing them on, reusing the segmentation code in `crates/nsplane-tun/src/offload.rs` (how it is shared, e.g. moved into `nsplane-packet`, is proposed to L1 before the move); the writer sends with an empty virtio-net header | tests with crafted GSO / partial-checksum frames; real guest in P4 with offloads on |
| P3 | Interface ownership: `TapConfig` / `ensure_tap(name, owner uid/gid)` creates a persistent TAP (`TUNSETIFF` with `IFF_TAP \| IFF_NO_PI \| IFF_VNET_HDR`, `TUNSETOWNER` / `TUNSETGROUP`, `TUNSETPERSIST`), turns off IPv6 and address autoconfiguration on it so the host kernel does not answer the guest, brings it up, and removes it on drop; an existing interface is used as it is and left in place | tests as P1; the TAP is gone after drop |
| P4 | Example and real guest: `vm_wireguard` gets `--packet <ifname>` (with `--create-tap`) next to the Unix socket; a script starts Firecracker with KVM, the example and wireguard-go in labelled siblings; the guest gets its lease, reaches the peer and is reached by it, and the ACL check of the VM example passes | run once, result in the report; ignored by `just check` |
| P5 | Reference page `nsplane-ether` (transport, capabilities `CAP_NET_RAW` and, for `--create-tap`, `CAP_NET_ADMIN`), guide section on Firecracker in both languages, CHANGELOG `[Unreleased]` | `just docs` |

## Constraints

- No new dependency: `libc` is already a Linux dependency of `nsplane-ether`. Linux only;
  other targets do not build the module.
- The unsafe code (socket options, `ioctl`) carries `SAFETY` comments, as in `tap.rs`.
- Every container and network the scripts start carries `--label ai-agent=true`.
- Gate: `just check`, `cargo doc -D warnings`, `just cross`, `just test-windows`.

Ships with 0.18.0; it builds on the VM example (`20261024-1329-vm-wireguard-example`).

## Out of scope

- Several guests on one socket, `PACKET_MMAP` ring buffers, a bridge setup.
