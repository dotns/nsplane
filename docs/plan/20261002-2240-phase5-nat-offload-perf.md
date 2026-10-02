# 20261002-2240-phase5-nat-offload-perf Phase 5: translation and NAT, offload, performance

- **status**: approved
- **createdAt**: 2026-10-02 22:40
- **approvedAt**: 2026-10-02 22:40 (user: run the roadmap to the end)
- **relatedTask**: 20261002-1020-data-plane-core, 20261002-1509-phase1-followups

## Context

Last phase of plan `20261002-1024-data-plane-core` inside this repository (Phase 6 is the ns
migration and happens in ns). Inputs:
- docs site `ns/next.md` §4.3 (IPv4 is a local view: stateless 4<->6 translation filter
  `alias6 <-> node6`, `alias4 <-> node4`, `self4 <-> node4(self)`, `lan4 <-> lan6` via the low
  32 bits; incremental TCP/UDP/ICMP checksums; applied after decryption and before
  encryption, shared by TUN and netstack; alias allocation is a node-local ns concern) and
  §6 (IPv6 fragmentation and ICMPv6 Packet Too Big handled once in the engine after
  translation; TUN and netstack share the limits). Read-only.
- ns code that moves (same owner; read-only): `quick-runtime/src/translate.rs` (~1.2k),
  `quick-runtime` fragment/mtu modules, `nat/src/subnet_route.rs`, `nat/src/conntrack/**`,
  `nat/src/packet_nat/{primitives,forward,reverse}.rs`.
- Plan annotations: Tailscale zero-copy receive (shared GRO buffers, encrypt into the UDP GSO
  buffer, `writev` for the virtio-net header, measured queue depths), ACL as a per-flow hook
  with per-peer bypass, per-PeerId principal caching, pending-dependency eviction counter.
- Follow-ups #1 (small-packet overhead), #12 (UAPI listen-port rebinding replaces non-UDP
  transports), #13 (fixed e2e container prefixes in linux.sh / lib.sh).

## Proposal

### Contract (fixed before parallel work; changes go through L1)

`nsplane-packet` (additive, owned by 5C, merged first):
- `PacketBuf::advance(n)` / `PacketBuf::reserve_front(n)`: O(1) move of the packet start
  inside the allocation (headroom shrinks/grows) without copying; `headroom()`.
- `PacketBuf::from_shared(BytesMut, offset, len)`: a packet that is a slice of a larger
  buffer (e.g. one GRO read); no headroom guaranteed; sealing such a buffer goes through the
  existing copy-into-pooled path, opening happens in place.

`nsplane-nat` (new crate, 5A): `Translator: PacketFilter` configured with a
`TranslationTable` (peer -> {alias4, alias6, node4, node6}, self mapping, lan4 <-> lan6
prefix pairs) supplied by the caller and replaceable atomically; RFC 7915-style IPv4<->IPv6
header translation incl. ICMP/ICMPv6 type mapping and ICMP error inner packets; incremental
checksums. `Fragmenter` stage in the engine after the filter chain (IPv6 fragmentation of
oversized packets toward the tunnel, ICMPv6 PTB / ICMPv4 frag-needed toward the local side,
per the engine MTU). `Conntrack` + `PortMap` (DNAT/SNAT for service publishing) as a
`PacketFilter`, bounded table, counted evictions.

`nsplane` driver and `nsplane-tun` (5B): Linux TUN `IFF_VNET_HDR` with GSO segmentation on
read and GRO coalescing on write (virtio-net header written with `writev`); `UdpTransport`
GSO send / GRO receive through `quinn-udp` (pre-approved) with zero-copy GRO slices
(`PacketBuf::from_shared`); `PacketBatch` end to end in the driver; behaviour without
offload unchanged and selectable.

`nsplane` / `nsplane-core` / `nsplane-acl` performance (5C): follow-up #1 (no rx buffer swap,
no `set_len` zero-fill, `advance` instead of `copy_within`); ACL hook (zero cost when not
installed, per-peer bypass, flow verdict cache keyed by peer + five-tuple + policy
generation, unified with the stateful-reply table, differential test vs full evaluation);
per-PeerId principal caching; pending-dependency eviction counter; queue high-water-mark
counters for every bounded queue and defaults set from measurements; optional crypto worker
pool in the driver (off by default, per-peer ordering preserved); netstack throughput
re-measured in release.

### Workstreams (L2)

| L2 | Scope | Depends on |
|---|---|---|
| 5A nat | `crates/nsplane-nat/**`, the fragmenter stage hook in `crates/nsplane/src/engine.rs` (one module `fragment.rs` + call site), its e2e tests and examples (`translate_node`, `port_map`), container cases | - |
| 5B offload | `crates/nsplane-tun/**`, `crates/nsplane/src/{udp,transport,io}.rs` and batch plumbing, `crates/nsplane-uapi/**` (#12), `scripts/e2e/**` (#13, iperf), its e2e and examples | 5C-T1 (`PacketBuf` additions) on main |
| 5C perf | `crates/nsplane-packet/**`, `crates/nsplane-core/**`, `crates/nsplane-acl/**`, `crates/nsplane/src/{engine,builder,handle,events}.rs` except the 5A hook, `crates/nsplane-netstack` (measurement only), benches | - |

Merge order: 5C-T1 (`PacketBuf` additions) is merged into main early as its own step; then
5A, 5C, 5B in completion order with L1 resolving conflicts in `engine.rs`, `lib.rs`,
`Cargo.lock`, `crates/nsplane-e2e`, `examples`, `scripts/e2e`.

### End-to-end tests and examples (required for every feature)

- 5A: in-process: IPv4-only app over alias4 reaching an IPv6-only peer and back; lan4<->lan6;
  ICMP echo and ICMP errors through translation; oversized packets fragmented and PTB
  delivered; port map DNAT/SNAT with conntrack expiry. Container: an IPv4-only client
  container talking through a translating nsplane node to a kernel-WireGuard IPv6-only peer;
  `translate_node` and `port_map` examples added to `just e2e-examples`.
- 5B: container iperf (TCP and UDP) TUN node <-> kernel WireGuard with offload off vs on,
  numbers in the report; GSO/GRO correctness (sizes around MTU, mixed flows, IPv4/IPv6);
  every existing matrix cell still PASS with offload on.
- 5C: data_path bench: core vs device-equivalent target <= 10 % at 64 B (follow-up #1) and no
  regression at 1420 B; ACL hook targets established flow <= 50 ns, bypass peer <= 10 ns,
  differential test; worker pool on/off throughput note; queue HWM report.

### Acceptance

`just check`, `just cross`, `just test-windows`, `cargo doc -D warnings`, release CLI +
`linux.sh`, `lib.sh`, `e2e-examples` green on each branch and on main after each merge;
benches reported per workstream.

## Risks

- Offload in containers depends on the host kernel (virtio-net header on TUN is generic;
  UDP GSO needs Linux >= 4.18, GRO >= 5.0); fall back cleanly when unsupported and report.
- Translation correctness: ported ns tests plus RFC 7915 vectors are the guard.
- Flow verdict cache must never outlive a policy change: generation check on every hit.

## Scope

nsplane repository only; `/srv/dotns/ns` and `/srv/dotns/docs` read-only. Dependencies:
`quinn-udp` (pre-approved) and crates already in Cargo.lock; anything else is a yellow.

## Annotations
