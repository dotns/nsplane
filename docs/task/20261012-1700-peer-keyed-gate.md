# 20261012-1700-peer-keyed-gate Peer-keyed, address-family-agnostic flow gate

- **status**: in_progress (owner lifted the freeze for it, 2026-10-12; ADR
  `2026-10-08-feature-freeze-0-11`)
- **priority**: P1
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-12 17:00

## Description

Requested by ns (ns plan `20261010-1542-concurrent-nsd-connections`, section "nsplane request:
node-keyed, address-family-agnostic flow gate", ns commit `b0a4652c`). The owner agrees: the
flow gate should decide by peer, for both address families, on the wire side of any
translation, not as an IPv4 address filter in front of the translator.

Today (0.12):
- `gate::FlowGate` handles IPv4 only. `replace` rejects IPv6 with `GatePolicyError::Ipv6`, and
  IPv6 packets pass unevaluated. This was decision Q5 of plan `20261007-0900`, now reversed.
- `AclFilterScope` (`outbound_sources`, `other_protocols`) is fixed when the `AclFilter` is
  built, and there is one per filter, not one per local identity.

As a result, a consumer with peer-keyed rules has to put the gate on its local IPv4 view in front
of its translator. It cannot govern the same peer's IPv6 traffic, and it cannot change a local
identity's admitted sources at runtime.

Item IDs are GF-n here: ns numbers them NG-1..4, which collides with this repository's nsgw items
NG-1..9.

| Item | ns ID | What | Crate |
| --- | --- | --- | --- |
| GF-1 | NG-1 | Address-family-agnostic gate. `GatePolicy` scopes, bindings, grants, holds, unbound rules and `unbound_addresses` accept IPv6. Flow state, IPv6 fragments (Fragment header) and ICMPv6 errors quoting a flow follow the IPv4 rules. IPv4 behavior unchanged | `nsplane-acl` |
| GF-2 | NG-2 | Peer-keyed bindings: a `GateBinding` with no addresses binds every packet of that `PeerId`, whatever its address family. Address-listed bindings keep working. A per-local-identity qualifier is not needed, because a `PeerId` already fixes the identity (0.12) | `nsplane-acl` |
| GF-3 | NG-3 | Outbound grants and holds by destination for both families, so outbound traffic to a peer's IPv6 address is governed like IPv4, without removing allowed IPs and without touching inbound source checks. Mostly follows from GF-1 | `nsplane-acl` |
| GF-4 | NG-4 | Runtime scopes per local identity. `AclFilterScope` becomes replaceable on a running filter, atomically, with a generation as `FlowGate::replace` has. It can be set per local identity, chosen by the identity of the packet's peer (the filter learns a peer's identity from the engine or from its `PeerIdentity` hook; the design note decides which), with the current single scope as the default | `nsplane-acl`, `nsplane` |

Conventions:
- Additive: an IPv4-only policy behaves and costs as today, shown by the node_l3/gate and
  namespaces bench A/B.
- An nsplane-e2e test per item:
  - an IPv6 flow admitted and denied by a peer binding;
  - outbound IPv6 to an enforced peer denied while its inbound control traffic still arrives;
  - a scope replaced under traffic.
- The specs `docs/specs/node-l3.md` and `acl-generic-api.md` are updated where IPv4-only was
  stated.

What ns does once it lands:
- compiles Node L3 on the peer's identity addresses, wire side of the translator;
- denies outbound native IPv6 to nodes of an enforced network;
- admits subnet sources per membership at runtime.

## Assessment (L1, 2026-10-12)

- Generic and business-agnostic. It removes a limitation (IPv4-only) that was only ever a
  porting artifact.
- Size: medium to large. The gate is about 2,900 lines with IPv4-specific parsing, state keys,
  fragment and ICMP-error handling. GF-1 is most of the work; GF-2 and GF-3 are small on top.
  GF-4 is a separate, small-to-medium change in `AclFilter`.
- Breaking surface: none for IPv4 users if `GatePolicyError::Ipv6` is kept as a never-returned
  variant or removed in a minor release. Proposed release: 0.13.0.
- One L2, with a design note first: the family-generic state key, the IPv6 extension-header walk
  (bounded), ICMPv6 error matching, the per-identity scope selection, the bench plan.
