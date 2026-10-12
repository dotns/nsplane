# 20261012-1800-peer-keyed-gate Peer-keyed, address-family-agnostic flow gate

- **status**: approved
- **createdAt**: 2026-10-12 18:00
- **approvedAt**: 2026-10-12 (user: "开始处理，这个是底层逻辑问题，需要处理"; the freeze is lifted for this
  feature only; auto mode, no round cap, automatic merges, watchdog with stuck-process checks)
- **relatedTask**: 20261012-1700-peer-keyed-gate

## Context

See the task: GF-1..4 (from ns NG-1..4). The flow gate becomes address-family-agnostic and
peer-keyed, and `AclFilterScope` becomes replaceable at runtime and per local identity. This
reverses decision Q5 of plan `20261007-0900` (IPv4-only gate), which was a porting artifact.

## Work (one L2)

1. Design note to L1 (yellow gate). It covers:
   - the family-generic flow and fragment keys;
   - the IPv6 extension-header walk (bounded), IPv6 fragments, and ICMPv6 errors quoting a flow;
   - peer-keyed bindings (empty addresses) and their interaction with address-listed bindings
     and `unbound_addresses`;
   - the `GatePolicyError::Ipv6` fate;
   - GF-4, which needs:
     - a replaceable, generation-tagged `AclFilterScope`;
     - per-local-identity selection: how the filter learns a peer's identity;
     - the default scope;
   - the bench plan.
2. GF-1 + GF-3 in the gate, with the IPv4 tests unchanged plus IPv6 equivalents. The model test
   gets IPv6 seeds.
3. GF-2: peer-keyed bindings.
4. GF-4: runtime per-identity scopes in `AclFilter` (+ an `nsplane` handle if needed).
5. e2e:
   - an IPv6 flow admitted and denied by a peer binding;
   - outbound IPv6 to an enforced peer denied while its inbound control traffic arrives;
   - a scope replaced under traffic;
   - a mixed IPv4/IPv6 peer.
   Benches: node_l3/gate and namespaces A/B for IPv4 (no regression) and IPv6 numbers. Docs:
   `docs/specs/node-l3.md`, `acl-generic-api.md`, architecture, CHANGELOG, a consumer note.

## Acceptance

- An IPv4-only policy behaves and costs as today (slot A/B).
- IPv6 is enforced with the same semantics.
- The full gate is green (just check with the term scan, cross, test-windows, cargo doc, e2e
  scripts).
- Release 0.13.0 on the owner's go.

## Annotations
