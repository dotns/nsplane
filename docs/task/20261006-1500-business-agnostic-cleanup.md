# 20261006-1500-business-agnostic-cleanup Remove product concepts from nsplane

- **status**: pending
- **priority**: P1
- **owner**: L1 (7f5cstru); runs after plan 20261006-0900-ns-requests-2
- **createdAt**: 2026-10-06 15:00

## Description

ADR `2026-10-06-business-agnostic-scope`. An audit on main (2026-10-06) found product
concepts in nsplane-acl and nsplane-nat. The other crates are business-agnostic. Owner
decisions (2026-10-06):
- The removed parts are specified in documentation, and the products implement them
  themselves.
- The work runs after the current round.
- There is no compatibility layer.

## Items

| Item | What changes in nsplane | Specified for products (doc) |
| --- | --- | --- |
| AG-1 generic ACL core | Opaque source label sets, explicit policy states, opaque rule IDs and a packet-independent evaluation API (task 20261006-1300 NG-1..4). The rule model stays generic: prefixes, ports, protocols, ICMP types and labels | - |
| AG-2 source identity | `SourceAssertion` (`WgPeerKey`, `Terminate`, `External`), `TerminateBinding` and the source classes are replaced by labels from the peer identity hook | How ns maps WireGuard keys, terminate bindings and IdP assertions to labels; parity cases from the ported crates/acl tests |
| AG-3 policy document | `AclPolicy` JSON (`hosts`, `acls`, `tests`, accept-only) and `crates_acl()` are removed. nsplane keeps a typed rule API | The document format, host alias expansion, the self-test semantics and the crates_acl preset, expressed as rules plus filter config; the differential fixtures (12,181 packets) re-pointed at the product side |
| AG-4 node L3 gate | The ns model is removed: `NodeL3Config` (Node / Service / Subnet grants, peer bindings, policy requirements, transport), `NodeL3Reason` mapped to ns, `GatewayConsumer*`. What remains is a generic stateful flow gate: grants as labels to destination prefix / protocol / ports; per-protocol idle timeouts; per-source and global limits; orphan-fragment and ICMP-error handling; an enforce/observe switch; a generic divert callback; generic reasons and counters | The node L3 semantics (grant kinds, source binding, same-owner rule, Subnet LAN DNS admission, modes, reason mapping, gateway consumer) and how to compile them into the generic gate; the 6,361-step differential fixture moves with it |
| AG-5 translator names | `PeerMapping` and table lookups use generic names for per-peer explicit address mappings (RFC 7757 EAM); the Quick v2 names (`node6`, `node4`, `alias6`, `alias4`, `self4`, native alias) go away | The Quick v2 address plan mapped onto the generic fields |
| AG-7 WsFrame stream carrier | `WssStreamClient`, `WssStreamServer` and the WsFrame codec are deprecated. ns drops `tunnel-ws` stream proxying (ns/next) and the gateway offers no WebSocket stream services (nsgw G20). They are removed once ns has switched (M6). The WSS datagram dialer stays | - |
| AG-6 documentation wording | About 125 rustdoc lines that cite ns, Quick or NSD are reworded generically; provenance stays in task docs and the CHANGELOG | - |

## Acceptance

- No product concept in any public nsplane API, checked by a term scan in the gate: ns,
  Quick, NSD, nsgw, realm, subject, group, terminate, idp, alias4/6, node6, gateway consumer.
- Generic tests per item, and the fixtures are kept as product-side parity data.
- A specification document per removed concept, under docs/, for products to implement.
- The CHANGELOG lists every removed item and its generic replacement, under a breaking minor
  release (0.11.0).
