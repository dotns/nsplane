# ADR: nsplane stays business-agnostic; policy semantics are compiled above it

Status   : Accepted
Date     : 2026-10-06

## Context

nsplane started as the data plane for ns, and several ns concepts were ported into it with
their behavior intact: `SourceAssertion::Terminate` and `External { idp }`, the
`crates_acl()` preset that reproduces ns's `crates/acl`, and the node L3 gate with Node /
Service / Subnet grants. A second consumer, the nsgw gateway rebuild (docs site
`nsgw/next.md`, item L2), asked for NSD's gateway policy semantics in `nsplane-acl`:
subjects, groups, external subjects with several subjects, terminate anchors, the virtual
dial port, and policy self-tests. Each such request makes nsplane a model of one product's
control plane and harder to reuse.

The owner's direction (2026-10-06): ns is one product that uses nsplane, and nsplane must
stay usable by other libraries and products. nsplane's ACL works on business-agnostic flows.
Every other policy is a layer above it that compiles its model down to flow rules and
pushes them.

## Decision

nsplane provides data-plane mechanisms with generic inputs. A product's model (identities,
subjects, groups, realms, services, leases, grants, tokens) is translated by the product, or
by a shared contract library such as nsshared, into those generic inputs before it reaches
nsplane.

### What nsplane does

- Packet and flow processing: WireGuard, transports and carriers (ADR
  `2026-10-03-data-channel-protocols-in-nsplane`), the local-side graph, TUN, the user-space
  stack, NAT and translation, fragmentation, path MTU, counters and status.
- Flow-level access control in `nsplane-acl`:
  - Matching on the five-tuple, CIDR prefixes, ports, protocols and ICMP types.
  - Matching on opaque source labels. A source carries a set of labels, and a rule matches
    when any label matches. nsplane never interprets a label.
  - A stateful flow table with reply allowance and timeouts, fragment handling, and bounded
    caches.
  - An atomic, generation-tagged replacement of the whole rule set.
  - Explicit policy states: not installed (the configured default applies), installed and
    empty (deny), and failed (fail closed).
  - Opaque rule IDs carried into decisions and logs.
  - A packet-independent evaluation API for proxies that admit connections without a packet:
    flow description plus labels in, decision out.
- Narrow traits and callbacks where a decision needs the product, for example the WSS open
  resolver, the redirect decision, the inbound-destination source and the dialer. They are
  called with generic arguments and return generic results.

### What nsplane does not do

- No product identity or policy model: no subjects, groups, group expansion, realms, tenants,
  organizations, roles, services or grants as types or semantics in nsplane. No parsing of a
  product's policy documents, no policy self-test language, and no business-specific
  "unknown vs anonymous" classification. Those are compiled above nsplane into labels and
  flow rules.
- No control-plane protocol, enrollment, token issuing or validation of product claims, and
  no persistence of product state.
- No choice of which port or address a product's policy is about. For example, the virtual
  dial port versus the backend port is decided by the caller that builds the flow
  description.
- No host integration that belongs to the product: nft, TPROXY, policy routing and their
  accounting stay in the product (nsgw decision G7).
- No product-specific presets added from now on. A product that needs one keeps it in its own
  code or in a shared contract library, and builds it from the generic API.

### Existing product concepts

`SourceAssertion::Terminate` / `External`, `crates_acl()` and the node L3 gate's grant model
predate this decision and ns depends on them. They stay until they can be expressed through
the generic API. Then they move to a preset outside the generic core, or to ns, without a
behavior change for ns. No new feature builds on them.

## Consequences

- nsgw's L2 shrinks to the generic additions listed above: label sets, explicit policy states,
  rule IDs and the packet-independent evaluation API. The NSD subject semantics, the policy
  compiler and its parity vectors against v1 `acl` live in nsshared (serialized policy and
  compiler) and nsgw (use). This replaces the recommendation for decision G5 in
  `nsgw/next.md`, which is the owner's to update.
- A request to nsplane is checked against this ADR first. A request that names a product
  concept is restated in generic terms or declined with the reason.
- Parity with a product's old behavior is tested in the product's compiler. nsplane tests its
  generic semantics.
