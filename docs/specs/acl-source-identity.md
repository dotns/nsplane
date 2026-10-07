# ACL source identity: rebuilding the removed model on labels (AG-2)

- **Status**: spec for workstream AC, item AG-2 (slice C3 of `acl-generic-api.md`)
- **Audience**: products that feed `nsplane-acl`; ns is the reference product
- **Normative API**: `docs/specs/acl-generic-api.md` sections 1.3-1.5, 2.1, 2.4, 3 and 4.2.
  Rust snippets below are **illustrative**: they use the design note's names, and the final
  names follow the merged code.

## 1. Scope and status

ADR `docs/decisions/2026-10-06-business-agnostic-scope.md` makes nsplane business-agnostic:
a source carries a set of opaque labels, and nsplane compares them for equality without
interpreting them. The identity model that nsplane-acl took over from ns is therefore
removed in slice C3:

| Removed item | Replacement in nsplane | Owner of the old semantics |
| --- | --- | --- |
| `SourceAssertion::WgPeerKey { pubkey }` | a label chosen by the product (3.1) | product |
| `SourceAssertion::Terminate { binding }`, `TerminateBinding { ip, anchor }` | labels plus the address label `A` (3.2) | product |
| `SourceAssertion::External { idp }` | a label (3.3) | product |
| `SourceAssertion::source_class()` (`"client-wg-key"`, `"terminate-binding"`, `"external-idp"`) | none; the product logs its own class next to the `RuleId` (3.7) | product |
| `SourceAssertion::source_anchor()`, `SourceAssertion::ip()` | none; the label text is the product's | product |
| `wg_peer_anchor(&[u8; 32]) -> "key:<hex>"` | none; the product formats its key label | product |
| `AccessRequest::{from_ip, with_wg_peer_key}` | `Flow` plus `&LabelSet` | - |
| `PeerIdentity::{assertion, assertion_for}` | `PeerIdentity::{labels, labels_for}` returning `Option<LabelSet>` | - |
| `PeerIdentityMap` (`insert(peer, SourceAssertion)`, `insert_by_source(peer)`) | `PeerLabelMap` (`insert(peer, LabelSet)`, `insert_by_source(peer, Vec<(IpNet, LabelSet)>)`) | - |
| `NamespaceMember::principal`, `GrantEnd::Peer`, `PinholeSpec::peer` (principal strings) | `NamespaceMember::label`, `GrantEnd::Label`, `PinholeSpec::label` | - |
| `NamespaceId::is_app` and the `"app:"` id prefix | `NamespaceKind::Pinholes`, `pinhole_kinds` | product chooses ids |
| `PinholeError::NotAppNamespace` | `PinholeError::NotPinholeNamespace` | - |

The product owns the mapping from its identities to labels. Nothing in this document is
implemented by nsplane; it states what a product must build to keep the old verdicts.

## 2. Semantics of the removed model

### 2.1 Principal and anchor per assertion kind

A source was a `SourceAssertion`. Its **principal** was `source_anchor()`, a string used
for namespace membership, grant ends and pinholes. Its IP (`ip()`) was used by CIDR rules.

| Kind | `source_class()` | Principal (`source_anchor()`) | `ip()` | Matches rule `src` |
| --- | --- | --- | --- | --- |
| `WgPeerKey { pubkey }` | `"client-wg-key"` | `wg_peer_anchor(pubkey)` = `"key:"` + 64 lowercase hex | `None` | `*`; `key:<hex>` with the same 32 bytes |
| `Terminate { binding }` | `"terminate-binding"` | `binding.anchor` (verbatim) | `binding.ip` | `*`; a CIDR or alias containing `binding.ip` (never when `ip` is `None`) |
| `External { idp }` | `"external-idp"` | `"idp:" + idp` | `None` | `*` only |

Notes that a product compiler must reproduce:

- A rule `src` of `key:<hex>` was parsed into 32 bytes (`parse_hex32`, upper or lower case
  accepted) and compared to the key bytes. Labels compare text, so the product must
  canonicalize both sides (lowercase hex).
- A CIDR source compared against `binding.ip`, **not** the packet's source address
  (`AccessRequest::src_ip` was kept only for logs). For a by-source peer both are equal
  (2.2); for a terminate binding inserted with `insert`, a packet from another address still
  matched as `binding.ip`.
- A key or IdP source never matched a CIDR rule, even when its packet's source address lay
  inside the prefix (`SrcMatcher::Cidr` reads `ip()`, which is `None` for them).
- The principal namespace was one flat string space: a terminate anchor equal to a
  `key:<hex>` string or to `idp:<x>` collided with the other kinds.

### 2.2 The by-source principal

`PeerIdentityMap::insert_by_source(peer)` marked a peer (for ns: every peer that is not a
relay client, typically a gateway or node carrying several source addresses). For each
packet the filter called `assertion_for(peer, remote)`, which returned
`SourceAssertion::from_ip(remote)`: `Terminate { ip: Some(remote), anchor:
remote.to_string() }`. So:

- one principal per remote address, the address's `Display` text (`10.0.0.1`, `fd00::1`);
- every address had a principal: a by-source peer was never unknown;
- a namespace member whose `principal` was an address string (`"fd00::a"`) captured
  exactly the packets from that address (nsplane test helper `address_namespace`);
- `assertion(peer)` returned `None`; `by_source(peer)` returned `true`;
- the filter cached the resolved principal per `(peer, address)` in an LRU bounded by
  `reply_capacity`, and computed the bypass per address.

### 2.3 Namespaces, grants and pinholes

- `NamespaceMember::principal` placed a principal in a namespace. ns (`crates/overlay`)
  used `wg_peer_anchor(wg_key)` for every member.
- `GrantEnd::Peer(principal)` named one principal. ns built grant ends with
  `wg_peer_anchor`.
- `PinholeSpec::peer` named the principal the pinhole serves.
- A namespace id starting with `"app:"` was an app namespace: no accept rules, no
  `allow_app_pinholes`, no grant may name it, members get access only through pinholes.
  `allow_app_pinholes` of a member's non-app namespaces gated the pinhole kind.

### 2.4 Decision logs

nsplane-acl itself logged `src`, `dst`, `port`, `proto` and the rule index; the source
class and anchor strings were read by the product (`source_class()`, `source_anchor()`)
for its own decision logs (`source_class=client-wg-key`, `source_wg_peer`).

## 3. Mapping onto the generic API

The product picks a label scheme. nsplane never parses labels, so the prefixes below are
recommendations, not API. Recommended scheme (used in the rest of this spec):

| Label | Text | Given to |
| --- | --- | --- |
| key label | `key:<64 lowercase hex>` | a peer judged by its WireGuard key |
| address label `A` | `addr` | every address-bound source (old IP-bearing terminate bindings, by-source peers) |
| address principal | `addr:<ip Display>` | by-source address that is a namespace member by address (3.4) |
| anchor label | `anchor:<anchor>` | a terminate binding's stable anchor |
| IdP label | `idp:<idp>` | an external identity-provider assertion |

Distinct prefixes remove the old collision between anchors and key or IdP strings. Any
scheme works as long as the rule compiler and the identity side produce the same text.

### 3.1 WireGuard key

```rust
// Illustrative.
fn key_label(pubkey: &[u8; 32]) -> Label {
    let mut s = String::with_capacity(68);
    s.push_str("key:");
    for b in pubkey { let _ = write!(s, "{b:02x}"); }
    Label::new(s)
}
identities.insert(peer, LabelSet::new([key_label(&pubkey)]));
// Rule `src: ["key:<hex>"]` -> labels only, no sources:
Rule::new(id, protocols).with_labels(vec![key_label(&parsed_key)]);
```

A key-labelled source carries no `A`, so it never matches a CIDR rule (2.1), whatever its
packet's source address.

### 3.2 Terminate binding

- `binding.ip = Some(ip)`: labels `{A, anchor:<anchor>}`.
- `binding.ip = None`: labels `{anchor:<anchor>}` (no `A`: CIDR rules never match).
- A rule `src` CIDR or alias becomes `sources: [cidr]` **and** `labels: [A]` (2.2 of the
  design note: conjunction), so only address-bound sources match it.

The new `sources` condition reads `Flow::src` (the packet), not the binding's IP. A product
keeps the old verdicts with one of:

1. **Source equals binding IP** (recommended when the transport already enforces it, as
   WireGuard allowed IPs do): `insert(peer, {A, anchor})`.
2. **Bind the label to the IP**: `insert_by_source(peer, vec![(ip/32 or /128, {A,
   anchor})])`. A packet from another address resolves to `None` and is dropped
   `UNKNOWN_PEER` instead of being judged as `binding.ip`. The verdict for such a packet
   can differ from the old model (old: judged as `ip`); the product decides whether that
   matters (it is stricter).

### 3.3 IdP assertion

`External { idp }` becomes `{idp:<idp>}`. No `A`, so only `*` rules and rules naming that
label match, as before.

### 3.4 By-source peers

Two cases:

- **Default policy only** (ns `crates/acl` preset, design note 4.2): `insert(peer, {A})`.
  CIDR rules read the flow's source address directly, so no per-address principal is
  needed.
- **Namespace members by address** (members whose old principal was an address string):
  `insert_by_source` with a prefix table. Each address that was a member gets its own
  entry; catch-all prefixes keep every other address known, as the old model did.

```rust
// Illustrative: the old "every remote address is its own principal" for a peer whose
// addresses fd00::a and 10.0.0.1 are namespace members.
let a = Label::from("addr");
identities.insert_by_source(gateway, vec![
    ("fd00::a/128".parse()?, LabelSet::new([a.clone(), Label::from("addr:fd00::a")])),
    ("10.0.0.1/32".parse()?, LabelSet::new([a.clone(), Label::from("addr:10.0.0.1")])),
    ("0.0.0.0/0".parse()?,  LabelSet::new([a.clone()])),
    ("::/0".parse()?,       LabelSet::new([a])),
]);
// Namespace member: NamespaceMember { label: "addr:fd00::a".into(), addresses: vec![..] }
```

Longest prefix wins; an address outside every prefix is unknown (`UNKNOWN_PEER`). Without
the catch-all entries a by-source peer can now be unknown, which the old model never was.
Use `Display` text of `IpAddr` for `addr:<ip>` so that the member label and the identity
label are byte-equal.

### 3.5 Namespace members, grant ends and pinholes

| Old | New |
| --- | --- |
| `NamespaceMember { principal: wg_peer_anchor(k), addresses }` | `NamespaceMember { label: key_label(k), addresses }` |
| `NamespaceMember { principal: "<ip>", .. }` | `NamespaceMember { label: "addr:<ip>", .. }` with 3.4 |
| `GrantEnd::Peer(wg_peer_anchor(k))` | `GrantEnd::Label(key_label(k))` |
| `PinholeSpec { peer: wg_peer_anchor(k), .. }` | `PinholeSpec { label: key_label(k), .. }` |
| `allow_app_pinholes: {"transfer"}` | `pinhole_kinds: {"transfer"}` |

Membership is keyed by label: a source is a member of the union of the namespaces of all
its labels. A destination address resolves to the member label owning it (longest prefix,
then the smallest label).

### 3.6 `app:` namespaces

The id stays the product's (`"app:<session>"` is fine) but no longer carries meaning:

```rust
// Illustrative.
engine.store_namespace("app:s1", NamespacePolicy {
    kind: NamespaceKind::Pinholes,
    members: vec![NamespaceMember { label: key_label(&k), addresses }],
    rules: vec![],                       // must be empty
    pinhole_kinds: BTreeSet::new(),      // must be empty
    outbound: Some(vec![]),
})?;
engine.store_namespace("nsd:a", NamespacePolicy {
    kind: NamespaceKind::Rules,
    pinhole_kinds: BTreeSet::from(["transfer".to_owned()]),
    ..policy
})?;
let guard = engine.open_pinhole("app:s1", PinholeSpec { label: key_label(&k), kind: "transfer".into(), .. })?;
```

Rules or `pinhole_kinds` on a `Pinholes` namespace are rejected (`Error::InvalidNamespace`),
as are grants naming one (`Error::InvalidGrant`). A pinhole on a `Rules` namespace fails
with `PinholeError::NotPinholeNamespace`.

### 3.7 Decision logs

nsplane reports a `RuleId` (in `Decision`, `Matched` and its `tracing::debug!` line) or a
`reasons::*` constant. It no longer knows a source class. A product that logged
`source_class` keeps a map from its label prefix to its class and logs both:

| Label prefix | Old `source_class` |
| --- | --- |
| `key:` | `client-wg-key` |
| `anchor:`, `addr`, `addr:` | `terminate-binding` |
| `idp:` | `external-idp` |

```rust
// Illustrative.
let decision = engine.evaluate(&labels, &flow);
tracing::info!(source_class = class_of(&labels), rule = ?decision.rule_id(),
               reason = ?decision.reason(), "acl decision");
```

Rule ids are opaque; ns uses `"<source>#<index>"` (design note 4.2), so the old rule index
is still recoverable from the id.

## 4. Parity cases

A product compiler (rules per design note 4.2, identities per section 3) must reproduce
these verdicts. Keys are written `kNN` = 32 bytes of `0xNN`; `key(kNN)` is its key label.
"nsplane" paths are relative to this repository before C3; "ns" paths are on branch
`refactor/nsplane` of `/srv/dotns/ns`. Unless stated, the source is in no namespace and
the default rule set is installed.

| # | Rule set / setup | Source labels | Flow | Expected | Source |
| --- | --- | --- | --- | --- | --- |
| 1 | `key(k07)` -> any | `{key(k07)}` | TCP to 10.0.0.2:80 | Accept | nsplane `crates/nsplane-acl/src/engine.rs` `key_principal_rule_matches_wg_peer_key_only`; ns `crates/acl/src/engine.rs` same test |
| 2 | same | `{key(k09)}` | same | Deny `DENIED` | same tests |
| 3 | same | `{A}` (from 10.0.0.2) | same | Deny `DENIED` | same tests |
| 4 | `sources 10.0.0.0/24, labels [A]` -> any | `{key(k01)}`, flow src 10.0.0.7 | TCP to 10.0.0.2:80 | Deny `DENIED` | nsplane `engine.rs` and ns `crates/acl/src/engine.rs` `cidr_rule_does_not_match_a_keyed_source` |
| 5 | `src key(..)` matcher | key bytes equal / differ / IP source | - | match / no / no | ns `crates/acl/src/matcher.rs` `src_key_parses_and_matches_wg_peer_key` |
| 6 | test policy: `10.0.0.1/32 -> 10.0.0.2:80 tcp`, `fd00::1/128 -> fd00::2:443 tcp`, `key(KEY) -> *:53 udp` | key peer `{key(KEY)}` | UDP 10.0.0.1 -> 10.0.0.2:53, and fd00::7 -> fd00::2:53 | Accept (any address, both families) | nsplane `crates/nsplane-acl/src/filter.rs` `key_principal_and_cidr_principal` |
| 7 | same | key peer | TCP 10.0.0.1 -> 10.0.0.2:80 | Drop `DENIED` | same test |
| 8 | same | terminate peer `{A}` at 10.0.0.1 | UDP 10.0.0.1 -> 10.0.0.2:53 | Drop `DENIED` | same test |
| 9 | same | peer 99 not in the map (`None`) | TCP 10.0.0.1 -> 10.0.0.2:80 | Drop `UNKNOWN_PEER`, counter `unknown_peer` = 1 | `filter.rs` `unknown_peer_is_dropped` |
| 10 | same, closure identity returning `Some` only for one peer | other peer | UDP to :53 | Drop `UNKNOWN_PEER` | `filter.rs` `closure_identity` |
| 11 | same | terminate peer, then `remove(peer)` | TCP 10.0.0.1 -> 10.0.0.2:80 | Accept, then Drop `UNKNOWN_PEER` on the next packet | `filter.rs` `identity_map_updates_through_shared_handle` |
| 12 | same; gateway via 3.4 (with catch-all) and a key peer in the same map | gateway | TCP 10.0.0.1 -> :80; TCP 10.0.0.5 -> :80 (twice each, new source port) | Accept; Drop `DENIED` (stable per address) | `filter.rs` `by_source_peer_is_judged_by_each_source` |
| 13 | same | key peer | UDP 10.0.0.5 -> :53; TCP 10.0.0.1 -> :80 | Accept; Drop `DENIED` | same test |
| 14 | same, `reply_capacity = 2` | gateway from 10.0.0.1, .5, .6, .7, three rounds | TCP -> :80 | only .1 accepted, every round; per-address cache size <= 2 | `filter.rs` `by_source_cache_is_bounded` |
| 15 | namespace `nsd:a` with member `addr:<m>` (address m), rule any -> :22 tcp; no default set | gateway by source | TCP m -> local:22; TCP fd00::77 -> local:22 | Accept; Drop `NO_POLICY` | `filter.rs` `switching_between_by_source_and_by_key_applies_to_the_next_packet` |
| 16 | same, then `insert(gateway, {key(A)})`, then by source again, then `remove` | gateway | TCP m -> local:22 after each change | Drop `NO_POLICY`; Accept; Drop `UNKNOWN_PEER` (each on the next packet) | same test |
| 17 | namespace `nsd:a` with member `addr:fd00::b`, accept-all rule | gateway by source | UDP fd00::b -> local; UDP fd00::c -> local | Accept; Drop `NO_POLICY` (bypass not shared across addresses) | `filter.rs` `bypass_is_never_shared_across_sources` |
| 18 | same plus default set `any -> any udp`, then `sources fd00::d/128, labels [A] -> udp` | gateway | UDP fd00::c; then fd00::d and fd00::c | Accept; then Accept and Drop `DENIED` | same test |
| 19 | ns relay test: `key(public(1))` -> any | relay client `{key(public(1))}` | UDP to 10.9.0.5:5000 | delivered | ns `crates/ns/src/account_engine/tunnel/tests/acl_relay.rs` `a_relay_client_is_judged_by_its_wireguard_key` |
| 20 | same | same key, not a relay client (`{A}`) | same | not delivered | same test |
| 21 | `sources 100.64.0.0/10, labels [A]` -> any | non-relay peer `{A}` from its tunnel address | UDP to 10.9.0.5:5000 | delivered | ns `acl_relay.rs` `a_peer_outside_the_relay_client_set_is_judged_by_its_source_address` |
| 22 | same | relay client `{key(..)}` | same | not delivered | same test |
| 23 | fixture `recorded/relay_keys`: `key(ka1) -> *:22,80 tcp`; `key(kb2) -> 10.1.0.0/16 udp any port`; `10.0.0.0/24 -> 10.1.0.1:53 udp`; `192.168.0.0/16 -> 10.1.2.0/23:1-1024` | peers 1-2 `{A}`, 3 `{key(ka1)}`, 4 `{key(kb2)}`, 5 `{key(kc3)}` | TCP 10.9.9.9 -> 10.1.0.1:22 and :80 | only peer 3 accepted; port 81 nobody | nsplane `crates/nsplane-acl/tests/crates_acl_parity.rs` `crates_acl_mode_matches_ns_acl_check_packet` (fixture `tests/fixtures/crates_acl_parity.json`) |
| 24 | same | same | UDP 10.9.9.9 -> 10.1.0.1:22, -> 10.1.255.255:9; -> 10.2.0.0:9 | only peer 4 accepted; nobody | same |
| 25 | same | same | UDP 10.0.0.7 -> 10.1.0.1:53 | peer 1 (by source, inside 10.0.0.0/24) and peer 4 (lan rule) accepted; peer 3 denied although its source is inside the prefix; peer 5 denied | same |
| 26 | same | same | TCP 192.168.4.4 -> 10.1.3.1:1024 | only peer 1 (by source) accepted; UDP to :1 accepts peers 1 and 4 | same |
| 27 | fixture, all 16 sequences (12,181 packets, 30 marked deviations) | by-source peers 1-2, relay peers 3-5 | as recorded | ns verdicts | same |
| 28 | ns overlay: one key in two sources | `{key(k01)}` | - | member of both namespaces (`memberships(key(k01))` lists both); no grant | ns `crates/overlay/src/policy.rs` `same_identity_in_two_sources_is_a_member_of_both_without_grant` |
| 29 | ns overlay: user allow | - | - | grant `from: Label(key(k01)), to: Label(key(k02))` | ns `crates/overlay/src/policy.rs` `user_allow_grants_each_trusted_target_once` |
| 30 | ns overlay: `app:s1` source | - | - | stored as `Pinholes`; no grant names its peers | ns `crates/overlay/src/policy.rs` `app_only_peers_are_never_granted` |
| 31 | member label in `nsd:a` (any -> :80) and `quick` (any -> :22) | `{key(1)}` | TCP to local :80; :22; :443 | Accept (`nsd:a`); Accept (`quick`); Deny | nsplane `engine.rs` `rules_of_all_namespaces_of_a_principal_apply` |
| 32 | `Pinholes` namespace with rules or `pinhole_kinds`; default accept-all | member only of `app:s1` | TCP to local :22 | store rejected; Deny | `engine.rs` `app_namespaces_never_widen_permissions` |
| 33 | grant naming a `Pinholes` namespace (either end) | - | - | rejected, no grant stored | `engine.rs` `grants_cannot_name_app_namespaces` |
| 34 | default `any -> any tcp`; E in `app:s1` (outbound `[]`), A in `nsd:a` | E | TCP E -> local:22; E -> A:22; outbound local -> E | `DENIED`; `CROSS_NAMESPACE`; `OUTBOUND` | `filter.rs` `app_namespace_member_gets_nothing_inbound` |
| 35 | inbound pinhole for E's label, TCP 9000 | E | TCP E -> local:9000 before / during / after the guard | `DENIED` / Accept (UDP and :9001 `DENIED`) / `DENIED`, allowances revoked | `filter.rs` `session_only_peer_works_only_through_its_inbound_pinhole` |

Case 27 is the whole parity fixture; its compiler from the fixture's document lives with
the AG-3 spec (`docs/specs/acl-policy-document.md`). Cases 15-18 use member labels
`addr:<ip>` per 3.4.

## 5. Edge cases

- **Unknown peer.** `labels_for` returns `None` (not in the map, removed, or by-source
  address outside every prefix): inbound drop `UNKNOWN_PEER`, counter `unknown_peer`.
  `evaluate` cannot express it; it is a filter-only outcome. An unknown source never
  bypasses. Reply allowances are checked before identity, so with `stateful_replies` on a
  reply to a flow the local side opened still passes after the peer became unknown, until
  the allowance idles out.
- **Peer with no labels / empty label set.** `Some(LabelSet::empty())` is a known source:
  it matches only rules with empty `labels` (old `*` rules; a CIDR rule compiled per 3.2
  carries `A` and never matches it), is in no namespace, and is governed by the default
  rule set (`NO_POLICY` while nothing is installed). Use it for a known peer without any product identity; it never
  matches a key, CIDR (`A`) or IdP rule.
- **Multiple labels in several namespaces.** Membership is the union over all labels.
  Rules of every common namespace apply (union). Outbound restriction holds only when
  every namespace of every label sets `outbound`. Pinhole permission is checked against
  all its `Rules` namespaces. A destination address owned by several labels resolves to
  the longest prefix, then the smallest label. A product that gives one peer both a key
  label and `A` makes it match key rules **and** CIDR rules, which the old model never did
  (one assertion per peer): do not add `A` to key-judged peers when parity matters.
- **Label text.** Equality is byte-wise: no case folding, no hex or IP normalization. The
  product canonicalizes (lowercase hex, `IpAddr` `Display`).
- **Identity generation bumps.** `PeerLabelMap` bumps its generation under its write lock
  on every `insert`, `insert_by_source` and `remove`, so the next packet sees the change
  (cases 11, 16). A custom `PeerIdentity` must return a non-zero generation that changes
  after every visible change, and `by_source(peer) == true` for every peer whose labels
  depend on the address; otherwise a stale per-peer cache entry applies to every address.
  Generation 0 disables the peer cache, the verdict cache and the bypass: every packet is
  resolved and evaluated (correct, slower).
- **Caching expectations.** Labels are cached per peer, or per `(peer, address)` for
  by-source peers in an LRU bounded by `reply_capacity` (evicted addresses are resolved
  again, case 14). Each cache entry and verdict is tagged with the engine and identity
  generations; a mismatch is re-evaluated. Verdicts and counters of cached evaluation equal
  a full evaluation of every packet (differential test). A product should therefore pass
  the same `LabelSet` (one `Arc`) for many peers when possible, and avoid bumping the
  generation when nothing changed: every bump invalidates every cached peer and verdict.
- **Switching modes.** Moving a peer between `insert` and `insert_by_source` is one map
  update and applies to the next packet (case 16); the previous mode's cache entries are
  discarded by the generation change.
