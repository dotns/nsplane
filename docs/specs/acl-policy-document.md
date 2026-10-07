# ACL policy document and the `crates_acl` preset (AG-3) — product specification

- **Status**: specification of items removed from `nsplane-acl` in slice C4 of plan
  `20261007-0900-business-agnostic`.
- **Audience**: a product (ns first) that keeps the JSON policy document, its self-tests,
  layered merge, deny scope and the ns `crates/acl` filter mode on top of the generic API.
- **Generic API**: [`acl-generic-api.md`](acl-generic-api.md) (typed `Rule` / `RuleSet`,
  `PolicyState`, `PeerLabelMap`, `AclEngine::evaluate`). Snippets are illustrative; the
  final names follow the merged code.
- **Parity data**: [`data/acl-crates-acl-parity.json`](data/acl-crates-acl-parity.json),
  see [`data/README.md`](data/README.md).

## 1. Scope and status

`nsplane-acl` before C4 parsed and compiled a JSON policy document, ran its self-tests,
merged policy layers, applied a deny scope, and offered a filter preset reproducing the ns
`crates/acl` step. Under ADR
[`2026-10-06-business-agnostic-scope`](../decisions/2026-10-06-business-agnostic-scope.md)
nsplane enforces business-agnostic typed rules only; a policy language, its layering and
product presets belong to the product that compiles them. C4 removes:

| Removed item | Product replacement (this spec) |
| --- | --- |
| `AclPolicy` (`hosts`, `acls`, `tests`), `AclRule`, `AclAction`, `AclTest` (`src/policy.rs`, hosts deserializer) | The product's document types (section 2) |
| String parsers `parse_src`, `parse_dst`, `parse_ports`, `parse_protocol`, `parse_hex32` (`src/matcher.rs`) | The product's compiler to `Rule` (section 3) |
| `CompiledPolicy::compile`, `CompiledPolicy::validate_tests`, `parse_test_dst`, `AclTestFailure`, `RuleSet::from_document` | Compile, then `RuleSet::new` (section 3); self-tests with `RuleSet::matching` (section 4) |
| `AclEngine::load` | `RuleSet::new` + `AclEngine::install`; `AclEngine::fail` on a product-side failure |
| `merge_layered`, `PolicyLayers`, `RemotePolicy`, `MergedPolicy`, `MergeStats`, `RuleProvenance`, `acl_rule_key`, `acl_test_key` (`src/merge.rs`) | Product merge before compilation (section 5.1) |
| `apply_deny_scope`, `DenyScope`, `DenyScopeOutcome`, `DroppedRule`, `DropReason` (`src/deny_scope.rs`) | Product deny scope before compilation (section 5.2) |
| `AclFilterConfig::crates_acl`, `FragmentMode::ALLOW_ONLY` | Explicit `AclFilterConfig` values (section 6) |
| `Error::{InvalidCidr, InvalidDst, UnknownAlias, TestsFailed, InvalidPolicy}` | Product errors (sections 2.4, 4); nsplane keeps `Error::InvalidRule { id, reason }` |
| `tests/crates_acl_parity.rs` and `tests/fixtures/crates_acl_parity.json` | Parity data under `docs/specs/data/` and the replay procedure (section 7) |

The product owns: the document format and its versioning, alias expansion, rule IDs,
self-tests and their failure policy, layer sources and caches, the deny scope, the filter
configuration and the peer labels. nsplane owns enforcement of the resulting `RuleSet`.

## 2. The document format

### 2.1 Schema

```json
{
  "hosts": { "<alias>": "<cidr or address>" },
  "acls": [
    { "action": "accept", "src": ["<src>", "..."], "dst": ["<host>:<ports>", "..."], "proto": "tcp" }
  ],
  "tests": [
    { "src": "<ip>", "dst": "<ip>:<port>", "proto": "udp", "allow": true }
  ]
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `hosts` | object of string to string, or an **empty** array `[]` | no (default `{}`) | Alias to CIDR. A non-empty array is a parse error |
| `acls` | array of rules | no (default `[]`) | Accept rules; order only decides which rule is reported |
| `acls[].action` | `"accept"` (lowercase, exact) | yes | The only action; any other value is a parse error |
| `acls[].src` | array of strings | yes | Source matchers (2.2); the rule matches if any matches |
| `acls[].dst` | array of strings | yes | Destination matchers (2.3); the rule matches if any matches |
| `acls[].proto` | `"tcp"` / `"udp"` (ASCII case-insensitive) or absent / `null` | no | Absent: TCP and UDP |
| `tests` | array of tests | no (default `[]`) | Self-tests (section 4) |
| `tests[].src` | IP address string | yes | Source address of the test flow |
| `tests[].dst` | `"<ip>:<port>"` | yes | Destination address and port (split at the last `:`; IPv6 without brackets, e.g. `fd00::1:443`) |
| `tests[].proto` | `"tcp"` / `"udp"` (case-insensitive) or absent | no (default `tcp`) | Protocol of the test flow |
| `tests[].allow` | bool | yes | Expected verdict |

Unknown fields are ignored. An empty document `{}` is a valid policy with no rules (every
new flow denied once installed). A rule with an empty `src` or `dst` list matches nothing.

### 2.2 Sources

Each `src` entry is tried in this order; the first form that applies wins:

1. `*`: any source.
2. `key:<64 hex>`: a principal holding that WireGuard public key (hex of either case). It
   matches only a source identified by key (a relay client), never by address. Not exactly
   64 hex digits: error.
3. A CIDR or a bare address (`10.0.0.0/24`, `10.0.0.5` = `/32`, IPv6 likewise): matches a
   source identified by its address (a by-source peer) whose packet source address lies in
   the prefix. A key-identified source never matches a CIDR.
4. A host alias from `hosts`: as its CIDR (same address-only rule).
5. Anything else: error (unknown alias).

An alias whose name parses as a CIDR is shadowed by step 3.

### 2.3 Destinations

Each `dst` entry is `<host>:<ports>`, split at the **last** `:` (so IPv6 CIDRs work:
`fd00::/64:443`).

- `<host>`: `*` (any address), a CIDR or bare address, or a host alias, tried in that
  order. Anything else: error (unknown alias). No `:`: error.
- `<ports>`, with ports `0..=65535`:
  - `*`: every port;
  - `N`: one port;
  - `N,M,...`: a list (each element trimmed of spaces; a list cannot contain ranges);
  - `LO-HI`: an inclusive range, `LO <= HI` (no spaces).

A destination matches a flow when both its host and its port set match.

### 2.4 Validation and errors

Compilation rejects the whole document (nothing installed, previous rules stay) when:

| Case | Old error |
| --- | --- |
| A `hosts` value is not a CIDR or address (checked for every alias, used or not) | `InvalidCidr { addr, reason }` |
| A `src` entry: unknown alias or a malformed `key:` | `InvalidPolicy("rule <i> src: unknown host alias: '<s>'")` |
| A `dst` entry: no `:`, a bad port, list element or range, or `LO > HI` | `InvalidPolicy("rule <i> dst: invalid destination ...")` |
| A `dst` host that is no `*`, CIDR or alias | `InvalidPolicy("rule <i> dst: unknown host alias: ...")` |
| `proto` other than tcp/udp | `InvalidPolicy("rule <i> proto: ...")` |
| Any self-test fails (section 4) | `TestsFailed { count }` |

Parse errors (`action` not `accept`, a missing required field, a non-empty `hosts` array)
fail at deserialization. A product maps these to its own error type; the messages above
are informative.

## 3. Compilation to typed rules

The product expands aliases and emits `Rule`s (generic API 2.2) in document order. It uses
one product label `A` (for example `"addr"`) that only address-identified sources carry
(section 6.2), and the label `key:<hex>` (hex **lowercased**: labels compare as exact
strings) for key-identified sources.

| Document form | `Rule` fields |
| --- | --- |
| `src: *` | `labels: []`, `sources: []` |
| `src: key:<hex>` | `labels: ["key:<hex>"]`, `sources: []` |
| `src: <cidr>` / alias | `labels: [A]`, `sources: [<cidr>]` |
| `dst: *:<ports>` | `destinations: []` |
| `dst: <cidr>:<ports>` / alias | `destinations: [<cidr>]` |
| ports `*` | `PortSet::Any` |
| ports `N` / `N,M` / `LO-HI` | `PortSet::Ranges([N..=N])` / `[N..=N, M..=M]` / `[LO..=HI]` |
| `proto: tcp` / `udp` | `[Tcp(p)]` / `[Udp(p)]` |
| `proto` absent | `[Tcp(p), Udp(p)]` (never `ProtocolMatch::Any`, which would also accept ICMP and other protocols) |

Because `labels` and `sources` are a conjunction while a document rule's sources are a
union, one document rule becomes, for each `dst` entry (in order):

- if any `src` is `*`: one rule with no labels and no sources (it covers the others);
- otherwise up to two rules: one with every `key:` label of the rule, and one with label
  `A` and every source CIDR.

A rule with an empty `src` or `dst` emits nothing. Emitting one typed rule per
(source, destination) pair is equally correct; the grouping only reduces the count.

**Rule IDs.** Every typed rule emitted from document rule `i` shares one `RuleId`
(IDs need not be unique). Recommended: `"<layer>:<i>"`, where `<layer>` is the
provenance of section 5.1 (`local`, `remote/<source id>`, `cache/<source id>`) and `i` the
rule's index in the merged document, or the product's own stable rule ID. Rules are a
union: the verdict does not depend on order; the reported ID is that of the first
matching rule, the same rule the old engine reported as `matched_rule_index`.

Compilation sketch:

```rust
fn compile(doc: &Document, layer: &str) -> Result<Vec<Rule>, DocError> {
    let hosts = resolve_hosts(&doc.hosts)?;                     // alias -> IpNet, all checked
    let mut out = Vec::new();
    for (i, r) in doc.acls.iter().enumerate() {
        let src: Vec<Src> = r.src.iter().map(|s| parse_src(s, &hosts)).collect::<Result<_, _>>()?;
        let ports_proto = |p: PortSet| match r.proto.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("tcp") => Ok(vec![ProtocolMatch::Tcp(p)]),
            Some("udp") => Ok(vec![ProtocolMatch::Udp(p)]),
            None => Ok(vec![ProtocolMatch::Tcp(p.clone()), ProtocolMatch::Udp(p)]),
            Some(other) => Err(DocError::Proto(i, other.into())),
        };
        for d in &r.dst {
            let (host, ports) = parse_dst(d, &hosts)?;          // Option<IpNet>, PortSet
            let id = format!("{layer}:{i}");
            let base = Rule::new(id.as_str(), ports_proto(ports)?)
                .with_destinations(host.into_iter().collect());
            if src.iter().any(Src::is_any) { out.push(base); continue; }
            let keys: Vec<Label> = src.iter().filter_map(Src::key_label).collect();
            let nets: Vec<IpNet> = src.iter().filter_map(Src::cidr).collect();
            if !keys.is_empty() { out.push(base.clone().with_labels(keys)); }
            if !nets.is_empty() { out.push(base.with_labels(vec![ADDR.into()]).with_sources(nets)); }
        }
    }
    Ok(out)
}
```

The result goes through `RuleSet::new` (which rejects nothing a valid document produces)
and `AclEngine::install`. A document the product cannot compile is not installed; the
product either keeps the previous set or calls `AclEngine::fail()` (fail closed,
`POLICY_FAILED`), per its own policy. The old `load` kept the previous policy.

## 4. Self-tests

The old engine ran `tests` on every compilation (`AclEngine::load`), after compiling the
rules and before publishing them. Each test builds a flow from `src` (an address-identified
source, `AccessRequest::from_ip`), `dst` and `proto` (default TCP), evaluates it against
the new rules only (no namespaces, grants or pinholes), and compares accept with `allow`.
A test fails when its expectation differs, or when `src`, `dst` or `proto` does not parse.
Any failure rejects the whole policy (`TestsFailed { count }`, each failure logged at warn
with src, dst, expected and reason); the previous policy stays.

A product reproduces this before `install`:

```rust
let set = RuleSet::new(compile(&doc, layer)?)?;
let addr = LabelSet::new([Label::from(ADDR)]);                  // tests run as by-source sources
let failures: Vec<_> = doc.tests.iter().filter(|t| {
    match test_flow(t) {                                        // parse src, dst, proto
        Ok(flow) => set.matching(&addr, &flow).is_some() != t.allow,
        Err(_) => true,
    }
}).collect();
if failures.is_empty() { engine.install(set) } else { /* reject: keep previous or fail() */ }
```

`test_flow` builds `Flow::tcp` / `Flow::udp` with any source port (the old test used none)
and the test's destination. Key (`key:`) rules never match a self-test, since the test
source carries only label `A`. `AclEngine::evaluate(&addr, &flow)` gives the same answer
once the set is installed and the source is in no namespace; `matching` is the form to use
before installation. The product decides whether merged documents (section 5) are tested
after the merge (as before: tests are merged and run on the merged rules) or per layer.

## 5. Layered merge and deny scope

Both run on documents, before compilation (section 3) and before `RuleSet::new`.

### 5.1 Layered merge

Inputs: an optional local document, any number of remote documents each tagged with a
source id and a `cached` flag (served from the last-good cache after a failed fetch), an
optional deny scope, and a `degraded` flag (a remote failed and had no cache).

1. **Order**: the local layer first, then remotes sorted by source id (byte order).
2. **Hosts**: union; for an alias defined more than once the first definition in layer
   order wins, silently.
3. **Rules**: appended in layer order, each layer in file order, deduplicated by the key
   `accept \0 sorted(src) joined by U+001F \0 sorted(dst) joined by U+001F \0 lowercase(proto) or "*"`
   (no trimming). The first occurrence is kept and gets the provenance `Local`,
   `Remote { id }` or `Cache { id }` (by the `cached` flag); later duplicates are dropped.
4. **Tests**: appended in the same order, deduplicated by
   `src \0 dst \0 lowercase(proto) or "tcp" \0 allow`; tests carry no provenance.
5. **Stats**: rules kept per layer (`local`, per remote id, per cached id).
6. **Deny scope** (5.2) on the merged document; provenance entries of dropped rules are
   removed, so provenance stays index-aligned with the kept rules.
7. **Output**: the merged document, the provenance per rule, `degraded` passed through,
   the deny-scope drops and the stats.

Because aliases are merged first-wins, a remote rule naming an alias that the local
document also defines resolves to the local CIDR. A product that keeps the merge should
detect and report conflicting alias definitions. Provenance becomes the `RuleId` prefix
(section 3). Alternatively the product keeps the layers apart as namespaces
(`store_namespace`) when its sources govern disjoint source sets.

### 5.2 Deny scope

A local operator filter `{ "dst_cidr": [..], "src_cidr": [..], "proto": "tcp"|"udp"|absent }`
(every field optional) that removes merged rules able to reach (or come from) a forbidden
prefix. The engine stays accept-only; the scope only removes rules.

- Both lists empty: no-op. Otherwise every scope CIDR and every `hosts` value is parsed; a
  failure is an error (`InvalidCidr`). The old merge logged that error and **skipped the
  scope** (fail open); a product should instead reject the merge or fail closed.
- `proto`: a rule is examined when the scope has no `proto`, the rule has no `proto`, or
  both are equal ignoring case; other rules are kept. A protocol-less rule is dropped
  whole, not narrowed.
- Each examined rule is checked against `dst_cidr` first, then `src_cidr`; the first hit
  drops it. A side is checked only when its list is non-empty. Per entry of the rule's
  `dst` hosts (the part before the last `:`, trimmed) or `src` (trimmed), in order:

| Rule entry | Result |
| --- | --- |
| `*` | dropped: `WildcardShadowed { scope_cidr: <first scope entry> }` |
| CIDR inside a scope entry (first overlapping entry in scope order) | dropped: `DstFullyCovered` / `SrcFullyCovered { scope_cidr }` |
| CIDR overlapping a scope entry without being inside it (also a CIDR wider than it) | dropped: `PartialOverlap { scope_cidr }` (never split) |
| Alias whose CIDR is inside the first overlapping scope entry | dropped: `HostAliasOverlap { alias, scope_cidr }` |
| Alias whose CIDR only overlaps it | dropped: `PartialOverlap { scope_cidr }` |
| Disjoint CIDR or alias, `key:` source, unknown name | next entry; the rule is kept if none hits |

- Prefixes of different families never overlap. Containment: the outer prefix is not
  longer than the inner and contains its network address.
- Output: the kept rules in order, and for each dropped rule its pre-filter index, a copy
  and the reason (each also logged at warn). Tests are not filtered, so a test expecting a
  dropped rule to allow fails the self-tests (section 4).

A product applies the scope to the merged document, then compiles, self-tests and installs.
Applying it to typed rules is equivalent when `*` and absent `destinations` / `sources`
count as wildcards.

## 6. The `crates_acl` preset as explicit configuration

### 6.1 Filter configuration

`AclFilterConfig::crates_acl(local)` equalled, for inbound IPv4, ns
`is_local_node_packet(pkt, local) || is_icmp_echo_reply(pkt) || acl_check_packet(..)`.
The product sets every field itself:

| Field | Value | Effect |
| --- | --- | --- |
| `stateful_replies` | `false` | No reply allowances in either direction; replies are judged by the rules |
| `allow_other_protocols` | `false` | Protocols other than TCP and UDP dropped `PROTOCOL` (except the echo-reply bypass) |
| `fragments` | `FragmentMode::AllowOnly { ttl: 15 s, capacity: 4096 }` | A non-first IPv4 fragment passes only after an accepted first fragment of the same datagram (key without peer or direction) within 15 s; at capacity expired entries are removed first and nothing is recorded if still full; the last fragment keeps the entry; non-first fragments are judged before the no-policy check |
| `accept_to_local` | `Some(local tunnel IPv4)` or `None` | An inbound IPv4 packet (>= 20 bytes) to that address passes first, without the rules (`bypassed`) |
| `accept_icmp_echo_reply` | `true` | An inbound IPv4 ICMP echo reply (IHL >= 20, 8 bytes after the header, protocol 1, type 0, also a non-first fragment passing that check) passes without the rules (`bypassed`) |
| `ipv6` | `Ipv6Mode::Accept` | Every IPv6 packet passes in both directions, first, with no state; the product restricts IPv6 with the core's per-peer `inbound_destinations` |
| `fragment_capacity` | `1024` (default) | Unchanged |
| `reply_capacity` | `4096` (default) | Unchanged |
| `reply_idle_timeout` | `120 s` (default) | Unchanged (no allowances are created) |

Malformed IPv4 (total length beyond the buffer or below the header, truncated TCP/UDP
header) is dropped `MALFORMED` and later fragments of such a first fragment `FRAGMENT`;
ns allows some of these (section 7.1). No policy installed: `NO_POLICY` for every packet
except the two bypasses and IPv6.

### 6.2 Identity

- A relay client (ns `relay_client_keys`): `PeerLabelMap::insert(peer, {"key:<hex>"})`.
- Every other peer: `PeerLabelMap::insert(peer, {A})`. CIDR rules read the packet source
  address through `sources`, so no per-address principal is needed.
- A peer absent from the map is dropped `UNKNOWN_PEER` (ns drops unmapped peers too).

```rust
let engine = Arc::new(AclEngine::new());                        // NotInstalled::Deny
let labels = Arc::new(PeerLabelMap::new());
labels.insert(relay_peer, LabelSet::new([Label::from(format!("key:{}", hex_lower(&pubkey)))]));
labels.insert(gateway_peer, LabelSet::new([Label::from(ADDR)]));
let config = AclFilterConfig {
    stateful_replies: false,
    allow_other_protocols: false,
    fragments: FragmentMode::AllowOnly { ttl: Duration::from_secs(15), capacity: 4096 },
    accept_to_local: Some(tun_ip),
    accept_icmp_echo_reply: true,
    ipv6: Ipv6Mode::Accept,
    ..AclFilterConfig::default()
};
let filter = AclFilter::with_config(Arc::clone(&engine), labels, config);
engine.install(RuleSet::new(compile(&doc, "local")?)?);         // after the self-tests
```

## 7. Parity data

[`data/acl-crates-acl-parity.json`](data/acl-crates-acl-parity.json) is byte-identical to
`crates/nsplane-acl/tests/fixtures/crates_acl_parity.json` as last changed in commit
`b548bebc297c4cf14e7b6e9eae878ae5b8e7b26d` (sha256 in [`data/README.md`](data/README.md)).
It records the verdicts ns gave to IPv4 packet sequences in the ns `crates/acl` step.

### 7.1 Format

```text
{
  "seed": u64,                     // LCG seed of the generated sequences (7958828577287202049)
  "ns_commit": "<sha>",            // ns commit of the verdicts (e98259bc97e5d2053e4d971d76b5099826bf511a)
  "generator": "<text>",
  "deviations": 30,                // packets marked as an intended deviation
  "sequences": [{
    "name": "recorded/<case>" | "generated/<policy>",
    "policy": <document of section 2> | null,       // null: nothing installed
    "local_ip": "a.b.c.d" | null,                   // accept_to_local; null: none
    "peers": [{ "id": u32, "kind": "by_source" | "relay_key", "key": "<64 hex>" }],
    "packets": [
      [peer id, t_ms, "0x<IPv4 packet hex>", allowed],
      [peer id, t_ms, "0x<hex>", false, { "ns": true, "deviation": "malformed-ipv4" | "malformed-first-fragment" }]
    ]
  }]
}
```

- `t_ms`: the clock offset from the sequence start (fragment TTL and capacity are
  deterministic).
- `allowed`: the expected verdict (accept vs any drop).
- Peers 1 and 2 are `by_source` (keys `01..`, `02..`); 3 to 5 are `relay_key` (`a1..`,
  `b2..`, `c3..`; 5 is named by no rule).
- Counts (verified with `jq`): 16 sequences, **12,181 packets**, 12,413 lines; 10
  `recorded/*` sequences (none, empty, no_local, aliases, relay_keys, malformed,
  malformed_denied, fragments, fragment_ttl, fragment_capacity) and 6 `generated/*`
  (none, empty, allow_all: 400 packets each; aliases, relay_keys, ports: 2,200 each).
  30 deviations: 29 `malformed-ipv4`, 1 `malformed-first-fragment`.
- Policies cover host aliases (map and `[]`), CIDR and alias sources, `key:` sources next
  to CIDR rules, port 0 and 65535, lists, ranges, mixed-case `proto`, and passing
  self-tests (`generated/aliases`).

**Deviations.** ns `parse_five_tuple` reads only IHL + 4 bytes; nsplane drops malformed IPv4
(section 6.1). A deviation packet was allowed by ns and is expected dropped with
`MALFORMED` (`malformed-ipv4`) or `FRAGMENT` (`malformed-first-fragment`: a later fragment
ns admitted only through such a first fragment). Every other packet must match ns.

### 7.2 Origin

Generated by a throwaway crate (never committed) built against ns `refactor/nsplane` at
`ns_commit`: ns's own `ipv4_fragment_meta`, `FragmentKey`, `FragmentAclGate`,
`parse_five_tuple` and `acl` engine run `is_local_node_packet || is_icmp_echo_reply ||
acl_check_packet` with the fragment gate on the `t_ms` clock; sequences shorter than 15 s
were cross-checked against the real `tunnel_wg::acl_check_packet`. The generator, the
packet pools and the regeneration procedure are documented in the module docs of
`crates/nsplane-acl/tests/crates_acl_parity.rs` (removed by C4; see its history at the
commit above).

### 7.3 Replay procedure

A product proves its compiler plus nsplane reproduces the old mode by replaying every
sequence (nsplane keeps this as a test with a test-local compiler, slice C3; design
note 4.3 lists the generic tests that replace it after C4):

1. Parse the fixture; for each sequence create an `AclEngine::with_clock` on a manual
   clock set to `start`.
2. `policy` null: install nothing (`NotInstalled`, `Deny`). Otherwise compile it
   (section 3), run its self-tests (section 4, all must pass), `RuleSet::new`, `install`.
   `{"acls": []}` installs an empty set (`DENIED`, not `NO_POLICY`).
3. Labels: `by_source` peer -> `{A}`; `relay_key` peer -> `{"key:<key>"}` (section 6.2).
4. Build one `AclFilter` with the section 6.1 configuration and
   `accept_to_local = local_ip`.
5. For each packet in order: set the clock to `start + t_ms`, call `inbound(peer, packet)`.
   A plain packet must give `Accept` exactly when `allowed`. A deviation packet must be
   recorded `ns: true`, `allowed: false`, and give `Drop` with its kind's reason.
6. Require zero mismatches over all 12,181 packets and exactly 30 deviation packets,
   equal to the fixture's `deviations`. Report the first mismatches with sequence name,
   index, peer, `t_ms`, packet hex, `ns_commit` and `seed`.
