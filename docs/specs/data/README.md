# Spec data

Data files referenced by the specs in `docs/specs/`. Each file is kept byte-identical to its
origin; verify with `sha256sum docs/specs/data/<file>`.

| File | What it is | Origin | sha256 |
| --- | --- | --- | --- |
| `acl-crates-acl-parity.json` | ns `crates/acl` inbound IPv4 verdicts on 16 packet sequences (12,181 packets, 30 marked deviations) for replay against a product's policy compiler plus `nsplane-acl`; format and procedure in [`acl-policy-document.md`](../acl-policy-document.md) section 7 | Copy of `crates/nsplane-acl/tests/fixtures/crates_acl_parity.json` at commit `b548bebc297c4cf14e7b6e9eae878ae5b8e7b26d` (verdicts from ns commit `e98259bc97e5d2053e4d971d76b5099826bf511a`) | `30defa65e5f219618f3f5bd27ee5ed3225a8cebddddd61958cb6c824ea3ff657` |
| `node-l3-differential.json` | ns `NodeL3Runtime` results on 26 scenarios (6,693 steps, of which 6,361 packet steps) for replay against a product's Node L3 compiler plus the `nsplane-acl` flow gate; format and procedure in [`node-l3.md`](../node-l3.md) section 5 | Copy of `crates/nsplane-acl/src/node_l3/fixtures/differential.json` at commit `de314a863e4c2b2a90eec39f72b20d04ea0d6d13` (results from ns commit `e98259bc97e5d2053e4d971d76b5099826bf511a`) | `90cf700a9b5d9097e7d0cd7c838ab0a0526da3e51a1f9641c0708441bb9b160c` |
