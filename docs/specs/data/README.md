# Spec data

Data files referenced by the specs in `docs/specs/`. Each file is kept byte-identical to its
origin; verify with `sha256sum docs/specs/data/<file>`.

| File | What it is | Origin | sha256 |
| --- | --- | --- | --- |
| `acl-crates-acl-parity.json` | ns `crates/acl` inbound IPv4 verdicts on 16 packet sequences (12,181 packets, 30 marked deviations) for replay against a product's policy compiler plus `nsplane-acl`; format and procedure in [`acl-policy-document.md`](../acl-policy-document.md) section 7 | Copy of `crates/nsplane-acl/tests/fixtures/crates_acl_parity.json` at commit `b548bebc297c4cf14e7b6e9eae878ae5b8e7b26d` (verdicts from ns commit `e98259bc97e5d2053e4d971d76b5099826bf511a`) | `30defa65e5f219618f3f5bd27ee5ed3225a8cebddddd61958cb6c824ea3ff657` |
