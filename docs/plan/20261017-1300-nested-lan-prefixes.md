# 20261017-1300-nested-lan-prefixes Nested LAN prefixes with longest-prefix match

- **status**: in_progress
- **createdAt**: 2026-10-17 13:00
- **approvedAt**: 2026-10-17 (owner: "2，需要，开始修改然后发布0.15.0", the fifth exception to the
  freeze, released as 0.15.0)
- **relatedTask**: ns plan `20261017-0422-gateway-as-node` (read only, in /srv/dotns/ns)

## Context

ns treats a gateway as an ordinary Node. A default IPv4 exit is then a LAN prefix `0.0.0.0/0` on
the gateway Node: local IPv4 destinations map into a /96 the gateway owns, and the gateway does
6->4. Today `TranslationTableBuilder::build` rejects a LAN IPv4 prefix that overlaps another
one, the self `eam4`, a peer's `eam4` or a `peer6_eam4` (`TableError::Lan4Overlap`), so
`0.0.0.0/0` cannot coexist with any other mapping. Lookups keep the LAN prefixes sorted and
disjoint (`TranslationTable::lan4`, one binary search).

Generic form, no product concepts: an operator may install LAN prefixes that nest, and the most
specific mapping wins.

## Requirements

| Item | Requirement | Crate |
|---|---|---|
| NL-1 | LAN IPv4 prefixes may nest (CIDR prefixes either nest or are disjoint). `lan4_to_lan6` returns the longest LAN prefix that contains the address. Two LAN prefixes with the same IPv4 network stay an error | `nsplane-nat` |
| NL-2 | Exact IPv4 addresses (self `eam4`, a peer's `eam4`, `peer6_eam4`) may lie inside a LAN prefix and always win over it, in every lookup: outbound destination and source, ICMP inner packets, `map4to6`/`map6to4` | `nsplane-nat` |
| NL-3 | Reverse consistency: `lan6_to_lan4` accepts an address under a LAN's /96 only if the IPv4 address it maps to resolves to that same LAN through NL-1/NL-2. A reply under the default prefix that claims an address of a more specific LAN or an exact mapping is not translated | `nsplane-nat` |
| NL-4 | `Nat64Lan` / `LanRoute::resolve` follow the same longest-prefix rule where routes nest | `nsplane-nat` |
| NL-5 | Opt-in: the current strict check stays the default, so existing callers keep their conflict detection. A builder option enables nesting; the public API only grows | `nsplane-nat` |

## Constraints

- Lookup cost: one binary search per lookup, as today (nested prefixes flattened into disjoint
  intervals when the table is built); slot A/B of the `translate` bench against 0.14.2.
- Bounded build cost, measured for 10 k LAN prefixes.
- std only, no new crate, no unsafe; existing behaviour unchanged without the option.
- Every item has unit tests, and an nsplane-e2e test covers a default prefix next to a more
  specific LAN, an exact peer mapping inside it, and a spoofed reply (NL-3) that is dropped.

## Items

- **NL-A** design note to L1 (yellow): API shape of the option, flattening, the lookup order
  in `translate.rs` (today `by_peer6_eam4` is checked after the LAN lookup and must move before
  it), NL-3 check, `Nat64Lan`.
- **NL-B** implementation with tests (TDD).
- **NL-C** e2e test, slot A/B, docs (docs/architecture.md, CHANGELOG [Unreleased] Added).

## Acceptance

- NL-1..5 met, full gate green (just check, cross, test-windows, cargo doc, release CLI +
  linux.sh, lib.sh, examples.sh), `translate` rows at par with 0.14.2.
- Released as 0.15.0 after the owner confirms.

## Results

Final gate (NL-C2) on `bkd/r5khbxgy` after merging `bkd/blx9cozk` (4698be4), every cargo and
just command in the `ai-agent/nstun-dev` image. Logs in `/tmp/r5khbxgy/` of the agent container.

| Gate | Command | Exit | Log |
|---|---|---|---|
| a | `just check` (1915 tests run, 1915 passed) | 0 | `a-check.log` |
| b | `just cross` | 0 | `b-cross.log` |
| c | `just test-windows` | 0 | `c-test-windows.log` |
| d | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | 0 | `d-doc.log` |
| e | `cargo build --release -p nsplane-cli --locked`, then `NSPLANE_E2E_PREFIX=e2e-r5khbxgy scripts/e2e/linux.sh` | 0, 0 | `e0-build-cli.log`, `e-linux.log` |
| f | `NSPLANE_E2E_LIB_PREFIX=lib-r5khbxgy scripts/e2e/lib.sh` | 0 | `f-lib.log` |
| g | `NSPLANE_E2E_EX_PREFIX=ex-r5khbxgy scripts/e2e/examples.sh` (matrix and 19 scenarios PASS) | 0 | `g-examples.log` |

`data_path` bench (`crates/nsplane-core/benches/data_path`), branch tip, through
`scripts/bench/slot.sh`, slot 0, cpus 1-7, load 0.75 / 1.30 / 1.54 before, 0.82 / 1.28 / 1.53
after:

| Row | Branch | 0.14.2 (CHANGELOG) | 0.10.0 (reference) |
|---|---|---|---|
| `core_round_trip/64` | 414.5 ns | 417 ns | 530 ns |
| `core_round_trip/1420` | 1.218 us | 1.224 us | 1.334 us |

`translate` bench, slot A/B, v0.14.2 (detached worktree at the tag) against the branch tip:
3 invocations of `scripts/bench/slot.sh`, each one interleaved A,B,A,B in criterion containers
with `--cpuset-cpus "$BENCH_CPUS"`, at least 120 s apart. All three took slot 0, cpus 1-7.

| Round | Load before | Load after |
|---|---|---|
| r1 | 3.21 / 3.18 / 3.78 | 1.59 / 1.68 / 2.54 |
| r2 | 0.62 / 1.30 / 2.29 | 1.53 / 1.57 / 1.89 |
| r3 | 0.55 / 1.17 / 1.70 | 1.58 / 1.62 / 1.67 |

Delta per round is the mean of the two branch runs against the mean of the two v0.14.2 runs;
spread is the larger A/A run-to-run difference of the round; the ns columns and the aggregate
are medians over the rounds. Within means |median delta| <= max(2 %, median spread). In r3
the second v0.14.2 run was disturbed on every `*_out` row (about +35 %, e.g.
`eam4_out/tcp/64B/1` 39.0 ns then 52.9 ns), so its r3 out deltas are negative and its spread
large; the medians do not depend on that round. Strict mode:

| Row | v0.14.2 ns | Branch ns | r1 | r2 | r3 | Median | Spread | Within |
|---|---|---|---|---|---|---|---|---|
| `eam4_out/tcp/64B/1` | 39.1 | 39.2 | +0.46 % | +0.10 % | -14.48 % | +0.10 % | 2.35 % | yes |
| `eam4_out/tcp/1400B/1` | 77.5 | 77.2 | +0.57 % | -0.42 % | -5.66 % | -0.42 % | 2.51 % | yes |
| `eam4_out/tcp/64B/1000` | 39.3 | 39.4 | +0.35 % | +1.76 % | -15.43 % | +0.35 % | 1.62 % | yes |
| `eam4_out/tcp/1400B/1000` | 77.2 | 77.5 | +0.22 % | +0.89 % | -4.33 % | +0.22 % | 1.86 % | yes |
| `eam4_in/tcp/64B/1` | 52.7 | 52.8 | +0.88 % | -0.18 % | +0.26 % | +0.26 % | 1.03 % | yes |
| `eam4_in/tcp/1400B/1` | 75.1 | 74.9 | +0.42 % | +0.33 % | -0.16 % | +0.33 % | 0.82 % | yes |
| `eam4_in/tcp/64B/1000` | 52.6 | 52.7 | +0.20 % | -0.21 % | +0.95 % | +0.20 % | 1.28 % | yes |
| `eam4_in/tcp/1400B/1000` | 74.8 | 74.9 | +1.34 % | -0.56 % | +0.14 % | +0.14 % | 1.76 % | yes |
| `lan_out/tcp/64B/1` | 40.8 | 40.6 | -0.46 % | +0.74 % | -15.11 % | -0.46 % | 1.47 % | yes |
| `lan_out/tcp/1400B/1` | 78.8 | 80.4 | +3.25 % | +1.27 % | -4.99 % | +1.27 % | 2.86 % | yes |
| `lan_out/tcp/64B/1000` | 56.1 | 56.2 | -0.04 % | +1.64 % | -11.69 % | -0.04 % | 1.63 % | yes |
| `lan_out/tcp/1400B/1000` | 87.8 | 88.9 | +1.87 % | +1.82 % | -6.87 % | +1.82 % | 1.10 % | yes |
| `lan_in/tcp/64B/1` | 54.8 | 55.0 | +0.19 % | +0.05 % | +0.34 % | +0.19 % | 0.69 % | yes |
| `lan_in/tcp/1400B/1` | 77.9 | 77.7 | +0.13 % | -0.67 % | -0.25 % | -0.25 % | 0.59 % | yes |
| `lan_in/tcp/64B/1000` | 55.0 | 55.3 | +0.65 % | -0.49 % | +1.09 % | +0.65 % | 0.64 % | yes |
| `lan_in/tcp/1400B/1000` | 77.7 | 78.5 | +0.21 % | +0.78 % | +1.55 % | +0.78 % | 1.26 % | yes |
| `lan_remap_out/tcp/64B/1` | 40.2 | 40.3 | -0.77 % | +1.76 % | -8.44 % | -0.77 % | 1.67 % | yes |
| `lan_remap_out/tcp/1400B/1` | 78.2 | 79.5 | +1.77 % | +2.99 % | -4.78 % | +1.77 % | 1.54 % | yes |
| `lan_remap_out/tcp/64B/1000` | 55.5 | 55.9 | +1.58 % | +1.38 % | -12.33 % | +1.38 % | 2.54 % | yes |
| `lan_remap_out/tcp/1400B/1000` | 87.9 | 89.2 | +1.52 % | +2.48 % | -5.84 % | +1.52 % | 3.97 % | yes |
| `lan_remap_in/tcp/64B/1` | 54.4 | 54.7 | +0.50 % | +0.49 % | +0.71 % | +0.50 % | 0.61 % | yes |
| `lan_remap_in/tcp/1400B/1` | 77.2 | 77.0 | -0.40 % | -0.91 % | -0.11 % | -0.40 % | 0.84 % | yes |
| `lan_remap_in/tcp/64B/1000` | 54.6 | 54.7 | +0.11 % | -0.98 % | +0.81 % | +0.11 % | 0.62 % | yes |
| `lan_remap_in/tcp/1400B/1000` | 77.7 | 77.0 | +0.21 % | -3.33 % | +0.18 % | +0.18 % | 2.09 % | yes |

24 of 24 strict rows are within over 3 rounds. The earlier single-round edge row
`lan_in/tcp/1400B/1` (+2.01 %) does not hold: it is at +0.13 / -0.67 / -0.25 %, median -0.25 %.

Nested mode, on the branch, `lan96_nested_*` (a /0 next to the per-peer /96 LANs) against the
strict `lan_*` rows of the same invocation:

| Row | Strict `lan_*` ns | Nested ns | r1 | r2 | r3 | Median | Spread | Within |
|---|---|---|---|---|---|---|---|---|
| `lan96_nested_out/tcp/64B/1` | 40.6 | 42.9 | +6.27 % | +5.62 % | +4.19 % | +5.62 % | 2.40 % | **no** |
| `lan96_nested_out/tcp/1400B/1` | 80.4 | 81.0 | +0.48 % | +1.50 % | +0.42 % | +0.48 % | 2.47 % | yes |
| `lan96_nested_out/tcp/64B/1000` | 56.2 | 56.3 | +0.37 % | -0.19 % | -0.20 % | -0.19 % | 1.22 % | yes |
| `lan96_nested_out/tcp/1400B/1000` | 88.9 | 88.7 | -0.83 % | +0.12 % | -0.69 % | -0.69 % | 0.87 % | yes |
| `lan96_nested_in/tcp/64B/1` | 55.0 | 54.9 | +0.03 % | +0.24 % | -0.08 % | +0.03 % | 0.47 % | yes |
| `lan96_nested_in/tcp/1400B/1` | 77.7 | 77.5 | -0.40 % | +0.23 % | -0.61 % | -0.40 % | 0.58 % | yes |
| `lan96_nested_in/tcp/64B/1000` | 55.3 | 55.1 | -0.51 % | +0.02 % | -0.48 % | -0.48 % | 0.64 % | yes |
| `lan96_nested_in/tcp/1400B/1000` | 78.5 | 77.9 | +0.05 % | -0.75 % | -1.05 % | -0.75 % | 1.26 % | yes |

7 of 8 nested rows are within. `lan96_nested_out/tcp/64B/1` is not: +5.62 % median (about
2.3 ns, 40.6 to 42.9 ns), consistent over the 3 rounds (+6.27 / +5.62 / +4.19 %). The same
row at 1000 peers and every inbound row are at par.

Build cost (`table_build`, branch, 6 runs over the 3 rounds) and segment count:

| Row | Runs | Median |
|---|---|---|
| `table_build/strict_10k` | 1.969, 1.972, 1.984, 1.968, 1.979, 1.986 ms | 1.976 ms |
| `table_build/nested_10k` | 2.080, 2.098, 2.095, 2.074, 2.097, 2.110 ms | 2.096 ms |

Nested costs +6.1 % over strict at 10 k prefixes. Segment count from
`table::tests_nested::segment_count_at_10k_prefixes_and_10k_exact_addresses` (`--nocapture`):
20001 nested segments for 10 000 prefixes and 10 000 exact addresses, as NL-B1 measured.

New public API: `TranslationTableBuilder::nested_lans`, `TranslationTable::nested_lans`,
`Nat64LanConfig::nested_routes`.

## Annotations

- 2026-10-17 (L1, NL-A design note): sections 1-7 approved. Precedence lives in the table: the
  exact addresses are /32 holes in the flattened segments, so every lookup site holds "exact
  first, then the longest LAN" by construction, and the call sites in `translate.rs` are
  unchanged. This supersedes the Items text "today `by_peer6_eam4` is checked after the LAN
  lookup and must move before it". Conditions: (1) the public rustdoc states the nested
  semantics, with a /0 + /16 + `eam4` doc example; (2) the site tests a-h and the randomized
  reference test run in both modes; (3) NL-3 drops are visible (the e2e test asserts `UNMAPPED`
  and `dropped_in`; the CHANGELOG says spoofed replies are dropped, not translated); (4) the
  build-cost rows and the segment count are in Results; (5) the version is 0.15.0, CHANGELOG
  [Unreleased] Added, released by L1 after the owner confirms.
- 2026-10-17 (NL-B1 perf rework): simple prefixes (no nested prefix or exact address inside)
  skip the owner search, and the segment element is compacted to 48 B.
