# 20261112-0002-nat-quotas-and-fragments Masquerade quota, ICMP quotes with trailing bytes, NAT64-LAN fragments

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 00:02

## Description

Four audited P3 items in `nsplane-nat`:

1. `Masquerade`: one inside source could fill the table (4096 flows, TCP flows for 5 min, no
   close tracking), and a full table was scanned for expired flows on every packet of a new
   flow.
2. `Translator`: an ICMP error whose quoted packet is followed by more bytes (padding, an
   RFC 4884 extension structure) was dropped with `LENGTH_MISMATCH`.
3. `Nat64Lan`: IPv4 fragments from the LAN and IPv6 fragments / extension headers passed
   untranslated (`NotOurs`), so a fragmented datagram was lost without a trace.
4. `Translator`: the fragment state was cleaned twice per fragment.

## ActiveForm

Bounding the masquerade table per source, accepting ICMP quotes with trailing bytes and
dropping the fragments NAT64-LAN cannot translate.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

### 1. Masquerade

- Per-source quota: `Masquerade::max_flows_per_source`, default `max_flows.div_ceil(2)` (2048),
  set with the builder `Masquerade::with_max_flows_per_source`. Refusals drop with
  `reasons::SOURCE_QUOTA` and are counted by `Masquerade::source_quota_drops`. The table's
  own bound is checked first, so `CAPACITY` keeps its meaning. `MasqueradeConfig` and
  `MasqueradeStats` are exhaustive public structs: a new field would break struct literals,
  so the setting is a builder and the counter an accessor. Moving both into the structs is a
  candidate for the next breaking release.
- Scan gate: the table keeps `first_expiry`, a lower bound of the earliest expiry, lowered
  on insert and when a flow turns closing, recomputed exactly by each scan. `expire_all`
  returns at once while the clock is before it, so `len`, `stats` and the full-table path
  stay exact. Not added: a minimum interval between scans. A scan that removes nothing needs
  the earliest flow to have been refreshed since the previous scan, so the scans are bounded
  by the refresh packets of the flows, not by the new-flow packets.
- TCP close: a flow that saw a FIN or RST (either direction, after the checksum
  verification and the route check) uses `min(tcp_timeout, 30 s)`; a SYN from the inside
  host reopens it, as `Conntrack` does. The 30 s are a constant (no config field can be
  added); `Conntrack`'s `TcpState` was not reused because the masquerade keeps its own
  table.
- Measured with the new criterion case `refused_at_capacity` (default table full of flows
  that cannot expire, one refused packet), release profile, old and new binaries interleaved
  three times in one bench slot on a loaded host: 15.9 / 20.9 / 16.3 us before, 0.116 /
  0.129 / 0.135 us after. `new_flow` and `established/*` moved within the noise of that host
  (`new_flow` 306-544 ns before, 254-416 ns after).

### 2. ICMP quotes

- A quoted packet now ends at its own total length; bytes after it are accepted. The RFC
  4884 length attribute (ICMP types 3, 11, 12: byte 5 in 32-bit words; ICMPv6 types 1, 3:
  byte 4 in 64-bit words) bounds the original datagram field first, so a truncated quote
  followed by an extension is not read into the extension. A length past the message is
  ignored.
- Truncated quotes are handled as before (total length above the bytes present: the payload
  is what is there).
- Left undone: the extension structure is not carried into the translated error (RFC 7915
  section 4.2 asks for it, with the length attribute recomputed and the quote re-padded).
  The translated error has no length attribute; the source's attribute byte lands in an
  unused byte of the other family, as before. An ICMPv6 error that is only rewritten
  (`peer6`/`local6`) keeps its trailing bytes. Documented in the reference.

### 3. NAT64-LAN fragments

Chosen: the minimum, a dedicated drop. Reason: translating fragments needs reassembly (a
later fragment has no ports), and the case the audit names, a large UDP reply fragmented by
the LAN host, then needs the reassembled IPv6 packet split into IPv6 fragments for the
tunnel MTU. `Nat64Lan::reverse` and `Nat64LanSource` are one packet in, at most one out, and
the engine's fragmentation stage answers an oversized IPv6 packet with Packet Too Big instead
of splitting it. Emitting several packets means a queue in `Nat64LanSource` (with
`recv_batch` capacity handling), a held-fragment verdict, an IPv6 fragment emitter and the
MTU in `Nat64Lan`: a restructuring, not a reuse. The existing `Reassembler` would cover the
forward half alone (IPv6 fragments reassembled, IPv4 left to the LAN stack to fragment), but
a request path that works with a reply path that does not is not worth the state.

- Forward: an IPv6 packet to an address of a `mapped` prefix whose first next header is 44
  drops with `reasons::FRAGMENT`; 0, 43 or 60 with `reasons::EXTENSION_HEADER` (kept dropped
  rather than skipped as `rfc7915.rs` does: the in-place rewrite assumes the transport
  header at offset 40).
- Reverse: an IPv4 fragment from a route's `real` prefix to its `snat_source` drops with
  `reasons::FRAGMENT`, whether or not a flow exists (it cannot be told).
- Counters: `Nat64Lan::fragment_drops`, `Nat64Lan::extension_header_drops` (accessors:
  `Nat64LanStats` is exhaustive).
- Two existing tests asserted `NotOurs` for these packets and were changed.

### 4. Double cleanup

`rfc7915::reassemble` runs `Reassembly::cleanup(now)` before it reads the markers, then
called `observe`, which ran it again with the same `now` under the same lock. `cleanup` is
idempotent for one `now`, and `reassemble` is the only caller outside tests, so the call in
`observe` went.

## Validation

- Item 2: 6 of the 7 tests in `translate::tests::icmp_extensions` failed before the fix
  (`translation length mismatch`, and the rewritten quote left alone); 297 pass after.
- Item 1: `masquerade::tests::quota` did not compile before (new API). With the closing
  timeout disabled in the implementation, `a_closing_tcp_flow_expires_after_30_s` and
  `a_closing_flow_makes_room_in_a_full_table` fail.
- Item 3: with only the reasons and accessors added, 6 tests failed (4 in
  `nat64_lan::tests::untranslatable`, 2 changed existing ones); all pass after.
- Item 4: covered by the existing reassembly tests.
- Gates, in the dev container: `cargo fmt --all --check`; `cargo hack clippy -p nsplane-nat
  --each-feature --all-targets --locked`; `cargo nextest run -p nsplane-nat -p nsplane-e2e
  --all-features --locked` (697 passed, 18 skipped); `cargo test -p nsplane-nat
  --all-features --doc --locked`; `cargo deny check`; `cargo shear`; `typos`;
  `scripts/check-docs.sh`; `scripts/check-product-terms.sh`; `cargo-zigbuild clippy -p
  nsplane-nat --all-targets --all-features --target aarch64-apple-darwin`. All pass.
