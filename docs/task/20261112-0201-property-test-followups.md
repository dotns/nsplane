# 20261112-0201-property-test-followups Follow-ups of the parser and codec property tests

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 02:01

## Description

The property tests of `20261112-0102-parser-property-tests` modelled eight behaviours as they
were instead of as they should be. Each one is settled here from the code, the crate's
reference document and the RFC: a real defect gets a failing regression test, a minimal fix and
a corrected model in its property test; a deliberate limit or an unreachable case gets no code
change, a reason, and a sentence in the reference document where it was missing.

Acceptance: every item has a verdict below; every fix was seen failing first; the gates of
`nsplane-nat`, `nsplane-dns`, `simple-dns`, `nsplane-uapi`, `nsplane-ether` and `nsplane-acl`
pass. No new dependency, additive public API only.

## ActiveForm

Settling the follow-ups of the property tests item by item.

## Dependencies

- **blocked by**: `20261112-0102-parser-property-tests`
- **blocks**: (none)

## Notes

1. **nat, zero UDP checksum in a quote (IPv4 to IPv6): deliberate.** A quote is usually cut
   short, so no checksum can be computed over it; the host that gets the error matches the
   quote by addresses and ports and verifies no checksum inside it; a datagram that reached the
   quoting host through this translator never carries a zero (the unquoted path computes one,
   as RFC 7915 4.5 asks). The behaviour was already pinned by
   `zero_udp_checksum_in_icmp_quotes_keeps_family_specific_rules`; the reference now gives the
   reason. No code change.
2. **nat, quoted echo header cut below four bytes: defect, fixed.** The type of a quoted echo
   header was translated only when the quote held the checksum too, so a quote of one to three
   bytes kept the type of the other family. The type is now translated from one byte on, the
   checksum from four.
3. **nat, ESP and No Next Header behind a Fragment header, quotes of any protocol:
   deliberate.** The parser reads the two as the fragmented protocol, and the translation then
   refuses them like an unfragmented packet (`UNSUPPORTED_PROTOCOL`), so nothing of them is
   translated. They pass only where any protocol does: inside a quote, whose upper layer is
   opaque past its addresses, and in a `peer6`/`local6` address rewrite, which translates no
   upper layer. Pinned by tests and stated in the reference. No code change.
4. **dns, names outside host-name syntax: defect, fixed.** `Query::name()` came from a lossy
   text form, so a label with a dot, a backslash or a non-printable octet could not be told
   from other names: such a query got SERVFAIL after `FakePool` had spent a binding on it, a
   label holding a dot read as two labels (the single label `allowed.example` matched an exact
   rule for the name `allowed.example`), and the forwarder compared questions through the same
   text. The text is now canonical and unambiguous (lowercase, no trailing dot, `\DDD` for
   every octet that is not printable ASCII and for `.` and `\` inside a label), record names
   are built from it without host-name validation, and rules match on label boundaries.
5. **dns, reserved header bit: defect, fixed.** RFC 1035 4.1.1 reserves Z and asks for zero on
   sending; refusing it on receipt made a query with the bit FORMERR and, worse, made an
   upstream response with the bit unreadable, which timed out into SERVFAIL. The bit is now
   ignored on receipt (the change is in the `simple-dns` copy, noted in its `UPSTREAM.md`) and
   cleared in everything sent: answers, the query sent upstream and the response relayed.
6. **uapi, malformed `public_key=` line: defect, fixed.** The key was parsed before the section
   the line closes was applied, so a complete, valid peer section was discarded, against "the
   settings before a failing one stay applied". The closed section is applied first, as
   wireguard-go does. No atomicity is promised anywhere: interface settings already took
   effect line by line. The section a failing line stands in is still not applied, and the
   reference now says both.
7. **ether, checks on the DHCP path and on passed IPv4: split.**
   - DHCP datagram: defect, fixed. The adapter is the receiving host, so it now checks the IPv4
     header checksum (RFC 1122 3.2.1.2) and that the UDP length is at least 8 and within the IP
     payload; the message ends at the UDP length. A failure counts as `drop_malformed`.
   - UDP checksum of that datagram: deliberately not checked. The adapter is handed bare
     frames; `PacketReader` completes a `VIRTIO_NET_HDR_F_NEEDS_CSUM` checksum before the
     adapter, but another `FrameRead` may not, and a guest that cannot take a lease is a far
     worse failure than a corrupted message on a virtual link. The header checksum is never
     offloaded, so checking it breaks no offloaded traffic.
   - Passed IPv4 packets: deliberate and documented ("no checksum check"); the adapter is a
     link for them and the receiver or router on the IP side verifies. The reference now gives
     the reason. No code change.
8. **acl, `quote_v4` past the total length: defect at the public API, fixed.** In-tree sources
   hand the gate exact packets (the tunnel trims padding to the IP length), but
   `FlowGate::evaluate_inbound` and `evaluate_outbound` take any buffer, and bytes behind the
   total length of an ICMP error were accepted as its quote. `quote_v4` now stops at the total
   length, as `quote_v6` already stopped at the payload length. There was no `icmp_error/v4`
   bench to measure the path, so one was added next to `icmp_error/v6`.

Left undone: no UDP checksum check for DHCP and no checksum check for passed packets (reasons
above); the zero UDP checksum of a quote is not replaced; `simple-dns` was not otherwise changed.

## Validation

Seen failing before the fix, passing after:

- nat: `a_quoted_echo_header_cut_before_its_checksum_gets_its_type_translated`,
  `the_reported_cut_echo_quote_is_translated`, and the property test with the quoted echo type
  asserted.
- dns names: the five tests of `tests/names.rs`, and the forwarder property tests against the
  old question comparison.
- dns reserved bit: `the_reserved_header_bit_is_ignored_and_answered_with_zero`,
  `an_upstream_response_with_the_reserved_bit_is_accepted`,
  `the_reserved_bit_of_a_client_is_not_sent_upstream`, and
  `reserved_bit_is_ignored_on_parse_and_written_as_zero` in `simple-dns`.
- uapi: `a_peer_section_before_a_malformed_public_key_stays_applied`.
- ether: `dhcp_needs_a_sound_ip_header_and_udp_length`, and
  `the_adapter_accounts_for_every_frame_and_passes_only_whole_ip_packets` with the new
  assertion against the unfixed adapter.
- acl: `an_icmp_error_quote_ends_with_the_packet_not_the_buffer`.

`cargo bench -p nsplane-acl --bench gate -- icmp_error`, bench profile, one
`scripts/bench/slot.sh` invocation (slot 0, CPUs 1-7, load 1.5), before and after interleaved,
three rounds, criterion means in ns:

| Bench | Before | After |
| --- | --- | --- |
| `icmp_error/v4` | 36.02, 36.24, 36.20 | 36.49, 36.57, 36.45 |
| `icmp_error/v6` | 47.58, 47.97, 47.82 | 47.17, 47.36, 47.34 |

The bound costs `icmp_error/v4` about 0.35 ns (1 %); `icmp_error/v6`, whose code did not
change, moved by 0.5 ns the other way between the two binaries, so the cost is within what
code layout alone does.
