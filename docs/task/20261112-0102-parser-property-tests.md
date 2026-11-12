# 20261112-0102-parser-property-tests Property tests for the parsers that take untrusted bytes

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 01:02

## Description

The code audit found that the parsers fed from the network, a guest or a control socket were
tested by examples only. This task adds property tests for them in `nsplane-packet`,
`nsplane-noise`, `nsplane-nat`, `nsplane-dns`, `nsplane-ether`, `nsplane-uapi` and `nsplane-acl`,
one commit per crate.

Acceptance: the properties are real (round trips, an independent second decoder, invariants over
valid inputs with a few fields changed), deterministic, add no dependency and cost about 10 s
of `cargo nextest run` at most. A defect found on the way gets a hand-written regression test and
its own `fix` commit when the fix is small and unambiguous, and is reported otherwise.

## ActiveForm

Adding seeded property tests for the untrusted-input parsers of seven crates.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

The tests follow the convention already in the tree: a local `SplitMix64` generator with a fixed
seed, no `proptest`, no fuzz harness, no change to `Cargo.lock`. Most generators start from a
valid message and change a few fields, since uniformly random bytes are refused at the first
check. Every test ends with thresholds on how often each branch was reached, so a generator that
drifts cannot leave a property vacuous.

What was added, with the number of cases:

- `nsplane-packet` (`tests/properties.rs`, 9 tests): the IP, TCP, UDP and ICMP parsers against the
  header layout, the checksum helpers, and the virtio-net header and segmentation paths.
- `nsplane-noise` (`src/noise/property_tests.rs`, 5 tests): the datagram parser and forged or
  changed handshake and data messages against a live session.
- `nsplane-nat` (`src/translate/tests/properties.rs`, 5 tests): the strict parsers and the
  translator in both directions, with round trips and checksum validity of every output.
- `nsplane-dns` (`tests/properties.rs`, 6 tests; `src/forward/property_tests.rs`, 3 tests):
  decoding (30,000), responses echoing the query within the size limit (8,000), the server on
  arbitrary messages (12,000), passed upstream responses (400 over loopback UDP), CNAME rules
  (4,000), the fake address pool (60 pools of 300 operations), and response matching in the
  forwarder (20,000 + 20,000 + 30,000).
- `nsplane-ether` (`tests/properties.rs`, 7 tests; `src/vnet/property_tests.rs`, 2 tests): the
  frame parser (30,000), ARP (30,000), neighbor discovery against a second decoder (30,000) and
  its answers (20,000), DHCP parsing (30,000) and the server's one-client promise (200 runs of
  150 steps), the adapter's accounting (40 runs of 500 frames), GSO splitting (400) and untrusted
  virtio-net headers (30,000).
- `nsplane-uapi` (`src/uapi/property_tests.rs`, 3 tests): key text forms (20,000), `set` requests
  against a model of the errno and the resulting `get` state (30 engines, 30 rounds each), and
  arbitrary request bytes (3,000).
- `nsplane-acl` (`src/gate/tests/properties.rs`, 2 tests; `src/filter/tests/properties.rs`,
  1 test): the gate's header readers against a second decoder (40,000), twin gates on untrusted
  packets (60 rounds of 1,000 steps), and twin filters with one counter per packet (4 configs of
  6,000 packets).

Two defects were found and fixed, each with a regression test seen failing first:

- `nsplane-packet`: a `GSO_UDP_L4` super-packet whose IP version nibble is neither 4 nor 6 was
  segmented as IPv4. It is refused now.
- `nsplane-nat`: an IPv6 atomic fragment (offset 0, no more fragments) was translated to IPv4
  without the TCP or UDP checksum and UDP length checks a whole datagram gets. It is checked now.

One existing test was wrong: `a_cookie_holder_gets_tokens_back_over_time` in `nsplane-noise`
bounded the second flood by the time spent verifying only, not by the time between the floods, in
which the bucket refills as well. It failed on a busy machine, with or without the new tests
(5 of 5 with every core busy). It now measures the whole span.

Observed and left as they are, since each is a design decision or needs a wider change:

- `nsplane-nat`: an ICMP error that quotes an IPv4 UDP datagram with a zero checksum is
  translated to IPv6 with the quoted checksum still zero; a quoted ICMP echo header cut below
  four bytes keeps its untranslated type; ESP and No Next Header are accepted behind a Fragment
  header.
- `nsplane-dns`: a query name with a label outside hostname syntax (`foo-.test`, `a b.test`,
  `*.test`) decodes, but a resolver that answers with records of that owner name gets SERVFAIL,
  and the fake pool still spends a binding on it; a label that contains a dot is not told from
  two labels. A message with the reserved Z header bit set is answered FORMERR, upstream
  responses included.
- `nsplane-uapi`: a peer section is applied when the next valid `public_key=` line or the end of
  the request arrives, so a malformed `public_key=` line drops the complete section before it.
  The model in the test mirrors this.
- `nsplane-ether`: the DHCP path does not check the UDP length or checksum, and the adapter
  passes IPv4 packets without verifying the header checksum.
- `nsplane-acl`: the reader of a quoted IPv4 packet in an ICMP error takes bytes beyond the outer
  total length when the buffer has trailing bytes.

Not covered: the forwarder's retry and timeout paths and the TCP framing of the DNS server, the
tap and packet-socket system calls and the stream framing of `nsplane-ether`, real rebinding for
`listen_port` and `fwmark` in `nsplane-uapi`, rule compilation and concurrency in `nsplane-acl`
(the existing model and differential tests cover them), and the cryptographic internals of
`nsplane-noise`. They need sockets, privileges or wall-clock time, or are not parsers.

## Validation

`udp_super_packet_of_another_ip_version_is_rejected` and
`an_atomic_ipv6_fragment_is_checked_as_the_whole_datagram_it_is` failed before their fixes and
pass after.

`cargo nextest run` over the seven crates, all features, dev profile: 1091 tests before, 1136
after. On a busy 32-core machine, six runs each in turn: 2.47-2.63 s without the new tests,
2.78-3.05 s with them (two earlier runs at 4.2-4.4 s while a load test was ending), so about
half a second added.

`cargo fmt --all --check`, `cargo hack clippy --each-feature --all-targets --locked`, the doc
tests, `cargo deny check`, `cargo shear`, `typos`, `scripts/check-docs.sh` and
`scripts/check-product-terms.sh` pass for the seven crates; `cargo nextest run` with
`nsplane-e2e` added passes (1519 tests, 20 skipped); clippy passes for `aarch64-apple-darwin`
and `x86_64-pc-windows-gnu`.
