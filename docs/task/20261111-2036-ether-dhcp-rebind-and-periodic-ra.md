# 20261111-2036-ether-dhcp-rebind-and-periodic-ra The DHCP lease outlives its guest and router advertisements are sent once

- **status**: completed
- **priority**: P2
- **owner**: audit-fix
- **createdAt**: 2026-11-11 20:36

## Description

Two audited defects in `nsplane-ether`:

1. The single DHCP lease binds to the first client MAC that gets an ACK and never expires (the
   server has no clock). The adapter follows a changed guest MAC but kept the binding, so a
   guest recreated with another MAC and no DHCPRELEASE got no OFFER and a NAK to its REQUEST
   until the process restarted.
2. A router advertisement was sent only when the guest MAC was first learned and in answer to a
   router solicitation, with router and RDNSS lifetimes of 1800 s. A host stops soliciting once
   it has an advertisement (RFC 4861), so its default router and DNS servers expired 30 minutes
   after link-up. Derived from the code, not observed on a real guest.

Acceptance: a new guest MAC frees the lease and the new guest gets the same address; the port
repeats the router advertisement at an interval well below the lifetime once a guest is known
and advertisements are in use; regression tests for both; the crate gates pass.

## ActiveForm

Freeing the DHCP lease on a guest MAC change and repeating router advertisements.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

DHCP: `EtherAdapter` frees the lease (`DhcpServer::release`, new) where it already drops the
other state of the old guest MAC. A DHCP message is handled after its source MAC is learned,
so in the adapter the lease now always goes to the current guest MAC: the binding of a
standalone `DhcpServer` is unchanged, but behind the adapter a second MAC is no longer refused.
That is the trust model MAC learning already had (one guest per port); a frame from a stray
source frees the lease, and the holder's next REQUEST is acknowledged again. A guest that
bridges several MACs onto one port could have two of them take the one address.

Router advertisements: the adapter stays sans-I/O and without a clock.
`EtherAdapter::periodic_ra` returns the unsolicited advertisement and the caller owns the
timer; the reader task of `spawn_port` calls it every `adapter::RA_INTERVAL` (600 s, a third
of the 1800 s lifetime). `spawn_port` is the only driver of the adapter in the workspace
(stream, TAP and packet transports and the examples all go through it); `EtherAdapter` is
public, so the method documents that a direct embedder has to call it. It returns a frame only
after an advertisement was sent (first learn with a prefix, or an answered router
solicitation), so an IPv4-only guest gets none. The read future is not cancellation safe, so
the task keeps it pinned across the timer instead of dropping it. `tokio` gains the `time`
feature in `nsplane-ether`.

No breaking API change: `DhcpServer::release`, `EtherAdapter::periodic_ra` and
`adapter::RA_INTERVAL` are additions.

## Validation

Red before the fixes, green after:

- `adapter::tests::dhcp_lease_follows_the_guest_mac` (no OFFER for the second MAC before).
- `adapter::tests::periodic_ra_repeats_the_unsolicited_one`,
  `adapter::tests::periodic_ra_needs_an_earlier_advertisement` and, on paused Tokio time,
  `port::tests::router_advertisements_repeat_once_the_guest_is_known` (failed with `Elapsed`
  before); `port::tests::no_router_advertisements_without_ipv6` holds the negative case.

`cargo fmt --all --check`, `cargo hack clippy -p nsplane-ether --each-feature --all-targets
--locked`, `cargo nextest run -p nsplane-ether --all-features --locked` (83 passed, 1 skipped),
the doc tests, `typos` and `scripts/check-docs.sh` pass. Not run against a real guest; the
Windows and macOS builds were not run here.
