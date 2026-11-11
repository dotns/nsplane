# 20261111-2036-ether-dhcp-rebind-and-periodic-ra The DHCP lease outlives its guest and router advertisements are sent once

- **status**: in_progress
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

## Validation
