# 20261024-1430-netstack-any-destination Netstack mode that accepts any destination address

- **status**: completed (transparent mode in 0.17.0, plan 20261024-1600-egress-0-17)
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-24 14:30
- **plan**: 20261024-1430-netstack-any-destination

## Description

The owner asked whether `nsplane-netstack` can accept TCP connections and UDP flows to any
destination address and hand the original destination to the application on accept
(transparent-proxy style termination).

Findings (main at 0.16.2):

- `classify` drops every ingress packet whose destination is not one of the stack's addresses
  (`Reject::NoAddress`); the PMTU handler, reassembly and `owns()` apply the same `is_local`
  check (9 call sites).
- The listener pool listens on ports with an unspecified address, so a SYN to any address
  would be accepted once it reaches smoltcp; `TcpConnection::local_addr` is the socket's local
  endpoint, i.e. the destination of the SYN. `UdpFlow::local_addr` is the datagram's
  destination and replies are sourced from it.
- smoltcp at `v0.14.0-nsplane.6` has `Interface::set_any_ip`: with it `has_ip_addr` is true for
  every address, on ingress (`ipv4.rs`, `ipv6.rs`) and on TCP egress (`tcp.rs` dispatch). No
  fork change is needed.
- `NetStackConfig` is an exhaustive struct with public fields: a new field breaks struct
  literals without `..Default::default()`, so the change ships as 0.17.0.
- Today the only route is a `Redirect` in front of the stack plus a caller-side mapping to
  recover the original destination.

## Dependencies

- **blocked by**: owner approval, and a freeze exception (it is a feature)
- **blocks**: (none)
