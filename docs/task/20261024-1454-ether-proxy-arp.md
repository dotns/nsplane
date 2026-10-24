# 20261024-1454-ether-proxy-arp nsplane-ether: answer ARP and NDP for every address of the guest's link but its own

- **status**: in progress (merged into main fa086dd; ships with the next release)
- **priority**: P2
- **owner**: L1 (7f5cstru)
- **createdAt**: 2026-10-24 14:54
- **plan**: 20261024-1454-ether-proxy-arp

## Description

`nsplane-ether` answers ARP and IPv6 neighbor solicitations only for the gateway address, so other hosts of the leased prefix, which the guest sees as on-link, are unreachable from it. The owner asked the gateway to act as an ARP proxy.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- Targets the IP side cannot deliver to (unspecified, broadcast, multicast, loopback,
  link-local) are not proxied; the guest's own link-local address is therefore never
  answered. Confirmed by L1.
