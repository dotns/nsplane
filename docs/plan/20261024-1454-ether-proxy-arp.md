# 20261024-1454-ether-proxy-arp nsplane-ether: answer ARP and NDP for every address of the guest's link but its own

- **status**: completed (released as 0.19.0)
- **createdAt**: 2026-10-24 14:54
- **relatedTask**: 20261024-1454-ether-proxy-arp

## Work

| Step | Work | Verify |
| --- | --- | --- |
| A1 | Proxy mode in `EtherConfig` (default on, opt-out kept for the current behavior): ARP requests for any IPv4 address other than the guest's own leased address, and neighbor solicitations for any IPv6 address other than the guest's own addresses (link-local and the ones it uses in the advertised prefix, learned from its traffic and DAD), are answered with the gateway MAC; gratuitous ARP, ARP probes (sender 0.0.0.0) and DAD solicitations are never answered for the guest's own candidate address, so duplicate address detection keeps working; counters for proxied answers | unit tests: on-link peer resolved, own address not answered, probe and DAD not answered, opt-out restores the old behavior |
| A2 | `vm_wireguard`: a host of the tunnel prefix other than the gateway is reachable from the guest (in-process test with a second address on the remote side); README / guide text on on-link reachability updated; QEMU real-guest script pings a second address of the peer's prefix | test in `just check`; real run once, result in the report |
| A3 | Reference `nsplane-ether`, CHANGELOG `[Unreleased]` | `just docs` |

## Constraints

- Feature by owner exception (freeze amendment 9). No new dependency.
- Gate: `just check`, `cargo doc -D warnings`, `just cross`, `just test-windows`.
