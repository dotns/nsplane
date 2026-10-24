# 20261024-1430-netstack-any-destination Netstack mode that accepts any destination address

- **status**: proposed (folded into 20261024-1600-egress-0-17, workstream W1)
- **createdAt**: 2026-10-24 14:30
- **relatedTask**: 20261024-1430-netstack-any-destination

## Goal

With one configuration switch, a `NetStack` terminates TCP and UDP addressed to any IP
address, and the application learns the original destination of every accepted connection
and flow. With the switch off, behavior and per-packet cost are unchanged.

## API

- `NetStackConfig::accept_any_destination: bool`, default `false`.
- No new accessor: `TcpConnection::local_addr()` and `UdpFlow::local_addr()` already return
  the destination of the SYN or datagram; in this mode that is the original destination. The
  rustdoc of both states it.
- `NetStackConfig::addresses` keeps its role for the stack's own traffic: `connect_tcp*`,
  `connect_udp*` and `bind_udp` still require a stack address (or the unspecified address).

## Behavior with the switch on

| Path | Change |
| --- | --- |
| `classify` | no `NoAddress` reject; TCP and UDP to any address of either family go on |
| smoltcp interface | `set_any_ip(true)`; listeners keep listening on ports with no address, so a SYN to any `(address, port)` is accepted and replies are sourced from its destination |
| UDP dispatch | a datagram to any address reaches a connected or bound socket of its tuple first, otherwise `incoming_udp` as a new flow; replies are sourced from the flow's destination |
| ICMP (PMTU) | a Fragmentation Needed / Packet Too Big is matched by the quoted tuple of a live connection, not by the stack's addresses |
| Reassembly | fragments to any address are reassembled (same `ReassemblyConfig` bounds) |
| `owns()` | a bare SYN or UDP datagram to any address is `Listener`; registered tuples stay `Flow` |
| Bounds | unchanged: the listener pool cap, the flow limit and every queue bound apply to all addresses together |

The stack then answers for every address the engine delivers to it. Which destinations reach
it is decided in front of it: the peers' allowed IPs, `PeerConfig::inbound_destinations`, the
ACL or a `Splitter`. The rustdoc of the field states this.

## Steps

| Step | Work | Verify |
| --- | --- | --- |
| A1 | Config field, `Settings` flag, `classify`, `set_any_ip`, UDP dispatch, PMTU and reassembly checks, `owns()` | unit tests: `classify` with the switch on and off; `owns()` for SYN, UDP and fragments to a foreign address |
| A2 | `nsplane-e2e` `netstack_any_destination`: two engines, the client side routes `0.0.0.0/0` and `::/0` to the stack's peer; TCP to `192.0.2.10:443` and `[2001:db8::10]:443`, UDP to `198.51.100.7:53`; accepted `local_addr()` equals the dialed address, echo replies arrive from it; with the switch off the same packets count as `no_address` | the new test, `just check` |
| A3 | Cost: `send_stream` and `netstack_udp_send` interleaved A/B (switch off against main) | no regression beyond noise; numbers in `docs/performance.md` only if a row changes |
| A4 | Docs: rustdoc, `docs/reference/nsplane-netstack.md`, both guide languages (section 8), `CHANGELOG.md` `[Unreleased]` | `just docs`, doctests |

Release as 0.17.0 (new public field on an exhaustive struct), after the owner's go-ahead.

## Out of scope

- No change to the smoltcp fork.
- No transparent outbound (connecting from an arbitrary source address); `connect_*` keep
  requiring a stack address.
- No ICMP echo responder for foreign addresses.
