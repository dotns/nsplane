# nsplane examples

Runnable programs that show how the nsplane crates fit together. Each example is a binary
of the `nsplane-examples` package; every one has `--help`:

```sh
cargo run -p nsplane-examples --bin <name> -- --help
```

`just check` builds all of them (`just examples`), and `examples/tests/` runs the ones that
need no root. `just e2e-examples` runs them in containers (see [End-to-end](#end-to-end)).
The package `nsplane-examples` is not published.

| Example | What it shows | Root |
|---|---|---|
| [`udp_pair`](#udp_pair) | Two engines over loopback UDP with netstacks: handshake, TCP and UDP echo, stats | no |
| [`tun_node`](#tun_node) | A node on a TUN device, managed with `wg` | yes |
| [`netstack_node`](#netstack_node) | A node whose local side is a userspace TCP/IP stack | no |
| [`hybrid`](#hybrid) | A TUN device and a netstack behind one engine (`Splitter`, `MergeSource`) | yes |
| [`acl_gateway`](#acl_gateway) | A TUN node filtered by a reloadable ACL policy | yes |
| [`translate_node`](#translate_node) | Local IPv4 to peers reached over IPv6 only (`Translator`, RFC 7915) | yes |
| [`port_map`](#port_map) | Local services published to peers through DNAT/SNAT (`PortMap`, `Conntrack`) | yes |
| [`subnet_gateway`](#subnet_gateway) | IPv6 peers reaching an IPv4 LAN through stateful NAT64 (`Nat64Lan`) | yes |
| [`fd_bridge`](#fd_bridge) | The engine on a TUN handed over by a host: by fd or by packet channels | yes |
| [`events_stats`](#events_stats) | Events, peer stats, drop counters, suspend/resume, MTU | no |
| [`relay_server`](#relay_server) | A single-port relay with its own WireGuard engine, over UDP and WSS | no |
| [`relay_transport`](#relay_transport) | Relay discovery and the direct/relay path ladder, in-process | no |
| [`app_session`](#app_session) | App sessions on ACL namespaces: a file transfer through source-gated pinholes | no (`--tun`: yes) |

## Examples

### udp_pair

Quick start: two engines in one process over loopback UDP, each on a userspace netstack;
handshake, TCP and UDP echo through the tunnel, peer stats. No root.

```sh
cargo run -p nsplane-examples --bin udp_pair -- [--ipv6] [--check-timeout <SECS>] [--log <FILTER>]
```

### tun_node

A TUN node managed with `wg show` / `wg set` (UAPI on the standard socket), echo and checks
on the kernel stack. Needs root.

Flags: node, echo and check flags, `--tun-name <NAME>` (default `nsp0`), `--address <CIDR>`
(repeatable), `--mtu <N>` (default 1420).

```sh
sudo cargo run -p nsplane-examples --bin tun_node -- --private-key-file a.key --address 10.0.0.1/24 --peer <B_PUB>,endpoint=192.0.2.2:51820,allowed-ips=10.0.0.2/32 --echo-port 7
```

### netstack_node

A node without TUN and without root: the engine's local side is `nsplane-netstack`, echo and
checks run on the userspace stack.

Flags: node, echo and check flags, `--address <CIDR>` (repeatable, required; one IPv4 and one
IPv6 are used), `--mtu <N>` (default 1420).

```sh
cargo run -p nsplane-examples --bin netstack_node -- --private-key-file b.key --listen 127.0.0.1:51821 --address 10.0.0.2/24 --peer <A_PUB>,endpoint=127.0.0.1:51820,allowed-ips=10.0.0.1/32 --check tcp:10.0.0.1:7 --exit-after-checks
```

### hybrid

A TUN device and a userspace netstack behind one engine: a `Splitter` routes each delivered
packet by destination (inside a `--tun-address` prefix to the TUN, anything else to the
netstack), a `MergeSource` merges both sides' packets. Echo and checks run on the netstack.
Status: `extra.splitter.misrouted`, `extra.netstack`. Needs root.

Flags: node, echo and check flags, `--tun-name <NAME>` (default `nsp0`), `--tun-address <CIDR>`
(repeatable), `--stack-address <CIDR>` (repeatable, required), `--mtu <N>` (default 1420).
`--no-offload` opens a plain TUN device and binds UDP without GSO/GRO; the startup log shows
`offload=` and `udp_offload=`.

```sh
sudo cargo run -p nsplane-examples --bin hybrid -- --private-key-file a.key --tun-address 10.0.0.1/24 --stack-address 10.1.0.1/24 --peer <B_PUB>,endpoint=192.0.2.2:51820,allowed-ips=10.0.0.2/32+10.1.0.2/32 --echo-port 7
```

### acl_gateway

A TUN node with an `nsplane-acl` `AclFilter` and a `FlowTracker`: inbound packets pass only as
the JSON `--policy` allows for the peer's `--identity`; replies to connections the gateway
opens always pass (stateful replies). The policy file is re-read every second and swapped in
atomically (`policy reloaded (N rules)`; a broken file keeps the previous policy); before the
first valid policy everything inbound is dropped. Status: `extra.acl` (filter counters,
`policy_loaded`, `rules`, `reloads`, `reload_errors`) and `extra.flows`. Needs root.

Flags: node, echo and check flags, `--tun-name`, `--address <CIDR>` (repeatable), `--mtu`,
`--policy <PATH>`, `--identity <WG_PUBKEY>=<IP|key>` (repeatable). The sample
[`policies/acl_gateway.json`](policies/acl_gateway.json) allows TCP and UDP port 7 from the
peer identity `10.0.0.2` to the gateway `10.0.0.1` and denies everything else (e.g. TCP 8).

```sh
sudo cargo run -p nsplane-examples --bin acl_gateway -- --private-key-file a.key --address 10.0.0.1/24 --peer <B_PUB>,endpoint=192.0.2.2:51820,allowed-ips=10.0.0.2/32 --identity <B_PUB>=10.0.0.2 --policy examples/policies/acl_gateway.json --echo-port 7
```

### translate_node

A TUN node with an `nsplane-nat` `Translator`: local IPv4 packets to a peer leave as IPv6 in
the tunnel and the peer's IPv6 replies arrive as IPv4. Every peer owns a /127 IPv6 group,
`node6` (native) and `node4` (its IPv4 side); `--map` names them and the local aliases:
IPv4 to `alias4` becomes IPv6 to `node4`, and `alias6` is rewritten to and from `node6`.
`--self <SELF4>=<NODE4>` maps this node's IPv4 address to its own `node4` (`self4/32` is
added to the interface unless an `--address` covers it). `--lan <LAN4>=<LAN6>[@<PUBKEY>]`
pairs an IPv4 prefix with an IPv6 /96 (the IPv4 address in the low 32 bits); without `@`
the LAN is behind this node, whose hosts route the aliases through it (IP forwarding on).
Each mapped peer's allowed IPs get its `alias4/32`, `alias6`, `node4`, `node6` and the LAN
prefixes behind it, since the core routes and checks sources before the filter runs; the
interface gets the routes. Status: `extra.translate` (translated, rewritten and dropped
counters per direction). Needs root.

Flags: node, echo and check flags, `--tun-name`, `--address <CIDR>` (repeatable), `--mtu`,
`--self <SELF4>=<NODE4>`, `--map <PUBKEY>,node6=<IPv6>,node4=<IPv6>[,alias4=<IPv4>][,alias6=<IPv6>]`
(repeatable), `--lan <IPv4>/<len>=<IPv6>/96[@<PUBKEY>]` (repeatable).

```sh
sudo cargo run -p nsplane-examples --bin translate_node -- --private-key-file a.key --self 10.200.0.1=fd00:a::1:1 --peer <B_PUB>,endpoint=192.0.2.2:51820 --map <B_PUB>,node6=fd00:a::2:0,node4=fd00:a::2:1,alias4=10.200.0.2 --lan 192.168.50.0/24=fd00:1::/96
```

### port_map

A TUN node with an `nsplane-nat` `PortMap`: each `--publish` maps a tunnel-facing address and
port to a local service. A peer's packet to `listen` is rewritten to `target` (DNAT) and its
flow recorded in a bounded `Conntrack`; the service's replies are rewritten back to come
from `listen` (SNAT). With `@<PUBKEY>` only that peer may use the rule, other peers' packets
to `listen` are dropped. `listen` and `target` are of the same family (e.g. an interface
address and the `--echo-port` on it). Idle flows expire after the conntrack timeouts.
Status: `extra.port_map` (`rules`, `conntrack` counters: `entries`, `inserted`, `expired`,
`evicted`, `removed`, `hits`, `misses`). Needs root.

Flags: node, echo and check flags, `--tun-name`, `--address <CIDR>` (repeatable), `--mtu`,
`--publish <tcp|udp>:<listen>=<target>[@<PUBKEY>]` (repeatable, IPv6 in brackets),
`--tcp-established-timeout`, `--tcp-transitory-timeout`, `--udp-timeout`, `--icmp-timeout`
(seconds; defaults 300, 30, 30, 30), `--max-flows` (default 65536).

```sh
sudo cargo run -p nsplane-examples --bin port_map -- --private-key-file a.key --address fd00:b::1/64 --peer <B_PUB>,endpoint=192.0.2.2:51820,allowed-ips=fd00:b::2/128 --echo-port 7 --publish 'tcp:[fd00:b::1]:8007=[fd00:b::1]:7@<B_PUB>' --udp-timeout 5
```

### subnet_gateway

A TUN node whose local side is wrapped in an `nsplane-nat` `Nat64Lan`: each `--route` maps
an IPv6 /96 to an IPv4 LAN prefix. A peer's TCP, UDP or ping to `<MAPPED>::<IPv4>` leaves
the TUN device as IPv4 to that LAN host, from `snat` with a port reserved for the flow, and
the host's reply comes back to the peer as IPv6 from the mapped address; unsafe targets
(broadcast, loopback, ...) are dropped. `snat` must not be an address of this host: the node
routes `snat/32` into the TUN device and the LAN routes it to this host (IP forwarding on).
The peers route the mapped /96 to this node. Status: `extra.nat64_lan` (`forwarded`,
`reversed`, `packet_too_big`, `unsafe_target`, `port_exhausted`, `other_drops`,
`not_ours`, `flows`, `flows_inserted`, ...). Needs root.

Flags: node, echo and check flags, `--tun-name`, `--address <CIDR>` (repeatable), `--mtu`,
`--route <IPv6>/96=<IPv4>/<len>,snat=<IPv4>` (repeatable), `--max-tcp-mss`.

```sh
sudo cargo run -p nsplane-examples --bin subnet_gateway -- --private-key-file a.key --address fd00:c::1/64 --peer <B_PUB>,endpoint=192.0.2.2:51820,allowed-ips=fd00:c::2/128 --route fd00:64::/96=192.168.50.0/24,snat=10.201.0.1
```

### fd_bridge

A host bridge as mobile platforms do it. The host creates and configures the TUN; with
`--mode fd` (default) it clears `FD_CLOEXEC` on the TUN fd and re-executes itself with
`--child-fd <N>`, and the child adopts the fd (`Tun::from_raw_fd`) and runs the engine; with
`--mode channel` the host pumps packets between the TUN and an engine on `ChannelSource` /
`ChannelSink` and forwards MTU changes. Echo and checks run on the kernel stack. Needs root.

Flags: node, echo and check flags, `--tun-name`, `--address <CIDR>` (repeatable), `--mtu`,
`--mode <fd|channel>`, `--child-fd <N>` (internal, set by the parent).

```sh
sudo cargo run -p nsplane-examples --bin fd_bridge -- --mode channel --private-key-file a.key --address 10.0.0.1/24 --peer <B_PUB>,endpoint=192.0.2.2:51820,allowed-ips=10.0.0.2/32 --echo-port 7
```

### events_stats

Two engines over loopback UDP on netstacks (no root). Prints every engine event (`EVENT ...`),
peer stats (`STATS ...`) and drop counters (`DROPS ...`), and runs self-checked steps:
`handshake` (checks pass, counters grow), `suspend` (a check fails, counters frozen), `resume`
(a new handshake, the check passes), `mtu` (lowering a merged channel source's MTU yields
`MtuChanged` and `EngineHandle::mtu`), `drop` (a datagram to an unowned address counts as
`no route`). Each prints `STEP <name> PASS|FAIL`; the run ends with `STEPS PASS` (exit 0) or
`STEPS FAIL` (exit 1).

```sh
cargo run -p nsplane-examples --bin events_stats -- [--step-timeout <SECS>] [--suspended-check <SECS>] [--log <FILTER>]
```

### relay_server

A single-port relay that is also a WireGuard node. One UDP socket carries WireGuard to the
relay's own engine (netstack with `--address`, echo with `--echo-port`), WireGuard between
other peers relayed blindly by mac1 and receiver index, and the relay's control messages
(`register_source`, reflexive address). The design is in
`docs/decisions/2026-10-02-single-port-relay.md`. No root.

Flags: node, echo and check flags, `--address <CIDR>` (repeatable, required), `--mtu <N>`,
`--config <PATH>`, `--target <MACHINE=WGKEY>`, `--static-target <WGKEY=IP:PORT>` (both
repeatable), `--gateway-id <ID>` (carried in reflexive responses, default `relay`),
`--wss-listen <IP:PORT>`, `--wss-name <NAME>`, `--wss-cert-out <PATH>`. The subcommand
`gen-machine-key <PATH>` writes a new machine key (base64 Ed25519 seed, mode 0600; an existing
file is not overwritten) and prints its public key.
`--no-offload` binds the relay's UDP socket without GSO/GRO; the startup log shows
`udp_offload=`.

```sh
cargo run -p nsplane-examples --bin relay_server -- gen-machine-key a.machine   # prints the public key
cargo run -p nsplane-examples --bin relay_server -- --private-key-file r.key --listen 0.0.0.0:51820 \
  --address 10.0.0.1/24 --config relay.json --peer <A_PUB>,allowed-ips=10.0.0.2/32 --echo-port 7 \
  --status-file relay.status.json
```

Targets (the WireGuard keys it relays to) come from `--target <MACHINE_PUB>=<WG_PUB>`,
`--static-target <WG_PUB>=<IP:PORT>` and `--config`, re-read within a second of a change:

```json
{"machine_keys": [{"machine_key": "<ed25519 public b64>", "wg_public_key": "<b64>"}],
 "static_targets": [{"wg_public_key": "<b64>", "endpoint": "192.0.2.7:51820"}]}
```

A pinned target's source is learned from its `register_source`, signed by that machine key
(machine id: the key's base64), fresh and not replayed; a static target (a native WireGuard
peer, which cannot register) is at a fixed endpoint. Status `extra.relay`:

| JSON path | Meaning |
|---|---|
| `.extra.relay.counters.own_engine` | datagrams handed to the own engine |
| `.extra.relay.counters.forwarded` | datagrams relayed |
| `.extra.relay.counters.control_rx` / `control_tx` | control frames received / reflexive replies sent |
| `.extra.relay.counters.registrations` | accepted `register_source` |
| `.extra.relay.counters.route_evictions` | routes evicted by the table bounds |
| `.extra.relay.counters.dropped_{ambiguous,unknown_target,invalid,rate_limited,replay,bad_signature}` | drops by reason |
| `.extra.relay.routes[]` | `{receiver_index, from, to, idle_secs, confirmed}` |
| `.extra.relay.targets[]` | `{wg_public_key, machine_key, source, learned_secs_ago}` |

`--wss-listen <IP:PORT>` adds a WebSocket-over-TLS listener feeding the same router: each
binary message carries one datagram (the same bytes as on UDP), so WSS and UDP clients relay
to each other and reach the own engine. The certificate is self-signed at start for
`--wss-name` (default `relay.example`) plus the listen address as an IP name, and written to
`--wss-cert-out <PATH>` for clients to pin. Text, oversized (> 65535 bytes) and non-WireGuard,
non-control messages are dropped and counted; pings are answered; a closed connection's
learned sources and routes are forgotten. A WSS connection shows up as `ws:<id>` in
`routes[]` and `targets[].source`.

```sh
cargo run -p nsplane-examples --bin relay_server -- --private-key-file r.key --listen 0.0.0.0:51820 \
  --address 10.0.0.1/24 --config relay.json --wss-listen 0.0.0.0:8443 --wss-cert-out relay.pem
```

| JSON path | Meaning |
|---|---|
| `.extra.wss.connections` | open WSS connections |
| `.extra.wss.{accepted,handshake_failures,closed}` | connections accepted, failed TLS/WebSocket handshakes, closed |
| `.extra.wss.{rx,tx,pings}` | datagrams received / sent over WSS, pings answered |
| `.extra.wss.dropped_{text,oversized,invalid,queue_full,closed}` | drops by reason |

### relay_transport

The relay's client side, in one process on loopback (no root): a relay (router and own
engine), nodes A and B with the extension-aware transport and the direct-first path
ladder, and a plain WireGuard peer. A gate on A's socket blocks the direct path to show
direct -> relay -> direct. Prints `STEP <name> PASS|FAIL` for `discovery`, `relay-engine`,
`direct-first`, `direct-checks`, `block`, `unblock`, `plain-endpoint`, then `STEPS PASS`.
With `--carrier wss` A and B reach the relay only over WebSocket over TLS (a pinned
certificate generated at start); the direct path stays UDP, and the extra step `wss-carrier`
checks both connections carried datagrams.

Flags: `--carrier <udp|wss>` (default `udp`), `--probe-backoff-ms` (200),
`--direct-timeout-ms` (2000), `--direct-probe-interval-ms` (3000), `--step-timeout <SECS>`
(20), `--log <FILTER>` (default `warn`).

```sh
cargo run -p nsplane-examples --bin relay_transport -- --carrier udp
cargo run -p nsplane-examples --bin relay_transport -- --carrier wss
```

Every node example runs the same client with `--transport relay`:

| Flag | Meaning |
|---|---|
| `--relay <IP:PORT>` | relay endpoint to discover, repeatable |
| `--machine-key-file <PATH>` | Ed25519 machine key (`relay_server gen-machine-key`); required |
| `--peer-candidates <FILE>` | `{"<wg pubkey b64>": ["ip:port", ...]}` direct candidates, polled every second |
| `--reflexive-out <FILE>` | writes `{"reflexive": "ip:port", "relay": "ip:port", "unix_ms": N}` |
| `--pin <auto\|direct\|relay>` | path of peers reached through a relay, default `auto` |
| `--probe-backoff-ms`, `--probe-attempts` | discovery backoff (1000 ms doubling) and attempts (5) |
| `--register-interval-ms`, `--reflexive-interval-ms` | cadence with a capable relay (30000, 20000) |
| `--direct-timeout-ms`, `--direct-probe-interval-ms` | ladder fallback time (5000) and direct probes on the relay (30000) |

`--transport wss` is the same client with the relay reached over WebSocket over TLS; UDP on
`--listen` still carries the direct paths and any other `--relay`. The relay's address
(below) is added to the endpoints and is the `endpoint=` of peers reached through it.
The client is an `nsplane::LinkTransport` with a tokio-tungstenite dialer. Datagrams to
the relay wait in the link's queue (256) while the connection is down, and a send fails at
once when it is full; the connection reconnects with backoff (250 ms doubling to 5 s),
pings every 10 s and is redialed after 35 s without a frame, and discovery restarts on
every connect, so the node registers again right away.

| Flag | Meaning |
|---|---|
| `--relay-url <wss://host[:port]/>` | WebSocket URL; the host is the TLS server name (SNI); required |
| `--relay-ca <PEM>` | the relay's certificate (`relay_server --wss-cert-out`), the only one trusted; required |
| `--relay-addr <IP:PORT>` | connect here instead of resolving the URL host |
| `--machine-key-file <PATH>` | as for `--transport relay`; required |

```sh
cargo run -p nsplane-examples --bin netstack_node -- --private-key-file a.key --address 10.0.0.2/24 \
  --transport wss --relay-url wss://relay.example:8443/ --relay-addr 192.0.2.1:8443 \
  --relay-ca relay.pem --machine-key-file a.machine \
  --peer <RELAY_PUB>,endpoint=192.0.2.1:8443,allowed-ips=10.0.0.1/32
```

An endpoint is extension-capable only after a reflexive reply that echoes an outstanding
nonce; until then the node sends it nothing but WireGuard, and an endpoint that never
answers is stopped after the last attempt. A peer whose `--peer` endpoint is a capable
relay and that has candidates goes on the ladder: direct first, the relay when direct does
not authenticate in time or stops answering, back to direct when a periodic probe
authenticates. Status:

| JSON path | Meaning |
|---|---|
| `.extra.relay.endpoints["<ip:port>"].state` | `unknown`, `probing`, `capable` or `stopped` |
| `.extra.relay.endpoints["<ip:port>"].{attempts,control_sent,control_answered,rate_limited,reflexive,demotions}` | per-endpoint counters; `demotions`: times a capable endpoint stopped answering for three reflexive intervals and was probed again |
| `.extra.relay.reflexive`, `.extra.relay.reflexive_from` | learned reflexive address and the relay that reported it |
| `.extra.relay.{dropped_invalid,dropped_control}` | datagrams the transport dropped |
| `.extra.paths["<peer pubkey b64>"].active` | `direct` or `relay` |
| `.extra.paths["<peer pubkey b64>"].{confirmed,direct,relay,candidates,to_direct,to_relay}` | ladder state and transition counters |
| `.extra.wss.{connected,reconnects,connect_failures}` | `--transport wss`: connection up, reconnects after the first connect, failed attempts |
| `.extra.wss.{tx,rx,drops}` | datagrams sent / received over the connection, dropped |
| `.extra.wss.dropped.{disconnected,queue_full,text,oversized,no_route}` | drops by reason; `disconnected` stays 0 (datagrams wait in the queue), `queue_full` counts sends that failed on a full queue |
| `.extra.wss.{url,relay}` | the URL and the relay's address |

### app_session

App sessions on `nsplane-acl` rule namespaces, in one process on loopback UDP with netstacks
(no root). Every node has its own `AclEngine` and `AclFilter`, principals are WireGuard keys,
and an in-process mailbox stands in for the rendezvous. A session adds an `app:<id>`
namespace with the peer as member, opens pinholes on the app port (`open_pinhole`) and sends
a generated file over in-tunnel TCP, verified by SHA-256; ending the session drops the
guards and removes the namespace. Prints `STEP <name> PASS|FAIL` for `a` (reuse: existing
peers in `quick`, no new peer or handshake), `b` (not-permitted: `quick` no longer allows
`transfer`), `c` (revoke: `transfer` removed mid-transfer closes the pinhole), `d`
(session-only peers with `outbound: Some([])`: only the app port passes, then the peer is
removed), `e` (cross-namespace through a hub, opened in one direction by a directed grant),
then `CHECKS PASS` (exit 0) or `CHECKS FAIL` (exit 1). With `--tun <NAME>` (Linux, needs
`CAP_NET_ADMIN`) node A also runs a TUN next to its netstack and `STEP tun-outbound` checks
that host traffic to a session-only peer is dropped (`acl outbound denied`). Status
(`--status`, node A at the end): `extra.acl` (filter counters and namespaces) and
`extra.pinhole_stats`.

Flags: `--step <a|b|c|d|e|all>` (default `all`), `--ipv6`, `--tun <NAME>`, `--status <PATH>`,
`--log <FILTER>` (default `warn`).

```sh
cargo run -p nsplane-examples --bin app_session
sudo cargo run -p nsplane-examples --bin app_session -- --tun nsp-app --status app_session.json
```

## Shared flags

### Node (`NodeArgs`)

| Flag | Meaning |
|---|---|
| `--private-key <BASE64>` / `--private-key-file <PATH>` | own key in `wg genkey` format; exactly one is required |
| `--listen <SOCKETADDR>` | local transport address, default `0.0.0.0:51820` |
| `--peer <SPEC>` | repeatable; `<base64 pubkey>[,endpoint=<host:port>][,allowed-ips=<cidr>[+<cidr>...]][,keepalive=<secs>][,psk-file=<path>]` |
| `--status-file <PATH>` | write a JSON status snapshot every second |
| `--log <FILTER>` | stderr log filter, default `info` (e.g. `nsplane=debug,info`) |
| `--no-offload` | turn segmentation offload off (on by default): TUN nodes (`tun_node`, `fd_bridge`, `acl_gateway`, `hybrid`) open a plain TUN device, and the UDP socket (also `relay_server`'s) runs without GSO/GRO. The startup log names the modes in use: `offload=tso,uso` / `offload=off` for the TUN, `udp_offload=gso,gro` / `udp_offload=off` for UDP |
| `--transport <udp\|relay\|wss>` | transport to run, default `udp`; `relay` and `wss` take the flags under [relay_transport](#relay_transport) |

### Echo and checks (`EchoArgs`)

| Flag | Meaning |
|---|---|
| `--echo-port <PORT>` | serve TCP and UDP echo on this port of all local addresses |
| `--check <PROTO:IP:PORT>` | repeatable, e.g. `tcp:10.0.0.2:7`, `udp:[fd00::2]:7` |
| `--check-timeout <SECS>` | each check retries until it passes or this elapses, default 30 |
| `--exit-after-checks` | exit after the checks; code 0 iff all passed |

A TCP check connects, writes 1024 bytes, shuts its write half down and reads the echo to
EOF. A UDP check sends a 512-byte datagram every 500 ms until it comes back. Each check
prints one line to stdout, then a summary:

```text
CHECK tcp 10.0.0.2:7 PASS 42ms
CHECK udp [fd00::2]:7 FAIL timed out
CHECKS FAIL
```

### Status file

`--status-file <PATH>` is rewritten every second (via a temporary `<PATH>.<pid>.<n>.tmp` and a rename):

```json
{
  "public_key": "<base64>",
  "listen": "0.0.0.0:51820",
  "mtu": 1420,
  "peers": [
    {"public_key": "<base64>", "endpoint": "192.0.2.2:51820", "transport": 0,
     "rx": 1234, "tx": 1234, "last_handshake_secs_ago": 3,
     "peer": 0, "data_rx": 1000, "data_tx": 1000,
     "allowed_ips": ["10.0.0.2/32"], "persistent_keepalive": null}
  ],
  "drops": {"<reason>": 1},
  "extra": {}
}
```

`extra` holds example-specific state, e.g. `extra.netstack` (the netstack's drop counters)
on `netstack_node`.

## End-to-end

`just e2e-examples` (`scripts/e2e/examples.sh`) runs the release example binaries as the
design's "presentation x transport" scenarios, each node in its own container, against each
other and against kernel WireGuard. It needs docker and the `wireguard` kernel module on the
host; nothing on the host is reconfigured. The containers use `scripts/e2e/Dockerfile`
(`wireguard-tools`, `socat`, `iptables`, `tcpdump`, `iperf3`).

The matrix has 12 cells; each lists its cases, whose ids are `<row>/<column>/<case>`. In the
UDP column the peers are the same example or kernel WireGuard; in the relay columns the node
and a `tun_node` reach each other only through `relay_server`, with the direct path blocked.

| Row | `udp` | `relay-udp` | `relay-wss` |
|---|---|---|---|
| `tun` (`tun_node`) | `tun_pair`, `tun_kernel` | `relay_tun` | `relay_tun` |
| `netstack` (`netstack_node`) | `netstack_pair`, `netstack_kernel` | `relay_netstack` | `relay_netstack` |
| `fd` (`fd_bridge --mode fd`) | `fd_kernel` | `relay_fd` | `relay_fd` |
| `channel` (`fd_bridge --mode channel`) | `channel_tun` | `relay_channel` | `relay_channel` |

Scenarios: `udp_pair`, `events_stats` (self-checks), `hybrid`, `acl_gateway` (against kernel
WireGuard), `native_wg`, `native_wg_reverse` (native kernel WireGuard through the relay, in
both directions), `ladder_tun`, `ladder_netstack` (direct -> relay -> direct),
`nat_hole_punch` (the ladder behind MASQUERADE routers), `plain_wg_compat` (the relay
extension against a plain WireGuard server), `app_session` (self-checks), `app_session_tun`
(`app_session --tun`: `STEP tun-outbound` and `extra.acl.outbound_denied` in the status),
`translate_node` (an IPv4-only client container on the node's LAN reaches an IPv6-only
kernel WireGuard peer through its `alias4`: ping, TCP and UDP echo), `port_map` (a kernel
WireGuard peer reaches the echo service through the listen port, a rule for another peer
refuses it, an idle UDP flow expires after `--udp-timeout`), `subnet_gateway` (an
IPv6-only kernel WireGuard peer reaches an IPv4 host on the node's LAN through the mapped
/96: TCP and UDP echo and ping, with flows recorded in `extra.nat64_lan`; a ping to the
LAN's broadcast address is refused as an unsafe target),
`offload_fallback` (`tun_node --no-offload` against kernel WireGuard: the checks of
`tun_kernel` on the plain TUN device and UDP without GSO/GRO), `offload_fallback_hybrid`
(`hybrid --no-offload`: the checks of `hybrid`), `offload_fallback_relay` (`relay_server`
and two `tun_node`s over relay UDP, all with `--no-offload`: one UDP check through the
relay), each asserting `offload=off` / `udp_offload=off` in the startup logs, `offload_iperf` (`tun_node`
against kernel WireGuard with offload on and with `--no-offload`: 5 s iperf3 runs of TCP and
UDP in both directions; passes when every run moved data and prints the Mbit/s of all 8
runs, UDP loss reported but not gated). The run ends with the matrix and the scenario list
and fails if anything failed.

| Variable | Meaning |
|---|---|
| `NSPLANE_E2E_EX_ONLY` | run only the cases whose id (`<row>/<column>/<case>`, `scenario/<name>`) matches this regex |
| `NSPLANE_E2E_EX_BIN_DIR` | directory holding prebuilt example binaries; otherwise they are built in the dev image |
| `NSPLANE_E2E_EX_PREFIX` | name prefix of the containers, networks and image (default `nsplane-e2e-ex-<pid>`) |

```sh
just e2e-examples
NSPLANE_E2E_EX_ONLY='acl|hybrid' scripts/e2e/examples.sh
```
