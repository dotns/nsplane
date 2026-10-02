# nsplane examples

Runnable programs that show how the nsplane crates fit together. Each example is a binary
of the `nsplane-examples` package; every one has `--help`:

```sh
cargo run -p nsplane-examples --bin <name> -- --help
```

`just check` builds all of them (`just examples`), and `examples/tests/` runs the ones that
need no root.

## Examples

### udp_pair

Quick start: two engines in one process over loopback UDP, each on a userspace netstack;
handshake, TCP and UDP echo through the tunnel, peer stats. No root.

```sh
cargo run -p nsplane-examples --bin udp_pair -- [--ipv6]
```

### tun_node

A TUN node managed with `wg show` / `wg set` (UAPI on the standard socket), echo and checks
on the kernel stack. Needs root.

```sh
sudo cargo run -p nsplane-examples --bin tun_node -- --private-key-file a.key --address 10.0.0.1/24 --peer <B_PUB>,endpoint=192.0.2.2:51820,allowed-ips=10.0.0.2/32 --echo-port 7
```

### netstack_node

A node without TUN and without root: the engine's local side is `nsplane-netstack`, echo and
checks run on the userspace stack.

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
cargo run -p nsplane-examples --bin events_stats
```

### relay_server

A single-port relay that is also a WireGuard node. One UDP socket carries WireGuard to the
relay's own engine (netstack with `--address`, echo with `--echo-port`), WireGuard between
other peers relayed blindly by mac1 and receiver index, and the relay's control messages
(`register_source`, reflexive address). The design is in
`docs/decisions/2026-10-02-single-port-relay.md`. No root.

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
Datagrams to it while the connection is down are dropped and counted; the connection
reconnects with backoff (250 ms doubling to 5 s) and discovery restarts on every connect,
so the node registers again right away.

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
| `.extra.wss.dropped.{disconnected,queue_full,text,oversized,no_route}` | drops by reason |
| `.extra.wss.{url,relay}` | the URL and the relay's address |

## Shared flags

### Node (`NodeArgs`)

| Flag | Meaning |
|---|---|
| `--private-key <BASE64>` / `--private-key-file <PATH>` | own key in `wg genkey` format; exactly one is required |
| `--listen <SOCKETADDR>` | local transport address, default `0.0.0.0:51820` |
| `--peer <SPEC>` | repeatable; `<base64 pubkey>[,endpoint=<host:port>][,allowed-ips=<cidr>[+<cidr>...]][,keepalive=<secs>][,psk-file=<path>]` |
| `--status-file <PATH>` | write a JSON status snapshot every second |
| `--log <FILTER>` | stderr log filter, default `info` (e.g. `nsplane=debug,info`) |
| `--transport <udp>` | transport to run, default `udp` |

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

`--status-file <PATH>` is rewritten every second (via `<PATH>.tmp` and a rename):

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
