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

### hybrid (planned)

A TUN device and a netstack side by side behind one engine (`Splitter`, `MergeSource`).

```sh
sudo cargo run -p nsplane-examples --bin hybrid -- --help
```

### acl_gateway (planned)

A node that filters forwarded traffic with `nsplane-acl` and reports its counters.

```sh
cargo run -p nsplane-examples --bin acl_gateway -- --help
```

### fd_bridge (planned)

A host bridge: the engine on an adopted TUN fd, as mobile platforms hand it over.

```sh
cargo run -p nsplane-examples --bin fd_bridge -- --help
```

### events_stats (planned)

Subscribes to engine events and prints handshakes, roaming, drops and periodic stats.

```sh
cargo run -p nsplane-examples --bin events_stats -- --help
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

### relay_transport

The relay's client side, in one process on loopback (no root): a relay (router and own
engine), nodes A and B with the extension-aware transport and the direct-first path
ladder, and a plain WireGuard peer. A gate on A's socket blocks the direct path to show
direct -> relay -> direct. Prints `STEP <name> PASS|FAIL` for `discovery`, `relay-engine`,
`direct-first`, `direct-checks`, `block`, `unblock`, `plain-endpoint`, then `STEPS PASS`.

```sh
cargo run -p nsplane-examples --bin relay_transport -- --carrier udp
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

An endpoint is extension-capable only after a reflexive reply that echoes an outstanding
nonce; until then the node sends it nothing but WireGuard, and an endpoint that never
answers is stopped after the last attempt. A peer whose `--peer` endpoint is a capable
relay and that has candidates goes on the ladder: direct first, the relay when direct does
not authenticate in time or stops answering, back to direct when a periodic probe
authenticates. Status:

| JSON path | Meaning |
|---|---|
| `.extra.relay.endpoints["<ip:port>"].state` | `unknown`, `probing`, `capable` or `stopped` |
| `.extra.relay.endpoints["<ip:port>"].{attempts,control_sent,control_answered,rate_limited,reflexive}` | per-endpoint counters |
| `.extra.relay.reflexive`, `.extra.relay.reflexive_from` | learned reflexive address and the relay that reported it |
| `.extra.relay.{dropped_invalid,dropped_control}` | datagrams the transport dropped |
| `.extra.paths["<peer pubkey b64>"].active` | `direct` or `relay` |
| `.extra.paths["<peer pubkey b64>"].{confirmed,direct,relay,candidates,to_direct,to_relay}` | ladder state and transition counters |

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
