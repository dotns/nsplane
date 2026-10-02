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

### relay_server (planned)

A relay that forwards datagrams between peers that cannot reach each other directly.

```sh
cargo run -p nsplane-examples --bin relay_server -- --help
```

### relay_transport (planned)

A node whose transport is the relay (UDP or WSS) instead of direct UDP.

```sh
cargo run -p nsplane-examples --bin relay_transport -- --help
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
