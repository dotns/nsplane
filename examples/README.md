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
