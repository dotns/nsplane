# nsplane

nsplane is the WireGuard<sup>®</sup> data plane for dotns projects, a userspace
implementation of the WireGuard protocol written in Rust. It:

- uses `aws-lc-rs` for ChaCha20-Poly1305,
- follows the pma-rust baseline (edition 2024, strict workspace lints, no panics in
  runtime code, documented `unsafe` only in platform modules),
- has a zero-copy data path (in-place seal/open, `zerocopy` message views),
- batches I/O with segmentation offload: virtio-net TSO/USO on Linux/Android TUN devices
  and UDP GSO/GRO through `quinn-udp`, falling back to one packet at a time where the
  kernel lacks them,
- is built from a sans-I/O core (`nsplane-core`) and a tokio driver (`nsplane`), with TUN
  devices (including Windows through Wintun) in `nsplane-tun` and a user-space TCP/IP
  stack in `nsplane-netstack`.

See [CHANGELOG.md](CHANGELOG.md) for details.

## Repository layout

| Path                     | Crate            | Description                                                                 |
| ------------------------ | ---------------- | --------------------------------------------------------------------------- |
| `crates/nsplane-noise/`  | `nsplane-noise`  | Protocol library: Noise handshake, sessions, timers (`noise`); no I/O |
| `crates/nsplane-packet/` | `nsplane-packet` | Packet buffers, IP header views and shared value types; no I/O |
| `crates/nsplane-core/`   | `nsplane-core`   | Sans-I/O WireGuard engine core: peers, cryptokey routing, timers, path policy, filters |
| `crates/nsplane-acl/`    | `nsplane-acl`    | Accept-only ACL policy engine with atomic reload, per-source rule namespaces, directed grants, outbound rules and app pinholes, and the `AclFilter` and `FlowTracker` packet filters |
| `crates/nsplane-nat/`    | `nsplane-nat`    | IPv4/IPv6 translation (`Translator`, RFC 7915) and service-publishing DNAT/SNAT (`PortMap`, `Conntrack`) packet filters |
| `crates/nsplane/`        | `nsplane`        | Tokio driver: `Engine` (several transports at once, suspend/resume, MTU change events, optional fragmentation stage), `EngineBuilder`, `EngineHandle`, events, I/O traits, UDP transport (with an optional side channel), `LinkTransport` over a dialed message link |
| `crates/nsplane-wss/`    | `nsplane-wss`    | WebSocket-over-TLS carriers: `WssDialer` (datagrams for `LinkTransport`), and the `WsFrame` stream protocol of ns and NSGW with its client (`WssStreamClient`, TCP streams and UDP flows multiplexed per session) and terminate leg (`WssStreamServer`, backends from the embedder's `WssResolver`) |
| `crates/nsplane-tun/`    | `nsplane-tun`    | OS TUN devices (Linux, Android, macOS, iOS, Windows through Wintun) as packet sources and sinks |
| `crates/nsplane-netstack/` | `nsplane-netstack` | User-space TCP/IP stack on smoltcp ([dotns/smoltcp](https://github.com/dotns/smoltcp) fork; TCP and UDP endpoints, IPv4 and IPv6) as a packet source and sink |
| `crates/nsplane-uapi/`   | `nsplane-uapi`   | The `wg` configuration protocol (UAPI) over an engine; Unix socket and Windows named-pipe listeners |
| `crates/nsplane-cli/`    | `nsplane-cli`    | Development and test daemon for Linux and macOS, configured through `wg`; products embed the library |
| `crates/nsplane-e2e/`    | `nsplane-e2e`    | End-to-end tests: engines against each other and against kernel WireGuard |
| `examples/`              | `nsplane-examples` | Runnable examples (not published); see [examples/README.md](examples/README.md) |

### `nsplane-noise` features

| Feature        | Purpose                                                    |
| -------------- | ---------------------------------------------------------- |
| *(none)*       | Protocol only, with no network or TUN stack (`noise` module) |

## Examples

Runnable programs in [`examples/`](examples/README.md) (package `nsplane-examples`, not
published) show how the crates fit together: TUN and netstack nodes, a hybrid local side, an
ACL gateway, app sessions on ACL namespaces and pinholes, IPv4 applications reaching
IPv6-only peers (`translate_node`), services published by DNAT/SNAT (`port_map`), host
bridges by fd or channels,
events and stats, and a single-port relay with its client transport over UDP and WebSocket
over TLS. Every example has `--help`:

```bash
cargo run -p nsplane-examples --bin udp_pair       # quick start, no root
cargo run -p nsplane-examples --bin <name> -- --help
```

Node examples open TUN devices and UDP sockets with offload on; `--no-offload` turns it off.

`just e2e-examples` runs them in containers as a matrix of local sides (TUN, netstack,
bridge by fd, bridge by channel) and transports (UDP, relay over UDP, relay over WSS) plus
scenarios, against each other and kernel WireGuard; see
[examples/README.md](examples/README.md#end-to-end).

## Using nsplane as a dependency

Pin a commit so that builds are reproducible:

```toml
[dependencies]
# the engine with TUN devices and the wg UAPI:
nsplane = { git = "https://github.com/dotns/nsplane", rev = "<commit>" }
nsplane-tun = { git = "https://github.com/dotns/nsplane", rev = "<commit>" }
nsplane-uapi = { git = "https://github.com/dotns/nsplane", rev = "<commit>" }
# or the protocol only:
# nsplane-noise = { git = "https://github.com/dotns/nsplane", rev = "<commit>" }
```

For local co-development, override it with a path dependency:

```toml
[patch."https://github.com/dotns/nsplane"]
nsplane = { path = "../nsplane/crates/nsplane" }
nsplane-tun = { path = "../nsplane/crates/nsplane-tun" }
nsplane-uapi = { path = "../nsplane/crates/nsplane-uapi" }
```

## Optional features and defaults

A basic client (an `EngineBuilder` on a TUN device and a `UdpTransport`, with peers and no
filters) needs only `nsplane` and `nsplane-tun`, which pull in `nsplane-core`,
`nsplane-packet` and `nsplane-noise`; `nsplane-acl`, `nsplane-nat`, `nsplane-netstack` and
`nsplane-wss` are not dependencies of either and are not built. A feature that is not
installed is not on the data path, so such a client pays no extra latency for it:

| Feature | How to enable | Default | Cost when not enabled |
| ------- | ------------- | ------- | --------------------- |
| `Translator` (`nsplane-nat`) | `EngineBuilder::filter(Box::new(Translator::new(table)))` | off | none (empty filter chain) |
| `PortMap` / `Conntrack` (`nsplane-nat`) | `EngineBuilder::filter(Box::new(PortMap::new(rules)?))` | off | none |
| `AclFilter` (`nsplane-acl`) | `EngineBuilder::filter(Box::new(AclFilter::new(engine, identity)))` | off | none |
| `FlowTracker` (`nsplane-acl`) | `EngineBuilder::filter(Box::new(FlowTracker::new(capacity)))` | off | none |
| Fragmentation stage | `EngineBuilder::fragmenter(FragmentConfig::default())` | off | one `Option` check per local packet |
| Crypto worker pool | `EngineBuilder::crypto_workers(n)`, `n` >= 2 | 0 (owner task) | one `Option` check per packet; each peer owns its tunnel, no lock (with workers it is shared behind a `Mutex`) |
| Netstack (`nsplane-netstack`), `Splitter`, `MergeSource` | `NetStack::split`, `Splitter`, `MergeSource` as the builder's source and sink | not used | none |
| TUN offload (Linux, Android) | on with `Tun::create`; `TunOptions::new().offload(false)` opts out | on where the kernel supports it | off: one system call per packet |
| UDP offload (GSO/GRO) | on with `UdpTransport::bind`; `UdpTransport::bind_with_offload(.., false)` opts out | on | off: one system call per datagram |
| UDP side channel | `UdpTransport::with_side_channel(classify, capacity)` | off | one `Option` check per received datagram; nothing is classified |
| `LinkTransport` | `LinkTransport::new(id, peer, dialer, config)` as a transport | not used | none: no task runs unless it is created |
| WSS carriers (`nsplane-wss`) | add the crate: `WssDialer::into_transport`, `WssStreamClient::new`, `WssStreamServer::new` | not a dependency | none: `nsplane` has no WebSocket or TLS dependency; only `nsplane-wss` pulls in `tokio-tungstenite` and `rustls` (aws-lc-rs), and it bundles no system or web PKI roots (the caller passes a `RootCertStore` or a `rustls::ClientConfig`) |

Offload never waits for more packets: the engine fills batches only with packets already
queued (non-blocking `try_recv`, no timers), TUN and UDP segmentation coalesce only within
the batch they are handed, a GRO read returns what one receive yields, and the crypto
worker pool hands work over when a batch is full or the owner task runs out of work, never
on a timer.

The address family is the caller's choice: IPv4 only, IPv6 only or dual stack follows from
the transport's bind address (`0.0.0.0:port`, an IPv6 address, or `[::]:port` for a
dual-stack socket), the TUN device's addresses and routes (configured outside nsplane) and
the peers' allowed IPs. A minimal IPv4-only client:

```rust
use std::error::Error;
use std::net::SocketAddr;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{Ecn, EngineBuilder, Path, Peer, TransportId, UdpTransport};
use nsplane_tun::Tun;

async fn client(
    key: StaticSecret,
    server_key: PublicKey,
    server: SocketAddr, // e.g. 198.51.100.1:51820
) -> Result<(), Box<dyn Error>> {
    const UDP: TransportId = TransportId::new(0);
    // The caller sets up the TUN device's addresses and routes, e.g.
    // `ip addr add 10.0.0.2/32 dev wg0` and `ip route add 10.0.0.0/24 dev wg0`.
    let (source, sink) = Tun::create("wg0")?.split()?;
    let udp = UdpTransport::bind(UDP, "0.0.0.0:0".parse()?)?;
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    let mut peer = Peer::new(server_key);
    peer.allowed_ips = vec!["10.0.0.0/24".parse()?];
    peer.persistent_keepalive = Some(25);
    peer.path = Some(Path { transport: UDP, addr: server, ecn: Ecn::NotEct });
    engine.handle().add_or_update_peer(peer).await?;
    engine.wait().await?;
    Ok(())
}
```

See [docs/architecture.md](docs/architecture.md#optional-features-and-defaults) for the
details.

## Performance

Measured with `just bench-wg` (`scripts/bench/wg-compare.sh`): two containers per pair,
pinned CPU sets, real TUN devices, MTU 1420, iperf3, 30 s x 3, medians, on a quiet 32-CPU
host (2026-10-04, main `92652cb`):

| Pair | TCP 1 stream | TCP 4 streams | UDP 3 Gbit/s loss |
| --- | --- | --- | --- |
| nsplane <-> nsplane | 8.1 Gbit/s | 8.9 Gbit/s | 0.4 % |
| nsplane -> kernel WireGuard | 7.7 Gbit/s | 7.6 Gbit/s | 0.0 % |
| kernel WireGuard -> nsplane | 7.0 Gbit/s | 6.9 Gbit/s | 0.0 % |
| wireguard-go <-> wireguard-go | 10.0 Gbit/s | 10.1 Gbit/s | 0.4 % |
| kernel WireGuard <-> kernel WireGuard | 4.0 Gbit/s | 4.1 Gbit/s | 0.0 % |

Kernel WireGuard is held back by the CPU pinning (its crypto threads run outside the pinned
sets). Offload carries nsplane: without it, 3.1 Gbit/s on one stream. Details, latency and CPU
per GB are in [docs/architecture.md](docs/architecture.md#against-wireguard-implementations).

## Tuning

The engine's packet queues hold 1024 packets each by default
(`EngineBuilder::queue_capacity`), measured to leave 1.5x headroom over a single bulk TCP
flow. `EngineHandle::queue_stats` reports each queue's high-water mark, and
`take_queue_stats` restarts the marks: a mark at its capacity together with
`DROP_SINK_FULL` or `DROP_TRANSMIT_FULL` in `EngineHandle::drop_counters` means the queue is
too small for the load (raise `queue_capacity`, e.g. to 2048 for many parallel bulk flows
through a userspace netstack); marks far below the capacity mean it can shrink. With crypto
workers, `QueueStats::crypto` and `crypto_done` cover the jobs with the workers, and
`EngineHandle::fragment_stats` reports the fragmentation stage's counters. See
[docs/architecture.md](docs/architecture.md#queue-depths) for the measurements.

By default one owner task encrypts and decrypts every packet. A hub with several busy peers
can spread that work over a pool of worker tasks with `EngineBuilder::crypto_workers(n)`
(`n` of 2 or more; 0 or 1 is the default single task). The pool is sharded by peer, so
each peer's packets keep their order, and it only helps on a multi-threaded tokio runtime
with traffic from several peers: one peer's packets always go to one worker. See
[docs/architecture.md](docs/architecture.md#crypto-worker-pool) for the design and the
throughput note.

Performance: on an x86-64 dev host a core round trip (seal and open) takes about 532 ns at
64 B and 1.35 us at 1420 B one packet at a time, and 412 ns and 1.23 us per packet in
batches of 32 (`Core::handle_datagrams` / `handle_locals`), an ACL-filtered established flow about 51-55 ns per packet, and
a hub with 8 peers moves about 0.9 Mpps of 1420 B packets on one owner task and 0.9-1.3 Mpps
with 2 or 4 crypto workers. The bench commands and the full table are in
[docs/architecture.md](docs/architecture.md#performance).

## Building

The toolchain is pinned in `rust-toolchain.toml` (1.99.0); the MSRV is 1.95. Building
`aws-lc-sys` needs a C compiler, and NASM as well for x86_64 Windows targets.

```bash
# Protocol library only
cargo build -p nsplane-noise --lib --release

# Engine, TUN devices and UAPI
cargo build -p nsplane -p nsplane-tun -p nsplane-uapi --release

# CLI daemon
cargo build -p nsplane-cli --release
```

### Development CLI (Linux and macOS)

`nsplane-cli` runs an nsplane engine on a TUN interface in the foreground and logs to
stderr; SIGINT (Ctrl-C) or SIGTERM stops it. Run it in a separate terminal (or tmux) and
configure it with the standard `wg` tooling:

```bash
sudo setcap cap_net_admin+epi target/release/nsplane-cli
target/release/nsplane-cli -v info wg0
wg setconf wg0 /path/to/wg0.conf
```

| Argument                    | Env var        | Meaning                                                   |
| --------------------------- | -------------- | --------------------------------------------------------- |
| `<interface_name>`          |                | TUN interface to create (`utun` or `utunN` on macOS)      |
| `-t`, `--threads`           | `WG_THREADS`   | Tokio runtime worker threads (default 4)                  |
| `-v`, `--verbosity`         | `WG_LOG_LEVEL` | `error` (default), `info`, `debug` or `trace`             |
| `--disable-drop-privileges` | `WG_SUDO`      | Keep root; otherwise switch to `SUDO_UID`/`SUDO_GID` after setup |
| `--tun-fd <FD>`             | `WG_TUN_FD`    | Adopt this already-open TUN fd instead of creating the interface |
| `--uapi-fd <FD>`            | `WG_UAPI_FD`   | Also serve the UAPI on this already-connected Unix stream socket |
| `--crypto-workers <N>`      | `WG_CRYPTO_WORKERS` | Crypto worker tasks (default 0: crypto on the engine task; 2 or more enables the pool) |
| `--no-offload`              | `WG_NO_OFFLOAD` | Open the TUN device and bind the UDP socket without segmentation offload |

- The UAPI listens on `/var/run/wireguard/<name>.sock`.
- The UDP socket is bound to an ephemeral port at startup; `wg set <name> listen-port <port>`
  rebinds it.
- `--tun-fd` and `--uapi-fd` take fds inherited from a parent process (FD_CLOEXEC cleared).
  The daemon takes ownership of both and closes them on exit; a closed or invalid fd fails
  startup. An adopted TUN fd starts with MTU 1420 and then follows the interface MTU. The
  interface name stays required: the UAPI socket is named after the adopted device's name
  when it can be queried, else after `<interface_name>`.
- `--uapi-fd` serves one client connection next to the standard socket, which is still
  bound; the daemon keeps running when that connection ends.
- On Linux the TUN device uses virtio-net offload (`IFF_VNET_HDR`, TSO/USO) and the UDP
  socket GSO/GRO when the kernel supports them, else plain per-packet I/O. With offload the
  socket sets DF; raise `net.core.rmem_max` / `wmem_max` (e.g. to 4194304) for the full
  4 MiB socket buffers.
- `--no-offload` applies to the device and socket created at startup. With `--tun-fd` the
  adopted device is used as is and only the UDP socket is affected. A `listen-port` or
  `fwmark` set over the UAPI binds a new socket with offload, so keep the ephemeral port
  (`wg show <name> listen-port`) when offload must stay off. `-v info` logs the offloads and
  crypto workers in use (`Data path configured`).
- `--disable-connected-udp` and `--disable-multi-queue` are gone with the synchronous device
  they configured.

It does not daemonize, so `wg-quick` with `WG_QUICK_USERSPACE_IMPLEMENTATION` is not
supported.

### Windows (library)

`nsplane-tun` builds on Windows on top of Wintun:

- `wintun.dll` (from <https://www.wintun.net/>, matching the architecture) must sit next to
  the executable, which runs elevated.
- `nsplane-uapi` listens on the named pipe
  `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<iface>` with the default security
  descriptor; the path and descriptor are not yet verified on a real Windows host.

### Platform local sides

- Linux, macOS, Windows: `Tun` opens (or, on Unix, adopts) a TUN device.
- Android: `TunSlot` over the `VpnService` fd; `TunSlot::replace` hot-swaps the fd on every
  reconfiguration while the engine runs, and `disable`/`enable` park I/O in between.
- iOS: `host_tun` bridges `NEPacketTunnelFlow`: the host pushes read packets into the
  `HostTunInput` and the engine writes through the host's `write` callback.

## Quality gates

There is no CI; run the gates locally before pushing (see `docs/decisions/`):

```bash
just check          # fmt, clippy for every feature, nextest, doctests, deny, shear, typos, MSRV
just cross          # clippy for aarch64-apple-darwin (zig) and x86_64-pc-windows-gnu (mingw)
just test-windows   # library unit tests for Windows under wine
just e2e            # interop with kernel WireGuard in two containers (docker)
just e2e-examples   # the examples as e2e scenarios in containers (docker)
```

## License

BSD 3-Clause; copyright, origin and trademark notices are in [LICENSE.md](LICENSE.md).
