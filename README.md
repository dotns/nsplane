# nsplane

nsplane is the WireGuard<sup>®</sup> data plane for dotns projects, a userspace
implementation of the WireGuard protocol written in Rust. It:

- uses `aws-lc-rs` for ChaCha20-Poly1305,
- follows the pma-rust baseline (edition 2024, strict workspace lints, no panics in
  runtime code, documented `unsafe` only in platform modules),
- has a zero-copy data path (in-place seal/open, `zerocopy` message views),
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
| `crates/nsplane/`        | `nsplane`        | Tokio driver: `Engine` (several transports at once, suspend/resume, MTU change events), `EngineBuilder`, `EngineHandle`, events, I/O traits, UDP transport |
| `crates/nsplane-tun/`    | `nsplane-tun`    | OS TUN devices (Linux, Android, macOS, iOS, Windows through Wintun) as packet sources and sinks |
| `crates/nsplane-netstack/` | `nsplane-netstack` | User-space TCP/IP stack on smoltcp (TCP and UDP endpoints, IPv4 and IPv6) as a packet source and sink |
| `crates/nsplane-uapi/`   | `nsplane-uapi`   | The `wg` configuration protocol (UAPI) over an engine; Unix socket and Windows named-pipe listeners |
| `crates/nsplane-cli/`    | `nsplane-cli`    | Development and test daemon for Linux and macOS, configured through `wg`; products embed the library |
| `crates/nsplane-e2e/`    | `nsplane-e2e`    | End-to-end tests: engines against each other and against kernel WireGuard |

### `nsplane-noise` features

| Feature        | Purpose                                                    |
| -------------- | ---------------------------------------------------------- |
| *(none)*       | Protocol only, with no network or TUN stack (`noise` module) |
| `mock-instant` | Mocks `Instant` for deterministic timer tests              |

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

## Quality gates

There is no CI; run the gates locally before pushing (see `docs/decisions/`):

```bash
just check          # fmt, clippy for every feature, nextest, doctests, deny, shear, typos, MSRV
just cross          # clippy for aarch64-apple-darwin (zig) and x86_64-pc-windows-gnu (mingw)
just test-windows   # library unit tests for Windows under wine
just e2e            # interop with kernel WireGuard in two containers (docker)
```

## License

BSD 3-Clause; copyright, origin and trademark notices are in [LICENSE.md](LICENSE.md).
