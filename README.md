# nstun

nstun is the WireGuard<sup>®</sup> dependency for dotns projects. It is a fork of
[cloudflare/boringtun](https://github.com/cloudflare/boringtun), and we build our
own changes on top of it.

Upstream boringtun is a userspace implementation of the WireGuard protocol, written
in Rust for portability and speed. On top of it, nstun:

- uses `aws-lc-rs` instead of `ring` for ChaCha20-Poly1305,
- follows the pma-rust baseline (edition 2024, strict workspace lints, no panics in
  runtime code, documented `unsafe` only in platform and FFI modules),
- carries protocol fixes that [mullvad/gotatun](https://github.com/mullvad/gotatun) found
  (re-implemented, not copied: gotatun is MPL-2.0),
- has a zero-copy data path (in-place seal/open, `zerocopy` message views),
- replaces the synchronous `device` layer with a sans-I/O core (`nstun-core`) and a tokio
  driver (`nstun`), with TUN devices (including Windows through Wintun) in `nstun-tun`.

See [CHANGELOG.md](CHANGELOG.md) for details.

## Repository layout

| Path             | Crate           | Description                                                                 |
| ---------------- | --------------- | --------------------------------------------------------------------------- |
| `boringtun/`     | `boringtun`     | Protocol library: Noise handshake, sessions, timers (`noise`), C FFI and JNI bindings; no I/O |
| `nstun-packet/`  | `nstun-packet`  | Packet buffers, IP header views and shared value types; no I/O |
| `nstun-core/`    | `nstun-core`    | Sans-I/O WireGuard engine core: peers, cryptokey routing, timers, path policy, filters |
| `nstun/`         | `nstun`         | Tokio driver: `Engine`, `EngineBuilder`, `EngineHandle`, events, I/O traits, UDP transport |
| `nstun-tun/`     | `nstun-tun`     | OS TUN devices (Linux, Android, macOS, iOS, Windows through Wintun) as packet sources and sinks |
| `nstun-uapi/`    | `nstun-uapi`    | The `wg` configuration protocol (UAPI) over an engine; Unix socket listener |
| `boringtun-cli/` | `boringtun-cli` | Development and test daemon for Linux and macOS, configured through `wg`; products embed the library |

`boringtun` and `boringtun-cli` keep the upstream names, which keeps merges from upstream
simple.

### `boringtun` features

| Feature        | Purpose                                                    |
| -------------- | ---------------------------------------------------------- |
| *(none)*       | Protocol only, with no network or TUN stack (`noise` module) |
| `ffi-bindings` | C ABI (`boringtun/src/wireguard_ffi.h`)                    |
| `jni-bindings` | Java/Android JNI bindings                                  |
| `mock-instant` | Mocks `Instant` for deterministic timer tests              |

## Using nstun as a dependency

Pin a commit so that builds are reproducible:

```toml
[dependencies]
# the engine with TUN devices and the wg UAPI:
nstun = { git = "https://github.com/dotns/nstun", rev = "<commit>" }
nstun-tun = { git = "https://github.com/dotns/nstun", rev = "<commit>" }
nstun-uapi = { git = "https://github.com/dotns/nstun", rev = "<commit>" }
# or the protocol only:
# boringtun = { git = "https://github.com/dotns/nstun", rev = "<commit>" }
```

For local co-development, override it with a path dependency:

```toml
[patch."https://github.com/dotns/nstun"]
nstun = { path = "../nstun/nstun" }
nstun-tun = { path = "../nstun/nstun-tun" }
nstun-uapi = { path = "../nstun/nstun-uapi" }
```

## Building

The toolchain is pinned in `rust-toolchain.toml` (1.99.0); the MSRV is 1.95. Building
`aws-lc-sys` needs a C compiler, and NASM as well for x86_64 Windows targets.

```bash
# Protocol library only
cargo build -p boringtun --lib --release

# Engine, TUN devices and UAPI
cargo build -p nstun -p nstun-tun -p nstun-uapi --release

# CLI daemon
cargo build -p boringtun-cli --release
```

### Development CLI (Linux and macOS)

`boringtun-cli` runs an nstun engine on a TUN interface in the foreground and logs to
stderr; SIGINT (Ctrl-C) or SIGTERM stops it. Run it in a separate terminal (or tmux) and
configure it with the standard `wg` tooling:

```bash
sudo setcap cap_net_admin+epi target/release/boringtun-cli
target/release/boringtun-cli -v info wg0
wg setconf wg0 /path/to/wg0.conf
```

| Argument                    | Env var        | Meaning                                                   |
| --------------------------- | -------------- | --------------------------------------------------------- |
| `<interface_name>`          |                | TUN interface to create (`utun` or `utunN` on macOS)      |
| `-t`, `--threads`           | `WG_THREADS`   | Tokio runtime worker threads (default 4)                  |
| `-v`, `--verbosity`         | `WG_LOG_LEVEL` | `error` (default), `info`, `debug` or `trace`             |
| `--disable-drop-privileges` | `WG_SUDO`      | Keep root; otherwise switch to `SUDO_UID`/`SUDO_GID` after setup |

- The UAPI listens on `/var/run/wireguard/<name>.sock`.
- The UDP socket is bound to an ephemeral port at startup; `wg set <name> listen-port <port>`
  rebinds it.
- `--tun-fd`/`WG_TUN_FD` and `--uapi-fd`/`WG_UAPI_FD` are gone: adopting a raw fd needs
  `unsafe`, which the CLI forbids (the library keeps `nstun_tun::Tun::from_fd`).
  `--disable-connected-udp` and `--disable-multi-queue` are gone with the synchronous device
  they configured.

It does not daemonize, so `wg-quick` with `WG_QUICK_USERSPACE_IMPLEMENTATION` is not
supported.

### Windows (library)

`nstun-tun` builds on Windows on top of Wintun:

- `wintun.dll` (from <https://www.wintun.net/>, matching the architecture) must sit next to
  the executable, which runs elevated.
- `nstun-uapi` has no Windows listener (named pipe) yet; embedders configure the engine
  through `EngineHandle` or `Uapi::handle_request`.

## Quality gates

There is no CI; run the gates locally before pushing (see `docs/decisions/`):

```bash
just check          # fmt, clippy for every feature, nextest, doctests, deny, shear, typos, MSRV
just cross          # clippy for aarch64-apple-darwin (zig) and x86_64-pc-windows-gnu (mingw)
just test-windows   # library unit tests for Windows under wine
just e2e            # interop with kernel WireGuard in two containers (docker)
```

## Syncing with upstream

| Remote     | URL                                       | Branch   |
| ---------- | ----------------------------------------- | -------- |
| `origin`   | `https://github.com/dotns/nstun`          | `main`   |
| `upstream` | `https://github.com/cloudflare/boringtun` | `master` |

```bash
git remote add upstream https://github.com/cloudflare/boringtun   # once
git fetch upstream
git merge upstream/master        # resolve conflicts, run tests, then push main
```

The fork has diverged a lot (edition 2024, lint cleanup, new modules), so upstream changes
usually have to be ported by hand rather than merged. Guidelines for our changes:

- Put new functionality in new modules or behind feature flags.
- Send generic fixes upstream when they are not dotns-specific.

## License

BSD 3-Clause, inherited from upstream. See [LICENSE.md](LICENSE.md). The original
copyright notices must be retained.

---

<sub>WireGuard is a registered trademark of Jason A. Donenfeld. nstun is not sponsored
or endorsed by Jason A. Donenfeld or Cloudflare.</sub>
