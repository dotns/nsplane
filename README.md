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
- runs the `device` layer on Windows through Wintun.

See [CHANGELOG.md](CHANGELOG.md) for details.

## Repository layout

| Path             | Crate           | Description                                                                 |
| ---------------- | --------------- | --------------------------------------------------------------------------- |
| `boringtun/`     | `boringtun`     | Protocol library: Noise handshake, sessions, timers, and the optional `device` layer (TUN + UDP) |
| `boringtun-cli/` | `boringtun-cli` | Userspace WireGuard daemon for Linux, macOS and Windows, configured through `wg` |

The crate names are still the upstream names, which keeps merges from upstream
simple.

### Library features

| Feature        | Purpose                                                    |
| -------------- | ---------------------------------------------------------- |
| *(none)*       | Protocol only, with no network or TUN stack (`noise` module) |
| `device`       | Userspace device: TUN interface, UDP sockets, `wg` UAPI (Linux, macOS, Windows) |
| `ffi-bindings` | C ABI (`boringtun/src/wireguard_ffi.h`)                    |
| `jni-bindings` | Java/Android JNI bindings                                  |
| `mock-instant` | Mocks `Instant` for deterministic timer tests              |

## Using nstun as a dependency

Pin a commit so that builds are reproducible:

```toml
[dependencies]
boringtun = { git = "https://github.com/dotns/nstun", rev = "<commit>" }
# with the userspace device layer:
# boringtun = { git = "https://github.com/dotns/nstun", rev = "<commit>", features = ["device"] }
```

For local co-development, override it with a path dependency:

```toml
[patch."https://github.com/dotns/nstun"]
boringtun = { path = "../nstun/boringtun" }
```

## Building

The toolchain is pinned in `rust-toolchain.toml` (1.99.0); the MSRV is 1.95. Building
`aws-lc-sys` needs a C compiler, and NASM as well for x86_64 Windows targets.

```bash
# Library only
cargo build -p boringtun --lib --release

# Library with the device layer
cargo build -p boringtun --lib --features device --release

# CLI daemon
cargo build -p boringtun-cli --release
```

### Running on Linux and macOS

Run a userspace tunnel and configure it with the standard `wg` tooling:

```bash
sudo setcap cap_net_admin+epi target/release/boringtun-cli
target/release/boringtun-cli [-f] wg0
wg setconf wg0 /path/to/wg0.conf
```

### Running on Windows

- Put `wintun.dll` (from <https://www.wintun.net/>, matching the architecture) next to
  `boringtun-cli.exe`.
- Run from an elevated prompt: `boringtun-cli.exe wg0`. The daemon stays in the foreground;
  Ctrl-C stops it.
- Configure it with `wg.exe` (shipped with WireGuard for Windows), which talks to the named
  pipe `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\wg0`.
- Addresses and routes are set with the usual Windows tools (`netsh`, `New-NetIPAddress`).
- On Windows, `--threads` and `--disable-connected-udp` have no effect.

## Quality gates

There is no CI; run the gates locally before pushing (see `docs/decisions/`):

```bash
just check          # fmt, clippy for every feature, nextest, doctests, deny, shear, typos, MSRV
just cross          # clippy for aarch64-apple-darwin (zig) and x86_64-pc-windows-gnu (mingw)
just test-windows   # Windows unit tests under wine
just e2e            # interop with kernel WireGuard in two containers (docker)
just integration    # upstream integration tests (root, TUN, docker; reconfigures the host)
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
