# nstun

nstun is the WireGuard<sup>®</sup> dependency for dotns projects. It is a fork of
[cloudflare/boringtun](https://github.com/cloudflare/boringtun), and we build our
own changes on top of it.

Upstream boringtun is a userspace implementation of the WireGuard protocol, written
in Rust for portability and speed. nstun tracks it closely and adds whatever dotns
needs on top.

## Repository layout

| Path             | Crate           | Description                                                                 |
| ---------------- | --------------- | --------------------------------------------------------------------------- |
| `boringtun/`     | `boringtun`     | Protocol library: Noise handshake, sessions, timers, and the optional `device` layer (TUN + UDP) |
| `boringtun-cli/` | `boringtun-cli` | Userspace WireGuard daemon for Linux and macOS, configured through `wg`      |

The crate names are still the upstream names, which keeps merges from upstream
simple.

### Library features

| Feature        | Purpose                                                    |
| -------------- | ---------------------------------------------------------- |
| *(none)*       | Protocol only, with no network or TUN stack (`noise` module) |
| `device`       | Userspace device: TUN interface, UDP sockets, `wg` UAPI    |
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

```bash
# Library only
cargo build -p boringtun --lib --release

# Library with the device layer
cargo build -p boringtun --lib --features device --release

# CLI daemon
cargo build -p boringtun-cli --release
```

Run a userspace tunnel and configure it with the standard `wg` tooling:

```bash
sudo setcap cap_net_admin+epi target/release/boringtun-cli
target/release/boringtun-cli [-f] wg0
wg setconf wg0 /path/to/wg0.conf
```

## Testing

```bash
cargo test -p boringtun
```

The device integration tests need `sudo` (to create TUN interfaces) and Docker.

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

Guidelines for our changes:

- Keep changes small and localized, so that upstream merges stay cheap.
- Put new functionality in new modules or behind feature flags rather than
  rewriting upstream code paths where possible.
- Send generic fixes upstream when they are not dotns-specific.

## License

BSD 3-Clause, inherited from upstream. See [LICENSE.md](LICENSE.md). The original
copyright notices must be retained.

---

<sub>WireGuard is a registered trademark of Jason A. Donenfeld. nstun is not sponsored
or endorsed by Jason A. Donenfeld or Cloudflare.</sub>
