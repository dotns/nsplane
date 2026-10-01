# nstun Architecture

nstun is the dotns fork of [cloudflare/boringtun](https://github.com/cloudflare/boringtun), a
userspace WireGuard implementation. The upstream remote is kept for merges.

## Crates

| Crate | Path | Role |
|---|---|---|
| `boringtun` | `boringtun/` | Library: the Noise protocol state machine (`noise`), plus the optional userspace device (`device`), C FFI (`ffi`), and JNI (`jni`) |
| `boringtun-cli` | `boringtun-cli/` | Daemon that runs a `device` on a TUN interface and exposes the `wg` UAPI |

## Library layers

- `noise`: transport-agnostic protocol core. `Tunn` owns the handshake, the session ring,
  the timers, and the per-peer packet queue. It never does I/O: callers pass datagrams in
  and get back a `TunnResult` telling them what to write and where.
  - `handshake`: Noise_IKpsk2 handshake and cookie handling.
  - `session`: transport-data AEAD and the anti-replay window.
  - `rate_limiter`: mac1/mac2 verification and cookie replies under load.
  - `timers`: the WireGuard timer state machine (rekey, keepalive, expiry).
- `device` (feature `device`): event loop, TUN, UDP sockets, peer table (cryptokey
  routing via `AllowedIps`), and the cross-platform `wg` UAPI.
- `ffi` / `jni` (features `ffi-bindings` / `jni-bindings`): C ABI and Android bindings
  over `noise`.

## Crypto

- ChaCha20-Poly1305 (transport data, handshake fields): `ring`.
- XChaCha20-Poly1305 (cookies), BLAKE2s, HMAC: RustCrypto.
- X25519: `x25519-dalek`.
