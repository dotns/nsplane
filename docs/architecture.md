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
- `noise::wire`: `zerocopy` views of the four message layouts. Transport data is sealed
  and opened in place (`Tunn::encapsulate_in_place` / `decapsulate_in_place`).
- `device` (feature `device`): TUN, UDP sockets, peer table, and the `wg` UAPI.
  - Shared: `PeerTable` (peers by key, session index and allowed IP; cryptokey routing),
    `uapi` (get/set over any `BufRead`/`Write`), and the per-packet functions
    `receive_datagram`, `send_from_tun`, `update_timers`.
  - `unix`: epoll (Linux) or kqueue (macOS) event loop with N threads, TUN via
    `/dev/net/tun` or utun, UAPI on `/var/run/wireguard/<name>.sock`.
  - `windows`: blocking threads (Wintun reader, one reader per UDP socket, timers, UAPI
    named pipe `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>`) around a
    `RwLock`ed state; Ctrl-C stops the device.
- `ffi` / `jni` (features `ffi-bindings` / `jni-bindings`): C ABI and Android bindings
  over `noise`.

## Crypto

- ChaCha20-Poly1305 (transport data, handshake fields): `aws-lc-rs` (`aws-lc-sys` C/asm core,
  the pma-rust pre-sanctioned crypto exception).
- Constant-time comparisons: `subtle`.
- XChaCha20-Poly1305 (cookies), BLAKE2s, HMAC: RustCrypto.
- X25519: `x25519-dalek`.
