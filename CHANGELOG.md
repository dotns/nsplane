# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Breaking: replace `ring` with `aws-lc-rs` for ChaCha20-Poly1305, and with `subtle` for
  constant-time comparisons. `ring` is no longer a dependency.
- Edition 2024, MSRV 1.95, workspace-wide lint policy (warnings denied, clippy pedantic and
  nursery, no `unwrap`/`expect`/`panic` in runtime code).
- Breaking: `Tunn::encapsulate` and the session code return
  `WireGuardError::DestinationBufferTooSmall` instead of panicking on short buffers.
- Breaking: `AllowedIps::insert` takes the prefix length as `u8`.
- CLI: argument parsing uses clap derive; core dumps are disabled at startup and panics are
  logged.

### Security
- Cookies (mac2) cover the source port as well as the IP, as the whitepaper requires.
- Handshake rate limiting counts per source IP, so one flooding source no longer pushes every
  peer into cookie mode; a device-wide budget (10x the per-source limit) remains as backstop.
- Enforce `Reject-After-Messages`: a sending key never wraps its nonce, and received counters
  at the limit are rejected. Keys that reach `Rekey-After-Messages` are renegotiated.
- Malformed base64 keys are rejected instead of being read as an all-zero key.
- Decapsulated packets are only accepted when the longest allowed-IP match of their source
  is the sending peer; a peer could previously use addresses inside another peer's subnet.
- Cookie replies no longer move the peer's endpoint (roaming).

### Added
- Zero-copy data path: `Tunn::encapsulate_in_place` seals a packet where it was read (behind
  `DATA_HEADER_SZ` bytes of header room) and `Tunn::decapsulate_in_place` decrypts transport
  data inside the receive buffer. The device reads TUN packets straight into the
  encapsulation buffer and decrypts UDP datagrams in place. `encapsulate`/`decapsulate` remain
  as copying wrappers.
- Messages are parsed and built through `zerocopy` views (`noise::wire`) instead of
  hand-written offsets.
- `data_path` benchmark (copying versus in-place round trip).
- `scripts/e2e/linux.sh` (`just e2e`): interop test against kernel WireGuard in two containers.
- `Tunn::set_preshared_key` and `Tunn::set_persistent_keepalive`. The UAPI updates existing
  peers in place (endpoint, keepalive, preshared key, allowed IPs including
  `replace_allowed_ips`) instead of panicking.

### Changed
- Breaking: `Tunn::decapsulate` and `RateLimiter::verify_packet` take the source as
  `Option<SocketAddr>`.
- Breaking: `Peer` no longer keeps its own allowed-IP table; the device routing table is the
  only source of truth. `Peer::new` lost its `allowed_ips` argument.
- Data packets are padded to a multiple of 16 bytes (when the buffer has room).
- The anti-replay window grows from 1024 to 8192 packets, like Linux and wireguard-go.
- Timers: the passive keepalive is due 10 s after the first unanswered data packet, a
  handshake 15 s after the first unanswered data packet sent; the persistent keepalive is sent
  as soon as it is enabled and is suppressed while traffic flows; handshake retries add
  0-333 ms of jitter.

### Fixed
- UAPI `set`: settings of one peer section no longer leak into the next section.
- UAPI `get` reports `last_handshake_time_*` as wall-clock Unix time, as `wg` expects, instead
  of the age of the handshake ("56 years ago").
- CLI: `WG_SUDO=1` is accepted again (any boolish value).
- Re-binding the listen port now unregisters the previous UDP sockets; the old sockets were
  leaked because their events were cleared under the wrong fd.
- The UAPI socket is bound at `/var/run/wireguard/<name>.sock` without a doubled slash.
- In daemon mode the log writer thread is started after the fork, so logs are written.
- JNI: `x25519_key_to_hex`/`x25519_key_to_base64` no longer leak the string.
- FFI/JNI: NULL tunnel pointers and short buffers return an error instead of crashing.
- TUN devices close their fd on every error path (Linux and macOS).
- `Debug` output redacts preshared keys, chaining keys, and cookies.

## [0.7.1] - 2026-05-01

### Security
- use a 64-bit nonce counter on 32-bit platforms to avoid the possibility of nonce re-use with large REKEY_AFTER_TIME
- CLI only: remove vulnerable dependency: `atty`

### Fixed
- use portable-atomic to support targets without native 64-bit atomics

## [0.7.0] - 2026-01-09

### Changes

- Breaking: make `noise::Tunn::new` infallible
- Upgrade vulnerable dependencies: ring, x25519-dalek
- Fix a compilation error on freebsd
- Fix incorrect socket type in `device::Peer::connect_endpoint`