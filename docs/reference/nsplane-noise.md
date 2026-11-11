# nsplane-noise

The WireGuard protocol: the Noise_IKpsk2 handshake, sessions, timers and cookies, with no
I/O. `nsplane-core` builds the engine on it; an application can use it alone with its own I/O.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `noise::Tunn` (handshake, sessions, timers; `encapsulate_in_place` / `decapsulate_in_place`, `set_pad_limit`, `remote_index`, `is_expired` / `expiry_cause`, `stats`, `tx_bytes` / `last_handshake_rtt`), `noise::rate_limiter::RateLimiter` (`with_budget`, `mac1_matches`), `x25519` keys | `noise::rate_limiter::HandshakeBudget`, `TunnResult`, `noise::errors::WireGuardError`, `noise::ExpiryCause` |

## Behavior

- `noise`: transport-agnostic protocol core. `Tunn` owns the handshake, the session ring,
  the timers, and the per-peer packet queue. It never does I/O: callers pass datagrams in
  and get back a `TunnResult` telling them what to write and where.
  - `handshake`: Noise_IKpsk2 handshake and cookie handling.
  - `session`: transport-data AEAD and the anti-replay window.
  - `rate_limiter`: mac1/mac2 verification and cookie replies under load. A source whose
    mac2 is valid under load is held to 20 handshakes per second with a burst of 5, per
    IPv4 address or IPv6 /64 (at most 4096 tracked sources); the excess is dropped as
    `WireGuardError::UnderLoad`.
  - `timers`: the WireGuard timer state machine (rekey, keepalive, expiry). The tunnel
    expires after `REJECT_AFTER_TIME * 3` (540 s) without a new session
    (`ExpiryCause::SessionAge`) or after `REKEY_ATTEMPT_TIME` (90 s) of unanswered
    initiations (`ExpiryCause::HandshakeTimeout`); `Tunn::expiry_cause` returns the cause
    while `Tunn::is_expired`, and the next handshake initiation clears both. With a
    persistent keepalive the timers send that initiation one interval after the expiry, so
    an unanswered peer is tried again in cycles for as long as the keepalive is set.
- `Tunn::stats` returns the time since the last handshake, the data bytes sent and received,
  the estimated packet loss and the round-trip time of the last handshake this side initiated.
  It computes all of them, the loss estimate under the receive locks of every session;
  `Tunn::tx_bytes` and `Tunn::last_handshake_rtt` read one field each and nothing else.
- `noise::wire`: `zerocopy` views of the four message layouts. Transport data is sealed
  and opened in place (`Tunn::encapsulate_in_place` / `decapsulate_in_place`).

## Decrypted IP validation

All receive paths (copying, in-place and `commit_open`) require IPv4 IHL >= 5
and header length <= declared total length <= available plaintext. IPv4 options are
accepted. IPv6 requires its fixed 40-byte header plus declared payload to fit the
plaintext. Delivery trims trailing padding; empty plaintext is a keepalive.

Invalid bounds return `WireGuardError::InvalidPacket` before plaintext `rx_bytes` or
the data-received timer advances. As for other invalid IP shapes, authentication has
already advanced replay state, session confirmation and the authenticated-packet timer.
The engine logs a `Decapsulate error` and reports `DECAPSULATE_ERROR` before wire-byte
accounting, authenticated-message notifications, filters or delivery.

## Errors and drop reasons

`TunnResult::Err` carries a `noise::errors::WireGuardError` (invalid message, wrong index,
replayed counter, expired session, under load). The engine maps them onto its drop reasons
(`nsplane-core` `reasons`).

## See also

- [nsplane-core](nsplane-core.md): the engine core on `Tunn`.
- [Architecture: crypto](../architecture.md#crypto): the cryptographic primitives.
