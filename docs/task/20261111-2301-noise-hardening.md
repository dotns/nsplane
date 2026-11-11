# 20261111-2301-noise-hardening Hardening of the Noise state machine

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-11 23:01

## Description

Four audit findings in `nsplane-noise`, none exploitable against a correctly configured peer:

1. X25519 results were used without rejecting the all-zero output of a low-order public key,
   which the kernel and wireguard-go reject.
2. `Tunn::set_static_private` asserted on its arguments and `Tunn::decapsulate` had an
   `unreachable!()`.
3. Chaining keys, intermediate keys of the key schedule and the preshared key were plain
   arrays that were never wiped.
4. The `usize` byte counters of the tunnel were added to with `+=`.

Acceptance: each finding is fixed with a test where one is possible, the public API is
unchanged, and the gates of the crate and its consumers pass.

## ActiveForm

Hardening the Noise handshake and tunnel state against low-order keys, panics and key residue.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Low-order keys: every `diffie_hellman` result goes through `SharedSecret::was_contributory`
(a constant-time comparison with zero). A message with a low-order ephemeral fails with
`InvalidPacket`. The precomputed static-static secret is `None` for a peer whose static key has
small order: `Tunn::new` still accepts the key, and every handshake step with that peer fails
with `WrongKey`, before any handshake state changes when initiating. Before, anyone could
complete a handshake as such a peer, because its static-static secret is all zero.
`WireGuardError` is not `#[non_exhaustive]`, so no variant was added.

Panics: the assertion was reachable through the public API (a mismatched key pair passed to
`Tunn::set_static_private`). The public key is now derived from the private key and the
argument is ignored; the default rate limiter uses the derived key too. The `unreachable!()`
was a true invariant of `RateLimiter::verify_packet`, whose public error type is wider than
what it returns: a crate-private `Rejection` type now carries the two cases.

Wiping: `zeroize` is a direct dependency. The HMAC helpers of the key schedule return
`Zeroizing` arrays, so chaining keys (also those stored in the handshake state), intermediate
keys and the derived session keys are wiped when dropped; `Session::new` borrows the keys.
Shared secrets are read in place instead of copied, and the preshared key is wiped when the
handshake is dropped. Not covered: a preshared key replaced by `Tunn::set_preshared_key` (a
`pub const fn`, which cannot run the wipe), the keys owned by the AEAD key objects of
aws-lc-rs and the hash state inside `hmac`/`blake2`, copies the compiler leaves on the stack,
and the cookie secrets of the rate limiter. The per-packet paths are unchanged.

Counters: `Tunn::stats` returns `usize`, so the fields keep their type and saturate, like the
peer counters of `nsplane-core` that read them.

## Validation

New tests: `initiation_with_a_low_order_ephemeral_is_rejected`,
`response_with_a_low_order_ephemeral_is_rejected`,
`peer_with_a_low_order_static_key_cannot_handshake`,
`peer_with_a_low_order_static_key_gets_no_handshake`,
`set_static_private_derives_the_public_key` and `byte_counters_saturate`; each failed before
its fix. The wiping has no test of its own.
