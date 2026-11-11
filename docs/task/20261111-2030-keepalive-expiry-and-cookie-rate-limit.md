# 20261111-2030-keepalive-expiry-and-cookie-rate-limit Persistent keepalive ends at the expiry; cookie holders are not rate limited

- **status**: completed
- **priority**: P1
- **owner**: audit-fix
- **createdAt**: 2026-11-11 20:30

## Description

Two defects from an audit of `nsplane-noise`.

1. (P1) With a persistent keepalive and a peer that never answers, the timers send handshake
   initiations for `REKEY_ATTEMPT_TIME` (90 s), expire the tunnel and then stay silent for
   good: `update_timers_at` returned `ConnectionExpired` before the persistent keepalive
   was looked at. Kernel WireGuard and wireguard-go start a new handshake attempt on every
   keepalive interval while there is no session.
2. (P2) Under load, a handshake whose mac2 verified was accepted without any further limit,
   so one real source address that obtained a cookie could send unlimited initiations, each
   costing a DH in the core. Kernel WireGuard holds such a source to a token bucket of 20
   handshakes per second with a burst of 5.

Acceptance: with a persistent keepalive, an expired tunnel starts a new handshake attempt
(normal retries and `REKEY_ATTEMPT_TIME` limit) one interval after each expiry, indefinitely,
every expiry is still reported, and nothing is resent per tick; without one nothing changes.
After a valid mac2 under load a bounded per-source token bucket (IPv4 address, IPv6 /64)
drops the excess. No public API change.

## ActiveForm

Restarting handshakes from the persistent keepalive after an expiry and rate limiting cookie
holders.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Timers: `update_timers_at` starts a handshake initiation when the tunnel was already expired
on entry and the persistent keepalive is due. The expiry clears the timers to its own time,
so the keepalive is due one interval after the expiry (kernel WireGuard counts from the last
initiation sent, a few seconds earlier). The tick that expires the tunnel always returns
`ConnectionExpired`, so `Core::handle_timeout` reports each attempt's expiry as
`Event::SessionExpired`; `PeerStats::expirations` therefore grows by one per cycle (115 s
with a 25 s interval) for an unreachable peer with a keepalive.

Rate limiter: the buckets live in the shared `HandshakeBudget`, so the rate holds across the
local keys sharing it. Tokens are counted in time (50 ms per handshake, at most 250 ms). The
table reuses `MAX_TRACKED_SOURCES` (4096); buckets untouched for 250 ms are full and are
removed, at most once per 250 ms; a new source that finds the table full is refused. The map
hashes with the keyed SipHash of `RandomState`. The buckets run on the crate clock, like the
cookie secret rotation, because `verify_packet` takes no time argument: a core driven by a
simulated clock still refills them in real time. The excess fails with
`WireGuardError::UnderLoad`, which the core drops as `reasons::INVALID_HANDSHAKE`.

## Validation

Red before the fixes: `noise::tests::persistent_keepalive_starts_a_new_handshake_cycle_after_each_expiry`
(1 expiry in 1200 s instead of 10), `noise::rate_limiter::tests::a_cookie_holder_is_limited_to_its_burst_under_load`
(100 of 100 passed in 5.8 ms) and `a_cookie_holder_gets_tokens_back_over_time` (100 of 100
passed with the bucket empty). Green after, with
`without_persistent_keepalive_an_expired_tunnel_stays_silent`, the bucket tests on an
injected clock (`cookie_holder_bucket_is_a_burst_of_5_refilled_at_20_per_second`,
`cookie_holders_are_keyed_by_ipv6_prefix_64`, `cookie_holder_table_is_bounded_and_swept`) and
the core test `timers::persistent_keepalive_starts_a_new_attempt_after_the_handshake_gave_up`.
No existing test changed.

`cargo fmt --all --check`, `cargo hack clippy -p nsplane-noise -p nsplane-core --each-feature
--all-targets --locked`, `typos` and `scripts/check-docs.sh` pass;
`cargo nextest run -p nsplane-noise -p nsplane-core -p nsplane --all-features --locked`:
560 passed, 4 skipped.
