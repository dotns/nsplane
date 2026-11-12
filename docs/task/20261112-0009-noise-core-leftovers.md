# 20261112-0009-noise-core-leftovers Leftovers of the audit in the Noise state machine and the core

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 00:09

## Description

Six audit findings left over in `nsplane-noise` and `nsplane-core`, none of them a defect in
what a peer can observe:

1. A preshared key replaced through `Tunn::set_preshared_key`, the cookie received from a peer
   and the cookie secret of the rate limiter were not wiped.
2. Opening an encrypted handshake field allocated a `Vec`, and the key of a peer's cookie
   replies was hashed again for every reply.
3. `Tunn::stats` runs the loss estimate; the core called it for one counter.
4. `Core::peer_stats` collects a peer's allowed IPs; the driver's path MTU code called it to
   test that a peer exists or to read its path.
5. Removing a peer or replacing its allowed IPs scanned every network of its local identity,
   so removing N peers one by one was quadratic.
6. The core walks every peer on each timer tick (250 ms).

Acceptance: each item is fixed or measured and left with the reason, the public API only
grows, performance items carry before and after numbers, and the gates of the touched crates
pass.

## ActiveForm

Wiping the remaining key material and removing per-query and per-peer scans in the core.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Preshared key: `Tunn::set_preshared_key` is a `pub const fn`, and a `const fn` can neither run
a wipe nor drop a `Zeroizing` value. The handshake now stores the key as a plain 32-byte
array, all zero without a key (the value such a handshake mixes in anyway), so the assignment
writes the new key, or the zeros, over the old one in place. The signature is unchanged. The
`Debug` output still shows only whether a key is set; an all-zero key now prints as none,
which is what it is in the protocol. Not covered: the copy of the preshared key that the
core's `Peer` keeps to report it in `PeerStats`, and the by-value argument on the stack.

Cookies: the cookie of a cookie reply is decrypted in place in a `Zeroizing` buffer (it was a
`Vec` returned by the AEAD, never wiped) and wiped when it is replaced, cleared or dropped;
the crate-private `Handshake::clear_cookie` lost its `const`. The cookie secret of the
`RateLimiter` is `Zeroizing`. The nonce key of the rate limiter only spaces out nonces and
stays a plain array.

Handshake allocations: `aead_chacha20_open` copies the field into a 48-byte stack buffer, the
size of the largest field (the static key and its tag); a longer input fails like a bad tag.
The key of the cookie replies a peer sends, `HASH("cookie--" || peer public key)`, is computed
once in `NoiseParams::new` like the mac1 key next to it. The mac1 and cookie keys of the
receiving side were already cached in the `RateLimiter`.

Counters: `Tunn::tx_bytes` and `Tunn::last_handshake_rtt` (new, additive) return one field of
`Tunn::stats` each. `Peer::data_tx` and the handshake completion in `core/receive.rs` use them.
Neither call site is on the per-packet path: `data_tx` runs per `Core::peer_stats` /
`all_peer_stats` entry and per `Event::PeerStats`, the round-trip time per completed handshake.

Peer path: `Core::peer_path` (new, additive) returns the stored path, `None` for an unknown
peer. `Engine::peer_mtu` uses it as the existence test and the path MTU table's `stored_path`
reads the path through it; the latter runs for every peer on each path MTU report.

Allowed IPs: a table made by `AllowedIps::indexed` keeps, per address family, the networks of
each value next to the networks themselves, updated by `insert` (also when a network moves to
another value), `remove_network`, `remove` and `clear`. `remove_value` and `iter_value` visit
those networks only, in the order of the scan they replace. The tables of the local identities
are indexed; the merged table, the source sets and the inbound destination sets are not (few
values with many networks, or no removal by value). `PeerTable::remove_allowed_ips` and
`PeerTable::allowed_ips` use the index, so a single `Core::peer_stats` no longer scans either.

The index holds one network per value in place and switches to a set from the second network
of a family. The first version used a set for every value and slowed the timer tick by 1.5 to
2 times in the measurement below (20 000 idle peers: 0.55 ms to 1.2 ms): the set's allocation
landed between the boxed tunnels of peers added in a row, and the tick, which reads a few
cache lines of every tunnel, depends on how the tunnels lie in the heap. With the network in
place the tick is unchanged. Memory: one hash map entry per peer and family in use (64
bytes before the spare capacity of the map), plus a B-tree set for a peer with several networks
in a family.

Removal order: what is left of removing peers one by one is `Vec::remove` on the peer vectors,
which are kept in id order: removing the oldest peer shifts all others. `replace_peers` of the
UAPI with several local identities removes the default identity's peers one by one and now
does it from the newest down. With one identity it already used `RemoveAllPeers`. Not done: a
batched removal in the core. `ConfigChange` is not `#[non_exhaustive]`, so it would be a new
method on `Core` and `EngineHandle` with its own command; a caller that removes many peers in
ascending id order still pays the shift (0.42 s for 20 000 peers, below).

Timers: not changed. One tick over idle peers costs about 0.5 to 0.7 ms at 20 000 peers on a
quiet core (0.2 to 0.3 % of the owner task at one tick per 250 ms; up to 1.3 ms in runs on the
loaded host) and 9 to 14 ms at 100 000 (4 to 5 %). That is below the bar set for this item
(1 ms at 20 000), and a deadline structure is not a small change here:

- The tunnel's clock only advances in `Tunn::update_timers_at`: it stores `now` as the
  current time, and every event until the next call (data sent or received, a handshake) is
  timed at that value. A tunnel that is skipped while nothing is due would time its events
  at a stale instant, so the tunnel would first need the time passed into every call that
  records one, on the data path and in the crypto jobs.
- Every data message moves a deadline (keepalive after receive, handshake after unanswered
  send, persistent keepalive after silence), so the data path would re-arm an entry per
  packet or the structure would hold lower bounds that are re-checked when they fire.
- `REKEY_AFTER_MESSAGES` is a counter condition without a deadline, and the rate limiter
  reset and the expiry bookkeeping of the core (`Peer::expired`, the handshake counts taken
  on each tick) ride on the same walk.

What it would look like: `Tunn` reports after each call the earliest instant at which
`update_timers_at` could return something other than `Done` (the minimum over the armed
timers, with the counter condition mapped to "next tick"); the core keeps that instant per
peer in a min-heap or a wheel of 250 ms slots keyed by peer slot, re-arms it from the data
path when a message moves it earlier, and on a tick visits only the due peers. The existing
tests in `crates/nsplane-core/tests/timers.rs` drive the timers through `handle_timeout` with
a simulated clock and would hold the visible behavior, but they do not pin the timestamps of
events between ticks, which is where such a change goes wrong. A smaller step with most of
the gain at 100 000 peers would be to keep that earliest instant in the `Peer` struct, which
is contiguous, and skip the tunnel (one or more cache misses each) until it is due; it needs
the same decoupling of the tunnel's clock first.

## Validation

Tests. `noise::tests::single_counters_match_the_stats` and
`config::peer_path_is_the_stored_path` were written first and failed to compile without the
new methods. `allowed_ips::tests::matches_the_trie_on_random_tables` now runs half of its
rounds on an indexed table, removes by value through `remove_value` as well as by predicate,
and after every step compares `iter_value` with the reference trie and the index of both
families with a scan of the networks (exact equality: no stale and no empty entries). It
failed to compile before the index existed; with the index in place it fails when a replaced
value keeps its old entry and when a removed network stays in the index (both checked by
breaking the code and restoring it). `open_takes_the_static_key_field_and_nothing_longer`
covers the bound of the stack buffer. The wiping has no test of its own: the old key is no
longer a separate value that a test could look for.

Measurements. Temporary `#[ignore]`d tests, not kept: `nsplane-noise` (a loop over the
handshake steps in `handshake.rs`) and `nsplane-core` (`tests/zz_measure.rs`), release
profile, built once for the base `1f0a4f4` (A) and once for this branch (B) and run
interleaved A, B, A, B inside one `scripts/bench/slot.sh` invocation per table (slot 0, CPUs
1-7, the container pinned with `--cpuset-cpus`). The host was loaded throughout (load
average 6 to 18), so differences of a few percent are noise; both runs are given.

Handshake, per call (3 rounds of 20 000 handshakes per run; range over the rounds):

| step | A | B |
| --- | ---: | ---: |
| open the static key and timestamp fields (2 000 000 pairs) | 389-411 ns | 383-402 ns |
| initiation: anonymous parse (`parse_handshake_anon`) | 32.0-41.2 us | 32.1-48.8 us |
| initiation: receive and format the response | 109-140 us | 109-165 us |
| response: receive | 64.5-83.1 us | 65.6-99.4 us |
| cookie reply: receive (1 000 000 per round) | 1.06-2.05 us | 0.96-1.69 us |
| `Tunn::stats().1` against `Tunn::tx_bytes()` | 23.4 ns | 0.2-0.6 ns |

The two allocations are worth about 10 ns of a 110 us initiation, which three X25519
operations dominate: no measurable change per handshake. The cookie reply is about 0.1 us
(9 %) cheaper.

Peer table, N peers of the default identity with one /32 each and every 1000th with 8 more
/24 and 8 /64 (20 320 networks at 20 000 peers), best of 3 inside each run; run 1 / run 2:

| operation | A | B |
| --- | ---: | ---: |
| remove 5 000 peers one by one, newest first | 13.8 / 13.5 ms | 4.6 / 3.5 ms |
| remove 20 000 peers one by one, newest first | 206 / 201 ms | 22.5 / 19.9 ms |
| remove 5 000 peers one by one, oldest first | 40.5 / 40.2 ms | 26.4 / 25.8 ms |
| remove 20 000 peers one by one, oldest first | 712 / 710 ms | 425 / 420 ms |
| replace the allowed IPs of each of 20 000 peers | 458 / 477 ms | 16.4 / 16.4 ms |
| `Core::peer_stats` of each of 20 000 peers | 380 / 410 ms | 3.0 / 3.9 ms |

Newest first is linear now (4 times the peers: 5 times the time). Oldest first keeps the
quadratic shift of the peer vectors, about 21 us per removal at 20 000 peers.

Timer tick over idle peers (no session, no keepalive), 40 ticks 250 ms apart per size,
min / median; run 1, run 2:

| peers | A | B |
| ---: | ---: | ---: |
| 1 000 | 14.3 / 17.1 us, 16.0 / 16.5 us | 17.0 / 18.4 us, 16.6 / 17.0 us |
| 20 000 | 0.47 / 0.62 ms, 0.92 / 1.29 ms | 0.57 / 0.74 ms, 0.90 / 1.08 ms |
| 100 000 | 12.4 / 13.6 ms, 11.6 / 12.0 ms | 12.6 / 13.9 ms, 12.5 / 13.2 ms |

Outside the slot, on a quieter moment, both sides gave 0.46-0.50 ms min at 20 000 and
8.9-11.1 ms at 100 000. That is 25 ns per peer at 20 000 and about 100 ns at 100 000, where
the tunnels no longer fit the caches.

Gates, in the dev container, for `nsplane-noise`, `nsplane-core`, `nsplane` and `nsplane-uapi`:
`cargo fmt --all --check`; `cargo hack clippy --each-feature --all-targets --locked`;
`cargo nextest run --all-features --locked` with `nsplane-e2e` added (992 passed, 23 skipped);
the doc tests; `cargo deny check`; `cargo shear`; `typos`; `scripts/check-docs.sh` (the
allowlist entry for the removed `TODO: pre-compute` comment went with it);
`scripts/check-product-terms.sh`; `cargo-zigbuild clippy --all-targets --all-features --target
aarch64-apple-darwin`; `cargo hack clippy --each-feature --all-targets --target
x86_64-pc-windows-gnu` for `nsplane-noise`, `nsplane` and `nsplane-uapi`. All pass.

`noise::rate_limiter::tests::a_cookie_holder_gets_tokens_back_over_time`, which reads the real
clock, failed once in a parallel run on the loaded host and passed in every other run (6 runs
alone, 2 full runs); it predates this work and none of it touches the token buckets.
