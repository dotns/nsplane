# Peer-level connection expiry signal

Design note. Status: decided by the owner on 2026-10-28 (O1-O5 as recommended, see
[Owner decisions](#owner-decisions-2026-10-28)); implemented on `feat/0.21.0-m3-removals` for
0.21.0. Plan:
[20261027-0433-post-freeze-schedule](../20261027-0433-post-freeze-schedule.md) (M3); task:
[20261027-0433-peer-expiry-signal](../../task/20261027-0433-peer-expiry-signal.md). Ships in
0.21.0 with release C. All code references are at `main` right after v0.20.0 (the commit that
added the post-freeze schedule).

## Starting point: the event exists

The task assumes a consumer learns about an expired peer only by polling handshake ages. That
is not the case: `Event::SessionExpired { peer }` (`crates/nsplane-core/src/types.rs`) has
existed since the core's first version and is emitted on the `CONNECTION_EXPIRED` paths.

- `nsplane-noise` `Tunn::check_expiry` (`noise/timers.rs`) expires the whole tunnel, i.e.
  the peer, on two paths. Both log `CONNECTION_EXPIRED(..)` at debug, call
  `handshake.set_expired()` and `clear_all()` (every session slot, the queued packets, the
  timers) and return `Err(ConnectionExpired)`:
  1. `REJECT_AFTER_TIME * 3` (540 s) since `TimeSessionEstablished`: no new keys for that
     long.
  2. `REKEY_ATTEMPT_TIME` (90 s) since `TimeLastHandshakeStarted` while an initiation is
     outstanding: the retries give up.
  While the handshake stays `Expired`, every later `update_timers_at` returns
  `Err(ConnectionExpired)` from the early check. The next handshake initiation (data to
  send, `force_handshake`) leaves that state.
- `nsplane-core` `Core::handle_timeout` (`core/timers.rs`) turns the first
  `Err(ConnectionExpired)` into `Event::SessionExpired { peer }`, guarded by
  `Peer::expired`. A tick that returns `Done` or a datagram, or a completed handshake,
  clears the guard, so the event fires once per expiry episode
  (`tests/timers.rs` `handshake_gives_up_after_rekey_attempt_time`,
  `session_expires_after_reject_after_time_x3`; `nsplane-e2e` `timers.rs`, `suspend.rs`).
- The engine publishes it unchanged on the broadcast channel (`engine/output.rs`
  `Owner::event` only looks at `PathAdopted` and `Dropped`), and the guide shows it as the
  "down" signal (`docs/guide.md` section 14).

Not signalled, and staying that way:

- `SESSION_EXPIRED(REJECT_AFTER_TIME)` in `update_session_timers` drops one session slot
  after 180 s. That is routine key rotation: the peer still has, or is about to get, a
  current session. It is per session, not per peer.
- `ConnectionExpired` from `Session::receive_packet_data` / `format_packet_data` and from a
  `CryptoJob` sealed with a replaced key is a per-packet decrypt or seal failure, counted as
  a drop (`reasons::DECRYPT` and the job outcome), not a state change of the peer.

So the actual gaps are:

1. **Loss.** Events are best effort: a subscriber that falls more than `event_capacity`
   behind gets `RecvError::Lagged` and loses them. A missed `SessionExpired` cannot be
   recovered. `last_handshake` and `peer_has_session` show the current state, not that an
   expiry happened, and `unanswered_handshakes` covers only the give-up path.
2. **No cause.** The two paths mean different things. Path 2 means the peer does not
   answer. Path 1 means nobody needed the tunnel for 9 minutes. A consumer that treats
   `SessionExpired` as "peer down" (as the guide does) reads an idle peer as down.
3. **A peer that was never up goes down.** Path 1 measures from the timer origin when no
   session was ever established. A peer that is added and never contacted emits
   `SessionExpired` 540 s after its first timer tick. Checked on that commit with a scratch
   core test (two cores, no traffic): no event at 539 s, `SessionExpired { peer }` at 541 s,
   `peer_has_session` false, nothing more by 1141 s.

## Decisions proposed

### D1: keep `Event::SessionExpired` as the signal and add its cause

The signal is per peer (one `Tunn` per peer) and fires on the two timer paths above, once per
episode, as today. The variant gains one field:

```rust
/// The tunnel with `peer` expired: its sessions and queued packets were discarded and the
/// next packet to the peer starts a new handshake.
///
/// Emitted by the timers once per expiry: again only after the peer sent a handshake
/// initiation or completed a handshake since. An expiry for [`ExpiryCause::SessionAge`] is
/// emitted only if a handshake completed (an [`Event::HandshakeCompleted`] was emitted)
/// since the peer was added or since its previous `SessionExpired`. Counted in
/// [`PeerStats::expirations`].
SessionExpired {
    /// The peer.
    peer: PeerId,
    /// Why the tunnel expired.
    cause: ExpiryCause,
},
```

```rust
/// Why a peer's tunnel expired ([`Event::SessionExpired`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExpiryCause {
    /// No handshake completed for `REJECT_AFTER_TIME * 3` (540 s): the keys were too old to
    /// keep, typically because no traffic needed a rekey. Not a sign that the peer is
    /// unreachable.
    SessionAge,
    /// Handshake initiations got no response for `REKEY_ATTEMPT_TIME` (90 s): the peer did
    /// not answer and the retries gave up.
    HandshakeTimeout,
}
```

- Defined in `nsplane-noise` as `noise::ExpiryCause`, so the tunnel can report it. It is
  re-exported as `nsplane_core::ExpiryCause` (the core already re-exports `noise`) and
  `nsplane::ExpiryCause`. That is one type, not a mapping.
- `nsplane-noise` additions: `Timers` records the cause where `check_expiry` calls
  `set_expired`; `Tunn::expiry_cause(&self) -> Option<ExpiryCause>` returns it while
  `is_expired()` and `None` otherwise. `format_handshake_initiation`, which already calls
  `timers.clear()` when expired, clears it. The protocol state machine does not change.
- The name stays `SessionExpired`. Renaming it to `ConnectionExpired` would break every
  consumer arm for a cosmetic gain. The rustdoc says "tunnel" and the cause carries the
  meaning.

### D2: no `SessionAge` expiry for a peer that was never up (behaviour change)

The core emits, and counts, an expiry for `SessionAge` only if it reported a completed
handshake for the peer since the peer was added or since its previous reported expiry.
`HandshakeTimeout` is always emitted, also for a peer that was never up: it is the "does not
answer" signal. The result for consumers: a "down for being idle" always follows an "up".

- Implementation: `Peer` gets `up: bool`, set where the core reports `completed > 0`
  (`Core::authenticated`, `handle_timeout`) and cleared when it emits `SessionExpired`. On
  `Err(ConnectionExpired)` with `expiry_cause() == Some(SessionAge)` and `!up`, the core
  sets `Peer::expired` (so the episode guard still works) and emits nothing.
- The tunnel still expires as today. Only the report changes.
- A responder session that the initiator never confirmed was never reported as completed,
  so its age expiry is not reported either. That matches the `HandshakeCompleted` contract.

### D3: a loss-proof counter

`PeerStats` gains:

```rust
/// Expiries of the peer's tunnel the core reported as [`Event::SessionExpired`], any cause;
/// monotonic since the peer was added.
pub expirations: u64,
```

The periodic `Event::PeerStats` variant gains the same field, `expirations: u64`, after
`data_tx`. A subscriber that lagged learns from the next periodic event, without a command,
that an expiry happened. `EngineHandle::peer_stats` / `peers` carry it through
`Core::peer_stats`.

- Semantics: incremented exactly when `SessionExpired` is pushed, so the counter equals the
  number of `SessionExpired` events for the peer (D2's suppressed expiries count in
  neither). It is a plain `u64` field of `Peer` next to `expired` (single owner, no atomic).
  Removing a peer drops it. A peer added again starts at 0, like `rx` / `tx`.
- No per-cause split (see O2). For "does not answer", `unanswered_handshakes` already counts
  the given-up initiation.
- WireGuard UAPI (`nsplane-uapi`) has no key for it and does not report it.

### D4: ordering against existing events

Everything is emitted from `Core::handle_timeout`, in output-queue order, which the engine
publishes FIFO:

1. Per peer, in peer-table order: `HandshakeCompleted` for handshakes the tick noticed, then
   that peer's timer result (`SessionExpired`, or a transmit). A tick that completes a
   handshake does not also expire the tunnel: completion resets `TimeSessionEstablished`
   and leaves the `InitSent` state.
2. After all peers: the periodic `Event::PeerStats` of that tick. A `PeerStats` event or
   snapshot taken after a `SessionExpired` already counts it (`expirations` includes it).
   This is the invariant consumers can rely on.
3. Suspended engines run no timers. On resume, `Event::Resumed` is published first, then the
   timers run once and any expiry follows (`suspend.rs`
   `a_session_that_expired_while_suspended_rehandshakes_on_resume`).
4. Packets queued in the tunnel for the handshake are discarded silently on expiry, as
   today (no `Dropped` events). Unchanged here (see O5).

### D5: data-path cost: none

- The cause is written once per expiry in the timer path. The core reads it only in the
  `Err(ConnectionExpired)` arm of `handle_timeout` when the guard is not set.
- `Peer` grows by one `u64` and one `bool`. Both go in the cold fields next to `expired` and
  `unanswered_handshakes`, which the data path does not touch. Check: one `slot.sh` A/B of
  `core_pair` / `local_graph` with the implementation, to show no change beyond noise.
- Sizes on that commit (x86_64, scratch test): `Event` 64 bytes, `Output` 96 bytes,
  `Path` 36 bytes, `PacketBuf` 56 bytes, `PeerStats` 192 bytes. `SessionExpired` gains one
  byte and stays far below the largest variant. The `Event::PeerStats` variant grows from
  52 to 60 bytes of fields, so `Event` stays at 64 bytes or grows to 72. Either way,
  `Output` stays at 96 bytes, because `Output::Transmit` (`Path` plus `PacketBuf`, 92 bytes)
  is the largest variant. The per-packet output queue therefore does not change. Pin this
  with a `size_of::<Output>()` assertion in the core's unit tests. `PeerStats` grows by
  8 bytes, but it is a snapshot type.

### D6: `#[non_exhaustive]` on `Event` and `PeerStats`

**Enum-level on `Event` only, not per variant.** Enum-level `#[non_exhaustive]` makes later
variants additive. Other crates keep constructing and fully destructuring existing variants.
This matters because `nsplane` constructs `Event::Dropped`, `Suspended`, `Resumed` and
`MtuChanged` (`engine/output.rs`, `engine/command.rs`, `engine/run.rs`), and tests compare
whole events. Adding a field to an existing variant stays breaking (see O3).

**`PeerStats` struct-level, with a constructor.** Other crates can no longer use a struct
expression or functional update (`..base`) on `PeerStats`. Since it has no `Default` (it
holds a public key), add:

```rust
impl PeerStats {
    /// A snapshot of `peer` with key `public_key` and nothing else: default identity, no
    /// path, no allowed IPs, no preshared key, no keepalive, zero counters, no handshake.
    /// For tests and consumers that build snapshots; assign the other fields.
    pub fn new(peer: PeerId, public_key: x25519::PublicKey) -> Self;
}
```

Sites in this workspace that change (inside `nsplane-core`'s `src/` the attribute has no
effect):

| Site | Today | Change |
| --- | --- | --- |
| `examples/src/bin/events_stats.rs` `describe` | exhaustive `match` on `Event`, destructures `SessionExpired { peer }` and every `PeerStats` field | wildcard arm; `SessionExpired { peer, cause }` prints the cause; `PeerStats` prints `expirations` |
| `crates/nsplane-uapi/src/uapi.rs` test `config_reports_the_handshake_as_unix_time` | struct expression | `PeerStats::new` plus field assignments |
| `crates/nsplane-core/tests/batch.rs`, `tunnel_storage.rs` | `PeerStats { public_key, ..core.peer_stats(..) }` | take the snapshot, assign `public_key` |
| `crates/nsplane-e2e/tests/uapi.rs` `settings` | `PeerStats { rx: 0, .., ..p }` | assign the zeroed fields; also `expirations = 0` |
| `crates/nsplane-core/tests/timers.rs` | `[Event::SessionExpired { peer }]` | `{ peer, cause: ExpiryCause::.. }` |
| `crates/nsplane-e2e/tests/timers.rs`, `suspend.rs` | `matches!(.., SessionExpired { peer: p } ..)` | add `..` or assert the cause |
| `crates/nsplane-core/tests/counters.rs`, `config.rs`; `nsplane-e2e` `counters.rs`, `events.rs`, `timers.rs` | `Event::PeerStats { .. }` patterns | those without `..` gain `expirations` or `..` |
| `docs/guide.md`, `docs/guide.zh-CN.md` section 14 | `SessionExpired { peer, .. }` as "down" | compiles unchanged; text: "down" is `cause: HandshakeTimeout`, and `expirations` is for consumers that may lag |

Every other `Event` use in the workspace is `matches!` / `if let` / `==` and compiles
unchanged. Reading fields and comparing values are unchanged.

## CHANGELOG text (0.21.0)

Under `### Added`:

```markdown
- `Event::SessionExpired` carries `cause: ExpiryCause` (`SessionAge`: no handshake for
  540 s; `HandshakeTimeout`: initiations unanswered for 90 s), also as
  `nsplane_noise::noise::ExpiryCause` and `Tunn::expiry_cause`. `PeerStats::expirations`
  and the `expirations` field of `Event::PeerStats` count the reported expiries per peer, so
  a subscriber that lagged still learns about them. `PeerStats::new` builds a snapshot.
```

Under `#### Breaking`:

````markdown
- nsplane-core `Event` and `PeerStats` are `#[non_exhaustive]`, so later variants and fields
  are not breaking again (re-exported by `nsplane`). A `match` on `Event` needs a wildcard
  arm. Other crates can no longer build `PeerStats` with a struct expression, also not with
  `..base`: start from `PeerStats::new(peer, public_key)` or a snapshot and assign the
  fields. Constructing and matching existing `Event` variants, reading fields and comparing
  values are unchanged. In the same release, `Event::SessionExpired` gains `cause` and
  `Event::PeerStats` gains `expirations`, so patterns that name every field need the new
  field or `..`.

  ```rust
  // Before
  match event {
      Event::SessionExpired { peer } => mark_down(peer),
      Event::PeerStats { peer, rx, tx, data_rx, data_tx, last_handshake } => {
          record(peer, rx, tx, data_rx, data_tx, last_handshake)
      }
      Event::HandshakeCompleted { peer, .. } => mark_up(peer),
      Event::Authenticated { .. }
      | Event::PathAdopted { .. }
      | Event::Dropped { .. }
      | Event::Suspended
      | Event::Resumed
      | Event::MtuChanged { .. } => {}
  }
  let zeroed = PeerStats { rx: 0, tx: 0, ..snapshot };
  // After
  match event {
      Event::SessionExpired { peer, cause: ExpiryCause::HandshakeTimeout } => mark_down(peer),
      Event::SessionExpired { peer, .. } => mark_idle(peer),
      Event::PeerStats { peer, rx, tx, data_rx, data_tx, last_handshake, .. } => {
          record(peer, rx, tx, data_rx, data_tx, last_handshake)
      }
      Event::HandshakeCompleted { peer, .. } => mark_up(peer),
      _ => {}
  }
  let mut zeroed = snapshot;
  zeroed.rx = 0;
  zeroed.tx = 0;
  ```
````

Under `#### Other` (behaviour change, D2):

```markdown
- nsplane-core: a peer that never completed a handshake (or none since its last expiry) no
  longer reports `Event::SessionExpired` when its idle timer runs out (540 s after it was
  added); its tunnel still expires. Handshakes that go unanswered are still reported
  (`ExpiryCause::HandshakeTimeout`).
```

## Tests to add (implementation, test first)

`nsplane-noise` (unit, `noise/tests`):

- `expiry_cause` is `None` on a fresh tunnel and after a completed handshake.
- An unanswered initiation reports `HandshakeTimeout` after `REKEY_ATTEMPT_TIME`. A
  session left alone reports `SessionAge` after `REJECT_AFTER_TIME * 3`.
- A handshake initiation after the expiry clears it back to `None`.

`nsplane-core` (`tests/timers.rs`, fake clock):

- The two existing expiry tests assert the cause.
- A never-contacted peer reports nothing at 541 s and 1141 s; `expirations == 0` (D2,
  fails today).
- A never-contacted peer whose initiations go unanswered reports `HandshakeTimeout` and
  `expirations == 1`.
- `expirations` equals the number of `SessionExpired` events over two episodes (one per
  cause) and is unchanged by a completed handshake.
- With `stats_interval` set, the `Event::PeerStats` of the tick that expired the peer comes
  after the `SessionExpired` and carries the incremented `expirations` (D4.2).
- Unit: `size_of::<Output>()` is unchanged (D5).

`nsplane-e2e`:

- `timers.rs`: an engine with `event_capacity(1)` whose subscriber lags past the expiry
  reads `peer_stats(peer).expirations == 1` (gap 1).
- `timers.rs` / `suspend.rs`: assert the cause on the existing expiry checks.
- `uapi.rs`: the existing settings comparison with `expirations` zeroed.

Plus the compile changes of D6. The gate (`just check`, `cargo doc -D warnings`,
`just cross`, `just test-windows`) and one `slot.sh` A/B for D5.

## Open questions for the owner

- **O1 (D2).** Suppress the `SessionAge` expiry of a peer that was never up (recommended),
  or report it, documented as a "never up" case? Suppressing is a behaviour change.
  Reporting keeps today's behaviour but leaves "down without up" in the event stream.
- **O2 (D3).** One `expirations` counter (recommended) or one per cause
  (`expired_idle`, `expired_unreachable`)? Per-cause counters would let a lagging consumer
  tell idle from unreachable without the event. Today `unanswered_handshakes` growing
  already signals the latter.
- **O3 (D6).** Enum-level `#[non_exhaustive]` only (recommended)? The alternative also marks
  the core-emitted struct variants (`HandshakeCompleted`, `Authenticated`, `PathAdopted`,
  `SessionExpired`, `PeerStats`) `#[non_exhaustive]`, so later fields on them are additive.
  The cost: other crates can no longer construct those variants, which breaks consumer
  tests that build events to feed their handlers, and every pattern needs `..`.
  `Dropped`, `Suspended`, `Resumed` and `MtuChanged` cannot take it, because `nsplane`
  constructs them.
- **O4 (D6).** Add `PeerStats::new` (recommended)? Without it, other crates cannot build a
  `PeerStats` at all, and `nsplane-uapi`'s unit test would have to drive a `Core`.
- **O5.** Out of scope here, but observed while reading the code:
  (a) packets queued for a handshake are discarded silently on expiry, without `Dropped`;
  (b) path 1 can abort a handshake that started just before the 540 s mark, because the
  timer measures from the last established session (or the origin), not from the attempt.
  Should either become a task?

## Owner decisions (2026-10-28)

Answered together with the decision to ship 0.21.0 as release C plus M3 and the removal of the
deprecated `WsFrame` stream carrier and `TransparentConfig::admission`:

- **O1**: suppress the `SessionAge` expiry of a peer that was never up (D2, behaviour change).
- **O2**: one `expirations` counter (D3), no per-cause split.
- **O3**: enum-level `#[non_exhaustive]` only, on `Event` and `PeerStats` (D6); no
  per-variant attribute.
- **O4**: add `PeerStats::new`.
- **O5**: both observations become follow-up tasks after 0.21.0, not part of this release:
  [20261028-0611-expiry-queued-packets-dropped](../../task/20261028-0611-expiry-queued-packets-dropped.md)
  and
  [20261028-0611-session-age-aborts-fresh-handshake](../../task/20261028-0611-session-age-aborts-fresh-handshake.md).

Implementation notes against this design:

- A `ConnectionExpired` that the timers return while the tunnel is not expired (a keepalive
  that could not be sealed, possible only at Reject-After-Messages) is not an expiry: the core
  neither reports nor counts it and treats it like the other timer errors. Before, it would
  have been reported as `SessionExpired`.
- The `Peer` bookkeeping is one method, `Peer::tunnel_expired(cause) -> bool`, called on every
  expired tick. Instead of D2's `up: bool`, `Peer` keeps `handshakes_at_expiry`, the count of
  reported handshakes at the last reported expiry (or when the peer was added): the peer is up
  while its reported count is above it. Same semantics, no store in `Core::authenticated`
  (`core/receive.rs` is unchanged) and no fifth `bool` in `Peer`.
- D5: `size_of::<Output>()` stays 96 and `size_of::<Event>()` 64 bytes (both measured on
  `bcb68f1` before the change and pinned by a core unit test); `PeerStats` grows from 192 to
  200 bytes, the core's `Peer` from 224 to 240, `Tunn` stays 9952 (the cause fits in padding).
  Two interleaved `data_path` A/B invocations against `bcb68f1` are within the noise (table in
  `docs/performance.md`, "Peer expiry signal").
