# 20261111-2034-cli-uapi-hardening Hardening defects in the CLI and the UAPI server

- **status**: completed
- **priority**: P2
- **owner**: audit-fix
- **createdAt**: 2026-11-11 20:34

## Description

Five defects from an audit of `nsplane-cli` and `nsplane-uapi`:

1. `drop_privileges` switched the group and user IDs but kept the supplementary groups, so a
   daemon started through `sudo` stayed a member of root's groups.
2. `--threads 0` made the tokio runtime builder panic.
3. `Uapi::serve` retried a failed accept at once: a persistent error such as `EMFILE` spun
   the task and flooded the log.
4. `read_line` read a request line into a `String` without a limit, so a client that never
   sent a newline grew the buffer for as long as it kept sending.
5. A `set=1` request held the network state lock while waiting for its remaining lines, so
   one stalled client blocked every other `get=1` and `set=1`.

Acceptance: each defect fixed with a test where one is feasible, the gates of both crates
pass, no new dependency.

## ActiveForm

Fixing the audited hardening defects of the CLI and the UAPI server.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

1. A root process calls `setgroups` with the target group alone before `setgid`. A process
   that is not root skips the call, which would fail with `EPERM`, and keeps the groups it
   was started with. macOS gap: `nix` has no `setgroups` on Apple targets, so the call is
   compiled out there and the supplementary groups are kept.
2. `threads` is a `NonZeroUsize`; clap rejects 0 with a usage error. `--crypto-workers 0`
   stays valid: 0 and 1 both mean the engine task does the cryptography itself.
3. `serve` waits 100 ms after a failed accept and returns at once when the engine stops
   during the wait. `nsplane-uapi` enables the `time` feature of tokio for it.
4. A line is at most 4096 bytes. A longer one is an `InvalidData` read error: the
   connection is closed without a response, except inside the settings of a `set=1`, where
   read errors were and are answered with `errno=5` before the connection is closed.
5. The settings of a `set=1` are read up to the empty line, then applied under the lock by
   the unchanged loop: same order, same error codes, settings before a failing one stay
   applied, each peer section starts fresh. Buffering the raw lines keeps `set` requests
   atomic towards each other; applying section by section with the lock taken per section
   would let two requests interleave. The buffer is capped at 16 MiB of settings, room for
   some 40 000 peers of about 400 bytes each; more is answered with `errno=5`.

   Two differences remain. A request with a bad line is answered once the request is
   complete (empty line or end of input), no longer as soon as the bad line arrives. A read
   error in the middle of a request now leaves nothing applied, where the lines before it
   used to be.

## Validation

1. Manual, in a container running as root with supplementary groups 4 and 27, a TUN device
   and `SUDO_UID=1000 SUDO_GID=1000`: `/proc/<pid>/status` of the running daemon showed
   `Groups: 0 4 27` before the fix and `Groups: 1000` after it, with `Uid` and `Gid` 1000 in
   both. Started as uid 1000 with `CAP_NET_ADMIN` and no `SUDO_*`, the daemon still starts
   and keeps its groups. No unit test: it would need root and a forked process.
2. `tests::zero_threads_is_rejected` (failed before the fix).
3. `listener::tests::failed_accepts_are_retried_after_a_pause`: 212864 warnings in 350 ms
   before the fix, at most 10 allowed after it; the same test stops the engine and expects
   `serve` to return.
4. `uapi::tests::an_overlong_line_fails_the_request` (failed before the fix).
5. `uapi::tests::a_stalled_set_does_not_block_other_requests` (timed out before the fix),
   `an_oversized_set_fails_before_it_is_applied` and
   `settings_before_a_failing_one_stay_applied`.

Gates for `nsplane-cli` and `nsplane-uapi`: `cargo fmt --all --check`, `cargo hack clippy
--each-feature --all-targets --locked`, `cargo nextest run --all-features --locked` (30
passed, 1 skipped), `cargo deny check`, `cargo shear`, `typos` and `scripts/check-docs.sh`
pass. Cross targets: clippy for `aarch64-apple-darwin` (both crates) and
`x86_64-pc-windows-gnu` (`nsplane-uapi`) passes, and the `nsplane-uapi` tests pass under
wine; nothing ran on a macOS or Windows host.
