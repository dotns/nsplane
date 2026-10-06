# ADR: nsplane-netstack depends on the dotns/smoltcp fork

Status   : Accepted
Date     : 2026-10-03
Sunset   : when an upstream smoltcp release ships the fixes below

## Context

Two smoltcp 0.14.0 TCP defects stalled `nsplane-netstack` connections for good under loss
when both ends send (an echo, a request and its response):

- After a retransmission timeout smoltcp rewinds its send position to `SND.UNA` and stamps
  every empty segment (pure ACKs, window updates) with it. A peer that already received
  past that point drops those segments as old, acknowledgement included; with both ends in
  that state neither learns that its data arrived.
- When an ACK closes the peer's window while data is in flight (window scaling rounds a few
  free bytes down to zero), the zero-window probe timer replaces the retransmission timer:
  the lost bytes are never resent, and once the window reopens no timer runs at all.

Phase 5 worked around both in the driver without touching smoltcp: the device rewrote the
sequence number of outgoing pure ACKs (`device::fix_ack_seq`), and a connection idle for
1 s took up to 1 KiB more into a full application buffer and kept a 1 s keep-alive standing
in for the persist timer (`stack::nudge_stalled`). Both patch symptoms from outside the TCP
state machine, cost per-packet work and bookkeeping, and the keep-alive changed what goes
on the wire.

## Decision

`nsplane-netstack` depends on `github.com/dotns/smoltcp`, pinned to a tag, and the
workarounds are removed. `deny.toml` allows that one git source; `unknown-git` stays
`deny`.

The fork is branch `nsplane/v0.14-fixes`, cut from upstream `v0.14.0`. Tag
`v0.14.0-nsplane.3` (`4566ba607cf8e0a275be6cd08f0a349f64815559`) carries five commits on
top of it:

- `35ec5eb` tcp: send empty segments with the highest sequence number sent (RFC 9293
  `SEQ=SND.NXT`; a rewind for retransmission does not move it).
- `998d9f9` tcp: keep lost data under the retransmission timer on a zero window (RFC 6298
  5.1; the probe timer only starts without a running retransmission timer, and a
  retransmission timeout expiring on a zero window probes from `SND.UNA`).
- `045279d` tcp: do not let empty segments undo a retransmission rewind. `35ec5eb` alone
  let the first pure ACK after a timeout move the send position back up to the highest
  sequence number sent, so retransmission stopped after one to three segments and the
  rest waited for the next, doubled, timeout.
- `8c74844` tcp: keep a pending fast retransmission until its segment is emitted
  (upstream defect). The third duplicate ACK reset the timer and cleared the pending
  flag before the segment was handed to the device; when the device had no room (the
  netstack's bounded egress backlog), the segment was never sent and no timer ran.
- the tagged commit, tcp: do not fast-retransmit when only a FIN is outstanding (upstream
  defect). Three duplicate ACKs replaced the retransmission timer of a lost FIN by a fast
  retransmission, which only resends data and found none: the FIN had no timer left.

The first two fix the defects above; the other three were found by running
`tests/netstack_lossy.rs` without the driver workarounds, where they stalled a connection
for good: `v0.14.0-nsplane.1` (the first two commits) in 3 of 10 debug runs of the
eight-flow lossy echo, `v0.14.0-nsplane.2` in 1 of 10 debug runs of the loss-free one.

Tag `v0.14.0-nsplane.4` (`b4a44da877b7e2aee07fa232e7a2c6e867bfee3e`, branch
`nsplane/v0.14-perf` on top of `.3`) adds the throughput round of plan
`20261004-1730-optimization`, which `nsplane-netstack` uses since then:

- `5d87540` checksum over 64-bit words (bit-identical, about 22 % fewer operations).
- `a56c712` tcp: the advertised right window edge never moves left under window scaling.
- `2e165a7` tcp: NewReno partial-ACK retransmission (RFC 6582, careful variant).
- `01267ee` tcp: sender silly-window avoidance (Minshall).
- `b4a44da` tcp: Limited Transmit (RFC 3042).

With them four netstack TCP streams reach at least the one-stream rate on the default
configuration (quiet harness: 6.85 / 7.29 Gbit/s for one / four streams, `.3`: 6.21 / 2.48).

Tag `v0.14.0-nsplane.5` (`cf04a5b9cb0bf1a206ae0b7cb811c70420a02081`, branch
`nsplane/v0.14-pmtu` on top of `.4`) adds `tcp::Socket::reduce_mss(timestamp, mss, seq)`
for path MTU discovery (ns MB-x7): smoltcp has no ICMP handling for its TCP sockets and no
way to lower a live socket's MSS. The call lowers the MSS of a synchronized connection
when the quoted `seq` lies within `SND.UNA..SND.NXT` and `mss` is below the current one,
and resends the data in flight at once in segments of the new size, without a congestion
or timer back-off (RFC 1191 section 7). `nsplane-netstack` reads the ICMP messages and
calls it.

Tag `v0.14.0-nsplane.6` (`687c56ad47bd831b395bb532da904d20d205140c`, branch
`nsplane/v0.14-tlp` on top of `.5`) adds a tail loss probe (QN F3, RFC 8985 section 7):
a probe timeout of two smoothed RTTs plus 10 ms (plus 200 ms with one segment in flight)
next to the retransmission timer, restarted by every segment sent and every ACK of new
data, resends the first unacknowledged segment once (fast recovery starts unless one is
running). It also runs in fast recovery and after a timeout, where it resends a lost
retransmission, which before waited for a timeout of at least 1 s (doubled after a
timeout). Chosen over SACK: smoltcp's receiver reports one SACK block and keeps four holes,
so a sender scoreboard would see little; the probe is one flag and one timer field.
`netstack_lossy` at 3 % loss: median 12.7 s to 1.0 s over 10 interleaved runs against
`main`, 1 % loss 1.1 s to 0.1 s, the loss-free and bottleneck rows and the harness's
netstack pair unchanged (see "Netstack throughput" in `docs/architecture.md`).

The commit messages in the fork carry the full analysis and each has a regression test.
The dependency keeps `version = "0.14.0"` next to `git` and `tag` so `cargo deny` does not
see a wildcard.

## Maintenance

- Rebase onto an upstream release: create `nsplane/vX.Y-fixes` from the upstream tag,
  cherry-pick the fix commits that upstream does not contain, run smoltcp's own tests, tag
  `vX.Y.Z-nsplane.N`, then move the tag (and the lock entry) in `nsplane-netstack` and run
  `tests/netstack_lossy.rs` and the throughput measurement in `docs/architecture.md`.
- Never move a published tag; a further fix on the same base is `-nsplane.N+1`.
- Cargo resolves a dependency with both `git` and `version` from the registry when the
  crate is published, i.e. without the fixes. While the fork is in use,
  `nsplane-netstack` is not published to crates.io (or the fork is published under its
  own name first).

## Exit criterion

Drop the fork and return to the crates.io dependency when an upstream smoltcp release
contains these fixes (or equivalent ones) and `tests/netstack_lossy.rs` passes on it.
Reporting the defects upstream is outward-facing and the user's call (follow-up #19 in
`docs/task/20261002-1509-phase1-followups.md`).

## Consequences

- The driver no longer parses or rewrites outgoing TCP segments, keeps no per-connection
  acknowledgement map, never takes data past an application buffer's bound while the
  connection is open and sets no keep-alives; the retransmission and persist timers are
  smoltcp's own.
- The build fetches one git repository; `Cargo.lock` pins the commit.
- Security advisories are published against crates.io releases of smoltcp; whether one
  applies to the fork is checked by hand when it appears.
