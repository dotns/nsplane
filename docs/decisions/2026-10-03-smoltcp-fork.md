# ADR: nsplane-netstack depends on the dotns/smoltcp fork

- **Status**: Accepted
- **Date**: 2026-10-03
- **Review**: when an upstream smoltcp release ships the fixes below

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

Tag `v0.14.0-nsplane.7` (tag object `28356d128d7d910d7212209ca42a3caf65cca254`, commit
`85e9796162bf36e0afbaad8c75c397c7729c8cd2`, branch `nsplane/upstream-24bda3b`, 2026-10-24)
moves the fork onto upstream smoltcp `main` at `24bda3b` (plan
`20261024-1453-smoltcp-upstream-fixes`). The base brings upstream's TCP fixes since v0.14.0:
`336a1dd` (the last advertised window saturates at zero after a FIN at a zero-window edge),
`bd424c8` (a fast retransmission whose emit failed is retried), `bfe5f95` (no zero-window
probe timer while data is in flight; a retransmission timeout on a closed window arms the
probe timer), the per-socket RTO bounds (`c7595c5`, `7d961a1`, `51c662c`:
`Socket::set_min_rto` / `set_initial_rto`, the maximum stays the 60 s constant), the Cubic
`no_std` fix `5fe57a1` and the MLD gating `f878f18`. The crate version stays `0.14.0`. The
patches of `.1` to `.6`, reapplied in order:

- Kept: `35ec5eb` (as `f62700c`), `045279d` (`90a7487`), the FIN fix tagged as `.3`
  (`1f9054b`, upstream lacks it), `5d87540` (`3e051ed`), `a56c712` (`419f085`; independent of `336a1dd`, which only
  saturates one computation, while `a56c712` keeps the advertised edge and clamps the
  accepted data), `2e165a7` (`0b35d84`), `01267ee` (`4d2a376`), `b4a44da` (`762a065`),
  `cf04a5b` (`95ceea4`). Each keeps its regression test; those of `35ec5eb`, `045279d` and
  the FIN fix were checked to fail without the fix on the new base.
- Dropped `998d9f9`: `bfe5f95` fixes both of its defects and its tests cover them. Upstream
  probes one backed-off RTO after a timeout on a closed window where `998d9f9` probed at
  once; that is the only difference, and the old test fails only on that timing.
- Dropped `8c74844`: `bd424c8` is the same code change, and the old test passes on
  upstream.
- Reduced `687c56a`, the tail loss probe (`85e9796`): the probe timeout is compared with the
  RTO, now a `u16`, and the probe is armed only when it expires before the RTO, so a minimum
  RTO below two smoothed RTTs plus the margin leaves the loss to the retransmission timer
  (`test_tail_loss_probe_yields_to_a_lower_retransmission_timeout`). Upstream's
  `test_zero_window_reopens_inflight_data` is adapted to the probe that expires first (a
  no-op on a closed window).

smoltcp's tests on the branch: 705 library tests with the default features, 450 with the
features `nsplane-netstack` uses, 722 with `socket-tcp-reno` added. `nsplane-netstack`
exposes the RTO bounds as `NetStackConfig::tcp_min_rto` and `tcp_initial_rto` (default 1 s,
smoltcp's), applied to every TCP socket; no fork-only maximum.

Measured against `.6` (A) with default RTO bounds (B), interleaved per `scripts/bench/slot.sh`
invocation on slot 0, 120 s apart, release, load 0.1-5.9. `netstack_lossy` `throughput`, 10
invocations, median [range]:

| Case | `.6` | `.7` |
| --- | --- | --- |
| TCP 64 MiB, no loss | 0.161 s [0.115-0.166] | 0.161 s [0.117-0.169] |
| TCP 16 MiB, 1 % loss | 1.085 s [0.106-1.180] | 0.118 s [0.082-1.090] |
| TCP 16 MiB, 3 % loss | 1.305 s [0.311-3.380] | 0.834 s [0.287-3.270] |
| TCP 16 MiB, 25 MB/s bottleneck | 0.798 s [0.779-0.807] | 0.794 s [0.780-0.804] |
| UDP burst | 1027 MB/s [985-1385] | 1043 MB/s [930-1424] |

The lossy rows are bimodal (about 0.1 s, or about 1.1 s when an RTO fires) for both; the
minima are equal. The asserted `netstack_lossy` tests, each alone (median ms, `.6` / `.7`):
`bulk_tcp_without_loss` 40 / 40, `bulk_tcp_with_loss` 67 / 67.5, `bulk_tcp_with_heavy_loss`
435 / 435.5, `parallel_echo_without_loss` 28.5 / 29.5, `parallel_echo_with_loss` 2122 / 1176
(ranges 1062-3146 / 1060-3047).

`nsplane-netstack` criterion `send_stream`, mean of three invocations: TCP send is 1-2 %
slower on `.7` (`netstack_send` 1 / 4 streams +1.1 / +1.7 %, `netstack_send_1cpu` +1.8 / 0 %;
a second series of three, with `.6` run again last in each invocation, gave +1.0 / +2.3 /
+1.7 / +0.7 % with the repeated `.6` within 0.5 % of the first); UDP send unchanged within
about 1 %. Reverting `5fe57a1` was slower still (+1.5 / +1.7 / +3.1 / +2.4 %): it replaced a
`mul_add`, a libm call without the `fma` target feature, by a plain multiply-add. The u16 RTO
and `bfe5f95`'s `flight_size` check are off the per-segment path and could not be reverted
alone; the delta is taken as code size and layout of the larger socket and accepted, as the
end-to-end rows above are unchanged.

With `tcp_min_rto` at 20 ms (one invocation against the default, load 0.4): 1 % loss 1.100 s
to 0.106 s, 3 % loss 0.356 s to 0.300 s, `bulk_tcp_with_heavy_loss` 435 ms to 243 ms,
`parallel_echo_with_loss` 1073 ms to 133 ms; loss-free and bottleneck unchanged.

Tag `v0.14.0-nsplane.8` (tag object `bf491baacb0e3907f362b5e50f871a8c996b2863`, commit
`9e228d6285a3e87128d62bf810dfed4b752b82aa`, branch `nsplane/upstream-24bda3b`, 2026-11-10) adds
`9e228d6` on `.7`: a zero-length segment outside a zero receive window has its ACK processed
when the ACK is in SND.UNA..=SND.NXT (RFC 9293 3.10.7.4), with SND.WND updated by the
SND.WL1/SND.WL2 rule. A Linux peer fills the window rounded up to the scale (`419f085`), its
SND.NXT then passes RCV.NXT and its pure ACKs were dropped; with both windows closed the
connection stalled for good (a TUN-to-netstack 32 MiB echo stalled in 3 of 78 runs, none of 75
with the fix). The rounding up stays: rounding down moves the advertised edge left again.
smoltcp's tests: 709 library tests with the default features.

Tag `v0.14.0-nsplane.9` (tag object `a05c861406aaf0a33c141ff62ba266507770a9a8`, commit
`49d6dc94d778ac80c1c08655d696ed65338927ea`, branch `nsplane/upstream-c68ace4`, 2026-11-18)
rebases the eleven patches of `.8` unchanged (range-diff) on upstream `main` `c68ace4`
(2026-11-13: a keep-alive timer fix, SLAAC fixes nsplane does not enable) and adds two, from a
downstream fault check of 0.23.0. `d0d1120` adds `Socket::reset_received`: a socket closed by
a reset from the remote endpoint kept no trace of it, so a reader could not tell a reset
from a FIN. `49d6dc9` keeps the tail loss probe armed at the time it was set while `recover`
is set: every segment sent re-armed it, and in fast recovery each duplicate ACK lets a new
segment out, so a lost fast retransmission waited for the retransmission timeout (at least
1 s) instead of the probe two round trips later. smoltcp's tests: 714 library tests with the
default features, 457 with the features nsplane uses.

Tag `v0.14.0-nsplane.11` (tag object `06abdad9e77a184e5eccd14fccd748ff733b4e7c`, commit
`a48690459a707e0fa0429fde4209e956c2056e45`, branch `nsplane/upstream-c68ace4`, 2026-11-18)
adds three commits on `.9`. `560f8e4` raises the maximum of `ASSEMBLER_MAX_SEGMENT_COUNT`
from 32 to 256 (nsplane enables 256). `82737d6` and `a486904` stop the sender from taking
late or overtaken segments for lost ones: a probe fired after two smoothed RTTs and was
handled as a loss, the retransmissions suppressed every RTT sample, and nothing took a
needless window cut back, so a connection whose acknowledgements arrived late after fast
first round trips sent at a trickle (4 MiB in minutes) and one on a reordering link took 8
to 20 times as long as kernel TCP. The receiver now reports duplicate segments (RFC 2883).
Towards such a remote a probe only resends, and the window is reduced once the loss shows
(a SACK block above the next ACK, an ACK of data sent after the probe with no report of the
probe, or no report by the time one was due); the ACKs after a probe are RTT samples. A
reduction after a fast retransmit is withdrawn once every retransmission was reported as a
duplicate (`Controller::on_spurious_loss`, RFC 9438 4.9; `Controller::on_loss_confirmed`
marks where the count starts), and the third duplicate ACK then waits up to one smoothed
RTT. Slow start counts acknowledged octets (RFC 3465), and a FIN ahead of missing data is
kept. Still no SACK scoreboard: the sender reads SACK blocks only to find a duplicate
report or a hole above the ACK. Tag `.10` (`82737d6`) is the same without `a486904`: it
reduced the window on the ACK after a probe and withdrew that on the report, which on a
link that delivers in slots left reductions standing when the first RTT samples were a
little off (a test that passed alone failed under a parallel test run). smoltcp's tests:
726 library tests with the default features, 471 with the features nsplane uses.

The commit messages in the fork carry the full analysis and each has a regression test.
The dependency keeps `version = "0.14.0"` next to `git` and `tag` so `cargo deny` does not
see a wildcard.

## Maintenance

- Rebase onto an upstream release (or, as for `.7`, an upstream commit): create
  `nsplane/vX.Y-fixes` (`nsplane/upstream-<sha>`) from the upstream tag (commit),
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

Tag `v0.14.0-nsplane.12` (commit `e48a5e43db30a653704ff0fc907d104b7caac3aa`, branch
`nsplane/upstream-c68ace4`, 2026-11-19) adds `e48a5e4` on `.11`: the probe is repeated.
One probe was sent per stall, and at 5 % loss in both directions a transfer spent most of
its time in the retransmission timeouts of at least 1 s that followed. Traces of both ends
showed two states: the remote had answered a whole flight with one ACK and that ACK was
lost, so nothing showed a loss and the one probe or its report was lost one time in ten;
or a hole was known and the probe was the only segment the remote could answer. Up to
three probes are now sent for one SND.UNA where a loss is known and two where none is, each
after twice the wait of the one before; the second probe without a sign of loss only
resends and changes nothing of what the first one recorded. smoltcp's tests: 728 library
tests with the default features, 762 with both congestion controllers.
