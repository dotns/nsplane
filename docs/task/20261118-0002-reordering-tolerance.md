# 20261118-0002-reordering-tolerance Netstack TCP is slow on a link that reorders packets

- **status**: completed
- **priority**: P2
- **owner**: perf-net
- **createdAt**: 2026-11-18 00:02

## Description

Found by `20261117-1556-cross-host-network-perf.md`, work item 4 (`scripts/bench/netem.sh`).

On a link with jitter, which reorders packets, a 4 MiB netstack transfer takes 8.6 s at
`delay 20ms 2ms` and 43 s at `delay 100ms 10ms`; kernel TCP on the same link takes 1.0 s
and 2.2 s, and the netstack on the same delays without jitter 0.6 s and 2.8 s. The sender
has no SACK and no reordering window: three duplicate acknowledgements from reordered
segments start a fast retransmit and reduce the congestion window every time.

The same table shows `loss5` at 3.5 s against 1 s or less; look at it once reordering is
handled, it may share the cause (one hole repaired per round trip without SACK).

Options to weigh in the investigation: SACK in the fork (receiver and sender), a duplicate
acknowledgement threshold that adapts when a retransmission turns out needless, or a short
reordering delay before the fast retransmit in the manner of RACK (RFC 8985).

Acceptance: `jitter20` and `jitter100` of `scripts/bench/netem.sh` within twice kernel TCP's
time, an in-process test with a reordering link in `nsplane-e2e` that runs in `just check`,
`netstack_lossy`'s bounds unchanged.

## ActiveForm

Making the netstack TCP sender tolerate reordering.

## Dependencies

- **blocked by**: owner's approval (a change of the smoltcp fork and a new fork tag)
- **blocks**: (none)

## Notes

2026-11-18, done in smoltcp fork tag `v0.14.0-nsplane.11` together with
`20261118-0001-probe-timeout-on-held-acks`. Four causes, each needed:

1. Nothing took a needless fast retransmit back. Now: duplicate reports (RFC 2883) from the
   receiver, a count of retransmissions per window cut on the sender, the cut restored when
   all were duplicates, and a wait of up to one smoothed RTT before the next third
   duplicate ACK. Two fast retransmits in a row overwrote the record of the window before
   the first (one run in ten took 2 to 5 times as long); a cut while the last
   retransmission is younger than the retransmission timeout now shares the record and
   the count of the one before.
2. The receiver kept 4 out-of-order ranges and dropped every segment beyond: 256 now.
3. Slow start added one MSS per ACK whatever it covered: it counts octets now (RFC 3465).
4. A FIN ahead of missing data was dropped and came back with the 1 s timeout.

Acceptance: `jitter20` 0.62 to 0.73 s (kernel TCP 1.04 s) and `jitter100` 3.2 s
(2.2 s) over four runs; `netstack_jitter`'s asserted test runs in `just check`;
`netstack_lossy` unchanged. `loss5` does not share the cause and is unchanged (0.2 to
10 s): its time is retransmission timeouts, filed as
`20261118-1832-timeouts-under-heavy-loss`.
