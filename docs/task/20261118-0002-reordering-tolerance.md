# 20261118-0002-reordering-tolerance Netstack TCP is slow on a link that reorders packets

- **status**: pending
- **priority**: P2
- **owner**: (unassigned)
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

(none)
