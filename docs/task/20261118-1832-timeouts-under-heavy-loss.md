# 20261118-1832-timeouts-under-heavy-loss Netstack TCP waits for retransmission timeouts at 5 % loss

- **status**: completed
- **priority**: P3
- **owner**: (unassigned)
- **createdAt**: 2026-11-18 18:32

## Description

Found while fixing `20261118-0002-reordering-tolerance`. At 5 % random loss in both
directions a netstack transfer spends most of its time in retransmission timeouts of at
least 1 s: 16 MiB in process (`netstack_lossy`'s `throughput` with 50 per mille) takes 2.6
to 8.8 s with 4 to 7 timeouts, 4 MiB in `scripts/bench/netem.sh`
`loss5` 0.2 to 10 s
against 1 s or less for kernel TCP; at 10 % loss 16 MiB take 33 to 54 s. The same with
smoltcp fork tags `v0.14.0-nsplane.9` and `.11`.

Every timeout seen had the same state: fast recovery, one fast retransmission and one probe
sent for the first unacknowledged segment. Often nothing else is in flight by then (the
peer holds everything behind the hole), so the loss of the one probe or of its ACK, 10 % at
this rate, leaves only the timeout. One probe per stall is what RFC 8985 allows; its
timeout floor is 200 ms in Linux, 1 s here.

Options: a second probe before the timeout, a retransmission timeout floor below 1 s for
netstack-to-netstack paths (`tcp_min_rto` exists), or a SACK scoreboard in the fork.

Acceptance: `loss5` within twice kernel TCP's time; the in-process 5 % transfer without a
timeout in most runs; the bounds of `netstack_lossy`, `netstack_held` and `netstack_jitter`
unchanged.

## ActiveForm

Finding why a lost retransmission waits for the timeout under heavy loss.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

2026-11-19: done in smoltcp fork tag `v0.14.0-nsplane.12`. Traces of both ends at 5 % loss
showed that the description's cause was one of two. The more frequent one: the remote
answers a whole flight with one ACK, that ACK is lost, nothing shows a loss, and the single
probe or its duplicate report is lost as well. The probe is now repeated (three where a
loss is known, two where none is, doubling). `loss5`: 1.0 to 2.9 s, 0.15 to 1.5 s late,
kernel TCP 1 to 6 s in the same runs; no timeout after the handshake in eight traced runs.
In process at 5 %: 0.8 to 2.9 s for 16 MiB without a timeout (2.6 to 8.8 s before). What
remains is NewReno repairing one loss per probe or round trip. The held and jitter reports
are unchanged.
