# 20261118-0001-probe-timeout-on-held-acks A TCP sender stalls when acknowledgements arrive late after fast first round trips

- **status**: pending
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-11-18 00:01

## Description

Found by `20261117-1556-cross-host-network-perf.md`, work item 1
(`crates/nsplane-e2e/tests/netstack_held.rs`). It explains a consumer's report of a 4 MiB
transfer from a macOS host on Wi-Fi that took about 10 minutes with no loss on the wire.

A netstack TCP connection whose first round trips are fast and whose acknowledgements then
arrive late (held 100 ms or more and released in clumps, as a Wi-Fi access point does for a
client in power save) sends at a trickle. In process, 4 MiB with acknowledgements held in
100 ms slots after 4 immediate messages does not complete within 12 s (about 3 s when the
first measured round trip already includes the delay); with 300 ms slots it took 210 s in
one run and did not complete within 120 s in others, with about 1860 needless
retransmissions.

The trigger is any path whose round trip grows after a connection's first measurement, not
only held delivery: in `scripts/bench/netem.sh`, a connection opened on an unshaped link
takes 8.5 s for 4 MiB once `delay 20ms` applies and 25.7 s with `delay 100ms` (0.6 s and
2.8 s when the delay is there from the start), and stalls beyond 90 s with `slot 100ms` on
both directions or `slot 300ms` on the return direction.

Cause, in the smoltcp fork (`v0.14.0-nsplane.8`, `src/socket/tcp.rs`):

1. The tail loss probe timeout is `2 * srtt + 10 ms` (`probe_timeout`). With a smoothed RTT
   of 0 to 2 ms it fires 10 to 14 ms after the last send, long before a held
   acknowledgement arrives.
2. Outside loss recovery the probe is handled as a loss: `on_loss` and fast recovery. At the
   start of a connection the flight is one or two segments, so the slow-start threshold
   drops to two segments and slow start ends. In recovery every partial acknowledgement of
   the clump retransmits one more segment that was not lost.
3. Every retransmission cancels the pending RTT measurement (Karn's rule,
   `RttEstimator::on_retransmit`), and a probe goes out in every round, so the estimate
   never sees the real delay and stays at its first value. The state is permanent.

Tried on a copy of the fork: taking the delay from the arming of a probe's timeout to the
next acknowledgement of new data as an RTT sample (an upper bound of the round trip, so the
estimate errs towards late), and using `max(2 * srtt, srtt + 4 * rttvar)` for the probe
timeout. One spurious probe per connection remains instead of one per round: 100 ms slots
7.7 to 11.4 s, 300 ms 10.5 to 13.5 s, 1000 ms 18 to 37 s (debug and release runs mixed),
no retransmission beyond the first. The remaining cost is item 2: the one spurious probe
still ends slow start at two segments.

Open design question for the fix: how a probe that turns out spurious avoids the loss
response. Candidates: resend on the probe without a congestion response and reduce only
when the following acknowledgements show a loss; Eifel detection (RFC 3522) with TCP
timestamps, which the netstack does not enable today; a floor on the probe timeout until
several RTT samples exist.

Acceptance: the two asserted tests of `netstack_held.rs` run in `just check` and pass
within a bound of a few seconds; the late transfers of `scripts/bench/netem.sh` within twice
the time of the same profile from the start; `netstack_lossy`'s bounds (tail loss probe on a lossy
link) still hold; the fix lives in the fork with unit tests there, as a new fork tag.

## ActiveForm

Fixing the netstack TCP sender's stall on late acknowledgements.

## Dependencies

- **blocked by**: owner's approval (a change of the smoltcp fork and a new fork tag)
- **blocks**: the `held` and `held-ack` criteria of `20261117-1556-cross-host-network-perf`

## Notes

(none)
