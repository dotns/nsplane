# 20261111-2303-driver-netstack-robustness Driver and netstack robustness items from the audit

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-11 23:03

## Description

Four robustness items of the audit in `nsplane` and `nsplane-netstack`:

1. With path MTU discovery on, the UDP receive path retried a failed read without a bound
   inside one readiness callback (`udp/linux/recv.rs`), while the send side gives up after 7
   retries.
2. `ChannelSource::new`, `ChannelSink::new` and `ChannelTransport::pair` panic on capacity 0
   (tokio's `mpsc::channel`) without saying so; `pipe` documents it.
3. `nsplane-netstack` logged at `warn` once per dropped packet on paths a remote peer drives
   (UDP flow table at capacity, listener pool at its cap), and swept the whole flow table for
   closed flows on every datagram of a new tuple while it was full.
4. `connect_tcp` collects the local TCP ports in use into a set per connect, and `connect_udp`
   sweeps the connected sockets and scans them per candidate port.

Acceptance: each item is fixed with a test where one is feasible, or left alone with the reason
recorded; the public API and the port uniqueness rules do not change; the gates pass.

## ActiveForm

Fixing the audited robustness items in the driver and the netstack.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Item 1. The read now returns the eighth failure in a row, as a send does. The engine's receive
task logs an error other than `BrokenPipe` at debug and receives again, so the error does not
close the transport; but it called the transport again at once, which only moved the busy loop
one level up (683392 failed receives in 300 ms in the new test before the fix). The receive
task now waits after such an error, 1 ms doubling up to 64 ms for errors in a row, and the
count starts over at the first receive that succeeds. This holds for every `Transport`, not
only for UDP. The source and sink tasks (`read_source`, `write_sink`) repeat at once after an
error in the same way and were left alone: they are outside this item.

Item 2. Documentation only. The other constructors that take a capacity clamp it to 1.

Item 3. `throttle::LogLimit` is one `static` per call site: one log per second, carrying the
number of logs held back, two atomics and no allocation. The limit is per process, so the
stacks of one process share it. The drops were already counted (`udp_flow_limit`,
`syn_refused`) and still are. The sweep of a full flow table exists to make room once the
application dropped a flow; each `UdpFlow` now counts its drop in a counter the driver shares
(after its queue closed, by field order), and the driver sweeps a full table only when the
count moved since the last sweep. A flow is admitted as soon after a drop as before; no timer
is involved.

Item 4. Left as is. The TCP port set is not a plain function of the tables: a connection
counts only while its smoltcp socket still has a local endpoint, so a closed socket that is
still in `conns` does not hold its port, and the deferred connects from a port an abort is
about to release rely on that. A count kept by hand would hold such ports longer (a change of
the uniqueness rule), and would need updates at every change of `conns`, `connecting` and
`listeners`, the last of which is changed by free functions in `listeners.rs` without the
driver. For UDP, a count of connected local ports is simple, but the sweep of dropped sockets
before it stays linear, so the connect stays linear; removing that sweep needs the same drop
count as item 3 on `UdpSocket`. The scan per candidate port only repeats when the candidate is
taken.

## Validation

`udp::tests::icmp::read_recovery_does_not_spin_on_lasting_errors_or_backpressure` (8 attempts
with discovery, 1 without or on `WouldBlock`), `engine::lasting_receive_errors_back_off` (fails
before the fix), `throttle::tests::one_log_per_interval_carries_the_suppressed_count`, and
`stack::a_dropped_udp_flow_makes_room_at_the_flow_limit` (passes before and after: the sweep
keeps its purpose). The gates of both crates pass: fmt, `cargo hack clippy --each-feature`,
nextest, doc tests, `typos`, `scripts/check-docs.sh`, `scripts/check-product-terms.sh`.
