# 20261111-2032-splitter-gone-sink-closes-engine One gone sink of a Splitter closes the engine's whole sink

- **status**: completed
- **priority**: P2
- **owner**: audit-fix
- **createdAt**: 2026-11-11 20:32

## Description

Audit finding. `Splitter` returned the `BrokenPipe` of a single sink to its caller while its
other sinks were still open. For a `PacketSink`, `BrokenPipe` means the local side is gone: the
engine's sink task returns on it (`engine/tasks.rs`, `write_sink`), the owner marks the sink
closed (`engine/output.rs`, `deliver_inline`), and every later packet is dropped as
`DROP_SINK_CLOSED`, the ones for the open sinks included. A hybrid local side (TUN device next to
a netstack) lost both halves when one went away.

Acceptance: while at least one sink is open, a packet routed to a gone sink is dropped and
counted, the call does not return `BrokenPipe`, and the rest of the batch is delivered in order
under the `send_batch` / `send_batch_spent` contracts; `BrokenPipe` is returned only once every
sink is gone; tests cover both; rustdoc and `docs/reference/nsplane.md` say so.

## ActiveForm

Keeping a Splitter with an open sink from reporting the local side gone.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Dropping returns `Ok` rather than another error kind. Both engine loops log every error that is
not `BrokenPipe` or `WouldBlock` at warn level and call again for the rest of the batch, so a
substitute error would log one warning per packet routed to the gone sink, for as long as the
peer keeps sending. `Ok` is also what the splitter already returns for a misrouted packet, for
the same reason.

The drops are counted in the existing `SplitterStats::failed`; no new counter. Its meaning
widens from "`send` returned the error" to "not delivered because of the sink", documented on
the field.

A gone sink is no longer called: its packets are dropped by the splitter (their buffers go to
`spent` in `send_batch_spent`). Before, the sink itself was asked again for every packet. A sink
that returns `BrokenPipe` and later recovers (a `SwapSink` after `replace`) therefore stays gone
inside a splitter; that matches the `PacketSink` contract and the `open` count, which never went
back up either.

In `send_batch_spent`, when a sink goes while another is open, the rest of its run goes back to
the front of the batch and is routed again within the same call, then dropped. Only a
`Splitter::new` closure can run twice for a packet this way, as it already could across the
caller's retries; a `new_map` closure still rewrites each packet once.

`SwapSink` has the related problem (it forwards the current sink's `BrokenPipe`, after which a
`replace` cannot bring the engine's sink back). Left unchanged here.

## Validation

Red before the fix, 6 of 21 splitter tests failing (`gone_sink_drops_until_all_are_gone`,
`map_gone_sink_drops_until_all_are_gone`,
`batch_keeps_flowing_to_the_open_sink_after_the_other_is_gone`,
`spent_drops_the_runs_of_a_gone_sink`, `spent_new_map_drops_for_a_gone_sink_mapping_once`,
`spent_last_sink_gone_is_broken_pipe_and_keeps_the_rest`); green after it.

`cargo fmt --all --check`, `cargo hack clippy -p nsplane --each-feature --all-targets --locked`,
`cargo nextest run -p nsplane --all-features --locked`,
`cargo test -p nsplane --all-features --doc --locked`, `typos` and `scripts/check-docs.sh` pass.
