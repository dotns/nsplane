# 20261111-2031-responder-queue-flush A responder flushes its queue into a second handshake initiation

- **status**: completed
- **priority**: P2
- **owner**: audit-fix
- **createdAt**: 2026-11-11 20:31

## Description

Found in the audit and confirmed with an external test. A peer has packets queued for lack of a
session when the remote's handshake initiation arrives. The core answered it and flushed the
queue right away, but a responder may send in the new session only once the initiator's first
transport message confirms it. The tunnel therefore found no current session, queued the packet
again and returned a new handshake initiation, which `flush_queue` transmitted on the path
selected for `MessageKind::Data` and without the initiation bookkeeping. The queued packets left
only when that second, redundant handshake completed; the data path never flushed the queue.

Acceptance: answering an initiation emits the response alone; the first authenticated transport
message (data or keepalive) in that session sends the queued packets through it; whatever a
flush transmits is classified by its message type; the initiator path (flush after the handshake
response) is unchanged.

## ActiveForm

Moving the responder's queue flush to the confirmation of its session.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

The fix is in `nsplane-core` only; `nsplane-noise` is untouched.

- `receive_handshake` flushes only after a handshake response, where this side was the initiator
  and the session is current at once. After an answered initiation it does not.
- `opened` flushes when the message it accounts for completed a handshake (`completed > 0`).
  The tunnel counts a responder's handshake exactly when the first transport message of its
  unconfirmed session is authenticated (`timer_tick_session_confirmed`), in the same call that
  makes the session current, so this is the first moment the queue can leave, and it happens
  once per handshake rather than on every data message. `opened` is shared by the in-place
  receive path and by `complete_job`, so both the direct and the crypto-job path flush, and
  the steady state pays one predictable branch on a value it already has.
- `flush_queue` takes the message kind from the datagram (`message_kind`), like the timer path:
  should the tunnel still answer with an initiation (no usable session), it goes on the path for
  `MessageKind::HandshakeInit` and is recorded with `initiation_sent`.

Open doubt: without a session `Tunn::send_queued_packet` moves the packet it tried to the back
of the queue, so a flush without a session reorders the queue. The core no longer flushes in
that state, and the tunnel is left as it is.

## Validation

`core::tests::a_responder_sends_its_queued_packets_once_the_session_is_confirmed` (direct and
crypto-job paths) fails before the fix (`[HandshakeResponse, HandshakeInit]` instead of
`[HandshakeResponse]`) and passes with it. The gates pass in the dev container: `cargo fmt --all --check`,
`cargo hack clippy -p nsplane-noise -p nsplane-core --each-feature --all-targets --locked`,
`cargo nextest run -p nsplane-noise -p nsplane-core -p nsplane --all-features --locked` (553
passed, 4 skipped), `typos` and `scripts/check-docs.sh`.
