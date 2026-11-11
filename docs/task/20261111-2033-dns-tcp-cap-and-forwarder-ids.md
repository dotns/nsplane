# 20261111-2033-dns-tcp-cap-and-forwarder-ids DNS: TCP connection cap, accept under exhaustion, forwarder IDs

- **status**: completed
- **priority**: P2
- **owner**: audit-fix
- **createdAt**: 2026-11-11 20:33

## Description

Two audited defects in `nsplane-dns`.

1. (P2) `Server::serve_tcp` spawned a task per accepted connection without a limit: only
   queries in flight were bounded, and an idle connection lives up to `tcp_idle_timeout` per
   frame part. An `accept` failing with `EMFILE`, `ENFILE`, `ENOBUFS` or `ENOMEM` made
   `serve_tcp` return, which ended the TCP service for good.
2. (P3, hardening) The forwarder's transaction ID was a function of a query counter and the
   socket's source port, so it added nothing against off-path spoofing, and the raw path
   (`Forwarder::forward`) accepted a response on ID and opcode alone. `exchange` also zeroed
   a 64 KiB buffer per query.

Acceptance: a configurable cap on concurrent TCP connections with a counter for refused
ones; resource-exhaustion accept errors are retried, other errors stay fatal; transaction IDs
from the system's random number generator; the raw path compares the question section when
it can; tests for each; the crate gates pass.

## ActiveForm

Bounding TCP connections of the DNS server and hardening the forwarder's response matching.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Connection cap: `ServerConfig::max_tcp_connections` (default 256, `with_max_tcp_connections`),
shared by a server and its clones like `max_in_flight`. A connection over the cap is accepted
and closed at once (`ServerStats::rejected_connections`) instead of being left in the listen
queue: the queue keeps draining, the client learns of the refusal at once and can retry or
move to another server, and the refusals are countable. Leaving connections in the queue
would hold legitimate clients behind idle ones for up to the idle timeout. `serve_stream` and
the netstack `serve_tcp_connection` are driven by the embedder and stay outside the cap.

Accept errors: `EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM` (unix, through `libc`), `WSAEMFILE` and
`WSAENOBUFS` (Windows, by number) and `ErrorKind::OutOfMemory` are logged (warn for the first
of a shortage, debug after) and retried after 100 ms. `libc` becomes a direct unix dependency
of the crate; it was already in the lock file through tokio.

Transaction IDs: two bytes from `rand_core::OsRng` per attempt (`rand_core` 0.6.4 with
`getrandom`, as `nsplane-core` and `nsplane-noise` use it; no new crate in the lock file). An
attempt fails when the system returns no randomness.

Raw-path question check: when the request parses with at least one question, a response that
parses and carries questions must carry the same ones. Two cases fall back to ID and opcode:
a response that does not parse, and a response with an empty question section. The second is
a deliberate deviation from strict equality: servers answer messages they refuse (`NOTIMP`
for an unsupported opcode, `FORMERR`) with a bare header, and passthrough exists for such
messages; requiring an echoed question would turn those answers into a `SERVFAIL` after
every attempt timed out. A spoofer who has the ID and port can therefore still inject a
question-less response, but not answers for another name.

Buffer: the receive buffer is allocated with capacity only and filled through
`UdpSocket::recv_buf`, so no 64 KiB is zeroed per query; the capacity still holds the largest
datagram.

No breaking API change: `ServerConfig` and `ServerStats` are `#[non_exhaustive]`.

## Validation

Red before the fixes (4 of 88 failed), green after (88 of 88),
`cargo nextest run -p nsplane-dns --all-features --locked`:

- `server::tcp_closes_connections_above_the_cap`: the third connection at a cap of 2 was
  served instead of closed (`read: Err(Elapsed(()))`).
- `accept_exhaustion::tcp_accept_survives_descriptor_exhaustion` (Linux; lowers
  `RLIMIT_NOFILE` in its own test binary): `serve_tcp returned: Ok(Err(Os { code: 24, kind:
  TooManyOpenFiles, .. }))`.
- `forward::raw_forward_ignores_responses_with_another_question`: got `[192.0.2.77]` from the
  response to another name.
- `forward::transaction_ids_do_not_follow_the_count_and_source_port`: all 16 IDs matched the
  counter-and-port formula.
