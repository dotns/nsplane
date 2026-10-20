# 20261020-0854-udp-icmp-isolation Isolate asynchronous errors on shared UDP sockets

- **status**: completed
- **createdAt**: 2026-10-20 08:54
- **approvedAt**: 2026-10-20 08:54 (owner authorization in the current conversation)
- **relatedTask**: 20261020-0854-udp-icmp-isolation

## Context

Receive and send share the socket error state. Only receives drain queued ICMP errors. A send that runs first treats an earlier error as a failure of its current datagram, advances failed-batch accounting, and causes the engine to discard the datagram. This is independent of downstream flow lifecycle changes.

## Proposal and scope

Handle queued asynchronous errors within UDP I/O for every send entry point. Cover errors arriving between error processing and sending, with bounded retries only of messages not accepted by the socket. Preserve Packet Too Big report destinations, quoted bytes, queue bounds and drop accounting. Synchronous sends do not wait; asynchronous sends retain backpressure and cancellation safety. Genuine current-send failures remain errors.

No public API, dependency, product admission policy or caller-side retry changes; no release or main-branch merge.

## Risks and validation

Do not hide genuine EMSGSIZE/address errors, lose PMTU reports under concurrent error reads, resend accepted batch prefixes, or spin on persistent errors. Establish RED before implementation. Cover all send entry points, address families and offload modes, then run focused UDP/engine tests, the independent reproduction and `just check`. Linux behavior must execute on Linux; macOS results cannot substitute for it.

## Alternatives

Disabling Linux PMTU changes transport capabilities. Caller-side retry or receive adapters expand responsibilities and complicate batch semantics. Weakening direct-path qualification changes acceptance. None is selected.

## Exit criteria

Complete every task acceptance criterion before committing and pushing this repair branch. Downstream adoption and E2E are verified separately in the consuming repository; this repository's passing gates cannot substitute for integration evidence.

## Validation

All acceptance criteria are met. Linux `just check` passes on Rust 1.99.0 with 1,949 passing tests and 33 skipped tests. The four privileged UDP tests passed separately in a disposable network namespace; the independent reproduction delivered all 288 healthy sends. The two baseline fixture failures were repaired and validated under the linked fixture plan, without a gate exception. Native macOS portability failures remain recorded in their separate, out-of-scope task. Downstream integration remains separate.
