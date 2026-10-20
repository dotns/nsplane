# 20261020-1224-darwin-utun-name Validate Darwin utun descriptors before name queries

- **status**: completed
- **priority**: P1
- **owner**: a/darwin-name-20261020
- **createdAt**: 2026-10-20 12:24 UTC

## Description

The release gate exposed an existing Darwin bug: the utun option numbers also
select LOCAL_PEERPID on a Unix socket. PID bytes can be accepted as an interface
name. The user approved a minimal fix and regression coverage before v0.16.2.
See [the plan](../plan/20261020-1224-darwin-utun-name.md).

## Acceptance

- [x] Reject non-utun sockets before querying their interface name.
- [x] Cover Unix socket rejection independently of the process ID.
- [x] Preserve real utun name lookup and adopted-fd packet transport.
- [x] Pass native macOS just check and review the patch.

## ActiveForm

Completed: Darwin name queries reject non-utun sockets and preserve real utun behavior.

## Validation

- RED: Unix datagram and stream regressions failed on the old backend with PID bytes
  returned as successful interface names.
- GREEN: all 85 native TUN tests passed; the newly added privileged test is excluded
  from the ordinary run and was separately executed with system authentication.
- Real utun smoke: 1 passed, checking creation, adoption, split, names and MTU.
- Native macOS just check exited 0: 1912 tests passed, 9 configured skips (including
  the separately passed new smoke test); feature Clippy, doctests, dependency gates,
  Rust 1.95 MSRV, examples, terminology and documentation checks passed.
- Review: no additional findings. The syscall buffers are initialized and bounded;
  controller lookup is short-circuited for other socket families. No packet-path,
  dependency or public API changes. iOS uses this backend but was not device-tested.

- complete: Native macOS full gate and real-utun smoke passed.
