# 20261020-1224-darwin-utun-name Validate Darwin utun descriptors before name queries

- **status**: completed
- **createdAt**: 2026-10-20 12:24 UTC
- **approvedAt**: 2026-10-20 12:24 UTC
- **relatedTask**: 20261020-1224-darwin-utun-name

## Context

The unchanged fd adoption test fails on both 0.16.1 and the release candidate,
depending on the PID bytes returned by LOCAL_PEERPID. Darwin uses the same numeric
level and option for that query and UTUN_OPT_IFNAME.

## Proposal

Before UTUN_OPT_IFNAME, use getpeername to check the complete sockaddr_ctl family
and system address, then compare its controller ID with CTLIOCGINFO for utun.
Return the OS EINVAL error for a different socket identity. Reuse the existing
controller lookup from create. Add deterministic negative coverage and a real
utun creation/adoption smoke test requiring administrator privileges.

## Scope and risks

Only the Darwin backend, focused tests and accompanying records change. The
packet path and Linux implementation remain unchanged. A valid utun descriptor
must retain its name and MTU through adoption and split. No new dependencies.
The user authorized the fix, verification, commit, push and subsequent v0.16.2
release. Release preparation is a separate commit.

## Validation

- [x] Demonstrate the new negative regression fails on the old implementation.
- [x] Pass focused TUN tests and verify real-utun behavior where privileges allow.
- [x] Pass native macOS just check and inspect the final patch.

Apple's kernel control implementation returns a complete sockaddr_ctl from
getpeername; CTLIOCGINFO performs a controller lookup without a privilege check:
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_control.c

All validation passed; the real-utun smoke ran with system biometric authentication.
