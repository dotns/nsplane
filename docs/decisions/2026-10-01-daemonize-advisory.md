# ADR: Accept the unmaintained `daemonize` crate in the CLI

Status   : Superseded 2026-10-02 (the CLI no longer daemonizes; `daemonize` was removed)
Date     : 2026-10-01
Sunset   : 2027-03-31

## Context

`cargo deny` reports RUSTSEC-2025-0069 (`daemonize` is unmaintained). Replacing it requires
calling `fork` directly, which is `unsafe` and would break `#![forbid(unsafe_code)]` in
`boringtun-cli`.

## Decision

Waive RUSTSEC-2025-0069 in `deny.toml`. The CLI only forks once at startup, before any other
thread is spawned (the log writer thread is now started after the fork).

## Consequences

Revisit by the sunset date: either a maintained safe crate exists, or the CLI drops
self-daemonization in favour of the service manager (systemd, launchd).
