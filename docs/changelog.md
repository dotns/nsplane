# nstun - Development Changelog

Project-level history for PMA task and plan tracking. Release notes for the crates live in
the root `CHANGELOG.md`.

## 2026-10-01 19:05 [decision]

Forked cloudflare/boringtun `6dcc889` as `dotns/nstun`. Approved plan
`20261001-1859-fork-baseline`: remove upstream CI, adopt the pma-rust baseline, switch the
crypto backend from `ring` to `aws-lc-rs`, re-implement gotatun fixes F1-F10, add a
zero-copy data path and Windows support. gotatun code is not copied (MPL-2.0).

## 2026-10-01 19:34 [progress]

Phase B (pma-rust baseline) done: edition 2024, MSRV 1.95, toolchain 1.99.0,
`[workspace.lints]`, `missing_docs` on the library, `unsafe` confined to platform/FFI
modules with SAFETY comments (ADR `2026-10-01-unsafe-code-in-boringtun`), no CI
(ADR `2026-10-01-no-ci`), `daemonize` advisory waived (ADR `2026-10-01-daemonize-advisory`).
`just check` and `just cross` (macOS via zig, Windows via mingw-w64 + nasm) pass.

## 2026-10-01 19:34 [pitfall]

- `cargo clippy --fix` rewrote `Duration` subtraction into `checked_sub(..).unwrap()`;
  replaced with `saturating_sub`.
- Building `aws-lc-sys` for `x86_64-pc-windows-*` requires NASM on the build host.
- `kqueue.rs`/`tun_darwin.rs` are invisible to Linux builds; use `just cross`.

## 2026-10-01 19:48 [progress]

Phase D done: F1-F10 re-implemented with failing tests first (no gotatun code copied).
`device::PeerTable` extracted to make peer updates testable. `just check` and `just cross` pass.

## 2026-10-01 19:48 [pitfall]

- With `mock-instant`, timer ticks use the time of the last `update_timers` call; tests must
  call `update_timers` after advancing the clock, as the device does every 250 ms.
- Re-handshake tests need the mock clock to advance, or the responder rejects the initiation
  timestamp as a replay.

## 2026-10-01 20:19 [progress]

Phase F done (Windows). Plan `20261001-1859-fork-baseline` completed: all phases A-F landed,
`just check`, `just cross`, `just test-windows` and `just e2e` pass. Not verified on a real
Windows host with the Wintun driver.

## 2026-10-01 20:19 [pitfall]

- A clap derive `bool` flag only accepts `true`/`false` from its env var; use
  `BoolishValueParser` to keep `WG_SUDO=1` working.
- Under wine, `wintun.dll` cannot load, so the Windows device stops at adapter creation.

## 2026-10-02 10:20 [decision]

ns consumes nstun as a library; the CLI is a Linux/macOS development tool. Task
`20261002-1008-cli-dev-tool`: the CLI runs in the foreground only and no longer builds on
other targets; `daemonize` and its advisory waiver are gone (ADR superseded). The Windows
`device` layer stays in the library as a fallback.

## 2026-10-02 10:50 [decision]

Plan `20261002-1024-data-plane-core` approved: nstun becomes the complete data plane with
a sans-I/O core (`nstun-core`), a tokio driver (`nstun`), platform I/O (`nstun-tun`), an
in-process netstack, and the ACL; `boringtun::device` is deleted after Phase 1. Architecture
reviewed against firezone connlib, tailscale tstun/wgengine, gotatun, NepTUN, wireguard-go,
netbird, EasyTier and the userspace-stack crates. Phase 1 is executed as a BKD campaign.

## 2026-10-02 13:10 [progress]

Added `docs/design.md`, the one-page design overview (position in the NS architecture,
non-goals, principles, crate map, engine model, roadmap, decisions). Plan
`20261002-1024-data-plane-core` aligned with the NS next-architecture page: 4↔6
translation and fragmentation in Phase 5, both ns data planes in Phase 6, workstream E.

## 2026-10-02 14:40 [decision]

The project is renamed **nsplane**: it is the node's underlying data plane, not a TUN.
ADR `2026-10-02-rename-nsplane` records the candidates checked, the crate scheme
(`nsplane-noise`, `nsplane-core`, `nsplane`, `nsplane-tun`, ...) and the timing: executed
as its own task after the Phase 1 BKD campaign merges D and E. The docs-site nstun pages
were rewritten from `docs/design.md`.

## 2026-10-02 14:50 [progress]

Phase 1 workstream D done: the `nstun` Engine facade (`EngineBuilder`, `Engine`,
`EngineHandle`, broadcast events, bounded transmit backlog and engine drop counters),
`nstun-uapi` (the `wg` UAPI over an engine, Unix socket listener), `boringtun-cli` on the
engine (tokio runtime, `--tun-fd`, `--uapi-fd`, `--disable-connected-udp` and
`--disable-multi-queue` removed, privilege drop via `SUDO_UID`/`SUDO_GID`), and the deletion
of `boringtun::device`, the `device` feature, its dependencies and `just integration`.
`just e2e` passes unchanged against kernel WireGuard. README, CHANGELOG, architecture and
the unsafe/Wintun ADRs updated; ADR `2026-10-02-async-engine-replaces-sync-device` added.

## 2026-10-02 15:36 [progress]

Task `20261002-1529-repo-cleanup-layout` done together with the rename (ADR
`2026-10-02-rename-nsplane`): the crates moved under `crates/` with their nsplane names
(`nsplane-noise`, `nsplane-cli`, `nsplane`, `nsplane-core`, `nsplane-packet`,
`nsplane-tun`, `nsplane-uapi`, `nsplane-e2e`), identifiers, test interface names, e2e env
vars and container prefixes follow. The FFI/JNI bindings, the upstream crypto benches and
the banner/logo images are deleted. Attribution (Cloudflare copyright, dotns copyright,
origin, WireGuard trademark) lives only in `LICENSE.md`; README and the living docs use the
new names.

## 2026-10-03 15:35 [decision]

Plan `20261003-1630-perf-and-wss` PW widened by the user: the WsFrame terminate leg (ns
`tunnel-ws` `WsTunnel`) moves into `nsplane-wss` now as PW (c), with OPEN resolution behind an
embedder trait, so ns can delete `tunnel-ws` whole. ADR
`2026-10-03-data-channel-protocols-in-nsplane` consequence updated (both legs move).

## 2026-10-04 06:00 [progress]

Campaigns since the Phase 5 follow-ups, all merged into `main` with their final gates and
the full e2e suites green: traffic counters and `EngineHandle::status`; the ns M4 engine hooks
(`inject_outbound_on`, `PacketFilter::inbound_from`, `observe_every_message`,
`force_handshake_on`, netstack accept backpressure and ports); the ns data-plane moves (plan
`20261003-1600`: netstack ownership, reassembly, send progress; UDP side channel and
`LinkTransport`; `Nat64Lan` and `Redirect`); throughput and WSS (plan `20261003-1630`:
benchmark harness, engine fast path +17 % / +19 %, netstack fixes, `nsplane-wss`); the ACL and
node L3 gate (plan `20261003-2300`, differential fixtures against ns); the local side (plan
`20261003-2330`: graph primitives, `Masquerade`, Echo reply, `TunSlot`, `host_tun`). ADR
`2026-10-03-data-channel-protocols-in-nsplane`: every data-channel protocol lives in nsplane.

## 2026-10-04 11:00 [release]

Release 0.8.0 (tag `v0.8.0`), the first release under the nsplane name. Quiet-host comparison
on main: nsplane <-> nsplane 8.1 / 8.9 Gbit/s (1 / 4 TCP streams), kernel WireGuard ->
nsplane 7.0, nsplane -> kernel 7.7, wireguard-go 10.0 / 10.1.

## 2026-10-04 15:30 [release]

Release 0.9.0 (tag `v0.9.0`): the remaining ns requests (plan `20261004-1100-ns-requests`,
campaigns RN, RW, RA, RS, RX), all additive. Next: the optimization round (quiet-host
re-measure, multi-stream throughput against wireguard-go, netstack 4-stream anomaly).

## 2026-10-05 20:30 [release]

Release 0.10.0 (tag `v0.10.0`): the optimization round (plan `20261004-1730-optimization`,
campaigns OE, ON, OH). Quiet harness against 0.9.0 main: default 9.60 / 10.39 -> 10.33 /
11.38 Gbit/s (1 / 4 TCP streams), two crypto workers 8.39 / 8.58 -> 11.67 / 12.65, sender CPU
1.24 -> 0.94 s/GB; netstack 6.21 / 2.48 -> 6.85 / 7.29. Next: the deferred ns requests (MF-4,
MF-5, MW-7, MB-x7, MQ-17) and the round's follow-ups.

## 2026-10-06 13:00 [decision]

ADR `2026-10-06-business-agnostic-scope` (owner): nsplane stays a business-agnostic data
plane that ns and other products use. The ACL works on flows, opaque labels and rule IDs, and
product policy is compiled above it. nsgw's requests (docs site `nsgw/next.md` L2, L4, L5, L6)
are recorded in generic form in task `20261006-1300-nsgw-requests`, with what is not planned
and why.

## 2026-10-06 08:00 [release]

Release 0.10.1 (tag `v0.10.1`, branch `release/0.10.x` from v0.10.0). It carries one fix: with
`crypto_workers >= 2`, seals in flight count against the local room, so a full transmit queue
holds back the source instead of dropping. Found by QE-6, campaign `nsplane-q2-202610060900`.

## 2026-10-08 06:00 [release]

Release 0.11.0 (tag `v0.11.0`). It is breaking: nsplane is business-agnostic (ADR
`2026-10-06-business-agnostic-scope`), and the products implement the removed concepts from
`docs/specs/`. The release table is in README Performance. A F1 re-check against 0.10.1 shows
nsplane -> kernel WireGuard at par.

## 2026-10-08 07:00 [decision]

Feature freeze at 0.11.x (ADR `2026-10-08-feature-freeze-0-11`, owner): only bug fixes until
ns and nsgw are integrated.

## 2026-10-12 [release]

Release 0.12.0 (tag `v0.12.0`): local identities, the one feature the owner exempted from the
0.11 freeze. The freeze applies again: bug fixes only.

## 2026-10-12 [release]

Release 0.13.0 (tag `v0.13.0`):
- a peer-keyed, address-family-agnostic flow gate, the second feature the owner exempted from
  the freeze;
- the removal of `arc-swap`, a soundness fix.

The quiet performance pass of both items is pending. The freeze applies again: bug fixes only.

## 2026-10-13 [release]

Release 0.14.0 (tag `v0.14.0`):
- LAN prefix mappings and cryptokey routing per local identity, the third exemption from the
  freeze;
- the fix of the 0.13.0 snapshot-cell read cost.

The remaining performance residuals are tracked in task `20261013-1600-perf-residuals`, to be
fixed as bugs. The freeze applies again: bug fixes only.

## 2026-10-15 [release]

Release 0.14.1 (tag `v0.14.1`), bug fixes only:
- the snapshot cell calls the read closure from one site, so the gate and translator bodies
  inline into their callers again: gate `established/*` 13-20 % and translate 0-9 % below
  0.12.0;
- the later-fragment early return of the inbound ACL path is back to its 0.13.0 cost;
- rustls 0.23.46 in `Cargo.lock` for RUSTSEC-2026-0346 to -0349.

Task `20261013-1600-perf-residuals` keeps PR-3 (two-identity routing cost) open. The freeze
applies: bug fixes only.

## 2026-10-17 [release]

Release 0.14.2 (tag `v0.14.2`), the fourth exception to the freeze (plan
`20261016-1800-route-lookup`), with the public API unchanged:
- allowed-IP tables run a binary search on the prefix lengths in use: one lookup on 10 k
  networks drops from 48 to 16 ns (IPv4) and from 175 to 26 ns (IPv6);
- a per-core route cache of 64 entries, invalidated by every routing change;
- writes at prefix lengths in use update in place; a new or emptied length rebuilds its family
  once per change.

`core_round_trip` 64 B drops from 531 to 417 ns, and the two-identity case from 594 to 421 ns,
which closes PR-3 of task `20261013-1600-perf-residuals`. The freeze applies again: bug fixes
only.

## 2026-10-17 [release] 0.15.0

Release 0.15.0 (tag `v0.15.0`), the fifth exception to the freeze (plan
`20261017-1300-nested-lan-prefixes`, from the ns gateway-as-node plan), additive:
- `TranslationTableBuilder::nested_lans` lets LAN prefixes nest, so a default `0.0.0.0/0`
  behind one peer coexists with more specific prefixes; the longest prefix wins and exact
  addresses (self `eam4`, `eam4`, `peer6_eam4`) win over every prefix;
- a reply under a shorter prefix's /96 that claims a more specific or exact address is dropped;
- `Nat64LanConfig::nested_routes` does the same for `Nat64Lan` routes.

Strict mode stays the default and unchanged. The freeze applies again: bug fixes only.

## 2026-10-17 [release] 0.16.0

Release 0.16.0 (tag `v0.16.0`), the sixth exception to the freeze (plan
`20261017-1800-flow-retirement`, R1 and R2 of task `20261017-1700-flow-lifecycle-request`),
additive:
- `control()` on `TcpConnection`, `UdpFlow`, `UdpReply` and `UdpSocket` returns a `FlowControl`;
  `revoke` is idempotent, sends no FIN or RST, fails the flow's handles and removes only that
  flow's state and queued output from a shared stack;
- `RetirementReceipt` reports `Retired`, `Failed` or `Unknown`, with a cancellation-safe,
  repeatable `wait`; the proof boundary is the stack;
- `bind_context(domain)` attaches an opaque `FlowContext` whose instance is never handed out twice;
- `NetStackHandle::retired_drops` counts output discarded for revoked flows.

Accepted residual: multi-flow UDP send +4.1 % in the netstack micro bench, every other path at
par. R3 (delivery gates) is deferred. The freeze applies again: bug fixes only.

## 2026-10-18 [docs] Documentation standard

Plan `20261018-1000-doc-system` (owner: "可以一起做，完成到D5，不需要L2，你直接做就可以了"),
executed by L1 directly on branch `doc-system`:
- `docs/README.md`: index, document classes, writing rules, templates, delivery table;
- `scripts/check-docs.sh` in `just check` (`just docs`): wording, links, reference coverage;
- usage guide in English and Chinese; its complete program runs as a doctest of
  `nsplane-examples`, fragments are `rust ignore`;
- `docs/reference/<crate>.md` for the eleven published crates, `docs/performance.md` with the
  current numbers, `docs/architecture.md` reduced to the cross-crate design;
  `docs/design.md` removed;
- specs in present tense with the spec header; the generic ACL API design note moved to
  `docs/plan/20261007-0900-business-agnostic-acl-api.md`; eleven ADRs on one header format;
- code comments without plan ids, versions or intentions.

The removed measurement history stays in git and in the plans that produced it.

## 2026-10-18 [release] 0.16.1

Release 0.16.1 (tag `v0.16.1`) on the owner's "合并推送发新版本": the documentation standard of
plan `20261018-1000-doc-system` (merge 24be670). Docs and comments only; no API or behavior
change, so the freeze is not affected.

## 2026-10-20 11:54 [progress]

The owner approved task `20261020-1000-macos-quality-gates` after the UDP repair review.
Plan `20261020-1154-macos-quality-gates` repairs the native macOS gate fixtures and
documentation checker on `fix/udp-icmp-isolation`, without merging or releasing.
The CLI tests use a valid platform interface name and require descriptor validation;
the slot fixture still checks MTU + 1 and truncated oversized reads, exact drop counts,
and subsequent valid packets. The checker supports system Bash 3.2 and native awk,
including empty source and decision-document arrays.

Validation: native macOS `just check` exited 0 (1909 tests passed, 8 configured skips);
the focused CLI/TUN suites passed 85 tests. Documentation self-tests passed with system
Bash 3.2/native awk, the installed Bash, and Linux Bash/awk. The task and plan are
completed; runtime and dependency files are unchanged.

## 2026-10-20 12:24 [progress]

The owner approved task `20261020-1224-darwin-utun-name` for the v0.16.2 release.
The Darwin backend checks the peer address family and registered utun controller
before reading UTUN_OPT_IFNAME. Unix datagram and stream regressions failed on the
old code and pass after the fix; connected UDP is also rejected. Adopted descriptors
retain packet transport and their supplied MTU when interface lookup is unavailable.
A privileged smoke test covers real utun creation, adoption and split.

Validation completed: native macOS just check passed with 1912 tests and 9 configured
skips. The new privileged real-utun smoke passed separately with system authentication.
The task and plan are complete; the reviewed patch has no additional findings.

## 2026-10-20 [release]

Prepare 0.16.2 (tag `v0.16.2`) after the owner merged the UDP repair branch and
approved release. This patch includes UDP asynchronous error isolation, Darwin
utun descriptor validation, synchronized replay/WSS fixtures, and native macOS
quality-gate portability fixes. Workspace versions, internal requirements and
guide examples are updated together; there is no public API change.
The owner explicitly approved the historical `release: 0.16.2` commit title as a
one-time exception to the local cog type allowlist; hooks and permanent rules
remain unchanged.

## 2026-10-24 [release]

Prepare 0.17.0 (tag `v0.17.0`), the seventh freeze exception (plan
`20261024-1600-egress-0-17`, task `20261024-1500-gino-egress-requests`). Three workstreams ran
as an auto-mode BKD campaign (`l1-7f5cstru-20261024-egress017`) and were merged by L1 after
review and a green full gate each:

- W1: transparent termination in nsplane-netstack (prefixes, immediate or decided
  admission with a bounded pending table, RST / ICMP rejects from the dialed address,
  connection limit, counters) and opt-in rate-limited flow decision events from the stack
  and from `FlowGate`. Two A/B rounds found and fixed off-path regressions (FlowGate event
  emission inlined into the hot path; LTO outlining checksum and payload helpers once the
  transparent paths added callers). The remaining multi-threaded four-stream TCP send delta
  (about 4.5 %, fewer instructions at equal IPC, single-CPU at par) was accepted as
  scheduling and layout noise.
- W2: nsplane-ether, an ethernet adapter for one guest with ARP, IPv6 ND / RA and a
  single-lease DHCPv4 server over a length-prefixed stream or a Linux TAP device, verified
  with a real QEMU/KVM guest.
- W3: nsplane-dns, generic DNS serving (codec, `Resolver` trait, static records, fake-address
  pool with reverse lookup, forwarder, UDP/TCP server on sockets or netstack flows). The codec
  is `simple-dns` from `github.com/dotns/simple-dns`, an independent copy maintained by
  dotns with only the protocol crate (tag `v0.12.0-nsplane.3`; ADR
  `2026-10-24-simple-dns-fork`). This partly reverses the 2026-10-15 decision: resolution
  policy stays with the consumer.

Baseline fixes on the way: `rustls-webpki` and `tokio` updated for RUSTSEC-2026-0382 and
RUSTSEC-2026-0386, and nsplane-tun moved to `AsyncFd::register` for tokio 1.54. R5 and R6 of
the request are not done. Known flaky timing tests (`netstack_flow_retirement`,
`netstack_lossy`) failed once each under host load during subtask gates and passed on re-run.

## 2026-10-24 [release]

Prepare 0.18.0 (tag `v0.18.0`), the eighth freeze exception. Four single-issue BKD
workstreams reported to L1, which reviewed each branch and merged it after a green full gate:

- DNS transparent forwarding (plan `20261024-1304-dns-passthrough`): messages nsplane-dns does
  not answer itself (other opcodes, other question counts, records it cannot parse) go to a
  `Forwarder` byte for byte under a `PassthroughPolicy`; the codec parses leniently
  (`simple-dns` tag `v0.12.0-nsplane.4`). The upstream OPT TTL layout is a recorded
  follow-up.
- DNS policy routing (plan `20261024-1313-dns-policy`): `PolicyResolver` with exact, suffix,
  wildcard and default rules, local actions, bounded CNAME chains, `NXDOMAIN` fallback,
  hosts-format text and atomic replacement.
- VM to WireGuard example (plan `20261024-1329-vm-wireguard-example`): `vm_wireguard`,
  verified in process and with a QEMU/KVM guest against wireguard-go, including the ACL. The
  real-guest run found that an accepted outbound echo request did not allow its reply
  unless other-protocol settings were present; fixed in nsplane-acl.
- AF_PACKET frame transport (plan `20261024-1338-af-packet-transport`): `PacketSocket` and
  `ensure_tap` in nsplane-ether for guests whose TAP another process holds, verified with a
  Firecracker/KVM guest against wireguard-go; the virtio-net segmentation moved to
  `nsplane_packet::vnet`. An interleaved A/B on the bench slots measured the TUN offload
  segment and coalesce paths about 28 % faster.

The `simple-dns` protocol crate moved into this repository (`third_party/simple-dns`, plan
`20261024-1437-simple-dns-in-tree`, ADR `2026-10-24-simple-dns-in-tree`) before the release;
`github.com/dotns/simple-dns` is archived.

One run of the release gate failed in
`udp::tests::icmp_recovery_preserves_partial_batches_and_real_errors` (loopback ICMP error
timing under full parallel load); it passed 50 of 50 stress runs alone and the re-run of the
full gate was green.

## 2026-10-24 [release]

Prepare 0.19.0 (tag `v0.19.0`), freeze exceptions nine and ten. Two single-issue BKD
workstreams reported to L1, which reviewed each branch and merged it after a green full gate:

- Neighbor proxy in nsplane-ether (plan `20261024-1454-ether-proxy-arp`): the adapter answers
  ARP and IPv6 neighbor solicitations for every routable address of the guest's link but the
  guest's own, so hosts of the leased prefix other than the gateway are reachable; duplicate
  address detection is never answered. Verified with QEMU and Firecracker guests against
  wireguard-go.
- smoltcp fork on upstream `main` (plan `20261024-1453-smoltcp-upstream-fixes`): tag
  `v0.14.0-nsplane.7` on upstream `24bda3b`, nine fork patches kept, two dropped in favor of
  upstream's equivalent fixes, the tail loss probe reduced to yield to a lower RTO;
  `NetStackConfig::tcp_min_rto` / `tcp_initial_rto` expose upstream's per-socket RTO settings.
  Interleaved A/B on the bench slots: loss-free and bottleneck throughput unchanged, lossy
  medians better, TCP send microbenchmarks about 1-2 % slower (reproducible, not caused by the
  Cubic change; accepted).

## 2026-10-25 [fix]

Revoke reply allowances of rule-accepted flows (task and plan
`20261024-2224-acl-rule-reply-revocation`, GitHub issue #8). A reply allowance recorded for an
inbound flow accepted by an ordinary rule had no dependency and survived policy and identity
changes. Such allowances now carry the flow as their dependency and are re-evaluated after any
generation change; new inbound allowances without a pending dependency derive it once from the
inbound policy. A first version that recorded the dependency on every inbound packet cost up
to +50 ns per packet and was replaced; the shipped version measured (slot 0, interleaved A/B
against main) +1.5 to +3 ns on established inbound flows, +4 to +10 % on new flows and -17 %
on repeated outbound packets.

## 2026-10-25 [release]

Prepare 0.19.1 (tag `v0.19.1`) at the owner's request: the reply allowance revocation fix
(task `20261024-2224-acl-rule-reply-revocation`, GitHub issue #8) and two additive queries
merged from the peer session readiness branch (`peer_has_session`, `NetStackSource::tcp_egress_drained`).
Workspace versions, internal requirements and guide tags synchronized.

## 2026-10-26 [release]

Prepare 0.19.2 (tag `v0.19.2`) at the owner's request: nsplane-tun and nsplane-ether declare
`tokio` 1.54.0, the first release with `AsyncFd::register` (a consumer locked to 1.53 failed to
compile them), and nsplane-noise logs the routine handshake timer events at debug instead of
warn / error (a server with about 110 clients logged some 380 such lines per 30 minutes at the
info level). Workspace versions, internal requirements and guide tags synchronized.

## 2026-10-26 [release]

Prepare 0.19.3 (tag `v0.19.3`) at the owner's request: nsplane-ether and nsplane-tun build for
Linux musl targets (`msg_iovlen` and the `ioctl` request type differ between glibc and musl), and
`just cross` runs clippy for `x86_64-unknown-linux-musl`. Also carries the module splits of
nsplane-core `core.rs` and nsplane-netstack `stack.rs` (pure moves, no API change). Workspace
versions, internal requirements and guide tags synchronized.

## 2026-10-26 08:34 [decision]

Owner decisions on plan `20261026-0822-node-gateway-requests` (task
`20261026-0819-node-gateway-requests`): release A (0.19.3, the vnet IPv4 IHL 10 and `walk_v6`
later-fragment fixes, including the latter's behaviour change) approved as a bug-fix release;
release B (0.20.0: netstack control from the first input, scoped flow-gate decisions, the local
barrier and validated plaintext ingress) approved as the eleventh freeze exception with the
plan's shapes and the recommended answers to O1-O7; release C (0.21.0: netstack ingress labels,
plaintext egress, send receipts) is designed first as one carrier, the packet tag, in a design
note for owner and consumer review, and is not implemented.

## 2026-10-26 [fix]

Fix the two defects of release A (0.19.4), plan `20261026-0822-node-gateway-requests`
(task `20261026-0851-vnet-walk-v6-fixes`), each with its regression test first:

- `vnet::segment` segmented an IPv4 super-packet with IHL 10 as IPv6, because `fix_segment` and
  `pseudo_sum` chose by header length; they now take the IP version. `nsplane-tun`'s coalescer
  keeps the version per group for the same choice (unreachable before: it merges only
  option-less IPv4 headers).
- The flow gate's `walk_v6` ran nine iterations and returned on a later Fragment header, so a
  ninth header passed; the ninth extension header of any kind is now malformed.

Slot A/B against `main`, interleaved, slot 1: `vnet/segment_tcpv4_64k` 3.185 vs 3.183 us (mean
of 3 rounds); `offload/coalesce_tcpv4_48` no regression (B at or below A in all 5 rounds, the
spread too wide to claim a gain); gate `established/*`, `baseline/pass_gate` and the IPv6 cases
within the round-to-round noise. A first `walk_v6` that left the loop with `break` and checked
the next header after it cost `icmp_error/v6` +4 ns (48 to 53 ns, two rounds); the shipped
version keeps the original loop and adds one bound check per header (48.0 / 48.3 ns against
48.9 / 47.9 ns).

## 2026-10-27 [decision]

Owner decision on plan `20261026-0822-node-gateway-requests`: `main` moved to `fb67db9` (0.19.3
released upstream, then the large module split), so release A becomes 0.19.4, and the plan,
release A and the release B workstreams are rebased onto `fb67db9` as new branches and release
B is integrated again; the branches go to the Gitea remote only.

## 2026-10-27 [release]

Prepare 0.20.0 (not tagged) on `fb67db9`, release B of plan
`20261026-0822-node-gateway-requests` under the eleventh freeze exception (ADR
`2026-10-08-feature-freeze-0-11` amended): scope-qualified flow gate decisions (task
`20261026-0837-scoped-flowgate`), the engine's local barrier and validated plaintext ingress
(task `20261026-0836-local-barrier-plaintext-ingress`), netstack control from the first input
with admission on every stack (task `20261026-0838-first-input-flow-control`), and the fixes of
release A, 0.19.4 (task `20261026-0851-vnet-walk-v6-fixes`). Each branch was rebased onto
`fb67db9` first, its changes moved into the modules of the split; merged in the order plan, A,
W2, W3, W1 on `release/0.20.0-v2`, where the conflicts were the changelogs and the task index
only. Breaking: `NetStackConfig`, `NetStackStats`, `TransparentConfig`, `FlowEventsConfig` and
`PendingProtocol` are `#[non_exhaustive]`. The 0.19.4 section of `CHANGELOG.md` stays as
prepared, unreleased; 0.20.0 lists its fixes under Fixed. Slot A/B of the integrated head
against `fb67db9` (`docs/performance.md`, "0.20.0 against 0.19.3"): the gate's established paths
+1.2 % / +2.0 % (the scoped check, as on its branch); `core_round_trip/1420` +1.7 % (+20 ns,
reproducible; 64-byte and batched round trips unchanged), open; `send_stream` and `local_graph`
within the noise.

## 2026-10-27 [investigation]

`core_round_trip/1420` +20 ns at 0.20.0 against 0.19.3: code placement, not added work. Bisected
by workstream on a quiet host: the bench binaries of release A, W2 and W1 equal `fb67db9`'s, W3
alone and every merge before the version commit measure as `fb67db9`, and the cost appears with
the version commit only; the same source at version 0.20.1 is 1 % faster than 0.19.3, and
`fb67db9` at version 0.20.0 is unchanged. The version enters every symbol hash and moves the
code: `objdump` shows the same instructions (526,948, equal function lengths, differences only
in RIP-relative offsets) and the bench's round-trip routines at another 16-byte offset. No
change made (`docs/performance.md`, "0.20.0 against 0.19.3"). `perf` and `valgrind` are not
available on the host, so instruction counts come from the disassembly, not from counters.

## 2026-10-27 [release]

Release 0.20.0 (tag `v0.20.0`) at the owner's request: release B of plan
`20261026-0822-node-gateway-requests` (netstack control from the first input with admission on
every stack, scope-qualified flow gate decisions, the engine's local barrier and validated
plaintext ingress; five netstack types `#[non_exhaustive]`) and release A, whose two fixes (IPv4
GSO segmentation with IHL 10, the `walk_v6` later-fragment header limit) ship in 0.20.0; 0.19.4
is not released separately and its changelog section is folded into 0.20.0. `main` fast-forwards
to the release head. Workspace versions, internal requirements and guide tags were synchronized
in the version commit.

## 2026-10-27 [decision]

The owner lifted the 0.11 feature freeze: normal maintenance, with breaking public API changes
called out in the plan and in the CHANGELOG (ADR `2026-10-27-normal-maintenance`, superseding
`2026-10-08-feature-freeze-0-11`).
