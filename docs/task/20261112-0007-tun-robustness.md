# 20261112-0007-tun-robustness TUN robustness: DLL loading, MTU watching, read sizing, slot framing

- **status**: completed
- **priority**: P3
- **owner**: audit-fix
- **createdAt**: 2026-11-12 00:07

## Description

Six audited P3 items in `nsplane-tun`:

1. Windows: without `TunOptions::wintun_pin`, `wintun.dll` was loaded by bare name through the
   default DLL search order (current directory, `PATH`), in a process that runs elevated.
2. Unix: the MTU watcher tracked the interface by the name captured at `Tun::split` and ended
   silently after a rename.
3. Unix: a plain (non-offload) read was sized to the MTU known at the call, so a larger packet
   arriving within the 1 s poll window after an MTU increase was truncated by the OS.
4. `TunSlot` reads and writes bare packets but is built for macOS and iOS, where a utun fd
   frames every packet with a 4-byte address-family header.
5. `HostTunInput::push` took the packet buffer before checking whether the queue had room.
6. Windows: the MTU watch never changed after creation, and a full Wintun send ring surfaced
   as `WouldBlock` from the async `send`.

Acceptance: each item fixed with a test where one is feasible, no breaking API change, the
gates of the crate pass on Linux, macOS (clippy) and Windows (clippy, unit tests under wine).

## ActiveForm

Fixing the audited robustness items of the TUN crate.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

One commit per item.

1. Unpinned `wintun.dll`: the path is resolved explicitly, first next to the executable
   (`current_exe`, the same helper the pin uses), then in the system directory
   (`GetSystemDirectoryW`; the `Win32_System_SystemInformation` feature of the `windows-sys`
   version already in the lock file, no new crate), nothing else, and loaded with
   `load_from_path`. Neither present: `NotFound` naming both paths and the wintun.net remedy.
   The SAFETY comment now says what holds: the origin of the file is fixed, its bytes are
   verified only with a pin. Behavior change: a `wintun.dll` reachable only through the
   current directory or `PATH` is no longer found. Not changed: the Windows loader still
   resolves the libraries `wintun.dll` imports by its own order (application directory, then
   system directory) for the pinned and the unpinned path alike; restricting that needs
   `LoadLibraryExW` flags, which `wintun-bindings` does not expose without a direct
   `libloading` dependency. ADR `2026-10-01-wintun.md` still says "or on the DLL search path";
   it is a dated record and was left as it is.
2. The watcher keeps no name: every poll asks the fd for its interface name (`TUNGETIFF`,
   `UTUN_OPT_IFNAME`) and then queries the MTU, so it follows renames on Linux and needs no
   interface index. A failed query is retried once at once (a rename between the two calls);
   a second failure logs one warning and ends the task, the watch keeping the last value.
   The task holds the fd only for the duration of a poll, so closing the device still ends it.
3. A plain `TunSource` reads with `readv` into the MTU-sized pooled buffer and, past its end,
   into one 65535-byte spill buffer it owns. A packet that fits is returned in place as
   before (no copy); a longer one is copied into a pooled buffer sized for it, with the same
   translation slack and tail room. Memory: 64 KiB per plain source for its lifetime, nothing
   per packet; an offload source allocates no spill buffer (it reads through the 64 KiB
   buffer it already had). Sizing every pooled buffer to 65535 bytes was rejected: each queued
   packet would pin 64 KiB and a buffer that is not recycled would cost a 64 KiB allocation
   and zero-fill per packet. Throughput was not measured: the hot path differs by one more
   `iovec` in the read call (on macOS and iOS the read was a `readv` already).
   `SlotSource` is unchanged: it has no watcher and its documented behavior is to drop and
   count reads longer than its fixed MTU.
4. `TunSlot` is not gated to Linux and Android: it is documented as built for macOS and iOS
   (crate docs, reference) and its integration tests run there over datagram socket pairs,
   so removing it would break that target's API. Instead `TunSlot::replace` checks on macOS
   and iOS whether the fd is a utun socket (the same check `Tun::name` uses); if so the
   source strips and the sink adds the header through the functions `Tun` uses, and a packet
   that is neither IPv4 nor IPv6 fails with `InvalidInput`. Any other fd stays bare, so the
   socket pair use keeps working. Unconditional framing on Apple targets was rejected for
   that reason.
5. `push` reserves the queue slot (`try_reserve`) before it takes a buffer.
6. MTU: `Tun::split` starts a thread (`nsplane-tun-mtu`) that reads the IPv4 `NlMtu` with the
   module's existing `GetIpInterfaceEntry` call every `MTU_POLL_INTERVAL` (now exported on
   Windows too); a thread, because the Windows `split` does not need a tokio runtime and a
   task would add that requirement. No IPv4 row keeps the value, a failed query logs one
   warning and ends the thread, and dropping the last half stops and joins it. Ring full: the
   `PacketSink` contract names `WouldBlock` only for `try_send_batch`; from `send` the engine
   (`engine/tasks.rs`, `engine/output.rs`) logs any error but `BrokenPipe` at warn per
   packet. The sink now drops the packet, counts it in the new `TunSink::ring_full_drops`,
   logs the first drop and returns `Ok`.

New public items (additive): `TunSink::ring_full_drops` and `MTU_POLL_INTERVAL` on Windows.

For the release notes:

- Windows: an unpinned `wintun.dll` is loaded only from next to the executable or from the
  system directory; one found through `PATH` or the current directory no longer loads.
- Windows: a full Wintun send ring no longer fails `send` with `WouldBlock`; the packet is
  dropped and counted. The MTU watch now follows the interface.
- macOS and iOS: a utun fd installed in a `TunSlot` is now framed; before, its header was
  delivered as packet bytes.
- Unix: a plain device returns a packet longer than the known MTU whole instead of truncated;
  the MTU watcher survives an interface rename and logs when it stops.

## Validation

Seen failing before the fix, passing after:

- `host::tests::push_into_a_full_queue_takes_no_buffer` (item 5).
- `linux_tun::tun_mtu_change_is_observed_after_a_rename` (item 2) and
  `linux_tun::plain_tun_read_after_an_mtu_increase_is_not_truncated` (item 3, read 1500 of
  9000 bytes before), both on a real TUN device in a container with `NET_ADMIN`,
  `/dev/net/tun` and `iproute2`. All ignored real-device tests of the crate pass (105 tests
  with `--run-ignored all`).
- `windows::tests::create_without_a_pin_ignores_the_current_directory` under wine (item 1):
  before, a file planted in the current directory was handed to `LoadLibraryExW`.

Without a failing run first:

- Item 6: `a_full_send_ring_is_a_counted_drop`, the `mtu_watcher_*` tests and the updated
  `send_errors_map_to_sink_contract` (it encoded the `WouldBlock` mapping) exercise new
  functions and pass under wine.
- Item 1: `wintun::tests::first_existing_*` (also run on Linux) and
  `windows::tests::system_directory_is_absolute` (wine).

Only compiled, never run:

- Windows, for lack of a Wintun driver under wine: loading an unpinned `wintun.dll` that
  exists, the MTU watcher thread against a real adapter (its loop is tested with a fake
  query), and the full-ring path through a real session (its error mapping is tested).
- macOS and iOS, for lack of a host: the utun detection and framing of `TunSlot` and the
  three-part `readv` of the plain read (`cargo-zigbuild clippy` for `aarch64-apple-darwin`
  only).
