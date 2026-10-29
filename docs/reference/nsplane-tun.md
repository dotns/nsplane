# nsplane-tun

OS TUN devices as the engine's local side: Linux, Android, macOS, iOS and Windows (through
Wintun), plus the fd slot for Android and the callback bridge for iOS. Builds on `nsplane`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| main | `Tun` (`create`, `create_with` (on Windows with the service TUN checks), `from_fd` / `from_raw_fd` on Unix, `split`, `offload`, `mtu`, `name`), `TunSlot` (`new`, `replace`, `clear`, `disable`, `enable`, `close`; Linux, Android, macOS, iOS), `host_tun` | `TunOptions` (Windows: `wintun_pin`, `exclusive`, `mtu`), `WintunPin` and `WintunError` (Windows), `TunSource` (`name`; `recycle`, on Windows too), `TunSink` (`name`), `Offload`, `adopt_fd` (Unix), `MTU_POLL_INTERVAL`; `SlotSource` (`oversize_drops`, `recycle`), `SlotSink`; `HostTunInput` (`push`), `HostTunSource` (`set_mtu`, `oversize_drops`, `recycle`), `HostTunSink`, `PushError`, `HOST_TUN_DEFAULT_CAPACITY` |

## Behavior

### Devices and names

`Tun::create` opens a TUN device, `Tun::from_fd` / `from_raw_fd` (Unix) adopt one, and
`Tun::split` yields a `TunSource` and a `TunSink` registered with the tokio reactor.
`Tun::name` and, after the split, `TunSource::name` / `TunSink::name` query the interface
name from the device (the kernel-assigned one for a `"tun%d"` or `"utun"` pattern, the
adapter alias on Windows). nsplane does not configure addresses, routes or DNS of the device.

- Linux and Android: `/dev/net/tun`, raw IP packets, or with `IFF_VNET_HDR` a 10-byte
  virtio-net header per read and write.
- macOS and iOS: the utun control socket, packets framed by a 4-byte address-family header.
- Unix: non-blocking fd I/O shared by both.
- Windows: a Wintun adapter; a reader thread feeds the source, so there is no fd.

### Offload (Linux, Android)

`Tun::create` opens the device with the virtio-net header and turns on TSO and USO where the
kernel supports them; `Tun::offload` reports what is on. The codec segments read
super-packets (GSO) and coalesces TCP and UDP writes (one `writev` of header and packet pieces
per super-packet). Segments are appended with `PacketBuf::extend_from_slice`, without
zero-filling first. Writes coalesce only the packets of the batch they are handed, and a
read returns what one receive yields.

### Buffers

`TunSource`, `SlotSource` and the Wintun reader size every read for the MTU, the translation
slack and `TAILROOM` behind the packet, so the core seals a full-size packet in place without
reallocating. `TunSource` implements `PacketSource::recycle`: the engine hands transmitted
buffers back and the source keeps them in its pool up to its bound, so reads stop allocating;
pooled buffers keep their initialized bytes and are not zero-filled again. `SlotSource` does
the same (up to 64 idle buffers). The Wintun `TunSource` hands them to the reader thread over
a 64-slot channel and the thread keeps up to 64 idle ones; excess buffers are dropped and
neither side waits.

`TunSource::recv_batch` keeps reading without waiting after the first packet, until
`EAGAIN`, a full batch or a split GSO read, so plain packets come in batches; a lone packet
returns at once.

### Windows service checks

`Tun::create_with(name, options)` adds opt-in checks; `Tun::create` loads `wintun.dll`
through the loader's search path and opens or creates the adapter. In order:

1. The MTU is validated: below 576 is `InvalidInput`.
2. With `TunOptions::wintun_pin(WintunPin)` the file at the pin's path (default
   `wintun.dll` next to the executable, made absolute) is read (at most 16 MiB) and its
   SHA-256 compared before any DLL code is loaded; then that absolute path is loaded. A
   missing file is `NotFound` with the wintun.net remedy (`bin\<arch>\wintun.dll`, elevated
   terminal), a mismatch `WintunError::HashMismatch`. The file can still be replaced between
   check and load, so it must sit in a directory only administrators can write.
3. With `exclusive(true)` a live Wintun adapter (`Adapter::open` succeeds; that handle is
   only closed) or any present interface with that alias (`ConvertInterfaceAliasToLuid`) is
   refused with `WintunError::AdapterExists`.
4. With either setting an orphan is replaced: the name resolves to a LUID whose interface is
   not present (`GetIfEntry2` reports `NotPresent` or has no row), the device of a process
   that died without closing its adapter. The handle is closed, the adapter created, and the
   assigned alias must equal the name, else the new adapter is removed and
   `WintunError::OrphanNotReplaced` returned. A present device (any other `OperStatus`,
   `Down` included) stands for a live owner; on the default path a failed IP Helper query
   counts as present.
5. Once the adapter is open, a pinned `driver_version` is compared with the running driver
   (`WintunError::DriverVersionMismatch`; dropping the handle removes an adapter this call
   created), then the session starts.
6. Only then `mtu(n)` sets the interface MTU (`SetIpInterfaceEntry` `NlMtu`) on IPv4 and
   IPv6. A new adapter creates its IP interface rows asynchronously, so the call polls every
   50 ms for the IPv4 row (5 s, else `TimedOut`) and then up to 500 ms for the IPv6 row
   (still absent: IPv6 counts as disabled and is skipped). Both are read back; a difference
   fails with `WintunError::MtuMismatch` (session and adapter dropped, a created adapter
   removed), and `Tun::mtu` reports the checked value. Without `mtu(n)` nothing waits and
   `Tun::mtu` is the IPv4 MTU read once.

The typed errors travel inside `io::Error` (`InvalidData`, `AlreadyExists`) and are recovered
with `downcast_ref::<WintunError>()`. The decisions (`Existing`, `classify`, `plan`,
`wait_for`, `check_mtu`) are pure functions in the `wintun` module.

### `TunSlot` (Android)

`TunSlot` is an fd local side the host swaps while the engine runs (Android `VpnService`).
`TunSlot::new(mtu)` returns the control handle, a `SlotSource` and a `SlotSink`; it is built
on Linux, Android, macOS and iOS.

- Fencing: every read and write runs under a shared lock and only if the fd it waited on is
  still installed (a generation counter); `replace`, `clear` and `close` take the lock
  exclusively and bump the generation. Once `replace(fd)` returns no syscall runs on the
  previous fd; a read completed on it but not returned yet is discarded and retried on the
  new one; the old fd closes when no I/O holds it.
- `disable` parks reads and writes until `enable`. `clear` removes the fd with the same
  fencing and keeps the slot open: reads and writes wait for the next `replace`. `close`, or
  dropping the last handle, fails the source, the sink and later `replace` calls with
  `BrokenPipe`.
- Reads get an MTU + 1 buffer: a longer read is dropped and counted
  (`SlotSource::oversize_drops`), a 0-byte read is `UnexpectedEof`. Each packet is one write
  without header; a short write is `WriteZero`. No offloads; the MTU watch keeps the value
  given to `new`.
- `SlotSink::send_batch_spent` writes the packets one at a time and appends each buffer once
  its write is done, written or failed, so a `pump` into the slot recycles them.
- The caller keeps its own generation numbering, attach and activate ordering and host-claim
  rules.

### `host_tun` (iOS and callback hosts)

`host_tun(mtu, capacity, write)` is a local side for hosts that hand packets over through
callbacks (iOS `NEPacketTunnelFlow`); it is platform-independent and returns a
`HostTunInput`, a `HostTunSource` and a `HostTunSink`.

- `HostTunInput::push` copies the packet once (`SharedPacketPool::alloc_from` on a pool of
  up to `capacity` idle buffers, refilled by `HostTunSource::recycle`) into a bounded queue
  of `capacity` packets (`HOST_TUN_DEFAULT_CAPACITY` = 4096) without blocking, from any
  thread, and fails with `PushError::Full` or `PushError::Closed` (source dropped).
- The source drops and counts packets longer than the MTU (`oversize_drops`), logging the
  first one, and returns `BrokenPipe` once every input is dropped and the queue is drained.
  `HostTunSource::set_mtu` changes the MTU: every packet read afterwards is checked against
  it, queued ones included; the value is published on the `PacketSource::mtu` watch only
  when it changes.
- The sink calls `write` synchronously on the engine task; `false` drops the packet and
  returns `BrokenPipe`.

## Configuration and defaults

| Feature | How to enable | Default | Cost when not enabled |
|---|---|---|---|
| Windows service TUN checks | `Tun::create_with(name, TunOptions::new().wintun_pin(pin).exclusive(true).mtu(n))` (Windows) | off: `wintun.dll` from the search path, an existing adapter opened, the MTU left as it is | none: `Tun::create` skips every check |
| TUN segmentation offload | `Tun::create` turns it on; `Tun::create_with(name, TunOptions::new().offload(false))` opts out; `Tun::offload` reports it | on where the kernel supports it (Linux, Android); macOS, iOS and Windows have none | off: one read or write system call per packet |

## Platform notes

- `unsafe` code lives only in this crate's platform modules (`unix`, `linux`, `darwin` and
  the Wintun loader), each with SAFETY comments.
- Windows needs `wintun.dll` next to the executable (or on the search path) and an elevated
  process. The pure Windows logic runs in Linux unit tests and the pin-before-load path under
  wine. Adapter creation, the exclusive refusal, orphan replacement, the MTU set and read-back,
  the driver version query and the Wintun buffer recycling have no automated test; they need
  a Windows host.

## See also

- [Usage guide: mobile](../guide.md#7-mobile-and-host-managed-devices)
- [nsplane](nsplane.md): `PacketSource` / `PacketSink`.
