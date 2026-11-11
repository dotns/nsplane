//! OS TUN devices as nsplane packet sources and sinks.
//!
//! [`Tun`] opens or adopts a TUN device; [`Tun::split`] registers it with the tokio
//! reactor and yields a [`TunSource`] (`nsplane::PacketSource`) and a [`TunSink`]
//! (`nsplane::PacketSink`) that share one non-blocking fd.
//!
//! Supported targets: Linux and Android (`/dev/net/tun`, raw IP packets), macOS and iOS
//! (utun control socket, packets framed by a 4-byte address-family header), and Windows
//! (a Wintun adapter; a reader thread feeds the source, so there is no fd). On every
//! other target only the host callback types are available.
//!
//! Offloads (Linux/Android): [`Tun::create`] opens the device with a virtio-net header
//! (`IFF_VNET_HDR`) and TCP segmentation offload, plus UDP segmentation offload where the
//! kernel supports it, so one read or write can carry up to 64 KiB of one flow: the
//! source splits such reads according to the kernel `gso_size` (the MTU-derived buffer
//! capacity is an allocation minimum, not a segment limit), and the sink coalesces runs of
//! packets into super-packets (`writev` of header and pieces, no copy). Kernels without
//! these features get a plain device. `Tun::create_with` with `TunOptions::offload(false)`
//! opts out, and `Tun::offload` reports what is in use.
//!
//! Windows service TUN: `Tun::create_with` with `TunOptions` verifies `wintun.dll`
//! against a `WintunPin` SHA-256 digest before loading it and optionally verifies the
//! running driver version after opening or creating the adapter. It can refuse a live
//! adapter or interface of the same name (`exclusive`), replaces an
//! orphaned (non-present) one and sets the interface MTU; refusals are `WintunError`s
//! inside the `io::Error`.
//!
//! Adopted fds (Unix): `Tun::from_fd` takes an `OwnedFd`, so ownership of the fd is
//! explicit and the crate never closes an fd it was not given. A host that only has an fd
//! number (a parent process, Android `VpnService`) turns it into an `OwnedFd` itself, at
//! the one place that knows nothing else in the process uses that number.
//!
//! MTU: `TunSource`'s `mtu` watch follows the interface MTU. On Linux/Android and
//! macOS/iOS, `Tun::split` queries the MTU (`SIOCGIFMTU`) and spawns a tokio task that
//! polls it every `MTU_POLL_INTERVAL` (1 s) and publishes changes; periodic polling
//! needs neither netlink nor a routing socket. The task ends when the source and every
//! receiver are dropped, the device fd is closed, or the interface is gone. An adopted
//! fd whose interface name cannot be queried (not a TUN device) is not watched: its MTU
//! stays the value it was adopted with. On Windows the MTU is read once when the
//! Wintun adapter opens and is not watched.
//!
//! Hot-swappable fd (Linux, Android, macOS, iOS): `TunSlot::new` yields a control
//! handle, a `SlotSource` and a `SlotSink` that do I/O on whichever fd is installed,
//! for a host that replaces the fd while the engine runs (Android `VpnService`).
//! `TunSlot::replace` fences the previous fd, `disable`/`enable` park I/O, and `close`
//! ends both sides with `BrokenPipe`. Packets are read and written one at a time, without
//! header or offloads.
//!
//! Host callbacks (every target): [`host_tun`] yields a [`HostTunInput`] the host pushes
//! packets into from any thread, a [`HostTunSource`] the engine reads them from, and a
//! [`HostTunSink`] that hands the engine's packets to the host's `write` callback, as iOS
//! `NEPacketTunnelFlow` needs.
//!
//! `unsafe` is confined to the platform modules that perform syscalls (`unix`,
//! `linux`, `darwin`) and to loading the Wintun library (`windows`); see
//! `docs/decisions/2026-10-01-unsafe-code-in-boringtun.md`.

mod host;
pub use host::{
    HOST_TUN_DEFAULT_CAPACITY, HostTunInput, HostTunSink, HostTunSource, PushError, host_tun,
};

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
mod tun;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
mod unix;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android", test))]
mod offload;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod darwin;
#[cfg(any(target_os = "macos", target_os = "ios", test))]
mod utun;

#[cfg(windows)]
mod windows;
#[cfg(any(windows, test))]
mod wintun;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub use tun::{MTU_POLL_INTERVAL, Offload, Tun, TunOptions, TunSink, TunSource};
#[cfg(windows)]
pub use windows::{Tun, TunOptions, TunSink, TunSource};
// Public on Windows; also re-exported in Linux unit-test builds so the module's public
// items stay reachable there.
#[cfg(any(windows, test))]
pub use wintun::{WintunError, WintunPin};
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
mod slot;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub use slot::{SlotSink, SlotSource, TunSlot};
