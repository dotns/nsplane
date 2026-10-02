//! OS TUN devices as nsplane packet sources and sinks.
//!
//! [`Tun`] opens or adopts a TUN device; [`Tun::split`] registers it with the tokio
//! reactor and yields a [`TunSource`] (`nsplane::PacketSource`) and a [`TunSink`]
//! (`nsplane::PacketSink`) that share one non-blocking fd.
//!
//! Supported targets: Linux and Android (`/dev/net/tun`, raw IP packets), macOS and iOS
//! (utun control socket, packets framed by a 4-byte address-family header), and Windows
//! (a Wintun adapter; a reader thread feeds the source, so there is no fd). On every
//! other target the crate is empty for now.
//!
//! Offloads (Linux/Android): [`Tun::create`] opens the device with a virtio-net header
//! (`IFF_VNET_HDR`) and TCP segmentation offload, plus UDP segmentation offload where the
//! kernel supports it, so one read or write can carry up to 64 KiB of one flow: the
//! source splits such reads into MTU-sized packets, and the sink coalesces runs of
//! packets into super-packets (`writev` of header and pieces, no copy). Kernels without
//! these features get a plain device. `Tun::create_with` with `TunOptions::offload(false)`
//! opts out, and `Tun::offload` reports what is in use.
//!
//! Raw fds (Unix): `adopt_fd` and `Tun::from_raw_fd` adopt an fd passed in by number
//! (a parent process, the CLI's `--tun-fd` and `--uapi-fd`) so that callers need no
//! `unsafe`. Either call takes ownership: the fd must be one the process inherited or
//! otherwise owns, nothing else may use or close it afterwards, and it is closed when
//! the returned value drops. A negative number or one that is not an open fd is
//! rejected without adopting anything.
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
//! `unsafe` is confined to the platform modules that perform syscalls (`unix`,
//! `linux`, `darwin`) and to loading the Wintun library (`windows`); see
//! `docs/decisions/2026-10-01-unsafe-code-in-boringtun.md`.

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

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub use tun::{MTU_POLL_INTERVAL, Offload, Tun, TunOptions, TunSink, TunSource};
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub use unix::adopt_fd;
#[cfg(windows)]
pub use windows::{Tun, TunSink, TunSource};
