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
pub use tun::{Tun, TunSink, TunSource};
#[cfg(windows)]
pub use windows::{Tun, TunSink, TunSource};
