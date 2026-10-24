//! Ethernet adapter for one guest: ethernet frames to IP packets, with ARP, IPv6 neighbor
//! discovery and router advertisements, and a single-lease `DHCPv4` server.
//!
//! The adapter stands in for the gateway on a point-to-point link to one guest (a virtual
//! machine or container speaking ethernet). [`spawn_port`] runs it over a frame transport
//! and exposes the IP side as an [`nsplane::PacketSource`] and [`nsplane::PacketSink`], so a
//! user-space stack or an engine plugs in unchanged:
//!
//! - [`adapter`]: the sans-I/O core ([`EtherAdapter`], [`EtherConfig`], [`EtherStats`]):
//!   learns the guest MAC, answers ARP and neighbor discovery for the gateway and, as a
//!   neighbor proxy, for every other address but the guest's, answers DHCP, and converts
//!   between frames and IP packets.
//! - [`port`]: the async ports ([`EtherSource`], [`EtherSink`], [`EtherHandle`]).
//! - [`transport`]: the frame transport traits ([`FrameRead`], [`FrameWrite`]);
//!   [`stream`] implements them over a length-prefixed byte stream (a Unix socket to passt,
//!   QEMU or libkrun), `tap` over a Linux TAP device and `packet` over a Linux `AF_PACKET`
//!   socket bound to an interface whose TAP another process holds; `tap` also creates such
//!   an interface.
//!
//! The protocol layer below the adapter is sans-I/O too: pure parsers, frame builders and
//! small state machines that take and return bytes.
//!
//! - [`frame`]: Ethernet II headers ([`Frame`], [`EtherType`]); 802.1Q tagged frames are
//!   reported as unsupported.
//! - [`arp`]: ARP for IPv4 over ethernet ([`ArpPacket`]) and replies for the gateway
//!   address; gratuitous announcements tell the guest's MAC.
//! - [`ndp`]: IPv6 neighbor discovery ([`Ndp`]): neighbor advertisements for the gateway
//!   addresses and router advertisements ([`RaConfig`]) with prefix, MTU and DNS options.
//! - [`dhcp`]: `DHCPv4` messages ([`DhcpMessage`]) and a [`DhcpServer`] that hands out exactly
//!   one lease ([`DhcpConfig`]).
//! - [`mac`]: MAC addresses ([`MacAddr`]) and the IPv6 addresses derived from them.
//!
//! Every parser is bounds-checked and returns an error on truncated or malformed input;
//! none panics.

pub mod adapter;
pub mod arp;
pub mod dhcp;
pub mod frame;
pub mod mac;
pub mod ndp;
#[cfg(target_os = "linux")]
pub mod packet;
pub mod port;
mod read;
pub mod stream;
#[cfg(target_os = "linux")]
pub mod tap;
pub mod transport;
#[cfg(target_os = "linux")]
mod vnet;

pub use adapter::{DEFAULT_MTU, EtherAdapter, EtherConfig, EtherStats};

pub use arp::{ArpError, ArpOp, ArpPacket};
pub use dhcp::{DhcpConfig, DhcpError, DhcpMessage, DhcpServer, MessageType};
pub use frame::{EtherType, Frame, FrameError};
pub use mac::MacAddr;
pub use ndp::{Ndp, NdpError, NdpMessage, RaConfig};
#[cfg(target_os = "linux")]
pub use packet::{PacketReader, PacketSocket, PacketWriter};
pub use port::{EtherHandle, EtherSink, EtherSource, spawn_port};
#[cfg(target_os = "linux")]
pub use tap::{TapConfig, TapDevice, TapInterface, TapReader, TapWriter, ensure_tap};
pub use transport::{FrameRead, FrameWrite, MAX_FRAME_LEN};
