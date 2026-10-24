//! Ethernet adapter for one guest: ethernet frames to IP packets, with ARP, IPv6 neighbor
//! discovery and router advertisements, and a single-lease `DHCPv4` server.
//!
//! The adapter stands in for the gateway on a point-to-point link to one guest (a virtual
//! machine or container speaking ethernet). This crate holds its protocol layer, which is
//! sans-I/O: pure parsers, frame builders and small state machines that take and return
//! bytes, with no sockets and no tasks.
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

pub mod arp;
pub mod dhcp;
pub mod frame;
pub mod mac;
pub mod ndp;
mod read;

pub use arp::{ArpError, ArpOp, ArpPacket};
pub use dhcp::{DhcpConfig, DhcpError, DhcpMessage, DhcpServer, MessageType};
pub use frame::{EtherType, Frame, FrameError};
pub use mac::MacAddr;
pub use ndp::{Ndp, NdpError, NdpMessage, RaConfig};
