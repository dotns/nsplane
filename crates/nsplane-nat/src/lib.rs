#![forbid(unsafe_code)]

//! IPv4/IPv6 translation and service-publishing NAT packet filters for nsplane.
//!
//! Applications that only speak IPv4 reach IPv6-only peers through local
//! aliases: every peer owns a /127 IPv6 group (`node6` and `node4`), and this
//! node presents it as an IPv6 alias (`alias6 <-> node6`) and an IPv4 alias
//! (`alias4 <-> node4`). The node itself is reachable as `self4 <-> node4`,
//! and IPv4 LAN prefixes map to IPv6 /96 prefixes by placing the IPv4 address
//! in the low 32 bits (`lan4 <-> lan6`).
//!
//! - **Translation table** ([`TranslationTable`]): the immutable, validated
//!   address model above, with O(1) / O(log n) lookups. Built with
//!   [`TranslationTableBuilder`]; replaced as a whole when the model changes.
//! - **Translator** ([`translate`]): a stateless IPv4 <-> IPv6 translation
//!   filter (RFC 7915 style, including ICMP/ICMPv6 and ICMP error inner
//!   packets) driven by a [`TranslationTable`], as an
//!   `nsplane_core::PacketFilter`.
//! - **Conntrack and port map** ([`conntrack`], [`port_map`]): a bounded
//!   connection table and the DNAT/SNAT filter that publishes local services,
//!   as an `nsplane_core::PacketFilter`.
//! - **Checksums** ([`checksum`]): RFC 1624 incremental checksum updates for
//!   rewritten words, addresses and pseudo-headers, plus the UDP zero
//!   checksum rule.

pub mod checksum;
pub mod conntrack;
pub mod port_map;
pub mod table;
pub mod translate;

pub use conntrack::{
    Conntrack, ConntrackConfig, ConntrackError, ConntrackStats, Flow, FlowDirection, FlowMatch,
    TcpState,
};
pub use port_map::{PortMap, PortMapError, PortMapProtocol, PortMapRule};
pub use table::{
    LanPrefix, PeerMapping, SelfMapping, TableError, TranslationTable, TranslationTableBuilder,
};
pub use translate::{Translator, TranslatorStats};
