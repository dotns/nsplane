//! The drop reasons of [`Translator`](crate::Translator).
//!
//! The core reports them in `Event::Dropped` for packets the translator drops,
//! inbound and outbound. Only packets the translator owns (their addresses are
//! in the [`TranslationTable`](crate::TranslationTable)) are ever dropped;
//! native traffic passes unchanged.

/// The packet is not a well-formed IP packet (bad version, header length,
/// reserved flag, IPv4 option or duplicate fragment header).
pub const MALFORMED: &str = "translation malformed";
/// A header (transport, ICMP, extension) is cut short.
pub const TRUNCATED: &str = "translation truncated";
/// A length field disagrees with the packet size, or the translated packet
/// would not fit its length field.
pub const LENGTH_MISMATCH: &str = "translation length mismatch";
/// An IPv4 header, TCP, UDP or ICMP checksum is wrong (or zero where one is
/// required).
pub const INVALID_CHECKSUM: &str = "translation invalid checksum";
/// A source or destination is unspecified, loopback, multicast or broadcast.
pub const ILLEGAL_ADDRESS: &str = "translation illegal address";
/// An address that must be translated (a source, or an address inside an ICMP
/// error) has no mapping in the table.
pub const UNMAPPED: &str = "translation unmapped";
/// The mapping of an address belongs to another peer than the packet's peer.
pub const PEER_MISMATCH: &str = "translation peer mismatch";
/// A peer sent a packet whose source is one of this node's local-view
/// addresses (an IPv4 alias, an IPv4 LAN address or an IPv6 alias).
pub const SPOOFED_SOURCE: &str = "translation spoofed source";
/// The transport protocol cannot be translated (only TCP, UDP and ICMP can).
pub const UNSUPPORTED_PROTOCOL: &str = "translation unsupported protocol";
/// The ICMP or `ICMPv6` type or code has no translation.
pub const UNSUPPORTED_ICMP: &str = "translation unsupported icmp";
/// The IPv6 extension header chain cannot be translated (too long, or a header
/// after a fragment header).
pub const UNSUPPORTED_EXTENSION: &str = "translation unsupported extension";
/// An IPv6 routing header still has segments left.
pub const ACTIVE_ROUTING_HEADER: &str = "translation active routing header";
/// An IPv4 packet carries an unexhausted source route option.
pub const SOURCE_ROUTE: &str = "translation source route";
/// The TTL or hop limit would reach zero.
pub const HOP_LIMIT_EXCEEDED: &str = "translation hop limit exceeded";
/// An ICMP or `ICMPv6` message is fragmented.
pub const FRAGMENTED_ICMP: &str = "translation fragmented icmp";
/// The first fragment of a UDP datagram does not hold the UDP header.
pub const TINY_FRAGMENT: &str = "translation tiny fragment";
/// A fragment is empty, not a multiple of 8 bytes before the last one, or
/// disagrees with the datagram's end.
pub const MALFORMED_FRAGMENT: &str = "translation malformed fragment";
/// A fragment overlaps another fragment of the same datagram.
pub const OVERLAP: &str = "translation fragment overlap";
/// A datagram being reassembled timed out.
pub const EXPIRED: &str = "translation fragment expired";
/// Reassembly is at its entry or byte limit.
pub const BUDGET_EXCEEDED: &str = "translation fragment budget exceeded";
/// The translated packet does not fit the buffer's capacity.
pub const NO_ROOM: &str = "translation no room";
