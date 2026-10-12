//! The two address families as one type parameter.
//!
//! Packet paths are monomorphized for [`Ipv4Addr`] and [`Ipv6Addr`]: each
//! family has its own keys, indexes and state maps, and a packet picks its
//! family once, from the version nibble. The IPv4 instance is the code (and
//! the key layout and hash) of an IPv4-only gate.

use std::fmt::Debug;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::hash::FastSet;
use super::packet::{PacketMeta, Quote, parse_v6, quote_v4, quote_v6};
use super::policy::{
    AddressSet, BindingKey, CompiledHoldRule, CompiledHolds, CompiledScope, ScopeAddrs,
};
use super::snapshot::{AddrIndex, Snapshot};
use super::state::{FamilyShard, Shard};

/// An address family the gate handles.
pub(super) trait GateAddr: Copy + Eq + Hash + Debug + Send + Sync + 'static {
    /// The fragment identification: 16 bits in IPv4, 32 in IPv6.
    type FragmentId: Copy + Eq + Hash + Debug;

    /// The family's ICMP protocol number (1, or 58 for `ICMPv6`).
    const ICMP: u8;

    /// The address length in bits.
    const BITS: u8;

    /// The address as an [`IpAddr`], to match an [`IpNet`](crate::net::IpNet).
    fn ip(self) -> IpAddr;

    /// The address of this family in `ip`, if any.
    fn of(ip: IpAddr) -> Option<Self>;

    /// The address folded to 32 bits for the key hashes; an IPv4 address is
    /// its own bits.
    fn fold(self) -> u32;

    /// Parse a packet of this family; `None` when it is malformed.
    fn parse(packet: &[u8]) -> Option<PacketMeta<Self>>;

    /// The `(source, destination)` of a packet whose fixed header is
    /// readable.
    fn endpoints(packet: &[u8]) -> Option<(Self, Self)>;

    /// The flow an ICMP error quotes; `None` when the quote is unreadable.
    fn quote(packet: &[u8]) -> Option<Quote<Self>>;

    /// Whether an ICMP type is an error quoting a flow.
    fn is_icmp_error(icmp_type: u8) -> bool;

    /// Whether an ICMP type never opens a flow.
    fn is_reverse_only_icmp(icmp_type: u8) -> bool;

    /// The family's state in `shard`.
    fn shard(shard: &mut Shard) -> FamilyShard<'_, Self>;

    /// The family's indexes in `snapshot`.
    fn index(snapshot: &Snapshot) -> &AddrIndex<Self>;

    /// The family's addresses of `scope`.
    fn scope(scope: &CompiledScope) -> &ScopeAddrs<Self>;

    /// The family's `(local, remote)` addresses of a hold rule.
    fn hold(rule: &CompiledHoldRule) -> (&AddressSet<Self>, &AddressSet<Self>);

    /// The family's released `(peer, remote)` pairs.
    fn release(holds: &CompiledHolds) -> &FastSet<BindingKey<Self>>;
}

impl GateAddr for Ipv4Addr {
    type FragmentId = u16;

    const ICMP: u8 = 1;

    const BITS: u8 = 32;

    #[inline]
    fn ip(self) -> IpAddr {
        IpAddr::V4(self)
    }

    fn of(ip: IpAddr) -> Option<Self> {
        match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        }
    }

    #[inline]
    fn fold(self) -> u32 {
        self.to_bits()
    }

    #[inline]
    fn parse(packet: &[u8]) -> Option<PacketMeta<Self>> {
        PacketMeta::parse(packet)
    }

    fn endpoints(packet: &[u8]) -> Option<(Self, Self)> {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return None;
        }
        Some((
            Self::new(packet[12], packet[13], packet[14], packet[15]),
            Self::new(packet[16], packet[17], packet[18], packet[19]),
        ))
    }

    fn quote(packet: &[u8]) -> Option<Quote<Self>> {
        quote_v4(packet)
    }

    #[inline]
    fn is_icmp_error(icmp_type: u8) -> bool {
        matches!(icmp_type, 3 | 4 | 11 | 12)
    }

    #[inline]
    fn is_reverse_only_icmp(icmp_type: u8) -> bool {
        matches!(icmp_type, 0 | 3 | 4 | 5 | 11 | 12)
    }

    #[inline]
    fn shard(shard: &mut Shard) -> FamilyShard<'_, Self> {
        FamilyShard {
            flows: &mut shard.flows,
            fragments: &mut shard.fragments,
            peer_flows: &mut shard.peer_flows,
        }
    }

    #[inline]
    fn index(snapshot: &Snapshot) -> &AddrIndex<Self> {
        &snapshot.v4
    }

    #[inline]
    fn scope(scope: &CompiledScope) -> &ScopeAddrs<Self> {
        &scope.v4
    }

    #[inline]
    fn hold(rule: &CompiledHoldRule) -> (&AddressSet<Self>, &AddressSet<Self>) {
        (&rule.local.0, &rule.remote.0)
    }

    #[inline]
    fn release(holds: &CompiledHolds) -> &FastSet<BindingKey<Self>> {
        &holds.release.0
    }
}

impl GateAddr for Ipv6Addr {
    type FragmentId = u32;

    const ICMP: u8 = 58;

    const BITS: u8 = 128;

    #[inline]
    fn ip(self) -> IpAddr {
        IpAddr::V6(self)
    }

    fn of(ip: IpAddr) -> Option<Self> {
        match ip {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => None,
        }
    }

    #[inline]
    fn fold(self) -> u32 {
        let octets = self.octets();
        let word = |at: usize| {
            u32::from_be_bytes([octets[at], octets[at + 1], octets[at + 2], octets[at + 3]])
        };
        word(0) ^ word(4) ^ word(8) ^ word(12)
    }

    #[inline]
    fn parse(packet: &[u8]) -> Option<PacketMeta<Self>> {
        parse_v6(packet)
    }

    fn endpoints(packet: &[u8]) -> Option<(Self, Self)> {
        if packet.len() < 40 || packet[0] >> 4 != 6 {
            return None;
        }
        Some((address_at(packet, 8), address_at(packet, 24)))
    }

    fn quote(packet: &[u8]) -> Option<Quote<Self>> {
        quote_v6(packet)
    }

    #[inline]
    fn is_icmp_error(icmp_type: u8) -> bool {
        matches!(icmp_type, 1..=4)
    }

    #[inline]
    fn is_reverse_only_icmp(icmp_type: u8) -> bool {
        matches!(icmp_type, 1..=4 | 129 | 137)
    }

    #[inline]
    fn shard(shard: &mut Shard) -> FamilyShard<'_, Self> {
        FamilyShard {
            flows: &mut shard.flows6,
            fragments: &mut shard.fragments6,
            peer_flows: &mut shard.peer_flows,
        }
    }

    #[inline]
    fn index(snapshot: &Snapshot) -> &AddrIndex<Self> {
        &snapshot.v6
    }

    #[inline]
    fn scope(scope: &CompiledScope) -> &ScopeAddrs<Self> {
        &scope.v6
    }

    #[inline]
    fn hold(rule: &CompiledHoldRule) -> (&AddressSet<Self>, &AddressSet<Self>) {
        (&rule.local.1, &rule.remote.1)
    }

    #[inline]
    fn release(holds: &CompiledHolds) -> &FastSet<BindingKey<Self>> {
        &holds.release.1
    }
}

/// The IPv6 address at `offset` of `packet`, which holds 16 bytes there.
pub(super) fn address_at(packet: &[u8], offset: usize) -> Ipv6Addr {
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&packet[offset..offset + 16]);
    Ipv6Addr::from(octets)
}
