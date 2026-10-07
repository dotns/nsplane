//! The translation address model: per-peer explicit address mappings (EAM,
//! RFC 7757), the self mapping and LAN prefix pairs.
//!
//! A peer has its own IPv6 address on the tunnel, `peer6`, and up to three
//! local addresses for it: an EAM `eam4 <-> eam6` (a local IPv4 address
//! translated to and from the IPv6 side of the mapping), an optional second
//! EAM `peer6_eam4 <-> peer6` (a local IPv4 address translated to and from
//! `peer6`; added with [`TranslationTableBuilder::peer_with_peer6_eam4`]) and
//! an optional local IPv6 address `local6 <-> peer6` ([`PeerMapping::local6`]).
//! The IPv4 EAM to `peer6` lets IPv4 applications reach the peer's own IPv6
//! address: unlike `local6`, which keeps the packet IPv6 and only rewrites the
//! address, it is translated between IPv4 and IPv6.
//!
//! A [`TranslationTable`] holds data and lookups only; it never rewrites
//! packets. It is immutable once built and validated by
//! [`TranslationTableBuilder::build`].

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nsplane_packet::PeerId;
use nsplane_packet::hash::KeyedState;
use thiserror::Error;

/// Prefix length of every LAN IPv6 prefix: the IPv4 address fills the low 32 bits.
pub const LAN6_PREFIX_LEN: u8 = 96;

/// Mask of the low 32 bits of a LAN IPv6 address (the embedded IPv4 address).
const LAN6_HOST_MASK: u128 = 0xFFFF_FFFF;

/// The addresses of one peer: its own IPv6 address, its EAM and its local
/// addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerMapping {
    /// The peer's own IPv6 address on the tunnel.
    pub peer6: Ipv6Addr,
    /// The IPv6 side of the peer's explicit address mapping (EAM).
    pub eam6: Ipv6Addr,
    /// A local IPv6 address for the peer, rewritten (not translated) to and
    /// from `peer6`.
    pub local6: Option<Ipv6Addr>,
    /// The local IPv4 side of the peer's EAM, translated to and from `eam6`.
    pub eam4: Option<Ipv4Addr>,
}

/// This node's own EAM: its local IPv4 address and the IPv6 address it
/// translates to and from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfMapping {
    /// This node's local IPv4 address.
    pub eam4: Ipv4Addr,
    /// This node's IPv6 address that `eam4` translates to and from.
    pub eam6: Ipv6Addr,
}

/// An IPv4 LAN prefix and the IPv6 /96 prefix it is translated to.
///
/// An IPv4 address `a` inside `lan4` maps to `lan6` with `a` in the low 32 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanPrefix {
    /// IPv4 prefix and its length.
    pub lan4: (Ipv4Addr, u8),
    /// IPv6 prefix and its length, which must be [`LAN6_PREFIX_LEN`].
    pub lan6: (Ipv6Addr, u8),
    /// `None` for the LAN behind this node, `Some(peer)` for a LAN behind that peer.
    pub peer: Option<PeerId>,
}

/// Why a [`TranslationTable`] was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TableError {
    /// The same peer was given more than one mapping.
    #[error("duplicate mapping for peer {0:?}")]
    DuplicatePeer(PeerId),
    /// A peer, EAM, local or self address is used more than once.
    #[error("duplicate address {0}")]
    DuplicateAddress(IpAddr),
    /// A peer's IPv4 EAM address equals the self mapping's `eam4`.
    #[error("IPv4 EAM address {0} equals the self address")]
    Eam4IsSelf(Ipv4Addr),
    /// A LAN IPv4 prefix is longer than 32 bits or has host bits set.
    #[error("invalid LAN IPv4 prefix {0}/{1}")]
    InvalidLan4(Ipv4Addr, u8),
    /// A LAN IPv6 prefix is not a /96 or has low 32 bits set.
    #[error("invalid LAN IPv6 prefix {0}/{1}: must be a /96 with zero low 32 bits")]
    InvalidLan6(Ipv6Addr, u8),
    /// A LAN IPv4 prefix overlaps another one or an IPv4 EAM/self address.
    #[error("LAN IPv4 prefix {0}/{1} overlaps another prefix or address")]
    Lan4Overlap(Ipv4Addr, u8),
    /// A LAN IPv6 prefix overlaps another one or a peer, EAM or local address.
    #[error("LAN IPv6 prefix {0}/96 overlaps another prefix or address")]
    Lan6Overlap(Ipv6Addr),
}

/// A validated LAN prefix pair in the table's lookup form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lan {
    /// First IPv4 address of the prefix.
    start4: u32,
    /// Last IPv4 address of the prefix.
    end4: u32,
    /// IPv4 prefix length, for error reports.
    len4: u8,
    /// The /96 prefix with zero low 32 bits.
    prefix6: u128,
    peer: Option<PeerId>,
}

impl Lan {
    const fn contains4(&self, addr: u32) -> bool {
        self.start4 <= addr && addr <= self.end4
    }

    const fn overlap4(&self) -> TableError {
        TableError::Lan4Overlap(Ipv4Addr::from_bits(self.start4), self.len4)
    }
}

/// Immutable translation address model with O(1) / O(log n) lookups.
///
/// Built with [`TranslationTable::builder`]. It is cheap to share behind an
/// `Arc` and is replaced as a whole when the model changes.
#[derive(Debug, Clone, Default)]
pub struct TranslationTable {
    peers: HashMap<PeerId, PeerMapping>,
    // The address indexes hold a copy of the mapping: one hash lookup per
    // translated packet instead of two.
    by_eam4: HashMap<Ipv4Addr, (PeerId, PeerMapping)>,
    // The IPv6 indexes are keyed by the address bits and use the cheaper
    // [`KeyedState`] hash: the inbound path looks one up per packet.
    by_local6: Ipv6Map<(PeerId, PeerMapping)>,
    by_eam6: Ipv6Map<(PeerId, PeerMapping)>,
    by_peer6: Ipv6Map<(PeerId, PeerMapping)>,
    by_peer6_eam4: HashMap<Ipv4Addr, (PeerId, PeerMapping)>,
    peer6_eam4: HashMap<PeerId, Ipv4Addr>,
    self_mapping: Option<SelfMapping>,
    /// LAN pairs sorted by `start4`, non-overlapping.
    lans: Vec<Lan>,
    /// `lan6` prefix to index into `lans`.
    by_lan6: Ipv6Map<usize>,
}

impl TranslationTable {
    /// Returns an empty builder.
    pub fn builder() -> TranslationTableBuilder {
        TranslationTableBuilder::default()
    }

    /// Returns the mapping of `peer`.
    pub fn peer(&self, peer: PeerId) -> Option<&PeerMapping> {
        self.peers.get(&peer)
    }

    /// Returns the peer whose `eam4` is `addr`.
    pub fn by_eam4(&self, addr: Ipv4Addr) -> Option<(PeerId, &PeerMapping)> {
        self.by_eam4
            .get(&addr)
            .map(|(peer, mapping)| (*peer, mapping))
    }

    /// Returns the peer whose `local6` is `addr`.
    pub fn by_local6(&self, addr: Ipv6Addr) -> Option<(PeerId, &PeerMapping)> {
        self.by_local6
            .get(&addr.to_bits())
            .map(|(peer, mapping)| (*peer, mapping))
    }

    /// Returns the peer whose `eam6` is `addr` (the self mapping is not included).
    pub fn by_eam6(&self, addr: Ipv6Addr) -> Option<(PeerId, &PeerMapping)> {
        self.by_eam6
            .get(&addr.to_bits())
            .map(|(peer, mapping)| (*peer, mapping))
    }

    /// Returns the peer whose `peer6` is `addr`.
    pub fn by_peer6(&self, addr: Ipv6Addr) -> Option<(PeerId, &PeerMapping)> {
        self.by_peer6
            .get(&addr.to_bits())
            .map(|(peer, mapping)| (*peer, mapping))
    }

    /// Returns the peer whose IPv4 EAM to `peer6` (an IPv4 address translated
    /// to and from its `peer6`; see
    /// [`TranslationTableBuilder::peer_with_peer6_eam4`]) is `addr`.
    pub fn by_peer6_eam4(&self, addr: Ipv4Addr) -> Option<(PeerId, &PeerMapping)> {
        self.by_peer6_eam4
            .get(&addr)
            .map(|(peer, mapping)| (*peer, mapping))
    }

    /// Returns the IPv4 EAM to `peer6` of `peer`, if it has one.
    pub fn peer6_eam4(&self, peer: PeerId) -> Option<Ipv4Addr> {
        self.peer6_eam4.get(&peer).copied()
    }

    /// Returns the self mapping, if configured.
    pub const fn self_mapping(&self) -> Option<SelfMapping> {
        self.self_mapping
    }

    /// Maps an IPv4 address inside a LAN prefix to its IPv6 address and the
    /// peer the LAN is behind (`None` for the local LAN).
    pub fn lan4_to_lan6(&self, addr: Ipv4Addr) -> Option<(Ipv6Addr, Option<PeerId>)> {
        let bits = addr.to_bits();
        let lan = self.lan4(bits)?;
        Some((
            Ipv6Addr::from_bits(lan.prefix6 | u128::from(bits)),
            lan.peer,
        ))
    }

    /// Maps an IPv6 address inside a LAN /96 prefix to its IPv4 address and the
    /// peer the LAN is behind, if the embedded IPv4 address is inside the
    /// paired IPv4 prefix.
    pub fn lan6_to_lan4(&self, addr: Ipv6Addr) -> Option<(Ipv4Addr, Option<PeerId>)> {
        let bits = addr.to_bits();
        let lan = self
            .lans
            .get(*self.by_lan6.get(&(bits & !LAN6_HOST_MASK))?)?;
        let addr4 = u32::try_from(bits & LAN6_HOST_MASK).ok()?;
        lan.contains4(addr4)
            .then_some((Ipv4Addr::from_bits(addr4), lan.peer))
    }

    /// Returns the LAN pair whose IPv4 prefix contains `addr` (binary search).
    fn lan4(&self, addr: u32) -> Option<&Lan> {
        let index = self.lans.partition_point(|lan| lan.start4 <= addr);
        self.lans
            .get(index.checked_sub(1)?)
            .filter(|lan| lan.contains4(addr))
    }
}

/// Collects mappings for a [`TranslationTable`]; [`build`](Self::build)
/// validates them all at once.
#[derive(Debug, Clone, Default)]
pub struct TranslationTableBuilder {
    /// Each peer with its IPv4 EAM to `peer6`, if any.
    peers: Vec<(PeerId, PeerMapping, Option<Ipv4Addr>)>,
    self_mapping: Option<SelfMapping>,
    lans: Vec<LanPrefix>,
}

impl TranslationTableBuilder {
    /// Adds the mapping of `id`.
    #[must_use]
    pub fn peer(mut self, id: PeerId, mapping: PeerMapping) -> Self {
        self.peers.push((id, mapping, None));
        self
    }

    /// Adds the mapping of `id`, as [`peer`](Self::peer), with a second EAM:
    /// `peer6_eam4`, a local IPv4 address translated to and from the peer's
    /// `peer6`, so IPv4 applications reach the peer's own IPv6 address.
    ///
    /// This differs from [`PeerMapping::local6`], a local IPv6 address that
    /// stays IPv6 and is only rewritten to and from `peer6`, and from
    /// [`PeerMapping::eam4`], which is translated to and from `eam6`. All
    /// three may be set for one peer. Like `eam4`, `peer6_eam4` must not be
    /// the self mapping's `eam4`, another peer's `eam4` or `peer6_eam4`, or
    /// inside a LAN IPv4 prefix.
    #[must_use]
    pub fn peer_with_peer6_eam4(
        mut self,
        id: PeerId,
        mapping: PeerMapping,
        peer6_eam4: Ipv4Addr,
    ) -> Self {
        self.peers.push((id, mapping, Some(peer6_eam4)));
        self
    }

    /// Sets the self mapping.
    #[must_use]
    pub const fn self_mapping(mut self, mapping: SelfMapping) -> Self {
        self.self_mapping = Some(mapping);
        self
    }

    /// Adds a LAN prefix pair.
    #[must_use]
    pub fn lan(mut self, lan: LanPrefix) -> Self {
        self.lans.push(lan);
        self
    }

    /// Validates the collected mappings and builds the table.
    pub fn build(self) -> Result<TranslationTable, TableError> {
        let mut table = TranslationTable {
            self_mapping: self.self_mapping,
            ..TranslationTable::default()
        };
        // Every IPv6 address (peer6, eam6, local6, self eam6) must be unique,
        // so a lookup never depends on which role is checked first.
        let mut v6 = HashSet::new();
        let mut eams4 = HashSet::new();
        let mut unique6 = |addr: Ipv6Addr| {
            if v6.insert(addr) {
                Ok(())
            } else {
                Err(TableError::DuplicateAddress(addr.into()))
            }
        };
        if let Some(own) = self.self_mapping {
            unique6(own.eam6)?;
        }
        // Every IPv4 EAM address (eam4 or peer6_eam4) must be unique and not
        // the self `eam4`.
        let mut unique4 = |addr: Ipv4Addr| {
            if self.self_mapping.is_some_and(|own| own.eam4 == addr) {
                Err(TableError::Eam4IsSelf(addr))
            } else if eams4.insert(addr) {
                Ok(())
            } else {
                Err(TableError::DuplicateAddress(addr.into()))
            }
        };
        for (id, mapping, peer6_eam4) in self.peers {
            if table.peers.insert(id, mapping).is_some() {
                return Err(TableError::DuplicatePeer(id));
            }
            unique6(mapping.peer6)?;
            unique6(mapping.eam6)?;
            table
                .by_peer6
                .insert(mapping.peer6.to_bits(), (id, mapping));
            table.by_eam6.insert(mapping.eam6.to_bits(), (id, mapping));
            if let Some(local6) = mapping.local6 {
                unique6(local6)?;
                table.by_local6.insert(local6.to_bits(), (id, mapping));
            }
            if let Some(eam4) = mapping.eam4 {
                unique4(eam4)?;
                table.by_eam4.insert(eam4, (id, mapping));
            }
            if let Some(eam4) = peer6_eam4 {
                unique4(eam4)?;
                table.by_peer6_eam4.insert(eam4, (id, mapping));
                table.peer6_eam4.insert(id, eam4);
            }
        }
        table.lans = self
            .lans
            .iter()
            .map(validate_lan)
            .collect::<Result<_, _>>()?;
        table.lans.sort_unstable_by_key(|lan| lan.start4);
        for pair in table.lans.windows(2) {
            if let [prev, next] = pair
                && prev.end4 >= next.start4
            {
                return Err(next.overlap4());
            }
        }
        let addrs4 = eams4
            .iter()
            .copied()
            .chain(self.self_mapping.map(|own| own.eam4));
        for addr in addrs4 {
            if let Some(lan) = table.lan4(addr.to_bits()) {
                return Err(lan.overlap4());
            }
        }
        for (index, lan) in table.lans.iter().enumerate() {
            if table.by_lan6.insert(lan.prefix6, index).is_some() {
                return Err(TableError::Lan6Overlap(Ipv6Addr::from_bits(lan.prefix6)));
            }
        }
        for addr in &v6 {
            let prefix = addr.to_bits() & !LAN6_HOST_MASK;
            if table.by_lan6.contains_key(&prefix) {
                return Err(TableError::Lan6Overlap(Ipv6Addr::from_bits(prefix)));
            }
        }
        Ok(table)
    }
}

/// A map keyed by IPv6 address bits, hashed with [`KeyedState`].
///
/// The keys are addresses an attacker chooses, but hash flooding cannot grow
/// a chain from traffic: the maps are filled only from the operator's model
/// when a table is built, and packets only look them up, so the worst-case
/// chain length is bounded by the model.
type Ipv6Map<V> = HashMap<u128, V, KeyedState>;

/// Checks the shape of one LAN prefix pair and converts it to lookup form.
fn validate_lan(lan: &LanPrefix) -> Result<Lan, TableError> {
    let (addr4, len4) = lan.lan4;
    let (addr6, len6) = lan.lan6;
    let host4 = u32::MAX.checked_shr(u32::from(len4)).unwrap_or(0);
    if len4 > 32 || addr4.to_bits() & host4 != 0 {
        return Err(TableError::InvalidLan4(addr4, len4));
    }
    if len6 != LAN6_PREFIX_LEN || addr6.to_bits() & LAN6_HOST_MASK != 0 {
        return Err(TableError::InvalidLan6(addr6, len6));
    }
    Ok(Lan {
        start4: addr4.to_bits(),
        end4: addr4.to_bits() | host4,
        len4,
        prefix6: addr6.to_bits(),
        peer: lan.peer,
    })
}

#[cfg(test)]
mod tests {
    use std::hash::BuildHasher;

    use super::*;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn mapping(n: u16) -> PeerMapping {
        PeerMapping {
            peer6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, n, 0),
            eam6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, n, 1),
            local6: Some(Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, n)),
            eam4: Some(Ipv4Addr::new(100, 64, 0, u8::try_from(n).unwrap())),
        }
    }

    fn own() -> SelfMapping {
        SelfMapping {
            eam4: v4("100.64.0.100"),
            eam6: v6("fd00::ff:1"),
        }
    }

    fn lan(lan4: &str, len4: u8, lan6: &str, peer: Option<u32>) -> LanPrefix {
        LanPrefix {
            lan4: (v4(lan4), len4),
            lan6: (v6(lan6), LAN6_PREFIX_LEN),
            peer: peer.map(PeerId::new),
        }
    }

    fn sample() -> TranslationTable {
        TranslationTable::builder()
            .peer(PeerId::new(1), mapping(1))
            .peer(
                PeerId::new(2),
                PeerMapping {
                    local6: None,
                    eam4: None,
                    ..mapping(2)
                },
            )
            .self_mapping(own())
            .lan(lan("192.168.1.0", 24, "fd64:1::", None))
            .lan(lan("10.0.0.0", 8, "fd64:2::", Some(1)))
            .build()
            .unwrap()
    }

    #[test]
    fn table_is_send_sync_clone_debug() {
        fn check<T: Send + Sync + Clone + std::fmt::Debug>() {}
        check::<TranslationTable>();
        check::<TableError>();
    }

    #[test]
    fn empty_table_finds_nothing() {
        let table = TranslationTable::builder().build().unwrap();
        assert!(table.peer(PeerId::new(1)).is_none());
        assert!(table.by_eam4(v4("100.64.0.1")).is_none());
        assert!(table.self_mapping().is_none());
        assert!(table.lan4_to_lan6(v4("10.0.0.1")).is_none());
        assert!(table.lan6_to_lan4(v6("fd64:2::a00:1")).is_none());
    }

    #[test]
    fn peer_lookups() {
        let table = sample();
        let one = mapping(1);
        let id = PeerId::new(1);
        assert_eq!(table.peer(id), Some(&one));
        assert_eq!(table.by_eam4(one.eam4.unwrap()), Some((id, &one)));
        assert_eq!(table.by_local6(one.local6.unwrap()), Some((id, &one)));
        assert_eq!(table.by_eam6(one.eam6), Some((id, &one)));
        assert_eq!(table.by_peer6(one.peer6), Some((id, &one)));
        // Roles do not mix.
        assert!(table.by_eam6(one.peer6).is_none());
        assert!(table.by_peer6(one.eam6).is_none());
        assert!(table.by_local6(one.peer6).is_none());

        let two = table.peer(PeerId::new(2)).unwrap();
        assert_eq!(
            table.by_peer6(two.peer6).map(|(id, _)| id),
            Some(PeerId::new(2))
        );
        assert!(table.by_eam4(v4("100.64.0.2")).is_none());
        assert!(table.peer(PeerId::new(3)).is_none());
    }

    #[test]
    fn self_mapping_lookup() {
        let table = sample();
        assert_eq!(table.self_mapping(), Some(own()));
        // The self eam6 is not a peer eam6.
        assert!(table.by_eam6(own().eam6).is_none());
    }

    #[test]
    fn lan_lookups() {
        let table = sample();
        assert_eq!(
            table.lan4_to_lan6(v4("192.168.1.7")),
            Some((v6("fd64:1::c0a8:107"), None))
        );
        assert_eq!(
            table.lan4_to_lan6(v4("10.1.2.3")),
            Some((v6("fd64:2::a01:203"), Some(PeerId::new(1))))
        );
        assert_eq!(
            table.lan6_to_lan4(v6("fd64:1::c0a8:1ff")),
            Some((v4("192.168.1.255"), None))
        );
        assert_eq!(
            table.lan6_to_lan4(v6("fd64:2::a00:0")),
            Some((v4("10.0.0.0"), Some(PeerId::new(1))))
        );
        // Outside every prefix.
        assert!(table.lan4_to_lan6(v4("192.168.2.1")).is_none());
        assert!(table.lan4_to_lan6(v4("9.255.255.255")).is_none());
        assert!(table.lan4_to_lan6(v4("11.0.0.0")).is_none());
        assert!(table.lan4_to_lan6(v4("1.1.1.1")).is_none());
        // Right /96, embedded address outside the paired IPv4 prefix.
        assert!(table.lan6_to_lan4(v6("fd64:1::c0a8:201")).is_none());
        // Unknown /96.
        assert!(table.lan6_to_lan4(v6("fd64:3::a00:1")).is_none());
    }

    #[test]
    fn lan_round_trip() {
        let table = sample();
        for addr in ["192.168.1.0", "192.168.1.200", "10.0.0.1", "10.255.255.255"] {
            let addr = v4(addr);
            let (lan6, peer) = table.lan4_to_lan6(addr).unwrap();
            assert_eq!(table.lan6_to_lan4(lan6), Some((addr, peer)));
        }
    }

    #[test]
    fn single_address_and_whole_space_lan4() {
        let table = TranslationTable::builder()
            .lan(lan("203.0.113.9", 32, "fd64:9::", None))
            .build()
            .unwrap();
        assert!(table.lan4_to_lan6(v4("203.0.113.9")).is_some());
        assert!(table.lan4_to_lan6(v4("203.0.113.8")).is_none());
        let table = TranslationTable::builder()
            .lan(lan("0.0.0.0", 0, "fd64:9::", None))
            .build()
            .unwrap();
        assert_eq!(
            table.lan4_to_lan6(v4("255.255.255.255")),
            Some((v6("fd64:9::ffff:ffff"), None))
        );
    }

    fn err(builder: TranslationTableBuilder) -> TableError {
        builder.build().unwrap_err()
    }

    #[test]
    fn rejects_duplicate_peer() {
        let builder = TranslationTable::builder()
            .peer(PeerId::new(1), mapping(1))
            .peer(PeerId::new(1), mapping(2));
        assert_eq!(err(builder), TableError::DuplicatePeer(PeerId::new(1)));
    }

    #[test]
    fn rejects_duplicate_eam4() {
        let builder = TranslationTable::builder()
            .peer(PeerId::new(1), mapping(1))
            .peer(
                PeerId::new(2),
                PeerMapping {
                    eam4: mapping(1).eam4,
                    ..mapping(2)
                },
            );
        assert_eq!(
            err(builder),
            TableError::DuplicateAddress(IpAddr::V4(v4("100.64.0.1")))
        );
    }

    #[test]
    fn rejects_duplicate_ipv6_addresses() {
        let one = mapping(1);
        let cases = [
            // local6, eam6 and peer6 reused by another peer.
            PeerMapping {
                local6: one.local6,
                ..mapping(2)
            },
            PeerMapping {
                eam6: one.eam6,
                ..mapping(2)
            },
            PeerMapping {
                peer6: one.peer6,
                ..mapping(2)
            },
            // An address reused in another role.
            PeerMapping {
                eam6: one.peer6,
                ..mapping(2)
            },
            PeerMapping {
                local6: Some(one.eam6),
                ..mapping(2)
            },
            // The self eam6.
            PeerMapping {
                eam6: own().eam6,
                ..mapping(2)
            },
        ];
        for second in cases {
            let builder = TranslationTable::builder()
                .self_mapping(own())
                .peer(PeerId::new(1), one)
                .peer(PeerId::new(2), second);
            assert!(
                matches!(err(builder), TableError::DuplicateAddress(IpAddr::V6(_))),
                "{second:?}"
            );
        }
        // Within one peer.
        let builder = TranslationTable::builder().peer(
            PeerId::new(1),
            PeerMapping {
                eam6: one.peer6,
                ..one
            },
        );
        assert_eq!(
            err(builder),
            TableError::DuplicateAddress(IpAddr::V6(one.peer6))
        );
    }

    #[test]
    fn rejects_eam4_equal_to_self_eam4() {
        let builder = TranslationTable::builder().self_mapping(own()).peer(
            PeerId::new(1),
            PeerMapping {
                eam4: Some(own().eam4),
                ..mapping(1)
            },
        );
        assert_eq!(err(builder), TableError::Eam4IsSelf(own().eam4));
    }

    #[test]
    fn rejects_invalid_lan4() {
        let builder = TranslationTable::builder().lan(lan("10.0.0.1", 24, "fd64:1::", None));
        assert_eq!(err(builder), TableError::InvalidLan4(v4("10.0.0.1"), 24));
        let builder = TranslationTable::builder().lan(lan("10.0.0.0", 33, "fd64:1::", None));
        assert_eq!(err(builder), TableError::InvalidLan4(v4("10.0.0.0"), 33));
    }

    #[test]
    fn rejects_invalid_lan6() {
        let builder = TranslationTable::builder().lan(LanPrefix {
            lan6: (v6("fd64:1::"), 64),
            ..lan("10.0.0.0", 8, "fd64:1::", None)
        });
        assert_eq!(err(builder), TableError::InvalidLan6(v6("fd64:1::"), 64));
        let builder = TranslationTable::builder().lan(lan("10.0.0.0", 8, "fd64:1::1", None));
        assert_eq!(err(builder), TableError::InvalidLan6(v6("fd64:1::1"), 96));
    }

    #[test]
    fn rejects_overlapping_lan4() {
        let builder = TranslationTable::builder()
            .lan(lan("10.1.0.0", 16, "fd64:2::", None))
            .lan(lan("10.0.0.0", 8, "fd64:1::", Some(1)));
        assert_eq!(err(builder), TableError::Lan4Overlap(v4("10.1.0.0"), 16));
        let builder = TranslationTable::builder()
            .lan(lan("10.0.0.0", 24, "fd64:1::", None))
            .lan(lan("10.0.0.0", 24, "fd64:2::", None));
        assert_eq!(err(builder), TableError::Lan4Overlap(v4("10.0.0.0"), 24));
        // Adjacent prefixes are fine.
        let table = TranslationTable::builder()
            .lan(lan("10.0.0.0", 24, "fd64:1::", None))
            .lan(lan("10.0.1.0", 24, "fd64:2::", None))
            .build();
        assert!(table.is_ok());
    }

    #[test]
    fn rejects_lan4_covering_eam4_or_self_eam4() {
        let builder = TranslationTable::builder()
            .peer(PeerId::new(1), mapping(1))
            .lan(lan("100.64.0.0", 24, "fd64:1::", None));
        assert_eq!(err(builder), TableError::Lan4Overlap(v4("100.64.0.0"), 24));
        let builder = TranslationTable::builder().self_mapping(own()).lan(lan(
            "100.64.0.100",
            32,
            "fd64:1::",
            None,
        ));
        assert_eq!(
            err(builder),
            TableError::Lan4Overlap(v4("100.64.0.100"), 32)
        );
    }

    #[test]
    fn rejects_overlapping_lan6() {
        let builder = TranslationTable::builder()
            .lan(lan("10.0.0.0", 8, "fd64:1::", None))
            .lan(lan("192.168.0.0", 16, "fd64:1::", None));
        assert_eq!(err(builder), TableError::Lan6Overlap(v6("fd64:1::")));
    }

    #[test]
    fn rejects_lan6_covering_a_peer_eam_or_local_address() {
        let one = mapping(1);
        for addr in [one.peer6, one.eam6, one.local6.unwrap(), own().eam6] {
            let prefix = Ipv6Addr::from_bits(addr.to_bits() & !LAN6_HOST_MASK);
            let builder = TranslationTable::builder()
                .self_mapping(own())
                .peer(PeerId::new(1), one)
                .lan(LanPrefix {
                    lan6: (prefix, LAN6_PREFIX_LEN),
                    ..lan("10.0.0.0", 8, "::", None)
                });
            assert_eq!(err(builder), TableError::Lan6Overlap(prefix), "{addr}");
        }
    }

    #[test]
    fn peer6_eam4_lookups() {
        let peer6_eam4 = v4("100.64.0.50");
        let one = mapping(1);
        let table = TranslationTable::builder()
            .peer_with_peer6_eam4(PeerId::new(1), one, peer6_eam4)
            .peer(PeerId::new(2), mapping(2))
            .build()
            .unwrap();
        assert_eq!(
            table.by_peer6_eam4(peer6_eam4),
            Some((PeerId::new(1), &one))
        );
        assert_eq!(table.peer6_eam4(PeerId::new(1)), Some(peer6_eam4));
        assert_eq!(table.peer(PeerId::new(1)), Some(&one));
        // The other roles of the peer are unchanged, and roles do not mix.
        assert_eq!(
            table.by_eam4(one.eam4.unwrap()).map(|(id, _)| id),
            Some(PeerId::new(1))
        );
        assert!(table.by_eam4(peer6_eam4).is_none());
        assert!(table.by_peer6_eam4(one.eam4.unwrap()).is_none());
        assert!(table.peer6_eam4(PeerId::new(2)).is_none());
        assert!(table.peer6_eam4(PeerId::new(3)).is_none());
    }

    #[test]
    fn rejects_a_peer6_eam4_in_use() {
        let one = mapping(1);
        let cases = [
            // Its own eam4, another peer's eam4, another peer6_eam4.
            (one.eam4.unwrap(), None),
            (mapping(2).eam4.unwrap(), None),
            (v4("100.64.0.50"), Some(v4("100.64.0.50"))),
        ];
        for (peer6_eam4, other_peer6_eam4) in cases {
            let builder =
                TranslationTable::builder().peer_with_peer6_eam4(PeerId::new(1), one, peer6_eam4);
            let builder = match other_peer6_eam4 {
                Some(eam4) => builder.peer_with_peer6_eam4(PeerId::new(2), mapping(2), eam4),
                None => builder.peer(PeerId::new(2), mapping(2)),
            };
            assert_eq!(
                err(builder),
                TableError::DuplicateAddress(IpAddr::V4(peer6_eam4)),
                "{peer6_eam4}"
            );
        }
        // The self eam4.
        let builder = TranslationTable::builder()
            .self_mapping(own())
            .peer_with_peer6_eam4(PeerId::new(1), one, own().eam4);
        assert_eq!(err(builder), TableError::Eam4IsSelf(own().eam4));
        // A duplicate peer stays a duplicate peer.
        let builder = TranslationTable::builder()
            .peer(PeerId::new(1), one)
            .peer_with_peer6_eam4(PeerId::new(1), mapping(2), v4("100.64.0.50"));
        assert_eq!(err(builder), TableError::DuplicatePeer(PeerId::new(1)));
    }

    #[test]
    fn rejects_lan4_covering_a_peer6_eam4() {
        for peer in [None, Some(1)] {
            let builder = TranslationTable::builder()
                .peer_with_peer6_eam4(PeerId::new(1), mapping(1), v4("10.9.0.1"))
                .lan(lan("10.0.0.0", 8, "fd64:1::", peer));
            assert_eq!(err(builder), TableError::Lan4Overlap(v4("10.0.0.0"), 8));
        }
    }

    #[test]
    fn errors_display() {
        assert_eq!(
            TableError::Eam4IsSelf(v4("100.64.0.1")).to_string(),
            "IPv4 EAM address 100.64.0.1 equals the self address"
        );
        assert_eq!(
            TableError::InvalidLan4(v4("10.0.0.1"), 8).to_string(),
            "invalid LAN IPv4 prefix 10.0.0.1/8"
        );
    }

    fn hash(state: &KeyedState, addr: Ipv6Addr) -> u64 {
        state.hash_one(addr.to_bits())
    }

    #[test]
    fn ipv6_hash_is_keyed_per_table() {
        let (one, two) = (sample(), sample());
        let (a, b) = (one.by_peer6.hasher(), two.by_peer6.hasher());
        let addr = v6("fd00::1");
        assert_ne!(hash(a, addr), hash(b, addr));
        // A clone keeps its keys, so its lookups still find the entries.
        let clone = one.clone();
        assert_eq!(hash(clone.by_peer6.hasher(), addr), hash(a, addr));
        assert_eq!(
            clone.by_peer6(mapping(1).peer6),
            one.by_peer6(mapping(1).peer6)
        );
    }
}
