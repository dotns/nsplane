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
//! A LAN prefix pair maps an IPv4 LAN prefix to an IPv6 prefix by copying
//! the host part of the address ([`LanPrefix`]). The IPv6 side is either a /96
//! that embeds the whole IPv4 address in its low 32 bits, or a longer prefix
//! whose low bits carry an IPv4 network other than the `lan4` one (RFC 7757
//! prefix mappings): with `lan4` 10.9.1.0/24 and `lan6`
//! `fd64:c::c0a8:100/120`, 10.9.1.5 maps to `fd64:c::c0a8:105` and back.
//!
//! LAN IPv4 prefixes are disjoint by default. With
//! [`TranslationTableBuilder::nested_lans`] they may nest instead: the
//! longest prefix that contains an address owns it, and the exact IPv4
//! addresses (the self `eam4`, every `eam4` and `peer6_eam4`) stay out of
//! every prefix.
//!
//! A [`TranslationTable`] holds data and lookups only; it never rewrites
//! packets. It is immutable once built and validated by
//! [`TranslationTableBuilder::build`].

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nsplane_packet::PeerId;
use nsplane_packet::hash::KeyedState;
use thiserror::Error;

/// Prefix length of the /96 base of every LAN IPv6 prefix: the embedded IPv4
/// address fills the low 32 bits.
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

/// An IPv4 LAN prefix and the IPv6 prefix it is translated to.
///
/// The IPv6 address of an IPv4 address `a` inside `lan4` is `lan6` with an
/// embedded IPv4 address in its low 32 bits, which keeps the host part of
/// `a`. `lan6` takes one of two forms:
///
/// - a /96 with zero low 32 bits: the embedded address is `a` itself
///   (`lan4` 10.9.1.0/24 and `lan6` `fd64:b::/96` map 10.9.1.5 to
///   `fd64:b::a09:105`);
/// - a /(96 + `lan4` length) without host bits: its low bits carry an
///   embedded IPv4 network, which may differ from the `lan4` network
///   (`lan4` 10.9.1.0/24 and `lan6` `fd64:c::c0a8:100/120` map 10.9.1.5 to
///   `fd64:c::c0a8:105`). With the `lan4` network embedded it is the same
///   as the /96 form.
///
/// The /96 that holds `lan6` (its first [`LAN6_PREFIX_LEN`] bits) is its base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanPrefix {
    /// IPv4 prefix and its length.
    pub lan4: (Ipv4Addr, u8),
    /// IPv6 prefix and its length: a /96 with zero low 32 bits, or a
    /// /(96 + `lan4` length) without host bits.
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
    /// A LAN IPv6 prefix is neither a /96 with zero low 32 bits nor a
    /// /(96 + IPv4 prefix length) without host bits.
    #[error(
        "invalid LAN IPv6 prefix {0}/{1}: must be a /96 with zero low 32 bits \
         or a /(96 + IPv4 prefix length) without host bits"
    )]
    InvalidLan6(Ipv6Addr, u8),
    /// A LAN IPv4 prefix overlaps another one or an IPv4 EAM/self address.
    /// With nested LAN prefixes
    /// ([`TranslationTableBuilder::nested_lans`]), only a prefix given twice
    /// or a /32 equal to an IPv4 EAM/self address.
    #[error("LAN IPv4 prefix {0}/{1} overlaps another prefix or address")]
    Lan4Overlap(Ipv4Addr, u8),
    /// The /96 base of a LAN IPv6 prefix is the base of another one or
    /// holds a peer, EAM or local address.
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
    /// The /96 base with zero low 32 bits.
    prefix6: u128,
    /// The `lan4` network XOR the embedded IPv4 network (zero for the /96
    /// form): an address XOR `delta` is its embedded address and back.
    delta: u32,
    peer: Option<PeerId>,
    /// Position of the prefix among the table's prefixes sorted by
    /// `start4` (then `len4`): its identity as the owner of segments.
    index: usize,
    /// Whether the prefix owns one segment, its whole range: always with
    /// disjoint prefixes; with nested ones, when no other prefix and no
    /// exact address lies inside it. Every address of a simple prefix
    /// resolves back to it.
    simple: bool,
}

impl Lan {
    const fn contains4(&self, addr: u32) -> bool {
        self.start4 <= addr && addr <= self.end4
    }

    const fn overlap4(&self) -> TableError {
        TableError::Lan4Overlap(Ipv4Addr::from_bits(self.start4), self.len4)
    }
}

/// A run of IPv4 addresses owned by one LAN prefix, with the owner's data
/// that [`TranslationTable::lan4_to_lan6`] reads: the whole prefix when
/// prefixes are disjoint; with nested prefixes, the part of the prefix that
/// no more specific prefix or exact address covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Segment {
    /// First IPv4 address of the segment.
    start4: u32,
    /// Last IPv4 address of the segment.
    end4: u32,
    /// The owner's `prefix6`, `delta` and peer.
    prefix6: u128,
    delta: u32,
    peer: Option<PeerId>,
    /// The owner's index in the table's prefixes.
    owner: usize,
}

impl Segment {
    /// The segment of `lan` from `start4` to `end4`.
    const fn new(start4: u32, end4: u32, lan: &Lan) -> Self {
        Self {
            start4,
            end4,
            prefix6: lan.prefix6,
            delta: lan.delta,
            peer: lan.peer,
            owner: lan.index,
        }
    }

    const fn contains4(&self, addr: u32) -> bool {
        self.start4 <= addr && addr <= self.end4
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
    /// LAN segments sorted by `start4`, non-overlapping: one per prefix
    /// unless the prefixes nest.
    lans: Vec<Segment>,
    /// LAN prefixes sorted by `start4` (then `len4`).
    prefixes: Vec<Lan>,
    /// `lan6` /96 base to index into `prefixes`.
    by_lan6: Ipv6Map<usize>,
    nested_lans: bool,
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

    /// Whether LAN IPv4 prefixes may nest; see
    /// [`TranslationTableBuilder::nested_lans`].
    pub const fn nested_lans(&self) -> bool {
        self.nested_lans
    }

    /// Maps an IPv4 address inside a LAN prefix to its IPv6 address and the
    /// peer the LAN is behind (`None` for the local LAN).
    ///
    /// The IPv6 address is `lan6` with the host part of `addr`: `addr` itself
    /// in the low 32 bits for a /96 `lan6`; for `lan4` 10.9.1.0/24 and `lan6`
    /// `fd64:c::c0a8:100/120`, 10.9.1.5 maps to `fd64:c::c0a8:105`.
    ///
    /// The longest prefix that contains `addr` wins (with disjoint prefixes
    /// there is at most one). With nested LAN prefixes
    /// ([`nested_lans`](Self::nested_lans)) an exact address (the self
    /// `eam4`, a peer's `eam4` or `peer6_eam4`) is never a LAN address: this
    /// returns `None` for it, even inside a prefix.
    pub fn lan4_to_lan6(&self, addr: Ipv4Addr) -> Option<(Ipv6Addr, Option<PeerId>)> {
        let bits = addr.to_bits();
        let lan = self.lan4(bits)?;
        Some((
            Ipv6Addr::from_bits(lan.prefix6 | u128::from(bits ^ lan.delta)),
            lan.peer,
        ))
    }

    /// Maps an IPv6 address inside a LAN prefix to its IPv4 address and the
    /// peer the LAN is behind, if the IPv4 address in its low 32 bits is
    /// inside the network `lan6` embeds (the `lan4` network for a /96).
    ///
    /// The IPv4 address is the `lan4` network with the host part of `addr`;
    /// for `lan4` 10.9.1.0/24 and `lan6` `fd64:c::c0a8:100/120`,
    /// `fd64:c::c0a8:105` maps to 10.9.1.5 and `fd64:c::a09:105` to nothing.
    ///
    /// With nested LAN prefixes ([`nested_lans`](Self::nested_lans)) the
    /// IPv4 address must also resolve back to the same prefix through
    /// [`lan4_to_lan6`](Self::lan4_to_lan6): an address of a more specific
    /// prefix, of another prefix or an exact address, claimed under this
    /// prefix's /96 base, maps to nothing. So `lan6_to_lan4` inverts
    /// `lan4_to_lan6` in both modes.
    pub fn lan6_to_lan4(&self, addr: Ipv6Addr) -> Option<(Ipv4Addr, Option<PeerId>)> {
        let bits = addr.to_bits();
        let index = *self.by_lan6.get(&(bits & !LAN6_HOST_MASK))?;
        let lan = self.prefixes.get(index)?;
        // XOR `delta` maps the embedded network onto `lan4` and every other
        // address outside it.
        let addr4 = u32::try_from(bits & LAN6_HOST_MASK).ok()? ^ lan.delta;
        // A simple prefix owns all of its range, so only the others need the
        // owner lookup.
        let owned = lan.contains4(addr4)
            && (!self.nested_lans
                || lan.simple
                || self
                    .lan4(addr4)
                    .is_some_and(|segment| segment.owner == index));
        owned.then_some((Ipv4Addr::from_bits(addr4), lan.peer))
    }

    /// Returns the LAN segment that contains `addr` (binary search).
    fn lan4(&self, addr: u32) -> Option<&Segment> {
        let index = self.lans.partition_point(|segment| segment.start4 <= addr);
        self.lans
            .get(index.checked_sub(1)?)
            .filter(|segment| segment.contains4(addr))
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
    nested_lans: bool,
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
    /// the self mapping's `eam4`, another peer's `eam4` or `peer6_eam4`, or,
    /// unless LAN prefixes nest ([`nested_lans`](Self::nested_lans)), inside
    /// a LAN IPv4 prefix.
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
    ///
    /// `lan6` is a /96 with zero low 32 bits, or a /(96 + `lan4` length)
    /// whose low bits carry an embedded IPv4 network; see [`LanPrefix`]. At
    /// most one LAN prefix may use a given /96 base, even with different
    /// embedded networks; prefixes under
    /// different bases may embed the same IPv4 network.
    #[must_use]
    pub fn lan(mut self, lan: LanPrefix) -> Self {
        self.lans.push(lan);
        self
    }

    /// Lets LAN IPv4 prefixes nest, for the whole table.
    ///
    /// By default LAN IPv4 prefixes must be disjoint and must not contain the
    /// self `eam4`, an `eam4` or a `peer6_eam4`
    /// ([`TableError::Lan4Overlap`]). With nested prefixes:
    ///
    /// - a prefix may contain other prefixes (a 0.0.0.0/0 behind one peer
    ///   and a 10.1.0.0/16 behind another); an address belongs to the longest
    ///   prefix that contains it, and a prefix that more specific ones cover
    ///   entirely is accepted and maps nothing;
    /// - the exact addresses (the self `eam4`, every `eam4` and
    ///   `peer6_eam4`) take precedence over every prefix: they are never LAN
    ///   addresses, so [`TranslationTable::lan4_to_lan6`] returns `None` for
    ///   them;
    /// - [`TranslationTable::lan6_to_lan4`] accepts an IPv6 address only when
    ///   its IPv4 address resolves back to the prefix of its /96 base.
    ///
    /// These errors stay: [`TableError::Lan4Overlap`] for the same prefix
    /// given twice and for a /32 prefix equal to an exact address,
    /// [`TableError::InvalidLan4`], [`TableError::InvalidLan6`] and every
    /// [`TableError::Lan6Overlap`] rule (one /96 base per prefix, no base
    /// that holds a `peer6`, `eam6`, `local6` or the self `eam6`).
    ///
    /// ```
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// use nsplane_nat::{LanPrefix, PeerMapping, TranslationTable};
    /// use nsplane_packet::PeerId;
    ///
    /// let (one, two) = (PeerId::new(1), PeerId::new(2));
    /// let eam4 = Ipv4Addr::new(100, 64, 0, 1);
    /// let table = TranslationTable::builder()
    ///     .nested_lans()
    ///     .peer(
    ///         one,
    ///         PeerMapping {
    ///             peer6: "fd00::1:0".parse()?,
    ///             eam6: "fd00::1:1".parse()?,
    ///             local6: None,
    ///             eam4: Some(eam4),
    ///         },
    ///     )
    ///     .lan(LanPrefix {
    ///         lan4: (Ipv4Addr::UNSPECIFIED, 0),
    ///         lan6: ("fd64:1::".parse()?, 96),
    ///         peer: Some(one),
    ///     })
    ///     .lan(LanPrefix {
    ///         lan4: (Ipv4Addr::new(10, 1, 0, 0), 16),
    ///         lan6: ("fd64:2::".parse()?, 96),
    ///         peer: Some(two),
    ///     })
    ///     .build()?;
    /// assert!(table.nested_lans());
    ///
    /// // The longest prefix wins.
    /// let host = Ipv4Addr::new(10, 1, 2, 3);
    /// let host6: Ipv6Addr = "fd64:2::a01:203".parse()?;
    /// assert_eq!(table.lan4_to_lan6(host), Some((host6, Some(two))));
    /// assert_eq!(
    ///     table.lan4_to_lan6(Ipv4Addr::new(10, 2, 0, 1)),
    ///     Some(("fd64:1::a02:1".parse()?, Some(one)))
    /// );
    /// // The peer's `eam4` is not a LAN address.
    /// assert_eq!(table.lan4_to_lan6(eam4), None);
    /// // A /16 address claimed under the /0's base does not map back.
    /// assert_eq!(table.lan6_to_lan4(host6), Some((host, Some(two))));
    /// assert_eq!(table.lan6_to_lan4("fd64:1::a01:203".parse()?), None);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn nested_lans(mut self) -> Self {
        self.nested_lans = true;
        self
    }

    /// Validates the collected mappings and builds the table.
    pub fn build(self) -> Result<TranslationTable, TableError> {
        let mut table = TranslationTable {
            self_mapping: self.self_mapping,
            nested_lans: self.nested_lans,
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
        let mut lans = self
            .lans
            .iter()
            .map(validate_lan)
            .collect::<Result<Vec<_>, _>>()?;
        let addrs4 = eams4
            .iter()
            .copied()
            .chain(self.self_mapping.map(|own| own.eam4));
        if self.nested_lans {
            let mut holes: Vec<u32> = addrs4.map(Ipv4Addr::to_bits).collect();
            holes.sort_unstable();
            table.lans = flatten(&mut lans, &holes)?;
        } else {
            lans.sort_unstable_by_key(|lan| lan.start4);
            for pair in lans.windows(2) {
                if let [prev, next] = pair
                    && prev.end4 >= next.start4
                {
                    return Err(next.overlap4());
                }
            }
            for (index, lan) in lans.iter_mut().enumerate() {
                lan.index = index;
            }
            table.lans = lans
                .iter()
                .map(|lan| Segment::new(lan.start4, lan.end4, lan))
                .collect();
            for addr in addrs4 {
                if let Some(segment) = table.lan4(addr.to_bits()) {
                    return Err(lans[segment.owner].overlap4());
                }
            }
        }
        for lan in &lans {
            if table.by_lan6.insert(lan.prefix6, lan.index).is_some() {
                return Err(TableError::Lan6Overlap(Ipv6Addr::from_bits(lan.prefix6)));
            }
        }
        table.prefixes = lans;
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
    // The low 32 bits of `lan6`: zero for a /96, else the embedded network.
    let [.., a, b, c, d] = addr6.octets();
    let embedded = u32::from_be_bytes([a, b, c, d]);
    let delta = if len6 == LAN6_PREFIX_LEN && embedded == 0 {
        0
    } else if len6 == LAN6_PREFIX_LEN + len4 && embedded & host4 == 0 {
        addr4.to_bits() ^ embedded
    } else {
        return Err(TableError::InvalidLan6(addr6, len6));
    };
    Ok(Lan {
        start4: addr4.to_bits(),
        end4: addr4.to_bits() | host4,
        len4,
        prefix6: addr6.to_bits() & !LAN6_HOST_MASK,
        delta,
        peer: lan.peer,
        index: 0,
        simple: true,
    })
}

/// Sorts nested LAN prefixes by (`start4`, `len4`), numbers them and splits
/// them into disjoint segments, each owned by the innermost prefix that
/// contains it, with the exact addresses `holes` (sorted) left out.
///
/// CIDR prefixes either nest or are disjoint, so one sweep with a stack of
/// the prefixes that contain the current address finds every segment.
fn flatten(lans: &mut [Lan], holes: &[u32]) -> Result<Vec<Segment>, TableError> {
    lans.sort_unstable_by_key(|lan| (lan.start4, lan.len4));
    for (index, lan) in lans.iter_mut().enumerate() {
        lan.index = index;
    }
    for pair in lans.windows(2) {
        if let [prev, next] = pair
            && (prev.start4, prev.len4) == (next.start4, next.len4)
        {
            return Err(next.overlap4());
        }
    }
    if let Some(lan) = lans
        .iter()
        .find(|lan| lan.len4 == 32 && holes.binary_search(&lan.start4).is_ok())
    {
        return Err(lan.overlap4());
    }
    let mut segments = Vec::new();
    // The prefixes that contain the current address, outermost first, and
    // the first address after the last segment (2^32 past the end).
    let mut open: Vec<Lan> = Vec::new();
    let mut next = 0_u64;
    for lan in lans.iter() {
        while let Some(outer) = open.last()
            && outer.end4 < lan.start4
        {
            push_segments(&mut segments, outer, next, outer.end4, holes);
            next = u64::from(outer.end4) + 1;
            open.pop();
        }
        if let Some(outer) = open.last()
            && let Some(end) = lan.start4.checked_sub(1)
        {
            push_segments(&mut segments, outer, next, end, holes);
        }
        next = u64::from(lan.start4);
        open.push(*lan);
    }
    while let Some(outer) = open.pop() {
        push_segments(&mut segments, &outer, next, outer.end4, holes);
        next = u64::from(outer.end4) + 1;
    }
    let mut simple = vec![false; lans.len()];
    for segment in &segments {
        let lan = &lans[segment.owner];
        if (segment.start4, segment.end4) == (lan.start4, lan.end4) {
            simple[segment.owner] = true;
        }
    }
    for lan in lans.iter_mut() {
        lan.simple = simple[lan.index];
    }
    Ok(segments)
}

/// Appends the segments of `lan` from `start` to `end`, around the `holes`.
fn push_segments(segments: &mut Vec<Segment>, lan: &Lan, start: u64, end: u32, holes: &[u32]) {
    let Ok(mut start) = u32::try_from(start) else {
        return;
    };
    let first = holes.partition_point(|&hole| hole < start);
    for &hole in holes[first..].iter().take_while(|&&hole| hole <= end) {
        if start < hole {
            segments.push(Segment::new(start, hole - 1, lan));
        }
        let Some(after) = hole.checked_add(1) else {
            return;
        };
        start = after;
    }
    if start <= end {
        segments.push(Segment::new(start, end, lan));
    }
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

    /// A LAN prefix pair with an explicit `lan6` length.
    fn lan_len6(lan4: &str, len4: u8, lan6: &str, len6: u8, peer: Option<u32>) -> LanPrefix {
        LanPrefix {
            lan6: (v6(lan6), len6),
            ..lan(lan4, len4, "::", peer)
        }
    }

    #[test]
    fn prefix_mapping_vectors() {
        let table = TranslationTable::builder()
            .peer(PeerId::new(1), mapping(1))
            .lan(lan_len6("10.9.1.0", 24, "fd64:c::c0a8:100", 120, Some(1)))
            .lan(lan_len6("172.16.0.0", 16, "fd64:d::a0a:0", 112, None))
            .lan(lan_len6(
                "203.0.113.9",
                32,
                "fd64:e::c000:201",
                128,
                Some(1),
            ))
            .lan(lan_len6("10.10.0.0", 15, "fd64:f::", 111, None))
            .build()
            .unwrap();
        let one = Some(PeerId::new(1));
        let vectors = [
            ("10.9.1.5", "fd64:c::c0a8:105", one),
            ("10.9.1.0", "fd64:c::c0a8:100", one),
            ("10.9.1.255", "fd64:c::c0a8:1ff", one),
            ("172.16.3.4", "fd64:d::a0a:304", None),
            ("172.16.255.255", "fd64:d::a0a:ffff", None),
            ("203.0.113.9", "fd64:e::c000:201", one),
            ("10.10.0.1", "fd64:f::1", None),
            ("10.11.255.255", "fd64:f::1:ffff", None),
        ];
        for (addr4, addr6, peer) in vectors {
            assert_eq!(
                table.lan4_to_lan6(v4(addr4)),
                Some((v6(addr6), peer)),
                "{addr4}"
            );
            assert_eq!(
                table.lan6_to_lan4(v6(addr6)),
                Some((v4(addr4), peer)),
                "{addr6}"
            );
        }
        // Right /96 base, outside the embedded network: the `lan4` range
        // itself included.
        for addr6 in [
            "fd64:c::a09:105",
            "fd64:c::c0a8:205",
            "fd64:c::c0a9:105",
            "fd64:d::ac10:304",
            "fd64:d::a0b:0",
            "fd64:e::c000:202",
            "fd64:f::2:0",
        ] {
            assert!(table.lan6_to_lan4(v6(addr6)).is_none(), "{addr6}");
        }
        // The embedded network is not a `lan4` range.
        assert!(table.lan4_to_lan6(v4("192.168.1.5")).is_none());
    }

    #[test]
    fn prefix_mapping_round_trips_for_every_lan4_length() {
        for len4 in 8..=32_u8 {
            let host4 = u32::MAX.checked_shr(u32::from(len4)).unwrap_or(0);
            let start4 = 0x0a12_3456 & !host4;
            let embedded = 0xc0a8_0000_u32.rotate_right(u32::from(len4)) & !host4;
            let lan6 = Ipv6Addr::from_bits((0xfd64_000c_u128 << 96) | u128::from(embedded));
            let table = TranslationTable::builder()
                .lan(LanPrefix {
                    lan4: (Ipv4Addr::from_bits(start4), len4),
                    lan6: (lan6, LAN6_PREFIX_LEN + len4),
                    peer: Some(PeerId::new(1)),
                })
                .build()
                .unwrap();
            for host in [0, host4 / 2, host4] {
                let addr4 = Ipv4Addr::from_bits(start4 | host);
                let (addr6, peer) = table.lan4_to_lan6(addr4).unwrap();
                assert_eq!(
                    addr6.to_bits(),
                    lan6.to_bits() | u128::from(host),
                    "/{len4}"
                );
                assert_eq!(peer, Some(PeerId::new(1)));
                assert_eq!(table.lan6_to_lan4(addr6), Some((addr4, peer)), "/{len4}");
            }
        }
    }

    #[test]
    fn a_96_and_the_equivalent_prefix_mapping_behave_identically() {
        let build = |lan6, len6| {
            TranslationTable::builder()
                .lan(lan_len6("10.9.1.0", 24, lan6, len6, Some(1)))
                .build()
                .unwrap()
        };
        let (a, b) = (build("fd64:b::", 96), build("fd64:b::a09:100", 120));
        assert_eq!(a.lans, b.lans);
        for addr4 in ["10.9.1.0", "10.9.1.5", "10.9.1.255", "10.9.2.0"] {
            assert_eq!(a.lan4_to_lan6(v4(addr4)), b.lan4_to_lan6(v4(addr4)));
        }
        for addr6 in ["fd64:b::a09:105", "fd64:b::a09:205", "fd64:b::c0a8:105"] {
            assert_eq!(a.lan6_to_lan4(v6(addr6)), b.lan6_to_lan4(v6(addr6)));
        }
    }

    #[test]
    fn prefix_mappings_may_embed_the_same_network_under_different_bases() {
        let table = TranslationTable::builder()
            .lan(lan_len6("10.9.1.0", 24, "fd64:c::c0a8:100", 120, Some(1)))
            .lan(lan("192.168.1.0", 24, "fd64:d::", Some(2)))
            .build()
            .unwrap();
        assert_eq!(
            table.lan6_to_lan4(v6("fd64:c::c0a8:105")),
            Some((v4("10.9.1.5"), Some(PeerId::new(1))))
        );
        assert_eq!(
            table.lan6_to_lan4(v6("fd64:d::c0a8:105")),
            Some((v4("192.168.1.5"), Some(PeerId::new(2))))
        );
    }

    #[test]
    fn rejects_invalid_prefix_mappings() {
        let cases = [
            // Lengths other than 96 and 96 + 24.
            ("fd64:c::c0a8:100", 112),
            ("fd64:c::c0a8:100", 121),
            ("fd64:c::c0a8:100", 128),
            ("fd64:c::", 64),
            // Host bits past the length.
            ("fd64:c::c0a8:101", 120),
            ("fd64:c::c0a8:180", 120),
            // A /96 with low bits set.
            ("fd64:c::c0a8:100", 96),
        ];
        for (lan6, len6) in cases {
            let builder =
                TranslationTable::builder().lan(lan_len6("10.9.1.0", 24, lan6, len6, None));
            assert_eq!(
                err(builder),
                TableError::InvalidLan6(v6(lan6), len6),
                "{lan6}/{len6}"
            );
        }
        // A whole-space `lan4` only has the /96 form.
        let builder =
            TranslationTable::builder().lan(lan_len6("0.0.0.0", 0, "fd64:c::c0a8:100", 96, None));
        assert_eq!(
            err(builder),
            TableError::InvalidLan6(v6("fd64:c::c0a8:100"), 96)
        );
    }

    #[test]
    fn rejects_two_prefix_mappings_in_one_base() {
        let base = v6("fd64:c::");
        // A /96 and a prefix mapping, two prefix mappings (even with the same
        // embedded network).
        let cases = [
            (
                lan("10.0.0.0", 24, "fd64:c::", None),
                lan_len6("10.1.0.0", 24, "fd64:c::c0a8:100", 120, Some(1)),
            ),
            (
                lan_len6("10.0.0.0", 24, "fd64:c::c0a8:200", 120, None),
                lan_len6("10.1.0.0", 24, "fd64:c::c0a8:100", 120, Some(1)),
            ),
            (
                lan_len6("10.0.0.0", 24, "fd64:c::c0a8:100", 120, None),
                lan_len6("10.1.0.0", 24, "fd64:c::c0a8:100", 120, Some(1)),
            ),
        ];
        for (first, second) in cases {
            let builder = TranslationTable::builder().lan(first).lan(second);
            assert_eq!(err(builder), TableError::Lan6Overlap(base), "{second:?}");
        }
    }

    #[test]
    fn rejects_a_prefix_mapping_base_holding_a_peer_eam_or_local_address() {
        let one = mapping(1);
        for addr in [one.peer6, one.eam6, one.local6.unwrap(), own().eam6] {
            let base = Ipv6Addr::from_bits(addr.to_bits() & !LAN6_HOST_MASK);
            // The embedded network does not contain the address.
            let lan6 = Ipv6Addr::from_bits(base.to_bits() | 0xc0a8_0100);
            let builder = TranslationTable::builder()
                .self_mapping(own())
                .peer(PeerId::new(1), one)
                .lan(LanPrefix {
                    lan6: (lan6, 120),
                    ..lan("10.9.1.0", 24, "::", None)
                });
            assert_eq!(err(builder), TableError::Lan6Overlap(base), "{addr}");
        }
    }

    #[test]
    fn rejects_a_prefix_mapping_lan4_covering_an_eam4() {
        // The `lan4` range counts, not the embedded network.
        let builder = TranslationTable::builder()
            .self_mapping(own())
            .peer_with_peer6_eam4(PeerId::new(1), mapping(1), v4("10.9.1.50"))
            .lan(lan_len6("10.9.1.0", 24, "fd64:c::6440:0", 120, None));
        assert_eq!(err(builder), TableError::Lan4Overlap(v4("10.9.1.0"), 24));
        let builder = TranslationTable::builder()
            .self_mapping(own())
            .peer(PeerId::new(1), mapping(1))
            .lan(lan_len6("100.64.0.0", 24, "fd64:c::c0a8:100", 120, None));
        assert_eq!(err(builder), TableError::Lan4Overlap(v4("100.64.0.0"), 24));
        // An embedded network holding the EAM addresses is fine.
        let table = TranslationTable::builder()
            .self_mapping(own())
            .peer(PeerId::new(1), mapping(1))
            .lan(lan_len6("10.9.1.0", 24, "fd64:c::6440:0", 120, None))
            .build();
        assert!(table.is_ok());
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
        assert_eq!(
            TableError::InvalidLan6(v6("fd64:c::c0a8:101"), 120).to_string(),
            "invalid LAN IPv6 prefix fd64:c::c0a8:101/120: must be a /96 with zero low 32 \
             bits or a /(96 + IPv4 prefix length) without host bits"
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

#[cfg(test)]
mod tests_nested;
