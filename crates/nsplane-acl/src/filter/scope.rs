//! Address scopes: outbound sources and other-protocol rules, per local
//! identity.

use std::collections::HashMap;
use std::net::IpAddr;

use nsplane_core::LocalIdentityId;
use nsplane_packet::{IpPacket, PeerId};

use super::Inner;
use super::packet::{EchoType, echo_type, is_icmp, source_in};
use crate::engine::Snapshot;
use crate::lru::FlowHash;
use crate::net::IpNet;
use thiserror::Error;

#[cfg(doc)]
use super::AclFilter;
#[cfg(doc)]
use super::config::{AclFilterConfig, AclFilterStats, Ipv6Mode};
#[cfg(doc)]
use super::identity::PeerIdentity;
#[cfg(doc)]
use crate::reasons;

/// Address scopes of an [`AclFilter`] (beyond [`AclFilterConfig`]).
///
/// Built with [`new`](Self::new) and the `with_*` setters; the default scopes
/// nothing and costs nothing on the packet path.
///
/// A filter holds one scope per local identity, plus a default one, in an
/// [`AclFilterScopes`]: given at build ([`AclFilter::with_scope`] sets the
/// default) and replaced at runtime by [`AclFilter::replace_scopes`]. Each
/// packet is judged under the scope of its peer's
/// [local identity](PeerIdentity::local_identity), or the default one when
/// that identity has none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AclFilterScope {
    /// Allowed source prefixes of outbound packets. `None` (default): no check.
    ///
    /// When set, every outbound packet (to any peer, of any protocol, every
    /// fragment included) whose source address is in none of the prefixes is
    /// dropped with [`reasons::OUTBOUND_SOURCE`] before the destination rules,
    /// the outbound pinholes and the reply allowances are consulted, and
    /// leaves no state. The source address is read from the raw IPv4 or IPv6
    /// header; a packet too short to hold it (or of another IP version) is
    /// dropped too. An empty list drops every outbound packet.
    /// [`Ipv6Mode::Accept`] still passes IPv6 packets unevaluated.
    pub outbound_sources: Option<Vec<IpNet>>,
    /// Accept rules for inbound packets that are neither TCP nor UDP, scoped to
    /// destinations. Empty (default): today's handling (dropped unless
    /// [`AclFilterConfig::allow_other_protocols`]).
    ///
    /// Checked after the reply allowances and `allow_other_protocols`, still
    /// behind a loaded policy: a packet some rule matches is accepted (counted
    /// in [`AclFilterStats::accepted`]), any other is dropped with
    /// [`reasons::PROTOCOL`]. Non-first fragments follow their first fragment.
    /// With [`AclFilterConfig::stateful_replies`] on, an accepted packet from
    /// an outbound-restricted peer (other than an ICMP message that is not an
    /// echo request) allows its reply back to that peer.
    pub other_protocols: Vec<OtherProtocolRule>,
}

/// An [`AclFilterScope::other_protocols`] rule: inbound packets of `protocol`
/// addressed to one of `destinations` are accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OtherProtocolRule {
    /// The packets the rule applies to.
    pub protocol: OtherProtocol,
    /// The destination prefixes the rule accepts; empty accepts nothing.
    pub destinations: Vec<IpNet>,
}

impl OtherProtocolRule {
    /// A rule accepting `protocol` to `destinations`.
    #[must_use]
    pub fn new(protocol: OtherProtocol, destinations: impl IntoIterator<Item = IpNet>) -> Self {
        Self {
            protocol,
            destinations: destinations.into_iter().collect(),
        }
    }

    /// Whether the rule accepts `packet` (neither TCP nor UDP).
    fn accepts(&self, packet: &IpPacket<'_>) -> bool {
        let protocol = match self.protocol {
            OtherProtocol::IcmpEcho => echo_type(packet) == Some(EchoType::Request),
            OtherProtocol::Icmp => is_icmp(packet.protocol()),
            OtherProtocol::Ip(number) => packet.protocol() == number,
        };
        protocol
            && self
                .destinations
                .iter()
                .any(|net| net.contains(&packet.dst()))
    }
}

/// The packets an [`OtherProtocolRule`] applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtherProtocol {
    /// ICMP Echo request (type 8) and `ICMPv6` Echo request (type 128).
    IcmpEcho,
    /// Every ICMP and `ICMPv6` message.
    Icmp,
    /// Every packet with this IP protocol number (TCP and UDP never reach these rules).
    Ip(u8),
}

impl AclFilterScope {
    /// The default scope: no constraint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`outbound_sources`](Self::outbound_sources) to `prefixes`.
    #[must_use]
    pub fn with_outbound_sources(mut self, prefixes: impl IntoIterator<Item = IpNet>) -> Self {
        self.outbound_sources = Some(prefixes.into_iter().collect());
        self
    }

    /// Appends `rule` to [`other_protocols`](Self::other_protocols).
    #[must_use]
    pub fn with_other_protocol(mut self, rule: OtherProtocolRule) -> Self {
        self.other_protocols.push(rule);
        self
    }

    /// Whether the scope constrains nothing.
    const fn is_unconstrained(&self) -> bool {
        self.outbound_sources.is_none() && self.other_protocols.is_empty()
    }

    /// Whether [`outbound_sources`](Self::outbound_sources) lets an outbound
    /// packet through.
    pub(super) fn allows_source(&self, bytes: &[u8]) -> bool {
        self.outbound_sources
            .as_deref()
            .is_none_or(|prefixes| source_in(bytes, prefixes))
    }

    /// Whether an [`other_protocols`](Self::other_protocols) rule accepts
    /// `packet`.
    #[inline]
    pub(super) fn accepts_other(&self, packet: &IpPacket<'_>) -> bool {
        self.other_protocols.iter().any(|rule| rule.accepts(packet))
    }
}

/// The [`AclFilterScope`]s of an [`AclFilter`], published together by
/// [`AclFilter::replace_scopes`].
///
/// A packet is judged under the scope of its peer's
/// [local identity](PeerIdentity::local_identity) in
/// [`identities`](Self::identities), or under [`default`](Self::default)
/// when that identity has no entry. Built with [`new`](Self::new) and the
/// `with_*` setters; the default scopes nothing.
///
/// A default scope alone adds only the read of the published scopes (see
/// [`AclFilter::replace_scopes`]). Only
/// with [`identities`](Self::identities) does a packet that needs a scope
/// also resolve its peer's identity (from the peer cache, or the
/// [`PeerIdentity::local_identity`] hook when the identity is not versioned)
/// and look its scope up; the outbound source check then follows the peer
/// lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AclFilterScopes {
    /// The scope of the peers whose identity has no entry.
    pub default: AclFilterScope,
    /// The scope of each local identity; an identity may be listed once.
    /// [`LocalIdentityId::DEFAULT`] may be listed too, and then replaces
    /// [`default`](Self::default) for its peers.
    pub identities: Vec<(LocalIdentityId, AclFilterScope)>,
}

impl AclFilterScopes {
    /// No scope: no constraint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`default`](Self::default) to `scope`.
    #[must_use]
    pub fn with_default(mut self, scope: AclFilterScope) -> Self {
        self.default = scope;
        self
    }

    /// Appends the scope of the local identity `id` to
    /// [`identities`](Self::identities).
    #[must_use]
    pub fn with_identity(mut self, id: LocalIdentityId, scope: AclFilterScope) -> Self {
        self.identities.push((id, scope));
        self
    }
}

/// Why [`AclFilter::replace_scopes`] rejected an [`AclFilterScopes`].
/// Nothing is published.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AclFilterScopeError {
    /// A local identity is listed twice.
    #[error("local identity {0:?} has two scopes")]
    DuplicateIdentity(LocalIdentityId),
}

/// The published [`AclFilterScopes`]: one value, so a packet loading it sees
/// every field of one generation.
#[derive(Debug)]
pub(super) struct ScopeSet {
    /// 0 for the scope given at build, then increased by every replace.
    pub(super) generation: u64,
    pub(super) default: AclFilterScope,
    pub(super) by_identity: HashMap<LocalIdentityId, AclFilterScope, FlowHash>,
}

impl ScopeSet {
    pub(super) fn new(
        generation: u64,
        scopes: AclFilterScopes,
    ) -> Result<Self, AclFilterScopeError> {
        let mut by_identity =
            HashMap::with_capacity_and_hasher(scopes.identities.len(), FlowHash::default());
        for (id, scope) in scopes.identities {
            if by_identity.insert(id, scope).is_some() {
                return Err(AclFilterScopeError::DuplicateIdentity(id));
            }
        }
        Ok(Self {
            generation,
            default: scopes.default,
            by_identity,
        })
    }

    /// Whether no scope constrains anything.
    pub(super) fn is_unscoped(&self) -> bool {
        self.default.is_unconstrained()
            && self
                .by_identity
                .values()
                .all(AclFilterScope::is_unconstrained)
    }

    /// The scope of the local identity `id`.
    pub(super) fn select(&self, id: LocalIdentityId) -> &AclFilterScope {
        self.by_identity.get(&id).unwrap_or(&self.default)
    }
}

impl Inner {
    /// The scope from `set` of `peer`'s inbound packets from `src`; `None`
    /// on an invariant failure of the peer cache.
    #[inline]
    pub(super) fn inbound_scope<'s>(
        &self,
        set: &'s ScopeSet,
        snapshot: &Snapshot,
        peer: PeerId,
        src: IpAddr,
    ) -> Option<&'s AclFilterScope> {
        if set.by_identity.is_empty() {
            return Some(&set.default);
        }
        self.identity_scope(set, snapshot, peer, src)
    }

    /// [`inbound_scope`](Self::inbound_scope) with per-identity scopes.
    #[inline(never)]
    fn identity_scope<'s>(
        &self,
        set: &'s ScopeSet,
        snapshot: &Snapshot,
        peer: PeerId,
        src: IpAddr,
    ) -> Option<&'s AclFilterScope> {
        let identity = self.identity_generation();
        let local = if identity == 0 {
            self.identity.local_identity(peer)
        } else {
            let mut table = self.table();
            self.cached_peer(&mut table, snapshot, peer, Some(src), identity)?
                .local_identity
        };
        Some(set.select(local))
    }
}
