//! Enforced denials offered to a [`GateDivert`](super::GateDivert).
//!
//! A diverted packet is not an allow verdict: its taker must use a bounded
//! queue of its own and check [`DivertedPacket::generation`] against
//! [`FlowGate::generation`] before it acts on the packet.

use nsplane_packet::PeerId;

use super::config::{ScopeId, UnboundAction};
use super::packet::PacketMeta;
use super::{FlowGate, PacketDirection};
use crate::rules::RuleId;

/// A packet the gate denied and an [`UnboundAction::Divert`] rule offers to
/// the filter's [`GateDivert`](super::GateDivert). It has no public
/// constructor and no mutable access to the packet.
#[derive(Debug)]
pub struct DivertedPacket {
    generation: u64,
    peer: PeerId,
    scope: ScopeId,
    rule: RuleId,
    packet: Box<[u8]>,
}

impl DivertedPacket {
    /// The gate generation the packet was checked against; it is current
    /// while it equals [`FlowGate::generation`]. Two packets are under the
    /// same authority when generation, peer and rule are equal.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The peer the packet came from.
    #[must_use]
    pub const fn peer(&self) -> PeerId {
        self.peer
    }

    /// The scope whose unbound rule matched.
    #[must_use]
    pub const fn scope(&self) -> &ScopeId {
        &self.scope
    }

    /// The id of the matching [`UnboundRule`](super::UnboundRule).
    #[must_use]
    pub const fn rule(&self) -> &RuleId {
        &self.rule
    }

    /// The packet.
    #[must_use]
    pub const fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Take the packet.
    #[must_use]
    pub fn into_packet(self) -> Box<[u8]> {
        self.packet
    }
}

impl FlowGate {
    /// The divert candidate of an enforced inbound denial: a TCP or UDP
    /// packet matching an [`UnboundAction::Divert`] rule for `peer` of the
    /// one enforcing scope governing its destination, whose source is no
    /// local, binding or unbound address of any scope and that no hold
    /// matches.
    pub(super) fn divert_candidate(&self, peer: PeerId, packet: &[u8]) -> Option<DivertedPacket> {
        let meta = PacketMeta::parse(packet)?;
        if !matches!(meta.protocol, 6 | 17) {
            return None;
        }
        let snapshot = self.snapshot.load();
        let mut scopes = snapshot.with_local(meta.destination);
        let scope = scopes.next()?;
        if scopes.next().is_some()
            || !scope.enforce
            || snapshot.is_scope_address(meta.source)
            || snapshot.held(
                PacketDirection::Inbound,
                peer,
                meta.destination,
                meta.source,
            )
        {
            return None;
        }
        let rule = scope.unbound.iter().find(|rule| {
            rule.action == UnboundAction::Divert
                && rule.matches(peer, meta.protocol, meta.transport())
        })?;
        Some(DivertedPacket {
            generation: snapshot.generation,
            peer,
            scope: scope.id.clone(),
            rule: rule.id.clone(),
            packet: packet.into(),
        })
    }
}
