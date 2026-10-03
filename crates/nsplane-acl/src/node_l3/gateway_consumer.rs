//! Authenticated gateway packets awaiting a consumer-flow ownership check.
//!
//! These are not an L3 allow verdict. Callers must use a separate bounded
//! consumer queue and must never forward an unmatched candidate to a host TUN.

use std::sync::Arc;

use super::config::NodeL3Mode;
use super::packet::PacketMeta;
use super::policy::{CompiledPolicy, TransportProjection};
use super::{NodeL3Gate, PacketDirection};

/// Authority captured from an installed gateway peer and a local Enforce policy.
/// Fields are opaque so a receiver cannot substitute a different peer or epoch.
#[derive(Debug, Clone)]
pub struct GatewayConsumerAuthority {
    peer_key: [u8; 32],
    gateway_id: String,
    source_id: String,
    policy: Arc<CompiledPolicy>,
    transport: Arc<TransportProjection>,
}

impl GatewayConsumerAuthority {
    /// Authenticated gateway id from the installed transport projection.
    #[must_use]
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    /// Source that owns the local policy snapshot.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Whether two fragments were admitted under the exact same authority.
    #[must_use]
    pub fn same_snapshot(&self, other: &Self) -> bool {
        self.peer_key == other.peer_key
            && self.gateway_id == other.gateway_id
            && self.source_id == other.source_id
            && Arc::ptr_eq(&self.policy, &other.policy)
            && Arc::ptr_eq(&self.transport, &other.transport)
    }
}

/// A decrypted packet that still requires an exact live Gateway Egress flow.
/// This type deliberately has no public constructor or mutable packet access.
#[derive(Debug)]
pub struct GatewayConsumerPacket {
    authority: GatewayConsumerAuthority,
    packet: Box<[u8]>,
}

impl GatewayConsumerPacket {
    /// Authority to recheck immediately before consumer delivery.
    #[must_use]
    pub const fn authority(&self) -> &GatewayConsumerAuthority {
        &self.authority
    }

    /// Read-only packet view for exact consumer-flow classification.
    #[must_use]
    pub const fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Consume a candidate after its authority and flow checks have passed.
    #[must_use]
    pub fn into_packet(self) -> Box<[u8]> {
        self.packet
    }
}

impl NodeL3Gate {
    /// Capture gateway authority without granting access to the Node L3 plane.
    /// The caller must still require an exact live consumer and its route owner.
    #[must_use]
    pub fn gateway_consumer_packet(
        &self,
        peer_key: [u8; 32],
        packet: &[u8],
    ) -> Option<GatewayConsumerPacket> {
        let meta = PacketMeta::parse(packet)?;
        if !matches!(meta.protocol, 6 | 17) {
            return None;
        }
        let snapshot = self.snapshot.load();
        let mut local = snapshot.with_local_ip(meta.destination);
        let policy = local.next()?;
        if local.next().is_some()
            || policy.mode != NodeL3Mode::Enforce
            || snapshot.is_node_ip(meta.source)
            || snapshot.policy_pending(
                PacketDirection::Inbound,
                peer_key,
                meta.source,
                meta.destination,
            )
        {
            return None;
        }
        let transport = snapshot.transport.clone()?;
        if !transport.installed || transport.local_ip != meta.destination {
            return None;
        }
        let gateway_id = transport.gateway_carriers.get(&peer_key)?.clone();
        let source = snapshot.tombstones.get(&policy.net)?;
        if source.generation != policy.generation
            || source.mode != NodeL3Mode::Enforce
            || source.target_machine_id != policy.target_machine_id
        {
            return None;
        }
        Some(GatewayConsumerPacket {
            authority: GatewayConsumerAuthority {
                peer_key,
                gateway_id,
                source_id: source.source_id.clone(),
                policy: Arc::clone(snapshot.policies.get(&policy.net)?),
                transport,
            },
            packet: packet.into(),
        })
    }

    /// Reject queued packets and fragments after a policy or device replacement.
    #[must_use]
    pub fn gateway_consumer_authority_current(&self, authority: &GatewayConsumerAuthority) -> bool {
        let snapshot = self.snapshot.load();
        snapshot
            .policies
            .get(&authority.policy.net)
            .is_some_and(|policy| Arc::ptr_eq(policy, &authority.policy))
            && snapshot
                .transport
                .as_ref()
                .is_some_and(|transport| Arc::ptr_eq(transport, &authority.transport))
    }
}
