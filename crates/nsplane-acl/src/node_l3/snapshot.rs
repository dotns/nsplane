//! The immutable snapshot read by packet paths and its precomputed indexes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use super::PacketDirection;
use super::config::NodeL3Mode;
use super::hash::{FastMap, FastSet};
use super::policy::{BindingKey, CompiledPolicy, NetIdx, ProviderListenerKey, TransportProjection};

/// The part of a Network tombstone that packet paths and queries read.
#[derive(Debug, Clone)]
pub(super) struct TombstoneView {
    pub(super) network_id: String,
    pub(super) source_id: String,
    pub(super) target_machine_id: String,
    pub(super) generation: u64,
    pub(super) mode: NodeL3Mode,
}

/// Provider listeners with an index by `(protocol, port)`.
#[derive(Debug, Default)]
pub(super) struct ProviderListeners {
    pub(super) set: HashSet<ProviderListenerKey>,
    /// `(target_machine_id, service_id)` per `(protocol, port)`.
    by_port: FastMap<(u8, u16), Vec<(String, String)>>,
}

impl ProviderListeners {
    pub(super) fn new(set: HashSet<ProviderListenerKey>) -> Self {
        let mut by_port = FastMap::<_, Vec<_>>::default();
        for key in &set {
            by_port
                .entry((key.protocol, key.port))
                .or_default()
                .push((key.target_machine_id.clone(), key.service_id.clone()));
        }
        Self { set, by_port }
    }

    /// Whether `target_machine_id` owns any listener on `protocol`/`port`.
    pub(super) fn target_listens(&self, target_machine_id: &str, protocol: u8, port: u16) -> bool {
        self.by_port
            .get(&(protocol, port))
            .is_some_and(|owners| owners.iter().any(|(target, _)| target == target_machine_id))
    }

    /// Whether the exact Service listener is owned by `target_machine_id`.
    pub(super) fn contains(
        &self,
        target_machine_id: &str,
        service_id: &str,
        protocol: u8,
        port: u16,
    ) -> bool {
        self.by_port.get(&(protocol, port)).is_some_and(|owners| {
            owners
                .iter()
                .any(|(target, service)| target == target_machine_id && service == service_id)
        })
    }
}

/// The transport's authoritative markers, and those that are not ready by
/// address and peer key.
#[derive(Debug, Default)]
struct PendingAuthority {
    /// The transport's authoritative local addresses.
    local_ips: FastSet<Ipv4Addr>,
    /// Every authoritative binding: whether its marker is not ready.
    bindings: FastMap<BindingKey, bool>,
    ips: FastSet<Ipv4Addr>,
    peers: FastSet<[u8; 32]>,
}

/// Everything packet paths read, published atomically as one value.
#[derive(Debug, Default)]
pub(super) struct Snapshot {
    /// Matches the epoch of every state shard once the publishing writer has
    /// migrated it.
    pub(super) epoch: u64,
    pub(super) policies: BTreeMap<NetIdx, Arc<CompiledPolicy>>,
    pub(super) transport: Option<Arc<TransportProjection>>,
    pub(super) listeners: Arc<ProviderListeners>,
    pub(super) tombstones: Arc<HashMap<NetIdx, TombstoneView>>,
    by_binding: FastMap<BindingKey, Vec<Arc<CompiledPolicy>>>,
    by_local_ip: FastMap<Ipv4Addr, Vec<Arc<CompiledPolicy>>>,
    by_remote_ip: FastMap<Ipv4Addr, Vec<Arc<CompiledPolicy>>>,
    pending: PendingAuthority,
}

impl Snapshot {
    pub(super) fn build(
        epoch: u64,
        policies: BTreeMap<NetIdx, Arc<CompiledPolicy>>,
        transport: Option<Arc<TransportProjection>>,
        listeners: Arc<ProviderListeners>,
        tombstones: Arc<HashMap<NetIdx, TombstoneView>>,
    ) -> Self {
        let mut by_binding = FastMap::<_, Vec<_>>::default();
        let mut by_local_ip = FastMap::<_, Vec<_>>::default();
        let mut by_remote_ip = FastMap::<_, Vec<_>>::default();
        for policy in policies.values() {
            by_local_ip
                .entry(policy.local.ip)
                .or_default()
                .push(Arc::clone(policy));
            for binding in &policy.binding_order {
                by_binding
                    .entry(*binding)
                    .or_default()
                    .push(Arc::clone(policy));
            }
            for ip in &policy.remote_ips {
                by_remote_ip
                    .entry(*ip)
                    .or_default()
                    .push(Arc::clone(policy));
            }
        }
        let pending = transport
            .as_deref()
            .map(|transport| pending_authority(transport, &policies))
            .unwrap_or_default();
        Self {
            epoch,
            policies,
            transport,
            listeners,
            tombstones,
            by_binding,
            by_local_ip,
            by_remote_ip,
            pending,
        }
    }

    fn resolve(
        policies: Option<&Vec<Arc<CompiledPolicy>>>,
    ) -> impl Iterator<Item = &CompiledPolicy> {
        policies.into_iter().flatten().map(AsRef::as_ref)
    }

    /// Policies binding `binding` as a remote Node.
    pub(super) fn bound(&self, binding: &BindingKey) -> impl Iterator<Item = &CompiledPolicy> {
        Self::resolve(self.by_binding.get(binding))
    }

    /// Policies whose local Node has address `ip`.
    pub(super) fn with_local_ip(&self, ip: Ipv4Addr) -> impl Iterator<Item = &CompiledPolicy> {
        Self::resolve(self.by_local_ip.get(&ip))
    }

    /// Policies with a remote Node at address `ip`.
    pub(super) fn with_remote_ip(&self, ip: Ipv4Addr) -> impl Iterator<Item = &CompiledPolicy> {
        Self::resolve(self.by_remote_ip.get(&ip))
    }

    /// Whether any policy has `ip` as its local or a remote Node address.
    pub(super) fn is_node_ip(&self, ip: Ipv4Addr) -> bool {
        self.by_local_ip.contains_key(&ip) || self.by_remote_ip.contains_key(&ip)
    }

    /// Whether `policy` is the live Enforce generation of its tombstone.
    /// The tombstone of `network_id` and its interned index.
    pub(super) fn tombstone(&self, network_id: &str) -> Option<(NetIdx, &TombstoneView)> {
        self.tombstones
            .iter()
            .find(|(_, tombstone)| tombstone.network_id == network_id)
            .map(|(net, tombstone)| (*net, tombstone))
    }

    /// The active policy of `network_id`.
    pub(super) fn policy_by_id(&self, network_id: &str) -> Option<&CompiledPolicy> {
        self.policies
            .values()
            .find(|policy| policy.network_id == network_id)
            .map(AsRef::as_ref)
    }

    pub(super) fn tombstone_enforced(&self, policy: &CompiledPolicy) -> bool {
        self.tombstones.get(&policy.net).is_some_and(|tombstone| {
            tombstone.generation == policy.generation && tombstone.mode == NodeL3Mode::Enforce
        })
    }

    /// The installed transport, if any.
    pub(super) fn installed_transport(&self) -> Option<&TransportProjection> {
        self.transport
            .as_deref()
            .filter(|transport| transport.installed)
    }

    pub(super) fn gateway_carrier_installed(
        &self,
        peer_key: [u8; 32],
        policy: &CompiledPolicy,
    ) -> bool {
        self.installed_transport().is_some_and(|transport| {
            transport.local_ip == policy.local.ip
                && transport.gateway_carriers.contains_key(&peer_key)
        })
    }

    /// Whether an authoritative transport marker for this packet's addresses
    /// is not yet matched by the applied policy (fail closed).
    pub(super) fn policy_pending(
        &self,
        direction: PacketDirection,
        peer_key: [u8; 32],
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> bool {
        if self.transport.is_none() {
            return false;
        }
        // A Node `/32` marker is authoritative for the address, not merely for
        // one route-table entry. If an accidental duplicate route selects a
        // different unmarked peer, it must not become a pre-policy Legacy
        // escape hatch. Service/Gateway `/32`s are absent from `node_ips` and
        // therefore remain on the legacy L4 path.
        match direction {
            PacketDirection::Outbound => self.pending.ips.contains(&destination),
            PacketDirection::Inbound => {
                if !self.pending.local_ips.contains(&destination) {
                    return false;
                }
                let exact = BindingKey {
                    peer_key,
                    ip: source,
                };
                if let Some(pending) = self.pending.bindings.get(&exact) {
                    return *pending;
                }
                // Before the snapshot exists, the marked peer must not bypass
                // the gate merely by forging an unprojected inner source.
                self.pending.ips.contains(&source) || self.pending.peers.contains(&peer_key)
            }
        }
    }
}

fn pending_authority(
    transport: &TransportProjection,
    policies: &BTreeMap<NetIdx, Arc<CompiledPolicy>>,
) -> PendingAuthority {
    let by_id: HashMap<&str, &CompiledPolicy> = policies
        .values()
        .map(|policy| (policy.network_id.as_str(), policy.as_ref()))
        .collect();
    let mut pending = PendingAuthority {
        local_ips: transport.authoritative_local_ips.iter().copied().collect(),
        ..PendingAuthority::default()
    };
    for (binding, requirement) in &transport.authoritative_bindings {
        let ready = transport.installed
            && transport.bindings.contains(binding)
            && by_id
                .get(requirement.network_id.as_str())
                .is_some_and(|policy| {
                    policy.generation == requirement.generation
                        && policy.mode == requirement.mode
                        && policy.local.ip == transport.local_ip
                        && policy.bindings.get(binding).is_some_and(|node| {
                            requirement.mode == NodeL3Mode::Enforce
                                || node.owner_id == policy.local.owner_id
                        })
                });
        pending.bindings.insert(*binding, !ready);
        if !ready {
            pending.ips.insert(binding.ip);
            pending.peers.insert(binding.peer_key);
        }
    }
    pending
}
