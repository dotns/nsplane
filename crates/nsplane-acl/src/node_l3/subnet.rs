//! Enforced Subnet authorization for ingress, return paths and transport.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::config::NodeL3Mode;
use super::decisions::Step;
use super::packet::{PacketMeta, flow_key};
use super::policy::{BindingKey, CompiledPolicy, CompiledSubnetGrant, TransportProjection};
use super::snapshot::Snapshot;
use super::state::{Admission, FlowState, ServiceFlowAuthorization, TcpClose, protocol_timeout};
use super::{NodeL3Gate, NodeL3SubnetAuthorization, PacketDirection};
use crate::net::IpNet;

/// Enforce policies whose tombstone is the same live Enforce generation.
fn enforced_policies(snapshot: &Snapshot) -> impl Iterator<Item = &CompiledPolicy> {
    snapshot
        .policies
        .values()
        .map(AsRef::as_ref)
        .filter(|policy| policy.mode == NodeL3Mode::Enforce && snapshot.tombstone_enforced(policy))
}

/// Whether `binding` is installed with the exact Enforce marker of `policy`.
fn binding_live(
    transport: &TransportProjection,
    binding: &BindingKey,
    policy: &CompiledPolicy,
) -> bool {
    transport.bindings.contains(binding) && transport.enforce_marker_matches(binding, policy)
}

/// Subnet Grants this local Node routes, for policies on the device address.
fn routed_grants<'a>(
    snapshot: &'a Snapshot,
    transport: &'a TransportProjection,
) -> impl Iterator<Item = (&'a CompiledPolicy, &'a CompiledSubnetGrant)> {
    enforced_policies(snapshot)
        .filter(|policy| transport.local_ip == policy.local.ip)
        .flat_map(|policy| {
            policy
                .subnet_grants
                .iter()
                .filter(|grant| grant.routing == policy.local.idx)
                .map(move |grant| (policy, grant))
        })
}

/// Sort key standing in for an order on [`IpNet`].
fn prefix_key(grant_prefix: &IpNet) -> (std::net::IpAddr, u8) {
    (grant_prefix.network(), grant_prefix.prefix_len())
}

impl NodeL3Gate {
    /// Return only Subnet Grants that are usable by this local Node now.
    ///
    /// A Grant remains withheld unless its policy is Enforce and the exact
    /// routing Node binding is installed with the matching authenticated peer
    /// marker. The caller must additionally intersect these rows with the
    /// source-scoped Subnet projection before publishing a route.
    #[must_use]
    pub fn enforced_subnet_authorizations(&self) -> Vec<NodeL3SubnetAuthorization> {
        let snapshot = self.snapshot.load();
        let Some(transport) = snapshot.installed_transport() else {
            return Vec::new();
        };
        let mut authorizations = Vec::new();
        for policy in enforced_policies(&snapshot) {
            if transport.local_ip != policy.local.ip {
                continue;
            }
            let Some(tombstone) = snapshot.tombstones.get(&policy.net) else {
                continue;
            };
            for grant in &policy.subnet_grants {
                if grant.source != policy.local.idx {
                    continue;
                }
                let Some((binding, _)) = policy.find_binding(|_, node| node.idx == grant.routing)
                else {
                    continue;
                };
                if !binding_live(transport, &binding, policy) {
                    continue;
                }
                authorizations.push(NodeL3SubnetAuthorization {
                    source_id: tombstone.source_id.clone(),
                    network_id: policy.network_id.clone(),
                    generation: policy.generation,
                    grant_id: grant.grant_id.clone(),
                    subnet_id: grant.subnet_id,
                    routing_node_id: grant.routing_node_id.clone(),
                    prefix: grant.prefix,
                    peer_key: binding.peer_key,
                });
            }
        }
        authorizations.sort_by(|left, right| {
            (
                left.source_id.as_str(),
                left.subnet_id,
                prefix_key(&left.prefix),
                left.grant_id.as_str(),
            )
                .cmp(&(
                    right.source_id.as_str(),
                    right.subnet_id,
                    prefix_key(&right.prefix),
                    right.grant_id.as_str(),
                ))
        });
        authorizations
    }

    /// Resolve an exact Subnet return identity back to its authenticated
    /// WireGuard peer while the matching Enforce Grant remains current.
    ///
    /// Subnet return identities embed the consumer Node IPv4 address, but a
    /// relay-carried peer need not own that address in WireGuard `AllowedIPs`.
    /// This lookup therefore matches the return prefix to the exact local
    /// Subnet Grant, its source Node, and the same fail-closed binding
    /// projection as packet authorization. Ambiguous identities are withheld.
    #[must_use]
    pub fn enforced_subnet_return_peer_key(&self, return_identity: Ipv6Addr) -> Option<[u8; 32]> {
        let address = return_identity.octets();
        if u16::from_be_bytes([address[6], address[7]]) != 2 || address[8..12] != [0, 0, 0, 0] {
            return None;
        }
        let node_ip = Ipv4Addr::new(address[12], address[13], address[14], address[15]);
        let snapshot = self.snapshot.load();
        let transport = snapshot.installed_transport()?;
        let mut matches = enforced_policies(&snapshot).flat_map(|policy| {
            policy.subnet_grants.iter().filter_map(move |grant| {
                if grant.routing != policy.local.idx || grant.network.octets()[..6] != address[..6]
                {
                    return None;
                }
                let (binding, _) = policy.find_binding(|binding, node| {
                    binding.ip == node_ip && node.idx == grant.source
                })?;
                binding_live(transport, &binding, policy).then_some(binding.peer_key)
            })
        });
        let peer_key = matches.next()?;
        matches
            .all(|candidate| candidate == peer_key)
            .then_some(peer_key)
    }

    /// Every exact Subnet return identity that
    /// [`Self::enforced_subnet_return_peer_key`] resolves now, with the peer it
    /// resolves to, sorted by identity. Read-only; a change bumps
    /// [`Self::authorization_generation`].
    #[must_use]
    pub fn enforced_subnet_return_owners(&self) -> Vec<(Ipv6Addr, [u8; 32])> {
        let snapshot = self.snapshot.load();
        let Some(transport) = snapshot.installed_transport() else {
            return Vec::new();
        };
        // `None` marks an identity whose matches disagree; it stays withheld.
        let mut owners = BTreeMap::<Ipv6Addr, Option<[u8; 32]>>::new();
        for policy in enforced_policies(&snapshot) {
            for grant in &policy.subnet_grants {
                if grant.routing != policy.local.idx {
                    continue;
                }
                let mut node_ips: Vec<Ipv4Addr> = Vec::new();
                for binding in &policy.binding_order {
                    if policy.bindings[binding].idx == grant.source
                        && !node_ips.contains(&binding.ip)
                    {
                        node_ips.push(binding.ip);
                    }
                }
                for node_ip in node_ips {
                    let Some((binding, _)) = policy.find_binding(|binding, node| {
                        binding.ip == node_ip && node.idx == grant.source
                    }) else {
                        continue;
                    };
                    if !binding_live(transport, &binding, policy) {
                        continue;
                    }
                    let mut identity = [0_u8; 16];
                    identity[..6].copy_from_slice(&grant.network.octets()[..6]);
                    identity[6..8].copy_from_slice(&2_u16.to_be_bytes());
                    identity[12..].copy_from_slice(&node_ip.octets());
                    owners
                        .entry(Ipv6Addr::from(identity))
                        .and_modify(|owner| {
                            if *owner != Some(binding.peer_key) {
                                *owner = None;
                            }
                        })
                        .or_insert(Some(binding.peer_key));
                }
            }
        }
        owners
            .into_iter()
            .filter_map(|(identity, owner)| owner.map(|owner| (identity, owner)))
            .collect()
    }

    /// Return whether an authenticated peer may originate a new flow toward a
    /// mapped Subnet owned by this local routing Node.
    ///
    /// Consumer route projection is intentionally directional and therefore
    /// does not publish the routing Node's own prefix back to itself. Inbound
    /// ownership must instead be proven by the exact enforced Subnet Grant and
    /// the currently installed peer binding for its source Node.
    #[must_use]
    pub fn enforced_subnet_ingress_authorized(
        &self,
        peer_key: [u8; 32],
        destination: Ipv6Addr,
    ) -> bool {
        let snapshot = self.snapshot.load();
        let Some(transport) = snapshot.installed_transport() else {
            return false;
        };
        routed_grants(&snapshot, transport).any(|(policy, grant)| {
            grant.contains(destination)
                && policy
                    .find_binding(|binding, node| {
                        binding.peer_key == peer_key
                            && node.idx == grant.source
                            && binding_live(transport, binding, policy)
                    })
                    .is_some()
        })
    }

    /// Every `(peer key, mapped prefix)` pair for which
    /// [`Self::enforced_subnet_ingress_authorized`] holds for the addresses of
    /// the prefix, under the same conditions, sorted and deduplicated.
    ///
    /// The runtime folds these prefixes into the per-peer inbound destinations
    /// of the data plane. It must recompute and push them whenever
    /// [`Self::authorization_generation`] changes.
    #[must_use]
    pub fn enforced_subnet_ingress_prefixes(&self) -> Vec<([u8; 32], IpNet)> {
        let snapshot = self.snapshot.load();
        let Some(transport) = snapshot.installed_transport() else {
            return Vec::new();
        };
        let mut prefixes: Vec<([u8; 32], IpNet)> = Vec::new();
        for (policy, grant) in routed_grants(&snapshot, transport) {
            for binding in &policy.binding_order {
                if policy.bindings[binding].idx == grant.source
                    && binding_live(transport, binding, policy)
                {
                    prefixes.push((binding.peer_key, grant.prefix));
                }
            }
        }
        prefixes.sort_by_key(|(peer_key, prefix)| (*peer_key, prefix_key(prefix)));
        prefixes.dedup();
        prefixes
    }

    /// Admit one reserved UDP request carried by an exact Enforce Subnet Grant.
    ///
    /// The application layer independently validates the directed Subnet/DNS
    /// fingerprint. This narrow transport exception only creates ordinary
    /// stateful Node L3 flow state when the request's decrypting peer, Node IP,
    /// policy generation, transport marker, and Subnet routing direction all
    /// agree. Replies and fragments then use the normal flow-state path.
    pub(super) fn evaluate_subnet_transport(
        &self,
        direction: PacketDirection,
        peer_key: [u8; 32],
        packet: &[u8],
        destination_port: u16,
    ) -> bool {
        let Some(meta) = PacketMeta::parse(packet) else {
            return false;
        };
        if meta.protocol != 17
            || meta.fragment_offset != 0
            || meta.dst_port != Some(destination_port)
        {
            return false;
        }
        let now = (self.clock)();
        let mut swept = false;
        loop {
            let snapshot = self.snapshot.load();
            match self.subnet_transport_once(&snapshot, direction, peer_key, &meta, now, swept) {
                Step::Done(admitted) => return admitted,
                Step::Retry => {}
                Step::SweepAll => {
                    drop(snapshot);
                    self.state.sweep_all(now);
                    swept = true;
                }
            }
        }
    }

    fn subnet_transport_once(
        &self,
        snapshot: &Snapshot,
        direction: PacketDirection,
        peer_key: [u8; 32],
        meta: &PacketMeta,
        now: Instant,
        swept: bool,
    ) -> Step<bool> {
        let Some(transport) = snapshot.installed_transport() else {
            return Step::Done(false);
        };
        let mut matches = enforced_policies(snapshot).filter(|policy| {
            if transport.local_ip != policy.local.ip {
                return false;
            }
            let (source, target, remote) = match direction {
                PacketDirection::Inbound if meta.destination == policy.local.ip => {
                    let binding = BindingKey {
                        peer_key,
                        ip: meta.source,
                    };
                    let Some(source) = policy.bindings.get(&binding) else {
                        return false;
                    };
                    (source, &policy.local, binding)
                }
                PacketDirection::Outbound if meta.source == policy.local.ip => {
                    let binding = BindingKey {
                        peer_key,
                        ip: meta.destination,
                    };
                    let Some(target) = policy.bindings.get(&binding) else {
                        return false;
                    };
                    (&policy.local, target, binding)
                }
                _ => return false,
            };
            binding_live(transport, &remote, policy)
                && policy
                    .subnet_grants
                    .iter()
                    .any(|grant| grant.source == source.idx && grant.routing == target.idx)
        });
        let Some(policy) = matches.next() else {
            return Step::Done(false);
        };
        if matches.next().is_some() {
            return Step::Done(false);
        }
        let Some(flow_key) = flow_key(policy, direction, peer_key, meta) else {
            return Step::Done(false);
        };
        let Some(mut shard) = self.lock_shard(snapshot, &peer_key) else {
            return Step::Retry;
        };
        let counts = &self.state.counts;
        if shard.touch_flow(&flow_key, now, counts) {
            return Step::Done(true);
        }
        let admission = shard.insert_flow_with_fragment(
            flow_key,
            FlowState {
                initiator: direction,
                service_authorization: ServiceFlowAuthorization::None,
                enforced: true,
                close: TcpClose::default(),
                expires_at: now + protocol_timeout(meta.protocol),
            },
            meta.more_fragments
                .then(|| meta.fragment_key(policy, direction, peer_key)),
            now,
            counts,
            swept,
        );
        match admission {
            Admission::Admitted => {
                self.counters
                    .enforced_allowed
                    .fetch_add(1, Ordering::Relaxed);
                Step::Done(true)
            }
            Admission::Full => {
                self.counters
                    .state_capacity_denied
                    .fetch_add(1, Ordering::Relaxed);
                Step::Done(false)
            }
            Admission::SweepAll => Step::SweepAll,
        }
    }
}
