//! Compiled Network policies and transport projections.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use super::config::{
    NodeL3Config, NodeL3Mode, NodeL3PeerPolicyRequirement, NodeL3Resource, NodeL3ServiceEndpoint,
    NodeL3Transport,
};
use super::hash::{FastMap, FastSet};
use super::state::peer_word;
use super::{NodeL3ConfigError, NodeL3TransportError};
use crate::net::IpNet;

/// Interned Network id, stable for the gate's lifetime.
pub(super) type NetIdx = u32;

/// Index of a Node within one compiled policy (the local Node is 0).
pub(super) type NodeIdx = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BindingKey {
    pub(super) peer_key: [u8; 32],
    pub(super) ip: Ipv4Addr,
}

impl Hash for BindingKey {
    /// One word: the address folded with the first word of the peer key.
    /// Bindings are looked up, never inserted, by packets.
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(peer_word(&self.peer_key) ^ u64::from(self.ip.to_bits()));
    }
}

#[derive(Debug, Clone)]
pub(super) struct NodeIdentity {
    pub(super) idx: NodeIdx,
    pub(super) node_id: String,
    pub(super) owner_id: String,
    pub(super) ip: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ServiceKey {
    pub(super) node: NodeIdx,
    pub(super) protocol: u8,
    pub(super) port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ProviderListenerKey {
    pub(super) target_machine_id: String,
    pub(super) service_id: String,
    pub(super) protocol: u8,
    pub(super) port: u16,
}

/// A validated Subnet Grant (always a mapped IPv6 prefix).
#[derive(Debug, Clone)]
pub(super) struct CompiledSubnetGrant {
    pub(super) grant_id: String,
    pub(super) source: NodeIdx,
    pub(super) subnet_id: u32,
    pub(super) routing: NodeIdx,
    pub(super) routing_node_id: String,
    pub(super) prefix: IpNet,
    pub(super) network: Ipv6Addr,
}

impl CompiledSubnetGrant {
    pub(super) fn contains(&self, address: Ipv6Addr) -> bool {
        self.prefix.contains(&IpAddr::V6(address))
    }
}

#[derive(Debug)]
pub(super) struct CompiledPolicy {
    pub(super) net: NetIdx,
    pub(super) network_id: String,
    pub(super) target_machine_id: String,
    pub(super) generation: u64,
    pub(super) mode: NodeL3Mode,
    pub(super) local: NodeIdentity,
    pub(super) bindings: FastMap<BindingKey, NodeIdentity>,
    /// Distinct binding keys in snapshot order, for deterministic searches.
    pub(super) binding_order: Vec<BindingKey>,
    pub(super) remote_ips: HashSet<Ipv4Addr>,
    pub(super) services: FastMap<ServiceKey, Arc<str>>,
    /// `(source, target)` Node Grants.
    pub(super) node_grants: FastSet<(NodeIdx, NodeIdx)>,
    /// `(source, target, protocol, port)` Service Grants. Compilation proves
    /// that the granted Service is the one projected on that listener.
    pub(super) service_grants: FastSet<(NodeIdx, NodeIdx, u8, u16)>,
    pub(super) subnet_grants: Vec<CompiledSubnetGrant>,
}

impl CompiledPolicy {
    pub(super) fn compile(config: &NodeL3Config, net: NetIdx) -> Result<Self, NodeL3ConfigError> {
        require_non_empty(&config.network_id, "network_id")?;
        require_non_empty(&config.target_machine_id, "target_machine_id")?;
        require_non_empty(&config.local_node.node_id, "local_node.node_id")?;
        require_non_empty(&config.local_node.owner_id, "local_node.owner_id")?;
        if config.generation == 0 && config.mode != NodeL3Mode::Disabled {
            return Err(NodeL3ConfigError::ZeroGeneration);
        }

        let local = NodeIdentity {
            idx: 0,
            node_id: config.local_node.node_id.clone(),
            owner_id: config.local_node.owner_id.clone(),
            ip: config.local_node.ip,
        };
        let Bindings {
            nodes,
            by_key: bindings,
            order: binding_order,
        } = compile_bindings(config, &local)?;
        let mut services = FastMap::default();
        for service in &config.services {
            validate_service(service, &nodes)?;
            let key = ServiceKey {
                node: nodes[&service.node_id].idx,
                protocol: service.protocol.ip_protocol(),
                port: service.port,
            };
            let service_id: Arc<str> = Arc::from(service.service_id.as_str());
            if let Some(previous) = services.insert(key, Arc::clone(&service_id))
                && previous != service_id
            {
                return Err(NodeL3ConfigError::Conflict("service listener"));
            }
        }

        let grants = compile_grants(config, &nodes, &services)?;
        let remote_ips = bindings.values().map(|node| node.ip).collect();
        Ok(Self {
            net,
            network_id: config.network_id.clone(),
            target_machine_id: config.target_machine_id.clone(),
            generation: config.generation,
            mode: config.mode,
            local,
            bindings,
            binding_order,
            remote_ips,
            services,
            node_grants: grants.node,
            service_grants: grants.service,
            subnet_grants: grants.subnet,
        })
    }

    pub(super) fn service_for(&self, node: NodeIdx, protocol: u8, port: u16) -> Option<&Arc<str>> {
        self.services.get(&ServiceKey {
            node,
            protocol,
            port,
        })
    }

    pub(super) fn has_node_grant(&self, source: NodeIdx, target: NodeIdx) -> bool {
        self.node_grants.contains(&(source, target))
    }

    pub(super) fn has_service_grant(
        &self,
        source: NodeIdx,
        target: NodeIdx,
        protocol: u8,
        port: u16,
    ) -> bool {
        self.service_grants
            .contains(&(source, target, protocol, port))
    }

    pub(super) fn has_remote_node_ip(&self, ip: Ipv4Addr) -> bool {
        self.remote_ips.contains(&ip)
    }

    /// The first binding (in snapshot order) matching `predicate`.
    pub(super) fn find_binding(
        &self,
        mut predicate: impl FnMut(&BindingKey, &NodeIdentity) -> bool,
    ) -> Option<(BindingKey, &NodeIdentity)> {
        self.binding_order.iter().find_map(|key| {
            let node = &self.bindings[key];
            predicate(key, node).then_some((*key, node))
        })
    }
}

/// Validated peer bindings and the Node table (local Node included).
struct Bindings {
    nodes: HashMap<String, NodeIdentity>,
    by_key: FastMap<BindingKey, NodeIdentity>,
    order: Vec<BindingKey>,
}

fn compile_bindings(
    config: &NodeL3Config,
    local: &NodeIdentity,
) -> Result<Bindings, NodeL3ConfigError> {
    let mut bindings = FastMap::default();
    let mut binding_order = Vec::new();
    let mut node_bindings = HashMap::new();
    let mut nodes = HashMap::from([(local.node_id.clone(), local.clone())]);
    let mut ip_nodes = HashMap::from([(local.ip, local.node_id.clone())]);
    for binding in &config.bindings {
        require_non_empty(&binding.node_id, "bindings.node_id")?;
        require_non_empty(&binding.owner_id, "bindings.owner_id")?;
        if binding.node_id == local.node_id || binding.ip == local.ip {
            return Err(NodeL3ConfigError::Conflict("local node peer binding"));
        }
        let next_idx = NodeIdx::try_from(nodes.len())
            .map_err(|_| NodeL3ConfigError::Conflict("node count"))?;
        let identity = NodeIdentity {
            idx: nodes
                .get(&binding.node_id)
                .map_or(next_idx, |node| node.idx),
            node_id: binding.node_id.clone(),
            owner_id: binding.owner_id.clone(),
            ip: binding.ip,
        };
        if let Some(previous) = nodes.insert(binding.node_id.clone(), identity.clone())
            && (previous.owner_id != identity.owner_id || previous.ip != identity.ip)
        {
            return Err(NodeL3ConfigError::Conflict("node identity"));
        }
        if let Some(previous) = ip_nodes.insert(binding.ip, binding.node_id.clone())
            && previous != binding.node_id
        {
            return Err(NodeL3ConfigError::Conflict("node IP"));
        }
        let key = BindingKey {
            peer_key: binding.peer_public_key,
            ip: binding.ip,
        };
        match bindings.insert(key, identity.clone()) {
            Some(previous) if previous.node_id != identity.node_id => {
                return Err(NodeL3ConfigError::Conflict("peer/source binding"));
            }
            Some(_) => {}
            None => binding_order.push(key),
        }
        if let Some(previous) = node_bindings.insert(binding.node_id.clone(), key)
            && previous.ip != binding.ip
        {
            return Err(NodeL3ConfigError::Conflict("node transport binding"));
        }
    }

    Ok(Bindings {
        nodes,
        by_key: bindings,
        order: binding_order,
    })
}

/// Validated Grants by kind.
struct Grants {
    node: FastSet<(NodeIdx, NodeIdx)>,
    service: FastSet<(NodeIdx, NodeIdx, u8, u16)>,
    subnet: Vec<CompiledSubnetGrant>,
}

fn compile_grants(
    config: &NodeL3Config,
    nodes: &HashMap<String, NodeIdentity>,
    services: &FastMap<ServiceKey, Arc<str>>,
) -> Result<Grants, NodeL3ConfigError> {
    let mut node_grants = FastSet::default();
    let mut service_grants = FastSet::default();
    let mut subnet_grants = Vec::new();
    for grant in &config.grants {
        require_non_empty(&grant.grant_id, "grants.grant_id")?;
        require_non_empty(&grant.source_node_id, "grants.source_node_id")?;
        // `grant_id` is logical policy provenance, not an expanded-edge
        // primary key. One UI ACL may intentionally project the same ID
        // over many source Node/resource pairs.
        let Some(source) = nodes.get(&grant.source_node_id) else {
            return Err(NodeL3ConfigError::UnknownNode(grant.source_node_id.clone()));
        };
        match &grant.resource {
            NodeL3Resource::Node { node_id } => {
                let Some(target) = nodes.get(node_id) else {
                    return Err(NodeL3ConfigError::UnknownNode(node_id.clone()));
                };
                node_grants.insert((source.idx, target.idx));
            }
            NodeL3Resource::Service {
                service_id,
                node_id,
                protocol,
                port,
            } => {
                let projected = nodes.get(node_id).and_then(|node| {
                    let key = ServiceKey {
                        node: node.idx,
                        protocol: protocol.ip_protocol(),
                        port: *port,
                    };
                    services.get(&key).map(|projected| (key, projected))
                });
                let Some((key, projected)) = projected else {
                    return Err(NodeL3ConfigError::UnknownService(service_id.clone()));
                };
                if **projected != **service_id {
                    return Err(NodeL3ConfigError::UnknownService(service_id.clone()));
                }
                service_grants.insert((source.idx, key.node, key.protocol, key.port));
            }
            NodeL3Resource::Subnet {
                subnet_id,
                routing_node_id,
                prefix,
            } => {
                let parsed_subnet_id = subnet_id
                    .parse::<u32>()
                    .ok()
                    .filter(|value| *value != 0 && value.to_string() == *subnet_id)
                    .ok_or_else(|| NodeL3ConfigError::InvalidSubnetId(subnet_id.clone()))?;
                let Some(routing) = nodes.get(routing_node_id) else {
                    return Err(NodeL3ConfigError::UnknownNode(routing_node_id.clone()));
                };
                let IpAddr::V6(network) = prefix.network() else {
                    return Err(NodeL3ConfigError::InvalidSubnetPrefix(*prefix));
                };
                if prefix.prefix_len() < 96 {
                    return Err(NodeL3ConfigError::InvalidSubnetPrefix(*prefix));
                }
                subnet_grants.push(CompiledSubnetGrant {
                    grant_id: grant.grant_id.clone(),
                    source: source.idx,
                    subnet_id: parsed_subnet_id,
                    routing: routing.idx,
                    routing_node_id: routing_node_id.clone(),
                    prefix: *prefix,
                    network,
                });
            }
        }
    }

    Ok(Grants {
        node: node_grants,
        service: service_grants,
        subnet: subnet_grants,
    })
}

pub(super) fn require_non_empty(value: &str, field: &'static str) -> Result<(), NodeL3ConfigError> {
    if value.trim().is_empty() {
        Err(NodeL3ConfigError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn validate_service(
    service: &NodeL3ServiceEndpoint,
    nodes: &HashMap<String, NodeIdentity>,
) -> Result<(), NodeL3ConfigError> {
    require_non_empty(&service.service_id, "services.service_id")?;
    require_non_empty(&service.node_id, "services.node_id")?;
    if service.port == 0 {
        return Err(NodeL3ConfigError::ZeroServicePort);
    }
    if !nodes.contains_key(&service.node_id) {
        return Err(NodeL3ConfigError::UnknownNode(service.node_id.clone()));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(super) struct TransportProjection {
    pub(super) local_ip: Ipv4Addr,
    /// Local addresses that an old or staged WireGuard device may still
    /// deliver while its replacement is not yet installed.
    pub(super) authoritative_local_ips: HashSet<Ipv4Addr>,
    pub(super) bindings: HashSet<BindingKey>,
    pub(super) authoritative_bindings: HashMap<BindingKey, NodeL3PeerPolicyRequirement>,
    /// Terminate/Public gateway peers named explicitly by the control plane.
    /// Endpoint- or port-derived gateway names are deliberately absent.
    pub(super) gateway_carriers: HashMap<[u8; 32], String>,
    pub(super) installed: bool,
}

impl TransportProjection {
    /// Whether `binding` carries the exact Enforce marker of `policy`.
    pub(super) fn enforce_marker_matches(
        &self,
        binding: &BindingKey,
        policy: &CompiledPolicy,
    ) -> bool {
        self.authoritative_bindings
            .get(binding)
            .is_some_and(|requirement| {
                requirement.network_id == policy.network_id
                    && requirement.generation == policy.generation
                    && requirement.mode == NodeL3Mode::Enforce
            })
    }
}

#[derive(Debug, Clone)]
pub(super) struct TransportProjectionSpec {
    pub(super) local_ip: Ipv4Addr,
    pub(super) bindings: HashSet<BindingKey>,
    pub(super) authoritative_bindings: HashMap<BindingKey, NodeL3PeerPolicyRequirement>,
    pub(super) gateway_carriers: HashMap<[u8; 32], String>,
}

pub(super) fn compile_transport_projection(
    config: &NodeL3Transport,
) -> Result<TransportProjectionSpec, NodeL3TransportError> {
    let mut bindings = HashSet::new();
    let mut authoritative_bindings = HashMap::new();
    let mut authoritative_owners = HashMap::<Ipv4Addr, [u8; 32]>::new();
    let mut gateway_carriers = HashMap::new();
    let mut seen_peer_keys = HashSet::new();
    for peer in &config.peers {
        if !seen_peer_keys.insert(peer.public_key) {
            // A WireGuard public key is the authenticated identity. Multiple
            // declarations could otherwise split gateway and Node/relay roles
            // across entries and inherit the least restrictive classifier.
            gateway_carriers.remove(&peer.public_key);
        } else if let Some(gateway_id) = peer
            .gateway_id
            .as_deref()
            .map(str::trim)
            .filter(|gateway_id| !gateway_id.is_empty())
            .filter(|_| peer.node_l3_policy.is_none() && !peer.relayed)
        {
            gateway_carriers.insert(peer.public_key, gateway_id.to_owned());
        }
        let mut peer_exact_ips = HashSet::new();
        for network in &peer.allowed_ips {
            let IpAddr::V4(ip) = network.network() else {
                continue;
            };
            if network.prefix_len() != 32 || ip == config.local_ip {
                continue;
            }
            bindings.insert(BindingKey {
                peer_key: peer.public_key,
                ip,
            });
            peer_exact_ips.insert(ip);
        }
        if let Some(requirement) = &peer.node_l3_policy {
            if requirement.network_id.trim().is_empty() {
                return Err(NodeL3TransportError::InvalidPolicyMarker(
                    "empty network_id",
                ));
            }
            if requirement.generation == 0 {
                return Err(NodeL3TransportError::InvalidPolicyMarker("zero generation"));
            }
            if requirement.mode == NodeL3Mode::Disabled {
                return Err(NodeL3TransportError::InvalidPolicyMarker("disabled mode"));
            }
            if requirement.node_ips.is_empty() {
                return Err(NodeL3TransportError::InvalidPolicyMarker("empty node_ips"));
            }
            for ip in &requirement.node_ips {
                if !peer_exact_ips.contains(ip) {
                    return Err(NodeL3TransportError::InvalidPolicyMarker(
                        "node_ip is not an exact allowed IP of this peer",
                    ));
                }
                if let Some(previous) = authoritative_owners.insert(*ip, peer.public_key)
                    && previous != peer.public_key
                {
                    return Err(NodeL3TransportError::AmbiguousNodeRoute { ip: *ip });
                }
                let binding = BindingKey {
                    peer_key: peer.public_key,
                    ip: *ip,
                };
                if let Some(previous) = authoritative_bindings.insert(binding, requirement.clone())
                    && previous != *requirement
                {
                    return Err(NodeL3TransportError::InvalidPolicyMarker(
                        "conflicting requirements for one peer Node",
                    ));
                }
            }
        }
    }
    Ok(TransportProjectionSpec {
        local_ip: config.local_ip,
        bindings,
        authoritative_bindings,
        gateway_carriers,
    })
}
