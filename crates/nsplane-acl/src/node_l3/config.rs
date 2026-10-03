//! Plain-data Node L3 policy snapshot and transport projection inputs.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::net::IpNet;

/// Wire schema understood by this gate.
pub const NODE_L3_SCHEMA_VERSION: u16 = 1;

/// Activation state of one target-bound Node L3 snapshot.
///
/// `disabled` is an explicit withdrawal. Absence of a snapshot and `observe`
/// both preserve the legacy packet verdict; only `enforce` may drop traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeL3Mode {
    /// Explicit withdrawal of the Network's policy.
    Disabled,
    /// Record prospective verdicts but keep the legacy packet behavior.
    Observe,
    /// Authoritative verdicts.
    Enforce,
}

/// Stable logical identity of one Node within a Network.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeL3Node {
    /// Node identifier, unique within the Network.
    pub node_id: String,
    /// Owner (account) of the Node; Nodes of one owner reach each other.
    pub owner_id: String,
    /// The Node's overlay IPv4 address.
    pub ip: Ipv4Addr,
}

/// Authenticated WireGuard transport binding for a projected peer Node.
///
/// The data plane resolves a source only by the exact pair
/// `(peer_public_key, inner source IP)`. A single terminate peer key may
/// therefore safely carry several explicitly projected Node addresses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeL3PeerBinding {
    /// WireGuard public key of the peer carrying this Node.
    pub peer_public_key: [u8; 32],
    /// Node identifier.
    pub node_id: String,
    /// Owner of the Node.
    pub owner_id: String,
    /// The Node's overlay IPv4 address.
    pub ip: Ipv4Addr,
}

/// Concrete transport exposed by a private Service on a Node address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeL3ServiceProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl NodeL3ServiceProtocol {
    /// IPv4 protocol number used by the packet classifier.
    #[must_use]
    pub const fn ip_protocol(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

/// A projected private-Service listener used to classify the resource plane.
/// `port` is the overlay virtual listener port, not the backend port.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeL3ServiceEndpoint {
    /// Stable Service resource id.
    pub service_id: String,
    /// Node exposing the listener.
    pub node_id: String,
    /// Listener transport.
    pub protocol: NodeL3ServiceProtocol,
    /// Overlay virtual listener port.
    pub port: u16,
}

/// Resource selected by a directional Node L3 Grant.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeL3Resource {
    /// Full IPv4 access to exactly one Node address.
    Node {
        /// Target Node.
        node_id: String,
    },
    /// Access to one exact Service virtual listener.
    Service {
        /// Service resource id.
        service_id: String,
        /// Node exposing the Service.
        node_id: String,
        /// Listener transport.
        protocol: NodeL3ServiceProtocol,
        /// Overlay virtual listener port.
        port: u16,
    },
    /// Access to one durable routed Subnet through its exact active routing
    /// Node and mapped prefix. Endpoints still require the independently
    /// authenticated Subnet route projection before this Grant becomes usable.
    Subnet {
        /// Canonical decimal, non-zero Subnet id.
        subnet_id: String,
        /// Node routing the Subnet.
        routing_node_id: String,
        /// Mapped IPv6 prefix (at least `/96`).
        #[serde(with = "ipnet_text")]
        prefix: IpNet,
    },
}

/// One directed authorization edge from a source Node to a resource.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeL3Grant {
    /// Logical policy provenance; several edges may share one id.
    pub grant_id: String,
    /// Node allowed to open flows.
    pub source_node_id: String,
    /// Resource the source may reach.
    pub resource: NodeL3Resource,
}

/// Versioned, target-bound Node L3 policy snapshot.
///
/// `target_machine_id` is validated against the gate's authenticated targets
/// before publication.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeL3Config {
    /// Must equal [`NODE_L3_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// Globally unique Network id.
    pub network_id: String,
    /// Machine this snapshot is bound to.
    pub target_machine_id: String,
    /// Security generation; non-zero unless the mode is `disabled`.
    pub generation: u64,
    /// Activation phase.
    pub mode: NodeL3Mode,
    /// The local Node of this machine in the Network.
    pub local_node: NodeL3Node,
    /// Peer Node bindings.
    #[serde(default)]
    pub bindings: Vec<NodeL3PeerBinding>,
    /// Projected Service listeners.
    #[serde(default)]
    pub services: Vec<NodeL3ServiceEndpoint>,
    /// Directed Grants.
    #[serde(default)]
    pub grants: Vec<NodeL3Grant>,
}

impl NodeL3Config {
    /// Snapshot identity shared by the observe and enforce phases.
    ///
    /// The control plane first asks every target to apply `observe`, then
    /// activates the same generation as `enforce`. Phase is therefore not
    /// security content and does not change the identity.
    #[must_use]
    pub fn policy_identity(&self) -> Self {
        let mut normalized = self.clone();
        if matches!(normalized.mode, NodeL3Mode::Observe | NodeL3Mode::Enforce) {
            normalized.mode = NodeL3Mode::Enforce;
        }
        normalized
    }
}

/// Peer-side proof that a WireGuard adjacency belongs to a Node L3 policy
/// generation. A peer without it keeps the legacy behavior; a marked peer
/// fails closed until the matching local snapshot is applied.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeL3PeerPolicyRequirement {
    /// Network the marker belongs to.
    pub network_id: String,
    /// Required policy generation.
    pub generation: u64,
    /// Required local phase. Observe peers remain compatibility traffic;
    /// cross-owner peers are projected only with Enforce.
    pub mode: NodeL3Mode,
    /// Exact Node `/32` addresses governed by this requirement. A peer can
    /// also carry Service/Gateway routes, which must not become L3-authoritative.
    pub node_ips: Vec<Ipv4Addr>,
}

/// The WireGuard device projection the gate needs: the local address and,
/// per peer, its routes, gateway role and policy marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeL3Transport {
    /// Local overlay IPv4 address of the device.
    pub local_ip: Ipv4Addr,
    /// Configured peers.
    pub peers: Vec<NodeL3TransportPeer>,
}

/// One peer of a [`NodeL3Transport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeL3TransportPeer {
    /// WireGuard public key.
    pub public_key: [u8; 32],
    /// Allowed IPs; only exact IPv4 `/32`s other than the local address are
    /// Node bindings.
    pub allowed_ips: Vec<IpNet>,
    /// Explicit Terminate/Public gateway identity named by the control plane.
    pub gateway_id: Option<String>,
    /// Whether the peer is reached through a relay (WG relay, WSS relay or
    /// WSS fallback). A relayed peer is never a gateway carrier.
    pub relayed: bool,
    /// Node L3 policy marker of this peer.
    pub node_l3_policy: Option<NodeL3PeerPolicyRequirement>,
}

/// Serde for [`IpNet`] as its `addr/len` text.
mod ipnet_text {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use crate::net::IpNet;

    pub(super) fn serialize<S: Serializer>(net: &IpNet, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(net)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IpNet, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(D::Error::custom)
    }
}
