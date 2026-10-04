//! Authenticated, target-bound Node L3 policy and stateful packet gate.
//!
//! A [`NodeL3Gate`] holds per-Network [`NodeL3Config`] snapshots received
//! from authenticated control sources, the local WireGuard projection
//! ([`NodeL3Transport`]) and the local Provider listeners, and judges
//! decrypted inbound and plaintext outbound IPv4 packets on the Node-address
//! plane:
//!
//! - **Source binding**: a packet is bound to a Network only through the
//!   exact `(peer key, inner Node address)` pair of a policy binding.
//! - **Grants**: Nodes of one owner reach each other; otherwise a Node Grant
//!   opens the whole target Node and a Service Grant one exact listener
//!   (inbound only while the local Provider listener is installed). Subnet
//!   Grants are exposed through the `enforced_subnet_*` queries and the
//!   reserved Subnet transport admission.
//! - **State**: allowed flows create bounded state (16,384 flows globally,
//!   2,048 per peer, 4,096 fragments) with per-protocol idle timeouts (TCP
//!   2 h, half-closed 5 min, closed 30 s, UDP 2 min, ICMP 30 s, other 60 s,
//!   fragments 30 s). Replies, later fragments and ICMP errors are admitted
//!   only through that state; a full table fails closed and never evicts.
//! - **Modes**: no snapshot means [`NodeL3Decision::Legacy`]; `observe`
//!   reports the prospective verdict without enforcing it; `enforce` is
//!   authoritative. A WireGuard peer carrying a policy marker fails closed
//!   until the matching snapshot is applied.
//!
//! [`NodeL3Filter`] runs the gate as a [`nsplane_core::PacketFilter`]
//! composed with an optional [`crate::AclFilter`]: an enforced verdict is
//! final, legacy and observed packets go on to the ACL, and enforced denials
//! of gateway returns can be diverted to a gateway-consumer sink.
//!
//! The gate is inert unless constructed. Packet paths read one immutable
//! snapshot and lock only the state shard of the remote peer; writers
//! serialize on one mutex and migrate state with every shard locked, so a
//! packet never observes a policy together with state of another policy.

use std::cell::OnceCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use thiserror::Error;

use crate::net::IpNet;

mod config;
mod decisions;
mod filter;
mod gateway_consumer;
mod hash;
mod packet;
mod policy;
mod projection;
mod snapshot;
mod sources;
mod state;
mod subnet;
#[cfg(test)]
mod tests;

pub use config::{
    NODE_L3_SCHEMA_VERSION, NodeL3Config, NodeL3Grant, NodeL3Mode, NodeL3Node, NodeL3PeerBinding,
    NodeL3PeerPolicyRequirement, NodeL3Resource, NodeL3ServiceEndpoint, NodeL3ServiceProtocol,
    NodeL3Transport, NodeL3TransportPeer,
};
pub use filter::{
    GatewayConsumerSink, NodeL3Filter, NodeL3FilterStats, PeerKeyMap, PeerPublicKeys,
};
pub use gateway_consumer::{GatewayConsumerAuthority, GatewayConsumerPacket};

use policy::{CompiledPolicy, NetIdx, TransportProjection};
use snapshot::{ProviderListeners, Snapshot, TombstoneView};
use state::{Shard, StateTable};

const DEFAULT_GLOBAL_STATE_LIMIT: usize = 16_384;
const DEFAULT_PEER_STATE_LIMIT: usize = 2_048;
const DEFAULT_FRAGMENT_LIMIT: usize = 4_096;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_hours(2);
const TCP_HALF_CLOSE_TIMEOUT: Duration = Duration::from_mins(5);
const TCP_TERMINAL_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_mins(2);
const ICMP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const OTHER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a packet was accepted or rejected by the Node L3 gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeL3Reason {
    /// Outside the Node-address plane, or no policy applies.
    Legacy,
    /// Matches existing flow or fragment state.
    ValidState,
    /// Source and target Nodes have the same owner.
    SameOwner,
    /// A Node Grant opens the target Node.
    NodeGrant,
    /// A Service Grant opens the exact listener.
    ServiceGrant,
    /// A Subnet Grant admits the flow.
    SubnetGrant,
    /// The peer key and inner address match no policy binding.
    SourceBinding,
    /// A reply-only or reverse packet without matching state.
    ReverseNewFlow,
    /// No Grant authorizes the new flow.
    NoGrant,
    /// The Service Grant's local Provider listener is not installed.
    ServiceProjection,
    /// A transport policy marker is not yet matched by the applied policy.
    PolicyPending,
    /// A later fragment without an authorized first fragment.
    OrphanFragment,
    /// The flow or fragment table is full.
    StateCapacity,
    /// More than one Network binds the packet.
    AmbiguousNetwork,
    /// The packet cannot be parsed.
    MalformedPacket,
}

impl NodeL3Reason {
    /// Stable snake-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::ValidState => "valid_state",
            Self::SameOwner => "same_owner",
            Self::NodeGrant => "node_grant",
            Self::ServiceGrant => "service_grant",
            Self::SubnetGrant => "subnet_grant",
            Self::SourceBinding => "source_binding",
            Self::ReverseNewFlow => "reverse_new_flow",
            Self::NoGrant => "no_grant",
            Self::ServiceProjection => "service_projection",
            Self::PolicyPending => "policy_pending",
            Self::OrphanFragment => "orphan_fragment",
            Self::StateCapacity => "state_capacity",
            Self::AmbiguousNetwork => "ambiguous_network",
            Self::MalformedPacket => "malformed_packet",
        }
    }

    /// Drop reason reported for an enforced denial with this reason.
    #[must_use]
    pub const fn drop_reason(self) -> &'static str {
        match self {
            Self::Legacy => "node l3: legacy",
            Self::ValidState => "node l3: valid state",
            Self::SameOwner => "node l3: same owner",
            Self::NodeGrant => "node l3: node grant",
            Self::ServiceGrant => "node l3: service grant",
            Self::SubnetGrant => "node l3: subnet grant",
            Self::SourceBinding => "node l3: source binding",
            Self::ReverseNewFlow => "node l3: reverse new flow",
            Self::NoGrant => "node l3: no grant",
            Self::ServiceProjection => "node l3: service projection",
            Self::PolicyPending => "node l3: policy pending",
            Self::OrphanFragment => "node l3: orphan fragment",
            Self::StateCapacity => "node l3: state capacity",
            Self::AmbiguousNetwork => "node l3: ambiguous network",
            Self::MalformedPacket => "node l3: malformed packet",
        }
    }
}

/// Result returned to the existing L4 pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeL3Decision {
    /// The packet is outside the Node-address plane or no policy is active.
    Legacy,
    /// Record the prospective result but preserve the pre-v1 packet behavior.
    Observe {
        /// Whether enforcement would allow the packet.
        would_allow: bool,
        /// Why.
        reason: NodeL3Reason,
    },
    /// Authoritative Node L3 verdict.
    Enforce {
        /// Whether the packet is allowed.
        allow: bool,
        /// Why.
        reason: NodeL3Reason,
    },
}

impl NodeL3Decision {
    /// Whether an enforce-mode packet may enter the legacy classifier.
    #[must_use]
    pub const fn enforced_verdict(&self) -> Option<bool> {
        match self {
            Self::Enforce { allow, .. } => Some(*allow),
            Self::Legacy | Self::Observe { .. } => None,
        }
    }
}

/// Validation failure that prevents atomic policy publication and ACK.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NodeL3ConfigError {
    /// The snapshot's schema version is not [`NODE_L3_SCHEMA_VERSION`].
    #[error("unsupported node L3 schema version {0}")]
    UnsupportedSchema(u16),
    /// The snapshot is bound to another machine.
    #[error("node L3 snapshot target {actual:?} does not match this machine {expected:?}")]
    WrongTarget {
        /// This gate's targets, comma-separated.
        expected: String,
        /// The snapshot's target.
        actual: String,
    },
    /// The Network is owned by another control source.
    #[error(
        "node L3 Network {network_id:?} is authoritative from source {applied_source:?}, not {actual_source:?}"
    )]
    AuthorityConflict {
        /// The Network.
        network_id: String,
        /// The source owning it.
        applied_source: String,
        /// The source that tried to apply.
        actual_source: String,
    },
    /// A required field is empty.
    #[error("node L3 snapshot has an empty {0}")]
    EmptyField(&'static str),
    /// An active snapshot has generation zero.
    #[error("node L3 snapshot generation must be non-zero")]
    ZeroGeneration,
    /// The snapshot is older than the applied generation.
    #[error("node L3 snapshot generation {actual} is older than applied generation {applied}")]
    StaleGeneration {
        /// Applied generation.
        applied: u64,
        /// Snapshot generation.
        actual: u64,
    },
    /// An applied enforce generation cannot return to observe.
    #[error("node L3 snapshot cannot regress generation {generation} from enforce to observe")]
    PhaseRegression {
        /// The generation.
        generation: u64,
    },
    /// The snapshot contradicts itself or the applied content.
    #[error("node L3 snapshot contains a conflicting {0}")]
    Conflict(&'static str),
    /// The snapshot could not be encoded. Kept for parity with the control
    /// plane's error set; this gate compares content structurally and never
    /// returns it.
    #[error("node L3 snapshot encoding failed: {0}")]
    SnapshotEncoding(String),
    /// A Grant or Service names an unknown Node.
    #[error("node L3 snapshot references unknown node {0:?}")]
    UnknownNode(String),
    /// A Service Grant names a Service that is not projected.
    #[error("node L3 snapshot references unknown service {0:?}")]
    UnknownService(String),
    /// A Service listener has port zero.
    #[error("node L3 service port must be non-zero")]
    ZeroServicePort,
    /// A Subnet id is not canonical non-zero decimal.
    #[error("node L3 snapshot has an invalid Subnet id {0:?}")]
    InvalidSubnetId(String),
    /// A Subnet prefix is not a mapped IPv6 prefix of at least `/96`.
    #[error("node L3 snapshot has an invalid mapped Subnet prefix {0}")]
    InvalidSubnetPrefix(IpNet),
}

/// A WireGuard projection cannot prove a unique peer owner for one Node IP.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NodeL3TransportError {
    /// Two peers carry the same marked Node address.
    #[error("WireGuard Node route {ip}/32 is assigned to more than one peer")]
    AmbiguousNodeRoute {
        /// The Node address.
        ip: Ipv4Addr,
    },
    /// A peer's policy marker is invalid.
    #[error("WireGuard peer has an invalid Node L3 policy marker: {0}")]
    InvalidPolicyMarker(&'static str),
    /// The installed projection is not a subset of the desired one.
    #[error("WireGuard installed projection is inconsistent with its desired config: {0}")]
    InvalidInstalledProjection(&'static str),
}

/// Metadata emitted only after a snapshot has been compiled and atomically
/// published. The caller uses it to build the signed applied ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeL3Applied {
    /// Network id.
    pub network_id: String,
    /// Target machine.
    pub target_machine_id: String,
    /// Applied generation.
    pub generation: u64,
    /// Applied mode.
    pub mode: NodeL3Mode,
}

/// One exact, locally usable Subnet Grant derived from an Enforce snapshot.
///
/// This is not a route by itself. The runtime must still match it against
/// the independently authenticated Subnet L3 projection, including Subnet ID,
/// mapped prefix, active peer key, and the same security generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeL3SubnetAuthorization {
    /// Control source owning the Network.
    pub source_id: String,
    /// Network id.
    pub network_id: String,
    /// Policy generation.
    pub generation: u64,
    /// Grant provenance.
    pub grant_id: String,
    /// Subnet id.
    pub subnet_id: u32,
    /// Routing Node.
    pub routing_node_id: String,
    /// Mapped IPv6 prefix.
    pub prefix: IpNet,
    /// Peer carrying the routing Node.
    pub peer_key: [u8; 32],
}

/// Bounded monotonic counters exposed to status/telemetry adapters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeL3Counters {
    /// Enforced allows.
    pub enforced_allowed: u64,
    /// Enforced denials.
    pub enforced_denied: u64,
    /// Observe-mode prospective denials.
    pub observed_denied: u64,
    /// Enforced [`NodeL3Reason::SourceBinding`] denials.
    pub source_binding_denied: u64,
    /// Enforced [`NodeL3Reason::StateCapacity`] denials.
    pub state_capacity_denied: u64,
}

/// Read-only explanation of whether one authenticated peer marker is usable.
///
/// This mirrors the fail-closed `policy_pending` predicate without probing or
/// mutating the data plane, so status adapters can distinguish a local rollout
/// mismatch from a remote transport failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeL3PeerReadiness {
    /// Marked Node address.
    pub ip: Ipv4Addr,
    /// Marker Network.
    pub network_id: String,
    /// Marker generation.
    pub marker_generation: u64,
    /// Marker mode.
    pub marker_mode: NodeL3Mode,
    /// Applied policy generation, if any.
    pub policy_generation: Option<u64>,
    /// Applied policy mode, if any.
    pub policy_mode: Option<NodeL3Mode>,
    /// Whether the marker is usable.
    pub ready: bool,
    /// Why.
    pub reason: NodeL3PeerReadinessReason,
}

/// Stable machine-readable reason for one peer marker's readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeL3PeerReadinessReason {
    /// The marker is usable.
    Ready,
    /// The transport projection is staged or withdrawn.
    TransportNotInstalled,
    /// The marked binding is not installed on the device.
    BindingNotInstalled,
    /// No policy is applied for the marker's Network.
    PolicyMissing,
    /// The policy generation differs from the marker's.
    GenerationMismatch,
    /// The policy mode differs from the marker's.
    ModeMismatch,
    /// The policy's local address differs from the device's.
    LocalIpMismatch,
    /// The policy has no such binding.
    BindingMissing,
    /// An observe marker on a binding of another owner.
    ObserveOwnerMismatch,
}

impl NodeL3PeerReadinessReason {
    /// Stable snake-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::TransportNotInstalled => "transport_not_installed",
            Self::BindingNotInstalled => "binding_not_installed",
            Self::PolicyMissing => "policy_missing",
            Self::GenerationMismatch => "generation_mismatch",
            Self::ModeMismatch => "mode_mismatch",
            Self::LocalIpMismatch => "local_ip_mismatch",
            Self::BindingMissing => "binding_missing",
            Self::ObserveOwnerMismatch => "observe_owner_mismatch",
        }
    }
}

#[derive(Debug, Default)]
struct RuntimeCounters {
    enforced_allowed: AtomicU64,
    enforced_denied: AtomicU64,
    observed_denied: AtomicU64,
    source_binding_denied: AtomicU64,
    state_capacity_denied: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PacketDirection {
    Inbound,
    Outbound,
}

/// Authority a Network keeps for the gate's lifetime, even when withdrawn.
#[derive(Debug, Clone)]
struct NetworkTombstone {
    net: NetIdx,
    network_id: String,
    source_id: String,
    target_machine_id: String,
    generation: u64,
    mode: NodeL3Mode,
    /// [`NodeL3Config::policy_identity`] of the applied snapshot; `None`
    /// after a source withdrawal, which conflicts with every replay.
    content: Option<NodeL3Config>,
}

/// State owned by the writer mutex.
#[derive(Debug, Default)]
struct WriterState {
    /// First authenticated source to claim a globally unique Network ID owns
    /// it for the gate's lifetime. Generation and content survive an
    /// explicit withdrawal so stale snapshots cannot resurrect old access.
    tombstones: HashMap<String, NetworkTombstone>,
    next_net: NetIdx,
}

impl WriterState {
    fn tombstone_views(&self) -> Arc<HashMap<NetIdx, TombstoneView>> {
        Arc::new(
            self.tombstones
                .values()
                .map(|tombstone| {
                    (
                        tombstone.net,
                        TombstoneView {
                            network_id: tombstone.network_id.clone(),
                            source_id: tombstone.source_id.clone(),
                            target_machine_id: tombstone.target_machine_id.clone(),
                            generation: tombstone.generation,
                            mode: tombstone.mode,
                        },
                    )
                })
                .collect(),
        )
    }
}

type Clock = Box<dyn Fn() -> Instant + Send + Sync>;
type AuthorizationCallback = Arc<dyn Fn(u64) + Send + Sync>;

/// Shared Node L3 gate: an immutable policy snapshot swapped atomically plus
/// bounded flow state sharded by remote peer.
pub struct NodeL3Gate {
    target_machine_ids: HashSet<String>,
    snapshot: ArcSwap<Snapshot>,
    /// The published snapshot has no policy and no transport, so every
    /// packet is Legacy. Read before the snapshot, without the clock.
    inert: AtomicBool,
    writer: Mutex<WriterState>,
    state: StateTable,
    counters: RuntimeCounters,
    authorization_generation: AtomicU64,
    on_authorization_change: Mutex<Option<AuthorizationCallback>>,
    clock: Clock,
}

impl fmt::Debug for NodeL3Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeL3Gate")
            .field("target_machine_ids", &self.target_machine_ids)
            .field("snapshot", &self.snapshot)
            .field("counters", &self.counters())
            .field("authorization_generation", &self.authorization_generation())
            .finish_non_exhaustive()
    }
}

impl NodeL3Gate {
    fn build(
        target_machine_ids: HashSet<String>,
        global: usize,
        peer: usize,
        fragments: usize,
        clock: Clock,
    ) -> Arc<Self> {
        Arc::new(Self {
            target_machine_ids,
            snapshot: ArcSwap::default(),
            inert: AtomicBool::new(true),
            writer: Mutex::default(),
            state: StateTable::new(global, peer, fragments),
            counters: RuntimeCounters::default(),
            authorization_generation: AtomicU64::new(0),
            on_authorization_change: Mutex::new(None),
            clock,
        })
    }

    /// Create the per-process gate. No snapshot means legacy behavior.
    #[must_use]
    pub fn new(target_machine_id: impl Into<String>) -> Arc<Self> {
        Self::new_for_targets([target_machine_id.into()])
    }

    /// Create a gate for a process authenticated to several independent
    /// control sources. Each source still receives and ACKs only its own
    /// target-bound snapshot; the gate keeps Network policies isolated by
    /// global id.
    #[must_use]
    pub fn new_for_targets(target_machine_ids: impl IntoIterator<Item = String>) -> Arc<Self> {
        Self::with_clock(target_machine_ids, Instant::now)
    }

    /// A gate for one target with explicit state limits: `global` flows,
    /// `peer` flows per remote peer and `fragments` remembered fragments.
    #[must_use]
    pub fn with_limits(
        target_machine_id: impl Into<String>,
        global: usize,
        peer: usize,
        fragments: usize,
    ) -> Arc<Self> {
        Self::build(
            HashSet::from([target_machine_id.into()]),
            global,
            peer,
            fragments,
            Box::new(Instant::now),
        )
    }

    /// A gate with the default limits whose flow and fragment expiry follows
    /// `clock` instead of [`Instant::now`] (e.g. a manual clock in tests and
    /// benches).
    #[must_use]
    pub fn with_clock(
        target_machine_ids: impl IntoIterator<Item = String>,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::build(
            target_machine_ids.into_iter().collect(),
            DEFAULT_GLOBAL_STATE_LIMIT,
            DEFAULT_PEER_STATE_LIMIT,
            DEFAULT_FRAGMENT_LIMIT,
            Box::new(clock),
        )
    }

    /// Compile, validate, and atomically publish one Network snapshot from
    /// the source `target:<target_machine_id>`.
    pub fn apply(&self, config: NodeL3Config) -> Result<NodeL3Applied, NodeL3ConfigError> {
        let source = format!("target:{}", config.target_machine_id);
        self.apply_from_source(&source, config)
    }

    /// Publish the peer/IP projection only after the local WireGuard device has
    /// successfully built it. ACK readiness proves a closed correspondence for
    /// the transport that actually exists: every installed route to a policy
    /// Node has the exact current marker, and every desired marker names an
    /// installed policy binding. A policy-only binding may represent an offline
    /// peer and therefore does not block the ACK.
    pub fn replace_transport_projection(
        &self,
        config: &NodeL3Transport,
    ) -> Result<(), NodeL3TransportError> {
        self.replace_transport_projection_after_build(config, config)
    }

    /// Evaluate a packet after successful WireGuard decryption.
    #[must_use]
    pub fn evaluate_inbound(&self, peer_key: [u8; 32], packet: &[u8]) -> NodeL3Decision {
        self.evaluate(PacketDirection::Inbound, peer_key, packet)
    }

    /// Evaluate a plaintext packet after the destination WireGuard peer was
    /// selected and before encryption.
    #[must_use]
    pub fn evaluate_outbound(&self, peer_key: [u8; 32], packet: &[u8]) -> NodeL3Decision {
        self.evaluate(PacketDirection::Outbound, peer_key, packet)
    }

    /// Evaluate and record one packet. An inert gate answers Legacy without
    /// parsing, loading the snapshot or reading the clock; otherwise the
    /// clock is read only once the packet reaches the state.
    fn evaluate(
        &self,
        direction: PacketDirection,
        peer_key: [u8; 32],
        packet: &[u8],
    ) -> NodeL3Decision {
        if self.inert.load(Ordering::Acquire) {
            return NodeL3Decision::Legacy;
        }
        let decision = self.evaluate_with(direction, peer_key, packet, OnceCell::new());
        self.record_decision(&decision);
        decision
    }

    /// Admit an inbound reserved Subnet transport request.
    #[must_use]
    pub fn evaluate_subnet_transport_inbound(
        &self,
        peer_key: [u8; 32],
        packet: &[u8],
        destination_port: u16,
    ) -> bool {
        self.evaluate_subnet_transport(PacketDirection::Inbound, peer_key, packet, destination_port)
    }

    /// Admit an outbound reserved Subnet transport request.
    #[must_use]
    pub fn evaluate_subnet_transport_outbound(
        &self,
        peer_key: [u8; 32],
        packet: &[u8],
        destination_port: u16,
    ) -> bool {
        self.evaluate_subnet_transport(
            PacketDirection::Outbound,
            peer_key,
            packet,
            destination_port,
        )
    }

    /// Read the current monotonic diagnostic counters.
    #[must_use]
    pub fn counters(&self) -> NodeL3Counters {
        NodeL3Counters {
            enforced_allowed: self.counters.enforced_allowed.load(Ordering::Relaxed),
            enforced_denied: self.counters.enforced_denied.load(Ordering::Relaxed),
            observed_denied: self.counters.observed_denied.load(Ordering::Relaxed),
            source_binding_denied: self.counters.source_binding_denied.load(Ordering::Relaxed),
            state_capacity_denied: self.counters.state_capacity_denied.load(Ordering::Relaxed),
        }
    }

    /// Monotonic counter bumped after every policy or transport change that
    /// may alter the set of locally usable Subnet Grants (and so the results
    /// of the `enforced_subnet_*` queries). Consumers always recompute from
    /// the queries; the value is only a latest-wins change marker.
    #[must_use]
    pub fn authorization_generation(&self) -> u64 {
        self.authorization_generation.load(Ordering::SeqCst)
    }

    /// Call `callback` with the new [`authorization_generation`] after every
    /// bump. It runs on the writer's thread after the change is published and
    /// outside the gate's locks, so it may query the gate; it replaces any
    /// previous callback.
    ///
    /// [`authorization_generation`]: Self::authorization_generation
    pub fn set_on_authorization_change(&self, callback: Box<dyn Fn(u64) + Send + Sync>) {
        *self
            .on_authorization_change
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::from(callback));
    }

    /// Bump the authorization generation and notify. The caller holds no
    /// gate lock.
    fn notify_authorization_change(&self) {
        let generation = self.authorization_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let callback = self
            .on_authorization_change
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(callback) = callback {
            callback(generation);
        }
    }

    fn lock_writer(&self) -> MutexGuard<'_, WriterState> {
        self.writer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publish a new snapshot built from the given parts and migrate the
    /// state to it with every shard locked. The caller holds the writer lock.
    fn publish(
        &self,
        policies: BTreeMap<NetIdx, Arc<CompiledPolicy>>,
        transport: Option<Arc<TransportProjection>>,
        listeners: Arc<ProviderListeners>,
        tombstones: Arc<HashMap<NetIdx, TombstoneView>>,
        migrate: impl FnOnce(&mut [MutexGuard<'_, Shard>], &Snapshot),
    ) {
        let mut shards = self.state.lock_all();
        let epoch = self.snapshot.load().epoch + 1;
        let inert = policies.is_empty() && transport.is_none();
        let snapshot = Arc::new(Snapshot::build(
            epoch, policies, transport, listeners, tombstones,
        ));
        self.snapshot.store(Arc::clone(&snapshot));
        // A packet still reading the previous value is ordered before this
        // publication, as if it had loaded the previous snapshot.
        self.inert.store(inert, Ordering::Release);
        migrate(&mut shards, &snapshot);
        for shard in &mut shards {
            shard.epoch = epoch;
        }
    }
}

const fn mode_decision(mode: NodeL3Mode, allow: bool, reason: NodeL3Reason) -> NodeL3Decision {
    match mode {
        NodeL3Mode::Disabled => NodeL3Decision::Legacy,
        NodeL3Mode::Observe => NodeL3Decision::Observe {
            would_allow: allow,
            reason,
        },
        NodeL3Mode::Enforce => NodeL3Decision::Enforce { allow, reason },
    }
}
