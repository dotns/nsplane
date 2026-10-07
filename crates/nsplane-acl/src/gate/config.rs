//! The plain-data inputs of a [`FlowGate`](super::FlowGate): the policy
//! (scopes, bindings, grants, unbound rules and holds) and the state limits
//! and timeouts.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use nsplane_packet::PeerId;
use thiserror::Error;

use crate::net::IpNet;
use crate::pinhole::Direction;
use crate::rules::{Label, LabelSet, ProtocolMatch, RuleId};

/// An opaque scope identifier, unique within one [`GatePolicy`]. nsplane
/// reports it and never interprets it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId(Arc<str>);

impl ScopeId {
    /// A scope id with the text `text`.
    pub fn new(text: impl Into<Arc<str>>) -> Self {
        Self(text.into())
    }

    /// The id's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

impl fmt::Display for ScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ScopeId {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

impl From<String> for ScopeId {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

/// How a [`GateScope`]'s decisions take effect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GateMode {
    /// The scope decides nothing (the same as leaving it out); its flow
    /// state is dropped.
    #[default]
    Off,
    /// Decisions are reported and state is kept, but packets pass on.
    Observe,
    /// Decisions are authoritative.
    Enforce,
}

/// One policy snapshot, replaced atomically as a whole by
/// [`FlowGate::replace`](super::FlowGate::replace).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GatePolicy {
    /// The scopes; their ids must be unique.
    pub scopes: Vec<GateScope>,
    /// Packets held fail closed before any scope is consulted.
    pub holds: GateHolds,
}

/// One governed address plane: local addresses, the remote sources bound to
/// it, its accept-only grants and its unbound rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateScope {
    /// The scope's identifier.
    pub id: ScopeId,
    /// How its decisions take effect.
    pub mode: GateMode,
    /// The local addresses this scope governs.
    pub local: Vec<IpAddr>,
    /// The remote sources bound to the scope.
    pub bindings: Vec<GateBinding>,
    /// Accept-only grants for new flows, in precedence order.
    pub grants: Vec<GateGrant>,
    /// What happens to unbound inbound packets of designated peers.
    pub unbound: Vec<UnboundRule>,
}

/// Packets of `peer` with a remote address in `addresses` are bound to the
/// scope and carry `labels`. The remote address is the IP source of an
/// inbound packet and the IP destination of an outbound one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateBinding {
    /// The peer the packets travel over.
    pub peer: PeerId,
    /// The remote addresses bound for that peer.
    pub addresses: Vec<IpAddr>,
    /// The labels the bound source carries.
    pub labels: LabelSet,
}

/// An accept-only grant for new flows initiated in one direction.
///
/// A new flow initiated in `direction` may open when the remote binding
/// carries one of `labels` (empty: any binding of the scope), the
/// destination address lies in `destinations` (empty: any) and a
/// `protocols` entry matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateGrant {
    /// The identifier reported when the grant admits a flow.
    pub id: RuleId,
    /// [`Direction::Inbound`]: the remote side initiates;
    /// [`Direction::Outbound`]: the local side initiates.
    pub direction: Direction,
    /// Remote labels; empty: any binding of the scope.
    pub labels: Vec<Label>,
    /// Destination prefixes; empty: any destination.
    pub destinations: Vec<IpNet>,
    /// Protocols (with destination ports or ICMP types); must not be empty.
    pub protocols: Vec<ProtocolMatch>,
    /// Present but not admitting: a new flow it alone would admit is denied
    /// [`GateReason::Suspended`](super::GateReason::Suspended).
    pub suspended: bool,
}

/// What an [`UnboundRule`] does with a matching packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnboundAction {
    /// Hand the packet on ([`GateDecision::Pass`](super::GateDecision::Pass)).
    Pass,
    /// Offer the enforced denial to the filter's
    /// [`GateDivert`](super::GateDivert).
    Divert,
}

/// What happens to unbound inbound packets of designated peers.
///
/// For inbound packets of `peers` to a local address of an
/// [`GateMode::Enforce`] scope that bind to no scope: [`UnboundAction::Pass`]
/// hands matching packets on; [`UnboundAction::Divert`] offers the enforced
/// denial to the filter's [`GateDivert`](super::GateDivert). The rule applies
/// only when its scope is the one scope governing the packet's local address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnboundRule {
    /// The identifier reported with a diverted packet.
    pub id: RuleId,
    /// The peers the rule applies to.
    pub peers: Vec<PeerId>,
    /// What happens to a matching packet.
    pub action: UnboundAction,
    /// Protocols (with destination ports or ICMP types); must not be empty.
    pub protocols: Vec<ProtocolMatch>,
}

/// Packets held fail closed ([`GateDecision::Enforce`](super::GateDecision::Enforce)
/// with [`GateReason::Held`](super::GateReason::Held)) in every mode, before
/// any scope is consulted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GateHolds {
    /// Rules for inbound packets.
    pub inbound: Vec<HoldRule>,
    /// Rules for outbound packets.
    pub outbound: Vec<HoldRule>,
    /// Exact (peer, remote address) pairs exempt from the inbound holds.
    pub release: Vec<(PeerId, IpAddr)>,
}

/// A packet is held when all three fields match it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HoldRule {
    /// The peers; `None`: any peer.
    pub peers: Option<Vec<PeerId>>,
    /// Local address prefixes; empty: any local address.
    pub local: Vec<IpNet>,
    /// Remote address prefixes; empty: any remote address.
    pub remote: Vec<IpNet>,
}

/// State limits of a [`FlowGate`](super::FlowGate). A full table fails
/// closed and never evicts a live entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateLimits {
    /// Flows in all.
    pub flows: usize,
    /// Flows per peer.
    pub flows_per_peer: usize,
    /// Remembered first fragments.
    pub fragments: usize,
}

impl Default for GateLimits {
    /// 16,384 flows, 2,048 per peer, 4,096 fragments.
    fn default() -> Self {
        Self {
            flows: 16_384,
            flows_per_peer: 2_048,
            fragments: 4_096,
        }
    }
}

/// Idle timeouts of the flow and fragment state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateTimeouts {
    /// An open TCP flow.
    pub tcp: Duration,
    /// A TCP flow after one FIN or RST.
    pub tcp_half_closed: Duration,
    /// A TCP flow with FIN both ways or an RST; never extended.
    pub tcp_closed: Duration,
    /// A UDP flow.
    pub udp: Duration,
    /// An ICMP flow.
    pub icmp: Duration,
    /// A flow of another protocol.
    pub other: Duration,
    /// A remembered first fragment.
    pub fragment: Duration,
}

impl Default for GateTimeouts {
    /// TCP 2 h, half-closed 5 min, closed 30 s, UDP 2 min, ICMP 30 s, other
    /// 60 s, fragments 30 s.
    fn default() -> Self {
        Self {
            tcp: Duration::from_hours(2),
            tcp_half_closed: Duration::from_mins(5),
            tcp_closed: Duration::from_secs(30),
            udp: Duration::from_mins(2),
            icmp: Duration::from_secs(30),
            other: Duration::from_secs(60),
            fragment: Duration::from_secs(30),
        }
    }
}

/// Limits and timeouts of a [`FlowGate`](super::FlowGate).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GateConfig {
    /// State limits.
    pub limits: GateLimits,
    /// Idle timeouts.
    pub timeouts: GateTimeouts,
}

/// Why [`FlowGate::replace`](super::FlowGate::replace) rejected a policy.
/// Nothing is published.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GatePolicyError {
    /// Two scopes share an id.
    #[error("duplicate gate scope '{0}'")]
    DuplicateScope(ScopeId),
    /// One scope binds the same peer and address twice.
    #[error("gate scope '{scope}' binds peer {peer:?} at {address} twice")]
    DuplicateBinding {
        /// The scope.
        scope: ScopeId,
        /// The peer.
        peer: PeerId,
        /// The address.
        address: IpAddr,
    },
    /// A grant or unbound rule is invalid (its protocols, validated as
    /// [`RuleSet::new`](crate::RuleSet::new) does).
    #[error("invalid gate rule '{id}': {reason}")]
    InvalidRule {
        /// The rule's identifier.
        id: RuleId,
        /// Why it is invalid.
        reason: String,
    },
    /// An IPv6 address or prefix: the gate handles IPv4 only.
    #[error("IPv6 entry {value} in {field}: the flow gate handles IPv4 only")]
    Ipv6 {
        /// The policy field (`local`, `bindings.addresses`,
        /// `grants.destinations`, `holds.local`, `holds.remote` or
        /// `holds.release`).
        field: &'static str,
        /// The entry.
        value: String,
    },
}
