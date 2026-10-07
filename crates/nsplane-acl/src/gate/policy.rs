//! Validation and the compiled form of the policy's scopes and holds.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};

use nsplane_packet::PeerId;

use super::PacketDirection;
use super::config::{
    GateBinding, GateGrant, GateHolds, GateMode, GatePolicy, GatePolicyError, GateScope, HoldRule,
    ScopeId, UnboundAction, UnboundRule,
};
use super::hash::{FastMap, FastSet};
use crate::net::{IpNet, Protocol};
use crate::pinhole::Direction;
use crate::rules::{Label, LabelSet, Protocols, RuleId, Transport};

/// The state key of a scope: stable while the scope id stays in the policy.
pub(super) type Slot = u32;

/// A `(peer, remote address)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BindingKey {
    pub(super) peer: PeerId,
    pub(super) ip: Ipv4Addr,
}

impl Hash for BindingKey {
    /// One word: the peer and the address.
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64((u64::from(self.peer.get()) << 32) | u64::from(self.ip.to_bits()));
    }
}

/// A grant in its matching form.
#[derive(Debug)]
pub(super) struct CompiledGrant {
    pub(super) id: RuleId,
    pub(super) direction: PacketDirection,
    labels: Box<[Label]>,
    destinations: Box<[IpNet]>,
    protocols: Protocols,
    pub(super) suspended: bool,
}

impl CompiledGrant {
    /// Whether a new flow initiated in `direction` from a source with
    /// `labels` to `destination` matches (`suspended` is not checked).
    pub(super) fn matches(
        &self,
        direction: PacketDirection,
        labels: &LabelSet,
        destination: Ipv4Addr,
        transport: Transport,
    ) -> bool {
        self.direction == direction
            && (self.labels.is_empty() || labels.intersects(&self.labels))
            && (self.destinations.is_empty()
                || self
                    .destinations
                    .iter()
                    .any(|net| net.contains(&IpAddr::V4(destination))))
            && self.protocols.matches(transport)
    }
}

/// An unbound rule in its matching form.
#[derive(Debug)]
pub(super) struct CompiledUnbound {
    pub(super) id: RuleId,
    peers: FastSet<PeerId>,
    pub(super) action: UnboundAction,
    protocols: Protocols,
}

impl CompiledUnbound {
    pub(super) fn has_peer(&self, peer: PeerId) -> bool {
        self.peers.contains(&peer)
    }

    /// Whether the rule matches a packet of `peer`: by `transport` for a
    /// first fragment, by protocol for a later one (`None`), which then
    /// needs a TCP or UDP entry covering every port.
    pub(super) fn matches(&self, peer: PeerId, protocol: u8, transport: Option<Transport>) -> bool {
        self.has_peer(peer)
            && transport.map_or_else(
                || {
                    Protocol::from_ip_number(protocol)
                        .is_some_and(|protocol| self.protocols.covers(protocol))
                },
                |transport| self.protocols.matches(transport),
            )
    }
}

/// The result of the grant search for a new flow.
#[derive(Debug, Clone, Copy)]
pub(super) enum Authorization<'a> {
    /// The first matching grant that is not suspended.
    Granted(&'a RuleId),
    /// Only suspended grants match; the first of them.
    Suspended(&'a RuleId),
    NoGrant,
}

/// A scope with a mode other than [`GateMode::Off`], in its matching form.
#[derive(Debug)]
pub(super) struct CompiledScope {
    pub(super) slot: Slot,
    pub(super) id: ScopeId,
    /// [`GateMode::Enforce`]; otherwise [`GateMode::Observe`].
    pub(super) enforce: bool,
    pub(super) local: Box<[Ipv4Addr]>,
    pub(super) bindings: FastMap<BindingKey, LabelSet>,
    /// Remote addresses of the scope without a binding.
    pub(super) unbound_addresses: Box<[Ipv4Addr]>,
    pub(super) grants: Box<[CompiledGrant]>,
    pub(super) unbound: Box<[CompiledUnbound]>,
    /// The scope as given, to detect a changed scope on the next replace.
    pub(super) source: GateScope,
}

impl CompiledScope {
    pub(super) fn governs(&self, local: Ipv4Addr) -> bool {
        self.local.contains(&local)
    }

    /// The grant search for a new flow initiated in `direction` from a
    /// source with `labels` to `destination`.
    pub(super) fn authorize(
        &self,
        direction: PacketDirection,
        labels: &LabelSet,
        destination: Ipv4Addr,
        transport: Transport,
    ) -> Authorization<'_> {
        let mut suspended = None;
        for grant in &self.grants {
            if grant.matches(direction, labels, destination, transport) {
                if !grant.suspended {
                    return Authorization::Granted(&grant.id);
                }
                suspended.get_or_insert(&grant.id);
            }
        }
        suspended.map_or(Authorization::NoGrant, Authorization::Suspended)
    }
}

/// A set of IPv4 addresses: empty (any address), hosts and prefixes.
#[derive(Debug, Default)]
struct AddressSet {
    any: bool,
    hosts: FastSet<Ipv4Addr>,
    prefixes: Box<[IpNet]>,
}

impl AddressSet {
    fn compile(nets: &[IpNet]) -> Self {
        let mut set = Self {
            any: nets.is_empty(),
            ..Self::default()
        };
        let mut prefixes = Vec::new();
        for net in nets {
            match net.network() {
                IpAddr::V4(host) if net.prefix_len() == 32 => {
                    set.hosts.insert(host);
                }
                _ => prefixes.push(*net),
            }
        }
        set.prefixes = prefixes.into();
        set
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        self.any
            || self.hosts.contains(&ip)
            || self
                .prefixes
                .iter()
                .any(|net| net.contains(&IpAddr::V4(ip)))
    }
}

#[derive(Debug)]
struct CompiledHoldRule {
    peers: Option<FastSet<PeerId>>,
    local: AddressSet,
    remote: AddressSet,
}

impl CompiledHoldRule {
    fn compile(rule: &HoldRule) -> Self {
        Self {
            peers: rule
                .peers
                .as_ref()
                .map(|peers| peers.iter().copied().collect()),
            local: AddressSet::compile(&rule.local),
            remote: AddressSet::compile(&rule.remote),
        }
    }

    fn matches(&self, peer: PeerId, local: Ipv4Addr, remote: Ipv4Addr) -> bool {
        self.peers
            .as_ref()
            .is_none_or(|peers| peers.contains(&peer))
            && self.local.contains(local)
            && self.remote.contains(remote)
    }
}

/// The holds in their matching form.
#[derive(Debug, Default)]
pub(super) struct CompiledHolds {
    inbound: Box<[CompiledHoldRule]>,
    outbound: Box<[CompiledHoldRule]>,
    release: FastSet<BindingKey>,
}

impl CompiledHolds {
    fn compile(holds: &GateHolds) -> Self {
        Self {
            inbound: holds
                .inbound
                .iter()
                .map(CompiledHoldRule::compile)
                .collect(),
            outbound: holds
                .outbound
                .iter()
                .map(CompiledHoldRule::compile)
                .collect(),
            release: holds
                .release
                .iter()
                .filter_map(|(peer, ip)| match ip {
                    IpAddr::V4(ip) => Some(BindingKey {
                        peer: *peer,
                        ip: *ip,
                    }),
                    IpAddr::V6(_) => None,
                })
                .collect(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.inbound.is_empty() && self.outbound.is_empty()
    }

    /// Whether a packet of `peer` between `local` and `remote` is held.
    pub(super) fn held(
        &self,
        direction: PacketDirection,
        peer: PeerId,
        local: Ipv4Addr,
        remote: Ipv4Addr,
    ) -> bool {
        let rules = match direction {
            PacketDirection::Inbound => {
                if self.inbound.is_empty()
                    || self.release.contains(&BindingKey { peer, ip: remote })
                {
                    return false;
                }
                &self.inbound
            }
            PacketDirection::Outbound => &self.outbound,
        };
        rules.iter().any(|rule| rule.matches(peer, local, remote))
    }
}

/// A validated policy: the compiled scopes (without the `Off` ones, in
/// policy order) and the holds.
pub(super) struct CompiledPolicy {
    pub(super) scopes: Vec<CompiledScope>,
    pub(super) holds: CompiledHolds,
}

/// Validate `policy` and compile it. `published` gives the slot of a scope id
/// kept from the published policy; new ids get the smallest slot neither
/// kept nor published, so no state of another scope can carry it.
pub(super) fn compile(
    policy: GatePolicy,
    published: &FastMap<ScopeId, Slot>,
) -> Result<CompiledPolicy, GatePolicyError> {
    let mut ids = HashSet::new();
    for scope in &policy.scopes {
        if !ids.insert(&scope.id) {
            return Err(GatePolicyError::DuplicateScope(scope.id.clone()));
        }
    }
    validate_holds(&policy.holds)?;
    let mut used: HashSet<Slot> = published.values().copied().collect();
    let mut next = 0;
    let holds = CompiledHolds::compile(&policy.holds);
    let mut scopes = Vec::new();
    for scope in policy.scopes {
        let compiled = compile_scope(scope)?;
        if compiled.source.mode == GateMode::Off {
            continue;
        }
        let slot = published.get(&compiled.id).copied().unwrap_or_else(|| {
            while used.contains(&next) {
                next += 1;
            }
            used.insert(next);
            next
        });
        scopes.push(CompiledScope { slot, ..compiled });
    }
    Ok(CompiledPolicy { scopes, holds })
}

fn compile_scope(scope: GateScope) -> Result<CompiledScope, GatePolicyError> {
    let local = scope
        .local
        .iter()
        .map(|ip| ipv4(*ip, "local"))
        .collect::<Result<_, _>>()?;
    let mut bindings = FastMap::default();
    for GateBinding {
        peer,
        addresses,
        labels,
    } in &scope.bindings
    {
        for address in addresses {
            let ip = ipv4(*address, "bindings.addresses")?;
            if bindings
                .insert(BindingKey { peer: *peer, ip }, labels.clone())
                .is_some()
            {
                return Err(GatePolicyError::DuplicateBinding {
                    scope: scope.id.clone(),
                    peer: *peer,
                    address: *address,
                });
            }
        }
    }
    let mut unbound_addresses: Vec<Ipv4Addr> = Vec::new();
    for address in &scope.unbound_addresses {
        let ip = ipv4(*address, "unbound_addresses")?;
        if unbound_addresses.contains(&ip) || bindings.keys().any(|binding| binding.ip == ip) {
            return Err(GatePolicyError::ConflictingAddress {
                scope: scope.id.clone(),
                address: *address,
            });
        }
        unbound_addresses.push(ip);
    }
    let grants = scope
        .grants
        .iter()
        .map(compile_grant)
        .collect::<Result<_, _>>()?;
    let unbound = scope
        .unbound
        .iter()
        .map(compile_unbound)
        .collect::<Result<_, _>>()?;
    Ok(CompiledScope {
        slot: 0,
        id: scope.id.clone(),
        enforce: scope.mode == GateMode::Enforce,
        local,
        bindings,
        unbound_addresses: unbound_addresses.into(),
        grants,
        unbound,
        source: scope,
    })
}

fn compile_grant(grant: &GateGrant) -> Result<CompiledGrant, GatePolicyError> {
    for net in &grant.destinations {
        ipv4_net(net, "grants.destinations")?;
    }
    Ok(CompiledGrant {
        id: grant.id.clone(),
        direction: match grant.direction {
            Direction::Inbound => PacketDirection::Inbound,
            Direction::Outbound => PacketDirection::Outbound,
        },
        labels: grant.labels.clone().into(),
        destinations: grant.destinations.clone().into(),
        protocols: protocols(&grant.id, &grant.protocols)?,
        suspended: grant.suspended,
    })
}

fn compile_unbound(rule: &UnboundRule) -> Result<CompiledUnbound, GatePolicyError> {
    Ok(CompiledUnbound {
        id: rule.id.clone(),
        peers: rule.peers.iter().copied().collect(),
        action: rule.action,
        protocols: protocols(&rule.id, &rule.protocols)?,
    })
}

fn protocols(
    id: &RuleId,
    protocols: &[crate::rules::ProtocolMatch],
) -> Result<Protocols, GatePolicyError> {
    Protocols::compile(protocols).map_err(|reason| GatePolicyError::InvalidRule {
        id: id.clone(),
        reason,
    })
}

fn validate_holds(holds: &GateHolds) -> Result<(), GatePolicyError> {
    for rule in holds.inbound.iter().chain(&holds.outbound) {
        for net in &rule.local {
            ipv4_net(net, "holds.local")?;
        }
        for net in &rule.remote {
            ipv4_net(net, "holds.remote")?;
        }
    }
    for (_, ip) in &holds.release {
        ipv4(*ip, "holds.release")?;
    }
    Ok(())
}

fn ipv4(ip: IpAddr, field: &'static str) -> Result<Ipv4Addr, GatePolicyError> {
    match ip {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(GatePolicyError::Ipv6 {
            field,
            value: ip.to_string(),
        }),
    }
}

fn ipv4_net(net: &IpNet, field: &'static str) -> Result<(), GatePolicyError> {
    if net.network().is_ipv4() {
        Ok(())
    } else {
        Err(GatePolicyError::Ipv6 {
            field,
            value: net.to_string(),
        })
    }
}
