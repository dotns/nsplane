//! The immutable snapshot read by packet paths and its precomputed indexes.

use std::net::{Ipv4Addr, Ipv6Addr};

use nsplane_packet::PeerId;

use super::PacketDirection;
use super::addr::GateAddr;
use super::config::ScopeId;
use super::hash::FastMap;
use super::policy::{BindingKey, CompiledHolds, CompiledPolicy, CompiledScope, Slot};

/// The scope indexes of one address family.
#[derive(Debug)]
pub(super) struct AddrIndex<A: GateAddr> {
    /// Scope indexes binding a `(peer, remote address)` pair.
    bindings: FastMap<BindingKey<A>, Vec<usize>>,
    /// Scope indexes governing a local address.
    local: FastMap<A, Vec<usize>>,
    /// Scope indexes holding an address as a binding or unbound address.
    remote: FastMap<A, Vec<usize>>,
}

impl<A: GateAddr> AddrIndex<A> {
    fn build(scopes: &[CompiledScope]) -> Self {
        let mut bindings = FastMap::<_, Vec<_>>::default();
        let mut local = FastMap::<_, Vec<_>>::default();
        let mut remote = FastMap::<_, Vec<_>>::default();
        for (index, scope) in scopes.iter().enumerate() {
            let addrs = A::scope(scope);
            for ip in &addrs.local {
                push_once(local.entry(*ip).or_default(), index);
            }
            for binding in addrs.bindings.keys() {
                bindings.entry(*binding).or_default().push(index);
                push_once(remote.entry(binding.ip).or_default(), index);
            }
            for ip in &addrs.unbound_addresses {
                push_once(remote.entry(*ip).or_default(), index);
            }
        }
        Self {
            bindings,
            local,
            remote,
        }
    }
}

/// Everything packet paths read, published atomically as one value.
#[derive(Debug)]
pub(super) struct Snapshot {
    /// The gate generation; matches the epoch of every state shard once the
    /// publishing writer has migrated it.
    pub(super) generation: u64,
    /// No scope and no hold rule: every packet passes.
    pub(super) inert: bool,
    pub(super) scopes: Box<[CompiledScope]>,
    pub(super) holds: CompiledHolds,
    pub(super) v4: AddrIndex<Ipv4Addr>,
    pub(super) v6: AddrIndex<Ipv6Addr>,
    /// Scope indexes with a peer-keyed binding of a peer.
    by_peer: FastMap<PeerId, Vec<usize>>,
    /// The slot of every scope id.
    pub(super) slots: FastMap<ScopeId, Slot>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self::build(
            0,
            CompiledPolicy {
                scopes: Vec::new(),
                holds: CompiledHolds::default(),
            },
        )
    }
}

impl Snapshot {
    pub(super) fn build(generation: u64, policy: CompiledPolicy) -> Self {
        let v4 = AddrIndex::build(&policy.scopes);
        let v6 = AddrIndex::build(&policy.scopes);
        let mut by_peer = FastMap::<_, Vec<_>>::default();
        for (index, scope) in policy.scopes.iter().enumerate() {
            for peer in scope.peer_bindings.keys() {
                by_peer.entry(*peer).or_default().push(index);
            }
        }
        let slots = policy
            .scopes
            .iter()
            .map(|scope| (scope.id.clone(), scope.slot))
            .collect();
        Self {
            generation,
            inert: policy.scopes.is_empty() && policy.holds.is_empty(),
            scopes: policy.scopes.into(),
            holds: policy.holds,
            v4,
            v6,
            by_peer,
            slots,
        }
    }

    fn resolve<'a>(
        &'a self,
        indexes: Option<&'a Vec<usize>>,
    ) -> impl Iterator<Item = &'a CompiledScope> {
        indexes
            .into_iter()
            .flatten()
            .map(|index| &self.scopes[*index])
    }

    /// Scopes binding `binding`.
    pub(super) fn bound<A: GateAddr>(
        &self,
        binding: &BindingKey<A>,
    ) -> impl Iterator<Item = &CompiledScope> {
        self.resolve(A::index(self).bindings.get(binding))
    }

    /// Whether any scope has a peer-keyed binding.
    pub(super) fn has_peer_keyed(&self) -> bool {
        !self.by_peer.is_empty()
    }

    /// Scopes with a peer-keyed binding of `peer`.
    pub(super) fn peer_keyed(&self, peer: PeerId) -> impl Iterator<Item = &CompiledScope> {
        self.resolve(if self.has_peer_keyed() {
            self.by_peer.get(&peer)
        } else {
            None
        })
    }

    /// The scope a packet of `binding` to or from `local` belongs to: the
    /// one governing `local` that binds the exact pair, else the one
    /// governing `local` with a peer-keyed binding of the peer. `None` when
    /// there is none or more than one at the chosen level.
    pub(super) fn select<A: GateAddr>(
        &self,
        binding: &BindingKey<A>,
        local: A,
    ) -> Option<&CompiledScope> {
        let mut exact = self.bound(binding).filter(|scope| scope.governs(local));
        let mut scopes = match exact.next() {
            Some(scope) => return exact.next().is_none().then_some(scope),
            None => self
                .peer_keyed(binding.peer)
                .filter(|scope| scope.governs(local)),
        };
        let scope = scopes.next()?;
        scopes.next().is_none().then_some(scope)
    }

    /// Scopes governing the local address `ip`.
    pub(super) fn with_local<A: GateAddr>(&self, ip: A) -> impl Iterator<Item = &CompiledScope> {
        self.resolve(A::index(self).local.get(&ip))
    }

    /// Scopes holding `ip` as a binding or unbound address.
    pub(super) fn with_remote<A: GateAddr>(&self, ip: A) -> impl Iterator<Item = &CompiledScope> {
        self.resolve(A::index(self).remote.get(&ip))
    }

    /// Whether `ip` is a local, binding or unbound address of any scope.
    pub(super) fn is_scope_address<A: GateAddr>(&self, ip: A) -> bool {
        let index = A::index(self);
        index.local.contains_key(&ip) || index.remote.contains_key(&ip)
    }

    /// The scope holding the state of `slot`.
    pub(super) fn scope_of_slot(&self, slot: Slot) -> Option<&CompiledScope> {
        self.scopes.iter().find(|scope| scope.slot == slot)
    }

    /// Whether a packet of `peer` between `local` and `remote` is held.
    pub(super) fn held<A: GateAddr>(
        &self,
        direction: PacketDirection,
        peer: PeerId,
        local: A,
        remote: A,
    ) -> bool {
        self.holds.held(direction, peer, local, remote)
    }
}

fn push_once(indexes: &mut Vec<usize>, index: usize) {
    if indexes.last() != Some(&index) {
        indexes.push(index);
    }
}
