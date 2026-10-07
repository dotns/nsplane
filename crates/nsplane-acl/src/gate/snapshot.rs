//! The immutable snapshot read by packet paths and its precomputed indexes.

use std::net::Ipv4Addr;

use nsplane_packet::PeerId;

use super::PacketDirection;
use super::config::ScopeId;
use super::hash::FastMap;
use super::policy::{BindingKey, CompiledHolds, CompiledPolicy, CompiledScope, Slot};

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
    /// Scope indexes binding a `(peer, remote address)` pair.
    by_binding: FastMap<BindingKey, Vec<usize>>,
    /// Scope indexes governing a local address.
    by_local: FastMap<Ipv4Addr, Vec<usize>>,
    /// Scope indexes holding an address as a binding address.
    by_remote: FastMap<Ipv4Addr, Vec<usize>>,
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
        let mut by_binding = FastMap::<_, Vec<_>>::default();
        let mut by_local = FastMap::<_, Vec<_>>::default();
        let mut by_remote = FastMap::<_, Vec<_>>::default();
        for (index, scope) in policy.scopes.iter().enumerate() {
            for ip in &scope.local {
                push_once(by_local.entry(*ip).or_default(), index);
            }
            for binding in scope.bindings.keys() {
                by_binding.entry(*binding).or_default().push(index);
                push_once(by_remote.entry(binding.ip).or_default(), index);
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
            by_binding,
            by_local,
            by_remote,
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
    pub(super) fn bound(&self, binding: &BindingKey) -> impl Iterator<Item = &CompiledScope> {
        self.resolve(self.by_binding.get(binding))
    }

    /// Scopes governing the local address `ip`.
    pub(super) fn with_local(&self, ip: Ipv4Addr) -> impl Iterator<Item = &CompiledScope> {
        self.resolve(self.by_local.get(&ip))
    }

    /// Scopes holding `ip` as a binding address.
    pub(super) fn with_remote(&self, ip: Ipv4Addr) -> impl Iterator<Item = &CompiledScope> {
        self.resolve(self.by_remote.get(&ip))
    }

    /// Whether `ip` is a local or binding address of any scope.
    pub(super) fn is_scope_address(&self, ip: Ipv4Addr) -> bool {
        self.by_local.contains_key(&ip) || self.by_remote.contains_key(&ip)
    }

    /// The scope holding the state of `slot`.
    pub(super) fn scope_of_slot(&self, slot: Slot) -> Option<&CompiledScope> {
        self.scopes.iter().find(|scope| scope.slot == slot)
    }

    /// Whether a packet of `peer` between `local` and `remote` is held.
    pub(super) fn held(
        &self,
        direction: PacketDirection,
        peer: PeerId,
        local: Ipv4Addr,
        remote: Ipv4Addr,
    ) -> bool {
        self.holds.held(direction, peer, local, remote)
    }
}

fn push_once(indexes: &mut Vec<usize>, index: usize) {
    if indexes.last() != Some(&index) {
        indexes.push(index);
    }
}
