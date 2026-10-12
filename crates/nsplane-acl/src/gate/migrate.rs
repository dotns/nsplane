//! State migration across [`FlowGate::replace`](super::FlowGate::replace).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::MutexGuard;

use super::PacketDirection;
use super::addr::GateAddr;
use super::hash::FastMap;
use super::policy::{Authorization, BindingKey, CompiledScope, Slot};
use super::snapshot::Snapshot;
use super::state::{Counts, FlowKey, FlowState, Shard};

/// What happens to the state of one published scope.
#[derive(Debug, Clone, Copy)]
enum Plan<'a> {
    /// Unchanged: flows and fragments stay untouched.
    Keep,
    /// Changed: flows are re-authorized, fragments dropped.
    Revalidate(&'a CompiledScope),
}

/// Migrate every shard from `previous` to `next`. The caller holds every
/// shard; slots of scopes absent from `next` (removed or `Off`) lose all
/// their state. When `next` has a peer-keyed binding, a flow is also kept
/// only while its scope is the one [`Snapshot::select`] picks for it.
pub(super) fn migrate(
    shards: &mut [MutexGuard<'_, Shard>],
    previous: &Snapshot,
    next: &Snapshot,
    counts: &Counts,
) {
    let mut plans = FastMap::<Slot, Plan<'_>>::default();
    let mut all_kept = true;
    for scope in &previous.scopes {
        let Some(successor) = next
            .scopes
            .iter()
            .find(|candidate| candidate.slot == scope.slot)
        else {
            all_kept = false;
            continue;
        };
        if successor.source == scope.source {
            plans.insert(scope.slot, Plan::Keep);
        } else {
            all_kept = false;
            plans.insert(scope.slot, Plan::Revalidate(successor));
        }
    }
    // With every scope kept and none added, every lookup selects as before.
    let select = next.has_peer_keyed().then_some(next);
    if all_kept && (select.is_none() || next.scopes.len() == previous.scopes.len()) {
        return;
    }
    for shard in shards.iter_mut() {
        migrate_family::<Ipv4Addr>(shard, &plans, select, counts);
        migrate_family::<Ipv6Addr>(shard, &plans, select, counts);
    }
}

/// Migrate the state of the family `A` of one shard by `plans`; with
/// `select`, a flow whose scope that snapshot no longer selects is dropped.
fn migrate_family<A: GateAddr>(
    shard: &mut Shard,
    plans: &FastMap<Slot, Plan<'_>>,
    select: Option<&Snapshot>,
    counts: &Counts,
) {
    let selected = |key: &FlowKey<A>| {
        select.is_none_or(|snapshot| {
            snapshot
                .select(
                    &BindingKey {
                        peer: key.peer,
                        ip: key.remote_ip,
                    },
                    key.local_ip,
                )
                .is_some_and(|scope| scope.slot == key.slot)
        })
    };
    let mut family = shard.family::<A>();
    family.retain_flows(counts, |key, state| match plans.get(&key.slot) {
        Some(Plan::Keep) => selected(key),
        Some(Plan::Revalidate(scope)) => selected(key) && reauthorize(scope, key, state),
        None => false,
    });
    family.retain_fragments(counts, |key, _| {
        matches!(plans.get(&key.slot), Some(Plan::Keep))
    });
}

/// Re-authorize a flow of a changed scope as a new flow by its initiator,
/// updating its grant and mode; `false` drops it.
fn reauthorize<A: GateAddr>(
    scope: &CompiledScope,
    key: &FlowKey<A>,
    state: &mut FlowState,
) -> bool {
    if !scope.governs(key.local_ip) {
        return false;
    }
    let Some(labels) = scope.labels(&BindingKey {
        peer: key.peer,
        ip: key.remote_ip,
    }) else {
        return false;
    };
    let destination = match state.initiator {
        PacketDirection::Inbound => key.local_ip,
        PacketDirection::Outbound => key.remote_ip,
    };
    match scope.authorize(state.initiator, labels, destination, state.opened) {
        Authorization::Granted(rule) => {
            state.rule = rule.clone();
            state.enforced = scope.enforce;
            true
        }
        Authorization::Suspended(_) | Authorization::NoGrant => false,
    }
}
