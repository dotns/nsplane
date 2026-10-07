//! State migration across [`FlowGate::replace`](super::FlowGate::replace).

use std::sync::MutexGuard;

use super::PacketDirection;
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
/// their state.
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
    if all_kept {
        return;
    }
    for shard in shards.iter_mut() {
        shard.retain_flows(counts, |key, state| match plans.get(&key.slot) {
            Some(Plan::Keep) => true,
            Some(Plan::Revalidate(scope)) => reauthorize(scope, key, state),
            None => false,
        });
        shard.retain_fragments(counts, |key, _| {
            matches!(plans.get(&key.slot), Some(Plan::Keep))
        });
    }
}

/// Re-authorize a flow of a changed scope as a new flow by its initiator,
/// updating its grant and mode; `false` drops it.
fn reauthorize(scope: &CompiledScope, key: &FlowKey, state: &mut FlowState) -> bool {
    if !scope.governs(key.local_ip) {
        return false;
    }
    let Some(labels) = scope.bindings.get(&BindingKey {
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
