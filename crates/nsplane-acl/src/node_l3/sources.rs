//! Applying and withdrawing projection sources and reporting peer readiness.

use std::collections::HashSet;
use std::sync::Arc;

use super::config::{
    NODE_L3_SCHEMA_VERSION, NodeL3Config, NodeL3Mode, NodeL3PeerPolicyRequirement,
};
use super::policy::{BindingKey, CompiledPolicy, NetIdx, require_non_empty};
use super::snapshot::ProviderListeners;
use super::state::{Counts, FlowKey, ServiceFlowAuthorization, Shard};
use super::{
    NetworkTombstone, NodeL3Applied, NodeL3ConfigError, NodeL3Gate, NodeL3PeerReadiness,
    NodeL3PeerReadinessReason, PacketDirection,
};

impl NodeL3Gate {
    /// Apply a snapshot received from one authenticated control source.
    ///
    /// A globally unique Network ID is permanently pinned to the first source
    /// that successfully publishes it. A second source cannot take ownership by
    /// racing a higher generation or by waiting for the first to withdraw.
    pub fn apply_from_source(
        &self,
        source_id: &str,
        config: NodeL3Config,
    ) -> Result<NodeL3Applied, NodeL3ConfigError> {
        let (applied, published) = self.apply_locked(source_id, config)?;
        if published {
            self.notify_authorization_change();
        }
        Ok(applied)
    }

    fn apply_locked(
        &self,
        source_id: &str,
        config: NodeL3Config,
    ) -> Result<(NodeL3Applied, bool), NodeL3ConfigError> {
        let mut writer = self.lock_writer();
        require_non_empty(source_id, "source_id")?;
        if config.schema_version != NODE_L3_SCHEMA_VERSION {
            return Err(NodeL3ConfigError::UnsupportedSchema(config.schema_version));
        }
        if !self.target_machine_ids.contains(&config.target_machine_id) {
            let mut expected: Vec<&str> =
                self.target_machine_ids.iter().map(String::as_str).collect();
            expected.sort_unstable();
            return Err(NodeL3ConfigError::WrongTarget {
                expected: expected.join(","),
                actual: config.target_machine_id,
            });
        }
        require_non_empty(&config.network_id, "network_id")?;

        // The tombstone owns source, generation, phase, target, and content
        // even while the active policy is withdrawn.
        let previous = writer.tombstones.get(&config.network_id);
        if let Some(previous) = previous
            && previous.source_id != source_id
        {
            return Err(NodeL3ConfigError::AuthorityConflict {
                network_id: config.network_id,
                applied_source: previous.source_id.clone(),
                actual_source: source_id.to_owned(),
            });
        }

        let identity = config.policy_identity();
        let applied = NodeL3Applied {
            network_id: config.network_id.clone(),
            target_machine_id: config.target_machine_id.clone(),
            generation: config.generation,
            mode: config.mode,
        };
        if let Some(previous) = previous
            && is_replay(previous, &config, &identity)?
        {
            return Ok((applied, false));
        }

        let net = previous.map_or(writer.next_net, |previous| previous.net);
        let compiled = if config.mode == NodeL3Mode::Disabled {
            None
        } else {
            Some(Arc::new(CompiledPolicy::compile(&config, net)?))
        };
        if previous.is_none() {
            writer.next_net += 1;
        }
        writer.tombstones.insert(
            config.network_id.clone(),
            NetworkTombstone {
                net,
                network_id: config.network_id,
                source_id: source_id.to_owned(),
                target_machine_id: config.target_machine_id,
                generation: config.generation,
                mode: config.mode,
                content: Some(identity),
            },
        );

        let current = self.snapshot.load_full();
        let mut policies = current.policies.clone();
        match &compiled {
            Some(policy) => policies.insert(net, Arc::clone(policy)),
            None => policies.remove(&net),
        };
        let counts = &self.state.counts;
        self.publish(
            policies,
            current.transport.clone(),
            Arc::clone(&current.listeners),
            writer.tombstone_views(),
            |shards, snapshot| {
                for shard in shards.iter_mut() {
                    match &compiled {
                        Some(policy) => {
                            revalidate_network(shard, policy, &snapshot.listeners, counts);
                        }
                        None => remove_networks(shard, &[net], counts),
                    }
                }
            },
        );
        Ok((applied, true))
    }

    /// Withdraw every Network policy last accepted from one authenticated
    /// control source.
    ///
    /// Revocation is intentionally independent of the last raw frame received
    /// from that source. A stale, wrong-target, unsupported, or malformed frame
    /// may be rejected after a valid snapshot; it must never prevent removal of
    /// the valid snapshot when the source credential is revoked. Tombstones
    /// retain the accepted generation and source ownership so queued stale
    /// frames cannot resurrect access.
    pub fn withdraw_source(&self, source_id: &str) -> Result<usize, NodeL3ConfigError> {
        require_non_empty(source_id, "source_id")?;
        let withdrawn = {
            let mut writer = self.lock_writer();
            let mut nets = Vec::new();
            for tombstone in writer.tombstones.values_mut() {
                if tombstone.source_id == source_id {
                    tombstone.mode = NodeL3Mode::Disabled;
                    // This is a source-authority withdrawal rather than a wire
                    // snapshot. No content makes every same-generation replay
                    // conflict while the retained generation rejects older ones.
                    tombstone.content = None;
                    nets.push(tombstone.net);
                }
            }
            if nets.is_empty() {
                return Ok(0);
            }
            let current = self.snapshot.load_full();
            let mut policies = current.policies.clone();
            for net in &nets {
                policies.remove(net);
            }
            let counts = &self.state.counts;
            self.publish(
                policies,
                current.transport.clone(),
                Arc::clone(&current.listeners),
                writer.tombstone_views(),
                |shards, _| {
                    for shard in shards.iter_mut() {
                        remove_networks(shard, &nets, counts);
                    }
                },
            );
            nets.len()
        };
        self.notify_authorization_change();
        Ok(withdrawn)
    }

    /// Whether this exact applied generation is safe to acknowledge. Disabled
    /// snapshots require only the durable tombstone; active snapshots also
    /// require the local WG device to own the same local IP and require every
    /// actually projected Node binding/marker to match the applied policy. A
    /// binding with no current transport is safe (it cannot carry packets) and
    /// becomes fail-closed through its marker before it is later installed.
    #[must_use]
    pub fn ready_for_ack(&self, applied: &NodeL3Applied) -> bool {
        let snapshot = self.snapshot.load();
        let Some((net, tombstone)) = snapshot.tombstone(&applied.network_id) else {
            return false;
        };
        if tombstone.target_machine_id != applied.target_machine_id
            || tombstone.generation != applied.generation
            || tombstone.mode != applied.mode
        {
            return false;
        }
        if applied.mode == NodeL3Mode::Disabled {
            return true;
        }
        let Some(policy) = snapshot.policies.get(&net) else {
            return false;
        };
        let Some(projection) = snapshot.transport.as_deref() else {
            return false;
        };
        if !projection.installed
            || policy.target_machine_id != applied.target_machine_id
            || policy.generation != applied.generation
            || policy.mode != applied.mode
            || projection.local_ip != policy.local.ip
        {
            return false;
        }
        let marker_matches = |requirement: &NodeL3PeerPolicyRequirement| {
            requirement.network_id == policy.network_id
                && requirement.generation == policy.generation
                && requirement.mode == policy.mode
        };
        let binding_usable = |binding: &BindingKey| {
            policy.bindings.get(binding).is_some_and(|node| {
                policy.mode == NodeL3Mode::Enforce || node.owner_id == policy.local.owner_id
            })
        };
        let installed_policy_bindings_are_marked = projection
            .bindings
            .iter()
            .filter(|binding| policy.has_remote_node_ip(binding.ip))
            .all(|binding| {
                binding_usable(binding)
                    && projection
                        .authoritative_bindings
                        .get(binding)
                        .is_some_and(marker_matches)
            });
        let desired_network_markers_are_installed = projection
            .authoritative_bindings
            .iter()
            .filter(|(_, requirement)| requirement.network_id == policy.network_id)
            .all(|(binding, requirement)| {
                marker_matches(requirement)
                    && projection.bindings.contains(binding)
                    && binding_usable(binding)
            });
        installed_policy_bindings_are_marked && desired_network_markers_are_installed
    }

    /// Snapshot the exact local readiness of every authoritative Node marker.
    ///
    /// Rows are deterministically ordered and expose only identifiers and
    /// rollout metadata already present in authenticated local projections.
    #[must_use]
    pub fn peer_readiness_snapshot(&self) -> Vec<NodeL3PeerReadiness> {
        let snapshot = self.snapshot.load();
        let Some(projection) = snapshot.transport.as_deref() else {
            return Vec::new();
        };
        let mut rows = projection
            .authoritative_bindings
            .iter()
            .map(|(binding, requirement)| {
                let policy = snapshot.policy_by_id(&requirement.network_id);
                let reason = if !projection.installed {
                    NodeL3PeerReadinessReason::TransportNotInstalled
                } else if !projection.bindings.contains(binding) {
                    NodeL3PeerReadinessReason::BindingNotInstalled
                } else if let Some(policy) = policy {
                    if policy.generation != requirement.generation {
                        NodeL3PeerReadinessReason::GenerationMismatch
                    } else if policy.mode != requirement.mode {
                        NodeL3PeerReadinessReason::ModeMismatch
                    } else if policy.local.ip != projection.local_ip {
                        NodeL3PeerReadinessReason::LocalIpMismatch
                    } else if let Some(node) = policy.bindings.get(binding) {
                        if requirement.mode == NodeL3Mode::Enforce
                            || node.owner_id == policy.local.owner_id
                        {
                            NodeL3PeerReadinessReason::Ready
                        } else {
                            NodeL3PeerReadinessReason::ObserveOwnerMismatch
                        }
                    } else {
                        NodeL3PeerReadinessReason::BindingMissing
                    }
                } else {
                    NodeL3PeerReadinessReason::PolicyMissing
                };
                NodeL3PeerReadiness {
                    ip: binding.ip,
                    network_id: requirement.network_id.clone(),
                    marker_generation: requirement.generation,
                    marker_mode: requirement.mode,
                    policy_generation: policy.map(|policy| policy.generation),
                    policy_mode: policy.map(|policy| policy.mode),
                    ready: reason == NodeL3PeerReadinessReason::Ready,
                    reason,
                }
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.ip
                .cmp(&right.ip)
                .then_with(|| left.network_id.cmp(&right.network_id))
                .then_with(|| left.marker_generation.cmp(&right.marker_generation))
        });
        rows
    }
}

/// Check a snapshot against its Network's tombstone: `Ok(true)` for an
/// idempotent replay, `Ok(false)` when it must be published.
fn is_replay(
    previous: &NetworkTombstone,
    config: &NodeL3Config,
    identity: &NodeL3Config,
) -> Result<bool, NodeL3ConfigError> {
    if config.generation < previous.generation {
        return Err(NodeL3ConfigError::StaleGeneration {
            applied: previous.generation,
            actual: config.generation,
        });
    }
    if config.generation != previous.generation {
        return Ok(false);
    }
    if previous.mode == NodeL3Mode::Disabled {
        if previous.content.as_ref() != Some(identity) {
            return Err(NodeL3ConfigError::Conflict(
                "content for an already-withdrawn generation",
            ));
        }
        return Ok(true);
    }
    // A withdrawal is always security-reducing and may replace the live
    // phase at the same generation. Its exact disabled content becomes the
    // new tombstone and cannot be re-enabled in place.
    if config.mode == NodeL3Mode::Disabled {
        return Ok(false);
    }
    if previous.content.as_ref() != Some(identity) {
        return Err(NodeL3ConfigError::Conflict(
            "content for an already-applied generation",
        ));
    }
    match (previous.mode, config.mode) {
        (NodeL3Mode::Enforce, NodeL3Mode::Observe) => Err(NodeL3ConfigError::PhaseRegression {
            generation: config.generation,
        }),
        (previous_mode, next_mode) if previous_mode == next_mode => Ok(true),
        // Observe to Enforce: compile and atomically replace only the phase
        // while preserving the generation identity.
        _ => Ok(false),
    }
}

/// Drop every flow and fragment of `nets`.
fn remove_networks(shard: &mut Shard, nets: &[NetIdx], counts: &Counts) {
    shard.retain_flows(counts, |key, _| !nets.contains(&key.net));
    shard.retain_fragments(counts, |key, _| !nets.contains(&key.net));
}

/// Carry live state into a newer generation only when the exact peer/IP
/// binding and the original initiator are still authorized by the new
/// snapshot. This prevents unrelated ACL edits from tearing down healthy
/// sessions while preserving immediate revocation for removed Grants,
/// owner changes, key rotations, listener changes, and Node withdrawal.
fn revalidate_network(
    shard: &mut Shard,
    policy: &CompiledPolicy,
    listeners: &ProviderListeners,
    counts: &Counts,
) {
    if shard.flows.keys().any(|key| key.net == policy.net) {
        shard.migrate_flows(counts, |mut key, mut state| {
            if key.net != policy.net {
                return Some((key, state));
            }
            state.service_authorization =
                authorize_existing_flow(policy, &key, state.initiator, listeners)?;
            key.generation = policy.generation;
            state.enforced = policy.mode == NodeL3Mode::Enforce;
            Some((key, state))
        });
    }
    // A later fragment does not carry the transport ports needed to prove
    // that a Service Grant remains valid. Never migrate that weaker state
    // across security content generations.
    shard.retain_fragments(counts, |key, _| key.net != policy.net);
}

fn authorize_existing_flow(
    policy: &CompiledPolicy,
    key: &FlowKey,
    initiator: PacketDirection,
    listeners: &ProviderListeners,
) -> Option<ServiceFlowAuthorization> {
    if key.local_ip != policy.local.ip {
        return None;
    }
    let remote = policy.bindings.get(&BindingKey {
        peer_key: key.remote_peer,
        ip: key.remote_ip,
    })?;
    let (source, target, destination_port) = match initiator {
        PacketDirection::Inbound => (remote, &policy.local, key.local_port),
        PacketDirection::Outbound => (&policy.local, remote, key.remote_port),
    };

    if source.owner_id == target.owner_id || policy.has_node_grant(source.idx, target.idx) {
        return Some(ServiceFlowAuthorization::NodeWide);
    }
    let service = policy.service_for(target.idx, key.protocol, destination_port)?;
    if !policy.has_service_grant(source.idx, target.idx, key.protocol, destination_port) {
        return None;
    }
    if initiator == PacketDirection::Inbound
        && !listeners.contains(
            &policy.target_machine_id,
            service,
            key.protocol,
            destination_port,
        )
    {
        return None;
    }
    Some(ServiceFlowAuthorization::Exact(Arc::clone(service)))
}

/// Networks of the policies bound to `target_machine_id`.
pub(super) fn target_networks<'a>(
    policies: impl Iterator<Item = &'a Arc<CompiledPolicy>>,
    target_machine_id: &str,
) -> HashSet<NetIdx> {
    policies
        .filter(|policy| policy.target_machine_id == target_machine_id)
        .map(|policy| policy.net)
        .collect()
}
