//! Transport projection staging and provider listener replacement.

use std::collections::HashSet;
use std::sync::{Arc, MutexGuard};

use super::config::{NodeL3ServiceProtocol, NodeL3Transport};
use super::policy::{ProviderListenerKey, TransportProjection, compile_transport_projection};
use super::snapshot::ProviderListeners;
use super::sources::target_networks;
use super::state::{Counts, FragmentDisposition, ServiceFlowAuthorization, Shard};
use super::{NodeL3Gate, NodeL3TransportError, PacketDirection};

impl NodeL3Gate {
    /// Activate only the peers that the replacement WireGuard device actually
    /// admitted. The desired projection is retained as authority evidence, so
    /// a marked peer skipped by device construction cannot make an ACK appear
    /// ready merely because it is absent from the installed peer table.
    pub fn replace_transport_projection_after_build(
        &self,
        desired: &NodeL3Transport,
        installed: &NodeL3Transport,
    ) -> Result<(), NodeL3TransportError> {
        let desired = compile_transport_projection(desired)?;
        let installed = compile_transport_projection(installed)?;
        if installed.local_ip != desired.local_ip {
            return Err(NodeL3TransportError::InvalidInstalledProjection(
                "local IP changed during device construction",
            ));
        }
        if !installed.bindings.is_subset(&desired.bindings) {
            return Err(NodeL3TransportError::InvalidInstalledProjection(
                "installed peer binding was absent from the desired config",
            ));
        }
        if installed
            .authoritative_bindings
            .iter()
            .any(|(binding, requirement)| {
                desired.authoritative_bindings.get(binding) != Some(requirement)
            })
        {
            return Err(NodeL3TransportError::InvalidInstalledProjection(
                "installed policy marker differed from the desired config",
            ));
        }
        if installed
            .gateway_carriers
            .iter()
            .any(|(peer_key, gateway_id)| {
                desired.gateway_carriers.get(peer_key) != Some(gateway_id)
            })
        {
            return Err(NodeL3TransportError::InvalidInstalledProjection(
                "installed gateway carrier differed from the desired config",
            ));
        }

        self.replace_transport(|_| {
            Some(TransportProjection {
                local_ip: desired.local_ip,
                authoritative_local_ips: HashSet::from([desired.local_ip]),
                bindings: installed.bindings,
                authoritative_bindings: desired.authoritative_bindings,
                gateway_carriers: installed.gateway_carriers,
                installed: true,
            })
        });
        Ok(())
    }

    /// Stage authority before a replacement WG device can receive packets.
    /// Staged bindings fail closed but are not ACK-ready until build succeeds.
    pub fn stage_transport_projection(
        &self,
        config: &NodeL3Transport,
    ) -> Result<(), NodeL3TransportError> {
        let mut staged = compile_transport_projection(config)?;
        self.replace_transport(|current| {
            // Until the old device is aborted, it may still deliver a packet
            // from a peer removed by the new config or to its old local
            // address. Retain both forms of authority during the staging
            // window; the new desired marker wins for bindings that remain.
            let mut authoritative_local_ips = HashSet::from([staged.local_ip]);
            if let Some(current) = current {
                authoritative_local_ips.extend(current.authoritative_local_ips.iter().copied());
                for (binding, requirement) in &current.authoritative_bindings {
                    staged
                        .authoritative_bindings
                        .entry(*binding)
                        .or_insert_with(|| requirement.clone());
                }
            }
            Some(TransportProjection {
                local_ip: staged.local_ip,
                authoritative_local_ips,
                bindings: staged.bindings,
                authoritative_bindings: staged.authoritative_bindings,
                gateway_carriers: staged.gateway_carriers,
                installed: false,
            })
        });
        Ok(())
    }

    /// Withdraw readiness before rebuilding or stopping the local WG device.
    /// Keep marker authority fail-closed until a later installed projection
    /// replaces it; an asynchronously aborting old device must never fall back
    /// to the legacy path merely because its manager stopped.
    pub fn withdraw_transport_projection(&self) {
        self.replace_transport(|current| {
            current.map(|current| TransportProjection {
                installed: false,
                ..current.clone()
            })
        });
    }

    /// Publish the transport `next` derives from the current one (`None`
    /// keeps no transport), drop legacy-L4 fragment authority and notify.
    fn replace_transport(
        &self,
        next: impl FnOnce(Option<&TransportProjection>) -> Option<TransportProjection>,
    ) {
        {
            let writer = self.lock_writer();
            let current = self.snapshot.load_full();
            let transport = next(current.transport.as_deref()).map(Arc::new);
            let counts = &self.state.counts;
            self.publish(
                current.policies.clone(),
                transport,
                Arc::clone(&current.listeners),
                Arc::clone(&current.tombstones),
                |shards, _| {
                    // A transport replacement starts a new carrier-authority
                    // epoch. A fragment admitted by a previously installed
                    // gateway must never revive merely because the same key
                    // is installed again within 30s.
                    for shard in shards.iter_mut() {
                        remove_legacy_l4_fragments(shard, counts);
                    }
                },
            );
            drop(writer);
        }
        self.notify_authorization_change();
    }

    /// Replace the local Provider listeners for one authenticated target.
    ///
    /// Service Grants are accepted on RX only when this independently applied
    /// listener snapshot contains the exact resource/protocol/port. This keeps
    /// a stale Node L3 Service projection from falling through to a raw Node
    /// port during configuration reordering or withdrawal.
    pub fn replace_provider_listeners(
        &self,
        target_machine_id: &str,
        listeners: impl IntoIterator<Item = (String, NodeL3ServiceProtocol, u16)>,
    ) {
        let _writer = self.lock_writer();
        let current = self.snapshot.load_full();
        let mut next = current.listeners.set.clone();
        next.retain(|listener| listener.target_machine_id != target_machine_id);
        next.extend(
            listeners
                .into_iter()
                .filter(|(service_id, _, port)| !service_id.trim().is_empty() && *port != 0)
                .map(|(service_id, protocol, port)| ProviderListenerKey {
                    target_machine_id: target_machine_id.to_owned(),
                    service_id,
                    protocol: protocol.ip_protocol(),
                    port,
                }),
        );
        if next == current.listeners.set {
            return;
        }

        // Exact Service state and fragment authority must follow listener
        // withdrawal before Provider packet ownership changes. NodeWide state
        // remains valid because same-owner/Node Grants intentionally authorize
        // the raw Node independently of any Service.
        let affected_networks = target_networks(current.policies.values(), target_machine_id);
        let counts = &self.state.counts;
        self.publish(
            current.policies.clone(),
            current.transport.clone(),
            Arc::new(ProviderListeners::new(next)),
            Arc::clone(&current.tombstones),
            |shards: &mut [MutexGuard<'_, Shard>], snapshot| {
                for shard in shards.iter_mut() {
                    shard.retain_flows(counts, |key, flow| {
                        let ServiceFlowAuthorization::Exact(service_id) =
                            &flow.service_authorization
                        else {
                            return true;
                        };
                        // A local Provider projection owns only inbound
                        // Service listeners. Exact state created by this Node
                        // initiating a remote Service is independent of local
                        // listener churn and remains valid while the policy
                        // continues to authorize that remote resource.
                        if flow.initiator == PacketDirection::Outbound {
                            return true;
                        }
                        let Some(policy) = snapshot.policies.get(&key.net) else {
                            return false;
                        };
                        if policy.target_machine_id != target_machine_id {
                            return true;
                        }
                        snapshot.listeners.contains(
                            target_machine_id,
                            service_id,
                            key.protocol,
                            key.local_port,
                        )
                    });
                    shard.retain_fragments(counts, |key, _| !affected_networks.contains(&key.net));
                }
            },
        );
    }
}

fn remove_legacy_l4_fragments(shard: &mut Shard, counts: &Counts) {
    shard.retain_fragments(counts, |_, state| {
        state.disposition != FragmentDisposition::LegacyL4
    });
}
