//! Writers and packet paths racing on one gate, and ported scenarios racing
//! on separate gates.

use std::sync::atomic::AtomicBool;
use std::thread;

use super::*;

const PEERS: u8 = 4;
const POLICY_OPS: u64 = 300;

fn peer(index: u8) -> [u8; 32] {
    [20 + index; 32]
}

fn remote(index: u8) -> Ipv4Addr {
    Ipv4Addr::new(100, 64, 1, index + 1)
}

/// Cross-owner policy: only the Node Grants (both directions, every remote
/// Node) admit traffic.
fn racing_policy(generation: u64, mode: NodeL3Mode, granted: bool) -> NodeL3Config {
    let mut policy = config(mode, false);
    policy.generation = generation;
    policy.bindings = (0..PEERS)
        .map(|index| NodeL3PeerBinding {
            peer_public_key: peer(index),
            node_id: format!("node-remote-{index}"),
            owner_id: "owner-remote".to_owned(),
            ip: remote(index),
        })
        .collect();
    if granted {
        for index in 0..PEERS {
            let node_id = format!("node-remote-{index}");
            policy.grants.push(NodeL3Grant {
                grant_id: "grant-in".to_owned(),
                source_node_id: node_id.clone(),
                resource: NodeL3Resource::Node {
                    node_id: "node-local".to_owned(),
                },
            });
            policy.grants.push(NodeL3Grant {
                grant_id: "grant-out".to_owned(),
                source_node_id: "node-local".to_owned(),
                resource: NodeL3Resource::Node { node_id },
            });
        }
    }
    policy
}

/// Unmarked transport for the racing peers, optionally with a gateway peer.
fn racing_transport(with_gateway: bool) -> NodeL3Transport {
    let mut transport = NodeL3Transport {
        local_ip: LOCAL,
        peers: (0..PEERS)
            .map(|index| NodeL3TransportPeer {
                public_key: peer(index),
                allowed_ips: vec![format!("{}/32", remote(index)).parse().unwrap()],
                gateway_id: None,
                relayed: false,
                node_l3_policy: None,
            })
            .collect(),
    };
    if with_gateway {
        transport
            .peers
            .extend(gateway_projection(Some("gateway-public")).peers);
    }
    transport
}

/// Policy op `k` grants for `k % 3 == 0`, revokes for 1 and withdraws for 2.
const fn granted_after(op: u64) -> bool {
    op.is_multiple_of(3)
}

/// Whether a Grant may be visible to a packet while the policy status is
/// `status`: `2k + 1` while op `k` runs, `2k + 2` after it, 0 before any.
const fn grant_may_be_visible(status: u64) -> bool {
    if status == 0 {
        return false;
    }
    let op = (status - 1) / 2;
    if status % 2 == 1 {
        granted_after(op) || (op > 0 && granted_after(op - 1))
    } else {
        granted_after(op)
    }
}

fn policy_writer(gate: &NodeL3Gate, status: &AtomicU64) {
    for op in 0..POLICY_OPS {
        status.store(2 * op + 1, Ordering::SeqCst);
        let generation = op + 1;
        let policy = match op % 3 {
            0 => racing_policy(generation, NodeL3Mode::Enforce, true),
            1 => racing_policy(generation, NodeL3Mode::Enforce, false),
            _ => racing_policy(generation, NodeL3Mode::Disabled, false),
        };
        gate.apply(policy).unwrap();
        // No packet admitted under an older snapshot may leave state behind:
        // every surviving flow carries the current generation, and a revoked
        // or withdrawn Grant leaves no state at all.
        {
            let shards = gate.state.lock_all();
            for shard in &shards {
                for key in shard.flows.keys() {
                    assert!(granted_after(op), "flow {key:?} survived revocation {op}");
                    assert_eq!(
                        key.generation, generation,
                        "flow {key:?} kept an old generation"
                    );
                }
                for key in shard.fragments.keys() {
                    assert!(
                        granted_after(op),
                        "fragment {key:?} survived revocation {op}"
                    );
                    assert_eq!(key.generation, generation);
                }
            }
        }
        status.store(2 * op + 2, Ordering::SeqCst);
        let _ = audit(gate);
        // Give the packet threads time to exercise each policy.
        thread::sleep(Duration::from_micros(300));
    }
}

fn transport_writer(gate: &NodeL3Gate, done: &AtomicBool) {
    let mut round = 0_u32;
    while !done.load(Ordering::SeqCst) {
        let transport = racing_transport(round.is_multiple_of(2));
        match round % 4 {
            0 => gate.replace_transport_projection(&transport).unwrap(),
            1 => gate.stage_transport_projection(&transport).unwrap(),
            2 => gate.withdraw_transport_projection(),
            _ => gate
                .replace_transport_projection_after_build(&transport, &racing_transport(false))
                .unwrap(),
        }
        let listeners: Vec<_> = (!round.is_multiple_of(3))
            .then(|| ("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443))
            .into_iter()
            .collect();
        gate.replace_provider_listeners("machine-1", listeners);
        round += 1;
        thread::yield_now();
    }
}

fn packet_thread(gate: &NodeL3Gate, status: &AtomicU64, done: &AtomicBool, thread: u8) {
    let mut sequence = 0_u16;
    while !done.load(Ordering::SeqCst) {
        sequence = sequence.wrapping_add(1);
        let index = u8::try_from(usize::from(sequence) % usize::from(PEERS)).unwrap();
        let (peer_key, remote_ip) = (peer(index), remote(index));
        let port = 1_000 + u16::from(thread) * 100 + sequence % 64;
        let before = status.load(Ordering::SeqCst);
        let decision = match sequence % 5 {
            0 => gate.evaluate_inbound(peer_key, &tcp(remote_ip, LOCAL, port, 22, 0x02)),
            1 => gate.evaluate_inbound(peer_key, &tcp(remote_ip, LOCAL, port, 22, 0x10)),
            2 => gate.evaluate_outbound(peer_key, &udp(LOCAL, remote_ip, port, 53)),
            3 => gate.evaluate_inbound(
                peer_key,
                &first_fragment(udp(remote_ip, LOCAL, port, 53), port),
            ),
            _ => gate.evaluate_inbound(peer_key, &later_fragment(remote_ip, LOCAL, port - 1)),
        };
        let after = status.load(Ordering::SeqCst);
        if let NodeL3Decision::Enforce {
            allow: true,
            reason,
        } = decision
        {
            assert!(
                matches!(reason, NodeL3Reason::NodeGrant | NodeL3Reason::ValidState),
                "{reason:?}"
            );
            assert!(
                (before..=after).any(grant_may_be_visible),
                "admitted with no Grant visible between policy status {before} and {after}"
            );
        }
        let counts = &gate.state.counts;
        assert!(counts.flows.load(Ordering::SeqCst) <= counts.global_limit);
        assert!(counts.fragments.load(Ordering::SeqCst) <= counts.fragment_limit);
    }
}

#[test]
fn writers_and_packets_never_observe_mixed_snapshot_and_state() {
    let gate = NodeL3Gate::with_limits("machine-1", 48, 12, 8);
    let status = AtomicU64::new(0);
    let done = AtomicBool::new(false);
    thread::scope(|scope| {
        let packets: Vec<_> = (0..4)
            .map(|thread| {
                let (gate, status, done) = (&gate, &status, &done);
                scope.spawn(move || packet_thread(gate, status, done, thread))
            })
            .collect();
        let transport = scope.spawn(|| transport_writer(&gate, &done));
        let policy = scope.spawn(|| policy_writer(&gate, &status));
        let result = policy.join();
        done.store(true, Ordering::SeqCst);
        transport.join().unwrap();
        for packet in packets {
            packet.join().unwrap();
        }
        result.unwrap();
    });
    let _ = audit(&gate);
    let counters = gate.counters();
    assert!(counters.enforced_allowed > 0, "{counters:?}");
    assert!(counters.enforced_denied > 0, "{counters:?}");
}

#[test]
fn ported_scenarios_run_concurrently_against_separate_gates() {
    let scenarios: [fn(); 12] = [
        grants_flow::return_state_does_not_become_reverse_initiation,
        grants_flow::terminal_tcp_state_cannot_be_recycled_by_a_new_syn,
        grants_flow::final_ack_does_not_extend_a_terminal_tcp_flow,
        grants_flow::generation_change_revokes_existing_state,
        grants_flow::partial_listener_change_revokes_only_changed_exact_flows,
        packets_fragments::related_icmp_error_requires_existing_flow_state,
        packets_fragments::fragments_require_an_authorized_first_fragment,
        packets_fragments::fragment_capacity_failure_does_not_leave_authorized_flow_state,
        subnet::subnet_transport_requires_exact_directed_grant_and_preserves_reply_state,
        subnet::subnet_return_owners_enumerate_the_return_peer_lookup,
        subnet::state_capacity_fails_closed_without_eviction,
        transport_policy::gateway_legacy_l4_fragment_delegation_is_exact_and_bounded_for_tcp_and_udp,
    ];
    thread::scope(|scope| {
        for _ in 0..4 {
            for scenario in scenarios {
                scope.spawn(scenario);
            }
        }
    });
}
