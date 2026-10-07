//! A writer and packet paths racing on one gate, and scenarios racing on
//! separate gates.

use std::sync::atomic::{AtomicBool, AtomicU64};
use std::thread;

use super::*;

const PEERS: u32 = 4;
const POLICY_OPS: u64 = 300;

fn peer(index: u32) -> PeerId {
    PeerId::new(20 + index)
}

fn remote(index: u32) -> Ipv4Addr {
    Ipv4Addr::new(100, 64, 1, u8::try_from(index).unwrap() + 1)
}

/// One scope binding every racing peer; with `granted` the only grants
/// admit every protocol in both directions. Odd variants also toggle a hold
/// on an unrelated address and an unbound rule, which change nothing for
/// the racing peers.
fn racing_policy(mode: GateMode, granted: bool, variant: u64) -> GatePolicy {
    let mut scope = scope("scope-1", mode, Vec::new());
    scope.bindings = (0..PEERS)
        .map(|index| binding(peer(index), remote(index), &["remote"]))
        .collect();
    if granted {
        scope.grants = vec![
            grant(
                "in",
                Direction::Inbound,
                &["remote"],
                Vec::new(),
                vec![ProtocolMatch::Any],
            ),
            grant(
                "out",
                Direction::Outbound,
                &["remote"],
                Vec::new(),
                vec![ProtocolMatch::Any],
            ),
        ];
    }
    let mut holds = GateHolds::default();
    if variant % 2 == 1 {
        scope.unbound.push(UnboundRule {
            id: "pass".into(),
            peers: vec![CARRIER],
            action: UnboundAction::Pass,
            protocols: vec![tcp_port(443)],
        });
        holds.outbound.push(HoldRule {
            remote: vec![host(Ipv4Addr::new(100, 64, 9, 9))],
            ..HoldRule::default()
        });
    }
    GatePolicy {
        scopes: vec![scope],
        holds,
    }
}

/// Policy op `k` grants for `k % 3 == 0`, revokes for 1 and turns the scope
/// off for 2.
const fn granted_after(op: u64) -> bool {
    op.is_multiple_of(3)
}

/// Whether a grant may be visible to a packet while the policy status is
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

fn policy_writer(gate: &FlowGate, status: &AtomicU64) {
    for op in 0..POLICY_OPS {
        status.store(2 * op + 1, Ordering::SeqCst);
        let policy = match op % 3 {
            0 => racing_policy(GateMode::Enforce, true, op / 3),
            1 => racing_policy(GateMode::Enforce, false, op / 3),
            _ => racing_policy(GateMode::Off, false, op / 3),
        };
        gate.replace(policy).unwrap();
        // No packet admitted under an older snapshot may leave state behind:
        // a revoked grant or an Off scope leaves no state at all.
        {
            let shards = gate.state.lock_all();
            for shard in &shards {
                for (key, flow) in &shard.flows {
                    assert!(granted_after(op), "flow {key:?} survived revocation {op}");
                    assert!(matches!(flow.rule.as_str(), "in" | "out"), "{flow:?}");
                }
                for key in shard.fragments.keys() {
                    assert!(
                        granted_after(op),
                        "fragment {key:?} survived revocation {op}"
                    );
                }
            }
        }
        status.store(2 * op + 2, Ordering::SeqCst);
        let _ = audit(gate);
        // Give the packet threads time to exercise each policy.
        thread::sleep(Duration::from_micros(300));
    }
}

fn packet_thread(gate: &FlowGate, status: &AtomicU64, done: &AtomicBool, thread: u16) {
    let mut sequence = 0_u16;
    while !done.load(Ordering::SeqCst) {
        sequence = sequence.wrapping_add(1);
        let index = u32::from(sequence) % PEERS;
        let (peer, remote_ip) = (peer(index), remote(index));
        let port = 1_000 + thread * 100 + sequence % 64;
        let before = status.load(Ordering::SeqCst);
        let decision = match sequence % 5 {
            0 => gate.evaluate_inbound(peer, &tcp(remote_ip, LOCAL, port, 22, 0x02)),
            1 => gate.evaluate_inbound(peer, &tcp(remote_ip, LOCAL, port, 22, 0x10)),
            2 => gate.evaluate_outbound(peer, &udp(LOCAL, remote_ip, port, 53)),
            3 => {
                gate.evaluate_inbound(peer, &first_fragment(udp(remote_ip, LOCAL, port, 53), port))
            }
            _ => gate.evaluate_inbound(peer, &later_fragment(remote_ip, LOCAL, 17, port - 1)),
        };
        let after = status.load(Ordering::SeqCst);
        if let GateDecision::Enforce {
            allow: true,
            reason,
            ..
        } = decision
        {
            assert!(
                matches!(reason, GateReason::Granted | GateReason::ValidState),
                "{reason:?}"
            );
            assert!(
                (before..=after).any(grant_may_be_visible),
                "admitted with no grant visible between policy status {before} and {after}"
            );
        }
        let counts = &gate.state.counts;
        assert!(counts.flows.load(Ordering::SeqCst) <= counts.global_limit);
        assert!(counts.fragments.load(Ordering::SeqCst) <= counts.fragment_limit);
    }
}

#[test]
fn writers_and_packets_never_observe_mixed_snapshot_and_state() {
    let gate = limited(48, 12, 8);
    let status = AtomicU64::new(0);
    let done = AtomicBool::new(false);
    thread::scope(|scope| {
        let packets: Vec<_> = (0..4)
            .map(|thread| {
                let (gate, status, done) = (&gate, &status, &done);
                scope.spawn(move || packet_thread(gate, status, done, thread))
            })
            .collect();
        let writer = scope.spawn(|| policy_writer(&gate, &status));
        let result = writer.join();
        done.store(true, Ordering::SeqCst);
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
fn scenarios_run_concurrently_against_separate_gates() {
    let scenarios: [fn(); 8] = [
        super::grants_flow::return_state_does_not_become_reverse_initiation,
        super::grants_flow::terminal_tcp_state_cannot_be_recycled_by_a_new_syn,
        super::grants_flow::a_final_ack_does_not_extend_a_terminal_tcp_flow,
        super::grants_flow::a_changed_scope_re_authorizes_its_flows_with_the_new_grant,
        super::packets_fragments::a_related_icmp_error_needs_the_quoted_flow,
        super::packets_fragments::later_fragments_need_an_admitted_first_fragment,
        super::grant_kinds::a_suspended_grant_denies_until_a_replace_lifts_it,
        super::holds_and_unbound::pass_dispositions_cover_later_fragments_until_the_scope_changes,
    ];
    thread::scope(|scope| {
        for _ in 0..4 {
            for scenario in scenarios {
                scope.spawn(scenario);
            }
        }
    });
}
