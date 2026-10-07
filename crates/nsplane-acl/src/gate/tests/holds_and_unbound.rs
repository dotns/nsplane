//! Holds, unbound rules (pass and divert) and divert generations.

use super::*;

const UNBOUND_SOURCE: Ipv4Addr = Ipv4Addr::new(100, 127, 0, 1);

fn holds_policy(holds: GateHolds) -> GatePolicy {
    GatePolicy {
        scopes: vec![open_scope(GateMode::Enforce)],
        holds,
    }
}

fn remote_hold() -> HoldRule {
    HoldRule {
        peers: None,
        local: vec![host(LOCAL)],
        remote: vec![host(REMOTE)],
    }
}

#[test]
fn an_inbound_hold_denies_in_every_mode_before_the_scopes() {
    let holds = GateHolds {
        inbound: vec![remote_hold()],
        ..GateHolds::default()
    };
    let gate = gate_with(holds_policy(holds.clone()));
    let syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(gate.evaluate_inbound(PEER, &syn), denied(GateReason::Held));
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 50_000, 22, 0x02)),
        granted("out"),
        "the inbound holds do not apply outbound"
    );
    gate.replace(GatePolicy {
        scopes: vec![open_scope(GateMode::Observe)],
        holds,
    })
    .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &syn),
        denied(GateReason::Held),
        "held is always enforced"
    );
}

#[test]
fn release_exempts_an_exact_pair_from_the_inbound_holds() {
    let peer_hold = HoldRule {
        peers: Some(vec![PEER]),
        local: vec![host(LOCAL)],
        remote: Vec::new(),
    };
    let mut holds = GateHolds {
        inbound: vec![peer_hold],
        ..GateHolds::default()
    };
    let gate = gate_with(holds_policy(holds.clone()));
    let syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(gate.evaluate_inbound(PEER, &syn), denied(GateReason::Held));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(UNBOUND_SOURCE, LOCAL, 1, 22, 0x02)),
        denied(GateReason::Held),
        "the peer hold covers every source of the peer"
    );
    holds.release.push((PEER, IpAddr::V4(REMOTE)));
    gate.replace(holds_policy(holds)).unwrap();
    assert_eq!(gate.evaluate_inbound(PEER, &syn), granted("in"));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(UNBOUND_SOURCE, LOCAL, 1, 22, 0x02)),
        denied(GateReason::Held),
        "only the released pair"
    );
}

#[test]
fn an_outbound_hold_denies_every_peer_routed_to_the_address() {
    let holds = GateHolds {
        outbound: vec![HoldRule {
            remote: vec![host(REMOTE)],
            ..HoldRule::default()
        }],
        release: vec![(PEER, IpAddr::V4(REMOTE))],
        ..GateHolds::default()
    };
    let gate = gate_with(holds_policy(holds));
    for peer in [PEER, OTHER_PEER] {
        assert_eq!(
            gate.evaluate_outbound(peer, &tcp(LOCAL, REMOTE, 50_000, 22, 0x02)),
            denied(GateReason::Held),
            "release does not apply outbound"
        );
    }
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, Ipv4Addr::new(100, 96, 0, 1), 1, 2, 0x02)),
        GateDecision::Pass
    );
}

#[test]
fn holds_alone_make_the_gate_active() {
    let gate = gate_with(GatePolicy {
        scopes: Vec::new(),
        holds: GateHolds {
            inbound: vec![remote_hold()],
            ..GateHolds::default()
        },
    });
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        denied(GateReason::Held)
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(UNBOUND_SOURCE, LOCAL, 40_000, 22, 0x02)),
        GateDecision::Pass
    );
    let mut malformed = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    malformed.truncate(24);
    malformed[2..4].copy_from_slice(&24_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &malformed),
        denied(GateReason::Held),
        "a malformed packet with readable addresses"
    );
}

#[test]
fn a_holds_only_change_keeps_every_flow() {
    let gate = gate_with(holds_policy(GateHolds::default()));
    let _ = gate.evaluate_inbound(PEER, &first_fragment(udp(REMOTE, LOCAL, 40_000, 53), 3));
    gate.replace(holds_policy(GateHolds {
        outbound: vec![HoldRule {
            remote: vec![host(Ipv4Addr::new(100, 64, 0, 50))],
            ..HoldRule::default()
        }],
        ..GateHolds::default()
    }))
    .unwrap();
    assert_eq!(audit(&gate), (1, 1));
}

/// An enforcing scope with a pass rule for [`CARRIER`] to TCP 443 and a
/// divert rule for TCP and UDP.
fn unbound_scope(mode: GateMode) -> GateScope {
    let mut scope = open_scope(mode);
    scope.unbound = vec![
        UnboundRule {
            id: "pass".into(),
            peers: vec![CARRIER],
            action: UnboundAction::Pass,
            protocols: vec![tcp_port(443)],
        },
        UnboundRule {
            id: "divert".into(),
            peers: vec![CARRIER],
            action: UnboundAction::Divert,
            protocols: vec![
                ProtocolMatch::Tcp(PortSet::Any),
                ProtocolMatch::Udp(PortSet::Any),
            ],
        },
    ];
    scope
}

#[test]
fn a_pass_rule_hands_on_only_its_peers_and_ports() {
    let gate = gate_with(policy(vec![unbound_scope(GateMode::Enforce)]));
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &tcp(UNBOUND_SOURCE, LOCAL, 40_000, 443, 0x02)),
        GateDecision::Pass
    );
    for (name, peer, packet) in [
        (
            "another port",
            CARRIER,
            tcp(UNBOUND_SOURCE, LOCAL, 40_000, 22, 0x02),
        ),
        ("UDP", CARRIER, udp(UNBOUND_SOURCE, LOCAL, 40_000, 443)),
        (
            "another peer",
            OTHER_PEER,
            tcp(UNBOUND_SOURCE, LOCAL, 40_000, 443, 0x02),
        ),
    ] {
        assert_eq!(
            gate.evaluate_inbound(peer, &packet),
            denied(GateReason::Unbound),
            "{name}"
        );
    }
    assert_eq!(
        gate.evaluate_outbound(CARRIER, &tcp(LOCAL, UNBOUND_SOURCE, 443, 40_000, 0x12)),
        GateDecision::Pass,
        "outbound to an address no scope binds"
    );
}

#[test]
fn unbound_rules_apply_only_under_one_enforcing_scope() {
    let gate = gate_with(policy(vec![unbound_scope(GateMode::Observe)]));
    let packet = tcp(UNBOUND_SOURCE, LOCAL, 40_000, 443, 0x02);
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &packet),
        observe(false, GateReason::Unbound, None)
    );
    let mut second = unbound_scope(GateMode::Enforce);
    second.id = "scope-2".into();
    gate.replace(policy(vec![unbound_scope(GateMode::Enforce), second]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &packet),
        denied(GateReason::Unbound),
        "two scopes govern the address"
    );
}

#[test]
pub(super) fn pass_dispositions_cover_later_fragments_until_the_scope_changes() {
    for protocol in [6, 17] {
        let mut scope = unbound_scope(GateMode::Enforce);
        scope.unbound[0].protocols = vec![tcp_port(443), ProtocolMatch::Udp(PortSet::single(443))];
        let gate = gate_with(policy(vec![scope.clone()]));
        let first = match protocol {
            6 => tcp(UNBOUND_SOURCE, LOCAL, 40_000, 443, 0x02),
            _ => udp(UNBOUND_SOURCE, LOCAL, 40_000, 443),
        };
        assert_eq!(
            gate.evaluate_inbound(CARRIER, &first_fragment(first, 5)),
            GateDecision::Pass
        );
        let later = later_fragment(UNBOUND_SOURCE, LOCAL, protocol, 5);
        assert_eq!(gate.evaluate_inbound(CARRIER, &later), GateDecision::Pass);
        assert_eq!(
            gate.evaluate_inbound(CARRIER, &later_fragment(UNBOUND_SOURCE, LOCAL, protocol, 6)),
            denied(GateReason::OrphanFragment)
        );
        assert_eq!(
            gate.evaluate_inbound(OTHER_PEER, &later),
            denied(GateReason::Unbound),
            "a peer no unbound rule names"
        );
        assert_eq!(audit(&gate), (0, 1));
        gate.replace(policy(vec![scope.clone()])).unwrap();
        assert_eq!(audit(&gate), (0, 1), "an unchanged scope keeps them");
        scope.unbound.reverse();
        gate.replace(policy(vec![scope])).unwrap();
        assert_eq!(audit(&gate), (0, 0), "a changed scope drops them");
        assert_eq!(
            gate.evaluate_inbound(CARRIER, &later),
            denied(GateReason::OrphanFragment)
        );
    }
}

#[test]
fn a_full_fragment_table_fails_a_passed_first_fragment_closed() {
    let gate = limited(16, 16, 0);
    gate.replace(policy(vec![unbound_scope(GateMode::Enforce)]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(
            CARRIER,
            &first_fragment(tcp(UNBOUND_SOURCE, LOCAL, 40_000, 443, 0x02), 5),
        ),
        denied(GateReason::StateCapacity)
    );
}

#[test]
fn a_divert_candidate_is_offered_only_for_its_rule() {
    let gate = gate_with(policy(vec![unbound_scope(GateMode::Enforce)]));
    let reply = udp(UNBOUND_SOURCE, LOCAL, 19_999, 49_152);
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &reply),
        denied(GateReason::Unbound),
        "a candidate is never an allow"
    );
    let candidate = gate.divert_candidate(CARRIER, &reply).expect("a candidate");
    assert_eq!(candidate.generation(), gate.generation());
    assert_eq!(candidate.peer(), CARRIER);
    assert_eq!(candidate.scope(), &ScopeId::from("scope-1"));
    assert_eq!(candidate.rule(), &RuleId::from("divert"));
    assert_eq!(candidate.packet(), reply.as_slice());
    assert_eq!(&*candidate.into_packet(), reply.as_slice());

    let later = later_fragment(UNBOUND_SOURCE, LOCAL, 17, 9);
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &later),
        denied(GateReason::OrphanFragment)
    );
    assert!(
        gate.divert_candidate(CARRIER, &later).is_some(),
        "TCP/UDP any port covers it"
    );

    for (name, peer, packet) in [
        ("another peer", OTHER_PEER, reply.clone()),
        ("from a binding address", CARRIER, udp(REMOTE, LOCAL, 1, 2)),
        ("from a local address", CARRIER, udp(LOCAL, LOCAL, 1, 2)),
        (
            "to another address",
            CARRIER,
            udp(UNBOUND_SOURCE, REMOTE, 1, 2),
        ),
        ("ICMP", CARRIER, icmp(UNBOUND_SOURCE, LOCAL, 0, 1)),
        ("malformed", CARRIER, reply[..24].to_vec()),
    ] {
        assert!(gate.divert_candidate(peer, &packet).is_none(), "{name}");
    }

    gate.replace(GatePolicy {
        scopes: vec![unbound_scope(GateMode::Enforce)],
        holds: GateHolds {
            inbound: vec![HoldRule {
                peers: Some(vec![CARRIER]),
                ..HoldRule::default()
            }],
            ..GateHolds::default()
        },
    })
    .unwrap();
    assert!(gate.divert_candidate(CARRIER, &reply).is_none(), "held");
    gate.replace(policy(vec![unbound_scope(GateMode::Observe)]))
        .unwrap();
    assert!(gate.divert_candidate(CARRIER, &reply).is_none(), "observed");
}

#[test]
fn a_divert_candidate_is_current_for_one_generation() {
    let gate = gate_with(policy(vec![unbound_scope(GateMode::Enforce)]));
    let reply = udp(UNBOUND_SOURCE, LOCAL, 19_999, 49_152);
    let first = gate.divert_candidate(CARRIER, &reply).unwrap();
    let second = gate.divert_candidate(CARRIER, &reply).unwrap();
    assert_eq!(
        (first.generation(), first.peer(), first.rule()),
        (second.generation(), second.peer(), second.rule()),
        "same authority"
    );
    let generation = gate
        .replace(policy(vec![unbound_scope(GateMode::Enforce)]))
        .unwrap();
    assert_ne!(
        first.generation(),
        gate.generation(),
        "stale after any replace"
    );
    assert_eq!(
        gate.divert_candidate(CARRIER, &reply).unwrap().generation(),
        generation
    );
}
