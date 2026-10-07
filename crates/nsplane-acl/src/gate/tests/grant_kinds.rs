//! Suspended, port, ICMP and outbound grants, observe mode and the state
//! limit of a new flow.

use std::time::Instant;

use super::*;

fn port_grant(suspended: bool) -> GateGrant {
    GateGrant {
        suspended,
        ..grant(
            "web",
            Direction::Inbound,
            &["remote"],
            vec![host(LOCAL)],
            vec![tcp_port(443)],
        )
    }
}

#[test]
fn a_port_grant_opens_only_its_port() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![port_grant(false)],
    )]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02)),
        granted("web")
    );
    for (name, packet) in [
        ("another port", tcp(REMOTE, LOCAL, 40_001, 22, 0x02)),
        ("UDP to the port", udp(REMOTE, LOCAL, 40_002, 443)),
        ("ICMP echo", icmp(REMOTE, LOCAL, 8, 1)),
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &packet),
            denied(GateReason::NoGrant),
            "{name}"
        );
    }
}

#[test]
pub(super) fn a_suspended_grant_denies_until_a_replace_lifts_it() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![port_grant(true)],
    )]));
    let syn = tcp(REMOTE, LOCAL, 40_000, 443, 0x02);
    assert_eq!(
        gate.evaluate_inbound(PEER, &syn),
        enforce(false, GateReason::Suspended, Some("web"))
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        denied(GateReason::NoGrant)
    );
    gate.replace(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![port_grant(false)],
    )]))
    .unwrap();
    assert_eq!(gate.evaluate_inbound(PEER, &syn), granted("web"));

    gate.replace(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![port_grant(true)],
    )]))
    .unwrap();
    assert_eq!(
        audit(&gate),
        (0, 0),
        "suspending drops the flows it alone admitted"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x10)),
        denied(GateReason::ReverseNewFlow)
    );
}

#[test]
fn another_grant_admits_what_a_suspended_one_would() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![port_grant(true), inbound_any("any", "remote")],
    )]));
    let _ = gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02));
    assert_eq!(
        gate.find_flow(
            SocketAddrV4::new(REMOTE, 40_000).into(),
            SocketAddrV4::new(LOCAL, 443).into(),
            Protocol::Tcp,
        )
        .map(|flow| flow.rule),
        Some("any".into())
    );
}

#[test]
fn icmp_grants_match_by_type_and_echo_flows_use_the_identifier() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![grant(
            "ping",
            Direction::Inbound,
            &["remote"],
            Vec::new(),
            vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![8]))],
        )],
    )]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp(REMOTE, LOCAL, 8, 77)),
        granted("ping")
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &icmp(LOCAL, REMOTE, 0, 77)),
        valid(),
        "the echo reply of the flow"
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &icmp(LOCAL, REMOTE, 0, 78)),
        denied(GateReason::ReverseNewFlow),
        "an echo reply without state"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp(REMOTE, LOCAL, 0, 79)),
        denied(GateReason::ReverseNewFlow),
        "an echo reply never opens a flow"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp(REMOTE, LOCAL, 13, 80)),
        denied(GateReason::NoGrant),
        "another type"
    );
}

#[test]
fn other_ip_protocols_follow_ip_grants() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![grant(
            "gre",
            Direction::Inbound,
            &["remote"],
            Vec::new(),
            vec![ProtocolMatch::Ip(47)],
        )],
    )]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &ipv4(REMOTE, LOCAL, 47, &[0; 4])),
        granted("gre")
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &ipv4(LOCAL, REMOTE, 47, &[0; 4])),
        valid()
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &ipv4(REMOTE, LOCAL, 50, &[0; 4])),
        denied(GateReason::NoGrant)
    );
}

#[test]
fn outbound_grants_check_the_remote_destination() {
    let second = Ipv4Addr::new(100, 64, 0, 3);
    let mut scope = scope(
        "scope-1",
        GateMode::Enforce,
        vec![outbound_any("out", "remote")],
    );
    scope.bindings.push(binding(PEER, second, &["remote"]));
    let gate = gate_with(policy(vec![scope]));
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 50_000, 22, 0x02)),
        granted("out")
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, second, 50_000, 22, 0x02)),
        denied(GateReason::NoGrant),
        "the grant's destinations name only the first address"
    );
}

#[test]
fn observe_mode_reports_and_records_state() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Observe,
        vec![inbound_any("in", "remote")],
    )]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        observe(true, GateReason::Granted, Some("in"))
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 22, 40_000, 0x12)),
        observe(true, GateReason::ValidState, None)
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 50_000, 22, 0x02)),
        observe(false, GateReason::NoGrant, None)
    );
    assert_eq!(
        gate.evaluate_inbound(
            PEER,
            &tcp(Ipv4Addr::new(100, 64, 0, 99), LOCAL, 1, 22, 0x02)
        ),
        observe(false, GateReason::Unbound, None)
    );
    assert_eq!(audit(&gate), (1, 0));
    let counters = gate.counters();
    assert_eq!(counters.observed_denied, 2);
    assert_eq!(
        (
            counters.enforced_allowed,
            counters.enforced_denied,
            counters.unbound_denied
        ),
        (0, 0, 0)
    );
}

#[test]
fn state_capacity_fails_closed_without_eviction() {
    let gate = limited(1, 1, 1);
    gate.replace(policy(vec![open_scope(GateMode::Enforce)]))
        .unwrap();
    let start = Instant::now();
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &udp(REMOTE, LOCAL, 40_000, 53),
            start,
        ),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_001, 53)),
        denied(GateReason::StateCapacity)
    );
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &udp(LOCAL, REMOTE, 53, 40_000),
            start + Duration::from_secs(1),
        ),
        valid(),
        "the live flow is never evicted"
    );
    assert_eq!(gate.counters().state_capacity_denied, 1);
    assert_eq!(audit(&gate), (1, 0));
}
