//! Bindings, grants, flow state and its migration across `replace`.

use std::time::Instant;

use super::*;

#[test]
fn a_label_grant_opens_new_flows_and_reports_its_id() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![inbound_any("in", "remote")],
    )]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x10)),
        valid()
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 22, 40_000, 0x12)),
        valid(),
        "the reply of an admitted flow"
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 50_000, 22, 0x02)),
        denied(GateReason::NoGrant),
        "no outbound grant"
    );
}

#[test]
fn a_grant_needs_one_of_its_labels() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![inbound_any("in", "someone-else")],
    )]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        denied(GateReason::NoGrant)
    );
    let any_binding = grant(
        "any",
        Direction::Inbound,
        &[],
        Vec::new(),
        vec![ProtocolMatch::Any],
    );
    gate.replace(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![any_binding],
    )]))
    .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        granted("any"),
        "a grant without labels admits any binding of the scope"
    );
}

#[test]
fn the_first_matching_grant_is_reported() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![
            grant(
                "port",
                Direction::Inbound,
                &["remote"],
                vec![host(LOCAL)],
                vec![tcp_port(443)],
            ),
            inbound_any("any", "remote"),
        ],
    )]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02)),
        granted("port")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_001, 22, 0x02)),
        granted("any")
    );
}

#[test]
fn the_peer_is_bound_to_its_remote_address() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let spoofed = tcp(Ipv4Addr::new(100, 64, 0, 99), LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        gate.evaluate_inbound(PEER, &spoofed),
        denied(GateReason::Unbound)
    );
    assert_eq!(
        gate.evaluate_inbound(OTHER_PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        denied(GateReason::Unbound),
        "another peer with the bound address"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, Ipv4Addr::new(10, 0, 0, 1), 1, 2, 0x02)),
        GateDecision::Pass,
        "an address no scope governs"
    );
    assert_eq!(gate.counters().unbound_denied, 2);
}

#[test]
fn outbound_to_a_bound_address_is_governed_whatever_the_peer_or_source() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    assert_eq!(
        gate.evaluate_outbound(OTHER_PEER, &tcp(LOCAL, REMOTE, 40_000, 22, 0x02)),
        denied(GateReason::Unbound),
        "another peer selected for the bound address"
    );
    assert_eq!(
        gate.evaluate_outbound(
            PEER,
            &tcp(Ipv4Addr::new(192, 0, 2, 99), REMOTE, 1, 22, 0x02)
        ),
        denied(GateReason::Unbound),
        "a local source the scope does not govern"
    );
    assert_eq!(
        gate.evaluate_outbound(
            PEER,
            &tcp(LOCAL, Ipv4Addr::new(100, 96, 0, 10), 1, 443, 0x02)
        ),
        GateDecision::Pass,
        "another address of the same peer"
    );
}

#[test]
fn two_scopes_binding_one_packet_are_ambiguous() {
    let mut second = open_scope(GateMode::Observe);
    second.id = "scope-2".into();
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce), second.clone()]));
    let packet = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        gate.evaluate_inbound(PEER, &packet),
        denied(GateReason::Ambiguous)
    );
    let mut first = open_scope(GateMode::Observe);
    first.id = "scope-1".into();
    gate.replace(policy(vec![first, second])).unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &packet),
        observe(false, GateReason::Ambiguous, None)
    );
}

#[test]
fn a_scope_governs_every_local_address() {
    let second_local = Ipv4Addr::new(100, 64, 0, 10);
    let mut scope = open_scope(GateMode::Enforce);
    scope.local.push(IpAddr::V4(second_local));
    scope.grants.push(grant(
        "in-2",
        Direction::Inbound,
        &["remote"],
        vec![host(second_local)],
        vec![ProtocolMatch::Any],
    ));
    let gate = gate_with(policy(vec![scope]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, second_local, 40_000, 22, 0x02)),
        granted("in-2")
    );
}

#[test]
pub(super) fn return_state_does_not_become_reverse_initiation() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![outbound_any("out", "remote")],
    )]));
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 50_000, 8080, 0x02)),
        granted("out")
    );
    let syn_ack = tcp(REMOTE, LOCAL, 8080, 50_000, 0x12);
    assert_eq!(gate.evaluate_inbound(PEER, &syn_ack), valid());
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 8080, 50_000, 0x02)),
        denied(GateReason::ReverseNewFlow),
        "a reverse bare SYN on the same five-tuple"
    );
    assert_eq!(gate.evaluate_inbound(PEER, &syn_ack), valid());
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 8081, 50_001, 0x02)),
        denied(GateReason::NoGrant)
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 8081, 50_001, 0x10)),
        denied(GateReason::ReverseNewFlow),
        "an ACK without state"
    );
}

#[test]
pub(super) fn terminal_tcp_state_cannot_be_recycled_by_a_new_syn() {
    for terminal_flags in [0x11, 0x04] {
        let gate = gate_with(policy(vec![scope(
            "scope-1",
            GateMode::Enforce,
            vec![outbound_any("out", "remote")],
        )]));
        let _ = gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 50_000, 8080, 0x02));
        let _ = gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 8080, 50_000, 0x12));
        assert_eq!(
            gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 50_000, 8080, terminal_flags)),
            valid()
        );
        assert_eq!(
            gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 8080, 50_000, 0x02)),
            denied(GateReason::ReverseNewFlow)
        );
    }
}

#[test]
pub(super) fn a_final_ack_does_not_extend_a_terminal_tcp_flow() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![outbound_any("out", "remote")],
    )]));
    let start = Instant::now();
    let at = |seconds| start + Duration::from_secs(seconds);
    let out = |flags, seconds| {
        gate.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &tcp(LOCAL, REMOTE, 50_000, 8080, flags),
            at(seconds),
        )
    };
    let back = |flags, seconds| {
        gate.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &tcp(REMOTE, LOCAL, 8080, 50_000, flags),
            at(seconds),
        )
    };
    assert_eq!(out(0x02, 0), granted("out"));
    assert_eq!(back(0x12, 1), valid());
    assert_eq!(out(0x11, 2), valid());
    assert_eq!(back(0x10, 3), valid(), "data during the half-close");
    assert_eq!(back(0x11, 4), valid());
    assert_eq!(out(0x10, 5), valid());
    assert_eq!(
        out(0x02, 35),
        granted("out"),
        "after the closed tail the same tuple is a new flow"
    );
}

#[test]
fn a_flow_expires_after_its_idle_timeout() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let start = Instant::now();
    let request = udp(REMOTE, LOCAL, 40_000, 53);
    let reply = udp(LOCAL, REMOTE, 53, 40_000);
    let _ = gate.evaluate_at(PacketDirection::Inbound, PEER, &request, start);
    let later = start + timeouts().udp.saturating_sub(Duration::from_secs(1));
    assert_eq!(
        gate.evaluate_at(PacketDirection::Outbound, PEER, &reply, later),
        valid()
    );
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &reply,
            later + timeouts().udp + Duration::from_secs(1),
        ),
        granted("out"),
        "the expired flow is gone; the outbound grant opens a new one"
    );
}

#[test]
fn removing_a_grant_revokes_the_flows_it_admitted() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![inbound_any("in", "remote")],
    )]));
    let _ = gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53));
    assert_eq!(audit(&gate), (1, 0));
    gate.replace(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        Vec::new(),
    )]))
    .unwrap();
    assert_eq!(audit(&gate), (0, 0));
    assert_eq!(
        gate.evaluate_outbound(PEER, &udp(LOCAL, REMOTE, 53, 40_000)),
        denied(GateReason::NoGrant)
    );
}

#[test]
pub(super) fn a_changed_scope_re_authorizes_its_flows_with_the_new_grant() {
    let gate = gate_with(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![inbound_any("in", "remote")],
    )]));
    let start = Instant::now();
    let request = udp(REMOTE, LOCAL, 40_000, 53);
    let _ = gate.evaluate_at(PacketDirection::Inbound, PEER, &request, start);
    gate.replace(policy(vec![scope(
        "scope-1",
        GateMode::Enforce,
        vec![
            grant(
                "dns",
                Direction::Inbound,
                &["remote"],
                Vec::new(),
                vec![ProtocolMatch::Udp(PortSet::single(53))],
            ),
            outbound_any("out", "remote"),
        ],
    )]))
    .unwrap();
    let flow = gate
        .find_flow(
            SocketAddrV4::new(REMOTE, 40_000).into(),
            SocketAddrV4::new(LOCAL, 53).into(),
            Protocol::Udp,
        )
        .expect("the flow survives under the new grant");
    assert_eq!(
        flow,
        LiveFlow {
            scope: "scope-1".into(),
            rule: "dns".into(),
            enforced: true,
        }
    );
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &udp(LOCAL, REMOTE, 53, 40_000),
            start + timeouts().udp.saturating_sub(Duration::from_secs(1)),
        ),
        valid(),
        "the flow keeps its idle deadline"
    );
}

#[test]
fn a_re_bound_or_relabelled_source_loses_its_flows() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let _ = gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53));
    let mut moved = open_scope(GateMode::Enforce);
    moved.bindings = vec![binding(OTHER_PEER, REMOTE, &["remote"])];
    gate.replace(policy(vec![moved])).unwrap();
    assert_eq!(audit(&gate), (0, 0), "the binding moved to another peer");

    gate.replace(policy(vec![open_scope(GateMode::Enforce)]))
        .unwrap();
    let _ = gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53));
    let mut relabelled = open_scope(GateMode::Enforce);
    relabelled.bindings = vec![binding(PEER, REMOTE, &["stranger"])];
    gate.replace(policy(vec![relabelled])).unwrap();
    assert_eq!(audit(&gate), (0, 0), "no grant matches the new labels");
}

#[test]
fn an_unchanged_scope_keeps_its_state_untouched() {
    let mut other = open_scope(GateMode::Enforce);
    other.id = "scope-2".into();
    other.local = vec![IpAddr::V4(Ipv4Addr::new(100, 65, 0, 1))];
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce), other.clone()]));
    let first = first_fragment(udp(REMOTE, LOCAL, 40_000, 53), 7);
    assert_eq!(gate.evaluate_inbound(PEER, &first), granted("in"));
    assert_eq!(audit(&gate), (1, 1));
    other.grants.clear();
    let generation = gate
        .replace(policy(vec![open_scope(GateMode::Enforce), other]))
        .unwrap();
    assert_eq!(generation, 2);
    assert_eq!(audit(&gate), (1, 1), "flow and fragment kept");
    assert_eq!(
        gate.evaluate_inbound(PEER, &later_fragment(REMOTE, LOCAL, 17, 7)),
        valid()
    );
}

#[test]
fn a_changed_scope_drops_its_fragments() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let _ = gate.evaluate_inbound(PEER, &first_fragment(udp(REMOTE, LOCAL, 40_000, 53), 7));
    let mut changed = open_scope(GateMode::Enforce);
    changed.grants.reverse();
    gate.replace(policy(vec![changed])).unwrap();
    assert_eq!(audit(&gate), (1, 0));
    assert_eq!(
        gate.evaluate_inbound(PEER, &later_fragment(REMOTE, LOCAL, 17, 7)),
        denied(GateReason::OrphanFragment)
    );
}

#[test]
fn observe_to_enforce_revalidates_and_enforces_the_flows() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Observe)]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53)),
        observe(true, GateReason::Granted, Some("in"))
    );
    let remote = SocketAddrV4::new(REMOTE, 40_000).into();
    let local = SocketAddrV4::new(LOCAL, 53).into();
    assert!(
        !gate
            .find_flow(remote, local, Protocol::Udp)
            .unwrap()
            .enforced
    );
    gate.replace(policy(vec![open_scope(GateMode::Enforce)]))
        .unwrap();
    assert!(
        gate.find_flow(remote, local, Protocol::Udp)
            .unwrap()
            .enforced
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &udp(LOCAL, REMOTE, 53, 40_000)),
        valid()
    );
}

#[test]
fn off_or_removed_scopes_drop_their_state_and_pass() {
    for removed in [
        policy(vec![open_scope(GateMode::Off)]),
        GatePolicy::default(),
    ] {
        let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
        let _ = gate.evaluate_inbound(PEER, &first_fragment(udp(REMOTE, LOCAL, 40_000, 53), 7));
        gate.replace(removed).unwrap();
        assert_eq!(audit(&gate), (0, 0));
        assert_eq!(
            gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
            GateDecision::Pass
        );
        assert!(gate.inert.load(Ordering::SeqCst));
    }
}

#[test]
fn a_re_added_scope_starts_without_state() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let _ = gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53));
    gate.replace(GatePolicy::default()).unwrap();
    gate.replace(policy(vec![open_scope(GateMode::Enforce)]))
        .unwrap();
    assert_eq!(
        gate.evaluate_outbound(PEER, &udp(LOCAL, REMOTE, 53, 40_000)),
        granted("out"),
        "a new flow, not the old state"
    );
}

#[test]
fn find_flow_reports_the_live_flow_and_refreshes_it() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let remote = SocketAddrV4::new(REMOTE, 40_000).into();
    let local = SocketAddrV4::new(LOCAL, 443).into();
    assert_eq!(gate.find_flow(remote, local, Protocol::Tcp), None);
    let _ = gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02));
    assert_eq!(
        gate.find_flow(remote, local, Protocol::Tcp),
        Some(LiveFlow {
            scope: "scope-1".into(),
            rule: "in".into(),
            enforced: true,
        })
    );
    assert_eq!(gate.find_flow(remote, local, Protocol::Udp), None);
    assert_eq!(
        gate.find_flow(
            "[fd00::1]:40000".parse().unwrap(),
            "[fd00::2]:443".parse().unwrap(),
            Protocol::Tcp,
        ),
        None
    );
}
