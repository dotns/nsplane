//! ICMP errors, fragments, malformed packets and other address families.

use super::*;

#[test]
pub(super) fn a_related_icmp_error_needs_the_quoted_flow() {
    let other = Ipv4Addr::new(100, 64, 0, 3);
    let mut scope = scope("scope-1", GateMode::Enforce, Vec::new());
    scope.bindings.push(binding(PEER, other, &["remote"]));
    scope.grants.push(grant(
        "out",
        Direction::Outbound,
        &["remote"],
        Vec::new(),
        vec![ProtocolMatch::Any],
    ));
    let gate = gate_with(policy(vec![scope]));
    let original = udp(LOCAL, REMOTE, 50_000, 53);
    assert_eq!(gate.evaluate_outbound(PEER, &original), granted("out"));
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp_error(REMOTE, LOCAL, &original)),
        valid()
    );
    assert_eq!(
        gate.evaluate_inbound(
            PEER,
            &icmp_error(REMOTE, LOCAL, &udp(LOCAL, REMOTE, 50_001, 53))
        ),
        denied(GateReason::ReverseNewFlow),
        "no flow for the quoted packet"
    );
    let to_other = udp(LOCAL, other, 50_002, 53);
    assert_eq!(gate.evaluate_outbound(PEER, &to_other), granted("out"));
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp_error(REMOTE, LOCAL, &to_other)),
        denied(GateReason::Malformed),
        "the error's source is not the quoted destination"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp_error(REMOTE, LOCAL, &[0x45, 0, 0])),
        denied(GateReason::Malformed),
        "an unreadable quote"
    );
    assert_eq!(audit(&gate), (2, 0), "errors never create state");
}

#[test]
pub(super) fn later_fragments_need_an_admitted_first_fragment() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let id = 0x1234;
    assert_eq!(
        gate.evaluate_inbound(PEER, &first_fragment(udp(REMOTE, LOCAL, 40_000, 53), id)),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &later_fragment(REMOTE, LOCAL, 17, id)),
        valid()
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &later_fragment(REMOTE, LOCAL, 17, id + 1)),
        denied(GateReason::OrphanFragment)
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &later_fragment(LOCAL, REMOTE, 17, id)),
        denied(GateReason::OrphanFragment),
        "fragment state is per direction"
    );
    // A first fragment of an existing flow remembers its fragments too.
    let reply = first_fragment(udp(LOCAL, REMOTE, 53, 40_000), 99);
    assert_eq!(gate.evaluate_outbound(PEER, &reply), valid());
    assert_eq!(
        gate.evaluate_outbound(PEER, &later_fragment(LOCAL, REMOTE, 17, 99)),
        valid()
    );
}

#[test]
fn a_fragment_capacity_failure_leaves_no_flow() {
    let gate = limited(16, 16, 0);
    gate.replace(policy(vec![open_scope(GateMode::Enforce)]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &first_fragment(udp(REMOTE, LOCAL, 40_000, 53), 1)),
        denied(GateReason::StateCapacity)
    );
    assert_eq!(audit(&gate), (0, 0));
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53)),
        granted("in"),
        "an unfragmented packet still opens the flow"
    );
}

#[test]
fn malformed_packets_are_decided_by_the_governing_scopes() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let mut truncated = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    truncated.truncate(30);
    truncated[2..4].copy_from_slice(&30_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &truncated),
        denied(GateReason::Malformed)
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 0, 22, 0x02)),
        denied(GateReason::Malformed),
        "TCP from port 0"
    );
    let mut elsewhere = truncated.clone();
    elsewhere[16..20].copy_from_slice(&[10, 0, 0, 1]);
    assert_eq!(
        gate.evaluate_inbound(PEER, &elsewhere),
        GateDecision::Pass,
        "a destination no scope governs"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &[0x45, 0, 0]),
        GateDecision::Pass
    );

    // Outbound, the scopes holding the remote address as a binding address.
    let mut outbound = tcp(LOCAL, REMOTE, 22, 40_000, 0x12);
    outbound.truncate(30);
    outbound[2..4].copy_from_slice(&30_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_outbound(PEER, &outbound),
        denied(GateReason::Malformed)
    );
    outbound[16..20].copy_from_slice(&[10, 0, 0, 1]);
    assert_eq!(gate.evaluate_outbound(PEER, &outbound), GateDecision::Pass);

    gate.replace(policy(vec![open_scope(GateMode::Observe)]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &truncated),
        observe(false, GateReason::Malformed, None)
    );
}

#[test]
fn non_ipv4_packets_pass() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let mut ipv6 = vec![0_u8; 48];
    ipv6[0] = 0x60;
    assert_eq!(gate.evaluate_inbound(PEER, &ipv6), GateDecision::Pass);
    assert_eq!(gate.evaluate_outbound(PEER, &ipv6), GateDecision::Pass);
    assert_eq!(gate.evaluate_inbound(PEER, &[]), GateDecision::Pass);
    assert_eq!(gate.counters(), GateCounters::default());
}

#[test]
fn an_inert_gate_passes_without_parsing() {
    let gate = FlowGate::with_clock(GateConfig::default(), || {
        panic!("an inert gate never reads the clock")
    });
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        GateDecision::Pass
    );
    assert_eq!(gate.evaluate_outbound(PEER, &[0xff]), GateDecision::Pass);
    gate.replace(policy(vec![open_scope(GateMode::Off)]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        GateDecision::Pass,
        "an Off scope is the same as none"
    );
}
