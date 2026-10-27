//! Scoped decisions: the selection, the decision table, and that a scoped
//! call reads and writes no state of a scope outside its selection.

use std::time::Instant;

use super::*;

const OTHER_REMOTE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);
const UNBOUND_SOURCE: Ipv4Addr = Ipv4Addr::new(100, 127, 0, 1);

fn select(id: &str) -> ScopeSelection {
    ScopeSelection::one(id.into())
}

fn any_of(ids: &[&str]) -> ScopeSelection {
    ScopeSelection::any_of(ids.iter().map(|id| ScopeId::from(*id))).unwrap()
}

/// Scope `id` in `mode` governing [`LOCAL`] and binding `peer` at
/// [`REMOTE`], whose grants `in-<id>` and `out-<id>` open every protocol.
fn peer_scope(id: &str, mode: GateMode, peer: PeerId) -> GateScope {
    GateScope {
        bindings: vec![binding(peer, REMOTE, &["remote"])],
        ..scope(
            id,
            mode,
            vec![
                inbound_any(&format!("in-{id}"), "remote"),
                outbound_any(&format!("out-{id}"), "remote"),
            ],
        )
    }
}

/// Scope `a` binding [`PEER`] and scope `b` binding [`OTHER_PEER`], both at
/// [`REMOTE`] and governing [`LOCAL`]: the same five-tuple may have a flow
/// in each.
fn two_scopes() -> GatePolicy {
    policy(vec![
        peer_scope("a", GateMode::Enforce, PEER),
        peer_scope("b", GateMode::Enforce, OTHER_PEER),
    ])
}

/// A gate with `policy` whose clock is the returned manual time.
fn manual_gate(policy: GatePolicy) -> (Arc<FlowGate>, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let read = Arc::clone(&clock);
    let gate = FlowGate::with_clock(GateConfig::default(), move || *read.lock().unwrap());
    gate.replace(policy).expect("the policy is valid");
    (gate, clock)
}

fn advance(clock: &Mutex<Instant>, seconds: u64) {
    *clock.lock().unwrap() += Duration::from_secs(seconds);
}

fn scoped(
    decision: GateDecision,
    scope: Option<&str>,
    rule: Option<&str>,
    generation: u64,
) -> ScopedDecision {
    ScopedDecision {
        decision,
        scope: scope.map(ScopeId::from),
        rule: rule.map(RuleId::from),
        generation,
    }
}

fn out_of_scope(generation: u64) -> ScopedDecision {
    scoped(denied(GateReason::OutOfScope), None, None, generation)
}

/// The deadlines of `peer`'s IPv4 flows and fragments in scope `id`.
fn state_of(gate: &FlowGate, id: &str, peer: PeerId) -> (Vec<Instant>, Vec<Instant>) {
    let slot = gate.snapshot.load().slots[&ScopeId::from(id)];
    let shards = gate.state.lock_all();
    let flows = shards
        .iter()
        .flat_map(|shard| shard.flows.iter())
        .filter(|(key, _)| key.slot == slot && key.peer == peer)
        .map(|(_, flow)| flow.expires_at)
        .collect();
    let fragments = shards
        .iter()
        .flat_map(|shard| shard.fragments.iter())
        .filter(|(key, _)| key.slot == slot && key.peer == peer)
        .map(|(_, fragment)| fragment.expires_at)
        .collect();
    (flows, fragments)
}

#[test]
fn a_selection_is_never_empty_and_ignores_order_and_repeats() {
    assert_eq!(
        ScopeSelection::any_of(Vec::<ScopeId>::new()),
        Err(EmptySelection)
    );
    assert_eq!(any_of(&["b", "a", "b"]), any_of(&["a", "b"]));
    assert_eq!(any_of(&["a"]), select("a"));
    assert_ne!(any_of(&["a", "b"]), select("a"));
}

#[test]
fn a_flow_in_the_selection_reports_its_scope_grant_and_generation() {
    let gate = gate_with(two_scopes());
    let syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &syn, &select("a")),
        scoped(granted("in-a"), Some("a"), Some("in-a"), 1)
    );
    let ack = tcp(REMOTE, LOCAL, 40_000, 22, 0x10);
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &ack, &select("a")),
        scoped(valid(), Some("a"), Some("in-a"), 1),
        "a packet of a live flow reports the flow's grant"
    );
    assert_eq!(
        gate.evaluate_outbound_in(PEER, &tcp(LOCAL, REMOTE, 22, 40_000, 0x10), &select("a")),
        scoped(valid(), Some("a"), Some("in-a"), 1)
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &ack),
        valid(),
        "the unscoped decision is unchanged"
    );
    assert_eq!(
        gate.evaluate_outbound_in(PEER, &tcp(LOCAL, REMOTE, 50_000, 80, 0x02), &select("a")),
        scoped(granted("out-a"), Some("a"), Some("out-a"), 1)
    );
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &tcp(REMOTE, LOCAL, 40_001, 22, 0x10), &select("a")),
        scoped(denied(GateReason::ReverseNewFlow), Some("a"), None, 1)
    );
}

#[test]
fn a_suspended_grant_is_reported() {
    let mut scope = peer_scope("a", GateMode::Enforce, PEER);
    scope.grants[0].suspended = true;
    let gate = gate_with(policy(vec![scope]));
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02), &select("a")),
        scoped(
            enforce(false, GateReason::Suspended, Some("in-a")),
            Some("a"),
            Some("in-a"),
            1
        )
    );
}

#[test]
fn another_scopes_flow_is_out_of_scope_and_untouched() {
    let (gate, clock) = manual_gate(two_scopes());
    let datagram = udp(REMOTE, LOCAL, 40_000, 53);
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &datagram, &select("a"))
            .decision,
        granted("in-a")
    );
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &datagram, &select("b"))
            .decision,
        granted("in-b")
    );
    let opened = state_of(&gate, "b", OTHER_PEER);
    assert_eq!(opened.0.len(), 1);

    advance(&clock, 60);
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &datagram, &select("a")),
        out_of_scope(1)
    );
    assert_eq!(
        gate.evaluate_outbound_in(OTHER_PEER, &udp(LOCAL, REMOTE, 53, 40_000), &select("a")),
        out_of_scope(1)
    );
    assert_eq!(
        state_of(&gate, "b", OTHER_PEER),
        opened,
        "b's flow is not refreshed"
    );
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &datagram, &select("a")),
        scoped(valid(), Some("a"), Some("in-a"), 1)
    );

    let entries = audit(&gate);
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &udp(REMOTE, LOCAL, 40_001, 53), &select("a")),
        out_of_scope(1)
    );
    assert_eq!(audit(&gate), entries, "no flow is created outside");

    // b's flow expires on its original deadline; a's was refreshed.
    advance(&clock, 61);
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &datagram, &select("b")),
        scoped(granted("in-b"), Some("b"), Some("in-b"), 1)
    );
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &datagram, &select("a")),
        scoped(valid(), Some("a"), Some("in-a"), 1)
    );
}

#[test]
fn later_fragments_follow_their_scope_and_report_no_grant() {
    let (gate, clock) = manual_gate(two_scopes());
    let first = first_fragment(udp(REMOTE, LOCAL, 40_000, 53), 9);
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &first, &select("b")),
        scoped(granted("in-b"), Some("b"), Some("in-b"), 1)
    );
    let opened = state_of(&gate, "b", OTHER_PEER);
    assert_eq!(opened.1.len(), 1);
    advance(&clock, 10);

    let later = later_fragment(REMOTE, LOCAL, 17, 9);
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &later, &select("a")),
        out_of_scope(1)
    );
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &later, &select("a")),
        scoped(denied(GateReason::OrphanFragment), Some("a"), None, 1),
        "a holds no first fragment of that id"
    );
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &later, &select("b")),
        scoped(valid(), Some("b"), None, 1)
    );
    assert_eq!(state_of(&gate, "b", OTHER_PEER), opened);

    // An expired fragment of b is not reclaimed by a lookup under a.
    advance(&clock, 30);
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &later, &select("a")),
        out_of_scope(1)
    );
    assert_eq!(state_of(&gate, "b", OTHER_PEER).1, opened.1);
}

#[test]
fn an_icmp_error_quoting_another_scopes_flow_is_out_of_scope() {
    let (gate, clock) = manual_gate(two_scopes());
    let request = udp(LOCAL, REMOTE, 50_000, 53);
    assert_eq!(
        gate.evaluate_outbound_in(OTHER_PEER, &request, &select("b")),
        scoped(granted("out-b"), Some("b"), Some("out-b"), 1)
    );
    let opened = state_of(&gate, "b", OTHER_PEER);
    advance(&clock, 60);

    let error = icmp_error(REMOTE, LOCAL, &request);
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &error, &select("a")),
        out_of_scope(1)
    );
    assert_eq!(state_of(&gate, "b", OTHER_PEER), opened);
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &error, &select("a")),
        scoped(denied(GateReason::ReverseNewFlow), Some("a"), None, 1),
        "a has no flow of the quoted tuple"
    );
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &error, &select("b")),
        scoped(valid(), Some("b"), Some("out-b"), 1),
        "an error quoting a flow reports the flow's grant"
    );
    assert_ne!(state_of(&gate, "b", OTHER_PEER), opened);
}

#[test]
fn the_peer_keyed_fallback_decides_only_without_an_exact_binding() {
    let mut keyed = peer_scope("keyed", GateMode::Enforce, PEER);
    keyed.bindings = vec![GateBinding {
        peer: PEER,
        addresses: Vec::new(),
        labels: labels(&["remote"]),
    }];
    let gate = gate_with(policy(vec![
        peer_scope("exact", GateMode::Enforce, PEER),
        keyed,
    ]));
    let exact = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    let other = tcp(OTHER_REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &exact, &select("keyed")),
        out_of_scope(1),
        "the exact binding takes precedence"
    );
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &other, &select("keyed")),
        scoped(granted("in-keyed"), Some("keyed"), Some("in-keyed"), 1)
    );
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &exact, &select("exact")),
        scoped(granted("in-exact"), Some("exact"), Some("in-exact"), 1)
    );
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &other, &select("exact")),
        out_of_scope(1)
    );
    assert_eq!(
        gate.evaluate_outbound_in(
            PEER,
            &tcp(LOCAL, OTHER_REMOTE, 22, 40_000, 0x12),
            &select("exact")
        ),
        out_of_scope(1)
    );
}

#[test]
fn ambiguity_is_enforced_whatever_the_modes() {
    let gate = gate_with(policy(vec![
        peer_scope("a", GateMode::Observe, PEER),
        peer_scope("b", GateMode::Observe, PEER),
    ]));
    let syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        gate.evaluate_inbound(PEER, &syn),
        observe(false, GateReason::Ambiguous, None)
    );
    for selection in [select("a"), any_of(&["a", "b"]), select("c")] {
        assert_eq!(
            gate.evaluate_inbound_in(PEER, &syn, &selection),
            scoped(denied(GateReason::Ambiguous), None, None, 1)
        );
    }
}

#[test]
fn unbound_packets_are_out_of_scope_and_record_no_pass_disposition() {
    let mut scope = peer_scope("a", GateMode::Enforce, PEER);
    scope.unbound = vec![UnboundRule {
        id: "pass".into(),
        peers: vec![CARRIER],
        action: UnboundAction::Pass,
        protocols: vec![ProtocolMatch::Udp(PortSet::Any)],
    }];
    let gate = gate_with(policy(vec![scope]));
    let first = first_fragment(udp(UNBOUND_SOURCE, LOCAL, 40_000, 53), 3);
    let later = later_fragment(UNBOUND_SOURCE, LOCAL, 17, 3);
    assert_eq!(
        gate.evaluate_inbound_in(CARRIER, &first, &select("a")),
        out_of_scope(1)
    );
    assert_eq!(audit(&gate), (0, 0), "no pass disposition is recorded");
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &later),
        denied(GateReason::OrphanFragment)
    );

    assert_eq!(gate.evaluate_inbound(CARRIER, &first), GateDecision::Pass);
    assert_eq!(
        gate.evaluate_inbound_in(CARRIER, &later, &select("a")),
        out_of_scope(1),
        "a pass disposition is not followed"
    );
    assert_eq!(gate.evaluate_inbound(CARRIER, &later), GateDecision::Pass);

    let syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        gate.evaluate_inbound(OTHER_PEER, &syn),
        denied(GateReason::Unbound)
    );
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &syn, &select("a")),
        out_of_scope(1)
    );
    let outbound = tcp(LOCAL, UNBOUND_SOURCE, 22, 40_000, 0x12);
    assert_eq!(gate.evaluate_outbound(PEER, &outbound), GateDecision::Pass);
    assert_eq!(
        gate.evaluate_outbound_in(PEER, &outbound, &select("a")),
        out_of_scope(1)
    );
}

#[test]
fn held_packets_are_denied_held() {
    let hold = HoldRule {
        peers: None,
        local: vec![host(LOCAL)],
        remote: vec![host(REMOTE)],
    };
    let gate = gate_with(GatePolicy {
        scopes: vec![peer_scope("a", GateMode::Observe, PEER)],
        holds: GateHolds {
            inbound: vec![hold.clone()],
            outbound: vec![hold],
            release: Vec::new(),
        },
    });
    let held = scoped(denied(GateReason::Held), None, None, 1);
    let mut truncated = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    truncated.truncate(30);
    truncated[2..4].copy_from_slice(&30_u16.to_be_bytes());
    for packet in [tcp(REMOTE, LOCAL, 40_000, 22, 0x02), truncated] {
        assert_eq!(gate.evaluate_inbound_in(PEER, &packet, &select("a")), held);
    }
    assert_eq!(
        gate.evaluate_outbound_in(PEER, &tcp(LOCAL, REMOTE, 22, 40_000, 0x12), &select("a")),
        held
    );
}

#[test]
fn malformed_packets_are_denied_malformed() {
    let gate = gate_with(policy(vec![
        peer_scope("a", GateMode::Observe, PEER),
        peer_scope("b", GateMode::Observe, OTHER_PEER),
    ]));
    let mut truncated = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    truncated.truncate(30);
    truncated[2..4].copy_from_slice(&30_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &truncated),
        observe(false, GateReason::Malformed, None)
    );
    let unreadable = vec![0x45, 0, 0];
    assert_eq!(gate.evaluate_inbound(PEER, &unreadable), GateDecision::Pass);
    let off_scope = tcp(REMOTE, UNBOUND_SOURCE, 40_000, 22, 0x02)[..30].to_vec();
    assert_eq!(gate.evaluate_inbound(PEER, &off_scope), GateDecision::Pass);
    for packet in [truncated, unreadable, off_scope] {
        assert_eq!(
            gate.evaluate_inbound_in(PEER, &packet, &select("a")),
            scoped(denied(GateReason::Malformed), None, None, 1),
            "enforced whatever the modes"
        );
    }

    // A packet that binds a scope before it is found malformed takes the
    // scope's decision.
    let port_zero = tcp(REMOTE, LOCAL, 0, 22, 0x02);
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &port_zero, &select("a")),
        scoped(
            observe(false, GateReason::Malformed, None),
            Some("a"),
            None,
            1
        )
    );
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &port_zero, &select("b")),
        out_of_scope(1)
    );
}

#[test]
fn an_inert_gate_and_other_versions_are_out_of_scope() {
    let inert = FlowGate::new(GateConfig::default());
    let syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(inert.evaluate_inbound(PEER, &syn), GateDecision::Pass);
    assert_eq!(
        inert.evaluate_inbound_in(PEER, &syn, &select("a")),
        out_of_scope(0)
    );

    let gate = gate_with(two_scopes());
    let mut other_version = syn.clone();
    other_version[0] = 0x55;
    assert_eq!(
        gate.evaluate_inbound(PEER, &other_version),
        GateDecision::Pass
    );
    let empty: &[u8] = &[];
    for packet in [&other_version[..], empty] {
        assert_eq!(
            gate.evaluate_inbound_in(PEER, packet, &select("a")),
            out_of_scope(1)
        );
        assert_eq!(
            gate.evaluate_outbound_in(PEER, packet, &select("a")),
            out_of_scope(1)
        );
    }

    gate.replace(policy(Vec::new())).unwrap();
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &syn, &select("a")),
        out_of_scope(2)
    );
}

#[test]
fn a_selection_of_several_scopes_decides_in_each() {
    let gate = gate_with(policy(vec![
        peer_scope("a", GateMode::Enforce, PEER),
        peer_scope("b", GateMode::Observe, OTHER_PEER),
        peer_scope("c", GateMode::Enforce, CARRIER),
    ]));
    let selection = any_of(&["a", "b"]);
    let syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &syn, &selection),
        scoped(granted("in-a"), Some("a"), Some("in-a"), 1)
    );
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &syn, &selection),
        scoped(
            observe(true, GateReason::Granted, Some("in-b")),
            Some("b"),
            Some("in-b"),
            1
        )
    );
    assert_eq!(
        gate.evaluate_inbound_in(
            OTHER_PEER,
            &tcp(REMOTE, LOCAL, 40_000, 22, 0x10),
            &selection
        ),
        scoped(
            observe(true, GateReason::ValidState, None),
            Some("b"),
            Some("in-b"),
            1
        )
    );
    assert_eq!(
        gate.evaluate_inbound_in(CARRIER, &syn, &selection),
        out_of_scope(1)
    );
}

#[test]
fn a_replace_between_calls_reports_the_new_generation() {
    let gate = gate_with(two_scopes());
    let syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    let ack = tcp(REMOTE, LOCAL, 40_000, 22, 0x10);
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &syn, &select("a")),
        scoped(granted("in-a"), Some("a"), Some("in-a"), 1)
    );

    let renamed = scope(
        "a",
        GateMode::Enforce,
        vec![
            inbound_any("in-a2", "remote"),
            outbound_any("out-a", "remote"),
        ],
    );
    let b = peer_scope("b", GateMode::Enforce, OTHER_PEER);
    assert_eq!(gate.replace(policy(vec![renamed, b.clone()])), Ok(2));
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &ack, &select("a")),
        scoped(valid(), Some("a"), Some("in-a2"), 2),
        "the flow was re-authorized under the changed scope"
    );

    assert_eq!(gate.replace(policy(vec![b])), Ok(3));
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &ack, &select("a")),
        out_of_scope(3)
    );
}

#[test]
fn ipv6_flows_are_scoped_like_ipv4() {
    let scope6_for = |id: &str, peer: PeerId| {
        let mut scope = open_scope6(GateMode::Enforce);
        scope.id = id.into();
        scope.bindings = vec![binding6(peer, REMOTE6, &["remote"])];
        scope
    };
    let gate = gate_with(policy(vec![
        scope6_for("a", PEER),
        scope6_for("b", OTHER_PEER),
    ]));
    let datagram = udp6(REMOTE6, LOCAL6, 40_000, 53);
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &datagram, &select("a")),
        scoped(granted("in"), Some("a"), Some("in"), 1)
    );
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &datagram, &select("a")),
        out_of_scope(1)
    );
    assert_eq!(
        gate.evaluate_outbound_in(PEER, &udp6(LOCAL6, REMOTE6, 53, 40_000), &select("a")),
        scoped(valid(), Some("a"), Some("in"), 1)
    );
    assert_eq!(
        gate.evaluate_outbound_in(
            OTHER_PEER,
            &tcp6(LOCAL6, REMOTE6, 53, 40_000, 0x12),
            &select("b")
        ),
        scoped(denied(GateReason::ReverseNewFlow), Some("b"), None, 1)
    );
}

#[test]
fn out_of_scope_denials_count_and_emit_like_any_denial() {
    let (gate, _clock) = manual_gate(two_scopes());
    let events = gate.enable_events(GateEventsConfig::default());
    let syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        gate.evaluate_inbound_in(OTHER_PEER, &syn, &select("a")),
        out_of_scope(1)
    );
    let counters = gate.counters();
    assert_eq!(
        (
            counters.enforced_allowed,
            counters.enforced_denied,
            counters.unbound_denied,
            counters.events_emitted
        ),
        (0, 1, 0, 1)
    );
    let event = events.try_recv().unwrap();
    assert_eq!(
        (
            event.peer,
            event.allow,
            event.enforced,
            event.reason,
            event.rule
        ),
        (OTHER_PEER, false, true, GateReason::OutOfScope, None)
    );

    assert_eq!(
        gate.evaluate_inbound_in(PEER, &syn, &select("a")).decision,
        granted("in-a")
    );
    assert_eq!(gate.counters().enforced_allowed, 1);
    assert_eq!(events.try_recv().unwrap().reason, GateReason::Granted);

    // A denial without readable addresses has no event.
    assert_eq!(
        gate.evaluate_inbound_in(PEER, &[0x45, 0, 0], &select("a")),
        scoped(denied(GateReason::Malformed), None, None, 1)
    );
    let counters = gate.counters();
    assert_eq!(
        (
            counters.enforced_denied,
            counters.events_emitted,
            counters.events_dropped
        ),
        (2, 2, 1)
    );
    assert_eq!(events.try_recv(), None);
}

#[test]
fn out_of_scope_has_stable_names() {
    assert_eq!(GateReason::OutOfScope.as_str(), "out_of_scope");
    assert_eq!(
        GateReason::OutOfScope.drop_reason(),
        "flow gate: out of scope"
    );
}
