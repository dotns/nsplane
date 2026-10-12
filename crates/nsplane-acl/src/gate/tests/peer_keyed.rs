//! Peer-keyed bindings: one binding covers every packet of a peer in both
//! families; exact bindings take precedence; validation; outbound governance;
//! migration across `replace`; divert.

use std::net::SocketAddrV6;

use super::*;

const SECOND: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);
const SECOND6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
const ELSEWHERE: Ipv4Addr = Ipv4Addr::new(100, 99, 0, 1);
const ELSEWHERE6: Ipv6Addr = Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 1);

fn v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddrV4::new(ip, port).into()
}

fn v6(ip: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddrV6::new(ip, port, 0, 0).into()
}

fn by_peer(peer: PeerId, with: &[&str]) -> GateBinding {
    GateBinding {
        peer,
        addresses: Vec::new(),
        labels: labels(with),
    }
}

/// Scope `id` governing [`LOCAL`] and [`LOCAL6`] with `bindings`; `label`
/// may open every protocol inbound (grant `in-{id}`) and outbound (grant
/// `out-{id}`) to any destination.
fn keyed_scope(id: &str, mode: GateMode, bindings: Vec<GateBinding>, label: &str) -> GateScope {
    let any = |direction, name: String| GateGrant {
        id: name.into(),
        ..grant(
            "",
            direction,
            &[label],
            Vec::new(),
            vec![ProtocolMatch::Any],
        )
    };
    GateScope {
        id: id.into(),
        mode,
        local: vec![IpAddr::V4(LOCAL), IpAddr::V6(LOCAL6)],
        bindings,
        unbound_addresses: Vec::new(),
        grants: vec![
            any(Direction::Inbound, format!("in-{id}")),
            any(Direction::Outbound, format!("out-{id}")),
        ],
        unbound: Vec::new(),
    }
}

#[test]
fn a_peer_keyed_binding_governs_every_address_of_both_families() {
    let gate = gate_with(policy(vec![keyed_scope(
        "s",
        GateMode::Enforce,
        vec![by_peer(PEER, &["remote"])],
        "remote",
    )]));
    for (name, syn, reply) in [
        (
            "IPv4",
            tcp(REMOTE, LOCAL, 40_000, 22, 0x02),
            tcp(LOCAL, REMOTE, 22, 40_000, 0x12),
        ),
        (
            "another IPv4 address",
            tcp(SECOND, LOCAL, 40_000, 22, 0x02),
            tcp(LOCAL, SECOND, 22, 40_000, 0x12),
        ),
        (
            "IPv6",
            tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x02),
            tcp6(LOCAL6, REMOTE6, 22, 40_000, 0x12),
        ),
        (
            "another IPv6 address",
            tcp6(SECOND6, LOCAL6, 40_000, 22, 0x02),
            tcp6(LOCAL6, SECOND6, 22, 40_000, 0x12),
        ),
    ] {
        assert_eq!(gate.evaluate_inbound(PEER, &syn), granted("in-s"), "{name}");
        assert_eq!(gate.evaluate_outbound(PEER, &reply), valid(), "{name}");
    }
    assert_eq!(
        gate.evaluate_outbound(PEER, &udp6(LOCAL6, SECOND6, 40_000, 53)),
        granted("out-s")
    );
    for (name, packet) in [
        ("IPv4", tcp(REMOTE, LOCAL, 40_001, 22, 0x02)),
        ("IPv6", tcp6(REMOTE6, LOCAL6, 40_001, 22, 0x02)),
    ] {
        assert_eq!(
            gate.evaluate_inbound(OTHER_PEER, &packet),
            denied(GateReason::Unbound),
            "another peer over {name}"
        );
    }
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_002, 22, 0x10)),
        denied(GateReason::ReverseNewFlow)
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, ELSEWHERE, 40_000, 22, 0x02)),
        GateDecision::Pass,
        "a local address no scope governs"
    );
}

#[test]
fn a_peer_keyed_binding_carries_its_labels_to_the_grants() {
    let mut scope = keyed_scope(
        "s",
        GateMode::Enforce,
        vec![by_peer(PEER, &["remote"])],
        "remote",
    );
    scope.grants = vec![grant(
        "ssh",
        Direction::Inbound,
        &["remote"],
        Vec::new(),
        vec![tcp_port(22)],
    )];
    let gate = gate_with(policy(vec![scope.clone()]));
    for packet in [
        tcp(SECOND, LOCAL, 40_000, 22, 0x02),
        tcp6(SECOND6, LOCAL6, 40_000, 22, 0x02),
    ] {
        assert_eq!(gate.evaluate_inbound(PEER, &packet), granted("ssh"));
    }
    for packet in [
        tcp(SECOND, LOCAL, 40_001, 80, 0x02),
        tcp6(SECOND6, LOCAL6, 40_001, 80, 0x02),
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &packet),
            denied(GateReason::NoGrant)
        );
    }
    scope.bindings = vec![by_peer(PEER, &["someone-else"])];
    gate.replace(policy(vec![scope])).unwrap();
    assert_eq!(audit_families(&gate), (0, 0), "the labels no longer match");
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(SECOND6, LOCAL6, 40_002, 22, 0x02)),
        denied(GateReason::NoGrant)
    );
}

#[test]
fn a_mixed_family_peer_shares_one_budget_and_its_grants() {
    let gate = limited(16, 2, 16);
    gate.replace(policy(vec![keyed_scope(
        "s",
        GateMode::Enforce,
        vec![by_peer(PEER, &["remote"])],
        "remote",
    )]))
    .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53)),
        granted("in-s")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(SECOND6, LOCAL6, 40_000, 53)),
        granted("in-s")
    );
    for packet in [
        udp(SECOND, LOCAL, 40_001, 53),
        udp6(REMOTE6, LOCAL6, 40_001, 53),
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &packet),
            denied(GateReason::StateCapacity),
            "one IPv4 and one IPv6 flow fill the peer's budget"
        );
    }
    assert_eq!(audit_families(&gate), (2, 0));
    let flow = |remote, local| gate.find_flow(remote, local, Protocol::Udp);
    for found in [
        flow(v4(REMOTE, 40_000), v4(LOCAL, 53)),
        flow(v6(SECOND6, 40_000), v6(LOCAL6, 53)),
    ] {
        assert_eq!(
            found,
            Some(LiveFlow {
                scope: "s".into(),
                rule: "in-s".into(),
                enforced: true,
            })
        );
    }
}

/// Scope `a` binds [`PEER`] at [`REMOTE`] and [`REMOTE6`] (label `a`);
/// scope `b` binds [`PEER`] by peer (label `b`).
fn exact_and_keyed() -> (GateScope, GateScope) {
    let mut exact = binding(PEER, REMOTE, &["a"]);
    exact.addresses.push(IpAddr::V6(REMOTE6));
    (
        keyed_scope("a", GateMode::Enforce, vec![exact], "a"),
        keyed_scope("b", GateMode::Enforce, vec![by_peer(PEER, &["b"])], "b"),
    )
}

#[test]
fn an_exact_binding_takes_precedence_over_a_peer_keyed_one() {
    let (a, b) = exact_and_keyed();
    let gate = gate_with(policy(vec![b, a]));
    for (name, packet, rule) in [
        ("exact IPv4", udp(REMOTE, LOCAL, 40_000, 53), "in-a"),
        ("exact IPv6", udp6(REMOTE6, LOCAL6, 40_000, 53), "in-a"),
        ("other IPv4", udp(SECOND, LOCAL, 40_000, 53), "in-b"),
        ("other IPv6", udp6(SECOND6, LOCAL6, 40_000, 53), "in-b"),
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &packet),
            granted(rule),
            "{name}"
        );
    }
    assert_eq!(
        gate.evaluate_outbound(PEER, &udp(LOCAL, REMOTE, 53, 40_000)),
        valid()
    );
    assert_eq!(
        gate.find_flow(v4(REMOTE, 40_000), v4(LOCAL, 53), Protocol::Udp)
            .unwrap()
            .scope,
        ScopeId::from("a")
    );
    assert_eq!(
        gate.find_flow(v6(SECOND6, 40_000), v6(LOCAL6, 53), Protocol::Udp)
            .unwrap()
            .scope,
        ScopeId::from("b")
    );
}

#[test]
fn candidates_at_the_chosen_level_are_ambiguous() {
    let keyed = |id, mode| keyed_scope(id, mode, vec![by_peer(PEER, &["b"])], "b");
    let gate = gate_with(policy(vec![
        keyed("b1", GateMode::Observe),
        keyed("b2", GateMode::Enforce),
    ]));
    for packet in [
        udp(REMOTE, LOCAL, 40_000, 53),
        udp6(SECOND6, LOCAL6, 40_000, 53),
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &packet),
            denied(GateReason::Ambiguous),
            "enforced as one of them enforces"
        );
    }
    gate.replace(policy(vec![
        keyed("b1", GateMode::Observe),
        keyed("b2", GateMode::Observe),
    ]))
    .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53)),
        observe(false, GateReason::Ambiguous, None)
    );

    // One exact binding settles the ambiguity of the peer-keyed ones.
    let (a, _) = exact_and_keyed();
    gate.replace(policy(vec![
        keyed("b1", GateMode::Enforce),
        keyed("b2", GateMode::Enforce),
        a.clone(),
    ]))
    .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53)),
        granted("in-a")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(SECOND, LOCAL, 40_000, 53)),
        denied(GateReason::Ambiguous)
    );

    // Two exact bindings are ambiguous; the peer-keyed one is not consulted.
    let mut a2 = a.clone();
    a2.id = "a2".into();
    gate.replace(policy(vec![keyed("b", GateMode::Enforce), a, a2]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53)),
        denied(GateReason::Ambiguous)
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(SECOND6, LOCAL6, 40_000, 53)),
        granted("in-b")
    );
}

#[test]
fn a_peer_bound_by_peer_has_no_other_binding_in_the_scope() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let rejected = |bindings: Vec<GateBinding>| {
        gate.replace(policy(vec![keyed_scope(
            "s",
            GateMode::Off,
            bindings,
            "remote",
        )]))
    };
    let error = Err(GatePolicyError::DuplicatePeerBinding {
        scope: "s".into(),
        peer: PEER,
    });
    assert_eq!(
        rejected(vec![by_peer(PEER, &["a"]), by_peer(PEER, &["b"])]),
        error,
        "two peer-keyed bindings"
    );
    assert_eq!(
        rejected(vec![by_peer(PEER, &["a"]), binding(PEER, REMOTE, &["b"])]),
        error,
        "a peer-keyed binding, then an address-listed one"
    );
    assert_eq!(
        rejected(vec![binding6(PEER, REMOTE6, &["b"]), by_peer(PEER, &["a"])]),
        error,
        "an address-listed binding, then a peer-keyed one"
    );
    assert_eq!(gate.generation(), 1, "nothing is published");

    let mut accepted = keyed_scope(
        "s",
        GateMode::Enforce,
        vec![by_peer(PEER, &["a"]), binding(OTHER_PEER, REMOTE, &["b"])],
        "a",
    );
    accepted.unbound_addresses = vec![IpAddr::V4(SECOND), IpAddr::V6(SECOND6)];
    let mut other = keyed_scope("t", GateMode::Enforce, vec![by_peer(PEER, &["a"])], "a");
    other.local = vec![IpAddr::V4(ELSEWHERE)];
    gate.replace(policy(vec![accepted, other]))
        .expect("other peers, other scopes and unbound addresses do not conflict");
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(SECOND, LOCAL, 40_000, 53)),
        granted("in-s"),
        "a peer-keyed binding binds an unbound address of its scope"
    );
    assert_eq!(
        gate.evaluate_outbound(OTHER_PEER, &udp6(LOCAL6, SECOND6, 40_000, 53)),
        denied(GateReason::Unbound),
        "an unbound address still governs other peers"
    );
}

#[test]
fn outbound_over_a_peer_keyed_peer_is_governed_from_any_source() {
    let mut scope = keyed_scope(
        "s",
        GateMode::Enforce,
        vec![by_peer(PEER, &["remote"])],
        "remote",
    );
    let gate = gate_with(policy(vec![scope.clone()]));
    let mut malformed = tcp(ELSEWHERE, SECOND, 50_000, 22, 0x02);
    malformed.truncate(30);
    malformed[2..4].copy_from_slice(&30_u16.to_be_bytes());
    for (name, packet, reason) in [
        (
            "IPv4",
            tcp(ELSEWHERE, SECOND, 50_000, 22, 0x02),
            GateReason::Unbound,
        ),
        (
            "IPv6",
            tcp6(ELSEWHERE6, SECOND6, 50_000, 22, 0x02),
            GateReason::Unbound,
        ),
        ("malformed", malformed.clone(), GateReason::Malformed),
    ] {
        assert_eq!(
            gate.evaluate_outbound(PEER, &packet),
            denied(reason),
            "{name}"
        );
    }
    assert_eq!(
        gate.evaluate_outbound(OTHER_PEER, &tcp(ELSEWHERE, SECOND, 50_000, 22, 0x02)),
        GateDecision::Pass,
        "another peer to an address no scope holds"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(SECOND, ELSEWHERE, 40_000, 22, 0x02)),
        GateDecision::Pass,
        "inbound to an ungoverned address is unchanged"
    );
    scope.mode = GateMode::Observe;
    gate.replace(policy(vec![scope])).unwrap();
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(ELSEWHERE6, SECOND6, 50_000, 22, 0x02)),
        observe(false, GateReason::Unbound, None)
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &malformed),
        observe(false, GateReason::Malformed, None)
    );
}

#[test]
fn replace_moves_flows_between_exact_and_peer_keyed_scopes() {
    let (a, b) = exact_and_keyed();
    let gate = gate_with(policy(vec![a.clone(), b.clone()]));
    let exact = |gate: &FlowGate| {
        gate.find_flow(v4(REMOTE, 40_000), v4(LOCAL, 53), Protocol::Udp)
            .map(|flow| flow.scope)
    };
    let other6 = |gate: &FlowGate| {
        gate.find_flow(v6(SECOND6, 40_000), v6(LOCAL6, 53), Protocol::Udp)
            .map(|flow| flow.scope)
    };
    let _ = gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53));
    let _ = gate.evaluate_inbound(PEER, &udp6(SECOND6, LOCAL6, 40_000, 53));
    assert_eq!(exact(&gate), Some("a".into()));
    assert_eq!(other6(&gate), Some("b".into()));

    // The exact binding leaves `a`: its flow is dropped and the next packet
    // of the pair opens in `b`.
    let mut a_without = a.clone();
    a_without.bindings[0].addresses = vec![IpAddr::V6(REMOTE6)];
    gate.replace(policy(vec![a_without.clone(), b.clone()]))
        .unwrap();
    assert_eq!(exact(&gate), None);
    assert_eq!(other6(&gate), Some("b".into()), "`b` is unchanged");
    assert_eq!(
        gate.evaluate_outbound(PEER, &udp(LOCAL, REMOTE, 53, 40_000)),
        granted("out-b"),
        "the reply opens a new flow under `b`"
    );
    assert_eq!(exact(&gate), Some("b".into()));

    // The exact binding returns to `a`: the flow `b` holds for the pair is
    // no longer selected and is dropped, though `b` is unchanged.
    gate.replace(policy(vec![a.clone(), b.clone()])).unwrap();
    assert_eq!(exact(&gate), None);
    assert_eq!(other6(&gate), Some("b".into()));
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53)),
        granted("in-a")
    );

    // A new scope binding the IPv6 pair exactly takes it from `b`, though no
    // published scope changed.
    let mut c = keyed_scope(
        "c",
        GateMode::Enforce,
        vec![binding6(PEER, SECOND6, &["c"])],
        "c",
    );
    c.local = vec![IpAddr::V6(LOCAL6)];
    gate.replace(policy(vec![a.clone(), b.clone(), c])).unwrap();
    assert_eq!(other6(&gate), None);
    assert_eq!(exact(&gate), Some("a".into()));
    assert_eq!(audit_families(&gate), (1, 0));
}

#[test]
fn replace_adding_and_removing_a_peer_keyed_binding_migrates_flows() {
    let mut scope = keyed_scope(
        "s",
        GateMode::Enforce,
        vec![binding(PEER, REMOTE, &["remote"])],
        "remote",
    );
    let gate = gate_with(policy(vec![scope.clone()]));
    let _ = gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53));
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53)),
        denied(GateReason::Unbound)
    );

    // The address-listed binding becomes peer-keyed: the flow stays.
    scope.bindings = vec![by_peer(PEER, &["remote"])];
    gate.replace(policy(vec![scope.clone()])).unwrap();
    assert_eq!(audit_families(&gate), (1, 0));
    assert_eq!(
        gate.evaluate_outbound(PEER, &udp(LOCAL, REMOTE, 53, 40_000)),
        valid()
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53)),
        granted("in-s")
    );
    assert_eq!(audit_families(&gate), (2, 0));

    // Another peer-keyed scope for the peer and the same local addresses
    // makes every flow ambiguous: they are dropped.
    let mut twin = scope.clone();
    twin.id = "twin".into();
    gate.replace(policy(vec![scope.clone(), twin])).unwrap();
    assert_eq!(audit_families(&gate), (0, 0));

    gate.replace(policy(vec![scope.clone()])).unwrap();
    let _ = gate.evaluate_inbound(PEER, &udp(SECOND, LOCAL, 40_000, 53));
    let _ = gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53));
    assert_eq!(audit_families(&gate), (2, 0));

    // Back to the IPv4 address only: the flows of other addresses go.
    scope.bindings = vec![binding(PEER, REMOTE, &["remote"])];
    gate.replace(policy(vec![scope.clone()])).unwrap();
    assert_eq!(audit_families(&gate), (0, 0));

    // The peer-keyed binding removed altogether.
    scope.bindings = vec![by_peer(PEER, &["remote"])];
    gate.replace(policy(vec![scope.clone()])).unwrap();
    let _ = gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53));
    scope.bindings.clear();
    gate.replace(policy(vec![scope])).unwrap();
    assert_eq!(audit_families(&gate), (0, 0));
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53)),
        denied(GateReason::Unbound)
    );
}

#[test]
fn a_packet_bound_by_peer_is_never_a_divert_candidate() {
    let mut scope = keyed_scope(
        "s",
        GateMode::Enforce,
        vec![by_peer(PEER, &["remote"])],
        "remote",
    );
    scope.unbound = vec![UnboundRule {
        id: "divert".into(),
        peers: vec![PEER, CARRIER],
        action: UnboundAction::Divert,
        protocols: vec![
            ProtocolMatch::Tcp(PortSet::Any),
            ProtocolMatch::Udp(PortSet::Any),
        ],
    }];
    let gate = gate_with(policy(vec![scope]));
    for later in [
        later_fragment(SECOND, LOCAL, 17, 9),
        later_fragment6(SECOND6, LOCAL6, 17, 9),
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &later),
            denied(GateReason::OrphanFragment)
        );
        assert!(gate.divert_candidate(PEER, &later).is_none());
        assert_eq!(
            gate.evaluate_inbound(CARRIER, &later),
            denied(GateReason::OrphanFragment),
            "an unbound peer named by the rule"
        );
        assert!(gate.divert_candidate(CARRIER, &later).is_some());
    }
}
