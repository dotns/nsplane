//! IPv6 twins of the bindings, grants, state, holds, unbound and migration
//! tests; both families in one gate; IPv6 policies; and IPv6 packets racing
//! a writer.

use std::net::SocketAddrV6;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Instant;

use super::*;

const UNBOUND6: Ipv6Addr = Ipv6Addr::new(0xfd7f, 0, 0, 0, 0, 0, 0, 1);
const ELSEWHERE6: Ipv6Addr = Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 1);

fn v6(ip: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddrV6::new(ip, port, 0, 0).into()
}

#[test]
fn an_ipv6_label_grant_opens_new_flows() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x02)),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x10)),
        valid()
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(LOCAL6, REMOTE6, 22, 40_000, 0x12)),
        valid(),
        "the reply of an admitted flow"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_001, 22, 0x10)),
        denied(GateReason::ReverseNewFlow),
        "an ACK without state"
    );
    let mut relabelled = open_scope6(GateMode::Enforce);
    relabelled.grants[0].labels = vec![Label::from("someone-else")];
    gate.replace(policy(vec![relabelled])).unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_002, 22, 0x02)),
        denied(GateReason::NoGrant)
    );
}

#[test]
fn the_ipv6_peer_is_bound_to_its_remote_address() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(UNBOUND6, LOCAL6, 40_000, 22, 0x02)),
        denied(GateReason::Unbound)
    );
    assert_eq!(
        gate.evaluate_inbound(OTHER_PEER, &tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x02)),
        denied(GateReason::Unbound),
        "another peer with the bound address"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, ELSEWHERE6, 1, 2, 0x02)),
        GateDecision::Pass,
        "an address no scope governs"
    );
    assert_eq!(gate.counters().unbound_denied, 2);
}

#[test]
fn outbound_to_a_bound_ipv6_address_is_governed_whatever_the_peer_or_source() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(LOCAL6, REMOTE6, 50_000, 22, 0x02)),
        granted("out")
    );
    assert_eq!(
        gate.evaluate_outbound(OTHER_PEER, &tcp6(LOCAL6, REMOTE6, 40_000, 22, 0x02)),
        denied(GateReason::Unbound),
        "another peer selected for the bound address"
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(ELSEWHERE6, REMOTE6, 1, 22, 0x02)),
        denied(GateReason::Unbound),
        "a local source the scope does not govern"
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(LOCAL6, ELSEWHERE6, 1, 443, 0x02)),
        GateDecision::Pass,
        "another address of the same peer"
    );
}

#[test]
fn outbound_ipv6_grants_check_the_remote_destination() {
    let second = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 1, 2);
    let mut scope = scope6(
        "scope-1",
        GateMode::Enforce,
        vec![grant(
            "out",
            Direction::Outbound,
            &["remote"],
            vec!["fd00::/112".parse().unwrap()],
            vec![ProtocolMatch::Any],
        )],
    );
    scope.bindings.push(binding6(PEER, second, &["remote"]));
    let gate = gate_with(policy(vec![scope]));
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(LOCAL6, REMOTE6, 50_000, 22, 0x02)),
        granted("out")
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(LOCAL6, second, 50_000, 22, 0x02)),
        denied(GateReason::NoGrant),
        "outside the grant's prefix"
    );
}

#[test]
fn ipv6_scopes_binding_one_packet_are_ambiguous() {
    let mut second = open_scope6(GateMode::Observe);
    second.id = "scope-2".into();
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce), second]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x02)),
        denied(GateReason::Ambiguous)
    );
}

#[test]
fn ipv6_port_and_suspended_grants() {
    let web = |suspended| GateGrant {
        suspended,
        ..grant(
            "web",
            Direction::Inbound,
            &["remote"],
            vec![host6(LOCAL6)],
            vec![tcp_port(443)],
        )
    };
    let gate = gate_with(policy(vec![scope6(
        "scope-1",
        GateMode::Enforce,
        vec![web(true)],
    )]));
    let syn = tcp6(REMOTE6, LOCAL6, 40_000, 443, 0x02);
    assert_eq!(
        gate.evaluate_inbound(PEER, &syn),
        enforce(false, GateReason::Suspended, Some("web"))
    );
    gate.replace(policy(vec![scope6(
        "scope-1",
        GateMode::Enforce,
        vec![web(false)],
    )]))
    .unwrap();
    assert_eq!(gate.evaluate_inbound(PEER, &syn), granted("web"));
    for (name, packet) in [
        ("another port", tcp6(REMOTE6, LOCAL6, 40_001, 22, 0x02)),
        ("UDP to the port", udp6(REMOTE6, LOCAL6, 40_002, 443)),
        ("ICMPv6 echo", icmp6(REMOTE6, LOCAL6, 128, 1)),
    ] {
        assert_eq!(
            gate.evaluate_inbound(PEER, &packet),
            denied(GateReason::NoGrant),
            "{name}"
        );
    }
    gate.replace(policy(vec![scope6(
        "scope-1",
        GateMode::Enforce,
        vec![web(true)],
    )]))
    .unwrap();
    assert_eq!(
        audit_families(&gate),
        (0, 0),
        "suspending drops the flows it alone admitted"
    );
}

#[test]
pub(super) fn ipv6_return_state_does_not_become_reverse_initiation() {
    let gate = gate_with(policy(vec![scope6(
        "scope-1",
        GateMode::Enforce,
        vec![grant(
            "out",
            Direction::Outbound,
            &["remote"],
            Vec::new(),
            vec![ProtocolMatch::Any],
        )],
    )]));
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(LOCAL6, REMOTE6, 50_000, 8080, 0x02)),
        granted("out")
    );
    let syn_ack = tcp6(REMOTE6, LOCAL6, 8080, 50_000, 0x12);
    assert_eq!(gate.evaluate_inbound(PEER, &syn_ack), valid());
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 8080, 50_000, 0x02)),
        denied(GateReason::ReverseNewFlow),
        "a reverse bare SYN on the same five-tuple"
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(LOCAL6, REMOTE6, 50_000, 8080, 0x04)),
        valid()
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(LOCAL6, REMOTE6, 50_000, 8080, 0x02)),
        denied(GateReason::ReverseNewFlow),
        "a reset flow is not recycled by a new SYN"
    );
}

#[test]
fn an_ipv6_flow_expires_after_its_idle_timeout() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    let start = Instant::now();
    let at = |packet: &[u8], direction, seconds| {
        gate.evaluate_at(
            direction,
            PEER,
            packet,
            start + Duration::from_secs(seconds),
        )
    };
    let (out, back) = (PacketDirection::Outbound, PacketDirection::Inbound);
    assert_eq!(
        at(&udp6(REMOTE6, LOCAL6, 40_000, 53), back, 0),
        granted("in")
    );
    let reply = udp6(LOCAL6, REMOTE6, 53, 40_000);
    assert_eq!(at(&reply, out, 119), valid());
    assert_eq!(at(&reply, out, 240), granted("out"), "expired, a new flow");
    // ICMPv6 flows take the ICMP timeout.
    assert_eq!(
        at(&icmp6(REMOTE6, LOCAL6, 128, 5), back, 300),
        granted("in")
    );
    assert_eq!(at(&icmp6(LOCAL6, REMOTE6, 129, 5), out, 329), valid());
    assert_eq!(
        at(&icmp6(LOCAL6, REMOTE6, 129, 5), out, 360),
        denied(GateReason::ReverseNewFlow)
    );
}

#[test]
fn ipv6_flows_follow_the_state_limits() {
    let gate = limited(16, 1, 16);
    gate.replace(policy(vec![open_scope6(GateMode::Enforce)]))
        .unwrap();
    let start = Instant::now();
    let inbound = |port, seconds| {
        gate.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &udp6(REMOTE6, LOCAL6, port, 53),
            start + Duration::from_secs(seconds),
        )
    };
    assert_eq!(inbound(40_000, 0), granted("in"));
    assert_eq!(inbound(40_001, 1), denied(GateReason::StateCapacity));
    assert_eq!(
        inbound(40_002, 200),
        granted("in"),
        "the expired flow is reclaimed"
    );
    assert_eq!(audit_families(&gate), (1, 0));
}

/// One scope governing [`LOCAL`] and [`LOCAL6`] that binds [`PEER`] at
/// [`REMOTE`] and [`REMOTE6`].
fn dual_scope(mode: GateMode) -> GateScope {
    let mut scope = open_scope(mode);
    scope.local.push(IpAddr::V6(LOCAL6));
    scope.bindings[0].addresses.push(IpAddr::V6(REMOTE6));
    scope
        .grants
        .extend(open_scope6(mode).grants.into_iter().map(|mut grant| {
            grant.id = format!("{}6", grant.id).into();
            grant
        }));
    scope
}

#[test]
fn both_families_share_the_per_peer_limit() {
    let gate = limited(16, 2, 16);
    gate.replace(policy(vec![dual_scope(GateMode::Enforce)]))
        .unwrap();
    let start = Instant::now();
    let inbound = |packet: &[u8], seconds| {
        gate.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            packet,
            start + Duration::from_secs(seconds),
        )
    };
    assert_eq!(inbound(&udp(REMOTE, LOCAL, 40_000, 53), 0), granted("in"));
    assert_eq!(
        inbound(&udp6(REMOTE6, LOCAL6, 40_000, 53), 60),
        granted("in6")
    );
    assert_eq!(
        inbound(&udp6(REMOTE6, LOCAL6, 40_001, 53), 61),
        denied(GateReason::StateCapacity),
        "one IPv4 and one IPv6 flow fill the peer's budget"
    );
    assert_eq!(
        inbound(&udp(REMOTE, LOCAL, 40_001, 53), 61),
        denied(GateReason::StateCapacity)
    );
    assert_eq!(audit_families(&gate), (2, 0));
    assert_eq!(
        inbound(&udp6(REMOTE6, LOCAL6, 40_002, 53), 150),
        granted("in6"),
        "the expired IPv4 flow is reclaimed for an IPv6 one"
    );
    assert_eq!(audit_families(&gate), (2, 0));
    assert_eq!(
        inbound(&udp(REMOTE, LOCAL, 40_000, 53), 151),
        denied(GateReason::StateCapacity)
    );
}

#[test]
fn both_families_share_the_global_and_fragment_limits() {
    let gate = limited(2, 16, 1);
    gate.replace(policy(vec![dual_scope(GateMode::Enforce)]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &first_fragment(udp(REMOTE, LOCAL, 40_000, 53), 1)),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &first_fragment6(REMOTE6, LOCAL6, 40_000, 53, 1)),
        denied(GateReason::StateCapacity),
        "the IPv4 first fragment holds the only fragment entry"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_001, 53)),
        granted("in6")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_002, 53)),
        denied(GateReason::StateCapacity),
        "two flows in all"
    );
    assert_eq!(audit_families(&gate), (2, 1));
}

#[test]
fn a_mixed_scope_keeps_the_families_apart() {
    let gate = gate_with(policy(vec![dual_scope(GateMode::Enforce)]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53)),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53)),
        granted("in6")
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &udp6(LOCAL6, REMOTE6, 53, 40_000)),
        valid()
    );
    assert_eq!(
        gate.evaluate_inbound(
            PEER,
            &tcp6(REMOTE6, LOCAL.to_ipv6_mapped(), 40_000, 22, 0x02)
        ),
        GateDecision::Pass,
        "the IPv4-mapped form of the IPv4 address is not governed"
    );
    let shards = gate.state.lock_all();
    let (v4, v6): (usize, usize) = shards
        .iter()
        .map(|shard| (shard.flows.len(), shard.flows6.len()))
        .fold((0, 0), |(a, b), (c, d)| (a + c, b + d));
    assert_eq!((v4, v6), (1, 1));
}

#[test]
fn find_flow_reports_ipv6_flows_and_never_mixes_families() {
    let gate = gate_with(policy(vec![dual_scope(GateMode::Enforce)]));
    let (remote, local) = (v6(REMOTE6, 40_000), v6(LOCAL6, 443));
    assert_eq!(gate.find_flow(remote, local, Protocol::Tcp), None);
    let _ = gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_000, 443, 0x02));
    let _ = gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02));
    assert_eq!(
        gate.find_flow(remote, local, Protocol::Tcp),
        Some(LiveFlow {
            scope: "scope-1".into(),
            rule: "in6".into(),
            enforced: true,
        })
    );
    assert_eq!(gate.find_flow(remote, local, Protocol::Udp), None);
    assert_eq!(gate.find_flow(remote, v6(LOCAL6, 444), Protocol::Tcp), None);
    let v4_remote = SocketAddrV4::new(REMOTE, 40_000).into();
    let v4_local = SocketAddrV4::new(LOCAL, 443).into();
    assert!(gate.find_flow(v4_remote, v4_local, Protocol::Tcp).is_some());
    assert_eq!(gate.find_flow(v4_remote, local, Protocol::Tcp), None);
    assert_eq!(gate.find_flow(remote, v4_local, Protocol::Tcp), None);
}

#[test]
fn find_flow_refreshes_an_ipv6_flow() {
    let start = Instant::now();
    let clock = Arc::new(std::sync::Mutex::new(start));
    let read = Arc::clone(&clock);
    let gate = FlowGate::with_clock(GateConfig::default(), move || *read.lock().unwrap());
    gate.replace(policy(vec![open_scope6(GateMode::Enforce)]))
        .unwrap();
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53)),
        granted("in")
    );
    let (remote, local) = (v6(REMOTE6, 40_000), v6(LOCAL6, 53));
    *clock.lock().unwrap() += Duration::from_secs(100);
    assert!(gate.find_flow(remote, local, Protocol::Udp).is_some());
    *clock.lock().unwrap() += Duration::from_secs(100);
    assert!(
        gate.find_flow(remote, local, Protocol::Udp).is_some(),
        "refreshed at 100 s, live at 200 s"
    );
    *clock.lock().unwrap() += Duration::from_secs(121);
    assert_eq!(gate.find_flow(remote, local, Protocol::Udp), None);
    assert_eq!(audit_families(&gate), (0, 0), "the expired flow is dropped");
}

#[test]
fn a_changed_scope_re_authorizes_its_ipv6_flows() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Observe)]));
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp6(REMOTE6, LOCAL6, 40_000, 53)),
        observe(true, GateReason::Granted, Some("in"))
    );
    let _ = gate.evaluate_inbound(PEER, &first_fragment6(REMOTE6, LOCAL6, 40_001, 53, 9));
    let (remote, local) = (v6(REMOTE6, 40_000), v6(LOCAL6, 53));
    assert!(
        !gate
            .find_flow(remote, local, Protocol::Udp)
            .unwrap()
            .enforced
    );
    let mut dns = open_scope6(GateMode::Enforce);
    dns.grants.insert(
        0,
        grant(
            "dns",
            Direction::Inbound,
            &["remote"],
            Vec::new(),
            vec![ProtocolMatch::Udp(PortSet::single(53))],
        ),
    );
    gate.replace(policy(vec![dns])).unwrap();
    assert_eq!(
        gate.find_flow(remote, local, Protocol::Udp),
        Some(LiveFlow {
            scope: "scope-1".into(),
            rule: "dns".into(),
            enforced: true,
        })
    );
    assert_eq!(
        audit_families(&gate),
        (2, 0),
        "fragments of a changed scope are dropped"
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &udp6(LOCAL6, REMOTE6, 53, 40_000)),
        valid()
    );

    let mut moved = open_scope6(GateMode::Enforce);
    moved.bindings = vec![binding6(OTHER_PEER, REMOTE6, &["remote"])];
    gate.replace(policy(vec![moved])).unwrap();
    assert_eq!(
        audit_families(&gate),
        (0, 0),
        "the binding moved to another peer"
    );
}

#[test]
fn unchanged_removed_and_off_scopes_migrate_ipv6_state() {
    let mut other = open_scope(GateMode::Enforce);
    other.id = "scope-2".into();
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce), other.clone()]));
    let _ = gate.evaluate_inbound(PEER, &first_fragment6(REMOTE6, LOCAL6, 40_000, 53, 7));
    let _ = gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53));
    assert_eq!(audit_families(&gate), (2, 1));
    other.grants.clear();
    gate.replace(policy(vec![open_scope6(GateMode::Enforce), other.clone()]))
        .unwrap();
    assert_eq!(
        audit_families(&gate),
        (1, 1),
        "the IPv6 scope kept its state"
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &later_fragment6(REMOTE6, LOCAL6, 17, 7)),
        valid()
    );
    gate.replace(policy(vec![open_scope6(GateMode::Off), other]))
        .unwrap();
    assert_eq!(audit_families(&gate), (0, 0));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x02)),
        GateDecision::Pass
    );
}

#[test]
fn ipv6_holds_deny_before_the_scopes() {
    let hold = HoldRule {
        peers: None,
        local: vec![host6(LOCAL6)],
        remote: vec![host6(REMOTE6)],
    };
    let mut holds = GateHolds {
        inbound: vec![hold],
        outbound: vec![HoldRule {
            remote: vec!["fd00::/120".parse().unwrap()],
            ..HoldRule::default()
        }],
        ..GateHolds::default()
    };
    let mut scope_v4 = open_scope(GateMode::Enforce);
    scope_v4.id = "scope-2".into();
    let gate = gate_with(GatePolicy {
        scopes: vec![open_scope6(GateMode::Observe), scope_v4],
        holds: holds.clone(),
    });
    let syn = tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x02);
    assert_eq!(gate.evaluate_inbound(PEER, &syn), denied(GateReason::Held));
    for peer in [PEER, OTHER_PEER] {
        assert_eq!(
            gate.evaluate_outbound(peer, &tcp6(LOCAL6, REMOTE6, 50_000, 22, 0x02)),
            denied(GateReason::Held)
        );
    }
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        granted("in"),
        "IPv6 holds never match IPv4"
    );
    let mut malformed = syn.clone();
    malformed.truncate(50);
    malformed[4..6].copy_from_slice(&10_u16.to_be_bytes());
    assert_eq!(
        gate.evaluate_inbound(PEER, &malformed),
        denied(GateReason::Held),
        "a malformed packet with readable addresses"
    );

    holds.release.push((PEER, IpAddr::V6(REMOTE6)));
    gate.replace(GatePolicy {
        scopes: vec![open_scope6(GateMode::Enforce)],
        holds,
    })
    .unwrap();
    assert_eq!(gate.evaluate_inbound(PEER, &syn), granted("in"));
    assert_eq!(
        gate.evaluate_inbound(OTHER_PEER, &syn),
        denied(GateReason::Held),
        "only the released pair"
    );
}

#[test]
fn a_hold_rule_of_one_family_never_matches_the_other() {
    let gate = gate_with(GatePolicy {
        scopes: Vec::new(),
        holds: GateHolds {
            inbound: vec![HoldRule {
                remote: vec![host(REMOTE)],
                ..HoldRule::default()
            }],
            outbound: vec![HoldRule {
                local: vec![host6(LOCAL6)],
                ..HoldRule::default()
            }],
            ..GateHolds::default()
        },
    });
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 1, 2, 0x02)),
        GateDecision::Pass
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp6(LOCAL6, REMOTE6, 1, 2, 0x02)),
        denied(GateReason::Held)
    );
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 1, 2, 0x02)),
        GateDecision::Pass
    );
}

/// [`open_scope6`] with a pass rule for [`CARRIER`] to TCP and UDP 443 and a
/// divert rule for TCP and UDP.
fn unbound_scope6(mode: GateMode) -> GateScope {
    let mut scope = open_scope6(mode);
    scope.unbound = vec![
        UnboundRule {
            id: "pass".into(),
            peers: vec![CARRIER],
            action: UnboundAction::Pass,
            protocols: vec![tcp_port(443), ProtocolMatch::Udp(PortSet::single(443))],
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
pub(super) fn ipv6_pass_dispositions_cover_later_fragments() {
    let mut scope = unbound_scope6(GateMode::Enforce);
    let gate = gate_with(policy(vec![scope.clone()]));
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &tcp6(UNBOUND6, LOCAL6, 40_000, 443, 0x02)),
        GateDecision::Pass
    );
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &tcp6(UNBOUND6, LOCAL6, 40_000, 22, 0x02)),
        denied(GateReason::Unbound)
    );
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &first_fragment6(UNBOUND6, LOCAL6, 40_000, 443, 5)),
        GateDecision::Pass
    );
    let later = later_fragment6(UNBOUND6, LOCAL6, 17, 5);
    assert_eq!(gate.evaluate_inbound(CARRIER, &later), GateDecision::Pass);
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &later_fragment6(UNBOUND6, LOCAL6, 17, 6)),
        denied(GateReason::OrphanFragment)
    );
    assert_eq!(
        gate.evaluate_inbound(OTHER_PEER, &later),
        denied(GateReason::Unbound),
        "a peer no unbound rule names"
    );
    assert_eq!(audit_families(&gate), (0, 1));
    scope.unbound.reverse();
    gate.replace(policy(vec![scope])).unwrap();
    assert_eq!(audit_families(&gate), (0, 0), "a changed scope drops them");
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &later),
        denied(GateReason::OrphanFragment)
    );
}

#[test]
fn an_ipv6_divert_candidate_is_offered_only_for_its_rule() {
    let gate = gate_with(policy(vec![unbound_scope6(GateMode::Enforce)]));
    let reply = udp6(UNBOUND6, LOCAL6, 19_999, 49_152);
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &reply),
        denied(GateReason::Unbound)
    );
    let candidate = gate.divert_candidate(CARRIER, &reply).expect("a candidate");
    assert_eq!(candidate.rule(), &RuleId::from("divert"));
    assert_eq!(candidate.packet(), reply.as_slice());
    let later = later_fragment6(UNBOUND6, LOCAL6, 17, 9);
    assert_eq!(
        gate.evaluate_inbound(CARRIER, &later),
        denied(GateReason::OrphanFragment)
    );
    assert!(gate.divert_candidate(CARRIER, &later).is_some());
    for (name, peer, packet) in [
        ("another peer", OTHER_PEER, reply.clone()),
        (
            "from a binding address",
            CARRIER,
            udp6(REMOTE6, LOCAL6, 1, 2),
        ),
        ("to another address", CARRIER, udp6(UNBOUND6, REMOTE6, 1, 2)),
        ("ICMPv6", CARRIER, icmp6(UNBOUND6, LOCAL6, 129, 1)),
        ("malformed", CARRIER, reply[..44].to_vec()),
    ] {
        assert!(gate.divert_candidate(peer, &packet).is_none(), "{name}");
    }
}

#[test]
fn outbound_to_an_unbound_ipv6_address_is_governed_by_its_scope() {
    let to_it = tcp6(LOCAL6, UNBOUND6, 50_000, 443, 0x02);
    let mut malformed = to_it.clone();
    malformed.truncate(50);
    malformed[4..6].copy_from_slice(&10_u16.to_be_bytes());
    let gate = gate_with(policy(vec![unbound_scope6(GateMode::Enforce)]));
    assert_eq!(gate.evaluate_outbound(PEER, &to_it), GateDecision::Pass);
    let mut scope = unbound_scope6(GateMode::Enforce);
    scope.unbound_addresses = vec![IpAddr::V6(UNBOUND6)];
    gate.replace(policy(vec![scope.clone()])).unwrap();
    for peer in [PEER, CARRIER, OTHER_PEER] {
        assert_eq!(
            gate.evaluate_outbound(peer, &to_it),
            denied(GateReason::Unbound)
        );
    }
    assert_eq!(
        gate.evaluate_outbound(PEER, &malformed),
        denied(GateReason::Malformed)
    );
    assert!(
        gate.divert_candidate(CARRIER, &udp6(UNBOUND6, LOCAL6, 1, 2))
            .is_none(),
        "no divert candidate from an unbound address"
    );
    scope.mode = GateMode::Observe;
    gate.replace(policy(vec![scope])).unwrap();
    assert_eq!(
        gate.evaluate_outbound(PEER, &to_it),
        observe(false, GateReason::Unbound, None)
    );
}

#[test]
fn ipv6_entries_are_validated_like_ipv4_ones() {
    let gate = gate_with(policy(vec![open_scope6(GateMode::Enforce)]));
    let mut twice = open_scope6(GateMode::Off);
    twice.bindings.push(binding6(PEER, REMOTE6, &["again"]));
    assert_eq!(
        gate.replace(policy(vec![twice])),
        Err(GatePolicyError::DuplicateBinding {
            scope: "scope-1".into(),
            peer: PEER,
            address: IpAddr::V6(REMOTE6),
        })
    );
    let mut listed_twice = open_scope6(GateMode::Enforce);
    listed_twice.unbound_addresses = vec![IpAddr::V6(UNBOUND6); 2];
    let mut bound = open_scope6(GateMode::Enforce);
    bound.unbound_addresses = vec![IpAddr::V6(REMOTE6)];
    for scope in [listed_twice, bound] {
        let address = *scope.unbound_addresses.last().unwrap();
        assert_eq!(
            gate.replace(policy(vec![scope])),
            Err(GatePolicyError::ConflictingAddress {
                scope: "scope-1".into(),
                address,
            })
        );
    }
    assert_eq!(gate.generation(), 1, "nothing published");
}

#[test]
fn replace_accepts_ipv6_in_every_field() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let v6_net: IpNet = "fd00::/64".parse().unwrap();
    let mut scope = open_scope(GateMode::Enforce);
    scope.local.push(IpAddr::V6(LOCAL6));
    scope.bindings[0].addresses.push(IpAddr::V6(REMOTE6));
    scope.unbound_addresses.push(IpAddr::V6(UNBOUND6));
    scope.grants[0].destinations.push(v6_net);
    let rule = HoldRule {
        peers: None,
        local: vec![v6_net],
        remote: vec![host6(ELSEWHERE6)],
    };
    let policy = GatePolicy {
        scopes: vec![scope],
        holds: GateHolds {
            inbound: vec![rule.clone()],
            outbound: vec![rule],
            release: vec![(PEER, IpAddr::V6(REMOTE6))],
        },
    };
    assert_eq!(gate.replace(policy), Ok(2));
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, 40_000, 22, 0x02)),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp6(ELSEWHERE6, LOCAL6, 40_000, 22, 0x02)),
        denied(GateReason::Held)
    );
}

/// The IPv6 twin of the writer race: a writer grants, revokes and turns off
/// a scope binding IPv4 and IPv6 sources while packet threads send both
/// families; no state may outlive a revocation and the counts stay exact.
#[test]
fn a_writer_and_ipv6_packets_never_observe_mixed_snapshot_and_state() {
    let gate = limited(48, 12, 8);
    let done = AtomicBool::new(false);
    let mixed = |mode, granted: bool| {
        let mut scope = dual_scope(mode);
        if !granted {
            scope.grants.clear();
        }
        policy(vec![scope])
    };
    thread::scope(|scope| {
        let packets: Vec<_> = (0..4_u16)
            .map(|thread| {
                let (gate, done) = (&gate, &done);
                scope.spawn(move || {
                    let mut sequence = 0_u16;
                    while !done.load(Ordering::SeqCst) {
                        sequence = sequence.wrapping_add(1);
                        let port = 1_000 + thread * 100 + sequence % 64;
                        let decision =
                            match sequence % 6 {
                                0 => gate
                                    .evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, port, 22, 0x02)),
                                1 => gate
                                    .evaluate_inbound(PEER, &tcp6(REMOTE6, LOCAL6, port, 22, 0x10)),
                                2 => gate.evaluate_outbound(PEER, &udp6(LOCAL6, REMOTE6, port, 53)),
                                3 => gate.evaluate_inbound(
                                    PEER,
                                    &first_fragment6(REMOTE6, LOCAL6, port, 53, u32::from(port)),
                                ),
                                4 => gate.evaluate_inbound(
                                    PEER,
                                    &later_fragment6(REMOTE6, LOCAL6, 17, u32::from(port) - 1),
                                ),
                                _ => gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, port, 53)),
                            };
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
                        }
                    }
                })
            })
            .collect();
        for op in 0..300_u32 {
            let granted = op % 3 == 0;
            let mode = if op % 3 == 2 {
                GateMode::Off
            } else {
                GateMode::Enforce
            };
            gate.replace(mixed(mode, granted)).unwrap();
            if !granted {
                let shards = gate.state.lock_all();
                for shard in &shards {
                    assert!(shard.flows6.is_empty() && shard.flows.is_empty(), "op {op}");
                    assert!(shard.fragments6.is_empty() && shard.fragments.is_empty());
                }
            }
            let _ = audit_families(&gate);
            thread::sleep(Duration::from_micros(300));
        }
        done.store(true, Ordering::SeqCst);
        for packet in packets {
            packet.join().unwrap();
        }
    });
    let _ = audit_families(&gate);
    let counters = gate.counters();
    assert!(counters.enforced_allowed > 0, "{counters:?}");
    assert!(counters.enforced_denied > 0, "{counters:?}");
}

#[test]
fn ipv6_scenarios_run_concurrently_against_separate_gates() {
    let scenarios: [fn(); 6] = [
        ipv6_return_state_does_not_become_reverse_initiation,
        ipv6_pass_dispositions_cover_later_fragments,
        super::ipv6_packets::later_ipv6_fragments_need_an_admitted_first_fragment,
        super::ipv6_packets::icmpv6_errors_of_each_type_need_the_quoted_flow,
        super::grants_flow::return_state_does_not_become_reverse_initiation,
        super::packets_fragments::a_related_icmp_error_needs_the_quoted_flow,
    ];
    thread::scope(|scope| {
        for _ in 0..4 {
            for scenario in scenarios {
                scope.spawn(scenario);
            }
        }
    });
}
