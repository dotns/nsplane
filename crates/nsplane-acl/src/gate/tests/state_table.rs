//! Lazy expiry with sweep-at-limit, the epoch retry, validation and the
//! data model.

use std::time::Instant;

use super::*;
use crate::gate::decisions::{PacketInput, Step};
use crate::gate::packet::PacketMeta;

const REMOTE_2: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);

/// A peer whose state lives in another shard than [`PEER`]'s.
fn peer_in_other_shard() -> PeerId {
    (0..u32::MAX)
        .map(PeerId::new)
        .find(|peer| state::shard_index(*peer) != state::shard_index(PEER))
        .unwrap()
}

/// [`open_scope`] with a second remote source behind `peer_2`.
fn two_peer_policy(peer_2: PeerId) -> GatePolicy {
    let mut scope = open_scope(GateMode::Enforce);
    scope.bindings.push(binding(peer_2, REMOTE_2, &["remote"]));
    policy(vec![scope])
}

#[test]
fn the_per_peer_limit_reclaims_expired_flows_before_failing_closed() {
    let gate = limited(16, 1, 16);
    gate.replace(policy(vec![open_scope(GateMode::Enforce)]))
        .unwrap();
    let start = Instant::now();
    let inbound = |port, at| {
        gate.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &udp(REMOTE, LOCAL, port, 53),
            at,
        )
    };
    assert_eq!(inbound(40_000, start), granted("in"));
    assert_eq!(
        inbound(40_001, start + Duration::from_secs(1)),
        denied(GateReason::StateCapacity),
        "a live flow is never evicted"
    );
    assert_eq!(
        inbound(40_002, start + timeouts().udp + Duration::from_secs(1)),
        granted("in"),
        "the expired flow is reclaimed before the limit is checked again"
    );
    assert_eq!(audit(&gate), (1, 0));
}

#[test]
fn the_global_limit_sweeps_every_shard_before_failing_closed() {
    let peer_2 = peer_in_other_shard();
    let gate = limited(1, 16, 16);
    gate.replace(two_peer_policy(peer_2)).unwrap();
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
    let other = udp(REMOTE_2, LOCAL, 40_000, 53);
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &other,
            start + Duration::from_secs(1),
        ),
        denied(GateReason::StateCapacity)
    );
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &other,
            start + timeouts().udp + Duration::from_secs(1),
        ),
        granted("in"),
        "the expired flow of the other shard is reclaimed"
    );
    assert_eq!(audit(&gate), (1, 0));
}

#[test]
fn the_fragment_limit_sweeps_every_shard_before_failing_closed() {
    let peer_2 = peer_in_other_shard();
    let gate = limited(16, 16, 1);
    gate.replace(two_peer_policy(peer_2)).unwrap();
    let start = Instant::now();
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &first_fragment(udp(REMOTE, LOCAL, 40_000, 53), 1),
            start,
        ),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &first_fragment(udp(REMOTE_2, LOCAL, 40_001, 53), 2),
            start + Duration::from_secs(1),
        ),
        denied(GateReason::StateCapacity)
    );
    assert_eq!(
        audit(&gate),
        (1, 1),
        "the failed first fragment left no flow"
    );
    let later = start + timeouts().fragment + Duration::from_secs(1);
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &first_fragment(udp(REMOTE_2, LOCAL, 40_002, 53), 3),
            later,
        ),
        granted("in")
    );
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &later_fragment(REMOTE_2, LOCAL, 17, 3),
            later,
        ),
        valid()
    );
    assert_eq!(audit(&gate), (2, 1));
}

#[test]
fn configured_timeouts_drive_expiry() {
    let gate = FlowGate::new(GateConfig {
        timeouts: GateTimeouts {
            udp: Duration::from_secs(5),
            ..GateTimeouts::default()
        },
        ..GateConfig::default()
    });
    gate.replace(policy(vec![open_scope(GateMode::Enforce)]))
        .unwrap();
    let start = Instant::now();
    let _ = gate.evaluate_at(
        PacketDirection::Inbound,
        PEER,
        &udp(REMOTE, LOCAL, 40_000, 53),
        start,
    );
    let reply = udp(LOCAL, REMOTE, 53, 40_000);
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &reply,
            start + Duration::from_secs(4),
        ),
        valid()
    );
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &reply,
            start + Duration::from_secs(10),
        ),
        granted("out")
    );
}

#[test]
fn a_stale_snapshot_retries_instead_of_touching_migrated_state() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let stale = gate.snapshot.load_full();
    gate.replace(GatePolicy::default()).unwrap();

    let packet = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    let input = PacketInput {
        direction: PacketDirection::Inbound,
        peer: PEER,
        packet: &packet,
        meta: PacketMeta::parse(&packet),
        now: Instant::now().into(),
        swept: false,
    };
    assert_eq!(gate.evaluate_once(&stale, &input), Step::Retry);
    assert_eq!(audit(&gate), (0, 0), "the stale allow created no state");
    assert_eq!(gate.evaluate_inbound(PEER, &packet), GateDecision::Pass);
    assert_eq!(
        gate.evaluate_once(&gate.snapshot.load(), &input),
        Step::Done(GateDecision::Pass)
    );
}

#[test]
fn every_replace_bumps_the_generation() {
    let gate = FlowGate::new(GateConfig::default());
    assert_eq!(gate.generation(), 0);
    assert_eq!(gate.replace(GatePolicy::default()), Ok(1));
    assert_eq!(gate.replace(GatePolicy::default()), Ok(2));
    assert!(
        gate.replace(policy(vec![open_scope(GateMode::Enforce); 2]))
            .is_err()
    );
    assert_eq!(gate.generation(), 2, "a rejected policy publishes nothing");
}

#[test]
fn replace_rejects_invalid_policies_as_a_whole() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let published = gate.generation();
    let check = |policy: GatePolicy, expected: GatePolicyError| {
        assert_eq!(gate.replace(policy), Err(expected));
        assert_eq!(gate.generation(), published);
    };

    check(
        policy(vec![
            open_scope(GateMode::Enforce),
            open_scope(GateMode::Off),
        ]),
        GatePolicyError::DuplicateScope("scope-1".into()),
    );
    let mut twice = open_scope(GateMode::Off);
    twice.bindings.push(binding(PEER, REMOTE, &["again"]));
    check(
        policy(vec![twice]),
        GatePolicyError::DuplicateBinding {
            scope: "scope-1".into(),
            peer: PEER,
            address: IpAddr::V4(REMOTE),
        },
    );
    let mut empty = open_scope(GateMode::Enforce);
    empty.grants[0].protocols.clear();
    check(
        policy(vec![empty]),
        GatePolicyError::InvalidRule {
            id: "in".into(),
            reason: "empty protocol list".to_owned(),
        },
    );
    let mut unbound = open_scope(GateMode::Enforce);
    unbound.unbound.push(UnboundRule {
        id: "pass".into(),
        peers: vec![CARRIER],
        action: UnboundAction::Pass,
        protocols: vec![ProtocolMatch::Ip(6)],
    });
    assert!(matches!(
        gate.replace(policy(vec![unbound])),
        Err(GatePolicyError::InvalidRule { id, .. }) if id.as_str() == "pass"
    ));
}

#[test]
fn replace_rejects_ipv6_entries() {
    let gate = gate_with(policy(vec![open_scope(GateMode::Enforce)]));
    let v6: IpAddr = "fd00::1".parse().unwrap();
    let v6_net: IpNet = "fd00::/64".parse().unwrap();
    let field = |policy: GatePolicy| match gate.replace(policy) {
        Err(GatePolicyError::Ipv6 { field, .. }) => field,
        other => panic!("{other:?}"),
    };

    let mut local = open_scope(GateMode::Off);
    local.local.push(v6);
    assert_eq!(field(policy(vec![local])), "local");
    let mut bound = open_scope(GateMode::Enforce);
    bound.bindings[0].addresses.push(v6);
    assert_eq!(field(policy(vec![bound])), "bindings.addresses");
    let mut granted = open_scope(GateMode::Enforce);
    granted.grants[0].destinations.push(v6_net);
    assert_eq!(field(policy(vec![granted])), "grants.destinations");
    let held = |rule: HoldRule| GatePolicy {
        scopes: Vec::new(),
        holds: GateHolds {
            outbound: vec![rule],
            ..GateHolds::default()
        },
    };
    assert_eq!(
        field(held(HoldRule {
            local: vec![v6_net],
            ..HoldRule::default()
        })),
        "holds.local"
    );
    assert_eq!(
        field(held(HoldRule {
            remote: vec![v6_net],
            ..HoldRule::default()
        })),
        "holds.remote"
    );
    assert_eq!(
        field(GatePolicy {
            scopes: Vec::new(),
            holds: GateHolds {
                release: vec![(PEER, v6)],
                ..GateHolds::default()
            },
        }),
        "holds.release"
    );
    assert_eq!(gate.generation(), 1);
}

#[test]
fn defaults_are_the_documented_values() {
    assert_eq!(
        GateLimits::default(),
        GateLimits {
            flows: 16_384,
            flows_per_peer: 2_048,
            fragments: 4_096,
        }
    );
    let timeouts = GateTimeouts::default();
    assert_eq!(timeouts.tcp, Duration::from_hours(2));
    assert_eq!(timeouts.tcp_half_closed, Duration::from_mins(5));
    assert_eq!(timeouts.tcp_closed, Duration::from_secs(30));
    assert_eq!(timeouts.udp, Duration::from_mins(2));
    assert_eq!(timeouts.icmp, Duration::from_secs(30));
    assert_eq!(timeouts.other, Duration::from_secs(60));
    assert_eq!(timeouts.fragment, Duration::from_secs(30));
    assert_eq!(GateMode::default(), GateMode::Off);
}

#[test]
fn reason_names_are_stable_and_one_to_one() {
    let reasons = [
        (GateReason::ValidState, "valid_state"),
        (GateReason::Granted, "granted"),
        (GateReason::Unbound, "unbound"),
        (GateReason::ReverseNewFlow, "reverse_new_flow"),
        (GateReason::NoGrant, "no_grant"),
        (GateReason::Suspended, "suspended"),
        (GateReason::Held, "held"),
        (GateReason::OrphanFragment, "orphan_fragment"),
        (GateReason::StateCapacity, "state_capacity"),
        (GateReason::Ambiguous, "ambiguous"),
        (GateReason::Malformed, "malformed"),
    ];
    let mut names = std::collections::HashSet::new();
    let mut drops = std::collections::HashSet::new();
    for (reason, name) in reasons {
        assert_eq!(reason.as_str(), name);
        assert_eq!(
            reason.drop_reason(),
            format!("flow gate: {}", name.replace('_', " "))
        );
        assert!(names.insert(reason.as_str()));
        assert!(drops.insert(reason.drop_reason()));
    }
}

#[test]
fn enforced_verdict_is_the_enforced_allow() {
    assert_eq!(granted("in").enforced_verdict(), Some(true));
    assert_eq!(denied(GateReason::Held).enforced_verdict(), Some(false));
    assert_eq!(
        observe(false, GateReason::NoGrant, None).enforced_verdict(),
        None
    );
    assert_eq!(GateDecision::Pass.enforced_verdict(), None);
}

#[test]
fn the_gate_and_filter_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FlowGate>();
    assert_send_sync::<GateFilter>();
    assert_send_sync::<DivertedPacket>();
}
