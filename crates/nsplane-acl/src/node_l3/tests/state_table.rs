//! Lazy expiry with sweep-at-limit, the epoch retry, the change notifications
//! and the data model of this implementation.

use std::sync::Mutex;

use super::*;
use crate::node_l3::decisions::{PacketInput, Step};
use crate::node_l3::packet::PacketMeta;

const REMOTE_2: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);

/// A peer key whose state lives in another shard than [`PEER`]'s.
fn peer_in_other_shard() -> [u8; 32] {
    (0..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|key| state::shard_index(key) != state::shard_index(&PEER))
        .unwrap()
}

/// Same-owner Enforce policy with a second remote Node behind `peer_2`.
fn two_peer_config(peer_2: [u8; 32]) -> NodeL3Config {
    let mut policy = config(NodeL3Mode::Enforce, true);
    policy.bindings.push(NodeL3PeerBinding {
        peer_public_key: peer_2,
        node_id: "node-remote-2".to_owned(),
        owner_id: "owner-local".to_owned(),
        ip: REMOTE_2,
    });
    policy
}

fn udp_first_fragment(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, id: u16) -> Vec<u8> {
    let mut packet = udp(src, dst, src_port, 53);
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    packet
}

#[test]
fn per_peer_limit_reclaims_expired_flows_before_failing_closed() {
    let gate = NodeL3Gate::with_limits("machine-1", 16, 1, 16);
    gate.apply(config(NodeL3Mode::Enforce, true)).unwrap();
    let start = Instant::now();
    let inbound = |port, at| {
        gate.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &udp(REMOTE, LOCAL, port, 53),
            at,
        )
    };

    assert!(matches!(
        inbound(40_000, start),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert_eq!(
        inbound(40_001, start + Duration::from_secs(1)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::StateCapacity,
        },
        "a live flow is never evicted"
    );
    assert_eq!(
        inbound(40_002, start + UDP_IDLE_TIMEOUT + Duration::from_secs(1)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::SameOwner,
        },
        "the expired flow is reclaimed before the limit is checked again"
    );
    assert_eq!(audit(&gate), (1, 0));
}

#[test]
fn global_limit_sweeps_every_shard_before_failing_closed() {
    let peer_2 = peer_in_other_shard();
    let gate = NodeL3Gate::with_limits("machine-1", 1, 16, 16);
    gate.apply(two_peer_config(peer_2)).unwrap();
    let start = Instant::now();

    assert!(matches!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &udp(REMOTE, LOCAL, 40_000, 53),
            start,
        ),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    let other = udp(REMOTE_2, LOCAL, 40_000, 53);
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &other,
            start + Duration::from_secs(1)
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::StateCapacity,
        }
    );
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &other,
            start + UDP_IDLE_TIMEOUT + Duration::from_secs(1),
        ),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::SameOwner,
        },
        "the expired flow of the other shard is reclaimed"
    );
    assert_eq!(audit(&gate), (1, 0));
}

#[test]
fn fragment_limit_sweeps_every_shard_before_failing_closed() {
    let peer_2 = peer_in_other_shard();
    let gate = NodeL3Gate::with_limits("machine-1", 16, 16, 1);
    gate.apply(two_peer_config(peer_2)).unwrap();
    let start = Instant::now();

    assert!(matches!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &udp_first_fragment(REMOTE, LOCAL, 40_000, 1),
            start,
        ),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &udp_first_fragment(REMOTE_2, LOCAL, 40_001, 2),
            start + Duration::from_secs(1),
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::StateCapacity,
        }
    );
    assert_eq!(
        audit(&gate),
        (1, 1),
        "the failed first fragment left no flow"
    );
    let later = start + FRAGMENT_TIMEOUT + Duration::from_secs(1);
    assert!(matches!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &udp_first_fragment(REMOTE_2, LOCAL, 40_002, 3),
            later,
        ),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert_eq!(
        gate.evaluate_at(
            PacketDirection::Inbound,
            peer_2,
            &later_fragment(REMOTE_2, LOCAL, 3),
            later,
        ),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState,
        }
    );
    assert_eq!(audit(&gate), (2, 1));
}

#[test]
fn a_stale_snapshot_retries_instead_of_touching_migrated_state() {
    let gate = NodeL3Gate::new("machine-1");
    let policy = config(NodeL3Mode::Enforce, true);
    gate.apply(policy.clone()).unwrap();
    let stale = gate.snapshot.load_full();
    let mut withdrawn = policy;
    withdrawn.mode = NodeL3Mode::Disabled;
    gate.apply(withdrawn).unwrap();

    let packet = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    let input = PacketInput {
        direction: PacketDirection::Inbound,
        peer_key: PEER,
        packet: &packet,
        meta: PacketMeta::parse(&packet),
        now: Instant::now(),
        swept: false,
    };
    assert_eq!(gate.evaluate_once(&stale, &input), Step::Retry);
    assert_eq!(audit(&gate), (0, 0), "the stale allow created no state");
    assert_eq!(
        gate.evaluate_inbound(PEER, &packet),
        NodeL3Decision::Legacy,
        "the retry evaluates the current snapshot"
    );
    assert_eq!(
        gate.evaluate_once(&gate.snapshot.load(), &input),
        Step::Done(NodeL3Decision::Legacy)
    );
}

#[test]
fn authorization_changes_bump_the_generation_and_call_back() {
    let gate = NodeL3Gate::new("machine-1");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    gate.set_on_authorization_change(Box::new(move |generation| {
        record.lock().unwrap().push(generation);
    }));
    let policy = config(NodeL3Mode::Enforce, false);

    gate.apply_from_source("source-a", policy.clone()).unwrap();
    assert_eq!(gate.authorization_generation(), 1);
    gate.apply_from_source("source-a", policy).unwrap();
    gate.replace_provider_listeners(
        "machine-1",
        [("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443)],
    );
    assert_eq!(
        gate.authorization_generation(),
        1,
        "an idempotent replay and a listener change are not authorization changes"
    );
    gate.replace_transport_projection(&wg_projection(None))
        .unwrap();
    gate.stage_transport_projection(&wg_projection(None))
        .unwrap();
    gate.withdraw_transport_projection();
    assert_eq!(gate.withdraw_source("source-a"), Ok(1));
    assert_eq!(gate.withdraw_source("source-b"), Ok(0));
    assert_eq!(gate.authorization_generation(), 5);
    assert_eq!(*seen.lock().unwrap(), vec![1, 2, 3, 4, 5]);
}

#[test]
fn subnet_ingress_prefixes_enumerate_the_ingress_check() {
    let gate = NodeL3Gate::new("machine-1");
    let prefix: IpNet = "fd00:1:2:1:0:7:c0a8:700/120".parse().unwrap();
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-subnet".to_owned(),
        source_node_id: "node-remote".to_owned(),
        resource: NodeL3Resource::Subnet {
            subnet_id: "7".to_owned(),
            routing_node_id: "node-local".to_owned(),
            prefix,
        },
    });
    // The same edge under another logical Grant id is listed once.
    let mut duplicate = policy.grants[0].clone();
    duplicate.grant_id = "grant-subnet-2".to_owned();
    policy.grants.push(duplicate);
    gate.apply(policy.clone()).unwrap();
    assert_eq!(gate.enforced_subnet_ingress_prefixes(), Vec::new());

    let generation = gate.authorization_generation();
    gate.replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .unwrap();
    assert!(gate.authorization_generation() > generation);
    let prefixes = gate.enforced_subnet_ingress_prefixes();
    assert_eq!(prefixes, vec![(PEER, prefix)]);
    let destination: Ipv6Addr = "fd00:1:2:1:0:7:c0a8:70a".parse().unwrap();
    for (peer_key, prefix) in prefixes {
        assert!(prefix.contains(&destination.into()));
        assert!(gate.enforced_subnet_ingress_authorized(peer_key, destination));
    }

    policy.mode = NodeL3Mode::Disabled;
    gate.apply(policy).unwrap();
    assert_eq!(gate.enforced_subnet_ingress_prefixes(), Vec::new());
}

#[test]
fn reason_names_are_stable_and_one_to_one() {
    let reasons = [
        NodeL3Reason::Legacy,
        NodeL3Reason::ValidState,
        NodeL3Reason::SameOwner,
        NodeL3Reason::NodeGrant,
        NodeL3Reason::ServiceGrant,
        NodeL3Reason::SubnetGrant,
        NodeL3Reason::SourceBinding,
        NodeL3Reason::ReverseNewFlow,
        NodeL3Reason::NoGrant,
        NodeL3Reason::ServiceProjection,
        NodeL3Reason::PolicyPending,
        NodeL3Reason::OrphanFragment,
        NodeL3Reason::StateCapacity,
        NodeL3Reason::AmbiguousNetwork,
        NodeL3Reason::MalformedPacket,
    ];
    let names: HashSet<_> = reasons.iter().map(|reason| reason.as_str()).collect();
    let drops: HashSet<_> = reasons.iter().map(|reason| reason.drop_reason()).collect();
    assert_eq!(names.len(), reasons.len());
    assert_eq!(drops.len(), reasons.len());
    for reason in reasons {
        assert_eq!(
            reason.drop_reason(),
            format!("node l3: {}", reason.as_str().replace('_', " "))
        );
    }
    assert_eq!(NodeL3Reason::SourceBinding.as_str(), "source_binding");
    assert_eq!(
        NodeL3PeerReadinessReason::ObserveOwnerMismatch.as_str(),
        "observe_owner_mismatch"
    );
}

#[test]
fn config_serde_matches_the_control_plane_shape() {
    let mut policy = config(NodeL3Mode::Observe, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-subnet".to_owned(),
        source_node_id: "node-local".to_owned(),
        resource: NodeL3Resource::Subnet {
            subnet_id: "7".to_owned(),
            routing_node_id: "node-remote".to_owned(),
            prefix: "fd00:1:2:1:0:7:c0a8:700/120".parse().unwrap(),
        },
    });
    let json = serde_json::to_value(&policy).unwrap();
    assert_eq!(json["mode"], "observe");
    assert_eq!(json["grants"][0]["resource"]["kind"], "subnet");
    assert_eq!(
        json["grants"][0]["resource"]["prefix"],
        "fd00:1:2:1:0:7:c0a8:700/120"
    );
    assert_eq!(json["services"][0]["protocol"], "tcp");
    assert_eq!(
        serde_json::from_value::<NodeL3Config>(json).unwrap(),
        policy
    );
    let minimal = serde_json::json!({
        "schema_version": 1,
        "network_id": "n",
        "target_machine_id": "m",
        "generation": 1,
        "mode": "enforce",
        "local_node": {"node_id": "a", "owner_id": "o", "ip": "100.64.0.1"},
    });
    let parsed: NodeL3Config = serde_json::from_value(minimal).unwrap();
    assert!(parsed.bindings.is_empty() && parsed.grants.is_empty());
}

#[test]
fn the_gate_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NodeL3Gate>();
    assert_send_sync::<GatewayConsumerPacket>();
}
