use super::*;

#[test]
pub(super) fn related_icmp_error_requires_existing_flow_state() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-out".to_owned(),
        source_node_id: "node-local".to_owned(),
        resource: NodeL3Resource::Node {
            node_id: "node-remote".to_owned(),
        },
    });
    runtime.apply(policy).expect("config is valid");
    let original = udp(LOCAL, REMOTE, 50_000, 53);
    assert!(matches!(
        runtime.evaluate_outbound(PEER, &original),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert_eq!(
        runtime.evaluate_inbound(PEER, &icmp_error(REMOTE, LOCAL, &original)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState,
        }
    );

    let unknown = udp(LOCAL, REMOTE, 50_001, 53);
    assert_eq!(
        runtime.evaluate_inbound(PEER, &icmp_error(REMOTE, LOCAL, &unknown)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::ReverseNewFlow,
        }
    );

    let remote_other = Ipv4Addr::new(100, 64, 0, 3);
    let mut next = config(NodeL3Mode::Enforce, false);
    next.generation = 2;
    next.bindings.push(NodeL3PeerBinding {
        peer_public_key: PEER,
        node_id: "node-other".to_owned(),
        owner_id: "owner-other".to_owned(),
        ip: remote_other,
    });
    next.grants.push(NodeL3Grant {
        grant_id: "grant-other".to_owned(),
        source_node_id: "node-local".to_owned(),
        resource: NodeL3Resource::Node {
            node_id: "node-other".to_owned(),
        },
    });
    runtime.apply(next).expect("second remote Node is valid");
    let to_other = udp(LOCAL, remote_other, 50_002, 53);
    assert!(matches!(
        runtime.evaluate_outbound(PEER, &to_other),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert_eq!(
        runtime.evaluate_inbound(PEER, &icmp_error(REMOTE, LOCAL, &to_other)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::MalformedPacket,
        }
    );
}
#[test]
pub(super) fn fragments_require_an_authorized_first_fragment() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("config is valid");
    let id = 0x1234_u16;
    let mut first = udp(REMOTE, LOCAL, 40_000, 53);
    first[4..6].copy_from_slice(&id.to_be_bytes());
    first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &first),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert_eq!(
        runtime.evaluate_inbound(PEER, &later_fragment(REMOTE, LOCAL, id)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState,
        }
    );
    assert_eq!(
        runtime.evaluate_inbound(PEER, &later_fragment(REMOTE, LOCAL, id + 1)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::OrphanFragment,
        }
    );
}

#[test]
pub(super) fn fragment_capacity_failure_does_not_leave_authorized_flow_state() {
    let runtime = NodeL3Gate::with_limits("machine-1", 16, 16, 0);
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-inbound".to_owned(),
        source_node_id: "node-remote".to_owned(),
        resource: NodeL3Resource::Node {
            node_id: "node-local".to_owned(),
        },
    });
    runtime.apply(policy).expect("config is valid");

    let mut first = udp(REMOTE, LOCAL, 40_000, 53);
    first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    assert_eq!(
        runtime.evaluate_inbound(PEER, &first),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::StateCapacity,
        }
    );
    assert_eq!(
        runtime.evaluate_outbound(PEER, &udp(LOCAL, REMOTE, 53, 40_000)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::NoGrant,
        }
    );
}

#[test]
fn same_generation_cannot_change_security_content() {
    let runtime = NodeL3Gate::new("machine-1");
    let policy = config(NodeL3Mode::Enforce, true);
    runtime.apply(policy.clone()).expect("config is valid");
    runtime
        .apply(policy.clone())
        .expect("identical redelivery is idempotent");
    let mut changed = policy;
    changed.bindings[0].owner_id = "changed-owner".to_owned();
    assert_eq!(
        runtime.apply(changed),
        Err(NodeL3ConfigError::Conflict(
            "content for an already-applied generation"
        ))
    );
}

#[test]
fn same_generation_promotes_observe_to_enforce_but_never_regresses() {
    let runtime = NodeL3Gate::new("machine-1");
    let observe = config(NodeL3Mode::Observe, true);
    let observe_identity = observe.policy_identity();
    runtime.apply(observe.clone()).expect("observe applies");

    let mut enforce = observe;
    enforce.mode = NodeL3Mode::Enforce;
    let enforce_identity = enforce.policy_identity();
    assert_eq!(observe_identity, enforce_identity);
    runtime
        .apply(enforce.clone())
        .expect("phase promotion applies");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce { allow: true, .. }
    ));

    let mut regression = enforce;
    regression.mode = NodeL3Mode::Observe;
    assert_eq!(
        runtime.apply(regression),
        Err(NodeL3ConfigError::PhaseRegression { generation: 1 })
    );
}
