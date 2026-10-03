use super::*;

/// Stand-in for ns's `tokio::sync::watch` receiver over
/// [`NodeL3Gate::authorization_generation`].
struct Changes<'a> {
    gate: &'a NodeL3Gate,
    seen: u64,
}

impl<'a> Changes<'a> {
    fn new(gate: &'a NodeL3Gate) -> Self {
        Self {
            gate,
            seen: gate.authorization_generation(),
        }
    }

    fn has_changed(&self) -> bool {
        self.gate.authorization_generation() != self.seen
    }

    fn borrow_and_update(&mut self) {
        self.seen = self.gate.authorization_generation();
    }
}

#[test]
fn subnet_authorization_requires_exact_enforced_peer_and_withdraws() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut changes = Changes::new(&runtime);
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-subnet".to_owned(),
        source_node_id: "node-local".to_owned(),
        resource: NodeL3Resource::Subnet {
            subnet_id: "7".to_owned(),
            routing_node_id: "node-remote".to_owned(),
            prefix: "fd00:1:2:1:0:7:c0a8:700/120"
                .parse()
                .expect("test prefix is valid"),
        },
    });
    runtime.apply(policy.clone()).expect("Subnet Grant applies");
    assert!(changes.has_changed());
    changes.borrow_and_update();
    assert_eq!(runtime.enforced_subnet_authorizations(), Vec::new());

    runtime
        .stage_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("exact transport projection stages");
    assert!(changes.has_changed());
    changes.borrow_and_update();
    assert_eq!(runtime.enforced_subnet_authorizations(), Vec::new());

    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("exact transport projection installs");
    assert!(changes.has_changed());
    changes.borrow_and_update();
    assert_eq!(
        runtime.enforced_subnet_authorizations(),
        vec![NodeL3SubnetAuthorization {
            source_id: "target:machine-1".to_owned(),
            network_id: "network-1".to_owned(),
            generation: 1,
            grant_id: "grant-subnet".to_owned(),
            subnet_id: 7,
            routing_node_id: "node-remote".to_owned(),
            prefix: "fd00:1:2:1:0:7:c0a8:700/120"
                .parse()
                .expect("test prefix is valid"),
            peer_key: PEER,
        }]
    );

    let mut withdrawn = policy;
    withdrawn.mode = NodeL3Mode::Disabled;
    runtime.apply(withdrawn).expect("withdrawal applies");
    assert!(changes.has_changed());
    assert_eq!(runtime.enforced_subnet_authorizations(), Vec::new());
}

#[test]
fn subnet_ingress_requires_exact_source_peer_and_local_routing_grant() {
    let runtime = NodeL3Gate::new("machine-1");
    let prefix: IpNet = "fd00:1:2:1:0:7:c0a8:700/120"
        .parse()
        .expect("test prefix is valid");
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
    runtime.apply(policy.clone()).expect("Subnet Grant applies");
    let destination: Ipv6Addr = "fd00:1:2:1:0:7:c0a8:70a"
        .parse()
        .expect("mapped destination is valid");
    assert!(!runtime.enforced_subnet_ingress_authorized(PEER, destination));
    let return_identity: Ipv6Addr = "fd00:1:2:2::6440:2"
        .parse()
        .expect("return identity is valid");
    assert_eq!(
        runtime.enforced_subnet_return_peer_key(return_identity),
        None
    );

    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("exact transport projection installs");
    assert!(runtime.enforced_subnet_ingress_authorized(PEER, destination));
    assert_eq!(
        runtime.enforced_subnet_return_peer_key(return_identity),
        Some(PEER)
    );
    assert_eq!(
        runtime.enforced_subnet_return_peer_key(
            "fd00:1:3:2::6440:2"
                .parse()
                .expect("foreign return identity is valid")
        ),
        None
    );
    assert!(!runtime.enforced_subnet_ingress_authorized([8; 32], destination));
    assert!(
        !runtime.enforced_subnet_ingress_authorized(
            PEER,
            "fd00:1:2:1:0:8:c0a8:70a"
                .parse()
                .expect("other mapped destination is valid")
        )
    );

    policy.mode = NodeL3Mode::Disabled;
    runtime.apply(policy).expect("withdrawal applies");
    assert!(!runtime.enforced_subnet_ingress_authorized(PEER, destination));
    assert_eq!(
        runtime.enforced_subnet_return_peer_key(return_identity),
        None
    );
}

#[test]
pub(super) fn subnet_return_owners_enumerate_the_return_peer_lookup() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut changes = Changes::new(&runtime);
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-subnet".to_owned(),
        source_node_id: "node-remote".to_owned(),
        resource: NodeL3Resource::Subnet {
            subnet_id: "7".to_owned(),
            routing_node_id: "node-local".to_owned(),
            prefix: "fd00:1:2:1:0:7:c0a8:700/120"
                .parse()
                .expect("test prefix is valid"),
        },
    });
    // A Grant this Node consumes rather than routes has no return identity here.
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-subnet-consumed".to_owned(),
        source_node_id: "node-local".to_owned(),
        resource: NodeL3Resource::Subnet {
            subnet_id: "8".to_owned(),
            routing_node_id: "node-remote".to_owned(),
            prefix: "fd00:1:3:1:0:8:c0a8:800/120"
                .parse()
                .expect("test prefix is valid"),
        },
    });
    runtime.apply(policy.clone()).expect("Subnet Grant applies");
    assert_eq!(runtime.enforced_subnet_return_owners(), Vec::new());

    changes.borrow_and_update();
    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("exact transport projection installs");
    assert!(changes.has_changed());
    let return_identity: Ipv6Addr = "fd00:1:2:2::6440:2"
        .parse()
        .expect("return identity is valid");
    let owners = runtime.enforced_subnet_return_owners();
    assert_eq!(owners, vec![(return_identity, PEER)]);
    for (identity, owner) in &owners {
        assert_eq!(
            runtime.enforced_subnet_return_peer_key(*identity),
            Some(*owner)
        );
    }

    changes.borrow_and_update();
    runtime.withdraw_transport_projection();
    assert!(changes.has_changed());
    assert_eq!(runtime.enforced_subnet_return_owners(), Vec::new());
    assert_eq!(
        runtime.enforced_subnet_return_peer_key(return_identity),
        None
    );

    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("exact transport projection installs");
    changes.borrow_and_update();
    policy.mode = NodeL3Mode::Disabled;
    runtime.apply(policy).expect("withdrawal applies");
    assert!(changes.has_changed());
    assert_eq!(runtime.enforced_subnet_return_owners(), Vec::new());
}

#[test]
pub(super) fn subnet_transport_requires_exact_directed_grant_and_preserves_reply_state() {
    const PORT: u16 = 53_535;
    let consumer = NodeL3Gate::new("machine-1");
    let mut outbound = config(NodeL3Mode::Enforce, false);
    outbound.grants.push(NodeL3Grant {
        grant_id: "grant-subnet-outbound".to_owned(),
        source_node_id: "node-local".to_owned(),
        resource: NodeL3Resource::Subnet {
            subnet_id: "7".to_owned(),
            routing_node_id: "node-remote".to_owned(),
            prefix: "fd00:1:2:1:0:7:c0a8:700/120"
                .parse()
                .expect("test prefix is valid"),
        },
    });
    consumer.apply(outbound).expect("Subnet Grant applies");
    consumer
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("exact transport projection installs");

    assert!(!consumer.evaluate_subnet_transport_outbound(
        [8; 32],
        &udp(LOCAL, REMOTE, 40_000, PORT),
        PORT,
    ));
    assert!(!consumer.evaluate_subnet_transport_outbound(
        PEER,
        &udp(LOCAL, REMOTE, 40_000, PORT + 1),
        PORT,
    ));
    assert!(consumer.evaluate_subnet_transport_outbound(
        PEER,
        &udp(LOCAL, REMOTE, 40_000, PORT),
        PORT,
    ));
    assert_eq!(
        consumer.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, PORT, 40_000)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState,
        }
    );

    let publisher = NodeL3Gate::new("machine-1");
    let mut inbound = config(NodeL3Mode::Enforce, false);
    inbound.grants.push(NodeL3Grant {
        grant_id: "grant-subnet-inbound".to_owned(),
        source_node_id: "node-remote".to_owned(),
        resource: NodeL3Resource::Subnet {
            subnet_id: "7".to_owned(),
            routing_node_id: "node-local".to_owned(),
            prefix: "fd00:1:2:1:0:7:c0a8:700/120"
                .parse()
                .expect("test prefix is valid"),
        },
    });
    publisher.apply(inbound).expect("Subnet Grant applies");
    publisher
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("exact transport projection installs");
    assert!(publisher.evaluate_subnet_transport_inbound(
        PEER,
        &udp(REMOTE, LOCAL, 40_000, PORT),
        PORT,
    ));
    assert_eq!(
        publisher.evaluate_outbound(PEER, &udp(LOCAL, REMOTE, PORT, 40_000)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState,
        }
    );
}

#[test]
fn subnet_snapshot_rejects_raw_cidr_and_noncanonical_id() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-subnet".to_owned(),
        source_node_id: "node-local".to_owned(),
        resource: NodeL3Resource::Subnet {
            subnet_id: "07".to_owned(),
            routing_node_id: "node-remote".to_owned(),
            prefix: "10.0.0.0/24".parse().expect("test prefix is valid"),
        },
    });
    assert_eq!(
        runtime.apply(policy.clone()),
        Err(NodeL3ConfigError::InvalidSubnetId("07".to_owned()))
    );
    if let NodeL3Resource::Subnet { subnet_id, .. } = &mut policy.grants[0].resource {
        *subnet_id = "7".to_owned();
    }
    assert_eq!(
        runtime.apply(policy),
        Err(NodeL3ConfigError::InvalidSubnetPrefix(
            "10.0.0.0/24".parse().expect("test prefix is valid")
        ))
    );
}

#[test]
fn observe_mode_preserves_legacy_verdict() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Observe, false))
        .expect("config is valid");
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Observe {
            would_allow: false,
            reason: NodeL3Reason::NoGrant,
        }
    );
}

#[test]
pub(super) fn state_capacity_fails_closed_without_eviction() {
    let runtime = NodeL3Gate::with_limits("machine-1", 1, 1, DEFAULT_FRAGMENT_LIMIT);
    runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("config is valid");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53)),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert_eq!(
        runtime.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_001, 53)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::StateCapacity,
        }
    );
}
