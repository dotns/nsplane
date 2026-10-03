use super::*;

#[test]
fn cross_owner_service_grant_does_not_open_node() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-service".to_owned(),
        source_node_id: "node-remote".to_owned(),
        resource: NodeL3Resource::Service {
            service_id: "service-web".to_owned(),
            node_id: "node-local".to_owned(),
            protocol: NodeL3ServiceProtocol::Tcp,
            port: 443,
        },
    });
    runtime.apply(policy).expect("service grant is valid");
    runtime.replace_provider_listeners(
        "machine-1",
        [("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443)],
    );

    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ServiceGrant
        }
    ));
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_001, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::NoGrant
        }
    ));
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_002, 444, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::NoGrant
        }
    ));
    runtime.replace_provider_listeners(
        "machine-1",
        std::iter::empty::<(String, NodeL3ServiceProtocol, u16)>(),
    );
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_003, 443, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::ServiceProjection
        }
    ));
}
#[test]
fn node_grant_opens_node_and_matching_service() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-node".to_owned(),
        source_node_id: "node-remote".to_owned(),
        resource: NodeL3Resource::Node {
            node_id: "node-local".to_owned(),
        },
    });
    runtime.apply(policy).expect("node grant is valid");

    for port in [22, 443] {
        assert!(matches!(
            runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000 + port, port, 0x02)),
            NodeL3Decision::Enforce {
                allow: true,
                reason: NodeL3Reason::NodeGrant
            }
        ));
    }
    assert!(runtime.service_flow_authorized(
        SocketAddrV4::new(REMOTE, 40_443).into(),
        SocketAddrV4::new(LOCAL, 443).into(),
        "machine-1",
        NodeL3ServiceProtocol::Tcp,
        "service-web",
    ));
}

#[test]
fn authenticated_peer_key_is_bound_to_inner_source() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("config is valid");
    let spoof = tcp(Ipv4Addr::new(100, 64, 0, 99), LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        runtime.evaluate_inbound(PEER, &spoof),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::SourceBinding,
        }
    );
}

#[test]
fn known_outbound_node_binding_rejects_a_spoofed_local_source() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("config is valid");
    let spoof = tcp(Ipv4Addr::new(192, 0, 2, 99), REMOTE, 40_000, 22, 0x02);
    assert_eq!(
        runtime.evaluate_outbound(PEER, &spoof),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::SourceBinding,
        }
    );
}

#[test]
fn service_vip_on_a_node_peer_remains_on_the_legacy_l4_path() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("config is valid");
    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("Node-only marker installs");

    assert_eq!(
        runtime.evaluate_outbound(PEER, &tcp(LOCAL, SERVICE_VIP, 40_000, 443, 0x02),),
        NodeL3Decision::Legacy,
        "a Service/Gateway /32 sharing the peer is not a Node L3 resource"
    );
}

#[test]
fn duplicate_service_routes_do_not_look_like_ambiguous_node_routes() {
    let runtime = NodeL3Gate::new("machine-1");
    let applied = runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("config is valid");
    let mut projection = wg_projection(Some((1, NodeL3Mode::Enforce)));
    let mut service_peer = projection.peers[0].clone();
    service_peer.public_key = [8; 32];
    service_peer.allowed_ips = vec![format!("{SERVICE_VIP}/32").parse().unwrap()];
    service_peer.node_l3_policy = None;
    projection.peers.push(service_peer);

    runtime
        .replace_transport_projection(&projection)
        .expect("non-Node Service routes may legitimately overlap");
    assert!(runtime.ready_for_ack(&applied));
}

#[test]
fn an_unmarked_duplicate_node_route_prevents_ack_readiness() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut projection = wg_projection(Some((1, NodeL3Mode::Enforce)));
    let mut duplicate_node_peer = projection.peers[0].clone();
    duplicate_node_peer.public_key = [8; 32];
    duplicate_node_peer.allowed_ips = vec![format!("{REMOTE}/32").parse().unwrap()];
    duplicate_node_peer.node_l3_policy = None;
    let duplicate_node_peer_key = duplicate_node_peer.public_key;
    projection.peers.push(duplicate_node_peer);

    runtime
        .replace_transport_projection(&projection)
        .expect("the runtime represents the actual ambiguous device projection");
    assert_eq!(
        runtime.evaluate_outbound(
            duplicate_node_peer_key,
            &tcp(LOCAL, REMOTE, 40_000, 22, 0x02),
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        },
        "an unmarked duplicate route cannot bypass the marked address before policy apply"
    );
    assert_eq!(
        runtime.evaluate_inbound(
            duplicate_node_peer_key,
            &tcp(REMOTE, LOCAL, 40_000, 22, 0x02),
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        },
        "an unmarked duplicate peer cannot inject the marked Node source before policy apply"
    );

    let applied = runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("config is valid");
    assert!(
        !runtime.ready_for_ack(&applied),
        "every actual route to a policy Node IP must use its exact marked peer binding"
    );
}

#[test]
fn peer_binding_cannot_redeclare_the_local_node_identity() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, true);
    policy.bindings.push(NodeL3PeerBinding {
        peer_public_key: [9; 32],
        node_id: "node-local".to_owned(),
        owner_id: "owner-local".to_owned(),
        ip: LOCAL,
    });
    assert_eq!(
        runtime.apply(policy),
        Err(NodeL3ConfigError::Conflict("local node peer binding"))
    );
}

#[test]
fn unknown_outbound_peer_for_local_source_fails_closed() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("config is valid");
    let packet = tcp(LOCAL, REMOTE, 40_000, 22, 0x02);
    assert_eq!(
        runtime.evaluate_outbound([8; 32], &packet),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::SourceBinding,
        }
    );
}

#[test]
fn one_logical_grant_may_expand_to_many_directed_edges() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.extend([
        NodeL3Grant {
            grant_id: "logical-acl-1".to_owned(),
            source_node_id: "node-remote".to_owned(),
            resource: NodeL3Resource::Node {
                node_id: "node-local".to_owned(),
            },
        },
        NodeL3Grant {
            grant_id: "logical-acl-1".to_owned(),
            source_node_id: "node-remote".to_owned(),
            resource: NodeL3Resource::Service {
                service_id: "service-web".to_owned(),
                node_id: "node-local".to_owned(),
                protocol: NodeL3ServiceProtocol::Tcp,
                port: 443,
            },
        },
        NodeL3Grant {
            grant_id: "logical-acl-1".to_owned(),
            source_node_id: "node-local".to_owned(),
            resource: NodeL3Resource::Node {
                node_id: "node-remote".to_owned(),
            },
        },
    ]);

    runtime
        .apply(policy)
        .expect("expanded edges may share logical provenance");
}

#[test]
pub(super) fn return_state_does_not_become_reverse_initiation() {
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

    let outbound_syn = tcp(LOCAL, REMOTE, 50_000, 8080, 0x02);
    assert!(matches!(
        runtime.evaluate_outbound(PEER, &outbound_syn),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::NodeGrant
        }
    ));
    let inbound_syn_ack = tcp(REMOTE, LOCAL, 8080, 50_000, 0x12);
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &inbound_syn_ack),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState
        }
    ));
    let same_tuple_reverse_syn = tcp(REMOTE, LOCAL, 8080, 50_000, 0x02);
    assert_eq!(
        runtime.evaluate_inbound(PEER, &same_tuple_reverse_syn),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::ReverseNewFlow,
        },
        "a direction-independent return-state key must not authorize a reverse bare SYN"
    );
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &inbound_syn_ack),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState
        }
    ));
    let reverse_new = tcp(REMOTE, LOCAL, 8081, 50_001, 0x02);
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &reverse_new),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::NoGrant
        }
    ));
}

#[test]
pub(super) fn terminal_tcp_state_cannot_be_recycled_by_a_new_syn() {
    for terminal_flags in [0x11, 0x04] {
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

        assert!(matches!(
            runtime.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 50_000, 8080, 0x02)),
            NodeL3Decision::Enforce { allow: true, .. }
        ));
        assert!(matches!(
            runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 8080, 50_000, 0x12)),
            NodeL3Decision::Enforce { allow: true, .. }
        ));
        assert!(matches!(
            runtime.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 50_000, 8080, terminal_flags),),
            NodeL3Decision::Enforce { allow: true, .. }
        ));
        assert_eq!(
            runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 8080, 50_000, 0x02),),
            NodeL3Decision::Enforce {
                allow: false,
                reason: NodeL3Reason::ReverseNewFlow,
            }
        );
    }
}

#[test]
pub(super) fn final_ack_does_not_extend_a_terminal_tcp_flow() {
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
    let start = Instant::now();

    assert!(matches!(
        runtime.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &tcp(LOCAL, REMOTE, 50_000, 8080, 0x02),
            start,
        ),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert!(matches!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &tcp(REMOTE, LOCAL, 8080, 50_000, 0x12),
            start + Duration::from_secs(1),
        ),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert!(matches!(
        runtime.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &tcp(LOCAL, REMOTE, 50_000, 8080, 0x11),
            start + Duration::from_secs(2),
        ),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    // The peer may continue sending data during a bounded half-close.
    assert!(matches!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &tcp(REMOTE, LOCAL, 8080, 50_000, 0x10),
            start + Duration::from_secs(3),
        ),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert!(matches!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            PEER,
            &tcp(REMOTE, LOCAL, 8080, 50_000, 0x11),
            start + Duration::from_secs(4),
        ),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert!(matches!(
        runtime.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &tcp(LOCAL, REMOTE, 50_000, 8080, 0x10),
            start + Duration::from_secs(5),
        ),
        NodeL3Decision::Enforce { allow: true, .. }
    ));

    assert_eq!(
        runtime.evaluate_at(
            PacketDirection::Outbound,
            PEER,
            &tcp(LOCAL, REMOTE, 50_000, 8080, 0x02),
            start + Duration::from_secs(35),
        ),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::NodeGrant,
        },
        "after the bounded terminal tail, the same tuple is evaluated as a fresh authorized flow"
    );
}

#[test]
pub(super) fn generation_change_revokes_existing_state() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-node".to_owned(),
        source_node_id: "node-remote".to_owned(),
        resource: NodeL3Resource::Node {
            node_id: "node-local".to_owned(),
        },
    });
    runtime.apply(policy.clone()).expect("config is valid");
    let _ = runtime.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 40_000, 53));

    policy.generation = 2;
    policy.grants.clear();
    runtime.apply(policy).expect("new generation is valid");
    assert!(matches!(
        runtime.evaluate_outbound(PEER, &udp(LOCAL, REMOTE, 53, 40_000)),
        NodeL3Decision::Enforce { allow: false, .. }
    ));
}

#[test]
fn unchanged_authorization_rekeys_live_flow_to_the_new_generation() {
    let runtime = NodeL3Gate::new("machine-1");
    let policy = config(NodeL3Mode::Enforce, true);
    runtime.apply(policy.clone()).expect("config is valid");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::SameOwner,
        }
    ));

    let mut next = policy;
    next.generation = 2;
    runtime.apply(next).expect("new generation is valid");
    assert_eq!(
        runtime.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 22, 40_000, 0x10)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState,
        }
    );
}

#[test]
fn unchanged_node_grant_rekeys_live_flow_to_the_new_generation() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-node".to_owned(),
        source_node_id: "node-remote".to_owned(),
        resource: NodeL3Resource::Node {
            node_id: "node-local".to_owned(),
        },
    });
    runtime.apply(policy.clone()).expect("config is valid");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::NodeGrant,
        }
    ));

    policy.generation = 2;
    runtime.apply(policy).expect("new generation is valid");
    assert_eq!(
        runtime.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 22, 40_000, 0x10)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState,
        }
    );
}

#[test]
fn unchanged_exact_listener_and_service_grant_preserve_live_flow() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-service".to_owned(),
        source_node_id: "node-remote".to_owned(),
        resource: NodeL3Resource::Service {
            service_id: "service-web".to_owned(),
            node_id: "node-local".to_owned(),
            protocol: NodeL3ServiceProtocol::Tcp,
            port: 443,
        },
    });
    runtime.replace_provider_listeners(
        "machine-1",
        [("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443)],
    );
    runtime.apply(policy.clone()).expect("config is valid");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ServiceGrant,
        }
    ));

    // Idempotent Provider refresh must not clear Exact flow state.
    runtime.replace_provider_listeners(
        "machine-1",
        [("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443)],
    );
    policy.generation = 2;
    runtime.apply(policy).expect("new generation is valid");
    assert_eq!(
        runtime.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 443, 40_000, 0x10)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState,
        }
    );
}

#[test]
pub(super) fn partial_listener_change_revokes_only_changed_exact_flows() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.services.push(NodeL3ServiceEndpoint {
        service_id: "service-admin".to_owned(),
        node_id: "node-local".to_owned(),
        protocol: NodeL3ServiceProtocol::Tcp,
        port: 8443,
    });
    for (id, port) in [("service-web", 443), ("service-admin", 8443)] {
        policy.grants.push(NodeL3Grant {
            grant_id: format!("grant-{id}"),
            source_node_id: "node-remote".to_owned(),
            resource: NodeL3Resource::Service {
                service_id: id.to_owned(),
                node_id: "node-local".to_owned(),
                protocol: NodeL3ServiceProtocol::Tcp,
                port,
            },
        });
    }
    runtime.replace_provider_listeners(
        "machine-1",
        [
            ("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443),
            ("service-admin".to_owned(), NodeL3ServiceProtocol::Tcp, 8443),
        ],
    );
    runtime.apply(policy).expect("config is valid");
    let _ = runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 443, 0x02));
    let _ = runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_001, 8443, 0x02));

    runtime.replace_provider_listeners(
        "machine-1",
        [("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443)],
    );
    assert!(matches!(
        runtime.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 443, 40_000, 0x10)),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert_eq!(
        runtime.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 8443, 40_001, 0x10)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::ReverseNewFlow,
        }
    );
}

#[test]
fn local_listener_change_preserves_outbound_remote_service_flow() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.services.push(NodeL3ServiceEndpoint {
        service_id: "service-remote".to_owned(),
        node_id: "node-remote".to_owned(),
        protocol: NodeL3ServiceProtocol::Tcp,
        port: 8443,
    });
    policy.grants.push(NodeL3Grant {
        grant_id: "grant-remote-service".to_owned(),
        source_node_id: "node-local".to_owned(),
        resource: NodeL3Resource::Service {
            service_id: "service-remote".to_owned(),
            node_id: "node-remote".to_owned(),
            protocol: NodeL3ServiceProtocol::Tcp,
            port: 8443,
        },
    });
    runtime.replace_provider_listeners(
        "machine-1",
        [("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443)],
    );
    runtime.apply(policy).expect("config is valid");
    assert_eq!(
        runtime.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 40_000, 8443, 0x02)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ServiceGrant,
        }
    );

    // Withdrawing an unrelated local Provider listener must not revoke a
    // flow whose Exact authorization names a Service on the remote Node.
    runtime.replace_provider_listeners("machine-1", []);
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 8443, 40_000, 0x10)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::ValidState,
        }
    );
}

#[test]
fn explicit_withdrawal_revokes_policy_state_but_retains_source_tombstone() {
    let runtime = NodeL3Gate::new_for_targets(["machine-1".to_owned(), "machine-2".to_owned()]);
    let policy = config(NodeL3Mode::Enforce, true);
    runtime
        .apply_from_source("source-a", policy.clone())
        .expect("policy applies");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_001, 443, 0x02)),
        NodeL3Decision::Enforce { allow: true, .. }
    ));
    assert!(runtime.service_flow_authorized(
        SocketAddrV4::new(REMOTE, 40_001).into(),
        SocketAddrV4::new(LOCAL, 443).into(),
        "machine-1",
        NodeL3ServiceProtocol::Tcp,
        "service-web",
    ));

    let mut withdrawn = policy;
    withdrawn.mode = NodeL3Mode::Disabled;
    runtime
        .apply_from_source("source-a", withdrawn)
        .expect("authoritative source may withdraw");
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_001, 443, 0x02)),
        NodeL3Decision::Legacy
    );
    assert!(!runtime.service_flow_authorized(
        SocketAddrV4::new(REMOTE, 40_001).into(),
        SocketAddrV4::new(LOCAL, 443).into(),
        "machine-1",
        NodeL3ServiceProtocol::Tcp,
        "service-web",
    ));

    let mut takeover = config(NodeL3Mode::Enforce, true);
    takeover.target_machine_id = "machine-2".to_owned();
    takeover.generation = 2;
    assert!(matches!(
        runtime.apply_from_source("source-b", takeover),
        Err(NodeL3ConfigError::AuthorityConflict { .. })
    ));
}

#[test]
fn source_revocation_withdraws_last_accepted_policy_after_rejected_raw_frames() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut accepted = config(NodeL3Mode::Enforce, true);
    accepted.generation = 10;
    runtime
        .apply_from_source("source-a", accepted.clone())
        .expect("generation ten applies");
    let _ = runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_001, 443, 0x02));

    let mut stale = accepted.clone();
    stale.generation = 9;
    assert!(matches!(
        runtime.apply_from_source("source-a", stale),
        Err(NodeL3ConfigError::StaleGeneration { .. })
    ));

    let mut wrong_target = accepted.clone();
    wrong_target.generation = 11;
    wrong_target.target_machine_id = "machine-2".to_owned();
    assert!(matches!(
        runtime.apply_from_source("source-a", wrong_target),
        Err(NodeL3ConfigError::WrongTarget { .. })
    ));

    let mut unsupported = accepted.clone();
    unsupported.generation = 11;
    unsupported.schema_version = NODE_L3_SCHEMA_VERSION + 1;
    assert!(matches!(
        runtime.apply_from_source("source-a", unsupported),
        Err(NodeL3ConfigError::UnsupportedSchema(_))
    ));

    assert_eq!(
        runtime
            .withdraw_source("source-a")
            .expect("source withdrawal"),
        1
    );
    assert!(runtime.snapshot.load().policies.is_empty());
    assert!(!runtime.service_flow_authorized(
        SocketAddrV4::new(REMOTE, 40_001).into(),
        SocketAddrV4::new(LOCAL, 443).into(),
        "machine-1",
        NodeL3ServiceProtocol::Tcp,
        "service-web",
    ));
    let writer = runtime.lock_writer();
    let tombstone = writer
        .tombstones
        .get("network-1")
        .expect("source tombstone remains");
    assert_eq!(tombstone.generation, 10);
    assert_eq!(tombstone.mode, NodeL3Mode::Disabled);
    drop(writer);
    assert!(matches!(
        runtime.apply_from_source("source-a", accepted),
        Err(NodeL3ConfigError::Conflict(_))
    ));
}

#[test]
fn withdrawal_tombstone_rejects_stale_and_same_generation_resurrection() {
    let runtime = NodeL3Gate::new("machine-1");
    let mut policy = config(NodeL3Mode::Enforce, true);
    policy.generation = 5;
    runtime
        .apply_from_source("source-a", policy.clone())
        .expect("generation five applies");

    let mut withdrawn = policy.clone();
    withdrawn.mode = NodeL3Mode::Disabled;
    runtime
        .apply_from_source("source-a", withdrawn)
        .expect("withdrawal applies");

    let mut stale = policy.clone();
    stale.generation = 1;
    assert_eq!(
        runtime.apply_from_source("source-a", stale),
        Err(NodeL3ConfigError::StaleGeneration {
            applied: 5,
            actual: 1,
        })
    );
    assert_eq!(
        runtime.apply_from_source("source-a", policy.clone()),
        Err(NodeL3ConfigError::Conflict(
            "content for an already-withdrawn generation"
        ))
    );

    policy.generation = 6;
    runtime
        .apply_from_source("source-a", policy)
        .expect("only a newer generation may re-enable");
}

#[test]
fn a_second_control_source_cannot_take_over_the_same_network() {
    let runtime = NodeL3Gate::new_for_targets(["machine-1".to_owned(), "machine-2".to_owned()]);
    runtime
        .apply_from_source("source-a", config(NodeL3Mode::Enforce, true))
        .expect("first authenticated source claims the Network");

    let mut contender = config(NodeL3Mode::Enforce, true);
    contender.target_machine_id = "machine-2".to_owned();
    contender.generation = 99;
    assert_eq!(
        runtime.apply_from_source("source-b", contender),
        Err(NodeL3ConfigError::AuthorityConflict {
            network_id: "network-1".to_owned(),
            applied_source: "source-a".to_owned(),
            actual_source: "source-b".to_owned(),
        })
    );

    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::SameOwner,
        }
    ));
}

#[test]
fn independent_sources_can_own_different_networks() {
    let runtime = NodeL3Gate::new_for_targets(["machine-1".to_owned(), "machine-2".to_owned()]);
    runtime
        .apply_from_source("source-a", config(NodeL3Mode::Enforce, true))
        .expect("source A Network applies");

    let local_b = Ipv4Addr::new(100, 65, 0, 1);
    let remote_b = Ipv4Addr::new(100, 65, 0, 2);
    let peer_b = [8; 32];
    let mut network_b = config(NodeL3Mode::Enforce, true);
    network_b.network_id = "network-2".to_owned();
    network_b.target_machine_id = "machine-2".to_owned();
    network_b.local_node.node_id = "node-local-b".to_owned();
    network_b.local_node.ip = local_b;
    network_b.bindings[0].peer_public_key = peer_b;
    network_b.bindings[0].node_id = "node-remote-b".to_owned();
    network_b.bindings[0].ip = remote_b;
    network_b.services[0].node_id = "node-local-b".to_owned();
    runtime
        .apply_from_source("source-b", network_b)
        .expect("source B's distinct Network applies");

    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::SameOwner,
        }
    ));
    assert!(matches!(
        runtime.evaluate_inbound(peer_b, &tcp(remote_b, local_b, 40_001, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::SameOwner,
        }
    ));
}
