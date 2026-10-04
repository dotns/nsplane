use super::*;

#[test]
fn same_owner_can_open_node_and_service_flows() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("same-owner config is valid");

    let node_syn = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        runtime.evaluate_inbound(PEER, &node_syn),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::SameOwner,
        }
    );
    let service_syn = tcp(REMOTE, LOCAL, 40_001, 443, 0x02);
    assert_eq!(
        runtime.evaluate_inbound(PEER, &service_syn),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::SameOwner,
        }
    );
    assert!(runtime.service_flow_authorized(
        SocketAddrV4::new(REMOTE, 40_001).into(),
        SocketAddrV4::new(LOCAL, 443).into(),
        "machine-1",
        NodeL3ServiceProtocol::Tcp,
        "service-web",
    ));
}
#[test]
fn authoritative_wg_peer_fails_closed_until_matching_snapshot_is_applied() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .stage_transport_projection(&wg_projection(Some((1, NodeL3Mode::Observe))))
        .unwrap();
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        }
    );
    assert_eq!(
        runtime.evaluate_inbound(
            PEER,
            &tcp(Ipv4Addr::new(192, 0, 2, 99), LOCAL, 40_001, 22, 0x02),
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        },
        "a marked peer cannot bypass a pending policy by spoofing inner source"
    );
    assert_eq!(
        runtime.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 22, 40_000, 0x10)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        }
    );
    assert_eq!(
        runtime.evaluate_outbound(PEER, &tcp(LOCAL, SERVICE_VIP, 40_002, 443, 0x02)),
        NodeL3Decision::Legacy,
        "a Service/Gateway IP on the same peer is not implicitly L3-authoritative"
    );

    let applied = runtime
        .apply(config(NodeL3Mode::Observe, true))
        .expect("matching observe snapshot applies");
    assert!(!runtime.ready_for_ack(&applied));
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        }
    );
    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Observe))))
        .unwrap();
    assert!(runtime.ready_for_ack(&applied));
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Observe {
            would_allow: true,
            reason: NodeL3Reason::SameOwner,
        }
    );
}

#[test]
fn marked_peer_skipped_by_device_build_never_satisfies_readiness() {
    let runtime = NodeL3Gate::new("machine-1");
    let desired = wg_projection(Some((1, NodeL3Mode::Observe)));
    runtime
        .stage_transport_projection(&desired)
        .expect("desired marker stages");
    let applied = runtime
        .apply(config(NodeL3Mode::Observe, true))
        .expect("matching policy applies");
    let installed = empty_projection();
    runtime
        .replace_transport_projection_after_build(&desired, &installed)
        .expect("an empty device projection is represented exactly");

    assert!(
        !runtime.ready_for_ack(&applied),
        "a desired marked peer absent from the actual device cannot fulfill ACK readiness"
    );
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        }
    );
}

#[test]
fn staging_a_removal_keeps_the_old_peer_fail_closed_until_device_swap() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Observe, true))
        .expect("observe policy applies");
    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Observe))))
        .expect("old device projection installs");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Observe {
            would_allow: true,
            ..
        }
    ));

    runtime
        .stage_transport_projection(&empty_projection())
        .expect("peer removal stages");
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        },
        "the old device can still deliver between staging and abort"
    );
}

#[test]
fn staging_a_local_ip_change_keeps_the_old_device_destination_fail_closed() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("old A device projection installs");

    let next_local = Ipv4Addr::new(100, 64, 0, 9);
    let mut next_policy = config(NodeL3Mode::Enforce, false);
    next_policy.generation = 2;
    next_policy.local_node.ip = next_local;
    runtime
        .apply(next_policy)
        .expect("the B-address policy arrives before its device");

    let old_device_packet = tcp(REMOTE, LOCAL, 40_000, 22, 0x02);
    assert_eq!(
        runtime.evaluate_inbound(PEER, &old_device_packet),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        },
        "the installed A device is pending after policy moves to B"
    );

    let mut next_projection = wg_projection(Some((2, NodeL3Mode::Enforce)));
    next_projection.local_ip = next_local;
    runtime
        .stage_transport_projection(&next_projection)
        .expect("B device projection stages before A aborts");
    assert_eq!(
        runtime.evaluate_inbound(PEER, &old_device_packet),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        },
        "staging B must retain A destination authority until the old device is aborted"
    );
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, next_local, 40_001, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        },
        "the staged B destination is pending until the replacement installs"
    );
}

#[test]
fn stopping_the_device_keeps_authoritative_peers_fail_closed() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Observe, true))
        .expect("observe policy applies");
    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Observe))))
        .expect("device projection installs");

    runtime.withdraw_transport_projection();
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        }
    );
}

#[test]
fn old_nsd_unmarked_wg_peer_remains_legacy_compatible() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .replace_transport_projection(&wg_projection(None))
        .unwrap();
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Legacy
    );
}

#[test]
fn explicit_gateway_carrier_delegates_only_the_exact_provider_listener_to_l4() {
    let runtime = NodeL3Gate::new_for_targets(["machine-1".to_owned(), "machine-other".to_owned()]);
    runtime
        .apply(config(NodeL3Mode::Enforce, false))
        .expect("Enforce policy applies");
    runtime.replace_provider_listeners(
        "machine-other",
        [("wrong-target".to_owned(), NodeL3ServiceProtocol::Tcp, 443)],
    );
    runtime
        .replace_transport_projection(&gateway_projection(Some("gateway-public")))
        .expect("explicit gateway projection installs");
    let public_source = Ipv4Addr::new(198, 51, 100, 24);

    assert_eq!(
        runtime.evaluate_inbound([9; 32], &tcp(public_source, LOCAL, 50_000, 443, 0x02),),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::SourceBinding,
        },
        "a listener owned by another authenticated target cannot open this target"
    );

    runtime.replace_provider_listeners(
        "machine-1",
        [
            ("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443),
            ("service-dns".to_owned(), NodeL3ServiceProtocol::Udp, 53),
        ],
    );
    assert_eq!(
        runtime.evaluate_inbound([9; 32], &tcp(public_source, LOCAL, 50_001, 443, 0x02),),
        NodeL3Decision::Legacy,
        "the exact TCP Provider listener must reach the existing L4 PEP"
    );
    assert_eq!(
        runtime.evaluate_inbound([9; 32], &udp(public_source, LOCAL, 50_002, 53)),
        NodeL3Decision::Legacy,
        "the exact UDP Provider listener must reach the existing L4 PEP"
    );

    for packet in [
        tcp(public_source, LOCAL, 50_003, 22, 0x02),
        tcp(public_source, LOCAL, 50_004, 53, 0x02),
        udp(public_source, LOCAL, 50_005, 443),
    ] {
        assert_eq!(
            runtime.evaluate_inbound([9; 32], &packet),
            NodeL3Decision::Enforce {
                allow: false,
                reason: NodeL3Reason::SourceBinding,
            },
            "gateway carrier access stays scoped to the exact protocol and port"
        );
    }
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(public_source, LOCAL, 50_006, 443, 0x02),),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::SourceBinding,
        },
        "a Node peer cannot inherit gateway-carrier trust"
    );
    assert_eq!(
        runtime.evaluate_inbound([8; 32], &tcp(public_source, LOCAL, 50_007, 443, 0x02),),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::SourceBinding,
        },
        "an unknown peer cannot inherit gateway-carrier trust"
    );
}

/// Raw-port, capacity, expiry and carrier-epoch part of
/// [`gateway_legacy_l4_fragment_delegation_is_exact_and_bounded_for_tcp_and_udp`].
fn assert_legacy_l4_fragment_authority_is_bounded(
    runtime: &NodeL3Gate,
    now: Instant,
    public_source: Ipv4Addr,
    (tcp_id, udp_id, overflow_id, raw_port_id): (u16, u16, u16, u16),
) {
    let raw_first = first_fragment(tcp(public_source, LOCAL, 50_002, 22, 0x02), raw_port_id);
    assert_eq!(
        runtime.evaluate_at(PacketDirection::Inbound, [9; 32], &raw_first, now),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::SourceBinding,
        },
        "a raw Node port cannot create legacy-L4 fragment authority"
    );
    assert_eq!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            [9; 32],
            &later_fragment_for_protocol(public_source, LOCAL, raw_port_id, 6),
            now,
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::OrphanFragment,
        }
    );

    let overflow_first = first_fragment(tcp(public_source, LOCAL, 50_003, 443, 0x02), overflow_id);
    assert_eq!(
        runtime.evaluate_at(PacketDirection::Inbound, [9; 32], &overflow_first, now),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::StateCapacity,
        },
        "the bounded fragment table fails closed at capacity"
    );
    assert_eq!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            [9; 32],
            &later_fragment_for_protocol(public_source, LOCAL, overflow_id, 6),
            now,
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::OrphanFragment,
        },
        "capacity failure cannot leave partial delegation state"
    );

    assert_eq!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            [9; 32],
            &later_fragment_for_protocol(public_source, LOCAL, tcp_id, 6),
            now + FRAGMENT_TIMEOUT,
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::OrphanFragment,
        },
        "legacy-L4 fragment authority expires after 30 seconds"
    );
    assert_eq!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            [9; 32],
            &later_fragment_for_protocol(public_source, LOCAL, udp_id, 17),
            now + FRAGMENT_TIMEOUT,
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::OrphanFragment,
        }
    );
    assert_eq!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            [9; 32],
            &overflow_first,
            now + FRAGMENT_TIMEOUT + Duration::from_secs(1),
        ),
        NodeL3Decision::Legacy,
        "expired entries release bounded capacity"
    );

    let gateway = gateway_projection(Some("gateway-public"));
    runtime
        .stage_transport_projection(&gateway)
        .expect("a replacement gateway projection stages");
    runtime
        .replace_transport_projection(&gateway)
        .expect("the replacement gateway projection installs");
    assert_eq!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            [9; 32],
            &later_fragment_for_protocol(public_source, LOCAL, overflow_id, 6),
            now + FRAGMENT_TIMEOUT + Duration::from_secs(2),
        ),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::OrphanFragment,
        },
        "a new carrier projection cannot revive prior fragment delegation"
    );
}

#[test]
pub(super) fn gateway_legacy_l4_fragment_delegation_is_exact_and_bounded_for_tcp_and_udp() {
    let runtime = NodeL3Gate::with_limits("machine-1", 16, 16, 2);
    runtime
        .apply(config(NodeL3Mode::Enforce, false))
        .expect("Enforce policy applies");
    runtime.replace_provider_listeners(
        "machine-1",
        [
            ("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443),
            ("service-dns".to_owned(), NodeL3ServiceProtocol::Udp, 53),
        ],
    );
    runtime
        .replace_transport_projection(&gateway_projection(Some("gateway-public")))
        .expect("explicit gateway projection installs");

    let now = Instant::now();
    let public_source = Ipv4Addr::new(198, 51, 100, 24);
    let tcp_id = 0x1001;
    let udp_id = 0x1002;
    let overflow_id = 0x1003;
    let raw_port_id = 0x1004;
    let tcp_first = first_fragment(tcp(public_source, LOCAL, 50_000, 443, 0x02), tcp_id);
    let udp_first = first_fragment(udp(public_source, LOCAL, 50_001, 53), udp_id);

    assert_eq!(
        runtime.evaluate_at(PacketDirection::Inbound, [9; 32], &tcp_first, now),
        NodeL3Decision::Legacy,
        "an exact fragmented TCP listener reaches the existing L4 PEP"
    );
    assert_eq!(
        runtime.evaluate_at(PacketDirection::Inbound, [9; 32], &udp_first, now),
        NodeL3Decision::Legacy,
        "an exact fragmented UDP listener reaches the existing L4 PEP"
    );
    assert_eq!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            [9; 32],
            &later_fragment_for_protocol(public_source, LOCAL, tcp_id, 6),
            now + Duration::from_secs(1),
        ),
        NodeL3Decision::Legacy,
        "the TCP continuation delegates only after its exact first fragment"
    );
    assert_eq!(
        runtime.evaluate_at(
            PacketDirection::Inbound,
            [9; 32],
            &later_fragment_for_protocol(public_source, LOCAL, udp_id, 17),
            now + Duration::from_secs(1),
        ),
        NodeL3Decision::Legacy,
        "the UDP continuation delegates only after its exact first fragment"
    );

    for packet in [
        later_fragment_for_protocol(public_source, LOCAL, 0x7777, 6),
        later_fragment_for_protocol(public_source, LOCAL, tcp_id, 17),
        later_fragment_for_protocol(Ipv4Addr::new(198, 51, 100, 25), LOCAL, tcp_id, 6),
    ] {
        assert_eq!(
            runtime.evaluate_at(PacketDirection::Inbound, [9; 32], &packet, now),
            NodeL3Decision::Enforce {
                allow: false,
                reason: NodeL3Reason::OrphanFragment,
            },
            "an orphan or non-exact fragment must fail closed"
        );
    }
    for peer in [PEER, [8; 32]] {
        assert_eq!(
            runtime.evaluate_at(
                PacketDirection::Inbound,
                peer,
                &later_fragment_for_protocol(public_source, LOCAL, tcp_id, 6),
                now,
            ),
            NodeL3Decision::Enforce {
                allow: false,
                reason: NodeL3Reason::SourceBinding,
            },
            "Node and unknown peers cannot consume gateway fragment authority"
        );
    }

    assert_legacy_l4_fragment_authority_is_bounded(
        &runtime,
        now,
        public_source,
        (tcp_id, udp_id, overflow_id, raw_port_id),
    );
}

#[test]
fn inferred_or_staged_gateway_identity_never_opens_the_provider_path() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Enforce, false))
        .expect("Enforce policy applies");
    runtime.replace_provider_listeners(
        "machine-1",
        [("service-web".to_owned(), NodeL3ServiceProtocol::Tcp, 443)],
    );
    let packet = tcp(Ipv4Addr::new(198, 51, 100, 25), LOCAL, 50_000, 443, 0x02);

    runtime
        .replace_transport_projection(&gateway_projection(None))
        .expect("legacy gateway projection installs");
    assert!(matches!(
        runtime.evaluate_inbound([9; 32], &packet),
        NodeL3Decision::Enforce { allow: false, .. }
    ));

    runtime
        .replace_transport_projection(&gateway_projection(Some("   ")))
        .expect("blank explicit identity remains untrusted");
    assert!(matches!(
        runtime.evaluate_inbound([9; 32], &packet),
        NodeL3Decision::Enforce { allow: false, .. }
    ));

    let mut contradictory_node_peer = wg_projection(Some((1, NodeL3Mode::Enforce)));
    contradictory_node_peer.peers[0].gateway_id = Some("gateway-public".to_owned());
    runtime
        .replace_transport_projection(&contradictory_node_peer)
        .expect("a marked Node peer remains representable but untrusted as a gateway");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &packet),
        NodeL3Decision::Enforce { allow: false, .. }
    ));

    let mut split_role_peer = gateway_projection(Some("gateway-public"));
    let mut duplicate_node = wg_projection(Some((1, NodeL3Mode::Enforce)))
        .peers
        .remove(0);
    duplicate_node.public_key = [9; 32];
    split_role_peer.peers.push(duplicate_node);
    runtime
        .replace_transport_projection(&split_role_peer)
        .expect("a duplicate key remains representable but ambiguous");
    assert!(matches!(
        runtime.evaluate_inbound([9; 32], &packet),
        NodeL3Decision::Enforce { allow: false, .. }
    ));

    let desired_gateway = gateway_projection(Some("gateway-public"));
    runtime
        .stage_transport_projection(&desired_gateway)
        .expect("gateway replacement stages");
    assert!(matches!(
        runtime.evaluate_inbound([9; 32], &packet),
        NodeL3Decision::Enforce { allow: false, .. }
    ));

    let skipped_gateway = empty_projection();
    runtime
        .replace_transport_projection_after_build(&desired_gateway, &skipped_gateway)
        .expect("the actual empty peer table installs without carrier trust");
    assert!(matches!(
        runtime.evaluate_inbound([9; 32], &packet),
        NodeL3Decision::Enforce { allow: false, .. }
    ));

    let mismatched_gateway = gateway_projection(Some("gateway-other"));
    assert_eq!(
        runtime.replace_transport_projection_after_build(&desired_gateway, &mismatched_gateway,),
        Err(NodeL3TransportError::InvalidInstalledProjection(
            "installed gateway carrier differed from the desired config",
        ))
    );
}

#[test]
fn observe_ack_does_not_require_unprojected_cross_owner_bindings() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .replace_transport_projection(&empty_projection())
        .unwrap();
    let applied = runtime
        .apply(config(NodeL3Mode::Observe, false))
        .expect("cross-owner graph can be precompiled without transport");
    assert!(
        runtime.ready_for_ack(&applied),
        "policy bindings absent from the actual WG projection do not block readiness"
    );
}

#[test]
fn observe_marker_never_exposes_a_cross_owner_binding() {
    let runtime = NodeL3Gate::new("machine-1");
    let applied = runtime
        .apply(config(NodeL3Mode::Observe, false))
        .expect("cross-owner graph precompiles in Observe");
    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Observe))))
        .expect("the malformed phase projection is represented fail closed");

    assert!(
        !runtime.ready_for_ack(&applied),
        "Observe transport is limited to same-owner bindings"
    );
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        },
        "a buggy cross-owner Observe marker cannot open compatibility traffic"
    );
}

#[test]
fn offline_same_owner_binding_does_not_block_observe_ack() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .replace_transport_projection(&empty_projection())
        .unwrap();
    let applied = runtime
        .apply(config(NodeL3Mode::Observe, true))
        .expect("same-owner graph applies");
    assert!(
        runtime.ready_for_ack(&applied),
        "a policy-only same-owner binding represents an offline peer and cannot carry traffic"
    );
}

#[test]
fn offline_explicit_binding_does_not_block_enforce_ack() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .replace_transport_projection(&empty_projection())
        .unwrap();
    let applied = runtime
        .apply(config(NodeL3Mode::Enforce, false))
        .expect("cross-owner graph applies without an online transport");
    assert!(
        runtime.ready_for_ack(&applied),
        "an absent explicit peer has no packet path and must not require simultaneous presence"
    );
}

#[test]
fn later_marker_stays_pending_until_the_peer_is_actually_installed() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .replace_transport_projection(&empty_projection())
        .unwrap();
    let applied = runtime
        .apply(config(NodeL3Mode::Enforce, false))
        .expect("offline peer policy applies");
    assert!(runtime.ready_for_ack(&applied));

    let marked = wg_projection(Some((1, NodeL3Mode::Enforce)));
    runtime
        .stage_transport_projection(&marked)
        .expect("the returning peer marker stages before device replacement");
    assert!(!runtime.ready_for_ack(&applied));
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        }
    );

    runtime
        .replace_transport_projection(&marked)
        .expect("the exact marked peer installs");
    assert!(runtime.ready_for_ack(&applied));
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::NoGrant,
        },
        "once marker, actual route, and policy agree, the enforced policy decides the packet"
    );
}

#[test]
fn later_unmarked_actual_peer_cannot_satisfy_or_bypass_policy_readiness() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .replace_transport_projection(&empty_projection())
        .unwrap();
    let applied = runtime
        .apply(config(NodeL3Mode::Enforce, false))
        .expect("offline peer policy applies");
    assert!(runtime.ready_for_ack(&applied));

    runtime
        .replace_transport_projection(&wg_projection(None))
        .expect("the unmarked transport is represented exactly");
    assert!(
        !runtime.ready_for_ack(&applied),
        "an actual Node route needs the exact marker even when its policy is already applied"
    );
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::NoGrant,
        },
        "the existing Enforce policy still prevents an unmarked cross-owner bypass"
    );

    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .expect("the exact marker arrives");
    assert!(runtime.ready_for_ack(&applied));
}

#[test]
fn enforce_marker_blocks_an_observe_snapshot_until_phase_promotion() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .replace_transport_projection(&wg_projection(Some((1, NodeL3Mode::Enforce))))
        .unwrap();
    let observe = runtime
        .apply(config(NodeL3Mode::Observe, true))
        .expect("observe snapshot applies");
    assert!(!runtime.ready_for_ack(&observe));
    assert_eq!(
        runtime.peer_readiness_snapshot(),
        vec![NodeL3PeerReadiness {
            ip: REMOTE,
            network_id: "network-1".to_owned(),
            marker_generation: 1,
            marker_mode: NodeL3Mode::Enforce,
            policy_generation: Some(1),
            policy_mode: Some(NodeL3Mode::Observe),
            ready: false,
            reason: NodeL3PeerReadinessReason::ModeMismatch,
        }]
    );
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        }
    );

    let enforce = runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("same-generation phase promotion applies");
    assert!(runtime.ready_for_ack(&enforce));
    assert_eq!(
        runtime.peer_readiness_snapshot()[0].reason,
        NodeL3PeerReadinessReason::Ready
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
fn newer_authoritative_wg_generation_blocks_the_old_policy() {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply(config(NodeL3Mode::Enforce, true))
        .expect("generation one applies");
    runtime
        .replace_transport_projection(&wg_projection(Some((2, NodeL3Mode::Enforce))))
        .unwrap();
    assert_eq!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::PolicyPending,
        }
    );

    let mut next = config(NodeL3Mode::Enforce, true);
    next.generation = 2;
    runtime.apply(next).expect("generation two applies");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        NodeL3Decision::Enforce {
            allow: true,
            reason: NodeL3Reason::SameOwner,
        }
    ));
}

#[test]
fn provider_preauthorization_cannot_cross_target_networks_with_same_tuple() {
    let runtime = NodeL3Gate::new_for_targets(["machine-1".to_owned(), "machine-2".to_owned()]);
    runtime
        .apply_from_source("source-a", config(NodeL3Mode::Enforce, true))
        .expect("Network A applies");
    assert!(matches!(
        runtime.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_001, 443, 0x02)),
        NodeL3Decision::Enforce { allow: true, .. }
    ));

    // Network B deliberately reuses every overlay tuple but represents a
    // different registration and Service resource.
    let mut network_b = config(NodeL3Mode::Enforce, true);
    network_b.network_id = "network-2".to_owned();
    network_b.target_machine_id = "machine-2".to_owned();
    network_b.services[0].service_id = "service-other".to_owned();
    runtime
        .apply_from_source("source-b", network_b)
        .expect("Network B applies independently");

    assert!(runtime.service_flow_authorized(
        SocketAddrV4::new(REMOTE, 40_001).into(),
        SocketAddrV4::new(LOCAL, 443).into(),
        "machine-1",
        NodeL3ServiceProtocol::Tcp,
        "service-web",
    ));
    assert!(!runtime.service_flow_authorized(
        SocketAddrV4::new(REMOTE, 40_001).into(),
        SocketAddrV4::new(LOCAL, 443).into(),
        "machine-2",
        NodeL3ServiceProtocol::Tcp,
        "service-other",
    ));
}
