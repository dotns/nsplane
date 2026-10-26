//! Namespaces: cross-namespace defaults, grants, outbound restriction and
//! revocation of replies.

use super::*;

#[test]
fn cross_namespace_default_deny_and_directed_grants() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A, C], None))
        .unwrap();
    engine
        .store_namespace("nsd:b", namespace(&[B], None))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, b, c, local) = (peer_addr(A), peer_addr(B), peer_addr(C), addr(LOCAL));

    // Same namespace: peer to peer and peer to local.
    assert_eq!(inbound(&f, A, tcp_packet(a, 4000, c, 22)), Verdict::Accept);
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 23)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, c, 23)),
        drop(reasons::DENIED)
    );
    // Different namespaces: denied even where each namespace's rules accept.
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, b, 22)),
        drop(reasons::CROSS_NAMESPACE)
    );
    assert_eq!(
        inbound(&f, B, tcp_packet(b, 4000, a, 22)),
        drop(reasons::CROSS_NAMESPACE)
    );

    // A grant from nsd:a to B on TCP 443 only, in that direction only.
    engine
        .store_grant(
            "a-to-b",
            Grant {
                from: GrantEnd::Namespace("nsd:a".into()),
                to: GrantEnd::Label(label(B)),
                protocols: vec![ProtocolMatch::Tcp(PortSet::single(443))],
            },
        )
        .unwrap();
    assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 443)), Verdict::Accept);
    assert_eq!(inbound(&f, C, tcp_packet(c, 4000, b, 443)), Verdict::Accept);
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, b, 22)),
        drop(reasons::CROSS_NAMESPACE)
    );
    assert_eq!(
        inbound(&f, A, udp_packet(a, 4000, b, 443)),
        drop(reasons::CROSS_NAMESPACE)
    );
    assert_eq!(
        inbound(&f, B, tcp_packet(b, 4000, a, 443)),
        drop(reasons::CROSS_NAMESPACE)
    );
    // A grant opens nothing towards the local node.
    assert_eq!(
        inbound(&f, B, tcp_packet(b, 4000, local, 443)),
        drop(reasons::DENIED)
    );

    let stats = f.stats();
    assert_eq!(
        (stats.accepted, stats.denied, stats.cross_namespace),
        (4, 3, 5)
    );
}

#[test]
fn grant_revocation_stops_new_flows_and_revokes_replies() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A], Some(Vec::new())))
        .unwrap();
    engine
        .store_namespace("nsd:b", namespace(&[B], None))
        .unwrap();
    let grant = Grant {
        from: GrantEnd::Label(label(A)),
        to: GrantEnd::Namespace("nsd:b".into()),
        protocols: vec![
            ProtocolMatch::Tcp(PortSet::single(443)),
            ProtocolMatch::Udp(PortSet::single(443)),
        ],
    };
    engine.store_grant("g", grant.clone()).unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, b) = (peer_addr(A), peer_addr(B));

    // A is outbound-restricted: the accepted inbound flow records an
    // outbound reply allowance, and the reply records an inbound one.
    assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 443)), Verdict::Accept);
    assert_eq!(
        outbound(&f, A, tcp_packet(b, 443, a, 4000)),
        Verdict::Accept
    );
    assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 443)), Verdict::Accept);
    let stats = f.stats();
    assert_eq!(
        (stats.accepted, stats.outbound_replies, stats.replies),
        (1, 1, 1)
    );

    // Replacing the grant under the same id keeps the allowances.
    engine.store_grant("g", grant).unwrap();
    assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 443)), Verdict::Accept);

    assert!(engine.remove_grant("g"));
    assert!(!engine.remove_grant("g"));
    // The established flow's allowances are revoked on their next lookup.
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, b, 443)),
        drop(reasons::CROSS_NAMESPACE)
    );
    assert_eq!(
        outbound(&f, A, tcp_packet(b, 443, a, 4000)),
        drop(reasons::OUTBOUND)
    );
    // New flows are evaluated from scratch.
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4001, b, 443)),
        drop(reasons::CROSS_NAMESPACE)
    );
    let stats = f.stats();
    assert_eq!(stats.reply_revoked, 2);
    assert_eq!(stats.cross_namespace, 2);
    assert_eq!(stats.outbound_denied, 1);
}

/// `namespace` without its accept rule.
fn closed_namespace(peers: &[PeerId], outbound: Option<Vec<OutboundRule>>) -> NamespacePolicy {
    NamespacePolicy {
        rules: Vec::new(),
        ..namespace(peers, outbound)
    }
}

#[test]
fn rule_removal_revokes_the_replies_of_rule_accepted_flows() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A], None))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, local) = (peer_addr(A), addr(LOCAL));
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 22, a, 4000)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );

    // An unrelated change keeps the flow.
    engine
        .store_namespace("nsd:b", namespace(&[B], None))
        .unwrap();
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );
    assert_eq!(f.stats().reply_revoked, 0);

    engine
        .store_namespace("nsd:a", closed_namespace(&[A], None))
        .unwrap();
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4001, local, 22)),
        drop(reasons::DENIED)
    );
    let stats = f.stats();
    assert_eq!((stats.replies, stats.reply_revoked), (2, 1));
}

#[test]
fn rule_removal_revokes_both_allowances_of_a_restricted_peer() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A], Some(Vec::new())))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, local) = (peer_addr(A), addr(LOCAL));
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 22, a, 4000)),
        Verdict::Accept
    );

    engine
        .store_namespace("nsd:a", closed_namespace(&[A], Some(Vec::new())))
        .unwrap();
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 22, a, 4000)),
        drop(reasons::OUTBOUND)
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        drop(reasons::DENIED)
    );
    assert_eq!(f.stats().reply_revoked, 2);
}

#[test]
fn label_change_revokes_the_replies_of_rule_accepted_flows() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A], None))
        .unwrap();
    let identity = ns_identity();
    let f = AclFilter::with_config(
        Arc::clone(&engine),
        Arc::clone(&identity),
        AclFilterConfig::default(),
    );
    let (a, local) = (peer_addr(A), addr(LOCAL));
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 22, a, 4000)),
        Verdict::Accept
    );

    identity.insert(A, LabelSet::new([Label::from("other-account")]));
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        drop(reasons::NO_POLICY)
    );
    assert_eq!(f.stats().reply_revoked, 1);
}

#[test]
fn default_rule_removal_revokes_the_replies_of_accepted_flows() {
    let engine = loaded_engine(vec![tcp_rule(PortSet::single(22))]);
    let f = AclFilter::new(Arc::clone(&engine), identity());
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 22)),
        Verdict::Accept
    );
    outbound(&f, PEER, tcp_packet(l, 22, r, 4000));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 22)),
        Verdict::Accept
    );

    engine.install(RuleSet::new(deny_all()).unwrap());
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 22)),
        drop(reasons::DENIED)
    );
    assert_eq!(f.stats().reply_revoked, 1);
}

#[test]
fn an_unversioned_identity_checks_the_flow_on_every_reply() {
    let engine = loaded_engine(vec![tcp_rule(PortSet::single(22))]);
    let revoked = Arc::new(AtomicBool::new(false));
    let identity = {
        let revoked = Arc::clone(&revoked);
        move |_: PeerId| (!revoked.load(Ordering::Relaxed)).then(|| label_set(&[ADDR]))
    };
    let f = AclFilter::new(engine, identity);
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 22)),
        Verdict::Accept
    );
    outbound(&f, PEER, tcp_packet(l, 22, r, 4000));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 22)),
        Verdict::Accept
    );

    revoked.store(true, Ordering::Relaxed);
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 22)),
        drop(reasons::UNKNOWN_PEER)
    );
    assert_eq!(f.stats().reply_revoked, 1);
}

#[test]
fn rule_removal_keeps_the_replies_of_local_flows() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A], None))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, local) = (peer_addr(A), addr(LOCAL));
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 80)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 80, local, 5000)),
        Verdict::Accept
    );

    engine
        .store_namespace("nsd:a", closed_namespace(&[A], None))
        .unwrap();
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 80, local, 5000)),
        Verdict::Accept
    );
    assert_eq!(f.stats().reply_revoked, 0);
}

#[test]
fn rule_removal_revokes_the_replies_of_a_forwarded_flow() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A, C], None))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, c) = (peer_addr(A), peer_addr(C));
    // The hub forwards A -> C and C's reply back to A.
    assert_eq!(inbound(&f, A, tcp_packet(a, 4000, c, 22)), Verdict::Accept);
    assert_eq!(outbound(&f, C, tcp_packet(a, 4000, c, 22)), Verdict::Accept);
    assert_eq!(inbound(&f, C, tcp_packet(c, 22, a, 4000)), Verdict::Accept);
    assert_eq!(outbound(&f, A, tcp_packet(c, 22, a, 4000)), Verdict::Accept);

    engine
        .store_namespace("nsd:a", closed_namespace(&[A, C], None))
        .unwrap();
    assert_eq!(
        inbound(&f, C, tcp_packet(c, 22, a, 4000)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, c, 22)),
        drop(reasons::DENIED)
    );
    assert_eq!(f.stats().reply_revoked, 2);
}

#[test]
fn a_rule_replaced_by_a_grant_keeps_the_flow_until_the_grant_goes() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A, B], None))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, b) = (peer_addr(A), peer_addr(B));
    assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 22)), Verdict::Accept);
    assert_eq!(outbound(&f, B, tcp_packet(a, 4000, b, 22)), Verdict::Accept);
    assert_eq!(inbound(&f, B, tcp_packet(b, 22, a, 4000)), Verdict::Accept);
    assert_eq!(outbound(&f, A, tcp_packet(b, 22, a, 4000)), Verdict::Accept);

    // B moves to its own namespace; a grant lets A reach it on TCP 22.
    engine
        .store_grant(
            "a-to-b",
            Grant {
                from: GrantEnd::Label(label(A)),
                to: GrantEnd::Namespace("nsd:b".into()),
                protocols: vec![ProtocolMatch::Tcp(PortSet::single(22))],
            },
        )
        .unwrap();
    engine
        .store_namespace("nsd:b", namespace(&[B], None))
        .unwrap();
    engine
        .store_namespace("nsd:a", namespace(&[A], None))
        .unwrap();
    assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 22)), Verdict::Accept);
    assert_eq!(inbound(&f, B, tcp_packet(b, 22, a, 4000)), Verdict::Accept);
    assert_eq!(f.stats().reply_revoked, 0);

    assert!(engine.remove_grant("a-to-b"));
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, b, 22)),
        drop(reasons::CROSS_NAMESPACE)
    );
    assert_eq!(
        inbound(&f, B, tcp_packet(b, 22, a, 4000)),
        drop(reasons::CROSS_NAMESPACE)
    );
    assert_eq!(f.stats().reply_revoked, 2);
}

#[test]
fn a_long_flow_keeps_its_rule_dependency() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A], None))
        .unwrap();
    let f = ns_filter(
        &engine,
        AclFilterConfig {
            reply_idle_timeout: Duration::from_millis(200),
            ..AclFilterConfig::default()
        },
    );
    let (a, local) = (peer_addr(A), addr(LOCAL));
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );
    // The flow outlives the idle timeout of the first packet's state.
    for _ in 0..3 {
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 22, a, 4000)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 22)),
            Verdict::Accept
        );
        std::thread::sleep(Duration::from_millis(120));
    }
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 22, a, 4000)),
        Verdict::Accept
    );

    engine
        .store_namespace("nsd:a", closed_namespace(&[A], None))
        .unwrap();
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        drop(reasons::DENIED)
    );
    assert_eq!(f.stats().reply_revoked, 1);
}

#[test]
fn outbound_restricted_only_when_every_namespace_opts_in() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace(
            "nsd:a",
            namespace(
                &[A, D],
                Some(vec![outbound_rule(false, PortSet::single(80))]),
            ),
        )
        .unwrap();
    engine
        .store_namespace("nsd:b", namespace(&[D], None))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, d, local) = (peer_addr(A), peer_addr(D), addr(LOCAL));

    // D is also in nsd:b, which does not restrict outbound.
    assert_eq!(
        outbound(&f, D, tcp_packet(local, 5000, d, 9999)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 9999)),
        drop(reasons::OUTBOUND)
    );
    // A peer in no namespace is unrestricted.
    assert_eq!(
        outbound(&f, PEER, tcp_packet(local, 5000, addr("fd00::99"), 9999)),
        Verdict::Accept
    );

    engine
        .store_namespace("nsd:b", namespace(&[D], Some(Vec::new())))
        .unwrap();
    assert_eq!(
        outbound(&f, D, tcp_packet(local, 5000, d, 9999)),
        drop(reasons::OUTBOUND)
    );
    // The union of the outbound rules of D's namespaces.
    assert_eq!(
        outbound(&f, D, tcp_packet(local, 5000, d, 80)),
        Verdict::Accept
    );
    assert_eq!(f.stats().outbound_denied, 2);
}

#[test]
fn outbound_rules_and_replies() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace(
            "nsd:a",
            namespace(
                &[A],
                Some(vec![outbound_rule(true, PortSet::list([80, 443]))]),
            ),
        )
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, local) = (peer_addr(A), addr(LOCAL));

    // Outbound rules.
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 443)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, A, udp_packet(local, 5000, a, 443)),
        drop(reasons::OUTBOUND)
    );
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 22)),
        drop(reasons::OUTBOUND)
    );
    // The accepted outbound flow's replies come back as today.
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 443, local, 5000)),
        Verdict::Accept
    );

    // Replies to an accepted inbound flow.
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 22, a, 4000)),
        drop(reasons::OUTBOUND)
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 22, a, 4000)),
        Verdict::Accept
    );
    // Not to another port of the same peer.
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 22, a, 4001)),
        drop(reasons::OUTBOUND)
    );
    // A denied inbound packet records nothing.
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 23)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 23, a, 4000)),
        drop(reasons::OUTBOUND)
    );

    // Other protocols need allow_other_protocols.
    let ping = || ip(local, a, protocol::ICMPV6, &icmp_echo(128, 1));
    assert_eq!(outbound(&f, A, ping()), drop(reasons::OUTBOUND));
    let stats = f.stats();
    assert_eq!(
        (stats.outbound_denied, stats.outbound_replies, stats.replies),
        (6, 1, 1)
    );

    let f = ns_filter(
        &engine,
        AclFilterConfig {
            allow_other_protocols: true,
            ..AclFilterConfig::default()
        },
    );
    assert_eq!(outbound(&f, A, ping()), Verdict::Accept);
}

#[test]
fn outbound_fragments_to_a_restricted_peer_follow_the_first() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace(
            "nsd:a",
            namespace(&[A], Some(vec![outbound_rule(false, PortSet::single(80))])),
        )
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (local, a) = (addr("10.0.0.2"), addr("10.0.0.1"));
    let frag = |id, offset_units, more, transport: &[u8]| {
        ip_frag(
            local,
            a,
            protocol::TCP,
            transport,
            Some(Frag {
                id,
                offset_units,
                more,
            }),
        )
    };
    assert_eq!(
        outbound(&f, A, frag(1, 0, true, &tcp(5000, 80, &[0; 8]))),
        Verdict::Accept
    );
    // Inbound fragments with the same addresses and id are tracked apart.
    let inbound_frag = ip_frag(
        local,
        a,
        protocol::TCP,
        &[0; 8],
        Some(Frag {
            id: 1,
            offset_units: 4,
            more: false,
        }),
    );
    assert_eq!(inbound(&f, A, inbound_frag), drop(reasons::FRAGMENT));
    assert_eq!(outbound(&f, A, frag(1, 4, false, &[0; 8])), Verdict::Accept);
    assert_eq!(
        outbound(&f, A, frag(2, 0, true, &tcp(5000, 81, &[0; 8]))),
        drop(reasons::OUTBOUND)
    );
    assert_eq!(
        outbound(&f, A, frag(2, 4, false, &[0; 8])),
        drop(reasons::OUTBOUND)
    );
    // Orphan fragment.
    assert_eq!(
        outbound(&f, A, frag(3, 4, false, &[0; 8])),
        drop(reasons::OUTBOUND)
    );
    assert_eq!(f.stats().outbound_denied, 3);
}

#[test]
fn pinhole_namespace_member_gets_nothing_inbound() {
    let engine = loaded_engine(vec![tcp_rule(PortSet::Any)]);
    engine
        .store_namespace(
            "s1",
            NamespacePolicy {
                kind: NamespaceKind::Pinholes,
                members: members(&[E]),
                outbound: Some(Vec::new()),
                ..NamespacePolicy::default()
            },
        )
        .unwrap();
    engine
        .store_namespace("nsd:a", namespace(&[A], None))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (e, a, local) = (peer_addr(E), peer_addr(A), addr(LOCAL));
    // The permissive default policy does not apply to a namespace member.
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 22)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, a, 22)),
        drop(reasons::CROSS_NAMESPACE)
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, e, 22)),
        drop(reasons::CROSS_NAMESPACE)
    );
    // Its outbound is restricted by the pinhole namespace.
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 22, e, 4000)),
        drop(reasons::OUTBOUND)
    );
}

#[test]
fn sources_in_no_namespace_use_the_default_policy() {
    let engine = rules_engine(test_policy());
    engine
        .store_namespace("nsd:a", namespace(&[A], Some(Vec::new())))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 22)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, KEY_PEER, udp_packet(r, 5000, l, 53)),
        Verdict::Accept
    );
    // Even towards a namespace member's address.
    assert_eq!(
        inbound(
            &f,
            PEER,
            tcp_packet(addr("fd00::99"), 4000, peer_addr(A), 22)
        ),
        drop(reasons::DENIED)
    );
    assert_eq!(
        outbound(&f, PEER, tcp_packet(l, 40000, r, 22)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 22, l, 40000)),
        Verdict::Accept
    );

    // Without a default policy they are fail-closed while namespaces exist.
    engine.uninstall();
    assert!(engine.is_loaded());
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        drop(reasons::NO_POLICY)
    );
    let stats = f.stats();
    assert_eq!(
        (stats.accepted, stats.denied, stats.replies, stats.no_policy),
        (2, 2, 1, 1)
    );
}

#[test]
fn grant_revocation_covers_replies_through_unrestricted_peers() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A], None))
        .unwrap();
    engine
        .store_namespace("nsd:c", namespace(&[C], None))
        .unwrap();
    engine
        .store_grant(
            "a-to-c",
            Grant {
                from: GrantEnd::Label(label(A)),
                to: GrantEnd::Namespace("nsd:c".into()),
                protocols: vec![ProtocolMatch::Tcp(PortSet::single(443))],
            },
        )
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, c) = (peer_addr(A), peer_addr(C));
    let request = || tcp_packet(a, 4000, c, 443);
    let reply = || tcp_packet(c, 443, a, 4000);

    // A hub forwards A -> C under the grant and C's replies back to A.
    assert_eq!(inbound(&f, A, request()), Verdict::Accept);
    assert_eq!(outbound(&f, C, request()), Verdict::Accept);
    assert_eq!(inbound(&f, C, reply()), Verdict::Accept);
    assert_eq!(outbound(&f, A, reply()), Verdict::Accept);
    assert_eq!(inbound(&f, A, request()), Verdict::Accept);
    assert_eq!((f.stats().accepted, f.stats().replies), (1, 2));

    // The replies in both directions depend on the grant.
    assert!(engine.remove_grant("a-to-c"));
    assert_eq!(inbound(&f, C, reply()), drop(reasons::CROSS_NAMESPACE));
    assert_eq!(inbound(&f, A, request()), drop(reasons::CROSS_NAMESPACE));
    assert_eq!(f.stats().reply_revoked, 2);
}
