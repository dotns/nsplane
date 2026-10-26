//! Pinholes: sessions, revocation and expiry.

use super::*;

#[test]
fn session_only_peer_works_only_through_its_inbound_pinhole() {
    let (engine, clock) = pinhole_engine(Some(Vec::new()));
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (e, a, local) = (peer_addr(E), peer_addr(A), addr(LOCAL));
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
        drop(reasons::DENIED)
    );

    let guard = open(&engine, &clock, E, Direction::Inbound, 9000);
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
        Verdict::Accept
    );
    // Only that protocol, port, direction and the local node.
    assert_eq!(
        inbound(&f, E, udp_packet(e, 4000, local, 9000)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 9001)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, a, 9000)),
        drop(reasons::CROSS_NAMESPACE)
    );
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 5000, e, 9000)),
        drop(reasons::OUTBOUND)
    );
    // The reply of the opened flow, and the flow continuing.
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
        Verdict::Accept
    );

    std::mem::drop(guard);
    assert_eq!(engine.pinhole_stats().closed, 1);
    // New flows are dropped, the opened flow's allowances are revoked.
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4001, local, 9000)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
        drop(reasons::OUTBOUND)
    );
    let stats = f.stats();
    assert_eq!(
        (stats.accepted, stats.replies, stats.outbound_replies),
        (1, 1, 1)
    );
    assert_eq!(stats.reply_revoked, 2);
}

#[test]
fn outbound_pinhole_to_a_restricted_peer() {
    let (engine, clock) = pinhole_engine(Some(Vec::new()));
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (e, local) = (peer_addr(E), addr(LOCAL));
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 5000, e, 7000)),
        drop(reasons::OUTBOUND)
    );

    let guard = open(&engine, &clock, E, Direction::Outbound, 7000);
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 5000, e, 7000)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, E, udp_packet(local, 5000, e, 7000)),
        drop(reasons::OUTBOUND)
    );
    // No reverse rule: the peer cannot open flows to the local port 7000.
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 7000)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 7000, local, 5000)),
        Verdict::Accept
    );

    guard.close();
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 5001, e, 7000)),
        drop(reasons::OUTBOUND)
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 7000, local, 5000)),
        drop(reasons::DENIED)
    );
    let stats = f.stats();
    assert_eq!((stats.replies, stats.reply_revoked), (1, 1));
    assert_eq!(stats.outbound_denied, 3);
}

#[test]
fn pinhole_revocation_covers_replies_through_unrestricted_peers() {
    let (engine, clock) = pinhole_engine(None);
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (e, local) = (peer_addr(E), addr(LOCAL));

    // Outbound pinhole: outbound is accepted anyway, the replies depend
    // on the pinhole.
    let out = open(&engine, &clock, E, Direction::Outbound, 7000);
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 5000, e, 7000)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 7000, local, 5000)),
        Verdict::Accept
    );
    // Inbound pinhole: the local node's replies are accepted anyway, and
    // the flow continuing depends on the pinhole.
    let into = open(&engine, &clock, E, Direction::Inbound, 9000);
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
        Verdict::Accept
    );
    assert_eq!((f.stats().accepted, f.stats().replies), (1, 2));

    std::mem::drop((out, into));
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 7000, local, 5000)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
        drop(reasons::DENIED)
    );
    assert_eq!(f.stats().reply_revoked, 2);
    assert_eq!(engine.pinhole_stats().closed, 2);
}

#[test]
fn source_member_keeps_its_rules_around_a_pinhole() {
    let (engine, clock) = pinhole_engine(None);
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, local) = (peer_addr(A), addr(LOCAL));
    let ssh = || tcp_packet(a, 4000, local, 22);
    let transfer = || tcp_packet(a, 4000, local, 9000);
    assert_eq!(inbound(&f, A, ssh()), Verdict::Accept);
    assert_eq!(inbound(&f, A, transfer()), drop(reasons::DENIED));

    let guard = open(&engine, &clock, A, Direction::Inbound, 9000);
    assert_eq!(inbound(&f, A, ssh()), Verdict::Accept);
    assert_eq!(inbound(&f, A, transfer()), Verdict::Accept);
    std::mem::drop(guard);
    assert_eq!(inbound(&f, A, ssh()), Verdict::Accept);
    assert_eq!(inbound(&f, A, transfer()), drop(reasons::DENIED));
    // Outbound stays unrestricted throughout.
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 9999)),
        Verdict::Accept
    );
}

#[test]
fn permission_revoked_mid_session_closes_the_pinhole() {
    let (engine, clock) = pinhole_engine(None);
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, local) = (peer_addr(A), addr(LOCAL));
    let guard = open(&engine, &clock, A, Direction::Inbound, 9000);
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 9000)),
        Verdict::Accept
    );
    // quick stops allowing "transfer".
    engine
        .store_namespace("quick", namespace(&[A], None))
        .unwrap();
    assert!(!guard.is_open());
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4001, local, 9000)),
        drop(reasons::DENIED)
    );
    assert_eq!(engine.pinhole_stats().revoked, 1);
    std::mem::drop(guard);
    assert_eq!(engine.pinhole_stats().closed, 0);
}

#[test]
fn expired_pinholes_stop_flows_without_sleeping() {
    let (engine, clock) = pinhole_engine(Some(Vec::new()));
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (e, local) = (peer_addr(E), addr(LOCAL));
    let guard = open(&engine, &clock, E, Direction::Inbound, 9000);
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
        Verdict::Accept
    );

    *clock.lock().unwrap() += Duration::from_secs(60);
    // The established flow's reply allowance is revoked, the pinhole is
    // swept once and new flows are dropped.
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
        drop(reasons::OUTBOUND)
    );
    assert_eq!(
        inbound(&f, E, tcp_packet(e, 4001, local, 9000)),
        drop(reasons::DENIED)
    );
    assert!(!guard.is_open());
    std::mem::drop(guard);
    let stats = engine.pinhole_stats();
    assert_eq!((stats.expired, stats.closed), (1, 0));
    assert_eq!(f.stats().reply_revoked, 1);
}

#[test]
fn namespace_removal_closes_pinholes() {
    let (engine, clock) = pinhole_engine(None);
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, local) = (peer_addr(A), addr(LOCAL));
    let guard = open(&engine, &clock, A, Direction::Inbound, 9000);
    assert!(engine.remove_namespace("s1"));
    assert!(!guard.is_open());
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 9000)),
        drop(reasons::DENIED)
    );
    // Other namespaces are unaffected.
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );
    assert_eq!(engine.pinhole_stats().namespace_removed, 1);
}

#[test]
fn clear_all_is_an_emergency_stop() {
    let (engine, clock) = pinhole_engine(Some(Vec::new()));
    engine.install(test_policy());
    engine
        .store_namespace("nsd:b", namespace(&[B], None))
        .unwrap();
    engine
        .store_grant(
            "a-to-b",
            Grant {
                from: GrantEnd::Label(label(A)),
                to: GrantEnd::Label(label(B)),
                protocols: vec![ProtocolMatch::Tcp(PortSet::single(443))],
            },
        )
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, b, e, local) = (peer_addr(A), peer_addr(B), peer_addr(E), addr(LOCAL));
    let (remote, v4_local) = (addr("10.0.0.1"), addr("10.0.0.2"));

    // A reply allowance of a flow the local side opened.
    assert_eq!(
        outbound(&f, PEER, tcp_packet(v4_local, 40000, remote, 9999)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(remote, 9999, v4_local, 40000)),
        Verdict::Accept
    );
    // A flow through a pinhole and one through a grant.
    let guard = open(&engine, &clock, E, Direction::Inbound, 9000);
    let pinholed = || tcp_packet(e, 4000, local, 9000);
    assert_eq!(inbound(&f, E, pinholed()), Verdict::Accept);
    assert_eq!(
        outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
        Verdict::Accept
    );
    let granted = || tcp_packet(a, 4000, b, 443);
    assert_eq!(inbound(&f, A, granted()), Verdict::Accept);
    assert_eq!(outbound(&f, B, granted()), Verdict::Accept);

    engine.clear_all();
    assert!(!engine.is_loaded());
    assert_eq!(engine.policy_state(), PolicyState::Failed);
    assert!(engine.namespaces().is_empty() && engine.grants().is_empty());
    assert!(!guard.is_open());
    for (peer, packet) in [
        (PEER, tcp_packet(remote, 9999, v4_local, 40000)),
        (E, pinholed()),
        (A, granted()),
        (B, tcp_packet(b, 443, a, 4000)),
        (A, tcp_packet(a, 4000, local, 22)),
    ] {
        assert_eq!(inbound(&f, peer, packet), drop(reasons::POLICY_FAILED));
    }
    let stats = f.stats();
    assert_eq!((stats.policy_failed, stats.no_policy), (5, 0));
    assert_eq!(stats.policy_state, PolicyState::Failed);

    // Dropping the guard afterwards is a no-op.
    std::mem::drop(guard);
    assert_eq!(
        engine.pinhole_stats(),
        crate::PinholeStats {
            opened: 1,
            cleared: 1,
            ..crate::PinholeStats::default()
        }
    );

    // Later updates work as usual.
    engine
        .store_namespace("nsd:b", namespace(&[B], None))
        .unwrap();
    assert_eq!(
        inbound(&f, B, tcp_packet(b, 4000, local, 22)),
        Verdict::Accept
    );
    engine.install(test_policy());
    assert_eq!(
        inbound(&f, PEER, tcp_packet(remote, 4000, v4_local, 80)),
        Verdict::Accept
    );
}
