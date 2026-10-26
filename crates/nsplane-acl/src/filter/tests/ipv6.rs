//! IPv6 modes.

use super::*;

#[test]
fn ipv6_is_evaluated_by_default() {
    assert_eq!(AclFilterConfig::default().ipv6, Ipv6Mode::Evaluate);
    let f = filter();
    let (r, l) = (addr("fd00::1"), addr("fd00::2"));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 444)),
        drop(reasons::DENIED)
    );
    assert_eq!(f.stats().ipv6_accepted, 0);
}

#[test]
fn ipv6_accept_passes_inbound_ipv6_unevaluated() {
    let (r, l) = (addr("fd00::1"), addr("fd00::2"));
    let frag = ip(r, l, 44, &[protocol::TCP, 0, 0, 8, 0, 0, 0, 1, 0, 0]);
    let echo = ip(r, l, protocol::ICMPV6, &icmp_echo(128, 1));
    let truncated = || PacketBuf::from_packet(&[0x60, 0, 0]);
    for config in [ipv6_accept(), stateless_options(None)] {
        // No policy loaded.
        let engine = Arc::new(AclEngine::new());
        let f = AclFilter::with_config(Arc::clone(&engine), identity(), config);
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 444)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(
                &f,
                PEER,
                tcp_packet(addr("10.0.0.1"), 4000, addr("10.0.0.2"), 80)
            ),
            drop(reasons::NO_POLICY)
        );
        engine.install(test_policy());
        // A denied port, a fragment, ICMPv6 and a truncated packet.
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 444)),
            Verdict::Accept
        );
        assert_eq!(inbound(&f, PEER, frag.clone()), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, echo.clone()), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, truncated()), Verdict::Accept);
        let stats = f.stats();
        assert_eq!((stats.ipv6_accepted, stats.accepted), (5, 0));
        assert_eq!(f.inner.table().entries.len(), 0);
        assert_eq!(allowed_len(&f), 0);
        assert_eq!(f.inner.fragments.lock().unwrap().entries.len(), 0);
        // IPv4 is unaffected.
        let (r4, l4) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r4, 4000, l4, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r4, 4000, l4, 81)),
            drop(reasons::DENIED)
        );
        let stats = f.stats();
        assert_eq!((stats.ipv6_accepted, stats.accepted), (5, 1));
    }
}

#[test]
fn ipv6_accept_passes_outbound_ipv6_unevaluated() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace(
            "nsd:a",
            namespace(&[A], Some(vec![outbound_rule(true, PortSet::single(80))])),
        )
        .unwrap();
    let (a, local) = (peer_addr(A), addr(LOCAL));
    let evaluate = ns_filter(&engine, AclFilterConfig::default());
    assert_eq!(
        outbound(&evaluate, A, tcp_packet(local, 5000, a, 22)),
        drop(reasons::OUTBOUND)
    );

    let f = ns_filter(&engine, ipv6_accept());
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 22)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(
            &f,
            A,
            ip(local, a, 44, &[protocol::TCP, 0, 0, 8, 0, 0, 0, 1, 0, 0])
        ),
        Verdict::Accept
    );
    // The reply passes unevaluated too; no allowance was recorded.
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 22, local, 5000)),
        Verdict::Accept
    );
    let stats = f.stats();
    assert_eq!(
        (stats.ipv6_accepted, stats.outbound_denied, stats.replies),
        (3, 0, 0)
    );
    assert_eq!(f.inner.table().entries.len(), 0);
}
