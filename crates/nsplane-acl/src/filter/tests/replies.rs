//! Stateful replies: allowances, expiry and eviction.

use super::*;

#[test]
fn replies_to_outbound_flows_are_accepted() {
    let engine = Arc::new(AclEngine::new());
    let f = AclFilter::new(Arc::clone(&engine), identity());
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        outbound(&f, PEER, tcp_packet(l, 40000, r, 22)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, PEER, udp_packet(l, 40001, r, 53)),
        Verdict::Accept
    );

    // Fail-closed wins while no policy is loaded.
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 22, l, 40000)),
        drop(reasons::NO_POLICY)
    );

    engine.install(RuleSet::new(deny_all()).unwrap());
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 22, l, 40000)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, udp_packet(r, 53, l, 40001)),
        Verdict::Accept
    );
    // Same local port, different remote port.
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 23, l, 40000)),
        drop(reasons::DENIED)
    );
    // Same tuple, different peer.
    assert_eq!(
        inbound(&f, OTHER_PEER, tcp_packet(r, 22, l, 40000)),
        drop(reasons::DENIED)
    );
    // The protocol is part of the key.
    assert_eq!(
        inbound(&f, PEER, udp_packet(r, 22, l, 40000)),
        drop(reasons::DENIED)
    );
    let stats = f.stats();
    assert_eq!((stats.replies, stats.denied, stats.no_policy), (2, 3, 1));
}

#[test]
fn reply_fragments_follow_the_first_fragment() {
    let f = AclFilter::new(loaded_engine(deny_all()), identity());
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        outbound(&f, PEER, tcp_packet(l, 80, r, 4000)),
        Verdict::Accept
    );
    assert_eq!(inbound(&f, PEER, first_fragment(5, 80)), Verdict::Accept);
    assert_eq!(
        inbound(&f, PEER, fragment(5, 4, false, &[0; 8])),
        Verdict::Accept
    );
    assert_eq!(f.stats().replies, 2);
}

#[test]
fn accepted_echo_requests_allow_their_replies() {
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let (r6, l6) = (addr("fd00::1"), addr("fd00::2"));
    let request = |id| ip(l, r, protocol::ICMP, &icmp_echo(8, id));
    let reply = |id| ip(r, l, protocol::ICMP, &icmp_echo(0, id));
    let request6 = |id| ip(l6, r6, protocol::ICMPV6, &icmp_echo(128, id));
    let reply6 = |id| ip(r6, l6, protocol::ICMPV6, &icmp_echo(129, id));

    // Without other-protocol settings: only the reply of a request passes.
    let f = AclFilter::new(loaded_engine(deny_all()), identity());
    assert_eq!(inbound(&f, PEER, reply(77)), drop(reasons::PROTOCOL));
    assert_eq!(outbound(&f, PEER, request(77)), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, reply(77)), Verdict::Accept);
    // Another identifier, an echo request with the same identifier or another
    // ICMP message is not that reply.
    assert_eq!(inbound(&f, PEER, reply(78)), drop(reasons::PROTOCOL));
    assert_eq!(inbound(&f, PEER, request(77)), drop(reasons::PROTOCOL));
    let unreachable = ip(r, l, protocol::ICMP, &icmp_echo(3, 77));
    assert_eq!(inbound(&f, PEER, unreachable), drop(reasons::PROTOCOL));
    // Nor does a reply from another peer pass.
    assert_eq!(inbound(&f, OTHER_PEER, reply(77)), drop(reasons::PROTOCOL));
    // ICMPv6.
    assert_eq!(inbound(&f, PEER, reply6(5)), drop(reasons::PROTOCOL));
    assert_eq!(outbound(&f, PEER, request6(5)), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, reply6(5)), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, reply6(6)), drop(reasons::PROTOCOL));
    assert_eq!(f.stats().replies, 2);

    // `allow_other_protocols` still accepts everything and counts replies.
    let f = AclFilter::with_config(
        loaded_engine(deny_all()),
        identity(),
        AclFilterConfig {
            allow_other_protocols: true,
            ..AclFilterConfig::default()
        },
    );
    outbound(&f, PEER, request(77));
    assert_eq!(inbound(&f, PEER, reply(77)), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, request(77)), Verdict::Accept);
    assert_eq!(f.stats().replies, 1);
}

#[test]
fn echo_reply_allowances_expire_and_need_stateful_replies() {
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let request = || ip(l, r, protocol::ICMP, &icmp_echo(8, 9));
    let reply = || ip(r, l, protocol::ICMP, &icmp_echo(0, 9));
    let f = AclFilter::with_config(
        loaded_engine(deny_all()),
        identity(),
        AclFilterConfig {
            reply_idle_timeout: Duration::from_millis(50),
            ..AclFilterConfig::default()
        },
    );
    outbound(&f, PEER, request());
    assert_eq!(inbound(&f, PEER, reply()), Verdict::Accept);
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(inbound(&f, PEER, reply()), drop(reasons::PROTOCOL));
    assert_eq!(f.stats().reply_expired, 1);

    let f = AclFilter::with_config(
        loaded_engine(deny_all()),
        identity(),
        AclFilterConfig {
            stateful_replies: false,
            ..AclFilterConfig::default()
        },
    );
    assert_eq!(outbound(&f, PEER, request()), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, reply()), drop(reasons::PROTOCOL));
    assert_eq!(f.inner.table().entries.len(), 0);
}

#[test]
fn reply_allowances_expire() {
    let f = AclFilter::with_config(
        loaded_engine(deny_all()),
        identity(),
        AclFilterConfig {
            reply_idle_timeout: Duration::from_millis(50),
            ..AclFilterConfig::default()
        },
    );
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    outbound(&f, PEER, udp_packet(l, 40000, r, 53));
    assert_eq!(
        inbound(&f, PEER, udp_packet(r, 53, l, 40000)),
        Verdict::Accept
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        inbound(&f, PEER, udp_packet(r, 53, l, 40000)),
        drop(reasons::DENIED)
    );
    let stats = f.stats();
    assert_eq!((stats.replies, stats.reply_expired), (1, 1));

    // Outbound traffic refreshes an allowance.
    outbound(&f, PEER, udp_packet(l, 40000, r, 53));
    std::thread::sleep(Duration::from_millis(30));
    outbound(&f, PEER, udp_packet(l, 40000, r, 53));
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(
        inbound(&f, PEER, udp_packet(r, 53, l, 40000)),
        Verdict::Accept
    );
}

#[test]
fn reply_table_evicts_oldest() {
    let f = AclFilter::with_config(
        loaded_engine(deny_all()),
        identity(),
        AclFilterConfig {
            reply_capacity: 2,
            ..AclFilterConfig::default()
        },
    );
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    for port in [1000, 1001, 1002] {
        outbound(&f, PEER, tcp_packet(l, port, r, 22));
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(f.stats().reply_evictions, 1);
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 22, l, 1000)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 22, l, 1001)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 22, l, 1002)),
        Verdict::Accept
    );
}

#[test]
fn stateful_replies_can_be_disabled() {
    let f = AclFilter::with_config(
        loaded_engine(deny_all()),
        identity(),
        AclFilterConfig {
            stateful_replies: false,
            ..AclFilterConfig::default()
        },
    );
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    outbound(&f, PEER, tcp_packet(l, 40000, r, 22));
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 22, l, 40000)),
        drop(reasons::DENIED)
    );
    assert_eq!(f.stats().replies, 0);
}
