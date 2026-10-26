//! Allow-only fragments, bypass flags and stateless replies.

use super::*;

/// An engine with `rules` installed whose clock is moved by hand.
fn clocked_engine(rules: RuleSet) -> (Arc<AclEngine>, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let handle = Arc::clone(&clock);
    let engine = AclEngine::with_clock(move || *handle.lock().unwrap());
    engine.install(rules);
    (Arc::new(engine), clock)
}

fn advance(clock: &Mutex<Instant>, by: Duration) {
    *clock.lock().unwrap() += by;
}

#[test]
fn bypass_and_fragment_defaults() {
    assert_eq!(FragmentMode::default(), FragmentMode::Outcome);
    let config = AclFilterConfig::default();
    assert_eq!(config.fragments, FragmentMode::Outcome);
    assert_eq!(config.accept_to_local, None);
    assert!(!config.accept_icmp_echo_reply);
}

#[test]
fn allow_only_remembers_until_ttl_then_expires() {
    let (engine, clock) = clocked_engine(test_policy());
    let f = AclFilter::with_config(engine, identity(), allow_only(4096));
    assert_eq!(
        inbound(&f, PEER, continuation(7)),
        drop(reasons::FRAGMENT),
        "empty gate denies"
    );
    assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
    advance(&clock, Duration::from_secs(1));
    assert_eq!(inbound(&f, PEER, continuation(7)), Verdict::Accept);
    // Still valid just before the TTL boundary...
    advance(&clock, Duration::from_millis(13_999));
    assert_eq!(inbound(&f, PEER, continuation(7)), Verdict::Accept);
    // ...and gone at it (expiry is exclusive), removed on lookup.
    advance(&clock, Duration::from_millis(1));
    assert_eq!(inbound(&f, PEER, continuation(7)), drop(reasons::FRAGMENT));
    assert_eq!(allowed_len(&f), 0, "expired entry removed on lookup");
    let stats = f.stats();
    assert_eq!((stats.accepted, stats.fragment), (3, 2));
}

/// A small capacity: expired entries are removed first, and nothing is
/// recorded while the table is still full.
#[test]
fn allow_only_is_bounded_and_prunes_expired_under_pressure() {
    let (engine, clock) = clocked_engine(test_policy());
    let f = AclFilter::with_config(engine, identity(), allow_only(2));
    for id in 1..=3 {
        assert_eq!(inbound(&f, PEER, first_fragment(id, 80)), Verdict::Accept);
    }
    assert_eq!(allowed_len(&f), 2, "table must stay bounded");
    // Live entries are never evicted: the third one was not recorded.
    assert_eq!(inbound(&f, PEER, continuation(1)), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, continuation(2)), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, continuation(3)), drop(reasons::FRAGMENT));
    assert_eq!(f.stats().fragment_evictions, 0);

    // Once the live entries have expired, a new one prunes and succeeds.
    advance(&clock, Duration::from_secs(16));
    assert_eq!(inbound(&f, PEER, first_fragment(4, 80)), Verdict::Accept);
    assert_eq!(allowed_len(&f), 1);
    assert_eq!(inbound(&f, PEER, continuation(4)), Verdict::Accept);
}

#[test]
fn allow_only_key_has_no_peer() {
    let f = filter_with(allow_only(4096));
    assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
    assert_eq!(inbound(&f, OTHER_PEER, continuation(7)), Verdict::Accept);
}

#[test]
fn allow_only_records_no_denied_first_fragment() {
    let f = filter_with(allow_only(4096));
    assert_eq!(
        inbound(&f, PEER, first_fragment(9, 81)),
        drop(reasons::DENIED)
    );
    assert_eq!(allowed_len(&f), 0);
    assert_eq!(inbound(&f, PEER, continuation(9)), drop(reasons::FRAGMENT));
    let stats = f.stats();
    assert_eq!((stats.denied, stats.fragment), (1, 1));
}

#[test]
fn allow_only_drops_out_of_order_continuations() {
    let f = filter_with(allow_only(4096));
    assert_eq!(inbound(&f, PEER, continuation(5)), drop(reasons::FRAGMENT));
    assert_eq!(inbound(&f, PEER, first_fragment(5, 80)), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, continuation(5)), Verdict::Accept);
}

#[test]
fn allow_only_last_fragment_keeps_the_entry() {
    let f = filter_with(allow_only(4096));
    let last = || fragment(6, 6, false, &[0; 8]);
    assert_eq!(inbound(&f, PEER, first_fragment(6, 80)), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, last()), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, last()), Verdict::Accept);
    assert_eq!(allowed_len(&f), 1);
}

#[test]
fn allow_only_records_first_fragments_of_several_only() {
    let f = filter_with(allow_only(4096));
    let r = addr("10.0.0.1");
    let l = addr("10.0.0.2");
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        Verdict::Accept
    );
    assert_eq!(allowed_len(&f), 0);
}

#[test]
fn allow_only_judges_continuations_before_the_policy_check() {
    let engine = rules_engine(test_policy());
    let f = AclFilter::with_config(Arc::clone(&engine), identity(), allow_only(4096));
    assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
    engine.uninstall();
    assert_eq!(inbound(&f, PEER, continuation(7)), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, continuation(8)), drop(reasons::FRAGMENT));
    assert_eq!(
        inbound(&f, PEER, first_fragment(9, 80)),
        drop(reasons::NO_POLICY)
    );
    // The outcome mode checks the policy first.
    let f = AclFilter::with_config(engine, identity(), AclFilterConfig::default());
    assert_eq!(inbound(&f, PEER, continuation(7)), drop(reasons::NO_POLICY));
}

#[test]
fn allow_only_leaves_ipv6_fragments_alone() {
    let (r, l) = (addr("fd00::1"), addr("fd00::2"));
    // A fragment header: next header TCP, offset 8 bytes, id 1.
    let frag = ip(r, l, 44, &[protocol::TCP, 0, 0, 8, 0, 0, 0, 1, 0, 0]);
    let first = ip(r, l, 44, &[protocol::TCP, 0, 0, 1, 0, 0, 0, 1, 0, 0]);
    for config in [AclFilterConfig::default(), allow_only(4096)] {
        let f = filter_with(config);
        assert_eq!(inbound(&f, PEER, first.clone()), drop(reasons::PROTOCOL));
        assert_eq!(inbound(&f, PEER, frag.clone()), drop(reasons::PROTOCOL));
        assert_eq!(allowed_len(&f), 0);
    }
}

#[test]
fn accept_to_local_precedes_the_policy() {
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let engine = Arc::new(AclEngine::new());
    let f = AclFilter::with_config(Arc::clone(&engine), identity(), AclFilterConfig::default());
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 9)),
        drop(reasons::NO_POLICY)
    );

    let f = AclFilter::with_config(
        engine,
        identity(),
        AclFilterConfig {
            accept_to_local: Some("10.0.0.2".parse().unwrap()),
            fragments: allow_only(4096).fragments,
            ..AclFilterConfig::default()
        },
    );
    // No policy, any port, an orphan fragment, another protocol.
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 9)),
        Verdict::Accept
    );
    assert_eq!(inbound(&f, PEER, continuation(3)), Verdict::Accept);
    assert_eq!(
        inbound(&f, PEER, ip(r, l, protocol::ICMP, &icmp_echo(8, 1))),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, addr("10.0.0.3"), 9)),
        drop(reasons::NO_POLICY)
    );
    // IPv6 is never bypassed.
    assert_eq!(
        inbound(
            &f,
            PEER,
            tcp_packet(addr("fd00::1"), 4000, addr("fd00::2"), 9)
        ),
        drop(reasons::NO_POLICY)
    );
    let stats = f.stats();
    assert_eq!((stats.bypassed, stats.accepted, stats.no_policy), (3, 0, 2));
    // Outbound is unaffected.
    assert_eq!(
        outbound(&f, PEER, tcp_packet(l, 9, r, 4000)),
        Verdict::Accept
    );
}

#[test]
fn echo_reply_bypass_reads_the_raw_header() {
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let reply = || ip(r, l, protocol::ICMP, &icmp_echo(0, 1));
    let request = || ip(r, l, protocol::ICMP, &icmp_echo(8, 1));
    let f = filter();
    assert_eq!(inbound(&f, PEER, reply()), drop(reasons::PROTOCOL));

    let f = AclFilter::with_config(
        Arc::new(AclEngine::new()),
        identity(),
        AclFilterConfig {
            accept_icmp_echo_reply: true,
            fragments: allow_only(4096).fragments,
            ..AclFilterConfig::default()
        },
    );
    assert_eq!(inbound(&f, PEER, reply()), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, request()), drop(reasons::NO_POLICY));
    // The type byte of a non-first fragment is read too.
    let tail = ip_frag(
        r,
        l,
        protocol::ICMP,
        &[0; 8],
        Some(Frag {
            id: 1,
            offset_units: 4,
            more: false,
        }),
    );
    assert_eq!(inbound(&f, PEER, tail), Verdict::Accept);
    // Too short for an ICMP header.
    assert_eq!(
        inbound(&f, PEER, ip(r, l, protocol::ICMP, &[0; 4])),
        drop(reasons::NO_POLICY)
    );
    // An ICMPv6 echo reply is not bypassed.
    let v6 = ip(
        addr("fd00::1"),
        addr("fd00::2"),
        protocol::ICMPV6,
        &icmp_echo(129, 1),
    );
    assert_eq!(inbound(&f, PEER, v6), drop(reasons::NO_POLICY));
    assert_eq!(f.stats().bypassed, 2);
    // The header length comes from the IHL: with 4 option bytes the type
    // byte follows them, and a header below 20 bytes is never bypassed.
    let with_options = |ihl: u8, icmp_type: u8| {
        let mut bytes = reply().as_packet().to_vec();
        bytes.splice(20..20, [1, 1, 1, 1]);
        bytes[0] = 0x40 | ihl;
        let total = u16::try_from(bytes.len()).unwrap();
        bytes[2..4].copy_from_slice(&total.to_be_bytes());
        bytes[24] = icmp_type;
        PacketBuf::from_packet(&bytes)
    };
    assert_eq!(inbound(&f, PEER, with_options(6, 0)), Verdict::Accept);
    assert_ne!(inbound(&f, PEER, with_options(6, 8)), Verdict::Accept);
    let mut short = reply().as_packet().to_vec();
    short[0] = 0x44;
    assert_ne!(
        inbound(&f, PEER, PacketBuf::from_packet(&short)),
        Verdict::Accept
    );
    // Fewer than 8 bytes after the header.
    let mut truncated = reply().as_packet().to_vec();
    truncated.truncate(27);
    assert_ne!(
        inbound(&f, PEER, PacketBuf::from_packet(&truncated)),
        Verdict::Accept
    );
    assert_eq!(f.stats().bypassed, 3);
}

#[test]
fn stateless_replies_are_judged_by_the_rules() {
    let f = AclFilter::with_config(
        rules_engine(test_policy()),
        identity(),
        AclFilterConfig {
            stateful_replies: false,
            allow_other_protocols: false,
            ..AclFilterConfig::default()
        },
    );
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    assert_eq!(
        outbound(&f, PEER, udp_packet(l, 5000, r, 9)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, udp_packet(r, 9, l, 5000)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        outbound(&f, PEER, ip(l, r, protocol::ICMP, &icmp_echo(8, 1))),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, ip(r, l, protocol::ICMP, &icmp_echo(0, 1))),
        drop(reasons::PROTOCOL)
    );
    // A reply the policy accepts is accepted as new traffic.
    assert_eq!(
        outbound(&f, PEER, tcp_packet(l, 80, r, 4000)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        Verdict::Accept
    );
    let stats = f.stats();
    assert_eq!((stats.replies, stats.accepted), (0, 1));
    let table = f.inner.table();
    assert_eq!(table.entries.len(), 0);
    assert!(table.pending.is_empty());
}

#[test]
fn stateless_replies_record_nothing_for_restricted_peers() {
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace(
            "nsd:a",
            namespace(&[A], Some(vec![outbound_rule(true, PortSet::single(80))])),
        )
        .unwrap();
    let config = AclFilterConfig {
        stateful_replies: false,
        ..AclFilterConfig::default()
    };
    let f = ns_filter(&engine, config);
    let (a, local) = (peer_addr(A), addr(LOCAL));
    for _ in 0..2 {
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 22)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 22, a, 4000)),
            drop(reasons::OUTBOUND)
        );
    }
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 80)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 80, local, 5000)),
        drop(reasons::DENIED)
    );
    let stats = f.stats();
    assert_eq!((stats.outbound_replies, stats.replies), (0, 0));
    let table = f.inner.table();
    assert_eq!(table.entries.len(), table.verdicts, "only cached verdicts");
    assert!(table.pending.is_empty());
}

/// The address label for a peer judged by source address, a key label
/// for another.
fn stateless_identity() -> Arc<PeerLabelMap> {
    let map = Arc::new(PeerLabelMap::new());
    map.insert(PEER, label_set(&[ADDR]));
    map.insert(KEY_PEER, LabelSet::new([key_label()]));
    map
}

/// The options combined: each keeps its own semantics.
#[test]
fn stateless_options_combine() {
    let engine = Arc::new(AclEngine::new());
    let f = AclFilter::with_config(
        Arc::clone(&engine),
        stateless_identity(),
        stateless_options(None),
    );
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    // Not installed: fail closed, except echo replies.
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        drop(reasons::NO_POLICY)
    );
    assert_eq!(
        inbound(&f, PEER, ip(r, l, protocol::ICMP, &icmp_echo(0, 1))),
        Verdict::Accept
    );
    engine.install(test_policy());
    // By label and source prefix.
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 81)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(addr("10.0.0.7"), 4000, l, 80)),
        drop(reasons::DENIED)
    );
    // By label alone, whatever the source address.
    assert_eq!(
        inbound(&f, KEY_PEER, udp_packet(addr("10.0.0.7"), 4000, l, 53)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, udp_packet(addr("10.0.0.7"), 4000, l, 53)),
        drop(reasons::DENIED)
    );
    // Not TCP or UDP.
    assert_eq!(
        inbound(&f, PEER, ip(r, l, protocol::ICMP, &icmp_echo(8, 1))),
        drop(reasons::PROTOCOL)
    );
    // No reply allowances.
    assert_eq!(
        outbound(&f, PEER, tcp_packet(l, 5000, r, 22)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 22, l, 5000)),
        drop(reasons::DENIED)
    );
    // Fragments through the allow-only gate, keyed without the peer.
    assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
    assert_eq!(inbound(&f, OTHER_PEER, continuation(7)), Verdict::Accept);
    assert_eq!(
        inbound(&f, PEER, first_fragment(8, 81)),
        drop(reasons::DENIED)
    );
    assert_eq!(inbound(&f, PEER, continuation(8)), drop(reasons::FRAGMENT));
    // The local address skips the rules.
    let f = AclFilter::with_config(
        engine,
        stateless_identity(),
        stateless_options(Some("10.0.0.2".parse().unwrap())),
    );
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 81)),
        Verdict::Accept
    );
}
