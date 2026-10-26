//! Labels per source address.

use super::*;

const GATEWAY: PeerId = PeerId::new(20);

/// The host prefix of `ip`.
fn host(ip: IpAddr) -> IpNet {
    ip.to_string().parse().unwrap()
}

/// The member label of the source address `ip`.
fn address_label(ip: IpAddr) -> Label {
    Label::from(format!("addr:{ip}"))
}

/// The ns identities plus [`GATEWAY`] labelled per source address:
/// `peer_addr(A)` carries `ADDR` and its own member label, every other
/// address `ADDR`.
fn by_source_identity() -> Arc<PeerLabelMap> {
    let map = ns_identity();
    let member = peer_addr(A);
    map.insert_by_source(
        GATEWAY,
        vec![
            (net("0.0.0.0/0"), label_set(&[ADDR])),
            (net("::/0"), label_set(&[ADDR])),
            (
                host(member),
                LabelSet::new([ADDR.into(), address_label(member)]),
            ),
        ],
    );
    map
}

/// A namespace whose only member is the label of the source address
/// `member`, with `rules` and the given outbound rules.
fn address_namespace(
    member: IpAddr,
    rules: Vec<Rule>,
    outbound: Option<Vec<OutboundRule>>,
) -> NamespacePolicy {
    NamespacePolicy {
        members: vec![NamespaceMember {
            label: address_label(member),
            addresses: vec![host(member)],
        }],
        rules,
        outbound,
        ..NamespacePolicy::default()
    }
}

#[test]
fn insert_by_source_takes_the_longest_prefix() {
    let map = PeerLabelMap::new();
    let generation = map.generation();
    map.insert_by_source(
        GATEWAY,
        vec![
            (net("10.0.0.0/8"), label_set(&["wide"])),
            (net("10.1.0.0/16"), label_set(&["narrow"])),
            (net("10.1.2.3/32"), label_set(&["host", "narrow"])),
            (net("10.1.0.0/16"), label_set(&["second"])),
        ],
    );
    assert!(map.generation() > generation);
    assert!(map.by_source(GATEWAY));
    assert_eq!(map.labels(GATEWAY), None);
    let labels = |ip| map.labels_for(GATEWAY, addr(ip));
    assert_eq!(labels("10.1.2.3"), Some(label_set(&["host", "narrow"])));
    // Equally long prefixes: the first listed wins.
    assert_eq!(labels("10.1.2.4"), Some(label_set(&["narrow"])));
    assert_eq!(labels("10.2.0.1"), Some(label_set(&["wide"])));
    // Outside every prefix (another family included): unknown.
    assert_eq!(labels("11.0.0.1"), None);
    assert_eq!(labels("fd00::1"), None);
    // An empty table makes every address unknown.
    map.insert_by_source(GATEWAY, Vec::new());
    assert_eq!(labels("10.1.2.3"), None);
    // `insert` replaces the table.
    map.insert(GATEWAY, label_set(&["fixed"]));
    assert!(!map.by_source(GATEWAY));
    assert_eq!(labels("11.0.0.1"), Some(label_set(&["fixed"])));
}

#[test]
fn by_source_peer_outside_its_prefixes_is_unknown() {
    let map = Arc::new(PeerLabelMap::new());
    map.insert_by_source(GATEWAY, vec![(net("10.0.0.0/30"), label_set(&[ADDR]))]);
    let f = AclFilter::new(rules_engine(test_policy()), Arc::clone(&map));
    let l = addr("10.0.0.2");
    assert_eq!(
        inbound(&f, GATEWAY, tcp_packet(addr("10.0.0.1"), 4000, l, 80)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, GATEWAY, tcp_packet(addr("10.0.0.5"), 4000, l, 80)),
        drop(reasons::UNKNOWN_PEER)
    );
    assert_eq!(f.stats().unknown_peer, 1);
}

#[test]
fn by_source_peer_is_judged_by_each_source() {
    let map = by_source_identity();
    let (r, other, l) = (addr("10.0.0.1"), addr("10.0.0.5"), addr("10.0.0.2"));
    assert!(map.by_source(GATEWAY) && !map.by_source(KEY_PEER));

    let f = AclFilter::new(rules_engine(test_policy()), Arc::clone(&map));
    assert_eq!(
        inbound(&f, GATEWAY, tcp_packet(r, 4000, l, 80)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, GATEWAY, tcp_packet(other, 4000, l, 80)),
        drop(reasons::DENIED)
    );
    // Each source keeps its own verdict on later packets.
    assert_eq!(
        inbound(&f, GATEWAY, tcp_packet(r, 4001, l, 80)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, GATEWAY, tcp_packet(other, 4001, l, 80)),
        drop(reasons::DENIED)
    );
    // A peer with a fixed label set in the same map keeps it.
    assert_eq!(
        inbound(&f, KEY_PEER, udp_packet(other, 5000, l, 53)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, KEY_PEER, tcp_packet(r, 4000, l, 80)),
        drop(reasons::DENIED)
    );
}

#[test]
fn by_source_cache_is_bounded() {
    let config = AclFilterConfig {
        reply_capacity: 2,
        ..AclFilterConfig::default()
    };
    let f = AclFilter::with_config(rules_engine(test_policy()), by_source_identity(), config);
    let l = addr("10.0.0.2");
    for round in 0..3 {
        for last in [1, 5, 6, 7] {
            let src = addr(&format!("10.0.0.{last}"));
            let expected = if last == 1 {
                Verdict::Accept
            } else {
                drop(reasons::DENIED)
            };
            assert_eq!(
                inbound(&f, GATEWAY, tcp_packet(src, 4000 + round, l, 80)),
                expected
            );
        }
    }
    let table = f.inner.table();
    assert!(table.sources.len() <= 2);
}

#[test]
fn closure_identity_uses_the_default_labels_for() {
    let identity = |peer: PeerId| (peer == PEER).then(|| LabelSet::new([key_label()]));
    let any = addr("10.0.0.9");
    assert_eq!(
        identity.labels_for(PEER, any),
        Some(LabelSet::new([key_label()]))
    );
    assert!(!identity.by_source(PEER));
    assert_eq!(identity.generation(), 0);
    let f = AclFilter::new(rules_engine(test_policy()), identity);
    assert_eq!(
        inbound(&f, PEER, udp_packet(any, 5000, addr("10.0.0.2"), 53)),
        Verdict::Accept
    );
}

#[test]
fn switching_between_by_source_and_by_key_applies_to_the_next_packet() {
    let engine = Arc::new(AclEngine::new());
    let member = peer_addr(A);
    engine
        .store_namespace(
            "nsd:a",
            address_namespace(member, vec![tcp_rule(PortSet::single(22))], None),
        )
        .unwrap();
    let map = by_source_identity();
    let f = AclFilter::new(Arc::clone(&engine), Arc::clone(&map));
    let local = addr(LOCAL);
    let packet = || tcp_packet(member, 4000, local, 22);

    // The member source's flow verdict is cached.
    assert_eq!(inbound(&f, GATEWAY, packet()), Verdict::Accept);
    assert_eq!(inbound(&f, GATEWAY, packet()), Verdict::Accept);
    // Another source of the same peer is in no namespace.
    assert_eq!(
        inbound(&f, GATEWAY, tcp_packet(addr("fd00::77"), 4000, local, 22)),
        drop(reasons::NO_POLICY)
    );

    // A fixed label set: `label(A)` is in no namespace either.
    map.insert(GATEWAY, LabelSet::new([label(A)]));
    assert_eq!(inbound(&f, GATEWAY, packet()), drop(reasons::NO_POLICY));
    let table = vec![(host(member), LabelSet::new([address_label(member)]))];
    map.insert_by_source(GATEWAY, table);
    assert_eq!(inbound(&f, GATEWAY, packet()), Verdict::Accept);
    map.remove(GATEWAY);
    assert_eq!(inbound(&f, GATEWAY, packet()), drop(reasons::UNKNOWN_PEER));
}

#[test]
fn bypass_is_never_shared_across_sources() {
    let engine = Arc::new(AclEngine::new());
    let open = addr("fd00::b");
    let accept_all = Rule::new(
        "0",
        vec![
            ProtocolMatch::Tcp(PortSet::Any),
            ProtocolMatch::Udp(PortSet::Any),
        ],
    );
    engine
        .store_namespace("nsd:a", address_namespace(open, vec![accept_all], None))
        .unwrap();
    let f = AclFilter::new(Arc::clone(&engine), by_source_identity());
    let local = addr(LOCAL);
    assert_eq!(
        inbound(&f, GATEWAY, udp_packet(open, 4000, local, 9999)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, GATEWAY, udp_packet(addr("fd00::c"), 4000, local, 9999)),
        drop(reasons::NO_POLICY)
    );

    // A default policy that accepts everything bypasses every source in no namespace.
    engine.install(RuleSet::new([udp_rule(PortSet::Any)]).unwrap());
    assert_eq!(
        inbound(&f, GATEWAY, udp_packet(addr("fd00::c"), 4000, local, 9999)),
        Verdict::Accept
    );
    // A partial default policy bypasses nothing.
    engine.install(
        RuleSet::new([Rule::new("d", vec![ProtocolMatch::Udp(PortSet::Any)])
            .with_labels([ADDR.into()])
            .with_sources([net("fd00::d/128")])])
        .unwrap(),
    );
    assert_eq!(
        inbound(&f, GATEWAY, udp_packet(addr("fd00::d"), 4000, local, 9999)),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, GATEWAY, udp_packet(addr("fd00::c"), 4000, local, 9999)),
        drop(reasons::DENIED)
    );
}

#[test]
fn outbound_restriction_follows_the_destination_address() {
    let engine = Arc::new(AclEngine::new());
    let restricted = peer_addr(A);
    engine
        .store_namespace(
            "nsd:a",
            address_namespace(
                restricted,
                vec![tcp_rule(PortSet::single(22))],
                Some(vec![outbound_rule(true, PortSet::single(80))]),
            ),
        )
        .unwrap();
    let local = addr(LOCAL);
    for f in [
        AclFilter::new(Arc::clone(&engine), by_source_identity()),
        AclFilter::uncached(
            Arc::clone(&engine),
            by_source_identity(),
            AclFilterConfig::default(),
        ),
    ] {
        assert_eq!(
            outbound(&f, GATEWAY, tcp_packet(local, 5000, restricted, 9999)),
            drop(reasons::OUTBOUND)
        );
        assert_eq!(
            outbound(&f, GATEWAY, tcp_packet(local, 5000, restricted, 80)),
            Verdict::Accept
        );
        // Another destination behind the same peer is unrestricted.
        assert_eq!(
            outbound(&f, GATEWAY, tcp_packet(local, 5000, addr("fd00::c"), 9999)),
            Verdict::Accept
        );
        // The restricted source's accepted inbound flow allows its reply.
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(restricted, 4000, local, 22)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, GATEWAY, tcp_packet(local, 22, restricted, 4000)),
            Verdict::Accept
        );
        let stats = f.stats();
        assert_eq!((stats.outbound_denied, stats.outbound_replies), (1, 1));
    }
}
