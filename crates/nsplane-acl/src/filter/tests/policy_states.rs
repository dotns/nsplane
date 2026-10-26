//! Policy states and typed rules.

use super::*;

#[test]
fn policy_states_decide_sources_in_no_namespace() {
    let engine = Arc::new(AclEngine::new());
    let f = AclFilter::new(Arc::clone(&engine), identity());
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let new_flow = |port| tcp_packet(r, 4000, l, port);
    assert_eq!(f.stats().policy_state, PolicyState::NotInstalled);

    // Installed and empty: new flows denied, replies still pass.
    engine.install(RuleSet::empty());
    assert_eq!(inbound(&f, PEER, new_flow(80)), drop(reasons::DENIED));
    assert_eq!(
        outbound(&f, PEER, tcp_packet(l, 40000, r, 22)),
        Verdict::Accept
    );
    let reply = || tcp_packet(r, 22, l, 40000);
    assert_eq!(inbound(&f, PEER, reply()), Verdict::Accept);
    assert_eq!(f.stats().policy_state, PolicyState::Installed { rules: 0 });

    // Failed with nothing else loaded: everything dropped, replies too.
    engine.fail();
    assert_eq!(inbound(&f, PEER, reply()), drop(reasons::POLICY_FAILED));
    assert_eq!(
        inbound(&f, PEER, new_flow(80)),
        drop(reasons::POLICY_FAILED)
    );
    let ping = ip(r, l, protocol::ICMP, &icmp_echo(8, 1));
    assert_eq!(inbound(&f, PEER, ping), drop(reasons::POLICY_FAILED));
    assert_eq!(f.stats().policy_state, PolicyState::Failed);

    // Not installed, deny: the state of an engine that never had a policy.
    engine.uninstall();
    assert_eq!(inbound(&f, PEER, reply()), drop(reasons::NO_POLICY));
    let stats = f.stats();
    assert_eq!(
        (
            stats.denied,
            stats.replies,
            stats.policy_failed,
            stats.no_policy
        ),
        (1, 1, 3, 1)
    );
}

#[test]
fn not_installed_accept_lets_every_known_peer_in() {
    let engine = Arc::new(AclEngine::new().with_not_installed(NotInstalled::Accept));
    let f = AclFilter::new(Arc::clone(&engine), identity());
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    for packet in [
        tcp_packet(r, 4000, l, 80),
        udp_packet(r, 4000, l, 9),
        ip(r, l, protocol::ICMP, &icmp_echo(8, 1)),
        ip(r, l, 47, &[0; 8]),
    ] {
        assert_eq!(inbound(&f, PEER, packet), Verdict::Accept);
    }
    // An unknown peer is still unknown; the protocol step reports it.
    let unknown = PeerId::new(99);
    assert_eq!(
        inbound(&f, unknown, tcp_packet(r, 4000, l, 80)),
        drop(reasons::UNKNOWN_PEER)
    );
    assert_eq!(
        inbound(&f, unknown, ip(r, l, 47, &[0; 8])),
        drop(reasons::PROTOCOL)
    );
    let stats = f.stats();
    assert_eq!((stats.accepted, stats.bypassed), (4, 0));
    // Namespace members are governed by their namespaces.
    engine
        .store_namespace(
            "nsd:a",
            NamespacePolicy {
                members: vec![NamespaceMember {
                    label: "peer-1".into(),
                    addresses: Vec::new(),
                }],
                ..NamespacePolicy::default()
            },
        )
        .unwrap();
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4001, l, 80)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, OTHER_PEER, tcp_packet(addr("10.0.0.9"), 4000, l, 80)),
        Verdict::Accept
    );
}

fn typed_rules(rules: impl IntoIterator<Item = crate::Rule>) -> Arc<AclEngine> {
    let engine = Arc::new(AclEngine::new());
    engine.install(RuleSet::new(rules).unwrap());
    engine
}

#[test]
fn other_protocols_reach_the_rules() {
    use crate::{IcmpTypes, ProtocolMatch, Rule};
    let engine = typed_rules([
        Rule::new(
            "ping",
            vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![8, 128]))],
        )
        .with_destinations(["10.0.0.2/32".parse().unwrap(), "fd00::/64".parse().unwrap()]),
        Rule::new("gre", vec![ProtocolMatch::Ip(47)]).with_labels(["peer-1".into()]),
    ]);
    let f = AclFilter::new(Arc::clone(&engine), identity());
    let (r, l, other) = (addr("10.0.0.1"), addr("10.0.0.2"), addr("10.0.0.3"));
    let icmp = |dst, icmp_type| ip(r, dst, protocol::ICMP, &icmp_echo(icmp_type, 1));
    assert_eq!(inbound(&f, PEER, icmp(l, 8)), Verdict::Accept);
    // Another type, another destination.
    assert_eq!(inbound(&f, PEER, icmp(l, 13)), drop(reasons::PROTOCOL));
    assert_eq!(inbound(&f, PEER, icmp(other, 8)), drop(reasons::PROTOCOL));
    // ICMPv6 by its own type numbers.
    let (r6, l6) = (addr("fd00::1"), addr("fd00::2"));
    let ping6 = ip(r6, l6, protocol::ICMPV6, &icmp_echo(128, 1));
    assert_eq!(inbound(&f, KEY_PEER, ping6), Verdict::Accept);
    // A labelled rule: only the labelled peer.
    let gre = |src| ip(src, l, 47, &[0; 8]);
    assert_eq!(inbound(&f, PEER, gre(r)), Verdict::Accept);
    assert_eq!(
        inbound(&f, OTHER_PEER, gre(addr("10.0.0.9"))),
        drop(reasons::PROTOCOL)
    );
    assert_eq!(inbound(&f, KEY_PEER, gre(r)), drop(reasons::PROTOCOL));
    assert_eq!(
        inbound(&f, PeerId::new(99), gre(r)),
        drop(reasons::PROTOCOL)
    );
    // A non-first fragment follows its first fragment.
    let first = ip_frag(
        r,
        l,
        47,
        &[0; 16],
        Some(Frag {
            id: 3,
            offset_units: 0,
            more: true,
        }),
    );
    let later = ip_frag(
        r,
        l,
        47,
        &[0; 8],
        Some(Frag {
            id: 3,
            offset_units: 2,
            more: false,
        }),
    );
    assert_eq!(inbound(&f, PEER, first), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, later), Verdict::Accept);
    let stats = f.stats();
    assert_eq!((stats.accepted, stats.protocol, stats.denied), (5, 5, 0));

    // TCP and UDP are unaffected by such rules.
    assert_eq!(
        inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
        drop(reasons::DENIED)
    );
}

#[test]
fn other_protocol_steps_come_first() {
    use crate::{ProtocolMatch, Rule};
    let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
    let ping = || ip(r, l, protocol::ICMP, &icmp_echo(8, 1));
    // Without a matching rule a scope rule or `allow_other_protocols`
    // still accepts.
    let engine = typed_rules([Rule::new("gre", vec![ProtocolMatch::Ip(47)])]);
    let scope = AclFilterScope::new().with_other_protocol(OtherProtocolRule::new(
        OtherProtocol::IcmpEcho,
        ["10.0.0.0/24".parse().unwrap()],
    ));
    let f = AclFilter::with_scope(
        Arc::clone(&engine),
        identity(),
        AclFilterConfig::default(),
        scope,
    );
    assert_eq!(inbound(&f, PEER, ping()), Verdict::Accept);
    let open = AclFilter::with_config(
        Arc::clone(&engine),
        identity(),
        AclFilterConfig {
            allow_other_protocols: true,
            ..AclFilterConfig::default()
        },
    );
    assert_eq!(inbound(&open, PEER, ping()), Verdict::Accept);
    // A rule set without ICMP entries leaves ICMP dropped.
    let plain = AclFilter::new(engine, identity());
    assert_eq!(inbound(&plain, PEER, ping()), drop(reasons::PROTOCOL));
}

#[test]
fn prefix_and_label_rule_needs_both() {
    use crate::{PortSet, ProtocolMatch, Rule};
    let engine = typed_rules([Rule::new("both", vec![ProtocolMatch::Tcp(PortSet::Any)])
        .with_labels([key_label()])
        .with_sources(["fd00::/64".parse().unwrap()])]);
    let f = AclFilter::new(engine, identity());
    let l = addr("fd00::2");
    assert_eq!(
        inbound(&f, KEY_PEER, tcp_packet(addr("fd00::7"), 4000, l, 80)),
        Verdict::Accept
    );
    // The labelled peer outside the prefix, another peer inside it.
    assert_eq!(
        inbound(&f, KEY_PEER, tcp_packet(addr("fd01::7"), 4000, l, 80)),
        drop(reasons::DENIED)
    );
    let map = identity();
    map.insert(PeerId::new(8), label_set(&["other"]));
    let f = AclFilter::new(
        typed_rules([
            Rule::new("any", vec![ProtocolMatch::Any]).with_sources(["fd00::/64".parse().unwrap()])
        ]),
        map,
    );
    assert_eq!(
        inbound(&f, PeerId::new(8), tcp_packet(addr("fd00::7"), 4000, l, 80)),
        Verdict::Accept
    );
}
