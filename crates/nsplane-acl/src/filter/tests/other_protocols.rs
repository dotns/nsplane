//! Other-protocol scope rules.

use super::*;

/// The local addresses `LOCAL4/32` and `LOCAL/128`.
fn own_addresses() -> [IpNet; 2] {
    [
        format!("{LOCAL4}/32").parse().unwrap(),
        format!("{LOCAL}/128").parse().unwrap(),
    ]
}

/// A filter of `engine` accepting `protocol` to [`own_addresses`].
fn other_scoped(
    engine: &Arc<AclEngine>,
    config: AclFilterConfig,
    protocol: OtherProtocol,
) -> AclFilter {
    let rule = OtherProtocolRule::new(protocol, own_addresses());
    let scope = AclFilterScope::new().with_other_protocol(rule);
    AclFilter::with_scope(Arc::clone(engine), ns_identity(), config, scope)
}

fn icmp_message(icmp_type: u8) -> Vec<u8> {
    vec![icmp_type, 0, 0, 0, 0, 0, 0, 0]
}

#[test]
fn default_scope_has_no_other_protocol_rules() {
    assert_eq!(AclFilterScope::default().other_protocols, Vec::new());
    let f = AclFilter::with_scope(
        scope_engine(),
        ns_identity(),
        AclFilterConfig::default(),
        AclFilterScope::default(),
    );
    let ping = ip(
        peer_addr(A),
        addr(LOCAL),
        protocol::ICMPV6,
        &icmp_echo(128, 1),
    );
    assert_eq!(inbound(&f, A, ping), drop(reasons::PROTOCOL));
    assert_eq!(f.stats().protocol, 1);
}

#[test]
fn icmp_echo_rule_accepts_echo_to_own_addresses_only() {
    let engine = scope_engine();
    let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
    let (a, local, local4) = (peer_addr(A), addr(LOCAL), addr(LOCAL4));
    let r4 = addr("10.0.0.1");

    // The ns evidence (`acl_passes_icmpv6_echo_to_n6_self`), flipped: an echo to
    // N6(self) passes, an echo to another peer's address is dropped.
    let ping = |dst| ip(a, dst, protocol::ICMPV6, &icmp_echo(128, 1));
    assert_eq!(inbound(&f, A, ping(local)), Verdict::Accept);
    assert_eq!(inbound(&f, A, ping(peer_addr(C))), drop(reasons::PROTOCOL));
    let ping4 = |dst| ip(r4, dst, protocol::ICMP, &icmp_echo(8, 1));
    assert_eq!(inbound(&f, PEER, ping4(local4)), Verdict::Accept);
    assert_eq!(
        inbound(&f, PEER, ping4(addr("10.0.0.9"))),
        drop(reasons::PROTOCOL)
    );

    // Other ICMP messages to an own address are not echo requests.
    let timestamp = || ip(r4, local4, protocol::ICMP, &icmp_message(13));
    let unreachable = || ip(a, local, protocol::ICMPV6, &icmp_message(1));
    assert_eq!(inbound(&f, PEER, timestamp()), drop(reasons::PROTOCOL));
    assert_eq!(inbound(&f, A, unreachable()), drop(reasons::PROTOCOL));
    let stats = f.stats();
    assert_eq!((stats.accepted, stats.protocol), (2, 4));

    // Every ICMP message under `Icmp`, still to own addresses only.
    let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::Icmp);
    assert_eq!(inbound(&f, PEER, timestamp()), Verdict::Accept);
    assert_eq!(inbound(&f, A, unreachable()), Verdict::Accept);
    assert_eq!(inbound(&f, A, ping(local)), Verdict::Accept);
    assert_eq!(inbound(&f, A, ping(peer_addr(C))), drop(reasons::PROTOCOL));
    // Neither TCP nor UDP is affected.
    assert_eq!(
        inbound(&f, PEER, udp_packet(r4, 4000, local4, 9)),
        drop(reasons::DENIED)
    );
    assert_eq!(f.stats().accepted, 3);

    // No policy loaded: still dropped.
    let f = other_scoped(
        &Arc::new(AclEngine::new()),
        AclFilterConfig::default(),
        OtherProtocol::Icmp,
    );
    assert_eq!(inbound(&f, A, ping(local)), drop(reasons::NO_POLICY));
}

#[test]
fn ip_protocol_rule_matches_the_protocol_number() {
    const GRE: u8 = 47;
    let engine = scope_engine();
    let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::Ip(GRE));
    let (r, local4) = (addr("10.0.0.1"), addr(LOCAL4));
    assert_eq!(
        inbound(&f, PEER, ip(r, local4, GRE, &[0; 4])),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, ip(r, addr("10.0.0.9"), GRE, &[0; 4])),
        drop(reasons::PROTOCOL)
    );
    assert_eq!(
        inbound(&f, PEER, ip(r, local4, protocol::ICMP, &icmp_echo(8, 1))),
        drop(reasons::PROTOCOL)
    );
}

#[test]
fn allow_other_protocols_still_accepts_everything() {
    let engine = scope_engine();
    let config = AclFilterConfig {
        allow_other_protocols: true,
        ..AclFilterConfig::default()
    };
    let f = other_scoped(&engine, config, OtherProtocol::IcmpEcho);
    let a = peer_addr(A);
    for packet in [
        ip(a, peer_addr(C), protocol::ICMPV6, &icmp_echo(128, 1)),
        ip(a, addr(LOCAL), protocol::ICMPV6, &icmp_message(1)),
        ip(a, addr("fd00::99"), 47, &[0; 4]),
    ] {
        assert_eq!(inbound(&f, A, packet), Verdict::Accept);
    }
    assert_eq!(f.stats().accepted, 3);
}

#[test]
fn echo_request_accepted_by_an_outbound_rule_allows_its_reply() {
    use crate::{IcmpTypes, ProtocolMatch};

    let ping_rule = OutboundRule::new("ping", vec![ProtocolMatch::Icmp(IcmpTypes::Any)]);
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace("nsd:a", namespace(&[A], Some(vec![ping_rule])))
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    let (a, local) = (peer_addr(A), addr(LOCAL));
    let request = |id| ip(local, a, protocol::ICMPV6, &icmp_echo(128, id));
    let reply = |id| ip(a, local, protocol::ICMPV6, &icmp_echo(129, id));
    let (a4, local4) = (addr("10.0.0.11"), addr("10.0.0.2"));
    let request4 = || ip(local4, a4, protocol::ICMP, &icmp_echo(8, 3));
    let reply4 = || ip(a4, local4, protocol::ICMP, &icmp_echo(0, 3));

    assert_eq!(inbound(&f, A, reply(7)), drop(reasons::PROTOCOL));
    assert_eq!(outbound(&f, A, request(7)), Verdict::Accept);
    assert_eq!(inbound(&f, A, reply(7)), Verdict::Accept);
    assert_eq!(inbound(&f, A, reply(8)), drop(reasons::PROTOCOL));
    assert_eq!(outbound(&f, A, request4()), Verdict::Accept);
    assert_eq!(inbound(&f, A, reply4()), Verdict::Accept);
    assert_eq!(f.stats().replies, 2);

    // An outbound rule without ICMP denies the request, and the reply stays out.
    let engine = Arc::new(AclEngine::new());
    engine
        .store_namespace(
            "nsd:a",
            namespace(&[A], Some(vec![outbound_rule(true, PortSet::single(80))])),
        )
        .unwrap();
    let f = ns_filter(&engine, AclFilterConfig::default());
    assert_eq!(outbound(&f, A, request(7)), drop(reasons::OUTBOUND));
    assert_eq!(inbound(&f, A, reply(7)), drop(reasons::PROTOCOL));
}

#[test]
fn restricted_peer_echo_is_answered_through_the_reply_table() {
    let engine = scope_engine();
    let (a, local) = (peer_addr(A), addr(LOCAL));
    let request = || ip(a, local, protocol::ICMPV6, &icmp_echo(128, 7));
    let reply = |id| ip(local, a, protocol::ICMPV6, &icmp_echo(129, id));

    // Without a scope rule the restricted peer's reply is denied as today.
    let unscoped = ns_filter(&engine, AclFilterConfig::default());
    assert_eq!(outbound(&unscoped, A, reply(7)), drop(reasons::OUTBOUND));

    let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
    // An unsolicited reply is denied.
    assert_eq!(outbound(&f, A, reply(7)), drop(reasons::OUTBOUND));
    assert_eq!(inbound(&f, A, request()), Verdict::Accept);
    assert_eq!(outbound(&f, A, reply(7)), Verdict::Accept);
    // A reply with another identifier, or another message, is not.
    assert_eq!(outbound(&f, A, reply(8)), drop(reasons::OUTBOUND));
    assert_eq!(
        outbound(&f, A, ip(local, a, protocol::ICMPV6, &icmp_echo(128, 7))),
        drop(reasons::OUTBOUND)
    );
    let stats = f.stats();
    assert_eq!((stats.outbound_replies, stats.outbound_denied), (1, 3));

    // Another protocol from the restricted peer is answered the same way.
    let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::Ip(47));
    assert_eq!(inbound(&f, A, ip(a, local, 47, &[0; 4])), Verdict::Accept);
    assert_eq!(outbound(&f, A, ip(local, a, 47, &[0; 4])), Verdict::Accept);
    assert_eq!(f.stats().outbound_replies, 1);

    // An unversioned identity resolves the peer on each packet.
    let identities = ns_identity();
    let identity = move |peer: PeerId| identities.labels(peer);
    let rule = OtherProtocolRule::new(OtherProtocol::IcmpEcho, own_addresses());
    let f = AclFilter::with_scope(
        Arc::clone(&engine),
        identity,
        AclFilterConfig::default(),
        AclFilterScope::new().with_other_protocol(rule),
    );
    assert_eq!(inbound(&f, A, request()), Verdict::Accept);
    assert_eq!(outbound(&f, A, reply(7)), Verdict::Accept);

    // No allowance without stateful replies.
    let config = AclFilterConfig {
        stateful_replies: false,
        ..AclFilterConfig::default()
    };
    let f = other_scoped(&engine, config, OtherProtocol::IcmpEcho);
    assert_eq!(inbound(&f, A, request()), Verdict::Accept);
    assert_eq!(outbound(&f, A, reply(7)), drop(reasons::OUTBOUND));
    assert_eq!(f.inner.table().entries.len(), 0);

    // An unrestricted peer records no outbound allowance.
    let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
    let ping = ip(
        addr("10.0.0.1"),
        addr(LOCAL4),
        protocol::ICMP,
        &icmp_echo(8, 1),
    );
    assert_eq!(inbound(&f, PEER, ping), Verdict::Accept);
    assert_eq!(f.inner.table().entries.len(), 0);
}

#[test]
fn own_pings_are_answered_with_a_scope_rule() {
    let engine = scope_engine();
    let (r, local4) = (addr("10.0.0.1"), addr(LOCAL4));
    let (r6, local) = (addr("fd00::6"), addr(LOCAL));
    let request = || ip(local4, r, protocol::ICMP, &icmp_echo(8, 9));
    let reply = || ip(r, local4, protocol::ICMP, &icmp_echo(0, 9));
    let request6 = || ip(local, r6, protocol::ICMPV6, &icmp_echo(128, 9));
    let reply6 = || ip(r6, local, protocol::ICMPV6, &icmp_echo(129, 9));

    let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
    assert_eq!(inbound(&f, PEER, reply()), drop(reasons::PROTOCOL));
    assert_eq!(outbound(&f, PEER, request()), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, reply()), Verdict::Accept);
    // IPv6, to an unrestricted key peer.
    let map = ns_identity();
    let peer6 = PeerId::new(6);
    map.insert(peer6, label_set(&["k6"]));
    let rule = OtherProtocolRule::new(OtherProtocol::IcmpEcho, own_addresses());
    let f6 = AclFilter::with_scope(
        Arc::clone(&engine),
        map,
        AclFilterConfig::default(),
        AclFilterScope::new().with_other_protocol(rule),
    );
    assert_eq!(outbound(&f6, peer6, request6()), Verdict::Accept);
    assert_eq!(inbound(&f6, peer6, reply6()), Verdict::Accept);
    assert_eq!((f.stats().replies, f6.stats().replies), (1, 1));

    // Without stateful replies the reply is judged as new traffic.
    let config = AclFilterConfig {
        stateful_replies: false,
        ..AclFilterConfig::default()
    };
    let f = other_scoped(&engine, config, OtherProtocol::IcmpEcho);
    assert_eq!(outbound(&f, PEER, request()), Verdict::Accept);
    assert_eq!(inbound(&f, PEER, reply()), drop(reasons::PROTOCOL));
}

#[test]
fn fragments_of_an_accepted_icmp_packet_follow_the_first_fragment() {
    let engine = scope_engine();
    let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
    let r = addr("10.0.0.1");
    let frag = |dst, offset_units, more, transport: &[u8]| {
        ip_frag(
            r,
            dst,
            protocol::ICMP,
            transport,
            Some(Frag {
                id: 3,
                offset_units,
                more,
            }),
        )
    };
    let (own, other) = (addr(LOCAL4), addr("10.0.0.9"));
    assert_eq!(
        inbound(&f, PEER, frag(own, 0, true, &icmp_echo(8, 1))),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, frag(own, 1, false, &[0; 8])),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, frag(other, 0, true, &icmp_echo(8, 1))),
        drop(reasons::PROTOCOL)
    );
    assert_eq!(
        inbound(&f, PEER, frag(other, 1, false, &[0; 8])),
        drop(reasons::PROTOCOL)
    );
    let stats = f.stats();
    assert_eq!((stats.accepted, stats.protocol), (2, 2));
}
