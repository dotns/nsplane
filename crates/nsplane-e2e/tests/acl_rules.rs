//! Typed ACL rules and policy states at engine level, over an in-memory channel transport:
//! two nodes `a` and `b`, where `b` runs an `AclFilter` and `a` runs none. `a`'s source
//! labels are its WireGuard key label. The tests install typed rules, move the default rule
//! set through its states (not installed, installed, failed) and check deliveries,
//! `Event::Dropped` reasons, the filter counters, and that `AclEngine::evaluate` gives the
//! decision the filter applies to the first packet of a flow.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use nsplane::{ChannelTransport, Event, TransportId};
use nsplane_acl::{
    AclEngine, AclFilter, Decision, Flow, IcmpTypes, IpNet, Label, LabelSet, Matched, NotInstalled,
    PeerIdentityMap, PolicyState, PortSet, ProtocolMatch, Rule, RuleId, RuleSet, SourceAssertion,
    reasons, wg_peer_anchor,
};
use nsplane_e2e::{Events, Node, Options, TestResult, icmp, introduce, udp};

/// Capacity of the channel transport pair.
const CAPACITY: usize = 1024;
/// The port `a`'s packets come from.
const SRC_PORT: u16 = 40000;
/// A port the rules of the tests allow on `b`.
const ALLOWED: u16 = 7000;
/// A port no rule allows.
const DENIED: u16 = 7001;

type AclNode = Node<ChannelTransport>;

/// Two peers linked by a channel transport, `b` with an `AclFilter` over `engine`; `a` is
/// known to `b` by its WireGuard key. Returns `a`'s source labels too.
async fn acl_pair(engine: &Arc<AclEngine>) -> TestResult<(AclNode, AclNode, AclFilter, LabelSet)> {
    let identities = Arc::new(PeerIdentityMap::new());
    let filter = AclFilter::new(Arc::clone(engine), Arc::clone(&identities));
    let a_end = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b_end = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(CAPACITY, a_end, b_end);
    let a = Node::with_builder(1, a_end.0, a_end.1, Options::default(), |builder| {
        builder.transport(link_a)
    })?;
    let b_filter = filter.clone();
    let b = Node::with_builder(2, b_end.0, b_end.1, Options::default(), |builder| {
        builder.transport(link_b).filter(Box::new(b_filter))
    })?;
    introduce(&a, &b, None).await?;
    let key = a.public().to_bytes();
    identities.insert(
        b.peer_of(&a).await?,
        SourceAssertion::WgPeerKey { pubkey: key },
    );
    let labels = LabelSet::new([Label::from(wg_peer_anchor(&key))]);
    Ok((a, b, filter, labels))
}

/// The host network of `ip`.
fn host(ip: IpAddr) -> TestResult<IpNet> {
    Ok(ip.to_string().parse()?)
}

/// Sends `packet` from `from` and checks that `to` delivers it unchanged.
async fn delivered(from: &AclNode, to: &mut AclNode, packet: &[u8]) -> TestResult {
    from.send(packet).await?;
    let (_, got) = to.expect_delivery().await?;
    if got != packet {
        return Err("packet changed in transit".into());
    }
    Ok(())
}

/// Sends `packet` from `from` and checks that `to` drops it with `reason`.
async fn dropped(
    from: &AclNode,
    to: &mut AclNode,
    events: &mut Events,
    packet: &[u8],
    reason: &'static str,
) -> TestResult {
    from.send(packet).await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason: r, .. } if *r == reason))
        .await?;
    to.expect_no_delivery().await
}

/// An echo request from `src` to `dst` with identifier `id`.
fn echo_request(src: IpAddr, dst: IpAddr, id: u16) -> Vec<u8> {
    let [hi, lo] = id.to_be_bytes();
    let kind = if src.is_ipv4() { 8 } else { 128 };
    icmp(src, dst, (kind, 0), [hi, lo, 0, 1], b"ping")
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn typed_rules_decide_and_report_their_ids() -> TestResult {
    let engine = Arc::new(AclEngine::new());
    let (a, mut b, filter, labels) = acl_pair(&engine).await?;
    let mut events = b.subscribe().await?;
    let (from, to) = (IpAddr::V4(a.ip4), IpAddr::V4(b.ip4));
    engine.install(RuleSet::new([
        Rule::new(
            "udp-to-b",
            vec![ProtocolMatch::Udp(PortSet::single(ALLOWED))],
        )
        .with_labels(labels.iter().cloned())
        .with_destinations([host(to)?, host(IpAddr::V6(b.ip6))?]),
        Rule::new("other-labels", vec![ProtocolMatch::Any]).with_labels([Label::from("x")]),
    ])?);
    assert_eq!(engine.policy_state(), PolicyState::Installed { rules: 2 });

    let allowed = SocketAddr::new(to, ALLOWED);
    let a_end = SocketAddr::new(from, SRC_PORT);
    let decision = engine.evaluate(&labels, &Flow::udp(a_end, allowed));
    assert_eq!(decision.rule_id().map(RuleId::as_str), Some("udp-to-b"));
    delivered(&a, &mut b, &udp(a_end, allowed, b"in")).await?;

    let denied = SocketAddr::new(to, DENIED);
    assert_eq!(
        engine.evaluate(&labels, &Flow::udp(a_end, denied)),
        Decision::Deny(reasons::DENIED)
    );
    dropped(
        &a,
        &mut b,
        &mut events,
        &udp(a_end, denied, b"in"),
        reasons::DENIED,
    )
    .await?;
    // Rules without ICMP entries leave ICMP to the protocol step.
    dropped(
        &a,
        &mut b,
        &mut events,
        &echo_request(from, to, 1),
        reasons::PROTOCOL,
    )
    .await?;

    let stats = filter.stats();
    assert_eq!((stats.accepted, stats.denied, stats.protocol), (1, 1, 1));
    assert_eq!(stats.policy_state, PolicyState::Installed { rules: 2 });
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn not_installed_denies_or_accepts() -> TestResult {
    let deny = Arc::new(AclEngine::new());
    let (a, mut b, filter, labels) = acl_pair(&deny).await?;
    let mut events = b.subscribe().await?;
    let (from, to) = (IpAddr::V4(a.ip4), IpAddr::V4(b.ip4));
    let a_end = SocketAddr::new(from, SRC_PORT);
    let flow = Flow::udp(a_end, SocketAddr::new(to, ALLOWED));
    assert_eq!(
        deny.evaluate(&labels, &flow),
        Decision::Deny(reasons::NO_POLICY)
    );
    let packet = udp(a_end, SocketAddr::new(to, ALLOWED), b"in");
    dropped(&a, &mut b, &mut events, &packet, reasons::NO_POLICY).await?;
    assert_eq!(filter.stats().no_policy, 1);

    let accept = Arc::new(AclEngine::new().with_not_installed(NotInstalled::Accept));
    let (a, mut b, filter, labels) = acl_pair(&accept).await?;
    assert_eq!(
        accept.evaluate(&labels, &flow),
        Decision::Accept(Matched::NotInstalled)
    );
    let (from, to) = (IpAddr::V4(a.ip4), IpAddr::V4(b.ip4));
    let a_end = SocketAddr::new(from, SRC_PORT);
    delivered(&a, &mut b, &udp(a_end, SocketAddr::new(to, DENIED), b"in")).await?;
    delivered(&a, &mut b, &echo_request(from, to, 1)).await?;
    let stats = filter.stats();
    assert_eq!(
        (stats.accepted, stats.policy_state),
        (2, PolicyState::NotInstalled)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn installed_empty_denies_new_flows_but_passes_replies() -> TestResult {
    let engine = Arc::new(AclEngine::new());
    let (mut a, mut b, filter, _) = acl_pair(&engine).await?;
    let mut events = b.subscribe().await?;
    engine.install(RuleSet::empty());
    let a_end = SocketAddr::new(IpAddr::V4(a.ip4), SRC_PORT);
    let b_end = SocketAddr::new(IpAddr::V4(b.ip4), ALLOWED);
    dropped(
        &a,
        &mut b,
        &mut events,
        &udp(a_end, b_end, b"in"),
        reasons::DENIED,
    )
    .await?;
    // `b` opens the flow; `a`'s reply passes the reply table.
    delivered(&b, &mut a, &udp(b_end, a_end, b"out")).await?;
    delivered(&a, &mut b, &udp(a_end, b_end, b"reply")).await?;
    let stats = filter.stats();
    assert_eq!((stats.denied, stats.replies), (1, 1));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn failed_rules_drop_replies_when_nothing_else_is_loaded() -> TestResult {
    let engine = Arc::new(AclEngine::new().with_not_installed(NotInstalled::Accept));
    let (mut a, mut b, filter, labels) = acl_pair(&engine).await?;
    let mut events = b.subscribe().await?;
    let a_end = SocketAddr::new(IpAddr::V4(a.ip4), SRC_PORT);
    let b_end = SocketAddr::new(IpAddr::V4(b.ip4), ALLOWED);
    delivered(&b, &mut a, &udp(b_end, a_end, b"out")).await?;
    delivered(&a, &mut b, &udp(a_end, b_end, b"reply")).await?;

    // Fail closed, even for the reply of the open flow and under `NotInstalled::Accept`.
    engine.fail();
    assert_eq!(engine.policy_state(), PolicyState::Failed);
    assert_eq!(
        engine.evaluate(&labels, &Flow::udp(a_end, b_end)),
        Decision::Deny(reasons::POLICY_FAILED)
    );
    let reply = udp(a_end, b_end, b"again");
    dropped(&a, &mut b, &mut events, &reply, reasons::POLICY_FAILED).await?;
    assert_eq!(b.drops(reasons::POLICY_FAILED).await?, 1);
    let stats = filter.stats();
    assert_eq!(
        (stats.policy_failed, stats.policy_state),
        (1, PolicyState::Failed)
    );

    // `clear_all` keeps it failed; `uninstall` returns to the not-installed action.
    engine.clear_all();
    dropped(&a, &mut b, &mut events, &reply, reasons::POLICY_FAILED).await?;
    engine.uninstall();
    delivered(&a, &mut b, &reply).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn evaluate_equals_the_first_packet_verdict() -> TestResult {
    let engine = Arc::new(AclEngine::new());
    let (a, mut b, filter, labels) = acl_pair(&engine).await?;
    let mut events = b.subscribe().await?;
    let (from4, to4) = (IpAddr::V4(a.ip4), IpAddr::V4(b.ip4));
    let (from6, to6) = (IpAddr::V6(a.ip6), IpAddr::V6(b.ip6));
    engine.install(RuleSet::new([
        Rule::new(
            "udp",
            vec![ProtocolMatch::Udp(PortSet::list([ALLOWED, 7002]))],
        )
        .with_labels(labels.iter().cloned()),
        Rule::new(
            "ping6",
            vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![128]))],
        )
        .with_destinations([host(to6)?]),
    ])?);

    let mut id = 0;
    for (src, dst, port) in [
        (from4, to4, ALLOWED),
        (from4, to4, DENIED),
        (from6, to6, 7002),
        (from6, to6, DENIED),
        (from4, to4, 0),
        (from6, to6, 0),
    ] {
        id += 1;
        // A new source port (or echo identifier) per flow: always a first packet.
        let a_end = SocketAddr::new(src, SRC_PORT + id);
        let b_end = SocketAddr::new(dst, port);
        let (flow, packet) = if port == 0 {
            let icmp_type = if src.is_ipv4() { 8 } else { 128 };
            (Flow::icmp(src, dst, icmp_type), echo_request(src, dst, id))
        } else {
            (Flow::udp(a_end, b_end), udp(a_end, b_end, b"in"))
        };
        match engine.evaluate(&labels, &flow) {
            Decision::Accept(_) => delivered(&a, &mut b, &packet).await?,
            // Denials of protocols other than TCP and UDP are reported as `PROTOCOL`.
            Decision::Deny(_) if port == 0 => {
                dropped(&a, &mut b, &mut events, &packet, reasons::PROTOCOL).await?;
            }
            Decision::Deny(reason) => dropped(&a, &mut b, &mut events, &packet, reason).await?,
            other => return Err(format!("unexpected decision {other:?}").into()),
        }
    }
    let stats = filter.stats();
    assert_eq!((stats.accepted, stats.denied, stats.protocol), (3, 2, 1));
    Ok(())
}
