//! The address scopes of the `AclFilter` (`AclFilterScope`) at engine level, over an
//! in-memory channel transport: two nodes `a` and `b`, where `b` runs an `AclFilter` built
//! with `AclFilter::with_scope` on its packets and `a` runs no filter. The tests keep a clone
//! of the filter for its counters and check deliveries, `Event::Dropped` reasons and the
//! filter counters.
//!
//! The runtime's clock is paused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane::{ChannelSink, ChannelSource, ChannelTransport, EngineBuilder, Event, TransportId};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, AclFilterScope, IpNet, Label, LabelSet, OtherProtocol,
    OtherProtocolRule, PeerLabelMap, RuleSet, reasons,
};
use nsplane_e2e::{Node, Options, TestResult, icmp, introduce, udp};

/// Capacity of the channel transport pair.
const CAPACITY: usize = 1024;
/// The key seed of `b`, which picks its tunnel addresses.
const B_SEED: u8 = 2;
/// `b`'s tunnel addresses (`Node::with_builder` derives them from the seed).
const B_IP4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const B_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

type AclNode = Node<ChannelTransport>;

/// Two peers linked like `channel_pair`, `b` with an `AclFilter` built with `scope` and a
/// empty rule set (outbound packets to the unrestricted `a` pass it). `a` carries the
/// label `node-a`.
async fn scoped_pair(scope: AclFilterScope) -> TestResult<(AclNode, AclNode, AclFilter)> {
    let engine = Arc::new(AclEngine::new());
    engine.install(RuleSet::empty());
    let identities = Arc::new(PeerLabelMap::new());
    let filter = AclFilter::with_scope(
        engine,
        Arc::clone(&identities),
        AclFilterConfig::default(),
        scope,
    );

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
    let b = Node::with_builder(B_SEED, b_end.0, b_end.1, Options::default(), |builder| {
        let builder: EngineBuilder<ChannelSource, ChannelSink> = builder.transport(link_b);
        builder.filter(Box::new(b_filter))
    })?;
    if (b.ip4, b.ip6) != (B_IP4, B_IP6) {
        return Err("b's tunnel addresses moved".into());
    }
    introduce(&a, &b, None).await?;
    identities.insert(b.peer_of(&a).await?, LabelSet::new([Label::from("node-a")]));
    Ok((a, b, filter))
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn outbound_from_a_foreign_source_is_dropped() -> TestResult {
    let scope = AclFilterScope::new().with_outbound_sources([
        format!("{B_IP4}/32").parse::<IpNet>()?,
        format!("{B_IP6}/128").parse()?,
    ]);
    let (mut a, b, filter) = scoped_pair(scope).await?;
    let mut events = b.subscribe().await?;

    for (own, foreign, to) in [
        (
            IpAddr::V4(b.ip4),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            IpAddr::V4(a.ip4),
        ),
        (
            IpAddr::V6(b.ip6),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x99)),
            IpAddr::V6(a.ip6),
        ),
    ] {
        let a_end = SocketAddr::new(to, 6000);
        let packet = udp(SocketAddr::new(own, 5000), a_end, b"own");
        b.send(&packet).await?;
        let (_, got) = a.expect_delivery().await?;
        if got != packet {
            return Err("packet changed in transit".into());
        }

        b.send(&udp(SocketAddr::new(foreign, 5000), a_end, b"foreign"))
            .await?;
        events
            .expect(|e| {
                matches!(e, Event::Dropped { reason, .. } if *reason == reasons::OUTBOUND_SOURCE)
            })
            .await?;
        a.expect_no_delivery().await?;
    }

    assert_eq!(b.drops(reasons::OUTBOUND_SOURCE).await?, 2);
    assert_eq!(filter.stats().outbound_source, 2);
    Ok(())
}

/// An echo message (`kind` 8 or 128 for a request, 0 or 129 for a reply) from `src` to `dst`
/// with identifier `id`.
fn echo(src: IpAddr, dst: IpAddr, kind: u8, id: u16) -> Vec<u8> {
    let [hi, lo] = id.to_be_bytes();
    icmp(src, dst, (kind, 0), [hi, lo, 0, 1], b"ping")
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

/// A scope accepting ICMP echo requests to `destinations`.
fn echo_scope(destinations: &[&str]) -> TestResult<AclFilterScope> {
    let destinations = destinations
        .iter()
        .map(|net| net.parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()?;
    let rule = OtherProtocolRule::new(OtherProtocol::IcmpEcho, destinations);
    Ok(AclFilterScope::new().with_other_protocol(rule))
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn echo_to_own_addresses_is_accepted_and_answered() -> TestResult {
    let scope = echo_scope(&[&format!("{B_IP4}/32"), &format!("{B_IP6}/128")])?;
    let (mut a, mut b, filter) = scoped_pair(scope).await?;
    for (from, to, request, reply) in [
        (IpAddr::V4(a.ip4), IpAddr::V4(b.ip4), 8, 0),
        (IpAddr::V6(a.ip6), IpAddr::V6(b.ip6), 128, 129),
    ] {
        delivered(&a, &mut b, &echo(from, to, request, 1)).await?;
        delivered(&b, &mut a, &echo(to, from, reply, 1)).await?;
    }
    let stats = filter.stats();
    assert_eq!((stats.accepted, stats.protocol), (2, 0));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn echo_outside_the_rule_is_dropped() -> TestResult {
    // Only b's IPv4 address: an echo to its IPv6 address is outside the rule.
    let (a, mut b, filter) = scoped_pair(echo_scope(&[&format!("{B_IP4}/32")])?).await?;
    let mut events = b.subscribe().await?;
    a.send(&echo(IpAddr::V6(a.ip6), IpAddr::V6(b.ip6), 128, 1))
        .await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason, .. } if *reason == reasons::PROTOCOL))
        .await?;
    b.expect_no_delivery().await?;
    // Neither is another ICMP message to the address in the rule.
    a.send(&icmp(
        IpAddr::V4(a.ip4),
        IpAddr::V4(b.ip4),
        (13, 0),
        [0; 4],
        &[0; 12],
    ))
    .await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason, .. } if *reason == reasons::PROTOCOL))
        .await?;
    b.expect_no_delivery().await?;
    assert_eq!(b.drops(reasons::PROTOCOL).await?, 2);
    assert_eq!(filter.stats().protocol, 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn replies_to_own_pings_pass_the_reply_table() -> TestResult {
    let scope = echo_scope(&[&format!("{B_IP4}/32"), &format!("{B_IP6}/128")])?;
    let (mut a, mut b, filter) = scoped_pair(scope).await?;
    for (own, remote, request, reply) in [
        (IpAddr::V4(b.ip4), IpAddr::V4(a.ip4), 8, 0),
        (IpAddr::V6(b.ip6), IpAddr::V6(a.ip6), 128, 129),
    ] {
        delivered(&b, &mut a, &echo(own, remote, request, 9)).await?;
        delivered(&a, &mut b, &echo(remote, own, reply, 9)).await?;
    }
    let stats = filter.stats();
    assert_eq!((stats.replies, stats.accepted, stats.protocol), (2, 0, 0));
    Ok(())
}
