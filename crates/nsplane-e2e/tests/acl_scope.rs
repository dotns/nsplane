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
    AclEngine, AclFilter, AclFilterConfig, AclFilterScope, AclPolicy, IpNet, PeerIdentityMap,
    SourceAssertion, reasons,
};
use nsplane_e2e::{Node, Options, TestResult, introduce, udp};

/// Capacity of the channel transport pair.
const CAPACITY: usize = 1024;
/// The key seed of `b`, which picks its tunnel addresses.
const B_SEED: u8 = 2;
/// `b`'s tunnel addresses (`Node::with_builder` derives them from the seed).
const B_IP4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const B_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

type AclNode = Node<ChannelTransport>;

/// Two peers linked like `channel_pair`, `b` with an `AclFilter` built with `scope` and a
/// deny-all policy (outbound packets to the unrestricted `a` pass it). `a`'s principal is
/// its WireGuard key.
async fn scoped_pair(scope: AclFilterScope) -> TestResult<(AclNode, AclNode, AclFilter)> {
    let engine = Arc::new(AclEngine::new());
    engine.load(AclPolicy::default())?;
    let identities = Arc::new(PeerIdentityMap::new());
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
    identities.insert(
        b.peer_of(&a).await?,
        SourceAssertion::WgPeerKey {
            pubkey: a.public().to_bytes(),
        },
    );
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
