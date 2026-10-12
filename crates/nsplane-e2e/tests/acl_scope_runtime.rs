//! The `AclFilter`'s scopes replaced at runtime (`AclFilter::replace_scopes`) at engine
//! level, over in-memory channel transports: `b` holds two local identities, the default one
//! with the peer `a` and a second one with the peer `c`, each over its own channel transport
//! pair. `b` runs an `AclFilter` whose `PeerLabelMap` names `c`'s local identity
//! (`PeerLabelMap::set_local_identity`); `a` and `c` run no filter. The tests check
//! deliveries, `Event::Dropped` reasons, the filter counters and the scope generation.
//!
//! The runtime's clock is paused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, ChannelTransport, Event, LocalIdentityId, Path, Peer, TransportId};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, AclFilterScope, AclFilterScopeError, AclFilterScopes,
    IpNet, Label, LabelSet, PeerLabelMap, RuleSet, reasons,
};
use nsplane_e2e::{Events, Node, Options, TestResult, introduce, udp};

/// Capacity of the channel transport pairs.
const CAPACITY: usize = 1024;
/// `b`'s source addresses for the second identity's peers.
const ALT4: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
const ALT6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 1, 0, 0, 0, 0, 2);
/// Rounds of [`a_replace_under_traffic_switches_the_verdicts_at_its_generation`]; the
/// scopes are replaced after each one.
const ROUNDS: u64 = 6;

type AclNode = Node<ChannelTransport>;

/// The nodes and `b`'s filter state the tests keep.
struct Setup {
    a: AclNode,
    b: AclNode,
    c: AclNode,
    filter: AclFilter,
    /// `b`'s second local identity, the one of `c`.
    second: LocalIdentityId,
}

/// The key of `b`'s second local identity.
fn second_key() -> StaticSecret {
    StaticSecret::from([12; 32])
}

/// `b` with the peer `a` under its default identity and the peer `c` under a second one,
/// and an `AclFilter` with an empty rule set and no scope (generation 0).
async fn setup() -> TestResult<Setup> {
    let engine = Arc::new(AclEngine::new());
    engine.install(RuleSet::empty());
    let identities = Arc::new(PeerLabelMap::new());
    let filter = AclFilter::with_scope(
        engine,
        Arc::clone(&identities),
        AclFilterConfig::default(),
        AclFilterScope::new(),
    );

    let a_end = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b_to_a = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let b_to_c = (
        TransportId::new(3),
        SocketAddr::from(([192, 0, 2, 2], 2001)),
    );
    let c_end = (
        TransportId::new(4),
        SocketAddr::from(([192, 0, 2, 3], 3000)),
    );
    let (link_a, link_ba) = ChannelTransport::pair(CAPACITY, a_end, b_to_a);
    let (link_bc, link_c) = ChannelTransport::pair(CAPACITY, b_to_c, c_end);
    let a = Node::with_builder(1, a_end.0, a_end.1, Options::default(), |builder| {
        builder.transport(link_a)
    })?;
    let c = Node::with_builder(3, c_end.0, c_end.1, Options::default(), |builder| {
        builder.transport(link_c)
    })?;
    let b_filter = filter.clone();
    let b = Node::with_builder(2, b_to_a.0, b_to_a.1, Options::default(), |builder| {
        builder
            .transport(link_ba)
            .transport(link_bc)
            .filter(Box::new(b_filter))
    })?;
    introduce(&a, &b, None).await?;
    // `a` and `c` accept `b`'s alternate sources too, so only `b`'s filter judges them.
    let b_peer = |via, path| Peer {
        allowed_ips: [b.as_peer(via).allowed_ips, alt_ips()].concat(),
        path: Some(path),
        ..b.as_peer(via)
    };
    a.handle.add_or_update_peer(b_peer(a_end.0, b.path)).await?;

    let second = b
        .handle
        .add_local_identity(second_key())
        .await?
        .ok_or("second identity refused")?;
    b.handle
        .add_or_update_peer(Peer {
            local_identity: Some(second),
            ..c.as_peer(b_to_c.0)
        })
        .await?;
    let to_b = Path {
        transport: c_end.0,
        addr: b_to_c.1,
        ..b.path
    };
    c.handle
        .add_or_update_peer(Peer {
            public_key: PublicKey::from(&second_key()),
            ..b_peer(c_end.0, to_b)
        })
        .await?;
    let c_peer = b
        .handle
        .peer_id_in(second, c.public())
        .await?
        .ok_or("no peer c")?;

    identities.insert(b.peer_of(&a).await?, LabelSet::new([Label::from("node-a")]));
    identities.insert(c_peer, LabelSet::new([Label::from("node-c")]));
    identities.set_local_identity(c_peer, second);
    Ok(Setup {
        a,
        b,
        c,
        filter,
        second,
    })
}

fn host(ip: IpAddr) -> TestResult<IpNet> {
    let len = if ip.is_ipv4() { 32 } else { 128 };
    Ok(format!("{ip}/{len}").parse()?)
}

/// A scope allowing outbound packets from `sources` only.
fn sources(sources: [IpAddr; 2]) -> TestResult<AclFilterScope> {
    Ok(AclFilterScope::new().with_outbound_sources([host(sources[0])?, host(sources[1])?]))
}

/// `b`'s own tunnel addresses.
const fn own(b: &AclNode) -> [IpAddr; 2] {
    [IpAddr::V4(b.ip4), IpAddr::V6(b.ip6)]
}

const ALT: [IpAddr; 2] = [IpAddr::V4(ALT4), IpAddr::V6(ALT6)];

/// [`ALT`] as allowed IPs.
fn alt_ips() -> Vec<AllowedIp> {
    vec![
        AllowedIp {
            addr: IpAddr::V4(ALT4),
            cidr: 32,
        },
        AllowedIp {
            addr: IpAddr::V6(ALT6),
            cidr: 128,
        },
    ]
}

/// Scopes giving peers of the default identity `default` as their sources and peers of
/// `second` the sources `other`.
fn scopes(
    second: LocalIdentityId,
    default: [IpAddr; 2],
    other: [IpAddr; 2],
) -> TestResult<AclFilterScopes> {
    Ok(AclFilterScopes::new()
        .with_default(sources(default)?)
        .with_identity(second, sources(other)?))
}

/// The tunnel addresses of `node`, IPv4 first.
const fn tunnel(node: &AclNode) -> [IpAddr; 2] {
    [IpAddr::V4(node.ip4), IpAddr::V6(node.ip6)]
}

/// Sends a UDP packet of each family from `b`'s `from` addresses to `to`'s tunnel addresses
/// and checks that `to` delivers it unchanged.
async fn delivered(b: &AclNode, from: [IpAddr; 2], to: &mut AclNode) -> TestResult {
    for (src, dst) in from.into_iter().zip(tunnel(to)) {
        let packet = udp(
            SocketAddr::new(src, 5000),
            SocketAddr::new(dst, 6000),
            b"in",
        );
        b.send(&packet).await?;
        let (_, got) = to.expect_delivery().await?;
        if got != packet {
            return Err("packet changed in transit".into());
        }
    }
    Ok(())
}

/// Sends a UDP packet of each family from `b`'s `from` addresses to `to`'s tunnel addresses
/// and checks that `b` drops it for its outbound source and `to` delivers nothing.
async fn dropped(
    b: &AclNode,
    events: &mut Events,
    from: [IpAddr; 2],
    to: &mut AclNode,
) -> TestResult {
    for (src, dst) in from.into_iter().zip(tunnel(to)) {
        let packet = udp(
            SocketAddr::new(src, 5000),
            SocketAddr::new(dst, 6000),
            b"in",
        );
        b.send(&packet).await?;
        events
            .expect(|e| {
                matches!(e, Event::Dropped { reason, .. } if *reason == reasons::OUTBOUND_SOURCE)
            })
            .await?;
        to.expect_no_delivery().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn each_local_identity_is_judged_under_its_own_scope() -> TestResult {
    let Setup {
        mut a,
        b,
        mut c,
        filter,
        second,
    } = setup().await?;
    let mut events = b.subscribe().await?;

    // Generation 0 scopes nothing: every source passes.
    assert_eq!(filter.scope_generation(), 0);
    delivered(&b, ALT, &mut a).await?;
    delivered(&b, own(&b), &mut c).await?;

    assert_eq!(filter.replace_scopes(scopes(second, own(&b), ALT)?)?, 1);
    delivered(&b, own(&b), &mut a).await?;
    dropped(&b, &mut events, ALT, &mut a).await?;
    delivered(&b, ALT, &mut c).await?;
    dropped(&b, &mut events, own(&b), &mut c).await?;

    // Without an entry of its own, the second identity falls back to the default scope.
    let only_default = AclFilterScopes::new().with_default(sources(own(&b))?);
    assert_eq!(filter.replace_scopes(only_default)?, 2);
    delivered(&b, own(&b), &mut c).await?;
    dropped(&b, &mut events, ALT, &mut c).await?;

    // A duplicate identity is rejected and publishes nothing.
    let duplicate = scopes(second, ALT, ALT)?.with_identity(second, AclFilterScope::new());
    assert_eq!(
        filter.replace_scopes(duplicate),
        Err(AclFilterScopeError::DuplicateIdentity(second))
    );
    assert_eq!(filter.scope_generation(), 2);
    delivered(&b, own(&b), &mut a).await?;

    assert_eq!(b.drops(reasons::OUTBOUND_SOURCE).await?, 6);
    assert_eq!(filter.stats().outbound_source, 6);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_replace_under_traffic_switches_the_verdicts_at_its_generation() -> TestResult {
    let Setup {
        mut a,
        b,
        mut c,
        filter,
        second,
    } = setup().await?;
    let mut events = b.subscribe().await?;
    // Even generations give `a` the own addresses and `c` the alternate ones; odd ones swap
    // them.
    let set = |generation: u64| {
        if generation.is_multiple_of(2) {
            scopes(second, own(&b), ALT)
        } else {
            scopes(second, ALT, own(&b))
        }
    };

    assert_eq!(filter.replace_scopes(set(0)?)?, 1);
    for round in 1..=ROUNDS {
        // Both peers' traffic keeps flowing while the scopes alternate.
        let (to_a, to_c) = if round.is_multiple_of(2) {
            (ALT, own(&b))
        } else {
            (own(&b), ALT)
        };
        delivered(&b, to_a, &mut a).await?;
        delivered(&b, to_c, &mut c).await?;
        dropped(&b, &mut events, to_c, &mut a).await?;
        dropped(&b, &mut events, to_a, &mut c).await?;
        assert_eq!(filter.replace_scopes(set(round)?)?, round + 1);
    }

    assert_eq!(filter.scope_generation(), ROUNDS + 1);
    // Two packets of each family per round, one to each peer.
    assert_eq!(b.drops(reasons::OUTBOUND_SOURCE).await?, 4 * ROUNDS);
    assert_eq!(filter.stats().outbound_source, 4 * ROUNDS);
    Ok(())
}
