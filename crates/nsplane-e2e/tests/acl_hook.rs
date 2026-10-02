//! The ACL as a per-flow hook, at engine level over in-memory channel transports. Node `b`
//! runs an `AclFilter` over a shared `AclEngine` and a `PeerIdentityMap` naming its peers'
//! WireGuard keys as principals; its peers run no filter.
//!
//! The filter caches each flow's verdict after its first packet. Every test sends a flow
//! (single UDP packets with the runtime's clock paused) until it is established, changes the
//! policy or the identities under the running engines (a namespace losing the permission, a
//! removed grant, a dropped pinhole guard, `clear_all`, a forgotten peer) and checks that the
//! very next packet of the flow is dropped with the expected `Event::Dropped` reason, and
//! that re-allowing it restores delivery on the next packet. A peer of a namespace accepting
//! everything bypasses the evaluation: its traffic is delivered both ways.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nsplane::x25519::PublicKey;
use nsplane::{AllowedIp, ChannelTransport, Event, Path, TransportId};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclPolicy, AclRule, Direction, Grant, GrantEnd,
    NamespaceMember, NamespacePolicy, PeerIdentityMap, PinholeSpec, Protocol, SourceAssertion,
    reasons, wg_peer_anchor,
};
use nsplane_e2e::{Events, Node, Options, TestResult, introduce, udp};
use nsplane_packet::PeerId;

/// Capacity of every channel link.
const CAPACITY: usize = 1024;
/// The port the peers' packets come from.
const SRC_PORT: u16 = 40000;
/// The port the "quick" namespace allows on `b`.
const QUICK_PORT: u16 = 7000;
/// The port of the app session's pinhole.
const APP_PORT: u16 = 9000;
/// The app kind of the pinhole.
const TRANSFER_KIND: &str = "transfer";
/// Packets that establish a flow before the policy changes.
const ESTABLISH: usize = 3;

type AclNode = Node<ChannelTransport>;

/// The ACL state of `b` the tests keep.
struct Acl {
    engine: Arc<AclEngine>,
    identities: Arc<PeerIdentityMap>,
    filter: AclFilter,
}

impl Acl {
    fn new() -> Self {
        let engine = Arc::new(AclEngine::new());
        let identities = Arc::new(PeerIdentityMap::new());
        let filter = AclFilter::new(Arc::clone(&engine), Arc::clone(&identities));
        Self {
            engine,
            identities,
            filter,
        }
    }

    /// Names the peer `peer` of `b` by its WireGuard key.
    fn identify(&self, peer: PeerId, key: &PublicKey) {
        self.identities.insert(
            peer,
            SourceAssertion::WgPeerKey {
                pubkey: key.to_bytes(),
            },
        );
    }
}

/// The endpoint `host` of a channel link: transport id and address.
fn end(id: u16, host: u8) -> (TransportId, SocketAddr) {
    (
        TransportId::new(id),
        SocketAddr::from(([192, 0, 2, host], 1000 + id)),
    )
}

/// The principal of a node's key.
fn principal(key: &PublicKey) -> String {
    wg_peer_anchor(&key.to_bytes())
}

/// A namespace member with both tunnel addresses of a node.
fn member(key: &PublicKey, ip4: Ipv4Addr, ip6: Ipv6Addr) -> TestResult<NamespaceMember> {
    Ok(NamespaceMember {
        principal: principal(key),
        addresses: vec![format!("{ip4}/32").parse()?, format!("{ip6}/128").parse()?],
    })
}

/// A namespace with `members` whose rule accepts `dst` (`host:ports`) from anyone over
/// `proto` (`None`: TCP and UDP), or no rule; app pinholes of `apps` are allowed.
fn namespace(
    members: Vec<NamespaceMember>,
    dst: Option<&str>,
    proto: Option<&str>,
    apps: &[&str],
) -> NamespacePolicy {
    let acls = dst
        .map(|dst| AclRule {
            action: AclAction::Accept,
            src: vec!["*".to_owned()],
            dst: vec![dst.to_owned()],
            proto: proto.map(str::to_owned),
        })
        .into_iter()
        .collect();
    NamespacePolicy {
        members,
        policy: AclPolicy {
            acls,
            ..AclPolicy::default()
        },
        allow_app_pinholes: apps.iter().map(|app| (*app).to_owned()).collect(),
        ..NamespacePolicy::default()
    }
}

/// The "quick" namespace of `a` accepting UDP to [`QUICK_PORT`] (or nothing).
fn quick(a: &AclNode, open: bool) -> TestResult<NamespacePolicy> {
    let dst = format!("*:{QUICK_PORT}");
    Ok(namespace(
        vec![member(&a.public(), a.ip4, a.ip6)?],
        open.then_some(dst.as_str()),
        Some("udp"),
        &[TRANSFER_KIND],
    ))
}

/// Packet nodes `a` (seed 1) and `b` (seed 2) linked and introduced, `b` filtering with
/// `acl`; `a` is identified by its key.
async fn packet_pair(acl: &Acl) -> TestResult<(AclNode, AclNode)> {
    let (a_end, b_end) = (end(1, 1), end(2, 2));
    let (link_a, link_b) = ChannelTransport::pair(CAPACITY, a_end, b_end);
    let a = Node::with_builder(1, a_end.0, a_end.1, Options::default(), |builder| {
        builder.transport(link_a)
    })?;
    let filter = acl.filter.clone();
    let b = Node::with_builder(2, b_end.0, b_end.1, Options::default(), |builder| {
        builder.transport(link_b).filter(Box::new(filter))
    })?;
    introduce(&a, &b, None).await?;
    acl.identify(b.peer_of(&a).await?, &a.public());
    Ok((a, b))
}

/// A UDP packet from `from`'s IPv4 address and `src_port` to `to` port `dst_port`.
fn udp_to(from: &AclNode, src_port: u16, to: Ipv4Addr, dst_port: u16) -> Vec<u8> {
    udp(
        SocketAddr::from((from.ip4, src_port)),
        SocketAddr::from((to, dst_port)),
        b"datagram",
    )
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

/// Sends `packet` [`ESTABLISH`] times from `from`, each delivered by `to`.
async fn established(from: &AclNode, to: &mut AclNode, packet: &[u8]) -> TestResult {
    for _ in 0..ESTABLISH {
        delivered(from, to, packet).await?;
    }
    Ok(())
}

/// Sends `packet` from `from` and checks that `b` drops it with `reason`.
async fn dropped(
    from: &AclNode,
    b: &mut AclNode,
    events: &mut Events,
    packet: &[u8],
    reason: &'static str,
) -> TestResult {
    from.send(packet).await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason: r, .. } if *r == reason))
        .await?;
    b.expect_no_delivery().await
}

/// Sends `packet` from `from` to the hub `b`, which forwards what it delivers back into the
/// tunnel (as its kernel would route it), and checks that `to` delivers it unchanged.
async fn relayed(from: &AclNode, b: &mut AclNode, to: &mut AclNode, packet: &[u8]) -> TestResult {
    delivered(from, b, packet).await?;
    b.send(packet).await?;
    let (_, got) = to.expect_delivery().await?;
    if got != packet {
        return Err("packet changed in the hub".into());
    }
    Ok(())
}

/// A namespace change that removes the permission drops the established flow on its next
/// packet; restoring it delivers the next one.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn namespace_change_applies_to_the_next_packet() -> TestResult {
    let acl = Acl::new();
    let (a, mut b) = packet_pair(&acl).await?;
    let mut events = b.subscribe().await?;
    let flow = udp_to(&a, SRC_PORT, b.ip4, QUICK_PORT);

    acl.engine.store_namespace("quick", quick(&a, true)?)?;
    established(&a, &mut b, &flow).await?;
    let generation = acl.engine.generation();
    acl.engine.store_namespace("quick", quick(&a, false)?)?;
    assert!(acl.engine.generation() > generation);
    dropped(&a, &mut b, &mut events, &flow, reasons::DENIED).await?;
    acl.engine.store_namespace("quick", quick(&a, true)?)?;
    delivered(&a, &mut b, &flow).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied), (ESTABLISH as u64 + 1, 1));
    assert_eq!(b.drops(reasons::DENIED).await?, 1);
    Ok(())
}

/// Hub `b` forwards `a` ("quick") to `c` ("nsd:x") under a directed grant: removing the
/// grant drops the established flow on its next packet, storing it again restores it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn removed_grant_applies_to_the_next_packet() -> TestResult {
    let acl = Acl::new();
    let (a_end, b_a_end, c_end, b_c_end) = (end(1, 1), end(2, 2), end(3, 3), end(4, 4));
    let (link_a, link_b_a) = ChannelTransport::pair(CAPACITY, a_end, b_a_end);
    let (link_c, link_b_c) = ChannelTransport::pair(CAPACITY, c_end, b_c_end);
    let a = Node::with_builder(1, a_end.0, a_end.1, Options::default(), |builder| {
        builder.transport(link_a)
    })?;
    let mut c = Node::with_builder(3, c_end.0, c_end.1, Options::default(), |builder| {
        builder.transport(link_c)
    })?;
    let filter = acl.filter.clone();
    let mut b = Node::with_builder(2, b_a_end.0, b_a_end.1, Options::default(), |builder| {
        builder
            .transport(link_b_a)
            .transport(link_b_c)
            .filter(Box::new(filter))
    })?;

    // `a` and `c` route each other's addresses through the hub.
    let via_hub = |node: &AclNode, hub_addr: SocketAddr, other: &AclNode| {
        let mut peer = b.as_peer(node.path.transport);
        peer.allowed_ips.extend([
            AllowedIp {
                addr: IpAddr::V4(other.ip4),
                cidr: 32,
            },
            AllowedIp {
                addr: IpAddr::V6(other.ip6),
                cidr: 128,
            },
        ]);
        peer.path = Some(Path {
            addr: hub_addr,
            ..node.path
        });
        peer
    };
    a.handle
        .add_or_update_peer(via_hub(&a, b_a_end.1, &c))
        .await?;
    c.handle
        .add_or_update_peer(via_hub(&c, b_c_end.1, &a))
        .await?;
    b.handle.add_or_update_peer(a.as_peer(b_a_end.0)).await?;
    b.handle.add_or_update_peer(c.as_peer(b_c_end.0)).await?;
    acl.identify(b.peer_of(&a).await?, &a.public());
    acl.identify(b.peer_of(&c).await?, &c.public());
    acl.engine.store_namespace(
        "quick",
        namespace(vec![member(&a.public(), a.ip4, a.ip6)?], None, None, &[]),
    )?;
    acl.engine.store_namespace(
        "nsd:x",
        namespace(vec![member(&c.public(), c.ip4, c.ip6)?], None, None, &[]),
    )?;
    let grant = Grant {
        from: GrantEnd::Namespace("quick".into()),
        to: GrantEnd::Peer(principal(&c.public())),
        proto: Some("udp".to_owned()),
        ports: Some(QUICK_PORT.to_string()),
    };
    acl.engine.store_grant("quick-to-c", grant.clone())?;
    let mut events = b.subscribe().await?;
    let flow = udp_to(&a, SRC_PORT, c.ip4, QUICK_PORT);

    for _ in 0..ESTABLISH {
        relayed(&a, &mut b, &mut c, &flow).await?;
    }
    assert!(acl.engine.remove_grant("quick-to-c"));
    dropped(&a, &mut b, &mut events, &flow, reasons::CROSS_NAMESPACE).await?;
    acl.engine.store_grant("quick-to-c", grant)?;
    relayed(&a, &mut b, &mut c, &flow).await?;

    let stats = acl.filter.stats();
    assert_eq!(
        (stats.accepted, stats.cross_namespace),
        (ESTABLISH as u64 + 1, 1)
    );
    assert_eq!(b.drops(reasons::CROSS_NAMESPACE).await?, 1);
    Ok(())
}

/// A flow accepted by an inbound pinhole is dropped on its next packet once the pinhole's
/// guard is dropped; a new pinhole restores it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn dropped_pinhole_guard_applies_to_the_next_packet() -> TestResult {
    let acl = Acl::new();
    let (a, mut b) = packet_pair(&acl).await?;
    let mut events = b.subscribe().await?;
    acl.engine.store_namespace("quick", quick(&a, false)?)?;
    acl.engine.store_namespace(
        "app:s1",
        namespace(vec![member(&a.public(), a.ip4, a.ip6)?], None, None, &[]),
    )?;
    let spec = PinholeSpec {
        peer: principal(&a.public()),
        kind: TRANSFER_KIND.to_owned(),
        protocol: Protocol::Udp,
        direction: Direction::Inbound,
        dst_port: APP_PORT,
        expires_at: Instant::now() + Duration::from_secs(3600),
    };
    let flow = udp_to(&a, SRC_PORT, b.ip4, APP_PORT);

    let guard = acl.engine.open_pinhole("app:s1", spec.clone())?;
    established(&a, &mut b, &flow).await?;
    drop(guard);
    dropped(&a, &mut b, &mut events, &flow, reasons::DENIED).await?;
    let guard = acl.engine.open_pinhole("app:s1", spec)?;
    delivered(&a, &mut b, &flow).await?;
    drop(guard);

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied), (ESTABLISH as u64 + 1, 1));
    let pinholes = acl.engine.pinhole_stats();
    assert_eq!((pinholes.opened, pinholes.closed), (2, 2));
    Ok(())
}

/// `clear_all` drops the established flow on its next packet with `NO_POLICY`; storing the
/// namespace again restores it. Forgetting the peer's identity drops it as unknown.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn clear_all_and_identity_changes_apply_to_the_next_packet() -> TestResult {
    let acl = Acl::new();
    let (a, mut b) = packet_pair(&acl).await?;
    let mut events = b.subscribe().await?;
    let flow = udp_to(&a, SRC_PORT, b.ip4, QUICK_PORT);

    acl.engine.store_namespace("quick", quick(&a, true)?)?;
    established(&a, &mut b, &flow).await?;
    acl.engine.clear_all();
    dropped(&a, &mut b, &mut events, &flow, reasons::NO_POLICY).await?;
    acl.engine.store_namespace("quick", quick(&a, true)?)?;
    delivered(&a, &mut b, &flow).await?;

    let peer = b.peer_of(&a).await?;
    acl.identities.remove(peer);
    dropped(&a, &mut b, &mut events, &flow, reasons::UNKNOWN_PEER).await?;
    acl.identify(peer, &a.public());
    delivered(&a, &mut b, &flow).await?;

    let stats = acl.filter.stats();
    assert_eq!(
        (stats.accepted, stats.no_policy, stats.unknown_peer),
        (ESTABLISH as u64 + 2, 1, 1)
    );
    Ok(())
}

/// A peer whose namespace accepts everything bypasses the evaluation: new flows to any port
/// and `b`'s traffic to it are delivered, and the bypass ends with the namespace's rule.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bypass_peer_traffic_is_delivered() -> TestResult {
    let acl = Acl::new();
    let (mut a, mut b) = packet_pair(&acl).await?;
    let mut events = b.subscribe().await?;
    let everything = |a: &AclNode| -> TestResult<NamespacePolicy> {
        Ok(namespace(
            vec![member(&a.public(), a.ip4, a.ip6)?],
            Some("*:*"),
            None,
            &[],
        ))
    };
    acl.engine.store_namespace("quick", everything(&a)?)?;
    let (a_ip, b_ip) = (a.ip4, b.ip4);

    for port in [22, 443, QUICK_PORT, APP_PORT] {
        delivered(&a, &mut b, &udp_to(&a, SRC_PORT, b_ip, port)).await?;
    }
    delivered(&b, &mut a, &udp_to(&b, QUICK_PORT, a_ip, SRC_PORT)).await?;
    established(&a, &mut b, &udp_to(&a, SRC_PORT + 1, b_ip, 443)).await?;

    acl.engine.store_namespace("quick", quick(&a, true)?)?;
    let other = udp_to(&a, SRC_PORT + 1, b_ip, 443);
    dropped(&a, &mut b, &mut events, &other, reasons::DENIED).await?;
    delivered(&a, &mut b, &udp_to(&a, SRC_PORT, b_ip, QUICK_PORT)).await?;

    let stats = acl.filter.stats();
    assert_eq!(stats.denied, 1);
    Ok(())
}
