//! ACL rule namespaces, directed grants and app pinholes at engine level, over in-memory
//! channel transports. Node `b` runs an `AclFilter` over a shared `AclEngine` and a
//! `PeerIdentityMap` naming its peers' WireGuard keys as principals; its peers run no
//! filter. The tests change namespaces, grants and pinholes under the running engines and
//! check deliveries, `Event::Dropped` reasons, the engine's drop counters and the filter and
//! pinhole counters.
//!
//! The namespace, grant and expiry tests send single UDP packets between packet nodes with
//! the runtime's clock paused; the expiry test's `AclEngine` follows that clock. The
//! pinhole and session tests run TCP over netstacks in real time: a "transfer" is a
//! multi-segment payload echoed byte for byte, and a refused connection is one whose SYNs
//! `b` drops. "Handshake counter" is the `Event::HandshakeCompleted`s on `b`'s subscription
//! together with the peer's `last_handshake`; "peer count" is `b`'s number of peers.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nsplane::x25519::PublicKey;
use nsplane::{AllowedIp, ChannelTransport, EngineHandle, Event, Path, Peer, TransportId};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclPolicy, AclRule, Direction, Grant, GrantEnd, IpNet,
    NamespaceId, NamespaceMember, NamespacePolicy, PeerIdentityMap, PinholeError, PinholeSpec,
    PinholeStats, Protocol, SourceAssertion, reasons, wg_peer_anchor,
};
use nsplane_e2e::{
    Events, Family, Node, Options, StackNode, TRANSFER, TestResult, introduce, serve_tcp_echo, udp,
};
use nsplane_netstack::{DEFAULT_MTU, NetStackHandle};
use nsplane_packet::PeerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Capacity of every channel link.
const CAPACITY: usize = 1024;
/// The port the peers' packets come from.
const SRC_PORT: u16 = 40000;
/// The port the "quick" namespace allows on `b`.
const QUICK_PORT: u16 = 7000;
/// The port the "nsd:x" namespace allows on `b`.
const NSD_PORT: u16 = 7100;
/// The port of the app sessions' pinholes.
const APP_PORT: u16 = 9000;
/// Bytes of one transfer: many segments at any MTU.
const FILE: usize = 256 << 10;
/// Bytes of a short exchange that establishes the tunnel or probes an open port.
const PROBE: usize = 4096;
/// How long a connection attempt runs before it counts as refused.
const REFUSED: Duration = Duration::from_secs(1);
/// The app kind of every pinhole.
const TRANSFER_KIND: &str = "transfer";

type AclNode = Node<ChannelTransport>;

/// The ACL state of `b` the tests keep.
struct Acl {
    engine: Arc<AclEngine>,
    identities: Arc<PeerIdentityMap>,
    filter: AclFilter,
}

impl Acl {
    fn new(engine: AclEngine) -> Self {
        let engine = Arc::new(engine);
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

/// An accept rule from `src` to `port` on any local address; `proto` `None` matches TCP
/// and UDP.
fn rule(src: &str, port: u16, proto: Option<&str>) -> AclRule {
    AclRule {
        action: AclAction::Accept,
        src: vec![src.to_owned()],
        dst: vec![format!("*:{port}")],
        proto: proto.map(str::to_owned),
    }
}

/// A source namespace with `members`, rules accepting the first member on `ports` with
/// `proto`, and pinholes allowed for `apps`.
fn source(
    members: Vec<NamespaceMember>,
    ports: &[u16],
    proto: Option<&str>,
    apps: &[&str],
) -> NamespacePolicy {
    let acls = members
        .first()
        .map(|m| {
            ports
                .iter()
                .map(|port| rule(&m.principal, *port, proto))
                .collect()
        })
        .unwrap_or_default();
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

/// An app namespace with `members` and no rules.
fn app(members: Vec<NamespaceMember>) -> NamespacePolicy {
    NamespacePolicy {
        members,
        ..NamespacePolicy::default()
    }
}

/// An inbound TCP pinhole of `peer` to the local [`APP_PORT`] until `expires_at`.
fn inbound_pinhole(peer: String, protocol: Protocol, expires_at: Instant) -> PinholeSpec {
    PinholeSpec {
        peer,
        kind: TRANSFER_KIND.to_owned(),
        protocol,
        direction: Direction::Inbound,
        dst_port: APP_PORT,
        expires_at,
    }
}

/// An hour from now on the standard clock, the default engine clock.
fn in_an_hour() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

fn ids(names: &[&str]) -> Vec<NamespaceId> {
    names.iter().map(|name| NamespaceId::from(*name)).collect()
}

/// How many drops `handle`'s engine counted under `reason`.
async fn drops(handle: &EngineHandle, reason: &str) -> TestResult<u64> {
    let counters = handle.drop_counters().await?;
    Ok(counters.get(reason).copied().unwrap_or(0))
}

// ── Packet nodes ─────────────────────────────────────────────────────────────

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

/// Scenario 1: one peer in two namespaces gets the union of their rules; replacing or
/// removing one namespace leaves the other in effect.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn namespaces_union_and_replace_independently() -> TestResult {
    let acl = Acl::new(AclEngine::new());
    let (a, mut b) = packet_pair(&acl).await?;
    let mut events = b.subscribe().await?;
    let a_member = member(&a.public(), a.ip4, a.ip6)?;
    let to = |port| udp_to(&a, SRC_PORT, b.ip4, port);
    let (quick, nsd, other) = (to(QUICK_PORT), to(NSD_PORT), to(QUICK_PORT + 1));

    acl.engine.store_namespace(
        "quick",
        source(vec![a_member.clone()], &[QUICK_PORT], Some("udp"), &[]),
    )?;
    acl.engine.store_namespace(
        "nsd:x",
        source(vec![a_member.clone()], &[NSD_PORT], Some("udp"), &[]),
    )?;
    assert_eq!(
        acl.engine.memberships(&principal(&a.public())),
        ids(&["nsd:x", "quick"])
    );
    delivered(&a, &mut b, &quick).await?;
    delivered(&a, &mut b, &nsd).await?;
    dropped(&a, &mut b, &mut events, &other, reasons::DENIED).await?;

    // "nsd:x" without its rule: only its port closes.
    acl.engine
        .store_namespace("nsd:x", source(vec![a_member], &[], None, &[]))?;
    dropped(&a, &mut b, &mut events, &nsd, reasons::DENIED).await?;
    delivered(&a, &mut b, &quick).await?;

    assert!(acl.engine.remove_namespace("nsd:x"));
    assert_eq!(acl.engine.namespaces(), ids(&["quick"]));
    assert_eq!(
        acl.engine.memberships(&principal(&a.public())),
        ids(&["quick"])
    );
    delivered(&a, &mut b, &quick).await?;
    dropped(&a, &mut b, &mut events, &nsd, reasons::DENIED).await?;

    let stats = acl.filter.stats();
    assert_eq!((stats.accepted, stats.denied), (4, 3));
    assert_eq!(b.drops(reasons::DENIED).await?, 3);
    Ok(())
}

/// Scenario 2: hub `b` forwards between `a` ("quick") and `c` ("nsd:x"). Cross-namespace
/// traffic is dropped both ways; a directed grant opens one port of `c` to "quick" (and
/// lets `c`'s replies pass) until it is removed.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn hub_drops_cross_namespace_and_follows_a_directed_grant() -> TestResult {
    let acl = Acl::new(AclEngine::new());
    let (a_end, b_a_end, c_end, b_c_end) = (end(1, 1), end(2, 2), end(3, 3), end(4, 4));
    let (link_a, link_b_a) = ChannelTransport::pair(CAPACITY, a_end, b_a_end);
    let (link_c, link_b_c) = ChannelTransport::pair(CAPACITY, c_end, b_c_end);
    let mut a = Node::with_builder(1, a_end.0, a_end.1, Options::default(), |builder| {
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
        source(vec![member(&a.public(), a.ip4, a.ip6)?], &[], None, &[]),
    )?;
    acl.engine.store_namespace(
        "nsd:x",
        source(vec![member(&c.public(), c.ip4, c.ip6)?], &[], None, &[]),
    )?;
    let mut events = b.subscribe().await?;
    let cross = reasons::CROSS_NAMESPACE;

    let a_to_c = udp_to(&a, SRC_PORT, c.ip4, QUICK_PORT);
    dropped(&a, &mut b, &mut events, &a_to_c, cross).await?;
    let c_to_a = udp_to(&c, SRC_PORT, a.ip4, QUICK_PORT);
    dropped(&c, &mut b, &mut events, &c_to_a, cross).await?;
    assert_eq!(b.drops(cross).await?, 2);
    assert_eq!(acl.filter.stats().cross_namespace, 2);

    acl.engine.store_grant(
        "quick-to-c",
        Grant {
            from: GrantEnd::Namespace("quick".into()),
            to: GrantEnd::Peer(principal(&c.public())),
            proto: Some("udp".to_owned()),
            ports: Some(QUICK_PORT.to_string()),
        },
    )?;
    relayed(&a, &mut b, &mut c, &a_to_c).await?;
    let other_port = udp_to(&a, SRC_PORT, c.ip4, QUICK_PORT + 1);
    dropped(&a, &mut b, &mut events, &other_port, cross).await?;
    // The grant is one-way: `c` opens nothing towards `a`, but its replies pass.
    let c_new_flow = udp_to(&c, SRC_PORT + 1, a.ip4, QUICK_PORT);
    dropped(&c, &mut b, &mut events, &c_new_flow, cross).await?;
    let c_reply = udp_to(&c, QUICK_PORT, a.ip4, SRC_PORT);
    relayed(&c, &mut b, &mut a, &c_reply).await?;
    relayed(&a, &mut b, &mut c, &a_to_c).await?;

    assert!(acl.engine.remove_grant("quick-to-c"));
    let a_new_flow = udp_to(&a, SRC_PORT + 2, c.ip4, QUICK_PORT);
    dropped(&a, &mut b, &mut events, &a_new_flow, cross).await?;
    // The flow the grant accepted is revoked in both directions.
    dropped(&c, &mut b, &mut events, &c_reply, cross).await?;
    dropped(&a, &mut b, &mut events, &a_to_c, cross).await?;

    let stats = acl.filter.stats();
    assert_eq!(stats.reply_revoked, 2);
    assert_eq!(stats.cross_namespace, 7);
    assert_eq!(b.drops(cross).await?, 7);
    Ok(())
}

/// Scenario 6: a pinhole whose guard outlives its expiry stops accepting new flows once the
/// engine clock (paused tokio time) passes `expires_at`.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pinhole_expires_on_the_engine_clock() -> TestResult {
    let acl = Acl::new(AclEngine::with_clock(|| {
        tokio::time::Instant::now().into_std()
    }));
    let (a, mut b) = packet_pair(&acl).await?;
    let mut events = b.subscribe().await?;
    let a_member = member(&a.public(), a.ip4, a.ip6)?;
    acl.engine.store_namespace(
        "quick",
        source(
            vec![a_member.clone()],
            &[QUICK_PORT],
            Some("udp"),
            &[TRANSFER_KIND],
        ),
    )?;
    acl.engine.store_namespace("app:s1", app(vec![a_member]))?;
    let lifetime = Duration::from_secs(60);
    let expires_at = tokio::time::Instant::now().into_std() + lifetime;
    let guard = acl.engine.open_pinhole(
        "app:s1",
        inbound_pinhole(principal(&a.public()), Protocol::Udp, expires_at),
    )?;

    let packet = udp_to(&a, SRC_PORT, b.ip4, APP_PORT);
    delivered(&a, &mut b, &packet).await?;
    tokio::time::advance(lifetime + Duration::from_secs(1)).await;
    let new_flow = udp_to(&a, SRC_PORT + 1, b.ip4, APP_PORT);
    dropped(&a, &mut b, &mut events, &new_flow, reasons::DENIED).await?;
    assert!(!guard.is_open());
    assert_eq!(
        acl.engine.pinhole_stats(),
        PinholeStats {
            opened: 1,
            expired: 1,
            ..PinholeStats::default()
        }
    );
    // The source namespace's own rule is unaffected.
    let packet = udp_to(&a, SRC_PORT, b.ip4, QUICK_PORT);
    delivered(&a, &mut b, &packet).await?;
    drop(guard);
    assert_eq!(acl.engine.pinhole_stats().closed, 0);
    Ok(())
}

// ── Stack nodes ──────────────────────────────────────────────────────────────

/// Stack nodes `remote` (seed 1) and `b` (seed 2) linked by a channel pair, `b` filtering
/// with `acl` and echoing every TCP connection. With `peered` they are introduced and
/// `remote` is identified by its key.
async fn stack_pair(acl: &Acl, peered: bool) -> TestResult<(StackNode, StackNode)> {
    let (r_end, b_end) = (end(1, 1), end(2, 2));
    let (link_r, link_b) = ChannelTransport::pair(CAPACITY, r_end, b_end);
    let remote = StackNode::with_builder(1, r_end.0, r_end.1, DEFAULT_MTU, |builder| {
        builder.transport(link_r)
    })?;
    let filter = acl.filter.clone();
    let b = StackNode::with_builder(2, b_end.0, b_end.1, DEFAULT_MTU, |builder| {
        builder.transport(link_b).filter(Box::new(filter))
    })?;
    serve_tcp_echo(&b.stack);
    if peered {
        remote
            .handle
            .add_or_update_peer(b.as_peer(remote.path.transport))
            .await?;
        b.handle
            .add_or_update_peer(remote.as_peer(b.path.transport))
            .await?;
        let peer = b
            .handle
            .peer_id(remote.public())
            .await?
            .ok_or("unknown peer")?;
        acl.identify(peer, &remote.public());
    }
    Ok((remote, b))
}

/// `len` bytes whose pattern (period 251) does not line up with any segment size.
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
}

/// Connects from `client` to `target`, sends `len` bytes, half-closes and checks that the
/// same bytes come back, followed by EOF.
async fn transfer(client: &NetStackHandle, target: SocketAddr, len: usize) -> TestResult {
    let conn = timeout(TRANSFER, client.connect_tcp(target)).await??;
    let sent = data(len);
    let (mut reader, mut writer) = tokio::io::split(conn);
    let write = async {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    };
    let read = async {
        let mut echoed = Vec::with_capacity(len);
        reader.read_to_end(&mut echoed).await?;
        Ok::<_, io::Error>(echoed)
    };
    let ((), echoed) = timeout(TRANSFER, async { tokio::try_join!(write, read) }).await??;
    if echoed != sent {
        return Err(format!(
            "{} of {len} bytes echoed intact from {target}",
            echoed.len()
        )
        .into());
    }
    Ok(())
}

/// Checks that a connection from `client` to `target` is not established within
/// [`REFUSED`] and that `filtering` (the engine whose filter drops the SYNs) counted drops
/// under `reason` meanwhile.
async fn refused(
    client: &NetStackHandle,
    target: SocketAddr,
    filtering: &EngineHandle,
    reason: &str,
) -> TestResult {
    let before = drops(filtering, reason).await?;
    if let Ok(Ok(_)) = timeout(REFUSED, client.connect_tcp(target)).await {
        return Err(format!("connected to {target}").into());
    }
    let after = drops(filtering, reason).await?;
    if after <= before {
        return Err(format!("no drop counted under {reason:?} for {target}").into());
    }
    Ok(())
}

/// What must not change while an app session reuses an existing tunnel.
#[derive(Debug, PartialEq, Eq)]
struct Tunnel {
    peers: usize,
    public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    last_handshake: Duration,
}

/// The tunnel of `b` to `remote`.
async fn tunnel(b: &StackNode, remote: &StackNode) -> TestResult<Tunnel> {
    let peer = b
        .handle
        .peer_id(remote.public())
        .await?
        .ok_or("unknown peer")?;
    let stats = b.handle.peer_stats(peer).await?.ok_or("no peer stats")?;
    Ok(Tunnel {
        peers: b.handle.peers().await?.len(),
        public_key: stats.public_key.to_bytes(),
        preshared_key: stats.preshared_key,
        last_handshake: stats.last_handshake.ok_or("no handshake")?,
    })
}

/// Checks that `now` is the tunnel `before` with no new handshake: `last_handshake` only
/// grew, and `events` saw no further `HandshakeCompleted`.
async fn same_tunnel(before: &Tunnel, now: &Tunnel, events: &mut Events) -> TestResult {
    assert_eq!(
        (now.peers, now.public_key, now.preshared_key),
        (before.peers, before.public_key, before.preshared_key)
    );
    assert!(
        now.last_handshake >= before.last_handshake,
        "a handshake completed: {now:?} after {before:?}"
    );
    events
        .expect_none(|e| matches!(e, Event::HandshakeCompleted { .. }))
        .await
}

const fn is_handshake(event: &Event) -> bool {
    matches!(event, Event::HandshakeCompleted { .. })
}

/// Scenario 3: a peer of the Quick-like source, which allows "transfer", gets a pinhole for
/// an app session over its existing tunnel; the transfer works until the guard is dropped,
/// and the source's own rules are unaffected throughout.
#[tokio::test]
async fn quick_source_allows_a_transfer_pinhole() -> TestResult {
    let acl = Acl::new(AclEngine::new());
    let (a, b) = stack_pair(&acl, true).await?;
    let mut events = b.subscribe().await?;
    let a_member = member(&a.public(), a.ip4, a.ip6)?;
    let a_principal = principal(&a.public());
    acl.engine.store_namespace(
        "quick",
        source(
            vec![a_member.clone()],
            &[QUICK_PORT],
            Some("tcp"),
            &[TRANSFER_KIND],
        ),
    )?;
    let at = |port| b.socket_addr(Family::V4, port);

    transfer(&a.stack, at(QUICK_PORT), PROBE).await?;
    events.expect(is_handshake).await?;
    let before = tunnel(&b, &a).await?;
    refused(&a.stack, at(APP_PORT), &b.handle, reasons::DENIED).await?;

    acl.engine.store_namespace("app:s1", app(vec![a_member]))?;
    assert_eq!(
        acl.engine.memberships(&a_principal),
        ids(&["app:s1", "quick"])
    );
    let guard = acl.engine.open_pinhole(
        "app:s1",
        inbound_pinhole(a_principal.clone(), Protocol::Tcp, in_an_hour()),
    )?;
    transfer(&a.stack, at(APP_PORT), FILE).await?;
    transfer(&a.stack, at(QUICK_PORT), PROBE).await?;
    // The pinhole opens its port only.
    refused(&a.stack, at(APP_PORT + 1), &b.handle, reasons::DENIED).await?;

    drop(guard);
    assert_eq!(acl.engine.pinhole_stats().closed, 1);
    refused(&a.stack, at(APP_PORT), &b.handle, reasons::DENIED).await?;
    transfer(&a.stack, at(QUICK_PORT), PROBE).await?;

    assert!(acl.engine.remove_namespace("app:s1"));
    assert_eq!(acl.engine.memberships(&a_principal), ids(&["quick"]));
    transfer(&a.stack, at(QUICK_PORT), PROBE).await?;
    same_tunnel(&before, &tunnel(&b, &a).await?, &mut events).await
}

/// Scenario 4: an nsd-like source that allows no app kinds refuses the pinhole and nothing
/// changes.
#[tokio::test]
async fn nsd_source_without_permission_refuses_the_pinhole() -> TestResult {
    let acl = Acl::new(AclEngine::new());
    let (a, b) = stack_pair(&acl, true).await?;
    let a_member = member(&a.public(), a.ip4, a.ip6)?;
    let a_principal = principal(&a.public());
    acl.engine.store_namespace(
        "nsd:x",
        source(vec![a_member.clone()], &[NSD_PORT], Some("tcp"), &[]),
    )?;
    acl.engine.store_namespace("app:s1", app(vec![a_member]))?;
    let at = |port| b.socket_addr(Family::V4, port);
    transfer(&a.stack, at(NSD_PORT), PROBE).await?;

    let refusal = acl.engine.open_pinhole(
        "app:s1",
        inbound_pinhole(a_principal.clone(), Protocol::Tcp, in_an_hour()),
    );
    assert!(
        matches!(refusal, Err(PinholeError::NotPermitted)),
        "{refusal:?}"
    );
    assert_eq!(
        acl.engine.pinhole_stats(),
        PinholeStats {
            not_permitted: 1,
            ..PinholeStats::default()
        }
    );
    assert_eq!(acl.engine.namespaces(), ids(&["app:s1", "nsd:x"]));
    assert_eq!(
        acl.engine.memberships(&a_principal),
        ids(&["app:s1", "nsd:x"])
    );
    refused(&a.stack, at(APP_PORT), &b.handle, reasons::DENIED).await?;
    transfer(&a.stack, at(NSD_PORT), PROBE).await
}

/// Scenario 5: an nsd-like source that allows "transfer" gets the pinhole; withdrawing the
/// permission mid-session revokes it and stops the transfer in flight and new ones.
#[tokio::test]
async fn nsd_source_withdrawing_permission_revokes_the_pinhole() -> TestResult {
    let acl = Acl::new(AclEngine::new());
    let (a, b) = stack_pair(&acl, true).await?;
    let a_member = member(&a.public(), a.ip4, a.ip6)?;
    let a_principal = principal(&a.public());
    acl.engine.store_namespace(
        "nsd:x",
        source(
            vec![a_member.clone()],
            &[NSD_PORT],
            Some("tcp"),
            &[TRANSFER_KIND],
        ),
    )?;
    acl.engine
        .store_namespace("app:s1", app(vec![a_member.clone()]))?;
    let at = |port| b.socket_addr(Family::V6, port);
    let guard = acl.engine.open_pinhole(
        "app:s1",
        inbound_pinhole(a_principal, Protocol::Tcp, in_an_hour()),
    )?;
    transfer(&a.stack, at(APP_PORT), FILE).await?;

    // A transfer in flight: one chunk echoed, then the source withdraws "transfer".
    let chunk = data(64 << 10);
    let conn = timeout(TRANSFER, a.stack.connect_tcp(at(APP_PORT))).await??;
    let (mut reader, mut writer) = tokio::io::split(conn);
    let mut echoed = vec![0; chunk.len()];
    timeout(TRANSFER, async {
        writer.write_all(&chunk).await?;
        reader.read_exact(&mut echoed).await
    })
    .await??;
    assert!(echoed == chunk, "chunk changed in transit");

    acl.engine.store_namespace(
        "nsd:x",
        source(vec![a_member], &[NSD_PORT], Some("tcp"), &[]),
    )?;
    assert!(!guard.is_open());
    assert_eq!(
        acl.engine.pinhole_stats(),
        PinholeStats {
            opened: 1,
            revoked: 1,
            ..PinholeStats::default()
        }
    );
    let stalled = timeout(REFUSED, async {
        writer.write_all(&chunk).await?;
        reader.read_exact(&mut echoed).await
    })
    .await;
    assert!(
        !matches!(stalled, Ok(Ok(_))),
        "the transfer went on after the revocation"
    );
    assert!(acl.filter.stats().reply_revoked > 0);
    refused(&a.stack, at(APP_PORT), &b.handle, reasons::DENIED).await?;
    transfer(&a.stack, at(NSD_PORT), PROBE).await
}

/// Scenario 7: a session-only peer. The session makes `d` a new peer of `b` (its /128 only,
/// its own preshared key) in an outbound-restricted app namespace with one pinhole; the
/// transfer works, nothing else does in either direction, and the session's end removes
/// the pinhole, the namespace and the peer.
#[tokio::test]
async fn session_only_peer_gets_the_pinhole_and_nothing_else() -> TestResult {
    let acl = Acl::new(AclEngine::new());
    let (d, b) = stack_pair(&acl, false).await?;
    assert_eq!(b.handle.peers().await?.len(), 0);
    let mut events = b.subscribe().await?;

    // Session start.
    let psk = Some([0x5e; 32]);
    let only_v6 = |ip6| {
        vec![AllowedIp {
            addr: IpAddr::V6(ip6),
            cidr: 128,
        }]
    };
    b.handle
        .add_or_update_peer(Peer {
            allowed_ips: only_v6(d.ip6),
            preshared_key: psk,
            ..d.as_peer(b.path.transport)
        })
        .await?;
    d.handle
        .add_or_update_peer(Peer {
            allowed_ips: only_v6(b.ip6),
            preshared_key: psk,
            ..b.as_peer(d.path.transport)
        })
        .await?;
    let peer_d = b.handle.peer_id(d.public()).await?.ok_or("unknown peer")?;
    acl.identify(peer_d, &d.public());
    let d_net: IpNet = format!("{}/128", d.ip6).parse()?;
    acl.engine.store_namespace(
        "app:s2",
        NamespacePolicy {
            members: vec![NamespaceMember {
                principal: principal(&d.public()),
                addresses: vec![d_net],
            }],
            outbound: Some(vec![]),
            ..NamespacePolicy::default()
        },
    )?;
    let guard = acl.engine.open_pinhole(
        "app:s2",
        inbound_pinhole(principal(&d.public()), Protocol::Tcp, in_an_hour()),
    )?;
    assert_eq!(b.handle.peers().await?.len(), 1);

    let at = |port| b.socket_addr(Family::V6, port);
    transfer(&d.stack, at(APP_PORT), FILE).await?;
    events.expect(is_handshake).await?;
    for port in [QUICK_PORT, APP_PORT + 1] {
        refused(&d.stack, at(port), &b.handle, reasons::DENIED).await?;
    }
    for port in [APP_PORT, QUICK_PORT] {
        let target = d.socket_addr(Family::V6, port);
        refused(&b.stack, target, &b.handle, reasons::OUTBOUND).await?;
    }
    assert!(acl.filter.stats().outbound_denied > 0);
    assert!(acl.filter.stats().outbound_replies > 0);

    // Session end.
    drop(guard);
    assert!(acl.engine.remove_namespace("app:s2"));
    b.handle.remove_peer(d.public()).await?;
    acl.identities.remove(peer_d);
    assert_eq!(acl.engine.namespaces(), ids(&[]));
    assert_eq!(b.handle.peers().await?.len(), 0);
    assert_eq!(
        acl.engine.pinhole_stats(),
        PinholeStats {
            opened: 1,
            closed: 1,
            ..PinholeStats::default()
        }
    );
    let before = b.handle.drop_counters().await?;
    if let Ok(Ok(_)) = timeout(REFUSED, d.stack.connect_tcp(at(APP_PORT))).await {
        return Err("connected after the session ended".into());
    }
    // Nothing reached `b`'s filter: without the peer the tunnel itself is gone.
    let after = b.handle.drop_counters().await?;
    for reason in [reasons::DENIED, reasons::UNKNOWN_PEER, reasons::OUTBOUND] {
        assert_eq!(after.get(reason), before.get(reason), "{reason}");
    }
    Ok(())
}

/// Scenario 8: an app session between peers that already have a tunnel reuses it: no peer
/// update, no new key, no handshake; other namespaces stay as they were and the session's
/// end removes only its app namespace.
#[tokio::test]
async fn session_reuses_an_existing_tunnel() -> TestResult {
    let acl = Acl::new(AclEngine::new());
    let (a, b) = stack_pair(&acl, true).await?;
    let mut events = b.subscribe().await?;
    let a_member = member(&a.public(), a.ip4, a.ip6)?;
    let a_principal = principal(&a.public());
    acl.engine.store_namespace(
        "quick",
        source(
            vec![a_member.clone()],
            &[QUICK_PORT],
            Some("tcp"),
            &[TRANSFER_KIND],
        ),
    )?;
    acl.engine.store_namespace(
        "nsd:x",
        source(vec![a_member.clone()], &[NSD_PORT], Some("tcp"), &[]),
    )?;
    let at = |port| b.socket_addr(Family::V6, port);
    transfer(&a.stack, at(QUICK_PORT), PROBE).await?;
    events.expect(is_handshake).await?;
    let before = tunnel(&b, &a).await?;

    acl.engine.store_namespace("app:s3", app(vec![a_member]))?;
    let guard = acl.engine.open_pinhole(
        "app:s3",
        inbound_pinhole(a_principal.clone(), Protocol::Tcp, in_an_hour()),
    )?;
    transfer(&a.stack, at(APP_PORT), FILE).await?;
    for port in [QUICK_PORT, NSD_PORT] {
        transfer(&a.stack, at(port), PROBE).await?;
    }
    same_tunnel(&before, &tunnel(&b, &a).await?, &mut events).await?;

    drop(guard);
    assert!(acl.engine.remove_namespace("app:s3"));
    assert_eq!(acl.engine.namespaces(), ids(&["nsd:x", "quick"]));
    assert_eq!(
        acl.engine.memberships(&a_principal),
        ids(&["nsd:x", "quick"])
    );
    for port in [QUICK_PORT, NSD_PORT] {
        transfer(&a.stack, at(port), PROBE).await?;
    }
    refused(&a.stack, at(APP_PORT), &b.handle, reasons::DENIED).await?;
    same_tunnel(&before, &tunnel(&b, &a).await?, &mut events).await
}
