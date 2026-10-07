//! The `PortMap` between two engines over a channel transport: node `a` publishes a local
//! service on its overlay IPv6 address, node `b` connects to it. Covers DNAT/SNAT for UDP
//! and TCP, peers a rule does not allow, conntrack expiry (with an injected clock) and
//! eviction, and once the full filter stack `[AclFilter, PortMap, Translator]` with an
//! IPv4-only service and client on `a`, allowed and denied by an ACL rule on the overlay
//! IPv6 address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nsplane::{AllowedIp, ChannelTransport, Event};
use nsplane_acl::{
    AclAction, AclEngine, AclFilter, AclPolicy, AclRule, Label, LabelSet, PeerLabelMap,
};
use nsplane_e2e::{
    Node, Options, SharedFilter, TestResult, channel_pair_with, introduce, payload, tcp, udp,
    verify_checksums,
};
use nsplane_nat::port_map::reasons;
use nsplane_nat::{
    Conntrack, ConntrackConfig, PeerMapping, PortMap, PortMapProtocol, PortMapRule, SelfMapping,
    TranslationTable, Translator,
};
use nsplane_packet::{IpPacket, PeerId};

/// The published port and the port of the local service behind it.
const LISTEN: u16 = 8080;
const SERVICE: u16 = 80;
/// A published port no peer of the tests may use.
const PRIVATE: u16 = 8081;
/// TCP flags.
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;

type TestNode = Node<ChannelTransport>;

/// A manual clock for the conntrack: `start` plus the milliseconds advanced so far.
#[derive(Clone)]
struct Clock {
    start: Instant,
    elapsed_ms: Arc<AtomicU64>,
}

impl Clock {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            elapsed_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn now(&self) -> Instant {
        self.start + Duration::from_millis(self.elapsed_ms.load(Ordering::Relaxed))
    }

    fn advance(&self, by: Duration) -> TestResult {
        self.elapsed_ms
            .fetch_add(u64::try_from(by.as_millis())?, Ordering::Relaxed);
        Ok(())
    }
}

/// A conntrack of at most `max_entries` flows with 1 s timeouts, following `clock`.
fn conntrack(max_entries: usize, clock: &Clock) -> Conntrack {
    let config = ConntrackConfig {
        max_entries,
        tcp_established_timeout: Duration::from_secs(1),
        tcp_transitory_timeout: Duration::from_secs(1),
        udp_timeout: Duration::from_secs(1),
        icmp_timeout: Duration::from_secs(1),
    };
    let clock = clock.clone();
    Conntrack::with_clock(config, move || clock.now())
}

/// A rule publishing `target` on `listen` for `peers`.
const fn rule(
    protocol: PortMapProtocol,
    listen: SocketAddr,
    target: SocketAddr,
    peers: Option<Vec<PeerId>>,
) -> PortMapRule {
    PortMapRule {
        protocol,
        listen,
        target,
        peers,
    }
}

const fn v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

const fn v6(ip: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(ip), port)
}

fn allowed(addr: impl Into<IpAddr>, cidr: u8) -> AllowedIp {
    AllowedIp {
        addr: addr.into(),
        cidr,
    }
}

/// Two peers, `a` with a port map whose flows `conntrack` records. The rules publish `a`'s
/// UDP and TCP service on `LISTEN` to `b` and on `PRIVATE` to another peer only.
async fn pair(conntrack: Conntrack) -> TestResult<(TestNode, TestNode, Arc<PortMap>)> {
    let port_map = Arc::new(PortMap::with_conntrack([], conntrack)?);
    let filter = Arc::clone(&port_map);
    let (a, b) = channel_pair_with(Options::default(), |seed, builder| match seed {
        1 => builder.filter(Box::new(SharedFilter(Arc::clone(&filter)))),
        _ => builder,
    })?;
    introduce(&a, &b, None).await?;
    let peer_b = a.peer_of(&b).await?;
    let (listen, target) = (v6(a.ip6, LISTEN), v6(a.ip6, SERVICE));
    let mut rules = Vec::new();
    for protocol in [PortMapProtocol::Udp, PortMapProtocol::Tcp] {
        rules.push(rule(protocol, listen, target, Some(vec![peer_b])));
        rules.push(rule(
            protocol,
            v6(a.ip6, PRIVATE),
            target,
            Some(vec![PeerId::new(u32::MAX)]),
        ));
    }
    port_map.set_rules(rules)?;
    Ok((a, b, port_map))
}

/// The next packet `node` delivers, with valid checksums, as `(src, dst)`.
async fn expect_endpoints(node: &mut TestNode) -> TestResult<(SocketAddr, SocketAddr, Vec<u8>)> {
    let (_, packet) = node.expect_delivery().await?;
    verify_checksums(&packet)?;
    let ip = IpPacket::parse(&packet).map_err(|e| format!("{e:?}"))?;
    let tuple = ip.five_tuple().ok_or("no five-tuple")?;
    Ok((
        SocketAddr::new(tuple.src, tuple.src_port),
        SocketAddr::new(tuple.dst, tuple.dst_port),
        ip.payload().to_vec(),
    ))
}

/// `b` sends a UDP datagram from `client` to `a`'s listen port; `a` delivers it to its
/// service (DNAT) and the service's reply reaches `b` from the listen address (SNAT).
async fn udp_through(a: &mut TestNode, b: &mut TestNode, client: SocketAddr) -> TestResult {
    let (listen, service) = (v6(a.ip6, LISTEN), v6(a.ip6, SERVICE));
    b.send(&udp(client, listen, &payload(200))).await?;
    let (src, dst, segment) = expect_endpoints(a).await?;
    assert_eq!((src, dst), (client, service));
    assert_eq!(segment[8..], payload(200));

    a.send(&udp(service, client, &payload(400))).await?;
    let (src, dst, segment) = expect_endpoints(b).await?;
    assert_eq!((src, dst), (listen, client));
    assert_eq!(segment[8..], payload(400));
    Ok(())
}

#[tokio::test]
async fn published_service_is_dnated_and_its_replies_snated() -> TestResult {
    let clock = Clock::new();
    let (mut a, mut b, port_map) = pair(conntrack(16, &clock)).await?;
    let client = v6(b.ip6, 40000);
    udp_through(&mut a, &mut b, client).await?;

    // TCP: the SYN is mapped, the SYN-ACK comes back from the listen port.
    let (listen, service) = (v6(a.ip6, LISTEN), v6(a.ip6, SERVICE));
    b.send(&tcp(client, listen, SYN, (1, 0), &[])).await?;
    assert_eq!(expect_endpoints(&mut a).await?.1, service);
    a.send(&tcp(service, client, SYN_ACK, (100, 2), &[]))
        .await?;
    let (src, dst, _) = expect_endpoints(&mut b).await?;
    assert_eq!((src, dst), (listen, client));

    let stats = port_map.conntrack().stats();
    assert_eq!((stats.entries, stats.inserted), (2, 2));
    Ok(())
}

#[tokio::test]
async fn a_peer_the_rule_does_not_allow_is_dropped() -> TestResult {
    let clock = Clock::new();
    let (mut a, b, port_map) = pair(conntrack(16, &clock)).await?;
    let mut events = a.subscribe().await?;
    let peer_b = a.peer_of(&b).await?;

    b.send(&udp(v6(b.ip6, 40001), v6(a.ip6, PRIVATE), b"private"))
        .await?;
    events
        .expect(|e| {
            matches!(e, Event::Dropped { peer: Some(p), reason } if *p == peer_b
                && *reason == reasons::PEER_NOT_ALLOWED)
        })
        .await?;
    a.expect_no_delivery().await?;
    assert_eq!(a.drops(reasons::PEER_NOT_ALLOWED).await?, 1);
    assert_eq!(port_map.conntrack().stats().inserted, 0);
    Ok(())
}

#[tokio::test]
async fn expired_flows_are_not_snated_and_new_flows_replace_them() -> TestResult {
    let clock = Clock::new();
    let (mut a, mut b, port_map) = pair(conntrack(16, &clock)).await?;
    let client = v6(b.ip6, 40002);
    let service = v6(a.ip6, SERVICE);
    udp_through(&mut a, &mut b, client).await?;

    // Past the UDP timeout the reply has no flow: it leaves from the service port.
    clock.advance(Duration::from_millis(1500))?;
    a.send(&udp(service, client, b"late")).await?;
    let (src, dst, _) = expect_endpoints(&mut b).await?;
    assert_eq!((src, dst), (service, client));
    let stats = port_map.conntrack().stats();
    assert_eq!((stats.entries, stats.expired), (0, 1));

    // The next request opens a new flow and replies are mapped again.
    udp_through(&mut a, &mut b, client).await?;
    let stats = port_map.conntrack().stats();
    assert_eq!((stats.entries, stats.inserted, stats.expired), (1, 2, 1));
    Ok(())
}

#[tokio::test]
async fn a_full_table_evicts_the_least_recently_seen_flow() -> TestResult {
    let clock = Clock::new();
    let (mut a, mut b, port_map) = pair(conntrack(2, &clock)).await?;
    let service = v6(a.ip6, SERVICE);
    let clients = [40010, 40011, 40012].map(|port| v6(b.ip6, port));
    for client in clients {
        udp_through(&mut a, &mut b, client).await?;
    }
    let stats = port_map.conntrack().stats();
    assert_eq!((stats.entries, stats.inserted), (2, 3));
    assert_eq!((stats.evicted, stats.expired), (1, 0));

    // The first flow is gone: its reply is not mapped; the last one's still is.
    a.send(&udp(service, clients[0], b"evicted")).await?;
    assert_eq!(expect_endpoints(&mut b).await?.0, service);
    a.send(&udp(service, clients[2], b"kept")).await?;
    assert_eq!(expect_endpoints(&mut b).await?.0, v6(a.ip6, LISTEN));
    Ok(())
}

/// Node `a`'s own IPv4 address and its `eam6`, which `b` reaches the service on.
const SELF_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 100);
const SELF_EAM6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xff, 1);
/// Node `b`'s `peer6`, `eam6` and `a`'s `eam4` for it.
const PEER6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 0);
const PEER_EAM6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 1);
const PEER_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

/// `a` with the full stack `[AclFilter, PortMap, Translator]` (wire side to local side),
/// publishing its IPv4-only service on `SELF_EAM6:LISTEN` with the ACL allowing `b` to
/// reach `SELF_EAM6:acl_port` over UDP; `b` is IPv6-only and runs no filter.
async fn full_stack(acl_port: u16) -> TestResult<(TestNode, TestNode, AclFilter)> {
    let acl_engine = Arc::new(AclEngine::new());
    let identities = Arc::new(PeerLabelMap::new());
    let acl = AclFilter::new(Arc::clone(&acl_engine), Arc::clone(&identities));
    let port_map = PortMap::new([rule(
        PortMapProtocol::Udp,
        v6(SELF_EAM6, LISTEN),
        v6(SELF_EAM6, SERVICE),
        None,
    )])?;
    let self_mapping = SelfMapping {
        eam4: SELF_EAM4,
        eam6: SELF_EAM6,
    };
    let translator = Arc::new(Translator::new(
        TranslationTable::builder()
            .self_mapping(self_mapping)
            .build()?,
    ));

    let filters = (acl.clone(), Arc::clone(&translator));
    let mut port_map = Some(port_map);
    let (a, b) = channel_pair_with(Options::default(), |seed, builder| {
        match (seed, port_map.take()) {
            (1, Some(port_map)) => builder
                .filter(Box::new(filters.0.clone()))
                .filter(Box::new(port_map))
                .filter(Box::new(SharedFilter(Arc::clone(&filters.1)))),
            _ => builder,
        }
    })?;
    introduce(&a, &b, None).await?;
    let mut peer = b.as_peer(a.path.transport);
    peer.allowed_ips = vec![
        allowed(PEER_EAM4, 32),
        allowed(PEER_EAM6, 128),
        allowed(PEER6, 128),
    ];
    a.handle.add_or_update_peer(peer).await?;
    let mut peer = a.as_peer(b.path.transport);
    peer.allowed_ips = vec![allowed(SELF_EAM6, 128)];
    b.handle.add_or_update_peer(peer).await?;

    let peer_b = a.peer_of(&b).await?;
    translator.store(
        TranslationTable::builder()
            .self_mapping(self_mapping)
            .peer(
                peer_b,
                PeerMapping {
                    peer6: PEER6,
                    eam6: PEER_EAM6,
                    local6: None,
                    eam4: Some(PEER_EAM4),
                },
            )
            .build()?,
    );
    // The label the policy's `key:<hex>` source compiles to.
    let key = b
        .public()
        .to_bytes()
        .iter()
        .fold(String::from("key:"), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        });
    identities.insert(peer_b, LabelSet::new([Label::from(key.as_str())]));
    acl_engine.load(AclPolicy {
        acls: vec![AclRule {
            action: AclAction::Accept,
            src: vec![key],
            dst: vec![format!("{SELF_EAM6}:{acl_port}")],
            proto: Some("udp".to_owned()),
        }],
        ..AclPolicy::default()
    })?;
    Ok((a, b, acl))
}

#[tokio::test]
async fn full_stack_lets_an_allowed_peer_reach_an_ipv4_service() -> TestResult {
    let (mut a, mut b, acl) = full_stack(LISTEN).await?;
    let client6 = v6(PEER_EAM6, 40020);
    let client4 = v4(PEER_EAM4, 40020);

    // `b` reaches the published listen address; the ACL accepts it on the overlay
    // address, the port map maps it to the service port, the translator hands it to the
    // IPv4-only service.
    b.send(&udp(client6, v6(SELF_EAM6, LISTEN), &payload(100)))
        .await?;
    let (src, dst, segment) = expect_endpoints(&mut a).await?;
    assert_eq!((src, dst), (client4, v4(SELF_EAM4, SERVICE)));
    assert_eq!(segment[8..], payload(100));

    // The IPv4 reply is translated, mapped back to the listen port and passes the ACL.
    a.send_with_room(&udp(v4(SELF_EAM4, SERVICE), client4, &payload(300)))
        .await?;
    let (src, dst, segment) = expect_endpoints(&mut b).await?;
    assert_eq!((src, dst), (v6(SELF_EAM6, LISTEN), client6));
    assert_eq!(segment[8..], payload(300));

    // An IPv4-only client on `a` reaches `b` through its `eam4`; `b`'s reply passes the
    // ACL as a reply although no rule allows it, since the ACL saw the same IPv6 flow
    // leave.
    let app = v4(SELF_EAM4, 40021);
    a.send_with_room(&udp(app, v4(PEER_EAM4, 7000), b"request"))
        .await?;
    let (src, dst, _) = expect_endpoints(&mut b).await?;
    assert_eq!((src, dst), (v6(SELF_EAM6, 40021), v6(PEER_EAM6, 7000)));
    b.send(&udp(v6(PEER_EAM6, 7000), v6(SELF_EAM6, 40021), b"reply"))
        .await?;
    let (src, dst, _) = expect_endpoints(&mut a).await?;
    assert_eq!((src, dst), (v4(PEER_EAM4, 7000), app));

    let stats = acl.stats();
    assert_eq!((stats.accepted, stats.replies, stats.denied), (1, 1, 0));
    Ok(())
}

#[tokio::test]
async fn full_stack_drops_a_peer_the_acl_denies() -> TestResult {
    // The ACL allows another port only.
    let (mut a, b, acl) = full_stack(LISTEN + 1).await?;
    let mut events = a.subscribe().await?;
    let peer_b = a.peer_of(&b).await?;

    b.send(&udp(v6(PEER_EAM6, 40030), v6(SELF_EAM6, LISTEN), b"denied"))
        .await?;
    events
        .expect(|e| {
            matches!(e, Event::Dropped { peer: Some(p), reason } if *p == peer_b
                && *reason == nsplane_acl::reasons::DENIED)
        })
        .await?;
    a.expect_no_delivery().await?;
    assert_eq!(a.drops(nsplane_acl::reasons::DENIED).await?, 1);
    assert_eq!(acl.stats().denied, 1);
    Ok(())
}
