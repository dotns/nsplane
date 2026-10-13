//! Published values replaced while traffic flows: the `AclEngine` policy, the `AclFilter`
//! scopes, the `FlowGate` policy, the `Translator` table and the `Nat64Lan` routes, each
//! read per packet through a per-thread cache. The engines run two crypto workers each on a
//! multi-threaded runtime, so their tasks run on several threads. Each round replaces the
//! value, then sends a burst of new flows; every packet of the burst must be judged by the
//! value of that round, never by a previous one a thread still caches.
//!
//! Nothing waits on timing: deliveries are checked in order, drops by their events and the
//! counters, and each test ends checking that nothing more is delivered.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Ecn, EngineBuilder, Event,
    PacketFilter, Path, Peer, PeerId, TransportId,
};
use nsplane_acl::gate::{
    FlowGate, GateBinding, GateConfig, GateFilter, GateGrant, GateHolds, GateMode, GatePolicy,
    GateReason, GateScope,
};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterScope, AclFilterScopes, Direction, IpNet, Label, LabelSet,
    PeerLabelMap, PortSet, ProtocolMatch, Rule, RuleSet, reasons,
};
use nsplane_e2e::{
    Events, Node, Options, QUIET, SharedFilter, TestResult, WAIT, channel_pair_with, introduce, udp,
};
use nsplane_nat::{
    LanRoute, LanRoutes, Nat64Lan, Nat64LanConfig, Nat64LanSink, Nat64LanSource, PeerMapping,
    SelfMapping, TranslationTable, Translator,
};
use nsplane_packet::{Ipv4Header, Ipv6Header};
use tokio::time::timeout;

/// Replacements per test; even rounds publish one value, odd rounds the other.
const ROUNDS: u16 = 8;
/// Packets sent after each replacement, each a new flow.
const BURST: u16 = 16;
/// Crypto workers of every engine.
const WORKERS: usize = 2;
/// A source address `b`'s second filter scope allows instead of its own.
const ALT4: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
/// The translator's self mapping, `b`'s `peer6` and `eam4`, and the two `eam6` the table
/// alternates between.
const SELF_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 100);
const SELF_EAM6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xff, 1);
const PEER6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 0);
const PEER_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const EAM6: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 1),
    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 2, 2),
];
/// The /96 the LAN client maps the LAN into, the LAN, its host and the two SNAT sources the
/// routes alternate between.
const MAPPED: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x64, 0, 0, 0, 0, 0, 0);
const REAL: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 0);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 10);
const SNAT: [Ipv4Addr; 2] = [
    Ipv4Addr::new(192, 168, 50, 1),
    Ipv4Addr::new(192, 168, 50, 2),
];
/// Capacity of the LAN gateway's channels and link.
const CAPACITY: usize = 1024;
const MTU: u16 = 1420;

type TestNode = Node<ChannelTransport>;

/// Two peers over a channel transport pair, each with [`WORKERS`] crypto workers; `b` runs
/// `filter`.
async fn pair<F: PacketFilter + 'static>(filter: &Arc<F>) -> TestResult<(TestNode, TestNode)> {
    let (a, b) = channel_pair_with(Options::default(), |seed, builder| {
        let builder = builder.crypto_workers(WORKERS);
        match seed {
            2 => builder.filter(Box::new(SharedFilter(Arc::clone(filter)))),
            _ => builder,
        }
    })?;
    introduce(&a, &b, None).await?;
    Ok((a, b))
}

/// Which of the two values round `round` publishes.
const fn second(round: u16) -> bool {
    round % 2 == 1
}

/// The source port of packet `index` of round `round`: every packet is a new flow.
const fn port(round: u16, index: u16) -> u16 {
    10_000 + round * BURST + index
}

/// The burst of round `round`: UDP packets from `src` to `dst`.
fn burst(round: u16, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<Vec<u8>> {
    (0..BURST)
        .map(|index| {
            udp(
                SocketAddr::from((src, port(round, index))),
                SocketAddr::from((dst, 7000)),
                b"burst",
            )
        })
        .collect()
}

/// Sends `packets` from `from`, then checks that `to` delivers each unchanged, in order.
async fn all_delivered(from: &TestNode, to: &mut TestNode, packets: &[Vec<u8>]) -> TestResult {
    for packet in packets {
        from.send(packet).await?;
    }
    for packet in packets {
        let (_, got) = to.expect_delivery().await?;
        if got != *packet {
            return Err("delivered a packet judged by another value".into());
        }
    }
    Ok(())
}

/// Sends `packets` from `from`, then checks that `events` reports a drop with `reason` for
/// each of them.
async fn all_dropped(
    from: &TestNode,
    events: &mut Events,
    packets: &[Vec<u8>],
    reason: &'static str,
) -> TestResult {
    for packet in packets {
        from.send(packet).await?;
    }
    for _ in packets {
        events
            .expect(|e| matches!(e, Event::Dropped { reason: r, .. } if *r == reason))
            .await?;
    }
    Ok(())
}

fn host(ip: IpAddr) -> TestResult<IpNet> {
    let len = if ip.is_ipv4() { 32 } else { 128 };
    Ok(format!("{ip}/{len}").parse()?)
}

/// The packets of each value over all rounds.
fn half() -> u64 {
    u64::from(ROUNDS / 2) * u64::from(BURST)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_packet_after_an_engine_policy_replace_is_judged_by_it() -> TestResult {
    let engine = Arc::new(AclEngine::new());
    let identities = Arc::new(PeerLabelMap::new());
    let filter = Arc::new(AclFilter::new(Arc::clone(&engine), Arc::clone(&identities)));
    let (a, mut b) = pair(&filter).await?;
    identities.insert(b.peer_of(&a).await?, LabelSet::new([Label::from("node-a")]));
    let mut events = b.subscribe().await?;
    let accept_udp = Arc::new(RuleSet::new([Rule::new(
        "udp",
        vec![ProtocolMatch::Udp(PortSet::Any)],
    )])?);

    for round in 0..ROUNDS {
        let packets = burst(round, a.ip4, b.ip4);
        if second(round) {
            engine.install(RuleSet::empty());
            all_dropped(&a, &mut events, &packets, reasons::DENIED).await?;
        } else {
            engine.install(Arc::clone(&accept_udp));
            all_delivered(&a, &mut b, &packets).await?;
        }
    }

    b.expect_no_delivery().await?;
    let stats = filter.stats();
    assert_eq!((stats.accepted, stats.denied), (half(), half()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_packet_after_a_scope_replace_is_judged_by_it() -> TestResult {
    let engine = Arc::new(AclEngine::new());
    engine.install(RuleSet::empty());
    let identities = Arc::new(PeerLabelMap::new());
    let filter = Arc::new(AclFilter::new(engine, Arc::clone(&identities)));
    let (mut a, b) = pair(&filter).await?;
    identities.insert(b.peer_of(&a).await?, LabelSet::new([Label::from("node-a")]));
    let mut events = b.subscribe().await?;

    for round in 0..ROUNDS {
        // Even rounds allow `b`'s own source, odd ones another one only.
        let source = if second(round) {
            IpAddr::V4(ALT4)
        } else {
            IpAddr::V4(b.ip4)
        };
        let scopes = AclFilterScopes::new()
            .with_default(AclFilterScope::new().with_outbound_sources([host(source)?]));
        assert_eq!(filter.replace_scopes(scopes)?, u64::from(round) + 1);
        let packets = burst(round, b.ip4, a.ip4);
        if second(round) {
            all_dropped(&b, &mut events, &packets, reasons::OUTBOUND_SOURCE).await?;
        } else {
            all_delivered(&b, &mut a, &packets).await?;
        }
    }

    a.expect_no_delivery().await?;
    assert_eq!(filter.stats().outbound_source, half());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_packet_after_a_gate_replace_is_judged_by_it() -> TestResult {
    let gate = FlowGate::new(GateConfig::default());
    let filter = Arc::new(GateFilter::new(Arc::clone(&gate)));
    let (a, mut b) = pair(&filter).await?;
    let a_peer = b.peer_of(&a).await?;
    let mut events = b.subscribe().await?;
    let no_grant = GateReason::NoGrant.drop_reason();

    for round in 0..ROUNDS {
        // Even rounds grant `a` every flow to `b`, odd ones nothing.
        let grants = if second(round) {
            Vec::new()
        } else {
            vec![GateGrant {
                id: "a-to-b".into(),
                direction: Direction::Inbound,
                labels: vec![Label::from("source:a")],
                destinations: vec![host(IpAddr::V4(b.ip4))?],
                protocols: vec![ProtocolMatch::Any],
                suspended: false,
            }]
        };
        let policy = GatePolicy {
            scopes: vec![GateScope {
                id: "scope-1".into(),
                mode: GateMode::Enforce,
                local: vec![IpAddr::V4(b.ip4)],
                bindings: vec![GateBinding {
                    peer: a_peer,
                    addresses: vec![IpAddr::V4(a.ip4)],
                    labels: LabelSet::new([Label::from("source:a")]),
                }],
                unbound_addresses: Vec::new(),
                grants,
                unbound: Vec::new(),
            }],
            holds: GateHolds::default(),
        };
        assert_eq!(gate.replace(policy)?, u64::from(round) + 1);
        let packets = burst(round, a.ip4, b.ip4);
        if second(round) {
            all_dropped(&a, &mut events, &packets, no_grant).await?;
        } else {
            all_delivered(&a, &mut b, &packets).await?;
        }
    }

    b.expect_no_delivery().await?;
    let stats = filter.stats();
    assert_eq!((stats.gate_accepted, stats.gate_denied), (half(), half()));
    Ok(())
}

/// The translator's table with `b` as `peer`, its `eam6` the first or the second of [`EAM6`].
fn table(peer: PeerId, second: bool) -> TestResult<TranslationTable> {
    Ok(TranslationTable::builder()
        .self_mapping(SelfMapping {
            eam4: SELF_EAM4,
            eam6: SELF_EAM6,
        })
        .peer(
            peer,
            PeerMapping {
                peer6: PEER6,
                eam6: EAM6[usize::from(second)],
                local6: None,
                eam4: Some(PEER_EAM4),
            },
        )
        .build()?)
}

fn allowed(addr: impl Into<IpAddr>, cidr: u8) -> AllowedIp {
    AllowedIp {
        addr: addr.into(),
        cidr,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_packet_after_a_table_replace_is_translated_by_it() -> TestResult {
    // A placeholder peer until `a` has an id on `b`; `b` translates what it sends to `a`.
    let translator = Arc::new(Translator::new(table(PeerId::new(u32::MAX), false)?));
    let (mut a, b) = pair(&translator).await?;
    let mut peer = a.as_peer(b.path.transport);
    peer.allowed_ips = vec![
        allowed(PEER_EAM4, 32),
        allowed(PEER6, 128),
        allowed(EAM6[0], 128),
        allowed(EAM6[1], 128),
    ];
    b.handle.add_or_update_peer(peer).await?;
    let mut peer = b.as_peer(a.path.transport);
    peer.allowed_ips = vec![allowed(SELF_EAM6, 128)];
    a.handle.add_or_update_peer(peer).await?;
    let a_peer = b.peer_of(&a).await?;

    for round in 0..ROUNDS {
        translator.store(table(a_peer, second(round))?);
        let packets = burst(round, SELF_EAM4, PEER_EAM4);
        for packet in &packets {
            b.send_with_room(packet).await?;
        }
        for index in 0..BURST {
            let (_, got) = a.expect_delivery().await?;
            let (ip, segment) = Ipv6Header::parse(&got)?;
            assert_eq!(
                (ip.src(), ip.dst()),
                (SELF_EAM6, EAM6[usize::from(second(round))])
            );
            assert_eq!(
                segment.get(..2),
                Some(&port(round, index).to_be_bytes()[..])
            );
        }
    }

    a.expect_no_delivery().await?;
    assert_eq!(translator.stats().translated_out, 2 * half());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_packet_after_a_route_replace_is_forwarded_by_it() -> TestResult {
    let client_path = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let gateway_path = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let route = |second: bool| LanRoute::new((MAPPED, 96), (REAL, 24), SNAT[usize::from(second)]);
    let routes = LanRoutes::new(vec![route(false)?]);
    let nat = Arc::new(Nat64Lan::new(routes.clone(), Nat64LanConfig::default()));

    let (link_client, link_gateway) = ChannelTransport::pair(CAPACITY, client_path, gateway_path);
    let client: TestNode = Node::with_builder(
        1,
        client_path.0,
        client_path.1,
        Options::default(),
        |builder| builder.transport(link_client).crypto_workers(WORKERS),
    )?;
    let (source, _lan_out, _mtu) = ChannelSource::new(CAPACITY, MTU);
    let (sink, mut lan_in) = ChannelSink::new(CAPACITY);
    let gateway_secret = StaticSecret::from([2; 32]);
    let gateway = EngineBuilder::new(
        Nat64LanSource::new(source, Arc::clone(&nat)),
        Nat64LanSink::new(sink, Arc::clone(&nat)),
    )
    .private_key(gateway_secret.clone())
    .transport(link_gateway)
    .crypto_workers(WORKERS)
    .build()?;
    gateway
        .handle()
        .add_or_update_peer(client.as_peer(gateway_path.0))
        .await?;
    client
        .handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![allowed(MAPPED, 96)],
            path: Some(Path {
                transport: client_path.0,
                addr: gateway_path.1,
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(PublicKey::from(&gateway_secret))
        })
        .await?;
    let target = Ipv6Addr::from(u128::from(MAPPED) | u128::from(u32::from(LAN_HOST)));

    for round in 0..ROUNDS {
        if round > 0 {
            routes.replace(vec![route(second(round))?]);
        }
        for index in 0..BURST {
            let packet = udp(
                SocketAddr::from((client.ip6, port(round, index))),
                SocketAddr::from((target, 53)),
                b"burst",
            );
            client.send(&packet).await?;
        }
        for _ in 0..BURST {
            let (_, packet) = timeout(WAIT, lan_in.recv())
                .await?
                .ok_or("gateway sink closed")?;
            let (ip, _) = Ipv4Header::parse(packet.as_packet())?;
            assert_eq!(
                (ip.src(), ip.dst()),
                (SNAT[usize::from(second(round))], LAN_HOST)
            );
        }
    }

    assert!(timeout(QUIET, lan_in.recv()).await.is_err());
    assert_eq!(nat.stats().forwarded, 2 * half());
    Ok(())
}
