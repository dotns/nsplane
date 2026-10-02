//! One engine on two transports at once: a direct `UdpTransport` on the loopback interface
//! and a relay-like `ChannelTransport`. Per-peer paths on each, roaming between them under
//! `StandardRoaming` and a pinning policy, adding, removing and replacing transports at
//! runtime, and datagrams to a transport that is not installed.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelTransport, DROP_NO_TRANSPORT, DynTransport, Ecn, Event, Path, PathPolicy,
    Peer, PeerId, Transport, TransportError, TransportId, UdpTransport,
};
use nsplane_core::{MessageKind, Roam};
use nsplane_e2e::{
    Family, Node, Options, TestResult, channel_pair, exchange, introduce, payload, transfer,
    udp_pair, udp4,
};

/// Nodes of different transport types share one `Node` type, so the harness helpers that
/// link two nodes apply to every pair.
type Any = Box<dyn DynTransport>;

/// The id of every node's direct UDP transport.
const UDP: TransportId = TransportId::new(1);
/// The id of every node's relay transport.
const RELAY: TransportId = TransportId::new(2);
/// Datagrams each relay link queues.
const RELAY_CAPACITY: usize = 1024;

/// The relay address of the node with key seed `seed`.
fn relay_addr(seed: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, seed], 1000 + u16::from(seed)))
}

/// A relay link between the nodes with seeds `a` and `b`.
fn relay(a: u8, b: u8) -> (ChannelTransport, ChannelTransport) {
    ChannelTransport::pair(
        RELAY_CAPACITY,
        (RELAY, relay_addr(a)),
        (RELAY, relay_addr(b)),
    )
}

/// A UDP transport on the loopback interface with an OS-chosen port.
fn udp() -> io::Result<UdpTransport> {
    UdpTransport::bind(UDP, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
}

const fn at(transport: TransportId, addr: SocketAddr) -> Path {
    Path {
        transport,
        addr,
        ecn: Ecn::NotEct,
    }
}

/// A node on `udp` only.
fn udp_node(seed: u8, udp: UdpTransport) -> Node<Any> {
    let addr = udp.local_addr();
    Node::new(seed, UDP, addr, Box::new(udp), Options::default())
}

/// A node on its end of a relay link only.
fn relay_node(seed: u8, end: ChannelTransport) -> Node<Any> {
    Node::new(
        seed,
        RELAY,
        relay_addr(seed),
        Box::new(end),
        Options::default(),
    )
}

/// Makes `a` and `b` peers of each other: `a` reaches `b` on `a_to_b`, `b` reaches `a` on
/// `b_to_a`.
async fn link(a: &Node<Any>, a_to_b: Path, b: &Node<Any>, b_to_a: Path) -> TestResult {
    a.handle
        .add_or_update_peer(Peer {
            path: Some(a_to_b),
            ..b.as_peer(a_to_b.transport)
        })
        .await?;
    b.handle
        .add_or_update_peer(Peer {
            path: Some(b_to_a),
            ..a.as_peer(b_to_a.transport)
        })
        .await?;
    Ok(())
}

/// The current path of `peer` in `node`'s engine.
async fn path_of(node: &Node<Any>, peer: PeerId) -> TestResult<Option<Path>> {
    let stats = node.handle.peer_stats(peer).await?.ok_or("unknown peer")?;
    Ok(stats.path)
}

/// Sends a packet from `from` to `to` and checks that it is not delivered.
async fn expect_lost(from: &Node<Any>, to: &mut Node<Any>) -> TestResult {
    from.send(&from.packet_to(to, Family::V4, &payload(64)))
        .await?;
    to.expect_no_delivery().await
}

#[tokio::test]
async fn peers_use_their_own_transport() -> TestResult {
    let hub_udp = udp()?;
    let hub_addr = hub_udp.local_addr();
    let (hub_relay, y_relay) = relay(1, 3);
    let mut hub = Node::<Any>::with_builder(1, UDP, hub_addr, Options::default(), |b| {
        b.transport(hub_udp).transport(hub_relay)
    })?;
    let mut x = udp_node(2, udp()?);
    let mut y = relay_node(3, y_relay);
    link(&hub, x.path, &x, hub.path).await?;
    link(&hub, y.path, &y, at(RELAY, relay_addr(1))).await?;

    exchange(&mut hub, &mut x).await?;
    exchange(&mut hub, &mut y).await?;

    let (to_x, to_y) = (hub.peer_of(&x).await?, hub.peer_of(&y).await?);
    assert_eq!(path_of(&hub, to_x).await?, Some(x.path));
    assert_eq!(path_of(&hub, to_y).await?, Some(at(RELAY, relay_addr(3))));
    assert_eq!(hub.drops(DROP_NO_TRANSPORT).await?, 0);
    Ok(())
}

/// A hub (seed 1) and a peer `x` (seed 2) that both run UDP and a relay link between them,
/// peers of each other over UDP. The hub runs `policy` if given, `StandardRoaming` otherwise.
async fn reachable_twice(
    policy: Option<Box<dyn PathPolicy>>,
) -> TestResult<(Node<Any>, Node<Any>)> {
    let (hub_udp, x_udp) = (udp()?, udp()?);
    let (hub_addr, x_addr) = (hub_udp.local_addr(), x_udp.local_addr());
    let (hub_relay, x_relay) = relay(1, 2);
    let hub = Node::<Any>::with_builder(1, UDP, hub_addr, Options::default(), |b| {
        let b = b.transport(hub_udp).transport(hub_relay);
        match policy {
            Some(policy) => b.policy(policy),
            None => b,
        }
    })?;
    let x = Node::<Any>::with_builder(2, UDP, x_addr, Options::default(), |b| {
        b.transport(x_udp).transport(x_relay)
    })?;
    introduce(&hub, &x, None).await?;
    Ok((hub, x))
}

#[tokio::test]
async fn standard_roaming_moves_a_peer_to_the_other_transport() -> TestResult {
    let (mut hub, mut x) = reachable_twice(None).await?;
    exchange(&mut hub, &mut x).await?;
    let to_x = hub.peer_of(&x).await?;
    assert_eq!(path_of(&hub, to_x).await?, Some(x.path));
    let mut events = hub.subscribe().await?;

    // `x` switches to the relay; its authenticated traffic arrives on the hub's relay.
    x.handle
        .set_path(hub.public(), at(RELAY, relay_addr(1)))
        .await?;
    transfer(&x, &mut hub, Family::V4, 64).await?;
    let relayed = at(RELAY, relay_addr(2));
    events
        .expect(
            |e| matches!(e, Event::PathAdopted { peer, path } if *peer == to_x && *path == relayed),
        )
        .await?;
    assert_eq!(path_of(&hub, to_x).await?, Some(relayed));

    // Replies follow the new path.
    transfer(&hub, &mut x, Family::V6, 1300).await?;
    transfer(&x, &mut hub, Family::V4, 1300).await?;
    Ok(())
}

/// A policy that never moves a peer off its configured path.
#[derive(Debug)]
struct Pinned;

impl PathPolicy for Pinned {
    fn select(&self, _peer: PeerId, _kind: MessageKind) -> Option<Path> {
        None
    }

    fn on_authenticated(&self, _peer: PeerId, _from: &Path, _kind: MessageKind) -> Roam {
        Roam::Keep
    }
}

#[tokio::test]
async fn pinning_policy_keeps_the_path() -> TestResult {
    let (mut hub, mut x) = reachable_twice(Some(Box::new(Pinned))).await?;
    exchange(&mut hub, &mut x).await?;
    let to_x = hub.peer_of(&x).await?;
    let mut events = hub.subscribe().await?;

    // Traffic from `x` over the relay is accepted, but the hub keeps answering over UDP.
    x.handle
        .set_path(hub.public(), at(RELAY, relay_addr(1)))
        .await?;
    transfer(&x, &mut hub, Family::V4, 64).await?;
    events
        .expect_none(|e| matches!(e, Event::PathAdopted { .. }))
        .await?;
    assert_eq!(path_of(&hub, to_x).await?, Some(x.path));
    transfer(&hub, &mut x, Family::V4, 64).await?;
    transfer(&x, &mut hub, Family::V6, 1300).await?;
    assert_eq!(path_of(&hub, to_x).await?, Some(x.path));
    Ok(())
}

#[tokio::test]
async fn transports_change_at_runtime() -> TestResult {
    let hub_udp = udp()?;
    let hub_addr = hub_udp.local_addr();
    let mut hub = Node::<Any>::with_builder(1, UDP, hub_addr, Options::default(), |b| {
        b.transport(hub_udp)
    })?;
    let mut x = udp_node(2, udp()?);
    link(&hub, x.path, &x, hub.path).await?;
    exchange(&mut hub, &mut x).await?;

    // Add the relay and reach `y` over it.
    let (hub_relay, y_relay) = relay(1, 3);
    hub.handle.add_transport(hub_relay).await?;
    let mut y = relay_node(3, y_relay);
    link(&hub, y.path, &y, at(RELAY, relay_addr(1))).await?;
    exchange(&mut hub, &mut y).await?;
    let (twice, _end) = relay(1, 3);
    assert_eq!(
        hub.handle.add_transport(twice).await,
        Err(TransportError::Duplicate(RELAY))
    );

    // Replace the relay link on both ends; the sessions carry on over the new one.
    let (hub_relay, y_relay) = relay(1, 3);
    hub.handle.replace_transport(hub_relay).await?;
    y.handle.replace_transport(y_relay).await?;
    exchange(&mut hub, &mut y).await?;

    // Remove the relay: `y` is cut off and the datagrams are counted, `x` is not affected.
    hub.handle.remove_transport(RELAY).await?;
    let before = hub.drops(DROP_NO_TRANSPORT).await?;
    expect_lost(&hub, &mut y).await?;
    assert!(hub.drops(DROP_NO_TRANSPORT).await? > before);
    exchange(&mut hub, &mut x).await?;
    assert_eq!(
        hub.handle.remove_transport(RELAY).await,
        Err(TransportError::Unknown(RELAY))
    );
    let (unknown, _end) = relay(1, 3);
    assert_eq!(
        hub.handle.replace_transport(unknown).await,
        Err(TransportError::Unknown(RELAY))
    );

    // Adding it back reconnects `y`.
    let (hub_relay, y_relay) = relay(1, 3);
    hub.handle.add_transport(hub_relay).await?;
    y.handle.replace_transport(y_relay).await?;
    exchange(&mut hub, &mut y).await?;
    Ok(())
}

#[tokio::test]
async fn datagrams_to_a_missing_transport_are_counted() -> TestResult {
    let hub_udp = udp()?;
    let hub_addr = hub_udp.local_addr();
    let (hub_relay, _y_relay) = relay(1, 3);
    let mut hub = Node::<Any>::with_builder(1, UDP, hub_addr, Options::default(), |b| {
        b.transport(hub_udp).transport(hub_relay)
    })?;
    let mut x = udp_node(2, udp()?);
    link(&hub, x.path, &x, hub.path).await?;

    // `z` (seed 4) is only a key, configured on a transport the hub does not run.
    let z = PublicKey::from(&StaticSecret::from([4; 32]));
    let z_ip = Ipv4Addr::new(10, 0, 0, 4);
    let missing = TransportId::new(9);
    hub.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![AllowedIp {
                addr: IpAddr::V4(z_ip),
                cidr: 32,
            }],
            path: Some(at(missing, relay_addr(4))),
            ..Peer::new(z)
        })
        .await?;
    let mut events = hub.subscribe().await?;

    // The packet to `z` starts a handshake whose initiation has no transport.
    hub.send(&udp4(hub.ip4, z_ip, &payload(64))).await?;
    events
        .expect(|e| matches!(e, Event::Dropped { reason, .. } if *reason == DROP_NO_TRANSPORT))
        .await?;
    assert_eq!(hub.drops(DROP_NO_TRANSPORT).await?, 1);

    // Peers on installed transports are not affected.
    exchange(&mut hub, &mut x).await?;
    assert_eq!(hub.drops(DROP_NO_TRANSPORT).await?, 1);
    Ok(())
}

/// Packets per measured round and rounds per measurement.
const BURST: u32 = 64;
const ROUNDS: u32 = 100;

/// Packets per second from `a` to `b`: rounds of [`BURST`] 1300-byte packets, each round
/// sent at once and then received.
async fn throughput<T: Transport>(a: &Node<T>, b: &mut Node<T>) -> TestResult<f64> {
    // The handshake is not measured.
    transfer(a, b, Family::V4, 64).await?;
    let packet = a.packet_to(b, Family::V4, &payload(1300));
    let start = Instant::now();
    for _ in 0..ROUNDS {
        for _ in 0..BURST {
            a.send(&packet).await?;
        }
        for _ in 0..BURST {
            b.expect_delivery().await?;
        }
    }
    Ok(f64::from(BURST * ROUNDS) / start.elapsed().as_secs_f64())
}

/// Throughput over a channel link and over UDP on the loopback interface, for comparing the
/// engine's data path between revisions; run with `--ignored --nocapture`, preferably with
/// `--release`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement, not a check"]
async fn measure_throughput() -> TestResult {
    let (a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    let channel = throughput(&a, &mut b).await?;

    let (a, mut b) = udp_pair(IpAddr::V4(Ipv4Addr::LOCALHOST), Options::default())?;
    introduce(&a, &b, None).await?;
    let udp = throughput(&a, &mut b).await?;

    writeln!(
        io::stderr(),
        "throughput: channel {channel:.0} packets/s, udp {udp:.0} packets/s"
    )?;
    Ok(())
}
