//! The after-delivery hook of `MapSink::with_after` behind an engine: a reverse mapping is
//! retired only once the TUN-like sink took the packet over.
//!
//! Engine A receives packets from peer X over a `ChannelTransport`. A's sink is a
//! `MapSink::with_after` over a TUN-like `ChannelSink`: the closure redirects a virtual
//! destination to a real one and drops a blocked port, and the hook retires the delivered
//! packet's UDP flow from a shared table. Every packet the TUN side received is reported
//! exactly once and in order, dropped packets never are, and the packet a closed TUN side
//! fails on is not.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, DROP_SINK_CLOSED, Ecn, Engine,
    EngineBuilder, Event, MapSink, MapVerdict, PacketBuf, PacketSink, Path, Peer, PeerId,
    TransportId,
};
use nsplane_e2e::{Family, Node, Options, QUIET, TestResult, WAIT, udp};
use nsplane_packet::IpPacket;
use tokio::sync::broadcast;
use tokio::time::timeout;

/// Capacity of the channels and the link.
const CAPACITY: usize = 1024;
/// MTU of A's local side.
const MTU: u16 = 1420;
/// Key seeds of peer X and engine A.
const X_SEED: u8 = 1;
const A_SEED: u8 = 2;
/// The destination port of every packet but the blocked ones.
const PORT: u16 = 5000;
/// The destination port the closure drops.
const BLOCKED_PORT: u16 = 9;
/// Packets per burst.
const BURST: u16 = 32;

const X_PATH: (TransportId, SocketAddr) = (
    TransportId::new(1),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1000),
);
const A_PATH: (TransportId, SocketAddr) = (
    TransportId::new(2),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 2000),
);

/// X's tunnel address, the virtual destination X sends to and the real one the closure
/// redirects it to.
const fn addresses(family: Family) -> (IpAddr, IpAddr, IpAddr) {
    match family {
        Family::V4 => (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, X_SEED)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 4, 4)),
            IpAddr::V4(Ipv4Addr::new(10, 9, 0, 4)),
        ),
        Family::V6 => (
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 4, 0, 0, 0, 0, 0, 4)),
            IpAddr::V6(Ipv6Addr::new(0xfd09, 0, 0, 0, 0, 0, 0, 4)),
        ),
    }
}

/// A UDP flow: source and destination address and port.
type Flow = (SocketAddr, SocketAddr);

/// The UDP flow of `packet`, if it is a UDP packet.
fn flow(packet: &[u8]) -> Option<Flow> {
    let ip = IpPacket::parse(packet).ok()?;
    let ports = ip.payload().get(..4)?;
    Some((
        SocketAddr::new(ip.src(), u16::from_be_bytes([ports[0], ports[1]])),
        SocketAddr::new(ip.dst(), u16::from_be_bytes([ports[2], ports[3]])),
    ))
}

/// The closure: drops packets to [`BLOCKED_PORT`], redirects the virtual destination to the
/// real one (rebuilding the packet with valid checksums), keeps the rest untouched.
fn redirect(packet: &mut PacketBuf) -> MapVerdict {
    let Some((src, dst)) = flow(packet.as_packet()) else {
        return MapVerdict::Drop;
    };
    if dst.port() == BLOCKED_PORT {
        return MapVerdict::Drop;
    }
    for family in [Family::V4, Family::V6] {
        let (_, virt, real) = addresses(family);
        if dst.ip() == virt {
            let header = if family == Family::V4 { 20 } else { 40 };
            let payload = packet.as_packet()[header + 8..].to_vec();
            let rewritten = udp(src, SocketAddr::new(real, dst.port()), &payload);
            packet.as_packet_mut().copy_from_slice(&rewritten);
        }
    }
    MapVerdict::Keep
}

/// The reverse mappings the hook retires and what it was called with.
#[derive(Debug, Default)]
struct Table {
    /// Flows expected to be delivered, keyed as the TUN side sees them.
    open: HashSet<Flow>,
    /// Every packet the hook was called with, in order.
    retired: Vec<Vec<u8>>,
    /// Calls for a flow that was not open (unknown or retired twice).
    unknown: u64,
}

impl Table {
    fn retire(&mut self, packet: &[u8]) {
        if !flow(packet).is_some_and(|flow| self.open.remove(&flow)) {
            self.unknown += 1;
        }
        self.retired.push(packet.to_vec());
    }
}

/// A sink shared between an engine and the test, so the test reads the counters of a sink
/// the engine owns.
struct Shared<S>(Arc<S>);

impl<S: PacketSink> PacketSink for Shared<S> {
    async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
        self.0.send(packet, from).await
    }

    async fn send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        self.0.send_batch(packets).await
    }
}

fn public(seed: u8) -> PublicKey {
    PublicKey::from(&StaticSecret::from([seed; 32]))
}

/// Peer X and engine A on one link, introduced to each other; A delivers into `sink`.
async fn x_and_a(sink: impl PacketSink) -> TestResult<(Node<ChannelTransport>, Engine)> {
    let (link_x, link_a) = ChannelTransport::pair(CAPACITY, X_PATH, A_PATH);
    let x = Node::new(X_SEED, X_PATH.0, X_PATH.1, link_x, Options::default());
    let (source, _local, _mtu) = ChannelSource::new(CAPACITY, MTU);
    let a = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([A_SEED; 32]))
        .transport(link_a)
        .build()?;
    a.handle().add_or_update_peer(x.as_peer(A_PATH.0)).await?;
    x.handle
        .add_or_update_peer(Peer {
            allowed_ips: [
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ]
            .into_iter()
            .map(|addr| AllowedIp { addr, cidr: 0 })
            .collect(),
            path: Some(Path {
                transport: X_PATH.0,
                addr: A_PATH.1,
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(public(A_SEED))
        })
        .await?;
    Ok((x, a))
}

/// Waits for a drop counted under [`DROP_SINK_CLOSED`].
async fn sink_closed(events: &mut broadcast::Receiver<Event>) {
    loop {
        match events.recv().await {
            Ok(Event::Dropped { reason, .. }) if reason == DROP_SINK_CLOSED => return,
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return std::future::pending().await,
        }
    }
}

/// X -> A -> `MapSink::with_after` -> TUN side: the hook retires exactly the delivered
/// packets' flows, once each and in delivery order, for IPv4 and IPv6; once the TUN side is
/// closed, the packet the sink fails on is not reported.
#[tokio::test]
async fn after_retires_delivered_packets() -> TestResult {
    let table = Arc::new(Mutex::new(Table::default()));
    let mapped = Arc::new(AtomicU64::new(0));
    let (tun_sink, mut tun_out) = ChannelSink::new(CAPACITY);
    let sink = Arc::new(MapSink::with_after(
        tun_sink,
        {
            let mapped = Arc::clone(&mapped);
            move |packet: &mut PacketBuf, _from: PeerId| {
                mapped.fetch_add(1, Ordering::Relaxed);
                redirect(packet)
            }
        },
        {
            let table = Arc::clone(&table);
            move |packet: &[u8]| {
                table
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .retire(packet);
            }
        },
    ));
    let (x, a) = x_and_a(Shared(Arc::clone(&sink))).await?;
    let lock = || table.lock().unwrap_or_else(PoisonError::into_inner);

    let mut received = Vec::new();
    let mut blocked = 0;
    for family in [Family::V4, Family::V6] {
        let (x_ip, virt, real) = addresses(family);
        for i in 0..BURST {
            let src = SocketAddr::new(x_ip, 10_000 + i);
            let payload = format!("packet {i}");
            if i % 4 == 3 {
                // Dropped by the closure: never delivered, never reported.
                x.send(&udp(
                    src,
                    SocketAddr::new(virt, BLOCKED_PORT),
                    payload.as_bytes(),
                ))
                .await?;
                blocked += 1;
                continue;
            }
            // Every third packet goes to the real address directly, untouched.
            let dst = SocketAddr::new(if i % 3 == 0 { real } else { virt }, PORT);
            lock().open.insert((src, SocketAddr::new(real, PORT)));
            x.send(&udp(src, dst, payload.as_bytes())).await?;
            let expected = udp(src, SocketAddr::new(real, PORT), payload.as_bytes());
            let (_, delivered) = timeout(WAIT, tun_out.recv())
                .await?
                .ok_or("TUN side closed")?;
            assert_eq!(delivered.as_packet(), expected);
            received.push(expected);
        }
    }
    // The hook runs right after the TUN side took a batch: wait until the last blocked
    // packet was mapped and every delivery was reported.
    let total = 2 * u64::from(BURST);
    timeout(WAIT, async {
        while mapped.load(Ordering::Relaxed) < total || lock().retired.len() < received.len() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    {
        let table = lock();
        assert_eq!(
            table.retired, received,
            "reported in delivery order, once each"
        );
        assert_eq!(table.unknown, 0, "a flow reported twice or never opened");
        assert!(table.open.is_empty(), "unretired flows: {:?}", table.open);
    }
    assert_eq!(sink.dropped(), blocked);
    assert!(
        tun_out.try_recv().is_err(),
        "unexpected packet on the TUN side"
    );

    // The TUN side closes: the packet the sink fails on (BrokenPipe) is not reported, and
    // its flow stays open.
    let mut events = a.handle().subscribe().await?;
    drop(tun_out);
    let (x_ip, _, real) = addresses(Family::V4);
    let before = mapped.load(Ordering::Relaxed);
    let mut closed = false;
    for i in 0..10 {
        let src = SocketAddr::new(x_ip, 20_000 + i);
        let dst = SocketAddr::new(real, PORT);
        lock().open.insert((src, dst));
        x.send(&udp(src, dst, b"lost")).await?;
        if timeout(QUIET, sink_closed(&mut events)).await.is_ok() {
            closed = true;
            break;
        }
    }
    assert!(closed, "no delivery dropped under {DROP_SINK_CLOSED}");
    assert!(
        mapped.load(Ordering::Relaxed) > before,
        "the sink never got a packet after the TUN side closed"
    );
    let table = lock();
    assert_eq!(table.retired, received, "a failed delivery was reported");
    assert!(!table.open.is_empty());
    Ok(())
}
