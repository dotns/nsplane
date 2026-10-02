//! Driver tests: engines on in-memory sources, sinks and transports.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, DROP_NO_TRANSPORT, DROP_SINK_FULL,
    DROP_TRANSMIT_FULL, Ecn, Engine, EngineBuilder, EngineError, EngineHandle, Event, PacketBuf,
    Path, Peer, PeerId, Transport, TransportId,
};
use nsplane_core::noise::{Tunn, TunnResult};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::{Instant, sleep, timeout};

/// Upper bound for anything that is expected to happen.
const WAIT: Duration = Duration::from_secs(5);
/// How long to watch for something that is expected not to happen.
const QUIET: Duration = Duration::from_millis(300);

const IP_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const IP_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn addr_a() -> SocketAddr {
    "192.0.2.1:1000".parse().unwrap()
}

fn addr_b() -> SocketAddr {
    "192.0.2.2:2000".parse().unwrap()
}

/// An IPv4 packet with a correct header checksum and an experimental protocol number.
fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + payload.len()).unwrap();
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0x40, 0, 64, 253, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let mut sum: u32 = packet
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn secret(seed: u8) -> StaticSecret {
    StaticSecret::from([seed; 32])
}

fn link(capacity: usize) -> (ChannelTransport, ChannelTransport) {
    ChannelTransport::pair(
        capacity,
        (TransportId::new(1), addr_a()),
        (TransportId::new(2), addr_b()),
    )
}

/// One engine with the test ends of its source and sink.
struct Node<T: Transport> {
    engine: Engine<T>,
    handle: EngineHandle<T>,
    local: mpsc::Sender<PacketBuf>,
    delivered: mpsc::Receiver<(PeerId, PacketBuf)>,
    _mtu: watch::Sender<u16>,
    secret: StaticSecret,
    ip: Ipv4Addr,
    addr: SocketAddr,
    transport: TransportId,
}

impl<T: Transport> Node<T> {
    fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// The description of this node as a peer of a node that reaches it on `via`.
    fn as_peer(&self, via: TransportId) -> Peer {
        Peer {
            allowed_ips: vec![AllowedIp {
                addr: IpAddr::V4(self.ip),
                cidr: 32,
            }],
            path: Some(Path {
                transport: via,
                addr: self.addr,
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(self.public())
        }
    }

    async fn send(&self, dst: Ipv4Addr, payload: &[u8]) {
        let packet = PacketBuf::from_packet(&ipv4(self.ip, dst, payload));
        self.local.send(packet).await.unwrap();
    }

    async fn expect_delivery(&mut self) -> (PeerId, Vec<u8>) {
        let (peer, packet) = timeout(WAIT, self.delivered.recv())
            .await
            .expect("no delivery")
            .expect("sink closed");
        (peer, packet.as_packet().to_vec())
    }

    async fn expect_no_delivery(&mut self) {
        assert!(timeout(QUIET, self.delivered.recv()).await.is_err());
    }

    async fn peer_of(&self, other: &Self) -> PeerId {
        self.handle
            .peer_id(other.public())
            .await
            .unwrap()
            .expect("unknown peer")
    }

    async fn drops(&self, reason: &str) -> u64 {
        let counters = self.handle.drop_counters().await.unwrap();
        counters.get(reason).copied().unwrap_or(0)
    }
}

struct Options {
    queue_capacity: usize,
    sink_capacity: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            sink_capacity: 64,
        }
    }
}

fn node<T: Transport>(
    seed: u8,
    ip: Ipv4Addr,
    addr: SocketAddr,
    transport_id: TransportId,
    transport: T,
    options: &Options,
) -> Node<T> {
    let (source, local, mtu) = ChannelSource::new(4, 1420);
    let (sink, delivered) = ChannelSink::new(options.sink_capacity);
    let engine = EngineBuilder::new(source, sink)
        .transport(transport)
        .private_key(secret(seed))
        .queue_capacity(options.queue_capacity)
        .build();
    Node {
        handle: engine.handle(),
        engine,
        local,
        delivered,
        _mtu: mtu,
        secret: secret(seed),
        ip,
        addr,
        transport: transport_id,
    }
}

/// Two engines linked by `a` and `b`, not yet peers of each other.
fn nodes<T: Transport>(a: T, b: T, options: &Options) -> (Node<T>, Node<T>) {
    (
        node(1, IP_A, addr_a(), TransportId::new(1), a, options),
        node(2, IP_B, addr_b(), TransportId::new(2), b, options),
    )
}

/// Makes `a` and `b` peers of each other.
async fn introduce<T: Transport>(a: &Node<T>, b: &Node<T>) {
    a.handle
        .add_or_update_peer(b.as_peer(a.transport))
        .await
        .unwrap();
    b.handle
        .add_or_update_peer(a.as_peer(b.transport))
        .await
        .unwrap();
}

/// Two linked engines that are peers of each other.
async fn peered() -> (Node<ChannelTransport>, Node<ChannelTransport>) {
    let (ta, tb) = link(64);
    let (a, b) = nodes(ta, tb, &Options::default());
    introduce(&a, &b).await;
    (a, b)
}

/// Waits for the first event matching `matches`.
async fn expect_event(
    events: &mut broadcast::Receiver<Event>,
    matches: impl Fn(&Event) -> bool + Send + Sync,
) -> Event {
    timeout(WAIT, async {
        loop {
            match events.recv().await {
                Ok(event) if matches(&event) => return event,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => panic!("events closed"),
            }
        }
    })
    .await
    .expect("event not observed")
}

const fn is_handshake(event: &Event) -> bool {
    matches!(event, Event::HandshakeCompleted { .. })
}

/// Waits until `condition` holds, polling it.
async fn eventually<F: Future<Output = bool>>(mut condition: impl FnMut() -> F) {
    let deadline = Instant::now() + WAIT;
    while !condition().await {
        assert!(Instant::now() < deadline, "condition not reached");
        sleep(Duration::from_millis(20)).await;
    }
}

/// Sends a packet each way and checks both arrive.
async fn exchange<T: Transport>(a: &mut Node<T>, b: &mut Node<T>) {
    a.send(IP_B, b"ping").await;
    let (from, packet) = b.expect_delivery().await;
    assert_eq!(from, b.peer_of(a).await);
    assert_eq!(packet, ipv4(IP_A, IP_B, b"ping"));

    b.send(IP_A, b"pong").await;
    let (from, packet) = a.expect_delivery().await;
    assert_eq!(from, a.peer_of(b).await);
    assert_eq!(packet, ipv4(IP_B, IP_A, b"pong"));
}

#[tokio::test]
async fn engines_handshake_and_exchange_packets() {
    let (mut a, mut b) = peered().await;
    let mut events = a.handle.subscribe().await.unwrap();

    a.send(IP_B, b"first").await;
    expect_event(&mut events, is_handshake).await;
    let (_, packet) = b.expect_delivery().await;
    assert_eq!(packet, ipv4(IP_A, IP_B, b"first"));

    exchange(&mut a, &mut b).await;
}

#[tokio::test]
async fn peers_are_added_and_removed() {
    let (mut a, mut b) = peered().await;
    let peers = a.handle.peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].public_key, b.public());
    assert_eq!(peers[0].allowed_ips, b.as_peer(a.transport).allowed_ips);
    exchange(&mut a, &mut b).await;

    a.handle.remove_peer(b.public()).await.unwrap();
    assert_eq!(a.handle.peers().await.unwrap().len(), 0);
    a.send(IP_B, b"lost").await;
    b.expect_no_delivery().await;
    assert_eq!(a.drops("no route").await, 1);

    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;
    a.handle.remove_all_peers().await.unwrap();
    assert_eq!(a.handle.peers().await.unwrap().len(), 0);
    a.send(IP_B, b"lost").await;
    b.expect_no_delivery().await;
    assert_eq!(a.drops("no route").await, 2);
}

#[tokio::test]
async fn allowed_ips_are_replaced() {
    let (a, b) = peered().await;
    let other = AllowedIp {
        addr: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
        cidr: 16,
    };
    a.handle
        .set_allowed_ips(b.public(), vec![other])
        .await
        .unwrap();
    let peers = a.handle.peers().await.unwrap();
    assert_eq!(peers[0].allowed_ips, vec![other]);

    a.send(IP_B, b"lost").await;
    eventually(|| async { a.drops("no route").await == 1 }).await;
}

#[tokio::test]
async fn preshared_keys_must_match() {
    let (a, b) = peered().await;
    let mut events = a.handle.subscribe().await.unwrap();
    let to_b = a.peer_of(&b).await;

    a.handle
        .set_preshared_key(b.public(), Some([1; 32]))
        .await
        .unwrap();
    b.handle
        .set_preshared_key(a.public(), Some([2; 32]))
        .await
        .unwrap();
    a.handle.force_handshake(to_b, None).await.unwrap();
    let rejected = expect_event(&mut events, |e| {
        matches!(e, Event::Dropped { reason, .. } if *reason == "handshake rejected")
            || is_handshake(e)
    })
    .await;
    assert!(
        !is_handshake(&rejected),
        "handshake completed: {rejected:?}"
    );

    b.handle
        .set_preshared_key(a.public(), Some([1; 32]))
        .await
        .unwrap();
    let stats = b.handle.peers().await.unwrap();
    assert_eq!(stats[0].preshared_key, Some([1; 32]));
    // `b` initiates: a second initiation from `a` would carry the same timestamp when the
    // tunnels run on the frozen mock clock (`--all-features`), and `b` would reject it as a
    // replay.
    let mut events = b.handle.subscribe().await.unwrap();
    let to_a = b.peer_of(&a).await;
    b.handle.force_handshake(to_a, None).await.unwrap();
    expect_event(&mut events, is_handshake).await;
}

#[tokio::test]
async fn keepalives_are_sent() {
    let (ta, tb) = link(64);
    let (ta, _gate) = Tapped::new(ta);
    let (tb, _gate_b) = Tapped::new(tb);
    let keepalives = Arc::clone(&ta.keepalives);
    let (mut a, mut b) = nodes(ta, tb, &Options::default());
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;
    let to_b = a.peer_of(&b).await;

    let before = keepalives.load(Ordering::Relaxed);
    a.handle.set_keepalive(b.public(), Some(1)).await.unwrap();
    let stats = a.handle.peer_stats(to_b).await.unwrap().unwrap();
    assert_eq!(stats.persistent_keepalive, Some(1));
    // Enabling the keepalive sends one right away; later ones need the tunnel clock to move,
    // which is frozen under the mock clock (`--all-features`).
    eventually(|| async { keepalives.load(Ordering::Relaxed) > before }).await;
    // Keepalives carry no packet.
    a.expect_no_delivery().await;
    b.expect_no_delivery().await;
}

#[tokio::test]
async fn peer_stats_count_traffic() {
    let (mut a, mut b) = peered().await;
    let to_b = a.peer_of(&b).await;
    let before = a.handle.peer_stats(to_b).await.unwrap().unwrap();
    assert_eq!((before.rx, before.tx, before.data_rx), (0, 0, 0));
    assert_eq!(before.last_handshake, None);

    exchange(&mut a, &mut b).await;
    let after = a.handle.peer_stats(to_b).await.unwrap().unwrap();
    assert!(after.rx > 0 && after.tx > 0);
    assert_eq!(
        after.data_rx,
        u64::try_from(ipv4(IP_B, IP_A, b"pong").len()).unwrap()
    );
    assert!(after.last_handshake.is_some());
    assert_eq!(a.handle.peer_stats(PeerId::new(999)).await.unwrap(), None);
}

#[tokio::test]
async fn injected_packets_are_delivered_and_sent() {
    let (mut a, mut b) = peered().await;
    let to_b = a.peer_of(&b).await;

    let inbound = ipv4(IP_B, IP_A, b"injected inbound");
    a.handle
        .inject_inbound(to_b, PacketBuf::from_packet(&inbound))
        .await
        .unwrap();
    assert_eq!(a.expect_delivery().await, (to_b, inbound));
    b.expect_no_delivery().await;

    let outbound = ipv4(IP_A, IP_B, b"injected outbound");
    a.handle
        .inject_outbound(PacketBuf::from_packet(&outbound))
        .await
        .unwrap();
    let (from, packet) = b.expect_delivery().await;
    assert_eq!(from, b.peer_of(&a).await);
    assert_eq!(packet, outbound);
}

#[tokio::test]
async fn forced_handshake_completes() {
    let (a, b) = peered().await;
    let mut events = a.handle.subscribe().await.unwrap();
    let to_b = a.peer_of(&b).await;
    let path = Path {
        transport: a.transport,
        addr: b.addr,
        ecn: Ecn::NotEct,
    };
    a.handle.force_handshake(to_b, Some(path)).await.unwrap();
    match expect_event(&mut events, is_handshake).await {
        Event::HandshakeCompleted { peer, .. } => assert_eq!(peer, to_b),
        event => panic!("unexpected {event:?}"),
    }
}

#[tokio::test]
async fn replaced_transport_keeps_traffic_flowing() {
    let (mut a, mut b) = peered().await;
    exchange(&mut a, &mut b).await;

    let (ta, tb) = link(64);
    a.handle.set_transport(ta).await.unwrap();
    b.handle.set_transport(tb).await.unwrap();
    exchange(&mut a, &mut b).await;
}

#[tokio::test]
async fn keys_are_reported() {
    let (a, _b) = peered().await;
    let key = a.handle.private_key().await.unwrap().unwrap();
    assert_eq!(key.to_bytes(), a.secret.to_bytes());
    assert_eq!(a.handle.public_key().await.unwrap(), Some(a.public()));

    a.handle.set_private_key(secret(9)).await.unwrap();
    let key = a.handle.private_key().await.unwrap().unwrap();
    assert_eq!(key.to_bytes(), secret(9).to_bytes());
    assert_eq!(
        a.handle.public_key().await.unwrap(),
        Some(PublicKey::from(&secret(9)))
    );
}

#[tokio::test]
async fn path_is_set() {
    let (a, b) = peered().await;
    let path = Path {
        transport: TransportId::new(7),
        addr: "198.51.100.1:51820".parse().unwrap(),
        ecn: Ecn::NotEct,
    };
    a.handle.set_path(b.public(), path).await.unwrap();
    assert_eq!(a.handle.peers().await.unwrap()[0].path, Some(path));
}

#[tokio::test]
async fn full_sink_drops_with_a_counted_reason() {
    let (ta, tb) = link(64);
    let options = Options {
        queue_capacity: 1,
        sink_capacity: 1,
    };
    let (mut a, b) = nodes(ta, tb, &options);
    introduce(&a, &b).await;
    let to_b = a.peer_of(&b).await;
    let mut events = a.handle.subscribe().await.unwrap();

    // Nothing reads the sink: one packet sits in the sink, one in its task, one in the queue.
    for i in 0..10u8 {
        let packet = PacketBuf::from_packet(&ipv4(IP_B, IP_A, &[i]));
        a.handle.inject_inbound(to_b, packet).await.unwrap();
    }
    expect_event(
        &mut events,
        |e| matches!(e, Event::Dropped { reason, .. } if *reason == DROP_SINK_FULL),
    )
    .await;
    let dropped = a.drops(DROP_SINK_FULL).await;
    assert!((7..=9).contains(&dropped), "dropped {dropped}");

    // The engine is still alive and delivers again once the sink drains.
    assert_eq!(a.handle.peers().await.unwrap().len(), 1);
    while timeout(QUIET, a.delivered.recv()).await.is_ok() {}
    let packet = ipv4(IP_B, IP_A, b"after");
    a.handle
        .inject_inbound(to_b, PacketBuf::from_packet(&packet))
        .await
        .unwrap();
    assert_eq!(a.expect_delivery().await.1, packet);
}

/// Size of a WireGuard keepalive: the data header and the AEAD tag.
const KEEPALIVE_SZ: usize = 32;

/// A transport that counts the keepalives it sends and whose sends wait while its gate is
/// closed.
struct Tapped {
    inner: Arc<ChannelTransport>,
    open: watch::Receiver<bool>,
    keepalives: Arc<AtomicUsize>,
}

impl Tapped {
    /// Wraps `inner` with an open gate; returns the gate.
    fn new(inner: ChannelTransport) -> (Self, watch::Sender<bool>) {
        let (gate, open) = watch::channel(true);
        let tapped = Self {
            inner: Arc::new(inner),
            open,
            keepalives: Arc::default(),
        };
        (tapped, gate)
    }
}

impl Transport for Tapped {
    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        self.inner.recv(buf).await
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        let mut open = self.open.clone();
        open.wait_for(|open| *open)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        if datagram.len() == KEEPALIVE_SZ {
            self.keepalives.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.send(datagram, to).await
    }
}

#[tokio::test]
async fn full_transmit_queue_holds_back_the_source() {
    let (ta, tb) = link(64);
    let (ta, gate) = Tapped::new(ta);
    let (tb, _gate_b) = Tapped::new(tb);
    let options = Options {
        queue_capacity: 2,
        sink_capacity: 64,
    };
    let (mut a, mut b) = nodes(ta, tb, &options);
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;

    gate.send(false).unwrap();
    let local = a.local.clone();
    let sender = tokio::spawn(async move {
        for i in 0..20u8 {
            let packet = PacketBuf::from_packet(&ipv4(IP_A, IP_B, &[i]));
            local.send(packet).await.unwrap();
        }
    });
    sleep(QUIET).await;
    assert!(!sender.is_finished(), "the source was not held back");

    gate.send(true).unwrap();
    timeout(WAIT, sender).await.unwrap().unwrap();
    for i in 0..20u8 {
        assert_eq!(b.expect_delivery().await.1, ipv4(IP_A, IP_B, &[i]));
    }
    assert!(a.handle.drop_counters().await.unwrap().is_empty());
}

/// A handshake initiation from `initiator` to `responder`.
fn initiation(initiator: StaticSecret, responder: PublicKey) -> Vec<u8> {
    let mut tunn = Tunn::new(initiator, responder, None, None, 0, None);
    let mut buf = [0; 148];
    match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(data) => data.to_vec(),
        _ => panic!("no initiation"),
    }
}

#[tokio::test]
async fn transmit_backlog_is_bounded() {
    const FLOOD: u8 = 20;
    let (ta, tb) = link(64);
    let (ta, gate) = Tapped::new(ta);
    let (tb, _gate_b) = Tapped::new(tb);
    // The test sends on `b`'s link end too.
    let tb_end = Arc::clone(&tb.inner);
    let options = Options {
        queue_capacity: 2,
        sink_capacity: 64,
    };
    let (mut a, mut b) = nodes(ta, tb, &options);
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;
    for seed in 0..FLOOD {
        let peer = Peer::new(PublicKey::from(&secret(100 + seed)));
        a.handle.add_or_update_peer(peer).await.unwrap();
    }
    let mut events = a.handle.subscribe().await.unwrap();

    // `a` answers every initiation, but nothing leaves it any more: one response waits in
    // the transmit task, two in the transmit queue and two in the owner; the rest are
    // dropped.
    gate.send(false).unwrap();
    let to_a = Path {
        transport: b.transport,
        addr: a.addr,
        ecn: Ecn::NotEct,
    };
    for seed in 0..FLOOD {
        let datagram = initiation(secret(100 + seed), a.public());
        tb_end.send(&datagram, &to_a).await.unwrap();
    }
    let dropped = expect_event(
        &mut events,
        |e| matches!(e, Event::Dropped { reason, .. } if *reason == DROP_TRANSMIT_FULL),
    )
    .await;
    assert!(matches!(dropped, Event::Dropped { peer: None, .. }));
    eventually(|| async { a.drops(DROP_TRANSMIT_FULL).await >= u64::from(FLOOD) - 5 }).await;
    assert_eq!(
        a.handle.peers().await.unwrap().len(),
        usize::from(FLOOD) + 1
    );

    // Local packets are held back behind the waiting responses, not dropped.
    let local = a.local.clone();
    let sender = tokio::spawn(async move {
        for i in 0..20u8 {
            let packet = PacketBuf::from_packet(&ipv4(IP_A, IP_B, &[i]));
            local.send(packet).await.unwrap();
        }
    });
    sleep(QUIET).await;
    assert!(!sender.is_finished(), "the source was not held back");

    gate.send(true).unwrap();
    timeout(WAIT, sender).await.unwrap().unwrap();
    for i in 0..20u8 {
        assert_eq!(b.expect_delivery().await.1, ipv4(IP_A, IP_B, &[i]));
    }
    let counters = a.handle.drop_counters().await.unwrap();
    assert_eq!(
        counters.keys().copied().collect::<Vec<_>>(),
        [DROP_TRANSMIT_FULL]
    );
}

#[tokio::test]
async fn missing_transport_drops_with_a_counted_reason() {
    let (source, local, _mtu) = ChannelSource::new(4, 1420);
    let (sink, _delivered) = ChannelSink::new(4);
    let engine = EngineBuilder::new(source, sink)
        .private_key(secret(1))
        .build();
    let handle = engine.handle();
    let peer = Peer {
        allowed_ips: vec![AllowedIp {
            addr: IpAddr::V4(IP_B),
            cidr: 32,
        }],
        path: Some(Path {
            transport: TransportId::new(1),
            addr: addr_b(),
            ecn: Ecn::NotEct,
        }),
        ..Peer::new(PublicKey::from(&secret(2)))
    };
    handle.add_or_update_peer(peer).await.unwrap();
    let to_b = handle
        .peer_id(PublicKey::from(&secret(2)))
        .await
        .unwrap()
        .unwrap();
    handle.force_handshake(to_b, None).await.unwrap();
    let counters = handle.drop_counters().await.unwrap();
    assert_eq!(counters.get(DROP_NO_TRANSPORT), Some(&1));
    drop(local);
    handle.shutdown().await.unwrap();
    timeout(WAIT, engine.wait()).await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_is_clean() {
    let (mut a, mut b) = peered().await;
    exchange(&mut a, &mut b).await;
    let mut events = a.handle.subscribe().await.unwrap();

    a.handle.shutdown().await.unwrap();
    timeout(WAIT, a.engine.wait()).await.unwrap().unwrap();

    assert_eq!(a.handle.peers().await.unwrap_err(), EngineError);
    assert_eq!(a.handle.shutdown().await.unwrap_err(), EngineError);
    let closed = timeout(WAIT, async {
        loop {
            if let Err(e) = events.recv().await {
                return e;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(closed, broadcast::error::RecvError::Closed);
    assert_eq!(EngineError.to_string(), "the engine has stopped");
    // The other engine keeps running.
    assert_eq!(b.handle.peers().await.unwrap().len(), 1);
}
