//! Driver tests: engines on in-memory sources, sinks and transports.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness"
)]

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, BuildError, ChannelSink, ChannelSource, ChannelTransport, DROP_NO_TRANSPORT,
    DROP_SINK_FULL, DROP_TRANSMIT_FULL, DROP_TRANSPORT_REMOVED, DROP_TRANSPORT_SEND_ERROR, Ecn,
    Engine, EngineBuilder, EngineError, EngineHandle, Event, PacketBuf, PacketSource, Path, Peer,
    PeerId, Transport, TransportError, TransportId,
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
struct Node {
    engine: Engine,
    handle: EngineHandle,
    local: mpsc::Sender<PacketBuf>,
    delivered: mpsc::Receiver<(PeerId, PacketBuf)>,
    _mtu: watch::Sender<u16>,
    secret: StaticSecret,
    ip: Ipv4Addr,
    addr: SocketAddr,
    transport: TransportId,
}

impl Node {
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
    crypto_workers: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            sink_capacity: 64,
            crypto_workers: 0,
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
) -> Node {
    node_with(seed, ip, addr, transport_id, transport, options, |source| {
        source
    })
}

/// A node whose channel source is wrapped by `wrap`.
fn node_with<T: Transport, Src: PacketSource>(
    seed: u8,
    ip: Ipv4Addr,
    addr: SocketAddr,
    transport_id: TransportId,
    transport: T,
    options: &Options,
    wrap: impl FnOnce(ChannelSource) -> Src,
) -> Node {
    let (source, local, mtu) = ChannelSource::new(4, 1420);
    let (sink, delivered) = ChannelSink::new(options.sink_capacity);
    let engine = EngineBuilder::new(wrap(source), sink)
        .transport(transport)
        .private_key(secret(seed))
        .queue_capacity(options.queue_capacity)
        .crypto_workers(options.crypto_workers)
        .build()
        .unwrap();
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
fn nodes<T: Transport>(a: T, b: T, options: &Options) -> (Node, Node) {
    (
        node(1, IP_A, addr_a(), TransportId::new(1), a, options),
        node(2, IP_B, addr_b(), TransportId::new(2), b, options),
    )
}

/// Makes `a` and `b` peers of each other.
async fn introduce(a: &Node, b: &Node) {
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
async fn peered() -> (Node, Node) {
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
async fn exchange(a: &mut Node, b: &mut Node) {
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
    a.handle.replace_transport(ta).await.unwrap();
    b.handle.replace_transport(tb).await.unwrap();
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
        ..Options::default()
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
    fn id(&self) -> TransportId {
        self.inner.id()
    }

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
        ..Options::default()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_transmit_queue_holds_back_the_source_with_crypto_workers() {
    const PACKETS: usize = 2000;
    let (ta, tb) = link(PACKETS);
    let (ta, gate) = Tapped::new(ta);
    let (tb, _gate_b) = Tapped::new(tb);
    let options = Options {
        queue_capacity: 256,
        sink_capacity: PACKETS,
        crypto_workers: 2,
    };
    let (mut a, mut b) = nodes(ta, tb, &options);
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;

    // The local packets with the workers count against the room for local packets, so
    // none is dropped, neither while the transport is stalled nor while it drains.
    gate.send(false).unwrap();
    let local = a.local.clone();
    let sender = tokio::spawn(async move {
        for i in 0..PACKETS {
            let packet = PacketBuf::from_packet(&numbered(i));
            local.send(packet).await.unwrap();
        }
    });
    sleep(QUIET).await;
    assert!(!sender.is_finished(), "the source was not held back");
    assert!(a.handle.drop_counters().await.unwrap().is_empty());

    gate.send(true).unwrap();
    timeout(WAIT, sender).await.unwrap().unwrap();
    for i in 0..PACKETS {
        assert_eq!(b.expect_delivery().await.1, numbered(i));
    }
    assert!(a.handle.drop_counters().await.unwrap().is_empty());
}

/// A transport whose sends fail, as for a datagram too large for the path, once `failing`
/// is set.
struct Failing {
    inner: ChannelTransport,
    failing: Arc<AtomicBool>,
}

impl Transport for Failing {
    fn id(&self) -> TransportId {
        self.inner.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        self.inner.recv(buf).await
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        if self.failing.load(Ordering::Relaxed) {
            return Err(io::Error::other("message too long"));
        }
        self.inner.send(datagram, to).await
    }
}

#[tokio::test]
async fn failed_sends_drop_with_a_counted_reason() {
    const SENT: u8 = 5;
    let (ta, tb) = link(64);
    let failing = Arc::new(AtomicBool::new(false));
    let ta = Failing {
        inner: ta,
        failing: Arc::clone(&failing),
    };
    let tb = Failing {
        inner: tb,
        failing: Arc::default(),
    };
    let (mut a, mut b) = nodes(ta, tb, &Options::default());
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;
    let mut events = a.handle.subscribe().await.unwrap();

    failing.store(true, Ordering::Relaxed);
    for i in 0..SENT {
        a.send(IP_B, &[i]).await;
    }
    let dropped = expect_event(
        &mut events,
        |e| matches!(e, Event::Dropped { reason, .. } if *reason == DROP_TRANSPORT_SEND_ERROR),
    )
    .await;
    assert!(matches!(dropped, Event::Dropped { peer: None, .. }));
    eventually(|| async { a.drops(DROP_TRANSPORT_SEND_ERROR).await == u64::from(SENT) }).await;
    b.expect_no_delivery().await;
    assert_eq!(
        a.handle.drop_counters().await.unwrap().len(),
        1,
        "only failed sends are dropped"
    );

    // The transmit task keeps going.
    failing.store(false, Ordering::Relaxed);
    exchange(&mut a, &mut b).await;
    assert_eq!(a.drops(DROP_TRANSPORT_SEND_ERROR).await, u64::from(SENT));
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
        ..Options::default()
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
    // The engine runs transport 3 only; the peer's path names transport 1.
    let (other, _end) = ChannelTransport::pair(
        4,
        (TransportId::new(3), addr_a()),
        (TransportId::new(4), addr_b()),
    );
    let engine = EngineBuilder::new(source, sink)
        .transport(other)
        .private_key(secret(1))
        .build()
        .unwrap();
    let handle = engine.handle();
    let mut events = handle.subscribe().await.unwrap();
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
    let dropped = expect_event(
        &mut events,
        |e| matches!(e, Event::Dropped { reason, .. } if *reason == DROP_NO_TRANSPORT),
    )
    .await;
    assert!(matches!(dropped, Event::Dropped { peer: None, .. }));
    drop(local);
    handle.shutdown().await.unwrap();
    timeout(WAIT, engine.wait()).await.unwrap().unwrap();
}

#[tokio::test]
async fn build_needs_unique_transports() {
    let builder = || {
        let (source, _local, _mtu) = ChannelSource::new(4, 1420);
        let (sink, _delivered) = ChannelSink::new(4);
        EngineBuilder::new(source, sink)
    };
    assert_eq!(builder().build().unwrap_err(), BuildError::NoTransport);

    let (ta, tb) = link(4);
    let (same, _end) = link(4);
    let err = builder()
        .transport(ta)
        .transport(tb)
        .transport(same)
        .build()
        .unwrap_err();
    assert_eq!(err, BuildError::DuplicateTransport(TransportId::new(1)));
    assert_eq!(err.to_string(), "transport 1 was added more than once");
    assert_eq!(
        BuildError::NoTransport.to_string(),
        "the engine has no transport"
    );

    // Distinct ids of different types build.
    let (ta, _tb) = link(4);
    let (tapped, _gate) = Tapped::new(
        ChannelTransport::pair(
            4,
            (TransportId::new(3), addr_a()),
            (TransportId::new(4), addr_b()),
        )
        .0,
    );
    let engine = builder().transport(ta).transport(tapped).build().unwrap();
    engine.handle().shutdown().await.unwrap();
}

/// The second link of `a` and `b`: transport 3 on `a`, 4 on `b`, at new addresses.
fn second_link() -> (ChannelTransport, ChannelTransport) {
    ChannelTransport::pair(
        64,
        (TransportId::new(3), "192.0.2.11:1000".parse().unwrap()),
        (TransportId::new(4), "192.0.2.12:2000".parse().unwrap()),
    )
}

#[tokio::test]
async fn transports_are_added_removed_and_replaced() {
    let (mut a, mut b) = peered().await;
    exchange(&mut a, &mut b).await;
    let to_b = a.peer_of(&b).await;

    // A second link: both ends move their peer to it and traffic follows.
    let (ta, tb) = second_link();
    a.handle.add_transport(ta).await.unwrap();
    b.handle.add_transport(tb).await.unwrap();
    let (dup, _end) = second_link();
    assert_eq!(
        a.handle.add_transport(dup).await,
        Err(TransportError::Duplicate(TransportId::new(3)))
    );
    let path = Path {
        transport: TransportId::new(3),
        addr: "192.0.2.12:2000".parse().unwrap(),
        ecn: Ecn::NotEct,
    };
    a.handle.set_path(b.public(), path).await.unwrap();
    b.handle
        .set_path(
            a.public(),
            Path {
                transport: TransportId::new(4),
                addr: "192.0.2.11:1000".parse().unwrap(),
                ecn: Ecn::NotEct,
            },
        )
        .await
        .unwrap();
    // The first link is gone; only the second can carry the exchange.
    a.handle
        .remove_transport(TransportId::new(1))
        .await
        .unwrap();
    exchange(&mut a, &mut b).await;
    assert_eq!(
        a.handle.peer_stats(to_b).await.unwrap().unwrap().path,
        Some(path)
    );

    let (ta, tb) = second_link();
    a.handle.replace_transport(ta).await.unwrap();
    b.handle.replace_transport(tb).await.unwrap();
    exchange(&mut a, &mut b).await;

    assert_eq!(
        a.handle.remove_transport(TransportId::new(1)).await,
        Err(TransportError::Unknown(TransportId::new(1)))
    );
    let (unknown, _end) = link(4);
    assert_eq!(
        a.handle.replace_transport(unknown).await,
        Err(TransportError::Unknown(TransportId::new(1)))
    );
    assert_eq!(
        TransportError::Unknown(TransportId::new(1)).to_string(),
        "transport 1 is not installed"
    );
    assert_eq!(
        TransportError::Duplicate(TransportId::new(3)).to_string(),
        "transport 3 is already installed"
    );

    // Without a transport for the path, datagrams are dropped.
    a.handle
        .remove_transport(TransportId::new(3))
        .await
        .unwrap();
    a.send(IP_B, b"lost").await;
    b.expect_no_delivery().await;
    assert!(a.drops(DROP_NO_TRANSPORT).await >= 1);

    a.handle.shutdown().await.unwrap();
    let (late, _end) = second_link();
    assert_eq!(
        a.handle.add_transport(late).await,
        Err(TransportError::Stopped)
    );
    assert_eq!(
        a.handle.remove_transport(TransportId::new(3)).await,
        Err(TransportError::Stopped)
    );
    assert_eq!(TransportError::Stopped.to_string(), EngineError.to_string());
}

#[tokio::test]
async fn stalled_transport_does_not_hold_back_another() {
    const IP_C: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
    let (ta, tb) = link(64);
    let (ta, gate) = Tapped::new(ta);
    let (tb, _gate_b) = Tapped::new(tb);
    let options = Options {
        queue_capacity: 2,
        sink_capacity: 64,
        ..Options::default()
    };
    let (mut a, mut b) = nodes(ta, tb, &options);
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;

    // `a` also reaches `c` on its second link (transport 3).
    let (ta2, tc) = second_link();
    a.handle.add_transport(ta2).await.unwrap();
    let mut c = node(
        3,
        IP_C,
        "192.0.2.12:2000".parse().unwrap(),
        TransportId::new(4),
        tc,
        &options,
    );
    a.handle
        .add_or_update_peer(c.as_peer(TransportId::new(3)))
        .await
        .unwrap();
    c.handle
        .add_or_update_peer(Peer {
            path: Some(Path {
                transport: TransportId::new(4),
                addr: "192.0.2.11:1000".parse().unwrap(),
                ecn: Ecn::NotEct,
            }),
            ..a.as_peer(TransportId::new(4))
        })
        .await
        .unwrap();
    a.send(IP_C, b"hello").await;
    assert_eq!(c.expect_delivery().await.1, ipv4(IP_A, IP_C, b"hello"));

    // Transport 1 stops draining: its queue and backlog fill, and the local packets to `b`
    // beyond them are dropped instead of holding back the source.
    gate.send(false).unwrap();
    let local = a.local.clone();
    let sender = tokio::spawn(async move {
        for i in 0..20u8 {
            let packet = PacketBuf::from_packet(&ipv4(IP_A, IP_B, &[i]));
            local.send(packet).await.unwrap();
        }
    });
    // Local packets to `c` on transport 3 keep going meanwhile.
    for i in 0..5u8 {
        a.send(IP_C, &[i]).await;
        assert_eq!(c.expect_delivery().await.1, ipv4(IP_A, IP_C, &[i]));
    }
    timeout(WAIT, sender)
        .await
        .expect("the source was held back")
        .unwrap();
    a.send(IP_C, b"after").await;
    assert_eq!(c.expect_delivery().await.1, ipv4(IP_A, IP_C, b"after"));
    eventually(|| async { a.drops(DROP_TRANSMIT_FULL).await > 0 }).await;

    // Once transport 1 drains, at most the datagram being sent, the transmit queue and the
    // backlog arrive, in order.
    gate.send(true).unwrap();
    let mut delivered = Vec::new();
    while let Ok(Some((_, packet))) = timeout(QUIET, b.delivered.recv()).await {
        delivered.push(packet.as_packet().to_vec());
    }
    assert!(
        (1..=5).contains(&delivered.len()),
        "delivered {}",
        delivered.len()
    );
    let mut sent = (0..20u8).map(|i| ipv4(IP_A, IP_B, &[i]));
    for packet in &delivered {
        assert!(sent.any(|p| p == *packet), "out of order: {packet:?}");
    }
}

/// Two peered nodes on one link that `a` sends through `gate`, with `queued` datagrams
/// injected for `b` while the gate is closed: one being sent, two in the transmit queue and
/// the rest waiting for room in it.
async fn queued_behind_a_closed_gate(queued: u8) -> (Node, Node, watch::Sender<bool>) {
    let (ta, tb) = link(64);
    let (ta, gate) = Tapped::new(ta);
    let (tb, _gate_b) = Tapped::new(tb);
    let options = Options {
        queue_capacity: 2,
        sink_capacity: 64,
        ..Options::default()
    };
    let (mut a, mut b) = nodes(ta, tb, &options);
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;

    gate.send(false).unwrap();
    for i in 0..queued {
        let packet = PacketBuf::from_packet(&ipv4(IP_A, IP_B, &[i]));
        a.handle.inject_outbound(packet).await.unwrap();
    }
    // Lets the transmit task take its datagram.
    sleep(QUIET).await;
    (a, b, gate)
}

#[tokio::test]
async fn removed_transport_counts_its_queued_datagrams() {
    const QUEUED: u8 = 8;
    let (a, mut b, _gate) = queued_behind_a_closed_gate(QUEUED).await;
    let mut events = a.handle.subscribe().await.unwrap();

    a.handle
        .remove_transport(TransportId::new(1))
        .await
        .unwrap();
    let counters = a.handle.drop_counters().await.unwrap();
    assert_eq!(
        counters.get(DROP_TRANSPORT_REMOVED),
        Some(&u64::from(QUEUED))
    );
    assert_eq!(counters.get(DROP_NO_TRANSPORT), None);
    let dropped = expect_event(
        &mut events,
        |e| matches!(e, Event::Dropped { reason, .. } if *reason == DROP_TRANSPORT_REMOVED),
    )
    .await;
    assert!(matches!(dropped, Event::Dropped { peer: None, .. }));
    b.expect_no_delivery().await;

    // Later datagrams to the removed transport are not queued for it.
    a.send(IP_B, b"lost").await;
    eventually(|| async { a.drops(DROP_NO_TRANSPORT).await == 1 }).await;
    assert_eq!(a.drops(DROP_TRANSPORT_REMOVED).await, u64::from(QUEUED));
}

#[tokio::test]
async fn replaced_transport_carries_over_its_queued_datagrams() {
    const QUEUED: u8 = 8;
    let (a, mut b, _gate) = queued_behind_a_closed_gate(QUEUED).await;

    let (ta, tb) = link(64);
    b.handle.replace_transport(tb).await.unwrap();
    a.handle.replace_transport(ta).await.unwrap();
    for i in 0..QUEUED {
        assert_eq!(b.expect_delivery().await.1, ipv4(IP_A, IP_B, &[i]));
    }
    b.expect_no_delivery().await;
    assert!(a.handle.drop_counters().await.unwrap().is_empty());
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

const fn is_suspension(event: &Event) -> bool {
    matches!(event, Event::Suspended | Event::Resumed)
}

#[tokio::test]
async fn suspend_and_resume_are_idempotent() {
    let (mut a, mut b) = peered().await;
    exchange(&mut a, &mut b).await;
    let mut events = a.handle.subscribe().await.unwrap();

    a.handle.suspend().await.unwrap();
    a.handle.suspend().await.unwrap();
    a.handle.resume().await.unwrap();
    a.handle.resume().await.unwrap();
    assert!(matches!(
        expect_event(&mut events, is_suspension).await,
        Event::Suspended
    ));
    assert!(matches!(
        expect_event(&mut events, is_suspension).await,
        Event::Resumed
    ));
    assert!(
        timeout(QUIET, expect_event(&mut events, is_suspension))
            .await
            .is_err(),
        "a second transition was published"
    );
    exchange(&mut a, &mut b).await;

    a.handle.shutdown().await.unwrap();
    assert_eq!(a.handle.suspend().await, Err(EngineError));
    assert_eq!(a.handle.resume().await, Err(EngineError));
}

#[tokio::test]
async fn transports_replaced_while_suspended_start_suspended() {
    let (mut a, mut b) = peered().await;
    exchange(&mut a, &mut b).await;

    a.handle.suspend().await.unwrap();
    let (ta, tb) = link(64);
    a.handle.replace_transport(ta).await.unwrap();
    b.handle.replace_transport(tb).await.unwrap();
    // Handle calls still run; the datagram they cause waits for the resume.
    let packet = ipv4(IP_A, IP_B, b"held");
    a.handle
        .inject_outbound(PacketBuf::from_packet(&packet))
        .await
        .unwrap();
    b.expect_no_delivery().await;

    a.handle.resume().await.unwrap();
    assert_eq!(b.expect_delivery().await.1, packet);
    exchange(&mut a, &mut b).await;
}

#[tokio::test]
async fn mtu_is_kept_once_the_source_watch_closes() {
    let (source, _local, mtu) = ChannelSource::new(4, 1420);
    let (sink, _delivered) = ChannelSink::new(4);
    let (transport, _other) = link(4);
    let engine = EngineBuilder::new(source, sink)
        .transport(transport)
        .build()
        .unwrap();
    let handle = engine.handle();
    let mut events = handle.subscribe().await.unwrap();
    assert_eq!(handle.mtu().await.unwrap(), 1420);

    mtu.send(1280).unwrap();
    assert_eq!(
        expect_event(&mut events, |e| matches!(e, Event::MtuChanged { .. })).await,
        Event::MtuChanged { mtu: 1280 }
    );
    drop(mtu);
    sleep(QUIET).await;
    assert_eq!(handle.mtu().await.unwrap(), 1280);
    handle.shutdown().await.unwrap();
    assert_eq!(handle.mtu().await, Err(EngineError));
}

/// A packet from `a` to `b` numbered `i`.
fn numbered(i: usize) -> Vec<u8> {
    ipv4(IP_A, IP_B, &u16::try_from(i).unwrap().to_be_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crypto_workers_hold_back_datagrams_for_a_slow_sink() {
    const PACKETS: usize = 400;
    let (ta, tb) = link(64);
    let mut a = node(
        1,
        IP_A,
        addr_a(),
        TransportId::new(1),
        ta,
        &Options::default(),
    );
    let options = Options {
        queue_capacity: 16,
        sink_capacity: 1,
        crypto_workers: 2,
    };
    let mut b = node(2, IP_B, addr_b(), TransportId::new(2), tb, &options);
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;

    let local = a.local.clone();
    let sender = tokio::spawn(async move {
        for i in 0..PACKETS {
            let packet = PacketBuf::from_packet(&numbered(i));
            local.send(packet).await.unwrap();
        }
    });
    // The sink keeps up with a fraction of the link: the received datagrams wait in the
    // transport instead of being decrypted into a full deliver queue.
    for i in 0..PACKETS {
        if i % 8 == 0 {
            sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(b.expect_delivery().await.1, numbered(i));
    }
    timeout(WAIT, sender).await.unwrap().unwrap();
    assert!(b.handle.drop_counters().await.unwrap().is_empty());
    let deliver = b.handle.queue_stats().await.unwrap().deliver;
    assert!(deliver.high_water <= deliver.capacity, "{deliver:?}");
}

/// A transport that records how many datagrams each `send_batch` call carries.
struct Recording {
    inner: ChannelTransport,
    calls: Arc<Mutex<Vec<usize>>>,
}

impl Transport for Recording {
    fn id(&self) -> TransportId {
        self.inner.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        self.inner.recv(buf).await
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        self.inner.send(datagram, to).await
    }

    async fn send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        self.calls.lock().unwrap().push(datagrams.len() - *sent);
        while let Some((path, data)) = datagrams.get(*sent) {
            let result = self.inner.send(data.as_packet(), path).await;
            *sent += 1;
            result.inspect_err(|_| *failed += 1)?;
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_drain_reaches_the_transport_in_one_batch() {
    const QUEUED: usize = 32;
    let (ta, tb) = link(64);
    let calls = Arc::default();
    let ta = Recording {
        inner: ta,
        calls: Arc::clone(&calls),
    };
    let (tb, gate_b) = Tapped::new(tb);
    let options = Options::default();
    let a = node(1, IP_A, addr_a(), TransportId::new(1), ta, &options);
    let mut b = node(2, IP_B, addr_b(), TransportId::new(2), tb, &options);
    introduce(&a, &b).await;

    // `b` holds back its handshake response, so `a`'s core queues the packets; the response
    // releases all of them in one drain.
    gate_b.send(false).unwrap();
    for i in 0..QUEUED {
        let packet = PacketBuf::from_packet(&numbered(i));
        a.local.send(packet).await.unwrap();
    }
    eventually(|| async { !calls.lock().unwrap().is_empty() }).await;
    sleep(QUIET).await;
    gate_b.send(true).unwrap();
    for i in 0..QUEUED {
        assert_eq!(b.expect_delivery().await.1, numbered(i));
    }
    // The handshake initiation, then the queued packets (and the core's other output of
    // that drain) at once, counted as datagrams in the transmit queue.
    let calls = calls.lock().unwrap().clone();
    assert!(calls.len() == 2 && calls[1] >= QUEUED, "{calls:?}");
    let transmit = a.handle.queue_stats().await.unwrap().transmit;
    assert_eq!(transmit.high_water, calls[1], "{transmit:?}");
}

/// A channel source that keeps up to `bound` recycled buffers and records every offer.
struct Recycling {
    inner: ChannelSource,
    kept: Vec<PacketBuf>,
    bound: usize,
    taken: Arc<AtomicUsize>,
    largest_offer: Arc<AtomicUsize>,
}

impl PacketSource for Recycling {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        self.inner.recv().await
    }

    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        self.largest_offer.fetch_max(bufs.len(), Ordering::Relaxed);
        let take = bufs.len().min(self.bound - self.kept.len());
        self.kept.extend(bufs.drain(..take));
        self.taken.fetch_add(take, Ordering::Relaxed);
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.inner.mtu()
    }
}

#[tokio::test]
async fn transmitted_buffers_go_back_to_the_source() {
    const CAPACITY: usize = 4;
    const INJECTED: usize = 50;
    let (ta, tb) = link(64);
    let taken = Arc::new(AtomicUsize::new(0));
    let largest_offer = Arc::new(AtomicUsize::new(0));
    let options = Options {
        queue_capacity: CAPACITY,
        ..Options::default()
    };
    let wrap = |inner| Recycling {
        inner,
        kept: Vec::new(),
        bound: 1000,
        taken: Arc::clone(&taken),
        largest_offer: Arc::clone(&largest_offer),
    };
    let mut a = node_with(1, IP_A, addr_a(), TransportId::new(1), ta, &options, wrap);
    let mut b = node(2, IP_B, addr_b(), TransportId::new(2), tb, &options);
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;
    a.send(IP_B, b"again").await;
    b.expect_delivery().await;
    eventually(|| async { taken.load(Ordering::Relaxed) > 0 }).await;

    // The source task waits for a packet and takes no buffers meanwhile: its full queue
    // drops them, and sending never waits for it.
    let to_b = a.peer_of(&b).await;
    let path = b.as_peer(a.transport).path.unwrap();
    for i in 0..INJECTED {
        let packet = PacketBuf::from_packet(&numbered(i));
        timeout(WAIT, a.handle.inject_outbound_on(to_b, path, packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b.expect_delivery().await.1, numbered(i));
    }
    let before = taken.load(Ordering::Relaxed);
    a.send(IP_B, b"wake").await;
    b.expect_delivery().await;
    eventually(|| async { taken.load(Ordering::Relaxed) > before }).await;
    let largest = largest_offer.load(Ordering::Relaxed);
    assert!((1..=CAPACITY).contains(&largest), "largest offer {largest}");
    assert!(a.handle.drop_counters().await.unwrap().is_empty());
}

/// A packet from `src` to `dst` carrying the sequence number `n`.
fn sequenced(src: Ipv4Addr, dst: Ipv4Addr, n: u32) -> Vec<u8> {
    ipv4(src, dst, &n.to_be_bytes())
}

/// Sends `count` sequenced packets from `src` to `dst` into `local`, in a task.
fn flood(
    local: &mpsc::Sender<PacketBuf>,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    count: u32,
) -> tokio::task::JoinHandle<()> {
    let local = local.clone();
    tokio::spawn(async move {
        for n in 0..count {
            let packet = PacketBuf::from_packet(&sequenced(src, dst, n));
            if local.send(packet).await.is_err() {
                return;
            }
        }
    })
}

/// A node's sink.
type Delivered = mpsc::Receiver<(PeerId, PacketBuf)>;

/// The sequence numbers received from each source, in the order they arrived.
type Sequences = BTreeMap<Ipv4Addr, Vec<u32>>;

/// Starts receiving at `node` until no packet arrives for a while; the task hands back
/// the sequence numbers of each source and the node's sink.
fn receive(node: &mut Node) -> tokio::task::JoinHandle<(Sequences, Delivered)> {
    let mut delivered = std::mem::replace(&mut node.delivered, mpsc::channel(1).1);
    tokio::spawn(async move {
        let mut received = Sequences::new();
        while let Ok(Some((_, packet))) = timeout(QUIET, delivered.recv()).await {
            let packet = packet.as_packet();
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let n = u32::from_be_bytes(packet[20..24].try_into().unwrap());
            received.entry(src).or_default().push(n);
        }
        (received, delivered)
    })
}

/// Waits for `receiver` of `node` and gives the sink back.
async fn received(
    node: &mut Node,
    receiver: tokio::task::JoinHandle<(Sequences, Delivered)>,
) -> Sequences {
    let (received, delivered) = receiver.await.unwrap();
    node.delivered = delivered;
    received
}

/// Every drop the nodes counted; only reasons of a full queue are allowed.
async fn queue_drops(nodes: &[&Node]) -> u64 {
    let mut total = 0;
    for node in nodes {
        for (reason, count) in node.handle.drop_counters().await.unwrap() {
            assert!(
                [DROP_TRANSMIT_FULL, DROP_SINK_FULL].contains(&reason),
                "{reason}: {count}"
            );
            total += count;
        }
    }
    total
}

/// Checks that every sequence is a strictly increasing run of numbers below `sent` (no
/// reordering, no duplicate); returns how many packets arrived.
fn in_order(sequences: &[&Sequences], sent: u32) -> u64 {
    let mut total = 0;
    for sequence in sequences.iter().flat_map(|s| s.values()) {
        assert!(sequence.windows(2).all(|w| w[0] < w[1]), "{sequence:?}");
        assert!(sequence.iter().all(|&n| n < sent));
        total += sequence.len() as u64;
    }
    total
}

/// Options of a node with `workers` crypto workers and room for bursts.
fn pooled(workers: usize) -> Options {
    Options {
        sink_capacity: 1024,
        crypto_workers: workers,
        ..Options::default()
    }
}

/// Two linked peers with `workers` crypto workers each, sessions up.
async fn pooled_pair(workers: usize) -> (Node, Node) {
    let (ta, tb) = link(1024);
    let (mut a, mut b) = nodes(ta, tb, &pooled(workers));
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;
    (a, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_peer_on_every_crypto_worker_keeps_its_order() {
    const PACKETS: u32 = 3000;
    let (mut a, mut b) = pooled_pair(4).await;
    let (at_a, at_b) = (receive(&mut a), receive(&mut b));
    let senders = [
        flood(&a.local, IP_A, IP_B, PACKETS),
        flood(&b.local, IP_B, IP_A, PACKETS),
    ];
    for sender in senders {
        timeout(WAIT, sender).await.unwrap().unwrap();
    }
    let (at_a, at_b) = (received(&mut a, at_a).await, received(&mut b, at_b).await);
    let arrived = in_order(&[&at_a, &at_b], PACKETS);
    assert_eq!(
        arrived + queue_drops(&[&a, &b]).await,
        2 * u64::from(PACKETS)
    );
    // One way at a time, nothing is dropped.
    let at_b = receive(&mut b);
    timeout(WAIT, flood(&a.local, IP_A, IP_B, PACKETS))
        .await
        .unwrap()
        .unwrap();
    let at_b = received(&mut b, at_b).await;
    assert_eq!(at_b[&IP_A], (0..PACKETS).collect::<Vec<_>>());
}

/// A hub (key seed 1) and `count` spokes (seeds from 2), each on a link of its own and with
/// `workers` crypto workers, sessions up.
async fn star(count: u8, workers: usize) -> (Node, Vec<Node>) {
    let hub_ip = Ipv4Addr::new(10, 0, 0, 1);
    let mut links = Vec::new();
    let mut spokes = Vec::new();
    for seed in 2..2 + count {
        let spoke_addr = SocketAddr::from(([192, 0, 2, seed], 2000));
        let (hub_end, spoke_end) = ChannelTransport::pair(
            1024,
            (
                TransportId::new(u16::from(seed)),
                SocketAddr::from(([192, 0, 2, 1], u16::from(seed))),
            ),
            (TransportId::new(1), spoke_addr),
        );
        links.push(hub_end);
        let ip = Ipv4Addr::new(10, 0, 0, seed);
        let options = pooled(workers);
        spokes.push(node(
            seed,
            ip,
            spoke_addr,
            TransportId::new(1),
            spoke_end,
            &options,
        ));
    }
    let (source, local, mtu) = ChannelSource::new(4, 1420);
    let (sink, delivered) = ChannelSink::new(1024);
    let engine = links
        .into_iter()
        .fold(EngineBuilder::new(source, sink), EngineBuilder::transport)
        .private_key(secret(1))
        .crypto_workers(workers)
        .build()
        .unwrap();
    let mut hub = Node {
        handle: engine.handle(),
        engine,
        local,
        delivered,
        _mtu: mtu,
        secret: secret(1),
        ip: hub_ip,
        addr: SocketAddr::from(([192, 0, 2, 1], 2)),
        transport: TransportId::new(1),
    };
    for spoke in &mut spokes {
        let seed = spoke.ip.octets()[3];
        hub.handle
            .add_or_update_peer(spoke.as_peer(TransportId::new(u16::from(seed))))
            .await
            .unwrap();
        let mut hub_peer = hub.as_peer(TransportId::new(1));
        hub_peer.path = Some(Path {
            transport: TransportId::new(1),
            addr: SocketAddr::from(([192, 0, 2, 1], u16::from(seed))),
            ecn: Ecn::NotEct,
        });
        spoke.handle.add_or_update_peer(hub_peer).await.unwrap();
        spoke.send(hub_ip, b"hello").await;
        hub.expect_delivery().await;
    }
    (hub, spokes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_peers_on_many_crypto_workers_lose_and_reorder_nothing() {
    const SPOKES: u8 = 8;
    const PACKETS: u32 = 400;
    let (mut hub, mut spokes) = star(SPOKES, 4).await;
    let hub_ip = hub.ip;

    // Every spoke to the hub, then the hub to every spoke: each way nothing is dropped.
    let at_hub = receive(&mut hub);
    let senders: Vec<_> = spokes
        .iter()
        .map(|spoke| flood(&spoke.local, spoke.ip, hub_ip, PACKETS))
        .collect();
    for sender in senders {
        timeout(WAIT, sender).await.unwrap().unwrap();
    }
    let at_hub = received(&mut hub, at_hub).await;
    let all: Vec<u32> = (0..PACKETS).collect();
    for spoke in &spokes {
        assert_eq!(at_hub[&spoke.ip], all, "{} -> hub", spoke.ip);
    }
    let at_spokes: Vec<_> = spokes.iter_mut().map(receive).collect();
    let senders: Vec<_> = spokes
        .iter()
        .map(|spoke| flood(&hub.local, hub_ip, spoke.ip, PACKETS))
        .collect();
    for sender in senders {
        timeout(WAIT, sender).await.unwrap().unwrap();
    }
    for (spoke, at_spoke) in spokes.iter_mut().zip(at_spokes) {
        let at_spoke = received(spoke, at_spoke).await;
        assert_eq!(at_spoke[&hub_ip], all, "hub -> {}", spoke.ip);
    }
    let nodes: Vec<&Node> = std::iter::once(&hub).chain(&spokes).collect();
    assert_eq!(queue_drops(&nodes).await, 0);

    // Both ways at once: only full queues drop packets, and they count every one.
    let at: Vec<_> = std::iter::once(&mut hub)
        .chain(spokes.iter_mut())
        .map(receive)
        .collect();
    let mut senders = Vec::new();
    for spoke in &spokes {
        senders.push(flood(&spoke.local, spoke.ip, hub_ip, PACKETS));
        senders.push(flood(&hub.local, hub_ip, spoke.ip, PACKETS));
    }
    for sender in senders {
        timeout(WAIT, sender).await.unwrap().unwrap();
    }
    let mut sequences = Vec::new();
    for (node, at) in std::iter::once(&mut hub).chain(spokes.iter_mut()).zip(at) {
        sequences.push(received(node, at).await);
    }
    let arrived = in_order(&sequences.iter().collect::<Vec<_>>(), PACKETS);
    let nodes: Vec<&Node> = std::iter::once(&hub).chain(&spokes).collect();
    assert_eq!(
        arrived + queue_drops(&nodes).await,
        2 * u64::from(SPOKES) * u64::from(PACKETS)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rekey_under_load_keeps_every_packet_in_order() {
    const PACKETS: u32 = 4000;
    let (a, mut b) = pooled_pair(4).await;
    let mut events = a.handle.subscribe().await.unwrap();
    let to_b = a.peer_of(&b).await;
    let at_b = receive(&mut b);
    let sender = flood(&a.local, IP_A, IP_B, PACKETS);
    // Jobs of the current session are in flight while the new one is established.
    sleep(Duration::from_millis(5)).await;
    a.handle.force_handshake(to_b, None).await.unwrap();
    timeout(WAIT, sender).await.unwrap().unwrap();
    expect_event(&mut events, is_handshake).await;
    let at_b = received(&mut b, at_b).await;
    assert_eq!(at_b[&IP_A], (0..PACKETS).collect::<Vec<_>>());
    assert_eq!(queue_drops(&[&a, &b]).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suspend_and_resume_with_jobs_in_flight_lose_nothing() {
    const PACKETS: u32 = 3000;
    let (a, mut b) = pooled_pair(4).await;
    let at_b = receive(&mut b);
    let sender = flood(&a.local, IP_A, IP_B, PACKETS);
    sleep(Duration::from_millis(5)).await;
    a.handle.suspend().await.unwrap();
    b.handle.suspend().await.unwrap();
    sleep(QUIET / 3).await;
    b.handle.resume().await.unwrap();
    a.handle.resume().await.unwrap();
    timeout(WAIT, sender).await.unwrap().unwrap();
    let at_b = received(&mut b, at_b).await;
    assert_eq!(at_b[&IP_A], (0..PACKETS).collect::<Vec<_>>());
    assert_eq!(queue_drops(&[&a, &b]).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_peer_with_jobs_in_flight_counts_every_packet() {
    const PACKETS: u32 = 3000;
    let (a, mut b) = pooled_pair(4).await;
    let at_b = receive(&mut b);
    let sender = flood(&a.local, IP_A, IP_B, PACKETS);
    sleep(Duration::from_millis(5)).await;
    a.handle.remove_peer(b.public()).await.unwrap();
    timeout(WAIT, sender).await.unwrap().unwrap();
    // Every packet read before the removal is delivered, in order; every later one is
    // dropped for lack of a route.
    let at_b = received(&mut b, at_b).await;
    let at_b = at_b.get(&IP_A).cloned().unwrap_or_default();
    let delivered = u32::try_from(at_b.len()).unwrap();
    assert_eq!(at_b, (0..delivered).collect::<Vec<_>>());
    let unrouted = a.drops(nsplane_core::reasons::NO_ROUTE).await;
    assert_eq!(u64::from(delivered) + unrouted, u64::from(PACKETS));
    assert!(b.handle.drop_counters().await.unwrap().is_empty());
}

/// A transport that sends every datagram twice.
struct Doubling(ChannelTransport);

impl Transport for Doubling {
    fn id(&self) -> TransportId {
        self.0.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        self.0.recv(buf).await
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        self.0.send(datagram, to).await?;
        self.0.send(datagram, to).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicates_opened_on_different_workers_are_rejected_as_replays() {
    const PACKETS: u32 = 2000;
    let (ta, tb) = link(1024);
    let (mut a, mut b) = nodes(Doubling(ta), Doubling(tb), &pooled(4));
    introduce(&a, &b).await;
    exchange(&mut a, &mut b).await;
    let replays = b.drops(nsplane_core::reasons::DECAPSULATE_ERROR).await;

    let at_b = receive(&mut b);
    timeout(WAIT, flood(&a.local, IP_A, IP_B, PACKETS))
        .await
        .unwrap()
        .unwrap();
    let at_b = received(&mut b, at_b).await;
    assert_eq!(at_b[&IP_A], (0..PACKETS).collect::<Vec<_>>());
    // Each packet's copy, opened next to it on another worker, is rejected when completed.
    let replayed = b.drops(nsplane_core::reasons::DECAPSULATE_ERROR).await - replays;
    assert_eq!(replayed, u64::from(PACKETS));
}
