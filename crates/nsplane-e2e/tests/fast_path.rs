//! The owner task's fast path without crypto workers: it hands datagrams to an idle
//! transport and packets to an idle sink itself (`try_send_batch`), and falls back to the
//! transmit and deliver queues, in order, whenever those would block or still hold anything.
//! With crypto workers the owner never sends or delivers itself.
//!
//! The engines here run on an in-memory network of scripted transports and sinks: each
//! `try_send_batch` takes everything, nothing (`WouldBlock`) or one item, and the sends of the
//! transmit and sink tasks wait behind a gate the test opens and closes.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSource, DROP_SINK_CLOSED, DROP_SINK_FULL, DROP_TRANSMIT_FULL,
    DROP_TRANSPORT_REMOVED, Ecn, Engine, EngineBuilder, EngineHandle, MAX_BATCH, PacketBuf,
    PacketSink, Path, Peer, PeerId, Transport, TransportId,
};
use nsplane_e2e::{QUIET, TestResult, WAIT, payload, udp4};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep, timeout};

/// The id of every node's transport.
const ID: TransportId = TransportId::new(1);
/// Capacity of a node's source channel.
const SOURCE: usize = 64;

/// How a scripted `try_send_batch` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Takes everything.
    Accept,
    /// Takes nothing: `WouldBlock`.
    Block,
    /// Takes one item, then `WouldBlock`.
    Partial,
    /// Accept, Block and Partial in turn, one per call.
    Cycle,
}

/// The script of a transport or sink, shared with the test, and what went through it.
#[derive(Debug)]
struct Control {
    mode: Mutex<Mode>,
    turn: AtomicUsize,
    /// While `false`, the task-side sends wait.
    open: watch::Sender<bool>,
    /// A closed sink fails every delivery with `BrokenPipe`.
    closed: AtomicBool,
    try_calls: AtomicUsize,
    /// Items taken by `try_send_batch`.
    try_done: AtomicUsize,
    /// Items taken by the task-side sends.
    task_done: AtomicUsize,
}

impl Control {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mode: Mutex::new(Mode::Accept),
            turn: AtomicUsize::new(0),
            open: watch::Sender::new(true),
            closed: AtomicBool::new(false),
            try_calls: AtomicUsize::new(0),
            try_done: AtomicUsize::new(0),
            task_done: AtomicUsize::new(0),
        })
    }

    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap_or_else(PoisonError::into_inner) = mode;
    }

    fn set_open(&self, open: bool) {
        self.open.send_replace(open);
    }

    fn try_calls(&self) -> usize {
        self.try_calls.load(Ordering::Relaxed)
    }

    fn try_done(&self) -> usize {
        self.try_done.load(Ordering::Relaxed)
    }

    fn task_done(&self) -> usize {
        self.task_done.load(Ordering::Relaxed)
    }

    /// Counts a `try_send_batch` call; how many items it may take.
    fn room(&self) -> usize {
        self.try_calls.fetch_add(1, Ordering::Relaxed);
        let mode = *self.mode.lock().unwrap_or_else(PoisonError::into_inner);
        let mode = match mode {
            Mode::Cycle => [Mode::Accept, Mode::Block, Mode::Partial]
                [self.turn.fetch_add(1, Ordering::Relaxed) % 3],
            mode => mode,
        };
        match mode {
            Mode::Accept | Mode::Cycle => usize::MAX,
            Mode::Partial => 1,
            Mode::Block => 0,
        }
    }

    /// Waits until the gate is open.
    async fn pass(&self) {
        let mut open = self.open.subscribe();
        // The control keeps the sender, so the wait ends only once the gate is open.
        let _ = open.wait_for(|open| *open).await;
    }
}

/// What a node's transport receives: the sender's address and the datagram.
type Wire = mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>;

/// An in-memory network: each test transport receives what is sent to its address.
#[derive(Debug, Clone, Default)]
struct Net(Arc<Mutex<HashMap<SocketAddr, Wire>>>);

impl Net {
    /// A transport at `addr`, taking over the address from an earlier one.
    fn transport(&self, addr: SocketAddr, control: Arc<Control>) -> TestTransport {
        let (tx, rx) = mpsc::unbounded_channel();
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(addr, tx);
        TestTransport {
            addr,
            net: self.clone(),
            rx: tokio::sync::Mutex::new(rx),
            control,
        }
    }

    /// Sends `datagram` from `from` to `to`; lost if nothing is at `to`.
    fn send(&self, from: SocketAddr, to: SocketAddr, datagram: &[u8]) {
        if let Some(wire) = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&to)
        {
            let _ = wire.send((from, datagram.to_vec()));
        }
    }
}

/// A scripted transport on a [`Net`].
#[derive(Debug)]
struct TestTransport {
    addr: SocketAddr,
    net: Net,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
    control: Arc<Control>,
}

impl Transport for TestTransport {
    fn id(&self) -> TransportId {
        ID
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        let (from, datagram) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let len = datagram.len().min(buf.capacity());
        buf.set_len(buf.capacity());
        buf.as_packet_mut()[..len].copy_from_slice(&datagram[..len]);
        buf.set_len(len);
        Ok((len, at(from)))
    }

    /// Takes every datagram already queued, up to [`MAX_BATCH`], as a socket read with
    /// receive offload does.
    async fn recv_batch(
        &self,
        _buf: &mut PacketBuf,
        datagrams: &mut VecDeque<(Path, PacketBuf)>,
    ) -> io::Result<()> {
        let mut rx = self.rx.lock().await;
        if datagrams.len() >= MAX_BATCH {
            return Ok(());
        }
        let (from, datagram) = rx
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        datagrams.push_back((at(from), PacketBuf::from_packet(&datagram)));
        while datagrams.len() < MAX_BATCH
            && let Ok((from, datagram)) = rx.try_recv()
        {
            datagrams.push_back((at(from), PacketBuf::from_packet(&datagram)));
        }
        Ok(())
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        self.control.pass().await;
        self.net.send(self.addr, to.addr, datagram);
        self.control.task_done.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        _failed: &mut usize,
    ) -> io::Result<()> {
        let room = self.control.room();
        let mut taken = 0;
        while let Some((to, datagram)) = datagrams.get(*sent) {
            if taken == room {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.net.send(self.addr, to.addr, datagram.as_packet());
            self.control.try_done.fetch_add(1, Ordering::Relaxed);
            *sent += 1;
            taken += 1;
        }
        Ok(())
    }
}

/// A scripted sink delivering into a channel.
#[derive(Debug)]
struct TestSink {
    tx: mpsc::UnboundedSender<(PeerId, PacketBuf)>,
    control: Arc<Control>,
}

impl PacketSink for TestSink {
    async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
        self.control.pass().await;
        if self.control.closed.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let _ = self.tx.send((from, packet));
        self.control.task_done.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn try_send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        let room = self.control.room();
        if self.control.closed.load(Ordering::Relaxed) {
            packets.pop_front();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut taken = 0;
        while !packets.is_empty() {
            if taken == room {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if let Some(packet) = packets.pop_front() {
                let _ = self.tx.send(packet);
            }
            self.control.try_done.fetch_add(1, Ordering::Relaxed);
            taken += 1;
        }
        Ok(())
    }
}

/// The address of the node with seed `seed` on the network.
fn addr_of(seed: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, seed], 1000 + u16::from(seed)))
}

/// The tunnel address of the node with seed `seed`.
const fn ip_of(seed: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, seed)
}

const fn at(addr: SocketAddr) -> Path {
    Path {
        transport: ID,
        addr,
        ecn: Ecn::NotEct,
    }
}

/// The sequence number of a packet from [`Node::packet_to`].
fn seq_of(packet: &[u8]) -> Option<u32> {
    packet
        .get(28..32)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
}

/// An engine on a scripted transport and sink.
struct Node {
    /// Keeps the engine running.
    _engine: Engine,
    handle: EngineHandle,
    local: mpsc::Sender<PacketBuf>,
    delivered: mpsc::UnboundedReceiver<(PeerId, PacketBuf)>,
    transport: Arc<Control>,
    sink: Arc<Control>,
    seed: u8,
}

impl Node {
    /// A node with key seed `seed` at [`addr_of`] on `net`, with `configure` adding
    /// settings to the engine builder.
    fn new(
        net: &Net,
        seed: u8,
        configure: impl FnOnce(
            EngineBuilder<ChannelSource, TestSink>,
        ) -> EngineBuilder<ChannelSource, TestSink>,
    ) -> TestResult<Self> {
        Self::with_source(net, seed, SOURCE, configure)
    }

    /// [`Node::new`] with a source channel of `source` packets.
    fn with_source(
        net: &Net,
        seed: u8,
        source: usize,
        configure: impl FnOnce(
            EngineBuilder<ChannelSource, TestSink>,
        ) -> EngineBuilder<ChannelSource, TestSink>,
    ) -> TestResult<Self> {
        let (transport, sink) = (Control::new(), Control::new());
        let (source, local, _mtu) = ChannelSource::new(source, nsplane_e2e::MTU);
        let (tx, delivered) = mpsc::unbounded_channel();
        let builder = EngineBuilder::new(
            source,
            TestSink {
                tx,
                control: Arc::clone(&sink),
            },
        )
        .private_key(StaticSecret::from([seed; 32]))
        .transport(net.transport(addr_of(seed), Arc::clone(&transport)));
        let engine = configure(builder).build()?;
        Ok(Self {
            handle: engine.handle(),
            _engine: engine,
            local,
            delivered,
            transport,
            sink,
            seed,
        })
    }

    fn public(&self) -> PublicKey {
        PublicKey::from(&StaticSecret::from([self.seed; 32]))
    }

    fn as_peer(&self) -> Peer {
        Peer {
            allowed_ips: vec![AllowedIp {
                addr: IpAddr::V4(ip_of(self.seed)),
                cidr: 32,
            }],
            path: Some(at(addr_of(self.seed))),
            ..Peer::new(self.public())
        }
    }

    /// Packet number `seq` from this node to `other`.
    fn packet_to(&self, other: &Self, seq: u32) -> Vec<u8> {
        let mut body = seq.to_be_bytes().to_vec();
        body.extend(payload(60));
        udp4(ip_of(self.seed), ip_of(other.seed), &body)
    }

    async fn send(&self, packet: &[u8]) -> TestResult {
        self.local.send(PacketBuf::from_packet(packet)).await?;
        Ok(())
    }

    /// The next delivered packet and its peer, within [`WAIT`].
    async fn expect_delivery(&mut self) -> TestResult<(PeerId, Vec<u8>)> {
        match timeout(WAIT, self.delivered.recv()).await {
            Ok(Some((peer, packet))) => Ok((peer, packet.as_packet().to_vec())),
            Ok(None) => Err("sink closed".into()),
            Err(_) => Err(format!("no delivery within {WAIT:?}").into()),
        }
    }

    /// The sequence numbers of the packets delivered until none comes within [`QUIET`].
    async fn deliveries(&mut self) -> Vec<Option<u32>> {
        let mut seqs = Vec::new();
        while let Ok(Some((_, packet))) = timeout(QUIET, self.delivered.recv()).await {
            seqs.push(seq_of(packet.as_packet()));
        }
        seqs
    }

    /// Expects packets `seqs` from `from`, in order.
    async fn expect_seqs(&mut self, from: &Self, seqs: std::ops::Range<u32>) -> TestResult {
        let peer = self.peer_of(from).await?;
        for seq in seqs {
            let (got_peer, packet) = self.expect_delivery().await?;
            assert_eq!(got_peer, peer, "packet {seq} attributed to {got_peer:?}");
            assert_eq!(seq_of(&packet), Some(seq), "out of order");
            assert_eq!(packet, from.packet_to(self, seq), "packet {seq} changed");
        }
        Ok(())
    }

    async fn peer_of(&self, other: &Self) -> TestResult<PeerId> {
        self.handle
            .peer_id(other.public())
            .await?
            .ok_or_else(|| "unknown peer".into())
    }

    async fn drops(&self, reason: &str) -> TestResult<u64> {
        let counters = self.handle.drop_counters().await?;
        Ok(counters.get(reason).copied().unwrap_or(0))
    }

    /// Datagrams this node's engine received from `other`.
    async fn received_from(&self, other: &Self) -> TestResult<u64> {
        let peer = self.peer_of(other).await?;
        let stats = self.handle.peer_stats(peer).await?.ok_or("unknown peer")?;
        Ok(stats.rx)
    }

    /// Waits until this node's engine received `count` datagrams from `other`.
    async fn wait_received(&self, other: &Self, count: u64) -> TestResult {
        let deadline = Instant::now() + WAIT;
        while self.received_from(other).await? < count {
            if Instant::now() > deadline {
                return Err(format!("fewer than {count} datagrams within {WAIT:?}").into());
            }
            sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }

    /// Waits until this node's transmit queue holds `count` datagrams.
    async fn wait_transmit_queue(&self, count: usize) -> TestResult {
        let deadline = Instant::now() + WAIT;
        while self.handle.queue_stats().await?.transmit.high_water < count {
            if Instant::now() > deadline {
                return Err(format!("fewer than {count} datagrams queued within {WAIT:?}").into());
            }
            sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }
}

/// Makes `a` and `b` peers and completes a handshake with a packet each way.
async fn connect(a: &mut Node, b: &mut Node) -> TestResult {
    a.handle.add_or_update_peer(b.as_peer()).await?;
    b.handle.add_or_update_peer(a.as_peer()).await?;
    let ping = a.packet_to(b, u32::MAX);
    a.send(&ping).await?;
    assert_eq!(b.expect_delivery().await?.1, ping);
    let pong = b.packet_to(a, u32::MAX);
    b.send(&pong).await?;
    assert_eq!(a.expect_delivery().await?.1, pong);
    Ok(())
}

#[tokio::test]
async fn idle_transport_and_sink_take_everything_from_the_owner() -> TestResult {
    let net = Net::default();
    let mut a = Node::new(&net, 1, |b| b)?;
    let mut b = Node::new(&net, 2, |b| b)?;
    connect(&mut a, &mut b).await?;
    for seq in 0..50 {
        let ping = a.packet_to(&b, seq);
        a.send(&ping).await?;
        assert_eq!(b.expect_delivery().await?.1, ping);
        let pong = b.packet_to(&a, seq);
        b.send(&pong).await?;
        assert_eq!(a.expect_delivery().await?.1, pong);
    }

    for node in [&a, &b] {
        // Nothing entered a queue or a task: the owner sent and delivered everything.
        let stats = node.handle.queue_stats().await?;
        for depth in [stats.transmit, stats.backlog, stats.deliver, stats.recycle] {
            assert_eq!(depth.high_water, 0, "{stats:?}");
        }
        assert_eq!(node.transport.task_done(), 0);
        assert_eq!(node.sink.task_done(), 0);
        assert_eq!(node.sink.try_done(), 51);
        // The handshake message, 51 data packets and nothing else.
        let sent = node.transport.try_done();
        assert!(sent >= 52, "{sent}");
        let traffic = node.handle.transport_stats().await?;
        assert_eq!(traffic[0].tx_datagrams, sent as u64);
        assert_eq!(traffic[0].tx_failed, 0);
    }
    Ok(())
}

#[tokio::test]
async fn stalled_transport_queues_in_order_and_holds_back_local_packets() -> TestResult {
    const CAPACITY: usize = 16;
    let net = Net::default();
    let mut a = Node::new(&net, 1, |b| b.queue_capacity(CAPACITY))?;
    let mut b = Node::new(&net, 2, |b| b)?;
    connect(&mut a, &mut b).await?;

    a.transport.set_mode(Mode::Block);
    a.transport.set_open(false);
    a.handle.take_queue_stats().await?;
    let tried = a.transport.try_calls();
    let total = 1000;
    let packets: Vec<Vec<u8>> = (0..total).map(|seq| a.packet_to(&b, seq)).collect();
    let local = a.local.clone();
    let sender = tokio::spawn(async move {
        for packet in packets {
            local.send(PacketBuf::from_packet(&packet)).await?;
        }
        TestResult::Ok(())
    });
    a.wait_transmit_queue(CAPACITY).await?;
    sleep(QUIET).await;
    assert!(!sender.is_finished(), "local packets are held back");
    let stats = a.handle.queue_stats().await?;
    assert_eq!(stats.transmit.high_water, CAPACITY, "{stats:?}");
    assert!(
        stats.backlog.high_water <= MAX_BATCH.min(CAPACITY),
        "{stats:?}"
    );
    assert!(stats.local.high_water <= CAPACITY, "{stats:?}");
    // One try found the transport blocked; everything after it queued behind.
    assert_eq!(a.transport.try_calls(), tried + 1);
    assert_eq!(a.transport.task_done(), 0);

    a.transport.set_mode(Mode::Accept);
    a.transport.set_open(true);
    b.expect_seqs(&a, 0..total).await?;
    timeout(WAIT, sender).await???;
    assert_eq!(a.drops(DROP_TRANSMIT_FULL).await?, 0);
    assert!(a.transport.task_done() > 0);

    // Once the queue drained, the owner sends itself again.
    let done = a.transport.try_done();
    let packet = a.packet_to(&b, total);
    a.send(&packet).await?;
    assert_eq!(b.expect_delivery().await?.1, packet);
    assert!(a.transport.try_done() > done);
    Ok(())
}

/// A hub (seed 1) whose transport cycles through taking everything, nothing and one
/// datagram per call sends `per_peer` interleaved packets to each of `peers` peers on that
/// one transport; each peer gets all of its packets in order.
async fn interleaved_would_block(peers: u8) -> TestResult {
    let per_peer = 300;
    let net = Net::default();
    let mut hub = Node::new(&net, 1, |b| b)?;
    let mut others = Vec::new();
    for seed in 2..2 + peers {
        let mut peer = Node::new(&net, seed, |b| b)?;
        connect(&mut hub, &mut peer).await?;
        others.push(peer);
    }
    hub.transport.set_mode(Mode::Cycle);

    let packets: Vec<Vec<u8>> = (0..per_peer)
        .flat_map(|seq| others.iter().map(move |peer| (seq, peer)))
        .map(|(seq, peer)| hub.packet_to(peer, seq))
        .collect();
    let local = hub.local.clone();
    let sender = tokio::spawn(async move {
        for packet in packets {
            local.send(PacketBuf::from_packet(&packet)).await?;
        }
        TestResult::Ok(())
    });
    for peer in &mut others {
        peer.expect_seqs(&hub, 0..per_peer).await?;
    }
    timeout(WAIT, sender).await???;
    // Both the owner and the transmit task sent.
    assert!(hub.transport.try_done() > 0);
    assert!(hub.transport.task_done() > 0);
    for peer in &mut others {
        assert_eq!(peer.deliveries().await, Vec::<Option<u32>>::new());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interleaved_would_block_keeps_one_peer_in_order() -> TestResult {
    interleaved_would_block(1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interleaved_would_block_keeps_two_peers_on_one_transport_in_order() -> TestResult {
    interleaved_would_block(2).await
}

#[tokio::test]
async fn replace_and_remove_hand_back_what_was_queued() -> TestResult {
    let net = Net::default();
    let mut a = Node::new(&net, 1, |b| b)?;
    let mut b = Node::new(&net, 2, |b| b)?;
    connect(&mut a, &mut b).await?;

    // Queued behind a blocked transport, one of them being sent.
    a.transport.set_mode(Mode::Block);
    a.transport.set_open(false);
    a.handle.take_queue_stats().await?;
    for seq in 0..8 {
        a.send(&a.packet_to(&b, seq)).await?;
    }
    a.wait_transmit_queue(8).await?;

    // The replacement sends them first, in order, then the new ones.
    let control = Control::new();
    a.handle
        .replace_transport(net.transport(addr_of(1), Arc::clone(&control)))
        .await?;
    for seq in 8..16 {
        a.send(&a.packet_to(&b, seq)).await?;
    }
    b.expect_seqs(&a, 0..16).await?;
    assert!(
        control.task_done() >= 8,
        "the old datagrams waited in the queue"
    );
    assert_eq!(a.drops(DROP_TRANSPORT_REMOVED).await?, 0);

    // Removing a blocked transport counts every datagram queued for it.
    control.set_mode(Mode::Block);
    control.set_open(false);
    a.handle.take_queue_stats().await?;
    for seq in 16..21 {
        a.send(&a.packet_to(&b, seq)).await?;
    }
    a.wait_transmit_queue(5).await?;
    a.handle.remove_transport(ID).await?;
    assert_eq!(a.drops(DROP_TRANSPORT_REMOVED).await?, 5);
    assert_eq!(b.deliveries().await, Vec::<Option<u32>>::new());
    Ok(())
}

#[tokio::test]
async fn nothing_goes_out_from_the_owner_while_suspended() -> TestResult {
    let net = Net::default();
    let mut a = Node::new(&net, 1, |b| b)?;
    let mut b = Node::new(&net, 2, |b| b)?;
    connect(&mut a, &mut b).await?;

    a.handle.suspend().await?;
    let tried = a.transport.try_calls();
    for seq in 0..5 {
        let packet = PacketBuf::from_packet(&a.packet_to(&b, seq));
        a.handle.inject_outbound(packet).await?;
    }
    assert!(
        b.deliveries().await.is_empty(),
        "datagrams wait while suspended"
    );
    assert_eq!(a.transport.try_calls(), tried);

    a.handle.resume().await?;
    for seq in 5..10 {
        a.send(&a.packet_to(&b, seq)).await?;
    }
    b.expect_seqs(&a, 0..10).await?;
    assert!(
        a.transport.task_done() >= 5,
        "the waiting datagrams went to the task"
    );
    Ok(())
}

#[tokio::test]
async fn sink_falls_back_to_the_deliver_queue_and_counts_drops_as_before() -> TestResult {
    const DELIVER: usize = 8;
    let net = Net::default();
    let mut a = Node::new(&net, 1, |b| b)?;
    let mut b = Node::new(&net, 2, |b| b.queue_capacity(DELIVER))?;
    connect(&mut a, &mut b).await?;
    let mut next = 0;
    let mut received = b.received_from(&a).await?;

    // One packet per try: the rest goes through the deliver queue, in order.
    b.sink.set_mode(Mode::Partial);
    for seq in next..next + 100 {
        a.send(&a.packet_to(&b, seq)).await?;
    }
    b.expect_seqs(&a, next..next + 100).await?;
    assert!(b.sink.try_done() > 0 && b.sink.task_done() > 0);
    next += 100;
    received += 100;

    // One packet per try while the sink task is stuck: once a packet is queued, later ones
    // queue behind it instead of overtaking it, and the overflow is dropped.
    b.sink.set_open(false);
    let burst = 50;
    for seq in next..next + burst {
        a.send(&a.packet_to(&b, seq)).await?;
    }
    received += u64::from(burst);
    b.wait_received(&a, received).await?;
    let full = b.drops(DROP_SINK_FULL).await?;
    b.sink.set_open(true);
    let seqs = b.deliveries().await;
    assert_eq!(
        seqs.len() as u64 + full,
        u64::from(burst),
        "every packet delivered or counted"
    );
    assert!(
        seqs.windows(2).all(|pair| pair[0] < pair[1]),
        "in order: {seqs:?}"
    );
    next += burst;

    // A sink that takes nothing: the sink task holds a batch, the deliver queue fills and
    // the received datagrams wait in the transport instead of being dropped.
    b.sink.set_mode(Mode::Block);
    b.sink.set_open(false);
    let burst = 300;
    for seq in next..next + burst {
        a.send(&a.packet_to(&b, seq)).await?;
    }
    received += u64::from(burst);
    b.wait_received(&a, received).await?;
    let full = b.drops(DROP_SINK_FULL).await? - full;
    assert_eq!(full, 0);
    b.sink.set_mode(Mode::Accept);
    b.sink.set_open(true);
    let seqs = b.deliveries().await;
    assert_eq!(
        seqs.len() as u64 + full,
        u64::from(burst),
        "every packet delivered or counted"
    );
    assert!(
        seqs.windows(2).all(|pair| pair[0] < pair[1]),
        "in order: {seqs:?}"
    );
    next += burst;

    // A closed sink: the packet that found it closed is lost, later ones are counted.
    b.sink.closed.store(true, Ordering::Relaxed);
    let tried = b.sink.try_calls();
    a.send(&a.packet_to(&b, next)).await?;
    received += 1;
    b.wait_received(&a, received).await?;
    assert_eq!(b.sink.try_calls(), tried + 1);
    for seq in next + 1..next + 5 {
        a.send(&a.packet_to(&b, seq)).await?;
    }
    received += 4;
    b.wait_received(&a, received).await?;
    assert_eq!(b.drops(DROP_SINK_CLOSED).await?, 4);
    assert_eq!(b.sink.try_calls(), tried + 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crypto_workers_keep_the_tasks_sending_and_delivering() -> TestResult {
    let net = Net::default();
    let mut a = Node::new(&net, 1, |b| b.crypto_workers(2))?;
    let mut b = Node::new(&net, 2, |b| b.crypto_workers(2))?;
    connect(&mut a, &mut b).await?;
    for seq in 0..200 {
        a.send(&a.packet_to(&b, seq)).await?;
        b.send(&b.packet_to(&a, seq)).await?;
    }
    b.expect_seqs(&a, 0..200).await?;
    a.expect_seqs(&b, 0..200).await?;
    for node in [&a, &b] {
        assert_eq!(node.transport.try_calls(), 0);
        assert_eq!(node.sink.try_calls(), 0);
        assert!(node.transport.task_done() > 200);
        assert_eq!(node.sink.task_done(), 201);
    }
    Ok(())
}

#[tokio::test]
async fn owner_hands_datagrams_to_the_transmit_task_while_input_is_waiting() -> TestResult {
    let net = Net::default();
    let mut a = Node::with_source(&net, 1, 1024, |b| b)?;
    let mut b = Node::new(&net, 2, |b| b)?;
    connect(&mut a, &mut b).await?;

    // While `a` is suspended neither its transport nor its source is read: datagrams from
    // `b` and local packets pile up. After the resume its owner finds received datagrams
    // waiting whenever it seals local packets, so it hands those to the transmit task.
    a.handle.suspend().await?;
    for seq in 0..300 {
        b.send(&b.packet_to(&a, seq)).await?;
    }
    let deadline = Instant::now() + WAIT;
    while b.transport.try_done() + b.transport.task_done() < 300 + 2 {
        assert!(Instant::now() < deadline, "b did not send everything");
        sleep(Duration::from_millis(5)).await;
    }
    for seq in 0..100 {
        a.send(&a.packet_to(&b, seq)).await?;
    }
    a.handle.take_queue_stats().await?;
    a.handle.resume().await?;
    b.expect_seqs(&a, 0..100).await?;
    a.expect_seqs(&b, 0..300).await?;
    assert!(
        a.transport.task_done() > 0,
        "the transmit task sent under load"
    );
    let stats = a.handle.queue_stats().await?;
    assert!(stats.transmit.high_water > 0, "{stats:?}");

    // Idle again, once the transmit task is done with its last batch: the owner sends
    // itself.
    sleep(QUIET).await;
    let sent = a.transport.try_done();
    a.send(&a.packet_to(&b, 100)).await?;
    b.expect_seqs(&a, 100..101).await?;
    assert_eq!(a.transport.try_done(), sent + 1);
    Ok(())
}

#[tokio::test]
async fn backoff_bounds_the_tries_on_a_transport_and_sink_that_take_nothing() -> TestResult {
    let net = Net::default();
    let mut a = Node::new(&net, 1, |b| b)?;
    let mut b = Node::new(&net, 2, |b| b)?;
    connect(&mut a, &mut b).await?;
    // Like the default `try_send_batch`: nothing is ever taken without waiting.
    a.transport.set_mode(Mode::Block);
    b.sink.set_mode(Mode::Block);
    let (transport_tries, sink_tries) = (a.transport.try_calls(), b.sink.try_calls());

    // One packet at a time, each in drains of its own on an idle transport and sink.
    let count = 300;
    for seq in 0..count {
        a.send(&a.packet_to(&b, seq)).await?;
        b.expect_seqs(&a, seq..seq + 1).await?;
    }
    // Waits of 1, 2, 4, ... drains: about log2 of the drains instead of one per packet.
    let tries = a.transport.try_calls() - transport_tries;
    assert!((1..=12).contains(&tries), "{tries} transport tries");
    let tries = b.sink.try_calls() - sink_tries;
    assert!((1..=12).contains(&tries), "{tries} sink tries");

    // Once they take again, the owner gets back to them within the longest wait and then
    // sends and delivers itself every time.
    a.transport.set_mode(Mode::Accept);
    b.sink.set_mode(Mode::Accept);
    let (sent, delivered) = (a.transport.try_done(), b.sink.try_done());
    let mut seq = count;
    while a.transport.try_done() == sent || b.sink.try_done() == delivered {
        assert!(seq < count + 2100, "no try within the longest wait");
        a.send(&a.packet_to(&b, seq)).await?;
        b.expect_seqs(&a, seq..seq + 1).await?;
        seq += 1;
    }
    let (sent, delivered) = (a.transport.try_done(), b.sink.try_done());
    for next in seq..seq + 10 {
        a.send(&a.packet_to(&b, next)).await?;
        b.expect_seqs(&a, next..next + 1).await?;
    }
    assert_eq!(a.transport.try_done(), sent + 10);
    assert_eq!(b.sink.try_done(), delivered + 10);
    Ok(())
}
