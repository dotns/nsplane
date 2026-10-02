//! `PacketBatch` end to end: engines whose source, sink and transport implement the batch
//! methods move a burst in fewer calls than packets in both directions, in order per peer
//! and intact; a source, sink and transport implementing only the single methods take the
//! default path and interoperate; removing or replacing a transport while a batch is half
//! sent counts or moves every datagram, in order.
//!
//! The nodes share one in-memory switch: every transport port has an address and delivers
//! to the port registered under the destination address, so one transport reaches several
//! peers. The test doubles count their calls and the packets they move.

use std::collections::{HashMap, VecDeque};
use std::future::ready;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, DROP_NO_TRANSPORT, DROP_TRANSMIT_FULL, DROP_TRANSPORT_REMOVED, Ecn, Engine,
    EngineBuilder, EngineHandle, MAX_BATCH, PacketBatch, PacketBuf, PacketSink, PacketSource, Path,
    Peer, PeerId, Transport, TransportId,
};
use nsplane_e2e::{MTU, QUIET, TestResult, WAIT, udp4};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep, timeout};

/// Every node's only transport.
const LINK: TransportId = TransportId::new(1);
/// Packets each source queues; more than any burst, so a burst is handed over at once.
const SOURCE_CAPACITY: usize = 1024;
/// Packets per burst and sender.
const BURST: usize = 2 * MAX_BATCH;
/// Datagrams a stalling transport sends from the batch it stalls in.
const STALL_AFTER: usize = 5;

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "closed")
}

/// Calls of one direction of a test double and the packets they moved.
#[derive(Debug, Default)]
struct Calls {
    single: AtomicUsize,
    batch: AtomicUsize,
    packets: AtomicUsize,
}

impl Calls {
    fn single(&self) {
        self.single.fetch_add(1, Ordering::Relaxed);
        self.packets.fetch_add(1, Ordering::Relaxed);
    }

    fn batch(&self, packets: usize) {
        self.batch.fetch_add(1, Ordering::Relaxed);
        self.packets.fetch_add(packets, Ordering::Relaxed);
    }

    /// `(single calls, batch calls, packets)` so far.
    fn get(&self) -> (usize, usize, usize) {
        (
            self.single.load(Ordering::Relaxed),
            self.batch.load(Ordering::Relaxed),
            self.packets.load(Ordering::Relaxed),
        )
    }
}

/// The calls of one node's I/O, by direction.
#[derive(Debug, Default, Clone)]
struct Io {
    source: Arc<Calls>,
    sink: Arc<Calls>,
    recv: Arc<Calls>,
    send: Arc<Calls>,
}

/// A source on a channel that reads every queued packet into a batch.
#[derive(Debug)]
struct TestSource {
    rx: mpsc::Receiver<PacketBuf>,
    mtu: watch::Receiver<u16>,
    calls: Arc<Calls>,
}

impl PacketSource for TestSource {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        let packet = self.rx.recv().await.ok_or_else(closed)?;
        self.calls.single();
        Ok(packet)
    }

    async fn recv_batch(&mut self, batch: &mut PacketBatch) -> io::Result<()> {
        let mut next = Some(self.rx.recv().await.ok_or_else(closed)?);
        let before = batch.len();
        while let Some(packet) = next.take() {
            if let Err(packet) = batch.push(packet) {
                return Err(io::Error::other(format!(
                    "batch overflow with {} bytes",
                    packet.len()
                )));
            }
            if !batch.is_full() {
                next = self.rx.try_recv().ok();
            }
        }
        self.calls.batch(batch.len() - before);
        Ok(())
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu.clone()
    }
}

/// A sink into an unbounded channel that delivers a whole batch per call.
#[derive(Debug)]
struct TestSink {
    tx: mpsc::UnboundedSender<(PeerId, PacketBuf)>,
    calls: Arc<Calls>,
}

impl PacketSink for TestSink {
    fn send(&self, packet: PacketBuf, from: PeerId) -> impl Future<Output = io::Result<()>> + Send {
        self.calls.single();
        ready(self.tx.send((from, packet)).map_err(|_| closed()))
    }

    fn send_batch(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        self.calls.batch(packets.len());
        let delivered = packets
            .drain(..)
            .try_for_each(|packet| self.tx.send(packet).map_err(|_| closed()));
        ready(delivered)
    }
}

/// Makes a port stall once, in the middle of a batch.
#[derive(Debug, Default)]
struct Gate {
    armed: AtomicBool,
    /// Datagrams sent from the batch before the stall and datagrams left in it.
    stalled: Mutex<Option<(usize, usize)>>,
}

impl Gate {
    fn stalled(&self) -> Option<(usize, usize)> {
        *self.stalled.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

type Inbox = mpsc::UnboundedSender<(SocketAddr, PacketBuf)>;

/// Ports by address; a datagram to an unknown address is dropped.
#[derive(Debug, Default, Clone)]
struct Switch(Arc<Mutex<HashMap<SocketAddr, Inbox>>>);

impl Switch {
    /// A port at `addr`, replacing any port there.
    fn attach(&self, addr: SocketAddr, io: &Io, gate: Arc<Gate>) -> Port {
        let (tx, rx) = mpsc::unbounded_channel();
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(addr, tx);
        Port {
            addr,
            switch: self.clone(),
            inbox: tokio::sync::Mutex::new(rx),
            recv_calls: Arc::clone(&io.recv),
            send_calls: Arc::clone(&io.send),
            gate,
        }
    }

    fn forward(&self, from: SocketAddr, datagram: &[u8], to: &Path) {
        let ports = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(inbox) = ports.get(&to.addr) {
            // A port that is gone drops the datagram, like UDP to nowhere.
            let _ = inbox.send((from, PacketBuf::from_packet(datagram)));
        }
    }
}

/// A transport port on the switch that receives and sends whole batches.
#[derive(Debug)]
struct Port {
    addr: SocketAddr,
    switch: Switch,
    inbox: tokio::sync::Mutex<mpsc::UnboundedReceiver<(SocketAddr, PacketBuf)>>,
    recv_calls: Arc<Calls>,
    send_calls: Arc<Calls>,
    gate: Arc<Gate>,
}

const fn at(addr: SocketAddr) -> Path {
    Path {
        transport: LINK,
        addr,
        ecn: Ecn::NotEct,
    }
}

impl Transport for Port {
    fn id(&self) -> TransportId {
        LINK
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        let (from, datagram) = self.inbox.lock().await.recv().await.ok_or_else(closed)?;
        buf.set_len(datagram.len());
        buf.as_packet_mut().copy_from_slice(datagram.as_packet());
        self.recv_calls.single();
        Ok((datagram.len(), at(from)))
    }

    fn send(&self, datagram: &[u8], to: &Path) -> impl Future<Output = io::Result<()>> + Send {
        self.send_calls.single();
        self.switch.forward(self.addr, datagram, to);
        ready(Ok(()))
    }

    async fn recv_batch(
        &self,
        _buf: &mut PacketBuf,
        datagrams: &mut VecDeque<(Path, PacketBuf)>,
    ) -> io::Result<()> {
        let mut inbox = self.inbox.lock().await;
        let before = datagrams.len();
        let (from, first) = inbox.recv().await.ok_or_else(closed)?;
        datagrams.push_back((at(from), first));
        while datagrams.len() < MAX_BATCH {
            let Ok((from, next)) = inbox.try_recv() else {
                break;
            };
            datagrams.push_back((at(from), next));
        }
        self.recv_calls.batch(datagrams.len() - before);
        Ok(())
    }

    async fn send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
    ) -> io::Result<()> {
        let start = *sent;
        let stall_at = start + STALL_AFTER.min(datagrams.len().saturating_sub(start + 1));
        self.send_calls.batch(0);
        while let Some((path, data)) = datagrams.get(*sent) {
            if *sent == stall_at && *sent > start && self.gate.armed.swap(false, Ordering::Relaxed)
            {
                *self
                    .gate
                    .stalled
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) =
                    Some((*sent - start, datagrams.len() - *sent));
                std::future::pending::<()>().await;
            }
            self.switch.forward(self.addr, data.as_packet(), path);
            self.send_calls.packets.fetch_add(1, Ordering::Relaxed);
            *sent += 1;
        }
        Ok(())
    }
}

/// Hides the batch methods of a source, sink or transport, so the engine gets the defaults.
#[derive(Debug)]
struct Single<T>(T);

impl PacketSource for Single<TestSource> {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        self.0.recv().await
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.0.mtu()
    }
}

impl PacketSink for Single<TestSink> {
    async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
        self.0.send(packet, from).await
    }
}

impl Transport for Single<Port> {
    fn id(&self) -> TransportId {
        self.0.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        self.0.recv(buf).await
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        self.0.send(datagram, to).await
    }
}

/// Whether a node's I/O implements the batch methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Batched,
    Single,
}

/// One engine on the switch with the test ends of its source and sink.
#[derive(Debug)]
struct Host {
    _engine: Engine,
    handle: EngineHandle,
    local: mpsc::Sender<PacketBuf>,
    delivered: mpsc::UnboundedReceiver<(PeerId, PacketBuf)>,
    seed: u8,
    ip4: Ipv4Addr,
    addr: SocketAddr,
    io: Io,
    gate: Arc<Gate>,
}

fn start<Src: PacketSource, Snk: PacketSink, T: Transport>(
    seed: u8,
    source: Src,
    sink: Snk,
    transport: T,
) -> TestResult<Engine> {
    Ok(EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([seed; 32]))
        .transport(transport)
        .build()?)
}

impl Host {
    /// A node with key seed `seed` at `192.0.2.<seed>:1000` and tunnel address
    /// `10.0.0.<seed>`.
    fn new(seed: u8, switch: &Switch, mode: Mode) -> TestResult<Self> {
        let io = Io::default();
        let addr = SocketAddr::from(([192, 0, 2, seed], 1000));
        let (local, rx) = mpsc::channel(SOURCE_CAPACITY);
        // The MTU never changes; the engine keeps the value once the sender is gone.
        let (_, mtu) = watch::channel(MTU);
        let source = TestSource {
            rx,
            mtu,
            calls: Arc::clone(&io.source),
        };
        let (tx, delivered) = mpsc::unbounded_channel();
        let sink = TestSink {
            tx,
            calls: Arc::clone(&io.sink),
        };
        let gate = Arc::new(Gate::default());
        let port = switch.attach(addr, &io, Arc::clone(&gate));
        let engine = match mode {
            Mode::Batched => start(seed, source, sink, port)?,
            Mode::Single => start(seed, Single(source), Single(sink), Single(port))?,
        };
        Ok(Self {
            handle: engine.handle(),
            _engine: engine,
            local,
            delivered,
            seed,
            ip4: Ipv4Addr::new(10, 0, 0, seed),
            addr,
            io,
            gate,
        })
    }

    fn public(&self) -> PublicKey {
        PublicKey::from(&StaticSecret::from([self.seed; 32]))
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

    /// The packet number `seq` of a burst from this node to `to`; its size varies with
    /// `seq`.
    fn numbered(&self, to: &Self, seq: usize) -> Vec<u8> {
        let mut data = vec![self.seed; 16 + seq * 37 % 1300];
        data[..8].copy_from_slice(&(seq as u64).to_be_bytes());
        udp4(self.ip4, to.ip4, &data)
    }

    /// Hands every packet to the source at once, without yielding in between.
    fn queue(&self, packets: &[Vec<u8>]) -> TestResult {
        for packet in packets {
            self.local.try_send(PacketBuf::from_packet(packet))?;
        }
        Ok(())
    }

    /// The next `count` delivered packets with the peers they came from.
    async fn delivered(&mut self, count: usize) -> TestResult<Vec<(PeerId, Vec<u8>)>> {
        let mut delivered = Vec::with_capacity(count);
        while delivered.len() < count {
            match timeout(WAIT, self.delivered.recv()).await {
                Ok(Some((peer, packet))) => delivered.push((peer, packet.as_packet().to_vec())),
                Ok(None) => return Err("sink closed".into()),
                Err(_) => {
                    return Err(
                        format!("{} of {count} packets within {WAIT:?}", delivered.len()).into(),
                    );
                }
            }
        }
        Ok(delivered)
    }

    async fn expect_no_delivery(&mut self) -> TestResult {
        match timeout(QUIET, self.delivered.recv()).await {
            Ok(Some((peer, _))) => Err(format!("unexpected delivery from {peer:?}").into()),
            Ok(None) => Err("sink closed".into()),
            Err(_) => Ok(()),
        }
    }
}

/// Makes `a` and `b` peers of each other on [`LINK`] and completes the handshake.
async fn link(a: &mut Host, b: &mut Host) -> TestResult {
    for (from, to) in [(&*a, &*b), (&*b, &*a)] {
        from.handle
            .add_or_update_peer(Peer {
                allowed_ips: vec![AllowedIp {
                    addr: to.ip4.into(),
                    cidr: 32,
                }],
                path: Some(at(to.addr)),
                ..Peer::new(to.public())
            })
            .await?;
    }
    let packet = a.numbered(b, 0);
    a.queue(std::slice::from_ref(&packet))?;
    if b.delivered(1).await?[0].1 != packet {
        return Err("handshake packet changed".into());
    }
    let packet = b.numbered(a, 0);
    b.queue(std::slice::from_ref(&packet))?;
    if a.delivered(1).await?[0].1 != packet {
        return Err("handshake packet changed".into());
    }
    Ok(())
}

/// Checks that `delivered` holds exactly the packets of `expected`, attributed to the right
/// peer and, per peer, in order.
fn check_per_peer(
    delivered: &[(PeerId, Vec<u8>)],
    expected: &[(PeerId, Vec<Vec<u8>>)],
) -> TestResult {
    let total: usize = expected.iter().map(|(_, packets)| packets.len()).sum();
    if delivered.len() != total {
        return Err(format!("{} packets delivered, {total} expected", delivered.len()).into());
    }
    for (peer, packets) in expected {
        let from_peer: Vec<&Vec<u8>> = delivered
            .iter()
            .filter(|(from, _)| from == peer)
            .map(|(_, packet)| packet)
            .collect();
        if from_peer.len() != packets.len() {
            return Err(format!(
                "{} packets from {peer:?}, {} sent",
                from_peer.len(),
                packets.len()
            )
            .into());
        }
        if let Some(seq) = (0..packets.len()).find(|&seq| *from_peer[seq] != packets[seq]) {
            return Err(format!("packet {seq} from {peer:?} lost, changed or out of order").into());
        }
    }
    Ok(())
}

/// What `calls` did since `before`: `(single calls, batch calls, packets)`.
fn since(calls: &Calls, before: (usize, usize, usize)) -> (usize, usize, usize) {
    let now = calls.get();
    (now.0 - before.0, now.1 - before.1, now.2 - before.2)
}

/// Checks that `packets` crossed `what` in batch calls only, fewer calls than packets.
fn batched(what: &str, calls: (usize, usize, usize), packets: usize) -> TestResult {
    let (single, batch, moved) = calls;
    if single != 0 || moved != packets || batch == 0 || batch >= packets {
        return Err(format!(
            "{what}: {packets} packets moved as {moved} in {batch} batch and {single} single calls"
        )
        .into());
    }
    Ok(())
}

#[tokio::test]
async fn bursts_cross_in_batches_in_order_per_peer() -> TestResult {
    let switch = Switch::default();
    let mut hub = Host::new(1, &switch, Mode::Batched)?;
    let mut x = Host::new(2, &switch, Mode::Batched)?;
    let mut y = Host::new(3, &switch, Mode::Batched)?;
    link(&mut hub, &mut x).await?;
    link(&mut hub, &mut y).await?;
    let (hub_x, hub_y) = (hub.peer_of(&x).await?, hub.peer_of(&y).await?);
    let (x_hub, y_hub) = (x.peer_of(&hub).await?, y.peer_of(&hub).await?);

    // Out: one burst from the hub, interleaved between `x` and `y`.
    let before = [&hub.io, &x.io, &y.io]
        .map(|io| [&io.source, &io.sink, &io.recv, &io.send].map(|calls| calls.get()));
    let to_x: Vec<_> = (0..BURST).map(|seq| hub.numbered(&x, seq)).collect();
    let to_y: Vec<_> = (0..BURST).map(|seq| hub.numbered(&y, seq)).collect();
    let interleaved: Vec<_> = to_x
        .iter()
        .zip(&to_y)
        .flat_map(|(a, b)| [a.clone(), b.clone()])
        .collect();
    hub.queue(&interleaved)?;
    check_per_peer(&x.delivered(BURST).await?, &[(x_hub, to_x)])?;
    check_per_peer(&y.delivered(BURST).await?, &[(y_hub, to_y)])?;
    batched("hub source", since(&hub.io.source, before[0][0]), 2 * BURST)?;
    batched(
        "hub transport send",
        since(&hub.io.send, before[0][3]),
        2 * BURST,
    )?;
    for (node, before) in [(&x, before[1]), (&y, before[2])] {
        batched(
            "peer transport receive",
            since(&node.io.recv, before[2]),
            BURST,
        )?;
        batched("peer sink", since(&node.io.sink, before[1]), BURST)?;
    }

    // In: `x` and `y` each send a burst to the hub at once.
    let before = [&hub.io, &x.io, &y.io]
        .map(|io| [&io.source, &io.sink, &io.recv, &io.send].map(|calls| calls.get()));
    let from_x: Vec<_> = (0..BURST).map(|seq| x.numbered(&hub, seq)).collect();
    let from_y: Vec<_> = (0..BURST).map(|seq| y.numbered(&hub, seq)).collect();
    x.queue(&from_x)?;
    y.queue(&from_y)?;
    check_per_peer(
        &hub.delivered(2 * BURST).await?,
        &[(hub_x, from_x), (hub_y, from_y)],
    )?;
    for (node, before) in [(&x, before[1]), (&y, before[2])] {
        batched("peer source", since(&node.io.source, before[0]), BURST)?;
        batched(
            "peer transport send",
            since(&node.io.send, before[3]),
            BURST,
        )?;
    }
    batched(
        "hub transport receive",
        since(&hub.io.recv, before[0][2]),
        2 * BURST,
    )?;
    batched("hub sink", since(&hub.io.sink, before[0][1]), 2 * BURST)?;
    Ok(())
}

#[tokio::test]
async fn single_methods_take_the_default_path() -> TestResult {
    let switch = Switch::default();
    let mut batched_node = Host::new(1, &switch, Mode::Batched)?;
    let mut single = Host::new(2, &switch, Mode::Single)?;
    link(&mut batched_node, &mut single).await?;
    let to_single = batched_node.peer_of(&single).await?;
    let to_batched = single.peer_of(&batched_node).await?;

    let out: Vec<_> = (0..BURST)
        .map(|seq| batched_node.numbered(&single, seq))
        .collect();
    let back: Vec<_> = (0..BURST)
        .map(|seq| single.numbered(&batched_node, seq))
        .collect();
    batched_node.queue(&out)?;
    single.queue(&back)?;
    check_per_peer(&single.delivered(BURST).await?, &[(to_batched, out)])?;
    check_per_peer(&batched_node.delivered(BURST).await?, &[(to_single, back)])?;

    // The single-method node moved every packet one call at a time, the handshake's too.
    for (what, calls) in [
        ("source", &single.io.source),
        ("sink", &single.io.sink),
        ("transport receive", &single.io.recv),
        ("transport send", &single.io.send),
    ] {
        let (single_calls, batch, packets) = calls.get();
        if batch != 0 || single_calls != packets || packets < BURST {
            return Err(format!(
                "{what}: {packets} packets in {single_calls} single and {batch} batch calls"
            )
            .into());
        }
    }
    Ok(())
}

/// The hub (seed 1) linked to `x` (seed 2); then the hub's transport stalls in the middle
/// of the next batch it sends, after a burst of [`BURST`] packets to `x` was queued. Returns
/// the burst and how many of its datagrams were sent before the stall.
async fn stalled_mid_batch(switch: &Switch) -> TestResult<(Host, Host, Vec<Vec<u8>>, usize)> {
    let mut hub = Host::new(1, switch, Mode::Batched)?;
    let mut x = Host::new(2, switch, Mode::Batched)?;
    link(&mut hub, &mut x).await?;

    let sent_before = hub.io.send.get().2;
    hub.gate.armed.store(true, Ordering::Relaxed);
    let burst: Vec<_> = (0..BURST).map(|seq| hub.numbered(&x, seq)).collect();
    hub.queue(&burst)?;
    let deadline = Instant::now() + WAIT;
    let (in_batch, left) = loop {
        if let Some(stalled) = hub.gate.stalled() {
            break stalled;
        }
        if Instant::now() > deadline {
            return Err(format!("no stall within {WAIT:?}").into());
        }
        sleep(QUIET / 10).await;
    };
    if in_batch == 0 || left == 0 {
        return Err(format!("stalled with {in_batch} sent and {left} left, not mid-batch").into());
    }
    let sent = hub.io.send.get().2 - sent_before;
    Ok((hub, x, burst, sent))
}

#[tokio::test]
async fn removing_a_transport_mid_batch_counts_every_datagram() -> TestResult {
    let switch = Switch::default();
    let (hub, mut x, burst, sent) = stalled_mid_batch(&switch).await?;
    let x_hub = x.peer_of(&hub).await?;
    check_per_peer(
        &x.delivered(sent).await?,
        &[(x_hub, burst[..sent].to_vec())],
    )?;

    hub.handle.remove_transport(LINK).await?;
    // Every packet of the burst became one datagram. Each one not sent was dropped while its
    // backlog was full, dropped by the removal (in the half-sent batch, the transmit queue or
    // the backlog), or reached the core after the removal and found no transport.
    let not_sent = (BURST - sent) as u64;
    let deadline = Instant::now() + WAIT;
    let counted = loop {
        let counted = (
            hub.drops(DROP_TRANSMIT_FULL).await?,
            hub.drops(DROP_TRANSPORT_REMOVED).await?,
            hub.drops(DROP_NO_TRANSPORT).await?,
        );
        if counted.0 + counted.1 + counted.2 >= not_sent || Instant::now() > deadline {
            break counted;
        }
        sleep(QUIET / 10).await;
    };
    let (full, removed, none) = counted;
    assert_eq!(
        full + removed + none,
        not_sent,
        "{not_sent} not sent: full {full}, removed {removed}, no transport {none}"
    );
    assert!(removed > 0, "nothing was counted by the removal");
    x.expect_no_delivery().await?;
    let counted_later = (
        hub.drops(DROP_TRANSMIT_FULL).await?,
        hub.drops(DROP_TRANSPORT_REMOVED).await?,
        hub.drops(DROP_NO_TRANSPORT).await?,
    );
    assert_eq!(counted_later, counted, "datagrams counted twice");
    Ok(())
}

#[tokio::test]
async fn replacing_a_transport_mid_batch_sends_every_datagram_in_order() -> TestResult {
    let switch = Switch::default();
    let (hub, mut x, burst, _) = stalled_mid_batch(&switch).await?;
    let x_hub = x.peer_of(&hub).await?;

    let port = switch.attach(hub.addr, &hub.io, Arc::new(Gate::default()));
    hub.handle.replace_transport(port).await?;
    check_per_peer(&x.delivered(BURST).await?, &[(x_hub, burst)])?;
    x.expect_no_delivery().await?;
    for reason in [
        DROP_TRANSMIT_FULL,
        DROP_TRANSPORT_REMOVED,
        DROP_NO_TRANSPORT,
    ] {
        assert_eq!(hub.drops(reason).await?, 0, "{reason}");
    }
    Ok(())
}
