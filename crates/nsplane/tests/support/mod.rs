//! Two engines on a scripted in-memory link, for the tracked-packet and plaintext-egress tests.
//!
//! Engine `a` (10.0.0.1) and engine `b` (10.0.0.2) are peers of each other. `a`'s end of the
//! link follows a [`Script`]: a gate that holds its sends, datagrams to fail by tag (an I/O
//! error or the transport closing), whether the owner task may hand datagrams to it itself
//! (`try_send_batch`), and a log of the data messages each call carried.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "shared by several test crates, each of which uses a different part of it"
)]

use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, Ecn, Engine, EngineBuilder, EngineHandle,
    FragmentConfig, PacketBuf, PacketFilter, Path, PathPolicy, Peer, PeerId, PlaintextEgress,
    SendResult, SendResults, TrackedSender, Transport, TransportId,
};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep, timeout};

pub const WAIT: Duration = Duration::from_secs(5);
pub const QUIET: Duration = Duration::from_millis(200);
pub const IP_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const IP_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub const IP_NOWHERE: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
pub const MTU: u16 = 1420;

pub const fn tag(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

pub fn addr(i: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, i], 51820))
}

/// An IPv4 packet of `len` bytes with a valid header checksum and an experimental protocol,
/// DF set with `df`.
pub fn ipv4_len(src: Ipv4Addr, dst: Ipv4Addr, len: usize, df: bool) -> Vec<u8> {
    let total = u16::try_from(len).unwrap();
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 1, if df { 0x40 } else { 0 }, 0, 64, 253, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let sum = nsplane_packet::checksum::ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.resize(len, 0xab);
    packet
}

/// An IPv4 packet carrying `payload`.
pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut packet = ipv4_len(src, dst, 20 + payload.len(), true);
    packet[20..].copy_from_slice(payload);
    packet
}

/// A packet from `a` to `dst` tagged `value`, not marked.
pub fn tagged(dst: Ipv4Addr, value: u64) -> PacketBuf {
    let mut packet = PacketBuf::from_packet(&ipv4(IP_A, dst, &value.to_be_bytes()));
    packet.set_tag(Some(tag(value)));
    packet
}

pub fn secret(seed: u8) -> StaticSecret {
    StaticSecret::from([seed; 32])
}

/// What `a`'s end of the link does.
#[derive(Debug, Default)]
pub struct ScriptState {
    /// Datagrams with these tags fail with an I/O error.
    pub fail: HashSet<u64>,
    /// A datagram with this tag fails with `BrokenPipe`, and every later call too.
    pub close_on: Option<u64>,
    pub closed: bool,
    /// The owner task may hand datagrams over itself (`try_send_batch`).
    pub inline: bool,
    /// The data messages (tag, marker) of each call, in call order.
    pub calls: Vec<Vec<(Option<u64>, bool)>>,
}

#[derive(Debug)]
pub struct Script {
    pub state: Mutex<ScriptState>,
    /// Sends wait while this is `false`.
    pub gate: watch::Sender<bool>,
}

impl Script {
    fn new(inline: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ScriptState {
                inline,
                ..ScriptState::default()
            }),
            gate: watch::Sender::new(true),
        })
    }

    pub fn fail(&self, value: u64) {
        self.state.lock().unwrap().fail.insert(value);
    }

    pub fn close_on(&self, value: u64) {
        self.state.lock().unwrap().close_on = Some(value);
    }

    pub fn hold(&self) {
        self.gate.send_replace(false);
    }

    pub fn release(&self) {
        self.gate.send_replace(true);
    }

    pub fn calls(&self) -> Vec<Vec<(Option<u64>, bool)>> {
        self.state.lock().unwrap().calls.clone()
    }
}

/// One end of an in-memory link.
pub struct Wire {
    id: TransportId,
    addr: SocketAddr,
    to_peer: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    from_peer: tokio::sync::Mutex<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
    script: Option<Arc<Script>>,
}

/// A link: `a`'s end (transport 1, scripted) and `b`'s end (transport 2).
pub fn wire(inline: bool) -> (Wire, Wire, Arc<Script>) {
    wire_ids(TransportId::new(1), TransportId::new(2), inline)
}

/// A link between `a`'s end (scripted) with id `a` and `b`'s end with id `b`.
pub fn wire_ids(a: TransportId, b: TransportId, inline: bool) -> (Wire, Wire, Arc<Script>) {
    let (to_b, from_a) = mpsc::unbounded_channel();
    let (to_a, from_b) = mpsc::unbounded_channel();
    let script = Script::new(inline);
    (
        Wire {
            id: a,
            addr: addr(1),
            to_peer: to_b,
            from_peer: tokio::sync::Mutex::new(from_b),
            script: Some(Arc::clone(&script)),
        },
        Wire {
            id: b,
            addr: addr(2),
            to_peer: to_a,
            from_peer: tokio::sync::Mutex::new(from_a),
            script: None,
        },
        script,
    )
}

/// The tag and marker of a data message carrying a packet; `None` for anything else.
fn data_message(data: &PacketBuf) -> Option<(Option<u64>, bool)> {
    (data.as_packet()[0] == 4 && data.len() > 32)
        .then(|| (data.tag().map(NonZeroU64::get), data.is_tracked()))
}

impl Wire {
    /// Hands `datagrams[*sent..]` to the peer by the script, without waiting.
    fn hand_off(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        if let Some(script) = &self.script {
            let mut state = script.state.lock().unwrap();
            let call = datagrams[*sent..]
                .iter()
                .filter_map(|(_, d)| data_message(d));
            let call = call.collect();
            state.calls.push(call);
            while let Some((_, data)) = datagrams.get(*sent) {
                let value = data.tag().map(NonZeroU64::get);
                if state.closed || (value.is_some() && value == state.close_on) {
                    state.closed = true;
                    *sent += 1;
                    *failed += 1;
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                if value.is_some_and(|v| state.fail.contains(&v)) {
                    *sent += 1;
                    *failed += 1;
                    return Err(io::Error::other("scripted failure"));
                }
                let _ = self.to_peer.send((self.addr, data.as_packet().to_vec()));
                *sent += 1;
            }
            return Ok(());
        }
        while let Some((_, data)) = datagrams.get(*sent) {
            let _ = self.to_peer.send((self.addr, data.as_packet().to_vec()));
            *sent += 1;
        }
        Ok(())
    }
}

impl Transport for Wire {
    fn id(&self) -> TransportId {
        self.id
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        let Some((from, data)) = self.from_peer.lock().await.recv().await else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        buf.set_len(data.len());
        buf.as_packet_mut().copy_from_slice(&data);
        let path = Path {
            transport: self.id,
            addr: from,
            ecn: Ecn::NotEct,
        };
        Ok((data.len(), path))
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        let mut sent = 0;
        let mut failed = 0;
        let packet = PacketBuf::from_packet(datagram);
        self.send_batch(&[(*to, packet)], &mut sent, &mut failed)
            .await
    }

    async fn send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        if let Some(script) = &self.script {
            let mut gate = script.gate.subscribe();
            let _ = gate.wait_for(|open| *open).await;
        }
        self.hand_off(datagrams, sent, failed)
    }

    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        let Some(script) = &self.script else {
            return self.hand_off(datagrams, sent, failed);
        };
        if !script.state.lock().unwrap().inline || !*script.gate.borrow() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.hand_off(datagrams, sent, failed)
    }
}

/// How `a` is built.
pub struct Setup {
    pub workers: usize,
    pub inline: bool,
    pub fragmenter: bool,
    pub filters: Vec<Box<dyn PacketFilter>>,
    pub tracked: Option<usize>,
    pub egress: Option<usize>,
    pub queue_capacity: usize,
    pub policy: Option<Box<dyn PathPolicy>>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            workers: 0,
            inline: false,
            fragmenter: false,
            filters: Vec::new(),
            tracked: Some(64),
            egress: None,
            queue_capacity: 1024,
            policy: None,
        }
    }
}

/// An engine and the test ends of its queues.
pub struct Node {
    pub engine: Option<Engine>,
    pub handle: EngineHandle,
    pub local: mpsc::Sender<PacketBuf>,
    pub delivered: mpsc::Receiver<(PeerId, PacketBuf)>,
    pub tracked: Option<TrackedSender>,
    pub results: Option<SendResults>,
    pub egress: Option<PlaintextEgress>,
    _mtu: watch::Sender<u16>,
    pub secret: StaticSecret,
    pub ip: Ipv4Addr,
    pub addr: SocketAddr,
    pub transport: TransportId,
}

impl Node {
    pub fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// This node as a peer of a node that reaches it on `via`.
    pub fn as_peer(&self, via: TransportId) -> Peer {
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

    pub async fn peer_of(&self, other: &Self) -> PeerId {
        self.handle
            .peer_id(other.public())
            .await
            .unwrap()
            .expect("unknown peer")
    }

    pub async fn drops(&self, reason: &str) -> u64 {
        let counters = self.handle.drop_counters().await.unwrap();
        counters.get(reason).copied().unwrap_or(0)
    }

    /// Accepts `packet` on the tracked sender.
    pub async fn track(&self, packet: PacketBuf) {
        self.tracked.as_ref().unwrap().send(packet).await.unwrap();
    }

    /// The next result.
    pub async fn result(&mut self) -> SendResult {
        let results = self.results.as_mut().unwrap();
        timeout(WAIT, results.recv())
            .await
            .expect("no result")
            .expect("results ended")
    }

    /// Waits until no result comes for a while.
    pub async fn no_result(&mut self) {
        let results = self.results.as_mut().unwrap();
        assert!(timeout(QUIET, results.recv()).await.is_err());
    }

    pub async fn expect_delivery(&mut self) -> (PeerId, Vec<u8>) {
        let (peer, packet) = timeout(WAIT, self.delivered.recv())
            .await
            .expect("no delivery")
            .expect("sink closed");
        (peer, packet.as_packet().to_vec())
    }

    pub async fn expect_no_delivery(&mut self) {
        assert!(timeout(QUIET, self.delivered.recv()).await.is_err());
    }

    /// Sends a packet from the source.
    pub async fn send(&self, packet: PacketBuf) {
        self.local.send(packet).await.unwrap();
    }
}

/// An engine with private key `seed` at `ip`, on `transport` only.
pub fn node_on<T: Transport>(seed: u8, ip: Ipv4Addr, transport: T, setup: Setup) -> Node {
    let id = transport.id();
    node(seed, ip, transport, id, setup)
}

fn node<T: Transport>(
    seed: u8,
    ip: Ipv4Addr,
    transport: T,
    transport_id: TransportId,
    setup: Setup,
) -> Node {
    let (source, local, mtu) = ChannelSource::new(64, MTU);
    let (sink, delivered) = ChannelSink::new(64);
    let mut builder = EngineBuilder::new(source, sink)
        .transport(transport)
        .private_key(secret(seed))
        .queue_capacity(setup.queue_capacity)
        .crypto_workers(setup.workers);
    for filter in setup.filters {
        builder = builder.filter(filter);
    }
    if let Some(policy) = setup.policy {
        builder = builder.policy(policy);
    }
    if setup.fragmenter {
        builder = builder.fragmenter(FragmentConfig::default());
    }
    let (mut tracked, mut results, mut egress) = (None, None, None);
    if let Some(capacity) = setup.tracked {
        let (b, sender, receiver) = builder.tracked_sender(capacity);
        builder = b;
        tracked = Some(sender);
        results = Some(receiver);
    }
    if let Some(capacity) = setup.egress {
        let (b, receiver) = builder.plaintext_egress(capacity);
        builder = b;
        egress = Some(receiver);
    }
    let engine = builder.build().unwrap();
    Node {
        handle: engine.handle(),
        engine: Some(engine),
        local,
        delivered,
        tracked,
        results,
        egress,
        _mtu: mtu,
        secret: secret(seed),
        ip,
        addr: addr(seed),
        transport: transport_id,
    }
}

/// Engines `a` (built by `setup`) and `b`, peers of each other, without a session.
pub async fn pair(setup: Setup) -> (Node, Node, Arc<Script>) {
    let (wa, wb, script) = wire(setup.inline);
    let a = node(1, IP_A, wa, TransportId::new(1), setup);
    let b = node(
        2,
        IP_B,
        wb,
        TransportId::new(2),
        Setup {
            tracked: None,
            ..Setup::default()
        },
    );
    a.handle
        .add_or_update_peer(b.as_peer(a.transport))
        .await
        .unwrap();
    b.handle
        .add_or_update_peer(a.as_peer(b.transport))
        .await
        .unwrap();
    (a, b, script)
}

/// [`pair`] with a session up.
pub async fn connected(setup: Setup) -> (Node, Node, Arc<Script>) {
    let (a, mut b, script) = pair(setup).await;
    let peer = a.peer_of(&b).await;
    a.handle.force_handshake(peer, None).await.unwrap();
    eventually(|| async { a.handle.peer_has_session(peer).await.unwrap() == Some(true) }).await;
    // Drain whatever `b` delivered meanwhile.
    while b.delivered.try_recv().is_ok() {}
    (a, b, script)
}

/// Waits until `condition` holds, polling it.
pub async fn eventually<F: Future<Output = bool>>(mut condition: impl FnMut() -> F) {
    let deadline = Instant::now() + WAIT;
    while !condition().await {
        assert!(Instant::now() < deadline, "condition not reached");
        sleep(Duration::from_millis(10)).await;
    }
}

/// Collects `n` results.
pub async fn results(a: &mut Node, n: usize) -> VecDeque<SendResult> {
    let mut out = VecDeque::new();
    for _ in 0..n {
        out.push_back(a.result().await);
    }
    out
}
