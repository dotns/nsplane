//! The packet tag and the receipt marker through the engine: the tag reaches the outbound
//! filter and the transport from every source and inject call, and the sink from the inbound
//! side; the engine clears the marker on every packet it takes in or hands out, and both on
//! the buffers it hands back to its source for recycling.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness"
)]

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, Ecn, Engine, EngineBuilder,
    EngineHandle, PacketBuf, PacketFilter, PacketSink, PacketSource, Path, Peer, PeerId,
    PlaintextIngress, Transport, TransportId, pipe,
};
use nsplane_core::Verdict;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep, timeout};

const WAIT: Duration = Duration::from_secs(5);
const IP_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const IP_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// A tag and a receipt marker as seen somewhere.
type Seen = (Option<NonZeroU64>, bool);

const fn tag(value: u64) -> Option<NonZeroU64> {
    NonZeroU64::new(value)
}

fn addr(i: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, i], 51820))
}

/// An IPv4 packet with a valid header checksum and an experimental protocol.
fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + payload.len()).unwrap();
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0x40, 0, 64, 253, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let sum = nsplane_packet::checksum::ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// A packet from `src` to `dst` with tag `value` and the receipt marker set.
fn tagged(src: Ipv4Addr, dst: Ipv4Addr, value: u64) -> PacketBuf {
    let mut packet = PacketBuf::from_packet(&ipv4(src, dst, &value.to_be_bytes()));
    packet.set_tag(tag(value));
    packet.set_tracked(true);
    packet
}

/// Records what the outbound and the inbound filter see; tags the inbound packets that have
/// no tag with `set_in`.
#[derive(Debug, Default)]
struct Filter {
    outbound: Mutex<Vec<Seen>>,
    inbound: Mutex<Vec<Seen>>,
    set_in: Option<NonZeroU64>,
}

#[derive(Debug)]
struct Installed(Arc<Filter>);

impl PacketFilter for Installed {
    fn inbound(&self, _peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let seen = (packet.tag(), packet.is_tracked());
        self.0.inbound.lock().unwrap().push(seen);
        if packet.tag().is_none() {
            packet.set_tag(self.0.set_in);
        }
        Verdict::Accept
    }

    fn outbound(&self, _peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let seen = (packet.tag(), packet.is_tracked());
        self.0.outbound.lock().unwrap().push(seen);
        Verdict::Accept
    }
}

/// A channel transport that records the tag and marker of every data message carrying a
/// packet (type 4, longer than a keepalive) the engine offers it, on the owner task (`try_send_batch`, which hands nothing off here) and
/// on the transmit task (`send_batch`).
struct Recording {
    inner: ChannelTransport,
    offered: Arc<Mutex<Vec<Seen>>>,
    sent: Arc<Mutex<Vec<Seen>>>,
}

fn record(log: &Mutex<Vec<Seen>>, datagrams: &[(Path, PacketBuf)]) {
    // A keepalive is the 16-byte header and the 16-byte AEAD tag.
    let data = datagrams
        .iter()
        .filter(|(_, d)| d.as_packet()[0] == 4 && d.len() > 32);
    log.lock()
        .unwrap()
        .extend(data.map(|(_, d)| (d.tag(), d.is_tracked())));
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
        record(&self.sent, &datagrams[*sent..]);
        while let Some((path, data)) = datagrams.get(*sent) {
            let result = self.inner.send(data.as_packet(), path).await;
            *sent += 1;
            result.inspect_err(|_| *failed += 1)?;
        }
        Ok(())
    }

    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        _failed: &mut usize,
    ) -> io::Result<()> {
        record(&self.offered, &datagrams[*sent..]);
        Err(io::ErrorKind::WouldBlock.into())
    }
}

/// A source wrapper that records the tag and marker of every buffer handed back to it, and
/// keeps them.
struct Recycled<S> {
    inner: S,
    kept: Vec<PacketBuf>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl<S: PacketSource> PacketSource for Recycled<S> {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        self.inner.recv().await
    }

    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        let mut seen = self.seen.lock().unwrap();
        seen.extend(bufs.iter().map(|b| (b.tag(), b.is_tracked())));
        self.kept.append(bufs);
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.inner.mtu()
    }
}

/// One engine with what the tests watch.
struct Node {
    _engine: Engine,
    handle: EngineHandle,
    delivered: mpsc::Receiver<(PeerId, PacketBuf)>,
    filter: Arc<Filter>,
    offered: Arc<Mutex<Vec<Seen>>>,
    sent: Arc<Mutex<Vec<Seen>>>,
    plaintext: PlaintextIngress,
    key: PublicKey,
}

fn peer(key: PublicKey, ip: Ipv4Addr, transport: u16, at: SocketAddr) -> Peer {
    Peer {
        allowed_ips: vec![AllowedIp {
            addr: IpAddr::V4(ip),
            cidr: 32,
        }],
        path: Some(Path {
            transport: TransportId::new(transport),
            addr: at,
            ecn: Ecn::NotEct,
        }),
        ..Peer::new(key)
    }
}

fn node<S: PacketSource>(
    seed: u8,
    source: S,
    transport: ChannelTransport,
    filter: Filter,
    workers: usize,
) -> Node {
    let (sink, delivered) = ChannelSink::new(64);
    let filter = Arc::new(filter);
    let (offered, sent) = (Arc::default(), Arc::default());
    let transport = Recording {
        inner: transport,
        offered: Arc::clone(&offered),
        sent: Arc::clone(&sent),
    };
    let secret = StaticSecret::from([seed; 32]);
    let (builder, plaintext) = EngineBuilder::new(source, sink).plaintext_ingress(16);
    let engine = builder
        .transport(transport)
        .private_key(secret.clone())
        .filter(Box::new(Installed(Arc::clone(&filter))))
        .crypto_workers(workers)
        .build()
        .unwrap();
    Node {
        handle: engine.handle(),
        _engine: engine,
        delivered,
        filter,
        offered,
        sent,
        plaintext,
        key: PublicKey::from(&secret),
    }
}

/// Engine `a` on `source` and engine `b` on a channel source, peered, with a session up and
/// the logs cleared; `b` tags what its inbound filter sees untagged with 42. `warm` sends a
/// packet into `a`'s source.
async fn pair<S: PacketSource>(
    source: S,
    workers: usize,
    warm: impl Fn(PacketBuf),
) -> (Node, Node) {
    let (ta, tb) = ChannelTransport::pair(
        64,
        (TransportId::new(1), addr(1)),
        (TransportId::new(2), addr(2)),
    );
    let a = node(1, source, ta, Filter::default(), workers);
    let (b_source, _b_local, _) = ChannelSource::new(4, 1420);
    let b_filter = Filter {
        set_in: tag(42),
        ..Filter::default()
    };
    let b = node(2, b_source, tb, b_filter, workers);
    a.handle
        .add_or_update_peer(peer(b.key, IP_B, 1, addr(2)))
        .await
        .unwrap();
    b.handle
        .add_or_update_peer(peer(a.key, IP_A, 2, addr(1)))
        .await
        .unwrap();
    // The first packet waits behind the handshake in the tunnel's queue, which keeps bytes
    // only: it goes out untagged.
    let mut b = b;
    warm(PacketBuf::from_packet(&ipv4(IP_A, IP_B, b"warm")));
    delivery(&mut b).await;
    for log in [&a.filter.outbound, &b.filter.inbound, &a.sent, &a.offered] {
        log.lock().unwrap().clear();
    }
    (a, b)
}

async fn delivery(node: &mut Node) -> (PeerId, PacketBuf) {
    timeout(WAIT, node.delivered.recv())
        .await
        .expect("no delivery")
        .expect("sink closed")
}

/// Waits until `log` holds `len` entries and returns them.
async fn logged(log: &Mutex<Vec<Seen>>, len: usize) -> Vec<Seen> {
    let deadline = Instant::now() + WAIT;
    loop {
        let seen = log.lock().unwrap().clone();
        if seen.len() >= len {
            return seen;
        }
        assert!(Instant::now() < deadline, "{seen:?}");
        sleep(Duration::from_millis(10)).await;
    }
}

/// Sends tagged, marked packets 1 to 3 through `send` and checks what the filter, the
/// transport and the receiving sink see: the tag up to the transport, no marker anywhere,
/// and on the receiving side only the inbound filter's tag.
async fn check_outbound<S: PacketSource>(
    source: S,
    workers: usize,
    send: impl Fn(PacketBuf) + Sync,
) {
    let (a, mut b) = pair(source, workers, &send).await;
    for value in 1..=3 {
        send(tagged(IP_A, IP_B, value));
        let (_, packet) = delivery(&mut b).await;
        assert_eq!(packet.as_packet()[20..], value.to_be_bytes());
        // Received from the wire untagged; tagged by `b`'s inbound filter; delivered
        // unmarked.
        assert_eq!((packet.tag(), packet.is_tracked()), (tag(42), false));
    }
    let expected = [(tag(1), false), (tag(2), false), (tag(3), false)];
    assert_eq!(*a.filter.outbound.lock().unwrap(), expected);
    assert_eq!(*b.filter.inbound.lock().unwrap(), [(None, false); 3]);
    // Every data message the transport was offered or sent carries its packet's tag.
    let mut sent = logged(&a.sent, 3).await;
    sent.extend(a.offered.lock().unwrap().iter());
    for value in 1..=3 {
        assert!(sent.contains(&(tag(value), false)), "{sent:?}");
    }
    assert!(
        sent.iter().all(|seen| seen.0.is_some() && !seen.1),
        "{sent:?}"
    );
}

#[tokio::test]
async fn the_tag_goes_from_a_channel_source_to_the_filter_and_the_transport() {
    for workers in [0, 2] {
        let (source, local, _mtu) = ChannelSource::new(4, 1420);
        check_outbound(source, workers, |packet| local.try_send(packet).unwrap()).await;
    }
}

#[tokio::test]
async fn the_tag_goes_from_a_pipe_source_to_the_filter_and_the_transport() {
    for workers in [0, 2] {
        let (sink, source) = pipe(4, 1420);
        check_outbound(source, workers, |packet| {
            let mut one = VecDeque::from([(PeerId::new(1), packet)]);
            sink.try_send_batch(&mut one).unwrap();
        })
        .await;
    }
}

#[tokio::test]
async fn inject_calls_keep_the_tag_and_clear_the_marker() {
    let (source, local, _mtu) = ChannelSource::new(4, 1420);
    let (a, mut b) = pair(source, 0, |p| local.try_send(p).unwrap()).await;
    a.handle
        .inject_outbound(tagged(IP_A, IP_B, 1))
        .await
        .unwrap();
    delivery(&mut b).await;
    let to_b = a.handle.peer_id(b.key).await.unwrap().unwrap();
    let path = peer(b.key, IP_B, 1, addr(2)).path.unwrap();
    a.handle
        .inject_outbound_on(to_b, path, tagged(IP_A, IP_B, 2))
        .await
        .unwrap();
    delivery(&mut b).await;
    let mut seen = logged(&a.sent, 2).await;
    seen.extend(a.offered.lock().unwrap().iter());
    assert!(seen.contains(&(tag(1), false)), "{seen:?}");
    assert!(seen.contains(&(tag(2), false)), "{seen:?}");
    assert!(seen.iter().all(|seen| !seen.1), "{seen:?}");

    // Inbound: delivered with the tag, unmarked.
    let from_a = b.handle.peer_id(a.key).await.unwrap().unwrap();
    b.handle
        .inject_inbound(from_a, tagged(IP_A, IP_B, 3))
        .await
        .unwrap();
    let (from, packet) = delivery(&mut b).await;
    assert_eq!(from, from_a);
    assert_eq!((packet.tag(), packet.is_tracked()), (tag(3), false));
}

#[tokio::test]
async fn plaintext_ingress_keeps_the_tag_and_clears_the_marker() {
    let (source, local, _mtu) = ChannelSource::new(4, 1420);
    let (a, mut b) = pair(source, 0, |p| local.try_send(p).unwrap()).await;
    let from_a = b.handle.peer_id(a.key).await.unwrap().unwrap();
    let from = peer(a.key, IP_A, 2, addr(1)).path.unwrap();
    b.plaintext
        .send(from_a, from, tagged(IP_A, IP_B, 5))
        .await
        .unwrap();
    let (_, packet) = delivery(&mut b).await;
    assert_eq!((packet.tag(), packet.is_tracked()), (tag(5), false));
    // The inbound filter saw the tag, not the marker.
    assert_eq!(*b.filter.inbound.lock().unwrap(), [(tag(5), false)]);
}

#[tokio::test]
async fn recycled_buffers_reach_the_source_untagged_and_unmarked() {
    for workers in [0, 2] {
        let (inner, local, _mtu) = ChannelSource::new(4, 1420);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let source = Recycled {
            inner,
            kept: Vec::new(),
            seen: Arc::clone(&seen),
        };
        let warm = |p| local.try_send(p).unwrap();
        let (_a, mut b) = pair(source, workers, warm).await;
        // The source task hands the buffers back before its next read.
        for value in 1..=8 {
            local.send(tagged(IP_A, IP_B, value)).await.unwrap();
            delivery(&mut b).await;
        }
        let seen = logged(&seen, 1).await;
        assert!(seen.iter().all(|seen| *seen == (None, false)), "{seen:?}");
    }
}
