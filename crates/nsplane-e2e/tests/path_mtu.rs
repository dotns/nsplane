//! Per-path MTU ceilings between engines over channel transports with a fragmenter installed:
//! a router in front of node 1's link to node 2 drops a datagram above a new outer limit and
//! reports the limit (quoting the datagram) through the transport's path MTU feed, so node
//! 1's inner MTU for node 2 follows the path (`peer_mtu`, `peer_mtus`), its fragmentation
//! stage answers with Packet Too Big and fragments IPv4 for that peer, and a second peer on
//! another path keeps the source MTU; the learned MTU expires and the full MTU comes back.
//!
//! The core pads every data message's plaintext to a multiple of 16 bytes, also past the
//! inner MTU, so a packet at the inner MTU may make an outer packet up to 15 bytes above the
//! path MTU; a sending host without DF (`UdpTransport` today) fragments it. The router models
//! that: once it has reported the limit, it counts such datagrams and passes them on.
//! Reports for unknown paths, increases and wrong quotes change nothing. An engine that
//! never uses the feature keeps no state and spawns no report forwarder.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nsplane::{
    ChannelTransport, Event, FragmentConfig, PacketBuf, Path, PathMtuReport, PathMtuStats, PeerId,
    PeerMtus, Transport, TransportId,
};
use nsplane_e2e::{MTU, Node, Options, TestResult, introduce, payload, udp4, udp6};
use nsplane_packet::checksum::{ipv4_header_checksum, transport_checksum_v6};
use nsplane_packet::{Ipv4Header, Ipv6Header, protocol};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};

/// How long a learned path MTU lasts in these tests.
const EXPIRY: Duration = Duration::from_secs(30);
/// The outer limit of an unconstrained path.
const OPEN: u16 = u16::MAX;
/// The outer MTU the router lowers node 1's path to node 2 to, and the inner MTU that gives
/// over IPv6 (1400 - 40 - 8 - 32).
const LIMIT: u16 = 1400;
const INNER: u16 = 1320;
/// How long to wait for the engine to take a report.
const WAIT: Duration = Duration::from_secs(5);

/// A router in front of a channel transport: the first datagram whose IPv6 packet is above
/// a new limit is dropped and the limit reported, quoting the datagram, like an `ICMPv6`
/// Packet Too Big; later ones above it count as fragmented by the sending host and pass.
struct Router {
    inner: ChannelTransport,
    limit: Arc<AtomicU16>,
    /// The limit was reported since it was set.
    reported: Arc<AtomicBool>,
    /// Datagrams above the reported limit.
    host_fragmented: Arc<AtomicU64>,
    reports: mpsc::Sender<PathMtuReport>,
    feed: Mutex<Option<mpsc::Receiver<PathMtuReport>>>,
    /// The leading bytes of the last datagram dropped.
    dropped: Arc<Mutex<Option<Vec<u8>>>>,
}

/// The test's end of a [`Router`].
#[derive(Clone)]
struct Control {
    limit: Arc<AtomicU16>,
    reported: Arc<AtomicBool>,
    host_fragmented: Arc<AtomicU64>,
    reports: mpsc::Sender<PathMtuReport>,
    dropped: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Router {
    fn new(inner: ChannelTransport) -> (Self, Control) {
        let (reports, feed) = mpsc::channel(16);
        let control = Control {
            limit: Arc::new(AtomicU16::new(OPEN)),
            reported: Arc::default(),
            host_fragmented: Arc::default(),
            reports,
            dropped: Arc::default(),
        };
        let router = Self {
            inner,
            limit: Arc::clone(&control.limit),
            reported: Arc::clone(&control.reported),
            host_fragmented: Arc::clone(&control.host_fragmented),
            reports: control.reports.clone(),
            feed: Mutex::new(Some(feed)),
            dropped: Arc::clone(&control.dropped),
        };
        (router, control)
    }
}

impl Control {
    fn set_limit(&self, limit: u16) {
        self.limit.store(limit, Ordering::Relaxed);
        self.reported.store(false, Ordering::Relaxed);
    }

    /// Datagrams above the reported limit, fragmented by the sending host.
    fn host_fragmented(&self) -> u64 {
        self.host_fragmented.load(Ordering::Relaxed)
    }

    /// The leading bytes of the last dropped datagram.
    fn dropped(&self) -> TestResult<Vec<u8>> {
        self.dropped
            .lock()
            .map_err(|_| "poisoned")?
            .clone()
            .ok_or_else(|| "nothing dropped".into())
    }
}

impl Transport for Router {
    fn id(&self) -> TransportId {
        self.inner.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> std::io::Result<(usize, Path)> {
        self.inner.recv(buf).await
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> std::io::Result<()> {
        let limit = self.limit.load(Ordering::Relaxed);
        if datagram.len() + 48 > usize::from(limit) && self.reported.load(Ordering::Relaxed) {
            self.host_fragmented.fetch_add(1, Ordering::Relaxed);
        } else if datagram.len() + 48 > usize::from(limit) {
            self.reported.store(true, Ordering::Relaxed);
            let quote = &datagram[..datagram.len().min(8)];
            if let Ok(mut dropped) = self.dropped.lock() {
                *dropped = Some(quote.to_vec());
            }
            // A full feed loses the report, as a rate-limited router would.
            let _ = self
                .reports
                .try_send(PathMtuReport::with_quote(*to, limit, quote));
            return Ok(());
        }
        self.inner.send(datagram, to).await
    }

    fn path_mtu_reports(&self) -> Option<mpsc::Receiver<PathMtuReport>> {
        self.feed.lock().ok()?.take()
    }
}

/// Node 1 with a fragmenter, linked to node 2 over IPv6 through a [`Router`] (transport 1)
/// and to node 3 over a plain channel (transport 3); 2 and 3 are peers of 1.
struct Net {
    a: Node<Router>,
    b: Node<ChannelTransport>,
    c: Node<ChannelTransport>,
    router: Control,
    /// Node 1's ids for nodes 2 and 3.
    b_id: PeerId,
    c_id: PeerId,
}

fn addr(s: &str) -> TestResult<SocketAddr> {
    Ok(s.parse()?)
}

async fn net() -> TestResult<Net> {
    let a_addr = addr("[2001:db8::1]:1000")?;
    let b_addr = addr("[2001:db8::2]:2000")?;
    let c_addr = addr("[2001:db8::3]:3000")?;
    let (t1, t3) = (TransportId::new(1), TransportId::new(3));
    let (to_b, from_a) = ChannelTransport::pair(64, (t1, a_addr), (TransportId::new(2), b_addr));
    let (to_c, from_a3) = ChannelTransport::pair(64, (t3, a_addr), (TransportId::new(4), c_addr));
    let (router, control) = Router::new(to_b);
    let a = Node::with_builder(1, t1, a_addr, Options::default(), |builder| {
        builder
            .transport(router)
            .transport(to_c)
            .fragmenter(FragmentConfig::default())
            .path_mtu_expiry(EXPIRY)
    })?;
    let b = Node::new(2, TransportId::new(2), b_addr, from_a, Options::default());
    let c = Node::new(3, TransportId::new(4), c_addr, from_a3, Options::default());
    introduce_pair(&a, &b, t1).await?;
    introduce_pair(&a, &c, t3).await?;
    Ok(Net {
        b_id: a.peer_of(&b).await?,
        c_id: a.peer_of(&c).await?,
        a,
        b,
        c,
        router: control,
    })
}

/// Makes `a` (reaching `other` over its transport `via`) and `other` peers.
async fn introduce_pair<T: Transport>(
    a: &Node<Router>,
    other: &Node<T>,
    via: TransportId,
) -> TestResult {
    a.handle.add_or_update_peer(other.as_peer(via)).await?;
    other
        .handle
        .add_or_update_peer(a.as_peer(other.path.transport))
        .await?;
    Ok(())
}

/// Sends `packet` from `from` and expects it at `to` unchanged.
async fn deliver<T: Transport, U: Transport>(
    from: &Node<T>,
    packet: &[u8],
    to: &mut Node<U>,
) -> TestResult {
    from.send(packet).await?;
    let (_, delivered) = to.expect_delivery().await?;
    assert_eq!(delivered, packet);
    Ok(())
}

/// An IPv6 packet of `len` bytes from node 1 to `to`.
fn v6_to<T: Transport>(a: &Node<Router>, to: &Node<T>, len: usize) -> Vec<u8> {
    udp6(a.ip6, to.ip6, &payload(len - 48))
}

/// Waits until `watch` holds a value matching `predicate`.
async fn wait_for(
    watch: &mut watch::Receiver<PeerMtus>,
    predicate: impl FnMut(&PeerMtus) -> bool,
) -> TestResult<PeerMtus> {
    let value = timeout(WAIT, watch.wait_for(predicate)).await??;
    Ok(value.clone())
}

/// Waits until node 1 has taken `reports` reports in all.
async fn wait_for_reports(a: &Node<Router>, reports: u64) -> TestResult<PathMtuStats> {
    timeout(WAIT, async {
        loop {
            let stats = a.handle.path_mtu_stats().await?;
            if stats.reports >= reports {
                return Ok::<_, nsplane::EngineError>(stats);
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await?
    .map_err(Into::into)
}

/// Checks that node 1 received a Packet Too Big about `original` carrying `mtu` from `from`.
async fn expect_packet_too_big(
    a: &mut Node<Router>,
    from: PeerId,
    original: &[u8],
    mtu: u16,
) -> TestResult {
    let (peer, reply) = a.expect_delivery().await?;
    assert_eq!(peer, from);
    let (orig, _) = Ipv6Header::parse(original)?;
    let (header, icmp) = Ipv6Header::parse(&reply)?;
    assert_eq!((header.src(), header.dst()), (orig.dst(), orig.src()));
    assert_eq!(header.next_header(), protocol::ICMPV6);
    assert_eq!((icmp[0], icmp[1]), (2, 0));
    assert_eq!(icmp[4..8], u32::from(mtu).to_be_bytes());
    assert_eq!(
        transport_checksum_v6(header.src(), header.dst(), protocol::ICMPV6, icmp),
        0
    );
    Ok(())
}

/// A UDP-in-IPv4 packet of `len` bytes from `src` to `dst` with DF clear.
fn ipv4_without_df(src: Ipv4Addr, dst: Ipv4Addr, len: usize) -> Vec<u8> {
    let mut packet = udp4(src, dst, &payload(len - 28));
    packet[6] &= !0x40;
    packet[10..12].fill(0);
    let sum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// Receives IPv4 fragments at `node` until the last one, each at most `mtu` bytes, and
/// returns the reassembled packet and the number of fragments.
async fn reassemble<T: Transport>(node: &mut Node<T>, mtu: u16) -> TestResult<(Vec<u8>, usize)> {
    let mut header = None;
    let mut body = Vec::new();
    let mut count = 0;
    loop {
        let (_, fragment) = node.expect_delivery().await?;
        count += 1;
        assert!(
            fragment.len() <= usize::from(mtu),
            "fragment of {} bytes above {mtu}",
            fragment.len()
        );
        let (ip, data) = Ipv4Header::parse(&fragment)?;
        assert_eq!(usize::from(ip.fragment_offset()), body.len(), "in order");
        body.extend_from_slice(data);
        header.get_or_insert_with(|| fragment[..ip.header_len()].to_vec());
        if !ip.more_fragments() {
            break;
        }
    }
    let mut packet = header.ok_or("no fragment")?;
    let total = u16::try_from(packet.len() + body.len())?;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[6..8].fill(0);
    packet[10..12].fill(0);
    let sum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(&body);
    Ok((packet, count))
}

const fn is_mtu_change(event: &Event) -> bool {
    matches!(event, Event::MtuChanged { .. })
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_inner_mtu_follows_the_path_and_recovers() -> TestResult {
    let Net {
        mut a,
        mut b,
        mut c,
        router,
        b_id,
        c_id,
    } = net().await?;
    let mut events = a.subscribe().await?;
    let mut mtus = a.handle.peer_mtus().await?;

    // Before: full-size packets to both peers.
    deliver(&a, &v6_to(&a, &b, 1420), &mut b).await?;
    deliver(&a, &v6_to(&a, &c, 1420), &mut c).await?;
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(MTU));
    assert!(mtus.borrow_and_update().peers.is_empty());

    // The path to node 2 shrinks: the next full-size packet is lost and reported.
    router.set_limit(LIMIT);
    a.send(&v6_to(&a, &b, 1420)).await?;
    let published = wait_for(&mut mtus, |m| m.peers.contains_key(&b_id)).await?;
    assert_eq!(published.peers.get(&b_id), Some(&INNER));
    assert_eq!(published.min, INNER);
    assert_eq!(published.peers.len(), 1);
    b.expect_no_delivery().await?;
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(INNER));
    assert_eq!(a.handle.peer_mtu(c_id).await?, Some(MTU));
    let stats = a.handle.path_mtu_stats().await?;
    assert_eq!((stats.reports, stats.applied, stats.paths), (1, 1, 1));

    // Too large for node 2: a Packet Too Big carrying its MTU; node 3 still takes 1420.
    let too_big = v6_to(&a, &b, 1420);
    a.send(&too_big).await?;
    expect_packet_too_big(&mut a, b_id, &too_big, INNER).await?;
    b.expect_no_delivery().await?;
    // 1312 bytes fit the path with their datagram; 1320 bytes are padded to 1328 and
    // their outer packet (1408 bytes) is fragmented by the sending host.
    deliver(&a, &v6_to(&a, &b, 1312), &mut b).await?;
    assert_eq!(router.host_fragmented(), 0);
    deliver(&a, &v6_to(&a, &b, usize::from(INNER)), &mut b).await?;
    assert_eq!(router.host_fragmented(), 1);
    deliver(&a, &v6_to(&a, &c, 1420), &mut c).await?;

    // IPv4 without DF arrives at node 2 in fragments within its MTU.
    let packet = ipv4_without_df(a.ip4, b.ip4, 3000);
    a.send(&packet).await?;
    let (joined, fragments) = reassemble(&mut b, INNER).await?;
    assert_eq!(joined, packet);
    assert_eq!(fragments, 3);
    // The two full fragments (1316 bytes) are padded past the path too.
    assert_eq!(router.host_fragmented(), 3);
    let fragment_stats = a.handle.fragment_stats().await?;
    assert_eq!(fragment_stats.ptb_sent, 1);
    assert_eq!(fragment_stats.fragmented, 1);

    // The source MTU keeps its meaning.
    assert_eq!(a.handle.mtu().await?, MTU);
    events.expect_none(is_mtu_change).await?;
    let status = a.handle.status().await?;
    assert_eq!(status.mtu, MTU);
    assert_eq!(status.peer_mtus.peers.get(&b_id), Some(&INNER));
    assert_eq!(status.path_mtu.applied, 1);

    // The path recovers; once the learned MTU expires the full MTU is back.
    router.set_limit(OPEN);
    sleep(EXPIRY).await;
    let published = wait_for(&mut mtus, |m| m.peers.is_empty()).await?;
    assert_eq!(published.min, MTU);
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(MTU));
    let stats = a.handle.path_mtu_stats().await?;
    assert_eq!((stats.expired, stats.paths), (1, 0));
    deliver(&a, &v6_to(&a, &b, 1420), &mut b).await?;
    events.expect_none(is_mtu_change).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reports_that_lower_nothing_change_nothing() -> TestResult {
    let Net {
        a,
        mut b,
        router,
        b_id,
        ..
    } = net().await?;
    let to_b = Path {
        transport: TransportId::new(1),
        ..b.path
    };
    deliver(&a, &v6_to(&a, &b, 100), &mut b).await?;

    // An unknown path: another address, another transport.
    let unknown = Path {
        addr: addr("[2001:db8::9]:2000")?,
        ..to_b
    };
    assert!(!a.handle.report_path_mtu(unknown, 1300).await?);
    let other_transport = Path {
        transport: TransportId::new(9),
        ..to_b
    };
    assert!(!a.handle.report_path_mtu(other_transport, 1300).await?);
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(MTU));

    // A real drop teaches 1400; an increase is ignored, an equal report confirms it.
    router.set_limit(LIMIT);
    a.send(&v6_to(&a, &b, 1420)).await?;
    wait_for_reports(&a, 3).await?;
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(INNER));
    assert!(!a.handle.report_path_mtu(to_b, 1450).await?);
    assert!(a.handle.report_path_mtu(to_b, LIMIT).await?);
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(INNER));

    // A quote of another session (its receiver index changed) or another message type.
    let mut quote = router.dropped()?;
    assert_eq!(quote[0], 4);
    quote[4] ^= 1;
    router
        .reports
        .send(PathMtuReport::with_quote(to_b, 1280, &quote))
        .await?;
    router
        .reports
        .send(PathMtuReport::with_quote(to_b, 1280, &[1, 0, 0, 0]))
        .await?;
    let stats = wait_for_reports(&a, 7).await?;
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(INNER));
    assert_eq!(
        (stats.reports, stats.applied, stats.ignored, stats.paths),
        (7, 2, 5, 1)
    );

    // The same quote with the right index lowers it further.
    quote[4] ^= 1;
    router
        .reports
        .send(PathMtuReport::with_quote(to_b, 1300, &quote))
        .await?;
    wait_for_reports(&a, 8).await?;
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(1280));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn transport_ceilings_apply_at_once() -> TestResult {
    let Net {
        mut a,
        mut b,
        mut c,
        b_id,
        c_id,
        ..
    } = net().await?;
    let mut mtus = a.handle.peer_mtus().await?;
    // Node 3's transport carries datagrams of at most 1352 bytes: 1320 inside.
    a.handle
        .set_transport_max_datagram(TransportId::new(3), Some(1352))
        .await?;
    let published = wait_for(&mut mtus, |m| !m.peers.is_empty()).await?;
    assert_eq!(published.peers, [(c_id, INNER)].into());
    assert_eq!(a.handle.peer_mtu(b_id).await?, Some(MTU));
    let too_big = v6_to(&a, &c, 1400);
    a.send(&too_big).await?;
    expect_packet_too_big(&mut a, c_id, &too_big, INNER).await?;
    deliver(&a, &v6_to(&a, &b, 1420), &mut b).await?;

    // Cleared: the full MTU again.
    a.handle
        .set_transport_max_datagram(TransportId::new(3), None)
        .await?;
    wait_for(&mut mtus, |m| m.peers.is_empty()).await?;
    deliver(&a, &v6_to(&a, &c, 1420), &mut c).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_engine_without_the_feature_keeps_no_state() -> TestResult {
    let tasks = || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    };
    let link = |port: u16| {
        let a = (
            TransportId::new(1),
            SocketAddr::from(([192, 0, 2, 1], port)),
        );
        let b = (
            TransportId::new(2),
            SocketAddr::from(([192, 0, 2, 2], port)),
        );
        (a, b, ChannelTransport::pair(64, a, b))
    };

    // A transport without reports.
    let (a_end, b_end, (to_b, from_a)) = link(1000);
    let before = tasks();
    let mut a = Node::new(1, a_end.0, a_end.1, to_b, Options::default());
    let plain = tasks() - before;
    let mut b = Node::new(2, b_end.0, b_end.1, from_a, Options::default());
    introduce(&a, &b, None).await?;
    deliver(&a, &udp6(a.ip6, b.ip6, &payload(1372)), &mut b).await?;
    deliver(&b, &udp4(b.ip4, a.ip4, &payload(1392)), &mut a).await?;
    let mtus = a.handle.peer_mtus().await?;
    assert_eq!(mtus.borrow().min, MTU);
    assert!(mtus.borrow().peers.is_empty());
    assert_eq!(a.handle.path_mtu_stats().await?, PathMtuStats::default());
    assert_eq!(a.handle.status().await?.path_mtu, PathMtuStats::default());
    assert_eq!(a.handle.peer_mtu(a.peer_of(&b).await?).await?, Some(MTU));

    // A transport with reports gets one forwarder task more.
    let (a_end, _, (to_b, _from_a)) = link(2000);
    let (router, _control) = Router::new(to_b);
    let before = tasks();
    let _reporting = Node::new(1, a_end.0, a_end.1, router, Options::default());
    assert_eq!(tasks() - before, plain + 1);
    Ok(())
}
