//! A local-side graph: engines and endpoints on one host joined by `pipe`s, `pump`s and the
//! `MapSink` / `MapSource` transform wrappers, with no forwarding task of their own.
//!
//! Engine A serves peer X and engine B serves peer Y over `ChannelTransport`s. A's sink
//! routes Y's virtual range through a Redirect-like `MapSink` into a pipe that is B's
//! source; B's sink is a pipe that A's `MergeSource` reads through the reverse `MapSource`.
//! Further cases pump a TUN-like channel into and out of an engine and check backpressure,
//! the end of either side of a pipe, the cancellation of a pump and the `Splitter` drop
//! counters.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSink, ChannelSource, ChannelTransport, DROP_SINK_CLOSED, Ecn, Engine,
    EngineBuilder, Event, MapSink, MapSource, MapVerdict, MergeSource, PacketBuf, PacketSink,
    PacketSource, Path, Peer, PeerId, PumpStats, Splitter, TransportId, pipe, pump,
};
use nsplane_e2e::{Family, Node, Options, QUIET, TestResult, WAIT, udp};
use nsplane_packet::checksum::{
    ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{IpPacket, protocol};
use tokio::sync::{broadcast, oneshot};
use tokio::time::timeout;

/// Capacity of the channels, the links and the roomy pipes.
const CAPACITY: usize = 1024;
/// MTU of every local side.
const MTU: u16 = 1420;
/// Key seeds: peer X, engine A, engine B, peer Y. The nodes' tunnel addresses are
/// `10.0.0.<seed>` and `fd00::<seed>`.
const X_SEED: u8 = 1;
const A_SEED: u8 = 2;
const B_SEED: u8 = 3;
const Y_SEED: u8 = 4;
/// The address X reaches Y on, redirected to Y's tunnel address.
const VIRT4: Ipv4Addr = Ipv4Addr::new(10, 0, 4, 4);
const VIRT6: Ipv6Addr = Ipv6Addr::new(0xfd00, 4, 0, 0, 0, 0, 0, 4);
/// An address in Y's virtual range the forward transform drops.
const BLOCKED4: Ipv4Addr = Ipv4Addr::new(10, 0, 4, 9);
const BLOCKED6: Ipv6Addr = Ipv6Addr::new(0xfd00, 4, 0, 0, 0, 0, 0, 9);
/// A host behind A's TUN side, outside Y's virtual range.
const OTHER4: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
const OTHER6: Ipv6Addr = Ipv6Addr::new(0xfd09, 0, 0, 0, 0, 0, 0, 1);
/// UDP port of every packet.
const PORT: u16 = 5000;
/// Packets per burst.
const BURST: usize = 32;
/// The peer a pump hands its packets to a sink as.
const TUN: PeerId = PeerId::new(0);

/// Transport ids and addresses: X and A share one link, B and Y another.
const X_PATH: (TransportId, SocketAddr) = (
    TransportId::new(1),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1000),
);
const A_PATH: (TransportId, SocketAddr) = (
    TransportId::new(2),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 2000),
);
const B_PATH: (TransportId, SocketAddr) = (
    TransportId::new(3),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 3000),
);
const Y_PATH: (TransportId, SocketAddr) = (
    TransportId::new(4),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)), 4000),
);

/// A node's tunnel address of `family`.
fn tunnel(seed: u8, family: Family) -> IpAddr {
    match family {
        Family::V4 => IpAddr::V4(Ipv4Addr::new(10, 0, 0, seed)),
        Family::V6 => IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed))),
    }
}

/// A UDP packet from `src` to `dst`, both on [`PORT`], with valid checksums.
fn packet(src: IpAddr, dst: IpAddr, payload: &str) -> Vec<u8> {
    udp(
        SocketAddr::new(src, PORT),
        SocketAddr::new(dst, PORT),
        payload.as_bytes(),
    )
}

/// Whether `dst` is in Y's virtual range, `10.0.4.0/24` or `fd00:4::/64`.
fn to_y(packet: &PacketBuf) -> bool {
    IpPacket::parse(packet.as_packet()).is_ok_and(|ip| match ip.dst() {
        IpAddr::V4(dst) => dst.octets()[..3] == [10, 0, 4],
        IpAddr::V6(dst) => dst.segments()[..4] == [0xfd00, 4, 0, 0],
    })
}

/// Which address a [`rewrite`] replaces.
#[derive(Debug, Clone, Copy)]
enum Field {
    Src,
    Dst,
}

/// Replaces the `field` address of a UDP packet without IP options or extension headers
/// with `to` if it is `from`, and recomputes the checksums, as a Redirect does. Returns
/// whether it rewrote the packet.
fn rewrite(packet: &mut [u8], field: Field, from: IpAddr, to: IpAddr) -> bool {
    let (from, to) = match (from, to) {
        (IpAddr::V4(from), IpAddr::V4(to)) => (from.octets().to_vec(), to.octets().to_vec()),
        (IpAddr::V6(from), IpAddr::V6(to)) => (from.octets().to_vec(), to.octets().to_vec()),
        _ => return false,
    };
    let (header, at) = match (packet.first().map(|byte| byte >> 4), field) {
        (Some(4), Field::Src) => (20, 12),
        (Some(4), Field::Dst) => (20, 16),
        (Some(6), Field::Src) => (40, 8),
        (Some(6), Field::Dst) => (40, 24),
        _ => return false,
    };
    if packet.get(at..at + from.len()) != Some(&from[..]) || packet.len() < header + 8 {
        return false;
    }
    packet[at..at + to.len()].copy_from_slice(&to);
    let checksum = header + 6..header + 8;
    packet[checksum.clone()].fill(0);
    let Ok(ip) = IpPacket::parse(packet) else {
        return false;
    };
    let sum = match (ip.src(), ip.dst()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            transport_checksum_v4(src, dst, protocol::UDP, ip.payload())
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            transport_checksum_v6(src, dst, protocol::UDP, ip.payload())
        }
        _ => return false,
    };
    let sum = if sum == 0 { 0xFFFF } else { sum };
    packet[checksum].copy_from_slice(&sum.to_be_bytes());
    if header == 20 {
        let sum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    true
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

/// An engine with key seed `seed` on `link` with `source` and `sink` as its local side.
fn engine(
    seed: u8,
    source: impl PacketSource,
    sink: impl PacketSink,
    link: ChannelTransport,
) -> TestResult<Engine> {
    Ok(EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([seed; 32]))
        .transport(link)
        .build()?)
}

/// The engine with key seed `seed` as a peer reached over `via` at `addr`, with every
/// address routed to it.
fn gateway(seed: u8, via: TransportId, addr: SocketAddr) -> Peer {
    Peer {
        allowed_ips: [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ]
        .into_iter()
        .map(|addr| AllowedIp { addr, cidr: 0 })
        .collect(),
        path: Some(Path {
            transport: via,
            addr,
            ecn: Ecn::NotEct,
        }),
        ..Peer::new(public(seed))
    }
}

fn public(seed: u8) -> PublicKey {
    PublicKey::from(&StaticSecret::from([seed; 32]))
}

/// Peer X and engine A on one link, introduced to each other; A's local side is `source`
/// and `sink`.
async fn x_and_a(
    source: impl PacketSource,
    sink: impl PacketSink,
) -> TestResult<(Node<ChannelTransport>, Engine)> {
    let (link_x, link_a) = ChannelTransport::pair(CAPACITY, X_PATH, A_PATH);
    let x = Node::new(X_SEED, X_PATH.0, X_PATH.1, link_x, Options::default());
    let a = engine(A_SEED, source, sink, link_a)?;
    a.handle().add_or_update_peer(x.as_peer(A_PATH.0)).await?;
    x.handle
        .add_or_update_peer(gateway(A_SEED, X_PATH.0, A_PATH.1))
        .await?;
    Ok((x, a))
}

/// The next packet `node` delivers, checked to be `expected` and to come from the engine
/// with key seed `seed`.
async fn expect_from(node: &mut Node<ChannelTransport>, seed: u8, expected: &[u8]) -> TestResult {
    let (peer, delivered) = node.expect_delivery().await?;
    let from = node.handle.peer_id(public(seed)).await?;
    assert_eq!(Some(peer), from, "packet attributed to {peer:?}");
    assert_eq!(delivered, expected);
    Ok(())
}

fn assert_broken_pipe<T>(result: io::Result<T>) {
    assert_eq!(
        result.err().map(|err| err.kind()),
        Some(io::ErrorKind::BrokenPipe)
    );
}

/// The forward Redirect: rewrites the virtual destination to Y's address; returns whether it
/// did.
fn redirect(packet: &mut [u8]) -> bool {
    [
        (IpAddr::V4(VIRT4), tunnel(Y_SEED, Family::V4)),
        (IpAddr::V6(VIRT6), tunnel(Y_SEED, Family::V6)),
    ]
    .into_iter()
    .any(|(virt, y)| rewrite(packet, Field::Dst, virt, y))
}

/// The reverse Redirect: rewrites Y's source address back to the virtual one.
fn unredirect(packet: &mut PacketBuf) -> MapVerdict {
    let packet = packet.as_packet_mut();
    for (y, virt) in [
        (tunnel(Y_SEED, Family::V4), IpAddr::V4(VIRT4)),
        (tunnel(Y_SEED, Family::V6), IpAddr::V6(VIRT6)),
    ] {
        if rewrite(packet, Field::Src, y, virt) {
            break;
        }
    }
    MapVerdict::Keep
}

/// The virtual, blocked and other addresses of `family`.
const fn targets(family: Family) -> (IpAddr, IpAddr, IpAddr) {
    match family {
        Family::V4 => (IpAddr::V4(VIRT4), IpAddr::V4(BLOCKED4), IpAddr::V4(OTHER4)),
        Family::V6 => (IpAddr::V6(VIRT6), IpAddr::V6(BLOCKED6), IpAddr::V6(OTHER6)),
    }
}

/// The ns service graph in miniature: X -> A -> `Splitter` -> `MapSink` -> pipe -> B -> Y
/// and back Y -> B -> pipe -> `MapSource` -> `MergeSource` -> A -> X, for IPv4 and IPv6.
#[tokio::test]
async fn graph_two_engines_joined_by_pipe() -> TestResult {
    // A -> B: the forward Redirect from the virtual address to Y's, and a Drop rule for the
    // rest of Y's virtual range.
    let (to_b_sink, to_b_source) = pipe(CAPACITY, MTU);
    let kept = Arc::new(AtomicU64::new(0));
    let forward = Arc::new(MapSink::new(to_b_sink, {
        let kept = Arc::clone(&kept);
        move |packet: &mut PacketBuf, _from: PeerId| {
            if redirect(packet.as_packet_mut()) {
                kept.fetch_add(1, Ordering::Relaxed);
                MapVerdict::Keep
            } else {
                MapVerdict::Drop
            }
        }
    }));
    // B -> A: a plain pipe, and the reverse translation on A's side of it.
    let (to_a_sink, to_a_source) = pipe(CAPACITY, MTU);
    let reverse = MapSource::new(to_a_source, unredirect);

    let (tun_source, tun_in, _tun_mtu) = ChannelSource::new(CAPACITY, MTU);
    let (tun_sink, mut tun_out) = ChannelSink::new(CAPACITY);
    let (mut x, a) = x_and_a(
        MergeSource::new().source(tun_source).source(reverse),
        Splitter::new(|_peer, packet| usize::from(to_y(packet)))
            .sink(tun_sink)
            .sink(Shared(Arc::clone(&forward))),
    )
    .await?;

    let (link_b, link_y) = ChannelTransport::pair(CAPACITY, B_PATH, Y_PATH);
    let mut y = Node::new(Y_SEED, Y_PATH.0, Y_PATH.1, link_y, Options::default());
    let b = engine(B_SEED, to_b_source, to_a_sink, link_b)?;
    b.handle().add_or_update_peer(y.as_peer(B_PATH.0)).await?;
    y.handle
        .add_or_update_peer(gateway(B_SEED, Y_PATH.0, B_PATH.1))
        .await?;
    let x_at_a = a
        .handle()
        .peer_id(x.public())
        .await?
        .ok_or("unknown peer")?;

    let mut redirected = 0;
    for family in [Family::V4, Family::V6] {
        let (virt, blocked, other) = targets(family);
        let (x_ip, y_ip) = (tunnel(X_SEED, family), tunnel(Y_SEED, family));

        // One round trip first, so both sessions are up before the bursts.
        x.send(&packet(x_ip, virt, "hello")).await?;
        expect_from(&mut y, B_SEED, &packet(x_ip, y_ip, "hello")).await?;
        y.send(&packet(y_ip, x_ip, "hello back")).await?;
        expect_from(&mut x, A_SEED, &packet(virt, x_ip, "hello back")).await?;

        // X -> Y, rewritten on the way and in order.
        for i in 0..BURST {
            x.send(&packet(x_ip, virt, &format!("to Y {i}"))).await?;
        }
        for i in 0..BURST {
            expect_from(&mut y, B_SEED, &packet(x_ip, y_ip, &format!("to Y {i}"))).await?;
        }
        // Y -> X, translated back on the way and in order.
        for i in 0..BURST {
            y.send(&packet(y_ip, x_ip, &format!("to X {i}"))).await?;
        }
        for i in 0..BURST {
            expect_from(&mut x, A_SEED, &packet(virt, x_ip, &format!("to X {i}"))).await?;
        }
        redirected += 1 + BURST as u64;

        // The Drop rule: the blocked packet never reaches Y, the one after it does.
        let dropped = forward.dropped();
        x.send(&packet(x_ip, blocked, "blocked")).await?;
        x.send(&packet(x_ip, virt, "after")).await?;
        expect_from(&mut y, B_SEED, &packet(x_ip, y_ip, "after")).await?;
        redirected += 1;
        assert_eq!(forward.dropped(), dropped + 1);

        // Packets outside Y's range go to A's TUN side, untouched.
        let to_other = packet(x_ip, other, "to the TUN side");
        x.send(&to_other).await?;
        let (peer, delivered) = timeout(WAIT, tun_out.recv())
            .await?
            .ok_or("A's TUN sink closed")?;
        assert_eq!((peer, delivered.as_packet()), (x_at_a, &to_other[..]));

        // And A's TUN side still reaches X through the merge.
        let from_other = packet(other, x_ip, "from the TUN side");
        tun_in.send(PacketBuf::from_packet(&from_other)).await?;
        expect_from(&mut x, A_SEED, &from_other).await?;
    }

    assert_eq!(forward.dropped(), 2);
    assert_eq!(kept.load(Ordering::Relaxed), redirected);
    y.expect_no_delivery().await?;
    assert!(
        tun_out.try_recv().is_err(),
        "unexpected packet on A's TUN side"
    );
    Ok(())
}

/// A TUN-like channel pumped into an engine's input pipe, and the engine's output pipe
/// pumped into a TUN-like channel.
#[tokio::test]
async fn pump_channel_source_into_engine() -> TestResult {
    let (in_sink, in_source) = pipe(CAPACITY, MTU);
    let (out_sink, out_source) = pipe(CAPACITY, MTU);
    let (mut x, a) = x_and_a(in_source, out_sink).await?;
    let (tun_source, tun_in, _tun_mtu) = ChannelSource::new(CAPACITY, MTU);
    let (tun_sink, mut tun_out) = ChannelSink::new(CAPACITY);
    let inbound = tokio::spawn(pump(tun_source, in_sink, TUN));
    let outbound = tokio::spawn(pump(out_source, tun_sink, TUN));

    let (a_ip, x_ip) = (tunnel(A_SEED, Family::V4), tunnel(X_SEED, Family::V4));
    // One packet first, so the session is up before the bursts.
    let hello = packet(a_ip, x_ip, "hello");
    tun_in.send(PacketBuf::from_packet(&hello)).await?;
    expect_from(&mut x, A_SEED, &hello).await?;

    // A's TUN side -> X, in order.
    for i in 0..BURST {
        let packet = packet(a_ip, x_ip, &format!("to X {i}"));
        tun_in.send(PacketBuf::from_packet(&packet)).await?;
    }
    for i in 0..BURST {
        expect_from(&mut x, A_SEED, &packet(a_ip, x_ip, &format!("to X {i}"))).await?;
    }
    // X -> A's TUN side, in order, handed over as the pump's peer.
    for i in 0..BURST {
        x.send(&packet(x_ip, a_ip, &format!("to A {i}"))).await?;
    }
    for i in 0..BURST {
        let (peer, delivered) = timeout(WAIT, tun_out.recv())
            .await?
            .ok_or("A's TUN sink closed")?;
        let expected = packet(x_ip, a_ip, &format!("to A {i}"));
        assert_eq!((peer, delivered.as_packet()), (TUN, &expected[..]));
    }

    // The TUN side closing ends the inbound pump; stopping the engine drops its output
    // pipe's sink, which ends the outbound pump.
    let sent = 1 + BURST as u64;
    drop(tun_in);
    let stats = timeout(WAIT, inbound).await???;
    assert_eq!(stats.packets, sent);
    assert!((1..=sent).contains(&stats.batches), "{stats:?}");
    drop(a);
    let stats = timeout(WAIT, outbound).await???;
    assert_eq!(stats.packets, BURST as u64);
    assert!((1..=BURST as u64).contains(&stats.batches), "{stats:?}");
    Ok(())
}

/// A pump into a small pipe nobody reads waits instead of dropping; once the consumer
/// reads, every packet arrives in order.
#[tokio::test]
async fn backpressure_without_loss() -> TestResult {
    let (source, tx, _mtu) = ChannelSource::new(CAPACITY, MTU);
    let (sink, mut consumer) = pipe(2, MTU);
    for i in 0..BURST {
        tx.send(PacketBuf::from_packet(format!("{i}").as_bytes()))
            .await?;
    }
    let mut pumping = tokio::spawn(pump(source, sink, TUN));
    assert!(
        timeout(QUIET, &mut pumping).await.is_err(),
        "the pump ended while the consumer was not reading"
    );
    // The pump holds back what does not fit: the pipe holds two packets and the pump the
    // one it waits to hand over (a ChannelSource yields one packet per batch); the rest are
    // still queued at the source.
    assert_eq!(CAPACITY - tx.capacity(), BURST - 3);

    for i in 0..BURST {
        let packet = timeout(WAIT, consumer.recv()).await??;
        assert_eq!(packet.as_packet(), format!("{i}").as_bytes());
    }
    drop(tx);
    let stats = timeout(WAIT, pumping).await???;
    assert_eq!(stats.packets, BURST as u64);
    assert_broken_pipe(timeout(WAIT, consumer.recv()).await?);
    Ok(())
}

/// The end of either side of a pipe reaches the other side: a pump ends, an engine keeps
/// running without the I/O side that ended, a producer gets `BrokenPipe`.
#[tokio::test]
async fn broken_pipe_propagation() -> TestResult {
    // The downstream consumer goes away: the pump ends with Ok and what it moved.
    let (in_sink, in_source) = pipe(CAPACITY, MTU);
    let (out_sink, mut out_source) = pipe(CAPACITY, MTU);
    let pumping = tokio::spawn(pump(in_source, out_sink, TUN));
    for i in 0..3_u8 {
        in_sink.send(PacketBuf::from_packet(&[i]), TUN).await?;
        assert_eq!(timeout(WAIT, out_source.recv()).await??.as_packet(), [i]);
    }
    drop(out_source);
    in_sink.send(PacketBuf::from_packet(&[3]), TUN).await?;
    let stats = timeout(WAIT, pumping).await???;
    assert_eq!(
        stats,
        PumpStats {
            packets: 3,
            batches: 3
        }
    );
    // The pump dropped its source, so the producer gets BrokenPipe.
    assert_broken_pipe(in_sink.send(PacketBuf::from_packet(&[4]), TUN).await);

    // Every producer goes away: a pump drains the pipe, then ends with Ok.
    let (in_sink, in_source) = pipe(CAPACITY, MTU);
    let (tun_sink, mut tun_out) = ChannelSink::new(CAPACITY);
    let other = in_sink.clone();
    in_sink.send(PacketBuf::from_packet(&[1]), TUN).await?;
    other.send(PacketBuf::from_packet(&[2]), TUN).await?;
    drop((in_sink, other));
    let stats = timeout(WAIT, pump(in_source, tun_sink, TUN)).await??;
    assert_eq!(stats.packets, 2);
    for i in 1..=2 {
        let (_, packet) = tun_out.recv().await.ok_or("sink closed")?;
        assert_eq!(packet.as_packet(), [i]);
    }

    // Every producer of an engine's input pipe goes away: the engine sends what was queued,
    // then its source task stops and the engine keeps running without it.
    let (in_sink, in_source) = pipe(CAPACITY, MTU);
    let (a_sink, mut a_out) = ChannelSink::new(CAPACITY);
    let (mut x, a) = x_and_a(in_source, a_sink).await?;
    let (a_ip, x_ip) = (tunnel(A_SEED, Family::V6), tunnel(X_SEED, Family::V6));
    let other = in_sink.clone();
    for i in 0..4 {
        let producer = if i % 2 == 0 { &in_sink } else { &other };
        let packet = packet(a_ip, x_ip, &format!("queued {i}"));
        producer.send(PacketBuf::from_packet(&packet), TUN).await?;
    }
    drop((in_sink, other));
    for i in 0..4 {
        expect_from(&mut x, A_SEED, &packet(a_ip, x_ip, &format!("queued {i}"))).await?;
    }
    let inbound = packet(x_ip, a_ip, "still running");
    x.send(&inbound).await?;
    let (_, delivered) = timeout(WAIT, a_out.recv()).await?.ok_or("sink closed")?;
    assert_eq!(delivered.as_packet(), inbound);
    drop(a);

    // An engine's output pipe loses its consumer: the engine's sink gets BrokenPipe, its sink
    // task stops, and later deliveries are dropped and counted under DROP_SINK_CLOSED, while
    // the engine keeps sending.
    let (tun_source, tun_in, _tun_mtu) = ChannelSource::new(CAPACITY, MTU);
    let (out_sink, out_source) = pipe(CAPACITY, MTU);
    let producer = out_sink.clone();
    let (mut x, a) = x_and_a(tun_source, out_sink).await?;
    let mut events = a.handle().subscribe().await?;
    let hello = packet(a_ip, x_ip, "hello");
    tun_in.send(PacketBuf::from_packet(&hello)).await?;
    expect_from(&mut x, A_SEED, &hello).await?;
    drop(out_source);
    assert_broken_pipe(producer.send(PacketBuf::from_packet(&[1]), TUN).await);

    // Which delivery finds the sink task gone depends on when the task stops: send until
    // one is counted.
    let mut closed = false;
    for i in 0..10 {
        x.send(&packet(x_ip, a_ip, &format!("lost {i}"))).await?;
        if timeout(QUIET, sink_closed(&mut events)).await.is_ok() {
            closed = true;
            break;
        }
    }
    assert!(closed, "no delivery dropped under {DROP_SINK_CLOSED}");
    let after = packet(a_ip, x_ip, "after");
    tun_in.send(PacketBuf::from_packet(&after)).await?;
    expect_from(&mut x, A_SEED, &after).await?;
    Ok(())
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

/// A pump cancelled while it waits for its source loses nothing; one cancelled while it
/// waits for its sink loses at most the batch in flight. Nothing is duplicated and nothing
/// arrives after the cancellation.
#[tokio::test]
async fn pump_cancellation() -> TestResult {
    // Cancelled by `select!` at a batch boundary, waiting for the source.
    let (in_sink, in_source) = pipe(CAPACITY, MTU);
    let (out_sink, mut out_source) = pipe(CAPACITY, MTU);
    let (cancel, cancelled) = oneshot::channel::<()>();
    let pumping = tokio::spawn(async move {
        tokio::select! {
            stats = pump(in_source, out_sink, TUN) => Some(stats),
            _ = cancelled => None,
        }
    });
    for i in 0..3_u8 {
        in_sink.send(PacketBuf::from_packet(&[i]), TUN).await?;
        assert_eq!(timeout(WAIT, out_source.recv()).await??.as_packet(), [i]);
    }
    cancel.send(()).map_err(|()| "pump task gone")?;
    assert!(
        timeout(WAIT, pumping).await??.is_none(),
        "the pump ended on its own"
    );
    // The source and the sink went with the pump: nothing more comes out, nothing more goes
    // in.
    assert_broken_pipe(timeout(WAIT, out_source.recv()).await?);
    assert_broken_pipe(in_sink.send(PacketBuf::from_packet(&[3]), TUN).await);

    // Aborted while it waits for a full sink: what the sink took over arrives once and in
    // order, the rest of the batch in flight is lost, and nothing arrives afterwards.
    let (in_sink, in_source) = pipe(CAPACITY, MTU);
    let (out_sink, mut out_source) = pipe(1, MTU);
    for i in 0..4_u8 {
        in_sink.send(PacketBuf::from_packet(&[i]), TUN).await?;
    }
    let pumping = tokio::spawn(pump(in_source, out_sink, TUN));
    assert_eq!(timeout(WAIT, out_source.recv()).await??.as_packet(), [0]);
    pumping.abort();
    assert!(
        timeout(WAIT, pumping)
            .await?
            .is_err_and(|err| err.is_cancelled())
    );
    let mut rest = Vec::new();
    loop {
        match timeout(WAIT, out_source.recv()).await? {
            Ok(packet) => rest.push(packet.as_packet()[0]),
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => break,
            Err(err) => return Err(err.into()),
        }
    }
    // The pipe holds one packet: the next one, if the pump got to hand it over.
    assert!(rest.is_empty() || rest == [1], "after the abort: {rest:?}");
    assert_broken_pipe(in_sink.send(PacketBuf::from_packet(&[4]), TUN).await);
    Ok(())
}

/// An engine delivers through a `Splitter` the test still reads: packets to Y's virtual range
/// are routed to an index without a sink and counted as misrouted, the others arrive.
#[tokio::test]
async fn splitter_stats_count_misrouted_packets() -> TestResult {
    let (tun_source, _tun_in, _tun_mtu) = ChannelSource::new(CAPACITY, MTU);
    let (tun_sink, mut tun_out) = ChannelSink::new(CAPACITY);
    let splitter =
        Arc::new(Splitter::new(|_peer, packet| if to_y(packet) { 5 } else { 0 }).sink(tun_sink));
    let (x, a) = x_and_a(tun_source, Shared(Arc::clone(&splitter))).await?;
    let x_at_a = a
        .handle()
        .peer_id(x.public())
        .await?
        .ok_or("unknown peer")?;

    let mut misrouted = 0;
    for family in [Family::V4, Family::V6] {
        let (virt, _, other) = targets(family);
        let x_ip = tunnel(X_SEED, family);
        for i in 0..BURST {
            let to_other = packet(x_ip, other, &format!("to the TUN side {i}"));
            x.send(&packet(x_ip, virt, &format!("misrouted {i}")))
                .await?;
            x.send(&to_other).await?;
            let (peer, delivered) = timeout(WAIT, tun_out.recv())
                .await?
                .ok_or("A's TUN sink closed")?;
            assert_eq!((peer, delivered.as_packet()), (x_at_a, &to_other[..]));
        }
        misrouted += BURST as u64;
        // Each misrouted packet was sent before a delivered one, so it is counted by now.
        assert_eq!(splitter.stats().misrouted, misrouted);
    }

    let stats = splitter.stats();
    assert_eq!((stats.misrouted, stats.failed), (2 * BURST as u64, 0));
    assert_eq!(splitter.misrouted(), 2 * BURST as u64);
    assert!(
        tun_out.try_recv().is_err(),
        "unexpected packet on A's TUN side"
    );
    Ok(())
}
