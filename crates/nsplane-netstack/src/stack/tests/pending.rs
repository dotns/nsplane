//! `Admission::Decide`: new connections and flows held for the application's decision.

use super::*;
use crate::{PendingFlow, PendingProtocol, TransparentConfig};

const RST: u8 = 0x04;
const ACK: u8 = 0x10;

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 2);
const DIALED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

/// A transparent stack at [`LOCAL`] for every destination, deciding with `timeout` and
/// `max_pending`, and `max_connections`.
fn decide(timeout: Duration, max_pending: usize, max_connections: Option<usize>) -> NetStackConfig {
    NetStackConfig {
        transparent: Some(TransparentConfig {
            admission: Admission::Decide {
                timeout,
                max_pending,
            },
            max_connections,
            ..Default::default()
        }),
        ..config(LOCAL)
    }
}

/// Opens a client socket to `dst:443` from `local_port` and returns it with its SYN, which
/// the caller sends.
fn client_syn(
    peer: &mut RawPeer,
    dst: Ipv4Addr,
    local_port: u16,
) -> Result<(SocketHandle, PacketBuf), Box<dyn Error>> {
    let socket = peer.connect(dst, 443, local_port)?;
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    let syn = peer.device.drain_tx().next().ok_or("no SYN")?;
    Ok((socket, syn))
}

/// The next packet the stack sends.
async fn next_egress(peer: &mut RawPeer) -> Result<PacketBuf, Box<dyn Error>> {
    Ok(timeout(WAIT, peer.source.rx.recv())
        .await?
        .ok_or("stack stopped")?)
}

/// Waits until `ready` holds for the stack's counters.
async fn until_stats(
    handle: &NetStackHandle,
    ready: impl Fn(&NetStackStats) -> bool + Sync,
) -> TestResult {
    timeout(WAIT, async {
        while !ready(&handle.stats()) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| format!("counters should converge: {:?}", handle.stats()))?;
    Ok(())
}

/// Checks that `reset` is a RST from `from` to `to` that the client socket takes.
fn assert_reset(
    peer: &mut RawPeer,
    socket: SocketHandle,
    reset: PacketBuf,
    from: SocketAddr,
    to: SocketAddr,
) -> TestResult {
    assert_eq!(tcp_tuple(reset.as_packet()), Some((from, to)));
    let segment = tcp_segment(reset.as_packet()).ok_or("not TCP")?;
    assert_eq!(segment[13], RST | ACK);
    peer.device.inject(reset);
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    assert_eq!(
        peer.state(socket),
        tcp::State::Closed,
        "checksums and ack hold"
    );
    Ok(())
}

#[tokio::test]
async fn an_accepted_syn_is_answered_only_after_the_decision() -> TestResult {
    let (handle, mut peer) = RawPeer::start(decide(WAIT * 5, 8, None), CLIENT, 31);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    let (socket, syn) = client_syn(&mut peer, DIALED, 40_000)?;
    peer.sink.send(syn, PeerId::new(0)).await?;

    let item = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;
    let dialed = SocketAddr::new(DIALED.into(), 443);
    assert_eq!(item.protocol(), PendingProtocol::Tcp);
    assert_eq!(item.local_addr(), dialed);
    assert_eq!(item.peer_addr(), SocketAddr::new(CLIENT.into(), 40_000));
    peer.pump(4).await;
    assert_eq!(
        peer.state(socket),
        tcp::State::SynSent,
        "no SYN-ACK while held"
    );
    let stats = handle.stats();
    assert_eq!((stats.pending, stats.accepted), (1, 0));

    item.accept();
    peer.pump_until(|peer| peer.state(socket) == tcp::State::Established)
        .await?;
    let mut conn = None;
    for _ in 0..40 {
        peer.pump(1).await;
        conn = try_next(&mut incoming);
        if conn.is_some() {
            break;
        }
    }
    let conn = conn.ok_or("connection should arrive")?;
    assert_eq!(conn.local_addr(), dialed);
    assert_eq!(conn.peer_addr(), SocketAddr::new(CLIENT.into(), 40_000));
    let stats = handle.stats();
    assert_eq!(
        (stats.pending, stats.accepted, stats.rejected_hook),
        (0, 1, 0)
    );
    Ok(())
}

#[tokio::test]
async fn a_rejected_or_dropped_syn_is_reset_from_its_destination() -> TestResult {
    let (handle, mut peer) = RawPeer::start(decide(WAIT * 5, 8, None), CLIENT, 32);
    let mut pending = handle.incoming_pending();
    let client = |port| SocketAddr::new(CLIENT.into(), port);
    let dialed = SocketAddr::new(DIALED.into(), 443);
    for (port, drop_it) in [(40_000, false), (40_001, true)] {
        let (socket, syn) = client_syn(&mut peer, DIALED, port)?;
        peer.sink.send(syn, PeerId::new(0)).await?;
        let item = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;
        if drop_it {
            drop(item);
        } else {
            item.reject();
        }
        let reset = next_egress(&mut peer).await?;
        assert_reset(&mut peer, socket, reset, dialed, client(port))?;
    }
    let stats = handle.stats();
    assert_eq!(
        (stats.rejected_hook, stats.pending, stats.accepted),
        (2, 0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn a_syn_without_a_decision_times_out_and_a_late_decision_is_ignored() -> TestResult {
    let (handle, mut peer) =
        RawPeer::start(decide(Duration::from_millis(100), 8, None), CLIENT, 33);
    let mut pending = handle.incoming_pending();
    let (socket, syn) = client_syn(&mut peer, DIALED, 40_000)?;
    peer.sink.send(syn, PeerId::new(0)).await?;
    let item = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;

    let reset = next_egress(&mut peer).await?;
    let dialed = SocketAddr::new(DIALED.into(), 443);
    assert_reset(
        &mut peer,
        socket,
        reset,
        dialed,
        SocketAddr::new(CLIENT.into(), 40_000),
    )?;
    item.accept();
    sleep(Duration::from_millis(50)).await;
    assert!(peer.source.rx.try_recv().is_err(), "nothing answers it");
    let stats = handle.stats();
    assert_eq!(
        (
            stats.rejected_timeout,
            stats.rejected_hook,
            stats.accepted,
            stats.pending
        ),
        (1, 0, 0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn a_retransmitted_syn_is_absorbed_while_held() -> TestResult {
    let (handle, mut peer) = RawPeer::start(decide(WAIT * 5, 8, None), CLIENT, 34);
    let mut pending = handle.incoming_pending();
    let (_socket, syn) = client_syn(&mut peer, DIALED, 40_000)?;
    let copy = PacketBuf::from_packet(syn.as_packet());
    peer.sink.send(syn, PeerId::new(0)).await?;
    let _item = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;
    peer.sink.send(copy, PeerId::new(0)).await?;
    sleep(Duration::from_millis(50)).await;
    assert!(try_next(&mut pending).is_none(), "a single item");
    assert!(peer.source.rx.try_recv().is_err(), "nothing answers it");
    let stats = handle.stats();
    assert_eq!((stats.pending, stats.rejected_connection_limit), (1, 0));
    Ok(())
}

#[tokio::test]
async fn a_full_table_resets_at_once() -> TestResult {
    let (handle, mut peer) = RawPeer::start(decide(WAIT * 5, 1, None), CLIENT, 35);
    let mut pending = handle.incoming_pending();
    let (_first, syn) = client_syn(&mut peer, DIALED, 40_000)?;
    peer.sink.send(syn, PeerId::new(0)).await?;
    let _item = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;

    let (second, syn) = client_syn(&mut peer, DIALED, 40_001)?;
    peer.sink.send(syn, PeerId::new(0)).await?;
    let reset = next_egress(&mut peer).await?;
    assert_reset(
        &mut peer,
        second,
        reset,
        SocketAddr::new(DIALED.into(), 443),
        SocketAddr::new(CLIENT.into(), 40_001),
    )?;

    // A UDP flow does not fit either.
    let client: SocketAddr = "10.7.0.2:5353".parse()?;
    let dst: SocketAddr = "192.0.2.7:53".parse()?;
    let datagram = build_udp(client, dst, b"query").ok_or("build")?;
    peer.sink.send(datagram, PeerId::new(0)).await?;
    let unreachable = next_egress(&mut peer).await?;
    let ip = IpPacket::parse(unreachable.as_packet())?;
    assert_eq!((ip.src(), ip.protocol()), (dst.ip(), protocol::ICMP));

    assert!(try_next(&mut pending).is_none());
    let stats = handle.stats();
    assert_eq!((stats.rejected_table_full, stats.pending), (2, 1));
    Ok(())
}

#[tokio::test]
async fn the_connection_limit_is_checked_at_accept() -> TestResult {
    let (handle, mut peer) = RawPeer::start(decide(WAIT * 5, 8, Some(1)), CLIENT, 36);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    let (first, syn) = client_syn(&mut peer, DIALED, 40_000)?;
    peer.sink.send(syn, PeerId::new(0)).await?;
    let first_item = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;
    let (second, syn) = client_syn(&mut peer, DIALED, 40_001)?;
    peer.sink.send(syn, PeerId::new(0)).await?;
    let second_item = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;

    first_item.accept();
    peer.pump_until(|peer| peer.state(first) == tcp::State::Established)
        .await?;
    let mut conn = None;
    for _ in 0..40 {
        peer.pump(1).await;
        conn = try_next(&mut incoming);
        if conn.is_some() {
            break;
        }
    }
    let _conn = conn.ok_or("first connection should arrive")?;

    second_item.accept();
    let reset = next_egress(&mut peer).await?;
    assert_reset(
        &mut peer,
        second,
        reset,
        SocketAddr::new(DIALED.into(), 443),
        SocketAddr::new(CLIENT.into(), 40_001),
    )?;
    let stats = handle.stats();
    assert_eq!(
        (
            stats.accepted,
            stats.rejected_connection_limit,
            stats.pending
        ),
        (1, 1, 0)
    );
    Ok(())
}

/// Sends a datagram from `client` to `dst` and returns its packet and its pending item.
async fn held_datagram(
    sink: &NetStackSink,
    pending: &mut (impl Stream<Item = PendingFlow> + Send + Unpin),
    client: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Result<(Vec<u8>, PendingFlow), Box<dyn Error>> {
    let datagram = build_udp(client, dst, payload).ok_or("build")?;
    let bytes = datagram.as_packet().to_vec();
    sink.send(datagram, PeerId::new(0)).await?;
    let item = timeout(WAIT, next(pending)).await?.ok_or("no item")?;
    assert_eq!(item.protocol(), PendingProtocol::Udp);
    assert_eq!((item.peer_addr(), item.local_addr()), (client, dst));
    Ok((bytes, item))
}

#[tokio::test]
async fn an_accepted_flow_opens_with_its_first_datagram() -> TestResult {
    let (handle, peer) = RawPeer::start(decide(WAIT * 5, 8, None), CLIENT, 37);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_udp();
    let client: SocketAddr = "10.7.0.2:5353".parse()?;
    let dst: SocketAddr = "192.0.2.7:53".parse()?;
    let (_, item) = held_datagram(&peer.sink, &mut pending, client, dst, b"first").await?;
    // Dropped while the flow is held.
    let second = build_udp(client, dst, b"second").ok_or("build")?;
    peer.sink.send(second, PeerId::new(0)).await?;
    until_stats(&handle, |stats| stats.udp_queue_full == 1).await?;
    assert!(try_next(&mut incoming).is_none());
    assert!(try_next(&mut pending).is_none());

    item.accept();
    let mut flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    assert_eq!((flow.peer_addr(), flow.local_addr()), (client, dst));
    assert_eq!(
        timeout(WAIT, flow.recv()).await?.as_deref(),
        Some(&b"first"[..])
    );
    let third = build_udp(client, dst, b"third").ok_or("build")?;
    peer.sink.send(third, PeerId::new(0)).await?;
    assert_eq!(
        timeout(WAIT, flow.recv()).await?.as_deref(),
        Some(&b"third"[..])
    );
    let stats = handle.stats();
    assert_eq!((stats.accepted, stats.pending), (1, 0));
    Ok(())
}

/// Checks that `reply` is a valid port unreachable from `dst` to `client` quoting
/// `original`.
fn assert_port_unreachable(
    reply: &[u8],
    original: &[u8],
    client: SocketAddr,
    dst: SocketAddr,
) -> TestResult {
    let ip = IpPacket::parse(reply)?;
    assert_eq!((ip.src(), ip.dst()), (dst.ip(), client.ip()));
    let message = ip.payload();
    match (ip.src(), ip.dst()) {
        (IpAddr::V4(_), _) => {
            assert_eq!(ip.protocol(), protocol::ICMP);
            assert_eq!(checksum::internet_checksum(&reply[..20]), 0, "IP header");
            assert_eq!(checksum::internet_checksum(message), 0, "ICMP");
            assert_eq!(&message[..2], &[3, 3]);
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            assert_eq!(ip.protocol(), protocol::ICMPV6);
            assert_eq!(
                checksum::transport_checksum_v6(src, dst, protocol::ICMPV6, message),
                0,
                "ICMPv6"
            );
            assert_eq!(&message[..2], &[1, 4]);
        }
        _ => return Err("mixed families".into()),
    }
    assert_eq!(&message[8..], original, "the whole datagram is quoted");
    Ok(())
}

#[tokio::test]
async fn a_rejected_flow_is_answered_with_port_unreachable() -> TestResult {
    let config = NetStackConfig {
        addresses: vec![
            (IpAddr::V4(LOCAL), 32),
            (IpAddr::V6("fd00::1".parse()?), 128),
        ],
        ..decide(WAIT * 5, 8, None)
    };
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 38);
    let mut pending = handle.incoming_pending();
    let cases: [(SocketAddr, SocketAddr, bool); 3] = [
        ("10.7.0.2:5353".parse()?, "192.0.2.7:53".parse()?, false),
        (
            "[fd00::2]:5353".parse()?,
            "[2001:db8::7]:53".parse()?,
            false,
        ),
        ("10.7.0.2:5354".parse()?, "192.0.2.7:53".parse()?, true),
    ];
    for (client, dst, drop_it) in cases {
        let (original, item) =
            held_datagram(&peer.sink, &mut pending, client, dst, b"query").await?;
        if drop_it {
            drop(item);
        } else {
            item.reject();
        }
        let reply = next_egress(&mut peer).await?;
        assert_port_unreachable(reply.as_packet(), &original, client, dst)?;
    }
    let stats = handle.stats();
    assert_eq!((stats.rejected_hook, stats.pending), (3, 0));
    Ok(())
}

#[test]
fn port_unreachable_quotes_within_the_minimum_mtu() -> TestResult {
    let client: SocketAddr = "10.7.0.2:5353".parse()?;
    let dst: SocketAddr = "192.0.2.7:53".parse()?;
    let datagram = build_udp(client, dst, &[7; 1000]).ok_or("build")?;
    let reply = crate::pending::port_unreachable(datagram.as_packet(), 1360).ok_or("build")?;
    assert_eq!(reply.len(), 576);
    let quoted = 576 - 28;
    assert_port_unreachable(
        reply.as_packet(),
        &datagram.as_packet()[..quoted],
        client,
        dst,
    )?;

    let client: SocketAddr = "[fd00::2]:5353".parse()?;
    let dst: SocketAddr = "[2001:db8::7]:53".parse()?;
    let datagram = build_udp(client, dst, &[7; 1400]).ok_or("build")?;
    let reply = crate::pending::port_unreachable(datagram.as_packet(), 1360).ok_or("build")?;
    assert_eq!(reply.len(), 1280);
    assert_port_unreachable(
        reply.as_packet(),
        &datagram.as_packet()[..1280 - 48],
        client,
        dst,
    )?;
    Ok(())
}

#[tokio::test]
async fn incoming_pending_ends_without_decide() -> TestResult {
    let (_stack, handle) = NetStack::new(config(LOCAL));
    assert!(
        timeout(WAIT, next(&mut handle.incoming_pending()))
            .await?
            .is_none()
    );
    let (_stack, handle) = NetStack::new(decide(WAIT, 8, None));
    let _first = handle.incoming_pending();
    assert!(
        timeout(WAIT, next(&mut handle.incoming_pending()))
            .await?
            .is_none()
    );
    Ok(())
}
