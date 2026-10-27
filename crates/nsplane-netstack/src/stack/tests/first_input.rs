//! Control from the first input: the `FlowControl` of a lifetime held under
//! `Admission::Decide` from its `PendingFlow` on, its delivery receipt, and a revoke at every
//! stage before and after the hand-out.

use std::net::SocketAddrV4;

use super::*;
use crate::{
    DeliveryOutcome, FlowControl, Ownership, PendingFlow, PendingProtocol, RetirementOutcome,
    TransparentConfig, Undelivered,
};

const RST: u8 = 0x04;
const ACK: u8 = 0x10;

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
const DIALED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);

const DECIDE: Admission = Admission::Decide {
    timeout: Duration::from_secs(5),
    max_pending: 8,
};

/// An ordinary stack at [`LOCAL`] admitting with `admission`.
fn ordinary(admission: Admission) -> NetStackConfig {
    NetStackConfig {
        admission,
        ..config(LOCAL)
    }
}

/// A transparent stack at [`LOCAL`] for every destination, admitting with `admission`.
fn transparent(admission: Admission) -> NetStackConfig {
    NetStackConfig {
        admission,
        transparent: Some(TransparentConfig::default()),
        ..config(LOCAL)
    }
}

/// Waits for the delivery outcome of `control`'s lifetime.
async fn delivery(control: &FlowControl) -> Result<DeliveryOutcome, Box<dyn Error>> {
    Ok(timeout(WAIT, control.delivery().wait()).await?)
}

/// Revokes `control` and waits for the retirement outcome.
async fn retire(control: &FlowControl) -> Result<RetirementOutcome, Box<dyn Error>> {
    Ok(timeout(WAIT, control.revoke().wait()).await?)
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

/// Waits until `ready` holds.
async fn until(ready: impl Fn() -> bool + Sync) -> TestResult {
    timeout(WAIT, async {
        while !ready() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "the state should converge")?;
    Ok(())
}

/// Shuttles packets both ways once, taking the stack's egress through the same check as
/// `NetStackSource::recv`; returns the stack's packets it moved.
async fn pump_once(peer: &mut RawPeer) -> Vec<PacketBuf> {
    let mut seen = Vec::new();
    while let Some(packet) = peer.source.try_admit() {
        seen.push(packet.clone());
        peer.device.inject(packet);
    }
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    let packets: Vec<PacketBuf> = peer.device.drain_tx().collect();
    for packet in packets {
        let _ = peer.sink.send(packet, PeerId::new(0)).await;
    }
    seen
}

/// Shuttles packets for `ticks` short ticks; returns the stack's packets it moved.
async fn pump(peer: &mut RawPeer, ticks: usize) -> Vec<PacketBuf> {
    let mut seen = Vec::new();
    for _ in 0..ticks {
        seen.extend(pump_once(peer).await);
        sleep(Duration::from_millis(5)).await;
    }
    seen
}

/// Pumps until `ready` holds, for at most five seconds.
async fn pump_until(peer: &mut RawPeer, ready: impl Fn(&RawPeer) -> bool + Sync) -> TestResult {
    timeout(Duration::from_secs(5), async {
        while !ready(peer) {
            pump(peer, 1).await;
        }
    })
    .await
    .map_err(|_| "the state should converge")?;
    Ok(())
}

/// Pumps until `incoming` hands a connection out.
async fn handed_out(
    peer: &mut RawPeer,
    incoming: &mut (impl Stream<Item = TcpConnection> + Unpin),
) -> Result<TcpConnection, Box<dyn Error>> {
    for _ in 0..200 {
        if let Some(conn) = try_next(incoming) {
            return Ok(conn);
        }
        pump(peer, 1).await;
    }
    Err("a connection should be handed out".into())
}

/// Opens a client socket from port `port` of [`CLIENT`] to `dst:443` and sends its SYN;
/// returns the socket, a copy of the SYN and the pending item.
async fn held_syn(
    peer: &mut RawPeer,
    pending: &mut (impl Stream<Item = PendingFlow> + Unpin),
    dst: Ipv4Addr,
    port: u16,
) -> Result<(SocketHandle, PacketBuf, PendingFlow), Box<dyn Error>> {
    let socket = peer.connect(dst, 443, port)?;
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    let syn = peer.device.drain_tx().next().ok_or("no SYN")?;
    let copy = PacketBuf::from_packet(syn.as_packet());
    peer.sink.send(syn, PeerId::new(0)).await?;
    let item = timeout(WAIT, next(pending)).await?.ok_or("no item")?;
    assert_eq!(item.protocol(), PendingProtocol::Tcp);
    assert_eq!(item.peer_addr(), SocketAddr::new(CLIENT.into(), port));
    Ok((socket, copy, item))
}

/// Sends a datagram from `remote` to `local` and returns its pending item.
async fn held_datagram(
    sink: &NetStackSink,
    pending: &mut (impl Stream<Item = PendingFlow> + Unpin),
    remote: SocketAddr,
    local: SocketAddr,
    payload: &[u8],
) -> Result<PendingFlow, Box<dyn Error>> {
    datagram_in(sink, remote, local, payload).await?;
    let item = timeout(WAIT, next(pending)).await?.ok_or("no item")?;
    assert_eq!(item.protocol(), PendingProtocol::Udp);
    assert_eq!((item.peer_addr(), item.local_addr()), (remote, local));
    Ok(item)
}

/// Sends a UDP datagram from `remote` to `local` into the stack.
async fn datagram_in(
    sink: &NetStackSink,
    remote: SocketAddr,
    local: SocketAddr,
    payload: &[u8],
) -> TestResult {
    let packet = build_udp(remote, local, payload).ok_or("build")?;
    sink.send(packet, PeerId::new(0)).await?;
    Ok(())
}

/// The `(src, dst)` of a TCP or UDP packet.
fn tuple_of(packet: &PacketBuf) -> Option<(SocketAddr, SocketAddr)> {
    tcp_tuple(packet.as_packet())
        .or_else(|| udp::parse_udp(packet.clone()).map(|datagram| (datagram.src, datagram.dst)))
}

/// An IPv4 TCP segment from `src` to `dst` with `flags`, for `owns`.
fn segment(src: SocketAddr, dst: SocketAddr, flags: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (src, dst) else {
        return Err("IPv4 only".into());
    };
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = protocol::TCP;
    pkt[12..16].copy_from_slice(&src.ip().octets());
    pkt[16..20].copy_from_slice(&dst.ip().octets());
    pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
    pkt[32] = 5 << 4;
    pkt[33] = flags;
    Ok(pkt)
}

/// The RST the client of the IPv4 `syn` sends while the stack's socket is in SYN-RECEIVED:
/// sequence number ISN + 1, valid checksums.
fn client_reset(syn: &[u8]) -> Result<PacketBuf, Box<dyn Error>> {
    let (src, dst) = tcp_tuple(syn).ok_or("not TCP")?;
    let seq = u32::from_be_bytes(syn[24..28].try_into()?).wrapping_add(1);
    let mut pkt = segment(src, dst, RST)?;
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    let header = checksum::ipv4_header_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&header.to_be_bytes());
    let sum = crate::pending::pseudo_header_checksum(src.ip(), dst.ip(), protocol::TCP, &pkt[20..]);
    pkt[36..38].copy_from_slice(&sum.to_be_bytes());
    Ok(PacketBuf::from_packet(&pkt))
}

/// Whether the stack registered `client -> dialed` as a connection: its socket took the
/// SYN.
fn owns_tuple(handle: &NetStackHandle, client: SocketAddr, dialed: SocketAddr) -> bool {
    segment(client, dialed, ACK).is_ok_and(|pkt| handle.owns(&pkt) == Ownership::Flow)
}

// ── One lifetime from the first input to the handle ──────────────────

#[tokio::test]
async fn the_pending_control_is_the_delivered_connections_control() -> TestResult {
    let (handle, mut peer) = RawPeer::start(transparent(DECIDE), CLIENT, 41);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    let (socket, _, item) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let control = item.control();
    let context = control.bind_context(7)?;
    assert_eq!(control.delivery().outcome(), None);

    item.accept();
    pump_until(&mut peer, |peer| {
        peer.state(socket) == tcp::State::Established
    })
    .await?;
    let conn = handed_out(&mut peer, &mut incoming).await?;
    assert_eq!(conn.control().context(), Some(context));
    assert_eq!(
        control.delivery().outcome(),
        Some(DeliveryOutcome::Delivered)
    );
    assert_eq!(
        conn.control().delivery().outcome(),
        Some(DeliveryOutcome::Delivered)
    );
    // One lifetime: a revoke on either control is a revoke of both.
    assert_eq!(retire(&conn.control()).await?, RetirementOutcome::Retired);
    assert!(control.is_revoked());
    assert_eq!(control.revoke().outcome(), Some(RetirementOutcome::Retired));
    assert_eq!(
        control.delivery().outcome(),
        Some(DeliveryOutcome::Delivered)
    );
    Ok(())
}

#[tokio::test]
async fn the_pending_control_is_the_delivered_flows_control() -> TestResult {
    let (stack, handle) = NetStack::new(ordinary(DECIDE));
    let (_source, sink) = stack.split();
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_udp();
    let remote: SocketAddr = "10.8.0.2:5353".parse()?;
    let local: SocketAddr = "10.8.0.1:53".parse()?;
    let item = held_datagram(&sink, &mut pending, remote, local, b"first").await?;
    let control = item.control();
    let context = control.bind_context(9)?;
    item.accept();
    let mut flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    assert_eq!(flow.control().context(), Some(context));
    assert_eq!(delivery(&control).await?, DeliveryOutcome::Delivered);
    assert_eq!(
        timeout(WAIT, flow.recv()).await?.as_deref(),
        Some(&b"first"[..])
    );
    assert_eq!(
        retire(&flow.reply_handle().control()).await?,
        RetirementOutcome::Retired
    );
    assert!(control.is_revoked());
    assert_eq!(handle.stats().accepted, 1);
    Ok(())
}

#[tokio::test]
async fn immediate_and_opened_handles_report_delivered_at_once() -> TestResult {
    let server: SocketAddr = "10.8.0.1:53".parse()?;
    let (stack, handle) = NetStack::new(ordinary(Admission::Immediate));
    let (_source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    datagram_in(&sink, "10.8.0.2:5353".parse()?, server, b"x").await?;
    let flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    let delivered = Some(DeliveryOutcome::Delivered);
    assert_eq!(flow.control().delivery().outcome(), delivered);
    let bound = handle.bind_udp("10.8.0.1:5000".parse()?).await?;
    assert_eq!(bound.control().delivery().outcome(), delivered);
    let connected = handle.connect_udp("10.8.0.2:6000".parse()?).await?;
    assert_eq!(connected.control().delivery().outcome(), delivered);
    // A revoke of a delivered flow leaves the delivery as it was.
    assert_eq!(retire(&flow.control()).await?, RetirementOutcome::Retired);
    assert_eq!(flow.control().delivery().outcome(), delivered);
    Ok(())
}

// ── Ordinary stacks ──────────────────────────────────────────────────

#[tokio::test]
async fn an_ordinary_stack_decides_on_its_own_addresses() -> TestResult {
    let (handle, mut peer) = RawPeer::start(ordinary(DECIDE), CLIENT, 42);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    let ours = SocketAddr::new(LOCAL.into(), 443);

    // Rejected: a RST from the stack's own address, nothing else.
    let (socket, _, item) = held_syn(&mut peer, &mut pending, LOCAL, 40_000).await?;
    assert_eq!(item.local_addr(), ours);
    let control = item.control();
    pump(&mut peer, 4).await;
    assert_eq!(peer.state(socket), tcp::State::SynSent, "held");
    item.reject();
    assert_eq!(
        delivery(&control).await?,
        DeliveryOutcome::NotDelivered(Undelivered::Rejected)
    );
    let seen = pump(&mut peer, 4).await;
    assert_eq!(seen.len(), 1);
    assert_eq!(
        tcp_tuple(seen[0].as_packet()),
        Some((ours, SocketAddr::new(CLIENT.into(), 40_000)))
    );
    assert_eq!(peer.state(socket), tcp::State::Closed);

    // Accepted: handed out as on a transparent stack.
    let (socket, _, item) = held_syn(&mut peer, &mut pending, LOCAL, 40_001).await?;
    let control = item.control();
    item.accept();
    pump_until(&mut peer, |peer| {
        peer.state(socket) == tcp::State::Established
    })
    .await?;
    let conn = handed_out(&mut peer, &mut incoming).await?;
    assert_eq!(conn.local_addr(), ours);
    assert_eq!(delivery(&control).await?, DeliveryOutcome::Delivered);

    // A datagram to another address is not the stack's: neither held nor answered.
    datagram_in(
        &peer.sink,
        "10.8.0.2:5353".parse()?,
        "10.8.0.9:53".parse()?,
        b"x",
    )
    .await?;
    until_stats(&handle, |stats| stats.no_address == 1).await?;
    assert!(try_next(&mut pending).is_none());

    // UDP to the stack's address: a rejection is a port unreachable from it.
    let remote: SocketAddr = "10.8.0.2:5353".parse()?;
    let local: SocketAddr = "10.8.0.1:53".parse()?;
    let item = held_datagram(&peer.sink, &mut pending, remote, local, b"query").await?;
    item.reject();
    let reply = timeout(WAIT, peer.source.rx.recv())
        .await?
        .ok_or("stopped")?;
    let ip = IpPacket::parse(reply.as_packet())?;
    assert_eq!(
        (ip.src(), ip.dst(), ip.protocol()),
        (local.ip(), remote.ip(), protocol::ICMP)
    );
    let stats = handle.stats();
    assert_eq!(
        (stats.accepted, stats.rejected_hook, stats.pending),
        (1, 2, 0)
    );
    Ok(())
}

// ── A revoke at every stage ──────────────────────────────────────────

#[tokio::test]
async fn a_revoke_while_held_retires_and_sends_nothing() -> TestResult {
    let (handle, mut peer) = RawPeer::start(transparent(DECIDE), CLIENT, 43);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    // One item is accepted after the revoke, the other dropped: neither answers.
    for (port, accept) in [(40_000, true), (40_001, false)] {
        let (socket, _, item) = held_syn(&mut peer, &mut pending, DIALED, port).await?;
        let control = item.control();
        let receipt = control.revoke();
        assert_eq!(
            control.delivery().outcome(),
            Some(DeliveryOutcome::NotDelivered(Undelivered::Revoked))
        );
        assert_eq!(
            timeout(WAIT, receipt.wait()).await?,
            RetirementOutcome::Retired
        );
        until_stats(&handle, |stats| stats.pending == 0).await?;
        if accept {
            item.accept();
        } else {
            drop(item);
        }
        assert!(pump(&mut peer, 6).await.is_empty(), "no SYN-ACK and no RST");
        assert_eq!(peer.state(socket), tcp::State::SynSent);
        assert!(try_next(&mut incoming).is_none());
    }

    // UDP: no flow and no port unreachable.
    let mut flows = handle.incoming_udp();
    let remote: SocketAddr = "10.8.0.2:5353".parse()?;
    let local: SocketAddr = "192.0.2.7:53".parse()?;
    let item = held_datagram(&peer.sink, &mut pending, remote, local, b"query").await?;
    assert_eq!(retire(&item.control()).await?, RetirementOutcome::Retired);
    item.accept();
    assert!(pump(&mut peer, 6).await.is_empty());
    assert!(try_next(&mut flows).is_none());
    let stats = handle.stats();
    assert_eq!(
        (stats.pending, stats.accepted, stats.rejected_hook),
        (0, 0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn a_revoke_after_accept_before_the_next_turn_retires() -> TestResult {
    let (handle, mut peer) = RawPeer::start(transparent(DECIDE), CLIENT, 44);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    let (socket, _, item) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let control = item.control();
    // No await in between: the driver sees the decision and the revoke in one turn.
    item.accept();
    let receipt = control.revoke();
    assert_eq!(
        timeout(WAIT, receipt.wait()).await?,
        RetirementOutcome::Retired
    );
    assert_eq!(
        delivery(&control).await?,
        DeliveryOutcome::NotDelivered(Undelivered::Revoked)
    );
    assert!(pump(&mut peer, 6).await.is_empty(), "no SYN-ACK");
    assert_eq!(peer.state(socket), tcp::State::SynSent);
    assert!(try_next(&mut incoming).is_none());

    let mut flows = handle.incoming_udp();
    let remote: SocketAddr = "10.8.0.2:5353".parse()?;
    let local: SocketAddr = "192.0.2.7:53".parse()?;
    let item = held_datagram(&peer.sink, &mut pending, remote, local, b"query").await?;
    let control = item.control();
    item.accept();
    assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
    assert!(pump(&mut peer, 6).await.is_empty());
    assert!(try_next(&mut flows).is_none());
    assert_eq!(
        control.delivery().outcome(),
        Some(DeliveryOutcome::NotDelivered(Undelivered::Revoked))
    );
    Ok(())
}

#[tokio::test]
async fn a_revoke_in_syn_received_drops_the_syn_ack_and_a_new_syn_is_a_new_lifetime() -> TestResult
{
    let (handle, mut peer) = RawPeer::start(transparent(DECIDE), CLIENT, 45);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    let client = SocketAddr::new(CLIENT.into(), 40_000);
    let dialed = SocketAddr::new(DIALED.into(), 443);
    let (socket, _, item) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let control = item.control();
    let first = control.bind_context(1)?;
    item.accept();
    // The socket took the SYN; its SYN-ACK waits in the egress queue.
    until(|| owns_tuple(&handle, client, dialed)).await?;
    assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
    assert_eq!(
        control.delivery().outcome(),
        Some(DeliveryOutcome::NotDelivered(Undelivered::Revoked))
    );
    assert!(!owns_tuple(&handle, client, dialed));
    let seen = pump(&mut peer, 6).await;
    assert!(
        seen.iter()
            .all(|packet| tuple_of(packet) != Some((dialed, client))),
        "SYN-ACK held back"
    );
    assert!(handle.retired_drops() >= 1, "the SYN-ACK counts as retired");
    assert_eq!(peer.state(socket), tcp::State::SynSent);

    // The client retransmits its SYN: a new lifetime with its own control.
    let mut item = None;
    for _ in 0..400 {
        pump(&mut peer, 1).await;
        item = try_next(&mut pending);
        if item.is_some() {
            break;
        }
    }
    let item = item.ok_or("the retransmitted SYN should be held anew")?;
    let control = item.control();
    assert!(!control.is_revoked());
    let second = control.bind_context(1)?;
    assert_ne!(first, second);
    item.accept();
    pump_until(&mut peer, |peer| {
        peer.state(socket) == tcp::State::Established
    })
    .await?;
    let conn = handed_out(&mut peer, &mut incoming).await?;
    assert_eq!(conn.control().context(), Some(second));
    assert!(
        try_next(&mut incoming).is_none(),
        "nothing of the revoked lifetime"
    );
    Ok(())
}

#[tokio::test]
async fn a_revoke_while_waiting_for_the_accept_queue_retires() -> TestResult {
    let config = NetStackConfig {
        accept_capacity: 1,
        accept_backpressure: true,
        ..transparent(DECIDE)
    };
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 46);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    let (first, _, first_item) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let (second, _, second_item) = held_syn(&mut peer, &mut pending, DIALED, 40_001).await?;
    let control = second_item.control();
    first_item.accept();
    second_item.accept();
    pump_until(&mut peer, |peer| {
        peer.state(first) == tcp::State::Established
            && peer.state(second) == tcp::State::Established
    })
    .await?;
    pump(&mut peer, 4).await;
    assert_eq!(control.delivery().outcome(), None, "waiting in the stack");

    assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
    let client = SocketAddr::new(CLIENT.into(), 40_001);
    let seen = pump(&mut peer, 6).await;
    assert!(
        seen.iter()
            .all(|packet| tuple_of(packet).is_none_or(|(_, dst)| dst != client))
    );
    let conn = timeout(WAIT, next(&mut incoming)).await?.ok_or("first")?;
    assert_eq!(conn.peer_addr(), SocketAddr::new(CLIENT.into(), 40_000));
    pump(&mut peer, 6).await;
    assert!(
        try_next(&mut incoming).is_none(),
        "the revoked one never arrives"
    );
    assert_eq!(
        control.delivery().outcome(),
        Some(DeliveryOutcome::NotDelivered(Undelivered::Revoked))
    );
    Ok(())
}

#[tokio::test]
async fn a_revoke_in_the_accept_channel_is_never_handed_out() -> TestResult {
    let (handle, mut peer) = RawPeer::start(transparent(DECIDE), CLIENT, 47);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    let (socket, _, item) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let control = item.control();
    item.accept();
    pump_until(&mut peer, |peer| {
        peer.state(socket) == tcp::State::Established
    })
    .await?;
    pump(&mut peer, 4).await;
    assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
    assert_eq!(
        control.delivery().outcome(),
        Some(DeliveryOutcome::NotDelivered(Undelivered::Revoked))
    );
    let client = SocketAddr::new(CLIENT.into(), 40_000);
    let seen = pump(&mut peer, 6).await;
    assert!(
        seen.iter()
            .all(|packet| tuple_of(packet).is_none_or(|(_, dst)| dst != client)),
        "no FIN, no RST"
    );
    assert!(try_next(&mut incoming).is_none());

    // UDP: the flow and its datagrams are skipped; the tuple's next datagram is a new
    // lifetime.
    let mut flows = handle.incoming_udp();
    let remote: SocketAddr = "10.8.0.2:5353".parse()?;
    let local: SocketAddr = "192.0.2.7:53".parse()?;
    let item = held_datagram(&peer.sink, &mut pending, remote, local, b"one").await?;
    let control = item.control();
    item.accept();
    until(|| {
        build_udp(remote, local, b"probe")
            .is_some_and(|packet| handle.owns(packet.as_packet()) == Ownership::Flow)
    })
    .await?;
    assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
    assert!(try_next(&mut flows).is_none());
    let item = held_datagram(&peer.sink, &mut pending, remote, local, b"two").await?;
    assert!(!item.control().is_revoked());
    item.accept();
    let mut flow = timeout(WAIT, next(&mut flows)).await?.ok_or("new flow")?;
    assert_eq!(
        timeout(WAIT, flow.recv()).await?.as_deref(),
        Some(&b"two"[..])
    );
    assert_eq!(
        control.delivery().outcome(),
        Some(DeliveryOutcome::NotDelivered(Undelivered::Revoked))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoke_racing_the_hand_out_ends_with_one_outcome() -> TestResult {
    const ROUNDS: usize = 200;
    let remote: SocketAddr = "10.8.0.2:5353".parse()?;
    let local: SocketAddr = "10.8.0.1:53".parse()?;
    let spin = |turns: usize| {
        for _ in 0..turns * 64 {
            std::hint::spin_loop();
        }
    };
    let (mut delivered, mut revoked) = (0, 0);
    for round in 0..ROUNDS {
        let (stack, handle) = NetStack::new(ordinary(DECIDE));
        let (_source, sink) = stack.split();
        let mut pending = handle.incoming_pending();
        let mut incoming = handle.incoming_udp();
        let item = held_datagram(&sink, &mut pending, remote, local, b"x").await?;
        let control = item.control();
        item.accept();
        until(|| {
            build_udp(remote, local, b"probe")
                .is_some_and(|packet| handle.owns(packet.as_packet()) == Ownership::Flow)
        })
        .await?;
        // Two threads released together, each after its own short spin.
        let start = std::sync::Barrier::new(2);
        let (flow, receipt) = std::thread::scope(|scope| {
            let taker = scope.spawn(|| {
                start.wait();
                spin(round % 8);
                try_next(&mut incoming)
            });
            let revoker = scope.spawn(|| {
                start.wait();
                spin(round / 8 % 8);
                control.revoke()
            });
            (taker.join(), revoker.join())
        });
        let (flow, receipt) = (
            flow.map_err(|_| "taker panicked")?,
            receipt.map_err(|_| "revoker panicked")?,
        );
        assert_eq!(
            timeout(WAIT, receipt.wait()).await?,
            RetirementOutcome::Retired
        );
        if let Some(flow) = flow {
            delivered += 1;
            assert_eq!(
                control.delivery().outcome(),
                Some(DeliveryOutcome::Delivered)
            );
            assert!(flow.control().is_revoked());
        } else {
            revoked += 1;
            assert_eq!(
                control.delivery().outcome(),
                Some(DeliveryOutcome::NotDelivered(Undelivered::Revoked))
            );
        }
        assert!(try_next(&mut incoming).is_none(), "never handed out later");
    }
    assert_eq!(delivered + revoked, ROUNDS);
    Ok(())
}

// ── Every reason a lifetime is not delivered ─────────────────────────

#[tokio::test]
async fn rejected_and_timed_out_lifetimes_are_not_delivered() -> TestResult {
    let admission = Admission::Decide {
        timeout: Duration::from_millis(100),
        max_pending: 8,
    };
    let (stack, handle) = NetStack::new(ordinary(admission));
    let (_source, sink) = stack.split();
    let mut pending = handle.incoming_pending();
    let local: SocketAddr = "10.8.0.1:53".parse()?;
    let rejected = held_datagram(&sink, &mut pending, "10.8.0.2:1".parse()?, local, b"x").await?;
    let dropped = held_datagram(&sink, &mut pending, "10.8.0.2:2".parse()?, local, b"x").await?;
    let late = held_datagram(&sink, &mut pending, "10.8.0.2:3".parse()?, local, b"x").await?;
    let controls = [rejected.control(), dropped.control(), late.control()];
    rejected.reject();
    drop(dropped);
    let rejected_outcome = DeliveryOutcome::NotDelivered(Undelivered::Rejected);
    assert_eq!(delivery(&controls[0]).await?, rejected_outcome);
    assert_eq!(delivery(&controls[1]).await?, rejected_outcome);
    assert_eq!(
        delivery(&controls[2]).await?,
        DeliveryOutcome::NotDelivered(Undelivered::TimedOut)
    );
    late.accept();
    sleep(Duration::from_millis(20)).await;
    assert_eq!(
        controls[2].delivery().outcome(),
        Some(DeliveryOutcome::NotDelivered(Undelivered::TimedOut))
    );
    // Ended undelivered and holding nothing: a revoke retires at once.
    assert_eq!(retire(&controls[2]).await?, RetirementOutcome::Retired);
    let stats = handle.stats();
    assert_eq!((stats.rejected_hook, stats.rejected_timeout), (2, 1));
    Ok(())
}

#[tokio::test]
async fn the_connection_limit_at_accept_is_not_delivered() -> TestResult {
    let config = NetStackConfig {
        admission: DECIDE,
        transparent: Some(TransparentConfig {
            max_connections: Some(1),
            ..Default::default()
        }),
        ..config(LOCAL)
    };
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 48);
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_tcp();
    let (first, _, first_item) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let (_, _, second_item) = held_syn(&mut peer, &mut pending, DIALED, 40_001).await?;
    let control = second_item.control();
    first_item.accept();
    pump_until(&mut peer, |peer| {
        peer.state(first) == tcp::State::Established
    })
    .await?;
    let _conn = handed_out(&mut peer, &mut incoming).await?;
    second_item.accept();
    assert_eq!(
        delivery(&control).await?,
        DeliveryOutcome::NotDelivered(Undelivered::ConnectionLimit)
    );
    assert_eq!(handle.stats().rejected_connection_limit, 1);
    Ok(())
}

#[tokio::test]
async fn a_syn_without_a_listener_socket_is_not_delivered() -> TestResult {
    let config = NetStackConfig {
        listener_pool: 1,
        ..transparent(DECIDE)
    };
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 49);
    let mut pending = handle.incoming_pending();
    let (_, _, first) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let (_, _, second) = held_syn(&mut peer, &mut pending, DIALED, 40_001).await?;
    let controls = [first.control(), second.control()];
    // Both in one driver turn: the pool has one socket for the port.
    first.accept();
    second.accept();
    until(|| {
        controls.iter().any(|control| {
            control.delivery().outcome()
                == Some(DeliveryOutcome::NotDelivered(Undelivered::NoListener))
        })
    })
    .await?;
    let refused = controls
        .iter()
        .filter(|control| {
            control.delivery().outcome()
                == Some(DeliveryOutcome::NotDelivered(Undelivered::NoListener))
        })
        .count();
    assert_eq!(refused, 1);
    assert_eq!(handle.stats().syn_refused, 1);
    Ok(())
}

#[tokio::test]
async fn a_handshake_reset_in_syn_received_is_not_delivered() -> TestResult {
    let (handle, mut peer) = RawPeer::start(transparent(DECIDE), CLIENT, 50);
    let mut pending = handle.incoming_pending();
    let client = SocketAddr::new(CLIENT.into(), 40_000);
    let dialed = SocketAddr::new(DIALED.into(), 443);
    let (_, syn, item) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let control = item.control();
    item.accept();
    until(|| owns_tuple(&handle, client, dialed)).await?;
    peer.sink
        .send(client_reset(syn.as_packet())?, PeerId::new(0))
        .await?;
    assert_eq!(
        delivery(&control).await?,
        DeliveryOutcome::NotDelivered(Undelivered::HandshakeFailed)
    );
    assert_eq!(handle.stats().handshake_failed, 1);
    assert!(!owns_tuple(&handle, client, dialed));
    // Its SYN-ACK still in the egress queue goes with a revoke.
    assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
    let seen = pump(&mut peer, 4).await;
    assert!(
        seen.iter()
            .all(|packet| tuple_of(packet) != Some((dialed, client)))
    );
    Ok(())
}

#[tokio::test]
async fn a_handshake_reset_on_an_immediate_stack_is_counted() -> TestResult {
    let server: SocketAddrV4 = "10.8.0.1:443".parse()?;
    let (handle, mut peer) = RawPeer::start(config(LOCAL), CLIENT, 51);
    let _incoming = handle.incoming_tcp();
    peer.connect(*server.ip(), server.port(), 40_000)?;
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    let syn = peer.device.drain_tx().next().ok_or("no SYN")?;
    let reset = client_reset(syn.as_packet())?;
    peer.sink.send(syn, PeerId::new(0)).await?;
    let client = SocketAddr::new(CLIENT.into(), 40_000);
    until(|| owns_tuple(&handle, client, SocketAddr::V4(server))).await?;
    peer.sink.send(reset, PeerId::new(0)).await?;
    until_stats(&handle, |stats| stats.handshake_failed == 1).await?;
    Ok(())
}

#[tokio::test]
async fn a_full_or_gone_accept_queue_is_not_delivered() -> TestResult {
    let config = NetStackConfig {
        accept_capacity: 1,
        ..transparent(DECIDE)
    };
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 52);
    let mut pending = handle.incoming_pending();
    let incoming = handle.incoming_tcp();
    let (first, _, first_item) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let (second, _, second_item) = held_syn(&mut peer, &mut pending, DIALED, 40_001).await?;
    let controls = [first_item.control(), second_item.control()];
    first_item.accept();
    pump_until(&mut peer, |peer| {
        peer.state(first) == tcp::State::Established
    })
    .await?;
    pump(&mut peer, 4).await;
    second_item.accept();
    pump_until(&mut peer, |peer| peer.state(second) != tcp::State::SynSent).await?;
    assert_eq!(
        delivery(&controls[1]).await?,
        DeliveryOutcome::NotDelivered(Undelivered::AcceptQueueFull)
    );
    assert_eq!(handle.stats().tcp_not_accepted, 1);

    // The connection in the channel when the stream is dropped.
    assert_eq!(controls[0].delivery().outcome(), None);
    drop(incoming);
    assert_eq!(
        delivery(&controls[0]).await?,
        DeliveryOutcome::NotDelivered(Undelivered::AcceptQueueGone)
    );

    // The stream gone before the connection is established.
    let (third, _, third_item) = held_syn(&mut peer, &mut pending, DIALED, 40_002).await?;
    let control = third_item.control();
    third_item.accept();
    pump_until(&mut peer, |peer| {
        peer.state(third) == tcp::State::Established
    })
    .await?;
    assert_eq!(
        delivery(&control).await?,
        DeliveryOutcome::NotDelivered(Undelivered::AcceptQueueGone)
    );
    assert_eq!(handle.stats().tcp_not_accepted, 2);
    Ok(())
}

#[tokio::test]
async fn a_full_or_gone_udp_accept_queue_and_the_flow_limit_are_not_delivered() -> TestResult {
    let config = NetStackConfig {
        accept_capacity: 1,
        max_udp_flows: 2,
        ..ordinary(DECIDE)
    };
    let (stack, handle) = NetStack::new(config);
    let (_source, sink) = stack.split();
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_udp();
    let local: SocketAddr = "10.8.0.1:53".parse()?;
    let mut held = Vec::new();
    for port in 1..=4 {
        let remote = SocketAddr::new(CLIENT.into(), port);
        held.push(held_datagram(&sink, &mut pending, remote, local, b"x").await?);
    }
    let controls: Vec<FlowControl> = held.iter().map(PendingFlow::control).collect();
    let mut held = held.into_iter();
    // The first fills the channel, the second finds it full.
    held.next().ok_or("item")?.accept();
    held.next().ok_or("item")?.accept();
    assert_eq!(
        delivery(&controls[1]).await?,
        DeliveryOutcome::NotDelivered(Undelivered::AcceptQueueFull)
    );
    let _first = timeout(WAIT, next(&mut incoming)).await?.ok_or("first")?;
    assert_eq!(delivery(&controls[0]).await?, DeliveryOutcome::Delivered);
    // The third opens the second flow, which leaves the fourth over the limit.
    held.next().ok_or("item")?.accept();
    held.next().ok_or("item")?.accept();
    assert_eq!(
        delivery(&controls[3]).await?,
        DeliveryOutcome::NotDelivered(Undelivered::FlowLimit)
    );
    // The third, still in the channel, goes with the stream.
    drop(incoming);
    assert_eq!(
        delivery(&controls[2]).await?,
        DeliveryOutcome::NotDelivered(Undelivered::AcceptQueueGone)
    );
    let stats = handle.stats();
    assert_eq!((stats.udp_not_accepted, stats.udp_flow_limit), (1, 1));
    Ok(())
}

#[tokio::test]
async fn a_stopped_stack_delivers_nothing_more() -> TestResult {
    let (stack, handle) = NetStack::new(ordinary(DECIDE));
    let (_source, sink) = stack.split();
    let mut pending = handle.incoming_pending();
    let mut incoming = handle.incoming_udp();
    let local: SocketAddr = "10.8.0.1:53".parse()?;
    let held = held_datagram(&sink, &mut pending, "10.8.0.2:1".parse()?, local, b"x").await?;
    let queued = held_datagram(&sink, &mut pending, "10.8.0.2:2".parse()?, local, b"x").await?;
    let controls = [held.control(), queued.control()];
    queued.accept();
    let probe = build_udp("10.8.0.2:2".parse()?, local, b"probe").ok_or("build")?;
    until(|| handle.owns(probe.as_packet()) == Ownership::Flow).await?;

    drop(sink);
    let stopped = DeliveryOutcome::NotDelivered(Undelivered::Stopped);
    assert_eq!(delivery(&controls[0]).await?, stopped);
    assert_eq!(delivery(&controls[1]).await?, stopped);
    assert!(
        timeout(WAIT, next(&mut incoming)).await?.is_none(),
        "skipped"
    );
    assert_eq!(retire(&controls[0]).await?, RetirementOutcome::Unknown);
    held.accept();
    Ok(())
}

// ── Refusals ─────────────────────────────────────────────────────────

#[tokio::test]
async fn refusals_on_a_lifetime_not_handed_out() -> TestResult {
    let (handle, mut peer) = RawPeer::start(transparent(DECIDE), CLIENT, 53);
    let mut pending = handle.incoming_pending();
    let (_, _, item) = held_syn(&mut peer, &mut pending, DIALED, 40_000).await?;
    let control = item.control();
    let not_adopted = |source: &NetStackSource| {
        source
            .tcp_egress_drained(&control)
            .err()
            .map(|error| error.kind())
    };
    assert_eq!(
        not_adopted(&peer.source),
        Some(io::ErrorKind::InvalidInput),
        "held"
    );
    item.accept();
    let client = SocketAddr::new(CLIENT.into(), 40_000);
    until(|| owns_tuple(&handle, client, SocketAddr::new(DIALED.into(), 443))).await?;
    assert_eq!(
        not_adopted(&peer.source),
        Some(io::ErrorKind::InvalidInput),
        "mid handshake"
    );
    control.bind_context(1)?;
    let error = control.bind_context(2).err().ok_or("bound once")?;
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);

    let udp = held_datagram(
        &peer.sink,
        &mut pending,
        "10.8.0.2:5353".parse()?,
        "192.0.2.7:53".parse()?,
        b"x",
    )
    .await?;
    let control = udp.control();
    let error = peer
        .source
        .tcp_egress_drained(&control)
        .err()
        .ok_or("not TCP")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
    let error = control.bind_context(3).err().ok_or("revoked")?;
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    Ok(())
}
