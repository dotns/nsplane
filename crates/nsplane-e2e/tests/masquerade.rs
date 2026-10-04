//! The local-side `Masquerade` between an IPv6 client and a LAN host: the client (a
//! netstack in the place of the service TUN) talks TCP and UDP to the LAN host (a second
//! netstack), `forward` gives each flow the masquerade source and a token from the
//! configured range, and `reverse` restores the client as the destination of the replies.
//! Covers an `ICMPv6` Echo answered by `nsplane_packet::icmp::echo_reply_in_place` on the
//! far side (and an IPv4 Echo through `echo_reply_in_place` alone, which the masquerade
//! passes), a route change that drops the next reply and removes its flow (or, with
//! `recheck_route_on_forward`, the next forward packet), and the counters.
//!
//! The masquerade is applied at the netstack hop by a test-local pump, as `redirect.rs`
//! does; it moves to the `MapSink` / `MapSource` wrappers once those land.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use nsplane::{PacketBuf, PacketSink, PacketSource};
use nsplane_e2e::{QUIET, TRANSFER, TestResult, WAIT, icmp, next_within, verify_checksums};
use nsplane_nat::masquerade::reasons;
use nsplane_nat::{Masquerade, MasqueradeConfig, MasqueradeDecision, MasqueradeVerdict};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, UdpFlow, UdpSocket};
use nsplane_packet::icmp::echo_reply_in_place;
use nsplane_packet::{FiveTuple, IpPacket, PeerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// The client's address (ns's LAN host `fd00:aa::10`).
const CLIENT: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xaa, 0, 0, 0, 0, 0, 0x10);
/// The LAN host the client talks to.
const LAN_HOST: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 0, 0, 0xb01);
/// The masquerade source the decision closure answers; the LAN host replies to it.
const SOURCE: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 2, 2, 0, 0, 0x6440, 1);
/// The services of the LAN host.
const TCP_PORT: u16 = 80;
const UDP_PORT: u16 = 53;
/// The tokens the masquerade hands out.
const PORTS: RangeInclusive<u16> = 50_000..=50_099;
/// `ICMPv6` and ICMP Echo request / reply types.
const ECHO_REQUEST_V6: u8 = 128;
const ECHO_REPLY_V6: u8 = 129;
const ECHO_REQUEST_V4: u8 = 8;
const ECHO_REPLY_V4: u8 = 0;

/// The client, the LAN host and the masquerade between them.
struct Rig {
    client: NetStackHandle,
    lan: NetStackHandle,
    masquerade: Arc<Masquerade>,
    /// The route the decision closure answers.
    route: Arc<AtomicU64>,
    /// Calls of the decision closure.
    decisions: Arc<AtomicUsize>,
    /// Drop reasons of either direction, in order.
    drops: mpsc::UnboundedReceiver<&'static str>,
}

/// Starts both stacks and the masquerade between them.
///
/// The decision closure masquerades every flow of the client to [`SOURCE`] with the route
/// `route` holds when it is asked, and passes everything else.
fn rig() -> Rig {
    rig_with(MasqueradeConfig {
        ports: PORTS,
        ..MasqueradeConfig::default()
    })
}

/// As [`rig`], with the masquerade settings `config`.
fn rig_with(config: MasqueradeConfig) -> Rig {
    let route = Arc::new(AtomicU64::new(1));
    let decisions = Arc::new(AtomicUsize::new(0));
    let (current, counter) = (Arc::clone(&route), Arc::clone(&decisions));
    let decide = move |tuple: &FiveTuple| {
        counter.fetch_add(1, Ordering::Relaxed);
        (tuple.src == IpAddr::V6(CLIENT)).then(|| MasqueradeDecision {
            source: SOURCE,
            route: current.load(Ordering::Relaxed),
        })
    };
    let masquerade = Arc::new(Masquerade::new(decide, config));

    let (client_stack, client) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V6(CLIENT), 128)],
        DEFAULT_MTU,
    ));
    let (lan_stack, lan) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V6(LAN_HOST), 128)],
        DEFAULT_MTU,
    ));
    let (client_out, client_in) = client_stack.split();
    let (lan_out, lan_in) = lan_stack.split();
    let (dropped, drops) = mpsc::unbounded_channel();
    pump(
        client_out,
        lan_in,
        Arc::clone(&masquerade),
        Masquerade::forward,
        dropped.clone(),
    );
    pump(
        lan_out,
        client_in,
        Arc::clone(&masquerade),
        Masquerade::reverse,
        dropped,
    );
    Rig {
        client,
        lan,
        masquerade,
        route,
        decisions,
        drops,
    }
}

/// Moves packets from `from` to `to` through `step` until either side stops, as the local
/// path would: rewritten and passed packets go on, dropped ones are reported on `dropped`.
fn pump<S, K>(
    mut from: S,
    to: K,
    masquerade: Arc<Masquerade>,
    step: fn(&Masquerade, &mut PacketBuf) -> MasqueradeVerdict,
    dropped: mpsc::UnboundedSender<&'static str>,
) where
    S: PacketSource + Send + 'static,
    K: PacketSink + Send + Sync + 'static,
{
    tokio::spawn(async move {
        while let Ok(mut packet) = from.recv().await {
            if let MasqueradeVerdict::Drop(reason) = step(&masquerade, &mut packet) {
                // The test may have stopped listening; the pump still runs.
                let _ = dropped.send(reason);
                continue;
            }
            if to.send(packet, PeerId::new(0)).await.is_err() {
                break;
            }
        }
    });
}

const fn v6(ip: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(ip), port)
}

/// Checks that the LAN host sees `peer` as a masqueraded source: [`SOURCE`] and a token.
fn assert_masqueraded(peer: SocketAddr) {
    assert_eq!(peer.ip(), IpAddr::V6(SOURCE));
    assert!(
        PORTS.contains(&peer.port()),
        "token {} out of range",
        peer.port()
    );
}

/// The next datagram of `socket` within [`WAIT`], with its source.
async fn recv(socket: &mut UdpSocket) -> TestResult<(Vec<u8>, SocketAddr)> {
    let (datagram, from) = timeout(WAIT, socket.recv_from()).await??;
    Ok((datagram.to_vec(), from))
}

/// The next drop reason of the pumps within [`WAIT`].
async fn next_drop(drops: &mut mpsc::UnboundedReceiver<&'static str>) -> TestResult<&'static str> {
    Ok(timeout(WAIT, drops.recv()).await?.ok_or("pumps stopped")?)
}

/// Sends `payload` from `socket` to the LAN host's UDP service, accepts the flow the LAN
/// host reports for it and checks that it carries the payload from a masqueraded source.
async fn open_udp_flow(
    socket: &UdpSocket,
    incoming: &mut (impl futures_core::Stream<Item = UdpFlow> + Unpin),
    payload: &[u8],
) -> TestResult<UdpFlow> {
    socket.send_to(payload, v6(LAN_HOST, UDP_PORT)).await?;
    let mut flow = next_within(incoming, WAIT).await?;
    let received = timeout(WAIT, flow.recv())
        .await?
        .ok_or("LAN host stopped")?;
    assert_eq!(&received[..], payload);
    assert_eq!(flow.local_addr(), v6(LAN_HOST, UDP_PORT));
    assert_masqueraded(flow.peer_addr());
    Ok(flow)
}

/// The Echo identifier of an ICMP or `ICMPv6` Echo packet, with its type.
fn echo(packet: &[u8]) -> TestResult<(u8, u16)> {
    let ip = IpPacket::parse(packet).map_err(|e| format!("malformed packet: {e:?}"))?;
    let message = ip.payload();
    let identifier = message.get(4..6).ok_or("short Echo")?;
    Ok((
        message[0],
        u16::from_be_bytes([identifier[0], identifier[1]]),
    ))
}

/// The source and destination of an IP packet.
fn addresses(packet: &[u8]) -> TestResult<(IpAddr, IpAddr)> {
    let ip = IpPacket::parse(packet).map_err(|e| format!("malformed packet: {e:?}"))?;
    Ok((ip.src(), ip.dst()))
}

#[tokio::test]
async fn tcp_flow_is_masqueraded_both_ways() -> TestResult {
    let rig = rig();
    let mut incoming = rig.lan.incoming_tcp();
    let (conn, accepted) = tokio::join!(
        timeout(TRANSFER, rig.client.connect_tcp(v6(LAN_HOST, TCP_PORT))),
        next_within(&mut incoming, TRANSFER),
    );
    let (conn, accepted) = (conn??, accepted?);
    assert_eq!(conn.peer_addr(), v6(LAN_HOST, TCP_PORT));
    assert_eq!(accepted.local_addr(), v6(LAN_HOST, TCP_PORT));
    assert_masqueraded(accepted.peer_addr());

    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(accepted);
        tokio::io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await
    });
    let sent = b"masqueraded through the LAN source".repeat(64);
    let (mut reader, mut writer) = tokio::io::split(conn);
    let write = async {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    };
    let read = async {
        let mut echoed = Vec::new();
        reader.read_to_end(&mut echoed).await?;
        Ok::<_, io::Error>(echoed)
    };
    let ((), echoed) = timeout(TRANSFER, async { tokio::try_join!(write, read) }).await??;
    assert_eq!(echoed, sent);

    // The closure is asked for the first packet and again for every reply.
    assert!(rig.decisions.load(Ordering::Relaxed) > 1);
    assert_eq!(rig.masquerade.len(), 1);
    let stats = rig.masquerade.stats();
    assert!(stats.forwarded > 0 && stats.reversed > 0);
    assert_eq!((stats.created, stats.flows, stats.route_changed), (1, 1, 0));
    Ok(())
}

#[tokio::test]
async fn udp_flow_is_masqueraded_both_ways() -> TestResult {
    let rig = rig();
    let mut incoming = rig.lan.incoming_udp();
    let any = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    let mut socket = rig.client.bind_udp(any).await?;

    let flow = open_udp_flow(&socket, &mut incoming, b"query").await?;
    flow.send(b"answer").await?;
    assert_eq!(
        recv(&mut socket).await?,
        (b"answer".to_vec(), v6(LAN_HOST, UDP_PORT))
    );

    assert_eq!(rig.decisions.load(Ordering::Relaxed), 2);
    assert_eq!(rig.masquerade.len(), 1);
    let stats = rig.masquerade.stats();
    assert_eq!((stats.forwarded, stats.reversed), (1, 1));
    assert_eq!((stats.created, stats.flows, stats.route_changed), (1, 1, 0));
    Ok(())
}

#[tokio::test]
async fn icmpv6_echo_is_answered_through_the_masquerade() -> TestResult {
    let rig = rig();
    let (identifier, body) = (0x1234_u16, b"ping through the masquerade");
    let [hi, lo] = identifier.to_be_bytes();
    let request = icmp(
        CLIENT.into(),
        LAN_HOST.into(),
        (ECHO_REQUEST_V6, 0),
        [hi, lo, 0, 1],
        body,
    );

    // The client's request on its way to the LAN host: new source and identifier.
    let mut packet = PacketBuf::from_packet(&request);
    assert_eq!(
        rig.masquerade.forward(&mut packet),
        MasqueradeVerdict::Rewritten
    );
    verify_checksums(packet.as_packet())?;
    assert_eq!(
        addresses(packet.as_packet())?,
        (SOURCE.into(), LAN_HOST.into())
    );
    let (kind, token) = echo(packet.as_packet())?;
    assert_eq!(kind, ECHO_REQUEST_V6);
    assert!(PORTS.contains(&token), "token {token} out of range");

    // The far side answers the forwarded request in place.
    assert!(echo_reply_in_place(packet.as_packet_mut()));
    verify_checksums(packet.as_packet())?;
    assert_eq!(
        addresses(packet.as_packet())?,
        (LAN_HOST.into(), SOURCE.into())
    );
    assert_eq!(echo(packet.as_packet())?, (ECHO_REPLY_V6, token));

    // The reply on its way back: the client's address and identifier again.
    assert_eq!(
        rig.masquerade.reverse(&mut packet),
        MasqueradeVerdict::Rewritten
    );
    verify_checksums(packet.as_packet())?;
    assert_eq!(
        addresses(packet.as_packet())?,
        (LAN_HOST.into(), CLIENT.into())
    );
    assert_eq!(echo(packet.as_packet())?, (ECHO_REPLY_V6, identifier));
    let reply = IpPacket::parse(packet.as_packet()).map_err(|e| format!("{e:?}"))?;
    assert_eq!(&reply.payload()[8..], body);

    let stats = rig.masquerade.stats();
    assert_eq!((stats.forwarded, stats.reversed), (1, 1));
    assert_eq!((stats.created, stats.flows), (1, 1));
    Ok(())
}

#[tokio::test]
async fn ipv4_echo_passes_the_masquerade_and_is_answered() -> TestResult {
    let rig = rig();
    let (client, host) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
    let request = icmp(
        client.into(),
        host.into(),
        (ECHO_REQUEST_V4, 0),
        [0x43, 0x21, 0, 7],
        b"ping",
    );

    let mut packet = PacketBuf::from_packet(&request);
    assert_eq!(rig.masquerade.forward(&mut packet), MasqueradeVerdict::Pass);
    assert_eq!(packet.as_packet(), &request[..]);

    assert!(echo_reply_in_place(packet.as_packet_mut()));
    assert_eq!(rig.masquerade.reverse(&mut packet), MasqueradeVerdict::Pass);
    verify_checksums(packet.as_packet())?;
    assert_eq!(addresses(packet.as_packet())?, (host.into(), client.into()));
    assert_eq!(echo(packet.as_packet())?, (ECHO_REPLY_V4, 0x4321));
    let reply = IpPacket::parse(packet.as_packet()).map_err(|e| format!("{e:?}"))?;
    assert_eq!(&reply.payload()[8..], b"ping");

    // Neither direction asked the closure or recorded a flow.
    assert_eq!(rig.decisions.load(Ordering::Relaxed), 0);
    let stats = rig.masquerade.stats();
    assert_eq!((stats.passed, stats.created, stats.flows), (2, 0, 0));
    Ok(())
}

#[tokio::test]
async fn a_route_change_drops_the_reply_and_the_next_flow_is_mapped_again() -> TestResult {
    let mut rig = rig();
    let mut incoming = rig.lan.incoming_udp();
    let any = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    let mut first = rig.client.bind_udp(any).await?;
    let second = rig.client.bind_udp(any).await?;

    let flow = open_udp_flow(&first, &mut incoming, b"one").await?;
    flow.send(b"one back").await?;
    assert_eq!(
        recv(&mut first).await?,
        (b"one back".to_vec(), v6(LAN_HOST, UDP_PORT))
    );
    let other = open_udp_flow(&second, &mut incoming, b"two").await?;
    assert_ne!(other.peer_addr(), flow.peer_addr());
    assert_eq!(rig.masquerade.len(), 2);

    // The route changes: the next reply is dropped and takes its flow with it.
    rig.route.store(2, Ordering::Relaxed);
    flow.send(b"late").await?;
    assert_eq!(next_drop(&mut rig.drops).await?, reasons::ROUTE_CHANGED);
    assert!(timeout(QUIET, first.recv_from()).await.is_err());
    assert_eq!(rig.masquerade.len(), 1);
    assert_eq!(rig.masquerade.stats().route_changed, 1);

    // The client's next datagram is a new flow with a fresh mapping on the new route.
    let again = open_udp_flow(&first, &mut incoming, b"again").await?;
    assert_ne!(again.peer_addr(), flow.peer_addr());
    again.send(b"again back").await?;
    assert_eq!(
        recv(&mut first).await?,
        (b"again back".to_vec(), v6(LAN_HOST, UDP_PORT))
    );
    assert_eq!(rig.masquerade.len(), 2);
    let stats = rig.masquerade.stats();
    assert_eq!((stats.created, stats.flows, stats.route_changed), (3, 2, 1));
    Ok(())
}

#[tokio::test]
async fn with_recheck_a_route_change_drops_the_next_forward_packet() -> TestResult {
    let mut rig = rig_with(MasqueradeConfig {
        ports: PORTS,
        recheck_route_on_forward: true,
        ..MasqueradeConfig::default()
    });
    let mut incoming = rig.lan.incoming_udp();
    let any = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    let mut socket = rig.client.bind_udp(any).await?;

    let mut flow = open_udp_flow(&socket, &mut incoming, b"one").await?;
    socket.send_to(b"two", v6(LAN_HOST, UDP_PORT)).await?;
    let received = timeout(WAIT, flow.recv())
        .await?
        .ok_or("LAN host stopped")?;
    assert_eq!(&received[..], b"two");
    assert_eq!(rig.decisions.load(Ordering::Relaxed), 2);

    // The route changes: the client's next datagram is dropped and takes its flow with it.
    rig.route.store(2, Ordering::Relaxed);
    socket.send_to(b"late", v6(LAN_HOST, UDP_PORT)).await?;
    assert_eq!(next_drop(&mut rig.drops).await?, reasons::ROUTE_CHANGED);
    assert!(timeout(QUIET, flow.recv()).await.is_err());
    assert_eq!(rig.masquerade.len(), 0);

    // The datagram after it is a new flow with a fresh mapping on the new route.
    let again = open_udp_flow(&socket, &mut incoming, b"again").await?;
    assert_ne!(again.peer_addr(), flow.peer_addr());
    again.send(b"again back").await?;
    assert_eq!(
        recv(&mut socket).await?,
        (b"again back".to_vec(), v6(LAN_HOST, UDP_PORT))
    );
    let stats = rig.masquerade.stats();
    assert_eq!((stats.created, stats.flows, stats.route_changed), (2, 1, 1));
    Ok(())
}
