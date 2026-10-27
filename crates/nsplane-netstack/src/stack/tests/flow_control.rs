use std::future::Future;
use std::net::SocketAddrV4;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::flow::{Fence, MAX_FENCES};
use crate::{FlowControl, Ownership, RetirementOutcome};

// ── Per-flow control: revoke and its retirement receipt ───────────────

const FIN: u8 = 0x01;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// The TCP flags of a packet, 0 for anything else.
fn tcp_flags(packet: &PacketBuf) -> u8 {
    tcp_segment(packet.as_packet())
        .and_then(|segment| segment.get(13).copied())
        .unwrap_or(0)
}

/// The `(src, dst)` of a TCP or UDP packet.
fn tuple_of(packet: &PacketBuf) -> Option<(SocketAddr, SocketAddr)> {
    tcp_tuple(packet.as_packet())
        .or_else(|| udp::parse_udp(packet.clone()).map(|datagram| (datagram.src, datagram.dst)))
}

/// An IPv4 TCP segment from `src` to `dst` with `flags`, for `owns`.
fn segment(src: SocketAddrV4, dst: SocketAddrV4, flags: u8) -> Vec<u8> {
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
    pkt
}

/// Polls `future` once, so it runs up to its first wait.
fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
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
async fn pump_until(
    peer: &mut RawPeer,
    ready: impl Fn(&RawPeer) -> bool + Send + Sync,
) -> TestResult {
    timeout(Duration::from_secs(5), async {
        while !ready(peer) {
            pump(peer, 1).await;
        }
    })
    .await
    .map_err(|_| "the state should converge")?;
    Ok(())
}

/// Pumps `peer` until `future` resolves, for at most five seconds.
async fn pump_while<F: Future + Unpin>(
    peer: &mut RawPeer,
    future: &mut F,
) -> Result<F::Output, Box<dyn Error>> {
    let output = timeout(Duration::from_secs(5), async {
        loop {
            if let Poll::Ready(output) = poll_once(future) {
                return output;
            }
            pump(peer, 1).await;
        }
    })
    .await
    .map_err(|_| "the future should resolve")?;
    Ok(output)
}

/// Takes every packet the stack lets out until it stays quiet for 50 ms.
async fn drain(source: &mut NetStackSource) -> Vec<PacketBuf> {
    let mut packets = Vec::new();
    while let Ok(Ok(packet)) = timeout(Duration::from_millis(50), source.recv()).await {
        packets.push(packet);
    }
    packets
}

/// A stack at `server`'s address with `config`, wired to a client peer at `client_ip`.
fn start(config: NetStackConfig, client_ip: Ipv4Addr) -> (NetStackHandle, RawPeer) {
    RawPeer::start(config, client_ip, 0xf10f)
}

/// Opens a client socket from `client` to `server` and returns it with the stack's side.
async fn accept(
    handle: &NetStackHandle,
    incoming: &mut (impl Stream<Item = TcpConnection> + Unpin),
    peer: &mut RawPeer,
    server: SocketAddrV4,
    client: SocketAddrV4,
) -> Result<(TcpConnection, SocketHandle), Box<dyn Error>> {
    let socket = peer.connect(*server.ip(), server.port(), client.port())?;
    for _ in 0..40 {
        pump(peer, 2).await;
        if let Some(conn) = try_next(incoming) {
            assert_eq!(conn.peer_addr(), SocketAddr::V4(client));
            let tuple = segment(client, server, ACK);
            assert_eq!(handle.owns(&tuple), Ownership::Flow);
            return Ok((conn, socket));
        }
    }
    Err("TCP handshake should complete".into())
}

/// Establishes `client` -> `server` on a stack with `config`.
async fn establish(
    config: NetStackConfig,
    server: SocketAddrV4,
    client: SocketAddrV4,
) -> Result<(NetStackHandle, TcpConnection, RawPeer, SocketHandle), Box<dyn Error>> {
    let (handle, mut peer) = start(config, *client.ip());
    let mut incoming = handle.incoming_tcp();
    let (conn, socket) = accept(&handle, &mut incoming, &mut peer, server, client).await?;
    Ok((handle, conn, peer, socket))
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

/// Revokes `control` and waits for the outcome.
async fn retire(control: &FlowControl) -> Result<RetirementOutcome, Box<dyn Error>> {
    Ok(timeout(WAIT, control.revoke().wait()).await?)
}

/// Asserts that the driver wrote the outcome in the turn that took the revoke.
fn assert_one_turn(control: &FlowControl) {
    let (observed, completed) = control.revoke().turns();
    assert!(observed > 0, "the revoke was observed");
    assert_eq!(observed, completed, "retired in the observing turn");
}

#[tokio::test]
async fn control_survives_moved_and_cloned_handles() -> TestResult {
    let server: SocketAddrV4 = "10.9.40.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.40.2:49200".parse()?;
    let (handle, conn, mut peer, _socket) = establish(config(*server.ip()), server, client).await?;

    // TCP: the connection moves into a task that blocks on a read.
    let control = conn.control();
    let copy = control.clone();
    let reader = tokio::spawn(async move {
        let mut conn = conn;
        let mut buf = [0u8; 16];
        conn.read(&mut buf).await.map_err(|error| error.kind())
    });
    pump(&mut peer, 2).await;
    assert!(!control.is_revoked());
    assert_eq!(retire(&copy).await?, RetirementOutcome::Retired);
    assert!(control.is_revoked());
    assert_eq!(
        timeout(WAIT, reader).await??,
        Err(io::ErrorKind::ConnectionAborted)
    );

    // UDP: the flow moves into a task; reply clones share its control.
    let local = SocketAddr::V4(SocketAddrV4::new(*server.ip(), 53));
    let remote: SocketAddr = "10.9.40.2:5353".parse()?;
    let mut incoming = handle.incoming_udp();
    datagram_in(&peer.sink, remote, local, b"one").await?;
    let flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    let flow_control = flow.control();
    let reply = flow.reply_handle();
    let reply_clone = reply.clone();
    let receiver = tokio::spawn(async move {
        let mut flow = flow;
        let mut received = 0;
        while flow.recv().await.is_some() {
            received += 1;
        }
        received
    });
    pump(&mut peer, 2).await;
    assert_eq!(
        retire(&reply_clone.control()).await?,
        RetirementOutcome::Retired
    );
    assert!(flow_control.is_revoked());
    assert!(reply.control().is_revoked());
    assert_eq!(timeout(WAIT, receiver).await??, 1);
    let error = reply.send(b"late").await.err().ok_or("send must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);

    // A socket's control outlives the socket.
    let socket = handle.bind_udp("10.9.40.1:5000".parse()?).await?;
    let control = socket.control();
    drop(socket);
    assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
    Ok(())
}

#[tokio::test]
async fn revoke_is_idempotent_and_wakes_blocked_read_write_send() -> TestResult {
    let server: SocketAddrV4 = "10.9.41.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.41.2:49200".parse()?;
    let mut config = config(*server.ip());
    config.stream_buffer = 2048;
    config.tcp_tx_buffer = Some(4096);
    let (handle, conn, _peer, _socket) = establish(config, server, client).await?;
    let control = conn.control();
    let (mut read_half, mut write_half) = tokio::io::split(conn);
    let reader = tokio::spawn(async move {
        let mut buf = [0u8; 16];
        read_half.read(&mut buf).await.map_err(|error| error.kind())
    });
    // The peer is silent: the writer fills the socket and its buffer, then blocks.
    let writer = tokio::spawn(async move {
        loop {
            if let Err(error) = write_half.write(&[7; 1024]).await {
                return error.kind();
            }
        }
    });
    // Nobody drains the egress: the sender fills every queue, then blocks.
    let socket = handle.connect_udp("10.9.41.2:5353".parse()?).await?;
    let udp_control = socket.control();
    let sender = tokio::spawn(async move {
        loop {
            if let Err(error) = socket.send(b"flood").await {
                return error.kind();
            }
        }
    });
    sleep(Duration::from_millis(200)).await;
    assert!(!reader.is_finished() && !writer.is_finished() && !sender.is_finished());

    let first = control.revoke();
    let udp_first = udp_control.revoke();
    assert_eq!(
        timeout(WAIT, reader).await??,
        Err(io::ErrorKind::ConnectionAborted)
    );
    assert_eq!(
        timeout(WAIT, writer).await??,
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(
        timeout(WAIT, sender).await??,
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(
        timeout(WAIT, first.wait()).await?,
        RetirementOutcome::Retired
    );
    assert_eq!(
        timeout(WAIT, udp_first.wait()).await?,
        RetirementOutcome::Retired
    );

    // A second revoke changes nothing and reports the same outcome.
    let drops = handle.retired_drops();
    let second = control.revoke();
    assert_eq!(second.outcome(), Some(RetirementOutcome::Retired));
    assert_eq!(udp_control.revoke().outcome(), first.outcome());
    sleep(Duration::from_millis(50)).await;
    assert_eq!(handle.retired_drops(), drops);
    assert!(control.is_revoked() && udp_control.is_revoked());
    Ok(())
}

#[tokio::test]
async fn revoked_handles_fail_with_connection_aborted() -> TestResult {
    let server: SocketAddrV4 = "10.9.42.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.42.2:49200".parse()?;
    let (handle, mut conn, mut peer, _socket) =
        establish(config(*server.ip()), server, client).await?;
    assert_eq!(retire(&conn.control()).await?, RetirementOutcome::Retired);
    let mut buf = [0u8; 8];
    let aborted = Some(io::ErrorKind::ConnectionAborted);
    assert_eq!(conn.read(&mut buf).await.err().map(|e| e.kind()), aborted);
    assert_eq!(conn.write(b"x").await.err().map(|e| e.kind()), aborted);
    assert_eq!(conn.flush().await.err().map(|e| e.kind()), aborted);
    assert_eq!(conn.shutdown().await.err().map(|e| e.kind()), aborted);
    // The release `terminated` waits for has happened.
    timeout(WAIT, conn.terminated()).await?;

    let local = SocketAddr::V4(SocketAddrV4::new(*server.ip(), 53));
    let remote: SocketAddr = "10.9.42.2:5353".parse()?;
    let mut incoming = handle.incoming_udp();
    datagram_in(&peer.sink, remote, local, b"one").await?;
    datagram_in(&peer.sink, remote, local, b"two").await?;
    let mut flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    pump(&mut peer, 2).await;
    let reply = flow.reply_handle();
    assert_eq!(retire(&flow.control()).await?, RetirementOutcome::Retired);
    // Buffered datagrams are never returned.
    assert!(timeout(WAIT, flow.recv()).await?.is_none());
    assert_eq!(flow.send(b"x").await.err().map(|e| e.kind()), aborted);
    assert_eq!(reply.send(b"x").await.err().map(|e| e.kind()), aborted);

    let mut connected = handle.connect_udp(remote).await?;
    let mut bound = handle.bind_udp("10.9.42.1:5000".parse()?).await?;
    assert_eq!(
        retire(&connected.control()).await?,
        RetirementOutcome::Retired
    );
    assert_eq!(retire(&bound.control()).await?, RetirementOutcome::Retired);
    assert_eq!(connected.send(b"x").await.err().map(|e| e.kind()), aborted);
    assert_eq!(
        connected
            .send_to(b"x", remote)
            .await
            .err()
            .map(|e| e.kind()),
        aborted
    );
    assert_eq!(
        bound.send_to(b"x", remote).await.err().map(|e| e.kind()),
        aborted
    );
    let received = timeout(WAIT, connected.recv_from()).await?;
    assert_eq!(received.err().map(|e| e.kind()), aborted);
    let received = timeout(WAIT, bound.recv_from()).await?;
    assert_eq!(received.err().map(|e| e.kind()), aborted);
    Ok(())
}

#[tokio::test]
async fn revoke_sends_no_fin_and_no_rst() -> TestResult {
    let server: SocketAddrV4 = "10.9.43.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.43.2:49200".parse()?;
    let (handle, mut conn, mut peer, socket) =
        establish(config(*server.ip()), server, client).await?;
    // The client acknowledges at once, so nothing of it is left to answer after the revoke.
    peer.socket(socket).set_ack_delay(None);
    conn.write_all(b"before").await?;
    pump_until(&mut peer, |peer| {
        peer.sockets
            .get::<client_tcp::Socket<'_>>(socket)
            .recv_queue()
            == 6
    })
    .await?;
    pump(&mut peer, 4).await;

    assert_eq!(retire(&conn.control()).await?, RetirementOutcome::Retired);
    assert_eq!(handle.owns(&segment(client, server, ACK)), Ownership::None);
    let seen = pump(&mut peer, 20).await;
    assert!(
        seen.iter()
            .all(|packet| tcp_flags(packet) & (FIN | RST) == 0),
        "revoke sends neither FIN nor RST"
    );
    assert_eq!(
        peer.state(socket),
        tcp::State::Established,
        "the peer is not told"
    );

    // The peer learns from the stateless RST to its next segment.
    peer.socket(socket).send_slice(b"after")?;
    pump_until(&mut peer, |peer| peer.state(socket) == tcp::State::Closed).await?;
    Ok(())
}

#[tokio::test]
async fn revoke_cleans_only_its_flow_two_tcp_two_udp() -> TestResult {
    let server: SocketAddrV4 = "10.9.44.1:80".parse()?;
    let client_a: SocketAddrV4 = "10.9.44.2:49200".parse()?;
    let client_b: SocketAddrV4 = "10.9.44.2:49201".parse()?;
    let (handle, mut peer) = start(config(*server.ip()), *client_a.ip());
    let mut incoming = handle.incoming_tcp();
    let (conn_a, socket_a) = accept(&handle, &mut incoming, &mut peer, server, client_a).await?;
    let (mut conn_b, socket_b) =
        accept(&handle, &mut incoming, &mut peer, server, client_b).await?;
    let local = SocketAddr::V4(SocketAddrV4::new(*server.ip(), 53));
    let remote_1: SocketAddr = "10.9.44.2:5001".parse()?;
    let remote_2: SocketAddr = "10.9.44.2:5002".parse()?;
    let mut flows = handle.incoming_udp();
    datagram_in(&peer.sink, remote_1, local, b"1").await?;
    let mut flow_1 = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    datagram_in(&peer.sink, remote_2, local, b"2").await?;
    let mut flow_2 = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    assert_eq!(
        timeout(WAIT, flow_1.recv()).await?.as_deref(),
        Some(&b"1"[..])
    );
    assert_eq!(
        timeout(WAIT, flow_2.recv()).await?.as_deref(),
        Some(&b"2"[..])
    );

    assert_eq!(retire(&conn_a.control()).await?, RetirementOutcome::Retired);
    assert_eq!(retire(&flow_1.control()).await?, RetirementOutcome::Retired);
    assert!(!conn_b.control().is_revoked() && !flow_2.control().is_revoked());
    assert_eq!(
        handle.owns(&segment(client_a, server, ACK)),
        Ownership::None
    );
    assert_eq!(
        handle.owns(&segment(client_b, server, ACK)),
        Ownership::Flow
    );

    // The other connection keeps working both ways.
    conn_b.write_all(b"to b").await?;
    peer.socket(socket_b).send_slice(b"from b")?;
    let seen = pump(&mut peer, 10).await;
    let mut buf = [0u8; 6];
    timeout(WAIT, conn_b.read_exact(&mut buf)).await??;
    assert_eq!(&buf, b"from b");
    let client_b_socket = peer.sockets.get::<client_tcp::Socket<'_>>(socket_b);
    assert_eq!(client_b_socket.recv_queue(), 4);
    assert_eq!(peer.state(socket_a), tcp::State::Established);
    let a_tuple = (SocketAddr::V4(server), SocketAddr::V4(client_a));
    assert!(seen.iter().all(|packet| tuple_of(packet) != Some(a_tuple)));

    // The other flow keeps working both ways.
    datagram_in(&peer.sink, remote_2, local, b"2b").await?;
    assert_eq!(
        timeout(WAIT, flow_2.recv()).await?.as_deref(),
        Some(&b"2b"[..])
    );
    flow_2.send(b"pong").await?;
    let packet = timeout(WAIT, peer.source.recv()).await??;
    assert_eq!(tuple_of(&packet), Some((local, remote_2)));

    // The revoked flow's tuple opens a new flow; the old one stays dead.
    datagram_in(&peer.sink, remote_1, local, b"1b").await?;
    let mut reopened = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    assert_eq!(reopened.peer_addr(), remote_1);
    assert_eq!(
        timeout(WAIT, reopened.recv()).await?.as_deref(),
        Some(&b"1b"[..])
    );
    assert!(timeout(WAIT, flow_1.recv()).await?.is_none());
    assert!(!reopened.control().is_revoked());
    Ok(())
}

#[tokio::test]
async fn revoke_purges_backlog_and_fences_egress() -> TestResult {
    let server: SocketAddrV4 = "10.9.45.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.45.2:49200".parse()?;
    let mut config = config(*server.ip());
    config.egress_capacity = 8;
    let (handle, mut conn, mut peer, _socket) = establish(config, server, client).await?;
    let remote: SocketAddr = "10.9.45.2:5353".parse()?;
    let socket_a = handle.bind_udp("10.9.45.1:5001".parse()?).await?;
    let socket_b = handle.bind_udp("10.9.45.1:5002".parse()?).await?;

    // Nobody drains the egress from here on. One segment of the connection lands in the
    // egress queue, the B datagrams fill it, the next segment waits in the backlog behind
    // them, and A's datagrams follow.
    conn.write_all(&[1; 1000]).await?;
    sleep(Duration::from_millis(20)).await;
    for _ in 0..10 {
        socket_b.send_to(b"b", remote).await?;
    }
    sleep(Duration::from_millis(20)).await;
    conn.write_all(&[2; 1000]).await?;
    sleep(Duration::from_millis(20)).await;
    for _ in 0..10 {
        socket_a.send_to(b"a", remote).await?;
        socket_b.send_to(b"b", remote).await?;
    }
    sleep(Duration::from_millis(20)).await;

    let tcp_control = conn.control();
    let udp_control = socket_a.control();
    assert_eq!(retire(&tcp_control).await?, RetirementOutcome::Retired);
    assert_eq!(retire(&udp_control).await?, RetirementOutcome::Retired);
    assert_one_turn(&tcp_control);
    assert_one_turn(&udp_control);

    let packets = drain(&mut peer.source).await;
    let a = (socket_a.local_addr(), remote);
    let b = (socket_b.local_addr(), remote);
    let tcp = (SocketAddr::V4(server), SocketAddr::V4(client));
    assert!(packets.iter().all(|packet| tuple_of(packet) != Some(a)));
    assert!(packets.iter().all(|packet| tuple_of(packet) != Some(tcp)));
    let from_b = packets
        .iter()
        .filter(|packet| tuple_of(packet) == Some(b))
        .count();
    assert_eq!(from_b, 20, "the other flow loses nothing");
    // Ten datagrams and at least the two segments.
    assert!(handle.retired_drops() >= 12, "{}", handle.retired_drops());
    assert_eq!(handle.stats(), NetStackStats::default());
    Ok(())
}

#[tokio::test]
async fn receipt_wait_is_cancellation_safe_and_repeatable() -> TestResult {
    let (stack, handle) = NetStack::new(config(Ipv4Addr::new(10, 9, 46, 1)));
    let (_source, _sink) = stack.split();
    let socket = handle.bind_udp("10.9.46.1:5000".parse()?).await?;
    let control = socket.control();

    // The driver has not run since: the receipt is pending.
    let receipt = control.revoke();
    assert_eq!(receipt.outcome(), None);
    let mut cancelled = Box::pin(receipt.wait());
    assert!(poll_once(&mut cancelled).is_pending());
    drop(cancelled);

    let clone = receipt.clone();
    let (first, second) =
        timeout(WAIT, async { tokio::join!(receipt.wait(), clone.wait()) }).await?;
    assert_eq!(
        (first, second),
        (RetirementOutcome::Retired, RetirementOutcome::Retired)
    );
    assert_eq!(
        timeout(WAIT, receipt.wait()).await?,
        RetirementOutcome::Retired
    );
    assert_eq!(receipt.outcome(), Some(RetirementOutcome::Retired));
    assert_eq!(control.revoke().outcome(), Some(RetirementOutcome::Retired));
    Ok(())
}

#[test]
fn receipt_is_unknown_when_driver_stops() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (control, stack) = runtime.block_on(async {
        let (stack, handle) = NetStack::new(config(Ipv4Addr::new(10, 9, 47, 1)));
        let socket = handle.bind_udp("10.9.47.1:5000".parse()?).await?;
        Ok::<_, Box<dyn Error>>((socket.control(), stack))
    })?;
    // The runtime does not run: the driver never takes the revoke.
    let receipt = control.revoke();
    assert_eq!(receipt.outcome(), None);
    drop(runtime);
    assert_eq!(receipt.outcome(), Some(RetirementOutcome::Unknown));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let outcome = runtime.block_on(async { timeout(WAIT, receipt.wait()).await })?;
    assert_eq!(outcome, RetirementOutcome::Unknown);
    assert_eq!(control.revoke().outcome(), Some(RetirementOutcome::Unknown));
    drop(stack);
    Ok(())
}

#[tokio::test]
async fn revoke_after_stop_is_unknown() -> TestResult {
    let (stack, handle) = NetStack::new(config(Ipv4Addr::new(10, 9, 48, 1)));
    let (source, sink) = stack.split();
    let socket = handle.bind_udp("10.9.48.1:5000".parse()?).await?;
    drop(sink);
    let any_port: SocketAddr = "10.9.48.1:0".parse()?;
    timeout(WAIT, async {
        while handle.bind_udp(any_port).await.is_ok() {
            sleep(Duration::from_millis(5)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    let receipt = socket.control().revoke();
    assert_eq!(receipt.outcome(), Some(RetirementOutcome::Unknown));
    assert_eq!(
        timeout(WAIT, receipt.wait()).await?,
        RetirementOutcome::Unknown
    );
    let error = socket.send_to(b"x", "10.9.48.2:53".parse()?).await.err();
    assert_eq!(
        error.map(|e| e.kind()),
        Some(io::ErrorKind::ConnectionAborted)
    );
    drop(source);
    Ok(())
}

#[tokio::test]
async fn receipt_fails_when_fence_table_is_full() -> TestResult {
    let (stack, handle) = NetStack::new(config(Ipv4Addr::new(10, 9, 49, 1)));
    let (source, _sink) = stack.split();
    let remote: SocketAddr = "10.9.49.2:53".parse()?;
    let sending = handle.bind_udp("10.9.49.1:5000".parse()?).await?;
    let quiet = handle.bind_udp("10.9.49.1:5001".parse()?).await?;
    // The datagram waits in the egress queue: only a fence can hold it back.
    sending.send_to(b"held", remote).await?;
    sleep(Duration::from_millis(20)).await;
    for _ in 0..MAX_FENCES {
        let fence = Fence::Tcp {
            local: remote,
            peer: remote,
            start: 0,
            end: u64::MAX,
        };
        assert!(source.fences.insert(fence).is_ok());
    }

    assert_eq!(retire(&sending.control()).await?, RetirementOutcome::Failed);
    // The flow is still revoked; one with nothing queued still retires.
    let error = sending.send_to(b"x", remote).await.err();
    assert_eq!(
        error.map(|e| e.kind()),
        Some(io::ErrorKind::ConnectionAborted)
    );
    assert_eq!(retire(&quiet.control()).await?, RetirementOutcome::Retired);
    Ok(())
}

#[tokio::test]
async fn retires_in_one_turn_with_silent_peer_full_egress_time_wait() -> TestResult {
    let server: SocketAddrV4 = "10.9.50.1:80".parse()?;
    let silent: SocketAddrV4 = "10.9.50.2:49200".parse()?;
    let closing: SocketAddrV4 = "10.9.50.2:49201".parse()?;
    let mut config = config(*server.ip());
    config.egress_capacity = 8;
    let (handle, mut peer) = start(config, *silent.ip());
    let mut incoming = handle.incoming_tcp();
    let (mut silent_conn, _) = accept(&handle, &mut incoming, &mut peer, server, silent).await?;
    let (mut closing_conn, closing_socket) =
        accept(&handle, &mut incoming, &mut peer, server, closing).await?;

    // TIME-WAIT: the stack closes first, the peer sends bytes nobody reads and closes.
    let mut shutdown = Box::pin(closing_conn.shutdown());
    pump_while(&mut peer, &mut shutdown).await??;
    drop(shutdown);
    pump_until(&mut peer, |peer| {
        peer.state(closing_socket) == tcp::State::CloseWait
    })
    .await?;
    let socket = peer.socket(closing_socket);
    socket.send_slice(b"unread")?;
    socket.close();
    pump_until(&mut peer, |peer| {
        peer.state(closing_socket) == tcp::State::Closed
    })
    .await?;
    assert!(
        timeout(Duration::from_millis(50), closing_conn.terminated())
            .await
            .is_err()
    );

    // The peer goes silent with bytes in flight, and nobody drains the egress any more:
    // a flood fills the egress queue and the backlog.
    silent_conn.write_all(&[1; 2000]).await?;
    let flood = handle.bind_udp("10.9.50.1:5000".parse()?).await?;
    for _ in 0..400 {
        flood.send_to(b"flood", "10.9.50.2:53".parse()?).await?;
    }
    sleep(Duration::from_millis(50)).await;

    for control in [
        silent_conn.control(),
        closing_conn.control(),
        flood.control(),
    ] {
        assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
        assert_one_turn(&control);
    }
    timeout(WAIT, closing_conn.terminated()).await?;
    Ok(())
}

#[tokio::test]
async fn revoke_after_abort_or_release_retires() -> TestResult {
    let server: SocketAddrV4 = "10.9.51.1:80".parse()?;
    let aborted: SocketAddrV4 = "10.9.51.2:49200".parse()?;
    let released: SocketAddrV4 = "10.9.51.2:49201".parse()?;
    let mut config = config(*server.ip());
    config.egress_capacity = 8;
    let (handle, mut peer) = start(config, *aborted.ip());
    let mut incoming = handle.incoming_tcp();
    let (released_conn, released_socket) =
        accept(&handle, &mut incoming, &mut peer, server, released).await?;
    let (aborted_conn, _) = accept(&handle, &mut incoming, &mut peer, server, aborted).await?;

    // Released: a graceful close both ways, then the revoke.
    let released_control = released_conn.control();
    let mut terminal = released_conn.terminal();
    drop(released_conn);
    pump_until(&mut peer, |peer| {
        peer.state(released_socket) == tcp::State::CloseWait
    })
    .await?;
    peer.socket(released_socket).close();
    let mut released_wait = Box::pin(terminal.wait_for(|terminal| *terminal));
    pump_while(&mut peer, &mut released_wait).await??;
    drop(released_wait);
    assert_eq!(retire(&released_control).await?, RetirementOutcome::Retired);
    assert_one_turn(&released_control);

    // Aborted: a full egress keeps the RST from being sent, so the abort waits for it.
    let flood = handle.bind_udp("10.9.51.1:5000".parse()?).await?;
    for _ in 0..400 {
        flood.send_to(b"flood", "10.9.51.2:53".parse()?).await?;
    }
    sleep(Duration::from_millis(50)).await;
    let aborted_control = aborted_conn.control();
    let mut terminal = aborted_conn.terminal();
    aborted_conn.abort();
    sleep(Duration::from_millis(50)).await;
    assert!(!*terminal.borrow(), "the abort waits for its RST");
    assert_eq!(retire(&aborted_control).await?, RetirementOutcome::Retired);
    assert_one_turn(&aborted_control);
    timeout(WAIT, terminal.wait_for(|terminal| *terminal)).await??;
    let aborted_tuple = (SocketAddr::V4(server), SocketAddr::V4(aborted));
    let packets = drain(&mut peer.source).await;
    assert!(
        packets
            .iter()
            .all(|packet| tuple_of(packet) != Some(aborted_tuple)),
        "the RST never leaves"
    );
    Ok(())
}

#[tokio::test]
async fn retired_drops_counts_everything_discarded_for_revoked_flows() -> TestResult {
    let mut config = config(Ipv4Addr::new(10, 9, 52, 1));
    config.egress_capacity = 4;
    let (stack, handle) = NetStack::new(config);
    let (mut source, _sink) = stack.split();
    let remote: SocketAddr = "10.9.52.2:53".parse()?;
    let revoked = handle.bind_udp("10.9.52.1:5000".parse()?).await?;
    let kept = handle.bind_udp("10.9.52.1:5001".parse()?).await?;

    // Four datagrams in the egress queue, six in the backlog, five not taken yet.
    for _ in 0..10 {
        revoked.send_to(b"r", remote).await?;
    }
    kept.send_to(b"k", remote).await?;
    sleep(Duration::from_millis(20)).await;
    for _ in 0..5 {
        revoked.send_to(b"r", remote).await?;
    }
    let receipt = revoked.control().revoke();
    assert_eq!(
        timeout(WAIT, receipt.wait()).await?,
        RetirementOutcome::Retired
    );

    let packets = drain(&mut source).await;
    assert_eq!(packets.len(), 1, "only the kept flow's datagram leaves");
    assert_eq!(tuple_of(&packets[0]), Some((kept.local_addr(), remote)));
    assert_eq!(handle.retired_drops(), 15);
    assert_eq!(handle.stats(), NetStackStats::default());
    Ok(())
}

#[tokio::test]
async fn graceful_release_keeps_final_ack_pending_until_source_takes_it() -> TestResult {
    let server: SocketAddrV4 = "10.9.60.1:80".parse()?;
    let client_addr: SocketAddrV4 = "10.9.60.2:49152".parse()?;
    let (handle, mut peer) = start(config(*server.ip()), *client_addr.ip());
    let mut incoming = handle.incoming_tcp();
    let (mut conn, client) = accept(&handle, &mut incoming, &mut peer, server, client_addr).await?;
    let control = conn.control();
    let udp = handle.bind_udp("10.9.60.1:8081".parse()?).await?;
    assert_eq!(
        peer.source
            .tcp_egress_drained(&udp.control())
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(!peer.source.tcp_egress_drained(&control)?);
    conn.shutdown().await?;
    pump_until(&mut peer, |peer| {
        peer.state(client) == tcp::State::CloseWait
    })
    .await?;
    peer.socket(client).close();
    // Drive the peer's FIN and delayed ACK without taking stack output.
    timeout(Duration::from_secs(5), async {
        loop {
            let now = peer.now();
            peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
            let packets: Vec<_> = peer.device.drain_tx().collect();
            for packet in packets {
                peer.sink.send(packet, PeerId::new(0)).await?;
            }
            tokio::select! {
                () = conn.terminated() => return Ok::<_, io::Error>(()),
                () = sleep(Duration::from_millis(5)) => {}
            }
        }
    })
    .await??;
    assert!(
        !peer.source.tcp_egress_drained(&control)?,
        "release must not imply the final ACK left the stack"
    );
    timeout(WAIT, async {
        while !peer.source.tcp_egress_drained(&control)? {
            let packet = peer.source.recv().await?;
            peer.device.inject(packet);
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    pump_until(&mut peer, |peer| peer.state(client) == tcp::State::Closed).await?;
    let (other, _) = NetStack::new(config(Ipv4Addr::new(10, 10, 0, 1)));
    let (other_source, _) = other.split();
    assert_eq!(
        other_source
            .tcp_egress_drained(&control)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    control.revoke();
    assert_eq!(
        peer.source.tcp_egress_drained(&control).unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    Ok(())
}
