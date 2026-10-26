//! `FlowControl::revoke` between two engines over an in-memory channel transport whose
//! local sides are netstacks: one TCP connection and one UDP flow of a shared stack retire
//! under full queues while the others complete intact, a revoke does not wait for an
//! unresponsive peer, a flow re-opened on the same 5-tuple never carries output queued for
//! the old one, and a stopped stack reports its receipts unknown, never retired.
//!
//! Each stack's egress passes a gate the test closes to keep the stack's output queued and
//! that records every packet it lets out.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use nsplane::x25519::StaticSecret;
use nsplane::{ChannelTransport, EngineBuilder, PacketSource};
use nsplane_e2e::{
    Family, MTU, QUIET, StackNode, TRANSFER, TestResult, WAIT, next_within, payload,
    serve_tcp_echo, serve_udp_echo,
};
use nsplane_netstack::{
    FlowControl, NetStack, NetStackConfig, NetStackSource, RetirementOutcome, RetirementReceipt,
    TcpConnection, UdpSocket,
};
use nsplane_packet::{Ecn, IpPacket, PacketBuf, Path, TransportId, protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

/// Bytes each TCP connection sends and gets echoed back.
const BULK: usize = 256 << 10;
/// The stacks' TCP socket and stream buffers: small, so the windows fill quickly.
const BUFFER: usize = 16 << 10;
/// The stacks' egress queue: small, so it fills quickly.
const EGRESS: usize = 8;
/// Payload bytes of the test datagrams.
const DATAGRAM: usize = 100;

/// Every packet a gate let out, in order.
type Log = Arc<Mutex<Vec<Vec<u8>>>>;

/// A stack's egress that passes packets only while open, and records them.
struct Gate {
    inner: NetStackSource,
    open: watch::Receiver<bool>,
    log: Log,
}

impl PacketSource for Gate {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        loop {
            if self.open.wait_for(|open| *open).await.is_err() {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            tokio::select! {
                biased;
                // Closed (or reopened) meanwhile: check again before taking a packet.
                changed = self.open.changed() => {
                    if changed.is_err() {
                        return Err(io::ErrorKind::BrokenPipe.into());
                    }
                }
                packet = self.inner.recv() => {
                    let packet = packet?;
                    self.log
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(packet.as_packet().to_vec());
                    return Ok(packet);
                }
            }
        }
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.inner.mtu()
    }
}

/// A stack node with the test's end of its gate.
struct Side {
    node: StackNode,
    gate: watch::Sender<bool>,
    log: Log,
}

impl Side {
    /// Keeps the stack's output inside the stack.
    fn close(&self) {
        self.gate.send_replace(false);
    }

    /// Lets the stack's output out again.
    fn open(&self) {
        self.gate.send_replace(true);
    }

    /// How many packets the gate let out so far.
    fn sent(&self) -> usize {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// The packets the gate let out after the first `from`.
    fn sent_since(&self, from: usize) -> Vec<Vec<u8>> {
        self.log.lock().unwrap_or_else(PoisonError::into_inner)[from..].to_vec()
    }
}

/// A stack node with key seed `seed` on `transport` at `at`, its egress behind an open
/// gate.
fn side(seed: u8, at: (TransportId, SocketAddr), transport: ChannelTransport) -> TestResult<Side> {
    let ip4 = Ipv4Addr::new(10, 0, 0, seed);
    let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed));
    let mut config = NetStackConfig::new(vec![(IpAddr::V4(ip4), 32), (IpAddr::V6(ip6), 128)], MTU);
    config.egress_capacity = EGRESS;
    config.tcp_rx_buffer = Some(BUFFER);
    config.tcp_tx_buffer = Some(BUFFER);
    config.stream_buffer = BUFFER;
    let (stack, handle) = NetStack::new(config);
    let (source, sink) = stack.split();
    let (gate, open) = watch::channel(true);
    let log = Log::default();
    let source = Gate {
        inner: source,
        open,
        log: Arc::clone(&log),
    };
    let engine = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([seed; 32]))
        .transport(transport)
        .build()?;
    let node = StackNode {
        handle: engine.handle(),
        engine,
        stack: handle,
        secret: StaticSecret::from([seed; 32]),
        ip4,
        ip6,
        path: Path {
            transport: at.0,
            addr: at.1,
            ecn: Ecn::NotEct,
        },
    };
    Ok(Side { node, gate, log })
}

/// Two gated stack nodes (seeds 1 and 2), linked by a channel transport pair and
/// introduced to each other.
async fn pair() -> TestResult<(Side, Side)> {
    let ends = (
        (
            TransportId::new(1),
            SocketAddr::from(([192, 0, 2, 1], 1000)),
        ),
        (
            TransportId::new(2),
            SocketAddr::from(([192, 0, 2, 2], 2000)),
        ),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, ends.0, ends.1);
    let a = side(1, ends.0, link_a)?;
    let b = side(2, ends.1, link_b)?;
    a.node
        .handle
        .add_or_update_peer(b.node.as_peer(a.node.path.transport))
        .await?;
    b.node
        .handle
        .add_or_update_peer(a.node.as_peer(b.node.path.transport))
        .await?;
    Ok((a, b))
}

/// The `(src, dst)` of a TCP or UDP packet and its payload.
fn parse(packet: &[u8]) -> Option<(u8, SocketAddr, SocketAddr, &[u8])> {
    let ip = IpPacket::parse(packet).ok()?;
    let (proto, src, dst) = (ip.protocol(), ip.src(), ip.dst());
    let segment = ip.payload();
    let ports = |at: &[u8]| -> Option<(u16, u16)> {
        Some((
            u16::from_be_bytes([*at.first()?, *at.get(1)?]),
            u16::from_be_bytes([*at.get(2)?, *at.get(3)?]),
        ))
    };
    let (src_port, dst_port) = ports(segment)?;
    let data = match proto {
        protocol::TCP => segment.get(usize::from(segment.get(12)? >> 4) * 4..)?,
        protocol::UDP => segment.get(8..)?,
        _ => return None,
    };
    Some((
        proto,
        SocketAddr::new(src, src_port),
        SocketAddr::new(dst, dst_port),
        data,
    ))
}

/// Whether `packet` is of `proto` from `src` to `dst`.
fn of(packet: &[u8], proto: u8, src: SocketAddr, dst: SocketAddr) -> bool {
    parse(packet).is_some_and(|(p, s, d, _)| (p, s, d) == (proto, src, dst))
}

/// A datagram carrying `seq`.
fn numbered(seq: u16) -> Vec<u8> {
    let mut datagram = vec![0x33; DATAGRAM];
    datagram[..2].copy_from_slice(&seq.to_be_bytes());
    datagram
}

/// Waits for the receipt of `control`'s revoke.
async fn retire(control: &FlowControl) -> TestResult<RetirementOutcome> {
    Ok(timeout(WAIT, control.revoke().wait()).await?)
}

/// The kind of the error of `result`, if it failed.
fn kind<T>(result: io::Result<T>) -> Option<io::ErrorKind> {
    result.err().map(|error| error.kind())
}

#[tokio::test]
async fn revoke_under_full_queues_leaves_the_other_flows_intact() -> TestResult {
    let (a, b) = pair().await?;
    serve_tcp_echo(&b.node.stack);
    let _flows = serve_udp_echo(&b.node.stack);
    let tcp_target = b.node.socket_addr(Family::V4, 7);
    let mut tcp = Vec::new();
    for _ in 0..2 {
        tcp.push(timeout(TRANSFER, a.node.stack.connect_tcp(tcp_target)).await??);
    }
    let mut udp = Vec::new();
    let mut udp_tuples = Vec::new();
    for port in [53, 54] {
        let remote = b.node.socket_addr(Family::V4, port);
        let socket = a.node.stack.connect_udp(remote).await?;
        udp_tuples.push((socket.local_addr(), remote));
        udp.push(socket);
    }
    let tcp_controls: Vec<_> = tcp.iter().map(TcpConnection::control).collect();
    let udp_controls: Vec<_> = udp.iter().map(UdpSocket::control).collect();
    let tcp_tuples: Vec<_> = tcp
        .iter()
        .map(|conn| (conn.local_addr(), conn.peer_addr()))
        .collect();

    // Input queues full: both connections send more than the windows and buffers hold
    // and nobody reads the echo, the revoked UDP flow gets back more datagrams than its
    // queue holds, the other one 64 nobody reads yet.
    let data = payload(BULK);
    let mut readers = Vec::new();
    let mut writers = Vec::new();
    for conn in tcp {
        let (reader, mut writer) = tokio::io::split(conn);
        readers.push(reader);
        let data = data.clone();
        writers.push(tokio::spawn(async move {
            writer.write_all(&data).await?;
            writer.shutdown().await
        }));
    }
    let mut kept_udp = udp.pop().ok_or("two sockets")?;
    let revoked_udp = udp.pop().ok_or("two sockets")?;
    for seq in 0..300 {
        revoked_udp.send(&numbered(seq)).await?;
    }
    for seq in 0..64 {
        kept_udp.send(&numbered(seq)).await?;
    }
    sleep(QUIET).await;
    assert!(
        writers.iter().all(|writer| !writer.is_finished()),
        "the windows should be full"
    );

    // Output queues full: nothing leaves the stack, the other flow queues 128 datagrams
    // more and the revoked one fills the egress queue, the backlog and the send queue and
    // then waits for room.
    a.close();
    for seq in 64..192 {
        kept_udp.send(&numbered(seq)).await?;
    }
    let blocked_udp = tokio::spawn(async move {
        for seq in 0..1000 {
            revoked_udp.send(&numbered(seq)).await?;
        }
        Ok::<_, io::Error>(())
    });
    sleep(QUIET).await;
    assert!(!blocked_udp.is_finished(), "the send queue should be full");

    let mark = a.sent();
    assert_eq!(retire(&tcp_controls[0]).await?, RetirementOutcome::Retired);
    assert_eq!(retire(&udp_controls[0]).await?, RetirementOutcome::Retired);
    a.open();

    // The other connection and flow complete, byte-exact.
    let mut echoed = Vec::new();
    timeout(TRANSFER, readers[1].read_to_end(&mut echoed)).await??;
    assert!(echoed == data, "the echo of the other connection differs");
    timeout(TRANSFER, writers.pop().ok_or("two writers")?).await???;
    let mut datagrams = Vec::new();
    for _ in 0..192 {
        let (datagram, from) = timeout(WAIT, kept_udp.recv_from()).await??;
        assert_eq!(from, udp_tuples[1].1);
        datagrams.push(datagram.to_vec());
    }
    datagrams.sort();
    assert_eq!(datagrams, (0..192).map(numbered).collect::<Vec<_>>());
    assert!(timeout(QUIET, kept_udp.recv_from()).await.is_err());

    // The revoked ones fail, and nothing of theirs left the stack after the revoke.
    let mut buf = [0; 16];
    assert_eq!(
        kind(readers[0].read(&mut buf).await),
        Some(io::ErrorKind::ConnectionAborted)
    );
    let revoked_writer = timeout(WAIT, writers.pop().ok_or("two writers")?).await??;
    assert_eq!(kind(revoked_writer), Some(io::ErrorKind::ConnectionAborted));
    let blocked = timeout(WAIT, blocked_udp).await??;
    assert_eq!(kind(blocked), Some(io::ErrorKind::ConnectionAborted));
    let (tcp_local, tcp_peer) = tcp_tuples[0];
    let (udp_local, udp_peer) = udp_tuples[0];
    assert!(a.sent_since(mark).iter().all(|packet| {
        !of(packet, protocol::TCP, tcp_local, tcp_peer)
            && !of(packet, protocol::UDP, udp_local, udp_peer)
    }));
    assert!(a.node.stack.retired_drops() > 0);
    Ok(())
}

#[tokio::test]
async fn revoke_does_not_wait_for_an_unresponsive_peer() -> TestResult {
    let (a, b) = pair().await?;
    let mut incoming = b.node.stack.incoming_tcp();
    let target = b.node.socket_addr(Family::V4, 80);
    let mut client = timeout(TRANSFER, a.node.stack.connect_tcp(target)).await??;
    let _server = next_within(&mut incoming, WAIT).await?;
    let _quiet = b
        .node
        .stack
        .bind_udp(b.node.socket_addr(Family::V4, 53))
        .await?;
    let socket = a
        .node
        .stack
        .connect_udp(b.node.socket_addr(Family::V4, 53))
        .await?;

    // The peer stops: it never reads and sends nothing, not even an ACK.
    b.close();
    let silent = b.sent();
    let tcp = client.control();
    let writer = tokio::spawn(async move { client.write_all(&payload(BULK)).await });
    for seq in 0..32 {
        socket.send(&numbered(seq)).await?;
    }
    sleep(QUIET).await;
    assert!(!writer.is_finished(), "the window should be full");

    // Both retire at once, without anything from the peer.
    let receipts = [tcp.revoke(), socket.control().revoke()];
    for receipt in &receipts {
        let outcome = timeout(Duration::from_millis(500), receipt.wait()).await?;
        assert_eq!(outcome, RetirementOutcome::Retired);
    }
    let written = timeout(WAIT, writer).await?;
    assert_eq!(kind(written?), Some(io::ErrorKind::ConnectionAborted));
    assert_eq!(b.sent(), silent, "the peer stayed silent throughout");
    Ok(())
}

#[tokio::test]
async fn reopened_tcp_tuple_never_carries_old_queued_output() -> TestResult {
    const PORT: u16 = 40_000;
    let (a, b) = pair().await?;
    let mut incoming = b.node.stack.incoming_tcp();
    let target = b.node.socket_addr(Family::V4, 80);
    let client = timeout(TRANSFER, a.node.stack.connect_tcp_from(PORT, target)).await??;
    let mut server = next_within(&mut incoming, WAIT).await?;
    let tuple = (server.local_addr(), server.peer_addr());

    // Output queued in the stack for the old connection at the revoke.
    b.close();
    let mark = b.sent();
    timeout(WAIT, server.write_all(&[0xaa; 8 << 10])).await??;
    sleep(QUIET).await;
    assert_eq!(retire(&server.control()).await?, RetirementOutcome::Retired);
    client.abort();
    b.open();

    // A new connection on the same 5-tuple.
    let mut client = timeout(TRANSFER, a.node.stack.connect_tcp_from(PORT, target)).await??;
    let mut server = next_within(&mut incoming, WAIT).await?;
    assert_eq!((server.local_addr(), server.peer_addr()), tuple);
    server.write_all(&[0x55; 3000]).await?;
    server.shutdown().await?;
    let mut received = Vec::new();
    timeout(TRANSFER, client.read_to_end(&mut received)).await??;
    assert!(received == [0x55; 3000], "only the new connection's bytes");
    assert!(
        b.sent_since(mark)
            .iter()
            .filter_map(|packet| parse(packet))
            .all(|(_, _, _, data)| !data.contains(&0xaa)),
        "none of the old queued output left the stack"
    );
    assert!(b.node.stack.retired_drops() > 0, "old output was queued");
    Ok(())
}

#[tokio::test]
async fn reopened_udp_tuple_never_carries_old_queued_output() -> TestResult {
    let (a, b) = pair().await?;
    let mut incoming = b.node.stack.incoming_udp();
    let target = b.node.socket_addr(Family::V4, 53);
    let mut socket = a
        .node
        .stack
        .bind_udp(a.node.socket_addr(Family::V4, 5300))
        .await?;
    socket.send_to(b"hi", target).await?;
    let mut flow = next_within(&mut incoming, WAIT).await?;
    assert_eq!(
        timeout(WAIT, flow.recv()).await?.as_deref(),
        Some(&b"hi"[..])
    );
    let tuple = (flow.peer_addr(), flow.local_addr());

    // Output queued in the stack for the old flow at the revoke.
    b.close();
    let mark = b.sent();
    let reply = flow.reply_handle();
    for _ in 0..40 {
        reply.send(&[0xaa; DATAGRAM]).await?;
    }
    sleep(QUIET).await;
    assert_eq!(retire(&flow.control()).await?, RetirementOutcome::Retired);
    b.open();

    // A new flow on the same 5-tuple; the old reply handle stays dead.
    socket.send_to(b"again", target).await?;
    let mut flow = next_within(&mut incoming, WAIT).await?;
    assert_eq!((flow.peer_addr(), flow.local_addr()), tuple);
    assert_eq!(
        timeout(WAIT, flow.recv()).await?.as_deref(),
        Some(&b"again"[..])
    );
    for _ in 0..5 {
        flow.send(&[0x55; DATAGRAM]).await?;
    }
    assert_eq!(
        kind(reply.send(&[0xaa; DATAGRAM]).await),
        Some(io::ErrorKind::ConnectionAborted)
    );
    for _ in 0..5 {
        let (datagram, from) = timeout(WAIT, socket.recv_from()).await??;
        assert_eq!((datagram.as_ref(), from), (&[0x55; DATAGRAM][..], target));
    }
    assert!(timeout(QUIET, socket.recv_from()).await.is_err());
    assert!(
        b.sent_since(mark)
            .iter()
            .filter_map(|packet| parse(packet))
            .all(|(_, _, _, data)| !data.contains(&0xaa)),
        "none of the old queued output left the stack"
    );
    assert!(b.node.stack.retired_drops() > 0, "old output was queued");
    Ok(())
}

/// Asserts that `receipt` is unknown and stays so, however often it is awaited.
async fn assert_unknown(receipt: &RetirementReceipt) -> TestResult {
    assert_eq!(receipt.outcome(), Some(RetirementOutcome::Unknown));
    for _ in 0..3 {
        let outcome = timeout(WAIT, receipt.wait()).await?;
        assert_eq!(outcome, RetirementOutcome::Unknown);
    }
    Ok(())
}

#[tokio::test]
async fn revoke_after_the_stack_stopped_is_unknown() -> TestResult {
    let (a, b) = pair().await?;
    let mut incoming = b.node.stack.incoming_tcp();
    let target = b.node.socket_addr(Family::V4, 80);
    let client = timeout(TRANSFER, a.node.stack.connect_tcp(target)).await??;
    let _server = next_within(&mut incoming, WAIT).await?;
    let socket = a
        .node
        .stack
        .connect_udp(b.node.socket_addr(Family::V4, 53))
        .await?;
    let stack = a.node.stack.clone();
    let any_port = a.node.socket_addr(Family::V4, 0);

    // Stopping the engine drops the stack's source and sink, and the driver stops.
    drop(a);
    timeout(WAIT, async {
        while stack.bind_udp(any_port).await.is_ok() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    for control in [client.control(), socket.control()] {
        assert_unknown(&control.revoke()).await?;
        assert_unknown(&control.revoke()).await?;
    }
    Ok(())
}

#[test]
fn receipts_are_unknown_when_the_stack_stops_during_retirement() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (a, b, client, socket) = runtime.block_on(async {
        let (a, b) = pair().await?;
        let mut incoming = b.node.stack.incoming_tcp();
        let target = b.node.socket_addr(Family::V4, 80);
        let client = timeout(TRANSFER, a.node.stack.connect_tcp(target)).await??;
        next_within(&mut incoming, WAIT).await?;
        let socket = a
            .node
            .stack
            .connect_udp(b.node.socket_addr(Family::V4, 53))
            .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((a, b, client, socket))
    })?;

    // Revoked while the runtime does not run: no driver turn takes them before the
    // runtime, and with it the driver, goes away.
    let receipts = [client.control().revoke(), socket.control().revoke()];
    assert!(receipts.iter().all(|receipt| receipt.outcome().is_none()));
    drop(runtime);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        for receipt in &receipts {
            assert_unknown(receipt).await?;
        }
        drop((a, b, client, socket));
        Ok(())
    })
}
