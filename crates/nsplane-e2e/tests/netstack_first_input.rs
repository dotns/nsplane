//! Control from the first input between two engines over an in-memory channel transport
//! whose local sides are netstacks: the server stack admits with `Admission::Decide`, and
//! each connection or flow it revokes at a stage before the hand-out (held, accepted before
//! the next driver turn, mid handshake, queued for the application) is never handed out
//! and sends nothing, while a lifetime accepted on the same stack echoes intact under load
//! and the next input on a revoked tuple starts a new lifetime.
//!
//! The server's egress passes a gate the test can close to keep its output queued in the
//! stack, and that records every packet it lets out.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_core::Stream;
use nsplane::x25519::StaticSecret;
use nsplane::{ChannelTransport, EngineBuilder, PacketSource};
use nsplane_e2e::{
    Family, MTU, QUIET, StackNode, TRANSFER, TestResult, WAIT, next_within, payload, tcp, udp,
};
use nsplane_netstack::{
    Admission, DeliveryOutcome, FlowControl, NetStack, NetStackConfig, NetStackHandle,
    NetStackSource, Ownership, PendingFlow, RetirementOutcome, TcpConnection, Undelivered,
};
use nsplane_packet::{Ecn, IpPacket, PacketBuf, Path, TransportId, protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

/// Bytes the connection under load sends and gets echoed back.
const BULK: usize = 1 << 20;
/// Datagrams the flow under load sends and gets echoed back.
const DATAGRAMS: u16 = 200;
/// The server's admission: long enough that nothing times out during a test.
const DECIDE: Admission = Admission::Decide {
    timeout: TRANSFER,
    max_pending: 64,
};
const ACK: u8 = 0x10;

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

/// A stack node with key seed `seed` admitting with `admission` on `transport` at `at`, its
/// egress behind an open gate.
fn side(
    seed: u8,
    admission: Admission,
    at: (TransportId, SocketAddr),
    transport: ChannelTransport,
) -> TestResult<Side> {
    let ip4 = Ipv4Addr::new(10, 0, 0, seed);
    let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(seed));
    let mut config = NetStackConfig::new(vec![(IpAddr::V4(ip4), 32), (IpAddr::V6(ip6), 128)], MTU);
    config.admission = admission;
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

/// A client node (seed 1, admitting immediately) and a server node (seed 2, deciding),
/// linked by a channel transport pair and introduced to each other.
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
    let a = side(1, Admission::Immediate, ends.0, link_a)?;
    let b = side(2, DECIDE, ends.1, link_b)?;
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

/// The protocol, `(src, dst)` of a TCP or UDP packet.
fn tuple(packet: &[u8]) -> Option<(u8, SocketAddr, SocketAddr)> {
    let ip = IpPacket::parse(packet).ok()?;
    let ports = ip.payload().get(..4)?;
    Some((
        ip.protocol(),
        SocketAddr::new(ip.src(), u16::from_be_bytes([ports[0], ports[1]])),
        SocketAddr::new(ip.dst(), u16::from_be_bytes([ports[2], ports[3]])),
    ))
}

/// Whether `packet` goes to `client`: a TCP or UDP packet to it, or an ICMP or `ICMPv6`
/// message to its address.
fn to_client(packet: &[u8], client: SocketAddr) -> bool {
    let Ok(ip) = IpPacket::parse(packet) else {
        return false;
    };
    match ip.protocol() {
        protocol::ICMP | protocol::ICMPV6 => ip.dst() == client.ip(),
        _ => tuple(packet).is_some_and(|(_, _, dst)| dst == client),
    }
}

/// The next pending item for `local`. Items for other destinations (a client
/// retransmitting the SYN of a revoked lifetime starts a new one) are parked undecided, so
/// that nothing answers them.
async fn offered(
    pending: &mut (impl Stream<Item = PendingFlow> + Unpin),
    local: SocketAddr,
    parked: &mut Vec<PendingFlow>,
) -> TestResult<PendingFlow> {
    loop {
        let item = next_within(pending, WAIT).await?;
        if item.local_addr() == local {
            return Ok(item);
        }
        parked.push(item);
    }
}

/// Revokes `control`, waits for the retirement and checks the delivery ended revoked.
async fn retire_undelivered(control: &FlowControl) -> TestResult {
    let outcome = timeout(WAIT, control.revoke().wait()).await?;
    assert_eq!(outcome, RetirementOutcome::Retired);
    assert_eq!(
        control.delivery().outcome(),
        Some(DeliveryOutcome::NotDelivered(Undelivered::Revoked))
    );
    Ok(())
}

/// Waits until `stack` owns `packet` as a connection's or flow's.
async fn until_owned(stack: &NetStackHandle, packet: &[u8]) -> TestResult {
    timeout(WAIT, async {
        while stack.owns(packet) != Ownership::Flow {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "the stack should own the tuple")?;
    Ok(())
}

/// A connect from the client to `target` in the background.
fn dial(a: &Side, target: SocketAddr) -> JoinHandle<io::Result<TcpConnection>> {
    let stack = a.node.stack.clone();
    tokio::spawn(async move { stack.connect_tcp(target).await })
}

/// Asserts that none of the packets the server let out goes to one of `clients`.
fn assert_nothing_to(sent: &[Vec<u8>], clients: &[SocketAddr]) {
    for client in clients {
        assert!(
            sent.iter().all(|packet| !to_client(packet, *client)),
            "a packet to {client} left the stack"
        );
    }
}

/// A datagram carrying `seq`.
fn numbered(seq: u16) -> Vec<u8> {
    let mut datagram = vec![0x33; 100];
    datagram[..2].copy_from_slice(&seq.to_be_bytes());
    datagram
}

#[tokio::test]
async fn tcp_lifetimes_revoked_before_the_hand_out_never_arrive_and_send_nothing() -> TestResult {
    let (a, b) = pair().await?;
    let mut pending = b.node.stack.incoming_pending();
    let mut incoming = b.node.stack.incoming_tcp();
    let mut parked = Vec::new();

    // Load: an accepted connection echoing 1 MiB while the others are revoked.
    let echo_target = b.node.socket_addr(Family::V4, 80);
    let client = dial(&a, echo_target);
    let item = offered(&mut pending, echo_target, &mut parked).await?;
    let echo_control = item.control();
    let context = echo_control.bind_context(1)?;
    item.accept();
    let conn = timeout(TRANSFER, client).await???;
    let server = next_within(&mut incoming, WAIT).await?;
    assert_eq!(server.control().context(), Some(context));
    assert_eq!(
        echo_control.delivery().outcome(),
        Some(DeliveryOutcome::Delivered)
    );
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(server);
        tokio::io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await
    });
    let data = payload(BULK);
    let (mut reader, mut writer) = tokio::io::split(conn);
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    });
    let reader = tokio::spawn(async move {
        let mut echoed = Vec::new();
        reader.read_to_end(&mut echoed).await.map(|_| echoed)
    });

    let mark = b.sent();
    let mut revoked = Vec::new();
    let mut dials = Vec::new();

    // Held.
    let target = b.node.socket_addr(Family::V4, 81);
    dials.push(dial(&a, target));
    let item = offered(&mut pending, target, &mut parked).await?;
    revoked.push(item.peer_addr());
    retire_undelivered(&item.control()).await?;
    drop(item);

    // Accepted, revoked before the driver's next turn.
    let target = b.node.socket_addr(Family::V4, 82);
    dials.push(dial(&a, target));
    let item = offered(&mut pending, target, &mut parked).await?;
    revoked.push(item.peer_addr());
    let control = item.control();
    item.accept();
    let receipt = control.revoke();
    assert_eq!(
        timeout(WAIT, receipt.wait()).await?,
        RetirementOutcome::Retired
    );

    // Mid handshake, its SYN-ACK queued in the stack.
    let target = b.node.socket_addr(Family::V4, 83);
    b.close();
    dials.push(dial(&a, target));
    let item = offered(&mut pending, target, &mut parked).await?;
    let peer = item.peer_addr();
    revoked.push(peer);
    let control = item.control();
    item.accept();
    until_owned(&b.node.stack, &tcp(peer, target, ACK, (1, 1), &[])).await?;
    retire_undelivered(&control).await?;
    b.open();

    // Established and queued for `incoming_tcp`; its handshake left before the revoke.
    let target = b.node.socket_addr(Family::V4, 84);
    let client = dial(&a, target);
    let item = offered(&mut pending, target, &mut parked).await?;
    let established_client = item.peer_addr();
    let control = item.control();
    item.accept();
    let _established = timeout(TRANSFER, client).await???;
    sleep(QUIET).await;
    let established_mark = b.sent();
    retire_undelivered(&control).await?;

    // The load completes byte-exact; none of the revoked lifetimes is handed out, and
    // nothing left the stack towards their clients after the first revoke.
    let echoed = timeout(TRANSFER, reader).await???;
    assert!(echoed == data, "the echo differs");
    timeout(TRANSFER, writer).await???;
    assert!(
        next_within(&mut incoming, QUIET).await.is_err(),
        "a revoked lifetime was handed out"
    );
    assert_nothing_to(&b.sent_since(mark), &revoked);
    assert_nothing_to(&b.sent_since(established_mark), &[established_client]);
    assert!(
        b.node.stack.retired_drops() > 0,
        "the SYN-ACK was held back"
    );
    for dial in dials {
        dial.abort();
    }
    Ok(())
}

#[tokio::test]
async fn udp_lifetimes_revoked_before_the_hand_out_never_arrive_and_the_tuple_starts_anew()
-> TestResult {
    let (a, b) = pair().await?;
    let mut pending = b.node.stack.incoming_pending();
    let mut incoming = b.node.stack.incoming_udp();
    let mut parked = Vec::new();

    // Load: an accepted flow echoing its datagrams while the others are revoked.
    let echo_target = b.node.socket_addr(Family::V4, 53);
    let mut echo = a.node.stack.connect_udp(echo_target).await?;
    echo.send(&numbered(0)).await?;
    let item = offered(&mut pending, echo_target, &mut parked).await?;
    item.accept();
    let mut flow = next_within(&mut incoming, WAIT).await?;
    tokio::spawn(async move {
        let reply = flow.reply_handle();
        while let Some(datagram) = flow.recv().await {
            reply.send(&datagram).await?;
        }
        Ok::<_, io::Error>(())
    });
    let mark = b.sent();

    // Held: no port unreachable follows.
    let target = b.node.socket_addr(Family::V4, 54);
    let held = a.node.stack.connect_udp(target).await?;
    held.send(b"held").await?;
    let item = offered(&mut pending, target, &mut parked).await?;
    let held_client = item.peer_addr();
    retire_undelivered(&item.control()).await?;
    drop(item);

    // Queued for `incoming_udp`, with a second datagram in its queue.
    let target = b.node.socket_addr(Family::V4, 55);
    let queued = a.node.stack.connect_udp(target).await?;
    queued.send(b"one").await?;
    let item = offered(&mut pending, target, &mut parked).await?;
    let queued_client = item.peer_addr();
    let control = item.control();
    item.accept();
    until_owned(&b.node.stack, &udp(queued_client, target, b"probe")).await?;
    queued.send(b"two").await?;
    sleep(QUIET).await;
    retire_undelivered(&control).await?;

    // The load completes.
    for seq in 1..DATAGRAMS {
        echo.send(&numbered(seq)).await?;
    }
    let mut echoed = Vec::new();
    for _ in 0..DATAGRAMS {
        let (datagram, _) = timeout(WAIT, echo.recv_from()).await??;
        echoed.push(datagram.to_vec());
    }
    echoed.sort();
    assert_eq!(echoed, (0..DATAGRAMS).map(numbered).collect::<Vec<_>>());
    assert!(
        next_within(&mut incoming, QUIET).await.is_err(),
        "a revoked lifetime was handed out"
    );
    assert_nothing_to(&b.sent_since(mark), &[held_client, queued_client]);

    // The tuple's next datagram is a new lifetime that carries only its own datagram.
    queued.send(b"three").await?;
    let item = offered(&mut pending, target, &mut parked).await?;
    assert_eq!(item.peer_addr(), queued_client);
    assert!(!item.control().is_revoked());
    item.accept();
    let mut flow = next_within(&mut incoming, WAIT).await?;
    assert_eq!(
        timeout(WAIT, flow.recv()).await?.as_deref(),
        Some(&b"three"[..])
    );
    assert!(
        timeout(QUIET, flow.recv()).await.is_err(),
        "nothing of the old lifetime"
    );
    Ok(())
}
