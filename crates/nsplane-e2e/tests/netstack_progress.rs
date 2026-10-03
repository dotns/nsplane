//! Netstack send progress and oversize UDP replies between engines over an in-memory channel
//! transport: a sender's `TcpConnection::unacked` / `last_ack` while the receiving
//! application stops reading and after it resumes, and `udp_allow_fragmentation` handing an
//! oversize IPv4 reply to the engine's fragmenter (split on the wire, reassembled intact at
//! the peer), IPv6 still refused and the default unchanged.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures_core::Stream;
use nsplane::x25519::StaticSecret;
use nsplane::{ChannelTransport, EngineBuilder, FragmentConfig};
use nsplane_e2e::{
    MTU, Node, Options, QUIET, StackNode, TRANSFER, TestResult, WAIT, next_within, stack_pair,
    udp4, udp6,
};
use nsplane_netstack::{NetStack, NetStackConfig, UdpFlow};
use nsplane_packet::checksum::{ipv4_header_checksum, transport_checksum_v4};
use nsplane_packet::{Ecn, Ipv4Header, Path, TransportId, protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

/// TCP port of the receiving application.
const TCP_PORT: u16 = 7;
/// Bytes the sender writes: well above what the receiver's stack buffers while its
/// application does not read.
const BULK: usize = 4 << 20;
/// UDP port the raw node sends from; the stack replies to it.
const SRC_PORT: u16 = 40000;
/// UDP port of the builders' packets on the stack.
const DST_PORT: u16 = 9;
/// IPv4 DF flag in byte 6 of the header.
const DF: u8 = 0x40;
/// IPv4 MF flag in byte 6 of the header.
const MF: u8 = 0x20;

/// `len` bytes with a pattern of period 251.
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
}

#[tokio::test]
async fn unacked_and_last_ack_show_a_stalled_receiver() -> TestResult {
    let (a, b) = stack_pair(MTU).await?;
    let mut incoming = b.stack.incoming_tcp();
    let target = SocketAddr::new(IpAddr::V4(b.ip4), TCP_PORT);
    let mut conn = timeout(TRANSFER, a.stack.connect_tcp(target)).await??;
    let mut server = next_within(&mut incoming, WAIT).await?;
    assert_eq!(conn.unacked(), 0);
    assert_eq!(conn.last_ack(), None, "no data acknowledged yet");

    // The receiving application does not read until told to.
    let (resume, resumed) = oneshot::channel::<()>();
    let reader = tokio::spawn(async move {
        let _ = resumed.await;
        let mut received = Vec::with_capacity(BULK);
        server.read_to_end(&mut received).await?;
        Ok::<_, io::Error>(received)
    });

    // Write until a write stays pending: every buffer up to the receiver is full.
    let sent = data(BULK);
    let mut written = 0;
    while written < BULK {
        match timeout(QUIET, conn.write(&sent[written..])).await {
            Ok(n) => written += n?,
            Err(_) => break,
        }
    }
    assert!(
        written < BULK,
        "the stalled receiver must hold the sender back"
    );
    sleep(QUIET).await;
    let stalled_at = conn.last_ack().ok_or("the first bytes were acknowledged")?;
    assert!(conn.unacked() > 0, "bytes are outstanding while stalled");
    sleep(2 * QUIET).await;
    assert_eq!(
        conn.last_ack(),
        Some(stalled_at),
        "no progress while stalled"
    );
    assert!(conn.unacked() > 0);

    // The receiver resumes: everything is delivered and acknowledged.
    let _ = resume.send(());
    timeout(TRANSFER, async {
        conn.write_all(&sent[written..]).await?;
        conn.shutdown().await
    })
    .await??;
    let received = timeout(TRANSFER, reader).await???;
    assert_eq!(received.len(), BULK);
    assert!(received == sent, "the transfer changed the data");
    timeout(WAIT, async {
        while conn.unacked() > 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "every byte must be acknowledged")?;
    let resumed_at = conn.last_ack().ok_or("acknowledged")?;
    assert!(
        resumed_at > stalled_at,
        "last_ack advances once the receiver reads"
    );
    Ok(())
}

/// A stack node (seed 1, `udp_allow_fragmentation` set to `allow`, a fragmenter on its
/// engine) and a raw node (seed 2) linked by a channel transport and introduced.
async fn stack_and_raw(allow: bool) -> TestResult<(StackNode, Node<ChannelTransport>)> {
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, a, b);
    let ip4 = std::net::Ipv4Addr::new(10, 0, 0, 1);
    let ip6 = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let (stack, handle) = NetStack::new(NetStackConfig {
        udp_allow_fragmentation: allow,
        ..NetStackConfig::new(vec![(IpAddr::V4(ip4), 32), (IpAddr::V6(ip6), 128)], MTU)
    });
    let (source, sink) = stack.split();
    let engine = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([1; 32]))
        .transport(link_a)
        .fragmenter(FragmentConfig::default())
        .build()?;
    let node = StackNode {
        handle: engine.handle(),
        engine,
        stack: handle,
        secret: StaticSecret::from([1; 32]),
        ip4,
        ip6,
        path: Path {
            transport: a.0,
            addr: a.1,
            ecn: Ecn::NotEct,
        },
    };
    let raw = Node::new(2, b.0, b.1, link_b, Options::default());
    node.handle
        .add_or_update_peer(raw.as_peer(node.path.transport))
        .await?;
    raw.handle
        .add_or_update_peer(node.as_peer(raw.path.transport))
        .await?;
    Ok((node, raw))
}

/// Sends one datagram from `raw` to the stack (over IPv6 with `v6`) and returns the flow
/// the stack's application accepts from `incoming`.
async fn open_flow(
    stack: &StackNode,
    raw: &Node<ChannelTransport>,
    incoming: &mut (impl Stream<Item = UdpFlow> + Unpin),
    v6: bool,
) -> TestResult<UdpFlow> {
    let packet = if v6 {
        udp6(raw.ip6, stack.ip6, b"hello")
    } else {
        udp4(raw.ip4, stack.ip4, b"hello")
    };
    raw.send(&packet).await?;
    let flow = next_within(incoming, WAIT).await?;
    assert_eq!(flow.local_addr().port(), DST_PORT);
    assert_eq!(flow.peer_addr().port(), SRC_PORT);
    Ok(flow)
}

/// Collects the IPv4 fragments of one datagram delivered to `raw` and reassembles it,
/// checking every fragment against the MTU and the shared identification; returns the
/// datagram (header checksum not updated) and the number of fragments.
async fn reassemble(raw: &mut Node<ChannelTransport>) -> TestResult<(Vec<u8>, usize)> {
    let mut parts: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut header = Vec::new();
    let mut total = None;
    let mut id = None;
    while total.is_none_or(|total| parts.iter().map(|(_, p)| p.len()).sum::<usize>() < total) {
        let (_, fragment) = raw.expect_delivery().await?;
        assert!(
            fragment.len() <= usize::from(MTU),
            "fragment within the MTU"
        );
        let (ip, payload) = Ipv4Header::parse(&fragment)?;
        assert_eq!(
            ipv4_header_checksum(&fragment[..20]).to_be_bytes(),
            fragment[10..12]
        );
        assert_eq!(fragment[6] & DF, 0, "DF clear");
        assert_eq!(
            *id.get_or_insert_with(|| ip.identification()),
            ip.identification()
        );
        let flags = u16::from_be_bytes([fragment[6], fragment[7]]);
        let offset = usize::from(flags & 0x1FFF) * 8;
        if offset == 0 {
            header = fragment[..20].to_vec();
        }
        if fragment[6] & MF == 0 {
            total = Some(offset + payload.len());
        }
        parts.push((offset, payload.to_vec()));
    }
    let fragments = parts.len();
    parts.sort_by_key(|(offset, _)| *offset);
    let mut datagram = header;
    for (offset, part) in parts {
        assert_eq!(datagram.len() - 20, offset, "fragments are contiguous");
        datagram.extend(part);
    }
    // The first fragment's header, made whole: full length, no fragment flags.
    let len = u16::try_from(datagram.len())?;
    datagram[2..4].copy_from_slice(&len.to_be_bytes());
    datagram[6..8].fill(0);
    Ok((datagram, fragments))
}

#[tokio::test]
async fn oversize_ipv4_reply_is_fragmented_by_the_engine_and_reassembles() -> TestResult {
    let (stack, mut raw) = stack_and_raw(true).await?;
    let mut incoming = stack.stack.incoming_udp();
    let flow = open_flow(&stack, &raw, &mut incoming, false).await?;
    let payload = data(3000);
    flow.send(&payload).await?;

    let (datagram, fragments) = reassemble(&mut raw).await?;
    assert!(fragments > 1, "the engine split the datagram");
    let (ip, segment) = Ipv4Header::parse(&datagram)?;
    assert_eq!((ip.src(), ip.dst()), (stack.ip4, raw.ip4));
    assert_eq!(ip.protocol(), protocol::UDP);
    assert_eq!(
        transport_checksum_v4(ip.src(), ip.dst(), protocol::UDP, segment),
        0,
        "the reassembled datagram's UDP checksum verifies"
    );
    assert_eq!(segment[0..2], DST_PORT.to_be_bytes());
    assert_eq!(segment[2..4], SRC_PORT.to_be_bytes());
    assert_eq!(&segment[8..], payload.as_slice());
    raw.expect_no_delivery().await?;

    // IPv6 above the MTU is still refused.
    let flow = open_flow(&stack, &raw, &mut incoming, true).await?;
    let error = flow.send(&payload).await.err().ok_or("IPv6 must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    raw.expect_no_delivery().await?;
    Ok(())
}

#[tokio::test]
async fn oversize_reply_fails_by_default() -> TestResult {
    let (stack, mut raw) = stack_and_raw(false).await?;
    let mut incoming = stack.stack.incoming_udp();
    let flow = open_flow(&stack, &raw, &mut incoming, false).await?;
    let error = flow.send(&data(3000)).await.err().ok_or("must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

    // A reply that fits arrives whole, DF set as before.
    let payload = data(usize::from(MTU) - 28);
    flow.send(&payload).await?;
    let (_, packet) = raw.expect_delivery().await?;
    assert_eq!(packet.len(), usize::from(MTU));
    assert_eq!(packet[6], DF);
    assert_eq!(&packet[28..], payload.as_slice());
    raw.expect_no_delivery().await?;
    Ok(())
}
