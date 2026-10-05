//! Two stacks wired back to back (source -> sink) and single stacks fed crafted packets,
//! through the public API only.

use std::error::Error;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_core::Stream;
use nsplane::{HEADROOM, PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_netstack::{
    MIN_MTU, NetStack, NetStackConfig, NetStackHandle, NetStackSink, NetStackSource,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

type TestResult = Result<(), Box<dyn Error>>;

const WAIT: Duration = Duration::from_secs(5);

fn addr(s: &str) -> Result<SocketAddr, Box<dyn Error>> {
    Ok(s.parse()?)
}

/// The next item of `stream`, failing after [`WAIT`].
async fn next<S: Stream + Unpin>(stream: &mut S) -> Result<S::Item, Box<dyn Error>> {
    let item = timeout(WAIT, poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)))
        .await
        .map_err(|_| "timed out waiting for the stream")?;
    Ok(item.ok_or("stream ended")?)
}

/// Forwards every packet from `from` to `to`, recording the largest one.
async fn wire(mut from: NetStackSource, to: NetStackSink, largest: Arc<AtomicUsize>) {
    while let Ok(mut packet) = from.recv().await {
        assert_eq!(packet.with_headroom_mut().len(), HEADROOM + packet.len());
        largest.fetch_max(packet.len(), Ordering::Relaxed);
        if to.send(packet, PeerId::new(1)).await.is_err() {
            break;
        }
    }
}

/// Stack `a` (`10.0.0.1`, `fd00::1`) and stack `b` (`10.0.0.2`, `fd00::2`) wired back to back.
struct Pair {
    a: NetStackHandle,
    b: NetStackHandle,
    /// The largest packet either stack emitted.
    largest: Arc<AtomicUsize>,
}

fn pair_with(mtu: u16, b_config: impl FnOnce(&mut NetStackConfig)) -> Result<Pair, Box<dyn Error>> {
    let a_config = NetStackConfig::new(
        vec![(IpAddr::from([10, 0, 0, 1]), 24), ("fd00::1".parse()?, 64)],
        mtu,
    );
    let mut config = NetStackConfig::new(
        vec![(IpAddr::from([10, 0, 0, 2]), 24), ("fd00::2".parse()?, 64)],
        mtu,
    );
    b_config(&mut config);
    let (a_stack, a) = NetStack::new(a_config);
    let (b_stack, b) = NetStack::new(config);
    let (a_source, a_sink) = a_stack.split();
    let (b_source, b_sink) = b_stack.split();
    let largest = Arc::new(AtomicUsize::new(0));
    tokio::spawn(wire(a_source, b_sink, Arc::clone(&largest)));
    tokio::spawn(wire(b_source, a_sink, Arc::clone(&largest)));
    Ok(Pair { a, b, largest })
}

fn pair(mtu: u16) -> Result<Pair, Box<dyn Error>> {
    pair_with(mtu, |_| {})
}

/// `a` connects to `b` at `target`; `b` echoes everything until EOF, then half-closes.
#[tokio::test]
async fn tcp_echo_with_half_close_over_ipv4_and_ipv6() -> TestResult {
    let pair = pair(1420)?;
    let mut incoming = pair.b.incoming_tcp();
    for target in [addr("10.0.0.2:7000")?, addr("[fd00::2]:7000")?] {
        let mut client = pair.a.connect_tcp(target).await?;
        let mut server = next(&mut incoming).await?;
        assert_eq!(client.peer_addr(), target);
        assert_eq!(server.local_addr(), target);
        assert_eq!(server.peer_addr(), client.local_addr());
        assert_eq!(client.local_addr().is_ipv4(), target.is_ipv4());

        client.write_all(b"ping over the stack").await?;
        client.shutdown().await?;
        let mut request = Vec::new();
        timeout(WAIT, server.read_to_end(&mut request)).await??;
        assert_eq!(request, b"ping over the stack");

        // The server's read half saw FIN; its write half still works.
        server.write_all(&request).await?;
        server.shutdown().await?;
        let mut response = Vec::new();
        timeout(WAIT, client.read_to_end(&mut response)).await??;
        assert_eq!(response, request);

        timeout(WAIT, client.terminated()).await?;
        timeout(WAIT, server.terminated()).await?;
    }
    Ok(())
}

/// Bulk transfer: the advertised MSS keeps every packet within the MTU, and full-size
/// segments use all of it.
#[tokio::test]
async fn bulk_transfer_never_exceeds_the_mtu() -> TestResult {
    const MTU: u16 = 1280;
    let pair = pair(MTU)?;
    let mut incoming = pair.b.incoming_tcp();
    for (target, len) in [
        (addr("10.0.0.2:9000")?, 1 << 20),
        (addr("[fd00::2]:9000")?, 256 << 10),
    ] {
        let data: Vec<u8> = (0..len).map(|i: usize| i.to_le_bytes()[0] ^ 0x5a).collect();
        let mut client = pair.a.connect_tcp(target).await?;
        let mut server = next(&mut incoming).await?;
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&sent).await?;
            client.shutdown().await?;
            Ok::<_, io::Error>(client)
        });
        let mut received = Vec::new();
        timeout(Duration::from_secs(30), server.read_to_end(&mut received)).await??;
        writer.await??;
        assert_eq!(received.len(), data.len());
        assert!(received == data, "bulk data must arrive intact");
    }
    assert_eq!(
        pair.largest.load(Ordering::Relaxed),
        usize::from(MTU),
        "full segments fill the MTU and never exceed it"
    );
    Ok(())
}

#[tokio::test]
async fn connect_tcp_needs_an_address_of_the_family() -> TestResult {
    let (_stack, handle) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::from([10, 0, 0, 1]), 24)],
        1420,
    ));
    let error = handle
        .connect_tcp(addr("[fd00::2]:80")?)
        .await
        .err()
        .ok_or("connect must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    Ok(())
}

/// `a` sends from a bound socket; `b` reports a flow with the first datagram, replies on
/// it, and the reply reaches the bound socket. IPv4 and IPv6.
#[tokio::test]
async fn udp_flow_and_bound_socket_over_ipv4_and_ipv6() -> TestResult {
    let pair = pair(1420)?;
    let mut incoming = pair.b.incoming_udp();
    for (bind, target) in [
        (addr("0.0.0.0:0")?, addr("10.0.0.2:53")?),
        (addr("[::]:0")?, addr("[fd00::2]:53")?),
    ] {
        let mut socket = pair.a.bind_udp(bind).await?;
        assert_ne!(socket.local_addr().port(), 0);
        socket.send_to(b"query", target).await?;

        let mut flow = next(&mut incoming).await?;
        assert_eq!(flow.local_addr(), target);
        assert_eq!(flow.peer_addr().port(), socket.local_addr().port());
        assert_eq!(flow.peer_addr().is_ipv4(), target.is_ipv4());
        let first = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
        assert_eq!(first.as_ref(), b"query");

        socket.send_to(b"again", target).await?;
        let second = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
        assert_eq!(second.as_ref(), b"again");

        flow.send(b"answer").await?;
        let (payload, from) = timeout(WAIT, socket.recv_from()).await??;
        assert_eq!(payload.as_ref(), b"answer");
        assert_eq!(from, target);
    }
    Ok(())
}

/// Datagrams to a bound address go to the socket, not to `incoming_udp`.
#[tokio::test]
async fn bound_socket_takes_datagrams_before_incoming_udp() -> TestResult {
    let pair = pair(1420)?;
    let mut incoming = pair.b.incoming_udp();
    let target = addr("[fd00::2]:5353")?;
    let mut bound = pair.b.bind_udp(target).await?;
    let sender = pair.a.bind_udp(addr("[fd00::1]:4000")?).await?;

    sender.send_to(b"to the socket", target).await?;
    let (payload, from) = timeout(WAIT, bound.recv_from()).await??;
    assert_eq!(payload.as_ref(), b"to the socket");
    assert_eq!(from, addr("[fd00::1]:4000")?);
    assert!(
        timeout(Duration::from_millis(100), next(&mut incoming))
            .await
            .is_err(),
        "a bound address must not open a flow"
    );

    // Once the socket is dropped, the address opens flows again.
    drop(bound);
    sender.send_to(b"to a flow", target).await?;
    let mut flow = next(&mut incoming).await?;
    assert_eq!(flow.local_addr(), target);
    let first = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
    assert_eq!(first.as_ref(), b"to a flow");
    Ok(())
}

#[tokio::test]
async fn bind_udp_rejects_foreign_and_duplicate_addresses() -> TestResult {
    let pair = pair(1420)?;
    let error = pair
        .a
        .bind_udp(addr("10.0.0.9:53")?)
        .await
        .err()
        .ok_or("foreign address must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);

    let socket = pair.a.bind_udp(addr("10.0.0.1:53")?).await?;
    let error = pair
        .a
        .bind_udp(addr("10.0.0.1:53")?)
        .await
        .err()
        .ok_or("duplicate bind must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    drop(socket);
    pair.a.bind_udp(addr("10.0.0.1:53")?).await?;

    // Oversized and cross-family sends are refused.
    let socket = pair.a.bind_udp(addr("10.0.0.1:0")?).await?;
    let error = socket
        .send_to(&[0; 1500], addr("10.0.0.2:53")?)
        .await
        .err()
        .ok_or("oversized datagram must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let error = socket
        .send_to(b"x", addr("[fd00::2]:53")?)
        .await
        .err()
        .ok_or("cross-family send must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    Ok(())
}

/// A single stack with its sink and source, at 10.0.0.1.
fn single(
    config: impl FnOnce(&mut NetStackConfig),
) -> (NetStackHandle, NetStackSource, NetStackSink) {
    let mut base = NetStackConfig::new(vec![(IpAddr::from([10, 0, 0, 1]), 24)], 1420);
    config(&mut base);
    let (stack, handle) = NetStack::new(base);
    let (source, sink) = stack.split();
    (handle, source, sink)
}

/// An IPv4/UDP packet with a zero (unused) checksum.
fn udp(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> PacketBuf {
    let mut pkt = vec![0u8; 29];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&29u16.to_be_bytes());
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&9u16.to_be_bytes());
    PacketBuf::from_packet(&pkt)
}

/// Waits until `check` holds for the stack's counters.
async fn counted(
    handle: &NetStackHandle,
    check: impl Fn(&nsplane_netstack::NetStackStats) -> bool + Sync,
) -> TestResult {
    timeout(WAIT, async {
        while !check(&handle.stats()) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| format!("counters never matched: {:?}", handle.stats()))?;
    Ok(())
}

#[tokio::test]
async fn ingress_drops_are_counted() -> TestResult {
    let (handle, _source, sink) = single(|config| {
        config.accept_capacity = 1;
        config.datagram_capacity = 2;
    });
    let peer = PeerId::new(1);
    sink.send(PacketBuf::from_packet(&[0x45, 0]), peer).await?;
    sink.send(udp([10, 0, 0, 2], 1, [10, 0, 0, 9], 53), peer)
        .await?;
    let mut icmp = udp([10, 0, 0, 2], 1, [10, 0, 0, 1], 53);
    icmp.as_packet_mut()[9] = 1;
    sink.send(icmp, peer).await?;
    let mut bad_udp = udp([10, 0, 0, 2], 1, [10, 0, 0, 1], 53);
    bad_udp.as_packet_mut()[24..26].copy_from_slice(&200u16.to_be_bytes());
    sink.send(bad_udp, peer).await?;
    // One flow (queued in incoming_udp, never consumed) with a two-datagram queue.
    for _ in 0..3 {
        sink.send(udp([10, 0, 0, 2], 1, [10, 0, 0, 1], 53), peer)
            .await?;
    }
    // A second flow does not fit the one-entry accept queue.
    sink.send(udp([10, 0, 0, 3], 1, [10, 0, 0, 1], 53), peer)
        .await?;

    counted(&handle, |stats| {
        stats.malformed == 2
            && stats.no_address == 1
            && stats.unsupported == 1
            && stats.udp_queue_full == 1
            && stats.udp_not_accepted == 1
    })
    .await
}

/// Sends `burst` datagrams to a socket with a queue of `capacity` while a task waits on it,
/// all queued before the driver runs: the datagrams received and the counted drops.
async fn ingress_burst(capacity: usize, burst: u16) -> Result<(u64, u64), Box<dyn Error>> {
    let (handle, _source, sink) = single(|config| config.datagram_capacity = capacity);
    let local = addr("10.0.0.1:53")?;
    let mut socket = handle.bind_udp(local).await?;
    let received = Arc::new(AtomicUsize::new(0));
    let reader = Arc::clone(&received);
    tokio::spawn(async move {
        while socket.recv_from().await.is_ok() {
            reader.fetch_add(1, Ordering::Relaxed);
        }
    });
    // Without a cooperative yield, every send lands before the driver or the reader runs.
    tokio::task::unconstrained(async {
        for port in 1..=burst {
            sink.send(udp([10, 0, 0, 2], port, [10, 0, 0, 1], 53), PeerId::new(1))
                .await?;
        }
        Ok::<_, io::Error>(())
    })
    .await?;
    let total = u64::from(burst);
    counted(&handle, |stats| {
        received.load(Ordering::Relaxed) as u64 + stats.udp_queue_full == total
    })
    .await?;
    Ok((
        received.load(Ordering::Relaxed) as u64,
        handle.stats().udp_queue_full,
    ))
}

#[tokio::test]
async fn one_driver_turn_drops_a_burst_beyond_the_datagram_queue() -> TestResult {
    // The driver routes the whole burst in one step, so the waiting reader cannot help.
    assert_eq!(ingress_burst(8, 32).await?, (8, 24));
    assert_eq!(ingress_burst(32, 32).await?, (32, 0));
    Ok(())
}

#[tokio::test]
async fn udp_flow_limit_is_counted() -> TestResult {
    let (handle, _source, sink) = single(|config| config.max_udp_flows = 1);
    let mut incoming = handle.incoming_udp();
    sink.send(udp([10, 0, 0, 2], 1, [10, 0, 0, 1], 53), PeerId::new(1))
        .await?;
    let _live = next(&mut incoming).await?;
    sink.send(udp([10, 0, 0, 3], 1, [10, 0, 0, 1], 53), PeerId::new(1))
        .await?;
    counted(&handle, |stats| stats.udp_flow_limit == 1).await
}

#[tokio::test]
async fn unaccepted_tcp_connections_are_counted() -> TestResult {
    let pair = pair_with(1420, |config| config.accept_capacity = 1)?;
    // `b` never consumes `incoming_tcp`: the first connection waits there, the second
    // is closed.
    let _first = pair.a.connect_tcp(addr("10.0.0.2:80")?).await?;
    let mut second = pair.a.connect_tcp(addr("10.0.0.2:80")?).await?;
    counted(&pair.b, |stats| stats.tcp_not_accepted == 1).await?;
    let mut rest = Vec::new();
    timeout(WAIT, second.read_to_end(&mut rest)).await??;
    assert!(rest.is_empty(), "the dropped connection is closed");
    Ok(())
}

/// More SYNs than the listener pool, with the egress queue never read: the surplus is
/// refused with RSTs, and RSTs that find the egress backlog full are dropped.
#[tokio::test]
async fn refused_syns_and_full_egress_are_counted() -> TestResult {
    let (handle, _source, sink) = single(|config| config.egress_capacity = 1);
    for port in 0..300u16 {
        let mut syn = vec![0u8; 40];
        syn[0] = 0x45;
        syn[2..4].copy_from_slice(&40u16.to_be_bytes());
        syn[8] = 64;
        syn[9] = 6;
        syn[12..16].copy_from_slice(&[10, 0, 0, 2]);
        syn[16..20].copy_from_slice(&[10, 0, 0, 1]);
        syn[20..22].copy_from_slice(&40_000u16.to_be_bytes());
        syn[22..24].copy_from_slice(&(1000 + port).to_be_bytes());
        syn[32] = 0x50;
        syn[33] = 0x02;
        syn[34..36].copy_from_slice(&65535u16.to_be_bytes());
        let ip_sum = nsplane_packet::checksum::ipv4_header_checksum(&syn[..20]);
        syn[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        let tcp_sum = nsplane_packet::checksum::transport_checksum_v4(
            [10, 0, 0, 2].into(),
            [10, 0, 0, 1].into(),
            6,
            &syn[20..],
        );
        syn[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
        sink.send(PacketBuf::from_packet(&syn), PeerId::new(1))
            .await?;
    }
    counted(&handle, |stats| {
        stats.syn_refused > 0 && stats.egress_full > 0
    })
    .await
}

#[tokio::test]
async fn source_reports_mtu_and_ends_after_shutdown() -> TestResult {
    let (_handle, mut source, sink) = single(|config| config.mtu = 100);
    assert_eq!(*source.mtu().borrow(), MIN_MTU, "a too-small MTU is raised");
    drop(sink);
    for _ in 0..3 {
        let error = timeout(WAIT, source.recv())
            .await?
            .err()
            .ok_or("source must end")?;
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
    Ok(())
}
