use std::collections::HashSet;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicU64, Ordering};

use nsplane_packet::checksum::ipv4_header_checksum;
use nsplane_packet::reassembly::ReassemblyConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::{FlowContext, FlowControl, Ownership, RetirementOutcome};

// ── Flow context: the caller's label on a flow and its instance ───────

/// The `(src, dst)` of a TCP or UDP packet.
fn tuple_of(packet: &PacketBuf) -> Option<(SocketAddr, SocketAddr)> {
    tcp_tuple(packet.as_packet())
        .or_else(|| udp::parse_udp(packet.clone()).map(|datagram| (datagram.src, datagram.dst)))
}

/// The payload of a UDP packet.
fn udp_payload(packet: &PacketBuf) -> Option<Vec<u8>> {
    udp::parse_udp(packet.clone()).map(|datagram| datagram.payload.to_vec())
}

/// The payload of a TCP packet.
fn tcp_payload(packet: &PacketBuf) -> Option<&[u8]> {
    let segment = tcp_segment(packet.as_packet())?;
    let offset = usize::from(segment.get(12)? >> 4) * 4;
    segment.get(offset..)
}

/// Shuttles packets both ways once, taking the stack's egress through the same check as
/// `NetStackSource::recv`. Only TCP reaches the client; returns every packet it took.
async fn pump_once(peer: &mut RawPeer) -> Vec<PacketBuf> {
    let mut seen = Vec::new();
    while let Some(packet) = peer.source.try_admit() {
        if tcp_segment(packet.as_packet()).is_some() {
            peer.device.inject(packet.clone());
        }
        seen.push(packet);
    }
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    let packets: Vec<PacketBuf> = peer.device.drain_tx().collect();
    for packet in packets {
        let _ = peer.sink.send(packet, PeerId::new(0)).await;
    }
    seen
}

/// Shuttles packets for `ticks` short ticks; returns the stack's packets it took.
async fn pump(peer: &mut RawPeer, ticks: usize) -> Vec<PacketBuf> {
    let mut seen = Vec::new();
    for _ in 0..ticks {
        seen.extend(pump_once(peer).await);
        sleep(Duration::from_millis(5)).await;
    }
    seen
}

/// Pumps until `ready` holds, for at most five seconds; returns the packets it took.
async fn pump_until(
    peer: &mut RawPeer,
    ready: impl Fn(&RawPeer) -> bool + Send + Sync,
) -> Result<Vec<PacketBuf>, Box<dyn Error>> {
    let seen = timeout(Duration::from_secs(5), async {
        let mut seen = Vec::new();
        while !ready(peer) {
            seen.extend(pump(peer, 1).await);
        }
        seen
    })
    .await
    .map_err(|_| "the state should converge")?;
    Ok(seen)
}

/// Takes every packet the stack lets out until it stays quiet for 50 ms.
async fn drain(source: &mut NetStackSource) -> Vec<PacketBuf> {
    let mut packets = Vec::new();
    while let Ok(Ok(packet)) = timeout(Duration::from_millis(50), source.recv()).await {
        packets.push(packet);
    }
    packets
}

/// Opens a client socket from `client` to `server` and returns it with the stack's side.
async fn accept(
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
            return Ok((conn, socket));
        }
    }
    Err("TCP handshake should complete".into())
}

/// The bytes the client socket received so far.
fn client_received(peer: &mut RawPeer, socket: SocketHandle) -> Vec<u8> {
    let mut received = Vec::new();
    let _ = peer.socket(socket).recv(|data| {
        received.extend_from_slice(data);
        (data.len(), ())
    });
    received
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

/// The kind of the error of `result`, if it failed.
fn kind<T>(result: io::Result<T>) -> Option<io::ErrorKind> {
    result.err().map(|error| error.kind())
}

/// Waits until `ready` holds for `handle`, for at most five seconds.
async fn until(
    handle: &NetStackHandle,
    ready: impl Fn(&NetStackHandle) -> bool + Send + Sync,
) -> TestResult {
    timeout(Duration::from_secs(5), async {
        while !ready(handle) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| format!("never converged: {:?}", handle.stats()).into())
}

/// `packet` (IPv4, 20-byte header) split into fragments of `chunk` payload bytes (a
/// multiple of 8), with identification `id`.
fn fragments_v4(packet: &[u8], chunk: usize, id: u16) -> Vec<PacketBuf> {
    let (header, payload) = packet.split_at(20);
    let count = payload.len().div_ceil(chunk);
    payload
        .chunks(chunk)
        .enumerate()
        .map(|(i, data)| {
            let mut fragment = header.to_vec();
            let total = u16::try_from(20 + data.len()).unwrap_or(u16::MAX);
            fragment[2..4].copy_from_slice(&total.to_be_bytes());
            fragment[4..6].copy_from_slice(&id.to_be_bytes());
            let more = if i + 1 < count { 0x2000 } else { 0 };
            let offset = u16::try_from(i * chunk / 8).unwrap_or(0);
            fragment[6..8].copy_from_slice(&(more | offset).to_be_bytes());
            fragment[10..12].fill(0);
            let checksum = ipv4_header_checksum(&fragment);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
            fragment.extend_from_slice(data);
            PacketBuf::from_packet(&fragment)
        })
        .collect()
}

/// A fragmented UDP datagram of 3000 bytes from `remote` to `local`: its fragments (the
/// first one carries the ports) and its payload.
fn fragmented(
    remote: SocketAddr,
    local: SocketAddr,
    id: u16,
) -> Result<(Vec<PacketBuf>, Vec<u8>), Box<dyn Error>> {
    let payload: Vec<u8> = (0..3000_usize)
        .map(|i| (i % 251).to_le_bytes()[0])
        .collect();
    let packet = build_udp(remote, local, &payload).ok_or("build")?;
    Ok((fragments_v4(packet.as_packet(), 1336, id), payload))
}

/// A configuration with reassembly.
fn reassembling(ip: Ipv4Addr, reassembly: ReassemblyConfig) -> NetStackConfig {
    NetStackConfig {
        reassembly: Some(reassembly),
        ..config(ip)
    }
}

#[tokio::test]
async fn bind_context_once_and_not_after_revoke() -> TestResult {
    let server: SocketAddrV4 = "10.9.60.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.60.2:49200".parse()?;
    let (handle, mut peer) = RawPeer::start(config(*server.ip()), *client.ip(), 0xc0de);
    let mut incoming = handle.incoming_tcp();
    let (conn, _socket) = accept(&mut incoming, &mut peer, server, client).await?;
    let socket = handle.bind_udp("10.9.60.1:5000".parse()?).await?;

    for control in [conn.control(), socket.control()] {
        assert_eq!(control.context(), None);
        let context = control.bind_context(7)?;
        assert_eq!(context.domain(), 7);
        assert_eq!(control.context(), Some(context));
        assert_eq!(
            control.clone().context(),
            Some(context),
            "every control sees it"
        );
        // Binds once: neither the same nor another domain rebinds.
        for domain in [7, 8] {
            let again = control.bind_context(domain);
            assert_eq!(kind(again), Some(io::ErrorKind::AlreadyExists));
        }
        assert_eq!(control.context(), Some(context));
        // A revoke keeps the label and refuses every later bind.
        assert_eq!(retire(&control).await?, RetirementOutcome::Retired);
        assert_eq!(control.context(), Some(context));
        let after = control.bind_context(9);
        assert_eq!(kind(after), Some(io::ErrorKind::ConnectionAborted));
    }
    assert_eq!(conn.control().context().map(|c| c.domain()), Some(7));

    // Revoked before any bind: nothing ever binds, pending receipt or not.
    let unbound = handle.connect_udp("10.9.60.2:53".parse()?).await?;
    let control = unbound.control();
    let receipt = control.revoke();
    assert_eq!(
        kind(control.bind_context(7)),
        Some(io::ErrorKind::ConnectionAborted)
    );
    assert_eq!(
        timeout(WAIT, receipt.wait()).await?,
        RetirementOutcome::Retired
    );
    assert_eq!(
        kind(control.bind_context(7)),
        Some(io::ErrorKind::ConnectionAborted)
    );
    assert_eq!(control.context(), None);
    Ok(())
}

/// What a flow's traffic and retirement look like from outside the stack.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    client_bytes: Vec<u8>,
    server_bytes: Vec<u8>,
    udp_payloads: Vec<Vec<u8>>,
    flow_payloads: Vec<Vec<u8>>,
    outcomes: Vec<RetirementOutcome>,
    retired_drops: u64,
    stats: NetStackStats,
    owns: Ownership,
}

/// Runs one TCP connection and one UDP flow, labelled with `domain` if given, through
/// traffic and a revoke with queued output.
async fn observe(domain: Option<u64>) -> Result<Observed, Box<dyn Error>> {
    let server: SocketAddrV4 = "10.9.61.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.61.2:49200".parse()?;
    let local: SocketAddr = "10.9.61.1:53".parse()?;
    let remote: SocketAddr = "10.9.61.2:5353".parse()?;
    let mut config = config(*server.ip());
    config.egress_capacity = 4;
    let (handle, mut peer) = RawPeer::start(config, *client.ip(), 0xc0de);
    let mut incoming = handle.incoming_tcp();
    let (mut conn, socket) = accept(&mut incoming, &mut peer, server, client).await?;
    let mut flows = handle.incoming_udp();
    datagram_in(&peer.sink, remote, local, b"hello").await?;
    let mut flow = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    if let Some(domain) = domain {
        let tcp = conn.control().bind_context(domain)?;
        let udp = flow.control().bind_context(domain)?;
        assert_eq!((tcp.domain(), udp.domain()), (domain, domain));
        assert_ne!(tcp.instance(), udp.instance());
    }

    // Traffic both ways.
    let mut flow_payloads = Vec::new();
    flow_payloads.push(timeout(WAIT, flow.recv()).await?.ok_or("closed")?.to_vec());
    conn.write_all(b"to the client").await?;
    flow.send(b"reply").await?;
    peer.socket(socket).send_slice(b"to the server")?;
    let mut udp_payloads = Vec::new();
    let seen = pump_until(&mut peer, |peer| {
        peer.sockets
            .get::<client_tcp::Socket<'_>>(socket)
            .recv_queue()
            == 13
    })
    .await?;
    let mut server_bytes = vec![0u8; 13];
    timeout(WAIT, conn.read_exact(&mut server_bytes)).await??;
    let client_bytes = client_received(&mut peer, socket);
    udp_payloads.extend(seen.iter().filter_map(udp_payload));
    pump(&mut peer, 4).await;

    // A revoke with replies queued past the egress queue.
    for _ in 0..10 {
        flow.send(b"queued").await?;
    }
    sleep(Duration::from_millis(20)).await;
    let tcp_outcome = retire(&conn.control()).await?;
    let udp_outcome = retire(&flow.control()).await?;
    let outcomes = vec![tcp_outcome, udp_outcome];
    let seen = pump(&mut peer, 10).await;
    udp_payloads.extend(seen.iter().filter_map(udp_payload));
    let tuple = segment_tuple(client, server);
    Ok(Observed {
        client_bytes,
        server_bytes,
        udp_payloads,
        flow_payloads,
        outcomes,
        retired_drops: handle.retired_drops(),
        stats: handle.stats(),
        owns: handle.owns(&tuple),
    })
}

/// An IPv4 TCP ACK from `src` to `dst`, for `owns`.
fn segment_tuple(src: SocketAddrV4, dst: SocketAddrV4) -> Vec<u8> {
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
    pkt[33] = 0x10;
    pkt
}

#[tokio::test]
async fn stack_never_reads_the_context() -> TestResult {
    let unlabelled = observe(None).await?;
    assert_eq!(
        unlabelled.outcomes,
        [RetirementOutcome::Retired, RetirementOutcome::Retired]
    );
    assert_eq!(unlabelled.udp_payloads, [b"reply".to_vec()]);
    assert_eq!(unlabelled.flow_payloads, [b"hello".to_vec()]);
    assert_eq!(unlabelled.client_bytes, b"to the client");
    assert_eq!(unlabelled.server_bytes, b"to the server");
    assert!(unlabelled.retired_drops >= 10);
    // Flows that differ only in their context behave the same.
    for domain in [0, 1, u64::MAX] {
        assert_eq!(observe(Some(domain)).await?, unlabelled, "domain {domain}");
    }
    Ok(())
}

#[tokio::test]
async fn same_tuple_reopen_gets_new_queues_and_replies() -> TestResult {
    let server: SocketAddrV4 = "10.9.62.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.62.2:49200".parse()?;
    let mut config = config(*server.ip());
    config.egress_capacity = 4;
    let (handle, mut peer) = RawPeer::start(config, *client.ip(), 0xc0de);

    // TCP: the old connection's output waits in the stack when it is revoked.
    let mut incoming = handle.incoming_tcp();
    let (mut old, old_socket) = accept(&mut incoming, &mut peer, server, client).await?;
    let old_context = old.control().bind_context(1)?;
    old.write_all(&[0xaa; 3000]).await?;
    sleep(Duration::from_millis(20)).await;
    assert_eq!(retire(&old.control()).await?, RetirementOutcome::Retired);

    // The client re-opens the same tuple.
    peer.sockets.remove(old_socket);
    let (mut new, new_socket) = accept(&mut incoming, &mut peer, server, client).await?;
    assert!(!new.control().is_revoked());
    assert_eq!(new.control().context(), None, "nothing is inherited");
    let new_context = new.control().bind_context(1)?;
    assert_ne!(new_context.instance(), old_context.instance());
    new.write_all(b"fresh").await?;
    let seen = pump_until(&mut peer, |peer| {
        peer.sockets
            .get::<client_tcp::Socket<'_>>(new_socket)
            .recv_queue()
            == 5
    })
    .await?;
    assert_eq!(client_received(&mut peer, new_socket), b"fresh");
    assert!(
        seen.iter()
            .filter_map(tcp_payload)
            .all(|payload| !payload.contains(&0xaa)),
        "no byte of the old connection leaves"
    );
    let mut buf = [0u8; 8];
    assert_eq!(
        kind(old.read(&mut buf).await),
        Some(io::ErrorKind::ConnectionAborted)
    );
    assert_eq!(old.control().context(), Some(old_context));

    // UDP: the old flow's replies wait in the stack when it is revoked.
    let local: SocketAddr = "10.9.62.1:53".parse()?;
    let remote: SocketAddr = "10.9.62.2:5353".parse()?;
    let mut flows = handle.incoming_udp();
    datagram_in(&peer.sink, remote, local, b"first").await?;
    let mut old = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    let old_context = old.control().bind_context(1)?;
    let old_reply = old.reply_handle();
    for _ in 0..10 {
        old_reply.send(b"old").await?;
    }
    sleep(Duration::from_millis(20)).await;
    assert_eq!(retire(&old.control()).await?, RetirementOutcome::Retired);

    datagram_in(&peer.sink, remote, local, b"second").await?;
    let mut new = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    assert_eq!((new.peer_addr(), new.local_addr()), (remote, local));
    assert_eq!(new.control().context(), None, "nothing is inherited");
    let new_context = new.control().bind_context(1)?;
    assert_ne!(new_context.instance(), old_context.instance());
    assert_eq!(
        timeout(WAIT, new.recv()).await?.as_deref(),
        Some(&b"second"[..])
    );
    assert!(timeout(WAIT, old.recv()).await?.is_none());
    new.send(b"new").await?;
    assert_eq!(
        kind(old_reply.send(b"late").await),
        Some(io::ErrorKind::ConnectionAborted)
    );
    let payloads: Vec<Vec<u8>> = drain(&mut peer.source)
        .await
        .iter()
        .filter(|packet| tuple_of(packet) == Some((local, remote)))
        .filter_map(udp_payload)
        .collect();
    assert_eq!(
        payloads,
        [b"new".to_vec()],
        "only the new flow's reply leaves"
    );
    Ok(())
}

#[tokio::test]
async fn old_reply_clone_never_sends_after_revoke() -> TestResult {
    let mut config = config(Ipv4Addr::new(10, 9, 63, 1));
    config.egress_capacity = 4;
    let (stack, handle) = NetStack::new(config);
    let (mut source, sink) = stack.split();
    let local: SocketAddr = "10.9.63.1:53".parse()?;
    let remote: SocketAddr = "10.9.63.2:5353".parse()?;
    let mut flows = handle.incoming_udp();
    datagram_in(&sink, remote, local, b"one").await?;
    let flow = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    flow.control().bind_context(4)?;

    // A clone in another task floods until every queue is full and it blocks.
    let flooding = flow.reply_handle();
    let kept = flow.reply_handle();
    let sender = tokio::spawn(async move {
        loop {
            if let Err(error) = flooding.send(b"old").await {
                return error.kind();
            }
        }
    });
    sleep(Duration::from_millis(50)).await;
    assert!(!sender.is_finished());

    assert_eq!(retire(&kept.control()).await?, RetirementOutcome::Retired);
    assert_eq!(
        timeout(WAIT, sender).await??,
        io::ErrorKind::ConnectionAborted
    );
    let aborted = Some(io::ErrorKind::ConnectionAborted);
    assert_eq!(kind(kept.send(b"old").await), aborted);
    assert_eq!(kind(flow.reply_handle().send(b"old").await), aborted);
    assert!(drain(&mut source).await.is_empty(), "nothing queued leaves");
    assert!(handle.retired_drops() > 0);

    // A new flow on the tuple does not revive the old clones.
    datagram_in(&sink, remote, local, b"two").await?;
    let new = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    new.reply_handle().send(b"new").await?;
    assert_eq!(kind(kept.send(b"old").await), aborted);
    let payloads: Vec<Vec<u8>> = drain(&mut source)
        .await
        .iter()
        .filter_map(udp_payload)
        .collect();
    assert_eq!(payloads, [b"new".to_vec()]);
    Ok(())
}

#[tokio::test]
async fn instances_are_unique_and_exhaustion_refuses() -> TestResult {
    // Flows of two stacks bind from many tasks at once.
    let mut controls = Vec::new();
    let mut stacks = Vec::new();
    for ip in [Ipv4Addr::new(10, 9, 64, 1), Ipv4Addr::new(10, 9, 64, 2)] {
        let (stack, handle) = NetStack::new(config(ip));
        stacks.push(stack.split());
        for port in 6000..6032 {
            let socket = handle.bind_udp(SocketAddr::new(ip.into(), port)).await?;
            controls.push(socket.control());
        }
    }
    let tasks: Vec<_> = controls
        .iter()
        .cloned()
        .map(|control| tokio::spawn(async move { control.bind_context(1) }))
        .collect();
    let mut instances = HashSet::new();
    for task in tasks {
        let context = task.await??;
        assert_eq!(context.domain(), 1);
        assert!(instances.insert(context.instance()), "an instance repeats");
    }
    assert_eq!(instances.len(), 64);
    // Revoking never frees an instance for reuse.
    for control in &controls[..8] {
        assert_eq!(retire(control).await?, RetirementOutcome::Retired);
    }
    let (stack, handle) = NetStack::new(config(Ipv4Addr::new(10, 9, 64, 3)));
    let (_source, _sink) = stack.split();
    let later = handle.bind_udp("10.9.64.3:6000".parse()?).await?;
    let context = later.control().bind_context(1)?;
    assert!(!instances.contains(&context.instance()));

    // At the end of the counter every bind refuses; nothing wraps.
    let counter = AtomicU64::new(u64::MAX - 1);
    let last = handle.bind_udp("10.9.64.3:6001".parse()?).await?;
    let refused = handle.bind_udp("10.9.64.3:6002".parse()?).await?;
    let context: FlowContext = last.control().bind_context_from(2, &counter)?;
    assert_eq!(context.instance().get(), u64::MAX - 1);
    for _ in 0..3 {
        let result = refused.control().bind_context_from(2, &counter);
        assert_eq!(kind(result), Some(io::ErrorKind::QuotaExceeded));
        assert_eq!(counter.load(Ordering::SeqCst), u64::MAX);
    }
    assert_eq!(refused.control().context(), None);
    // The flow works on unlabelled and can still bind from a live counter.
    refused.send_to(b"x", "10.9.64.4:53".parse()?).await?;
    assert_eq!(refused.control().bind_context(2)?.domain(), 2);
    drop(stacks);
    Ok(())
}

#[tokio::test]
async fn two_domains_same_tuple_never_mix() -> TestResult {
    let local: SocketAddr = "10.9.65.1:53".parse()?;
    let remote: SocketAddr = "10.9.65.2:5353".parse()?;
    let mut config = config(Ipv4Addr::new(10, 9, 65, 1));
    config.egress_capacity = 4;

    // One stack: the tuple's holder of domain 1, then one of domain 2.
    let (stack, handle) = NetStack::new(config.clone());
    let (mut source, sink) = stack.split();
    let mut flows = handle.incoming_udp();
    datagram_in(&sink, remote, local, b"for 1").await?;
    let mut first = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    let first_context = first.control().bind_context(1)?;
    for _ in 0..10 {
        first.send(b"from 1").await?;
    }
    sleep(Duration::from_millis(20)).await;
    let first_receipt = first.control().revoke();
    assert_eq!(
        timeout(WAIT, first_receipt.wait()).await?,
        RetirementOutcome::Retired
    );
    datagram_in(&sink, remote, local, b"for 2").await?;
    let mut second = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    let second_context = second.control().bind_context(2)?;
    assert_ne!(first_context, second_context);
    assert_ne!(first_context.instance(), second_context.instance());
    second.send(b"from 2").await?;
    assert_eq!(
        timeout(WAIT, second.recv()).await?.as_deref(),
        Some(&b"for 2"[..])
    );
    assert!(timeout(WAIT, first.recv()).await?.is_none());
    let payloads: Vec<Vec<u8>> = drain(&mut source)
        .await
        .iter()
        .filter_map(udp_payload)
        .collect();
    assert_eq!(payloads, [b"from 2".to_vec()]);
    // Retiring the second holder leaves the first one's record as it was.
    assert_eq!(retire(&second.control()).await?, RetirementOutcome::Retired);
    assert_eq!(first_receipt.outcome(), Some(RetirementOutcome::Retired));
    assert_eq!(first.control().context(), Some(first_context));
    assert_eq!(second.control().context(), Some(second_context));

    // Two stacks at once, the same tuple in each, one domain per stack.
    let mut stacks = Vec::new();
    for domain in [1, 2] {
        let (stack, handle) = NetStack::new(config.clone());
        let (source, sink) = stack.split();
        let mut flows = handle.incoming_udp();
        datagram_in(&sink, remote, local, b"in").await?;
        let flow = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
        let context = flow.control().bind_context(domain)?;
        stacks.push((handle, source, sink, flow, context));
    }
    assert_ne!(stacks[0].4.instance(), stacks[1].4.instance());
    for (_, _, _, flow, context) in &stacks {
        for _ in 0..10 {
            flow.send(&context.domain().to_be_bytes()).await?;
        }
    }
    sleep(Duration::from_millis(20)).await;
    assert_eq!(
        retire(&stacks[0].3.control()).await?,
        RetirementOutcome::Retired
    );
    assert!(drain(&mut stacks[0].1).await.is_empty());
    let payloads: Vec<Vec<u8>> = drain(&mut stacks[1].1)
        .await
        .iter()
        .filter_map(udp_payload)
        .collect();
    assert_eq!(payloads, vec![2u64.to_be_bytes().to_vec(); 10]);
    assert_eq!(stacks[1].0.retired_drops(), 0);
    Ok(())
}

#[tokio::test]
async fn held_fragments_never_reach_a_new_flow() -> TestResult {
    let config = reassembling(Ipv4Addr::new(10, 9, 66, 1), ReassemblyConfig::default());
    let (stack, handle) = NetStack::new(config);
    let (_source, sink) = stack.split();
    let local: SocketAddr = "10.9.66.1:53".parse()?;
    let remote: SocketAddr = "10.9.66.2:5353".parse()?;

    // A flow with fragments of a datagram held when it is revoked.
    let mut flows = handle.incoming_udp();
    datagram_in(&sink, remote, local, b"hello").await?;
    let mut old = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    old.control().bind_context(1)?;
    assert_eq!(
        timeout(WAIT, old.recv()).await?.as_deref(),
        Some(&b"hello"[..])
    );
    let (mut fragments, _) = fragmented(remote, local, 7)?;
    let first = fragments.remove(0);
    for fragment in fragments {
        sink.send(fragment, PeerId::new(0)).await?;
    }
    sleep(Duration::from_millis(20)).await;
    assert_eq!(retire(&old.control()).await?, RetirementOutcome::Retired);

    // The datagram completes after the revoke: no new flow takes it.
    sink.send(first, PeerId::new(0)).await?;
    until(&handle, |handle| handle.stats().reassembled == 1).await?;
    assert_eq!(handle.retired_drops(), 1);
    assert!(
        timeout(Duration::from_millis(100), next(&mut flows))
            .await
            .is_err()
    );
    assert!(timeout(WAIT, old.recv()).await?.is_none());

    // Unfragmented traffic on the tuple opens a new flow, which sees only its own.
    datagram_in(&sink, remote, local, b"after").await?;
    let mut new = timeout(WAIT, next(&mut flows)).await?.ok_or("no flow")?;
    assert_eq!(
        timeout(WAIT, new.recv()).await?.as_deref(),
        Some(&b"after"[..])
    );
    assert!(
        timeout(Duration::from_millis(50), new.recv())
            .await
            .is_err()
    );

    // A bound socket: the held datagram never reaches the next socket on the address.
    let bound: SocketAddr = "10.9.66.1:5000".parse()?;
    let socket = handle.bind_udp(bound).await?;
    socket.control().bind_context(1)?;
    let (mut fragments, _) = fragmented(remote, bound, 8)?;
    let first = fragments.remove(0);
    for fragment in fragments {
        sink.send(fragment, PeerId::new(0)).await?;
    }
    sleep(Duration::from_millis(20)).await;
    assert_eq!(retire(&socket.control()).await?, RetirementOutcome::Retired);
    let mut next_socket = handle.bind_udp(bound).await?;
    sink.send(first, PeerId::new(0)).await?;
    until(&handle, |handle| handle.stats().reassembled == 2).await?;
    assert_eq!(handle.retired_drops(), 2);
    datagram_in(&sink, remote, bound, b"own").await?;
    let (payload, from) = timeout(WAIT, next_socket.recv_from()).await??;
    assert_eq!((payload.as_ref(), from), (&b"own"[..], remote));
    Ok(())
}

#[tokio::test]
async fn fragment_barriers_are_bounded_and_expire() -> TestResult {
    let reassembly = ReassemblyConfig {
        max_datagrams: 2,
        timeout: Duration::from_millis(300),
        ..ReassemblyConfig::default()
    };
    let (stack, handle) = NetStack::new(reassembling(Ipv4Addr::new(10, 9, 67, 1), reassembly));
    let (_source, sink) = stack.split();
    let remote: SocketAddr = "10.9.67.2:5353".parse()?;
    let addr = |port: u16| SocketAddr::new(Ipv4Addr::new(10, 9, 67, 1).into(), port);
    let mut sockets = Vec::new();
    for port in 7001..=7003 {
        sockets.push(handle.bind_udp(addr(port)).await?);
    }

    // One datagram held: each revoke needs a barrier, and the table holds two.
    let (fragments, _) = fragmented(remote, addr(7009), 1)?;
    sink.send(fragments[1].clone(), PeerId::new(0)).await?;
    sleep(Duration::from_millis(20)).await;
    let outcomes = [
        retire(&sockets[0].control()).await?,
        retire(&sockets[1].control()).await?,
        retire(&sockets[2].control()).await?,
    ];
    assert_eq!(
        outcomes,
        [
            RetirementOutcome::Retired,
            RetirementOutcome::Retired,
            RetirementOutcome::Failed
        ]
    );
    // The full table fails the revoke, not the flow's cleanup.
    let error = sockets[2].send_to(b"x", remote).await;
    assert_eq!(kind(error), Some(io::ErrorKind::ConnectionAborted));
    let mut reused = handle.bind_udp(addr(7003)).await?;

    // While the barrier lasts, a datagram completed for its address is dropped.
    let mut barred = handle.bind_udp(addr(7001)).await?;
    let (fragments, _) = fragmented(remote, addr(7001), 2)?;
    for fragment in fragments {
        sink.send(fragment, PeerId::new(0)).await?;
    }
    until(&handle, |handle| handle.retired_drops() == 1).await?;
    assert!(
        timeout(Duration::from_millis(50), barred.recv_from())
            .await
            .is_err()
    );

    // One reassembly timeout later the barriers are gone.
    sleep(Duration::from_millis(400)).await;
    for (socket, port, id) in [(&mut barred, 7001, 3), (&mut reused, 7003, 4)] {
        let (fragments, payload) = fragmented(remote, addr(port), id)?;
        for fragment in fragments {
            sink.send(fragment, PeerId::new(0)).await?;
        }
        let (got, from) = timeout(WAIT, socket.recv_from()).await??;
        assert_eq!((got.as_ref(), from), (&payload[..], remote));
    }
    assert_eq!(handle.retired_drops(), 1);

    // With a datagram held again there is room for a barrier.
    let (fragments, _) = fragmented(remote, addr(7009), 5)?;
    sink.send(fragments[1].clone(), PeerId::new(0)).await?;
    let socket = handle.bind_udp(addr(7004)).await?;
    sleep(Duration::from_millis(20)).await;
    assert_eq!(retire(&socket.control()).await?, RetirementOutcome::Retired);
    let other = handle.bind_udp(addr(7005)).await?;
    let third = handle.bind_udp(addr(7006)).await?;
    assert_eq!(retire(&other.control()).await?, RetirementOutcome::Retired);
    assert_eq!(retire(&third.control()).await?, RetirementOutcome::Failed);
    Ok(())
}

#[tokio::test]
async fn late_bound_context_still_drops_queued_output_on_revoke() -> TestResult {
    let server: SocketAddrV4 = "10.9.68.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.68.2:49200".parse()?;
    let mut config = config(*server.ip());
    config.egress_capacity = 4;
    let (handle, mut peer) = RawPeer::start(config, *client.ip(), 0xc0de);
    let mut incoming = handle.incoming_tcp();
    let (mut conn, _socket) = accept(&mut incoming, &mut peer, server, client).await?;
    let remote: SocketAddr = "10.9.68.2:53".parse()?;
    let socket = handle.bind_udp("10.9.68.1:5000".parse()?).await?;

    // Output queued everywhere in the stack before any context exists: the egress queue,
    // the backlog and the send queue.
    conn.write_all(&[0xaa; 2000]).await?;
    for _ in 0..10 {
        socket.send_to(b"early", remote).await?;
    }
    sleep(Duration::from_millis(20)).await;
    for _ in 0..5 {
        socket.send_to(b"early", remote).await?;
    }
    let tcp = conn.control().bind_context(5)?;
    let udp = socket.control().bind_context(5)?;
    assert_eq!(retire(&conn.control()).await?, RetirementOutcome::Retired);
    assert_eq!(retire(&socket.control()).await?, RetirementOutcome::Retired);
    assert_eq!(
        (conn.control().context(), socket.control().context()),
        (Some(tcp), Some(udp))
    );

    let seen = pump(&mut peer, 10).await;
    let flow_tuple = (socket.local_addr(), remote);
    let tcp_tuple = (SocketAddr::V4(server), SocketAddr::V4(client));
    assert!(
        seen.iter()
            .all(|packet| tuple_of(packet) != Some(flow_tuple)
                && tuple_of(packet) != Some(tcp_tuple)),
        "nothing queued before the bind leaves"
    );
    assert!(handle.retired_drops() >= 16, "{}", handle.retired_drops());
    Ok(())
}
