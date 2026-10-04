use super::*;
use crate::Ownership;
use crate::udp::parse_udp;

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 9, 8, 1);

/// A datagram from `src` to `dst` carrying `payload`, as raw bytes.
fn datagram(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(build_udp(src, dst, payload)
        .ok_or("build failed")?
        .as_packet()
        .to_vec())
}

async fn inject(sink: &NetStackSink, packet: &[u8]) -> TestResult {
    sink.send(PacketBuf::from_packet(packet), PeerId::new(0))
        .await?;
    Ok(())
}

#[tokio::test]
async fn connected_socket_exchanges_datagrams_with_its_remote_only() -> TestResult {
    let (stack, handle) = NetStack::new(config(LOCAL));
    let (mut source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    let remote: SocketAddr = "10.9.8.2:53".parse()?;
    let other: SocketAddr = "10.9.8.3:53".parse()?;

    let mut socket = handle.connect_udp(remote).await?;
    let local = socket.local_addr();
    assert_eq!(local.ip(), IpAddr::V4(LOCAL));
    assert_eq!(socket.peer_addr(), Some(remote));

    socket.send(b"query").await?;
    let sent = parse_udp(timeout(WAIT, source.recv()).await??).ok_or("must parse")?;
    assert_eq!((sent.src, sent.dst), (local, remote));
    assert_eq!(sent.payload.as_ref(), b"query");

    let from_remote = datagram(remote, local, b"answer")?;
    let from_other = datagram(other, local, b"stray")?;
    assert_eq!(handle.owns(&from_remote), Ownership::Flow);
    assert_eq!(handle.owns(&from_other), Ownership::Listener);

    inject(&sink, &from_other).await?;
    inject(&sink, &from_remote).await?;
    let (payload, from) = timeout(WAIT, socket.recv_from()).await??;
    assert_eq!((payload.as_ref(), from), (&b"answer"[..], remote));
    let mut flow = timeout(WAIT, next(&mut incoming))
        .await?
        .ok_or("the other remote opens a flow")?;
    assert_eq!((flow.peer_addr(), flow.local_addr()), (other, local));
    assert_eq!(
        timeout(WAIT, flow.recv())
            .await?
            .ok_or("flow closed")?
            .as_ref(),
        b"stray"
    );
    assert_eq!(handle.owns(&from_other), Ownership::Flow);

    drop(socket);
    assert_eq!(handle.owns(&from_remote), Ownership::Listener);
    // The tuple is free again: a datagram of it now opens a flow.
    inject(&sink, &from_remote).await?;
    let flow = timeout(WAIT, next(&mut incoming))
        .await?
        .ok_or("the tuple opens a flow")?;
    assert_eq!(flow.peer_addr(), remote);
    Ok(())
}

#[tokio::test]
async fn connected_tuple_wins_over_a_bound_socket() -> TestResult {
    let (stack, handle) = NetStack::new(config(LOCAL));
    let (_source, sink) = stack.split();
    let local = SocketAddr::new(LOCAL.into(), 5000);
    let remote: SocketAddr = "10.9.8.2:53".parse()?;
    let other: SocketAddr = "10.9.8.3:53".parse()?;
    let mut bound = handle.bind_udp(local).await?;
    let mut connected = handle.connect_udp_from(local, remote).await?;
    assert_eq!(connected.local_addr(), local);

    inject(&sink, &datagram(remote, local, b"mine")?).await?;
    inject(&sink, &datagram(other, local, b"bound")?).await?;
    let (payload, from) = timeout(WAIT, connected.recv_from()).await??;
    assert_eq!((payload.as_ref(), from), (&b"mine"[..], remote));
    let (payload, from) = timeout(WAIT, bound.recv_from()).await??;
    assert_eq!((payload.as_ref(), from), (&b"bound"[..], other));
    Ok(())
}

#[tokio::test]
async fn ephemeral_ports_differ_and_skip_bound_ports() -> TestResult {
    let (stack, handle) = NetStack::new(config(LOCAL));
    let (_source, _sink) = stack.split();
    let remote: SocketAddr = "10.9.8.2:53".parse()?;
    let first = handle.connect_udp(remote).await?;
    let second = handle
        .connect_udp_from("0.0.0.0:0".parse()?, remote)
        .await?;
    let explicit = handle
        .connect_udp_from(SocketAddr::new(LOCAL.into(), 0), remote)
        .await?;
    let ports = [first, second, explicit].map(|socket| socket.local_addr().port());
    assert!(ports.iter().all(|&port| port >= EPHEMERAL_START));
    assert!(ports[0] != ports[1] && ports[1] != ports[2] && ports[0] != ports[2]);

    // The ports the cursor hands out next, bound on the exact and the unspecified
    // address, are skipped.
    let following = |port: u16| {
        if port == u16::MAX {
            EPHEMERAL_START
        } else {
            port + 1
        }
    };
    let mut port = ports[2];
    let mut bound = Vec::new();
    for i in 0..8 {
        port = following(port);
        let ip = if i % 2 == 0 {
            IpAddr::V4(LOCAL)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        bound.push(handle.bind_udp(SocketAddr::new(ip, port)).await?);
    }
    let socket = handle.connect_udp(remote).await?;
    assert_eq!(socket.local_addr().port(), following(port));
    Ok(())
}

#[tokio::test]
async fn connect_udp_errors() -> TestResult {
    let (stack, handle) = NetStack::new(config(LOCAL));
    let (_source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    let remote: SocketAddr = "10.9.8.2:53".parse()?;
    let kind = |result: io::Result<UdpSocket>| result.err().map(|error| error.kind());

    let no_v6 = handle.connect_udp("[fd00::2]:53".parse()?).await;
    assert_eq!(kind(no_v6), Some(io::ErrorKind::AddrNotAvailable));
    let mixed = handle.connect_udp_from("[::]:0".parse()?, remote).await;
    assert_eq!(kind(mixed), Some(io::ErrorKind::InvalidInput));
    let foreign = handle.connect_udp_from("10.9.8.9:0".parse()?, remote).await;
    assert_eq!(kind(foreign), Some(io::ErrorKind::AddrNotAvailable));
    let unspecified = handle.connect_udp("10.9.8.2:0".parse()?).await;
    assert_eq!(kind(unspecified), Some(io::ErrorKind::InvalidInput));

    let local = SocketAddr::new(LOCAL.into(), 6000);
    let socket = handle.connect_udp_from(local, remote).await?;
    let duplicate = handle.connect_udp_from(local, remote).await;
    assert_eq!(kind(duplicate), Some(io::ErrorKind::AddrInUse));
    // Another remote from the same port is a different tuple.
    let _other = handle
        .connect_udp_from(local, "10.9.8.3:53".parse()?)
        .await?;
    drop(socket);
    let _again = handle.connect_udp_from(local, remote).await?;

    // A live incoming flow holds its tuple too.
    let flow_local = SocketAddr::new(LOCAL.into(), 7000);
    inject(&sink, &datagram(remote, flow_local, b"x")?).await?;
    let flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    let held = handle.connect_udp_from(flow_local, remote).await;
    assert_eq!(kind(held), Some(io::ErrorKind::AddrInUse));
    drop(flow);
    let _connected = handle.connect_udp_from(flow_local, remote).await?;

    // A bound socket is not connected.
    let bound = handle.bind_udp("0.0.0.0:0".parse()?).await?;
    assert_eq!(bound.peer_addr(), None);
    let error = bound.send(b"x").await.err().ok_or("send must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);

    drop(sink);
    let stopped = timeout(WAIT, async {
        loop {
            if let Err(error) = handle.connect_udp(remote).await
                && error.kind() == io::ErrorKind::BrokenPipe
            {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(stopped.is_ok(), "a stopped stack fails with BrokenPipe");
    Ok(())
}
