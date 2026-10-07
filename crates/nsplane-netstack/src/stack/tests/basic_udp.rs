use super::*;

/// A raw IPv4/UDP packet with a zero UDP checksum (checksum disabled).
fn raw_udp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&u16::try_from(8 + payload.len()).unwrap_or(0).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

#[test]
fn new_netstack_has_expected_ip() {
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let settings = Settings::new(config(ip));
    assert_eq!(settings.v4, Some((ip, 32)));
    assert_eq!(settings.v6, None);
}

#[test]
fn tcp_dst_port_extracts_port() {
    let mut pkt = vec![0u8; 24];
    pkt[0] = 0x45;
    pkt[9] = 6;
    pkt[22] = 0x1F;
    pkt[23] = 0x40;
    assert_eq!(tcp_dst_port(&pkt), Some(8000));
}

#[test]
fn tcp_dst_port_returns_none_for_udp() {
    let mut pkt = vec![0u8; 24];
    pkt[0] = 0x45;
    pkt[9] = 17;
    assert_eq!(tcp_dst_port(&pkt), None);
}

#[test]
fn tcp_dst_port_returns_none_for_short_packet() {
    assert_eq!(tcp_dst_port(&[0u8; 10]), None);
}

#[tokio::test]
async fn poll_exits_when_inject_rx_closes() -> TestResult {
    let (stack, _handle) = NetStack::new(config(Ipv4Addr::new(10, 0, 0, 1)));
    let (mut source, sink) = stack.split();
    drop(sink);
    let error = timeout(WAIT, source.recv())
        .await?
        .err()
        .ok_or("source must end")?;
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    Ok(())
}

#[tokio::test]
async fn poll_routes_udp_through_dispatcher() -> TestResult {
    let (stack, handle) = NetStack::new(config(Ipv4Addr::new(10, 8, 0, 1)));
    let (_source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    let pkt = raw_udp(
        [10, 0, 0, 2],
        [10, 8, 0, 1],
        12345,
        53,
        &[0xde, 0xad, 0xbe, 0xef],
    );
    sink.send(PacketBuf::from_packet(&pkt), PeerId::new(0))
        .await?;

    let mut flow = timeout(WAIT, next(&mut incoming))
        .await
        .map_err(|_| "timed out waiting for UDP datagram")?
        .ok_or("incoming_udp ended")?;
    assert_eq!(flow.peer_addr(), "10.0.0.2:12345".parse::<SocketAddr>()?);
    assert_eq!(flow.local_addr(), "10.8.0.1:53".parse::<SocketAddr>()?);

    let first = timeout(WAIT, flow.recv())
        .await
        .map_err(|_| "timed out waiting for first UDP payload")?
        .ok_or("flow closed")?;
    assert_eq!(first.as_ref(), &[0xde, 0xad, 0xbe, 0xefu8]);
    Ok(())
}

/// Regression: AUDIT-002 B2. Even when one TCP connection's application side is
/// saturated, UDP must keep flowing.
#[tokio::test]
async fn udp_flows_while_tcp_relay_is_slow() -> TestResult {
    let server_ip = Ipv4Addr::new(10, 8, 0, 1);
    let server_port = 5201;
    let (handle, mut peer) =
        RawPeer::start(config(server_ip), Ipv4Addr::new(10, 8, 0, 2), 0xc11e_c11e);
    let mut incoming_tcp = handle.incoming_tcp();
    let mut incoming_udp = handle.incoming_udp();
    let client = peer.connect(server_ip, server_port, 49_152)?;

    let mut conn = None;
    for _ in 0..40 {
        peer.pump(2).await;
        if let Some(c) = try_next(&mut incoming_tcp) {
            conn = Some(c);
            break;
        }
    }
    let conn = conn.ok_or("TCP handshake should complete")?;
    assert_eq!(conn.local_addr().port(), server_port);

    // Never read from `conn`: its application buffer fills and stays full.
    let payload = vec![0xABu8; 2048];
    for _ in 0..64 {
        let _ = peer.socket(client).send_slice(&payload);
    }
    peer.pump(20).await;

    // UDP must not deadlock behind the saturated TCP connection.
    let pkt = raw_udp(
        [10, 0, 0, 3],
        server_ip.octets(),
        54321,
        9000,
        &[1, 2, 3, 4],
    );
    peer.sink
        .send(PacketBuf::from_packet(&pkt), PeerId::new(0))
        .await?;

    let mut flow = timeout(Duration::from_secs(2), next(&mut incoming_udp))
        .await
        .map_err(|_| "UDP fast path must not deadlock on a slow TCP relay")?
        .ok_or("incoming_udp ended")?;
    assert_eq!(flow.local_addr().port(), 9000);
    let first = timeout(WAIT, flow.recv())
        .await
        .map_err(|_| "timed out waiting for UDP payload")?
        .ok_or("flow closed")?;
    assert_eq!(first.as_ref(), &[1u8, 2, 3, 4]);

    drop(conn);
    Ok(())
}
