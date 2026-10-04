use std::future::Future;
use std::net::SocketAddrV4;

use super::*;
use crate::Ownership;

const RST: u8 = 0x04;
const ACK: u8 = 0x10;

// ── Connection abort (RST and immediate release) ──────────────────────

/// An IPv4 TCP segment from `src` to `dst` with `flags` (checksums are not checked by
/// `owns`).
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

fn flags(packet: &PacketBuf) -> u8 {
    tcp_segment(packet.as_packet())
        .and_then(|segment| segment.get(13).copied())
        .unwrap_or(0)
}

/// Polls `future` once, so it runs up to its first wait.
fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
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
            peer.pump(1).await;
        }
    })
    .await
    .map_err(|_| "the future should resolve")?;
    Ok(output)
}

/// Establishes `client` -> `server` and returns the stack's handle and connection with
/// the client peer and its socket.
async fn establish(
    server: SocketAddrV4,
    client: SocketAddrV4,
) -> Result<(NetStackHandle, TcpConnection, RawPeer, SocketHandle), Box<dyn Error>> {
    let (handle, mut peer) = RawPeer::start(config(*server.ip()), *client.ip(), 0xab07);
    let mut incoming = handle.incoming_tcp();
    let socket = peer.connect(*server.ip(), server.port(), client.port())?;
    for _ in 0..40 {
        peer.pump(2).await;
        if let Some(conn) = try_next(&mut incoming) {
            return Ok((handle, conn, peer, socket));
        }
    }
    Err("TCP handshake should complete".into())
}

/// The stack's next RST, without anything entering the stack; earlier packets go to the
/// client.
async fn next_rst(peer: &mut RawPeer) -> Result<PacketBuf, Box<dyn Error>> {
    timeout(WAIT, async {
        loop {
            let packet = peer.source.rx.recv().await.ok_or("the stack stopped")?;
            if flags(&packet) & RST != 0 {
                return Ok(packet);
            }
            peer.device.inject(packet);
        }
    })
    .await
    .map_err(|_| "the stack should send an RST")?
}

#[tokio::test]
async fn abort_resets_the_peer_and_releases_at_once() -> TestResult {
    let server: SocketAddrV4 = "10.9.11.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.11.2:49200".parse()?;
    let (handle, conn, mut peer, socket) = establish(server, client).await?;
    // Unread bytes are discarded, not a reason to keep the socket.
    peer.socket(socket).send_slice(b"unread")?;
    peer.pump(4).await;
    assert_eq!(conn.buffered(), 6);
    let tuple = segment(client, server, ACK);
    assert_eq!(handle.owns(&tuple), Ownership::Flow);

    let mut terminal = conn.terminal();
    conn.abort();
    let rst = next_rst(&mut peer).await?;
    let rst_segment = tcp_segment(rst.as_packet()).ok_or("TCP")?;
    assert_eq!(rst_segment[2..4], client.port().to_be_bytes());
    // Released in the turn that sent the RST, before any answer of the peer.
    assert_eq!(handle.owns(&tuple), Ownership::None);
    timeout(WAIT, terminal.wait_for(|terminal| *terminal)).await??;

    peer.device.inject(rst);
    peer.pump_until(|peer| peer.state(socket) == tcp::State::Closed)
        .await?;
    Ok(())
}

#[tokio::test]
async fn abort_after_the_peer_reset_only_releases() -> TestResult {
    let server: SocketAddrV4 = "10.9.12.1:80".parse()?;
    let client: SocketAddrV4 = "10.9.12.2:49200".parse()?;
    let (handle, conn, mut peer, socket) = establish(server, client).await?;
    // The peer resets; unread bytes keep the closed socket with the stack.
    peer.socket(socket).send_slice(b"unread")?;
    peer.pump(4).await;
    peer.socket(socket).abort();
    peer.pump(4).await;
    let tuple = segment(client, server, ACK);
    assert_eq!(handle.owns(&tuple), Ownership::Flow);
    assert!(timeout(Duration::ZERO, conn.terminated()).await.is_err());

    let mut terminal = conn.terminal();
    conn.abort();
    timeout(WAIT, terminal.wait_for(|terminal| *terminal)).await??;
    assert_eq!(handle.owns(&tuple), Ownership::None);
    // Nothing answers the peer's reset.
    sleep(Duration::from_millis(50)).await;
    while let Ok(packet) = peer.source.rx.try_recv() {
        assert_eq!(flags(&packet) & RST, 0, "no RST to a reset tuple");
    }
    Ok(())
}

#[tokio::test]
async fn aborted_connect_from_frees_its_port_at_once() -> TestResult {
    let local_ip = Ipv4Addr::new(10, 9, 13, 1);
    let remote_ip = Ipv4Addr::new(10, 9, 13, 2);
    let remote = SocketAddr::new(remote_ip.into(), 443);
    let (handle, mut peer) = RawPeer::start(config(local_ip), remote_ip, 0xab08);
    let mut listeners = Vec::new();
    for _ in 0..2 {
        let rx_buf = client_tcp::SocketBuffer::new(vec![0u8; 4096]);
        let tx_buf = client_tcp::SocketBuffer::new(vec![0u8; 4096]);
        let mut socket = client_tcp::Socket::new(rx_buf, tx_buf);
        socket.listen(443)?;
        listeners.push(peer.sockets.add(socket));
    }

    let mut connect = Box::pin(handle.connect_tcp_from(40_000, remote));
    let first = pump_while(&mut peer, &mut connect).await??;
    assert_eq!(first.local_addr().port(), 40_000);

    // The second connect reaches the driver in the turn that observes the abort.
    first.abort();
    let mut connect = Box::pin(handle.connect_tcp_from(40_000, remote));
    assert!(poll_once(&mut connect).is_pending());
    let second = pump_while(&mut peer, &mut connect).await??;
    assert_eq!(second.local_addr().port(), 40_000);
    assert_eq!(peer.state(listeners[0]), tcp::State::Closed);
    let established = listeners[1];
    peer.pump_until(|peer| peer.state(established) == tcp::State::Established)
        .await?;
    Ok(())
}
