use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

// ── Half-close (FIN) propagation ──────────────────────────────────────

/// Establishes one client -> server TCP connection and hands back the server's
/// connection plus the client peer and its socket for further driving.
async fn connect_half_close(
    stream_buffer: Option<usize>,
) -> Result<(TcpConnection, RawPeer, SocketHandle), Box<dyn Error>> {
    let server_ip = Ipv4Addr::new(10, 9, 0, 1);
    let mut config = config(server_ip);
    if let Some(stream_buffer) = stream_buffer {
        config.stream_buffer = stream_buffer;
    }
    let (handle, mut peer) = RawPeer::start(config, Ipv4Addr::new(10, 9, 0, 2), 0x9a9a_9a9a);
    let mut incoming = handle.incoming_tcp();
    let client = peer.connect(server_ip, 80, 49_152)?;

    for _ in 0..40 {
        peer.pump(2).await;
        if let Some(conn) = try_next(&mut incoming) {
            assert_eq!(conn.local_addr().port(), 80);
            return Ok((conn, peer, client));
        }
    }
    Err("TCP handshake should complete".into())
}

#[tokio::test]
async fn terminal_receive_survives_close_timer_with_a_full_application_buffer() -> TestResult {
    let (mut conn, mut peer, client) = connect_half_close(Some(1024)).await?;
    // The application shuts its write half down and stops reading.
    conn.shutdown().await?;
    peer.pump_until(|peer| peer.state(client) == tcp::State::CloseWait)
        .await?;
    for value in [1, 2] {
        peer.socket(client).send_slice(&[value; 1024])?;
        peer.pump_until(|peer| {
            peer.sockets
                .get::<client_tcp::Socket<'_>>(client)
                .send_queue()
                == 0
        })
        .await?;
        assert_eq!(
            conn.buffered(),
            1024,
            "the 1024-byte application buffer stays full"
        );
    }
    let socket = peer.socket(client);
    socket.send_slice(&[3; 1024])?;
    socket.close();
    peer.pump_until(|peer| peer.state(client) == tcp::State::Closed)
        .await?;
    // Past smoltcp's 10 s TIME-WAIT timer: the unread bytes must survive it.
    sleep(Duration::from_secs(11)).await;
    assert!(
        timeout(Duration::ZERO, conn.terminated()).await.is_err(),
        "the socket is not released while received bytes are unread"
    );
    let mut received = Vec::new();
    timeout(Duration::from_secs(5), conn.read_to_end(&mut received)).await??;
    let expected = [vec![1; 1024], vec![2; 1024], vec![3; 1024]].concat();
    assert_eq!(received.len(), expected.len());
    assert_eq!(received, expected);
    timeout(Duration::from_secs(5), conn.terminated()).await?;

    drop(peer.sink);
    let error = timeout(WAIT, async {
        loop {
            if let Err(error) = peer.source.recv().await {
                return error;
            }
        }
    })
    .await?;
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    Ok(())
}

// Forward half close: when the application shuts its write half down (e.g. a
// connection-close-delimited HTTP/1.0 upstream finished), the stack must emit a FIN so
// the peer (curl) observes end-of-stream instead of hanging.
#[tokio::test]
async fn forward_half_close_emits_fin_when_relay_write_half_drops() -> TestResult {
    let (mut conn, mut peer, client) = connect_half_close(None).await?;
    conn.shutdown().await?; // Upstream EOF; the read half stays open.

    peer.pump(30).await;

    assert!(
        !peer.socket(client).may_recv(),
        "client must observe the server's FIN (receive half closed)"
    );
    Ok(())
}

// Reverse half close: when the peer closes its send half, the application's reader must
// observe EOF rather than block forever (which would leak the upstream connection).
#[tokio::test]
async fn reverse_half_close_signals_eof_when_peer_sends_fin() -> TestResult {
    let (mut conn, mut peer, client) = connect_half_close(None).await?;

    peer.socket(client).close(); // The client sends FIN.
    peer.pump(30).await;

    let mut buf = [0u8; 16];
    let n = timeout(WAIT, conn.read(&mut buf))
        .await
        .map_err(|_| "read must resolve (EOF), not hang")??;
    assert_eq!(
        n, 0,
        "the application must observe EOF after the peer's FIN"
    );
    Ok(())
}

#[tokio::test]
async fn terminal_barrier_resolves_only_after_socket_is_reaped() -> TestResult {
    let (conn, mut peer, client) = connect_half_close(None).await?;

    assert!(timeout(Duration::ZERO, conn.terminated()).await.is_err());
    peer.socket(client).abort();
    peer.pump(30).await;

    timeout(WAIT, conn.terminated())
        .await
        .map_err(|_| "terminal barrier should resolve after the socket is reaped")?;
    Ok(())
}

#[tokio::test]
async fn request_then_half_close_still_delivers_the_response() -> TestResult {
    let (mut conn, mut peer, client) = connect_half_close(None).await?;
    let request = b"request-before-fin";
    {
        let socket = peer.socket(client);
        socket.send_slice(request)?;
        socket.close();
    }
    peer.pump(30).await;

    let mut received = Vec::new();
    timeout(WAIT, conn.read_to_end(&mut received)).await??;
    assert_eq!(received, request);

    conn.write_all(b"response-after-fin").await?;
    conn.shutdown().await?;
    peer.pump(30).await;

    let socket = peer.socket(client);
    let response = socket
        .recv(|bytes| (bytes.len(), bytes.to_vec()))
        .map_err(|_| "response must remain readable after the request half-close")?;
    assert_eq!(response, b"response-after-fin");
    assert!(!socket.may_recv(), "response FIN must reach the client");
    Ok(())
}

#[tokio::test]
async fn dropping_the_connection_closes_it_gracefully() -> TestResult {
    let (mut conn, mut peer, client) = connect_half_close(None).await?;
    conn.write_all(b"last words").await?;
    drop(conn);
    peer.pump(30).await;

    let socket = peer.socket(client);
    let data = socket
        .recv(|bytes| (bytes.len(), bytes.to_vec()))
        .map_err(|_| "buffered bytes must be delivered before the FIN")?;
    assert_eq!(data, b"last words");
    assert!(!socket.may_recv(), "the FIN must follow");
    Ok(())
}
