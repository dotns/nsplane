use tokio::io::AsyncWriteExt;

use super::*;

/// Bytes the client has received and not read yet, discarded.
fn drain(peer: &mut RawPeer, client: SocketHandle) -> usize {
    let socket = peer.socket(client);
    let mut total = 0;
    while let Ok(n) = socket.recv(|data| (data.len(), data.len())) {
        if n == 0 {
            break;
        }
        total += n;
    }
    total
}

#[tokio::test]
async fn unacked_and_last_ack_follow_the_peer_window() -> TestResult {
    let server_ip = Ipv4Addr::new(10, 9, 1, 1);
    let (handle, mut peer) = RawPeer::start(config(server_ip), Ipv4Addr::new(10, 9, 1, 2), 7);
    let mut incoming = handle.incoming_tcp();
    let client = peer.connect(server_ip, 80, 49_200)?;
    let mut conn = None;
    for _ in 0..40 {
        peer.pump(2).await;
        conn = try_next(&mut incoming);
        if conn.is_some() {
            break;
        }
    }
    let mut conn = conn.ok_or("TCP handshake should complete")?;
    assert_eq!(conn.unacked(), 0);
    assert_eq!(conn.last_ack(), None, "no data acknowledged yet");

    // The client's 4 KiB receive buffer fills and it stops reading: the rest of the
    // 32 KiB stays unacknowledged.
    conn.write_all(&[7; 32 * 1024]).await?;
    peer.pump(40).await;
    let stalled_at = conn.last_ack().ok_or("the first window was acknowledged")?;
    assert!(conn.unacked() > 0);
    peer.pump(40).await;
    assert_eq!(
        conn.last_ack(),
        Some(stalled_at),
        "no progress while stalled"
    );
    assert!(conn.unacked() > 0);

    // The client reads again: everything is acknowledged.
    let mut received = 0;
    timeout(Duration::from_secs(5), async {
        while received < 32 * 1024 || conn.unacked() > 0 {
            received += drain(&mut peer, client);
            peer.pump(1).await;
        }
    })
    .await
    .map_err(|_| "the stack should see every byte acknowledged")?;
    assert_eq!(received, 32 * 1024);
    let resumed_at = conn.last_ack().ok_or("acknowledged")?;
    assert!(resumed_at > stalled_at);

    // The values stay readable once the connection is gone.
    peer.socket(client).abort();
    peer.pump(4).await;
    timeout(Duration::from_secs(5), conn.terminated()).await?;
    assert_eq!(conn.unacked(), 0);
    assert_eq!(conn.last_ack(), Some(resumed_at));
    Ok(())
}
