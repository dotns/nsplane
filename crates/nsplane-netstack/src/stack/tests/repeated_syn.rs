//! A bare SYN for a tuple the stack holds a socket for: a retransmission mid handshake opens
//! no second socket, and a client that reuses a port gets past a stale connection.

use tokio::io::AsyncReadExt;

use super::first_input::client_reset;
use super::labels::{
    CLIENT, KINDS, LOCAL, PORT, accept_all, connected, pump_labeled, send, stack_config,
    syn_and_ack, until_stats,
};
use super::*;

/// How long a stale connection may hold up a client that reuses its port.
const RECOVERY: Duration = Duration::from_secs(10);
const SEQ: usize = 24;
const ACK_NUMBER: usize = 28;
const FLAGS: usize = 33;
const CHECKSUM: usize = 36;
const ACK: u8 = 0x10;

/// A reset first handshake leaves a free slot below the socket of the second, which is where
/// a free listener for the retransmission lands.
#[tokio::test]
async fn a_retransmitted_syn_stays_with_its_socket() -> TestResult {
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 71);
        accept_all(&handle);
        let mut incoming = handle.incoming_tcp();
        let (reset, _) = syn_and_ack(&mut peer, 40_100, None).await?;
        let (syn, ack) = syn_and_ack(&mut peer, 40_101, None).await?;
        peer.sink
            .send(client_reset(&reset)?, PeerId::new(0))
            .await?;
        until_stats(&handle, |stats| stats.handshake_failed == 1).await?;

        send(&peer.sink, &syn, None).await?;
        sleep(Duration::from_millis(50)).await;
        assert!(
            peer.source.try_admit().is_none(),
            "{kind:?}: the retransmission got an answer from a second socket"
        );

        send(&peer.sink, &ack, None).await?;
        let conn = timeout(WAIT, next(&mut incoming))
            .await?
            .ok_or("no connection")?;
        assert_eq!(conn.peer_addr().port(), 40_101, "{kind:?}");
        assert_eq!(handle.stats().handshake_failed, 1, "{kind:?}");
    }
    Ok(())
}

/// A client restarted on the port of `socket`, which forgets it without a RST: its SYN meets
/// the stack's established connection `stale`, which must end for the new connection.
async fn reuse_port(
    peer: &mut RawPeer,
    incoming: &mut (impl Stream<Item = TcpConnection> + Unpin),
    server: IpAddr,
    socket: SocketHandle,
    mut stale: TcpConnection,
) -> TestResult {
    let port = peer
        .sockets
        .get::<client_tcp::Socket<'_>>(socket)
        .local_endpoint()
        .ok_or("the client should be connected")?
        .port;
    peer.sockets.remove(socket);
    let socket = peer.connect(server, stale.local_addr().port(), port)?;
    let conn = timeout(RECOVERY, async {
        loop {
            pump_labeled(peer, None).await;
            if let Some(conn) = try_next(incoming) {
                return conn;
            }
        }
    })
    .await
    .map_err(|_| "the client should get past the stale connection")?;
    assert_eq!(conn.peer_addr().port(), port);
    peer.pump_until(|peer| peer.state(socket) == tcp::State::Established)
        .await?;
    let mut byte = [0];
    timeout(WAIT, stale.read(&mut byte))
        .await
        .map_err(|_| "the stale connection should end")?
        .map_or(Ok(()), |read| {
            (read == 0).then_some(()).ok_or("the stale connection read")
        })?;
    Ok(())
}

/// Sequence numbers are random, so that the seeds cover where the SYN's numbers fall against
/// the connection's.
#[tokio::test(start_paused = true)]
async fn a_client_reusing_a_port_gets_past_a_stale_connection() -> TestResult {
    for kind in KINDS {
        for seed in 80..96 {
            let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, seed);
            accept_all(&handle);
            let mut incoming = handle.incoming_tcp();
            let (socket, stale) = connected(&mut peer, &mut incoming, 40_200, None).await?;
            reuse_port(&mut peer, &mut incoming, LOCAL.into(), socket, stale).await?;
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_client_reusing_a_port_gets_past_a_stale_connection_over_ipv6() -> TestResult {
    let server = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let client = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let config = NetStackConfig::new(vec![(server.into(), 128)], 1360);
    let (handle, mut peer) = RawPeer::start_at(config, client.into(), 97);
    let mut incoming = handle.incoming_tcp();
    let socket = peer.connect(server, PORT, 40_210)?;
    let stale = timeout(WAIT, async {
        loop {
            pump_labeled(&mut peer, None).await;
            if let Some(conn) = try_next(&mut incoming) {
                return conn;
            }
        }
    })
    .await?;
    reuse_port(&mut peer, &mut incoming, server.into(), socket, stale).await
}

/// RFC 5961: a SYN inside the receive window is challenged as well, and leaves the
/// connection alone.
#[tokio::test]
async fn a_syn_inside_the_window_is_challenged() -> TestResult {
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 72);
        accept_all(&handle);
        let mut incoming = handle.incoming_tcp();
        let (mut syn, ack) = syn_and_ack(&mut peer, 40_300, None).await?;
        send(&peer.sink, &ack, None).await?;
        let mut conn = timeout(WAIT, next(&mut incoming))
            .await?
            .ok_or("no connection")?;

        let expected = u32::from_be_bytes(ack[SEQ..SEQ + 4].try_into()?);
        syn[SEQ..SEQ + 4].copy_from_slice(&expected.wrapping_add(16).to_be_bytes());
        syn[CHECKSUM..CHECKSUM + 2].fill(0);
        let (src, dst) = tcp_tuple(&syn).ok_or("not TCP")?;
        let sum =
            crate::pending::pseudo_header_checksum(src.ip(), dst.ip(), protocol::TCP, &syn[20..]);
        syn[CHECKSUM..CHECKSUM + 2].copy_from_slice(&sum.to_be_bytes());
        send(&peer.sink, &syn, None).await?;

        let reply = timeout(WAIT, async {
            loop {
                match peer.source.try_admit() {
                    Some(reply) => return reply,
                    None => sleep(Duration::from_millis(5)).await,
                }
            }
        })
        .await?;
        let reply = reply.as_packet();
        assert_eq!(reply[FLAGS], ACK, "{kind:?}");
        assert_eq!(
            &reply[ACK_NUMBER..ACK_NUMBER + 4],
            &ack[SEQ..SEQ + 4],
            "{kind:?}"
        );
        let mut byte = [0];
        let idle = timeout(Duration::from_millis(100), conn.read(&mut byte)).await;
        assert!(idle.is_err(), "{kind:?}: the connection ended");
    }
    Ok(())
}
