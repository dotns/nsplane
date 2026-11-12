//! A driver turn bridges only the connections the application or smoltcp signalled. These
//! tests switch the periodic pass over every connection off, so each step has to be moved
//! by its own signal; a lost one leaves the step waiting until the test times out. Every
//! test of the crate also runs `Driver::assert_bridged` after each bridge pass.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::abort::pump_while;
use super::connections::FULL_PASS;
use super::*;

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 30, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 9, 30, 2);

/// A stack with `config` whose driver never passes over every connection, an established
/// connection from a client peer, and `idle` more that stay untouched.
async fn establish(
    config: NetStackConfig,
    idle: u16,
) -> Result<(TcpConnection, RawPeer, SocketHandle, Vec<TcpConnection>), Box<dyn Error>> {
    // The driver of this test's stack runs on this thread.
    FULL_PASS.set(Some(Duration::MAX));
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 0x51_6e);
    let mut incoming = handle.incoming_tcp();
    let mut accepted = Vec::new();
    let mut client = None;
    for port in 0..=idle {
        client = Some(peer.connect(SERVER, 80, 49_152 + port)?);
        let conn = pump_while(&mut peer, &mut Box::pin(next(&mut incoming))).await?;
        accepted.push(conn.ok_or("the stack stopped")?);
    }
    let conn = accepted.pop().ok_or("no connection")?;
    let client = client.ok_or("no client socket")?;
    // Long enough for a periodic pass, were one left.
    peer.pump(20).await;
    Ok((conn, peer, client, accepted))
}

fn client_socket(peer: &RawPeer, handle: SocketHandle) -> &client_tcp::Socket<'static> {
    peer.sockets.get::<client_tcp::Socket<'static>>(handle)
}

#[tokio::test]
async fn an_application_write_on_an_idle_connection_reaches_the_peer() -> TestResult {
    let (mut conn, mut peer, client, _idle) = establish(config(SERVER), 3).await?;
    conn.write_all(b"written").await?;
    peer.pump_until(|peer| client_socket(peer, client).recv_queue() == 7)
        .await?;
    let mut bytes = [0; 7];
    peer.socket(client).recv_slice(&mut bytes)?;
    assert_eq!(&bytes, b"written");
    Ok(())
}

#[tokio::test]
async fn peer_data_on_an_idle_connection_reaches_the_application() -> TestResult {
    let (mut conn, mut peer, client, _idle) = establish(config(SERVER), 3).await?;
    peer.socket(client).send_slice(b"received")?;
    let mut bytes = [0; 8];
    pump_while(&mut peer, &mut Box::pin(conn.read_exact(&mut bytes))).await??;
    assert_eq!(&bytes, b"received");
    Ok(())
}

#[tokio::test]
async fn an_application_close_and_the_peers_answer_release_the_connection() -> TestResult {
    let (mut conn, mut peer, client, _idle) = establish(config(SERVER), 3).await?;
    // The application's FIN.
    pump_while(&mut peer, &mut Box::pin(conn.shutdown())).await??;
    peer.pump_until(|peer| peer.state(client) == tcp::State::CloseWait)
        .await?;
    // The peer's last bytes and its FIN: read, then the end of the stream.
    let socket = peer.socket(client);
    socket.send_slice(b"last")?;
    socket.close();
    let mut bytes = Vec::new();
    pump_while(&mut peer, &mut Box::pin(conn.read_to_end(&mut bytes))).await??;
    assert_eq!(bytes, b"last");
    // Closed and read to the end: the socket is released.
    pump_while(&mut peer, &mut Box::pin(conn.terminated())).await?;
    Ok(())
}

#[tokio::test]
async fn a_peer_close_and_the_applications_drop_release_the_connection() -> TestResult {
    let (mut conn, mut peer, client, _idle) = establish(config(SERVER), 3).await?;
    peer.socket(client).close();
    let mut bytes = Vec::new();
    pump_while(&mut peer, &mut Box::pin(conn.read_to_end(&mut bytes))).await??;
    assert_eq!(bytes, b"");
    // The response of a half-closed connection still leaves.
    conn.write_all(b"answer").await?;
    peer.pump_until(|peer| client_socket(peer, client).recv_queue() == 6)
        .await?;
    let mut terminal = conn.terminal();
    drop(conn);
    peer.pump_until(|peer| peer.state(client) == tcp::State::TimeWait)
        .await?;
    pump_while(
        &mut peer,
        &mut Box::pin(terminal.wait_for(|terminal| *terminal)),
    )
    .await??;
    Ok(())
}

#[tokio::test]
async fn an_application_abort_resets_the_peer_and_releases() -> TestResult {
    let (conn, mut peer, client, _idle) = establish(config(SERVER), 3).await?;
    let mut terminal = conn.terminal();
    conn.abort();
    peer.pump_until(|peer| peer.state(client) == tcp::State::Closed)
        .await?;
    pump_while(
        &mut peer,
        &mut Box::pin(terminal.wait_for(|terminal| *terminal)),
    )
    .await??;
    Ok(())
}

#[tokio::test]
async fn a_peer_reset_ends_the_stream_and_releases() -> TestResult {
    let (mut conn, mut peer, client, _idle) = establish(config(SERVER), 3).await?;
    peer.socket(client).send_slice(b"before")?;
    peer.pump_until(|peer| client_socket(peer, client).send_queue() == 0)
        .await?;
    peer.socket(client).abort();
    let mut bytes = Vec::new();
    pump_while(&mut peer, &mut Box::pin(conn.read_to_end(&mut bytes))).await??;
    assert_eq!(bytes, b"before");
    pump_while(&mut peer, &mut Box::pin(conn.terminated())).await?;
    Ok(())
}

#[tokio::test]
async fn a_read_reopens_the_stacks_closed_window() -> TestResult {
    // One segment of window and one of application buffer: both fill at once.
    let config = NetStackConfig {
        tcp_rx_buffer: Some(1320),
        stream_buffer: 1320,
        ..config(SERVER)
    };
    let (mut conn, mut peer, client, _idle) = establish(config, 3).await?;
    let sent: Vec<u8> = (0..16_000u32).map(|i| (i % 251) as u8).collect();
    let mut offset = 0;
    let mut received = Vec::new();
    let mut stalled = false;
    let transfer = async {
        let (mut last_queue, mut steady) = (0, 0);
        while received.len() < sent.len() {
            if offset < sent.len() {
                offset += peer.socket(client).send_slice(&sent[offset..])?;
            }
            peer.pump(1).await;
            let queue = client_socket(&peer, client).send_queue();
            if offset == sent.len() && queue == 0 {
                received.extend(try_read(&mut conn));
            } else if queue > 0 && queue == last_queue {
                steady += 1;
            } else {
                steady = 0;
            }
            // The application reads only once the peer made no progress for a while:
            // the window is closed, and only the read can reopen it.
            if steady == 4 {
                assert_eq!(conn.buffered(), 1320);
                stalled = true;
                steady = 0;
                received.extend(try_read(&mut conn));
            }
            last_queue = queue;
        }
        Ok::<_, Box<dyn Error>>(())
    };
    timeout(Duration::from_secs(20), transfer)
        .await
        .map_err(|_| "the transfer stalled behind the closed window")??;
    assert!(stalled, "the window never closed");
    assert_eq!(received, sent);
    Ok(())
}

#[tokio::test]
async fn acknowledgements_refill_a_full_send_buffer() -> TestResult {
    // The application's bytes wait behind one segment of send buffer and a peer that
    // reads slowly: each acknowledgement has to bring the next bytes into the socket.
    let config = NetStackConfig {
        tcp_tx_buffer: Some(1320),
        stream_buffer: 1320,
        ..config(SERVER)
    };
    let (mut conn, mut peer, client, _idle) = establish(config, 3).await?;
    let sent: Vec<u8> = (0..40_000u32).map(|i| (i % 241) as u8).collect();
    let expected = sent.clone();
    let writer = tokio::spawn(async move {
        conn.write_all(&sent).await?;
        conn.shutdown().await?;
        Ok::<_, io::Error>(conn)
    });
    let mut received = Vec::new();
    let transfer = async {
        // The peer's 4096-byte window closes first.
        peer.pump(20).await;
        while peer.state(client) != tcp::State::CloseWait
            || client_socket(&peer, client).recv_queue() > 0
        {
            let mut chunk = [0; 700];
            let read = peer.socket(client).recv_slice(&mut chunk)?;
            received.extend_from_slice(&chunk[..read]);
            peer.pump(1).await;
        }
        Ok::<_, Box<dyn Error>>(())
    };
    timeout(Duration::from_secs(30), transfer)
        .await
        .map_err(|_| "the transfer stalled behind the full send buffer")??;
    assert_eq!(received, expected);
    drop(writer.await??);
    Ok(())
}

#[tokio::test]
async fn the_periodic_pass_bridges_a_connection_nothing_signalled() -> TestResult {
    let (conn, mut peer, _client, _idle) = establish(config(SERVER), 0).await?;
    // The idle timeout has no signal of its own; with the periodic pass back, it fires.
    let mut terminal = conn.terminal();
    IDLE_TIMEOUT.set(Some(SmolDuration::from_millis(100)));
    peer.pump(40).await;
    assert!(!*terminal.borrow(), "nothing should have bridged it");
    FULL_PASS.set(None);
    pump_while(
        &mut peer,
        &mut Box::pin(terminal.wait_for(|terminal| *terminal)),
    )
    .await??;
    Ok(())
}
