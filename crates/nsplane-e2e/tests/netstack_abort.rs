//! `TcpConnection::abort` between two engines over an in-memory channel transport whose
//! local sides are netstacks: an abort on either side resets the other (its connection is
//! released, reads end and writes fail without a close handshake), the aborting stack
//! stops owning the tuple at once and its local port can be connected from again, while
//! dropping a connection still closes it with a FIN.

use std::io;
use std::net::SocketAddr;

use futures_core::Stream;
use nsplane_e2e::{Family, QUIET, StackNode, TestResult, WAIT, next_within, stack_pair, tcp};
use nsplane_netstack::{DEFAULT_MTU, Ownership, TcpConnection};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// TCP port of the server on node B.
const SERVER_PORT: u16 = 80;
/// Explicit local port of the client on node A.
const CLIENT_PORT: u16 = 40_000;
/// TCP ACK flag.
const ACK: u8 = 0x10;

/// Connects A's stack from [`CLIENT_PORT`] to B's server and returns both ends after one
/// byte went through, so both are established.
async fn connect(
    a: &StackNode,
    incoming: &mut (impl Stream<Item = TcpConnection> + Unpin),
    target: SocketAddr,
) -> TestResult<(TcpConnection, TcpConnection)> {
    let mut client = timeout(WAIT, a.stack.connect_tcp_from(CLIENT_PORT, target)).await??;
    assert_eq!(client.local_addr().port(), CLIENT_PORT);
    let mut server = next_within(incoming, WAIT).await?;
    client.write_all(b"x").await?;
    let mut byte = [0; 1];
    timeout(WAIT, server.read_exact(&mut byte)).await??;
    Ok((client, server))
}

/// Checks that `conn`'s peer reset it: the stack released it, reads end and writes fail.
async fn expect_reset(mut conn: TcpConnection) -> TestResult {
    timeout(WAIT, conn.terminated())
        .await
        .map_err(|_| "the reset should release the connection")?;
    let mut buf = [0; 16];
    assert_eq!(timeout(WAIT, conn.read(&mut buf)).await??, 0);
    let error = conn
        .write_all(b"late")
        .await
        .err()
        .ok_or("writes must fail after a reset")?;
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    Ok(())
}

#[tokio::test]
async fn client_abort_resets_the_server_and_frees_the_port() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    let mut incoming = b.stack.incoming_tcp();
    let target = b.socket_addr(Family::V4, SERVER_PORT);
    let local = a.socket_addr(Family::V4, CLIENT_PORT);
    let (client, server) = connect(&a, &mut incoming, target).await?;
    let segment = tcp(target, local, ACK, (1, 1), &[]);
    assert_eq!(a.stack.owns(&segment), Ownership::Flow);

    client.abort();
    expect_reset(server).await?;
    // Released in the turn that sent the RST, so before the server saw it.
    assert_eq!(a.stack.owns(&segment), Ownership::None);

    // The same port to the same server, right away.
    let (mut client, mut server) = connect(&a, &mut incoming, target).await?;
    client.write_all(b"again").await?;
    let mut buf = [0; 5];
    timeout(WAIT, server.read_exact(&mut buf)).await??;
    assert_eq!(&buf, b"again");
    Ok(())
}

#[tokio::test]
async fn server_abort_resets_the_client() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    let mut incoming = b.stack.incoming_tcp();
    let target = b.socket_addr(Family::V6, SERVER_PORT);
    let local = a.socket_addr(Family::V6, CLIENT_PORT);
    let (client, server) = connect(&a, &mut incoming, target).await?;
    let segment = tcp(local, target, ACK, (1, 1), &[]);
    assert_eq!(b.stack.owns(&segment), Ownership::Flow);

    server.abort();
    expect_reset(client).await?;
    assert_eq!(b.stack.owns(&segment), Ownership::None);
    Ok(())
}

#[tokio::test]
async fn dropping_still_closes_with_fin() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    let mut incoming = b.stack.incoming_tcp();
    let target = b.socket_addr(Family::V4, SERVER_PORT);
    let (mut client, mut server) = connect(&a, &mut incoming, target).await?;
    client.write_all(b"last").await?;
    drop(client);

    let mut received = Vec::new();
    timeout(WAIT, server.read_to_end(&mut received)).await??;
    assert_eq!(received, b"last");
    // A FIN half-closes: the server can still answer and is not released.
    server.write_all(b"reply").await?;
    assert!(timeout(QUIET, server.terminated()).await.is_err());
    Ok(())
}
