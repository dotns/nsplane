//! Connected netstack UDP sockets between engines over an in-memory channel transport: a
//! socket from `NetStackHandle::connect_udp` exchanges datagrams with an echo server on the
//! other stack over IPv4 and IPv6, a datagram from a third party to its local port reaches
//! `incoming_udp` instead of the socket, and `owns` answers `Flow` only for the connected
//! remote until the socket is dropped.

use nsplane_e2e::{
    Family, QUIET, StackNode, TestResult, WAIT, next_within, serve_udp_echo, stack_pair, udp,
};
use nsplane_netstack::{DEFAULT_MTU, Ownership};
use tokio::time::timeout;

/// UDP port of the echo server.
const ECHO_PORT: u16 = 5353;
/// UDP port of the third party's bound socket.
const THIRD_PARTY_PORT: u16 = 6000;
/// Datagrams echoed per family.
const DATAGRAMS: usize = 8;

/// Connects a socket on `client` to the echo server on `server` and round-trips
/// [`DATAGRAMS`] datagrams; a third party on `server` then sends to the socket's local port.
async fn connected_round_trip(
    client: &StackNode,
    server: &StackNode,
    family: Family,
) -> TestResult {
    let target = server.socket_addr(family, ECHO_PORT);
    let mut socket = timeout(WAIT, client.stack.connect_udp(target)).await??;
    let local = socket.local_addr();
    assert_eq!(local, client.socket_addr(family, local.port()));
    assert_eq!(socket.peer_addr(), Some(target));

    for i in 0..DATAGRAMS {
        let datagram = format!("connected datagram {i} over {family:?}").repeat(i + 1);
        socket.send(datagram.as_bytes()).await?;
        let (echo, from) = timeout(WAIT, socket.recv_from()).await??;
        assert_eq!(from, target);
        assert_eq!(&echo[..], datagram.as_bytes());
    }

    let third_party = server
        .stack
        .bind_udp(server.socket_addr(family, THIRD_PARTY_PORT))
        .await?;
    let stray_from = third_party.local_addr();
    let owned = udp(target, local, b"x");
    let stray = udp(stray_from, local, b"x");
    assert_eq!(client.stack.owns(&owned), Ownership::Flow);
    assert_eq!(client.stack.owns(&stray), Ownership::Listener);

    let mut incoming = client.stack.incoming_udp();
    third_party.send_to(b"stray", local).await?;
    let mut flow = next_within(&mut incoming, WAIT).await?;
    assert_eq!((flow.peer_addr(), flow.local_addr()), (stray_from, local));
    let payload = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
    assert_eq!(&payload[..], b"stray");
    assert!(
        timeout(QUIET, socket.recv_from()).await.is_err(),
        "the third party's datagram must not reach the connected socket"
    );
    assert_eq!(
        client.stack.owns(&stray),
        Ownership::Flow,
        "held by its flow"
    );

    drop(socket);
    assert_eq!(client.stack.owns(&owned), Ownership::Listener);
    Ok(())
}

/// A connected socket on B round-trips with A's echo over IPv4.
#[tokio::test]
async fn connected_udp_ipv4() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    let _flows = serve_udp_echo(&a.stack);
    connected_round_trip(&b, &a, Family::V4).await
}

/// A connected socket on B round-trips with A's echo over IPv6.
#[tokio::test]
async fn connected_udp_ipv6() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    let _flows = serve_udp_echo(&a.stack);
    connected_round_trip(&b, &a, Family::V6).await
}
