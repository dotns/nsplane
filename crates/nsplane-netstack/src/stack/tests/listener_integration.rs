use super::*;

/// NETSTACK-001. A browser opens 6-12 TCP connections to a page in parallel, so their
/// SYNs land in one ingress batch. The stack must accept every one of them: with a single
/// listener per port, the first SYN takes it into `SynReceived` and smoltcp answers the
/// rest with RST, which a gateway surfaces as `Connection refused`.
/// Returns `(accepted, connections that actually carried a byte)`.
async fn concurrent_syn_burst_establishes(n: usize) -> Result<(usize, usize), Box<dyn Error>> {
    let server_ip = Ipv4Addr::new(10, 9, 0, 1);
    let server_port: u16 = 8080;
    let (handle, mut peer) =
        RawPeer::start(config(server_ip), Ipv4Addr::new(10, 9, 0, 2), 0xbeef_face);
    let mut incoming = handle.incoming_tcp();

    // Connect every client socket BEFORE pumping, so all N SYNs are emitted into the
    // same batch, exactly what a browser's parallel fetch does.
    let mut client_handles = Vec::new();
    for i in 0..n {
        client_handles.push(peer.connect(server_ip, server_port, 49_152 + u16::try_from(i)?)?);
    }

    let mut accepted: Vec<TcpConnection> = Vec::new();
    for _ in 0..60 {
        peer.pump(1).await;
        while let Some(conn) = try_next(&mut incoming) {
            assert_eq!(conn.local_addr().port(), server_port);
            // Hold the connections: dropping them would close them.
            accepted.push(conn);
        }
        if accepted.len() == n {
            break;
        }
    }

    // Accepting is not enough. A server socket destroyed under a live peer still counts
    // as "established" on the client, which only finds out when it sends. So every
    // connection must carry a byte.
    for &handle in &client_handles {
        let _ = peer.socket(handle).send_slice(b"ping");
    }
    peer.pump(60).await;
    let delivered = accepted
        .iter_mut()
        .map(try_read)
        .filter(|data| data == b"ping")
        .count();
    Ok((accepted.len(), delivered))
}

/// The minimal reproduction: two simultaneous SYNs. Before the per-port backlog, the
/// second was answered with RST-ACK.
#[tokio::test]
async fn two_simultaneous_syns_both_establish() -> TestResult {
    assert_eq!(
        concurrent_syn_burst_establishes(2).await?,
        (2, 2),
        "both simultaneous SYNs must be accepted and stay usable; the second used to be RST"
    );
    Ok(())
}

/// A browser-sized burst (12 parallel connections) must not lose any, and every one must
/// still be alive afterwards. Promotion tops the listener pool back up, and a careless
/// top-up prunes the siblings accepted in the same poll but not yet promoted, closing
/// live connections under their peer.
#[tokio::test]
async fn browser_sized_syn_burst_all_establish() -> TestResult {
    assert_eq!(
        concurrent_syn_burst_establishes(12).await?,
        (12, 12),
        "a browser opens 6-12 parallel connections; none may be refused or torn down"
    );
    Ok(())
}

/// Clients that translate service connections to unique local destination ports. A
/// permanent spare listener on every promoted port used to consume the global pool after
/// 32 requests and refuse every later SYN.
#[tokio::test]
async fn sequential_unique_destination_ports_reuse_listener_capacity() -> TestResult {
    const CONNECTIONS: usize = 32 + 8;

    let server_ip = Ipv4Addr::new(10, 10, 0, 1);
    let (handle, mut peer) =
        RawPeer::start(config(server_ip), Ipv4Addr::new(10, 10, 0, 2), 0xeeee_0001);
    let mut incoming = handle.incoming_tcp();
    let mut first_connection = None;

    for i in 0..CONNECTIONS {
        let server_port = 20_000 + u16::try_from(i)?;
        let client = peer.connect(server_ip, server_port, 49_152 + u16::try_from(i)?)?;

        let mut accepted = None;
        for _ in 0..100 {
            peer.pump(1).await;
            if let Some(conn) = try_next(&mut incoming) {
                assert_eq!(conn.local_addr().port(), server_port);
                accepted = Some(conn);
                break;
            }
        }
        let mut conn = accepted.ok_or_else(|| {
            format!("connection {i} to unique destination port {server_port} was refused")
        })?;

        assert_eq!(peer.socket(client).send_slice(b"ping")?, 4);
        let mut delivered = false;
        for _ in 0..100 {
            peer.pump(1).await;
            if try_read(&mut conn) == b"ping" {
                delivered = true;
                break;
            }
        }
        assert!(
            delivered,
            "connection {i} to unique destination port {server_port} did not carry payload"
        );

        if i == 0 {
            first_connection = Some((client, conn));
        } else {
            peer.socket(client).abort();
            peer.pump(1).await;
            peer.sockets.remove(client);
            drop(conn);
        }
    }

    let (first_client, mut first_conn) = first_connection.ok_or("first connection retained")?;
    assert_eq!(peer.socket(first_client).send_slice(b"still-alive")?, 11);
    let mut delivered = false;
    for _ in 0..100 {
        peer.pump(1).await;
        if try_read(&mut first_conn) == b"still-alive" {
            delivered = true;
            break;
        }
    }
    assert!(
        delivered,
        "the first established connection must survive listener slot reuse"
    );
    Ok(())
}
