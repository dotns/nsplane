//! Two engines over an in-memory channel transport whose local sides are netstacks: TCP and
//! UDP echo in both directions over IPv4 and IPv6, the MSS rule for tunnel MTUs below 1500
//! and TCP half close.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nsplane::{PacketBuf, PacketSource};
use nsplane_e2e::{
    Family, QUIET, StackNode, TRANSFER, TestResult, WAIT, next_within, serve_tcp_echo,
    serve_udp_echo, stack_pair, stack_pair_with,
};
use nsplane_netstack::{DEFAULT_MTU, NetStackHandle, NetStackSource};
use nsplane_packet::protocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

/// Bytes echoed per TCP round trip.
const BULK: usize = 1 << 20;
/// TCP port of the echo servers.
const TCP_PORT: u16 = 7;
/// UDP port of the echo servers.
const UDP_PORT: u16 = 5353;
/// Datagrams exchanged per UDP flow.
const DATAGRAMS: usize = 8;

/// `len` bytes whose pattern (period 251) does not line up with any segment size, so
/// reordered or duplicated segments change the data.
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
}

/// Connects from `client` to `target`, sends `len` bytes, half-closes and checks that the
/// same bytes come back, followed by EOF.
async fn tcp_round_trip(client: &NetStackHandle, target: SocketAddr, len: usize) -> TestResult {
    let conn = timeout(TRANSFER, client.connect_tcp(target)).await??;
    assert_eq!(conn.peer_addr(), target);
    assert_eq!(conn.local_addr().is_ipv4(), target.is_ipv4());

    let sent = data(len);
    let (mut reader, mut writer) = tokio::io::split(conn);
    let write = async {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    };
    let read = async {
        let mut echoed = Vec::with_capacity(len);
        reader.read_to_end(&mut echoed).await?;
        Ok::<_, io::Error>(echoed)
    };
    let ((), echoed) = timeout(TRANSFER, async { tokio::try_join!(write, read) }).await??;
    if echoed.len() != len {
        return Err(format!("{} of {len} bytes echoed from {target}", echoed.len()).into());
    }
    if echoed != sent {
        return Err(format!("echo from {target} changed the data").into());
    }
    Ok(())
}

/// The unspecified address of `family` with port 0.
const fn any(family: Family) -> SocketAddr {
    match family {
        Family::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Family::V6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// Binds a UDP socket on `client`, exchanges [`DATAGRAMS`] datagrams with the echo server
/// on `server` and checks that they all went through one flow.
async fn udp_round_trips(
    client: &StackNode,
    server: &StackNode,
    flows: &mut mpsc::UnboundedReceiver<(SocketAddr, SocketAddr)>,
    family: Family,
) -> TestResult {
    let target = server.socket_addr(family, UDP_PORT);
    let mut socket = timeout(WAIT, client.stack.bind_udp(any(family))).await??;
    for i in 0..DATAGRAMS {
        let datagram = format!("datagram {i} over {family:?}").repeat(i + 1);
        socket.send_to(datagram.as_bytes(), target).await?;
        let (echo, from) = timeout(WAIT, socket.recv_from()).await??;
        assert_eq!(from, target);
        assert_eq!(&echo[..], datagram.as_bytes());
    }

    let flow = timeout(WAIT, flows.recv())
        .await?
        .ok_or("echo server stopped")?;
    let remote = client.socket_addr(family, socket.local_addr().port());
    assert_eq!(flow, (remote, target));
    assert!(flows.try_recv().is_err(), "every datagram uses one flow");
    Ok(())
}

/// Scenario 1: B connects to A's stack, 1 MiB echoed over IPv4.
#[tokio::test]
async fn tcp_echo_ipv4() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    serve_tcp_echo(&a.stack);
    tcp_round_trip(&b.stack, a.socket_addr(Family::V4, TCP_PORT), BULK).await
}

/// Scenario 1: B connects to A's stack, 1 MiB echoed over IPv6.
#[tokio::test]
async fn tcp_echo_ipv6() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    serve_tcp_echo(&a.stack);
    tcp_round_trip(&b.stack, a.socket_addr(Family::V6, TCP_PORT), BULK).await
}

/// Scenario 2: B's bound socket exchanges datagrams with A's flow echo, over IPv4 and IPv6.
#[tokio::test]
async fn udp_echo() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    let mut flows = serve_udp_echo(&a.stack);
    for family in [Family::V4, Family::V6] {
        udp_round_trips(&b, &a, &mut flows, family).await?;
    }
    Ok(())
}

/// Scenario 3: the reverse direction, A's stack connects to and binds towards B's.
#[tokio::test]
async fn tcp_echo_reverse_direction() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    serve_tcp_echo(&b.stack);
    for family in [Family::V4, Family::V6] {
        tcp_round_trip(&a.stack, b.socket_addr(family, TCP_PORT), BULK).await?;
    }
    Ok(())
}

/// Scenario 3: the reverse direction for UDP.
#[tokio::test]
async fn udp_echo_reverse_direction() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    let mut flows = serve_udp_echo(&b.stack);
    for family in [Family::V4, Family::V6] {
        udp_round_trips(&a, &b, &mut flows, family).await?;
    }
    Ok(())
}

/// A TCP segment with SYN set, as a stack emitted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Syn {
    family: Family,
    /// ACK is set too: the SYN-ACK of the passive side.
    ack: bool,
    /// The MSS option, if present.
    mss: Option<u16>,
}

/// The SYN in `packet`, if it is a TCP segment with SYN set (no IPv6 extension headers).
fn syn_of(packet: &[u8]) -> Option<Syn> {
    let (family, next, offset) = match packet.first()? >> 4 {
        4 => (
            Family::V4,
            *packet.get(9)?,
            usize::from(packet.first()? & 0x0f) * 4,
        ),
        6 => (Family::V6, *packet.get(6)?, 40),
        _ => return None,
    };
    let tcp = packet.get(offset..)?;
    let flags = *tcp.get(13)?;
    if next != protocol::TCP || flags & 0x02 == 0 {
        return None;
    }
    let mut options = tcp.get(20..usize::from(tcp.get(12)? >> 4) * 4)?;
    let mut mss = None;
    loop {
        match options {
            [] | [0, ..] => break,
            [1, rest @ ..] => options = rest,
            [_, len, ..] => {
                let len = usize::from(*len).max(2);
                if let [2, 4, hi, lo] = options.get(..len)? {
                    mss = Some(u16::from_be_bytes([*hi, *lo]));
                }
                options = options.get(len..)?;
            }
            [_] => return None,
        }
    }
    Some(Syn {
        family,
        ack: flags & 0x10 != 0,
        mss,
    })
}

/// A stack's egress as the engine reads it, recording the largest packet and every SYN.
#[derive(Debug)]
struct Tap {
    inner: NetStackSource,
    largest: Arc<AtomicUsize>,
    syns: mpsc::UnboundedSender<Syn>,
}

impl PacketSource for Tap {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        let packet = self.inner.recv().await?;
        self.largest.fetch_max(packet.len(), Ordering::Relaxed);
        if let Some(syn) = syn_of(packet.as_packet()) {
            // The test may have finished reading; nothing depends on later SYNs.
            let _ = self.syns.send(syn);
        }
        Ok(packet)
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.inner.mtu()
    }
}

/// Scenario 4: with an engine MTU of `mtu`, bulk echo works over IPv4 and IPv6, no packet a
/// stack hands to its engine exceeds `mtu`, and both handshake ends advertise `mtu - 40`
/// (IPv4) or `mtu - 60` (IPv6) as MSS.
async fn mss_fits_the_tunnel_mtu(mtu: u16) -> TestResult {
    let largest = Arc::new(AtomicUsize::new(0));
    let (syn_tx, mut syns) = mpsc::unbounded_channel();
    let (a, b) = stack_pair_with(mtu, |inner| Tap {
        inner,
        largest: Arc::clone(&largest),
        syns: syn_tx.clone(),
    })
    .await?;
    assert_eq!(a.handle.mtu().await?, mtu);
    serve_tcp_echo(&a.stack);

    for (family, overhead) in [(Family::V4, 40), (Family::V6, 60)] {
        tcp_round_trip(&b.stack, a.socket_addr(family, TCP_PORT), BULK / 2).await?;
        let mut seen = Vec::new();
        while let Ok(syn) = syns.try_recv() {
            seen.push(syn);
        }
        assert!(seen.iter().any(|syn| !syn.ack), "no SYN seen: {seen:?}");
        assert!(seen.iter().any(|syn| syn.ack), "no SYN-ACK seen: {seen:?}");
        for syn in seen {
            assert_eq!(syn.family, family);
            assert_eq!(syn.mss, Some(mtu - overhead), "{syn:?}");
        }
    }
    let largest = largest.load(Ordering::Relaxed);
    assert!(
        largest <= usize::from(mtu),
        "a stack emitted {largest} bytes over an MTU of {mtu}"
    );
    Ok(())
}

#[tokio::test]
async fn mss_fits_a_1280_tunnel_mtu() -> TestResult {
    mss_fits_the_tunnel_mtu(1280).await
}

#[tokio::test]
async fn mss_fits_a_1420_tunnel_mtu() -> TestResult {
    mss_fits_the_tunnel_mtu(1420).await
}

/// Scenario 5: the client shuts its write half down, the server reads EOF and still sends
/// its reply, the client reads the whole reply and then EOF.
#[tokio::test]
async fn half_close() -> TestResult {
    let (a, b) = stack_pair(DEFAULT_MTU).await?;
    let mut incoming = a.stack.incoming_tcp();
    for family in [Family::V4, Family::V6] {
        let target = a.socket_addr(family, TCP_PORT);
        let mut client = timeout(TRANSFER, b.stack.connect_tcp(target)).await??;
        let mut server = next_within(&mut incoming, WAIT).await?;
        assert_eq!(server.local_addr(), target);
        assert_eq!(server.peer_addr(), client.local_addr());

        let request = data(4096);
        client.write_all(&request).await?;
        client.shutdown().await?;
        let mut received = Vec::new();
        timeout(TRANSFER, server.read_to_end(&mut received)).await??;
        assert!(received == request, "request changed in transit");

        // The client's read half stays open: nothing arrives before the server writes.
        let mut byte = [0; 1];
        assert!(
            timeout(QUIET, client.read(&mut byte)).await.is_err(),
            "the client read something before the reply"
        );

        let reply = data(256 << 10);
        let write = async {
            server.write_all(&reply).await?;
            server.shutdown().await
        };
        let read = async {
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let ((), response) = timeout(TRANSFER, async { tokio::try_join!(write, read) }).await??;
        assert_eq!(response.len(), reply.len());
        assert!(response == reply, "reply changed in transit");

        timeout(WAIT, client.terminated()).await?;
        timeout(WAIT, server.terminated()).await?;
    }
    Ok(())
}
