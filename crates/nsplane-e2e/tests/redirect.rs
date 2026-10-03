//! The local-side `Redirect` between a client and a netstack: the client (a netstack in the
//! place of the operating system behind a TUN device) talks TCP and UDP to a service
//! address, `forward` sends each flow into a second netstack on an endpoint the decision
//! closure picks, and `reverse` makes the stack's replies come from the service address.
//! Covers the original destination of accepted flows, `remove_flow` and idle expiry (after
//! which replies pass unchanged and the next client packet is decided again).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;

use nsplane::{PacketBuf, PacketSink, PacketSource};
use nsplane_e2e::{QUIET, TRANSFER, TestResult, WAIT, next_within};
use nsplane_nat::{Conntrack, ConntrackConfig, Redirect, RedirectDecision, RedirectVerdict};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, UdpFlow, UdpSocket};
use nsplane_packet::{FiveTuple, PeerId, protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

/// The client's address.
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// The address of the stack the flows are redirected to.
const STACK: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
/// The service addresses the client talks to; nothing owns them.
const SERVICE_TCP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 10), 80);
const SERVICE_UDP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 10), 53);
/// The first endpoint port the decision closure hands out.
const FIRST_PORT: u16 = 40_000;
/// UDP idle timeout of the expiry test.
const SHORT_TIMEOUT: Duration = Duration::from_millis(200);

/// The client, the service stack and the redirect between them.
struct Rig {
    client: NetStackHandle,
    stack: NetStackHandle,
    redirect: Arc<Redirect>,
    /// Calls of the decision closure.
    decisions: Arc<AtomicUsize>,
}

/// Starts both stacks and the redirect between them, with flows in a table of `config`.
///
/// The decision closure redirects the two service addresses to a new endpoint of the
/// stack per flow and passes everything else.
fn rig(config: ConntrackConfig) -> Rig {
    let decisions = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&decisions);
    let next_port = AtomicU16::new(FIRST_PORT);
    let decide = move |tuple: &FiveTuple| {
        counter.fetch_add(1, Ordering::Relaxed);
        let service = match (tuple.dst, tuple.protocol) {
            (IpAddr::V4(dst), protocol::TCP) => {
                SocketAddrV4::new(dst, tuple.dst_port) == SERVICE_TCP
            }
            (IpAddr::V4(dst), protocol::UDP) => {
                SocketAddrV4::new(dst, tuple.dst_port) == SERVICE_UDP
            }
            _ => false,
        };
        if !service {
            return RedirectDecision::Pass;
        }
        let port = next_port.fetch_add(1, Ordering::Relaxed);
        RedirectDecision::Redirect(SocketAddrV4::new(STACK, port))
    };
    let redirect = Arc::new(Redirect::with_conntrack(Conntrack::new(config), decide));

    let (client_stack, client) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(CLIENT), 32)],
        DEFAULT_MTU,
    ));
    let (stack_stack, stack) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(STACK), 32)],
        DEFAULT_MTU,
    ));
    let (client_out, client_in) = client_stack.split();
    let (stack_out, stack_in) = stack_stack.split();
    pump(
        client_out,
        stack_in,
        Arc::clone(&redirect),
        Redirect::forward,
    );
    pump(
        stack_out,
        client_in,
        Arc::clone(&redirect),
        Redirect::reverse,
    );
    Rig {
        client,
        stack,
        redirect,
        decisions,
    }
}

/// Moves packets from `from` to `to` through `step` until either side stops, as the local
/// path would: rewritten and passed packets go on, dropped ones do not.
fn pump<S, K>(
    mut from: S,
    to: K,
    redirect: Arc<Redirect>,
    step: fn(&Redirect, &mut PacketBuf) -> RedirectVerdict,
) where
    S: PacketSource + Send + 'static,
    K: PacketSink + Send + Sync + 'static,
{
    tokio::spawn(async move {
        while let Ok(mut packet) = from.recv().await {
            if matches!(step(&redirect, &mut packet), RedirectVerdict::Drop(_)) {
                continue;
            }
            if to.send(packet, PeerId::new(0)).await.is_err() {
                break;
            }
        }
    });
}

fn v4(addr: SocketAddr) -> TestResult<SocketAddrV4> {
    match addr {
        SocketAddr::V4(addr) => Ok(addr),
        SocketAddr::V6(addr) => Err(format!("IPv6 address {addr}").into()),
    }
}

/// The next datagram of `socket` within [`WAIT`], with its source.
async fn recv(socket: &mut UdpSocket) -> TestResult<(Vec<u8>, SocketAddr)> {
    let (datagram, from) = timeout(WAIT, socket.recv_from()).await??;
    Ok((datagram.to_vec(), from))
}

/// Sends `payload` from `socket` to the UDP service, accepts the flow the stack reports for
/// it and checks that it carries the payload and that the redirect knows the service as
/// its original destination.
async fn open_udp_flow(
    rig: &Rig,
    socket: &UdpSocket,
    incoming: &mut (impl futures_core::Stream<Item = UdpFlow> + Unpin),
    payload: &[u8],
) -> TestResult<UdpFlow> {
    socket.send_to(payload, SocketAddr::V4(SERVICE_UDP)).await?;
    let mut flow = next_within(incoming, WAIT).await?;
    let received = timeout(WAIT, flow.recv()).await?.ok_or("stack stopped")?;
    assert_eq!(&received[..], payload);
    let (endpoint, remote) = (v4(flow.local_addr())?, v4(flow.peer_addr())?);
    assert_eq!(*endpoint.ip(), STACK);
    assert_eq!(*remote.ip(), CLIENT);
    assert_eq!(
        rig.redirect
            .original_destination(protocol::UDP, endpoint, remote),
        Some(SERVICE_UDP)
    );
    Ok(flow)
}

/// How a test ends a redirected flow.
#[derive(Debug, Clone, Copy)]
enum End {
    /// [`Redirect::remove_flow`], as a stack reports a closed flow.
    Remove,
    /// Waiting out the idle timeout.
    Idle,
}

/// Exchanges a datagram each way on a new UDP flow, ends the flow, then checks that the
/// stack's next reply reaches the client unchanged (from the endpoint, not the service)
/// and that the client's next datagram is decided again and opens a new flow.
async fn udp_flow_ends(rig: &Rig, end: End) -> TestResult {
    let mut incoming = rig.stack.incoming_udp();
    let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let mut socket = rig.client.bind_udp(any).await?;

    let flow = open_udp_flow(rig, &socket, &mut incoming, b"ping").await?;
    flow.send(b"pong").await?;
    assert_eq!(
        recv(&mut socket).await?,
        (b"pong".to_vec(), SocketAddr::V4(SERVICE_UDP))
    );
    assert_eq!(rig.decisions.load(Ordering::Relaxed), 1);

    match end {
        End::Remove => {
            let (endpoint, remote) = (v4(flow.local_addr())?, v4(flow.peer_addr())?);
            assert!(rig.redirect.remove_flow(protocol::UDP, endpoint, remote));
        }
        End::Idle => sleep(SHORT_TIMEOUT + QUIET).await,
    }
    let passed = rig.redirect.stats().passed;
    flow.send(b"stale").await?;
    assert_eq!(
        recv(&mut socket).await?,
        (b"stale".to_vec(), flow.local_addr())
    );
    assert_eq!(rig.redirect.stats().passed, passed + 1);

    let again = open_udp_flow(rig, &socket, &mut incoming, b"again").await?;
    assert_eq!(rig.decisions.load(Ordering::Relaxed), 2);
    assert_ne!(again.local_addr(), flow.local_addr());
    again.send(b"pong").await?;
    assert_eq!(
        recv(&mut socket).await?,
        (b"pong".to_vec(), SocketAddr::V4(SERVICE_UDP))
    );
    Ok(())
}

#[tokio::test]
async fn tcp_flow_is_redirected_into_the_stack() -> TestResult {
    let rig = rig(ConntrackConfig::default());
    let mut incoming = rig.stack.incoming_tcp();
    let (conn, accepted) = tokio::join!(
        timeout(
            TRANSFER,
            rig.client.connect_tcp(SocketAddr::V4(SERVICE_TCP))
        ),
        next_within(&mut incoming, TRANSFER),
    );
    let (conn, accepted) = (conn??, accepted?);
    assert_eq!(conn.peer_addr(), SocketAddr::V4(SERVICE_TCP));
    let (endpoint, remote) = (v4(accepted.local_addr())?, v4(accepted.peer_addr())?);
    assert_eq!(endpoint, SocketAddrV4::new(STACK, FIRST_PORT));
    assert_eq!(remote, v4(conn.local_addr())?);
    assert_eq!(
        rig.redirect
            .original_destination(protocol::TCP, endpoint, remote),
        Some(SERVICE_TCP)
    );

    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(accepted);
        tokio::io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await
    });
    let sent = b"redirected through the service address".repeat(64);
    let (mut reader, mut writer) = tokio::io::split(conn);
    let write = async {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    };
    let read = async {
        let mut echoed = Vec::new();
        reader.read_to_end(&mut echoed).await?;
        Ok::<_, io::Error>(echoed)
    };
    let ((), echoed) = timeout(TRANSFER, async { tokio::try_join!(write, read) }).await??;
    assert_eq!(echoed, sent);

    assert_eq!(rig.decisions.load(Ordering::Relaxed), 1);
    let stats = rig.redirect.stats();
    assert!(stats.redirected > 0 && stats.reversed > 0);
    assert_eq!((stats.dropped, stats.conflicts), (0, 0));
    assert_eq!(stats.conntrack.inserted, 1);
    Ok(())
}

#[tokio::test]
async fn udp_flow_is_redirected_until_removed() -> TestResult {
    let rig = rig(ConntrackConfig::default());
    udp_flow_ends(&rig, End::Remove).await?;
    assert_eq!(rig.redirect.stats().conntrack.removed, 1);
    Ok(())
}

#[tokio::test]
async fn udp_flow_is_redirected_until_idle() -> TestResult {
    let config = ConntrackConfig {
        udp_timeout: SHORT_TIMEOUT,
        ..ConntrackConfig::default()
    };
    let rig = rig(config);
    udp_flow_ends(&rig, End::Idle).await?;
    assert_eq!(rig.redirect.stats().conntrack.expired, 1);
    Ok(())
}
