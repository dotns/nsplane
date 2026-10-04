//! The local-side `Redirect` with a small endpoint pool scanned through
//! `Redirect::endpoint_in_use`: the client (a netstack in the place of the operating system
//! behind a TUN device) sends UDP from one socket to several service addresses, and the
//! decision closure offers the first endpoint of a pool of three that no flow from the same
//! source uses. Every flow gets its own endpoint in one decision, a fourth flow is denied
//! while the pool is full, and an endpoint freed by `remove_flow` is found again.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use nsplane::{PacketBuf, PacketSink, PacketSource};
use nsplane_e2e::{QUIET, TestResult, WAIT, next_within};
use nsplane_nat::{Redirect, RedirectDecision, RedirectVerdict};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle, UdpFlow, UdpSocket};
use nsplane_packet::{FiveTuple, PeerId, protocol};
use tokio::time::timeout;

/// The client's address.
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// The address of the stack the flows are redirected to.
const STACK: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
/// The service port; the service addresses are `100.64.0.n`, owned by nobody.
const SERVICE_PORT: u16 = 53;
/// The endpoint pool: ports of the stack.
const POOL: [u16; 3] = [40_000, 40_001, 40_002];

/// The `n`th service address.
const fn service(n: u8) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, n), SERVICE_PORT)
}

/// The client, the service stack and the redirect between them.
struct Rig {
    client: NetStackHandle,
    stack: NetStackHandle,
    redirect: Arc<Redirect>,
    /// Calls of the decision closure.
    decisions: Arc<AtomicUsize>,
}

/// Starts both stacks and the redirect between them.
///
/// The decision closure redirects UDP to the service port to the first endpoint of
/// [`POOL`] not in use for the flow, denies the flow when every endpoint is, and passes
/// everything else.
fn rig() -> Rig {
    let decisions = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&decisions);
    // The closure reaches its own redirect through this slot to scan the pool.
    let slot: Arc<OnceLock<Weak<Redirect>>> = Arc::new(OnceLock::new());
    let inner = Arc::clone(&slot);
    let decide = move |tuple: &FiveTuple| {
        counter.fetch_add(1, Ordering::Relaxed);
        if tuple.protocol != protocol::UDP || tuple.dst_port != SERVICE_PORT {
            return RedirectDecision::Pass;
        }
        let Some(redirect) = inner.get().and_then(Weak::upgrade) else {
            return RedirectDecision::Drop;
        };
        POOL.iter()
            .map(|&port| SocketAddrV4::new(STACK, port))
            .find(|&endpoint| !redirect.endpoint_in_use(tuple, endpoint))
            .map_or(RedirectDecision::Drop, RedirectDecision::Redirect)
    };
    let redirect = Arc::new(Redirect::new(decide));
    slot.set(Arc::downgrade(&redirect))
        .unwrap_or_else(|_| unreachable!("the slot is set once"));

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

/// Sends `payload` from `socket` to `service`, accepts the flow the stack reports for it,
/// checks its payload and original destination, answers it and checks that the answer
/// comes from `service`.
async fn open_flow(
    rig: &Rig,
    socket: &mut UdpSocket,
    incoming: &mut (impl futures_core::Stream<Item = UdpFlow> + Unpin),
    service: SocketAddrV4,
) -> TestResult<UdpFlow> {
    socket.send_to(b"ping", SocketAddr::V4(service)).await?;
    let mut flow = next_within(incoming, WAIT).await?;
    let received = timeout(WAIT, flow.recv()).await?.ok_or("stack stopped")?;
    assert_eq!(&received[..], b"ping");
    let (endpoint, remote) = (v4(flow.local_addr())?, v4(flow.peer_addr())?);
    assert_eq!(*remote.ip(), CLIENT);
    assert_eq!(
        rig.redirect
            .original_destination(protocol::UDP, endpoint, remote),
        Some(service)
    );
    flow.send(b"pong").await?;
    let (datagram, from) = timeout(WAIT, socket.recv_from()).await??;
    assert_eq!(
        (&datagram[..], from),
        (&b"pong"[..], SocketAddr::V4(service))
    );
    Ok(flow)
}

#[tokio::test]
async fn a_small_pool_is_scanned_with_endpoint_in_use() -> TestResult {
    let rig = rig();
    let mut incoming = rig.stack.incoming_udp();
    let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let mut socket = rig.client.bind_udp(any).await?;

    // One socket (one source address and port) to three services: one endpoint each, in
    // pool order, one decision each.
    let mut flows = Vec::new();
    for (n, &port) in (1..).zip(&POOL) {
        let flow = open_flow(&rig, &mut socket, &mut incoming, service(n)).await?;
        assert_eq!(v4(flow.local_addr())?, SocketAddrV4::new(STACK, port));
        flows.push(flow);
    }
    assert_eq!(rig.decisions.load(Ordering::Relaxed), POOL.len());

    // The pool is full for this source: a fourth service is denied in one decision.
    socket.send_to(b"ping", SocketAddr::V4(service(4))).await?;
    assert!(
        next_within(&mut incoming, QUIET).await.is_err(),
        "a flow beyond the pool reached the stack"
    );
    let stats = rig.redirect.stats();
    assert_eq!(rig.decisions.load(Ordering::Relaxed), POOL.len() + 1);
    assert_eq!((stats.dropped, stats.conflicts), (1, 0));
    assert_eq!(stats.conntrack.entries, POOL.len());

    // Ending the middle flow in the redirect frees its endpoint for the fourth service; the
    // stack still has its flow for the endpoint and the client, which now carries the
    // fourth service's datagrams.
    let freed = v4(flows[1].local_addr())?;
    assert!(
        rig.redirect
            .remove_flow(protocol::UDP, freed, v4(flows[1].peer_addr())?)
    );
    socket.send_to(b"again", SocketAddr::V4(service(4))).await?;
    let received = timeout(WAIT, flows[1].recv())
        .await?
        .ok_or("stack stopped")?;
    assert_eq!(&received[..], b"again");
    assert_eq!(
        rig.redirect
            .original_destination(protocol::UDP, freed, v4(flows[1].peer_addr())?),
        Some(service(4))
    );
    flows[1].send(b"pong").await?;
    let (datagram, from) = timeout(WAIT, socket.recv_from()).await??;
    assert_eq!(
        (&datagram[..], from),
        (&b"pong"[..], SocketAddr::V4(service(4)))
    );
    assert_eq!(rig.decisions.load(Ordering::Relaxed), POOL.len() + 2);
    assert_eq!(rig.redirect.stats().conflicts, 0);
    Ok(())
}
