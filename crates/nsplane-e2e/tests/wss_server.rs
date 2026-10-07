//! Engines on `WssDialer`s served by one engine on a `WssServerTransport`, behind a plain
//! WebSocket listener on the loopback interface: several nodes on one transport, each on a
//! session address of its own; a session closed by the server, the node redialing and its
//! endpoint moving to the new session; the transport next to a `UdpTransport` in one engine;
//! sessions that cannot take over another node's endpoint; and a session that stops reading
//! without holding up the others.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::SinkExt as _;
use nsplane::{
    AllowedIp, DROP_TRANSPORT_SEND_ERROR, DynTransport, Ecn, LinkConfig, Path, Peer, TransportId,
    UdpTransport,
};
use nsplane_e2e::{Family, Node, Options, TestResult, WAIT, exchange, payload, transfer};
use nsplane_wss::{
    WssAcceptor, WssConfig, WssDialer, WssServerConfig, WssServerTransport,
    WssServerTransportStats, WssSession, WssSessionStats, WssStats, WssTls,
};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;

/// Nodes on different transports share one `Node` type.
type Any = Box<dyn DynTransport>;

/// The id of the hub's WSS server transport and of every node's WSS link transport.
const WSS: TransportId = TransportId::new(1);
/// The id of every UDP transport.
const UDP: TransportId = TransportId::new(2);
/// The key seed of the hub.
const HUB: u8 = 1;

/// The address a node's link transport gives the hub.
fn hub_link() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, HUB], 443))
}

/// The own address of the node with key seed `seed` (the hub does not reach it there).
fn addr(seed: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, seed], 1000 + u16::from(seed)))
}

const fn at(transport: TransportId, addr: SocketAddr) -> Path {
    Path {
        transport,
        addr,
        ecn: Ecn::NotEct,
    }
}

/// Locks `mutex`; a test that panicked holding it fails on its own.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Waits until `condition` holds, within [`WAIT`].
async fn until(what: &str, mut condition: impl FnMut() -> bool) -> TestResult {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        if Instant::now() > deadline {
            return Err(format!("{what} not within {WAIT:?}").into());
        }
        sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

/// A plain WebSocket listener handing every upgraded connection to a
/// [`WssServerTransport`], keeping the sessions in the order they were accepted. Its
/// connections have a small send buffer, so a session that is not read stops writing soon.
struct Server {
    addr: SocketAddr,
    sessions: Arc<Mutex<Vec<WssSession>>>,
    stats: Arc<WssServerTransportStats>,
}

impl Server {
    /// The listener and the transport it feeds.
    async fn start(config: WssServerConfig) -> TestResult<(Self, WssServerTransport)> {
        let socket = TcpSocket::new_v4()?;
        socket.set_send_buffer_size(4096)?;
        socket.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let listener = socket.listen(64)?;
        let (transport, acceptor) = WssServerTransport::new(WSS, config);
        let server = Self {
            addr: listener.local_addr()?,
            sessions: Arc::default(),
            stats: transport.stats(),
        };
        let sessions = Arc::clone(&server.sessions);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, sessions) = (acceptor.clone(), Arc::clone(&sessions));
                tokio::spawn(async move {
                    let config = Some(WssAcceptor::ws_config());
                    let Ok(ws) = tokio_tungstenite::accept_async_with_config(tcp, config).await
                    else {
                        return;
                    };
                    if let Ok(session) = acceptor.accept(ws) {
                        lock(&sessions).push(session);
                    }
                });
            }
        });
        Ok((server, transport))
    }

    /// The addresses of the sessions accepted so far, in order.
    fn addrs(&self) -> Vec<SocketAddr> {
        lock(&self.sessions).iter().map(WssSession::addr).collect()
    }

    /// The counters of the session at `addr`.
    fn session_stats(&self, addr: SocketAddr) -> TestResult<Arc<WssSessionStats>> {
        let sessions = lock(&self.sessions);
        let session = sessions
            .iter()
            .find(|s| s.addr() == addr)
            .ok_or_else(|| format!("no session at {addr}"))?;
        Ok(session.stats())
    }

    /// Closes the session at `addr`.
    fn close(&self, addr: SocketAddr) -> TestResult {
        let sessions = lock(&self.sessions);
        let session = sessions
            .iter()
            .find(|s| s.addr() == addr)
            .ok_or_else(|| format!("no session at {addr}"))?;
        session.close();
        Ok(())
    }
}

/// The hub (seed [`HUB`]) on `wss`, and on `udp` if given.
fn hub(wss: WssServerTransport, udp: Option<UdpTransport>) -> TestResult<Node<Any>> {
    Node::<Any>::with_builder(HUB, WSS, hub_link(), Options::default(), |b| {
        let b = b.transport(wss);
        match udp {
            Some(udp) => b.transport(udp),
            None => b,
        }
    })
}

/// A node with key seed `seed` dialing `ws://{target}` (the server, or a proxy to it), and
/// its dialer's counters. It redials 20 ms after a lost link.
fn wss_node(seed: u8, target: SocketAddr) -> TestResult<(Node<Any>, Arc<WssStats>)> {
    let config = WssConfig::new(
        format!("ws://{target}/wss"),
        WssTls::Roots(RootCertStore::empty()),
    )
    .allow_plaintext(true)
    .connect_timeout(Duration::from_secs(1))
    .backoff(Duration::from_millis(20), Duration::from_millis(200))
    .reconnect_delay(Duration::from_millis(20));
    let dialer = WssDialer::new(config)?;
    let stats = dialer.stats();
    let transport = dialer.into_transport(WSS, hub_link(), LinkConfig::default());
    let node = Node::<Any>::new(
        seed,
        WSS,
        addr(seed),
        Box::new(transport),
        Options::default(),
    );
    Ok((node, stats))
}

/// A node with key seed `seed` on a UDP transport on the loopback interface.
fn udp_node(seed: u8) -> TestResult<Node<Any>> {
    let udp = UdpTransport::bind(UDP, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = udp.local_addr();
    Ok(Node::<Any>::new(
        seed,
        UDP,
        addr,
        Box::new(udp),
        Options::default(),
    ))
}

/// Makes `node` a peer of the hub and the hub a peer of `node`, reached on `hub_path`. The
/// hub reaches `node` on `node_path`; `None` (a WSS node) until `node` authenticates. The
/// node routes all tunnel addresses to the hub, so nodes reach each other through it.
async fn join(
    hub: &Node<Any>,
    node: &Node<Any>,
    node_path: Option<Path>,
    hub_path: Path,
) -> TestResult {
    hub.handle
        .add_or_update_peer(Peer {
            path: node_path,
            ..node.as_peer(node.path.transport)
        })
        .await?;
    node.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![
                AllowedIp {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    cidr: 24,
                },
                AllowedIp {
                    addr: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)),
                    cidr: 64,
                },
            ],
            path: Some(hub_path),
            ..Peer::new(hub.public())
        })
        .await?;
    Ok(())
}

/// The hub's current path to `node`.
async fn path_of(hub: &Node<Any>, node: &Node<Any>) -> TestResult<Path> {
    let peer = hub.peer_of(node).await?;
    let stats = hub.handle.peer_stats(peer).await?.ok_or("unknown peer")?;
    stats.path.ok_or_else(|| "no path".into())
}

/// The hub's path to `node` is a session of the server: `[100::n]:0`.
async fn session_of(hub: &Node<Any>, node: &Node<Any>, server: &Server) -> TestResult<SocketAddr> {
    let path = path_of(hub, node).await?;
    assert_eq!(path.transport, WSS);
    let SocketAddr::V6(addr) = path.addr else {
        return Err(format!("endpoint {} is not a session address", path.addr).into());
    };
    assert_eq!(addr.ip().segments()[..4], [0x100, 0, 0, 0]);
    assert_eq!(addr.port(), 0);
    assert!(server.addrs().contains(&path.addr));
    Ok(path.addr)
}

/// Sends a `family` packet from `from` to `to` through the hub, which hands what it
/// delivers back to its engine, and checks that it arrives intact on both legs.
async fn via_hub(
    from: &Node<Any>,
    hub: &mut Node<Any>,
    to: &mut Node<Any>,
    family: Family,
) -> TestResult {
    let packet = from.packet_to(to, family, &payload(200));
    from.send(&packet).await?;
    let (peer, at_hub) = hub.expect_delivery().await?;
    assert_eq!(peer, hub.peer_of(from).await?);
    assert_eq!(at_hub, packet);
    hub.send(&at_hub).await?;
    let (peer, delivered) = to.expect_delivery().await?;
    assert_eq!(peer, to.peer_of(hub).await?);
    assert_eq!(delivered, packet);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_server_transport_serves_several_nodes() -> TestResult {
    let (server, wss) = Server::start(WssServerConfig::new()).await?;
    let mut hub = hub(wss, None)?;
    let mut nodes = Vec::new();
    for seed in 2..=4 {
        let (node, _) = wss_node(seed, server.addr)?;
        join(&hub, &node, None, at(WSS, hub_link())).await?;
        nodes.push(node);
    }
    // The nodes speak first: the hub learns their sessions from their handshakes.
    for node in &mut nodes {
        exchange(node, &mut hub).await?;
    }

    let mut endpoints = Vec::new();
    for node in &nodes {
        endpoints.push(session_of(&hub, node, &server).await?);
    }
    endpoints.sort_unstable();
    endpoints.dedup();
    assert_eq!(endpoints.len(), nodes.len(), "endpoints {endpoints:?}");
    assert_eq!(server.stats.active(), 3);

    // Each node reaches the next one through the hub.
    let [a, b, c] = &mut nodes[..] else {
        return Err("three nodes".into());
    };
    via_hub(a, &mut hub, b, Family::V4).await?;
    via_hub(b, &mut hub, c, Family::V6).await?;
    via_hub(c, &mut hub, a, Family::V4).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_session_redials_and_the_endpoint_moves() -> TestResult {
    let (server, wss) = Server::start(WssServerConfig::new()).await?;
    let mut hub = hub(wss, None)?;
    let (mut x, x_stats) = wss_node(2, server.addr)?;
    let (mut y, _) = wss_node(3, server.addr)?;
    for node in [&x, &y] {
        join(&hub, node, None, at(WSS, hub_link())).await?;
    }
    exchange(&mut x, &mut hub).await?;
    exchange(&mut y, &mut hub).await?;
    let old = session_of(&hub, &x, &server).await?;

    server.close(old)?;
    until("session close", || server.stats.closed_local() == 1).await?;
    // Sent before `x` is back: lost, a send error.
    hub.send(&hub.packet_to(&x, Family::V4, &payload(64)))
        .await?;

    until("redial", || x_stats.connects() == 2).await?;
    transfer(&x, &mut hub, Family::V4, 64).await?;
    let new = session_of(&hub, &x, &server).await?;
    assert_ne!(new, old);
    assert_eq!(server.addrs().last(), Some(&new));
    transfer(&hub, &mut x, Family::V6, 1300).await?;
    exchange(&mut x, &mut hub).await?;
    exchange(&mut y, &mut hub).await?;

    // Every datagram the hub sent to the closed session failed and was counted.
    assert_eq!(
        server.stats.sent_to_closed(),
        hub.drops(DROP_TRANSPORT_SEND_ERROR).await?
    );
    assert_eq!(server.stats.active(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wss_and_udp_nodes_on_one_engine() -> TestResult {
    let (server, wss) = Server::start(WssServerConfig::new()).await?;
    let udp = UdpTransport::bind(UDP, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let hub_udp = at(UDP, udp.local_addr());
    let mut hub = hub(wss, Some(udp))?;
    let (mut w, _) = wss_node(2, server.addr)?;
    let mut u = udp_node(3)?;
    join(&hub, &w, None, at(WSS, hub_link())).await?;
    join(&hub, &u, Some(u.path), hub_udp).await?;

    // Interleaved: both nodes' sessions are up at once.
    for family in [Family::V4, Family::V6] {
        transfer(&w, &mut hub, family, 64).await?;
        transfer(&u, &mut hub, family, 64).await?;
        transfer(&hub, &mut w, family, 1300).await?;
        transfer(&hub, &mut u, family, 1300).await?;
    }
    via_hub(&w, &mut hub, &mut u, Family::V4).await?;
    via_hub(&u, &mut hub, &mut w, Family::V6).await?;

    session_of(&hub, &w, &server).await?;
    assert_eq!(path_of(&hub, &u).await?, u.path);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_sessions_do_not_take_over_an_endpoint() -> TestResult {
    let (server, wss) = Server::start(WssServerConfig::new()).await?;
    let mut hub = hub(wss, None)?;
    let (mut x, x_stats) = wss_node(2, server.addr)?;
    join(&hub, &x, None, at(WSS, hub_link())).await?;
    exchange(&mut x, &mut hub).await?;
    let a = session_of(&hub, &x, &server).await?;

    // (a) Garbage on a new session: shaped as each message type, but not WireGuard.
    let rx = server.stats.rx();
    let tcp = TcpStream::connect(server.addr).await?;
    let (mut raw, _) =
        tokio_tungstenite::client_async(format!("ws://{}/wss", server.addr), tcp).await?;
    let garbage: [&[u8]; 5] = [&[1; 148], &[2; 92], &[3; 64], &[4; 32], b"garbage"];
    for datagram in garbage {
        raw.send(Message::binary(datagram.to_vec())).await?;
    }
    until("garbage received", || server.stats.rx() >= rx + 5).await?;
    // Received after the garbage, so the hub has handled the garbage by then.
    transfer(&x, &mut hub, Family::V4, 64).await?;
    assert_eq!(path_of(&hub, &x).await?.addr, a);

    // (b) A valid handshake on a new session, from a key the hub does not know.
    let (y, _) = wss_node(9, server.addr)?;
    y.handle
        .add_or_update_peer(Peer {
            path: Some(at(WSS, hub_link())),
            ..hub.as_peer(WSS)
        })
        .await?;
    let rx = server.stats.rx();
    y.send(&y.packet_to(&hub, Family::V4, &payload(64))).await?;
    until("handshake received", || server.stats.rx() > rx).await?;
    transfer(&x, &mut hub, Family::V4, 64).await?;
    assert_eq!(path_of(&hub, &x).await?.addr, a);
    assert_eq!(hub.handle.peer_id(y.public()).await?, None);
    transfer(&hub, &mut x, Family::V4, 64).await?;
    assert_eq!(server.stats.active(), 3);

    // (c) `x`'s own traffic on a new session moves it there.
    server.close(a)?;
    until("redial", || x_stats.connects() == 2).await?;
    transfer(&x, &mut hub, Family::V6, 64).await?;
    let c = session_of(&hub, &x, &server).await?;
    assert_ne!(c, a);
    assert_eq!(server.addrs().last(), Some(&c));
    transfer(&hub, &mut x, Family::V6, 1300).await?;
    Ok(())
}

/// A TCP proxy to `upstream` whose connections stop reading from `upstream` while stalled.
struct Proxy {
    addr: SocketAddr,
    stall: watch::Sender<bool>,
}

impl Proxy {
    async fn start(upstream: SocketAddr) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy = Self {
            addr: listener.local_addr()?,
            stall: watch::Sender::new(false),
        };
        let stall = proxy.stall.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(pipe(client, upstream, stall.subscribe()));
            }
        });
        Ok(proxy)
    }
}

/// Copies between `client` and a new connection to `upstream`; reads nothing from
/// `upstream` while `stall` is set. The upstream connection has a small receive buffer, so
/// the sender's buffers fill soon.
async fn pipe(
    client: TcpStream,
    upstream: SocketAddr,
    mut stall: watch::Receiver<bool>,
) -> io::Result<()> {
    let socket = TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(4096)?;
    let up = socket.connect(upstream).await?;
    let (mut client_rx, mut client_tx) = client.into_split();
    let (mut up_rx, mut up_tx) = up.into_split();
    let forward = tokio::io::copy(&mut client_rx, &mut up_tx);
    let backward = async {
        let mut buf = vec![0; 16 * 1024];
        loop {
            if stall.wait_for(|stalled| !*stalled).await.is_err() {
                return Ok(());
            }
            let n = up_rx.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            client_tx.write_all(&buf[..n]).await?;
        }
    };
    tokio::select! {
        result = forward => result.map(drop),
        result = backward => result,
    }
}

/// The session queue of the stalled-session test.
const STALL_QUEUE: usize = 8;
/// Packets each healthy node receives while one session is stalled.
const ROUNDS: usize = 200;
/// Packets the hub sends to the stalled node per round.
const TO_STALLED: usize = 4;

/// One node's session stops reading while the hub keeps sending to it; the other sessions of
/// the same transport keep flowing.
///
/// The criterion is a bounded, lossless stream rather than a throughput ratio: in each of
/// [`ROUNDS`] rounds the hub sends one packet to each healthy node and [`TO_STALLED`] to the
/// stalled one, then waits for the healthy nodes to receive theirs. With one packet in
/// flight per healthy session their queues never fill, so every packet must arrive, and all
/// rounds must end within [`WAIT`]. A send that waited on the stalled session would hold up
/// the hub's engine and miss that bound; the stalled session's overflow shows as
/// `dropped_queue_full` and as the engine's send errors instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_session_does_not_block_the_others() -> TestResult {
    let (server, wss) = Server::start(WssServerConfig::new().queue(STALL_QUEUE)).await?;
    let mut hub = hub(wss, None)?;
    let proxy = Proxy::start(server.addr).await?;
    let mut healthy = Vec::new();
    for seed in 2..=4 {
        let (node, _) = wss_node(seed, server.addr)?;
        join(&hub, &node, None, at(WSS, hub_link())).await?;
        healthy.push(node);
    }
    let (mut stalled, _) = wss_node(5, proxy.addr)?;
    join(&hub, &stalled, None, at(WSS, hub_link())).await?;
    for node in healthy.iter_mut().chain([&mut stalled]) {
        exchange(node, &mut hub).await?;
    }
    assert_eq!(server.stats.active(), 4);

    // Stall the session, and send to it until its writer is stuck: its queue overflows and
    // nothing more is written for 20 bursts in a row.
    let session = server.session_stats(session_of(&hub, &stalled, &server).await?)?;
    proxy.stall.send_replace(true);
    let to_stalled = hub.packet_to(&stalled, Family::V4, &payload(1300));
    let deadline = Instant::now() + WAIT;
    let (mut written, mut still) = (session.tx(), 0);
    while session.dropped_queue_full() == 0 || still < 20 {
        if Instant::now() > deadline {
            return Err(format!("session writer not stuck within {WAIT:?}: {session:?}").into());
        }
        for _ in 0..16 {
            hub.send(&to_stalled).await?;
        }
        sleep(Duration::from_millis(2)).await;
        still = if session.tx() == written {
            still + 1
        } else {
            0
        };
        written = session.tx();
    }
    let overflowed = server.stats.dropped_queue_full();
    let send_errors = hub.drops(DROP_TRANSPORT_SEND_ERROR).await?;

    let started = Instant::now();
    timeout(WAIT, async {
        for round in 0..ROUNDS {
            let mut sent = Vec::new();
            for node in &healthy {
                let packet = hub.packet_to(node, Family::V4, &round.to_be_bytes());
                hub.send(&packet).await?;
                sent.push(packet);
            }
            for _ in 0..TO_STALLED {
                hub.send(&to_stalled).await?;
            }
            for (node, packet) in healthy.iter_mut().zip(sent) {
                let (_, delivered) = node.expect_delivery().await?;
                assert_eq!(delivered, packet, "round {round}");
            }
        }
        TestResult::Ok(())
    })
    .await
    .map_err(|_| format!("{ROUNDS} rounds not within {WAIT:?}"))??;
    let elapsed = started.elapsed();

    // Every datagram to the stalled session overflowed its queue, and the engine counted it
    // as a send error.
    let more = (ROUNDS * TO_STALLED) as u64;
    until("overflow of every datagram", || {
        server.stats.dropped_queue_full() >= overflowed + more
    })
    .await?;
    let deadline = Instant::now() + WAIT;
    while hub.drops(DROP_TRANSPORT_SEND_ERROR).await? < send_errors + more {
        if Instant::now() > deadline {
            return Err(format!("send errors not counted within {WAIT:?}").into());
        }
        sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(session.tx(), written);
    eprintln!(
        "{ROUNDS} rounds to {} nodes in {elapsed:?}; dropped_queue_full {overflowed} -> {}, \
         send errors {send_errors} -> {}",
        healthy.len(),
        server.stats.dropped_queue_full(),
        hub.drops(DROP_TRANSPORT_SEND_ERROR).await?,
    );
    Ok(())
}
