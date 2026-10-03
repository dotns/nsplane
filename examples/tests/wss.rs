//! The WSS carrier on loopback: TLS and WebSocket round trips between `WssTransport` and
//! the relay's hub, UDP and WSS clients relaying to each other, certificate pinning,
//! what the hub drops, and reconnecting after the relay restarts.

use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{Ecn, PacketBuf, Path, Transport, UdpTransport};
use nsplane_examples::node::UDP_TRANSPORT;
use nsplane_examples::relay::envelope::MachineKey;
use nsplane_examples::relay::messages::build_register_source;
use nsplane_examples::relay::router::{MachinePin, Router, Source, TargetConfig, machine_id};
use nsplane_examples::relay::server::RelayServerTransport;
use nsplane_examples::relay::wss::client::{WssConfig, WssTransport};
use nsplane_examples::relay::wss::server::{WsHub, bind};
use nsplane_examples::relay::wss::{DEFAULT_NAME, ServerCert, client_tls};
use nsplane_noise::noise::{Tunn, TunnResult};
use nsplane_noise::x25519::{PublicKey, StaticSecret};
use serde_json::Value;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const OWN: u8 = 1;
const A: u8 = 2;
const B: u8 = 3;
const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(300);

fn secret(byte: u8) -> StaticSecret {
    StaticSecret::from([byte; 32])
}

fn public(byte: u8) -> [u8; 32] {
    PublicKey::from(&secret(byte)).to_bytes()
}

/// A handshake initiation from key `from` to key `to`, and the response.
fn handshake(from: u8, to: u8) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let mut initiator = Tunn::new(
        secret(from),
        PublicKey::from(public(to)),
        None,
        None,
        1,
        None,
    );
    let mut responder = Tunn::new(
        secret(to),
        PublicKey::from(public(from)),
        None,
        None,
        2,
        None,
    );
    let mut buf = vec![0u8; 2048];
    let TunnResult::WriteToNetwork(init) = initiator.format_handshake_initiation(&mut buf, false)
    else {
        return Err("no initiation".into());
    };
    let init = init.to_vec();
    let mut out = vec![0u8; 2048];
    let TunnResult::WriteToNetwork(response) = responder.decapsulate(None, &init, &mut out) else {
        return Err("no response".into());
    };
    Ok((init, response.to_vec()))
}

/// Polls `condition` until it holds, for at most [`WAIT`].
async fn until(what: &str, mut condition: impl FnMut() -> bool) -> TestResult {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if condition() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("timed out waiting for {what}").into())
}

/// A relay whose own engine is a channel of the datagrams handed to it, with a UDP socket
/// and a WSS listener.
struct Server {
    udp: SocketAddr,
    wss: SocketAddr,
    router: Arc<Mutex<Router>>,
    hub: Arc<WsHub>,
    transport: Arc<RelayServerTransport<UdpTransport>>,
    engine: mpsc::UnboundedReceiver<(Vec<u8>, Path)>,
    tasks: Vec<JoinHandle<()>>,
}

impl Server {
    async fn start(
        wss: SocketAddr,
        cert: &ServerCert,
        targets: Vec<TargetConfig>,
    ) -> TestResult<Self> {
        let udp = UdpTransport::bind(UDP_TRANSPORT, "127.0.0.1:0".parse()?)?;
        let udp_addr = udp.local_addr();
        let mut router = Router::new(public(OWN), "relay".into(), udp_addr);
        router.set_targets(targets);
        let router = Arc::new(Mutex::new(router));
        let hub = WsHub::new(Arc::clone(&router));
        let (wss, listener) = bind(wss, cert.server_tls()?, Arc::clone(&hub)).await?;
        let transport =
            Arc::new(RelayServerTransport::new(udp, Arc::clone(&router)).with_ws(Arc::clone(&hub)));
        let (tx, engine) = mpsc::unbounded_channel();
        let receiver = Arc::clone(&transport);
        let engine_task = tokio::spawn(async move {
            let mut buf = PacketBuf::with_capacity(2048);
            while let Ok((_, path)) = receiver.recv(&mut buf).await {
                if tx.send((buf.as_packet().to_vec(), path)).is_err() {
                    return;
                }
            }
        });
        Ok(Self {
            udp: udp_addr,
            wss,
            router,
            hub,
            transport,
            engine,
            tasks: vec![listener, engine_task],
        })
    }

    /// Stops the listener (closing every connection) and the receive loop.
    async fn stop(self) {
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
    }

    fn status(&self, key: &str) -> u64 {
        self.hub.status_json()[key].as_u64().unwrap_or_default()
    }

    fn target_source(&self) -> Option<Source> {
        let router = self.router.lock().unwrap_or_else(PoisonError::into_inner);
        router.targets(Instant::now()).first()?.source
    }

    /// The next datagram handed to the own engine.
    async fn engine_recv(&mut self) -> TestResult<(Vec<u8>, Path)> {
        Ok(timeout(WAIT, self.engine.recv())
            .await?
            .ok_or("engine closed")?)
    }
}

fn config(server: &Server, pem: &str) -> TestResult<WssConfig> {
    let mut config = WssConfig::new(
        format!("wss://{DEFAULT_NAME}:{}/", server.wss.port()),
        DEFAULT_NAME.try_into()?,
        server.wss,
        client_tls(pem.as_bytes())?,
    );
    config.backoff_min = Duration::from_millis(50);
    config.backoff_max = Duration::from_millis(200);
    Ok(config)
}

fn cert() -> TestResult<ServerCert> {
    Ok(ServerCert::generate(DEFAULT_NAME, &["127.0.0.1".parse()?])?)
}

async fn client_recv(client: &WssTransport) -> TestResult<(Vec<u8>, Path)> {
    let mut buf = PacketBuf::with_capacity(2048);
    let (len, path) = timeout(WAIT, client.recv(&mut buf)).await??;
    Ok((buf.as_packet()[..len].to_vec(), path))
}

const fn to(addr: SocketAddr) -> Path {
    Path {
        transport: UDP_TRANSPORT,
        addr,
        ecn: Ecn::NotEct,
    }
}

/// One datagram each way between a client and the relay's own engine.
async fn round_trip(server: &mut Server, client: &WssTransport) -> TestResult {
    let (init, response) = handshake(A, OWN)?;
    client.send(&init, &to(client.relay())).await?;
    let (received, path) = server.engine_recv().await?;
    assert_eq!(received, init);
    assert!(path.addr.ip().is_loopback());
    // The engine answers on the path it saw: the connection.
    server.transport.send(&response, &path).await?;
    let (received, path) = client_recv(client).await?;
    assert_eq!(received, response);
    assert_eq!(path.addr, client.relay());
    Ok(())
}

#[tokio::test]
async fn datagrams_round_trip_over_tls_and_websocket() -> TestResult {
    let cert = cert()?;
    let mut server = Server::start("127.0.0.1:0".parse()?, &cert, Vec::new()).await?;
    let client = WssTransport::connect(UDP_TRANSPORT, config(&server, &cert.pem)?, None)?;
    let stats = client.stats();
    until("the connection", || stats.connected()).await?;
    round_trip(&mut server, &client).await?;
    assert_eq!((stats.tx(), stats.rx(), stats.drops()), (1, 1, 0));
    assert_eq!((server.status("rx"), server.status("tx")), (1, 1));
    assert_eq!(server.hub.connections(), 1);
    let status = stats.status_json();
    assert_eq!(status["connected"], Value::Bool(true));
    assert_eq!(status["reconnects"], 0);

    // Without a direct socket, datagrams to other addresses are dropped.
    client.send(&[4; 32], &to(server.udp)).await?;
    assert_eq!(stats.drops(), 1);
    drop(client);
    until("the close", || server.hub.connections() == 0).await?;
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn udp_and_wss_clients_relay_to_each_other() -> TestResult {
    let cert = cert()?;
    let machine = MachineKey::generate();
    let pin = TargetConfig {
        wg_public_key: public(B),
        pin: Some(MachinePin {
            machine_id: machine_id(&machine.public()),
            machine_key: machine.public(),
        }),
        static_source: None,
    };
    let server = Server::start("127.0.0.1:0".parse()?, &cert, vec![pin]).await?;
    let b = WssTransport::connect(UDP_TRANSPORT, config(&server, &cert.pem)?, None)?;
    let stats = b.stats();
    until("the connection", || stats.connected()).await?;

    // B registers over its connection.
    let register = build_register_source(&machine_id(&machine.public()), &machine, public(B))?;
    b.send(&register, &to(b.relay())).await?;
    until("the registration", || {
        matches!(server.target_source(), Some(Source::Ws(_)))
    })
    .await?;

    // A, on UDP, reaches B through the relay, and B's answer comes back.
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let (init, response) = handshake(A, B)?;
    a.send_to(&init, server.udp).await?;
    assert_eq!(client_recv(&b).await?.0, init);
    b.send(&response, &to(b.relay())).await?;
    let mut buf = vec![0u8; 2048];
    let (len, _) = timeout(WAIT, a.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], response.as_slice());

    // Closing the connection forgets B's source and its routes.
    drop(b);
    until("the close", || server.target_source().is_none()).await?;
    let routes = server
        .router
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .routes(Instant::now());
    assert_eq!(routes, Vec::new());
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn a_foreign_certificate_is_rejected() -> TestResult {
    let (cert, foreign) = (cert()?, cert()?);
    let server = Server::start("127.0.0.1:0".parse()?, &cert, Vec::new()).await?;
    let client = WssTransport::connect(UDP_TRANSPORT, config(&server, &foreign.pem)?, None)?;
    let stats = client.stats();
    until("failed attempts", || stats.connect_failures() >= 2).await?;
    assert!(!stats.connected());
    assert_eq!(stats.connects(), 0);
    assert!(server.status("handshake_failures") >= 2);
    assert_eq!(server.status("accepted"), 0);
    // Datagrams to the relay wait for a connection in a queue of 256; send never waits,
    // it fails once the queue is full.
    let init = handshake(A, OWN)?.0;
    for _ in 0..256 {
        client.send(&init, &to(client.relay())).await?;
    }
    assert_eq!(stats.drops(), 0);
    let full = client.send(&init, &to(client.relay())).await;
    assert_eq!(
        full.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(stats.drops(), 1);
    assert_eq!(stats.status_json()["dropped"]["queue_full"], 1);
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn text_oversized_and_invalid_messages_are_dropped() -> TestResult {
    let cert = cert()?;
    let mut server = Server::start("127.0.0.1:0".parse()?, &cert, Vec::new()).await?;
    let tcp = TcpStream::connect(server.wss).await?;
    let tls = TlsConnector::from(client_tls(cert.pem.as_bytes())?)
        .connect(DEFAULT_NAME.try_into()?, tcp)
        .await?;
    let url = format!("wss://{DEFAULT_NAME}:{}/", server.wss.port());
    let (mut ws, _) = tokio_tungstenite::client_async(url, tls).await?;

    ws.send(Message::text("hello")).await?;
    ws.send(Message::binary(vec![9u8; 3])).await?;
    ws.send(Message::binary(vec![4u8; 70_000])).await?;
    ws.send(Message::Ping(b"ping".to_vec().into())).await?;
    let (init, _) = handshake(A, OWN)?;
    ws.send(Message::binary(init.clone())).await?;

    // Only the WireGuard message reaches the engine.
    assert_eq!(server.engine_recv().await?.0, init);
    assert!(
        timeout(QUIET, server.engine.recv()).await.is_err(),
        "nothing else reaches the engine"
    );
    let pong = timeout(WAIT, ws.next()).await?.ok_or("closed")??;
    assert_eq!(pong, Message::Pong(b"ping".to_vec().into()));
    assert_eq!(
        [
            "dropped_text",
            "dropped_invalid",
            "dropped_oversized",
            "pings",
            "rx"
        ]
        .map(|key| server.status(key)),
        [1, 1, 1, 1, 1]
    );
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn the_client_reconnects_after_the_relay_restarts() -> TestResult {
    let cert = cert()?;
    let mut server = Server::start("127.0.0.1:0".parse()?, &cert, Vec::new()).await?;
    let client = WssTransport::connect(UDP_TRANSPORT, config(&server, &cert.pem)?, None)?;
    let stats = client.stats();
    until("the connection", || stats.connected()).await?;
    round_trip(&mut server, &client).await?;

    let addr = server.wss;
    server.stop().await;
    until("the disconnect", || !stats.connected()).await?;
    // Sent while disconnected: it waits for the next connection.
    let (queued, _) = handshake(B, OWN)?;
    client.send(&queued, &to(client.relay())).await?;
    assert_eq!(stats.drops(), 0);

    // A new relay on the same address, with the pinned certificate.
    let mut server = Server::start(addr, &cert, Vec::new()).await?;
    until("the reconnect", || stats.connected()).await?;
    assert_eq!(stats.reconnects(), 1);
    assert_eq!(server.engine_recv().await?.0, queued);
    round_trip(&mut server, &client).await?;
    assert_eq!((stats.tx(), stats.rx(), stats.drops()), (3, 2, 0));
    server.stop().await;
    Ok(())
}
