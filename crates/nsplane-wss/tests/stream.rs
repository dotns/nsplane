//! `WssStreamClient` and `WssStreamServer` end to end: both dial a small test relay (a TLS
//! WebSocket server that forwards frames verbatim between a client session and a server
//! session, or a plain one for `ws://`), and the client's TCP streams and UDP flows run
//! through the server to local backends. The relay checks every frame it forwards against
//! the ns frame layout.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{BoxFuture, LinkState};
use nsplane_wss::frame::{FrameCommand, Protocol, WsFrame};
use nsplane_wss::{
    BearerProvider, Denied, WssCloseReason, WssConfig, WssOpen, WssResolver, WssServerLimits,
    WssServerStats, WssStreamClient, WssStreamEvent, WssStreamEventKind, WssStreamLimits,
    WssStreamServer, WssTcpStream, WssTls, WssUdpFlow,
};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// How long a test waits for something that should happen.
const WAIT: Duration = Duration::from_secs(10);

/// The relay's certificate name.
const NAME: &str = "relay.test";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Which side a relay session serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    /// A `WssStreamClient` session (`/client`).
    Client,
    /// A `WssStreamServer` session (`/terminate`).
    Server,
}

/// One WebSocket upgrade the relay saw.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Upgrade {
    role: Role,
    authorization: Option<String>,
    accepted: bool,
}

/// One frame the relay forwarded: from which side, on which slot.
#[derive(Debug, Clone)]
struct Seen {
    slot: usize,
    from: Role,
    bytes: Bytes,
}

/// A live relay session: its connection number and where its outgoing frames go.
type Live = HashMap<usize, (u64, mpsc::UnboundedSender<Bytes>)>;

/// The test relay. Client session `k` (the `k`-th live one) and the server session that
/// asked for slot `k` (header `X-Slot`) are paired; a frame is forwarded to whichever
/// session holds the peer slot at that moment, or dropped.
struct Relay {
    addr: SocketAddr,
    roots: RootCertStore,
    /// Plain WebSocket (`ws://`), without TLS.
    plain: bool,
    upgrades: Mutex<Vec<Upgrade>>,
    /// Upgrades without `Authorization: Bearer <this>` are answered 401.
    token: Mutex<Option<String>>,
    /// Upgrades are answered 403 while set.
    forbid: AtomicBool,
    clients: Mutex<Live>,
    servers: Mutex<Live>,
    connections: AtomicU64,
    /// Bumped to drop the sessions of a role.
    kick_clients: watch::Sender<u64>,
    kick_servers: watch::Sender<u64>,
    wire: Mutex<Vec<Seen>>,
}

impl Relay {
    async fn start() -> TestResult<Arc<Self>> {
        Self::launch(false).await
    }

    /// A relay without TLS, dialed with `ws://` URLs.
    async fn start_plain() -> TestResult<Arc<Self>> {
        Self::launch(true).await
    }

    async fn launch(plain: bool) -> TestResult<Arc<Self>> {
        let mut params = CertificateParams::new(vec![NAME.to_owned()])?;
        params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone())?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )?;
        let acceptor = (!plain).then(|| TlsAcceptor::from(Arc::new(server)));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay = Arc::new(Self {
            addr: listener.local_addr()?,
            roots,
            plain,
            upgrades: Mutex::new(Vec::new()),
            token: Mutex::new(Some("t".to_owned())),
            forbid: AtomicBool::new(false),
            clients: Mutex::new(HashMap::new()),
            servers: Mutex::new(HashMap::new()),
            connections: AtomicU64::new(0),
            kick_clients: watch::Sender::new(0),
            kick_servers: watch::Sender::new(0),
            wire: Mutex::new(Vec::new()),
        });
        let accepting = Arc::clone(&relay);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(Arc::clone(&accepting).serve(tcp, acceptor.clone()));
            }
        });
        Ok(relay)
    }

    fn config(&self, path: &str, token: &Arc<Token>) -> WssConfig {
        let tls = WssTls::Roots(self.roots.clone());
        let config = if self.plain {
            WssConfig::new(format!("ws://{}/{path}", self.addr), tls).allow_plaintext(true)
        } else {
            WssConfig::new(format!("wss://{NAME}:{}/{path}", self.addr.port()), tls)
                .connect_addr(self.addr)
        };
        config
            .bearer(Arc::clone(token) as Arc<dyn BearerProvider>)
            .backoff(Duration::from_millis(50), Duration::from_millis(200))
            .token_refresh(Duration::from_millis(50), WAIT)
            .keepalive(Duration::from_millis(100), Duration::from_millis(600))
            .connect_timeout(Duration::from_secs(2))
    }

    /// A client of this relay within `limits`, with the bearer `token`.
    fn client(&self, limits: WssStreamLimits, token: &Arc<Token>) -> TestResult<WssStreamClient> {
        Ok(WssStreamClient::new(self.config("client", token), limits)?)
    }

    /// Runs a server on `slot` resolving with `resolver`, until the returned handle drops.
    fn server(
        &self,
        slot: usize,
        limits: WssServerLimits,
        resolver: &Arc<Map>,
        token: &Arc<Token>,
    ) -> TestResult<Terminate> {
        let config = self
            .config("terminate", token)
            .header("X-Slot", slot.to_string());
        let (events, events_rx) = mpsc::channel(1024);
        let server =
            WssStreamServer::new(config, limits, Arc::clone(resolver) as _)?.with_events(events);
        let stats = server.stats();
        let state = server.state();
        let (stop, stopped) = oneshot::channel::<()>();
        let run = tokio::spawn(server.run(async {
            let _ = stopped.await;
        }));
        Ok(Terminate {
            stats,
            state,
            events: events_rx,
            stop: Some(stop),
            run,
        })
    }

    /// The role and slot of an upgrade, or the status refusing it.
    fn upgrade(&self, req: &Request) -> Result<(Role, usize), u16> {
        let header = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let authorization = header("authorization");
        let role = if req.uri().path() == "/terminate" {
            Role::Server
        } else {
            Role::Client
        };
        let status = if self.forbid.load(Ordering::SeqCst) {
            Some(403)
        } else {
            lock(&self.token)
                .as_ref()
                .filter(|token| authorization.as_deref() != Some(&format!("Bearer {token}")))
                .map(|_| 401)
        };
        lock(&self.upgrades).push(Upgrade {
            role,
            authorization,
            accepted: status.is_none(),
        });
        if let Some(status) = status {
            return Err(status);
        }
        let slot = match role {
            Role::Server => header("x-slot").and_then(|s| s.parse().ok()).unwrap_or(0),
            // Held by `serve` right after; client upgrades of one test do not race.
            Role::Client => {
                let clients = lock(&self.clients);
                (0..=clients.len())
                    .find(|slot| !clients.contains_key(slot))
                    .unwrap_or(0)
            }
        };
        Ok((role, slot))
    }

    async fn serve(self: Arc<Self>, tcp: TcpStream, acceptor: Option<TlsAcceptor>) {
        match acceptor {
            Some(acceptor) => {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    self.session(tls).await;
                }
            }
            None => self.session(tcp).await,
        }
    }

    async fn session(self: Arc<Self>, stream: impl AsyncRead + AsyncWrite + Unpin) {
        let mut upgraded = None;
        let callback = Upgrader {
            relay: &self,
            upgraded: &mut upgraded,
        };
        let Ok(ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
            return;
        };
        let Some((role, slot)) = upgraded else {
            return;
        };
        let connection = self.connections.fetch_add(1, Ordering::SeqCst);
        let (tx, mut outgoing) = mpsc::unbounded_channel();
        let (own, peers, kick) = match role {
            Role::Client => (&self.clients, &self.servers, &self.kick_clients),
            Role::Server => (&self.servers, &self.clients, &self.kick_servers),
        };
        lock(own).insert(slot, (connection, tx));
        let mut kick = kick.subscribe();
        let (mut sink, mut source) = ws.split();
        loop {
            tokio::select! {
                message = source.next() => match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        lock(&self.wire).push(Seen { slot, from: role, bytes: bytes.clone() });
                        if let Some((_, peer)) = lock(peers).get(&slot) {
                            let _ = peer.send(bytes);
                        }
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
                Some(bytes) = outgoing.recv() => {
                    if sink.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
                _ = kick.changed() => break,
            }
        }
        let mut own = lock(own);
        if own.get(&slot).is_some_and(|(c, _)| *c == connection) {
            own.remove(&slot);
        }
    }

    fn upgrades(&self, role: Role) -> Vec<Upgrade> {
        lock(&self.upgrades)
            .iter()
            .filter(|upgrade| upgrade.role == role)
            .cloned()
            .collect()
    }

    /// The frames forwarded (DATA payloads left out), as (slot, from, frame).
    fn frames(&self) -> Vec<(usize, Role, WsFrame)> {
        lock(&self.wire)
            .iter()
            .filter_map(|seen| {
                let frame = WsFrame::decode(&seen.bytes).ok()?;
                (frame.command != FrameCommand::Data).then_some((seen.slot, seen.from, frame))
            })
            .collect()
    }

    fn saw(&self, slot: usize, from: Role, frame: &WsFrame) -> bool {
        self.frames()
            .iter()
            .any(|(s, f, seen)| *s == slot && *f == from && seen == frame)
    }

    /// The OPENs forwarded, as (slot, stream id, target, protocol).
    fn opens(&self) -> Vec<(usize, u32, SocketAddr, Protocol)> {
        self.frames()
            .into_iter()
            .filter_map(|(slot, _, frame)| match frame.command {
                FrameCommand::Open { target, protocol } => {
                    Some((slot, frame.stream_id, target, protocol))
                }
                _ => None,
            })
            .collect()
    }

    /// Every forwarded message is a frame with the exact bytes the ns builders give it
    /// (W2's wire vectors), and the client sends no `CLOSE_ACK` but for a server's CLOSE.
    fn check_wire(&self) -> TestResult {
        let wire = lock(&self.wire).clone();
        if wire.is_empty() {
            return Err("no frames seen".into());
        }
        for seen in &wire {
            let frame = WsFrame::decode(&seen.bytes)
                .map_err(|e| format!("{:?} sent a message that is no frame: {e}", seen.from))?;
            if seen.bytes[..] != ns_frame(&frame)[..] {
                return Err(format!(
                    "{:?} frame bytes differ from the ns layout: {:?}",
                    seen.from,
                    &seen.bytes[..seen.bytes.len().min(32)]
                )
                .into());
            }
            if matches!(frame.command, FrameCommand::Open { .. }) && seen.from != Role::Client {
                return Err("an OPEN from the server".into());
            }
        }
        Ok(())
    }
}

struct Upgrader<'a> {
    relay: &'a Relay,
    upgraded: &'a mut Option<(Role, usize)>,
}

impl Callback for Upgrader<'_> {
    fn on_request(self, req: &Request, response: Response) -> Result<Response, ErrorResponse> {
        match self.relay.upgrade(req) {
            Ok(upgraded) => {
                *self.upgraded = Some(upgraded);
                Ok(response)
            }
            Err(status) => {
                let mut refused = ErrorResponse::new(None);
                *refused.status_mut() = status.try_into().unwrap_or_default();
                Err(refused)
            }
        }
    }
}

/// The ns bytes of `frame`: `proxy/wire.rs` `build_open_frame` (and its IPv6 form in
/// `tunnel-ws`), `build_data_frame`, `build_close_frame` and the `CLOSE_ACK` `tunnel-ws`
/// sends, as the W2 wire vectors.
fn ns_frame(frame: &WsFrame) -> Vec<u8> {
    let mut bytes = frame.stream_id.to_be_bytes().to_vec();
    match frame.command {
        FrameCommand::Open { target, protocol } => {
            match target.ip() {
                IpAddr::V4(ip) => {
                    bytes.push(0x01);
                    bytes.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    bytes.push(0x02);
                    bytes.extend_from_slice(&ip.octets());
                }
            }
            bytes.extend_from_slice(&target.port().to_be_bytes());
            bytes.push(match protocol {
                Protocol::Tcp => 0x00,
                Protocol::Udp => 0x01,
            });
        }
        FrameCommand::Data => {
            bytes.push(0x10);
            bytes.extend_from_slice(&frame.payload);
        }
        FrameCommand::Close => bytes.push(0x20),
        FrameCommand::CloseAck => bytes.push(0x21),
    }
    bytes
}

/// A running `WssStreamServer`; dropping it stops the server.
struct Terminate {
    stats: Arc<WssServerStats>,
    state: watch::Receiver<LinkState>,
    events: mpsc::Receiver<WssStreamEvent>,
    stop: Option<oneshot::Sender<()>>,
    run: tokio::task::JoinHandle<()>,
}

impl Terminate {
    async fn connected(&mut self) -> TestResult {
        timeout(WAIT, self.state.wait_for(|s| *s == LinkState::Connected)).await??;
        Ok(())
    }

    /// Stops the server and waits for its run to end.
    async fn stop(mut self) -> TestResult {
        drop(self.stop.take());
        timeout(WAIT, &mut self.run).await??;
        Ok(())
    }

    /// The events so far.
    fn events(&mut self) -> Vec<WssStreamEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.events.try_recv() {
            events.push(event);
        }
        events
    }

    /// The next event, within [`WAIT`].
    async fn event(&mut self) -> TestResult<WssStreamEvent> {
        Ok(timeout(WAIT, self.events.recv())
            .await?
            .ok_or("events gone")?)
    }

    /// The next close event for `reason`, skipping others, within [`WAIT`].
    async fn closed(&mut self, reason: WssCloseReason) -> TestResult<WssStreamEvent> {
        loop {
            let event = self.event().await?;
            if matches!(event.kind, WssStreamEventKind::Close { reason: r, .. } if r == reason) {
                return Ok(event);
            }
        }
    }
}

/// Maps virtual targets to local backends; denies the rest.
#[derive(Debug, Default)]
struct Map(Mutex<HashMap<SocketAddr, SocketAddr>>);

impl Map {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Maps the next virtual target (10.0.0.n:port, by protocol) to `backend`.
    fn add(&self, backend: SocketAddr) -> SocketAddr {
        let mut map = lock(&self.0);
        let n = u8::try_from(map.len() + 1).unwrap_or(u8::MAX);
        let target = SocketAddr::from(([10, 0, 0, n], 7000 + u16::from(n)));
        map.insert(target, backend);
        target
    }
}

impl WssResolver for Map {
    fn resolve(&self, open: WssOpen) -> BoxFuture<'_, Result<SocketAddr, Denied>> {
        let backend = lock(&self.0).get(&open.target).copied().ok_or(Denied);
        Box::pin(std::future::ready(backend))
    }
}

/// A TCP echo backend.
async fn tcp_echo() -> TestResult<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = tcp.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    Ok(addr)
}

/// A TCP backend that echoes `n` bytes and then closes the connection.
async fn tcp_echo_then_close(n: usize) -> TestResult<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0; n];
                if tcp.read_exact(&mut buf).await.is_ok() {
                    let _ = tcp.write_all(&buf).await;
                }
            });
        }
    });
    Ok(addr)
}

/// A TCP backend that writes `data` on each connection and closes it.
async fn tcp_source(data: Vec<u8>) -> TestResult<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let data = Arc::new(data);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let data = Arc::clone(&data);
            tokio::spawn(async move {
                let _ = tcp.write_all(&data).await;
            });
        }
    });
    Ok(addr)
}

/// A TCP backend that reads each connection to its end and reports the bytes.
async fn tcp_sink() -> TestResult<(SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut received = Vec::new();
                if tcp.read_to_end(&mut received).await.is_ok() {
                    let _ = tx.send(received);
                }
            });
        }
    });
    Ok((addr, rx))
}

/// A TCP backend that accepts and never reads, holding its connections open.
async fn tcp_stall() -> TestResult<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _held = tcp;
                std::future::pending::<()>().await;
            });
        }
    });
    Ok(addr)
}

/// A UDP echo backend.
async fn udp_echo() -> TestResult<SocketAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buf = vec![0; 65_536];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    Ok(addr)
}

/// A bearer token the test changes.
struct Token(Mutex<Option<String>>);

impl Token {
    fn new(token: &str) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(token.to_owned()))))
    }

    fn set(&self, token: &str) {
        *lock(&self.0) = Some(token.to_owned());
    }
}

impl BearerProvider for Token {
    fn token(&self) -> BoxFuture<'_, io::Result<Option<String>>> {
        let token = lock(&self.0).clone();
        Box::pin(std::future::ready(Ok(token)))
    }
}

/// `len` bytes of a pattern seeded by `seed`.
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(byte(i % 251))).collect()
}

/// The low byte of `n`.
const fn byte(n: usize) -> u8 {
    n.to_le_bytes()[0]
}

/// Echoes `len` bytes through `stream`, writing and reading at once; returns the stream.
async fn echo(stream: WssTcpStream, seed: u8, len: usize) -> TestResult<WssTcpStream> {
    let data = pattern(seed, len);
    let (mut read, mut write) = tokio::io::split(stream);
    let sent = data.clone();
    let writer = tokio::spawn(async move { write.write_all(&sent).await.map(|()| write) });
    let mut back = vec![0; len];
    timeout(WAIT * 4, read.read_exact(&mut back))
        .await
        .map_err(|_| format!("echo of {len} bytes not within {:?}", WAIT * 4))??;
    let write = writer.await??;
    if back != data {
        return Err("echoed bytes differ".into());
    }
    Ok(read.unsplit(write))
}

/// Sends `count` datagrams through `flow`, one at a time, and checks each echo.
async fn udp_round_trips(flow: &mut WssUdpFlow, seed: u8, count: usize) -> TestResult {
    for i in 0..count {
        let datagram = pattern(seed.wrapping_add(byte(i)), 100 + i * 37);
        flow.send(&datagram).await?;
        let back = timeout(WAIT, flow.recv())
            .await
            .map_err(|_| "datagram echo not within WAIT")??
            .ok_or("flow closed")?;
        if back != datagram {
            return Err("echoed datagram differs".into());
        }
    }
    Ok(())
}

/// Waits until `condition` holds, within [`WAIT`].
async fn until(what: &str, condition: impl Fn() -> bool) -> TestResult {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        if Instant::now() > deadline {
            return Err(format!("{what} not within {WAIT:?}").into());
        }
        sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

/// Reads `stream` to its end within [`WAIT`].
async fn read_to_end(stream: &mut WssTcpStream) -> TestResult<Vec<u8>> {
    let mut read = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut read))
        .await
        .map_err(|_| "EOF not within WAIT")??;
    Ok(read)
}

/// A relay with a server on slot 0 resolving with `map` within `limits`, connected.
async fn setup(map: &Arc<Map>, limits: WssServerLimits) -> TestResult<(Arc<Relay>, Terminate)> {
    let relay = Relay::start().await?;
    let mut terminate = relay.server(0, limits, map, &Token::new("t"))?;
    terminate.connected().await?;
    Ok((relay, terminate))
}

/// Large payloads both ways: 8 MiB up to a backend that reads to the end, 8 MiB down
/// from one that writes and closes, and an echo. The protocol has no flow control (as in
/// ns): an echo is kept within the 4 MiB stream budget, since a larger one can outrun the
/// backend's echo and is then closed at the budget (see the budget tests).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_large_payloads() -> TestResult {
    let map = Map::new();
    let (sink, mut received) = tcp_sink().await?;
    let sink_target = map.add(sink);
    let len = 8 * 1024 * 1024;
    let source = tcp_source(pattern(4, len)).await?;
    let source_target = map.add(source);
    let echo_target = map.add(tcp_echo().await?);
    let (relay, mut terminate) = setup(&map, WssServerLimits::default()).await?;
    let client = relay.client(WssStreamLimits::default(), &Token::new("t"))?;

    let mut up = client.open_tcp(sink_target).await?;
    assert_eq!(up.stream_id(), 1);
    let data = pattern(3, len);
    up.write_all(&data).await?;
    up.shutdown().await?;
    let got = timeout(WAIT, received.recv()).await?.ok_or("sink gone")?;
    assert!(got == data, "uploaded bytes differ");
    assert_eq!(read_to_end(&mut up).await?, b"");

    let mut down = client.open_tcp(source_target).await?;
    let got = read_to_end(&mut down).await?;
    assert!(got == pattern(4, len), "downloaded bytes differ");

    let echoed = 3 * 1024 * 1024;
    let mut stream = echo(client.open_tcp(echo_target).await?, 5, echoed).await?;
    stream.shutdown().await?;
    assert_eq!(read_to_end(&mut stream).await?, b"");

    let mut closes = HashMap::new();
    while closes.len() < 3 {
        let event = terminate.event().await?;
        match event.kind {
            WssStreamEventKind::Open => {
                let expected = [(sink_target, sink), (source_target, source)];
                if let Some(&(target, backend)) = expected.get(event.stream_id as usize - 1) {
                    assert_eq!((event.target, event.backend), (target, backend));
                }
                assert_eq!((event.session, event.protocol), (1, Protocol::Tcp));
            }
            kind => {
                closes.insert(event.stream_id, kind);
            }
        }
    }
    let close = |reason, to_backend: usize, from_backend: usize| WssStreamEventKind::Close {
        reason,
        to_backend: to_backend as u64,
        from_backend: from_backend as u64,
    };
    assert_eq!(closes[&1], close(WssCloseReason::PeerClosed, len, 0));
    assert_eq!(closes[&2], close(WssCloseReason::BackendClosed, 0, len));
    assert_eq!(
        closes[&3],
        close(WssCloseReason::PeerClosed, echoed, echoed)
    );
    let total = (len + echoed) as u64;
    let stats = client.stats();
    assert_eq!((stats.tx_bytes(), stats.rx_bytes()), (total, total));
    assert_eq!(stats.overflows(), 0);
    let server = &terminate.stats;
    assert_eq!((server.rx_bytes(), server.tx_bytes()), (total, total));
    assert_eq!((server.streams_opened(), server.streams_closed()), (3, 3));
    assert_eq!((server.overflows(), server.event_drops()), (0, 0));
    assert_eq!(server.sessions(), 1);
    assert!(relay.saw(0, Role::Server, &WsFrame::close_ack(1)));
    assert!(relay.saw(0, Role::Server, &WsFrame::close(2)));
    assert!(relay.saw(0, Role::Client, &WsFrame::close_ack(2)));
    assert_eq!(
        relay.opens(),
        [
            (0, 1, sink_target, Protocol::Tcp),
            (0, 2, source_target, Protocol::Tcp),
            (0, 3, echo_target, Protocol::Tcp)
        ]
    );
    assert_eq!(
        relay.upgrades(Role::Server),
        [Upgrade {
            role: Role::Server,
            authorization: Some("Bearer t".to_owned()),
            accepted: true
        }]
    );
    relay.check_wire()?;
    terminate.stop().await
}

/// Many TCP streams and UDP flows share one client session and one server session; a
/// CLOSE of one stream from either side leaves the others transferring.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_streams_and_flows_share_one_session() -> TestResult {
    let map = Map::new();
    let tcp_target = map.add(tcp_echo().await?);
    let closing_target = map.add(tcp_echo_then_close(1000).await?);
    let udp_target = map.add(udp_echo().await?);
    let (relay, mut terminate) = setup(&map, WssServerLimits::default()).await?;
    let client = relay.client(WssStreamLimits::default(), &Token::new("t"))?;
    client.connect().await?;

    let mut streams = Vec::new();
    for _ in 0..8 {
        streams.push(client.open_tcp(tcp_target).await?);
    }
    let closing = client.open_tcp(closing_target).await?;
    let mut flows = Vec::new();
    for _ in 0..4 {
        flows.push(client.open_udp(udp_target).await?);
    }
    let first_round = |streams: Vec<WssTcpStream>, flows: Vec<WssUdpFlow>, seed: usize| {
        let echoes: Vec<_> = streams
            .into_iter()
            .enumerate()
            .map(|(i, stream)| tokio::spawn(echo(stream, byte(seed + i), 512 * 1024)))
            .collect();
        let udp: Vec<_> = flows
            .into_iter()
            .enumerate()
            .map(|(i, mut flow)| {
                tokio::spawn(async move {
                    udp_round_trips(&mut flow, byte(seed + i), 10)
                        .await
                        .map(|()| flow)
                })
            })
            .collect();
        (echoes, udp)
    };
    let (echoes, udp) = first_round(streams, flows, 0);
    // The backend of `closing` echoes 1000 bytes and then closes: the server's CLOSE.
    let mut closing = echo(closing, 9, 1000).await?;
    assert_eq!(read_to_end(&mut closing).await?, b"");
    let closing_id = closing.stream_id();
    drop(closing);
    let mut streams = Vec::new();
    for echo in echoes {
        streams.push(echo.await??);
    }
    let mut flows = Vec::new();
    for flow in udp {
        flows.push(flow.await??);
    }

    // The client closes stream 1, mid-session.
    let mut first = streams.remove(0);
    first.shutdown().await?;
    assert_eq!(read_to_end(&mut first).await?, b"");
    drop(first);

    // The others keep transferring, all at once.
    let (echoes, udp) = first_round(streams, flows, 100);
    for echo in echoes {
        echo.await??;
    }
    for flow in udp {
        flow.await??;
    }

    assert!(relay.saw(0, Role::Client, &WsFrame::close(1)));
    assert!(relay.saw(0, Role::Server, &WsFrame::close_ack(1)));
    assert!(relay.saw(0, Role::Server, &WsFrame::close(closing_id)));
    assert!(relay.saw(0, Role::Client, &WsFrame::close_ack(closing_id)));
    assert_eq!(relay.upgrades(Role::Client).len(), 1);
    assert_eq!(relay.upgrades(Role::Server).len(), 1);
    let stats = client.stats();
    assert_eq!((stats.sessions(), stats.active_sessions()), (1, 1));
    assert_eq!(stats.streams_opened(), 13);
    assert_eq!(stats.overflows(), 0);
    let server = &terminate.stats;
    assert_eq!((server.sessions(), server.streams_opened()), (1, 13));
    assert_eq!(server.overflows(), 0);
    let opens = relay.opens();
    assert_eq!(opens.len(), 13);
    for (i, &(slot, id, target, protocol)) in opens.iter().enumerate() {
        let expected = match i {
            0..8 => (tcp_target, Protocol::Tcp),
            8 => (closing_target, Protocol::Tcp),
            _ => (udp_target, Protocol::Udp),
        };
        assert_eq!((slot, id), (0, u32::try_from(i + 1)?));
        assert_eq!((target, protocol), expected);
    }
    let reasons: Vec<_> = terminate
        .events()
        .into_iter()
        .filter_map(|event| match event.kind {
            WssStreamEventKind::Close { reason, .. } => Some((event.stream_id, reason)),
            _ => None,
        })
        .collect();
    assert!(reasons.contains(&(closing_id, WssCloseReason::BackendClosed)));
    assert!(reasons.contains(&(1, WssCloseReason::PeerClosed)));
    relay.check_wire()?;
    terminate.stop().await
}

/// A shutdown delivers what was written before it, and the backend sees EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_close_delivers_the_data_then_eof() -> TestResult {
    let map = Map::new();
    let (backend, mut received) = tcp_sink().await?;
    let target = map.add(backend);
    let (relay, terminate) = setup(&map, WssServerLimits::default()).await?;
    let client = relay.client(WssStreamLimits::default(), &Token::new("t"))?;
    let mut stream = client.open_tcp(target).await?;
    let data = pattern(9, 300 * 1024);
    stream.write_all(&data).await?;
    stream.shutdown().await?;
    let got = timeout(WAIT, received.recv()).await?.ok_or("sink gone")?;
    assert_eq!(got.len(), data.len());
    assert_eq!(got, data);
    assert_eq!(read_to_end(&mut stream).await?, b"");
    assert!(stream.write_all(b"more").await.is_err());
    assert!(relay.saw(0, Role::Client, &WsFrame::close(1)));
    relay.check_wire()?;
    terminate.stop().await
}

/// A client and a server on `ws://` URLs (no TLS) through a plain relay: a TCP stream
/// echoes, and the same URL without `allow_plaintext` is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_ws_urls_carry_streams() -> TestResult {
    let map = Map::new();
    let target = map.add(tcp_echo().await?);
    let relay = Relay::start_plain().await?;
    let token = Token::new("t");
    let mut terminate = relay.server(0, WssServerLimits::default(), &map, &token)?;
    terminate.connected().await?;
    let client = relay.client(WssStreamLimits::default(), &token)?;
    let mut stream = echo(client.open_tcp(target).await?, 11, 64 * 1024).await?;
    stream.shutdown().await?;
    assert_eq!(read_to_end(&mut stream).await?, b"");
    assert_eq!(client.stats().sessions(), 1);
    assert_eq!(
        relay.upgrades(Role::Client),
        [Upgrade {
            role: Role::Client,
            authorization: Some("Bearer t".to_owned()),
            accepted: true
        }]
    );
    relay.check_wire()?;

    let mut config = relay.config("client", &token);
    config.allow_plaintext = false;
    let err = WssStreamClient::new(config, WssStreamLimits::default()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    terminate.stop().await
}

/// The resolver's denial and a backend that refuses: the client's stream reads EOF (the
/// server's CLOSE), and acknowledges it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminate_denial_and_refused_backend_close_the_stream() -> TestResult {
    let map = Map::new();
    let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let refused = map.add(closed.local_addr()?);
    drop(closed);
    let (relay, mut terminate) = setup(&map, WssServerLimits::default()).await?;
    let client = relay.client(WssStreamLimits::default(), &Token::new("t"))?;

    let mut denied = client.open_tcp("10.9.9.9:22".parse()?).await?;
    assert_eq!(read_to_end(&mut denied).await?, b"");
    let err = denied.write_all(b"x").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    let mut flow = client.open_udp("10.9.9.9:53".parse()?).await?;
    assert_eq!(timeout(WAIT, flow.recv()).await??, None);

    let mut stream = client.open_tcp(refused).await?;
    assert_eq!(read_to_end(&mut stream).await?, b"");
    for id in 1..=3 {
        until("the CLOSE_ACK of a closed stream", || {
            relay.saw(0, Role::Client, &WsFrame::close_ack(id))
        })
        .await?;
        assert!(relay.saw(0, Role::Server, &WsFrame::close(id)));
    }
    let server = &terminate.stats;
    assert_eq!(server.streams_denied(), 2);
    assert_eq!(server.streams_opened(), 1);
    let open = terminate.event().await?;
    assert_eq!((open.stream_id, open.kind), (3, WssStreamEventKind::Open));
    let close = terminate.event().await?;
    assert!(matches!(
        close.kind,
        WssStreamEventKind::Close {
            reason: WssCloseReason::ConnectFailed,
            ..
        }
    ));
    assert_eq!(terminate.events(), Vec::new());
    assert_eq!(client.stats().streams_closed(), 3);
    relay.check_wire()?;
    terminate.stop().await
}

/// Watches `stats.buffered()` until the returned flag is set; yields the largest value.
fn watch_buffered(
    stats: &Arc<WssServerStats>,
) -> (Arc<AtomicBool>, tokio::task::JoinHandle<usize>) {
    let stats = Arc::clone(stats);
    let done = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&done);
    let task = tokio::spawn(async move {
        let mut max = 0;
        while !stop.load(Ordering::Relaxed) {
            max = max.max(stats.buffered());
            sleep(Duration::from_micros(200)).await;
        }
        max
    });
    (done, task)
}

/// Writes `len` bytes into `stream` until the server closes it: the write fails or the
/// read sees EOF.
async fn write_until_closed(mut stream: WssTcpStream, len: usize) -> TestResult {
    let data = pattern(1, len);
    // Generous: on a loaded host the overflow and the close it triggers take a while.
    let _ = timeout(WAIT * 4, stream.write_all(&data)).await?;
    assert_eq!(read_to_end(&mut stream).await?, b"");
    let Err(err) = stream.write_all(b"x").await else {
        return Err("a write after the close succeeded".into());
    };
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    Ok(())
}

/// A backend that does not read: its stream's queue grows to the 4 MiB stream budget and
/// no further, then the server closes that stream (ns `MAX_STREAM_BUFFER_BYTES`); another
/// stream of the session goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_backend_is_closed_at_the_stream_budget() -> TestResult {
    let map = Map::new();
    let stall = tcp_stall().await?;
    let stalled = map.add(stall);
    let echoing = map.add(tcp_echo().await?);
    let (relay, mut terminate) = setup(&map, WssServerLimits::default()).await?;
    let (done, max) = watch_buffered(&terminate.stats);
    let client = relay.client(WssStreamLimits::default(), &Token::new("t"))?;
    let other = client.open_tcp(echoing).await?;
    write_until_closed(client.open_tcp(stalled).await?, 24 * 1024 * 1024).await?;
    done.store(true, Ordering::Relaxed);
    let max = max.await?;
    assert!(max <= 4 * 1024 * 1024, "{max} bytes buffered");
    assert!(max > 0);
    until("the stalled stream's buffers released", || {
        terminate.stats.buffered() == 0
    })
    .await?;
    assert!(terminate.stats.overflows() >= 1);
    echo(other, 5, 256 * 1024).await?;
    let overflowed = terminate.closed(WssCloseReason::Overflow).await?;
    assert_eq!(overflowed.target, stalled);
    relay.check_wire()?;
    terminate.stop().await
}

/// The session budget bounds all streams together (ns `MAX_SESSION_BUFFER_BYTES`): two
/// stalled streams under a 1 MiB session budget never hold more, and each is closed; a
/// third stream goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_budget_bounds_all_streams() -> TestResult {
    let map = Map::new();
    let stall = tcp_stall().await?;
    let stalled = map.add(stall);
    let echoing = map.add(tcp_echo().await?);
    let cap = 1024 * 1024;
    let (relay, mut terminate) =
        setup(&map, WssServerLimits::default().session_buffer(cap)).await?;
    let (done, max) = watch_buffered(&terminate.stats);
    let client = relay.client(WssStreamLimits::default(), &Token::new("t"))?;
    let other = client.open_tcp(echoing).await?;
    let a = tokio::spawn(write_until_closed(
        client.open_tcp(stalled).await?,
        24 * 1024 * 1024,
    ));
    let b = tokio::spawn(write_until_closed(
        client.open_tcp(stalled).await?,
        24 * 1024 * 1024,
    ));
    a.await??;
    b.await??;
    done.store(true, Ordering::Relaxed);
    let max = max.await?;
    assert!(max <= cap, "{max} bytes buffered");
    assert!(terminate.stats.overflows() >= 2);
    echo(other, 6, 256 * 1024).await?;
    for _ in 0..2 {
        terminate.closed(WssCloseReason::Overflow).await?;
    }
    relay.check_wire()?;
    terminate.stop().await
}

/// The relay drops the server's session: its streams close (reported), the server dials
/// again after the backoff, and new streams of the same client session run through the
/// new server session. The client's CLOSE of a stream the new session never knew is
/// acknowledged all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_reconnects_after_the_relay_drops_it() -> TestResult {
    let map = Map::new();
    let target = map.add(tcp_echo().await?);
    let udp_target = map.add(udp_echo().await?);
    let (relay, mut terminate) = setup(&map, WssServerLimits::default()).await?;
    let client = relay.client(WssStreamLimits::default(), &Token::new("t"))?;
    let old = echo(client.open_tcp(target).await?, 1, 1000).await?;
    let mut flow = client.open_udp(udp_target).await?;
    udp_round_trips(&mut flow, 1, 2).await?;

    relay.kick_servers.send_modify(|n| *n += 1);
    timeout(
        WAIT,
        terminate.state.wait_for(|s| *s == LinkState::Disconnected),
    )
    .await??;
    terminate.connected().await?;
    assert_eq!(terminate.stats.sessions(), 2);
    let mut ended = Vec::new();
    for event in terminate.events() {
        if let WssStreamEventKind::Close { reason, .. } = event.kind {
            ended.push((event.session, event.stream_id, reason));
        }
    }
    ended.sort_unstable_by_key(|&(_, id, _)| id);
    assert_eq!(
        ended,
        [
            (1, 1, WssCloseReason::SessionEnded),
            (1, 2, WssCloseReason::SessionEnded)
        ]
    );

    let stream = client.open_tcp(target).await?;
    assert_eq!(stream.stream_id(), 3);
    echo(stream, 2, 100_000).await?;
    let mut flow = client.open_udp(udp_target).await?;
    udp_round_trips(&mut flow, 2, 2).await?;
    let open = terminate.event().await?;
    assert_eq!((open.session, open.stream_id), (2, 3));

    drop(old);
    until("the new session's CLOSE_ACK of the old stream", || {
        relay.saw(0, Role::Server, &WsFrame::close_ack(1))
    })
    .await?;
    assert_eq!(relay.upgrades(Role::Server).len(), 2);
    assert_eq!(client.stats().sessions(), 1);
    relay.check_wire()?;
    terminate.stop().await
}

/// A lost client session fails its streams and flows; the next open dials a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_session_loss_fails_flows_and_the_next_open_redials() -> TestResult {
    let map = Map::new();
    let tcp_target = map.add(tcp_echo().await?);
    let udp_target = map.add(udp_echo().await?);
    let (relay, mut terminate) = setup(&map, WssServerLimits::default()).await?;
    let client = relay.client(WssStreamLimits::default(), &Token::new("t"))?;
    let mut state = client.state();
    let mut stream = echo(client.open_tcp(tcp_target).await?, 1, 1000).await?;
    let mut flow = client.open_udp(udp_target).await?;
    udp_round_trips(&mut flow, 1, 2).await?;

    // A relay ends both legs of a pair: the server's session goes too.
    relay.kick_clients.send_modify(|n| *n += 1);
    relay.kick_servers.send_modify(|n| *n += 1);
    let mut buf = [0; 16];
    let err = timeout(WAIT, stream.read(&mut buf)).await?.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    let err = stream.write_all(b"x").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    let err = timeout(WAIT, flow.recv()).await?.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    timeout(WAIT, state.wait_for(|s| *s == LinkState::Disconnected)).await??;
    assert!(!client.stats().connected());
    until("the server's second session", || {
        terminate.stats.sessions() == 2 && terminate.stats.connected()
    })
    .await?;
    terminate.connected().await?;

    let stream = client.open_tcp(tcp_target).await?;
    assert_eq!(stream.stream_id(), 1);
    echo(stream, 2, 100_000).await?;
    let mut flow = client.open_udp(udp_target).await?;
    udp_round_trips(&mut flow, 2, 2).await?;
    assert_eq!(relay.upgrades(Role::Client).len(), 2);
    let stats = client.stats();
    assert_eq!((stats.sessions(), stats.active_sessions()), (2, 1));
    assert_eq!(*state.borrow(), LinkState::Connected);
    relay.check_wire()?;
    terminate.stop().await
}

/// 401 and 403 on the session dial: the client's open fails, the server reports
/// `Rejected`; after a 401 both wait for a new token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejections_on_the_session_dial() -> TestResult {
    let map = Map::new();
    let target = map.add(tcp_echo().await?);
    let relay = Relay::start().await?;
    *lock(&relay.token) = Some("good".to_owned());
    let server_token = Token::new("bad");
    let mut terminate = relay.server(0, WssServerLimits::default(), &map, &server_token)?;
    timeout(
        WAIT,
        terminate.state.wait_for(|s| *s == LinkState::Rejected(401)),
    )
    .await??;
    assert_eq!(terminate.stats.rejected_unauthorized(), 1);
    assert!(!terminate.stats.connected());
    server_token.set("good");
    terminate.connected().await?;
    let server_upgrades = relay.upgrades(Role::Server);
    assert_eq!(
        server_upgrades[0].authorization.as_deref(),
        Some("Bearer bad")
    );
    assert_eq!(
        server_upgrades.last().and_then(|u| u.authorization.clone()),
        Some("Bearer good".to_owned())
    );

    let token = Token::new("bad");
    let client = relay.client(WssStreamLimits::default(), &token)?;
    let state = client.state();
    let stats = client.stats();
    let err = client.open_tcp(target).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(*state.borrow(), LinkState::Rejected(401));
    assert_eq!(stats.rejected_unauthorized(), 1);
    token.set("good");
    echo(client.open_tcp(target).await?, 1, 1000).await?;
    let upgrades = relay.upgrades(Role::Client);
    assert_eq!(upgrades.len(), 2);
    assert_eq!(upgrades[0].authorization.as_deref(), Some("Bearer bad"));
    assert_eq!(upgrades[1].authorization.as_deref(), Some("Bearer good"));
    assert_eq!(*state.borrow(), LinkState::Connected);

    // A fresh client and server against a relay that forbids.
    relay.forbid.store(true, Ordering::SeqCst);
    let client = relay.client(WssStreamLimits::default(), &token)?;
    let err = client.connect().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(*client.state().borrow(), LinkState::Rejected(403));
    assert_eq!(client.stats().rejected_forbidden(), 1);
    assert_eq!(client.stats().connect_failures(), 1);
    let mut forbidden = relay.server(1, WssServerLimits::default(), &map, &token)?;
    timeout(
        WAIT,
        forbidden.state.wait_for(|s| *s == LinkState::Rejected(403)),
    )
    .await??;
    assert_eq!(forbidden.stats.rejected_forbidden(), 1);
    relay.forbid.store(false, Ordering::SeqCst);
    forbidden.connected().await?;
    echo(client.open_tcp(target).await?, 2, 1000).await?;
    assert_eq!(client.stats().sessions(), 1);
    relay.check_wire()?;
    forbidden.stop().await?;
    terminate.stop().await
}

/// With room for two streams per client session, the third goes to a second session,
/// served by a second server (slot 1); once a stream of the first is closed and
/// acknowledged, the next open uses the freed room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overflow_streams_go_to_another_session() -> TestResult {
    let map = Map::new();
    let tcp_target = map.add(tcp_echo().await?);
    let udp_target = map.add(udp_echo().await?);
    let (relay, first) = setup(&map, WssServerLimits::default()).await?;
    let mut second = relay.server(1, WssServerLimits::default(), &map, &Token::new("t"))?;
    second.connected().await?;
    let limits = WssStreamLimits::default().max_streams_per_session(2);
    let client = relay.client(limits, &Token::new("t"))?;
    let a = client.open_tcp(tcp_target).await?;
    let mut b = client.open_udp(udp_target).await?;
    assert_eq!(relay.upgrades(Role::Client).len(), 1);
    let c = client.open_tcp(tcp_target).await?;
    assert_eq!(relay.upgrades(Role::Client).len(), 2);
    assert_eq!((a.stream_id(), b.stream_id(), c.stream_id()), (1, 2, 1));
    let mut a = echo(a, 1, 100_000).await?;
    udp_round_trips(&mut b, 2, 3).await?;
    let c = echo(c, 3, 100_000).await?;
    let pairs = |relay: &Relay| -> Vec<(usize, u32)> {
        relay
            .opens()
            .iter()
            .map(|&(slot, id, ..)| (slot, id))
            .collect()
    };
    assert_eq!(pairs(&relay), [(0, 1), (0, 2), (1, 1)]);

    a.shutdown().await?;
    assert_eq!(read_to_end(&mut a).await?, b"");
    drop(a);
    let d = client.open_tcp(tcp_target).await?;
    until("the fourth OPEN", || relay.opens().len() == 4).await?;
    assert_eq!(relay.upgrades(Role::Client).len(), 2);
    assert_eq!(
        relay.opens().last(),
        Some(&(0, 3, tcp_target, Protocol::Tcp))
    );
    echo(d, 4, 100_000).await?;
    echo(c, 5, 1000).await?;
    let stats = client.stats();
    assert_eq!((stats.sessions(), stats.active_sessions()), (2, 2));
    assert_eq!(first.stats.streams_opened(), 3);
    assert_eq!(second.stats.streams_opened(), 1);
    relay.check_wire()?;
    second.stop().await?;
    first.stop().await
}

/// Dropping a server's run future (instead of its shutdown) ends its session at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_run_ends_the_session() -> TestResult {
    let map = Map::new();
    let target = map.add(tcp_echo().await?);
    let (relay, terminate) = setup(&map, WssServerLimits::default()).await?;
    let client = relay.client(WssStreamLimits::default(), &Token::new("t"))?;
    let mut stream = echo(client.open_tcp(target).await?, 1, 1000).await?;
    let mut state = terminate.state.clone();
    let stats = Arc::clone(&terminate.stats);
    terminate.run.abort();
    timeout(WAIT, state.wait_for(|s| *s == LinkState::Disconnected)).await??;
    assert!(!stats.connected());
    until("the relay to drop the server session", || {
        lock(&relay.servers).is_empty()
    })
    .await?;
    // The stream got no CLOSE: the client end stays open until its own session ends.
    stream.write_all(b"x").await?;
    assert_eq!(relay.opens().len(), 1);
    Ok(())
}
