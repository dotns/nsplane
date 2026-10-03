//! `WssStreamClient` TCP streams and UDP flows through a minimal test terminate: a TLS
//! WebSocket server that decodes OPEN (checking its bytes against the ns layout),
//! connects to local TCP and UDP targets, relays DATA and answers CLOSE with `CLOSE_ACK`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{BoxFuture, LinkState};
use nsplane_e2e::{TestResult, WAIT};
use nsplane_wss::frame::{self, FrameCommand, Protocol, WsFrame};
use nsplane_wss::{
    BearerProvider, WssConfig, WssStreamClient, WssStreamLimits, WssTcpStream, WssTls, WssUdpFlow,
};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

/// The terminate's certificate name.
const NAME: &str = "terminate.test";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One WebSocket upgrade the terminate saw.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Upgrade {
    authorization: Option<String>,
    accepted: bool,
}

/// A frame the terminate received, by the index of its session.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Open {
        session: usize,
        stream_id: u32,
        target: SocketAddr,
        protocol: Protocol,
    },
    Close {
        session: usize,
        stream_id: u32,
    },
    CloseAck {
        session: usize,
        stream_id: u32,
    },
}

/// The ns layout of an OPEN (`proxy/wire.rs` `build_open_frame`, and its IPv6 form in
/// `tunnel-ws`).
fn ns_open(stream_id: u32, target: SocketAddr, protocol: Protocol) -> Vec<u8> {
    let mut frame = stream_id.to_be_bytes().to_vec();
    match target.ip() {
        IpAddr::V4(ip) => {
            frame.push(0x01);
            frame.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            frame.push(0x02);
            frame.extend_from_slice(&ip.octets());
        }
    }
    frame.extend_from_slice(&target.port().to_be_bytes());
    frame.push(match protocol {
        Protocol::Tcp => 0x00,
        Protocol::Udp => 0x01,
    });
    frame
}

/// The streams of one terminate session: where their DATA goes, and their relay task.
type Streams = HashMap<u32, (mpsc::UnboundedSender<Bytes>, tokio::task::JoinHandle<()>)>;

/// The test terminate.
struct Terminate {
    addr: SocketAddr,
    roots: RootCertStore,
    upgrades: Mutex<Vec<Upgrade>>,
    /// Upgrades without `Authorization: Bearer <this>` are answered 401.
    token: Mutex<Option<String>>,
    /// Upgrades are answered 403 while set.
    forbid: AtomicBool,
    /// Bumped to drop every session.
    kick: watch::Sender<u64>,
    events: Mutex<Vec<Event>>,
    /// OPENs whose bytes differ from the ns layout.
    bad_opens: Mutex<Vec<Vec<u8>>>,
    /// Per session, where to send a CLOSE of a stream id to the client.
    closers: Mutex<Vec<mpsc::Sender<u32>>>,
}

impl Terminate {
    async fn start() -> TestResult<Arc<Self>> {
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
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let terminate = Arc::new(Self {
            addr: listener.local_addr()?,
            roots,
            upgrades: Mutex::new(Vec::new()),
            token: Mutex::new(None),
            forbid: AtomicBool::new(false),
            kick: watch::Sender::new(0),
            events: Mutex::new(Vec::new()),
            bad_opens: Mutex::new(Vec::new()),
            closers: Mutex::new(Vec::new()),
        });
        let accepting = Arc::clone(&terminate);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(Arc::clone(&accepting).serve(tcp, acceptor.clone()));
            }
        });
        Ok(terminate)
    }

    /// A client of this terminate within `limits`, with the bearer `token`.
    fn client(&self, limits: WssStreamLimits, token: &Arc<Token>) -> TestResult<WssStreamClient> {
        let config = WssConfig::new(
            format!("wss://{NAME}:{}/client", self.addr.port()),
            WssTls::Roots(self.roots.clone()),
        )
        .connect_addr(self.addr)
        .bearer(Arc::clone(token) as Arc<dyn BearerProvider>)
        .backoff(Duration::from_millis(50), Duration::from_millis(200))
        .token_refresh(Duration::from_millis(50), WAIT)
        .keepalive(Duration::from_millis(100), Duration::from_millis(600))
        .connect_timeout(Duration::from_secs(2));
        Ok(WssStreamClient::new(config, limits)?)
    }

    fn refusal(&self, req: &Request) -> Option<u16> {
        let authorization = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let status = if self.forbid.load(Ordering::SeqCst) {
            Some(403)
        } else {
            lock(&self.token)
                .as_ref()
                .filter(|token| authorization.as_deref() != Some(&format!("Bearer {token}")))
                .map(|_| 401)
        };
        lock(&self.upgrades).push(Upgrade {
            authorization,
            accepted: status.is_none(),
        });
        status
    }

    async fn serve(self: Arc<Self>, tcp: TcpStream, acceptor: TlsAcceptor) {
        let Ok(tls) = acceptor.accept(tcp).await else {
            return;
        };
        let Ok(ws) = tokio_tungstenite::accept_hdr_async(tls, Upgrader(&self)).await else {
            return;
        };
        let (closer, mut closes) = mpsc::channel(16);
        let session = {
            let mut closers = lock(&self.closers);
            closers.push(closer);
            closers.len() - 1
        };
        let (out, mut outgoing) = mpsc::channel::<Bytes>(1024);
        let mut streams = Streams::new();
        let mut kick = self.kick.subscribe();
        let (mut sink, mut source) = ws.split();
        loop {
            tokio::select! {
                message = source.next() => match message {
                    Some(Ok(Message::Binary(data))) => self.frame(session, &data, &mut streams, &out),
                    Some(Ok(_)) => {}
                    _ => break,
                },
                Some(frame) = outgoing.recv() => {
                    if sink.send(Message::Binary(frame)).await.is_err() {
                        break;
                    }
                }
                Some(id) = closes.recv() => {
                    if let Some((_, task)) = streams.remove(&id) {
                        task.abort();
                    }
                    if sink.send(Message::Binary(WsFrame::close(id).encode())).await.is_err() {
                        break;
                    }
                }
                _ = kick.changed() => break,
            }
        }
        for (_, task) in streams.values() {
            task.abort();
        }
    }

    fn frame(
        &self,
        session: usize,
        data: &Bytes,
        streams: &mut Streams,
        out: &mpsc::Sender<Bytes>,
    ) {
        let Ok(frame) = WsFrame::decode(data) else {
            return;
        };
        let stream_id = frame.stream_id;
        match frame.command {
            FrameCommand::Open { target, protocol } => {
                if data[..] != ns_open(stream_id, target, protocol)[..] {
                    lock(&self.bad_opens).push(data.to_vec());
                }
                lock(&self.events).push(Event::Open {
                    session,
                    stream_id,
                    target,
                    protocol,
                });
                let (tx, rx) = mpsc::unbounded_channel();
                let out = out.clone();
                let task = match protocol {
                    Protocol::Tcp => tokio::spawn(relay_tcp(stream_id, target, rx, out)),
                    Protocol::Udp => tokio::spawn(relay_udp(stream_id, target, rx, out)),
                };
                streams.insert(stream_id, (tx, task));
            }
            FrameCommand::Data => {
                if let Some((tx, _)) = streams.get(&stream_id) {
                    let _ = tx.send(frame.payload);
                }
            }
            FrameCommand::Close => {
                lock(&self.events).push(Event::Close { session, stream_id });
                // Dropping the sender lets the relay write what came before, end the
                // target's input and answer CLOSE_ACK.
                if streams.remove(&stream_id).is_none() {
                    let _ = out.try_send(WsFrame::close_ack(stream_id).encode());
                }
            }
            FrameCommand::CloseAck => {
                lock(&self.events).push(Event::CloseAck { session, stream_id });
                if let Some((_, task)) = streams.remove(&stream_id) {
                    task.abort();
                }
            }
        }
    }

    fn upgrades(&self) -> Vec<Upgrade> {
        lock(&self.upgrades).clone()
    }

    fn events(&self) -> Vec<Event> {
        lock(&self.events).clone()
    }

    /// The OPENs received, as (session, stream id, target, protocol).
    fn opens(&self) -> Vec<(usize, u32, SocketAddr, Protocol)> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::Open {
                    session,
                    stream_id,
                    target,
                    protocol,
                } => Some((session, stream_id, target, protocol)),
                _ => None,
            })
            .collect()
    }

    /// Sends the client a CLOSE of `stream_id` on session `session`.
    async fn close(&self, session: usize, stream_id: u32) -> TestResult {
        let closer = lock(&self.closers)[session].clone();
        closer.send(stream_id).await.map_err(|_| "session gone")?;
        Ok(())
    }

    fn check_opens(&self) -> TestResult {
        let bad = lock(&self.bad_opens).clone();
        if bad.is_empty() {
            Ok(())
        } else {
            Err(format!("OPEN bytes differ from the ns layout: {bad:?}").into())
        }
    }
}

struct Upgrader<'a>(&'a Terminate);

impl Callback for Upgrader<'_> {
    fn on_request(self, req: &Request, response: Response) -> Result<Response, ErrorResponse> {
        let Some(status) = self.0.refusal(req) else {
            return Ok(response);
        };
        let mut refused = ErrorResponse::new(None);
        *refused.status_mut() = status.try_into().unwrap_or_default();
        Err(refused)
    }
}

/// Relays one TCP stream: DATA to the target, the target's bytes back as DATA. The end of
/// the client's DATA (its CLOSE) ends the target's input and is answered with `CLOSE_ACK`;
/// the target's EOF is sent as CLOSE.
async fn relay_tcp(
    id: u32,
    target: SocketAddr,
    mut rx: mpsc::UnboundedReceiver<Bytes>,
    out: mpsc::Sender<Bytes>,
) {
    let Ok(tcp) = TcpStream::connect(target).await else {
        let _ = out.send(WsFrame::close(id).encode()).await;
        return;
    };
    let (mut read, mut write) = tcp.into_split();
    // Both directions run at once: an echo target only reads while its writes drain.
    let to_target = async {
        while let Some(data) = rx.recv().await {
            if write.write_all(&data).await.is_err() {
                return false;
            }
        }
        let _ = write.shutdown().await;
        true
    };
    let from_target = async {
        let mut buf = vec![0; 65_536];
        while let Ok(n @ 1..) = read.read(&mut buf).await {
            if out.send(frame::encode_data(id, &buf[..n])).await.is_err() {
                return;
            }
        }
    };
    let reply = tokio::select! {
        closed = to_target => if closed { WsFrame::close_ack(id) } else { WsFrame::close(id) },
        () = from_target => WsFrame::close(id),
    };
    let _ = out.send(reply.encode()).await;
}

/// Relays one UDP flow: one datagram per DATA frame.
async fn relay_udp(
    id: u32,
    target: SocketAddr,
    mut rx: mpsc::UnboundedReceiver<Bytes>,
    out: mpsc::Sender<Bytes>,
) {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
        return;
    };
    if socket.connect(target).await.is_err() {
        return;
    }
    let mut buf = vec![0; 65_536];
    loop {
        tokio::select! {
            data = rx.recv() => {
                let Some(data) = data else {
                    let _ = out.send(WsFrame::close_ack(id).encode()).await;
                    return;
                };
                let _ = socket.send(&data).await;
            }
            n = socket.recv(&mut buf) => match n {
                Ok(n) => {
                    if out.send(frame::encode_data(id, &buf[..n])).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            },
        }
    }
}

/// A TCP echo target.
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

/// A TCP target that reads each connection to its end and reports the bytes.
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

/// A UDP echo target.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_echo_of_a_large_payload() -> TestResult {
    let terminate = Terminate::start().await?;
    let target = tcp_echo().await?;
    let client = terminate.client(WssStreamLimits::default(), &Token::new("t"))?;
    let mut state = client.state();
    let stream = client.open_tcp(target).await?;
    assert_eq!(stream.stream_id(), 1);
    assert_eq!(stream.target(), target);
    timeout(WAIT, state.wait_for(|s| *s == LinkState::Connected)).await??;

    let len = 8 * 1024 * 1024;
    let mut stream = echo(stream, 3, len).await?;
    stream.shutdown().await?;
    assert_eq!(read_to_end(&mut stream).await?, b"");

    let stats = client.stats();
    assert_eq!(stats.tx_bytes(), len as u64);
    assert_eq!(stats.rx_bytes(), len as u64);
    assert_eq!(stats.overflows(), 0);
    assert_eq!(stats.sessions(), 1);
    assert_eq!(terminate.opens(), [(0, 1, target, Protocol::Tcp)]);
    assert_eq!(
        terminate.upgrades(),
        [Upgrade {
            authorization: Some("Bearer t".to_owned()),
            accepted: true
        }]
    );
    terminate.check_opens()
}

/// Many TCP streams and UDP flows share one session (one upgrade); a CLOSE of one stream
/// from either side leaves the others transferring.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_streams_and_flows_share_one_session() -> TestResult {
    let terminate = Terminate::start().await?;
    let (tcp_target, udp_target) = (tcp_echo().await?, udp_echo().await?);
    let client = terminate.client(WssStreamLimits::default(), &Token::new("t"))?;
    client.connect().await?;

    let mut streams = Vec::new();
    for _ in 0..8 {
        streams.push(client.open_tcp(tcp_target).await?);
    }
    let mut flows = Vec::new();
    for _ in 0..4 {
        flows.push(client.open_udp(udp_target).await?);
    }
    let mut ids: Vec<u32> = streams.iter().map(WssTcpStream::stream_id).collect();
    ids.extend(flows.iter().map(WssUdpFlow::stream_id));
    assert_eq!(ids, (1..=12).collect::<Vec<u32>>());

    let echoes = streams
        .into_iter()
        .enumerate()
        .map(|(i, stream)| tokio::spawn(echo(stream, byte(i), 512 * 1024)));
    let udp = flows.into_iter().enumerate().map(|(i, mut flow)| {
        tokio::spawn(async move { udp_round_trips(&mut flow, byte(i), 10).await.map(|()| flow) })
    });
    let udp: Vec<_> = udp.collect();
    let mut streams = Vec::new();
    for echo in echoes {
        streams.push(echo.await??);
    }
    let mut flows = Vec::new();
    for flow in udp {
        flows.push(flow.await??);
    }

    // The client closes stream 1; the terminate closes stream 2.
    let mut first = streams.remove(0);
    first.shutdown().await?;
    assert_eq!(read_to_end(&mut first).await?, b"");
    let mut second = streams.remove(0);
    terminate.close(0, second.stream_id()).await?;
    assert_eq!(read_to_end(&mut second).await?, b"");
    until("CLOSE_ACK of stream 2", || {
        terminate.events().contains(&Event::CloseAck {
            session: 0,
            stream_id: 2,
        })
    })
    .await?;
    assert!(terminate.events().contains(&Event::Close {
        session: 0,
        stream_id: 1
    }));
    drop((first, second));

    // The others keep transferring.
    let echoes: Vec<_> = streams
        .into_iter()
        .enumerate()
        .map(|(i, stream)| tokio::spawn(echo(stream, byte(100 + i), 256 * 1024)))
        .collect();
    for echo in echoes {
        echo.await??;
    }
    for (i, flow) in flows.iter_mut().enumerate() {
        udp_round_trips(flow, byte(50 + i), 5).await?;
    }

    assert_eq!(terminate.upgrades().len(), 1);
    let stats = client.stats();
    assert_eq!((stats.sessions(), stats.active_sessions()), (1, 1));
    assert_eq!(stats.streams_opened(), 12);
    assert_eq!(stats.overflows(), 0);
    let opens = terminate.opens();
    assert_eq!(opens.len(), 12);
    for (i, &(session, id, target, protocol)) in opens.iter().enumerate() {
        let tcp = i < 8;
        assert_eq!(session, 0);
        assert_eq!(id, ids[i]);
        assert_eq!(target, if tcp { tcp_target } else { udp_target });
        assert_eq!(protocol, if tcp { Protocol::Tcp } else { Protocol::Udp });
    }
    terminate.check_opens()
}

/// A shutdown delivers what was written before it, and the target sees EOF; the stream
/// reads on until the terminate acknowledges.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_close_delivers_the_data_then_eof() -> TestResult {
    let terminate = Terminate::start().await?;
    let (target, mut received) = tcp_sink().await?;
    let client = terminate.client(WssStreamLimits::default(), &Token::new("t"))?;
    let mut stream = client.open_tcp(target).await?;
    let data = pattern(9, 300 * 1024);
    stream.write_all(&data).await?;
    stream.shutdown().await?;
    let got = timeout(WAIT, received.recv()).await?.ok_or("sink gone")?;
    assert_eq!(got.len(), data.len());
    assert_eq!(got, data);
    assert_eq!(read_to_end(&mut stream).await?, b"");
    assert!(stream.write_all(b"more").await.is_err());
    assert_eq!(
        terminate.events().last(),
        Some(&Event::Close {
            session: 0,
            stream_id: 1
        })
    );
    terminate.check_opens()
}

/// A CLOSE from the terminate reads as EOF and is answered with `CLOSE_ACK`; the target's
/// own EOF arrives as a CLOSE too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_close_is_eof_and_acknowledged() -> TestResult {
    let terminate = Terminate::start().await?;
    let target = tcp_echo().await?;
    let client = terminate.client(WssStreamLimits::default(), &Token::new("t"))?;
    let mut stream = echo(client.open_tcp(target).await?, 1, 1000).await?;
    terminate.close(0, stream.stream_id()).await?;
    assert_eq!(read_to_end(&mut stream).await?, b"");
    until("CLOSE_ACK", || {
        terminate.events().contains(&Event::CloseAck {
            session: 0,
            stream_id: 1,
        })
    })
    .await?;
    let err = stream.write_all(b"x").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

    // A target that refuses the connection: the terminate closes the stream.
    let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let refused = closed.local_addr()?;
    drop(closed);
    let mut stream = client.open_tcp(refused).await?;
    assert_eq!(stream.stream_id(), 2);
    assert_eq!(read_to_end(&mut stream).await?, b"");
    until("CLOSE_ACK of the refused stream", || {
        terminate.events().contains(&Event::CloseAck {
            session: 0,
            stream_id: 2,
        })
    })
    .await?;
    assert_eq!(client.stats().streams_closed(), 2);
    terminate.check_opens()
}

/// A lost session fails its streams and flows; the next open dials a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_loss_fails_flows_and_the_next_open_redials() -> TestResult {
    let terminate = Terminate::start().await?;
    let (tcp_target, udp_target) = (tcp_echo().await?, udp_echo().await?);
    let client = terminate.client(WssStreamLimits::default(), &Token::new("t"))?;
    let mut state = client.state();
    let mut stream = echo(client.open_tcp(tcp_target).await?, 1, 1000).await?;
    let mut flow = client.open_udp(udp_target).await?;
    udp_round_trips(&mut flow, 1, 2).await?;

    terminate.kick.send_modify(|n| *n += 1);
    let mut buf = [0; 16];
    let err = timeout(WAIT, stream.read(&mut buf)).await?.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    let err = stream.write_all(b"x").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    let err = timeout(WAIT, flow.recv()).await?.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    timeout(WAIT, state.wait_for(|s| *s == LinkState::Disconnected)).await??;
    assert!(!client.stats().connected());

    let stream = client.open_tcp(tcp_target).await?;
    assert_eq!(stream.stream_id(), 1);
    echo(stream, 2, 100_000).await?;
    let mut flow = client.open_udp(udp_target).await?;
    udp_round_trips(&mut flow, 2, 2).await?;
    assert_eq!(terminate.upgrades().len(), 2);
    let stats = client.stats();
    assert_eq!((stats.sessions(), stats.active_sessions()), (2, 1));
    assert_eq!(*state.borrow(), LinkState::Connected);
    terminate.check_opens()
}

/// 401 and 403 on the session dial fail the open and are reported; the dial after a 401
/// waits for a new token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejections_on_the_session_dial() -> TestResult {
    let terminate = Terminate::start().await?;
    let target = tcp_echo().await?;
    *lock(&terminate.token) = Some("good".to_owned());
    let token = Token::new("bad");
    let client = terminate.client(WssStreamLimits::default(), &token)?;
    let state = client.state();
    let stats = client.stats();

    let err = client.open_tcp(target).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(*state.borrow(), LinkState::Rejected(401));
    assert_eq!(stats.rejected_unauthorized(), 1);
    token.set("good");
    echo(client.open_tcp(target).await?, 1, 1000).await?;
    let upgrades = terminate.upgrades();
    assert_eq!(upgrades.len(), 2);
    assert_eq!(upgrades[0].authorization.as_deref(), Some("Bearer bad"));
    assert_eq!(upgrades[1].authorization.as_deref(), Some("Bearer good"));
    assert_eq!(*state.borrow(), LinkState::Connected);

    // A fresh client against a terminate that forbids.
    terminate.forbid.store(true, Ordering::SeqCst);
    let client = terminate.client(WssStreamLimits::default(), &token)?;
    let err = client.connect().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(*client.state().borrow(), LinkState::Rejected(403));
    assert_eq!(client.stats().rejected_forbidden(), 1);
    assert_eq!(client.stats().connect_failures(), 1);
    terminate.forbid.store(false, Ordering::SeqCst);
    echo(client.open_tcp(target).await?, 2, 1000).await?;
    assert_eq!(client.stats().sessions(), 1);
    terminate.check_opens()
}

/// With room for two streams per session, the third goes to a second session; once a
/// stream of the first is closed and acknowledged, the next open uses the freed room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overflow_streams_go_to_another_session() -> TestResult {
    let terminate = Terminate::start().await?;
    let (tcp_target, udp_target) = (tcp_echo().await?, udp_echo().await?);
    let limits = WssStreamLimits::default().max_streams_per_session(2);
    let client = terminate.client(limits, &Token::new("t"))?;
    let a = client.open_tcp(tcp_target).await?;
    let mut b = client.open_udp(udp_target).await?;
    assert_eq!(terminate.upgrades().len(), 1);
    let c = client.open_tcp(tcp_target).await?;
    assert_eq!(terminate.upgrades().len(), 2);
    assert_eq!((a.stream_id(), b.stream_id(), c.stream_id()), (1, 2, 1));
    let mut a = echo(a, 1, 100_000).await?;
    udp_round_trips(&mut b, 2, 3).await?;
    let c = echo(c, 3, 100_000).await?;
    assert_eq!(
        terminate
            .opens()
            .iter()
            .map(|&(session, id, ..)| (session, id))
            .collect::<Vec<_>>(),
        [(0, 1), (0, 2), (1, 1)]
    );

    a.shutdown().await?;
    assert_eq!(read_to_end(&mut a).await?, b"");
    drop(a);
    let d = client.open_tcp(tcp_target).await?;
    until("the fourth OPEN", || terminate.opens().len() == 4).await?;
    assert_eq!(terminate.upgrades().len(), 2);
    assert_eq!(
        terminate.opens().last(),
        Some(&(0, 3, tcp_target, Protocol::Tcp))
    );
    echo(d, 4, 100_000).await?;
    echo(c, 5, 1000).await?;
    let stats = client.stats();
    assert_eq!((stats.sessions(), stats.active_sessions()), (2, 2));
    terminate.check_opens()
}
