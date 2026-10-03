//! Engines on `LinkTransport`s dialed by `WssDialer` through a local TLS WebSocket relay:
//! traffic and keepalive, 401 and 403 rejections, relay loss and a silent relay.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{BoxFuture, LinkConfig, LinkState, LinkTransport, TransportId};
use nsplane_e2e::{Node, Options, TestResult, WAIT, exchange, introduce};
use nsplane_wss::{BearerProvider, WssConfig, WssDialer, WssStats, WssTls};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

/// The id of every node's link transport.
const LINK: TransportId = TransportId::new(1);
/// The relay's certificate name.
const NAME: &str = "relay.test";
/// The ping interval of the test links.
const PING: Duration = Duration::from_millis(100);
/// The read idle of the test links.
const IDLE: Duration = Duration::from_millis(600);

/// The address of the node with key seed `seed` (side `seed - 1` of the relay).
fn addr(seed: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, seed], 1000 + u16::from(seed)))
}

/// Locks `mutex`; a test that panicked holding it fails on its own.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One WebSocket upgrade the relay saw.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Upgrade {
    side: usize,
    authorization: Option<String>,
    node: Option<String>,
    accepted: bool,
}

/// A TLS WebSocket relay between two sides (URL paths `/0` and `/1`): binary messages from
/// one side's current connection go to the other side's.
struct Relay {
    addr: SocketAddr,
    roots: RootCertStore,
    /// Per side, the sender into its current connection.
    links: Mutex<[Option<mpsc::Sender<Message>>; 2]>,
    upgrades: Mutex<Vec<Upgrade>>,
    /// Upgrades without `Authorization: Bearer <this>` are answered 401.
    token: Mutex<Option<String>>,
    /// Per side, upgrades are answered 403 while set.
    forbid: [AtomicBool; 2],
    /// Per side, bumped to drop the current connection.
    kick: [watch::Sender<u64>; 2],
    /// Per side, bumped to make the current connection silent: it neither reads nor
    /// writes (no pongs) from then on.
    freeze: [watch::Sender<u64>; 2],
}

impl Relay {
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
        let relay = Arc::new(Self {
            addr: listener.local_addr()?,
            roots,
            links: Mutex::new([None, None]),
            upgrades: Mutex::new(Vec::new()),
            token: Mutex::new(None),
            forbid: [AtomicBool::new(false), AtomicBool::new(false)],
            kick: [watch::Sender::new(0), watch::Sender::new(0)],
            freeze: [watch::Sender::new(0), watch::Sender::new(0)],
        });
        let accepting = Arc::clone(&relay);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(Arc::clone(&accepting).serve(tcp, acceptor.clone()));
            }
        });
        Ok(relay)
    }

    /// The status refusing an upgrade request of `side` (`None`: an unknown path), or
    /// `None` to accept it.
    fn refusal(&self, req: &Request, side: Option<usize>) -> Option<u16> {
        let header = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let authorization = header("authorization");
        let status = match side {
            None => Some(404),
            Some(side) if self.forbid[side].load(Ordering::SeqCst) => Some(403),
            Some(_) => lock(&self.token)
                .as_ref()
                .filter(|token| authorization.as_deref() != Some(&format!("Bearer {token}")))
                .map(|_| 401),
        };
        if let Some(side) = side {
            lock(&self.upgrades).push(Upgrade {
                side,
                authorization,
                node: header("x-node"),
                accepted: status.is_none(),
            });
        }
        status
    }

    async fn serve(self: Arc<Self>, tcp: TcpStream, acceptor: TlsAcceptor) {
        let Ok(tls) = acceptor.accept(tcp).await else {
            return;
        };
        let mut side = None;
        let upgrader = Upgrader {
            relay: &self,
            side: &mut side,
        };
        let Ok(ws) = tokio_tungstenite::accept_hdr_async(tls, upgrader).await else {
            return;
        };
        let Some(side) = side else {
            return;
        };
        let (tx, mut rx) = mpsc::channel(1024);
        let mut kick = self.kick[side].subscribe();
        let mut freeze = self.freeze[side].subscribe();
        lock(&self.links)[side] = Some(tx);
        let (mut sink, mut stream) = ws.split();
        loop {
            tokio::select! {
                message = stream.next() => match message {
                    Some(Ok(Message::Binary(data))) => {
                        let to = lock(&self.links)[1 - side].clone();
                        if let Some(to) = to {
                            let _ = to.try_send(Message::Binary(data));
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => return,
                },
                Some(message) = rx.recv() => {
                    if sink.send(message).await.is_err() {
                        return;
                    }
                }
                _ = kick.changed() => return,
                _ = freeze.changed() => {
                    // Hold the connection open without touching it.
                    let _ = kick.changed().await;
                    return;
                }
            }
        }
    }

    /// Sends `message` to the current connection of `side`.
    async fn send(&self, side: usize, message: Message) -> TestResult {
        let link = lock(&self.links)[side].clone().ok_or("no connection")?;
        link.send(message).await.map_err(|_| "connection gone")?;
        Ok(())
    }

    fn upgrades(&self, side: usize) -> Vec<Upgrade> {
        lock(&self.upgrades)
            .iter()
            .filter(|upgrade| upgrade.side == side)
            .cloned()
            .collect()
    }
}

/// Answers the upgrade request of one relay connection and records its side.
struct Upgrader<'a> {
    relay: &'a Relay,
    side: &'a mut Option<usize>,
}

impl Callback for Upgrader<'_> {
    fn on_request(self, req: &Request, response: Response) -> Result<Response, ErrorResponse> {
        let side = match req.uri().path() {
            "/0" => Some(0),
            "/1" => Some(1),
            _ => None,
        };
        *self.side = side;
        let Some(status) = self.relay.refusal(req, side) else {
            return Ok(response);
        };
        let mut refused = ErrorResponse::new(None);
        *refused.status_mut() = status.try_into().unwrap_or_default();
        Err(refused)
    }
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

/// One node's side of the relay.
struct Side {
    stats: Arc<WssStats>,
    state: watch::Receiver<LinkState>,
    token: Arc<Token>,
}

impl Side {
    /// Waits until the link state is `state`.
    async fn until(&mut self, state: LinkState) -> TestResult {
        timeout(WAIT, self.state.wait_for(|s| *s == state))
            .await
            .map_err(|_| format!("{state:?} not within {WAIT:?}"))??;
        Ok(())
    }
}

/// The link transport of the node with seed `seed`, dialing side `seed - 1` of `relay`.
fn transport(relay: &Relay, seed: u8) -> TestResult<(LinkTransport, Side)> {
    let side = usize::from(seed - 1);
    // Node 1 connects to the relay's address with the certificate name in the URL; node 2
    // dials the IP address in its URL.
    let config = if side == 0 {
        WssConfig::new(
            format!("wss://{NAME}:{}/0", relay.addr.port()),
            WssTls::Roots(relay.roots.clone()),
        )
        .connect_addr(relay.addr)
    } else {
        WssConfig::new(
            format!("wss://{}/1", relay.addr),
            WssTls::Roots(relay.roots.clone()),
        )
    };
    let token = Token::new(&format!("token-{seed}"));
    let config = config
        .header("X-Node", format!("n{seed}"))
        .bearer(token.clone())
        .backoff(Duration::from_millis(50), Duration::from_millis(200))
        .token_refresh(Duration::from_millis(50), WAIT)
        .keepalive(PING, IDLE)
        .connect_timeout(Duration::from_secs(2));
    let dialer = WssDialer::new(config)?;
    let side = Side {
        stats: dialer.stats(),
        state: dialer.state(),
        token,
    };
    let transport = dialer.into_transport(LINK, addr(3 - seed), LinkConfig::default());
    Ok((transport, side))
}

/// Two nodes (seeds 1 and 2) on WSS link transports through `relay`, introduced to each
/// other.
async fn pair(relay: &Relay) -> TestResult<(Node<LinkTransport>, Node<LinkTransport>, [Side; 2])> {
    let (ta, sa) = transport(relay, 1)?;
    let (tb, sb) = transport(relay, 2)?;
    let a = Node::new(1, LINK, addr(1), ta, Options::default());
    let b = Node::new(2, LINK, addr(2), tb, Options::default());
    introduce(&a, &b, None).await?;
    Ok((a, b, [sa, sb]))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_and_transfer_over_wss() -> TestResult {
    let relay = Relay::start().await?;
    let (mut a, mut b, mut sides) = pair(&relay).await?;
    for side in &mut sides {
        side.until(LinkState::Connected).await?;
    }
    exchange(&mut a, &mut b).await?;
    for (i, side) in sides.iter().enumerate() {
        assert!(side.stats.connected());
        assert_eq!(side.stats.connects(), 1);
        assert_eq!(side.stats.connect_failures(), 0);
        assert!(side.stats.tx() > 0 && side.stats.rx() > 0);
        // The bearer and the extra header reach the relay.
        assert_eq!(
            relay.upgrades(i),
            [Upgrade {
                side: i,
                authorization: Some(format!("Bearer token-{}", i + 1)),
                node: Some(format!("n{}", i + 1)),
                accepted: true,
            }]
        );
    }

    // Text and oversized messages are dropped and counted; the link stays up.
    relay.send(0, Message::text("hello")).await?;
    relay
        .send(0, Message::Binary(Bytes::from(vec![0; 70_000])))
        .await?;
    until("drops", || {
        sides[0].stats.dropped_text() == 1 && sides[0].stats.dropped_oversized() == 1
    })
    .await?;

    // Pongs keep a link without traffic up past its read idle.
    sleep(IDLE * 2).await;
    for side in &sides {
        assert_eq!(side.stats.connects(), 1);
    }
    exchange(&mut a, &mut b).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthorized_waits_for_a_new_token() -> TestResult {
    let relay = Relay::start().await?;
    *lock(&relay.token) = Some("good".to_owned());
    let (mut a, mut b, mut sides) = pair(&relay).await?;
    sides[1].token.set("good");
    sides[0].until(LinkState::Rejected(401)).await?;
    sides[1].until(LinkState::Connected).await?;

    // The refused token is not tried again.
    sleep(Duration::from_millis(500)).await;
    let upgrades = relay.upgrades(0);
    assert_eq!(upgrades.len(), 1);
    assert!(!upgrades[0].accepted);
    assert_eq!(upgrades[0].authorization.as_deref(), Some("Bearer token-1"));
    assert_eq!(sides[0].stats.rejected_unauthorized(), 1);
    assert_eq!(*sides[0].state.borrow(), LinkState::Rejected(401));

    // A new token is dialed with at once.
    sides[0].token.set("good");
    sides[0].until(LinkState::Connected).await?;
    let upgrades = relay.upgrades(0);
    assert_eq!(upgrades.len(), 2);
    assert!(upgrades[1].accepted);
    assert_eq!(upgrades[1].authorization.as_deref(), Some("Bearer good"));
    exchange(&mut a, &mut b).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_backs_off_and_retries() -> TestResult {
    let relay = Relay::start().await?;
    relay.forbid[0].store(true, Ordering::SeqCst);
    let (mut a, mut b, mut sides) = pair(&relay).await?;
    sides[0].until(LinkState::Rejected(403)).await?;
    // A 403 is retried with the same token, backing off.
    // The relay records an upgrade before the dialer counts its refusal.
    until("403 retries", || {
        relay.upgrades(0).len() >= 3 && sides[0].stats.rejected_forbidden() >= 3
    })
    .await?;
    assert_eq!(sides[0].stats.rejected_unauthorized(), 0);
    assert!(!sides[0].stats.connected());

    relay.forbid[0].store(false, Ordering::SeqCst);
    sides[0].until(LinkState::Connected).await?;
    let upgrades = relay.upgrades(0);
    assert!(
        upgrades
            .iter()
            .all(|u| u.authorization.as_deref() == Some("Bearer token-1"))
    );
    assert!(upgrades.last().is_some_and(|u| u.accepted));
    exchange(&mut a, &mut b).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_drop_reconnects_and_traffic_resumes() -> TestResult {
    let relay = Relay::start().await?;
    let (mut a, mut b, mut sides) = pair(&relay).await?;
    sides[0].until(LinkState::Connected).await?;
    sides[1].until(LinkState::Connected).await?;
    exchange(&mut a, &mut b).await?;

    relay.kick[0].send_modify(|n| *n += 1);
    until("reconnect", || sides[0].stats.connects() == 2).await?;
    sides[0].until(LinkState::Connected).await?;
    assert_eq!(sides[1].stats.connects(), 1);
    exchange(&mut a, &mut b).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_relay_trips_the_idle_watchdog() -> TestResult {
    let relay = Relay::start().await?;
    let (mut a, mut b, mut sides) = pair(&relay).await?;
    sides[0].until(LinkState::Connected).await?;
    sides[1].until(LinkState::Connected).await?;
    exchange(&mut a, &mut b).await?;

    let frozen = Instant::now();
    relay.freeze[0].send_modify(|n| *n += 1);
    until("idle redial", || sides[0].stats.connects() == 2).await?;
    assert!(frozen.elapsed() >= IDLE);
    assert_eq!(relay.upgrades(0).len(), 2);
    assert_eq!(sides[1].stats.connects(), 1);
    exchange(&mut a, &mut b).await?;
    relay.kick[0].send_modify(|n| *n += 1);
    Ok(())
}
