//! Engines on `LinkTransport`s dialed by `WssDialer` over plain `ws://` URLs (no TLS)
//! through a local WebSocket relay, and the same URLs refused without `allow_plaintext`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{LinkConfig, LinkState, LinkTransport, TransportId};
use nsplane_e2e::{Node, Options, TestResult, WAIT, exchange, introduce};
use nsplane_wss::{WssConfig, WssDialer, WssStats, WssTls};
use rustls::RootCertStore;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

/// The id of every node's link transport.
const LINK: TransportId = TransportId::new(1);

/// The address of the node with key seed `seed`.
fn addr(seed: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, seed], 1000 + u16::from(seed)))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A plain WebSocket relay between two sides (URL paths `/0` and `/1`): binary messages
/// from one side's current connection go to the other side's.
struct Relay {
    addr: SocketAddr,
    /// Per side, the sender into its current connection.
    links: Mutex<[Option<mpsc::Sender<Message>>; 2]>,
}

impl Relay {
    async fn start() -> TestResult<Arc<Self>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay = Arc::new(Self {
            addr: listener.local_addr()?,
            links: Mutex::new([None, None]),
        });
        let accepting = Arc::clone(&relay);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(Arc::clone(&accepting).serve(tcp));
            }
        });
        Ok(relay)
    }

    async fn serve(self: Arc<Self>, tcp: TcpStream) {
        let mut side = None;
        let upgrade = Upgrader { side: &mut side };
        let Ok(ws) = tokio_tungstenite::accept_hdr_async(tcp, upgrade).await else {
            return;
        };
        let Some(side) = side else {
            return;
        };
        let (tx, mut rx) = mpsc::channel(1024);
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
            }
        }
    }

    /// The configuration of side `side`: a `ws://` URL with `allow_plaintext`.
    fn config(&self, side: usize) -> WssConfig {
        WssConfig::new(
            format!("ws://{}/{side}", self.addr),
            WssTls::Roots(RootCertStore::empty()),
        )
        .allow_plaintext(true)
        .backoff(Duration::from_millis(50), Duration::from_millis(200))
        .keepalive(Duration::from_millis(100), Duration::from_millis(600))
        .connect_timeout(Duration::from_secs(2))
    }
}

/// Records the side (URL path) of one relay connection.
struct Upgrader<'a> {
    side: &'a mut Option<usize>,
}

impl Callback for Upgrader<'_> {
    fn on_request(self, req: &Request, response: Response) -> Result<Response, ErrorResponse> {
        *self.side = match req.uri().path() {
            "/0" => Some(0),
            "/1" => Some(1),
            _ => None,
        };
        Ok(response)
    }
}

/// The link transport of the node with seed `seed` on side `seed - 1` of `relay`, with its
/// stats and state.
fn transport(
    relay: &Relay,
    seed: u8,
) -> TestResult<(LinkTransport, Arc<WssStats>, watch::Receiver<LinkState>)> {
    let dialer = WssDialer::new(relay.config(usize::from(seed - 1)))?;
    let stats = dialer.stats();
    let state = dialer.state();
    let transport = dialer.into_transport(LINK, addr(3 - seed), LinkConfig::default());
    Ok((transport, stats, state))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_and_transfer_over_plain_ws() -> TestResult {
    let relay = Relay::start().await?;
    let (ta, stats_a, mut state_a) = transport(&relay, 1)?;
    let (tb, stats_b, mut state_b) = transport(&relay, 2)?;
    let mut a = Node::new(1, LINK, addr(1), ta, Options::default());
    let mut b = Node::new(2, LINK, addr(2), tb, Options::default());
    introduce(&a, &b, None).await?;
    for state in [&mut state_a, &mut state_b] {
        timeout(WAIT, state.wait_for(|s| *s == LinkState::Connected)).await??;
    }
    exchange(&mut a, &mut b).await?;
    for stats in [&stats_a, &stats_b] {
        assert_eq!(stats.connects(), 1);
        assert_eq!(stats.connect_failures(), 0);
        assert!(stats.tx() > 0 && stats.rx() > 0);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_ws_needs_allow_plaintext() -> TestResult {
    let relay = Relay::start().await?;
    let mut config = relay.config(0);
    config.allow_plaintext = false;
    let err = WssDialer::new(config).map(drop).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("allow_plaintext"), "{err}");
    Ok(())
}
