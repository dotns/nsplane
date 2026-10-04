//! `WssConfig::keepalive` on `WssDialer` links and `WssStreamClient` sessions: pings at
//! the configured interval, and a relay that stops answering ends the link or session after
//! the configured read idle, long before the 35 s default.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::{LinkConfig, TransportId};
use nsplane_e2e::{TestResult, WAIT};
use nsplane_wss::{WssConfig, WssDialEvent, WssDialer, WssStreamClient, WssStreamLimits, WssTls};
use rustls::RootCertStore;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch};
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;

/// How many ping intervals the relay counts pings over.
const INTERVALS: u32 = 10;
/// The latest a silent relay may end the link: well before the 35 s default read idle.
const LATEST: Duration = Duration::from_secs(10);

/// Locks `mutex`; a test that panicked holding it fails on its own.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A plain WebSocket relay recording the pings of each connection (answering them) until
/// frozen.
struct Relay {
    addr: SocketAddr,
    /// Per connection, when each ping arrived.
    pings: Mutex<Vec<Vec<Instant>>>,
    /// Bumped to freeze the open connections: each sends one last ping and from then on
    /// neither reads nor writes (no pongs).
    freeze: watch::Sender<u64>,
    /// When the last frozen connection sent its last frame.
    frozen: Mutex<Option<Instant>>,
}

impl Relay {
    async fn start() -> TestResult<Arc<Self>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay = Arc::new(Self {
            addr: listener.local_addr()?,
            pings: Mutex::new(Vec::new()),
            freeze: watch::Sender::new(0),
            frozen: Mutex::new(None),
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
        let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else {
            return;
        };
        let mut freeze = self.freeze.subscribe();
        let connection = {
            let mut pings = lock(&self.pings);
            pings.push(Vec::new());
            pings.len() - 1
        };
        let (mut sink, mut stream) = ws.split();
        loop {
            tokio::select! {
                message = stream.next() => match message {
                    Some(Ok(Message::Ping(_))) => {
                        lock(&self.pings)[connection].push(Instant::now());
                    }
                    Some(Ok(_)) => {}
                    _ => return,
                },
                _ = freeze.changed() => break,
            }
        }
        // The peer's last received frame is sent after this instant.
        *lock(&self.frozen) = Some(Instant::now());
        let _ = sink.send(Message::Ping(Bytes::new())).await;
        // Hold the connection open without touching it.
        std::future::pending::<()>().await;
    }

    /// The pings connection `connection` received.
    fn pings(&self, connection: usize) -> Vec<Instant> {
        lock(&self.pings)
            .get(connection)
            .cloned()
            .unwrap_or_default()
    }

    fn config(&self, ping: Duration, idle: Duration) -> WssConfig {
        WssConfig::new(
            format!("ws://{}/wss-relay", self.addr),
            WssTls::Roots(RootCertStore::empty()),
        )
        .allow_plaintext(true)
        .backoff(Duration::from_secs(1), Duration::from_secs(2))
        .keepalive(ping, idle)
        .connect_timeout(Duration::from_secs(2))
    }

    /// Checks that the first connection pings every `ping` and stays up past `idle` while
    /// it gets pongs, then freezes it and checks that it ends after `idle`, well before the
    /// default. `events` are the carrier's.
    async fn check(
        &self,
        events: &mut broadcast::Receiver<WssDialEvent>,
        ping: Duration,
        idle: Duration,
    ) -> TestResult {
        timeout(WAIT, async {
            while self.pings(0).is_empty() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let window = ping * INTERVALS;
        assert!(window > idle);
        let start = Instant::now();
        sleep(window).await;
        let pings = self
            .pings(0)
            .into_iter()
            .filter(|&at| at > start && at <= start + window)
            .count();
        // Loose bounds: a loaded host delays pings, the interval does not add any.
        let intervals = INTERVALS as usize;
        assert!(
            (intervals / 2..=intervals + 3).contains(&pings),
            "{pings} pings in {window:?} at {ping:?}"
        );
        assert_eq!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        );

        self.freeze.send_modify(|n| *n += 1);
        let lost = timeout(LATEST, events.recv()).await??;
        let silent = lock(&self.frozen).ok_or("not frozen")?.elapsed();
        assert_eq!(lost, WssDialEvent::Lost);
        assert!(silent >= idle, "lost after {silent:?} at {idle:?}");
        Ok(())
    }
}

async fn dialer_case(ping: Duration, idle: Duration) -> TestResult {
    let relay = Relay::start().await?;
    let dialer = WssDialer::new(relay.config(ping, idle))?;
    let mut events = dialer.events();
    let transport = dialer.into_transport(
        TransportId::new(1),
        "192.0.2.1:1000".parse()?,
        LinkConfig::default(),
    );
    assert_eq!(
        timeout(WAIT, events.recv()).await??,
        WssDialEvent::Connected
    );
    relay.check(&mut events, ping, idle).await?;
    drop(transport);
    Ok(())
}

async fn stream_client_case(ping: Duration, idle: Duration) -> TestResult {
    let relay = Relay::start().await?;
    let client = WssStreamClient::new(relay.config(ping, idle), WssStreamLimits::default())?;
    let mut events = client.events();
    timeout(WAIT, client.connect()).await??;
    assert_eq!(events.try_recv()?, WssDialEvent::Connected);
    relay.check(&mut events, ping, idle).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialer_pings_and_idles_as_configured() -> TestResult {
    dialer_case(Duration::from_millis(100), Duration::from_millis(600)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialer_honors_other_keepalive_values() -> TestResult {
    dialer_case(Duration::from_millis(200), Duration::from_millis(1100)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_client_pings_and_idles_as_configured() -> TestResult {
    stream_client_case(Duration::from_millis(100), Duration::from_millis(600)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_client_honors_other_keepalive_values() -> TestResult {
    stream_client_case(Duration::from_millis(200), Duration::from_millis(1100)).await
}
