//! `WssConfig::ping_interval(None)` on `WssDialer` links and `WssStreamClient` sessions:
//! data flows and no ping is sent while the relay keeps the link alive with its own pings,
//! and a relay gone silent still ends the link or session after the read idle. With pings
//! on, the same relay sees them.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use nsplane::LinkDialer as _;
use nsplane_e2e::{TestResult, WAIT};
use nsplane_wss::frame::{FrameCommand, WsFrame};
use nsplane_wss::{WssConfig, WssDialEvent, WssDialer, WssStreamClient, WssStreamLimits, WssTls};
use rustls::RootCertStore;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, interval, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;

/// The would-be ping interval, and how often the relay pings while live.
const PING: Duration = Duration::from_millis(100);
/// The read idle of the clients.
const IDLE: Duration = Duration::from_secs(1);
/// How many would-be ping intervals the relay counts pings over.
const INTERVALS: u32 = 15;
/// The latest a silent relay may end the link: well before the 35 s default read idle.
const LATEST: Duration = Duration::from_secs(10);

/// Locks `mutex`; a test that panicked holding it fails on its own.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the relay received on its connections, in order.
#[derive(Debug, Default)]
struct Received {
    pings: usize,
    pongs: usize,
    binary: usize,
}

/// A plain WebSocket relay that pings every [`PING`], echoes binary messages (but OPEN
/// frames) and records what it receives, until frozen.
struct Relay {
    addr: SocketAddr,
    received: Mutex<Received>,
    /// Bumped to freeze the open connections: each sends one last ping and from then on
    /// neither reads nor writes.
    freeze: watch::Sender<u64>,
    /// When the last frozen connection sent its last frame.
    frozen: Mutex<Option<Instant>>,
}

impl Relay {
    async fn start() -> TestResult<Arc<Self>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay = Arc::new(Self {
            addr: listener.local_addr()?,
            received: Mutex::new(Received::default()),
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
        let (mut sink, mut stream) = ws.split();
        let mut pings = interval(PING);
        loop {
            let reply = tokio::select! {
                message = stream.next() => match message {
                    Some(Ok(Message::Ping(_))) => {
                        lock(&self.received).pings += 1;
                        None
                    }
                    Some(Ok(Message::Pong(_))) => {
                        lock(&self.received).pongs += 1;
                        None
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        lock(&self.received).binary += 1;
                        let open = WsFrame::decode(&bytes)
                            .is_ok_and(|frame| matches!(frame.command, FrameCommand::Open { .. }));
                        (!open).then_some(Message::Binary(bytes))
                    }
                    Some(Ok(_)) => None,
                    _ => return,
                },
                _ = pings.tick() => Some(Message::Ping(Bytes::new())),
                _ = freeze.changed() => break,
            };
            if let Some(reply) = reply
                && sink.send(reply).await.is_err()
            {
                return;
            }
        }
        // The peer's last received frame is sent after this instant.
        *lock(&self.frozen) = Some(Instant::now());
        let _ = sink.send(Message::Ping(Bytes::new())).await;
        // Hold the connection open without touching it.
        std::future::pending::<()>().await;
    }

    fn config(&self) -> WssConfig {
        WssConfig::new(
            format!("ws://{}/wss-relay", self.addr),
            WssTls::Roots(RootCertStore::empty()),
        )
        .allow_plaintext(true)
        .backoff(Duration::from_secs(1), Duration::from_secs(2))
        .keepalive(PING, IDLE)
        .connect_timeout(Duration::from_secs(2))
    }

    /// The pings received so far.
    fn pings(&self) -> usize {
        lock(&self.received).pings
    }

    /// Waits until the client answered a relay ping, so the link is read and alive.
    async fn pong(&self) -> TestResult {
        timeout(WAIT, async {
            while lock(&self.received).pongs == 0 {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        Ok(())
    }

    /// Counts the client's pings over [`INTERVALS`] would-be intervals (longer than the
    /// read idle, which the relay's pings keep from passing): none with pings off, about
    /// one per interval with them on.
    async fn check_pings(&self, on: bool) {
        let window = PING * INTERVALS;
        assert!(window > IDLE);
        let before = self.pings();
        sleep(window).await;
        let pings = self.pings() - before;
        if on {
            let intervals = INTERVALS as usize;
            assert!(
                (intervals / 2..=intervals + 3).contains(&pings),
                "{pings} pings in {window:?} at {PING:?}"
            );
        } else {
            assert_eq!(pings, 0, "pings with pings off");
        }
    }

    /// Freezes the relay and checks that `lost` (the client noticing) completes after the
    /// read idle, well before the default; no ping arrives meanwhile with pings off.
    async fn check_idle(&self, on: bool, lost: impl Future<Output = TestResult>) -> TestResult {
        let before = self.pings();
        self.freeze.send_modify(|n| *n += 1);
        timeout(LATEST, lost).await??;
        let silent = lock(&self.frozen).ok_or("not frozen")?.elapsed();
        assert!(silent >= IDLE, "lost after {silent:?} at {IDLE:?}");
        if !on {
            assert_eq!(self.pings(), before);
        }
        Ok(())
    }
}

async fn dialer_case(on: bool) -> TestResult {
    let relay = Relay::start().await?;
    let config = relay.config();
    let config = if on {
        config
    } else {
        config.ping_interval(None)
    };
    let dialer = WssDialer::new(config)?;
    let (mut sender, mut receiver) = timeout(WAIT, dialer.dial()).await??;
    // The link's reader, as a transport runs it: datagrams out, then how it ended.
    let (received, mut datagrams) = mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(Some(datagram)) => {
                    let _ = received.send(datagram);
                }
                Ok(None) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    });

    timeout(WAIT, sender.send(b"over the link")).await??;
    let echoed = timeout(WAIT, datagrams.recv()).await?.ok_or("link ended")?;
    assert_eq!(&echoed[..], b"over the link");
    relay.pong().await?;
    relay.check_pings(on).await;
    assert!(!reader.is_finished(), "the relay's pings keep the link up");

    relay
        .check_idle(on, async {
            let error = reader.await?.err().ok_or("link closed, not silent")?;
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            Ok(())
        })
        .await
}

async fn stream_client_case(on: bool) -> TestResult {
    let relay = Relay::start().await?;
    let config = relay.config();
    let config = if on {
        config
    } else {
        config.ping_interval(None)
    };
    let client = WssStreamClient::new(config, WssStreamLimits::default())?;
    let mut events = client.events();
    timeout(WAIT, client.connect()).await??;
    assert_eq!(events.try_recv()?, WssDialEvent::Connected);

    let mut flow = timeout(WAIT, client.open_udp("192.0.2.1:53".parse()?)).await??;
    timeout(WAIT, flow.send(b"over the session")).await??;
    let echoed = timeout(WAIT, flow.recv()).await??.ok_or("flow ended")?;
    assert_eq!(&echoed[..], b"over the session");
    relay.pong().await?;
    relay.check_pings(on).await;
    assert!(
        events.try_recv().is_err(),
        "the relay's pings keep the session up"
    );

    relay
        .check_idle(on, async {
            assert_eq!(events.recv().await?, WssDialEvent::Lost);
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialer_without_pings_keeps_data_and_the_read_idle() -> TestResult {
    dialer_case(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialer_with_pings_still_pings() -> TestResult {
    dialer_case(true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_client_without_pings_keeps_data_and_the_read_idle() -> TestResult {
    stream_client_case(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_client_with_pings_still_pings() -> TestResult {
    stream_client_case(true).await
}
