//! `WssStreamLimits::open_timeout` on `WssStreamClient`: opens fail fast with the last
//! dial error (its `WssDialError` included) instead of waiting out the backoff, a relay
//! coming up later serves later opens, and without it an open waits for the dial.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use nsplane_e2e::{TestResult, WAIT};
use nsplane_wss::frame::{FrameCommand, WsFrame};
use nsplane_wss::{WssConfig, WssDialError, WssStreamClient, WssStreamLimits, WssTls};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

/// The open timeout of the fail-fast clients.
const OPEN_TIMEOUT: Duration = Duration::from_millis(300);

/// A backoff no test waits out.
const LONG_BACKOFF: Duration = Duration::from_secs(10);

/// Locks `mutex`; a test that panicked holding it fails on its own.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How the relay answers a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Closes the TCP connection at once, as a relay going down.
    Down,
    /// Refuses the upgrade with this status.
    Refuse(u16),
    /// Upgrades it and echoes the DATA of every stream, acknowledging each CLOSE.
    Echo,
}

/// A plain WebSocket relay answering each connection as its current [`Mode`] says.
struct Relay {
    addr: SocketAddr,
    mode: Mutex<Mode>,
}

impl Relay {
    async fn start(mode: Mode) -> TestResult<Arc<Self>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay = Arc::new(Self {
            addr: listener.local_addr()?,
            mode: Mutex::new(mode),
        });
        let accepting = Arc::clone(&relay);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(Arc::clone(&accepting).serve(tcp));
            }
        });
        Ok(relay)
    }

    fn set(&self, mode: Mode) {
        *lock(&self.mode) = mode;
    }

    async fn serve(self: Arc<Self>, tcp: TcpStream) {
        let mode = *lock(&self.mode);
        if mode == Mode::Down {
            return;
        }
        let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tcp, Upgrade(mode)).await else {
            return;
        };
        while let Some(Ok(message)) = ws.next().await {
            let Message::Binary(bytes) = message else {
                continue;
            };
            let Ok(frame) = WsFrame::decode(&bytes) else {
                continue;
            };
            let reply = match frame.command {
                FrameCommand::Data => WsFrame::data(frame.stream_id, frame.payload),
                FrameCommand::Close => WsFrame::close_ack(frame.stream_id),
                FrameCommand::Open { .. } | FrameCommand::CloseAck => continue,
            };
            if ws.send(Message::Binary(reply.encode())).await.is_err() {
                return;
            }
        }
    }
}

/// Answers an upgrade request as the relay's mode says.
struct Upgrade(Mode);

impl Callback for Upgrade {
    fn on_request(self, _: &Request, response: Response) -> Result<Response, ErrorResponse> {
        let Mode::Refuse(status) = self.0 else {
            return Ok(response);
        };
        let mut refused = ErrorResponse::new(None);
        *refused.status_mut() = status.try_into().unwrap_or_default();
        Err(refused)
    }
}

/// A client of `ws://addr` with `backoff` (floor and cap) and `limits`.
fn client(
    addr: SocketAddr,
    backoff: Duration,
    limits: WssStreamLimits,
) -> TestResult<WssStreamClient> {
    let config = WssConfig::new(
        format!("ws://{addr}/client"),
        WssTls::Roots(RootCertStore::empty()),
    )
    .allow_plaintext(true)
    .backoff(backoff, backoff)
    .connect_timeout(Duration::from_secs(2));
    Ok(WssStreamClient::new(config, limits)?)
}

fn fail_fast() -> WssStreamLimits {
    WssStreamLimits::default().open_timeout(OPEN_TIMEOUT)
}

/// A target the echo relay never dials.
fn target() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], 80))
}

/// One `open_tcp` of `client`, which must fail within [`WAIT`], and how long it took.
async fn open_error(client: &WssStreamClient) -> TestResult<(io::Error, Duration)> {
    let started = Instant::now();
    match timeout(WAIT, client.open_tcp(target())).await? {
        Ok(_) => Err("the open succeeded".into()),
        Err(err) => Ok((err, started.elapsed())),
    }
}

/// Echoes a few bytes through a stream opened on `client`.
async fn echo(client: &WssStreamClient) -> TestResult {
    let mut stream = timeout(WAIT, client.open_tcp(target())).await??;
    stream.write_all(b"fail fast").await?;
    let mut back = [0; 9];
    timeout(WAIT, stream.read_exact(&mut back)).await??;
    assert_eq!(&back, b"fail fast");
    Ok(())
}

/// The status of the `WssDialError` inside `err`.
fn status(err: &io::Error) -> Option<u16> {
    err.get_ref()
        .and_then(|e| e.downcast_ref::<WssDialError>())
        .map(|detail| detail.status)
}

/// Relay down, backoff 10 s: the first open fails with the dial error at once; a second
/// one fails after the open timeout with the same error, without waiting out the backoff
/// or dialing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opens_fail_fast_while_the_relay_is_down() -> TestResult {
    // A port nothing listens on: every dial is refused.
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    drop(listener);
    let client = client(addr, LONG_BACKOFF, fail_fast())?;
    let stats = client.stats();

    let (first, took) = open_error(&client).await?;
    assert!(
        took < Duration::from_secs(3),
        "the first open took {took:?}"
    );
    assert!(
        first.to_string().starts_with("wss connect failed"),
        "{first}"
    );
    assert_eq!(stats.connect_failures(), 1);

    for _ in 0..2 {
        let (err, took) = open_error(&client).await?;
        assert!(took >= OPEN_TIMEOUT, "an open failed after {took:?}");
        assert!(took < Duration::from_secs(3), "an open took {took:?}");
        assert_eq!(
            (err.kind(), err.to_string()),
            (first.kind(), first.to_string())
        );
    }
    let err = timeout(WAIT, client.connect()).await?.unwrap_err();
    assert_eq!(err.to_string(), first.to_string());
    let err = timeout(WAIT, client.open_udp(target())).await?.unwrap_err();
    assert_eq!(err.to_string(), first.to_string());
    // The dial behind them still waits its backoff.
    assert_eq!(stats.connect_failures(), 1);
    Ok(())
}

/// Relay answering 403: the open error, and that of an open timing out behind the next
/// dial, carry the `WssDialError` with status 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opens_carry_the_refusal() -> TestResult {
    let relay = Relay::start(Mode::Refuse(403)).await?;
    let client = client(relay.addr, LONG_BACKOFF, fail_fast())?;

    let (err, took) = open_error(&client).await?;
    assert!(took < Duration::from_secs(3), "the open took {took:?}");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(status(&err), Some(403));

    let (err, took) = open_error(&client).await?;
    assert!(took >= OPEN_TIMEOUT, "the open failed after {took:?}");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(err.to_string(), "wss upgrade rejected with HTTP 403");
    assert_eq!(status(&err), Some(403));
    assert_eq!(client.stats().rejected_forbidden(), 1);
    Ok(())
}

/// A relay coming up after failed opens serves a later open once the backoff elapsed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_coming_up_serves_later_opens() -> TestResult {
    let relay = Relay::start(Mode::Down).await?;
    let client = client(relay.addr, Duration::from_millis(200), fail_fast())?;
    let (err, _) = open_error(&client).await?;
    assert!(err.to_string().starts_with("wss connect failed"), "{err}");
    let failed = Instant::now();

    relay.set(Mode::Echo);
    let deadline = Instant::now() + WAIT;
    loop {
        match client.open_tcp(target()).await {
            Ok(_) => break,
            Err(err) if Instant::now() < deadline => {
                assert_eq!(err.kind(), io::ErrorKind::Other, "{err}");
            }
            Err(err) => return Err(format!("no session within {WAIT:?}: {err}").into()),
        }
    }
    assert!(failed.elapsed() >= Duration::from_millis(200));
    echo(&client).await?;
    assert_eq!(client.stats().sessions(), 1);
    Ok(())
}

/// Without an open timeout an open waits for the dial: one started while the relay is
/// down succeeds once it comes up within the backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_an_open_timeout_an_open_waits_for_the_dial() -> TestResult {
    let backoff = Duration::from_secs(1);
    let relay = Relay::start(Mode::Down).await?;
    let client = client(relay.addr, backoff, WssStreamLimits::default())?;
    let (err, _) = open_error(&client).await?;
    assert!(err.to_string().starts_with("wss connect failed"), "{err}");
    let failed = Instant::now();

    let waiting = {
        let client = client.clone();
        tokio::spawn(async move { client.open_tcp(target()).await.map(drop) })
    };
    sleep(Duration::from_millis(200)).await;
    relay.set(Mode::Echo);
    timeout(WAIT, waiting).await???;
    assert!(
        failed.elapsed() >= backoff,
        "the open came up {:?} after the failure",
        failed.elapsed()
    );
    echo(&client).await?;
    assert_eq!(client.stats().connect_failures(), 1);
    Ok(())
}
