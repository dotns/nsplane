//! `WssDialEvent`s of `WssDialer` and `WssStreamClient`: one event per link or session up
//! and lost, failed dial, timeout and 401/403 rejection, in order; and the reconnect delay
//! after a loss, apart from the failure backoff.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::StreamExt as _;
use nsplane::{LinkConfig, TransportId};
use nsplane_e2e::{TestResult, WAIT};
use nsplane_wss::{WssConfig, WssDialEvent, WssDialer, WssStreamClient, WssStreamLimits, WssTls};
use rustls::RootCertStore;
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch};
use tokio::time::{Instant, sleep};
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};

/// The connect timeout of the test dials.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Locks `mutex`; a test that panicked holding it fails on its own.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How the relay answers a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Upgrades it and holds it until kicked.
    Accept,
    /// Refuses the upgrade with this status.
    Refuse(u16),
    /// Closes the TCP connection at once, as a relay going down.
    Drop,
    /// Reads the request and never answers.
    Silent,
}

/// A plain WebSocket relay answering each connection as its current [`Mode`] says, and
/// logging what it did, in order.
struct Relay {
    addr: SocketAddr,
    mode: Mutex<Mode>,
    log: Mutex<Vec<Mode>>,
    /// Bumped to drop the upgraded connections.
    kick: watch::Sender<u64>,
}

impl Relay {
    async fn start() -> TestResult<Arc<Self>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay = Arc::new(Self {
            addr: listener.local_addr()?,
            mode: Mutex::new(Mode::Accept),
            log: Mutex::new(Vec::new()),
            kick: watch::Sender::new(0),
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

    fn kick(&self) {
        self.kick.send_modify(|n| *n += 1);
    }

    fn log(&self) -> Vec<Mode> {
        lock(&self.log).clone()
    }

    async fn serve(self: Arc<Self>, mut tcp: TcpStream) {
        let mode = *lock(&self.mode);
        lock(&self.log).push(mode);
        match mode {
            Mode::Drop => {}
            Mode::Silent => {
                let mut buf = [0; 1024];
                while tcp.read(&mut buf).await.is_ok_and(|n| n > 0) {}
            }
            Mode::Accept | Mode::Refuse(_) => {
                let upgrade = Upgrade(mode);
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tcp, upgrade).await else {
                    return;
                };
                let mut kick = self.kick.subscribe();
                loop {
                    tokio::select! {
                        message = ws.next() => if !matches!(message, Some(Ok(_))) {
                            return;
                        },
                        _ = kick.changed() => return,
                    }
                }
            }
        }
    }

    fn config(&self) -> WssConfig {
        WssConfig::new(
            format!("ws://{}/wss-relay", self.addr),
            WssTls::Roots(RootCertStore::empty()),
        )
        .allow_plaintext(true)
        .connect_timeout(CONNECT_TIMEOUT)
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

/// The events a carrier sends for the connections in `log`.
fn expected(log: &[Mode]) -> Vec<WssDialEvent> {
    log.iter()
        .flat_map(|mode| match *mode {
            Mode::Accept => vec![WssDialEvent::Connected, WssDialEvent::Lost],
            Mode::Refuse(status @ (401 | 403)) => vec![WssDialEvent::Rejected(status)],
            Mode::Refuse(_) | Mode::Drop => vec![WssDialEvent::DialFailed],
            Mode::Silent => vec![WssDialEvent::TimedOut],
        })
        .collect()
}

/// The events received so far, with when they arrived.
#[derive(Clone)]
struct Seen(Arc<Mutex<Vec<(Instant, WssDialEvent)>>>);

impl Seen {
    /// Records every event of `events`; a lagging receiver stops recording.
    fn record(mut events: broadcast::Receiver<WssDialEvent>) -> Self {
        let seen = Self(Arc::default());
        let recording = seen.clone();
        tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                lock(&recording.0).push((Instant::now(), event));
            }
        });
        seen
    }

    fn events(&self) -> Vec<WssDialEvent> {
        lock(&self.0).iter().map(|&(_, event)| event).collect()
    }

    /// When each `event` arrived.
    fn times(&self, event: WssDialEvent) -> Vec<Instant> {
        lock(&self.0)
            .iter()
            .filter(|&&(_, e)| e == event)
            .map(|&(at, _)| at)
            .collect()
    }

    fn count(&self, event: WssDialEvent) -> usize {
        self.times(event).len()
    }

    /// Waits until `n` `event`s arrived, within `wait`.
    async fn until(&self, event: WssDialEvent, n: usize, wait: Duration) -> TestResult {
        let deadline = Instant::now() + wait;
        while self.count(event) < n {
            if Instant::now() > deadline {
                return Err(
                    format!("{n} {event:?} not within {wait:?}: {:?}", self.events()).into(),
                );
            }
            sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }
}

/// The events match the relay's log one to one, in order. The events are taken first: the
/// relay may have logged one more connection, whose dial has not ended yet.
fn check_sequence(seen: &Seen, relay: &Relay) -> TestResult {
    let events = seen.events();
    let log = relay.log();
    let all = expected(&log);
    let settled = expected(&log[..log.len().saturating_sub(1)]);
    if events != all && events != settled {
        return Err(format!("events {events:?} for the connections {log:?}").into());
    }
    Ok(())
}

/// The event phases both carriers run through: up, lost and up again, two 401s, two 403s,
/// two dials to a relay that went down and a dial that times out. `dial` makes the carrier
/// dial (the dialer dials on its own).
async fn phases<F, D>(relay: &Relay, seen: &Seen, dial: D) -> TestResult
where
    D: Fn() -> F,
    F: Future<Output = ()>,
{
    use WssDialEvent::{Connected, DialFailed, Lost, Rejected, TimedOut};

    dial().await;
    seen.until(Connected, 1, WAIT).await?;
    relay.kick();
    seen.until(Lost, 1, WAIT).await?;
    dial().await;
    seen.until(Connected, 2, WAIT).await?;

    relay.set(Mode::Refuse(401));
    relay.kick();
    seen.until(Lost, 2, WAIT).await?;
    for (mode, event) in [
        (Mode::Refuse(401), Rejected(401)),
        (Mode::Refuse(403), Rejected(403)),
        (Mode::Drop, DialFailed),
    ] {
        relay.set(mode);
        for n in 1..=2 {
            dial().await;
            seen.until(event, n, WAIT).await?;
        }
    }
    relay.set(Mode::Silent);
    dial().await;
    seen.until(TimedOut, 1, WAIT).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialer_sends_one_event_per_occurrence() -> TestResult {
    let relay = Relay::start().await?;
    let config = relay
        .config()
        .backoff(Duration::from_millis(20), Duration::from_millis(40));
    let dialer = WssDialer::new(config)?;
    let stats = dialer.stats();
    let seen = Seen::record(dialer.events());
    let transport = dialer.into_transport(
        TransportId::new(1),
        "192.0.2.1:1000".parse()?,
        LinkConfig::default(),
    );
    // The dialer redials on its own.
    phases(&relay, &seen, || std::future::ready(())).await?;
    check_sequence(&seen, &relay)?;
    // The counters keep counting as before.
    assert_eq!(stats.connects(), 2);
    assert!(stats.rejected_unauthorized() >= 2 && stats.rejected_forbidden() >= 2);
    drop(transport);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_client_sends_one_event_per_occurrence() -> TestResult {
    let relay = Relay::start().await?;
    let config = relay
        .config()
        .backoff(Duration::from_millis(20), Duration::from_millis(40));
    let client = WssStreamClient::new(config, WssStreamLimits::default())?;
    let seen = Seen::record(client.events());
    phases(&relay, &seen, || {
        let client = client.clone();
        async move {
            let _ = client.connect().await;
        }
    })
    .await?;
    // Each dial ended before the next began: nothing is in flight.
    assert_eq!(seen.events(), expected(&relay.log()));
    let stats = client.stats();
    assert_eq!(stats.sessions(), 2);
    assert_eq!(
        (stats.rejected_unauthorized(), stats.rejected_forbidden()),
        (2, 2)
    );
    assert_eq!(stats.connect_failures(), 7);
    Ok(())
}

/// The reconnect delay of the tests: much shorter than the backoff floor.
const RECONNECT: Duration = Duration::from_millis(100);
/// The backoff floor of the reconnect tests.
const FLOOR: Duration = Duration::from_secs(2);

fn reconnect_config(relay: &Relay) -> WssConfig {
    relay
        .config()
        .backoff(FLOOR, FLOOR * 8)
        .reconnect_delay(RECONNECT)
}

/// After the loss at `lost`: the redial came up at `up`, after the reconnect delay but
/// before the floor; then, with the relay down, the failures at `failures` waited the
/// floor, then twice the floor.
fn check_waits(lost: Instant, up: Instant, failures: &[Instant]) -> TestResult {
    let redial = up - lost;
    assert!(
        redial >= RECONNECT && redial < FLOOR,
        "redial after {redial:?}"
    );
    let [first, second, third] = failures else {
        return Err(format!("{} failures", failures.len()).into());
    };
    assert!(*second - *first >= FLOOR, "{:?}", *second - *first);
    assert!(*third - *second >= FLOOR * 2, "{:?}", *third - *second);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialer_reconnects_after_the_delay_then_backs_off_from_the_floor() -> TestResult {
    use WssDialEvent::{Connected, DialFailed, Lost};

    let relay = Relay::start().await?;
    let dialer = WssDialer::new(reconnect_config(&relay))?;
    let seen = Seen::record(dialer.events());
    let transport = dialer.into_transport(
        TransportId::new(1),
        "192.0.2.1:1000".parse()?,
        LinkConfig::default(),
    );
    seen.until(Connected, 1, WAIT).await?;
    relay.kick();
    seen.until(Connected, 2, WAIT).await?;

    // The link drops with the relay: the first redial waits the reconnect delay, the
    // failures the floor, doubling.
    relay.set(Mode::Drop);
    relay.kick();
    seen.until(DialFailed, 3, WAIT + FLOOR * 3).await?;
    let lost = seen.times(Lost);
    assert!(seen.times(DialFailed)[0] - lost[1] >= RECONNECT);
    check_waits(
        lost[0],
        seen.times(Connected)[1],
        &seen.times(DialFailed)[..3],
    )?;
    drop(transport);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_client_reconnects_after_the_delay_then_backs_off_from_the_floor() -> TestResult {
    use WssDialEvent::{Connected, Lost};

    let relay = Relay::start().await?;
    let client = WssStreamClient::new(reconnect_config(&relay), WssStreamLimits::default())?;
    let seen = Seen::record(client.events());
    client.connect().await?;
    relay.kick();
    seen.until(Lost, 1, WAIT).await?;
    client.connect().await?;
    seen.until(Connected, 2, WAIT).await?;

    relay.set(Mode::Drop);
    relay.kick();
    seen.until(Lost, 2, WAIT).await?;
    let mut failures = Vec::new();
    for _ in 0..3 {
        assert!(client.connect().await.is_err());
        failures.push(Instant::now());
    }
    assert!(failures[0] - seen.times(Lost)[1] >= RECONNECT);
    check_waits(seen.times(Lost)[0], seen.times(Connected)[1], &failures)
}
