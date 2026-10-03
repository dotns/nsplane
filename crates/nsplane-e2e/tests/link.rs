//! Engines on `LinkTransport`s joined by an in-memory relay: traffic over the link, link
//! loss and redial, the bounded send queue while no link is up, the read idle timeout, and
//! datagrams to an address other than the link's peer.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use nsplane::{
    BoxFuture, DROP_TRANSPORT_SEND_ERROR, Ecn, LinkConfig, LinkDialer, LinkReceiver, LinkSender,
    LinkState, LinkTransport, PacketBuf, Path, Transport, TransportId,
};
use nsplane_e2e::{
    Family, Node, Options, QUIET, TestResult, WAIT, exchange, introduce, payload, transfer,
};
use tokio::sync::{Notify, mpsc};
use tokio::time::{Instant, sleep, timeout};

/// The id of every node's link transport.
const LINK: TransportId = TransportId::new(1);
/// Messages each side's current link holds before the relay drops them.
const LINK_CAPACITY: usize = 1024;

/// The address of the node with key seed `seed` (side `seed - 1` of the relay).
fn addr(seed: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, seed], 1000 + u16::from(seed)))
}

/// Locks `mutex`; a test that panicked holding it fails on its own.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An in-memory relay between two sides: what one side's link sends reaches the other
/// side's current link, and is dropped while that side has none.
#[derive(Default)]
struct Relay {
    /// Per side, the sender into its current link's receiver.
    links: Mutex<[Option<mpsc::Sender<Bytes>>; 2]>,
    /// Messages handed to a link.
    forwarded: AtomicU64,
}

impl Relay {
    /// Closes the current link of `side`: its receiver ends.
    fn close(&self, side: usize) {
        lock(&self.links)[side] = None;
    }
}

/// The sending half of a link: forwards to the other side's current link.
struct RelaySender {
    relay: Arc<Relay>,
    to: usize,
}

impl LinkSender for RelaySender {
    fn send(&mut self, message: &[u8]) -> BoxFuture<'_, io::Result<()>> {
        let to = lock(&self.relay.links)[self.to].clone();
        if let Some(to) = to
            && to.try_send(Bytes::copy_from_slice(message)).is_ok()
        {
            self.relay.forwarded.fetch_add(1, Ordering::SeqCst);
        }
        Box::pin(std::future::ready(Ok(())))
    }
}

/// The receiving half of a link.
struct RelayReceiver(mpsc::Receiver<Bytes>);

impl LinkReceiver for RelayReceiver {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Option<Bytes>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}

/// Dials one side's links on a [`Relay`]; records dials and states, and holds dials while
/// `hold` is set.
struct RelayDialer {
    relay: Arc<Relay>,
    side: usize,
    dials: AtomicUsize,
    states: Mutex<Vec<LinkState>>,
    hold: AtomicBool,
    release: Notify,
}

impl RelayDialer {
    fn new(relay: &Arc<Relay>, side: usize) -> Arc<Self> {
        Arc::new(Self {
            relay: relay.clone(),
            side,
            dials: AtomicUsize::new(0),
            states: Mutex::new(Vec::new()),
            hold: AtomicBool::new(false),
            release: Notify::new(),
        })
    }

    fn dials(&self) -> usize {
        self.dials.load(Ordering::SeqCst)
    }

    fn states(&self) -> Vec<LinkState> {
        lock(&self.states).clone()
    }

    /// Lets held and later dials through.
    fn unhold(&self) {
        self.hold.store(false, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

impl LinkDialer for RelayDialer {
    fn dial(&self) -> BoxFuture<'_, io::Result<(Box<dyn LinkSender>, Box<dyn LinkReceiver>)>> {
        Box::pin(async move {
            self.dials.fetch_add(1, Ordering::SeqCst);
            loop {
                let released = self.release.notified();
                if !self.hold.load(Ordering::SeqCst) {
                    break;
                }
                released.await;
            }
            let (tx, rx) = mpsc::channel(LINK_CAPACITY);
            lock(&self.relay.links)[self.side] = Some(tx);
            let sender = RelaySender {
                relay: self.relay.clone(),
                to: 1 - self.side,
            };
            let link: (Box<dyn LinkSender>, Box<dyn LinkReceiver>) =
                (Box::new(sender), Box::new(RelayReceiver(rx)));
            Ok(link)
        })
    }

    fn on_state(&self, state: LinkState) {
        lock(&self.states).push(state);
    }
}

/// The link transport of the node with seed `seed` over `dialer`.
fn transport(seed: u8, dialer: &Arc<RelayDialer>, config: LinkConfig) -> LinkTransport {
    let peer = addr(3 - seed);
    LinkTransport::new(LINK, peer, dialer.clone(), config)
}

/// Two nodes (seeds 1 and 2) on link transports joined by one relay, introduced to each
/// other; node 1's transport uses `config`.
async fn pair(
    config: LinkConfig,
) -> TestResult<(
    Node<LinkTransport>,
    Node<LinkTransport>,
    Arc<Relay>,
    [Arc<RelayDialer>; 2],
)> {
    let relay = Arc::new(Relay::default());
    let dialers = [RelayDialer::new(&relay, 0), RelayDialer::new(&relay, 1)];
    let a = Node::new(
        1,
        LINK,
        addr(1),
        transport(1, &dialers[0], config),
        Options::default(),
    );
    let b = Node::new(
        2,
        LINK,
        addr(2),
        transport(2, &dialers[1], LinkConfig::default()),
        Options::default(),
    );
    introduce(&a, &b, None).await?;
    Ok((a, b, relay, dialers))
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

#[tokio::test]
async fn handshake_and_transfer_over_link() -> TestResult {
    let (mut a, mut b, _relay, dialers) = pair(LinkConfig::default()).await?;
    exchange(&mut a, &mut b).await?;
    for dialer in &dialers {
        assert_eq!(dialer.dials(), 1);
        assert_eq!(dialer.states(), [LinkState::Connected]);
    }
    Ok(())
}

#[tokio::test]
async fn link_loss_redials_and_traffic_resumes() -> TestResult {
    let (mut a, mut b, relay, dialers) = pair(LinkConfig::default()).await?;
    exchange(&mut a, &mut b).await?;

    relay.close(0);
    let connected_again = [
        LinkState::Connected,
        LinkState::Disconnected,
        LinkState::Connected,
    ];
    until("redial", || dialers[0].states() == connected_again).await?;
    assert_eq!(dialers[0].dials(), 2);
    assert_eq!(dialers[1].states(), [LinkState::Connected]);
    exchange(&mut a, &mut b).await
}

#[tokio::test]
async fn bounded_queue_while_no_link() -> TestResult {
    const QUEUE: usize = 8;
    const OVER: u64 = 3;
    let (a, mut b, relay, dialers) = pair(LinkConfig::new().queue(QUEUE)).await?;
    transfer(&a, &mut b, Family::V4, 64).await?;

    // Lose node 1's link and hold the redial: no link is up.
    dialers[0].hold.store(true, Ordering::SeqCst);
    relay.close(0);
    until("link loss", || dialers[0].dials() == 2).await?;
    assert_eq!(
        dialers[0].states(),
        [LinkState::Connected, LinkState::Disconnected]
    );

    let packets: Vec<Vec<u8>> = (0..QUEUE as u64 + OVER)
        .map(|i| a.packet_to(&b, Family::V4, &i.to_be_bytes()))
        .collect();
    for packet in &packets {
        a.send(packet).await?;
    }
    let deadline = Instant::now() + WAIT;
    while a.drops(DROP_TRANSPORT_SEND_ERROR).await? < OVER {
        if Instant::now() > deadline {
            return Err("send errors not counted".into());
        }
        sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(a.drops(DROP_TRANSPORT_SEND_ERROR).await?, OVER);
    b.expect_no_delivery().await?;

    // The queued datagrams go out on the next link, in order.
    dialers[0].unhold();
    for packet in &packets[..QUEUE] {
        let (_, delivered) = b.expect_delivery().await?;
        assert_eq!(&delivered, packet);
    }
    b.expect_no_delivery().await?;
    assert_eq!(
        dialers[0].states(),
        [
            LinkState::Connected,
            LinkState::Disconnected,
            LinkState::Connected
        ]
    );
    Ok(())
}

#[tokio::test]
async fn read_idle_timeout_redials() -> TestResult {
    let idle = Duration::from_millis(200);
    let (_a, _b, _relay, dialers) = pair(LinkConfig::new().read_idle_timeout(Some(idle))).await?;
    until("idle redial", || dialers[0].dials() >= 2).await?;
    assert_eq!(
        dialers[0].states()[..2],
        [LinkState::Connected, LinkState::Disconnected]
    );
    // The other side has no idle timeout and keeps its first link.
    assert_eq!(dialers[1].dials(), 1);
    Ok(())
}

#[tokio::test]
async fn send_to_other_address_is_dropped() -> TestResult {
    let relay = Arc::new(Relay::default());
    let dialers = [RelayDialer::new(&relay, 0), RelayDialer::new(&relay, 1)];
    let a = transport(1, &dialers[0], LinkConfig::default());
    let b = transport(2, &dialers[1], LinkConfig::default());
    until("both links", || {
        dialers.iter().all(|d| d.states() == [LinkState::Connected])
    })
    .await?;

    let to = |addr| Path {
        transport: LINK,
        addr,
        ecn: Ecn::NotEct,
    };
    a.send(&payload(32), &to(addr(9))).await?;
    let mut buf = PacketBuf::with_capacity(1500);
    if timeout(QUIET, b.recv(&mut buf)).await.is_ok() {
        return Err("a datagram to another address reached the link".into());
    }
    assert_eq!(relay.forwarded.load(Ordering::SeqCst), 0);

    assert_eq!(a.peer(), addr(2));
    a.send(b"kept", &to(addr(2))).await?;
    let (len, path) = timeout(WAIT, b.recv(&mut buf)).await??;
    assert_eq!(&buf.as_packet()[..len], b"kept");
    assert_eq!(path, to(addr(1)));
    Ok(())
}
