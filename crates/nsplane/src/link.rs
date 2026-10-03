//! A transport over a message link that the embedder dials (a WebSocket, a relay stream).

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use nsplane_packet::{Ecn, PacketBuf, Path, TransportId};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::transport::{BoxFuture, Transport};

/// The two halves of a link, as [`LinkDialer::dial`] returns them.
type Link = (Box<dyn LinkSender>, Box<dyn LinkReceiver>);

/// The sending half of a link: hands one message to the link.
pub trait LinkSender: Send + 'static {
    /// Sends `message` as one message. An error ends the link; the transport dials a new
    /// one and `message` is lost.
    fn send(&mut self, message: &[u8]) -> BoxFuture<'_, io::Result<()>>;
}

/// The receiving half of a link: yields one message at a time.
pub trait LinkReceiver: Send + 'static {
    /// Receives the next message; `None` once the link is closed. `None` or an error ends
    /// the link and the transport dials a new one.
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Option<Bytes>>>;
}

/// The state of a [`LinkTransport`]'s link, reported to [`LinkDialer::on_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkState {
    /// A dial succeeded; the link carries datagrams.
    Connected,
    /// The link was lost (closed, failed or idle); the transport dials again.
    Disconnected,
    /// The far end refused the link with this HTTP status, e.g. 401 or 403. Reported by
    /// dialers (to their own observers, when a dial is refused), never by
    /// [`LinkTransport`] itself.
    Rejected(u16),
}

/// Opens the links a [`LinkTransport`] runs on.
pub trait LinkDialer: Send + Sync + 'static {
    /// Opens a new link and returns its two halves.
    ///
    /// The transport calls this whenever it has no link: at start, after a link was lost
    /// and again right after a failed dial. The dialer owns the backoff: it may sleep in
    /// here before connecting (and should, after failures), since the transport only
    /// yields to the runtime between calls.
    fn dial(&self) -> BoxFuture<'_, io::Result<Link>>;

    /// Called when the link comes up ([`LinkState::Connected`], after each successful
    /// [`dial`](Self::dial)) and when it is lost ([`LinkState::Disconnected`], before the
    /// next dial). Does nothing by default.
    fn on_state(&self, state: LinkState) {
        let _ = state;
    }
}

/// Settings of a [`LinkTransport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkConfig {
    /// How many datagrams wait for the link; once full, [`Transport::send`] fails at once.
    /// 256 by default; 0 is taken as 1.
    pub queue: usize,
    /// Closes the link (and dials again) when no message arrived on it for this long;
    /// `None` (the default) never does.
    pub read_idle_timeout: Option<Duration>,
}

impl LinkConfig {
    /// The default settings.
    pub const fn new() -> Self {
        Self {
            queue: 256,
            read_idle_timeout: None,
        }
    }

    /// Sets [`queue`](Self::queue).
    #[must_use]
    pub const fn queue(mut self, queue: usize) -> Self {
        self.queue = queue;
        self
    }

    /// Sets [`read_idle_timeout`](Self::read_idle_timeout).
    #[must_use]
    pub const fn read_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.read_idle_timeout = timeout;
        self
    }
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`Transport`] to one peer over a message link: one datagram is one message.
///
/// A background task dials the link through a [`LinkDialer`], drains the send queue into
/// the link's [`LinkSender`] and hands what its [`LinkReceiver`] yields to
/// [`recv`](Transport::recv). When the link is lost (the receiver yields `None` or an
/// error, a send fails, or [`LinkConfig::read_idle_timeout`] passes without a message) the
/// task reports [`LinkState::Disconnected`] and dials again; the dialer owns the backoff.
///
/// - Received datagrams come from `Path { transport: id, addr: peer, ecn: NotEct }`. A
///   message longer than the receive buffer is truncated to it, as the [`Transport`]
///   buffer contract says.
/// - A datagram sent to an address other than `peer` is dropped and counts as sent.
/// - Sent datagrams wait in a queue of [`LinkConfig::queue`] entries, also while no link
///   is up. `send` never waits: on a full queue it fails with
///   [`io::ErrorKind::WouldBlock`] and the engine counts
///   [`DROP_TRANSPORT_SEND_ERROR`](crate::DROP_TRANSPORT_SEND_ERROR). A datagram whose
///   send failed on a lost link is gone; the queued ones go out on the next link.
/// - `recv` keeps waiting while the task redials; it fails only once the task is gone.
///
/// Dropping the transport stops the task and drops its link.
///
/// ```no_run
/// use std::io;
/// use std::sync::Arc;
///
/// use nsplane::{
///     BoxFuture, LinkConfig, LinkDialer, LinkReceiver, LinkSender, LinkState, LinkTransport,
///     TransportId,
/// };
///
/// struct Relay;
///
/// impl LinkDialer for Relay {
///     fn dial(&self) -> BoxFuture<'_, io::Result<(Box<dyn LinkSender>, Box<dyn LinkReceiver>)>> {
///         Box::pin(async {
///             // Connect (a WebSocket, say), back off after failures, split the stream.
///             Err(io::Error::other("not implemented"))
///         })
///     }
///
///     fn on_state(&self, state: LinkState) {
///         println!("relay link {state:?}");
///     }
/// }
///
/// # async fn run() {
/// let transport = LinkTransport::new(
///     TransportId::new(2),
///     "192.0.2.1:443".parse().unwrap(),
///     Arc::new(Relay),
///     LinkConfig::default(),
/// );
/// # }
/// ```
pub struct LinkTransport {
    id: TransportId,
    peer: SocketAddr,
    outgoing: mpsc::Sender<Bytes>,
    incoming: Mutex<mpsc::Receiver<Bytes>>,
    task: JoinHandle<()>,
}

impl LinkTransport {
    /// Creates the transport and spawns its task, which starts dialing at once.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime.
    pub fn new(
        id: TransportId,
        peer: SocketAddr,
        dialer: Arc<dyn LinkDialer>,
        config: LinkConfig,
    ) -> Self {
        let capacity = config.queue.max(1);
        let (outgoing, outgoing_rx) = mpsc::channel(capacity);
        let (incoming_tx, incoming) = mpsc::channel(capacity);
        let task = tokio::spawn(run(
            dialer,
            config.read_idle_timeout,
            outgoing_rx,
            incoming_tx,
        ));
        Self {
            id,
            peer,
            outgoing,
            incoming: Mutex::new(incoming),
            task,
        }
    }

    /// The peer's address: the source of every received datagram and the only
    /// destination that is sent.
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }
}

impl fmt::Debug for LinkTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkTransport")
            .field("id", &self.id)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl Drop for LinkTransport {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The error once the task is gone.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "link transport closed")
}

impl Transport for LinkTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        let message = self.incoming.lock().await.recv().await.ok_or_else(closed)?;
        let len = message.len().min(buf.capacity());
        buf.set_len(buf.capacity());
        buf.as_packet_mut()[..len].copy_from_slice(&message[..len]);
        buf.set_len(len);
        let path = Path {
            transport: self.id,
            addr: self.peer,
            ecn: Ecn::NotEct,
        };
        Ok((len, path))
    }

    fn send(&self, datagram: &[u8], to: &Path) -> impl Future<Output = io::Result<()>> + Send {
        let result = if to.addr == self.peer {
            self.outgoing
                .try_send(Bytes::copy_from_slice(datagram))
                .map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => {
                        io::Error::new(io::ErrorKind::WouldBlock, "link send queue full")
                    }
                    mpsc::error::TrySendError::Closed(_) => closed(),
                })
        } else {
            Ok(())
        };
        std::future::ready(result)
    }
}

/// Why a link ended.
enum End {
    /// The link was lost; dial again.
    Lost,
    /// The transport is gone; stop.
    Finished,
}

/// The task: dials, pumps the link until it ends, and dials again.
async fn run(
    dialer: Arc<dyn LinkDialer>,
    idle: Option<Duration>,
    mut outgoing: mpsc::Receiver<Bytes>,
    incoming: mpsc::Sender<Bytes>,
) {
    loop {
        let (mut sender, mut receiver) = match dialer.dial().await {
            Ok(link) => link,
            Err(e) => {
                tracing::debug!(message = "Link dial failed", error = %e);
                tokio::task::yield_now().await;
                continue;
            }
        };
        dialer.on_state(LinkState::Connected);
        let end = pump(&mut *sender, &mut *receiver, &mut outgoing, &incoming, idle).await;
        drop((sender, receiver));
        dialer.on_state(LinkState::Disconnected);
        if matches!(end, End::Finished) {
            return;
        }
    }
}

/// Carries datagrams both ways over one link until it ends.
async fn pump(
    sender: &mut dyn LinkSender,
    receiver: &mut dyn LinkReceiver,
    outgoing: &mut mpsc::Receiver<Bytes>,
    incoming: &mpsc::Sender<Bytes>,
    idle: Option<Duration>,
) -> End {
    let mut send = pin!(async {
        while let Some(message) = outgoing.recv().await {
            if let Err(e) = sender.send(&message).await {
                tracing::debug!(message = "Link send failed", error = %e);
                return End::Lost;
            }
        }
        End::Finished
    });
    let mut recv = pin!(async {
        loop {
            let received = match idle {
                Some(idle) => {
                    let Ok(received) = tokio::time::timeout(idle, receiver.recv()).await else {
                        tracing::debug!(message = "Link read idle", timeout = ?idle);
                        return End::Lost;
                    };
                    received
                }
                None => receiver.recv().await,
            };
            match received {
                Ok(Some(message)) => {
                    if incoming.send(message).await.is_err() {
                        return End::Finished;
                    }
                }
                Ok(None) => return End::Lost,
                Err(e) => {
                    tracing::debug!(message = "Link receive failed", error = %e);
                    return End::Lost;
                }
            }
        }
    });
    poll_fn(|cx| {
        if let Poll::Ready(end) = send.as_mut().poll(cx) {
            return Poll::Ready(end);
        }
        recv.as_mut().poll(cx)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsplane_packet::HEADROOM;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    const PEER: &str = "192.0.2.1:443";

    /// One direction of an in-memory link.
    struct Tx(mpsc::Sender<Bytes>);

    impl LinkSender for Tx {
        fn send(&mut self, message: &[u8]) -> BoxFuture<'_, io::Result<()>> {
            let message = Bytes::copy_from_slice(message);
            Box::pin(async move {
                self.0
                    .send(message)
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
            })
        }
    }

    struct Rx(mpsc::Receiver<Bytes>);

    impl LinkReceiver for Rx {
        fn recv(&mut self) -> BoxFuture<'_, io::Result<Option<Bytes>>> {
            Box::pin(async move { Ok(self.0.recv().await) })
        }
    }

    /// The far end of one dialed link: what the transport sent, and a sender into it.
    struct Far {
        sent: mpsc::Receiver<Bytes>,
        reply: mpsc::Sender<Bytes>,
    }

    /// Hands out in-memory links while the far ends are taken; records dials and states.
    struct MemDialer {
        dials: AtomicUsize,
        states: StdMutex<Vec<LinkState>>,
        far: mpsc::UnboundedSender<Far>,
        /// Dials wait for a permit when set.
        gate: Option<Arc<Notify>>,
    }

    impl MemDialer {
        fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<Far>) {
            Self::with_gate(None)
        }

        fn with_gate(gate: Option<Arc<Notify>>) -> (Arc<Self>, mpsc::UnboundedReceiver<Far>) {
            let (tx, rx) = mpsc::unbounded_channel();
            let dialer = Self {
                dials: AtomicUsize::new(0),
                states: StdMutex::new(Vec::new()),
                far: tx,
                gate,
            };
            (Arc::new(dialer), rx)
        }

        fn states(&self) -> Vec<LinkState> {
            self.states.lock().unwrap().clone()
        }
    }

    impl LinkDialer for MemDialer {
        fn dial(&self) -> BoxFuture<'_, io::Result<Link>> {
            Box::pin(async move {
                self.dials.fetch_add(1, Ordering::SeqCst);
                if let Some(gate) = &self.gate {
                    gate.notified().await;
                }
                let (sent_tx, sent) = mpsc::channel(64);
                let (reply, reply_rx) = mpsc::channel(64);
                if self.far.send(Far { sent, reply }).is_err() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    return Err(io::Error::other("refused"));
                }
                let link: Link = (Box::new(Tx(sent_tx)), Box::new(Rx(reply_rx)));
                Ok(link)
            })
        }

        fn on_state(&self, state: LinkState) {
            self.states.lock().unwrap().push(state);
        }
    }

    fn peer() -> SocketAddr {
        PEER.parse().unwrap()
    }

    fn to(addr: SocketAddr) -> Path {
        Path {
            transport: TransportId::new(1),
            addr,
            ecn: Ecn::NotEct,
        }
    }

    fn transport(dialer: &Arc<MemDialer>, config: LinkConfig) -> LinkTransport {
        LinkTransport::new(TransportId::new(1), peer(), dialer.clone(), config)
    }

    #[test]
    fn config_defaults() {
        let config = LinkConfig::default();
        assert_eq!(config.queue, 256);
        assert_eq!(config.read_idle_timeout, None);
        let config = LinkConfig::new()
            .queue(4)
            .read_idle_timeout(Some(Duration::from_secs(1)));
        assert_eq!(config.queue, 4);
        assert_eq!(config.read_idle_timeout, Some(Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn both_directions() {
        let (dialer, mut links) = MemDialer::new();
        let link = transport(&dialer, LinkConfig::default());
        let mut far = links.recv().await.unwrap();

        link.send(b"out", &to(peer())).await.unwrap();
        assert_eq!(far.sent.recv().await.unwrap(), &b"out"[..]);

        far.reply.send(Bytes::from_static(b"in")).await.unwrap();
        let mut buf = PacketBuf::with_capacity(64);
        let (len, path) = link.recv(&mut buf).await.unwrap();
        assert_eq!(&buf.as_packet()[..len], b"in");
        assert_eq!(
            path,
            Path {
                transport: TransportId::new(1),
                addr: peer(),
                ecn: Ecn::NotEct
            }
        );
        assert_eq!(dialer.states(), [LinkState::Connected]);
    }

    #[tokio::test]
    async fn truncates_and_keeps_headroom() {
        let (dialer, mut links) = MemDialer::new();
        let link = transport(&dialer, LinkConfig::default());
        let far = links.recv().await.unwrap();
        let message: Vec<u8> = (0..=255).collect();
        far.reply.send(Bytes::from(message.clone())).await.unwrap();

        let mut buf = PacketBuf::with_capacity(16);
        buf.with_headroom_mut()[..HEADROOM].fill(0xAA);
        let capacity = buf.capacity();
        let (len, _) = link.recv(&mut buf).await.unwrap();
        assert_eq!(len, capacity);
        assert_eq!(buf.as_packet(), &message[..capacity]);
        assert!(
            buf.with_headroom_mut()[..HEADROOM]
                .iter()
                .all(|&b| b == 0xAA)
        );
    }

    #[tokio::test]
    async fn drops_wrong_address() {
        let (dialer, mut links) = MemDialer::new();
        let link = transport(&dialer, LinkConfig::default());
        let mut far = links.recv().await.unwrap();
        link.send(b"lost", &to("198.51.100.9:9".parse().unwrap()))
            .await
            .unwrap();
        link.send(b"kept", &to(peer())).await.unwrap();
        assert_eq!(far.sent.recv().await.unwrap(), &b"kept"[..]);
    }

    #[tokio::test]
    async fn queue_full_fails_then_drains() {
        let gate = Arc::new(Notify::new());
        let (dialer, mut links) = MemDialer::with_gate(Some(gate.clone()));
        let link = transport(&dialer, LinkConfig::new().queue(3));
        for i in 0..3u8 {
            link.send(&[i], &to(peer())).await.unwrap();
        }
        let err = link.send(&[3], &to(peer())).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        gate.notify_one();
        let mut far = links.recv().await.unwrap();
        for i in 0..3u8 {
            assert_eq!(far.sent.recv().await.unwrap(), &[i][..]);
        }
        link.send(&[4], &to(peer())).await.unwrap();
        assert_eq!(far.sent.recv().await.unwrap(), &[4][..]);
    }

    #[tokio::test]
    async fn redials_after_close() {
        let (dialer, mut links) = MemDialer::new();
        let link = transport(&dialer, LinkConfig::default());
        let far = links.recv().await.unwrap();
        drop(far);

        let mut far = links.recv().await.unwrap();
        link.send(b"again", &to(peer())).await.unwrap();
        assert_eq!(far.sent.recv().await.unwrap(), &b"again"[..]);
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
        assert_eq!(
            dialer.states(),
            [
                LinkState::Connected,
                LinkState::Disconnected,
                LinkState::Connected
            ]
        );
        far.reply.send(Bytes::from_static(b"back")).await.unwrap();
        let mut buf = PacketBuf::with_capacity(64);
        let (len, _) = link.recv(&mut buf).await.unwrap();
        assert_eq!(&buf.as_packet()[..len], b"back");
    }

    #[tokio::test]
    async fn redials_after_failed_dial() {
        let (dialer, links) = MemDialer::new();
        drop(links);
        let link = transport(&dialer, LinkConfig::default());
        while dialer.dials.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(dialer.states(), []);
        drop(link);
    }

    #[tokio::test]
    async fn idle_timeout_redials() {
        let (dialer, mut links) = MemDialer::new();
        let config = LinkConfig::new().read_idle_timeout(Some(Duration::from_millis(500)));
        let link = transport(&dialer, config);
        let first = links.recv().await.unwrap();

        // Messages keep the link up.
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            first.reply.send(Bytes::from_static(b"ping")).await.unwrap();
        }
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 1);

        let mut second = links.recv().await.unwrap();
        link.send(b"up", &to(peer())).await.unwrap();
        assert_eq!(second.sent.recv().await.unwrap(), &b"up"[..]);
        assert_eq!(dialer.dials.load(Ordering::SeqCst), 2);
        assert_eq!(
            dialer.states(),
            [
                LinkState::Connected,
                LinkState::Disconnected,
                LinkState::Connected
            ]
        );
    }

    #[tokio::test]
    async fn drop_stops_the_task() {
        let (dialer, mut links) = MemDialer::new();
        let link = transport(&dialer, LinkConfig::default());
        let mut far = links.recv().await.unwrap();
        drop(link);
        assert!(far.sent.recv().await.is_none());
    }
}
