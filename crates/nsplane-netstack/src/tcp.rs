//! The application side of a TCP connection.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, watch};

/// Progress of the application's write half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteHalf {
    /// Writes are accepted.
    Open,
    /// The application shut its write half down; FIN follows the buffered bytes.
    Shutdown,
    /// The FIN is queued in the socket (or the socket can no longer send).
    FinSent,
}

/// State shared between a [`TcpConnection`] and the driver.
///
/// `rx` holds bytes the stack received and the application has not read yet; `tx` holds
/// bytes the application wrote and the stack has not taken yet. Both are bounded by the
/// stream buffer size, except that bytes still in a terminal socket move into `rx` in one
/// go (bounded by the socket's receive buffer).
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) rx: VecDeque<u8>,
    /// The peer's FIN arrived and every byte before it is in `rx`.
    pub(crate) rx_eof: bool,
    pub(crate) reader: Option<Waker>,
    pub(crate) tx: VecDeque<u8>,
    pub(crate) write_half: WriteHalf,
    pub(crate) writer: Option<Waker>,
    /// The application dropped the connection.
    pub(crate) app_dropped: bool,
    /// The application aborted the connection: reset it instead of closing it.
    pub(crate) aborted: bool,
    /// The driver released the connection: the socket is gone (or the stack stopped).
    pub(crate) released: bool,
    pub(crate) capacity: usize,
}

impl Shared {
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            rx_eof: false,
            reader: None,
            tx: VecDeque::new(),
            write_half: WriteHalf::Open,
            writer: None,
            app_dropped: false,
            aborted: false,
            released: false,
            capacity,
        }
    }

    pub(crate) fn wake_reader(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
    }

    pub(crate) fn wake_writer(&mut self) {
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }
}

/// Send progress of a connection, written by the driver once per turn and read without a
/// lock by [`TcpConnection::unacked`] and [`TcpConnection::last_ack`].
#[derive(Debug)]
pub(crate) struct Progress {
    /// The instant `last_ack` counts from.
    epoch: Instant,
    unacked: AtomicU32,
    /// Microseconds after `epoch` plus one when the peer last acknowledged data; zero
    /// before it ever did.
    last_ack: AtomicU64,
}

impl Progress {
    pub(crate) const fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            unacked: AtomicU32::new(0),
            last_ack: AtomicU64::new(0),
        }
    }

    /// Records the bytes in the socket not acknowledged yet.
    pub(crate) fn set_unacked(&self, unacked: usize) {
        let unacked = u32::try_from(unacked).unwrap_or(u32::MAX);
        self.unacked.store(unacked, Ordering::Relaxed);
    }

    /// Records an acknowledgement `micros` after the epoch.
    pub(crate) fn set_last_ack(&self, micros: u64) {
        self.last_ack
            .store(micros.saturating_add(1), Ordering::Relaxed);
    }
}

/// Locks `shared`, ignoring poisoning (the state stays consistent at every unlock).
pub(crate) fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "connection closed")
}

/// A TCP connection terminated by the stack.
///
/// Reads return the bytes the peer sent and then `Ok(0)` once the peer's FIN arrived
/// (and every byte before it was read); writes keep working after that, so a peer that
/// half-closed still gets its response. Shutting the write half down
/// ([`AsyncWrite::poll_shutdown`], `AsyncWriteExt::shutdown`) sends a FIN once the
/// buffered bytes are handed to the stack, while reads keep working. Writes fail with
/// [`io::ErrorKind::BrokenPipe`] after a shutdown, after the connection was reset or
/// timed out, and once the stack stopped.
///
/// Dropping the connection closes it gracefully (FIN after the buffered bytes) and
/// discards bytes that arrive afterwards; the socket and its tuple stay with the stack
/// until the close completes. [`abort`](Self::abort) resets the connection instead and
/// releases it at once. A connection without traffic in either
/// direction for 5 minutes is aborted.
pub struct TcpConnection {
    shared: Arc<Mutex<Shared>>,
    progress: Arc<Progress>,
    driver: Arc<Notify>,
    local: SocketAddr,
    peer: SocketAddr,
    terminal: watch::Receiver<bool>,
}

impl TcpConnection {
    pub(crate) const fn new(
        shared: Arc<Mutex<Shared>>,
        progress: Arc<Progress>,
        driver: Arc<Notify>,
        local: SocketAddr,
        peer: SocketAddr,
        terminal: watch::Receiver<bool>,
    ) -> Self {
        Self {
            shared,
            progress,
            driver,
            local,
            peer,
            terminal,
        }
    }

    /// The stack's end of the connection.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The peer's end of the connection.
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Waits until the stack has released the connection's socket.
    ///
    /// After this resolves the connection can no longer emit packets, so state that
    /// correlates the connection with something outside the stack can be released. The
    /// socket is released once it is closed (or in TIME-WAIT) and every received byte was
    /// read, or after the idle timeout, or when the stack stops.
    pub async fn terminated(&self) {
        let mut terminal = self.terminal.clone();
        // An error means the driver is gone, which releases every connection.
        let _ = terminal.wait_for(|terminal| *terminal).await;
    }

    /// Resets the connection and releases it at once.
    ///
    /// The stack sends an RST to the peer instead of the FIN a drop sends, discards the
    /// bytes not read or not taken yet, and releases the socket within the driver turn
    /// that observes the abort, without waiting for the peer, TIME-WAIT or the idle
    /// timeout. After that turn [`NetStackHandle::owns`](crate::NetStackHandle::owns) no
    /// longer reports the connection's tuple, its local port can be connected from again,
    /// and the release [`terminated`](Self::terminated) waits for has happened. A
    /// connection the peer already reset or closed is only released; no RST is sent.
    pub fn abort(self) {
        let mut shared = lock(&self.shared);
        shared.aborted = true;
        shared.app_dropped = true;
        // Drop notifies the driver.
    }

    /// Bytes handed to the stack's socket that the peer has not acknowledged yet.
    ///
    /// This is SND.NXT - SND.UNA plus the bytes the socket holds back for the peer's window
    /// or the congestion window, so it stays above zero while the peer makes no progress.
    /// Bytes still waiting in the connection's own buffer (written but not taken by the
    /// stack yet) are not counted. The driver updates it once per turn; it keeps its last
    /// value after the connection closed and drops to zero on a reset.
    pub fn unacked(&self) -> u32 {
        self.progress.unacked.load(Ordering::Relaxed)
    }

    /// When the stack last saw the peer acknowledge new data (SND.UNA advance), or `None`
    /// before the peer acknowledged any data.
    ///
    /// The driver notices an acknowledgement in the turn that processes it, so the instant
    /// is that turn's time. The value stays readable after the connection closed.
    pub fn last_ack(&self) -> Option<Instant> {
        match self.progress.last_ack.load(Ordering::Relaxed) {
            0 => None,
            micros => Some(self.progress.epoch + Duration::from_micros(micros - 1)),
        }
    }

    /// The barrier behind [`terminated`](Self::terminated), observable after an abort.
    #[cfg(test)]
    pub(crate) fn terminal(&self) -> watch::Receiver<bool> {
        self.terminal.clone()
    }

    /// Bytes received and not read yet.
    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        lock(&self.shared).rx.len()
    }
}

impl fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpConnection")
            .field("local", &self.local)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut shared = lock(&self.shared);
        if shared.rx.is_empty() {
            if shared.rx_eof || shared.released {
                return Poll::Ready(Ok(()));
            }
            shared.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let before = shared.rx.len();
        let n = before.min(buf.remaining());
        let (front, back) = shared.rx.as_slices();
        let from_front = n.min(front.len());
        buf.put_slice(&front[..from_front]);
        buf.put_slice(&back[..n - from_front]);
        shared.rx.drain(..n);
        // The driver stops moving bytes while `rx` is full and reaps a terminal socket
        // only once `rx` is empty; both need it to run again.
        let wake = before >= shared.capacity || shared.rx.is_empty();
        drop(shared);
        if wake {
            self.driver.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut shared = lock(&self.shared);
        if shared.released || shared.write_half != WriteHalf::Open {
            return Poll::Ready(Err(broken_pipe()));
        }
        let room = shared.capacity.saturating_sub(shared.tx.len());
        if room == 0 {
            shared.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(buf.len());
        shared.tx.extend(&buf[..n]);
        drop(shared);
        self.driver.notify_one();
        Poll::Ready(Ok(n))
    }

    /// Waits until every written byte is handed to the stack's socket.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut shared = lock(&self.shared);
        if shared.tx.is_empty() {
            return Poll::Ready(Ok(()));
        }
        if shared.released {
            return Poll::Ready(Err(broken_pipe()));
        }
        shared.writer = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Shuts the write half down and waits until the FIN is queued behind the written bytes.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut shared = lock(&self.shared);
        if shared.write_half == WriteHalf::FinSent || shared.released {
            return Poll::Ready(Ok(()));
        }
        let notify = shared.write_half == WriteHalf::Open;
        shared.write_half = WriteHalf::Shutdown;
        shared.writer = Some(cx.waker().clone());
        drop(shared);
        if notify {
            self.driver.notify_one();
        }
        Poll::Pending
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        lock(&self.shared).app_dropped = true;
        self.driver.notify_one();
    }
}
