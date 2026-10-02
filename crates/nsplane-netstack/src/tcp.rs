//! The application side of a TCP connection.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

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
/// discards bytes that arrive afterwards. A connection without traffic in either
/// direction for 5 minutes is aborted.
pub struct TcpConnection {
    shared: Arc<Mutex<Shared>>,
    driver: Arc<Notify>,
    local: SocketAddr,
    peer: SocketAddr,
    terminal: watch::Receiver<bool>,
}

impl TcpConnection {
    pub(crate) const fn new(
        shared: Arc<Mutex<Shared>>,
        driver: Arc<Notify>,
        local: SocketAddr,
        peer: SocketAddr,
        terminal: watch::Receiver<bool>,
    ) -> Self {
        Self {
            shared,
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
