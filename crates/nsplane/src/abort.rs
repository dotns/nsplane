//! A [`PacketSink`] whose pending delivery can be cancelled: [`AbortSink`] and its
//! [`SinkAbort`] handle.

use std::collections::VecDeque;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::Poll;

use nsplane_packet::{PacketBuf, PeerId};
use tokio::sync::Notify;

#[cfg(doc)]
use crate::SwapSink;
use crate::io::PacketSink;

/// The state an [`AbortSink`] and its [`SinkAbort`] handles share.
#[derive(Debug, Default)]
struct AbortState {
    aborted: AtomicBool,
    notify: Notify,
}

/// Aborts an [`AbortSink`]: cancels the delivery it is waiting on and makes it drop
/// every later packet.
///
/// Clones abort the same sink. Aborting is permanent; aborting again does nothing.
#[derive(Debug, Clone)]
pub struct SinkAbort {
    state: Arc<AbortState>,
}

impl SinkAbort {
    /// Aborts the sink: a pending `send` or `send_batch` on it stops waiting for the inner
    /// sink and returns `Ok`, and every later call drops its packets.
    pub fn abort(&self) {
        self.state.aborted.store(true, Ordering::Release);
        self.state.notify.notify_waiters();
    }

    /// Whether [`SinkAbort::abort`] was called.
    pub fn is_aborted(&self) -> bool {
        self.state.aborted.load(Ordering::Acquire)
    }

    /// Resolves once the sink is aborted.
    async fn aborted(&self) {
        // Created before the check, so an abort in between still wakes it.
        let notified = self.state.notify.notified();
        if self.is_aborted() {
            return;
        }
        notified.await;
    }
}

/// A [`PacketSink`] whose pending delivery to `inner` can be cancelled through a
/// [`SinkAbort`].
///
/// For a sink replaced per generation in a [`SwapSink`] (see the [`SwapSink`]
/// example): a delivery stuck on the old generation's full sink would otherwise
/// hold up the engine until that sink drains, or deliver packets after the old
/// generation was stopped.
///
/// Semantics of [`PacketSink::send`] and [`PacketSink::send_batch`]:
/// - Until the sink is aborted, the call races the inner sink's call against the abort;
///   the inner result is returned unchanged. A call that does not wait costs one atomic
///   load more than the inner call.
/// - On [`SinkAbort::abort`], a pending inner call is dropped, so nothing it was
///   delivering arrives later: the packet, or for a batch the packet being delivered and
///   the ones left in `packets`, is dropped and counted in [`AbortSink::dropped`], and the
///   call returns `Ok` with `packets` empty. The packet being delivered is counted as one
///   once the inner sink took any packet of the batch over, per the [`PacketSink`]
///   contract that cancelling `send_batch` drops the packet being delivered; an inner
///   sink that takes several packets over at once may lose more than are counted.
/// - After the abort, every call drops and counts its packets and returns `Ok` at once,
///   without calling the inner sink.
///
/// [`PacketSink::try_send_batch`] goes to the inner sink until the abort, and drops and
/// counts every packet and returns `Ok` after it.
///
/// An aborted sink returns `Ok`, not [`io::ErrorKind::BrokenPipe`]: behind a [`SwapSink`]
/// the next generation may already be installed, and a `BrokenPipe` would make the
/// engine (or a `pump`) take the whole local side for gone. Stopping whatever feeds the
/// aborted sink stays the caller's job.
pub struct AbortSink<S> {
    inner: S,
    abort: SinkAbort,
    dropped: AtomicU64,
}

impl<S: PacketSink> AbortSink<S> {
    /// Wraps `sink`, returning the sink and the handle that aborts it.
    pub fn new(sink: S) -> (Self, SinkAbort) {
        let abort = SinkAbort {
            state: Arc::new(AbortState::default()),
        };
        let wrapped = Self {
            inner: sink,
            abort: abort.clone(),
            dropped: AtomicU64::new(0),
        };
        (wrapped, abort)
    }

    /// Packets dropped so far because the sink was aborted.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Counts `n` dropped packets.
    fn count(&self, n: usize) {
        self.dropped.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Runs `delivery` until it completes (`Some`) or the sink is aborted (`None`); the
    /// abort is polled only while `delivery` waits.
    async fn race(&self, delivery: impl Future<Output = io::Result<()>>) -> Option<io::Result<()>> {
        let mut delivery = pin!(delivery);
        let mut aborted = pin!(self.abort.aborted());
        poll_fn(|cx| {
            if let Poll::Ready(result) = delivery.as_mut().poll(cx) {
                return Poll::Ready(Some(result));
            }
            aborted.as_mut().poll(cx).map(|()| None)
        })
        .await
    }
}

impl<S: PacketSink> PacketSink for AbortSink<S> {
    async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
        if self.abort.is_aborted() {
            self.count(1);
            return Ok(());
        }
        self.race(self.inner.send(packet, from))
            .await
            .unwrap_or_else(|| {
                self.count(1);
                Ok(())
            })
    }

    async fn send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        let total = packets.len();
        if !self.abort.is_aborted()
            && let Some(result) = self.race(self.inner.send_batch(packets)).await
        {
            return result;
        }
        // Aborted: the packet being delivered, if the inner sink took any over, and the
        // ones it left.
        let in_flight = usize::from(packets.len() < total);
        self.count(packets.len() + in_flight);
        packets.clear();
        Ok(())
    }

    fn try_send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        if self.abort.is_aborted() {
            self.count(packets.len());
            packets.clear();
            return Ok(());
        }
        self.inner.try_send_batch(packets)
    }
}

impl<S: fmt::Debug> fmt::Debug for AbortSink<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbortSink")
            .field("inner", &self.inner)
            .field("aborted", &self.abort.is_aborted())
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::ChannelSink;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// How long a call must stay pending to count as waiting.
    const PENDING: Duration = Duration::from_millis(50);
    const WAIT: Duration = Duration::from_secs(5);

    fn packet(byte: u8) -> PacketBuf {
        PacketBuf::from_packet(&[byte])
    }

    fn batch(bytes: &[u8]) -> VecDeque<(PeerId, PacketBuf)> {
        bytes
            .iter()
            .map(|&byte| (PeerId::new(u32::from(byte)), packet(byte)))
            .collect()
    }

    /// The first byte of the next packet on `rx`.
    async fn next(rx: &mut tokio::sync::mpsc::Receiver<(PeerId, PacketBuf)>) -> Result<u8, String> {
        let (_, packet) = timeout(WAIT, rx.recv())
            .await
            .map_err(|_| "no packet")?
            .ok_or("closed")?;
        packet
            .as_packet()
            .first()
            .copied()
            .ok_or_else(|| "empty".into())
    }

    #[tokio::test]
    async fn abort_cancels_a_send_on_a_full_sink() -> TestResult {
        let (inner, mut rx) = ChannelSink::new(1);
        let (sink, abort) = AbortSink::new(inner);
        sink.send(packet(1), PeerId::new(1)).await?;
        let mut pending = Box::pin(sink.send(packet(2), PeerId::new(2)));
        assert!(timeout(PENDING, &mut pending).await.is_err());

        abort.abort();
        timeout(WAIT, pending).await??;
        assert!(abort.is_aborted());
        assert_eq!(sink.dropped(), 1);
        // The queue has room again, and nothing arrives after the abort.
        assert_eq!(next(&mut rx).await?, 1);
        assert!(timeout(PENDING, rx.recv()).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn abort_cancels_a_batch_stuck_on_a_full_sink() -> TestResult {
        let (inner, mut rx) = ChannelSink::new(2);
        let (sink, abort) = AbortSink::new(inner);
        let mut packets = batch(&[1, 2, 3, 4, 5]);
        let mut pending = Box::pin(sink.send_batch(&mut packets));
        assert!(timeout(PENDING, &mut pending).await.is_err());

        abort.clone().abort();
        timeout(WAIT, pending).await??;
        assert!(packets.is_empty());
        // 3 was being delivered; 4 and 5 were left.
        assert_eq!(sink.dropped(), 3);
        assert_eq!(next(&mut rx).await?, 1);
        assert_eq!(next(&mut rx).await?, 2);
        assert!(timeout(PENDING, rx.recv()).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn aborted_sink_drops_at_once() -> TestResult {
        let (inner, mut rx) = ChannelSink::new(4);
        let (sink, abort) = AbortSink::new(inner);
        sink.send(packet(1), PeerId::new(1)).await?;
        let mut packets = batch(&[2]);
        let err = sink
            .try_send_batch(&mut packets)
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(sink.dropped(), 0);

        abort.abort();
        abort.abort();
        sink.send(packet(3), PeerId::new(3)).await?;
        let mut more = batch(&[4, 5]);
        sink.send_batch(&mut more).await?;
        sink.try_send_batch(&mut packets)?;
        assert!(more.is_empty() && packets.is_empty());
        assert_eq!(sink.dropped(), 4);
        assert_eq!(next(&mut rx).await?, 1);
        assert!(rx.is_empty());
        Ok(())
    }
}
