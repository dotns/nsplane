//! A [`PacketSink`] whose inner sink can be replaced while the engine runs: [`SwapSink`].

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use nsplane_packet::{PacketBuf, PeerId};

#[cfg(doc)]
use crate::AbortSink;
use crate::io::PacketSink;

/// The state the clones of a [`SwapSink`] share.
struct SwapState<S> {
    current: RwLock<Option<Arc<S>>>,
    dropped: AtomicU64,
}

/// A [`PacketSink`] whose inner sink can be replaced, or removed, while the engine runs.
///
/// Clones share the inner sink and the drop counter: the engine owns one, the embedder
/// keeps another to call [`SwapSink::replace`] on.
///
/// An embedder that rebuilds the local side per generation (a new TUN writer, a new
/// encrypt sender) gives the engine a [`SwapSink`] and installs each generation's sink in
/// it, wrapped in an [`AbortSink`] so a delivery stuck on the old generation can be
/// cancelled:
///
/// ```
/// # use nsplane::{AbortSink, ChannelSink, SwapSink};
/// // The engine gets a clone: `EngineBuilder::new(source, swap.clone())`. While the slot
/// // is empty, delivered packets are dropped and counted.
/// let swap = SwapSink::new(None);
///
/// // Generation 1.
/// let (sink1, _rx1) = ChannelSink::new(64);
/// let (gen1, abort1) = AbortSink::new(sink1);
/// swap.replace(Some(gen1));
///
/// // Generation 2: later packets go to it. A delivery still waiting on generation 1 is
/// // cancelled: its packets are dropped and counted, and the call returns `Ok`, not
/// // `BrokenPipe`, so the engine does not take the local side for gone and carries on
/// // with generation 2.
/// let (sink2, _rx2) = ChannelSink::new(64);
/// let (gen2, abort2) = AbortSink::new(sink2);
/// let old = swap.replace(Some(gen2));
/// abort1.abort();
///
/// assert!(old.is_some_and(|gen1| gen1.dropped() == 0));
/// assert!(abort1.is_aborted() && !abort2.is_aborted());
/// ```
///
/// Semantics of [`PacketSink::send`] and [`PacketSink::send_batch`]:
/// - While the slot is empty, every packet is dropped, counted in [`SwapSink::dropped`],
///   and the call returns `Ok` (a batch leaves `packets` empty).
/// - Otherwise the call awaits the current sink. A call in flight finishes on the sink it
///   started on, also after a [`SwapSink::replace`]; `replace` does not wait for it.
/// - An error from a sink that was replaced while the call was in flight drops the failed
///   packet (and, for a batch, the ones left in `packets`), counts them in
///   [`SwapSink::dropped`] and returns `Ok`, so the engine does not take the local side
///   for gone. An error from the current sink is returned unchanged.
///
/// [`PacketSink::try_send_batch`] goes to the current sink, which returns
/// [`io::ErrorKind::WouldBlock`] when it would wait; while the slot is empty it drops and
/// counts every packet and returns `Ok`.
///
/// Each call takes a read lock only to clone the current sink's [`Arc`]; a delivered
/// packet costs no counter update.
pub struct SwapSink<S> {
    state: Arc<SwapState<S>>,
}

impl<S: PacketSink> SwapSink<S> {
    /// A sink delivering to `sink`, or dropping every packet while it is `None`.
    pub fn new(sink: Option<S>) -> Self {
        Self {
            state: Arc::new(SwapState {
                current: RwLock::new(sink.map(Arc::new)),
                dropped: AtomicU64::new(0),
            }),
        }
    }

    /// Installs `sink` (`None` empties the slot) and returns the sink it replaces.
    ///
    /// Calls that already started on the old sink finish on it, so they may still hold
    /// it: the old sink comes back as an [`Arc`], and is dropped once the last of them and
    /// the returned value are gone. Its counters stay readable through the returned value.
    pub fn replace(&self, sink: Option<S>) -> Option<Arc<S>> {
        let sink = sink.map(Arc::new);
        let mut current = self
            .state
            .current
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *current, sink)
    }

    /// Packets dropped so far, because the slot was empty or because the sink they were
    /// handed to failed after it was replaced.
    pub fn dropped(&self) -> u64 {
        self.state.dropped.load(Ordering::Relaxed)
    }

    /// The current sink, if any.
    fn current(&self) -> Option<Arc<S>> {
        self.state
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether `sink` is still the current sink.
    fn is_current(&self, sink: &Arc<S>) -> bool {
        self.state
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, sink))
    }

    /// Drops every packet in `packets` and counts them, plus `failed` more.
    fn drop_all(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>, failed: u64) {
        self.state
            .dropped
            .fetch_add(packets.len() as u64 + failed, Ordering::Relaxed);
        packets.clear();
    }
}

impl<S> Clone for SwapSink<S> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<S: PacketSink> PacketSink for SwapSink<S> {
    async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
        let Some(sink) = self.current() else {
            self.state.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        match sink.send(packet, from).await {
            Err(_) if !self.is_current(&sink) => {
                self.state.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            result => result,
        }
    }

    async fn send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        let Some(sink) = self.current() else {
            self.drop_all(packets, 0);
            return Ok(());
        };
        match sink.send_batch(packets).await {
            Err(_) if !self.is_current(&sink) => {
                self.drop_all(packets, 1);
                Ok(())
            }
            result => result,
        }
    }

    fn try_send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        let Some(sink) = self.current() else {
            self.drop_all(packets, 0);
            return Ok(());
        };
        sink.try_send_batch(packets)
    }
}

impl<S: fmt::Debug> fmt::Debug for SwapSink<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SwapSink")
            .field(
                "current",
                &*self
                    .state
                    .current
                    .read()
                    .unwrap_or_else(PoisonError::into_inner),
            )
            .field("dropped", &self.state.dropped.load(Ordering::Relaxed))
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
    async fn swap_empty_drops_and_counts() -> TestResult {
        let swap = SwapSink::<ChannelSink>::new(None);
        swap.send(packet(1), PeerId::new(1)).await?;
        let mut packets = batch(&[2, 3]);
        swap.send_batch(&mut packets).await?;
        assert!(packets.is_empty());
        let mut packets = batch(&[4, 5, 6]);
        swap.try_send_batch(&mut packets)?;
        assert!(packets.is_empty());
        assert_eq!(swap.dropped(), 6);
        Ok(())
    }

    #[tokio::test]
    async fn swap_replace_returns_old() -> TestResult {
        let (first, mut first_rx) = ChannelSink::new(4);
        let (second, mut second_rx) = ChannelSink::new(4);
        let swap = SwapSink::new(Some(first));
        swap.send(packet(1), PeerId::new(1)).await?;

        let old = swap.replace(Some(second)).ok_or("no old sink")?;
        old.send(packet(2), PeerId::new(2)).await?;
        swap.send(packet(3), PeerId::new(3)).await?;
        assert_eq!(next(&mut first_rx).await?, 1);
        assert_eq!(next(&mut first_rx).await?, 2);
        assert_eq!(next(&mut second_rx).await?, 3);

        assert!(swap.replace(None).is_some());
        assert!(swap.replace(None).is_none());
        swap.send(packet(4), PeerId::new(4)).await?;
        assert_eq!(swap.dropped(), 1);
        assert!(second_rx.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn swap_send_in_flight_finishes_on_old_sink() -> TestResult {
        let (old, mut old_rx) = ChannelSink::new(1);
        let (new, mut new_rx) = ChannelSink::new(4);
        let swap = SwapSink::new(Some(old));
        swap.send(packet(1), PeerId::new(1)).await?;
        let mut pending = Box::pin(swap.send(packet(2), PeerId::new(2)));
        assert!(timeout(PENDING, &mut pending).await.is_err());

        // `replace` does not wait for the send in flight.
        assert!(swap.replace(Some(new)).is_some());
        swap.send(packet(3), PeerId::new(3)).await?;
        swap.send_batch(&mut batch(&[4, 5])).await?;

        assert_eq!(next(&mut old_rx).await?, 1);
        timeout(WAIT, pending).await??;
        assert_eq!(next(&mut old_rx).await?, 2);
        for byte in [3, 4, 5] {
            assert_eq!(next(&mut new_rx).await?, byte);
        }
        assert!(old_rx.is_empty() && new_rx.is_empty());
        assert_eq!(swap.dropped(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn swap_error_from_replaced_sink_is_dropped() -> TestResult {
        let (old, mut old_rx) = ChannelSink::new(1);
        let (new, mut new_rx) = ChannelSink::new(4);
        let swap = SwapSink::new(Some(old));
        swap.send(packet(1), PeerId::new(1)).await?;
        let mut sending = Box::pin(swap.send(packet(2), PeerId::new(2)));
        assert!(timeout(PENDING, &mut sending).await.is_err());
        let mut packets = batch(&[3, 4, 5]);
        let mut batching = Box::pin(swap.send_batch(&mut packets));
        assert!(timeout(PENDING, &mut batching).await.is_err());

        assert!(swap.replace(Some(new)).is_some());
        assert_eq!(next(&mut old_rx).await?, 1);
        drop(old_rx);
        timeout(WAIT, sending).await??;
        timeout(WAIT, batching).await??;
        assert!(packets.is_empty());
        // 2 failed on its own; the batch lost 3, which failed, and 4 and 5 behind it.
        assert_eq!(swap.dropped(), 4);

        swap.send(packet(6), PeerId::new(6)).await?;
        assert_eq!(next(&mut new_rx).await?, 6);
        Ok(())
    }

    #[tokio::test]
    async fn swap_error_from_current_sink_propagates() -> TestResult {
        let (sink, rx) = ChannelSink::new(4);
        let swap = SwapSink::new(Some(sink));
        drop(rx);

        let err = swap
            .send(packet(1), PeerId::new(1))
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let mut packets = batch(&[2, 3]);
        let err = swap
            .send_batch(&mut packets)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(packets.len(), 1);
        let err = swap
            .try_send_batch(&mut packets)
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(swap.dropped(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn swap_clones_share_state() -> TestResult {
        let swap = SwapSink::new(None);
        let engine_side = swap.clone();
        engine_side.send(packet(1), PeerId::new(1)).await?;
        assert_eq!(swap.dropped(), 1);

        let (sink, mut rx) = ChannelSink::new(4);
        assert!(swap.replace(Some(sink)).is_none());
        engine_side.send(packet(2), PeerId::new(2)).await?;
        assert_eq!(next(&mut rx).await?, 2);
        assert!(engine_side.replace(None).is_some());
        swap.send(packet(3), PeerId::new(3)).await?;
        assert_eq!(engine_side.dropped(), 2);
        Ok(())
    }
}
