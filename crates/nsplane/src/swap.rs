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
    current: RwLock<Slot<S>>,
    dropped: AtomicU64,
}

/// The slot of a [`SwapSink`].
struct Slot<S> {
    sink: Option<Arc<S>>,
    /// `sink` returned [`io::ErrorKind::BrokenPipe`]: it is not called again.
    gone: bool,
}

/// A [`PacketSink`] whose inner sink can be replaced, or removed, while the engine runs.
///
/// Clones share the inner sink and the drop counter: the engine owns one, the embedder
/// keeps another to call [`SwapSink::replace`] on. While the embedder keeps one, the engine
/// never takes the local side for gone, whatever happens to the inner sink.
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
///   for gone.
/// - An [`io::ErrorKind::BrokenPipe`] from the current sink means that this sink is gone,
///   not the local side: it is not called again, the failed packet (and the ones left in
///   `packets`) and every later packet are dropped and counted as for an empty slot, and
///   the calls return `Ok`. The next [`SwapSink::replace`] resumes delivery.
/// - Any other error from the current sink is returned unchanged.
/// - Once the value called is the last clone, nobody can call [`SwapSink::replace`] any
///   more: with the slot empty or its sink gone, the local side is gone for good and every
///   call returns [`io::ErrorKind::BrokenPipe`] (the failed packet is dropped and counted,
///   the rest of a batch stays in `packets`). Every other clone counts, whoever holds it.
///
/// [`PacketSink::send_batch_spent`] behaves like `send_batch` over the sink's
/// `send_batch_spent`, so that sink's spent buffers reach the caller; the packets it drops
/// (the slot is empty or its sink gone, or they were left by a replaced sink that failed)
/// have their buffers appended to `spent`.
///
/// [`PacketSink::try_send_batch`] goes to the current sink, which returns
/// [`io::ErrorKind::WouldBlock`] when it would wait; an empty slot and an
/// [`io::ErrorKind::BrokenPipe`] are handled as above.
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
                current: RwLock::new(Slot {
                    sink: sink.map(Arc::new),
                    gone: false,
                }),
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
        current.gone = false;
        std::mem::replace(&mut current.sink, sink)
    }

    /// Packets dropped so far, because the slot was empty, its sink was gone, or the sink
    /// they were handed to failed after it was replaced.
    pub fn dropped(&self) -> u64 {
        self.state.dropped.load(Ordering::Relaxed)
    }

    /// Whether another clone exists, which may still call [`SwapSink::replace`].
    fn replaceable(&self) -> bool {
        Arc::strong_count(&self.state) > 1
    }

    /// The current sink; `None` while the slot is empty or its sink is gone. Once that is
    /// for good (no other clone is left), [`io::ErrorKind::BrokenPipe`].
    fn current(&self) -> io::Result<Option<Arc<S>>> {
        {
            let current = self
                .state
                .current
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            if !current.gone
                && let Some(sink) = &current.sink
            {
                return Ok(Some(Arc::clone(sink)));
            }
        }
        if self.replaceable() {
            Ok(None)
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "swap sink closed",
            ))
        }
    }

    /// Whether `sink` is still the current sink.
    fn is_current(&self, sink: &Arc<S>) -> bool {
        self.state
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .sink
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, sink))
    }

    /// Whether `err`, which `sink` returned, is absorbed (what it failed and left is
    /// dropped and the call returns `Ok`): `sink` was replaced, or it is the current sink
    /// reporting itself gone, which marks the slot, while another clone can replace it.
    fn absorbs(&self, sink: &Arc<S>, err: &io::Error) -> bool {
        if err.kind() != io::ErrorKind::BrokenPipe {
            return !self.is_current(sink);
        }
        {
            let mut current = self
                .state
                .current
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            if !current
                .sink
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, sink))
            {
                return true;
            }
            current.gone = true;
        }
        self.replaceable()
    }

    /// Counts one dropped packet.
    fn drop_one(&self) {
        self.state.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Drops every packet in `packets` and counts them, plus `failed` more.
    fn drop_all(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>, failed: u64) {
        self.state
            .dropped
            .fetch_add(packets.len() as u64 + failed, Ordering::Relaxed);
        packets.clear();
    }

    /// Like [`SwapSink::drop_all`], appending the buffers to `spent`.
    fn drop_all_spent(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
        spent: &mut Vec<PacketBuf>,
        failed: u64,
    ) {
        self.state
            .dropped
            .fetch_add(packets.len() as u64 + failed, Ordering::Relaxed);
        spent.extend(packets.drain(..).map(|(_, packet)| packet));
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
        let Some(sink) = self.current().inspect_err(|_| self.drop_one())? else {
            self.drop_one();
            return Ok(());
        };
        match sink.send(packet, from).await {
            Err(e) if self.absorbs(&sink, &e) => {
                self.drop_one();
                Ok(())
            }
            result => result,
        }
    }

    async fn send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        let current = self.current().inspect_err(|_| {
            if packets.pop_front().is_some() {
                self.drop_one();
            }
        });
        let Some(sink) = current? else {
            self.drop_all(packets, 0);
            return Ok(());
        };
        match sink.send_batch(packets).await {
            Err(e) if self.absorbs(&sink, &e) => {
                self.drop_all(packets, 1);
                Ok(())
            }
            result => result,
        }
    }

    async fn send_batch_spent(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
        spent: &mut Vec<PacketBuf>,
    ) -> io::Result<()> {
        let current = self.current().inspect_err(|_| {
            if let Some((_, packet)) = packets.pop_front() {
                self.drop_one();
                spent.push(packet);
            }
        });
        let Some(sink) = current? else {
            self.drop_all_spent(packets, spent, 0);
            return Ok(());
        };
        match sink.send_batch_spent(packets, spent).await {
            Err(e) if self.absorbs(&sink, &e) => {
                self.drop_all_spent(packets, spent, 1);
                Ok(())
            }
            result => result,
        }
    }

    fn try_send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        let current = self.current().inspect_err(|_| {
            if packets.pop_front().is_some() {
                self.drop_one();
            }
        });
        let Some(sink) = current? else {
            self.drop_all(packets, 0);
            return Ok(());
        };
        match sink.try_send_batch(packets) {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe && self.absorbs(&sink, &e) => {
                self.drop_all(packets, 1);
                Ok(())
            }
            result => result,
        }
    }
}

impl<S: fmt::Debug> fmt::Debug for SwapSink<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let current = self
            .state
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("SwapSink")
            .field("current", &current.sink)
            .field("gone", &current.gone)
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
    use crate::io::test_sinks::{SpentSink, bytes};

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
        let _handle = swap.clone();
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
        let _handle = swap.clone();
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

    /// A sink that is gone: every call is counted and returns `BrokenPipe`.
    #[derive(Debug, Default)]
    struct Dead(std::sync::atomic::AtomicUsize);

    impl Dead {
        fn calls(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }

        fn call(&self) -> io::Error {
            self.0.fetch_add(1, Ordering::Relaxed);
            io::ErrorKind::BrokenPipe.into()
        }
    }

    /// A [`Dead`] sink, or a live one.
    #[derive(Debug)]
    enum Generation {
        Dead(Dead),
        Live(SpentSink),
    }

    impl PacketSink for Generation {
        async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
            match self {
                Self::Dead(dead) => Err(dead.call()),
                Self::Live(sink) => sink.send(packet, from).await,
            }
        }

        async fn send_batch_spent(
            &self,
            packets: &mut VecDeque<(PeerId, PacketBuf)>,
            spent: &mut Vec<PacketBuf>,
        ) -> io::Result<()> {
            match self {
                Self::Dead(dead) => {
                    packets.pop_front();
                    Err(dead.call())
                }
                Self::Live(sink) => sink.send_batch_spent(packets, spent).await,
            }
        }

        fn try_send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
            match self {
                Self::Dead(dead) => {
                    packets.pop_front();
                    Err(dead.call())
                }
                Self::Live(_) => Err(io::ErrorKind::WouldBlock.into()),
            }
        }
    }

    fn calls(sink: Option<&Arc<Generation>>) -> Option<usize> {
        match sink.map(|sink| &**sink) {
            Some(Generation::Dead(dead)) => Some(dead.calls()),
            _ => None,
        }
    }

    fn broken<T: fmt::Debug>(result: io::Result<T>) -> Result<(), String> {
        match result {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            other => Err(format!("expected BrokenPipe, got {other:?}")),
        }
    }

    #[tokio::test]
    async fn swap_gone_current_sink_drops_until_replaced() -> TestResult {
        // Each form is the first to find the sink gone, and calls it once.
        for form in 0..4 {
            let swap = SwapSink::new(Some(Generation::Dead(Dead::default())));
            let handle = swap.clone();
            let mut packets = batch(&[1, 2, 3]);
            let mut spent = Vec::new();
            match form {
                0 => swap.send(packet(1), PeerId::new(1)).await?,
                1 => swap.send_batch(&mut packets).await?,
                2 => swap.send_batch_spent(&mut packets, &mut spent).await?,
                _ => swap.try_send_batch(&mut packets)?,
            }
            assert!(form == 0 || packets.is_empty());
            // The failed packet is the sink's; the ones it left are spent.
            assert_eq!(spent.len(), if form == 2 { 2 } else { 0 });
            assert_eq!(swap.dropped(), if form == 0 { 1 } else { 3 });

            // The gone sink is not called again.
            let before = swap.dropped();
            swap.send(packet(4), PeerId::new(4)).await?;
            let mut packets = batch(&[5, 6]);
            swap.send_batch(&mut packets).await?;
            assert!(packets.is_empty());
            let mut packets = batch(&[7]);
            let mut spent = Vec::new();
            swap.send_batch_spent(&mut packets, &mut spent).await?;
            assert_eq!(bytes(&spent), [[7]]);
            let mut packets = batch(&[8, 9]);
            swap.try_send_batch(&mut packets)?;
            assert!(packets.is_empty());
            assert_eq!(swap.dropped(), before + 6);

            // `replace` hands the gone sink back and resumes delivery.
            let live = SpentSink::default();
            let old = handle.replace(Some(Generation::Live(live.clone())));
            assert_eq!(calls(old.as_ref()), Some(1));
            swap.send(packet(10), PeerId::new(10)).await?;
            swap.send_batch(&mut batch(&[11])).await?;
            assert_eq!(live.taken(), [[10], [11]]);
            assert_eq!(swap.dropped(), before + 6);
        }
        Ok(())
    }

    #[tokio::test]
    async fn swap_last_clone_with_a_gone_sink_is_closed() -> TestResult {
        let swap = SwapSink::new(Some(Generation::Dead(Dead::default())));
        let handle = swap.clone();
        swap.send(packet(1), PeerId::new(1)).await?;
        drop(handle);

        // Nobody can replace the gone sink any more.
        broken(swap.send(packet(2), PeerId::new(2)).await)?;
        let mut packets = batch(&[3, 4]);
        broken(swap.send_batch(&mut packets).await)?;
        assert_eq!(packets.len(), 1);
        let mut packets = batch(&[5, 6]);
        let mut spent = Vec::new();
        broken(swap.send_batch_spent(&mut packets, &mut spent).await)?;
        assert_eq!(packets.len(), 1);
        assert_eq!(bytes(&spent), [[5]]);
        let mut packets = batch(&[7, 8]);
        broken(swap.try_send_batch(&mut packets))?;
        assert_eq!(packets.len(), 1);
        assert_eq!(swap.dropped(), 5);
        assert_eq!(calls(swap.replace(None).as_ref()), Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn swap_last_clone_finds_its_sink_gone() -> TestResult {
        // The sink's own error comes back: it dropped the failed packet.
        let swap = SwapSink::new(Some(Generation::Dead(Dead::default())));
        broken(swap.send(packet(1), PeerId::new(1)).await)?;
        assert_eq!(swap.dropped(), 0);
        let swap = SwapSink::new(Some(Generation::Dead(Dead::default())));
        let mut packets = batch(&[1, 2, 3]);
        broken(swap.send_batch(&mut packets).await)?;
        assert_eq!(packets.len(), 2);
        let swap = SwapSink::new(Some(Generation::Dead(Dead::default())));
        let mut packets = batch(&[1, 2, 3]);
        broken(swap.try_send_batch(&mut packets))?;
        assert_eq!(packets.len(), 2);
        assert_eq!(swap.dropped(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn swap_last_clone_with_an_empty_slot_is_closed() -> TestResult {
        let swap = SwapSink::<ChannelSink>::new(None);
        broken(swap.send(packet(1), PeerId::new(1)).await)?;
        let mut packets = batch(&[2, 3]);
        broken(swap.send_batch(&mut packets).await)?;
        assert_eq!(packets.len(), 1);
        assert_eq!(swap.dropped(), 2);

        // A clone can fill the slot again.
        let handle = swap.clone();
        swap.send(packet(4), PeerId::new(4)).await?;
        let (sink, mut rx) = ChannelSink::new(4);
        handle.replace(Some(sink));
        drop(handle);
        swap.send(packet(5), PeerId::new(5)).await?;
        assert_eq!(next(&mut rx).await?, 5);
        Ok(())
    }

    #[tokio::test]
    async fn swap_other_error_from_current_sink_propagates() -> TestResult {
        let swap = SwapSink::new(Some(SpentSink::default()));
        let _handle = swap.clone();
        let err = swap
            .send(packet(SpentSink::FAIL), PeerId::new(1))
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::Other);
        let mut packets = batch(&[SpentSink::FAIL, 3]);
        let err = swap
            .send_batch(&mut packets)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(packets.len(), 1);
        let err = swap
            .try_send_batch(&mut packets)
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(packets.len(), 1);
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

    #[tokio::test]
    async fn spent_empty_slot_returns_the_dropped_buffers() -> TestResult {
        let swap = SwapSink::<SpentSink>::new(None);
        let _handle = swap.clone();
        let mut packets = batch(&[1, 2]);
        let mut spent = Vec::new();
        swap.send_batch_spent(&mut packets, &mut spent).await?;
        assert!(packets.is_empty());
        assert_eq!(bytes(&spent), [[1], [2]]);
        assert_eq!(swap.dropped(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn spent_forwards_to_the_current_sink() -> TestResult {
        let inner = SpentSink::default();
        let swap = SwapSink::new(Some(inner.clone()));
        let mut packets = batch(&[1, 2]);
        let mut spent = Vec::new();
        swap.send_batch_spent(&mut packets, &mut spent).await?;
        assert!(packets.is_empty());
        assert_eq!(bytes(&spent), [[1], [2]]);
        assert_eq!(inner.taken(), [[1], [2]]);

        // An error from the current sink comes back unchanged, the rest left.
        let mut packets = batch(&[SpentSink::FAIL, 4]);
        let mut spent = Vec::new();
        let err = swap
            .send_batch_spent(&mut packets, &mut spent)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(spent.is_empty());
        assert_eq!(packets.len(), 1);
        assert_eq!(swap.dropped(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn spent_error_from_replaced_sink_returns_the_dropped_buffers() -> TestResult {
        let old = SpentSink::default();
        let swap = SwapSink::new(Some(old.clone()));
        let mut packets = batch(&[1, SpentSink::HOLD, 3, 4]);
        let mut spent = Vec::new();
        {
            let mut pending = Box::pin(swap.send_batch_spent(&mut packets, &mut spent));
            assert!(timeout(PENDING, &mut pending).await.is_err());
            assert!(swap.replace(Some(SpentSink::default())).is_some());
            old.release();
            timeout(WAIT, pending).await??;
        }
        assert!(packets.is_empty());
        // 1 was written; the held packet failed; 3 and 4 were left.
        assert_eq!(bytes(&spent), [vec![1], vec![3], vec![4]]);
        assert_eq!(swap.dropped(), 3);
        Ok(())
    }
}
