//! Moves packets from a [`PacketSource`] into a [`PacketSink`].

use std::collections::VecDeque;
use std::io;

use nsplane_packet::{MAX_BATCH, PacketBatch, PeerId};

use crate::io::{PacketSink, PacketSource};

/// What a [`pump`] moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PumpStats {
    /// Packets the sink took over.
    pub packets: u64,
    /// `send_batch` calls that completed.
    pub batches: u64,
}

/// Sorts a side's result: `Ok(true)` once it returned [`io::ErrorKind::BrokenPipe`].
fn ended(result: io::Result<()>) -> io::Result<bool> {
    match result {
        Ok(()) => Ok(false),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(true),
        Err(err) => Err(err),
    }
}

/// Moves every packet from `source` into `sink`, in order, as sent by `from`.
///
/// Replaces a hand-written receive/send loop between two local-side endpoints, e.g. from a
/// TUN device into an engine's input [`pipe`](crate::pipe):
///
/// ```
/// # use nsplane::{ChannelSink, ChannelSource, PeerId, pump};
/// # async fn demo() -> std::io::Result<()> {
/// let (source, _tx, _mtu) = ChannelSource::new(64, 1420);
/// let (sink, _rx) = ChannelSink::new(64);
/// let pumping = tokio::spawn(pump(source, sink, PeerId::new(1)));
/// // ... feed `_tx`, read `_rx`, then drop `_tx`:
/// let _stats = pumping.await??;
/// # Ok(())
/// # }
/// ```
///
/// Each round takes one [`PacketSource::recv_batch`] and hands it to
/// [`PacketSink::send_batch_spent`]; the batch and the delivery queue are allocated once. It
/// awaits the sink while it applies backpressure and never drops a packet.
///
/// The buffers the sink appends to `spent` go to [`PacketSource::recycle`] before the next
/// `recv_batch`, so a source with a pool (a [`pipe`](crate::pipe) whose producers
/// [`alloc`](crate::PipeSink::alloc)) reads into them again. If the source takes none of
/// the first buffers offered, the pump calls plain [`PacketSink::send_batch`] from then on.
///
/// It ends with `Ok` once either side returns [`io::ErrorKind::BrokenPipe`]; packets the
/// source appended before its error are delivered first. Any other error from either side
/// is returned, also after delivering those packets.
///
/// Cancellation-safe at batch boundaries: dropping the future while it waits for the source
/// loses nothing (as far as the source's `recv_batch` is cancellation-safe); dropping it
/// while it waits for the sink loses at most the batch in flight, the packets taken from the
/// source but not taken over by the sink yet, and the spent buffers not recycled yet. Either
/// way it drops the source and the sink.
pub async fn pump(
    mut source: impl PacketSource,
    sink: impl PacketSink,
    from: PeerId,
) -> io::Result<PumpStats> {
    let mut stats = PumpStats::default();
    let mut batch = PacketBatch::new();
    let mut packets = VecDeque::with_capacity(MAX_BATCH);
    let mut spent = Vec::new();
    // Whether spent buffers are still collected, and whether the source took any yet.
    let (mut recycling, mut recycled) = (true, false);
    loop {
        let received = source.recv_batch(&mut batch).await;
        packets.extend(batch.drain().map(|packet| (from, packet)));
        let mut sent = Ok(());
        if !packets.is_empty() {
            let queued = packets.len();
            sent = if recycling {
                sink.send_batch_spent(&mut packets, &mut spent).await
            } else {
                sink.send_batch(&mut packets).await
            };
            // On an error the packet that failed is dropped, not taken over.
            let taken = queued.saturating_sub(packets.len() + usize::from(sent.is_err()));
            stats.packets += taken as u64;
            if sent.is_ok() {
                stats.batches += 1;
            }
        }
        if !spent.is_empty() {
            let offered = spent.len();
            source.recycle(&mut spent);
            // A source that declines the first offer keeps the default `recycle`.
            recycled |= spent.len() < offered;
            recycling = recycled;
            spent.clear();
        }
        let sink_ended = ended(sent)?;
        if ended(received)? || sink_ended {
            return Ok(stats);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChannelSink, ChannelSource};
    use nsplane_packet::PacketBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::watch;
    use tokio::time::timeout;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const PENDING: Duration = Duration::from_millis(50);
    const WAIT: Duration = Duration::from_secs(5);

    /// A source that appends one packet to every batch and then fails with `kind`.
    struct EndingSource(io::ErrorKind);

    impl PacketSource for EndingSource {
        fn recv(&mut self) -> impl Future<Output = io::Result<PacketBuf>> + Send {
            std::future::ready(Err(self.0.into()))
        }

        fn recv_batch(
            &mut self,
            batch: &mut PacketBatch,
        ) -> impl Future<Output = io::Result<()>> + Send {
            let _ = batch.push(PacketBuf::from_packet(&[9]));
            std::future::ready(Err(self.0.into()))
        }

        fn mtu(&self) -> watch::Receiver<u16> {
            watch::channel(1420).1
        }
    }

    /// A sink that fails every packet with a non-BrokenPipe error.
    struct FailingSink;

    impl PacketSink for FailingSink {
        fn send(
            &self,
            _packet: PacketBuf,
            _from: PeerId,
        ) -> impl Future<Output = io::Result<()>> + Send {
            std::future::ready(Err(io::Error::other("sink failed")))
        }
    }

    /// What a [`ScriptSource`] and a [`SpentSink`] saw, in order.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Seen {
        /// A `recv_batch` call.
        Recv,
        /// A `recycle` offer of this many buffers.
        Recycle(usize),
        /// A packet the sink took through `send_batch_spent`.
        Spent(u8),
        /// A packet the sink took through `send`, i.e. plain `send_batch`.
        Plain(u8),
    }

    type Log = Arc<Mutex<Vec<Seen>>>;

    fn log(seen: &Log, event: Seen) {
        if let Ok(mut seen) = seen.lock() {
            seen.push(event);
        }
    }

    /// A source that yields `packets` one per batch, then ends; takes recycled buffers
    /// only if `takes`.
    struct ScriptSource {
        packets: VecDeque<u8>,
        takes: bool,
        seen: Log,
    }

    impl PacketSource for ScriptSource {
        fn recv(&mut self) -> impl Future<Output = io::Result<PacketBuf>> + Send {
            std::future::ready(Err(io::ErrorKind::Unsupported.into()))
        }

        fn recv_batch(
            &mut self,
            batch: &mut PacketBatch,
        ) -> impl Future<Output = io::Result<()>> + Send {
            log(&self.seen, Seen::Recv);
            let result = self.packets.pop_front().map_or_else(
                || Err(io::ErrorKind::BrokenPipe.into()),
                |byte| {
                    let _ = batch.push(PacketBuf::from_packet(&[byte]));
                    Ok(())
                },
            );
            std::future::ready(result)
        }

        fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
            log(&self.seen, Seen::Recycle(bufs.len()));
            if self.takes {
                bufs.clear();
            }
        }

        fn mtu(&self) -> watch::Receiver<u16> {
            watch::channel(1420).1
        }
    }

    /// A sink that returns every buffer it took through `send_batch_spent`.
    struct SpentSink(Log);

    impl PacketSink for SpentSink {
        fn send(
            &self,
            packet: PacketBuf,
            _from: PeerId,
        ) -> impl Future<Output = io::Result<()>> + Send {
            log(&self.0, Seen::Plain(packet.as_packet()[0]));
            std::future::ready(Ok(()))
        }

        fn send_batch_spent(
            &self,
            packets: &mut VecDeque<(PeerId, PacketBuf)>,
            spent: &mut Vec<PacketBuf>,
        ) -> impl Future<Output = io::Result<()>> + Send {
            for (_, packet) in packets.drain(..) {
                log(&self.0, Seen::Spent(packet.as_packet()[0]));
                spent.push(packet);
            }
            std::future::ready(Ok(()))
        }
    }

    fn script(packets: &[u8], takes: bool) -> (ScriptSource, Log) {
        let seen = Log::default();
        let source = ScriptSource {
            packets: packets.iter().copied().collect(),
            takes,
            seen: Arc::clone(&seen),
        };
        (source, seen)
    }

    fn seen(log: &Log) -> Vec<Seen> {
        log.lock().map(|seen| seen.clone()).unwrap_or_default()
    }

    #[tokio::test]
    async fn default_send_batch_spent_appends_nothing() -> TestResult {
        let (sink, mut rx) = ChannelSink::new(4);
        let mut packets: VecDeque<_> = (0..3)
            .map(|i| (PeerId::new(1), PacketBuf::from_packet(&[i])))
            .collect();
        let mut spent = Vec::new();
        sink.send_batch_spent(&mut packets, &mut spent).await?;
        assert!(packets.is_empty());
        assert!(spent.is_empty());
        for i in 0..3 {
            assert_eq!(rx.recv().await.ok_or("sink closed")?.1.as_packet(), [i]);
        }
        Ok(())
    }

    #[tokio::test]
    async fn spent_buffers_reach_recycle_before_the_next_read() -> TestResult {
        let (source, seen_log) = script(&[1, 2, 3], true);
        let stats = pump(source, SpentSink(Arc::clone(&seen_log)), PeerId::new(1)).await?;
        assert_eq!(stats.packets, 3);
        let mut expected = Vec::new();
        for i in 1..=3 {
            expected.extend([Seen::Recv, Seen::Spent(i), Seen::Recycle(1)]);
        }
        expected.push(Seen::Recv);
        assert_eq!(seen(&seen_log), expected);
        Ok(())
    }

    #[tokio::test]
    async fn declining_source_ends_the_offers() -> TestResult {
        let (source, seen_log) = script(&[1, 2, 3], false);
        let stats = pump(source, SpentSink(Arc::clone(&seen_log)), PeerId::new(1)).await?;
        assert_eq!(stats.packets, 3);
        assert_eq!(
            seen(&seen_log),
            [
                Seen::Recv,
                Seen::Spent(1),
                Seen::Recycle(1),
                Seen::Recv,
                Seen::Plain(2),
                Seen::Recv,
                Seen::Plain(3),
                Seen::Recv,
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn default_sink_offers_nothing() -> TestResult {
        let (source, seen_log) = script(&[1, 2], true);
        let (sink, _rx) = ChannelSink::new(4);
        assert_eq!(pump(source, sink, PeerId::new(1)).await?.packets, 2);
        assert_eq!(seen(&seen_log), [Seen::Recv; 3]);
        Ok(())
    }

    #[tokio::test]
    async fn delivers_in_order_until_source_ends() -> TestResult {
        let (source, tx, _mtu) = ChannelSource::new(16, 1420);
        let (sink, mut rx) = ChannelSink::new(16);
        let pumping = tokio::spawn(pump(source, sink, PeerId::new(7)));
        for i in 0..10 {
            tx.send(PacketBuf::from_packet(&[i])).await?;
        }
        drop(tx);

        let stats = timeout(WAIT, pumping).await???;
        // ChannelSource reads one packet per batch.
        assert_eq!(
            stats,
            PumpStats {
                packets: 10,
                batches: 10
            }
        );
        for i in 0..10 {
            let (peer, packet) = rx.recv().await.ok_or("sink closed")?;
            assert_eq!((peer, packet.as_packet()), (PeerId::new(7), &[i][..]));
        }
        assert!(rx.recv().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn ends_when_sink_is_gone() -> TestResult {
        let (source, tx, _mtu) = ChannelSource::new(4, 1420);
        let (sink, rx) = ChannelSink::new(4);
        drop(rx);
        tx.send(PacketBuf::from_packet(&[1])).await?;
        let stats = timeout(WAIT, pump(source, sink, PeerId::new(1))).await??;
        assert_eq!(stats, PumpStats::default());
        Ok(())
    }

    #[tokio::test]
    async fn awaits_backpressure() -> TestResult {
        let (source, tx, _mtu) = ChannelSource::new(8, 1420);
        let (sink, mut rx) = ChannelSink::new(1);
        for i in 0..5 {
            tx.send(PacketBuf::from_packet(&[i])).await?;
        }
        let mut pumping = tokio::spawn(pump(source, sink, PeerId::new(1)));
        assert!(timeout(PENDING, &mut pumping).await.is_err());

        for i in 0..5 {
            let (_, packet) = timeout(WAIT, rx.recv()).await?.ok_or("sink closed")?;
            assert_eq!(packet.as_packet(), [i]);
        }
        drop(tx);
        assert_eq!(timeout(WAIT, pumping).await???.packets, 5);
        Ok(())
    }

    #[tokio::test]
    async fn delivers_before_source_error() -> TestResult {
        let (sink, mut rx) = ChannelSink::new(4);
        let stats = pump(
            EndingSource(io::ErrorKind::BrokenPipe),
            sink.clone(),
            PeerId::new(1),
        )
        .await?;
        assert_eq!(
            stats,
            PumpStats {
                packets: 1,
                batches: 1
            }
        );
        assert_eq!(rx.recv().await.ok_or("sink closed")?.1.as_packet(), [9]);

        let err = pump(
            EndingSource(io::ErrorKind::InvalidData),
            sink,
            PeerId::new(1),
        )
        .await
        .err()
        .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(rx.recv().await.ok_or("sink closed")?.1.as_packet(), [9]);
        Ok(())
    }

    #[tokio::test]
    async fn returns_sink_error() -> TestResult {
        let (source, tx, _mtu) = ChannelSource::new(4, 1420);
        tx.send(PacketBuf::from_packet(&[1])).await?;
        let err = timeout(WAIT, pump(source, FailingSink, PeerId::new(1)))
            .await?
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::Other);
        Ok(())
    }

    #[tokio::test]
    async fn abort_at_batch_boundary() -> TestResult {
        let (source, tx, _mtu) = ChannelSource::new(4, 1420);
        let (sink, mut rx) = ChannelSink::new(4);
        let pumping = tokio::spawn(pump(source, sink, PeerId::new(1)));
        for i in 0..3 {
            tx.send(PacketBuf::from_packet(&[i])).await?;
        }
        for i in 0..3 {
            let (_, packet) = timeout(WAIT, rx.recv()).await?.ok_or("sink closed")?;
            assert_eq!(packet.as_packet(), [i]);
        }

        pumping.abort();
        assert!(
            timeout(WAIT, pumping)
                .await?
                .is_err_and(|err| err.is_cancelled())
        );
        // The source and the sink were dropped with the pump.
        assert!(tx.send(PacketBuf::from_packet(&[3])).await.is_err());
        assert!(rx.recv().await.is_none());
        Ok(())
    }

    #[test]
    fn future_is_send() {
        fn assert_send<T: Send>(_: &T) {}
        let (source, _tx, _mtu) = ChannelSource::new(1, 1420);
        let (sink, _rx) = ChannelSink::new(1);
        assert_send(&pump(source, sink, PeerId::new(1)));
    }
}
