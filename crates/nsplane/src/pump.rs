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
/// [`PacketSink::send_batch`]; the batch and the delivery queue are allocated once. It
/// awaits the sink while it applies backpressure and never drops a packet.
///
/// It ends with `Ok` once either side returns [`io::ErrorKind::BrokenPipe`]; packets the
/// source appended before its error are delivered first. Any other error from either side
/// is returned, also after delivering those packets.
///
/// Cancellation-safe at batch boundaries: dropping the future while it waits for the source
/// loses nothing (as far as the source's `recv_batch` is cancellation-safe); dropping it
/// while it waits for the sink loses at most the batch in flight, the packets taken from the
/// source but not taken over by the sink yet. Either way it drops the source and the sink.
pub async fn pump(
    mut source: impl PacketSource,
    sink: impl PacketSink,
    from: PeerId,
) -> io::Result<PumpStats> {
    let mut stats = PumpStats::default();
    let mut batch = PacketBatch::new();
    let mut packets = VecDeque::with_capacity(MAX_BATCH);
    loop {
        let received = source.recv_batch(&mut batch).await;
        packets.extend(batch.drain().map(|packet| (from, packet)));
        let mut sent = Ok(());
        if !packets.is_empty() {
            let queued = packets.len();
            sent = sink.send_batch(&mut packets).await;
            // On an error the packet that failed is dropped, not taken over.
            let taken = queued.saturating_sub(packets.len() + usize::from(sent.is_err()));
            stats.packets += taken as u64;
            if sent.is_ok() {
                stats.batches += 1;
            }
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
