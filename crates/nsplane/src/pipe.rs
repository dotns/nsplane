//! An in-memory loopback from a [`PacketSink`] to a [`PacketSource`].

use std::io;

use nsplane_packet::{PacketBatch, PacketBuf, PeerId};
use tokio::sync::{mpsc, watch};

use crate::io::{PacketSink, PacketSource};

/// The error both pipe ends return once the other end is gone.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed")
}

/// Creates a pipe queueing up to `capacity` packets, with an initial `mtu`.
///
/// What is sent to the [`PipeSink`] comes out of the [`PipeSource`] in order, so one
/// engine's (or [`Splitter`](crate::Splitter)'s) output feeds another engine's input
/// without a forwarding task. A [`ChannelSink`](crate::ChannelSink) and a
/// [`ChannelSource`](crate::ChannelSource) need a task to join them.
///
/// ```
/// # use nsplane::{PacketBuf, PacketSink, PacketSource, PeerId, pipe};
/// # async fn demo() -> std::io::Result<()> {
/// let (sink, mut source) = pipe(64, 1420);
/// sink.send(PacketBuf::from_packet(&[0x45]), PeerId::new(1)).await?;
/// assert_eq!(source.recv().await?.as_packet(), [0x45]);
/// # Ok(())
/// # }
/// ```
///
/// # Panics
///
/// If `capacity` is 0.
pub fn pipe(capacity: usize, mtu: u16) -> (PipeSink, PipeSource) {
    let (tx, rx) = mpsc::channel(capacity);
    let source = PipeSource {
        rx,
        mtu: watch::Sender::new(mtu),
    };
    (PipeSink { tx }, source)
}

/// The [`PacketSink`] end of a [`pipe`].
///
/// `send` waits while the pipe is full and returns [`io::ErrorKind::BrokenPipe`] once the
/// [`PipeSource`] is dropped, also when it was waiting. The `from` peer is not carried: a
/// [`PacketSource`] yields packets only. Clones feed the same pipe, so several producers
/// can share one input.
#[derive(Debug, Clone)]
pub struct PipeSink {
    tx: mpsc::Sender<PacketBuf>,
}

impl PacketSink for PipeSink {
    async fn send(&self, packet: PacketBuf, _from: PeerId) -> io::Result<()> {
        self.tx.send(packet).await.map_err(|_| closed())
    }
}

/// The [`PacketSource`] end of a [`pipe`].
///
/// `recv` yields the packets in the order they were sent. Once every [`PipeSink`] clone is
/// dropped and the queue is drained, it returns [`io::ErrorKind::BrokenPipe`] on every
/// call. `recv_batch` appends every packet already queued, up to the batch's room.
#[derive(Debug)]
pub struct PipeSource {
    rx: mpsc::Receiver<PacketBuf>,
    mtu: watch::Sender<u16>,
}

impl PipeSource {
    /// A sender that changes the MTU this source reports.
    ///
    /// Take it before moving the source into an engine.
    pub fn mtu_sender(&self) -> watch::Sender<u16> {
        self.mtu.clone()
    }
}

impl PacketSource for PipeSource {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        self.rx.recv().await.ok_or_else(closed)
    }

    async fn recv_batch(&mut self, batch: &mut PacketBatch) -> io::Result<()> {
        if batch.is_full() {
            return Ok(());
        }
        let packet = self.rx.recv().await.ok_or_else(closed)?;
        // The batch had room, so the push succeeds; so do the ones below.
        let _ = batch.push(packet);
        while !batch.is_full()
            && let Ok(packet) = self.rx.try_recv()
        {
            let _ = batch.push(packet);
        }
        Ok(())
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsplane_packet::MAX_BATCH;
    use std::time::Duration;
    use tokio::time::timeout;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const PENDING: Duration = Duration::from_millis(50);
    const WAIT: Duration = Duration::from_secs(5);

    async fn send(sink: &PipeSink, byte: u8) -> io::Result<()> {
        sink.send(PacketBuf::from_packet(&[byte]), PeerId::new(1))
            .await
    }

    fn assert_broken_pipe(result: io::Result<impl std::fmt::Debug>) {
        let err = result.expect_err("expected an error");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn preserves_order() -> TestResult {
        let (sink, mut source) = pipe(8, 1420);
        for i in 0..8 {
            send(&sink, i).await?;
        }
        for i in 0..8 {
            assert_eq!(source.recv().await?.as_packet(), [i]);
        }
        Ok(())
    }

    #[tokio::test]
    async fn send_waits_when_full() -> TestResult {
        let (sink, mut source) = pipe(1, 1420);
        send(&sink, 1).await?;
        let mut pending = Box::pin(send(&sink, 2));
        assert!(timeout(PENDING, &mut pending).await.is_err());

        assert_eq!(source.recv().await?.as_packet(), [1]);
        timeout(WAIT, pending).await??;
        assert_eq!(source.recv().await?.as_packet(), [2]);
        Ok(())
    }

    #[tokio::test]
    async fn dropping_source_breaks_send() -> TestResult {
        let (sink, source) = pipe(1, 1420);
        send(&sink, 1).await?;
        let mut pending = Box::pin(send(&sink, 2));
        assert!(timeout(PENDING, &mut pending).await.is_err());

        drop(source);
        assert_broken_pipe(timeout(WAIT, pending).await?);
        assert_broken_pipe(send(&sink, 3).await);
        Ok(())
    }

    #[tokio::test]
    async fn drains_after_every_sink_drops() -> TestResult {
        let (sink, mut source) = pipe(4, 1420);
        let other = sink.clone();
        send(&sink, 1).await?;
        drop(sink);
        send(&other, 2).await?;
        assert_eq!(source.recv().await?.as_packet(), [1]);
        assert_eq!(source.recv().await?.as_packet(), [2]);
        assert!(timeout(PENDING, source.recv()).await.is_err());

        send(&other, 3).await?;
        send(&other, 4).await?;
        drop(other);
        assert_eq!(source.recv().await?.as_packet(), [3]);
        assert_eq!(source.recv().await?.as_packet(), [4]);
        for _ in 0..2 {
            assert_broken_pipe(timeout(WAIT, source.recv()).await?);
        }
        Ok(())
    }

    #[tokio::test]
    async fn recv_batch_takes_queued_packets() -> TestResult {
        let (sink, mut source) = pipe(128, 1420);
        for i in 0..70 {
            send(&sink, i).await?;
        }
        let mut batch = PacketBatch::new();
        source.recv_batch(&mut batch).await?;
        assert_eq!(batch.len(), MAX_BATCH);
        let received: Vec<u8> = batch.drain().map(|packet| packet.as_packet()[0]).collect();
        assert_eq!(received, (0..64).collect::<Vec<_>>());

        source.recv_batch(&mut batch).await?;
        let received: Vec<u8> = batch.drain().map(|packet| packet.as_packet()[0]).collect();
        assert_eq!(received, (64..70).collect::<Vec<_>>());
        Ok(())
    }

    #[tokio::test]
    async fn recv_batch_respects_room_and_drains() -> TestResult {
        let (sink, mut source) = pipe(8, 1420);
        for i in 0..5 {
            send(&sink, i).await?;
        }
        let mut batch = PacketBatch::new();
        for _ in 0..MAX_BATCH - 2 {
            batch
                .push(PacketBuf::from_packet(&[0xff]))
                .map_err(|_| "full")?;
        }
        source.recv_batch(&mut batch).await?;
        assert!(batch.is_full());
        let tail: Vec<u8> = batch
            .iter()
            .skip(MAX_BATCH - 2)
            .map(|p| p.as_packet()[0])
            .collect();
        assert_eq!(tail, [0, 1]);

        // A full batch takes nothing.
        source.recv_batch(&mut batch).await?;
        assert!(batch.is_full());

        batch.clear();
        drop(sink);
        source.recv_batch(&mut batch).await?;
        let received: Vec<u8> = batch.drain().map(|packet| packet.as_packet()[0]).collect();
        assert_eq!(received, [2, 3, 4]);
        for _ in 0..2 {
            assert_broken_pipe(source.recv_batch(&mut batch).await);
            assert!(batch.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn mtu_updates() -> TestResult {
        let (_sink, source) = pipe(1, 1420);
        let mut mtu = source.mtu();
        assert_eq!(*mtu.borrow_and_update(), 1420);
        source.mtu_sender().send_replace(1280);
        timeout(WAIT, mtu.changed()).await??;
        assert_eq!(*mtu.borrow_and_update(), 1280);
        assert_eq!(*source.mtu().borrow(), 1280);
        Ok(())
    }
}
