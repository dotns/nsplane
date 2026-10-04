//! The generic in-place transform wrappers for the local side: [`MapSink`] and
//! [`MapSource`].
//!
//! A closure rewrites each packet in place, or drops it, on its way to a sink or from a
//! source. A Redirect is a [`MapSink`] running the forward translation plus a
//! [`MapSource`] running the reverse one; `Nat64LanSink` and `Nat64LanSource` in
//! `nsplane-nat` are equivalent to a [`MapSink`] and a [`MapSource`] over a `Nat64Lan`
//! (they stay as they are).

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use nsplane_packet::{PacketBatch, PacketBuf, PeerId};
use tokio::sync::watch;

use crate::io::{PacketSink, PacketSource};

/// What a [`MapSink`] or [`MapSource`] closure decided for a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapVerdict {
    /// Pass the (possibly rewritten) packet on.
    Keep,
    /// Discard the packet.
    Drop,
}

/// A [`PacketSink`] that runs a closure on every packet before `inner` gets it.
///
/// The closure gets the packet, which it may rewrite in place, and the peer it was
/// decrypted for. Kept packets go to `inner`; dropped packets are discarded and counted
/// in [`MapSink::dropped`], and `send` returns `Ok(())` for them.
pub struct MapSink<S, F> {
    inner: S,
    f: F,
    dropped: AtomicU64,
}

impl<S, F> MapSink<S, F>
where
    S: PacketSink,
    F: Fn(&mut PacketBuf, PeerId) -> MapVerdict + Send + Sync + 'static,
{
    /// Wraps `sink`, running `f` on every packet.
    pub const fn new(sink: S, f: F) -> Self {
        Self {
            inner: sink,
            f,
            dropped: AtomicU64::new(0),
        }
    }

    /// Packets dropped so far because the closure returned [`MapVerdict::Drop`].
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Runs the closure on `packet` and counts a drop; true if the packet is kept.
    fn map(&self, packet: &mut PacketBuf, from: PeerId) -> bool {
        let keep = (self.f)(packet, from) == MapVerdict::Keep;
        if !keep {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        keep
    }
}

impl<S, F> PacketSink for MapSink<S, F>
where
    S: PacketSink,
    F: Fn(&mut PacketBuf, PeerId) -> MapVerdict + Send + Sync + 'static,
{
    async fn send(&self, mut packet: PacketBuf, from: PeerId) -> io::Result<()> {
        if !self.map(&mut packet, from) {
            return Ok(());
        }
        self.inner.send(packet, from).await
    }

    /// Maps every packet, removes the dropped ones and hands the rest to `inner` in
    /// order. The packets left in `packets` after an error from `inner` are already
    /// mapped; a caller that calls again to deliver them maps them a second time, so a
    /// closure used with a retrying caller must tolerate seeing its own output.
    async fn send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        packets.retain_mut(|(from, packet)| self.map(packet, *from));
        self.inner.send_batch(packets).await
    }

    // `try_send_batch` keeps the default (`WouldBlock`, the engine delivers through
    // `send_batch` on its sink task): forwarding it would map the packets the inner sink
    // leaves behind, and the engine's later `send_batch` would map them a second time.
}

impl<S: fmt::Debug, F> fmt::Debug for MapSink<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapSink")
            .field("inner", &self.inner)
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// A [`PacketSource`] that runs a closure on every packet `inner` produces.
///
/// The closure gets the packet, which it may rewrite in place. Kept packets are returned;
/// dropped packets are skipped (and counted in [`MapSource::dropped`]) and the next one is
/// read. Errors from `inner` are returned unchanged. The MTU is `inner`'s. Cancellation
/// safety is that of `inner`.
pub struct MapSource<S, F> {
    inner: S,
    f: F,
    dropped: u64,
}

impl<S, F> MapSource<S, F>
where
    S: PacketSource,
    F: FnMut(&mut PacketBuf) -> MapVerdict + Send + 'static,
{
    /// Wraps `source`, running `f` on every packet.
    pub const fn new(source: S, f: F) -> Self {
        Self {
            inner: source,
            f,
            dropped: 0,
        }
    }

    /// Packets dropped so far because the closure returned [`MapVerdict::Drop`].
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

impl<S, F> PacketSource for MapSource<S, F>
where
    S: PacketSource,
    F: FnMut(&mut PacketBuf) -> MapVerdict + Send + 'static,
{
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        loop {
            let mut packet = self.inner.recv().await?;
            if (self.f)(&mut packet) == MapVerdict::Keep {
                return Ok(packet);
            }
            self.dropped += 1;
        }
    }

    /// Reads a batch from `inner`, maps the new packets and removes the dropped ones, in
    /// order; packets already in `batch` are left untouched. Reads again if every new
    /// packet was dropped and `batch` still has room. Packets `inner` appended before an
    /// error are mapped too.
    async fn recv_batch(&mut self, batch: &mut PacketBatch) -> io::Result<()> {
        loop {
            let start = batch.len();
            let result = self.inner.recv_batch(batch).await;
            let mut kept = PacketBatch::new();
            for (i, mut packet) in batch.drain().enumerate() {
                if i < start || (self.f)(&mut packet) == MapVerdict::Keep {
                    // `kept` has the room `batch` had.
                    let _ = kept.push(packet);
                } else {
                    self.dropped += 1;
                }
            }
            *batch = kept;
            result?;
            if batch.len() > start || batch.is_full() {
                return Ok(());
            }
        }
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.inner.mtu()
    }
}

impl<S: fmt::Debug, F> fmt::Debug for MapSource<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapSource")
            .field("inner", &self.inner)
            .field("dropped", &self.dropped)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChannelSink, ChannelSource};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Drops packets whose first byte is 0, rewrites the second byte to 0xFF.
    fn rewrite(packet: &mut PacketBuf) -> MapVerdict {
        match packet.as_packet_mut() {
            [0, ..] | [] => MapVerdict::Drop,
            [_, second, ..] => {
                *second = 0xFF;
                MapVerdict::Keep
            }
            [_] => MapVerdict::Keep,
        }
    }

    fn rewrite_sink(packet: &mut PacketBuf, _from: PeerId) -> MapVerdict {
        rewrite(packet)
    }

    #[tokio::test]
    async fn sink_keeps_rewrites_and_drops() -> TestResult {
        let (inner, mut rx) = ChannelSink::new(4);
        let sink = MapSink::new(inner, rewrite_sink);

        sink.send(PacketBuf::from_packet(&[1, 2, 3]), PeerId::new(7))
            .await?;
        let (peer, packet) = rx.recv().await.ok_or("closed")?;
        assert_eq!(
            (peer, packet.as_packet()),
            (PeerId::new(7), &[1, 0xFF, 3][..])
        );

        sink.send(PacketBuf::from_packet(&[0, 2]), PeerId::new(7))
            .await?;
        assert!(rx.is_empty());
        assert_eq!(sink.dropped(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn sink_passes_from() -> TestResult {
        let (inner, mut rx) = ChannelSink::new(4);
        let sink = MapSink::new(inner, |_: &mut PacketBuf, from: PeerId| {
            if from == PeerId::new(1) {
                MapVerdict::Drop
            } else {
                MapVerdict::Keep
            }
        });

        sink.send(PacketBuf::from_packet(&[1]), PeerId::new(1))
            .await?;
        sink.send(PacketBuf::from_packet(&[2]), PeerId::new(2))
            .await?;
        let (peer, packet) = rx.recv().await.ok_or("closed")?;
        assert_eq!((peer, packet.as_packet()), (PeerId::new(2), &[2][..]));
        assert!(rx.is_empty());
        assert_eq!(sink.dropped(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn sink_batch_in_order_without_dropped() -> TestResult {
        let (inner, mut rx) = ChannelSink::new(8);
        let sink = MapSink::new(inner, rewrite_sink);

        let mut packets: VecDeque<_> = [[1, 1], [0, 2], [3, 3], [0, 4], [5, 5]]
            .iter()
            .map(|p| (PeerId::new(u32::from(p[0])), PacketBuf::from_packet(p)))
            .collect();
        sink.send_batch(&mut packets).await?;
        assert!(packets.is_empty());
        for byte in [1, 3, 5] {
            let (peer, packet) = rx.recv().await.ok_or("closed")?;
            assert_eq!(
                (peer, packet.as_packet()),
                (PeerId::new(u32::from(byte)), &[byte, 0xFF][..])
            );
        }
        assert!(rx.is_empty());
        assert_eq!(sink.dropped(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn sink_broken_pipe() -> TestResult {
        let (inner, rx) = ChannelSink::new(4);
        let sink = MapSink::new(inner, rewrite_sink);
        drop(rx);

        let err = sink
            .send(PacketBuf::from_packet(&[1]), PeerId::new(1))
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let mut packets = VecDeque::from([(PeerId::new(1), PacketBuf::from_packet(&[1]))]);
        let err = sink
            .send_batch(&mut packets)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        Ok(())
    }

    #[tokio::test]
    async fn source_skips_dropped() -> TestResult {
        let (inner, tx, _mtu) = ChannelSource::new(4, 1420);
        let mut source = MapSource::new(inner, rewrite);

        tx.send(PacketBuf::from_packet(&[0, 1])).await?;
        tx.send(PacketBuf::from_packet(&[0, 2])).await?;
        tx.send(PacketBuf::from_packet(&[3, 3])).await?;
        assert_eq!(source.recv().await?.as_packet(), [3, 0xFF]);
        assert_eq!(source.dropped(), 2);

        drop(tx);
        let err = source.recv().await.err().ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        Ok(())
    }

    #[tokio::test]
    async fn source_batch_maps_only_new_packets() -> TestResult {
        let (inner, tx, _mtu) = ChannelSource::new(4, 1420);
        let mut source = MapSource::new(inner, rewrite);
        let mut batch = PacketBatch::new();
        // Already in the batch: neither rewritten nor dropped.
        let _ = batch.push(PacketBuf::from_packet(&[0, 9]));
        let _ = batch.push(PacketBuf::from_packet(&[8, 8]));

        // The inner source appends one packet per read: the first read's only new packet
        // is dropped, so it reads again.
        tx.send(PacketBuf::from_packet(&[0, 1])).await?;
        tx.send(PacketBuf::from_packet(&[2, 2])).await?;
        source.recv_batch(&mut batch).await?;
        let packets: Vec<_> = batch.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(packets, [&[0, 9][..], &[8, 8], &[2, 0xFF]]);
        assert_eq!(source.dropped(), 1);

        drop(tx);
        let err = source
            .recv_batch(&mut batch)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(batch.len(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn source_mtu_passes_through() -> TestResult {
        let (inner, _tx, mtu_tx) = ChannelSource::new(1, 1420);
        let source = MapSource::new(inner, rewrite);
        assert_eq!(*source.mtu().borrow(), 1420);
        mtu_tx.send(1280)?;
        assert_eq!(*source.mtu().borrow(), 1280);
        Ok(())
    }
}
