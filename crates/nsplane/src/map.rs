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
use std::sync::{Mutex, PoisonError};

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
///
/// A sink built with [`MapSink::with_after`] also runs an after-delivery hook `A` on every
/// packet `inner` took over; `MapSink<S, F>` names the sink [`MapSink::new`] builds, which
/// has none.
pub struct MapSink<S, F, A = fn(&[u8])> {
    inner: S,
    f: F,
    after: Option<A>,
    dropped: AtomicU64,
    /// Spare copy buffers for `after`, reused so a steady stream does not allocate.
    spare: Mutex<Vec<Copies>>,
}

/// Spare copy buffers a [`MapSink`] keeps: one per `send` or `send_batch` call in flight at
/// a time, as the engine's sink task makes, with room for a few concurrent callers.
const SPARE_COPIES: usize = 4;

/// The bytes of the packets a [`MapSink`] hands to `inner`, kept for its `after` hook.
#[derive(Default)]
struct Copies {
    /// The packets, back to back.
    bytes: Vec<u8>,
    /// Where each packet ends in `bytes`.
    ends: Vec<usize>,
}

impl Copies {
    fn push(&mut self, packet: &[u8]) {
        self.bytes.extend_from_slice(packet);
        self.ends.push(self.bytes.len());
    }

    /// Calls `after` for the first `count` packets, in order.
    fn report(&self, count: usize, after: impl Fn(&[u8])) {
        let mut start = 0;
        for &end in self.ends.iter().take(count) {
            after(self.bytes.get(start..end).unwrap_or_default());
            start = end;
        }
    }
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
            after: None,
            dropped: AtomicU64::new(0),
            spare: Mutex::new(Vec::new()),
        }
    }
}

impl<S, F, A> MapSink<S, F, A>
where
    S: PacketSink,
    F: Fn(&mut PacketBuf, PeerId) -> MapVerdict + Send + Sync + 'static,
    A: Fn(&[u8]) + Send + Sync + 'static,
{
    /// Wraps `sink`, running `f` on every packet and `after` on every packet `sink` took
    /// over.
    ///
    /// `after` is called once per delivered packet with its bytes as handed to `sink`
    /// (after `f`'s rewrite), only once `sink` took the packet over successfully: never for
    /// a packet `f` dropped, never for the one `sink` failed on. For example, a translation
    /// can retire a mapping only after the TUN writer took the packet.
    ///
    /// Since the packet moves into `sink`, its bytes are copied first: one copy of every
    /// kept packet, into a buffer reused from call to call, so a steady stream does not
    /// allocate.
    ///
    /// `send_batch` maps every packet, copies the kept ones, hands them to `sink`'s
    /// `send_batch` and then calls `after` in order for exactly the packets `sink` took
    /// over: all of them on success; on an error, the ones before the packet that failed.
    /// If the `send` or `send_batch` future is cancelled, `after` is not called for that
    /// packet or batch, so a cancelled batch may have delivered packets whose hook did not
    /// run. `try_send_batch` keeps the default (`WouldBlock`) here too, so the engine
    /// delivers every packet through `send_batch`.
    pub const fn with_after(sink: S, f: F, after: A) -> Self {
        Self {
            inner: sink,
            f,
            after: Some(after),
            dropped: AtomicU64::new(0),
            spare: Mutex::new(Vec::new()),
        }
    }
}

impl<S, F, A> MapSink<S, F, A>
where
    S: PacketSink,
    F: Fn(&mut PacketBuf, PeerId) -> MapVerdict + Send + Sync + 'static,
{
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

    /// An empty copy buffer, a spare one if there is one.
    fn take_copies(&self) -> Copies {
        self.spare
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or_default()
    }

    /// Keeps `copies` as a spare, unless there are enough.
    fn put_copies(&self, mut copies: Copies) {
        copies.bytes.clear();
        copies.ends.clear();
        let mut spare = self.spare.lock().unwrap_or_else(PoisonError::into_inner);
        if spare.len() < SPARE_COPIES {
            spare.push(copies);
        }
    }
}

impl<S, F, A> PacketSink for MapSink<S, F, A>
where
    S: PacketSink,
    F: Fn(&mut PacketBuf, PeerId) -> MapVerdict + Send + Sync + 'static,
    A: Fn(&[u8]) + Send + Sync + 'static,
{
    async fn send(&self, mut packet: PacketBuf, from: PeerId) -> io::Result<()> {
        if !self.map(&mut packet, from) {
            return Ok(());
        }
        let Some(after) = &self.after else {
            return self.inner.send(packet, from).await;
        };
        let mut copies = self.take_copies();
        copies.push(packet.as_packet());
        let result = self.inner.send(packet, from).await;
        if result.is_ok() {
            copies.report(1, after);
        }
        self.put_copies(copies);
        result
    }

    /// Maps every packet, removes the dropped ones and hands the rest to `inner` in
    /// order. The packets left in `packets` after an error from `inner` are already
    /// mapped; a caller that calls again to deliver them maps them a second time, so a
    /// closure used with a retrying caller must tolerate seeing its own output.
    ///
    /// With an `after` hook ([`MapSink::with_after`]) the kept packets are copied before
    /// `inner` gets them, and once `inner` returns `after` is called in order for the
    /// packets it took over: all of them on success; on an error, the ones before the
    /// packet that failed. Cancelling the call skips `after` for the whole batch.
    async fn send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        packets.retain_mut(|(from, packet)| self.map(packet, *from));
        let Some(after) = &self.after else {
            return self.inner.send_batch(packets).await;
        };
        let mut copies = self.take_copies();
        for (_, packet) in packets.iter() {
            copies.push(packet.as_packet());
        }
        let kept = packets.len();
        let result = self.inner.send_batch(packets).await;
        // On an error the packet that failed was dropped and the rest are left.
        let delivered = kept.saturating_sub(packets.len() + usize::from(result.is_err()));
        copies.report(delivered, after);
        self.put_copies(copies);
        result
    }

    // `try_send_batch` keeps the default (`WouldBlock`, the engine delivers through
    // `send_batch` on its sink task), with or without an `after` hook: forwarding it would
    // map the packets the inner sink leaves behind, and the engine's later `send_batch`
    // would map them a second time.
}

impl<S: fmt::Debug, F, A> fmt::Debug for MapSink<S, F, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapSink")
            .field("inner", &self.inner)
            .field("after", &self.after.is_some())
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

    /// Hands the buffers to `inner`: mapping does not change who owns them.
    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        self.inner.recycle(bufs);
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
    use std::sync::Arc;

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

    /// Records what `after` is called with.
    #[derive(Debug, Default)]
    struct Reported(Mutex<Vec<Vec<u8>>>);

    impl Reported {
        fn record(&self, packet: &[u8]) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(packet.to_vec());
        }

        fn take(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
        }
    }

    type Rewrite = fn(&mut PacketBuf, PeerId) -> MapVerdict;

    /// A [`MapSink::with_after`] over `inner` running [`rewrite_sink`], reporting into
    /// `reported`.
    fn after_sink<S: PacketSink>(
        inner: S,
        reported: &Arc<Reported>,
    ) -> MapSink<S, Rewrite, impl Fn(&[u8]) + Send + Sync + 'static> {
        let reported = Arc::clone(reported);
        MapSink::with_after(inner, rewrite_sink as Rewrite, move |packet: &[u8]| {
            reported.record(packet);
        })
    }

    /// Takes over every packet except those whose first byte is 0xEE, which fail with
    /// [`io::ErrorKind::Other`]; keeps what it took over.
    #[derive(Debug, Default)]
    struct FailingSink(Reported);

    impl PacketSink for FailingSink {
        fn send(
            &self,
            packet: PacketBuf,
            _from: PeerId,
        ) -> impl Future<Output = io::Result<()>> + Send {
            if packet.as_packet().first() == Some(&0xEE) {
                return std::future::ready(Err(io::Error::other("refused")));
            }
            self.0.record(packet.as_packet());
            std::future::ready(Ok(()))
        }
    }

    fn batch(packets: &[&[u8]]) -> VecDeque<(PeerId, PacketBuf)> {
        packets
            .iter()
            .map(|p| (PeerId::new(1), PacketBuf::from_packet(p)))
            .collect()
    }

    #[tokio::test]
    async fn after_reports_delivered_rewritten_packets() -> TestResult {
        let (inner, mut rx) = ChannelSink::new(4);
        let reported = Arc::new(Reported::default());
        let sink = after_sink(inner, &reported);

        sink.send(PacketBuf::from_packet(&[1, 2, 3]), PeerId::new(7))
            .await?;
        sink.send(PacketBuf::from_packet(&[0, 2]), PeerId::new(7))
            .await?;
        sink.send(PacketBuf::from_packet(&[4, 5]), PeerId::new(7))
            .await?;
        assert_eq!(reported.take(), [vec![1, 0xFF, 3], vec![4, 0xFF]]);
        for expected in [&[1, 0xFF, 3][..], &[4, 0xFF]] {
            let (_, packet) = rx.recv().await.ok_or("closed")?;
            assert_eq!(packet.as_packet(), expected);
        }
        assert!(rx.is_empty());
        assert_eq!(sink.dropped(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn after_skips_failed_send() -> TestResult {
        let (inner, rx) = ChannelSink::new(4);
        let reported = Arc::new(Reported::default());
        let sink = after_sink(inner, &reported);
        drop(rx);
        let err = sink
            .send(PacketBuf::from_packet(&[1, 1]), PeerId::new(1))
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let mut packets = batch(&[&[1, 1], &[2, 2]]);
        let err = sink
            .send_batch(&mut packets)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(reported.take(), Vec::<Vec<u8>>::new());

        let reported = Arc::new(Reported::default());
        let sink = after_sink(FailingSink::default(), &reported);
        let err = sink
            .send(PacketBuf::from_packet(&[0xEE, 1]), PeerId::new(1))
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(reported.take(), Vec::<Vec<u8>>::new());
        sink.send(PacketBuf::from_packet(&[1, 1]), PeerId::new(1))
            .await?;
        assert_eq!(reported.take(), [vec![1, 0xFF]]);
        Ok(())
    }

    #[tokio::test]
    async fn after_batch_reports_in_order() -> TestResult {
        let (inner, mut rx) = ChannelSink::new(8);
        let reported = Arc::new(Reported::default());
        let sink = after_sink(inner, &reported);

        let mut packets = batch(&[&[1, 1], &[0, 2], &[3, 3], &[0, 4], &[5, 5]]);
        sink.send_batch(&mut packets).await?;
        assert!(packets.is_empty());
        let expected = [vec![1, 0xFF], vec![3, 0xFF], vec![5, 0xFF]];
        assert_eq!(reported.take(), expected);
        for expected in &expected {
            let (_, packet) = rx.recv().await.ok_or("closed")?;
            assert_eq!(packet.as_packet(), expected);
        }
        assert_eq!(sink.dropped(), 2);

        // A second batch reuses the copy buffer and reports only its own packets.
        let mut packets = batch(&[&[7, 7]]);
        sink.send_batch(&mut packets).await?;
        assert_eq!(reported.take(), [vec![7, 0xFF]]);
        Ok(())
    }

    #[tokio::test]
    async fn after_batch_error_reports_packets_before_it() -> TestResult {
        let reported = Arc::new(Reported::default());
        let sink = after_sink(FailingSink::default(), &reported);

        let mut packets = batch(&[&[1, 1], &[0, 2], &[3, 3], &[0xEE, 4], &[5, 5]]);
        let err = sink
            .send_batch(&mut packets)
            .await
            .err()
            .ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(reported.take(), [vec![1, 0xFF], vec![3, 0xFF]]);
        assert_eq!(sink.inner.0.take(), [vec![1, 0xFF], vec![3, 0xFF]]);
        // The rest stays, already mapped; delivering it reports it.
        let rest: Vec<_> = packets
            .iter()
            .map(|(_, p)| p.as_packet().to_vec())
            .collect();
        assert_eq!(rest, [vec![5, 0xFF]]);
        sink.send_batch(&mut packets).await?;
        assert_eq!(reported.take(), [vec![5, 0xFF]]);
        Ok(())
    }

    #[test]
    fn debug_shows_after() {
        let (inner, _rx) = ChannelSink::new(1);
        let sink = after_sink(inner, &Arc::default());
        assert!(format!("{sink:?}").contains("after: true"));
        let (inner, _rx) = ChannelSink::new(1);
        let sink = MapSink::new(inner, rewrite_sink);
        assert!(format!("{sink:?}").contains("after: false"));
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

    /// Keeps every buffer it is handed back.
    struct PoolSource {
        pool: Vec<PacketBuf>,
        mtu: watch::Sender<u16>,
    }

    impl PacketSource for PoolSource {
        async fn recv(&mut self) -> io::Result<PacketBuf> {
            std::future::pending().await
        }

        fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
            self.pool.append(bufs);
        }

        fn mtu(&self) -> watch::Receiver<u16> {
            self.mtu.subscribe()
        }
    }

    #[test]
    fn source_recycle_reaches_inner() {
        let inner = PoolSource {
            pool: Vec::new(),
            mtu: watch::channel(1420).0,
        };
        let mut source = MapSource::new(inner, rewrite);
        let mut bufs = vec![PacketBuf::from_packet(&[1]), PacketBuf::from_packet(&[2])];
        source.recycle(&mut bufs);
        assert!(bufs.is_empty());
        let pooled: Vec<_> = source.inner.pool.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(pooled, [&[1][..], &[2]]);
    }

    #[test]
    fn source_recycle_default_inner_takes_nothing() {
        let (inner, _tx, _mtu) = ChannelSource::new(1, 1420);
        let mut source = MapSource::new(inner, rewrite);
        let mut bufs = vec![PacketBuf::from_packet(&[1])];
        source.recycle(&mut bufs);
        assert_eq!(bufs.len(), 1);
    }
}
