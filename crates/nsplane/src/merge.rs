//! A [`PacketSource`] that merges several sources fairly.

use std::fmt;
use std::io;
use std::task::{Context, Poll};

use nsplane_packet::PacketBuf;
use tokio::sync::watch;

use crate::io::PacketSource;
use crate::transport::BoxFuture;

/// A pending `recv` on one source; it owns the source and hands it back when done.
type Recv = BoxFuture<'static, (io::Result<PacketBuf>, Box<dyn Arm>)>;

/// Recycled buffers a [`MergeSource`] holds until a source can take them.
const RECYCLE_PENDING: usize = 64;

/// A pending wait for one source's next MTU change; `None` once its sender is gone.
type MtuChange = BoxFuture<'static, Option<watch::Receiver<u16>>>;

/// A type-erased source that can start its next owned `recv` and take recycled buffers.
trait Arm: Send + 'static {
    fn arm(self: Box<Self>) -> Recv;

    fn take_recycled(&mut self, bufs: &mut Vec<PacketBuf>);
}

impl<S: PacketSource> Arm for S {
    fn arm(self: Box<Self>) -> Recv {
        let mut source = self;
        Box::pin(async move {
            let result = PacketSource::recv(&mut *source).await;
            (result, source as Box<dyn Arm>)
        })
    }

    fn take_recycled(&mut self, bufs: &mut Vec<PacketBuf>) {
        PacketSource::recycle(self, bufs);
    }
}

fn mtu_change(mut rx: watch::Receiver<u16>) -> MtuChange {
    Box::pin(async move {
        match rx.changed().await {
            Ok(()) => Some(rx),
            Err(_) => None,
        }
    })
}

/// One merged source: its pending `recv` and its MTU.
struct Slot {
    recv: Recv,
    mtu: u16,
    mtu_change: Option<MtuChange>,
}

/// A [`PacketSource`] that merges several sources, of any types, fairly.
///
/// For a hybrid local side, e.g. a TUN device next to a userspace netstack. Build it with
/// [`MergeSource::new`] and add sources with [`MergeSource::source`].
///
/// Semantics of [`PacketSource::recv`]:
/// - Sources are served round-robin: each call polls the sources starting after the one
///   served last, so when several have packets ready each gets its turn and a busy source
///   cannot starve another.
/// - Every source has at most one `recv` in progress, kept across calls, so dropping a
///   merged `recv` future loses no packet. Each packet costs one boxed future.
/// - A source that returns [`io::ErrorKind::BrokenPipe`] is removed. Once every source has
///   ended (or none was added), `recv` returns [`io::ErrorKind::BrokenPipe`] on every call.
///   Other errors are passed through and the source stays.
///
/// [`PacketSource::mtu`] reports the minimum of the current MTUs of the sources that have
/// not ended (`u16::MAX` before the first source is added; the last value once all have
/// ended). It follows their changes without a helper task: changes are picked up while a
/// `recv` is being polled, so they reach the receiver while the engine reads from the merge
/// (it always has one `recv` in progress when running) and are applied on the next `recv`
/// otherwise. A source whose MTU sender is dropped keeps its last MTU.
///
/// Semantics of [`PacketSource::recycle`]:
/// - A source cannot take buffers while its `recv` is in progress, which is always the
///   case between calls, so the merge holds up to 64 recycled buffers and leaves the rest
///   in `bufs` for the caller to drop. It never blocks.
/// - When a source's `recv` completes, before its next one starts, the held buffers are
///   handed to that source's `recycle`; it takes what its pool allows and the rest are
///   dropped. A source removed for [`io::ErrorKind::BrokenPipe`] gets none.
/// - A merge that is never handed buffers holds none and does no extra work per packet.
pub struct MergeSource {
    slots: Vec<Slot>,
    next: usize,
    mtu: watch::Sender<u16>,
    /// Recycled buffers for the next source whose `recv` completes; at most
    /// [`RECYCLE_PENDING`].
    recycled: Vec<PacketBuf>,
}

impl MergeSource {
    /// Creates a merge with no sources.
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            next: 0,
            mtu: watch::Sender::new(u16::MAX),
            recycled: Vec::new(),
        }
    }

    /// Adds `source` to the merge.
    #[must_use]
    pub fn source<S: PacketSource>(mut self, source: S) -> Self {
        let mut rx = source.mtu();
        let mtu = *rx.borrow_and_update();
        self.slots.push(Slot {
            recv: Box::new(source).arm(),
            mtu,
            mtu_change: Some(mtu_change(rx)),
        });
        self.publish_mtu();
        self
    }

    /// Publishes the minimum MTU of the remaining sources, if it changed.
    fn publish_mtu(&self) {
        if let Some(min) = self.slots.iter().map(|slot| slot.mtu).min() {
            self.mtu.send_if_modified(|mtu| {
                let changed = *mtu != min;
                *mtu = min;
                changed
            });
        }
    }

    /// Applies every MTU change that is ready and registers for the next ones.
    fn poll_mtu(&mut self, cx: &mut Context<'_>) {
        let mut changed = false;
        for slot in &mut self.slots {
            while let Some(change) = &mut slot.mtu_change {
                match change.as_mut().poll(cx) {
                    Poll::Ready(Some(mut rx)) => {
                        slot.mtu = *rx.borrow_and_update();
                        slot.mtu_change = Some(mtu_change(rx));
                        changed = true;
                    }
                    Poll::Ready(None) => slot.mtu_change = None,
                    Poll::Pending => break,
                }
            }
        }
        if changed {
            self.publish_mtu();
        }
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<PacketBuf>> {
        self.poll_mtu(cx);
        // Walk the sources once, circularly from `next`. Removing a slot shifts the
        // following ones down, so `index` then already points at the next one to poll.
        let mut index = self.next;
        let mut polled = 0;
        while polled < self.slots.len() {
            if index >= self.slots.len() {
                index = 0;
            }
            let slot = &mut self.slots[index];
            match slot.recv.as_mut().poll(cx) {
                Poll::Pending => {
                    index += 1;
                    polled += 1;
                }
                Poll::Ready((Err(err), _)) if err.kind() == io::ErrorKind::BrokenPipe => {
                    self.slots.remove(index);
                    self.publish_mtu();
                }
                Poll::Ready((result, mut source)) => {
                    if !self.recycled.is_empty() {
                        source.take_recycled(&mut self.recycled);
                        self.recycled.clear();
                    }
                    slot.recv = source.arm();
                    self.next = index + 1;
                    return Poll::Ready(result);
                }
            }
        }
        if self.slots.is_empty() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "all merged sources ended",
            )))
        } else {
            Poll::Pending
        }
    }
}

impl Default for MergeSource {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSource for MergeSource {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Holds up to 64 buffers until a source's `recv` completes, then hands them to that
    /// source; the rest are left in `bufs` (see [`MergeSource`]).
    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        let take = (RECYCLE_PENDING - self.recycled.len()).min(bufs.len());
        self.recycled.extend(bufs.drain(..take));
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu.subscribe()
    }
}

impl fmt::Debug for MergeSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MergeSource")
            .field("sources", &self.slots.len())
            .field("mtu", &*self.mtu.borrow())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChannelSource;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::time::timeout;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const WAIT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn fair_between_ready_sources() -> TestResult {
        let (a, a_tx, _a_mtu) = ChannelSource::new(1000, 1420);
        let (b, b_tx, _b_mtu) = ChannelSource::new(1000, 1420);
        for _ in 0..1000 {
            a_tx.send(PacketBuf::from_packet(&[0])).await?;
            b_tx.send(PacketBuf::from_packet(&[1])).await?;
        }
        let mut merge = MergeSource::new().source(a).source(b);

        let mut counts = [0usize; 2];
        for _ in 0..1000 {
            let packet = merge.recv().await?;
            let tag = usize::from(packet.as_packet().first().copied().ok_or("empty packet")?);
            *counts.get_mut(tag).ok_or("unknown tag")? += 1;
        }
        assert!(counts.iter().all(|&count| count >= 400), "{counts:?}");
        Ok(())
    }

    #[tokio::test]
    async fn ends_after_all_sources_end() -> TestResult {
        let (a, a_tx, _a_mtu) = ChannelSource::new(4, 1420);
        let (b, b_tx, _b_mtu) = ChannelSource::new(4, 1420);
        let mut merge = MergeSource::new().source(a).source(b);

        a_tx.send(PacketBuf::from_packet(&[1])).await?;
        drop(a_tx);
        assert_eq!(merge.recv().await?.as_packet(), [1]);
        // `a` has ended; `b` still delivers.
        b_tx.send(PacketBuf::from_packet(&[2])).await?;
        assert_eq!(merge.recv().await?.as_packet(), [2]);
        assert!(
            timeout(Duration::from_millis(50), merge.recv())
                .await
                .is_err()
        );

        drop(b_tx);
        for _ in 0..2 {
            let err = timeout(WAIT, merge.recv())
                .await?
                .err()
                .ok_or("expected an error")?;
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }
        Ok(())
    }

    #[tokio::test]
    async fn no_sources_is_broken_pipe() -> TestResult {
        let mut merge = MergeSource::new();
        let err = merge.recv().await.err().ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        Ok(())
    }

    #[tokio::test]
    async fn mtu_is_min_and_follows_changes() -> TestResult {
        let (a, _a_tx, _a_mtu) = ChannelSource::new(1, 1420);
        let (b, _b_tx, b_mtu) = ChannelSource::new(1, 1280);
        let mut merge = MergeSource::new().source(a).source(b);
        let mut mtu = merge.mtu();
        assert_eq!(*mtu.borrow_and_update(), 1280);

        b_mtu.send(1500)?;
        let changed = timeout(WAIT, async {
            tokio::select! {
                result = merge.recv() => Err(format!("unexpected recv result {result:?}")),
                changed = mtu.changed() => changed.map_err(|err| err.to_string()),
            }
        })
        .await?;
        changed?;
        assert_eq!(*mtu.borrow_and_update(), 1420);
        Ok(())
    }

    #[tokio::test]
    async fn mtu_drops_ended_source() -> TestResult {
        let (a, _a_tx, _a_mtu) = ChannelSource::new(1, 1420);
        let (b, b_tx, _b_mtu) = ChannelSource::new(1, 1280);
        let mut merge = MergeSource::new().source(a).source(b);
        let mtu = merge.mtu();

        drop(b_tx);
        assert!(
            timeout(Duration::from_millis(50), merge.recv())
                .await
                .is_err()
        );
        assert_eq!(*mtu.borrow(), 1420);
        Ok(())
    }

    /// A channel source that takes up to `bound` recycled buffers in total and counts them.
    struct Counting {
        inner: ChannelSource,
        bound: usize,
        taken: Arc<AtomicUsize>,
    }

    impl Counting {
        fn new(inner: ChannelSource, bound: usize) -> (Self, Arc<AtomicUsize>) {
            let taken = Arc::new(AtomicUsize::new(0));
            let source = Self {
                inner,
                bound,
                taken: Arc::clone(&taken),
            };
            (source, taken)
        }
    }

    impl PacketSource for Counting {
        async fn recv(&mut self) -> io::Result<PacketBuf> {
            self.inner.recv().await
        }

        fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
            let room = self.bound - self.taken.load(Ordering::Relaxed);
            let take = room.min(bufs.len());
            bufs.drain(..take);
            self.taken.fetch_add(take, Ordering::Relaxed);
        }

        fn mtu(&self) -> watch::Receiver<u16> {
            self.inner.mtu()
        }
    }

    fn bufs(count: usize) -> Vec<PacketBuf> {
        (0..count).map(|_| PacketBuf::with_capacity(1600)).collect()
    }

    #[tokio::test]
    async fn recycle_reaches_the_source_whose_recv_completes() -> TestResult {
        let (a, a_tx, _a_mtu) = ChannelSource::new(4, 1420);
        let (a, taken) = Counting::new(a, 3);
        let mut merge = MergeSource::new().source(a);

        let mut recycled = bufs(5);
        merge.recycle(&mut recycled);
        assert!(recycled.is_empty());
        // Held while the source's `recv` is in progress.
        assert_eq!(taken.load(Ordering::Relaxed), 0);

        a_tx.send(PacketBuf::from_packet(&[1])).await?;
        assert_eq!(merge.recv().await?.as_packet(), [1]);
        // The source took what its bound allows; the rest were dropped.
        assert_eq!(taken.load(Ordering::Relaxed), 3);
        assert!(merge.recycled.is_empty());

        a_tx.send(PacketBuf::from_packet(&[2])).await?;
        assert_eq!(merge.recv().await?.as_packet(), [2]);
        assert_eq!(taken.load(Ordering::Relaxed), 3);
        Ok(())
    }

    #[tokio::test]
    async fn recycle_holds_at_most_its_bound() -> TestResult {
        let (a, a_tx, _a_mtu) = ChannelSource::new(4, 1420);
        let (a, taken) = Counting::new(a, usize::MAX);
        let mut merge = MergeSource::new().source(a);

        let mut recycled = bufs(RECYCLE_PENDING + 6);
        merge.recycle(&mut recycled);
        assert_eq!(recycled.len(), 6);
        merge.recycle(&mut recycled);
        assert_eq!(recycled.len(), 6, "a full merge takes nothing");

        a_tx.send(PacketBuf::from_packet(&[1])).await?;
        merge.recv().await?;
        assert_eq!(taken.load(Ordering::Relaxed), RECYCLE_PENDING);
        Ok(())
    }

    #[tokio::test]
    async fn recycle_skips_an_ended_source() -> TestResult {
        let (a, a_tx, _a_mtu) = ChannelSource::new(4, 1420);
        let (b, b_tx, _b_mtu) = ChannelSource::new(4, 1420);
        let (a, a_taken) = Counting::new(a, usize::MAX);
        let (b, b_taken) = Counting::new(b, usize::MAX);
        let mut merge = MergeSource::new().source(a).source(b);

        merge.recycle(&mut bufs(2));
        drop(a_tx);
        b_tx.send(PacketBuf::from_packet(&[2])).await?;
        assert_eq!(merge.recv().await?.as_packet(), [2]);
        assert_eq!(a_taken.load(Ordering::Relaxed), 0);
        assert_eq!(b_taken.load(Ordering::Relaxed), 2);
        Ok(())
    }
}
