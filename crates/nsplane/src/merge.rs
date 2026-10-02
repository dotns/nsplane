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

/// A pending wait for one source's next MTU change; `None` once its sender is gone.
type MtuChange = BoxFuture<'static, Option<watch::Receiver<u16>>>;

/// A type-erased source that can start its next owned `recv`.
trait Arm: Send + 'static {
    fn arm(self: Box<Self>) -> Recv;
}

impl<S: PacketSource> Arm for S {
    fn arm(self: Box<Self>) -> Recv {
        let mut source = self;
        Box::pin(async move {
            let result = PacketSource::recv(&mut *source).await;
            (result, source as Box<dyn Arm>)
        })
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
pub struct MergeSource {
    slots: Vec<Slot>,
    next: usize,
    mtu: watch::Sender<u16>,
}

impl MergeSource {
    /// Creates a merge with no sources.
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            next: 0,
            mtu: watch::Sender::new(u16::MAX),
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
                Poll::Ready((result, source)) => {
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
}
