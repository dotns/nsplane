//! A local side bridged through host callbacks, such as iOS `NEPacketTunnelFlow`.
//!
//! The host pushes the packets it reads into a [`HostTunInput`] from any thread; the
//! engine reads them from the [`HostTunSource`] and writes its packets back through the
//! host's `write` callback in the [`HostTunSink`]. Nothing here is platform-specific.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use nsplane::{PacketBatch, PacketBuf, PacketPool, PacketSink, PacketSource, PeerId, TAILROOM};
use tokio::sync::{mpsc, watch};

/// The host's packet writer; see [`host_tun`].
type Write = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// The recommended queue capacity for [`host_tun`], in packets.
pub const HOST_TUN_DEFAULT_CAPACITY: usize = 4096;

/// Creates the local side of a host that hands packets over through callbacks rather than
/// a file descriptor: the iOS `NEPacketTunnelFlow` local side, usable on every target.
///
/// This is the MT-2 local side; the contract's `HostTun::new` ships as `host_tun`.
///
/// The side starts with MTU `mtu` ([`HostTunSource::set_mtu`] changes it), queues up to
/// `capacity` packets from the host ([`HOST_TUN_DEFAULT_CAPACITY`] is recommended), and
/// writes the engine's packets with `write`, an `Arc<dyn Fn(&[u8]) -> bool + Send + Sync>`.
///
/// Returns the input the host pushes its packets into, the source the engine reads
/// them from, and the sink that hands the engine's packets to `write`.
///
/// `write` runs synchronously on the engine task, so it must not block for long; it
/// returns `false` once the host can no longer take packets.
/// `NEPacketTunnelFlow.writePackets` does not block.
///
/// Buffers handed back through [`PacketSource::recycle`] are kept, up to `capacity` idle
/// ones, for [`HostTunInput::push`] to copy the next packets into.
///
/// # Panics
///
/// Panics if `capacity` is 0.
pub fn host_tun(
    mtu: u16,
    capacity: usize,
    write: Write,
) -> (HostTunInput, HostTunSource, HostTunSink) {
    let (tx, rx) = mpsc::channel(capacity);
    let (mtu_tx, _) = watch::channel(mtu);
    let free = Arc::new(FreeList {
        pool: Mutex::new(PacketPool::new(capacity)),
        stocked: AtomicBool::new(false),
    });
    (
        HostTunInput {
            tx,
            free: Arc::clone(&free),
        },
        HostTunSource {
            rx,
            mtu,
            mtu_tx,
            oversize_drops: 0,
            free,
        },
        HostTunSink { write },
    )
}

/// Why [`HostTunInput::push`] did not queue a packet; the packet is dropped either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    /// The queue holds `capacity` packets; the engine has not caught up.
    Full,
    /// The [`HostTunSource`] was dropped; no packet will be read again.
    Closed,
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Full => "host packet queue is full",
            Self::Closed => "host packet source is closed",
        })
    }
}

impl std::error::Error for PushError {}

/// The recycled buffers of a [`host_tun`] local side, shared by the source and every input.
///
/// Lossy and never waited on: both sides only `try_lock` the pool, and a push skips it
/// while `stocked` says it is empty.
#[derive(Debug)]
struct FreeList {
    pool: Mutex<PacketPool>,
    /// Whether the pool may hold a buffer; a hint, rechecked under the lock.
    stocked: AtomicBool,
}

impl FreeList {
    /// A buffer holding a copy of `packet` behind the full headroom, with room for
    /// [`TAILROOM`] behind it; `None` if the pool is empty or busy.
    fn take(&self, packet: &[u8]) -> Option<PacketBuf> {
        if !self.stocked.load(Ordering::Relaxed) {
            return None;
        }
        let mut pool = self.pool.try_lock().ok()?;
        if pool.free_len() == 0 {
            self.stocked.store(false, Ordering::Relaxed);
            return None;
        }
        // Grows a recycled buffer that is too small.
        let mut buf = pool.get(packet.len() + TAILROOM);
        if pool.free_len() == 0 {
            self.stocked.store(false, Ordering::Relaxed);
        }
        drop(pool);
        buf.extend_from_slice(packet);
        Some(buf)
    }

    /// Takes buffers out of `bufs` until the pool is full; takes none while it is busy.
    fn put(&self, bufs: &mut Vec<PacketBuf>) {
        let Ok(mut pool) = self.pool.try_lock() else {
            return;
        };
        for buf in bufs.drain(..) {
            pool.put(buf);
        }
        if pool.free_len() > 0 {
            self.stocked.store(true, Ordering::Relaxed);
        }
    }
}

/// The host's end of a [`host_tun`] local side: packets the host read for the engine go in here.
///
/// Clones push into the same queue. Once every clone is dropped and the queue is drained,
/// the [`HostTunSource`] returns [`io::ErrorKind::BrokenPipe`].
#[derive(Debug, Clone)]
pub struct HostTunInput {
    tx: mpsc::Sender<PacketBuf>,
    free: Arc<FreeList>,
}

impl HostTunInput {
    /// Queues a copy of `packet` for the engine, without blocking; callable from any
    /// thread, inside a tokio runtime or not.
    ///
    /// The packet is copied once, into a buffer with the engine's headroom: a buffer
    /// recycled to the [`HostTunSource`] when one is idle, else a new one. Packets longer
    /// than the MTU are queued too and dropped by the [`HostTunSource`].
    pub fn push(&self, packet: &[u8]) -> Result<(), PushError> {
        let buf = self
            .free
            .take(packet)
            .unwrap_or_else(|| PacketBuf::from_packet(packet));
        self.tx.try_send(buf).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => PushError::Full,
            mpsc::error::TrySendError::Closed(_) => PushError::Closed,
        })
    }
}

/// The engine's source of a [`host_tun`] local side: the packets the host pushed, in order.
///
/// Packets longer than the MTU are dropped and counted ([`HostTunSource::oversize_drops`]);
/// the first one is logged as a warning. Once every [`HostTunInput`] is dropped and the
/// queue is drained, `recv` returns [`io::ErrorKind::BrokenPipe`] on every call. The MTU
/// is the one [`host_tun`] was given until [`HostTunSource::set_mtu`] changes it; each
/// packet is checked against the MTU current when it is read.
#[derive(Debug)]
pub struct HostTunSource {
    rx: mpsc::Receiver<PacketBuf>,
    mtu: u16,
    mtu_tx: watch::Sender<u16>,
    oversize_drops: u64,
    free: Arc<FreeList>,
}

impl HostTunSource {
    /// How many packets longer than the MTU this source dropped.
    pub const fn oversize_drops(&self) -> u64 {
        self.oversize_drops
    }

    /// Sets the MTU to `mtu`, e.g. once the host knows its configured MTU.
    ///
    /// Every packet read from then on is checked against `mtu`, including the packets the
    /// host pushed before the call, so a source created early loses none of them to the
    /// initial MTU. The new value is published on the [`PacketSource::mtu`] watch, so an
    /// engine built on the source afterwards starts with it; setting the current MTU again
    /// publishes nothing.
    /// [`HostTunSource::oversize_drops`] is not reset.
    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = mtu;
        self.mtu_tx.send_if_modified(|current| {
            let changed = *current != mtu;
            *current = mtu;
            changed
        });
    }

    /// `packet` if it fits the MTU; otherwise drops and counts it.
    fn admit(&mut self, packet: PacketBuf) -> Option<PacketBuf> {
        if packet.len() <= usize::from(self.mtu) {
            return Some(packet);
        }
        if self.oversize_drops == 0 {
            tracing::warn!(
                len = packet.len(),
                mtu = self.mtu,
                "dropping a host packet longer than the MTU"
            );
        }
        self.oversize_drops += 1;
        None
    }
}

impl PacketSource for HostTunSource {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        loop {
            let packet = self.rx.recv().await.ok_or_else(closed)?;
            if let Some(packet) = self.admit(packet) {
                return Ok(packet);
            }
        }
    }

    async fn recv_batch(&mut self, batch: &mut PacketBatch) -> io::Result<()> {
        if batch.is_full() {
            return Ok(());
        }
        let packet = self.recv().await?;
        // The batch had room, so the push succeeds.
        let _ = batch.push(packet);
        while !batch.is_full() {
            let Ok(packet) = self.rx.try_recv() else {
                break;
            };
            if let Some(packet) = self.admit(packet) {
                let _ = batch.push(packet);
            }
        }
        Ok(())
    }

    /// Keeps the buffers for [`HostTunInput::push`], up to the `capacity` given to
    /// [`host_tun`] idle ones; the rest are dropped. While a push is taking a buffer it
    /// takes none, so they are dropped too.
    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        self.free.put(bufs);
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu_tx.subscribe()
    }
}

/// The engine's sink of a [`host_tun`] local side: each packet goes to the host's `write` callback.
///
/// `send` calls `write` synchronously; when it returns `false` the packet is dropped and
/// `send` returns [`io::ErrorKind::BrokenPipe`].
#[derive(Clone)]
pub struct HostTunSink {
    write: Write,
}

impl fmt::Debug for HostTunSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostTunSink").finish_non_exhaustive()
    }
}

impl PacketSink for HostTunSink {
    fn send(
        &self,
        packet: PacketBuf,
        _from: PeerId,
    ) -> impl Future<Output = io::Result<()>> + Send {
        let result = if (self.write)(packet.as_packet()) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "host packet writer closed",
            ))
        };
        std::future::ready(result)
    }
}

/// The error the source returns once every input is gone.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "host packet input closed")
}

#[cfg(test)]
mod tests {
    use nsplane::HEADROOM;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn side(mtu: u16) -> (HostTunInput, HostTunSource) {
        let (input, source, _) = host_tun(mtu, 16, Arc::new(|_: &[u8]| true));
        (input, source)
    }

    #[tokio::test]
    async fn raising_the_mtu_admits_queued_packets() -> TestResult {
        let (input, mut source) = side(1280);
        input.push(&[0; 1400])?;
        input.push(&[1; 600])?;
        source.set_mtu(1500);
        assert_eq!(source.recv().await?.as_packet(), [0; 1400]);
        assert_eq!(source.recv().await?.as_packet(), [1; 600]);
        assert_eq!(source.oversize_drops(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn lowering_the_mtu_drops_queued_packets() -> TestResult {
        let (input, mut source) = side(1500);
        input.push(&[0; 1400])?;
        input.push(&[1; 600])?;
        source.set_mtu(1280);
        assert_eq!(source.recv().await?.as_packet(), [1; 600]);
        assert_eq!(source.oversize_drops(), 1);

        // The count survives later changes, and packets after them follow the new MTU.
        source.set_mtu(1500);
        input.push(&[2; 1400])?;
        source.set_mtu(1000);
        input.push(&[3; 1000])?;
        let mut batch = PacketBatch::new();
        source.recv_batch(&mut batch).await?;
        assert_eq!(batch.len(), 1);
        assert_eq!(source.oversize_drops(), 2);
        Ok(())
    }

    #[test]
    fn set_mtu_publishes_changes_only() -> TestResult {
        let (_input, mut source) = side(1280);
        let mut mtu = source.mtu();
        assert_eq!(*mtu.borrow_and_update(), 1280);

        source.set_mtu(1280);
        assert!(!mtu.has_changed()?);
        source.set_mtu(1400);
        assert!(mtu.has_changed()?);
        assert_eq!(*mtu.borrow_and_update(), 1400);
        // A receiver taken later starts at the current value.
        assert_eq!(*source.mtu().borrow(), 1400);
        Ok(())
    }

    fn idle(source: &HostTunSource) -> usize {
        source.free.pool.lock().unwrap().free_len()
    }

    #[test]
    fn recycle_refills_up_to_the_capacity() {
        let (_input, mut source) = side(1500);
        let mut bufs: Vec<_> = (0..19).map(|_| PacketBuf::with_capacity(1600)).collect();
        source.recycle(&mut bufs);
        assert!(bufs.is_empty());
        assert_eq!(idle(&source), 16);
    }

    #[tokio::test]
    async fn push_reuses_a_recycled_buffer() -> TestResult {
        let (input, mut source) = side(1500);
        input.push(&[1; 100])?;
        let first = source.recv().await?;
        let addr = first.as_packet().as_ptr();
        source.recycle(&mut vec![first]);

        // Fits with its tailroom into the first one's allocation.
        input.push(&[2; 60])?;
        let second = source.recv().await?;
        assert_eq!(second.as_packet(), [2; 60]);
        assert_eq!(second.as_packet().as_ptr(), addr);
        assert_eq!(second.headroom(), HEADROOM);
        assert_eq!(idle(&source), 0);
        assert!(!source.free.stocked.load(Ordering::Relaxed));
        Ok(())
    }

    #[tokio::test]
    async fn push_grows_a_too_small_recycled_buffer() -> TestResult {
        let (input, mut source) = side(1500);
        source.recycle(&mut vec![PacketBuf::with_capacity(8)]);
        let packet: Vec<u8> = (0..=255).cycle().take(1400).collect();
        input.push(&packet)?;
        let mut buf = source.recv().await?;
        assert_eq!(buf.as_packet(), packet);
        assert_eq!(buf.headroom(), HEADROOM);
        assert!(buf.capacity() >= packet.len() + TAILROOM);
        assert!(buf.with_headroom_mut()[..HEADROOM].iter().all(|&b| b == 0));
        assert_eq!(idle(&source), 0);
        Ok(())
    }

    #[tokio::test]
    async fn push_without_recycle_allocates_like_from_packet() -> TestResult {
        let (input, mut source) = side(1500);
        let mut held = Vec::new();
        for n in 0..4u8 {
            input.push(&[n; 300])?;
            let packet = source.recv().await?;
            let expected = PacketBuf::from_packet(&[n; 300]);
            assert_eq!(packet.as_packet(), expected.as_packet());
            assert_eq!(packet.headroom(), expected.headroom());
            assert_eq!(packet.capacity(), expected.capacity());
            held.push(packet);
        }
        let addrs: std::collections::HashSet<_> =
            held.iter().map(|p| p.as_packet().as_ptr()).collect();
        assert_eq!(addrs.len(), 4);
        assert!(!source.free.stocked.load(Ordering::Relaxed));
        Ok(())
    }

    #[test]
    fn a_busy_free_list_is_skipped() -> TestResult {
        let (input, mut source) = side(1500);
        source.recycle(&mut vec![PacketBuf::with_capacity(1600)]);
        let pool = source.free.pool.lock().unwrap();
        // Neither side waits: the push allocates and the recycle leaves its buffers.
        input.push(&[0; 10])?;
        let mut bufs = vec![PacketBuf::with_capacity(1600)];
        source.free.put(&mut bufs);
        assert_eq!(bufs.len(), 1);
        assert_eq!(pool.free_len(), 1);
        Ok(())
    }
}
