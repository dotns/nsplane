//! The adapter behind the `nsplane` packet I/O traits, over a frame transport.
//!
//! [`spawn_port`] starts a reader task that owns the [`FrameRead`] half: it runs every guest
//! frame through the [`EtherAdapter`], writes the local replies (ARP, neighbor and router
//! advertisements, DHCP) to the transport itself, and queues the IP packets for
//! [`EtherSource`]. The queue is bounded and lossy: when the IP side does not keep up, new
//! packets are dropped and counted in [`EtherStats::drop_backlog`], so local replies keep
//! flowing whether or not the IP side reads. [`EtherSink`] frames IP packets for the guest
//! and writes them to the same transport.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use nsplane::{PacketBuf, PacketSink, PacketSource, PeerId, SharedPacketPool};
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

use crate::MacAddr;
use crate::adapter::{EtherAdapter, EtherConfig, EtherStats};
use crate::frame::HEADER_LEN;
use crate::transport::{FrameRead, FrameWrite, MAX_FRAME_LEN};

/// IP packets from the guest queued for [`EtherSource`] before new ones are dropped.
const QUEUE_LEN: usize = 256;

/// Idle buffers [`EtherSource::recycle`] keeps for the reader task to reuse.
const POOL_LEN: usize = 256;

/// State shared by the reader task, the sink and the handle.
#[derive(Debug)]
struct Shared<W> {
    adapter: Arc<Mutex<EtherAdapter>>,
    writer: AsyncMutex<W>,
    closed: AtomicBool,
}

impl<W: FrameWrite> Shared<W> {
    fn adapter(&self) -> MutexGuard<'_, EtherAdapter> {
        lock(&self.adapter)
    }

    /// Writes `frame`; a failure closes the port.
    async fn write(&self, frame: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let result = self.writer.lock().await.write_frame(frame).await;
        result.map_err(|err| {
            tracing::debug!("ethernet transport write failed: {err}");
            self.closed.store(true, Ordering::Release);
            io::Error::new(io::ErrorKind::BrokenPipe, err)
        })
    }
}

/// Starts an adapter for one guest on the transport halves `reader` and `writer`.
///
/// Returns the IP side as a [`PacketSource`] (IP packets from the guest) and a
/// [`PacketSink`] (IP packets for the guest), plus a handle for counters. The reader task
/// is spawned on the current Tokio runtime. Transport EOF or a read failure closes the
/// port; the source then returns [`io::ErrorKind::BrokenPipe`] after queued packets,
/// and subsequent sink calls fail with it. A dropped source is detected only when the
/// reader next queues an IP packet: an idle or control-only transport can keep running.
/// That exit does not close the sink. A write failure closes the port, but does not
/// interrupt a pending read.
///
/// # Panics
///
/// Panics if called outside a Tokio runtime.
pub fn spawn_port<R: FrameRead, W: FrameWrite>(
    reader: R,
    writer: W,
    config: EtherConfig,
) -> (EtherSource, EtherSink<W>, EtherHandle) {
    let (mtu, _) = watch::channel(config.mtu);
    let adapter = Arc::new(Mutex::new(EtherAdapter::new(config)));
    let shared = Arc::new(Shared {
        adapter: Arc::clone(&adapter),
        writer: AsyncMutex::new(writer),
        closed: AtomicBool::new(false),
    });
    let pool = SharedPacketPool::new(POOL_LEN);
    let (tx, rx) = mpsc::channel(QUEUE_LEN);
    tokio::spawn(read_loop(reader, Arc::clone(&shared), pool.clone(), tx));
    (
        EtherSource { rx, pool, mtu },
        EtherSink { shared },
        EtherHandle { adapter },
    )
}

/// Reads guest frames until EOF, an I/O failure, or an IP enqueue detects a dropped source.
async fn read_loop<R: FrameRead, W: FrameWrite>(
    mut reader: R,
    shared: Arc<Shared<W>>,
    pool: SharedPacketPool,
    tx: mpsc::Sender<PacketBuf>,
) {
    let mut buf = vec![0; MAX_FRAME_LEN];
    let mut replies = Vec::new();
    loop {
        let len = match reader.read_frame(&mut buf).await {
            Ok(Some(len)) => len,
            Ok(None) => {
                tracing::debug!("ethernet transport closed");
                break;
            }
            Err(err) => {
                tracing::debug!("ethernet transport read failed: {err}");
                break;
            }
        };
        let frame = buf.get(..len).unwrap_or_default();
        let packet = shared.adapter().from_guest(frame, &mut replies);
        if let Some(packet) = packet {
            match tx.try_send(pool.alloc_from(packet)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => shared.adapter().count_backlog_drop(),
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
        for reply in std::mem::take(&mut replies) {
            if shared.write(&reply).await.is_err() {
                return;
            }
        }
    }
    shared.closed.store(true, Ordering::Release);
}

/// IP packets from the guest. See [`spawn_port`].
#[derive(Debug)]
pub struct EtherSource {
    rx: mpsc::Receiver<PacketBuf>,
    pool: SharedPacketPool,
    mtu: watch::Sender<u16>,
}

impl PacketSource for EtherSource {
    /// The next IP packet from the guest, behind [`HEADROOM`](nsplane::HEADROOM).
    /// Cancellation safe.
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }

    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        self.pool.recycle(bufs);
    }

    /// The configured MTU; it never changes.
    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu.subscribe()
    }
}

/// IP packets for the guest. See [`spawn_port`].
#[derive(Debug)]
pub struct EtherSink<W> {
    shared: Arc<Shared<W>>,
}

impl<W: FrameWrite> PacketSink for EtherSink<W> {
    /// Frames `packet` for the learned guest MAC in its headroom and writes it to the
    /// transport. A packet that cannot be framed (no guest MAC learned yet, not IPv4 or
    /// IPv6) is dropped, counted, and reported as delivered.
    async fn send(&self, mut packet: PacketBuf, _from: PeerId) -> io::Result<()> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let Some(header) = self.shared.adapter().to_guest(packet.as_packet()) else {
            return Ok(());
        };
        if packet.reserve_front(HEADER_LEN).is_ok() {
            packet.as_packet_mut()[..HEADER_LEN].copy_from_slice(&header);
        } else {
            let mut framed = PacketBuf::from_packet(&header);
            framed.extend_from_slice(packet.as_packet());
            packet = framed;
        }
        self.shared.write(packet.as_packet()).await
    }
}

/// Counters and state of a running adapter. See [`spawn_port`].
#[derive(Debug, Clone)]
pub struct EtherHandle {
    adapter: Arc<Mutex<EtherAdapter>>,
}

impl EtherHandle {
    /// The adapter counters.
    pub fn stats(&self) -> EtherStats {
        lock(&self.adapter).stats()
    }

    /// The learned guest MAC.
    pub fn guest_mac(&self) -> Option<MacAddr> {
        lock(&self.adapter).guest_mac()
    }
}

/// Locks `adapter`; it is never left inconsistent, so a poisoned lock is taken over.
fn lock(adapter: &Mutex<EtherAdapter>) -> MutexGuard<'_, EtherAdapter> {
    adapter.lock().unwrap_or_else(PoisonError::into_inner)
}
