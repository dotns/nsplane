//! The adapter behind the `nsplane` packet I/O traits, over a frame transport.
//!
//! [`spawn_port`] starts a reader task that owns the [`FrameRead`] half: it runs every guest
//! frame through the [`EtherAdapter`], writes the local replies (ARP, neighbor and router
//! advertisements, DHCP) to the transport itself, and queues the IP packets for
//! [`EtherSource`]. The queue is bounded and lossy: when the IP side does not keep up, new
//! packets are dropped and counted in [`EtherStats::drop_backlog`], so local replies keep
//! flowing whether or not the IP side reads. At random intervals of at most [`RA_INTERVAL`]
//! (and at least three quarters of it) the task also writes the
//! adapter's unsolicited router advertisement ([`EtherAdapter::periodic_ra`]), so the
//! guest's default router and DNS servers do not expire. [`EtherSink`] frames IP packets
//! for the guest and writes them to the same transport.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hasher as _};
use std::io;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use nsplane::{PacketBuf, PacketSink, PacketSource, PeerId, SharedPacketPool};
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use tokio::time::{Instant, timeout_at};

use crate::MacAddr;
use crate::adapter::{EtherAdapter, EtherConfig, EtherStats, RA_INTERVAL};
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
/// is spawned on the current Tokio runtime; it also repeats the router advertisement
/// at random intervals of at most [`RA_INTERVAL`] for as long as it runs. Transport EOF or a read failure closes the
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

/// The wait before a periodic router advertisement: [`RA_INTERVAL`] shortened by `random`,
/// uniformly over its last quarter. RFC 4861 6.2.4 asks for a random interval, so that the
/// routers of a link do not advertise in step.
fn ra_wait(random: u64) -> Duration {
    let span = (RA_INTERVAL / 4).as_nanos() + 1;
    let cut = u64::try_from(u128::from(random) % span).unwrap_or(0);
    RA_INTERVAL.saturating_sub(Duration::from_nanos(cut))
}

/// A random [`ra_wait`].
fn random_ra_wait() -> Duration {
    // A hasher of the standard library starts from random keys.
    ra_wait(RandomState::new().build_hasher().finish())
}

/// Reads guest frames until EOF, an I/O failure, or an IP enqueue detects a dropped source,
/// and writes the periodic router advertisement meanwhile.
async fn read_loop<R: FrameRead, W: FrameWrite>(
    mut reader: R,
    shared: Arc<Shared<W>>,
    pool: SharedPacketPool,
    tx: mpsc::Sender<PacketBuf>,
) {
    let mut buf = vec![0; MAX_FRAME_LEN];
    let mut replies = Vec::new();
    let mut next_ra = Instant::now() + random_ra_wait();
    loop {
        let read = {
            // The read is not cancellation safe: it stays pending across advertisements.
            let mut read = pin!(reader.read_frame(&mut buf));
            loop {
                if let Ok(read) = timeout_at(next_ra, read.as_mut()).await {
                    break read;
                }
                next_ra += random_ra_wait();
                let ra = shared.adapter().periodic_ra();
                if let Some(ra) = ra
                    && shared.write(&ra).await.is_err()
                {
                    return;
                }
            }
        };
        let len = match read {
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

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
    use tokio::time::{Instant, timeout};

    use super::*;
    use crate::adapter::RA_INTERVAL;
    use crate::frame::{self, EtherType, Frame};
    use crate::ndp;

    const GW_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const GUEST_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    /// The guest's frames, from a channel.
    struct Reader(UnboundedReceiver<Vec<u8>>);

    impl FrameRead for Reader {
        async fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
            let Some(frame) = self.0.recv().await else {
                return Ok(None);
            };
            buf[..frame.len()].copy_from_slice(&frame);
            Ok(Some(frame.len()))
        }
    }

    /// The frames for the guest, into a channel.
    struct Writer(UnboundedSender<Vec<u8>>);

    impl FrameWrite for Writer {
        fn write_frame(&mut self, frame: &[u8]) -> impl Future<Output = io::Result<()>> + Send {
            let sent = self.0.send(frame.to_vec());
            std::future::ready(sent.map_err(|_| io::ErrorKind::BrokenPipe.into()))
        }
    }

    /// A frame from the guest that the adapter drops after learning its MAC.
    fn guest_frame() -> Vec<u8> {
        let mut out = vec![0; HEADER_LEN + 46];
        frame::write_header(&mut out, GW_MAC, GUEST_MAC, EtherType(0x88cc)).unwrap();
        out
    }

    /// Whether `frame` is a router advertisement to all-nodes.
    fn is_unsolicited_ra(frame: &[u8]) -> bool {
        let frame = Frame::parse(frame).unwrap();
        frame.dst == MacAddr::ipv6_multicast(ndp::ALL_NODES)
            && frame.ethertype == EtherType::IPV6
            && frame.payload.get(40) == Some(&134)
    }

    #[tokio::test(start_paused = true)]
    async fn router_advertisements_repeat_once_the_guest_is_known() {
        let (guest_tx, reader) = unbounded_channel();
        let (writer, mut guest_rx) = unbounded_channel();
        let config = EtherConfig {
            ipv6_prefix: Some(Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 0)),
            ..EtherConfig::new(GW_MAC)
        };
        let (_source, _sink, handle) = spawn_port(Reader(reader), Writer(writer), config);

        // Nothing is advertised before a guest MAC is learned.
        let quiet = timeout(RA_INTERVAL * 7 / 2, guest_rx.recv()).await;
        assert!(quiet.is_err());

        guest_tx.send(guest_frame()).unwrap();
        let first = guest_rx.recv().await.unwrap();
        assert!(is_unsolicited_ra(&first));
        let learned = Instant::now();

        // The first repeat is due within the interval, the following ones after a random
        // wait in its last quarter.
        let mut last = learned;
        let mut waits = Vec::new();
        for n in 1..=6 {
            let ra = timeout(RA_INTERVAL * 2, guest_rx.recv()).await.unwrap();
            assert_eq!(ra, Some(first.clone()));
            let now = Instant::now();
            let wait = now - last;
            assert!(wait <= RA_INTERVAL, "{wait:?}");
            if n > 1 {
                assert!(wait >= RA_INTERVAL * 3 / 4, "{wait:?}");
                waits.push(wait);
            }
            last = now;
        }
        assert!(waits.iter().any(|wait| *wait != waits[0]), "{waits:?}");
        // Past the router lifetime of the first advertisement.
        assert!(last - learned > RA_INTERVAL * 3);
        assert_eq!(handle.stats().nd_replies, 7);
    }

    #[test]
    fn the_wait_is_in_the_last_quarter_of_the_interval() {
        let shortest = RA_INTERVAL * 3 / 4;
        assert_eq!(ra_wait(0), RA_INTERVAL);
        assert_eq!(ra_wait(150_000_000_000), shortest);
        assert_eq!(ra_wait(150_000_000_001), RA_INTERVAL);
        assert_eq!(ra_wait(60_000_000_000), Duration::from_secs(540));
        for random in [1, 149_999_999_999, u64::MAX / 3, u64::MAX] {
            let wait = ra_wait(random);
            assert!(shortest <= wait && wait <= RA_INTERVAL, "{wait:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn no_router_advertisements_without_ipv6() {
        let (guest_tx, reader) = unbounded_channel();
        let (writer, mut guest_rx) = unbounded_channel();
        let (_source, _sink, handle) =
            spawn_port(Reader(reader), Writer(writer), EtherConfig::new(GW_MAC));
        guest_tx.send(guest_frame()).unwrap();
        let quiet = timeout(RA_INTERVAL * 4, guest_rx.recv()).await;
        assert!(quiet.is_err());
        assert_eq!(handle.guest_mac(), Some(GUEST_MAC));
        assert_eq!(handle.stats().frames_out, 0);
    }
}
