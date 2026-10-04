//! A local side bridged through host callbacks, such as iOS `NEPacketTunnelFlow`.
//!
//! The host pushes the packets it reads into a [`HostTunInput`] from any thread; the
//! engine reads them from the [`HostTunSource`] and writes its packets back through the
//! host's `write` callback in the [`HostTunSink`]. Nothing here is platform-specific.

use std::fmt;
use std::io;
use std::sync::Arc;

use nsplane::{PacketBatch, PacketBuf, PacketSink, PacketSource, PeerId};
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
/// The side starts with MTU `mtu` ([`HostTunInput::set_mtu`] changes it later), queues up to `capacity` packets from the host
/// ([`HOST_TUN_DEFAULT_CAPACITY`] is recommended), and writes the engine's packets with
/// `write`, an `Arc<dyn Fn(&[u8]) -> bool + Send + Sync>`.
///
/// Returns the input the host pushes its packets into, the source the engine reads
/// them from, and the sink that hands the engine's packets to `write`.
///
/// `write` runs synchronously on the engine task, so it must not block for long; it
/// returns `false` once the host can no longer take packets.
/// `NEPacketTunnelFlow.writePackets` does not block.
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
    let (mtu_tx, mtu_rx) = watch::channel(mtu);
    (
        HostTunInput { tx, mtu: mtu_tx },
        HostTunSource {
            rx,
            mtu,
            mtu_rx,
            oversize_drops: 0,
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

/// The host's end of a [`host_tun`] local side: packets the host read for the engine go in here.
///
/// Clones push into the same queue and set the same MTU. Once every clone is dropped and the queue is drained,
/// the [`HostTunSource`] returns [`io::ErrorKind::BrokenPipe`].
#[derive(Debug, Clone)]
pub struct HostTunInput {
    tx: mpsc::Sender<PacketBuf>,
    mtu: watch::Sender<u16>,
}

impl HostTunInput {
    /// Queues a copy of `packet` for the engine, without blocking; callable from any
    /// thread, inside a tokio runtime or not.
    ///
    /// The packet is copied once, into a buffer with the engine's headroom. Packets longer
    /// than the MTU are queued too and dropped by the [`HostTunSource`].
    pub fn push(&self, packet: &[u8]) -> Result<(), PushError> {
        self.tx
            .try_send(PacketBuf::from_packet(packet))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => PushError::Full,
                mpsc::error::TrySendError::Closed(_) => PushError::Closed,
            })
    }

    /// Sets the MTU of the local side to `mtu`; callable from any thread.
    ///
    /// The engine sees the change through [`PacketSource::mtu`], as for any source, and
    /// the [`HostTunSource`] drops the packets it reads from then on that are longer than
    /// `mtu`, including those already queued. [`HostTunSource::oversize_drops`] keeps
    /// counting. Setting the current MTU again does nothing; setting it after the source
    /// was dropped is harmless.
    pub fn set_mtu(&self, mtu: u16) {
        self.mtu.send_if_modified(|current| {
            let changed = *current != mtu;
            *current = mtu;
            changed
        });
    }
}

/// The engine's source of a [`host_tun`] local side: the packets the host pushed, in order.
///
/// Packets longer than the MTU are dropped and counted ([`HostTunSource::oversize_drops`]);
/// the first one is logged as a warning. Once every [`HostTunInput`] is dropped and the
/// queue is drained, `recv` returns [`io::ErrorKind::BrokenPipe`] on every call. The MTU
/// is the one [`host_tun`] was given until [`HostTunInput::set_mtu`] changes it; each
/// packet is checked against the MTU current when it is read.
#[derive(Debug)]
pub struct HostTunSource {
    rx: mpsc::Receiver<PacketBuf>,
    mtu: u16,
    mtu_rx: watch::Receiver<u16>,
    oversize_drops: u64,
}

impl HostTunSource {
    /// How many packets longer than the MTU this source dropped.
    pub const fn oversize_drops(&self) -> u64 {
        self.oversize_drops
    }

    /// `packet` if it fits the MTU; otherwise drops and counts it.
    fn admit(&mut self, packet: PacketBuf) -> Option<PacketBuf> {
        // A version check without a lock; the lock is taken only after a change, or on
        // every packet once every input is gone (the closed channel may hide a last change).
        if !matches!(self.mtu_rx.has_changed(), Ok(false)) {
            self.mtu = *self.mtu_rx.borrow_and_update();
        }
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

    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu_rx.clone()
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
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn side(mtu: u16) -> (HostTunInput, HostTunSource) {
        let (input, source, _) = host_tun(mtu, 16, Arc::new(|_: &[u8]| true));
        (input, source)
    }

    #[tokio::test]
    async fn set_mtu_applies_to_queued_and_later_packets() -> TestResult {
        let (input, mut source) = side(100);
        input.push(&[0; 100])?;
        input.push(&[1; 80])?;
        input.clone().set_mtu(80);
        input.push(&[2; 81])?;
        input.push(&[3; 80])?;

        // Queued before the change or not, every packet is checked against the new MTU.
        assert_eq!(source.recv().await?.as_packet(), [1; 80]);
        assert_eq!(source.recv().await?.as_packet(), [3; 80]);
        assert_eq!(source.oversize_drops(), 2);

        input.set_mtu(200);
        input.push(&[4; 200])?;
        let mut batch = PacketBatch::new();
        source.recv_batch(&mut batch).await?;
        assert_eq!(batch.len(), 1);
        assert_eq!(source.oversize_drops(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn set_mtu_publishes_changes_only() -> TestResult {
        let (input, source) = side(1280);
        let mut mtu = source.mtu();
        assert_eq!(*mtu.borrow_and_update(), 1280);

        input.set_mtu(1280);
        assert!(!mtu.has_changed()?);
        input.set_mtu(1400);
        assert!(mtu.has_changed()?);
        assert_eq!(*mtu.borrow_and_update(), 1400);
        Ok(())
    }

    #[tokio::test]
    async fn last_change_before_inputs_drop_still_applies() -> TestResult {
        let (input, mut source) = side(100);
        input.push(&[0; 100])?;
        input.set_mtu(99);
        drop(input);
        let err = source.recv().await.err().ok_or("expected an error")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(source.oversize_drops(), 1);
        Ok(())
    }

    #[test]
    fn set_mtu_after_the_source_is_dropped() {
        let (input, source) = side(1280);
        drop(source);
        input.set_mtu(1400);
        assert_eq!(input.push(&[0; 10]), Err(PushError::Closed));
    }
}
