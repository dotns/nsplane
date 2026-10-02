//! Local-side driver traits: where plaintext packets come from and go to.

use std::io;

use nsplane_packet::{PacketBuf, PeerId};
use tokio::sync::watch;

/// Produces plaintext IP packets from the local side.
pub trait PacketSource: Send + 'static {
    /// Next packet from the local side (TUN read, netstack egress, host bridge).
    ///
    /// The packet occupies the packet region of the returned [`PacketBuf`]; its
    /// headroom is free for the engine to seal in place. Once the source is exhausted
    /// (device closed, all senders gone) this returns [`io::ErrorKind::BrokenPipe`],
    /// and keeps returning it on every later call.
    fn recv(&mut self) -> impl Future<Output = io::Result<PacketBuf>> + Send;

    /// The current local MTU; the receiver observes every later change.
    ///
    /// The engine calls this once when it starts and watches the receiver: every change to
    /// a different value is published as `Event::MtuChanged` and reported by
    /// [`EngineHandle::mtu`](crate::EngineHandle::mtu). Dropping the sender ends the
    /// watching; the engine keeps the last value.
    fn mtu(&self) -> watch::Receiver<u16>;
}

/// Consumes plaintext IP packets for the local side.
pub trait PacketSink: Send + Sync + 'static {
    /// Deliver a decrypted packet to the local side.
    ///
    /// `from` is the peer the packet was decrypted for. The future waits while the
    /// local side applies backpressure. Once the local side is gone this returns
    /// [`io::ErrorKind::BrokenPipe`] and the packet is dropped.
    fn send(&self, packet: PacketBuf, from: PeerId) -> impl Future<Output = io::Result<()>> + Send;
}
