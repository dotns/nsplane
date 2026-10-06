//! Local-side driver traits: where plaintext packets come from and go to.

use std::collections::VecDeque;
use std::io;

use nsplane_packet::{PacketBatch, PacketBuf, PeerId};
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

    /// Appends the next packets from the local side to `batch`, in order.
    ///
    /// On success at least one packet was appended, unless `batch` was already full, and
    /// never more than `batch` has room for. Each packet follows the [`recv`] buffer
    /// contract. Once the source is exhausted this returns [`io::ErrorKind::BrokenPipe`],
    /// like [`recv`]; packets appended before an error are kept in `batch`.
    ///
    /// The default appends one packet from [`recv`]; a source that can read several
    /// packets at once overrides it. Cancellation safety is that of [`recv`]: the default
    /// appends a packet only once [`recv`] resolved.
    ///
    /// [`recv`]: PacketSource::recv
    fn recv_batch(
        &mut self,
        batch: &mut PacketBatch,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            if !batch.is_full() {
                let packet = self.recv().await?;
                // The batch had room, so the push succeeds.
                let _ = batch.push(packet);
            }
            Ok(())
        }
    }

    /// Hands back buffers the engine no longer needs, so the source can read into them
    /// again instead of allocating.
    ///
    /// The source may take buffers out of `bufs` up to the bound of its pool and must drop
    /// the rest; the caller drops whatever it leaves in `bufs`. It never blocks.
    ///
    /// The default takes nothing.
    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        let _ = bufs;
    }

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

    /// Delivers the decrypted packets in `packets` to the local side, front first.
    ///
    /// Each entry is a packet and the peer it was decrypted for, as for [`send`]. The
    /// caller owns `packets` and reuses it, so delivering a batch does not allocate; the
    /// sink removes each packet from the front as it takes it over. On success `packets`
    /// is empty. On an error the packet that failed is dropped and the rest stay in
    /// `packets`, in order: after [`io::ErrorKind::BrokenPipe`] (the local side is gone)
    /// the caller stops; after any other error it may call again to deliver the rest.
    ///
    /// The default calls [`send`] for each packet in order. Cancelling it drops the packet
    /// being delivered, if any; the ones not taken over yet stay in `packets`.
    ///
    /// [`send`]: PacketSink::send
    fn send_batch(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            while let Some((from, packet)) = packets.pop_front() {
                self.send(packet, from).await?;
            }
            Ok(())
        }
    }

    /// Delivers `packets` like [`send_batch`], and appends the buffers of delivered packets
    /// to `spent` so the caller can reuse them.
    ///
    /// Only a buffer the sink no longer references may be appended: a packet written out
    /// (copied to the OS, say), or one it dropped. Ordering, backpressure and errors follow
    /// [`send_batch`] exactly: on success `packets` is empty; on an error the packet that
    /// failed is dropped and the rest stay in `packets`, in order. `spent` is only appended
    /// to, never read or cleared, and the caller must tolerate it staying empty.
    ///
    /// The default calls [`send_batch`] and appends nothing; a sink that is done with the
    /// buffers once it took the packets over, like a TUN device, overrides it. [`pump`]
    /// hands `spent` to [`PacketSource::recycle`]. Cancelling it is like cancelling
    /// [`send_batch`]; what was appended to `spent` stays there.
    ///
    /// [`send_batch`]: PacketSink::send_batch
    /// [`pump`]: crate::pump
    fn send_batch_spent(
        &self,
        packets: &mut VecDeque<(PeerId, PacketBuf)>,
        spent: &mut Vec<PacketBuf>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        let _ = spent;
        self.send_batch(packets)
    }

    /// Delivers packets from the front of `packets` like [`send_batch`], but never waits.
    ///
    /// Synchronous: the call returns as soon as it would have to wait, so the engine may
    /// call it from its owner task when the sink task is idle, saving the handoff to that
    /// task. Packets are taken over from the front, in order, under the [`send_batch`]
    /// contract: on success `packets` is empty; on an error the packet that failed is
    /// dropped and the rest stay in `packets` ([`io::ErrorKind::BrokenPipe`]: the local
    /// side is gone). When the front packet cannot be taken over now, this returns
    /// [`io::ErrorKind::WouldBlock`] and leaves it and the ones behind it in `packets` for
    /// the caller, who delivers them later, after the ones taken over.
    ///
    /// The default takes nothing and returns [`io::ErrorKind::WouldBlock`], so the engine
    /// delivers every packet through [`send_batch`] on the sink task.
    ///
    /// [`send_batch`]: PacketSink::send_batch
    fn try_send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        let _ = packets;
        Err(io::ErrorKind::WouldBlock.into())
    }
}
