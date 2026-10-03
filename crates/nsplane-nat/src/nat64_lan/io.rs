//! The local-side wrappers that install a [`Nat64Lan`]: [`Nat64LanSink`] and
//! [`Nat64LanSource`].

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use nsplane::{PacketSink, PacketSource};
use nsplane_packet::{PacketBatch, PacketBuf, PeerId};
use tokio::sync::watch;

use super::{Nat64Lan, Nat64Verdict};

/// A [`PacketSink`] that runs [`Nat64Lan::forward`] on every packet the
/// engine delivers before `inner` gets it.
///
/// Translated packets (IPv4 to a LAN host) and packets that are not ours go
/// to `inner`; dropped packets are discarded (and counted by the
/// [`Nat64Lan`]) with `Ok(())`. Install it as the engine's sink on the
/// gateway, with a [`Nat64LanSource`] around the source.
#[derive(Debug)]
pub struct Nat64LanSink<K> {
    inner: K,
    nat: Arc<Nat64Lan>,
}

impl<K: PacketSink> Nat64LanSink<K> {
    /// Wraps `inner`, translating through `nat`.
    pub const fn new(inner: K, nat: Arc<Nat64Lan>) -> Self {
        Self { inner, nat }
    }
}

impl<K: PacketSink> PacketSink for Nat64LanSink<K> {
    async fn send(&self, mut packet: PacketBuf, from: PeerId) -> io::Result<()> {
        if matches!(self.nat.forward(&mut packet), Nat64Verdict::Drop(_)) {
            return Ok(());
        }
        self.inner.send(packet, from).await
    }

    /// Translates every packet, removes the dropped ones and hands the rest
    /// to `inner` in order. When called again after an error, the packets
    /// left in `packets` are already translated: they are IPv4 or not ours,
    /// which [`Nat64Lan::forward`] leaves unchanged.
    async fn send_batch(&self, packets: &mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> {
        packets
            .retain_mut(|(_, packet)| !matches!(self.nat.forward(packet), Nat64Verdict::Drop(_)));
        self.inner.send_batch(packets).await
    }
}

/// A [`PacketSource`] that runs [`Nat64Lan::reverse`] on every local packet
/// `inner` produces before the engine routes it.
///
/// Translated packets (IPv6 replies to a peer) and packets that are not ours
/// are returned; dropped packets are skipped. The MTU is `inner`'s.
/// Cancellation safety is that of `inner`.
#[derive(Debug)]
pub struct Nat64LanSource<S> {
    inner: S,
    nat: Arc<Nat64Lan>,
}

impl<S: PacketSource> Nat64LanSource<S> {
    /// Wraps `inner`, translating through `nat`.
    pub const fn new(inner: S, nat: Arc<Nat64Lan>) -> Self {
        Self { inner, nat }
    }
}

impl<S: PacketSource> PacketSource for Nat64LanSource<S> {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        loop {
            let mut packet = self.inner.recv().await?;
            if !matches!(self.nat.reverse(&mut packet), Nat64Verdict::Drop(_)) {
                return Ok(packet);
            }
        }
    }

    /// Reads a batch from `inner`, translates the new packets and removes
    /// the dropped ones, in order; reads again if every new packet was
    /// dropped. Packets `inner` appended before an error are translated too.
    async fn recv_batch(&mut self, batch: &mut PacketBatch) -> io::Result<()> {
        loop {
            let start = batch.len();
            let result = self.inner.recv_batch(batch).await;
            let mut kept = PacketBatch::new();
            for (i, mut packet) in batch.drain().enumerate() {
                if i < start || !matches!(self.nat.reverse(&mut packet), Nat64Verdict::Drop(_)) {
                    // `kept` has the room `batch` had.
                    let _ = kept.push(packet);
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
