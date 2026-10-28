//! Routing the core's outputs: datagrams to the transports, packets to the sink, drops and
//! events.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use std::num::NonZeroU64;

use nsplane_core::{Event, Output, TrackedOutcome};
use nsplane_packet::{MAX_BATCH, PacketBuf, Path, PeerId, TransportId};
use tokio::sync::mpsc::error::TrySendError;

use super::Owner;
use super::queue::BatchQueue;
#[cfg(doc)]
use super::transport::TransportSlot;
use super::transport::{Datagram, TryDeliver};
use crate::events::{
    DROP_NO_TRANSPORT, DROP_PLAINTEXT_EGRESS_CLOSED, DROP_PLAINTEXT_EGRESS_FULL, DROP_SINK_CLOSED,
    DROP_SINK_FULL, DROP_TRANSPORT_CLOSED, DROP_TRANSPORT_SEND_ERROR,
};
use crate::io::PacketSink;

/// The sink as the owner task sees it.
pub(super) struct InlineSink {
    pub(super) try_deliver: TryDeliver,
    /// Packets in the deliver queue or in the batch the sink task is delivering: raised by
    /// the owner per queued packet, lowered by the sink task once it is done with its batch.
    pub(super) outstanding: Arc<AtomicUsize>,
    /// No crypto workers and not suspended: the owner task may deliver itself.
    pub(super) allowed: bool,
    /// The sink reported [`io::ErrorKind::BrokenPipe`] to the owner task.
    pub(super) closed: bool,
    pub(super) backoff: Backoff,
    /// Packets the owner task delivers itself at the end of the current drain, oldest
    /// first ([`Owner::deliver_inline`]).
    pub(super) delivered: VecDeque<(PeerId, PacketBuf)>,
}

impl InlineSink {
    pub(super) fn new<Snk: PacketSink>(
        sink: Arc<Snk>,
        outstanding: Arc<AtomicUsize>,
        allowed: bool,
    ) -> Self {
        Self {
            try_deliver: Box::new(move |packets| sink.try_send_batch(packets)),
            outstanding,
            allowed,
            closed: false,
            backoff: Backoff::default(),
            delivered: VecDeque::with_capacity(MAX_BATCH),
        }
    }
}

/// When the owner task sends and delivers itself.
pub(super) struct Inline {
    /// No crypto workers and not suspended: the owner task may send itself.
    pub(super) allowed: bool,
    /// For the current drain: allowed, and no local packet or received datagram is waiting,
    /// so the owner task would wait next and may also send itself. Under load it hands the
    /// datagrams to the transmit tasks, which send them while it seals the next batch.
    pub(super) send: bool,
    /// Some transport has datagrams in [`TransportSlot::inline`].
    pub(super) queued: bool,
    /// Drains so far, the clock of [`Backoff`].
    pub(super) drains: u64,
}

/// The longest a transport or sink that took nothing is skipped, in drains.
const MAX_BACKOFF: u64 = 1024;

/// Skips inline sending to a transport or sink that took nothing (one that does not
/// support it, or is full) for a number of drains that doubles with every such try, up to
/// [`MAX_BACKOFF`], and restarts once it takes something.
#[derive(Debug, Default)]
pub(super) struct Backoff {
    /// The first drain to try again in.
    retry_at: u64,
    /// The last wait, in drains.
    wait: u64,
}

impl Backoff {
    const fn ready(&self, drain: u64) -> bool {
        drain >= self.retry_at
    }

    /// Records a try in `drain`; `took` whether anything was taken.
    fn record(&mut self, drain: u64, took: bool) {
        if took {
            self.wait = 0;
        } else {
            self.wait = (self.wait * 2).clamp(1, MAX_BACKOFF);
            self.retry_at = drain + self.wait;
        }
    }
}

impl Owner {
    /// Routes the core's outputs, returns transmitted buffers to the core and arms the
    /// flush of waiting datagrams. With `droppable`, datagrams to transmit may overflow the
    /// waiting datagrams.
    pub(super) fn drain(&mut self, droppable: bool) {
        self.inline.drains += 1;
        self.inline.send = self.inline.allowed
            && self.datagrams.is_empty()
            && self.local.as_ref().is_none_or(BatchQueue::is_empty);
        while let Some(output) = self.core.poll_output() {
            match output {
                Output::Transmit { path, data } => self.transmit(path, data, droppable),
                Output::Deliver { from, mut packet } => {
                    packet.set_tracked(false);
                    self.deliver(from, packet);
                }
                Output::Event(event) => self.event(event),
                Output::Tracked { tag, peer, outcome } => self.tracked_outcome(tag, peer, outcome),
                Output::Plaintext { to, packet } => self.plaintext_egress(to, packet),
                // The core of this engine has no other outputs.
                _ => {}
            }
        }
        if std::mem::take(&mut self.inline.queued) {
            while let Some(id) = self
                .transports
                .iter()
                .find(|(_, slot)| !slot.inline.is_empty())
                .map(|(id, _)| *id)
            {
                self.send_inline(id, droppable);
            }
        }
        if std::mem::take(&mut self.staged) {
            self.hand_over();
        }
        if !self.sink.delivered.is_empty() {
            self.deliver_inline();
        }
        if !self.recycled.is_empty() {
            self.high_water.recycle.record(self.recycled.len());
            self.recycled.take_all(&mut self.recycle_bufs);
            self.recycled.release();
            for buf in self.recycle_bufs.drain(..) {
                self.core.recycle(buf);
            }
        }
        for slot in self.transports.values_mut() {
            if slot.flush.is_none() && !slot.pending.is_empty() {
                slot.flush = Some(Box::pin(Arc::clone(&slot.queue.permits).acquire_owned()));
            }
        }
    }

    /// Hands the staged datagrams of every transport to its transmit task, one message per
    /// transport; those of a transport whose queue is gone are dropped.
    pub(super) fn hand_over(&mut self) {
        let mut closed = 0;
        for slot in self.transports.values_mut() {
            if let Some(refused) = slot.hand_over() {
                closed += refused.len();
                for (_, data) in refused {
                    slot.traffic
                        .finish_tracked(&data, Some(DROP_TRANSPORT_CLOSED));
                    self.core.recycle(data);
                }
            }
        }
        for _ in 0..closed {
            self.dropped(None, DROP_TRANSPORT_CLOSED);
        }
    }

    /// Takes the datagrams the owner task sent itself out of `sent` and returns their
    /// buffers: to the source while it takes them, otherwise (or when its queue is full) to
    /// the core's pool.
    fn give_back(&mut self, sent: &mut Vec<Datagram>) {
        let to_source = self.recycle.to_source();
        for (_, data) in sent.drain(..) {
            if to_source {
                self.recycle_bufs.push(data);
            } else {
                self.core.recycle(data);
            }
        }
        if to_source {
            self.recycle.give(&mut self.recycle_bufs);
            for buf in self.recycle_bufs.drain(..) {
                self.core.recycle(buf);
            }
        }
    }

    /// Sends a datagram on the transport its path names: without crypto workers, the owner
    /// task sends it itself at the end of the drain when no input is waiting and nothing
    /// of that transport is waiting, queued or being sent, and otherwise queues it.
    ///
    /// A tracked datagram ends its batch: the owner task's call or the message to the
    /// transmit task that carries it.
    pub(super) fn transmit(&mut self, path: Path, data: PacketBuf, droppable: bool) {
        if self.inline.send
            && let Some(slot) = self.transports.get_mut(&path.transport)
            && (!slot.inline.is_empty() || (slot.backoff.ready(self.inline.drains) && slot.idle()))
        {
            let tracked = data.is_tracked();
            slot.inline.push((path, data));
            self.inline.queued = true;
            if tracked || slot.inline.len() >= MAX_BATCH {
                self.send_inline(path.transport, droppable);
            }
            return;
        }
        self.queue_datagram(path, data, droppable);
    }

    /// Hands the datagrams collected for transport `id` to it without waiting; returns the
    /// buffers of those it is done with to the core and queues the rest, in order.
    fn send_inline(&mut self, id: TransportId, droppable: bool) {
        let Some(slot) = self.transports.get_mut(&id) else {
            return;
        };
        let mut batch = std::mem::take(&mut slot.inline);
        let (sent, last_failed) = slot.send_now(&batch);
        slot.backoff.record(self.inline.drains, sent > 0);
        // Only the last datagram of a call can be tracked, and the call attributes it.
        if sent == batch.len()
            && let Some((_, last)) = batch.last()
        {
            let failure = last_failed.then_some(DROP_TRANSPORT_SEND_ERROR);
            slot.traffic.finish_tracked(last, failure);
        }
        for (path, data) in batch.drain(sent..) {
            self.queue_datagram(path, data, droppable);
        }
        self.give_back(&mut batch);
        if let Some(slot) = self.transports.get_mut(&id) {
            slot.inline = batch;
        }
    }

    /// Queues a datagram for the transport its path names.
    fn queue_datagram(&mut self, path: Path, data: PacketBuf, droppable: bool) {
        let result = match self.transports.get_mut(&path.transport) {
            Some(slot) => {
                let result = slot.transmit((path, data), droppable, self.queue_capacity);
                self.high_water.transmit.record(slot.queued());
                self.high_water.backlog.record(slot.pending.len());
                if !slot.staged.is_empty() {
                    self.staged = true;
                }
                // A message carries at most a batch, and ends with a tracked datagram; the
                // transmit task starts on it while the owner goes on.
                if (slot.staged.len() >= MAX_BATCH
                    || slot
                        .staged
                        .last()
                        .is_some_and(|(_, data)| data.is_tracked()))
                    && let Some(refused) = slot.hand_over()
                {
                    for (_, data) in refused {
                        self.finish_tracked(&data, DROP_TRANSPORT_CLOSED);
                        self.core.recycle(data);
                        self.dropped(None, DROP_TRANSPORT_CLOSED);
                    }
                }
                result
            }
            None => Err((data, DROP_NO_TRANSPORT)),
        };
        if let Err((data, reason)) = result {
            self.finish_tracked(&data, reason);
            self.core.recycle(data);
            self.dropped(None, reason);
        }
    }

    /// Reports the datagram `data`, if tracked, as not sent for `reason`.
    pub(super) fn finish_tracked(&self, data: &PacketBuf, reason: &'static str) {
        if data.is_tracked()
            && let Some(receipts) = &self.send_errors.receipts
        {
            receipts.finish(data, Some(reason));
        }
    }

    /// Reports the tracked packet with `tag` as not sent for `reason`.
    pub(super) fn not_sent(&self, tag: NonZeroU64, reason: &'static str) {
        if let Some(receipts) = &self.send_errors.receipts {
            receipts.not_sent(tag, reason);
        }
    }

    /// Records what the core did with a tracked packet.
    #[cold]
    fn tracked_outcome(&self, tag: NonZeroU64, peer: Option<PeerId>, outcome: TrackedOutcome) {
        let Some(receipts) = &self.send_errors.receipts else {
            return;
        };
        match outcome {
            TrackedOutcome::Sealed { bytes } => receipts.sealed(tag, peer, bytes),
            TrackedOutcome::NotSent { reason } => receipts.not_sent(tag, reason),
            // The core of this engine reports no other outcome.
            _ => {}
        }
    }

    /// Hands a packet routed to `to`, a peer marked for plaintext egress, to the plaintext
    /// egress queue without waiting; drops it when the queue is full or gone.
    #[cold]
    fn plaintext_egress(&mut self, to: PeerId, mut packet: PacketBuf) {
        packet.set_tracked(false);
        let Some(queue) = &self.plaintext_egress else {
            self.core.recycle(packet);
            return self.dropped(Some(to), DROP_PLAINTEXT_EGRESS_CLOSED);
        };
        let reason = match queue.try_send((to, packet)) {
            Ok(()) => return,
            Err(TrySendError::Full((_, packet))) => {
                self.core.recycle(packet);
                DROP_PLAINTEXT_EGRESS_FULL
            }
            Err(TrySendError::Closed((_, packet))) => {
                self.core.recycle(packet);
                DROP_PLAINTEXT_EGRESS_CLOSED
            }
        };
        self.dropped(Some(to), reason);
    }

    /// Moves the waiting datagrams of transport `id` to its transmit queue until it is full,
    /// in order.
    pub(super) fn move_pending(&mut self, id: TransportId) {
        let Some(slot) = self.transports.get_mut(&id) else {
            return;
        };
        for (path, data) in std::mem::take(&mut slot.pending) {
            self.transmit(path, data, false);
        }
    }

    /// Delivers a packet: the owner task hands it to the sink itself at the end of the drain
    /// when no packet is queued for or being delivered by the sink task, and otherwise
    /// queues it.
    fn deliver(&mut self, from: PeerId, packet: PacketBuf) {
        let sink = &mut self.sink;
        if sink.allowed
            && !sink.closed
            && (!sink.delivered.is_empty()
                || (sink.backoff.ready(self.inline.drains)
                    && sink.outstanding.load(Ordering::Acquire) == 0))
        {
            sink.delivered.push_back((from, packet));
            if sink.delivered.len() >= MAX_BATCH {
                self.deliver_inline();
            }
            return;
        }
        self.queue_delivery(from, packet);
    }

    /// Hands the packets collected for the sink to it without waiting and queues the rest,
    /// in order.
    fn deliver_inline(&mut self) {
        let mut packets = std::mem::take(&mut self.sink.delivered);
        let offered = packets.len();
        while !packets.is_empty() {
            match (self.sink.try_deliver)(&mut packets) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    tracing::debug!("Packet sink closed");
                    self.sink.closed = true;
                    break;
                }
                Err(e) => tracing::warn!(message = "Packet sink error", error = ?e),
            }
        }
        self.sink
            .backoff
            .record(self.inline.drains, packets.len() < offered);
        while let Some((from, packet)) = packets.pop_front() {
            self.queue_delivery(from, packet);
        }
        self.sink.delivered = packets;
    }

    /// Queues a packet for the sink task.
    fn queue_delivery(&mut self, from: PeerId, packet: PacketBuf) {
        if self.sink.closed {
            self.core.recycle(packet);
            self.dropped(Some(from), DROP_SINK_CLOSED);
            return;
        }
        self.sink.outstanding.fetch_add(1, Ordering::Relaxed);
        let result = self.deliver.try_send((from, packet));
        if result.is_err() {
            self.sink.outstanding.fetch_sub(1, Ordering::Relaxed);
        }
        let reason = match result {
            Ok(()) => {
                let queued = self.deliver.max_capacity() - self.deliver.capacity();
                self.high_water.deliver.record(queued);
                return;
            }
            Err(TrySendError::Full((_, packet))) => {
                self.high_water
                    .deliver
                    .record(self.high_water.deliver.capacity);
                self.core.recycle(packet);
                DROP_SINK_FULL
            }
            Err(TrySendError::Closed((_, packet))) => {
                self.core.recycle(packet);
                DROP_SINK_CLOSED
            }
        };
        self.dropped(Some(from), reason);
    }

    pub(super) fn dropped(&mut self, peer: Option<PeerId>, reason: &'static str) {
        self.event(Event::Dropped { peer, reason });
    }

    /// Counts and publishes the failed sends the transmit tasks reported.
    pub(super) fn send_errors(&mut self) {
        for _ in 0..self.send_errors.take() {
            self.dropped(None, DROP_TRANSPORT_SEND_ERROR);
        }
    }

    /// Counts drops and publishes the event; never blocks.
    pub(super) fn event(&mut self, event: Event) {
        if let Event::PathAdopted { peer, .. } = event
            && let Some(table) = &mut self.path_mtus.table
        {
            table.peer(peer, self.core.data_path(peer), self.mtu);
            if table.changed() {
                self.publish_peer_mtus();
            }
        }
        let dropped = if let Event::Dropped { reason, .. } = event {
            *self.drops.entry(reason).or_default() += 1;
            true
        } else {
            false
        };
        // No subscribers is not an error.
        let _ = self.events.send(event);
        // Reading the occupancy takes the channel's locks: not on the per-packet drop path.
        if !dropped {
            let depth = &mut self.high_water.events;
            depth.record(self.events.len().min(depth.capacity));
        }
    }
}
