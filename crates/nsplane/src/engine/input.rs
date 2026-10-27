//! Feeding local packets and received datagrams to the core or the crypto workers.

use nsplane_packet::{MAX_BATCH, PacketBuf};
use tokio::sync::{mpsc, oneshot};

use super::transport::Datagram;
use super::workers::JobBatch;
use super::{Owner, now};
use crate::fragment::Action;
use crate::handle::Plaintext;

/// Local barriers ([`EngineHandle::local_barrier`]) and how far the owner task is.
///
/// [`EngineHandle::local_barrier`]: crate::EngineHandle::local_barrier
#[derive(Default)]
pub(super) struct Barriers {
    /// Local packets taken through routing and the outbound filters so far.
    done: u64,
    /// Barriers waiting for `done` to reach their position.
    waiting: Vec<(u64, oneshot::Sender<()>)>,
}

/// The queue of [`crate::PlaintextIngress`].
pub(super) struct PlaintextQueue {
    pub(super) packets: mpsc::Receiver<Plaintext>,
    /// Alternates which of plaintext packets and datagrams is polled first.
    pub(super) first: bool,
}

impl Owner {
    /// Feeds `first` and the datagrams queued behind it to the core as one batch, or their
    /// cryptography to the crypto workers.
    ///
    /// Takes only what is already queued, never waiting for more: at most [`MAX_BATCH`]
    /// datagrams, no more than the crypto workers have room for and, since each may deliver a
    /// packet, no more than the deliver queue has room for beyond the received datagrams
    /// with the crypto workers (but always `first`, read only once there is room). Packets
    /// the owner task delivers itself take no room; those the sink does not take at once
    /// then fit in the queue.
    pub(super) fn input_datagrams(&mut self, first: Datagram) {
        self.high_water
            .datagrams
            .record_received(self.datagrams.len());
        let room = self.batch_room().min(self.deliver_room());
        let batch = &mut self.datagram_batch;
        batch.push(first);
        while batch.len() < room
            && let Some(datagram) = self.datagrams.try_recv()
        {
            batch.push(datagram);
        }
        self.datagrams.release();
        let now = now();
        if self.workers.is_some() {
            self.core
                .handle_datagrams_deferred(batch.drain(..), now, &mut self.jobs);
            self.dispatch_jobs(true);
        } else {
            self.core.handle_datagrams(batch.drain(..), now);
        }
    }

    /// Feeds `first` and the local packets queued behind it, each through the fragmentation
    /// stage if installed, to the core as one batch, or their cryptography to the crypto
    /// workers; ICMP errors from the fragmentation stage go back to the local side.
    ///
    /// Takes only what is already queued, never waiting for more: at most [`MAX_BATCH`]
    /// packets, no more than the crypto workers have room for and no more than the room for
    /// local packets ([`Owner::local_room`]), counting one datagram per packet (but always
    /// `first`). A packet that leads to several datagrams (fragments, a handshake) may take
    /// the waiting datagrams past the local threshold, up to their bound; those that find
    /// the bound reached are dropped as usual.
    pub(super) fn input_locals(&mut self, first: PacketBuf) {
        let Some(local) = &self.local else {
            return;
        };
        self.high_water.local.record_received(local.len());
        let room = self.batch_room().min(self.local_room());
        let now = now();
        let source = self.mtu;
        let floor = self
            .path_mtus
            .table
            .as_ref()
            .map_or(source, |table| table.floor(source));
        let mut next = Some(first);
        let mut taken = 0;
        while let Some(packet) = next {
            taken += 1;
            match &mut self.fragmenter {
                None => self.local_batch.push(packet),
                Some(fragmenter) => {
                    let core = &self.core;
                    let table = &mut self.path_mtus.table;
                    // Above the floor: the packet's peer and its MTU, following the
                    // path its data leaves on now (a policy may have moved it).
                    let lookup = |src, dst| {
                        let peer = core.route_from(src, dst);
                        let mtu = match (peer, table.as_deref_mut()) {
                            (Some(peer), Some(table)) => {
                                table.peer(peer, core.data_path(peer), source)
                            }
                            _ => source,
                        };
                        (peer, mtu)
                    };
                    match fragmenter.process(packet, floor, now, lookup) {
                        Action::Send(packet) => self.local_batch.push(packet),
                        Action::Fragments(fragments) => self.local_batch.extend(fragments),
                        Action::Reply(peer, packet) => self.core.inject_inbound(peer, packet),
                        Action::Drop(reason) => self.dropped(None, reason),
                    }
                }
            }
            next = match &mut self.local {
                Some(local) if taken < room => local.try_recv(),
                _ => None,
            };
        }
        if let Some(local) = &mut self.local {
            local.release();
        }
        if self
            .path_mtus
            .table
            .as_ref()
            .is_some_and(|table| table.changed())
        {
            self.publish_peer_mtus();
        }
        let batch = &mut self.local_batch;
        if self.workers.is_some() {
            self.core
                .handle_locals_deferred(batch.drain(..), now, &mut self.jobs);
            self.dispatch_jobs(false);
        } else {
            self.core.handle_locals(batch.drain(..), now);
        }
        // Routing and the outbound filters ran in the call above, also for deferred jobs.
        self.barriers.done += taken as u64;
        if !self.barriers.waiting.is_empty() {
            self.pass_barriers();
        }
    }

    /// Replies to the local barrier at `position` at once if the owner reached it, or once
    /// it does.
    pub(super) fn local_barrier(&mut self, position: u64, reply: oneshot::Sender<()>) {
        self.barriers.waiting.push((position, reply));
        self.pass_barriers();
    }

    /// Replies to the local barriers whose position the owner reached, or to every one once
    /// no local packet comes any more.
    #[cold]
    pub(super) fn pass_barriers(&mut self) {
        let done = if self.local.is_some() {
            self.barriers.done
        } else {
            u64::MAX
        };
        let (passed, waiting) = std::mem::take(&mut self.barriers.waiting)
            .into_iter()
            .partition(|(position, _)| *position <= done);
        self.barriers.waiting = waiting;
        for (_, reply) in passed {
            let _ = reply.send(());
        }
    }

    /// Runs `first` and the plaintext packets queued behind it, their receipt markers
    /// cleared, through the core's checks of decrypted data: at most [`MAX_BATCH`] and, since each may deliver a packet, no more
    /// than the deliver queue has room for beyond the received datagrams with the crypto
    /// workers (but always `first`, read only once there is room).
    pub(super) fn input_plaintext(&mut self, first: Plaintext) {
        let room = MAX_BATCH.min(self.deliver_room());
        let (peer, from, mut packet) = first;
        packet.set_tracked(false);
        self.core.receive_plaintext(peer, from, packet);
        let mut taken = 1;
        while taken < room
            && let Some(plaintext) = &mut self.plaintext
            && let Ok((peer, from, mut packet)) = plaintext.packets.try_recv()
        {
            packet.set_tracked(false);
            self.core.receive_plaintext(peer, from, packet);
            taken += 1;
        }
    }

    /// The most items to take from a packet queue at once: [`MAX_BATCH`], and no more than
    /// the crypto workers have room for, each item leading to at most one job.
    fn batch_room(&self) -> usize {
        self.workers.as_ref().map_or(MAX_BATCH, |workers| {
            MAX_BATCH.min(workers.bound.saturating_sub(workers.in_flight()))
        })
    }

    /// The local packets to take before every installed transport's transmit queue is full
    /// and its waiting datagrams are at the local threshold ([`MAX_BATCH`], at most the queue
    /// capacity), counting one datagram per packet: the most room over the transports, since
    /// which transport a packet leads to is only known once the core has handled it, less
    /// the local packets with the crypto workers, whose datagrams are still to come.
    /// Unbounded without transports.
    pub(super) fn local_room(&self) -> usize {
        let threshold = self.queue_capacity.min(MAX_BATCH);
        let seals = self
            .workers
            .as_ref()
            .map_or(0, |workers| workers.in_flight() - workers.opens);
        self.transports
            .values()
            .map(|slot| {
                // Waiting datagrams take the queue's free slots first.
                let free = if slot.pending.is_empty() {
                    slot.queue.permits.available_permits()
                } else {
                    0
                };
                free + threshold.saturating_sub(slot.pending.len())
            })
            .max()
            .map_or(usize::MAX, |room| room.saturating_sub(seals))
    }

    /// Adds every job of the current batch to its worker's batch, handing the batches over
    /// whenever one is full; `open` if they open received datagrams.
    fn dispatch_jobs(&mut self, open: bool) {
        let Some(workers) = &mut self.workers else {
            return;
        };
        for job in self.jobs.drain(..) {
            if workers.dispatch(job, open) {
                workers.flush(&mut self.core);
            }
        }
    }

    /// Hands every batch of jobs to its worker.
    pub(super) fn flush_jobs(&mut self) {
        if let Some(workers) = &mut self.workers {
            workers.flush(&mut self.core);
        }
    }

    /// Completes a batch the workers handed back.
    pub(super) fn complete_jobs(&mut self, batch: JobBatch) {
        let Some(workers) = &mut self.workers else {
            return;
        };
        self.high_water
            .crypto_done
            .record_received(workers.done.len());
        workers.complete(batch, &mut self.core);
    }

    /// Waits for every job with the crypto workers and completes it.
    pub(super) async fn settle(&mut self) {
        self.flush_jobs();
        while let Some(workers) = &mut self.workers
            && workers.in_flight() > 0
        {
            match workers.done.recv().await {
                Some(jobs) => self.complete_jobs(jobs),
                None => self.workers = None,
            }
            self.drain(true);
        }
        self.drain(true);
    }
}
