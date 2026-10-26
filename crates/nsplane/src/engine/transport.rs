//! The owner task's side of each transport: its transmit queue, traffic counters and the
//! recycling of transmitted buffers.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use nsplane_packet::{MAX_BATCH, PacketBuf, Path, PeerId, TransportId};
use tokio::sync::mpsc::OwnedPermit;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, TryAcquireError, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

#[cfg(doc)]
use super::Owner;
use super::Task;
use super::output::Backoff;
use super::queue::{BatchQueue, BatchSender, Handoff, batch_queue};
use super::tasks::{receive, transmit};
use crate::events::{DROP_TRANSMIT_FULL, DROP_TRANSPORT_CLOSED};
use crate::handle::TransportStats;
#[cfg(doc)]
use crate::io::{PacketSink, PacketSource};
use crate::transport::{PathMtuReport, Transport};

/// What a stopped transmit task hands back: its queue and the datagrams of the batch it was
/// sending that were not sent, oldest first.
pub(super) type Unsent = (BatchQueue<Datagram>, Vec<Datagram>);

/// A transport's transmit task, stopped through a signal so that it hands back the datagrams
/// it did not send; aborted when dropped.
pub(super) struct Transmitter {
    /// `None` once the stop was signalled.
    stop: Option<oneshot::Sender<()>>,
    /// Resolves to `None` when the task ended on its own (the transport or the engine is
    /// gone), having dropped its queue.
    task: JoinHandle<Option<Unsent>>,
}

impl Transmitter {
    /// Stops the task and returns the datagrams it did not send, oldest first.
    pub(super) async fn stop(mut self) -> VecDeque<Datagram> {
        if let Some(stop) = self.stop.take() {
            // The task may have ended already.
            let _ = stop.send(());
        }
        let mut unsent = VecDeque::new();
        // Nothing comes back from a task that ended on its own or failed.
        if let Ok(Some((mut queue, sending))) = (&mut self.task).await {
            unsent.extend(sending);
            while let Some(datagram) = queue.try_recv() {
                unsent.push_back(datagram);
            }
        }
        unsent
    }
}

impl Drop for Transmitter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A datagram and the path to send it on.
pub(super) type Datagram = (Path, PacketBuf);
/// Waits for room in the transmit queue.
type Reserve = Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>;
/// Waits for room in the deliver queue.
pub(super) type DeliverRoom =
    Pin<Box<dyn Future<Output = Result<OwnedPermit<(PeerId, PacketBuf)>, SendError<()>>> + Send>>;

/// Hands datagrams to a transport without waiting ([`Transport::try_send_batch`]).
type TrySend = Box<dyn Fn(&[Datagram], &mut usize, &mut usize) -> io::Result<()> + Send>;
/// Hands packets to the sink without waiting ([`PacketSink::try_send_batch`]).
pub(super) type TryDeliver =
    Box<dyn Fn(&mut VecDeque<(PeerId, PacketBuf)>) -> io::Result<()> + Send>;

/// Spawns a transport's receive and transmit tasks, given the queue receiving its datagrams,
/// its transmit queue, where transmitted buffers go back, the transport's traffic counters
/// (which report failed sends) and the suspension state; also returns how to send on it
/// without waiting and its path MTU reports, if it has any.
pub(super) type Start = Box<
    dyn FnOnce(
            BatchSender<Datagram>,
            BatchQueue<Datagram>,
            Recycle,
            Arc<Traffic>,
            watch::Receiver<bool>,
        ) -> (
            Task,
            Transmitter,
            TrySend,
            Option<mpsc::Receiver<PathMtuReport>>,
        ) + Send,
>;

/// A transport on its way to the owner task, erased to its id and the spawning of its tasks,
/// which stay generic over its type.
pub(crate) struct NewTransport {
    pub(crate) id: TransportId,
    pub(super) start: Start,
}

impl NewTransport {
    pub(crate) fn new<T: Transport>(transport: T) -> Self {
        Self {
            id: transport.id(),
            start: Box::new(move |datagrams, queue, recycle, traffic, suspended| {
                let reports = transport.path_mtu_reports();
                let transport = Arc::new(transport);
                let (stop, stopped) = oneshot::channel();
                let sender = Arc::clone(&transport);
                (
                    Task::spawn(receive(
                        Arc::clone(&transport),
                        datagrams,
                        Arc::clone(&traffic),
                        suspended.clone(),
                    )),
                    Transmitter {
                        stop: Some(stop),
                        task: tokio::spawn(transmit(
                            transport, queue, recycle, traffic, suspended, stopped,
                        )),
                    },
                    Box::new(move |datagrams, sent, failed| {
                        sender.try_send_batch(datagrams, sent, failed)
                    }),
                    reports,
                )
            }),
        }
    }
}

/// Where transmitted buffers go back for reuse: to the source task while the source takes
/// them ([`PacketSource::recycle`]), otherwise to the owner task, which puts them into the
/// core's pool. Both queues are bounded in buffers and lossy: a buffer that finds no room is
/// dropped (or, from the owner task, put into the core's pool), so returning never waits.
#[derive(Clone)]
pub(super) struct Recycle {
    source: BatchSender<PacketBuf>,
    owner: BatchSender<PacketBuf>,
    /// Set by the source task once the source took none of the first buffers it was given
    /// (it keeps the default [`PacketSource::recycle`]).
    pub(super) declined: Arc<AtomicBool>,
}

impl Recycle {
    /// The queues, each holding `capacity` buffers, and their receiving sides: the source
    /// task's and the owner task's.
    pub(super) fn new(capacity: usize) -> (Self, BatchQueue<PacketBuf>, BatchQueue<PacketBuf>) {
        let (source, to_source) = batch_queue(capacity, MAX_BATCH);
        let (owner, to_owner) = batch_queue(capacity, MAX_BATCH);
        let recycle = Self {
            source,
            owner,
            declined: Arc::default(),
        };
        (recycle, to_source, to_owner)
    }

    /// Whether buffers go to the source.
    pub(super) fn to_source(&self) -> bool {
        !self.declined.load(Ordering::Relaxed)
    }

    /// Hands back as many buffers from `bufs` as there is room for, without waiting; the
    /// rest stay in `bufs`.
    pub(super) fn give(&self, bufs: &mut Vec<PacketBuf>) {
        if self.to_source() {
            self.source.try_send(bufs);
        } else {
            self.owner.try_send(bufs);
        }
    }
}

/// Where transmit tasks report failed sends: a count the owner task takes, and a signal
/// that wakes it.
#[derive(Clone)]
pub(super) struct SendErrors {
    pub(super) count: Arc<AtomicUsize>,
    /// The owner keeps a sender, so the signal never closes; a full signal is already
    /// pending.
    pub(super) signal: mpsc::Sender<()>,
}

impl SendErrors {
    /// Reports `failed` datagrams.
    fn report(&self, failed: usize) {
        // The signal orders the count before the owner's take.
        self.count.fetch_add(failed, Ordering::Relaxed);
        let _ = self.signal.try_send(());
    }

    /// The failed sends since the last take.
    pub(super) fn take(&self) -> usize {
        self.count.swap(0, Ordering::Relaxed)
    }
}

/// The traffic counters of a transport, updated once per batch by its tasks or the owner
/// task, and where its failed sends are reported.
pub(super) struct Traffic {
    pub(super) rx_datagrams: AtomicU64,
    pub(super) rx_bytes: AtomicU64,
    tx_datagrams: AtomicU64,
    tx_bytes: AtomicU64,
    tx_failed: AtomicU64,
    /// Datagrams in the transmit queue or in the batch the transmit task is sending: raised
    /// by the owner per message it hands over, lowered by the transmit task once it is done
    /// with its batch.
    pub(super) outstanding: AtomicUsize,
    errors: SendErrors,
}

impl Traffic {
    pub(super) const fn new(errors: SendErrors) -> Self {
        Self {
            rx_datagrams: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_datagrams: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_failed: AtomicU64::new(0),
            outstanding: AtomicUsize::new(0),
            errors,
        }
    }

    /// Counts `failed` datagrams and reports them to the owner.
    pub(super) fn failed(&self, failed: usize) {
        self.tx_failed.fetch_add(failed as u64, Ordering::Relaxed);
        self.errors.report(failed);
    }

    /// Counts the datagrams of `done` as sent (handed off or failed).
    pub(super) fn sent(&self, done: &[Datagram]) {
        if done.is_empty() {
            return;
        }
        let bytes = done.iter().map(|(_, data)| data.len() as u64).sum();
        self.tx_datagrams
            .fetch_add(done.len() as u64, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(super) fn stats(&self, id: TransportId) -> TransportStats {
        TransportStats {
            id,
            rx_datagrams: self.rx_datagrams.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_datagrams: self.tx_datagrams.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_failed: self.tx_failed.load(Ordering::Relaxed),
        }
    }
}

/// An installed transport: its transmit queue, the datagrams waiting for room in it, its
/// two tasks and its traffic counters.
pub(super) struct TransportSlot {
    /// Bounded in datagrams; the owner task hands over what one drain queued as one message.
    pub(super) queue: BatchSender<Datagram>,
    /// Datagrams of the current drain that hold a slot of the transmit queue, oldest first,
    /// handed over at the end of the drain ([`TransportSlot::hand_over`]) or once
    /// [`MAX_BATCH`] are staged.
    pub(super) staged: Vec<Datagram>,
    /// Datagrams waiting for room in the transmit queue, oldest first.
    pub(super) pending: VecDeque<Datagram>,
    /// Armed while `pending` is not empty.
    pub(super) flush: Option<Reserve>,
    pub(super) receive: Task,
    pub(super) transmit: Transmitter,
    /// Forwards the transport's path MTU reports, if it has any.
    pub(super) reports: Option<Task>,
    pub(super) traffic: Arc<Traffic>,
    pub(super) try_send: TrySend,
    /// Datagrams the owner task sends itself at the end of the current drain, oldest
    /// first ([`Owner::send_inline`]).
    pub(super) inline: Vec<Datagram>,
    /// The transport reported [`io::ErrorKind::BrokenPipe`] to the owner task.
    pub(super) closed: bool,
    pub(super) backoff: Backoff,
}

impl TransportSlot {
    /// Stages `datagram` in a free slot of the queue, or adds it to the waiting datagrams
    /// when the queue is full or others are waiting. With `droppable`, a datagram that finds
    /// `bound` datagrams waiting is rejected; a closed queue rejects every datagram. Returns
    /// the rejected buffer and the reason.
    pub(super) fn transmit(
        &mut self,
        datagram: Datagram,
        droppable: bool,
        bound: usize,
    ) -> Result<(), (PacketBuf, &'static str)> {
        if self.closed {
            return Err((datagram.1, DROP_TRANSPORT_CLOSED));
        }
        if self.pending.is_empty() {
            match self.queue.permits.try_acquire() {
                Ok(slot) => {
                    slot.forget();
                    self.staged.push(datagram);
                    return Ok(());
                }
                Err(TryAcquireError::Closed) => return Err((datagram.1, DROP_TRANSPORT_CLOSED)),
                Err(TryAcquireError::NoPermits) => {}
            }
        }
        if droppable && self.pending.len() >= bound {
            return Err((datagram.1, DROP_TRANSMIT_FULL));
        }
        self.pending.push_back(datagram);
        Ok(())
    }

    /// Whether nothing of the transport is waiting, queued or being sent, so the owner task
    /// may send on it itself without passing any of it.
    pub(super) fn idle(&self) -> bool {
        self.pending.is_empty()
            && self.staged.is_empty()
            && !self.closed
            && !self.queue.is_closed()
            && self.traffic.outstanding.load(Ordering::Acquire) == 0
    }

    /// Sends `batch` on the transport without waiting, counting the datagrams it is done
    /// with and the failed ones as the transmit task does; returns how many it is done
    /// with. [`io::ErrorKind::BrokenPipe`] marks the transport closed.
    pub(super) fn send_now(&mut self, batch: &[Datagram]) -> usize {
        let mut sent = 0;
        while sent < batch.len() {
            let before = sent;
            let mut failed = 0;
            let Err(e) = (self.try_send)(batch, &mut sent, &mut failed) else {
                sent = batch.len();
                break;
            };
            if e.kind() == io::ErrorKind::WouldBlock {
                sent = sent.clamp(before, batch.len());
                if failed > 0 {
                    self.traffic.failed(failed.min(sent - before));
                }
                break;
            }
            // As in the transmit task: the failed datagram is dropped, and at least one and
            // at most the datagrams the call was done with count as failed.
            sent = sent.max(before + 1).min(batch.len());
            self.traffic.failed(failed.clamp(1, sent - before));
            if e.kind() == io::ErrorKind::BrokenPipe {
                tracing::debug!("Transport closed for sending");
                self.closed = true;
                break;
            }
            tracing::debug!(message = "Transport send error", error = ?e);
        }
        self.traffic.sent(&batch[..sent]);
        sent
    }

    /// Stops both tasks and returns every datagram still queued for the transport, oldest
    /// first: the one being sent, the transmit queue's, then the waiting ones.
    pub(super) async fn stop(mut self) -> VecDeque<Datagram> {
        self.flush = None;
        if let Some(reports) = self.reports.take() {
            reports.stop().await;
        }
        self.receive.stop().await;
        let mut unsent = self.transmit.stop().await;
        unsent.extend(self.staged.drain(..));
        unsent.append(&mut self.pending);
        unsent.extend(self.inline.drain(..));
        unsent
    }

    /// Datagrams in the transmit queue, counting the staged ones and the batch the transmit
    /// task is sending.
    pub(super) fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Hands the staged datagrams to the transmit task as one message; returns them if the
    /// queue is gone.
    pub(super) fn hand_over(&mut self) -> Option<Vec<Datagram>> {
        let n = self.staged.len();
        let handoff = match n {
            0 => return None,
            1 => Handoff::One(self.staged.pop()?),
            _ => {
                // Exactly sized; the staging buffer keeps its capacity.
                let mut datagrams = Vec::with_capacity(n);
                datagrams.append(&mut self.staged);
                Handoff::Many(datagrams)
            }
        };
        self.traffic.outstanding.fetch_add(n, Ordering::Relaxed);
        let Err(SendError(handoff)) = self.queue.batches.send(handoff) else {
            return None;
        };
        self.traffic.outstanding.fetch_sub(n, Ordering::Relaxed);
        Some(match handoff {
            Handoff::One(datagram) => vec![datagram],
            Handoff::Many(datagrams) => datagrams,
        })
    }
}
