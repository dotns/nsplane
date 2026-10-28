//! The I/O tasks around the owner task: source, sink, MTU watcher and, per transport,
//! receive and transmit.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;

use nsplane_packet::{MAX_BATCH, PacketBatch, PacketBuf, PeerId};
use tokio::sync::{mpsc, oneshot, watch};

use super::MAX_DATAGRAM;
use super::queue::{BatchQueue, BatchSender};
use super::transport::{Datagram, Recycle, Traffic, Unsent};
use crate::events::{DROP_TRANSPORT_CLOSED, DROP_TRANSPORT_SEND_ERROR};
use crate::io::{PacketSink, PacketSource};
use crate::transport::{PathMtuReport, Transport};

/// Waits while the engine is suspended; `false` once the engine is gone.
pub(super) async fn running(suspended: &mut watch::Receiver<bool>) -> bool {
    suspended.wait_for(|suspended| !suspended).await.is_ok()
}

/// Forwards every change of the source's MTU watch to the owner until the sender is dropped.
/// Changes while suspended collapse into the latest value, forwarded after resuming.
pub(super) async fn watch_mtu(
    mut mtu: watch::Receiver<u16>,
    changes: mpsc::Sender<u16>,
    mut suspended: watch::Receiver<bool>,
) {
    while mtu.changed().await.is_ok() {
        if !running(&mut suspended).await {
            return;
        }
        let value = *mtu.borrow_and_update();
        if changes.send(value).await.is_err() {
            return;
        }
    }
}

/// Forwards a transport's path MTU reports to the owner until either side is gone. Reports
/// that arrive while suspended wait until the engine resumes.
pub(super) async fn forward_path_mtu(
    mut reports: mpsc::Receiver<PathMtuReport>,
    owner: mpsc::Sender<PathMtuReport>,
    mut suspended: watch::Receiver<bool>,
) {
    while let Some(report) = reports.recv().await {
        if !running(&mut suspended).await || owner.send(report).await.is_err() {
            return;
        }
    }
}

/// How many local packets the source task took from the source, shared with the handles.
///
/// The word holds twice the count, plus one while the task is inside a read of the source:
/// what a read takes is counted when the read returns, in the same poll, so a reader that
/// finds a read in progress waits until it ended ([`SourceTaken::position`]).
#[derive(Debug, Default)]
pub(crate) struct SourceTaken(AtomicU64);

impl SourceTaken {
    /// The packets taken so far, including every packet a read in progress has taken.
    pub(crate) async fn position(&self) -> u64 {
        loop {
            let word = self.0.load(Ordering::Acquire);
            if word & 1 == 0 {
                return word >> 1;
            }
            // A read in progress ends within the poll that runs it.
            tokio::task::yield_now().await;
        }
    }
}

/// The source task's side of [`SourceTaken`], its only writer; ends a read in progress when
/// dropped.
struct Reading {
    shared: Arc<SourceTaken>,
    /// Twice the packets counted.
    word: u64,
}

impl Reading {
    /// Marks a read in progress.
    fn enter(&self) {
        self.shared.0.store(self.word | 1, Ordering::Release);
    }

    /// Ends the read in progress, counting the `read` packets it took.
    fn leave(&mut self, read: usize) {
        self.word += 2 * read as u64;
        self.shared.0.store(self.word, Ordering::Release);
    }
}

impl Drop for Reading {
    fn drop(&mut self) {
        self.leave(0);
    }
}

/// Reads batches of local packets into the owner's queue until the source closes, clearing
/// their receipt markers.
///
/// Each poll of a read runs inside [`Reading::enter`] and [`Reading::leave`], so the packets
/// a read takes are counted before a barrier can read the count. Before each read, hands the transmitted buffers queued in `recycled` to the source
/// ([`PacketSource::recycle`]), untagged and unmarked, and drops what it leaves. Sets
/// `declined` when the source takes none of the first buffers, so that later ones go to the
/// core's pool instead.
pub(super) async fn read_source<Src: PacketSource>(
    mut source: Src,
    local: BatchSender<PacketBuf>,
    mut recycled: BatchQueue<PacketBuf>,
    declined: Arc<AtomicBool>,
    taken: Arc<SourceTaken>,
    mut suspended: watch::Receiver<bool>,
) {
    let mut reading = Reading {
        shared: taken,
        word: 0,
    };
    let mut batch = PacketBatch::new();
    let mut packets = VecDeque::with_capacity(MAX_BATCH);
    let mut bufs = Vec::new();
    let mut offered = false;
    while running(&mut suspended).await {
        if !recycled.is_empty() {
            recycled.take_all(&mut bufs);
            recycled.release();
            // The buffers stop being the packets they carried.
            for buf in &mut bufs {
                buf.set_tag(None);
                buf.set_tracked(false);
            }
            let given = bufs.len();
            source.recycle(&mut bufs);
            if !std::mem::replace(&mut offered, true) && bufs.len() == given {
                declined.store(true, Ordering::Relaxed);
            }
            bufs.clear();
        }
        let result = {
            let mut read = pin!(source.recv_batch(&mut batch));
            poll_fn(|cx| {
                reading.enter();
                let poll = read.as_mut().poll(cx);
                if poll.is_pending() {
                    reading.leave(0);
                }
                poll
            })
            .await
        };
        reading.leave(batch.len());
        packets.extend(batch.drain().map(|mut packet| {
            packet.set_tracked(false);
            packet
        }));
        if local.send(&mut packets).await.is_err() {
            return;
        }
        match result {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                tracing::debug!("Packet source closed");
                return;
            }
            Err(e) => tracing::warn!(message = "Packet source error", error = ?e),
        }
    }
}

/// Delivers decrypted packets to the sink in batches of what is queued, until it closes.
pub(super) async fn write_sink<Snk: PacketSink>(
    sink: Arc<Snk>,
    mut deliver: mpsc::Receiver<(PeerId, PacketBuf)>,
    outstanding: Arc<AtomicUsize>,
    mut suspended: watch::Receiver<bool>,
) {
    let mut packets = VecDeque::with_capacity(MAX_BATCH);
    while let Some(first) = deliver.recv().await {
        packets.push_back(first);
        while packets.len() < MAX_BATCH {
            let Ok(next) = deliver.try_recv() else { break };
            packets.push_back(next);
        }
        let taken = packets.len();
        if !running(&mut suspended).await {
            return;
        }
        while !packets.is_empty() {
            match sink.send_batch(&mut packets).await {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    tracing::debug!("Packet sink closed");
                    return;
                }
                Err(e) => tracing::warn!(message = "Packet sink error", error = ?e),
            }
        }
        // Done with the batch: the owner may deliver itself once nothing else is queued.
        outstanding.fetch_sub(taken, Ordering::Release);
    }
}

/// Receives batches of datagrams into the owner's queue until the transport closes, counting
/// them in `traffic`.
pub(super) async fn receive<T: Transport>(
    transport: Arc<T>,
    datagrams: BatchSender<Datagram>,
    traffic: Arc<Traffic>,
    mut suspended: watch::Receiver<bool>,
) {
    let mut buf = PacketBuf::with_capacity(MAX_DATAGRAM);
    let mut received = VecDeque::with_capacity(MAX_BATCH);
    while running(&mut suspended).await {
        let result = transport.recv_batch(&mut buf, &mut received).await;
        if !received.is_empty() {
            let bytes = received.iter().map(|(_, data)| data.len() as u64).sum();
            traffic
                .rx_datagrams
                .fetch_add(received.len() as u64, Ordering::Relaxed);
            traffic.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
        if datagrams.send(&mut received).await.is_err() {
            return;
        }
        match result {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                tracing::debug!("Transport closed for receiving");
                return;
            }
            Err(e) => tracing::debug!(message = "Transport receive error", error = ?e),
        }
    }
}

/// Runs `future` unless `stop` fires first; `None` when stopped.
async fn unless_stopped<F: Future>(
    stop: &mut oneshot::Receiver<()>,
    future: F,
) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    poll_fn(|cx| {
        if Pin::new(&mut *stop).poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        future.as_mut().poll(cx).map(Some)
    })
    .await
}

/// Reports the tracked datagrams of `unsent` and of `queue`, which closes, as not sent: the
/// transport closed.
#[cold]
fn closed_with(queue: &mut BatchQueue<Datagram>, unsent: &[Datagram], traffic: &Traffic) {
    queue.close();
    let mut queued = Vec::new();
    queue.take_all(&mut queued);
    for (_, data) in unsent.iter().chain(&queued) {
        traffic.finish_tracked(data, Some(DROP_TRANSPORT_CLOSED));
    }
}

/// Sends queued datagrams in batches of up to [`MAX_BATCH`] until the transport closes;
/// returns the buffers of each batch for reuse as one message and counts the datagrams it is
/// done with, and every failed one, in `traffic`. Once `stop` fires, hands back its queue and
/// the datagrams of the batch it was sending that were not sent.
///
/// A batch takes what is queued, across the owner's messages, and keeps the slots of its
/// datagrams in the queue until it is done, so the queue and the batch together hold no
/// more than the queue's capacity. A tracked datagram ends its batch, so the call that sends
/// it attributes it exactly: its result is reported once the call is done with it, and when
/// the transport closes, the tracked datagrams it did not get to are reported closed.
pub(super) async fn transmit<T: Transport>(
    transport: Arc<T>,
    mut queue: BatchQueue<Datagram>,
    recycle: Recycle,
    traffic: Arc<Traffic>,
    mut suspended: watch::Receiver<bool>,
    mut stop: oneshot::Receiver<()>,
) -> Option<Unsent> {
    let mut batch = Vec::with_capacity(MAX_BATCH);
    loop {
        let Some(next) = unless_stopped(&mut stop, poll_fn(|cx| queue.poll_recv(cx))).await else {
            return Some((queue, batch));
        };
        batch.push(next?);
        while batch.len() < MAX_BATCH
            && !batch.last().is_some_and(|(_, data)| data.is_tracked())
            && let Some(next) = queue.try_recv()
        {
            batch.push(next);
        }
        let mut sent = 0;
        // Whether the call that was done with the last datagram done failed it.
        let mut last_failed = false;
        let mut closed = false;
        let outcome = unless_stopped(&mut stop, async {
            // `false` once the engine is gone or the transport is closed.
            if !running(&mut suspended).await {
                return false;
            }
            loop {
                let before = sent;
                let mut failed = 0;
                let Err(e) = transport.send_batch(&batch, &mut sent, &mut failed).await else {
                    sent = batch.len();
                    last_failed = false;
                    return true;
                };
                // The failed datagram is dropped, even if the transport did not count it or
                // advance past it. Only the datagrams the call reports failed are counted
                // (a failed segmented send loses its run, not the runs handed off before
                // it), at least one and never more than the call was done with.
                sent = sent.max(before + 1).min(batch.len());
                traffic.failed(failed.clamp(1, sent - before));
                last_failed = true;
                if e.kind() == io::ErrorKind::BrokenPipe {
                    tracing::debug!("Transport closed for sending");
                    closed = true;
                    return false;
                }
                tracing::debug!(message = "Transport send error", error = ?e);
                if sent == batch.len() {
                    return true;
                }
            }
        })
        .await;
        let done = sent.min(batch.len());
        traffic.sent(&batch[..done]);
        if done == batch.len()
            && let Some((_, last)) = batch.last()
        {
            traffic.finish_tracked(last, last_failed.then_some(DROP_TRANSPORT_SEND_ERROR));
        }
        if outcome == Some(false) {
            if closed {
                closed_with(&mut queue, &batch[done..], &traffic);
            }
            return None;
        }
        let mut bufs: Vec<PacketBuf> = batch.drain(..done).map(|(_, data)| data).collect();
        // What finds no room is dropped.
        recycle.give(&mut bufs);
        if outcome.is_none() {
            // Stopped: the datagrams not sent go back with the queue, in order.
            return Some((queue, batch));
        }
        // Done with the batch: its slots are free, and the owner may send itself once
        // nothing else is queued.
        queue.release();
        traffic.outstanding.fetch_sub(done, Ordering::Release);
    }
}
