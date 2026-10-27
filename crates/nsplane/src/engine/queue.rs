//! The bounded batch queues between the I/O tasks and the owner task.

use std::collections::VecDeque;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::sync::{Semaphore, mpsc};

/// A queue bounded in items whose senders hand over batches: one message and one semaphore
/// operation per batch rather than per item.
pub(super) fn batch_queue<T>(capacity: usize, handoff: usize) -> (BatchSender<T>, BatchQueue<T>) {
    let (batches, rx) = mpsc::unbounded_channel();
    let permits = Arc::new(Semaphore::new(capacity));
    (
        BatchSender {
            batches,
            permits: Arc::clone(&permits),
            most: handoff.clamp(1, capacity),
            capacity,
        },
        BatchQueue {
            batches: rx,
            held: VecDeque::new(),
            permits,
            capacity,
            taken: 0,
        },
    )
}

/// One message of a [`batch_queue`]: a lone item travels without an allocation.
pub(super) enum Handoff<T> {
    One(T),
    Many(Vec<T>),
}

/// The sending side of a [`batch_queue`]; a permit of its semaphore stands for a free item
/// slot.
pub(super) struct BatchSender<T> {
    pub(super) batches: mpsc::UnboundedSender<Handoff<T>>,
    pub(super) permits: Arc<Semaphore>,
    /// The most items one message carries, at most the capacity.
    most: usize,
    capacity: usize,
}

impl<T> Clone for BatchSender<T> {
    fn clone(&self) -> Self {
        Self {
            batches: self.batches.clone(),
            permits: Arc::clone(&self.permits),
            most: self.most,
            capacity: self.capacity,
        }
    }
}

impl<T> BatchSender<T> {
    /// Hands over every item of `items`, in order, waiting for room: in messages of up to
    /// `most` items, each as large as the free slots allow (at least one). Fails once the
    /// queue is gone.
    pub(super) async fn send(&self, items: &mut VecDeque<T>) -> Result<(), ()> {
        while !items.is_empty() {
            let n = items
                .len()
                .min(self.most)
                .min(self.permits.available_permits().max(1));
            // `n` is at most `most`, which is at most the capacity.
            let permits = u32::try_from(n).map_err(drop)?;
            self.permits
                .acquire_many(permits)
                .await
                .map_err(drop)?
                .forget();
            let handoff = match items.pop_front() {
                Some(item) if n == 1 => Handoff::One(item),
                Some(item) => {
                    let mut batch = Vec::with_capacity(n);
                    batch.push(item);
                    batch.extend(items.drain(..n - 1));
                    Handoff::Many(batch)
                }
                None => return Ok(()),
            };
            self.batches.send(handoff).map_err(drop)?;
        }
        Ok(())
    }

    /// Hands over as many items from the front of `items` as there are free slots, as one
    /// message, without waiting; the rest stay in `items`. Items handed to a queue that is
    /// gone are dropped.
    pub(super) fn try_send(&self, items: &mut Vec<T>) {
        let n = items.len().min(self.permits.available_permits());
        // Another sender may take the free slots first.
        let Some(permits) = u32::try_from(n)
            .ok()
            .filter(|&n| n > 0)
            .and_then(|n| self.permits.try_acquire_many(n).ok())
        else {
            return;
        };
        permits.forget();
        let handoff = if n == 1 {
            Handoff::One(items.remove(0))
        } else if n == items.len() {
            Handoff::Many(std::mem::take(items))
        } else {
            Handoff::Many(items.drain(..n).collect())
        };
        // The queue is gone: so are the items.
        let _ = self.batches.send(handoff);
    }

    /// Items in the queue, counting those taken whose slots are not freed yet.
    pub(super) fn len(&self) -> usize {
        self.capacity - self.permits.available_permits()
    }

    /// Whether the receiving side is gone.
    pub(super) fn is_closed(&self) -> bool {
        self.permits.is_closed()
    }
}

/// The receiving side of a [`batch_queue`], in the owner task. Items of a batch it has not
/// taken yet stay held here, in order, and keep their slots.
pub(super) struct BatchQueue<T> {
    batches: mpsc::UnboundedReceiver<Handoff<T>>,
    /// Received items not taken yet, oldest first.
    held: VecDeque<T>,
    permits: Arc<Semaphore>,
    capacity: usize,
    /// Items taken whose slots are not freed yet ([`BatchQueue::release`]).
    taken: usize,
}

impl<T> BatchQueue<T> {
    /// The next item; `None` once every sender is gone and every item was taken.
    pub(super) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        if self.held.is_empty() {
            return match self.batches.poll_recv(cx) {
                Poll::Ready(Some(handoff)) => Poll::Ready(self.unpack(handoff)),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            };
        }
        Poll::Ready(self.take())
    }

    /// The next item if one is queued.
    pub(super) fn try_recv(&mut self) -> Option<T> {
        if self.held.is_empty() {
            let handoff = self.batches.try_recv().ok()?;
            return self.unpack(handoff);
        }
        self.take()
    }

    /// Takes the first item of a message received with nothing held, holding the rest.
    fn unpack(&mut self, handoff: Handoff<T>) -> Option<T> {
        match handoff {
            Handoff::One(item) => {
                self.taken += 1;
                Some(item)
            }
            Handoff::Many(batch) => {
                self.held.extend(batch);
                self.take()
            }
        }
    }

    pub(super) fn take(&mut self) -> Option<T> {
        let item = self.held.pop_front()?;
        self.taken += 1;
        Some(item)
    }

    /// Takes every item held or queued and appends it to `out`, in order.
    pub(super) fn take_all(&mut self, out: &mut Vec<T>) {
        let before = out.len();
        out.extend(self.held.drain(..));
        while let Ok(handoff) = self.batches.try_recv() {
            match handoff {
                Handoff::One(item) => out.push(item),
                // A whole message moves without copying when it comes first.
                Handoff::Many(batch) if out.is_empty() => *out = batch,
                Handoff::Many(mut batch) => out.append(&mut batch),
            }
        }
        self.taken += out.len() - before;
    }

    /// Refuses every later message and frees no slot again, so the senders see the queue
    /// gone; what is held or queued stays to be taken.
    pub(super) fn close(&mut self) {
        self.batches.close();
        self.permits.close();
    }

    /// Whether no item is held or queued.
    pub(super) fn is_empty(&self) -> bool {
        self.held.is_empty() && self.batches.is_empty()
    }

    /// Frees the slots of the items taken, at once.
    pub(super) fn release(&mut self) {
        if self.taken > 0 {
            self.permits.add_permits(std::mem::take(&mut self.taken));
        }
    }

    /// Items in the queue, not counting those taken.
    pub(super) fn len(&self) -> usize {
        self.capacity - self.permits.available_permits() - self.taken
    }
}

impl<T> Drop for BatchQueue<T> {
    fn drop(&mut self) {
        // Wakes the senders waiting for room.
        self.permits.close();
    }
}
