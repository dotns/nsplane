//! The crypto worker pool.

use std::collections::VecDeque;
use std::panic::{self, AssertUnwindSafe};

use nsplane_core::{Core, CryptoJob};
use nsplane_packet::MAX_BATCH;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

#[cfg(doc)]
use super::Owner;
use super::Task;

/// The crypto worker tasks and their queues.
///
/// Jobs go to the workers in turn, whatever their peer, so even a single peer's packets are
/// encrypted on every worker. Jobs go to the workers in batches: each worker's batch is
/// handed over once it is full, or with every other batch once one is full or the owner has
/// nothing else to do, so a busy owner wakes each worker once per batch rather than once per
/// packet. The workers hand jobs back in any order; they are completed in the order they
/// were handed out, so each peer's packets keep their order.
pub(super) struct Workers {
    /// One job queue per worker.
    queues: Vec<mpsc::Sender<JobBatch>>,
    /// The jobs of each worker not handed over yet, oldest first.
    batches: Vec<JobBatch>,
    /// Batches the workers ran, in the order each worker ran them.
    pub(super) done: mpsc::Receiver<JobBatch>,
    /// The worker the next job goes to.
    next: usize,
    /// Jobs batched or with the workers and not completed yet, in the order they were
    /// handed out; at most `bound`. A job is here once its worker handed it back.
    order: VecDeque<Pending>,
    /// The sequence number of the front of `order`.
    first: u64,
    /// The jobs of `order` that open received datagrams, each of which may deliver a packet.
    pub(super) opens: usize,
    /// The most jobs in flight since [`Owner::queue_stats`] last took it.
    pub(super) peak: usize,
    pub(super) bound: usize,
    pub(super) tasks: Vec<Task>,
}

/// A job handed out and not completed yet.
pub(super) struct Pending {
    /// Whether it opens a received datagram.
    open: bool,
    /// The job, once a worker ran it.
    job: Option<CryptoJob>,
}

/// A batch of jobs for one worker, each with its sequence number.
pub(super) type JobBatch = Vec<(u64, CryptoJob)>;

impl Workers {
    /// Spawns `n` workers, with at most `bound` jobs in flight.
    pub(super) fn spawn(n: usize, bound: usize) -> Self {
        // Every queue holds a batch of each job in flight, so handing one over never waits.
        let (done_tx, done) = mpsc::channel(bound);
        let (queues, tasks) = (0..n)
            .map(|_| {
                let (queue, jobs) = mpsc::channel(bound);
                (queue, Task::spawn(crypto_worker(jobs, done_tx.clone())))
            })
            .unzip();
        Self {
            queues,
            batches: (0..n).map(|_| JobBatch::new()).collect(),
            done,
            next: 0,
            order: VecDeque::with_capacity(bound),
            first: 0,
            opens: 0,
            peak: 0,
            bound,
            tasks,
        }
    }

    /// Jobs batched or with the workers and not completed yet.
    pub(super) fn in_flight(&self) -> usize {
        self.order.len()
    }

    /// Adds `job` to the next worker's batch, `open` if it opens a received datagram; `true`
    /// once that batch is full.
    pub(super) fn dispatch(&mut self, job: CryptoJob, open: bool) -> bool {
        let seq = self.first + self.order.len() as u64;
        self.order.push_back(Pending { open, job: None });
        self.opens += usize::from(open);
        self.peak = self.peak.max(self.order.len());
        let batch = &mut self.batches[self.next];
        self.next = (self.next + 1) % self.queues.len();
        batch.push((seq, job));
        batch.len() >= MAX_BATCH
    }

    /// Takes back the jobs of `batch` and completes on `core` every job whose predecessors
    /// are all completed, in the order they were handed out.
    pub(super) fn complete(&mut self, batch: JobBatch, core: &mut Core) {
        for (seq, job) in batch {
            // Every job handed back is in `order`: it is only completed from there.
            if let Some(pending) = seq
                .checked_sub(self.first)
                .and_then(|at| usize::try_from(at).ok())
                .and_then(|at| self.order.get_mut(at))
            {
                pending.job = Some(job);
            }
        }
        while let Some(job) = self
            .order
            .front_mut()
            .and_then(|pending| pending.job.take())
        {
            if self.order.pop_front().is_some_and(|pending| pending.open) {
                self.opens -= 1;
            }
            self.first += 1;
            core.complete_job(job);
        }
    }

    /// Hands every batch of jobs to its worker; runs the jobs of a worker that is gone on
    /// the owner and completes them on `core`.
    pub(super) fn flush(&mut self, core: &mut Core) {
        for worker in 0..self.queues.len() {
            if self.batches[worker].is_empty() {
                continue;
            }
            // Never full: a queue holds a batch of each job in flight.
            if let Err(TrySendError::Full(mut batch) | TrySendError::Closed(mut batch)) =
                self.queues[worker].try_send(std::mem::take(&mut self.batches[worker]))
            {
                for (_, job) in &mut batch {
                    job.run();
                }
                self.complete(batch, core);
            }
        }
    }

    /// Whether the bound of jobs in flight is reached.
    pub(super) fn full(&self) -> bool {
        self.in_flight() >= self.bound
    }
}

/// Runs the batches of jobs from the owner and hands them back until the owner is gone.
async fn crypto_worker(mut jobs: mpsc::Receiver<JobBatch>, done: mpsc::Sender<JobBatch>) {
    while let Some(mut batch) = jobs.recv().await {
        for (_, job) in &mut batch {
            // A job that panics is handed back all the same, so the jobs behind it in the
            // owner's order are not held up; its packet is dropped.
            let _ = panic::catch_unwind(AssertUnwindSafe(|| job.run()));
        }
        // The queue holds a batch of each job in flight, so this does not wait.
        if done.send(batch).await.is_err() {
            return;
        }
    }
}
