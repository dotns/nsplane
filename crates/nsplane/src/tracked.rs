//! Tracked local packets: the entry that accepts them and the results it reports.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Poll;

use nsplane_core::reasons;
use nsplane_packet::{PacketBuf, PeerId};
use tokio::sync::{Notify, Semaphore, TryAcquireError, mpsc};

/// What became of a tracked packet; see [`SendResult`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendOutcome {
    /// The transport call that carried the packet's datagram succeeded.
    Sent {
        /// The peer the packet was routed to.
        peer: PeerId,
        /// The plaintext bytes handed to sealing, without padding or the data message
        /// header: what [`crate::PeerStats::data_tx`] counts.
        bytes: usize,
    },
    /// The packet was not sent, for this reason: one of the drop reasons
    /// ([`crate::reasons`]), a reason of the filter that dropped it,
    /// [`reasons::FILTER_HANDLED`], [`reasons::PLAINTEXT_EGRESS`] or
    /// [`reasons::ENGINE_STOPPED`].
    NotSent {
        /// Why.
        reason: &'static str,
    },
}

/// The one result the engine reports for a packet [`TrackedSender`] accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendResult {
    /// The packet's tag, its token.
    pub tag: NonZeroU64,
    /// Sent, or not sent and why.
    pub outcome: SendOutcome,
}

/// Why [`TrackedSender`] refused a packet, with the packet (its receipt marker cleared).
#[derive(Debug)]
pub enum TrackedRefused {
    /// The packet carries no tag.
    Untagged(PacketBuf),
    /// A packet with the same tag is outstanding: accepted, without a result yet.
    Duplicate(PacketBuf),
    /// [`TrackedSender::try_send`] only: as many results as the capacity are outstanding
    /// (not yet received from [`SendResults`]).
    Full(PacketBuf),
    /// The engine has stopped, or was never built.
    Stopped(PacketBuf),
}

impl TrackedRefused {
    /// The refused packet.
    pub fn into_packet(self) -> PacketBuf {
        match self {
            Self::Untagged(packet)
            | Self::Duplicate(packet)
            | Self::Full(packet)
            | Self::Stopped(packet) => packet,
        }
    }
}

impl fmt::Display for TrackedRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Untagged(_) => "a tracked packet needs a tag",
            Self::Duplicate(_) => "a packet with this tag is outstanding",
            Self::Full(_) => "the tracked sender is at its capacity",
            Self::Stopped(_) => "the engine has stopped",
        })
    }
}

impl Error for TrackedRefused {}

/// The entry for tracked local packets, from [`crate::EngineBuilder::tracked_sender`]. Cheap
/// to clone; every clone feeds the same engine and counts against the same capacity.
///
/// A packet it accepts is marked ([`PacketBuf::set_tracked`]) and enters the engine's local
/// path like a packet from the [`crate::PacketSource`]: the fragmentation stage, routing, the
/// outbound filters, sealing and the transport. The engine reports exactly one
/// [`SendResult`] for it on [`SendResults`], keyed by its tag (the token): `Sent` once the
/// transport call that carried its datagram succeeded, `NotSent` with the reason at every
/// place it can be dropped. See [`crate::Engine`] ("Tracked packets") for the whole rule.
///
/// Only packets it accepted are tracked: the engine clears the marker of every packet that
/// enters otherwise, and a clone of a tracked packet is untracked. The tag is the token: the
/// outbound filters see it, and what a filter does to the tag or the marker of a tracked
/// packet is undone. While the engine is suspended the accepted packets wait in its queue.
#[derive(Debug, Clone)]
pub struct TrackedSender {
    receipts: Arc<Receipts>,
}

impl TrackedSender {
    /// Accepts `packet`, waiting while as many results as the capacity are outstanding.
    ///
    /// # Errors
    ///
    /// Refuses, with the packet, an untagged packet ([`TrackedRefused::Untagged`]), one
    /// whose tag is outstanding ([`TrackedRefused::Duplicate`]) and every packet once the
    /// engine has stopped ([`TrackedRefused::Stopped`]). A refused packet gets no result.
    pub async fn send(&self, packet: PacketBuf) -> Result<(), TrackedRefused> {
        if packet.tag().is_none() {
            return Err(TrackedRefused::Untagged(untracked(packet)));
        }
        match self.receipts.permits.acquire().await {
            Ok(permit) => permit.forget(),
            Err(_) => return Err(TrackedRefused::Stopped(untracked(packet))),
        }
        self.receipts.accept(packet)
    }

    /// Like [`TrackedSender::send`], but refuses at once with [`TrackedRefused::Full`] when
    /// as many results as the capacity are outstanding.
    ///
    /// # Errors
    ///
    /// As [`TrackedSender::send`], and [`TrackedRefused::Full`].
    pub fn try_send(&self, packet: PacketBuf) -> Result<(), TrackedRefused> {
        if packet.tag().is_none() {
            return Err(TrackedRefused::Untagged(untracked(packet)));
        }
        match self.receipts.permits.try_acquire() {
            Ok(permit) => permit.forget(),
            Err(TryAcquireError::NoPermits) => {
                return Err(TrackedRefused::Full(untracked(packet)));
            }
            Err(TryAcquireError::Closed) => {
                return Err(TrackedRefused::Stopped(untracked(packet)));
            }
        }
        self.receipts.accept(packet)
    }
}

/// The results of the packets a [`TrackedSender`] accepted, one per packet, in the order the
/// engine decided them; from [`crate::EngineBuilder::tracked_sender`].
///
/// A result stays outstanding, and counts against the capacity, until it is received here.
/// When the engine stops, every accepted packet without a result gets
/// `NotSent { reason: ENGINE_STOPPED }`; once those are received, [`SendResults::recv`]
/// returns `None`. Dropping it discards the results, so the capacity no longer limits the
/// sender.
#[derive(Debug)]
pub struct SendResults {
    receipts: Arc<Receipts>,
}

impl SendResults {
    /// The next result; waits for one. `None` once the engine has stopped and every result
    /// was received.
    pub async fn recv(&mut self) -> Option<SendResult> {
        loop {
            if let Poll::Ready(next) = self.receipts.take() {
                return next;
            }
            self.receipts.ready.notified().await;
        }
    }

    /// The next result if one is ready.
    pub fn try_recv(&mut self) -> Option<SendResult> {
        match self.receipts.take() {
            Poll::Ready(result) => result,
            Poll::Pending => None,
        }
    }
}

impl Drop for SendResults {
    fn drop(&mut self) {
        let mut state = self.receipts.lock();
        state.receiver = false;
        let discarded = state.results.len();
        state.results.clear();
        drop(state);
        self.receipts.permits.add_permits(discarded);
    }
}

/// The receipts the engine keeps for tracked packets, shared by the [`TrackedSender`]s, the
/// [`SendResults`], the owner task and the transmit tasks.
#[derive(Debug)]
pub(crate) struct Receipts {
    state: Mutex<State>,
    /// Wakes [`SendResults::recv`].
    ready: Notify,
    /// One permit per result that may still be outstanding.
    permits: Semaphore,
    /// Packets accepted so far, the position of [`crate::EngineHandle::local_barrier`].
    accepted: AtomicU64,
}

#[derive(Debug)]
struct State {
    /// Accepted packets without a result, by tag: their peer and plaintext length once the
    /// core sealed them.
    outstanding: HashMap<NonZeroU64, Option<(PeerId, usize)>>,
    /// Results not received yet.
    results: VecDeque<SendResult>,
    /// The engine stopped, or was never built: nothing more is accepted.
    stopped: bool,
    /// [`SendResults`] exists.
    receiver: bool,
    /// The owner task's queue of accepted packets.
    queue: mpsc::UnboundedSender<PacketBuf>,
}

impl Receipts {
    /// A sender, its results and the owner task's side for `capacity` outstanding results.
    pub(crate) fn channel(capacity: usize) -> (TrackedSender, SendResults, TrackedInput) {
        let (queue, packets) = mpsc::unbounded_channel();
        let receipts = Arc::new(Self {
            state: Mutex::new(State {
                outstanding: HashMap::new(),
                results: VecDeque::new(),
                stopped: false,
                receiver: true,
                queue,
            }),
            ready: Notify::new(),
            permits: Semaphore::new(capacity.clamp(1, Semaphore::MAX_PERMITS)),
            accepted: AtomicU64::new(0),
        });
        (
            TrackedSender {
                receipts: Arc::clone(&receipts),
            },
            SendResults {
                receipts: Arc::clone(&receipts),
            },
            TrackedInput {
                receipts: Stopping(receipts),
                packets,
                first: false,
            },
        )
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks and queues `packet`, which holds a permit; refuses it, returning the permit,
    /// when its tag is outstanding or the engine stopped.
    fn accept(&self, mut packet: PacketBuf) -> Result<(), TrackedRefused> {
        let mut state = self.lock();
        let refused = |packet| {
            self.permits.add_permits(1);
            untracked(packet)
        };
        let Some(tag) = packet.tag() else {
            return Err(TrackedRefused::Untagged(refused(packet)));
        };
        if state.stopped {
            return Err(TrackedRefused::Stopped(refused(packet)));
        }
        let Entry::Vacant(entry) = state.outstanding.entry(tag) else {
            return Err(TrackedRefused::Duplicate(refused(packet)));
        };
        entry.insert(None);
        packet.set_tracked(true);
        if let Err(mpsc::error::SendError(packet)) = state.queue.send(packet) {
            state.outstanding.remove(&tag);
            return Err(TrackedRefused::Stopped(refused(packet)));
        }
        // Counted in queue order, under the lock.
        self.accepted.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// The packets accepted so far.
    pub(crate) fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Acquire)
    }

    /// Records that the core sealed the packet with `tag` for `peer`, `bytes` of plaintext.
    pub(crate) fn sealed(&self, tag: NonZeroU64, peer: Option<PeerId>, bytes: usize) {
        if let Some(peer) = peer
            && let Some(sealed) = self.lock().outstanding.get_mut(&tag)
        {
            *sealed = Some((peer, bytes));
        }
    }

    /// Reports the packet with `tag` as not sent for `reason`.
    pub(crate) fn not_sent(&self, tag: NonZeroU64, reason: &'static str) {
        let mut state = self.lock();
        if state.outstanding.remove(&tag).is_some() {
            self.post(&mut state, tag, SendOutcome::NotSent { reason });
        }
    }

    /// Reports the tracked datagram `data` as sent, or as not sent for `failure`.
    pub(crate) fn finish(&self, data: &PacketBuf, failure: Option<&'static str>) {
        let Some(tag) = data.tag() else {
            return;
        };
        let mut state = self.lock();
        let Some(sealed) = state.outstanding.remove(&tag) else {
            return;
        };
        let outcome = match (failure, sealed) {
            (None, Some((peer, bytes))) => SendOutcome::Sent { peer, bytes },
            (Some(reason), _) => SendOutcome::NotSent { reason },
            // The core reports every tracked datagram sealed before it transmits it.
            (None, None) => SendOutcome::NotSent {
                reason: reasons::ENCAPSULATE_ERROR,
            },
        };
        self.post(&mut state, tag, outcome);
    }

    /// Reports every outstanding packet as not sent because the engine stopped, and accepts
    /// nothing more.
    pub(crate) fn stop(&self) {
        let mut state = self.lock();
        state.stopped = true;
        let tags: Vec<_> = state.outstanding.drain().map(|(tag, _)| tag).collect();
        for tag in tags {
            let reason = reasons::ENGINE_STOPPED;
            self.post(&mut state, tag, SendOutcome::NotSent { reason });
        }
        drop(state);
        self.permits.close();
        self.ready.notify_one();
    }

    /// Queues a result for [`SendResults`], or discards it and returns its permit when
    /// there is no receiver.
    fn post(&self, state: &mut State, tag: NonZeroU64, outcome: SendOutcome) {
        if state.receiver {
            state.results.push_back(SendResult { tag, outcome });
            self.ready.notify_one();
        } else {
            self.permits.add_permits(1);
        }
    }

    /// The next result, `Ready(None)` once there are none and the engine stopped, `Pending`
    /// while one may still come.
    fn take(&self) -> Poll<Option<SendResult>> {
        let mut state = self.lock();
        match state.results.pop_front() {
            Some(result) => {
                drop(state);
                self.permits.add_permits(1);
                Poll::Ready(Some(result))
            }
            None if state.stopped => Poll::Ready(None),
            None => Poll::Pending,
        }
    }
}

/// Stops the receipts when dropped: the engine (or the builder that never built it) is gone.
#[derive(Debug)]
pub(crate) struct Stopping(pub(crate) Arc<Receipts>);

impl Drop for Stopping {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// The owner task's side of the tracked packets: their queue and the receipts.
#[derive(Debug)]
pub(crate) struct TrackedInput {
    pub(crate) receipts: Stopping,
    pub(crate) packets: mpsc::UnboundedReceiver<PacketBuf>,
    /// Alternates which of tracked and other local packets is polled first.
    pub(crate) first: bool,
}

/// `packet` with its receipt marker cleared.
const fn untracked(mut packet: PacketBuf) -> PacketBuf {
    packet.set_tracked(false);
    packet
}
