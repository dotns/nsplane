//! Per-flow control: revoking one connection or flow of a shared stack, and the receipt
//! that tells when the stack holds nothing of it any more.

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use smoltcp::iface::SocketHandle;
use tokio::sync::Notify;

use crate::tcp::{self, Shared};

/// Most fences the egress holds at once; a revoke that needs one more fails.
pub(crate) const MAX_FENCES: usize = 1024;

const PENDING: u8 = 0;
const RETIRED: u8 = 1;
const FAILED: u8 = 2;
const UNKNOWN: u8 = 3;

/// How a revoke ended, see [`RetirementReceipt`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetirementOutcome {
    /// The stack removed the flow's state and dropped its queued output: nothing of the
    /// flow leaves the stack any more.
    Retired,
    /// The stack removed the flow's state, but packets of the flow it could no longer
    /// reach may still leave: a bound on the state the stack keeps for that was reached.
    Failed,
    /// The stack stopped before it finished, or had stopped already.
    Unknown,
}

/// Where the driver finds a flow's state.
#[derive(Debug)]
pub(crate) enum Target {
    /// A TCP connection; `start` is the egress position of the socket's first packet.
    Tcp {
        handle: SocketHandle,
        shared: Arc<Mutex<Shared>>,
        local: SocketAddr,
        peer: SocketAddr,
        start: u64,
    },
    /// A UDP flow from `incoming_udp`, by `(remote, local)`.
    UdpFlow((SocketAddr, SocketAddr)),
    /// A UDP socket from `bind_udp`, by its bound address.
    UdpBound(SocketAddr),
    /// A UDP socket from `connect_udp`, by `(remote, local)`.
    UdpConnected((SocketAddr, SocketAddr)),
}

/// The state of one flow shared by its data handles, its controls, its receipts and the
/// driver. Queued output refers to this state, not to a copy of anything in it.
pub(crate) struct FlowState {
    target: Target,
    revoked: AtomicBool,
    outcome: AtomicU8,
    /// Wakes the receipts' waiters once the outcome is written.
    done: Notify,
    /// Wakes the flow's handles parked on a full queue or an empty one at the revoke.
    wake: Notify,
    /// TCP: the egress position after the socket's last packet, set when the driver drops
    /// the socket; `u64::MAX` before.
    end: AtomicU64,
    revocations: Arc<Revocations>,
    #[cfg(test)]
    observed_turn: AtomicU64,
    #[cfg(test)]
    completed_turn: AtomicU64,
}

impl FlowState {
    pub(crate) fn new(target: Target, revocations: &Arc<Revocations>) -> Arc<Self> {
        Arc::new(Self {
            target,
            revoked: AtomicBool::new(false),
            outcome: AtomicU8::new(PENDING),
            done: Notify::new(),
            wake: Notify::new(),
            end: AtomicU64::new(u64::MAX),
            revocations: Arc::clone(revocations),
            #[cfg(test)]
            observed_turn: AtomicU64::new(0),
            #[cfg(test)]
            completed_turn: AtomicU64::new(0),
        })
    }

    pub(crate) const fn target(&self) -> &Target {
        &self.target
    }

    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }

    /// Resolves once the flow is revoked.
    pub(crate) async fn revoked(&self) {
        loop {
            let mut notified = pin!(self.wake.notified());
            notified.as_mut().enable();
            if self.is_revoked() {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn end(&self) -> u64 {
        self.end.load(Ordering::Relaxed)
    }

    pub(crate) fn set_end(&self, end: u64) {
        self.end.store(end, Ordering::Relaxed);
    }

    /// Revokes the flow on the handle side and queues it for the driver; only the first
    /// call does anything.
    fn revoke(self: &Arc<Self>) {
        if self.revoked.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Target::Tcp { shared, .. } = &self.target {
            let mut shared = tcp::lock(shared);
            shared.rx.clear();
            shared.tx.clear();
            shared.wake_reader();
            shared.wake_writer();
        }
        self.wake.notify_waiters();
        let mut queue = self.revocations.lock();
        if queue.closed {
            drop(queue);
            self.finish(RetirementOutcome::Unknown);
            return;
        }
        queue.pending.push(Arc::clone(self));
        self.revocations.hint.store(true, Ordering::Relaxed);
        drop(queue);
        self.revocations.driver.notify_one();
    }

    /// Writes the outcome once and wakes the waiters; later calls change nothing.
    pub(crate) fn finish(&self, outcome: RetirementOutcome) {
        let value = match outcome {
            RetirementOutcome::Retired => RETIRED,
            RetirementOutcome::Failed => FAILED,
            RetirementOutcome::Unknown => UNKNOWN,
        };
        if self
            .outcome
            .compare_exchange(PENDING, value, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.done.notify_waiters();
        }
    }

    fn outcome(&self) -> Option<RetirementOutcome> {
        match self.outcome.load(Ordering::SeqCst) {
            RETIRED => Some(RetirementOutcome::Retired),
            FAILED => Some(RetirementOutcome::Failed),
            UNKNOWN => Some(RetirementOutcome::Unknown),
            _ => None,
        }
    }

    /// Records the driver turn that took the revoke.
    #[cfg(test)]
    pub(crate) fn observed_in(&self, turn: u64) {
        self.observed_turn.store(turn, Ordering::Relaxed);
    }

    /// Records the driver turn that wrote the outcome.
    #[cfg(test)]
    pub(crate) fn completed_in(&self, turn: u64) {
        self.completed_turn.store(turn, Ordering::Relaxed);
    }
}

impl fmt::Debug for FlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowState")
            .field("target", &self.target)
            .field("revoked", &self.is_revoked())
            .field("outcome", &self.outcome())
            .finish_non_exhaustive()
    }
}

/// Revoked flows waiting for the driver, shared by every flow of one stack.
#[derive(Debug)]
pub(crate) struct Revocations {
    queue: Mutex<Queue>,
    /// Set while `queue.pending` may hold flows: the driver's only cost per turn.
    hint: AtomicBool,
    driver: Arc<Notify>,
}

#[derive(Debug, Default)]
struct Queue {
    /// The driver stopped: revokes resolve as unknown at once.
    closed: bool,
    pending: Vec<Arc<FlowState>>,
}

impl Revocations {
    pub(crate) fn new(driver: Arc<Notify>) -> Self {
        Self {
            queue: Mutex::default(),
            hint: AtomicBool::new(false),
            driver,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Moves the pending revocations into `into`; one load while there are none.
    pub(crate) fn take(&self, into: &mut Vec<Arc<FlowState>>) {
        if !self.hint.load(Ordering::Relaxed) {
            return;
        }
        let mut queue = self.lock();
        self.hint.store(false, Ordering::Relaxed);
        into.append(&mut queue.pending);
    }

    /// Stops taking revocations: the pending ones and those in `retiring` end unknown.
    pub(crate) fn close(&self, retiring: &mut Vec<Arc<FlowState>>) {
        let mut queue = self.lock();
        queue.closed = true;
        for flow in queue.pending.drain(..).chain(retiring.drain(..)) {
            flow.finish(RetirementOutcome::Unknown);
        }
    }
}

/// Output of a revoked flow already in the egress queue, which only [`NetStackSource`]
/// can still drop.
///
/// [`NetStackSource`]: crate::NetStackSource
#[derive(Debug)]
pub(crate) enum Fence {
    /// TCP packets from `local` to `peer` at egress positions in `[start, end)`.
    Tcp {
        local: SocketAddr,
        peer: SocketAddr,
        start: u64,
        end: u64,
    },
    /// The UDP datagrams at these egress positions, ascending.
    Udp(VecDeque<u64>),
}

impl Fence {
    /// Whether every packet the fence holds back is behind `position`.
    fn passed(&mut self, position: u64) -> bool {
        match self {
            Self::Tcp { end, .. } => *end <= position,
            Self::Udp(positions) => {
                while positions.front().is_some_and(|&held| held < position) {
                    positions.pop_front();
                }
                positions.is_empty()
            }
        }
    }

    /// Whether the packet at `position`, a TCP packet from and to `tuple` if it is one,
    /// is held back.
    fn holds(&self, position: u64, tuple: Option<(SocketAddr, SocketAddr)>) -> bool {
        match self {
            Self::Tcp {
                local,
                peer,
                start,
                end,
            } => (*start..*end).contains(&position) && tuple == Some((*local, *peer)),
            Self::Udp(positions) => positions.front() == Some(&position),
        }
    }
}

/// The fences of one stack, written by the driver and checked by its source.
#[derive(Debug, Default)]
pub(crate) struct Fences {
    /// Set while the table may hold fences: the source's only cost per packet.
    active: AtomicBool,
    table: Mutex<Vec<Fence>>,
}

impl Fences {
    fn lock(&self) -> MutexGuard<'_, Vec<Fence>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds `fence`; `false` if the table is full.
    pub(crate) fn insert(&self, fence: Fence) -> bool {
        let mut table = self.lock();
        if table.len() >= MAX_FENCES {
            return false;
        }
        table.push(fence);
        self.active.store(true, Ordering::SeqCst);
        true
    }

    /// Whether the packet at egress `position` is held back; `tuple` gives the `(src,
    /// dst)` of a TCP packet, parsed only while a fence exists. Fences behind `position`
    /// are dropped.
    pub(crate) fn holds(
        &self,
        position: u64,
        tuple: impl FnOnce() -> Option<(SocketAddr, SocketAddr)>,
    ) -> bool {
        if !self.active.load(Ordering::SeqCst) {
            return false;
        }
        let mut table = self.lock();
        table.retain_mut(|fence| !fence.passed(position));
        if table.is_empty() {
            self.active.store(false, Ordering::SeqCst);
            return false;
        }
        let tuple = tuple();
        table.iter().any(|fence| fence.holds(position, tuple))
    }
}

/// The control of one TCP connection, UDP flow or UDP socket, independent of its data
/// handles.
///
/// [`TcpConnection::control`](crate::TcpConnection::control),
/// [`UdpFlow::control`](crate::UdpFlow::control),
/// [`UdpReply::control`](crate::UdpReply::control) and
/// [`UdpSocket::control`](crate::UdpSocket::control) return it. Every control of a flow
/// (clones included, and those of every [`UdpReply`](crate::UdpReply) of a flow) acts on
/// the same flow; it stays valid after the data handles moved to other tasks, were
/// aborted, dropped or released. Dropping a control does nothing.
///
/// # Proof boundary
///
/// [`revoke`](Self::revoke) covers the stack only: the flow's sockets, buffers, timers and
/// queued output inside the stack, up to and including [`NetStackSource`]. A packet
/// [`NetStackSource::recv`](nsplane::PacketSource::recv) already returned belongs to the
/// engine and is not covered.
///
/// [`NetStackSource`]: crate::NetStackSource
#[derive(Clone)]
pub struct FlowControl {
    state: Arc<FlowState>,
}

impl FlowControl {
    pub(crate) const fn new(state: Arc<FlowState>) -> Self {
        Self { state }
    }

    /// Revokes the flow and returns the receipt of its retirement.
    ///
    /// Idempotent and irreversible: later calls return a receipt of the same outcome. The
    /// call never waits. At once, blocked reads, writes and sends of the flow wake up, and
    /// every data handle of the flow fails from then on with
    /// [`io::ErrorKind::ConnectionAborted`](std::io::ErrorKind::ConnectionAborted)
    /// ([`UdpFlow::recv`](crate::UdpFlow::recv) returns `None`); bytes and datagrams the
    /// flow buffered are discarded, never returned.
    ///
    /// Unlike a shutdown or a drop, nothing is sent: no FIN, and unlike
    /// [`TcpConnection::abort`](crate::TcpConnection::abort) no RST either. The peer is not
    /// told; it times out on its own, or learns from the stateless RST the stack answers
    /// its next TCP segment with. The driver turn that observes the revoke removes the
    /// flow's socket or queue entry and drops its output still queued in the stack, without
    /// waiting for the peer, an RST, TIME-WAIT or room in the egress queue. Other flows of
    /// the stack are untouched; a later packet of the peer on the same tuple is new
    /// traffic (a new UDP flow, or the RST above).
    pub fn revoke(&self) -> RetirementReceipt {
        self.state.revoke();
        RetirementReceipt {
            state: Arc::clone(&self.state),
        }
    }

    /// Whether the flow was revoked.
    pub fn is_revoked(&self) -> bool {
        self.state.is_revoked()
    }
}

impl fmt::Debug for FlowControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowControl")
            .field("revoked", &self.is_revoked())
            .finish_non_exhaustive()
    }
}

/// The receipt of a [`FlowControl::revoke`]: when and how the stack retired the flow.
///
/// Every clone and every receipt of a later revoke of the same flow share one outcome,
/// written once by the stack's driver:
///
/// - [`Retired`](RetirementOutcome::Retired) in the driver turn that observes the revoke,
///   once the flow's state is gone and its queued output dropped;
/// - [`Failed`](RetirementOutcome::Failed) if that turn could not hold back all of the
///   flow's output (the table of held-back output is bounded);
/// - [`Unknown`](RetirementOutcome::Unknown) if the stack stopped before (or had stopped:
///   its [`NetStackSink`](crate::NetStackSink) or [`NetStackSource`](crate::NetStackSource)
///   was dropped, or the runtime shut down). A stopped stack never reports a retirement it
///   did not complete.
///
/// # Proof boundary
///
/// The outcome is about the stack only. Packets the engine already took from
/// [`NetStackSource`](crate::NetStackSource) are outside the stack and not covered.
#[derive(Clone)]
pub struct RetirementReceipt {
    state: Arc<FlowState>,
}

impl RetirementReceipt {
    /// The outcome, or `None` while the driver has not retired the flow yet.
    pub fn outcome(&self) -> Option<RetirementOutcome> {
        self.state.outcome()
    }

    /// Waits for the outcome.
    ///
    /// Cancellation-safe and repeatable: any number of callers may wait at any time, and
    /// dropping the future only stops that wait. There is no internal timeout; a caller
    /// that gives up leaves [`outcome`](Self::outcome) at `None`.
    pub async fn wait(&self) -> RetirementOutcome {
        loop {
            let mut notified = pin!(self.state.done.notified());
            notified.as_mut().enable();
            if let Some(outcome) = self.outcome() {
                return outcome;
            }
            notified.await;
        }
    }

    /// The driver turns that took the revoke and wrote the outcome.
    #[cfg(test)]
    pub(crate) fn turns(&self) -> (u64, u64) {
        (
            self.state.observed_turn.load(Ordering::Relaxed),
            self.state.completed_turn.load(Ordering::Relaxed),
        )
    }
}

impl fmt::Debug for RetirementReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetirementReceipt")
            .field("outcome", &self.outcome())
            .finish_non_exhaustive()
    }
}
