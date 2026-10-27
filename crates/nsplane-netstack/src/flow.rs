//! Per-flow control: revoking one connection or flow of a shared stack, the receipt that
//! tells when the stack holds nothing of it any more, the receipt of its hand-out, and the
//! caller's label on the flow.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use smoltcp::iface::SocketHandle;
use tokio::sync::Notify;

use crate::pending::Key;
use crate::tcp::{self, Shared};

/// Most fences the egress holds at once, TCP and UDP together; a revoke that needs one
/// more fails. A fence is dropped once the source took every position it holds back.
pub(crate) const MAX_FENCES: usize = 1024;

const PENDING: u8 = 0;
const RETIRED: u8 = 1;
const FAILED: u8 = 2;
const UNKNOWN: u8 = 3;

/// The delivery stage before it is fixed; `DELIVERED` once handed out, an
/// [`Undelivered::code`] once it ended without.
const UNDECIDED: u8 = 0;
const DELIVERED: u8 = 1;

/// The next instance [`FlowControl::bind_context`] hands out, shared by every stack of the
/// process.
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// Takes the next instance from `counter`; `None` once it is used up. It never wraps, so
/// no instance is handed out twice.
fn allocate(counter: &AtomicU64) -> Option<NonZeroU64> {
    let mut next = counter.load(Ordering::SeqCst);
    loop {
        let after = next.checked_add(1)?;
        match counter.compare_exchange_weak(next, after, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return NonZeroU64::new(next),
            Err(current) => next = current,
        }
    }
}

/// The caller's opaque label on one flow: an isolation domain the caller chooses and an
/// instance the stack allocates.
///
/// [`FlowControl::bind_context`] binds it. The instance is unique within the process: it
/// is never handed out again, to a flow of any stack, also not once the flow is revoked,
/// so a later flow on the same tuple, in the same domain or not, always has another one.
/// The stack never reads the context; it is the caller's way to tell flows apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowContext {
    domain: u64,
    instance: NonZeroU64,
}

impl FlowContext {
    /// The isolation domain the caller bound.
    pub const fn domain(&self) -> u64 {
        self.domain
    }

    /// The instance the stack allocated for the flow.
    pub const fn instance(&self) -> NonZeroU64 {
        self.instance
    }
}

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

/// How the hand-out of a connection's or flow's lifetime ended, see [`DeliveryReceipt`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeliveryOutcome {
    /// Handed out on [`incoming_tcp`](crate::NetStackHandle::incoming_tcp) or
    /// [`incoming_udp`](crate::NetStackHandle::incoming_udp), or opened by the application.
    Delivered,
    /// Never handed out; no handle of this lifetime appears afterwards.
    NotDelivered(Undelivered),
}

/// Why a lifetime held under [`Admission::Decide`](crate::Admission::Decide) was never
/// handed out, see [`DeliveryOutcome::NotDelivered`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Undelivered {
    /// [`PendingFlow::reject`](crate::PendingFlow::reject), or the item was dropped; see
    /// [`rejected_hook`](crate::NetStackStats::rejected_hook).
    Rejected,
    /// No decision within the [`Admission::Decide`](crate::Admission::Decide) timeout; see
    /// [`rejected_timeout`](crate::NetStackStats::rejected_timeout).
    TimedOut,
    /// [`TransparentConfig::max_connections`](crate::TransparentConfig::max_connections)
    /// was reached at the accept; see
    /// [`rejected_connection_limit`](crate::NetStackStats::rejected_connection_limit).
    ConnectionLimit,
    /// The accepted SYN found no socket of the listener pool; see
    /// [`syn_refused`](crate::NetStackStats::syn_refused).
    NoListener,
    /// The handshake ended before the connection was established: the peer reset it, or
    /// it closed; see [`handshake_failed`](crate::NetStackStats::handshake_failed).
    HandshakeFailed,
    /// `incoming_tcp` or `incoming_udp` was full (without
    /// [`accept_backpressure`](crate::NetStackConfig::accept_backpressure) for TCP); see
    /// [`tcp_not_accepted`](crate::NetStackStats::tcp_not_accepted) and
    /// [`udp_not_accepted`](crate::NetStackStats::udp_not_accepted).
    AcceptQueueFull,
    /// The `incoming_tcp` or `incoming_udp` stream was dropped, before the connection or
    /// flow reached it or with it in its queue.
    AcceptQueueGone,
    /// The UDP flow table held [`max_udp_flows`](crate::NetStackConfig::max_udp_flows)
    /// flows at the accept; see [`udp_flow_limit`](crate::NetStackStats::udp_flow_limit).
    FlowLimit,
    /// [`FlowControl::revoke`] before the hand-out.
    Revoked,
    /// The stack stopped first.
    Stopped,
}

impl Undelivered {
    const ALL: [Self; 10] = [
        Self::Rejected,
        Self::TimedOut,
        Self::ConnectionLimit,
        Self::NoListener,
        Self::HandshakeFailed,
        Self::AcceptQueueFull,
        Self::AcceptQueueGone,
        Self::FlowLimit,
        Self::Revoked,
        Self::Stopped,
    ];

    /// The delivery stage that stands for `self`.
    const fn code(self) -> u8 {
        DELIVERED + 1 + self as u8
    }
}

/// Where the driver finds a flow's state.
#[derive(Debug)]
pub(crate) enum Target {
    /// A TCP connection, or the socket of one mid handshake; `start` is the egress
    /// position of the socket's first packet.
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
///
/// A lifetime held under `Admission::Decide` gets its state at its first input, with its
/// `held` tuple and no target yet; the driver binds the target once it has a socket or a
/// flow entry. Every other flow is created with its target, already delivered.
pub(crate) struct FlowState {
    target: OnceLock<Target>,
    /// The tuple of a lifetime held under `Admission::Decide`, by which the driver finds it
    /// before its target is bound.
    held: Option<Key>,
    /// TCP: the lifetime has a connection (the handshake completed), not only a socket.
    adopted: AtomicBool,
    revoked: AtomicBool,
    /// `UNDECIDED`, `DELIVERED` or an [`Undelivered::code`]; fixed by the first
    /// compare-and-swap away from `UNDECIDED`.
    delivery: AtomicU8,
    outcome: AtomicU8,
    /// Wakes the receipts' waiters once the retirement or the delivery outcome is written.
    done: Notify,
    /// Wakes the flow's handles parked on a full queue or an empty one at the revoke.
    wake: Notify,
    /// TCP: the egress position after the socket's last packet, set when the driver drops
    /// the socket; `u64::MAX` before.
    end: AtomicU64,
    revocations: Arc<Revocations>,
    /// The caller's label; never read by the stack.
    context: OnceLock<FlowContext>,
    #[cfg(test)]
    observed_turn: AtomicU64,
    #[cfg(test)]
    completed_turn: AtomicU64,
}

impl FlowState {
    /// The state of a flow created with its target and handed out.
    pub(crate) fn new(target: Target, revocations: &Arc<Revocations>) -> Arc<Self> {
        Self::with(OnceLock::from(target), None, true, revocations)
    }

    /// The state of the lifetime of `key`, held under `Admission::Decide`.
    pub(crate) fn held(key: Key, revocations: &Arc<Revocations>) -> Arc<Self> {
        Self::with(OnceLock::new(), Some(key), false, revocations)
    }

    /// A delivered and adopted state, or an undecided one not adopted yet.
    fn with(
        target: OnceLock<Target>,
        held: Option<Key>,
        delivered: bool,
        revocations: &Arc<Revocations>,
    ) -> Arc<Self> {
        Arc::new(Self {
            target,
            held,
            adopted: AtomicBool::new(delivered),
            revoked: AtomicBool::new(false),
            delivery: AtomicU8::new(if delivered { DELIVERED } else { UNDECIDED }),
            outcome: AtomicU8::new(PENDING),
            done: Notify::new(),
            wake: Notify::new(),
            end: AtomicU64::new(u64::MAX),
            revocations: Arc::clone(revocations),
            context: OnceLock::new(),
            #[cfg(test)]
            observed_turn: AtomicU64::new(0),
            #[cfg(test)]
            completed_turn: AtomicU64::new(0),
        })
    }

    /// Where the driver finds the flow, once bound.
    pub(crate) fn target(&self) -> Option<&Target> {
        self.target.get()
    }

    /// Binds the target of a held lifetime; only the first call does anything.
    pub(crate) fn bind(&self, target: Target) {
        let _ = self.target.set(target);
    }

    /// Records that the TCP lifetime has its connection.
    pub(crate) fn mark_adopted(&self) {
        self.adopted.store(true, Ordering::SeqCst);
    }

    /// The tuple of a lifetime held under `Admission::Decide`.
    pub(crate) const fn held_key(&self) -> Option<&Key> {
        self.held.as_ref()
    }

    /// Fixes the delivery as handed out unless it ended before; whether the lifetime is
    /// delivered.
    pub(crate) fn deliver(&self) -> bool {
        match self.delivery.load(Ordering::SeqCst) {
            DELIVERED => true,
            UNDECIDED => match self.delivery.compare_exchange(
                UNDECIDED,
                DELIVERED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.done.notify_waiters();
                    true
                }
                Err(current) => current == DELIVERED,
            },
            _ => false,
        }
    }

    /// Fixes the delivery as never handed out for `reason` unless it is fixed already;
    /// whether this call fixed it.
    pub(crate) fn undeliver(&self, reason: Undelivered) -> bool {
        let fixed = self
            .delivery
            .compare_exchange(UNDECIDED, reason.code(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if fixed {
            self.done.notify_waiters();
        }
        fixed
    }

    /// Whether the delivery is still open.
    pub(crate) fn undecided(&self) -> bool {
        self.delivery.load(Ordering::SeqCst) == UNDECIDED
    }

    fn delivery(&self) -> Option<DeliveryOutcome> {
        match self.delivery.load(Ordering::SeqCst) {
            UNDECIDED => None,
            DELIVERED => Some(DeliveryOutcome::Delivered),
            code => Undelivered::ALL
                .into_iter()
                .find(|reason| reason.code() == code)
                .map(DeliveryOutcome::NotDelivered),
        }
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
    /// call does anything. A lifetime not handed out yet never will be.
    fn revoke(self: &Arc<Self>) {
        if self.revoked.swap(true, Ordering::SeqCst) {
            return;
        }
        // The driver answers a rejection only if it fixed the delivery first.
        self.undeliver(Undelivered::Revoked);
        if let Some(Target::Tcp { shared, .. }) = self.target() {
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
            .field("target", &self.target())
            .field("held", &self.held)
            .field("revoked", &self.is_revoked())
            .field("delivery", &self.delivery())
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
    /// TCP packets from `local` to `peer` at egress positions in `[start, end)`, clipped
    /// to the positions possibly in the egress queue: one per revoked connection, of fixed
    /// size.
    Tcp {
        local: SocketAddr,
        peer: SocketAddr,
        start: u64,
        end: u64,
    },
    /// The UDP datagrams at these egress positions, ascending: positions in the egress
    /// queue only, so at most `egress_capacity` of them. One per revoked flow.
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
/// Under [`Admission::Decide`](crate::Admission::Decide) the control exists from the
/// lifetime's first input on: [`PendingFlow::control`](crate::PendingFlow::control)
/// returns the control the delivered handle carries later, and a revoke before the
/// hand-out ends the lifetime undelivered (see [`delivery`](Self::delivery)).
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

    pub(crate) fn tcp_egress_end(&self, owner: &Arc<Revocations>) -> io::Result<Option<u64>> {
        if !Arc::ptr_eq(owner, &self.state.revocations)
            || !matches!(self.state.target(), Some(Target::Tcp { .. }))
            || !self.state.adopted.load(Ordering::SeqCst)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "flow is not a TCP connection of this stack",
            ));
        }
        if self.is_revoked() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "flow revoked",
            ));
        }
        let end = self.state.end();
        Ok((end != u64::MAX).then_some(end))
    }

    /// Revokes the flow and returns the receipt of its retirement.
    ///
    /// Idempotent and irreversible: later calls return a receipt of the same outcome. The
    /// call never waits. At once, blocked reads, writes and sends of the flow wake up, and
    /// every data handle of the flow fails from then on with
    /// [`io::ErrorKind::ConnectionAborted`](std::io::ErrorKind::ConnectionAborted)
    /// ([`UdpFlow::recv`](crate::UdpFlow::recv) returns `None`;
    /// [`UdpSocket::send`](crate::UdpSocket::send) on an unconnected socket still returns
    /// `NotConnected` before checking revocation). Bytes and datagrams the flow buffered
    /// are discarded, never returned.
    ///
    /// Unlike a shutdown or a drop, nothing is sent: no FIN, and unlike
    /// [`TcpConnection::abort`](crate::TcpConnection::abort) no RST either. The peer is not
    /// told; it times out on its own, or learns from the stateless RST the stack answers
    /// its next TCP segment with. The driver turn that observes the revoke removes the
    /// flow's socket or queue entry and drops its output still queued in the stack, without
    /// waiting for the peer, an RST, TIME-WAIT or room in the egress queue. Other flows of
    /// the stack are untouched; a later packet of the peer on the same tuple is new
    /// traffic (a new UDP flow, or the RST above).
    ///
    /// Before the hand-out the same holds at every stage of a lifetime held under
    /// [`Admission::Decide`](crate::Admission::Decide): the driver turn that observes the
    /// revoke removes the held entry (no RST or port unreachable follows, and a later
    /// decision on the [`PendingFlow`](crate::PendingFlow) does nothing), the listener
    /// socket of an accepted SYN in SYN-RECEIVED (its SYN-ACK still queued in the stack is
    /// dropped), the established connection waiting for `incoming_tcp`, or the flow
    /// entry with its queued datagrams; the handle is never returned by `incoming_tcp`
    /// or `incoming_udp`, and the delivery ends
    /// [`NotDelivered(Revoked)`](Undelivered::Revoked). A later SYN or datagram on the
    /// tuple is a new lifetime.
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

    /// The receipt of the hand-out of this connection's or flow's lifetime: delivered, or
    /// never delivered and why.
    ///
    /// A lifetime held under [`Admission::Decide`](crate::Admission::Decide) is delivered
    /// when the [`incoming_tcp`](crate::NetStackHandle::incoming_tcp) or
    /// [`incoming_udp`](crate::NetStackHandle::incoming_udp) stream takes its handle;
    /// until then the outcome is open. Every other connection, flow and socket (admitted
    /// with [`Admission::Immediate`](crate::Admission::Immediate) or opened by the
    /// application) reports [`Delivered`](DeliveryOutcome::Delivered) from the start.
    pub fn delivery(&self) -> DeliveryReceipt {
        DeliveryReceipt {
            state: Arc::clone(&self.state),
        }
    }

    /// Labels the flow with `domain` and a new instance, and returns that
    /// [`FlowContext`].
    ///
    /// Binds once per flow. Fails with
    /// [`io::ErrorKind::ConnectionAborted`](std::io::ErrorKind::ConnectionAborted) once the
    /// flow is revoked, [`AlreadyExists`](std::io::ErrorKind::AlreadyExists) if it has a
    /// context, and [`QuotaExceeded`](std::io::ErrorKind::QuotaExceeded) once the
    /// process's instances are used up; a failed call leaves the flow as it was.
    ///
    /// Bind right after the flow is handed out ([`incoming_tcp`], [`incoming_udp`],
    /// [`connect_tcp`], [`connect_udp`], [`bind_udp`]), or under
    /// [`Admission::Decide`](crate::Admission::Decide) on the
    /// [`PendingFlow`](crate::PendingFlow)'s control at the decision: the delivered handle
    /// carries the same control and context. A later bind loses nothing: the
    /// stack tracks a flow's queued output by the flow itself from its creation, so the
    /// context labels output queued before the bind too, and a revoke drops it either way.
    /// The stack never reads the context and treats flows with and without one alike.
    ///
    /// The context lives on the stack's state of the flow only. The proof boundary of
    /// [`revoke`](Self::revoke) applies: packets already taken from [`NetStackSource`] do
    /// not carry it.
    ///
    /// [`incoming_tcp`]: crate::NetStackHandle::incoming_tcp
    /// [`incoming_udp`]: crate::NetStackHandle::incoming_udp
    /// [`connect_tcp`]: crate::NetStackHandle::connect_tcp
    /// [`connect_udp`]: crate::NetStackHandle::connect_udp
    /// [`bind_udp`]: crate::NetStackHandle::bind_udp
    /// [`NetStackSource`]: crate::NetStackSource
    pub fn bind_context(&self, domain: u64) -> io::Result<FlowContext> {
        self.bind_context_from(domain, &NEXT_INSTANCE)
    }

    /// [`bind_context`](Self::bind_context) with the instance taken from `counter`.
    pub(crate) fn bind_context_from(
        &self,
        domain: u64,
        counter: &AtomicU64,
    ) -> io::Result<FlowContext> {
        if self.is_revoked() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "flow revoked",
            ));
        }
        let bound = || io::Error::new(io::ErrorKind::AlreadyExists, "flow context already bound");
        if self.state.context.get().is_some() {
            return Err(bound());
        }
        let instance = allocate(counter).ok_or_else(|| {
            io::Error::new(io::ErrorKind::QuotaExceeded, "flow instances used up")
        })?;
        let context = FlowContext { domain, instance };
        self.state.context.set(context).map_err(|_| bound())?;
        Ok(context)
    }

    /// The flow's context, if one was bound; it stays after a revoke.
    pub fn context(&self) -> Option<FlowContext> {
        self.state.context.get().copied()
    }
}

impl fmt::Debug for FlowControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowControl")
            .field("revoked", &self.is_revoked())
            .field("context", &self.context())
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
/// # Bounds
///
/// The state the stack keeps to hold back a revoked flow's output is bounded, and a
/// revoke that would need more fails instead of growing it:
///
/// - output already in the egress queue is held back by a fence, at most 1024 at once for
///   the whole stack; a UDP fence lists at most
///   [`egress_capacity`](crate::NetStackConfig::egress_capacity) positions;
/// - with [`reassembly`](crate::NetStackConfig::reassembly), fragments the reassembler may
///   hold are barred for one reassembly timeout, at most
///   [`max_datagrams`](crate::ReassemblyConfig::max_datagrams) bars at once.
///
/// The stack also tracks which flow each queued UDP datagram belongs to; that list is
/// bounded by the backlog and the egress queue themselves and never fails a revoke.
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

/// The receipt of a lifetime's hand-out, see [`FlowControl::delivery`].
///
/// Each lifetime has exactly one [`DeliveryOutcome`], shared by every clone and every
/// receipt of the lifetime's controls and fixed once by whichever comes first: the
/// `incoming_tcp` / `incoming_udp` stream taking its handle, or the first event that ends
/// it before (an [`Undelivered`] reason). A stream that finds a handle whose lifetime ended
/// skips it, so a lifetime revoked while its handle waits in the stream's queue is never
/// returned.
#[derive(Clone)]
pub struct DeliveryReceipt {
    state: Arc<FlowState>,
}

impl DeliveryReceipt {
    /// The outcome, or `None` while the lifetime is neither handed out nor ended.
    pub fn outcome(&self) -> Option<DeliveryOutcome> {
        self.state.delivery()
    }

    /// Waits for the outcome.
    ///
    /// Cancellation-safe and repeatable, like [`RetirementReceipt::wait`]. There is no
    /// internal timeout; a lifetime is held at most for the
    /// [`Admission::Decide`](crate::Admission::Decide) timeout, but one accepted waits for
    /// its handshake and then for the application to take it.
    pub async fn wait(&self) -> DeliveryOutcome {
        loop {
            let mut notified = pin!(self.state.done.notified());
            notified.as_mut().enable();
            if let Some(outcome) = self.outcome() {
                return outcome;
            }
            notified.await;
        }
    }
}

impl fmt::Debug for DeliveryReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryReceipt")
            .field("outcome", &self.outcome())
            .finish_non_exhaustive()
    }
}
