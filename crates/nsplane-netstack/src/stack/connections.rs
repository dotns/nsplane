//! Bridging established connections to the application, and their release.

use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::task::Waker;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use tokio::sync::{Notify, watch};

use crate::flow::{FlowState, Target};
use crate::ownership::Registration;
use crate::tcp::{Dirty, Mark, Progress, Shared, WriteHalf, lock};

use super::{Driver, FULL_PASS_INTERVAL, TCP_IDLE_TIMEOUT};

/// Driver-side state of one connection handed to the application.
pub(super) struct Conn {
    /// Keeps the connection's tuple visible to `owns` until the socket is released.
    pub(super) _registration: Registration,
    pub(super) shared: Arc<Mutex<Shared>>,
    pub(super) terminal: watch::Sender<bool>,
    pub(super) progress: Arc<Progress>,
    /// The socket's send queue at the end of the previous bridge pass.
    pub(super) queued: usize,
    /// `close()` was called on the socket.
    pub(super) local_closed: bool,
    pub(super) last_activity_at: SmolInstant,
    pub(super) flow: Arc<FlowState>,
    /// The connection's request for a bridge pass, shared with the application's side.
    pub(super) mark: Arc<Mark>,
    /// Sets `mark`; registered with the socket at every bridge pass, as smoltcp wakes a
    /// registration once.
    pub(super) waker: Waker,
}

/// Which connections a bridge pass visits.
pub(super) struct Signalled {
    /// The connections signalled by the application or by smoltcp since their last bridge
    /// pass; it also wakes the driver for the application.
    pub(super) dirty: Arc<Dirty>,
    /// The signalled connections taken from `dirty` for this turn's bridge pass; empty
    /// between turns.
    visit: Vec<SocketHandle>,
    /// When the last bridge pass over every connection ran.
    full_pass_at: SmolInstant,
}

impl Signalled {
    /// An empty work list whose signals wake `driver`.
    pub(super) fn new(driver: Arc<Notify>) -> Self {
        Self {
            dirty: Arc::new(Dirty::new(driver)),
            visit: Vec::new(),
            full_pass_at: SmolInstant::ZERO,
        }
    }
}

/// What one bridge pass did.
pub(super) struct Bridged {
    /// Bytes moved into the socket's send buffer.
    sent: bool,
    /// The socket can be released.
    terminal: bool,
    /// The socket was aborted and releases once its RST left.
    aborting: bool,
}

impl Conn {
    /// Whether bytes wait in the socket's send buffer or in the application's.
    fn sending(&self, socket: &tcp::Socket<'_>) -> bool {
        socket.send_queue() > 0 || !lock(&self.shared).tx.is_empty()
    }

    /// Moves bytes between the socket and the application and applies half closes,
    /// filling the socket's send buffer up to `limit` bytes.
    ///
    /// Without a send budget the outcome is a fixed point: a second call changes nothing
    /// until the application signals the connection, smoltcp wakes one of the wakers
    /// registered here (a state change, received bytes, acknowledged bytes, the RST of an
    /// abort sent) or a timeout passes.
    fn bridge(&mut self, socket: &mut tcp::Socket<'_>, now: SmolInstant, limit: usize) -> Bridged {
        // Before anything is read, so that no change falls between the reads and the
        // registration.
        socket.register_recv_waker(&self.waker);
        socket.register_send_waker(&self.waker);
        // Only an acknowledgement shrinks the send queue, except a reset, which empties it
        // and leaves the socket closed.
        if socket.send_queue() < self.queued && socket.state() != tcp::State::Closed {
            self.progress
                .set_last_ack(u64::try_from(now.total_micros()).unwrap_or(0));
        }
        let mut shared = lock(&self.shared);
        if shared.write_half == WriteHalf::Aborted {
            return abort(socket, &mut shared);
        }
        preserve_terminal_receive(socket, &mut shared, &mut self.last_activity_at, now);

        // smoltcp -> application.
        if shared.app_dropped {
            // Nobody reads any more: discard what arrives; the write half closes below.
            shared.rx.clear();
            while socket.can_recv() {
                if socket.recv(|data| (data.len(), ())).is_err() {
                    break;
                }
            }
        } else if receive_into(socket, &mut shared) > 0 {
            self.last_activity_at = now;
            shared.wake_reader();
        }
        // Reverse half close: the peer sent FIN and every byte before it was moved, so
        // the application reads EOF instead of blocking forever.
        if !shared.rx_eof && !socket.may_recv() && !socket.can_recv() {
            shared.rx_eof = true;
            shared.wake_reader();
        }

        // Application -> smoltcp.
        let mut sent = false;
        while !shared.tx.is_empty() && socket.can_send() {
            let room = limit.saturating_sub(socket.send_queue());
            let data = shared.tx.as_slices().0;
            let n = socket
                .send_slice(&data[..data.len().min(room)])
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            shared.tx.drain(..n);
            sent = true;
        }
        if sent {
            self.last_activity_at = now;
            shared.wake_writer();
        }
        let queued = socket.send_queue();
        if queued != self.queued {
            self.queued = queued;
            self.progress.set_unacked(queued);
        }
        // Forward half close: the application shut its write half down (or dropped the
        // connection). Once every byte is in the socket, FIN follows them, so the peer
        // observes the end of the stream.
        let closing = shared.write_half == WriteHalf::Shutdown
            || (shared.app_dropped && shared.write_half == WriteHalf::Open);
        if closing && shared.tx.is_empty() {
            if !self.local_closed && socket.may_send() {
                socket.close();
                self.local_closed = true;
            }
            shared.write_half = WriteHalf::FinSent;
            shared.wake_writer();
        }

        if tcp_idle_timeout_expired(socket.state(), self.last_activity_at, now) {
            tracing::debug!(target: "netstack", "TCP connection exceeded idle timeout; aborting");
            // Released like an application abort: once the RST left.
            shared.write_half = WriteHalf::Aborted;
            return abort(socket, &mut shared);
        }
        let terminal = tcp_terminal_ready(
            socket.state(),
            !shared.rx.is_empty() || socket.can_recv(),
            self.last_activity_at,
            now,
        );
        Bridged {
            sent,
            terminal,
            aborting: false,
        }
    }

    /// What a bridge pass would do for the connection now, timeouts aside: `None` at the
    /// fixed point [`bridge`](Self::bridge) leaves behind.
    #[cfg(test)]
    fn unbridged(&self, socket: &tcp::Socket<'_>) -> Option<&'static str> {
        let shared = lock(&self.shared);
        let terminal = matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait);
        let closing = shared.write_half == WriteHalf::Shutdown
            || (shared.app_dropped && shared.write_half == WriteHalf::Open);
        if shared.write_half == WriteHalf::Aborted {
            Some("an abort")
        } else if socket.send_queue() != self.queued {
            Some("a send queue that moved")
        } else if socket.can_recv()
            && (terminal || shared.app_dropped || shared.rx.len() < shared.capacity)
        {
            Some("received bytes to move")
        } else if !shared.rx_eof && !socket.may_recv() && !socket.can_recv() {
            Some("the end of the stream")
        } else if !shared.tx.is_empty() && socket.can_send() {
            Some("written bytes to move")
        } else if closing && shared.tx.is_empty() {
            Some("a close")
        } else if terminal && shared.rx.is_empty() {
            Some("a release")
        } else {
            None
        }
    }

    /// Tells the application the socket is gone.
    pub(super) fn release(&self) {
        let mut shared = lock(&self.shared);
        shared.released = true;
        shared.rx_eof = true;
        shared.wake_reader();
        shared.wake_writer();
        drop(shared);
        self.terminal.send_replace(true);
    }
}

/// Resets the socket of an aborted connection and discards its bytes.
///
/// smoltcp sends the RST on its next dispatch and then forgets the remote endpoint; until
/// then the socket must stay. A socket already closed (reset by the peer, or after the
/// close handshake) has nobody to reset and is released as is.
pub(super) fn abort(socket: &mut tcp::Socket<'_>, shared: &mut Shared) -> Bridged {
    shared.rx.clear();
    shared.tx.clear();
    if !matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
        socket.abort();
    }
    let terminal = socket.state() == tcp::State::TimeWait || socket.remote_endpoint().is_none();
    Bridged {
        sent: false,
        terminal,
        aborting: !terminal,
    }
}

/// Moves received bytes into the application buffer while it has room.
fn receive_into(socket: &mut tcp::Socket<'_>, shared: &mut Shared) -> usize {
    let mut total = 0;
    while socket.can_recv() && shared.rx.len() < shared.capacity {
        let room = shared.capacity - shared.rx.len();
        let received = socket.recv(|data| {
            let n = data.len().min(room);
            shared.rx.extend(&data[..n]);
            (n, n)
        });
        match received {
            Ok(n) if n > 0 => total += n,
            _ => break,
        }
    }
    total
}

impl Driver {
    /// A new delivered connection state for the socket `handle` with the ingress `label`,
    /// and its stream buffers.
    pub(super) fn tcp_state(
        &self,
        handle: SocketHandle,
        local: SocketAddr,
        peer: SocketAddr,
        start: u64,
        label: Option<NonZeroU64>,
    ) -> (Arc<FlowState>, Arc<Mutex<Shared>>) {
        let shared = Arc::new(Mutex::new(Shared::new(self.settings.stream_buffer)));
        let flow = FlowState::new(
            Target::Tcp {
                handle,
                shared: Arc::clone(&shared),
                local,
                peer,
                start,
            },
            label,
            &self.revocations,
        );
        (flow, shared)
    }

    /// Keeps the bytes of terminal sockets before smoltcp's timers discard the socket.
    ///
    /// Only signalled connections can hold such bytes: a socket turns terminal with a
    /// state change, which signals it, and the bridge pass that takes the signal moves
    /// every byte of a terminal socket.
    pub(super) fn preserve_signalled(&mut self, now: SmolInstant) {
        self.signalled.dirty.drain_into(&mut self.signalled.visit);
        for handle in &self.signalled.visit {
            let Some(conn) = self.conns.get_mut(handle) else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(*handle);
            let mut shared = lock(&conn.shared);
            preserve_terminal_receive(socket, &mut shared, &mut conn.last_activity_at, now);
        }
    }

    /// How long until the next bridge pass over every connection is due.
    pub(super) fn full_pass_due(&self, now: SmolInstant) -> std::time::Duration {
        let since = now.total_micros() - self.signalled.full_pass_at.total_micros();
        full_pass_interval().saturating_sub(std::time::Duration::from_micros(
            u64::try_from(since).unwrap_or(0),
        ))
    }

    /// Bridges the signalled connections, or every connection once
    /// [`FULL_PASS_INTERVAL`] passed since that was last done and in every turn with
    /// `tcp_send_budget` (a connection's share of the budget moves with the other
    /// connections), and releases terminal ones; `true` if bytes were sent or an aborted
    /// connection waits for its RST to be sent.
    pub(super) fn bridge_all(&mut self, now: SmolInstant) -> bool {
        let mut sent = false;
        let mut released = Vec::new();
        self.signalled.dirty.drain_into(&mut self.signalled.visit);
        let full = self.settings.tcp_send_budget.is_some() || self.full_pass_due(now).is_zero();
        // Each sending connection's share of the send budget.
        let limit = self.settings.tcp_send_budget.map_or(usize::MAX, |budget| {
            let senders = self
                .conns
                .iter()
                .filter(|&(&handle, conn)| {
                    conn.sending(self.sockets.get::<tcp::Socket<'_>>(handle))
                })
                .count();
            (budget / senders.max(1)).max(usize::from(self.settings.mtu) - 40)
        });
        let mut bridge = |handle: SocketHandle, conn: &mut Conn, socket: &mut tcp::Socket<'_>| {
            let bridged = conn.bridge(socket, now, limit);
            sent |= bridged.sent;
            if bridged.terminal {
                released.push(handle);
            } else if bridged.aborting {
                // Bridged again until its RST left.
                conn.mark.set();
                self.aborting.push(handle);
            }
        };
        if full {
            self.signalled.full_pass_at = now;
            self.signalled.visit.clear();
            for (&handle, conn) in &mut self.conns {
                conn.mark.take();
                bridge(
                    handle,
                    conn,
                    self.sockets.get_mut::<tcp::Socket<'_>>(handle),
                );
            }
        } else {
            for handle in self.signalled.visit.drain(..) {
                // An entry without the request is one a pass over every connection
                // served, or that of a released connection.
                if let Some(conn) = self.conns.get_mut(&handle)
                    && conn.mark.take()
                {
                    bridge(
                        handle,
                        conn,
                        self.sockets.get_mut::<tcp::Socket<'_>>(handle),
                    );
                }
            }
        }
        for handle in released {
            self.release_conn(handle);
        }
        #[cfg(test)]
        self.assert_bridged();
        sent || !self.aborting.is_empty()
    }

    /// Checks the dirty tracking against the pass over every connection it replaces: a
    /// connection without a request for a bridge pass has nothing to bridge. Only where
    /// the application runs on the driver's thread, as elsewhere it may have changed a
    /// connection and not signalled it yet.
    #[cfg(test)]
    fn assert_bridged(&self) {
        let single = tokio::runtime::Handle::current().runtime_flavor()
            == tokio::runtime::RuntimeFlavor::CurrentThread;
        if !single || self.settings.tcp_send_budget.is_some() {
            return;
        }
        for (&handle, conn) in &self.conns {
            let work = conn.unbridged(self.sockets.get::<tcp::Socket<'_>>(handle));
            assert!(
                conn.mark.is_set() || work.is_none(),
                "connection {handle} has {work:?} and no request for a bridge pass"
            );
        }
    }

    /// Releases the aborted connections whose RST the poll after the bridge pass sent (one
    /// the device could not send yet stays until a later bridge pass finds it sent), then
    /// retries the connects that waited for their ports.
    pub(super) fn release_aborted(&mut self) {
        for handle in std::mem::take(&mut self.aborting) {
            if self
                .sockets
                .get::<tcp::Socket<'_>>(handle)
                .remote_endpoint()
                .is_none()
            {
                self.release_conn(handle);
            }
        }
        for command in std::mem::take(&mut self.deferred) {
            self.command(command);
        }
    }

    /// Whether an aborted connection not released yet holds `port`.
    pub(super) fn aborting_port(&self, port: u16) -> bool {
        self.conns.iter().any(|(&handle, conn)| {
            self.sockets
                .get::<tcp::Socket<'_>>(handle)
                .local_endpoint()
                .is_some_and(|endpoint| endpoint.port == port)
                && lock(&conn.shared).write_half == WriteHalf::Aborted
        })
    }

    /// Releases a connection's tuple and socket and tells the application.
    pub(super) fn release_conn(&mut self, handle: SocketHandle) {
        let end = self.position();
        if let Some(conn) = self.conns.remove(&handle) {
            if let Some(&Target::Tcp { local, peer, .. }) = conn.flow.target() {
                self.labels.release((peer, local), handle);
                self.device.tcp_labels.remove(&(local, peer));
            }
            conn.flow.set_end(end);
            conn.release();
        }
        self.sockets.remove(handle);
    }
}

pub(super) fn tcp_idle_timeout_expired(
    state: tcp::State,
    last_activity_at: SmolInstant,
    now: SmolInstant,
) -> bool {
    !matches!(state, tcp::State::Closed | tcp::State::TimeWait)
        && now >= last_activity_at + idle_timeout()
}

#[cfg(not(test))]
const fn full_pass_interval() -> std::time::Duration {
    FULL_PASS_INTERVAL
}

#[cfg(test)]
thread_local! {
    /// Replaces [`FULL_PASS_INTERVAL`] for the stacks a test drives on its thread.
    pub(super) static FULL_PASS: std::cell::Cell<Option<std::time::Duration>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn full_pass_interval() -> std::time::Duration {
    FULL_PASS
        .with(std::cell::Cell::get)
        .unwrap_or(FULL_PASS_INTERVAL)
}

#[cfg(not(test))]
const fn idle_timeout() -> SmolDuration {
    TCP_IDLE_TIMEOUT
}

#[cfg(test)]
thread_local! {
    /// Replaces [`TCP_IDLE_TIMEOUT`] for the stacks a test drives on its thread.
    pub(super) static IDLE_TIMEOUT: std::cell::Cell<Option<SmolDuration>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn idle_timeout() -> SmolDuration {
    IDLE_TIMEOUT
        .with(std::cell::Cell::get)
        .unwrap_or(TCP_IDLE_TIMEOUT)
}

pub(super) fn tcp_terminal_ready(
    state: tcp::State,
    receive_pending: bool,
    last_activity_at: SmolInstant,
    now: SmolInstant,
) -> bool {
    matches!(state, tcp::State::Closed | tcp::State::TimeWait)
        && (!receive_pending || now >= last_activity_at + TCP_IDLE_TIMEOUT)
}

pub(super) const fn record_receive_activity(
    received: usize,
    last_activity_at: &mut SmolInstant,
    now: SmolInstant,
) {
    if received > 0 {
        *last_activity_at = now;
    }
}

/// Moves every byte of a terminal socket into the application buffer, past its bound.
fn preserve_terminal_receive(
    socket: &mut tcp::Socket<'_>,
    shared: &mut Shared,
    last_activity_at: &mut SmolInstant,
    now: SmolInstant,
) {
    if !matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) || !socket.can_recv() {
        return;
    }
    // FIN bounds this transfer to one receive buffer.
    let previous = shared.rx.len();
    while socket.can_recv() {
        let received = socket.recv(|bytes| {
            shared.rx.extend(bytes.iter());
            (bytes.len(), ())
        });
        if received.is_err() {
            break;
        }
    }
    record_receive_activity(shared.rx.len() - previous, last_activity_at, now);
    shared.wake_reader();
}
