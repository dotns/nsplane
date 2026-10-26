//! Bridging established connections to the application, and their release.

use std::sync::{Arc, Mutex};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use tokio::sync::watch;

use crate::flow::FlowState;
use crate::ownership::Registration;
use crate::tcp::{Progress, Shared, WriteHalf, lock};

use super::{Driver, TCP_IDLE_TIMEOUT};

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
    fn bridge(&mut self, socket: &mut tcp::Socket<'_>, now: SmolInstant, limit: usize) -> Bridged {
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
    /// Keeps the bytes of terminal sockets before smoltcp's timers discard the socket.
    pub(super) fn preserve_all(&mut self, now: SmolInstant) {
        for (&handle, conn) in &mut self.conns {
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
            let mut shared = lock(&conn.shared);
            preserve_terminal_receive(socket, &mut shared, &mut conn.last_activity_at, now);
        }
    }

    /// Bridges every connection and releases terminal ones; `true` if bytes were sent or
    /// an aborted connection waits for its RST to be sent.
    pub(super) fn bridge_all(&mut self, now: SmolInstant) -> bool {
        let mut sent = false;
        let mut released = Vec::new();
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
        for (&handle, conn) in &mut self.conns {
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
            let bridged = conn.bridge(socket, now, limit);
            sent |= bridged.sent;
            if bridged.terminal {
                released.push(handle);
            } else if bridged.aborting {
                self.aborting.push(handle);
            }
        }
        for handle in released {
            self.release_conn(handle);
        }
        sent || !self.aborting.is_empty()
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
