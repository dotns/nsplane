//! Handing inbound and connected TCP connections to the application.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{oneshot, watch};

use crate::flow::{FlowState, Target, Undelivered};
use crate::ownership::Registration;
use crate::stats::{self};
use crate::tcp::{Progress, Shared, TcpConnection};

use super::connections::Conn;
use super::listeners::tcp_listener_ready_for_promotion;
use super::wire::endpoint_to_socket_addr;
use super::{CONNECT_TIMEOUT, Driver, Inbound};

/// A `connect_tcp` waiting for its handshake.
pub(super) struct Connecting {
    pub(super) handle: SocketHandle,
    /// Keeps the connect's tuple visible to `owns` while it is in SYN-SENT.
    pub(super) _registration: Registration,
    pub(super) reply: oneshot::Sender<io::Result<TcpConnection>>,
    pub(super) started: SmolInstant,
    /// The egress position when the socket was created.
    pub(super) start: u64,
}

impl Driver {
    /// Promotes established listener sockets to connections for `incoming_tcp`.
    pub(super) fn promote(&mut self, now: SmolInstant) {
        let mut accepted = Vec::new();
        for (&port, handles) in &self.listeners {
            for &handle in handles {
                let state = self.sockets.get::<tcp::Socket<'_>>(handle).state();
                if tcp_listener_ready_for_promotion(state) {
                    accepted.push((handle, port));
                }
            }
        }
        // Take every accepted socket out of its pool BEFORE promoting any of them. The
        // next top-up prunes handles that are no longer `Listen`/`SynReceived`, which
        // would include connections accepted alongside this one and not yet promoted,
        // closing them under their peer.
        for (handle, port) in &accepted {
            if let Some(handles) = self.listeners.get_mut(port) {
                handles.retain(|h| h != handle);
            }
        }
        self.listeners.retain(|_, handles| !handles.is_empty());

        for (handle, port) in accepted {
            // A socket the batch tracking missed counts from the start, which covers it.
            let (start, lifetime) = self
                .inbound
                .remove(&handle)
                .map_or((0, None), |inbound| (inbound.start, inbound.flow));
            let connection = self.adopt(handle, now, start, lifetime);
            tracing::debug!(
                target: "netstack",
                port,
                remote = %connection.peer_addr(),
                "TCP connection accepted"
            );
            // A lifetime revoked meanwhile is not offered; the next turn retires it.
            if !connection.flow().is_revoked() {
                self.offer(connection);
            }
        }
    }

    /// Whether new TCP connections are held back: with `accept_backpressure`, while
    /// connections wait or `incoming_tcp` is full.
    pub(super) fn accept_full(&self) -> bool {
        self.settings.accept_backpressure
            && (!self.waiting.is_empty() || self.accept_tcp.capacity() == 0)
    }

    /// Hands `connection` to `incoming_tcp`; when it is full, keeps it waiting with
    /// `accept_backpressure` and closes it otherwise.
    fn offer(&mut self, connection: TcpConnection) {
        if !self.waiting.is_empty() && self.settings.accept_backpressure {
            return self.waiting.push_back(connection);
        }
        match self.accept_tcp.try_send(connection) {
            Ok(()) => {}
            Err(TrySendError::Full(connection)) if self.settings.accept_backpressure => {
                self.waiting.push_back(connection);
            }
            Err(TrySendError::Full(connection)) => {
                tracing::debug!(target: "netstack", "incoming_tcp full; closing");
                stats::add(&self.stats.tcp_not_accepted, 1);
                connection.flow().undeliver(Undelivered::AcceptQueueFull);
            }
            Err(TrySendError::Closed(connection)) => {
                tracing::debug!(target: "netstack", "incoming_tcp gone; closing");
                stats::add(&self.stats.tcp_not_accepted, 1);
                connection.flow().undeliver(Undelivered::AcceptQueueGone);
            }
        }
    }

    /// Moves waiting connections into `incoming_tcp` while it has room.
    pub(super) fn flush_waiting(&mut self) {
        while let Some(connection) = self.waiting.pop_front() {
            match self.accept_tcp.try_send(connection) {
                Ok(()) => {}
                Err(TrySendError::Full(connection)) => {
                    return self.waiting.push_front(connection);
                }
                Err(TrySendError::Closed(_)) => {
                    stats::add(&self.stats.tcp_not_accepted, 1);
                }
            }
        }
    }

    /// Completes, fails or abandons pending `connect_tcp` calls.
    pub(super) fn finish_connects(&mut self, now: SmolInstant) {
        for connecting in std::mem::take(&mut self.connecting) {
            let Connecting {
                handle,
                _registration: registration,
                reply,
                started,
                start,
            } = connecting;
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
            match socket.state() {
                tcp::State::Established | tcp::State::CloseWait => {
                    socket.set_timeout(None);
                    // A caller that gave up drops the connection, which closes it.
                    let _ = reply.send(Ok(self.adopt(handle, now, start, None)));
                }
                tcp::State::Closed => {
                    self.sockets.remove(handle);
                    let error = if now >= started + CONNECT_TIMEOUT {
                        io::Error::new(io::ErrorKind::TimedOut, "TCP handshake timed out")
                    } else {
                        io::Error::new(io::ErrorKind::ConnectionRefused, "TCP handshake reset")
                    };
                    let _ = reply.send(Err(error));
                }
                _ => {
                    if reply.is_closed() {
                        socket.abort();
                    }
                    self.connecting.push(Connecting {
                        handle,
                        _registration: registration,
                        reply,
                        started,
                        start,
                    });
                }
            }
        }
    }

    /// Registers an established socket as a connection and returns the application side;
    /// `start` is the egress position when the socket took or sent the SYN, and
    /// `lifetime` the state of a SYN accepted under `Admission::Decide`, bound to the
    /// socket.
    fn adopt(
        &mut self,
        handle: SocketHandle,
        now: SmolInstant,
        start: u64,
        lifetime: Option<Arc<FlowState>>,
    ) -> TcpConnection {
        let socket = self.sockets.get::<tcp::Socket<'_>>(handle);
        let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let local = socket
            .local_endpoint()
            .map_or(unspecified, endpoint_to_socket_addr);
        let peer = socket
            .remote_endpoint()
            .map_or(unspecified, endpoint_to_socket_addr);
        let (terminal, terminal_rx) = watch::channel(false);
        let progress = Arc::new(Progress::new(self.epoch.into_std()));
        // Taken before the caller drops the connect's or the handshake's registration.
        let registration = self.owners.tcp(local, peer);
        let bound = lifetime.and_then(|flow| match flow.target() {
            Some(Target::Tcp { shared, .. }) => {
                let shared = Arc::clone(shared);
                flow.mark_adopted();
                Some((flow, shared))
            }
            _ => None,
        });
        let (flow, shared) = bound.unwrap_or_else(|| self.tcp_state(handle, local, peer, start));
        self.conns.insert(
            handle,
            Conn {
                _registration: registration,
                shared: Arc::clone(&shared),
                progress: Arc::clone(&progress),
                queued: 0,
                terminal,
                local_closed: false,
                last_activity_at: now,
                flow: Arc::clone(&flow),
            },
        );
        TcpConnection::new(
            shared,
            progress,
            Arc::clone(&self.notify),
            local,
            peer,
            terminal_rx,
            flow,
        )
    }

    /// Unregisters listener sockets that left the handshake without being established
    /// (reset back to `Listen`, or closed), counting each; the lifetime of an accepted SYN
    /// ends undelivered.
    pub(super) fn release_inbound(&mut self) {
        let (sockets, stats, end) = (&self.sockets, &self.stats, self.position());
        self.inbound.retain(|&handle, inbound| {
            let failed = matches!(
                sockets.get::<tcp::Socket<'_>>(handle).state(),
                tcp::State::Listen | tcp::State::Closed | tcp::State::TimeWait
            );
            if failed {
                stats::add(&stats.handshake_failed, 1);
                if let Some(flow) = &inbound.flow {
                    flow.set_end(end);
                    flow.undeliver(Undelivered::HandshakeFailed);
                }
            }
            !failed
        });
    }

    /// Removes the listener socket `handle` of `port` mid handshake, without an RST: a
    /// revoked lifetime.
    pub(super) fn release_handshake(&mut self, handle: SocketHandle, port: u16) {
        self.inbound.remove(&handle);
        if let Some(handles) = self.listeners.get_mut(&port) {
            handles.retain(|&listener| listener != handle);
            if handles.is_empty() {
                self.listeners.remove(&port);
            }
        }
        self.sockets.remove(handle);
    }

    /// Registers the tuples of listener sockets a SYN of this batch moved into
    /// `SynReceived`, before their SYN-ACK leaves, with `mark`, the egress position before
    /// the batch. A socket that took a SYN accepted under `Admission::Decide` becomes the
    /// target of its lifetime; an accepted SYN no socket took ends undelivered.
    pub(super) fn track_inbound(&mut self, demand: &HashMap<u16, usize>, mark: u64) {
        for port in demand.keys() {
            let Some(handles) = self.listeners.get(port) else {
                continue;
            };
            for &handle in handles {
                let socket = self.sockets.get::<tcp::Socket<'_>>(handle);
                if socket.state() != tcp::State::SynReceived {
                    continue;
                }
                let (Some(local), Some(remote)) =
                    (socket.local_endpoint(), socket.remote_endpoint())
                else {
                    continue;
                };
                let (local, remote) = (
                    endpoint_to_socket_addr(local),
                    endpoint_to_socket_addr(remote),
                );
                if self
                    .inbound
                    .get(&handle)
                    .is_none_or(|inbound| !inbound.registration.is(local, remote))
                {
                    let flow = self
                        .pending
                        .as_mut()
                        .and_then(|table| table.take_admitted(local, remote));
                    if let Some(flow) = &flow {
                        flow.bind(Target::Tcp {
                            handle,
                            shared: Arc::new(Mutex::new(Shared::new(self.settings.stream_buffer))),
                            local,
                            peer: remote,
                            start: mark,
                        });
                    }
                    let registration = self.owners.tcp(local, remote);
                    self.inbound.insert(
                        handle,
                        Inbound {
                            registration,
                            start: mark,
                            flow,
                        },
                    );
                }
            }
        }
        if let Some(table) = self.pending.as_mut() {
            table.refuse_admitted();
        }
    }
}
