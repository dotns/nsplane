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

use crate::flow::{FlowState, Target};
use crate::ownership::Registration;
use crate::stats::{self};
use crate::tcp::{Progress, Shared, TcpConnection};

use super::connections::Conn;
use super::listeners::tcp_listener_ready_for_promotion;
use super::wire::endpoint_to_socket_addr;
use super::{CONNECT_TIMEOUT, Driver};

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
            let start = self.inbound.get(&handle).map_or(0, |&(_, start)| start);
            let connection = self.adopt(handle, now, start);
            self.inbound.remove(&handle);
            tracing::debug!(
                target: "netstack",
                port,
                remote = %connection.peer_addr(),
                "TCP connection accepted"
            );
            self.offer(connection);
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
            Err(_) => {
                tracing::debug!(target: "netstack", "incoming_tcp full or gone; closing");
                stats::add(&self.stats.tcp_not_accepted, 1);
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
                    let _ = reply.send(Ok(self.adopt(handle, now, start)));
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
    /// `start` is the egress position when the socket took or sent the SYN.
    fn adopt(&mut self, handle: SocketHandle, now: SmolInstant, start: u64) -> TcpConnection {
        let socket = self.sockets.get::<tcp::Socket<'_>>(handle);
        let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let local = socket
            .local_endpoint()
            .map_or(unspecified, endpoint_to_socket_addr);
        let peer = socket
            .remote_endpoint()
            .map_or(unspecified, endpoint_to_socket_addr);
        let shared = Arc::new(Mutex::new(Shared::new(self.settings.stream_buffer)));
        let (terminal, terminal_rx) = watch::channel(false);
        let progress = Arc::new(Progress::new(self.epoch.into_std()));
        // Taken before the caller drops the connect's or the handshake's registration.
        let registration = self.owners.tcp(local, peer);
        let flow = FlowState::new(
            Target::Tcp {
                handle,
                shared: Arc::clone(&shared),
                local,
                peer,
                start,
            },
            &self.revocations,
        );
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
    /// (reset back to `Listen`, or closed).
    pub(super) fn release_inbound(&mut self) {
        let sockets = &self.sockets;
        self.inbound.retain(|&handle, _| {
            !matches!(
                sockets.get::<tcp::Socket<'_>>(handle).state(),
                tcp::State::Listen | tcp::State::Closed | tcp::State::TimeWait
            )
        });
    }

    /// Registers the tuples of listener sockets a SYN of this batch moved into
    /// `SynReceived`, before their SYN-ACK leaves, with `mark`, the egress position before
    /// the batch.
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
                    .is_none_or(|(registration, _)| !registration.is(local, remote))
                {
                    self.inbound
                        .insert(handle, (self.owners.tcp(local, remote), mark));
                }
            }
        }
    }
}
