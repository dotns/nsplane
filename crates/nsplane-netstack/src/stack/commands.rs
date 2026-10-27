//! The driver side of the handle's commands: opening connections and sockets.

use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

use crate::flow::{FlowState, Target};
use crate::ownership::Registration;
use crate::udp::UdpSocket;

use super::accept::Connecting;
use super::handle::Command;
use super::listeners::new_tcp_socket;
use super::{COMMAND_CAPACITY, CONNECT_TIMEOUT, Driver, EPHEMERAL_START};

impl Driver {
    /// Handles queued requests from handles.
    pub(super) fn take_commands(&mut self) {
        for _ in 0..COMMAND_CAPACITY {
            let Some(commands) = &mut self.commands else {
                return;
            };
            match commands.try_recv() {
                Ok(command) => self.command(command),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.commands = None;
                    return;
                }
            }
        }
    }

    pub(super) fn command(&mut self, command: Command) {
        if let Command::Connect {
            local_port: Some(port),
            ..
        } = command
            && self.aborting_port(port)
        {
            // The abort releases the port later in this turn.
            self.deferred.push(command);
            return;
        }
        match command {
            Command::Connect {
                remote,
                local_port,
                registration,
                reply,
            } => match self.open_connect(remote, local_port, registration) {
                Ok((handle, registration)) => self.connecting.push(Connecting {
                    handle,
                    _registration: registration,
                    reply,
                    started: self.now(),
                    start: self.position(),
                }),
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Command::Bind { local, reply } => {
                let _ = reply.send(self.bind(local));
            }
            Command::ConnectUdp {
                local,
                remote,
                reply,
            } => {
                let _ = reply.send(self.connect_udp(local, remote));
            }
        }
    }

    /// Starts a handshake to `remote` from `local_port`, or an ephemeral port, keeping
    /// its tuple registered (`registration` already holds it for an explicit port).
    fn open_connect(
        &mut self,
        remote: SocketAddr,
        local_port: Option<u16>,
        registration: Option<Registration>,
    ) -> io::Result<(SocketHandle, Registration)> {
        if remote.port() == 0 || remote.ip().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote address or port is unspecified",
            ));
        }
        let local = self.settings.local_for(remote.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "the stack has no address of the remote's family",
            )
        })?;
        let port = match local_port {
            Some(port) if self.tcp_ports_in_use().contains(&port) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "local port already in use",
                ));
            }
            Some(port) => port,
            None => self.ephemeral_tcp_port().ok_or_else(|| {
                io::Error::new(io::ErrorKind::AddrInUse, "no free ephemeral port")
            })?,
        };
        let mut socket = new_tcp_socket(
            self.settings.tcp_rx_buffer(),
            self.settings.tcp_tx_buffer(),
            self.settings.tcp_rto,
        );
        socket.set_timeout(Some(CONNECT_TIMEOUT));
        socket
            .connect(
                self.iface.context(),
                IpEndpoint::new(remote.ip().into(), remote.port()),
                IpEndpoint::new(local.into(), port),
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        // Registered before the driver's next poll emits the SYN.
        let registration =
            registration.unwrap_or_else(|| self.owners.tcp(SocketAddr::new(local, port), remote));
        Ok((self.sockets.add(socket), registration))
    }

    /// The local ports of the stack's TCP connections (open or opening) and listeners.
    fn tcp_ports_in_use(&self) -> HashSet<u16> {
        self.conns
            .keys()
            .chain(self.connecting.iter().map(|connecting| &connecting.handle))
            .filter_map(|&handle| self.sockets.get::<tcp::Socket<'_>>(handle).local_endpoint())
            .map(|endpoint| endpoint.port)
            .chain(self.listeners.keys().copied())
            .collect()
    }

    /// The next ephemeral port no connection or listener uses.
    fn ephemeral_tcp_port(&mut self) -> Option<u16> {
        let used = self.tcp_ports_in_use();
        next_ephemeral(&mut self.next_tcp_port, |port| !used.contains(&port))
    }

    /// Binds a UDP socket, see [`NetStackHandle::bind_udp`].
    fn bind(&mut self, local: SocketAddr) -> io::Result<UdpSocket> {
        let not_available = || {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "not an address of the stack",
            )
        };
        let source = self
            .settings
            .local_for(local.ip())
            .ok_or_else(not_available)?;
        if !local.ip().is_unspecified() && local.ip() != source {
            return Err(not_available());
        }
        let port = if local.port() == 0 {
            let bound = &self.bound;
            next_ephemeral(&mut self.next_udp_port, |port| {
                !bound.contains_key(&SocketAddr::new(local.ip(), port))
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "no free ephemeral port"))?
        } else {
            local.port()
        };
        let addr = SocketAddr::new(local.ip(), port);
        if self.bound.get(&addr).is_some_and(|(tx, _)| !tx.is_closed()) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "address already bound",
            ));
        }
        let (tx, rx) = mpsc::channel(self.settings.datagram_capacity);
        let flow = FlowState::new(Target::UdpBound(addr), None, &self.revocations);
        self.bound.insert(addr, (tx, Arc::clone(&flow)));
        let registration = self.owners.udp_bound(addr);
        Ok(UdpSocket::new(
            registration,
            addr,
            source,
            None,
            rx,
            self.out.clone(),
            flow,
        ))
    }

    /// Connects a UDP socket, see [`NetStackHandle::connect_udp_from`].
    fn connect_udp(&mut self, local: SocketAddr, remote: SocketAddr) -> io::Result<UdpSocket> {
        if remote.port() == 0 || remote.ip().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote address or port is unspecified",
            ));
        }
        if local.is_ipv4() != remote.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "address families differ",
            ));
        }
        let source = self.settings.local_for(remote.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "the stack has no address of the remote's family",
            )
        })?;
        if !local.ip().is_unspecified() && local.ip() != source {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "not an address of the stack",
            ));
        }
        // Dropped sockets leave the table here too, so it empties when none is live.
        self.connected.retain(|_, (tx, _)| !tx.is_closed());
        let port = if local.port() == 0 {
            let (bound, connected) = (&self.bound, &self.connected);
            let any = unspecified(source);
            next_ephemeral(&mut self.next_udp_port, |port| {
                let addr = SocketAddr::new(source, port);
                !bound.contains_key(&addr)
                    && !bound.contains_key(&SocketAddr::new(any, port))
                    && !connected.keys().any(|&(_, local)| local == addr)
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "no free ephemeral port"))?
        } else {
            local.port()
        };
        let local = SocketAddr::new(source, port);
        let key = (remote, local);
        if self.connected.contains_key(&key)
            || self.flows.get(&key).is_some_and(|(tx, _)| !tx.is_closed())
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "UDP tuple already in use",
            ));
        }
        let (tx, rx) = mpsc::channel(self.settings.datagram_capacity);
        let flow = FlowState::new(Target::UdpConnected(key), None, &self.revocations);
        self.connected.insert(key, (tx, Arc::clone(&flow)));
        let registration = self.owners.udp_flow(local, remote);
        Ok(UdpSocket::new(
            registration,
            local,
            source,
            Some(remote),
            rx,
            self.out.clone(),
            flow,
        ))
    }
}

/// The unspecified address of `ip`'s family.
pub(super) const fn unspecified(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// A random port of the ephemeral range, where a stack starts handing out ports, so that
/// stacks (and restarts) do not reuse the same ports in the same order.
pub(super) fn random_ephemeral() -> u16 {
    let span = u64::from(u16::MAX - EPHEMERAL_START) + 1;
    let offset = RandomState::new().build_hasher().finish() % span;
    // `offset` < `span` <= 2^16, so it fits, and the sum stays within the range.
    EPHEMERAL_START.saturating_add(u16::try_from(offset).unwrap_or(0))
}

/// Takes the next port from `cursor` (cycling through the ephemeral range) that `free`
/// accepts.
fn next_ephemeral(cursor: &mut u16, free: impl Fn(u16) -> bool) -> Option<u16> {
    for _ in EPHEMERAL_START..=u16::MAX {
        let port = *cursor;
        *cursor = if port == u16::MAX {
            EPHEMERAL_START
        } else {
            port + 1
        };
        if free(port) {
            return Some(port);
        }
    }
    None
}
