//! Creating and setting up the socket, and the address mapping of dual-stack sockets.

use std::io;
use std::net::{SocketAddr, SocketAddrV6};

use quinn_udp::{UdpSockRef, UdpSocketState};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// Maps `addr` to the address family of a socket bound to `local`.
pub(super) fn target(local: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
    match (local, addr) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => {
            Ok(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0).into())
        }
        (SocketAddr::V4(_), SocketAddr::V6(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 destination on an IPv4 socket",
        )),
        _ => Ok(addr),
    }
}

/// Creates a dual-stack IPv6 socket bound to `addr`.
pub(super) fn bind_dual_stack(addr: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// Creates a UDP socket bound to exactly `addr`.
pub(super) fn bind_socket(addr: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// Sets `socket` up for `quinn-udp`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn set_up(socket: &UdpSocket) -> io::Result<UdpSocketState> {
    let state = UdpSocketState::new(UdpSockRef::from(socket))?;
    // Receive timestamps are not used, and their control message would crowd out the ECN
    // mark of a coalesced read from `quinn-udp`'s control buffer.
    nix::sys::socket::setsockopt(
        socket,
        nix::sys::socket::sockopt::ReceiveTimestampns,
        &false,
    )?;
    Ok(state)
}

/// Sets `socket` up for `quinn-udp`; `None` where it cannot.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) fn set_up(socket: &UdpSocket) -> Option<UdpSocketState> {
    UdpSocketState::new(UdpSockRef::from(socket))
        .inspect_err(|e| tracing::debug!(message = "Plain UDP sends", error = ?e))
        .ok()
}

/// Turns an IPv4-mapped IPv6 address back into an IPv4 address.
pub(super) fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(addr, |ip| (ip, v6.port()).into()),
        SocketAddr::V4(_) => addr,
    }
}
