//! Creating and setting up the socket, and the address mapping of dual-stack sockets.

use std::io;
#[cfg(any(windows, test))]
use std::net::{Ipv4Addr, Ipv6Addr};
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

/// Creates a dual-stack IPv6 socket bound to `addr`. Linux refuses the bind while another
/// socket holds the port for IPv4.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn bind_dual_stack(addr: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// Creates a dual-stack IPv6 socket bound to `addr`.
///
/// macOS and the BSDs accept the bind while another socket holds the port for IPv4, and
/// deliver the IPv4 datagrams to that socket only, so the port is first probed for IPv4
/// ([`free_for_ipv4`]).
#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
pub(super) fn bind_dual_stack(addr: SocketAddr) -> io::Result<Socket> {
    let mut tries = 0;
    loop {
        let chosen = SocketAddr::new(addr.ip(), free_for_ipv4(addr.port())?);
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        match socket.bind(&chosen.into()) {
            // A port chosen for being free for IPv4 is taken for IPv6: another one.
            Err(e)
                if addr.port() == 0
                    && tries < PAIR_TRIES
                    && e.kind() == io::ErrorKind::AddrInUse =>
            {
                tries += 1;
            }
            bound => return bound.map(|()| socket),
        }
    }
}

/// A port no socket holds for IPv4: `port`, or for 0 one the OS chose. The probe socket is
/// closed again, since the dual-stack socket bound next owns the IPv4 side once it is bound.
/// [`io::ErrorKind::AddrInUse`] if `port` is taken; a host without IPv4 passes.
#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
fn free_for_ipv4(port: u16) -> io::Result<u16> {
    match bind_socket((std::net::Ipv4Addr::UNSPECIFIED, port).into()) {
        Ok(probe) => Ok(probe
            .local_addr()?
            .as_socket()
            .map_or(port, |addr| addr.port())),
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => Err(e),
        Err(_) => Ok(port),
    }
}

/// Binds the two sockets that stand for `[::]:port` where a dual-stack socket does not own
/// the IPv4 side of its port (Windows): an IPv6-only socket and, on the same port, an
/// IPv4 one. For port 0 a port the OS chose for IPv6 that is taken for IPv4 is given up
/// for another one. If the IPv6 socket cannot be had for another reason than a port in
/// use, `0.0.0.0:port` is bound alone. A failure leaves nothing bound.
#[cfg(any(windows, test))]
pub(super) fn bind_pair(port: u16) -> io::Result<(Socket, Option<Socket>)> {
    let mut tries = 0;
    loop {
        let v6 = match bind_v6_only(port) {
            Err(e) if e.kind() != io::ErrorKind::AddrInUse => {
                return Ok((bind_socket((Ipv4Addr::UNSPECIFIED, port).into())?, None));
            }
            bound => bound?,
        };
        let chosen = v6
            .local_addr()?
            .as_socket()
            .map_or(port, |addr| addr.port());
        match bind_socket((Ipv4Addr::UNSPECIFIED, chosen).into()) {
            Ok(v4) => return Ok((v6, Some(v4))),
            Err(e)
                if port == 0
                    && tries < PAIR_TRIES
                    && matches!(
                        e.kind(),
                        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                    ) =>
            {
                tries += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// How many more ephemeral ports a bind of `[::]:0` tries after one that is taken for the
/// other address family.
#[cfg(any(windows, test, not(any(target_os = "linux", target_os = "android"))))]
const PAIR_TRIES: usize = 16;

/// Creates an IPv6-only socket bound to `[::]:port`, on Windows for its exclusive use as
/// [`bind_socket`] does.
#[cfg(any(windows, test))]
fn bind_v6_only(port: u16) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    #[cfg(windows)]
    nsplane_sys::set_exclusive_address_use(&socket, true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    Ok(socket)
}

/// The address the IPv4 socket of a [`bind_pair`] sends `addr` to: an IPv4 address as it
/// is and an IPv4-mapped IPv6 address unmapped; `None` for the addresses its IPv6-only
/// socket sends to.
#[cfg(any(windows, test))]
pub(super) fn ipv4_destination(addr: SocketAddr) -> Option<SocketAddr> {
    Some(unmap(addr)).filter(SocketAddr::is_ipv4)
}

/// Creates a UDP socket bound to exactly `addr`.
///
/// On Windows the socket gets `SO_EXCLUSIVEADDRUSE` first: next to a plain socket on a
/// wildcard address anyone of the same user binds one local address of the port and takes
/// the datagrams sent to it. Other platforms refuse that bind without an option.
pub(super) fn bind_socket(addr: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    #[cfg(windows)]
    nsplane_sys::set_exclusive_address_use(&socket, true)?;
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
