//! Winsock calls.

use std::io;
use std::os::windows::io::{AsRawSocket, AsSocket};

use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET, SOCKET_ERROR, SOL_SOCKET, setsockopt,
};

/// The size in bytes of a Winsock `BOOL` option value.
const BOOL_LEN: i32 = 4;

/// Turns exclusive use of the local address on or off for `socket`
/// (`SO_EXCLUSIVEADDRUSE`). Windows only.
///
/// A socket bound to a wildcard address with the option on owns every local address of its
/// port in its address family: a later bind of the wildcard address or of one local
/// address fails with `WSAEADDRINUSE` or `WSAEACCES`, whatever options that socket sets.
/// The bind of the socket itself fails with `WSAEADDRINUSE` while another socket holds any
/// address of the port. Without the option, a second socket of the same user binds one
/// local address of the port and receives the datagrams sent to it.
///
/// The option is for a socket that is not bound yet: the results above are those of
/// setting it before `bind`, and the call does not fail on a bound socket. It excludes
/// `SO_REUSEADDR` on the same socket.
///
/// # Errors
///
/// The error of `setsockopt`: `WSAEINVAL` ([`io::ErrorKind::InvalidInput`]) for a socket
/// that has `SO_REUSEADDR` set.
pub fn set_exclusive_address_use(socket: &impl AsSocket, exclusive: bool) -> io::Result<()> {
    let socket = socket.as_socket();
    let handle = SOCKET::try_from(socket.as_raw_socket())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let value: [u8; 4] = i32::from(exclusive).to_ne_bytes();
    #[allow(unsafe_code, reason = "Winsock FFI call")]
    // SAFETY: `handle` is the open socket `socket` borrows, so it stays open for the call;
    // `value` is readable for the `BOOL_LEN` bytes of the `BOOL` the option takes and
    // outlives the call, which copies it and keeps no pointer.
    let result = unsafe {
        setsockopt(
            handle,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            value.as_ptr(),
            BOOL_LEN,
        )
    };
    if result == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    /// A UDP socket bound to `0.0.0.0` on a port the OS chose after `set_up` ran on it,
    /// and that port.
    fn wildcard(set_up: impl FnOnce(&Socket)) -> (Socket, u16) {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        set_up(&socket);
        socket
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
            .unwrap();
        let port = socket.local_addr().unwrap().as_socket().unwrap().port();
        (socket, port)
    }

    /// With the option on, nobody binds a local address of the socket's port. Windows
    /// answers `WSAEACCES`, wine `WSAEADDRINUSE`.
    #[test]
    fn exclusive_socket_keeps_the_local_addresses_of_its_port() {
        let (_socket, port) = wildcard(|socket| set_exclusive_address_use(socket, true).unwrap());
        let err = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap_err();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse
        ));
    }

    /// Without the option, and with the option turned off again, the bind succeeds.
    #[test]
    #[ignore = "wine refuses the bind next to any socket on the port"]
    fn plain_socket_shares_the_local_addresses_of_its_port() {
        let (_socket, port) = wildcard(|_| ());
        UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();

        let (_socket, port) = wildcard(|socket| {
            set_exclusive_address_use(socket, true).unwrap();
            set_exclusive_address_use(socket, false).unwrap();
        });
        UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    }

    /// The error of the call is returned: the option excludes `SO_REUSEADDR`.
    #[test]
    fn socket_with_reuse_address_is_refused() {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket.set_reuse_address(true).unwrap();
        let err = set_exclusive_address_use(&socket, true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
