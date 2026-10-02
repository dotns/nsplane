//! The default network-side transport: one tokio UDP socket.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV6};

use nsplane_packet::{PacketBuf, Path, TransportId};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::transport::Transport;

/// A [`Transport`] over one UDP socket.
///
/// Bound to `[::]:port` the socket is dual-stack: IPv4 peers are reported in
/// [`Path::addr`] as plain IPv4 addresses, and IPv4 destinations are sent to as
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`). On an IPv4 socket, sending to an IPv6
/// address fails with [`io::ErrorKind::InvalidInput`].
///
/// ECN: on Linux and Android the TOS / traffic class byte of each received datagram is
/// read from its `recvmsg` control message (`IP_RECVTOS`, `IPV6_RECVTCLASS`) and
/// reported in [`Path::ecn`]; on send, `to.ecn` is set per datagram with an `IP_TOS` or
/// `IPV6_TCLASS` control message on `sendmsg`, so no socket-wide state changes. On other
/// platforms (macOS, iOS, Windows) received datagrams report [`Ecn::NotEct`](nsplane_packet::Ecn::NotEct) and `to.ecn`
/// is ignored.
///
/// Windows: a datagram larger than the receive buffer is truncated as on other
/// platforms, although `recvfrom` reports it as `WSAEMSGSIZE`; its sender is peeked
/// before the receive. ICMP port-unreachable errors, which Windows reports on a later
/// receive as `WSAECONNRESET`, are skipped and receiving continues.
///
/// The transport never closes: it lives as long as its socket.
#[derive(Debug)]
pub struct UdpTransport {
    id: TransportId,
    local: SocketAddr,
    socket: UdpSocket,
}

impl UdpTransport {
    /// Binds a non-blocking UDP socket to `addr`.
    ///
    /// For the IPv6 unspecified address (`[::]:port`) the socket is dual-stack
    /// (`IPV6_V6ONLY` off). If IPv6 is unavailable on the host, it binds `0.0.0.0:port`
    /// instead and serves IPv4 only; [`local_addr`](Self::local_addr) tells which. Any
    /// other address is bound exactly.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime with I/O enabled.
    pub fn bind(id: TransportId, addr: SocketAddr) -> io::Result<Self> {
        let socket = match addr {
            SocketAddr::V6(v6) if v6.ip().is_unspecified() => match bind_dual_stack(addr) {
                Err(e) if e.kind() != io::ErrorKind::AddrInUse => {
                    bind_socket((Ipv4Addr::UNSPECIFIED, addr.port()).into())?
                }
                bound => bound?,
            },
            _ => bind_socket(addr)?,
        };
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket.into())?;
        let local = socket.local_addr()?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        linux::enable_ecn(&socket, local)?;
        Ok(Self { id, local, socket })
    }

    /// The bound address (with the OS-chosen port when bound to port 0).
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Sets the socket's firewall mark (`SO_MARK`); needs `CAP_NET_ADMIN`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        socket2::SockRef::from(&self.socket).set_mark(mark)
    }

    /// Maps `addr` to the socket's address family.
    fn target(&self, addr: SocketAddr) -> io::Result<SocketAddr> {
        match (self.local, addr) {
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
}

impl Transport for UdpTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        buf.set_len(buf.capacity());
        let (len, addr, ecn) = self
            .recv_from(buf.as_packet_mut())
            .await
            .inspect_err(|_| buf.set_len(0))?;
        buf.set_len(len);
        let path = Path {
            transport: self.id,
            addr: unmap(addr),
            ecn,
        };
        Ok((len, path))
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        let target = self.target(to.addr)?;
        self.send_to(datagram, target, to.ecn).await
    }
}

/// Creates a dual-stack IPv6 socket bound to `addr`.
fn bind_dual_stack(addr: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// Creates a UDP socket bound to exactly `addr`.
fn bind_socket(addr: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// Turns an IPv4-mapped IPv6 address back into an IPv4 address.
fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(addr, |ip| (ip, v6.port()).into()),
        SocketAddr::V4(_) => addr,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    //! `recvmsg` / `sendmsg` with TOS and traffic class control messages.

    use std::io::{self, IoSlice, IoSliceMut};
    use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, sendmsg,
    };
    use nsplane_packet::Ecn;
    use socket2::SockRef;
    use tokio::io::Interest;
    use tokio::net::UdpSocket;

    use super::UdpTransport;

    /// Control-message buffer, aligned for `cmsghdr`; holds one TOS or traffic class
    /// message (24 bytes on 64-bit targets) with room to spare.
    #[repr(C, align(8))]
    struct CmsgBuf([u8; 64]);

    /// Asks for the TOS (IPv4, including IPv4-mapped peers of a dual-stack socket) and
    /// traffic class (IPv6) of every received datagram.
    pub(super) fn enable_ecn(socket: &UdpSocket, local: SocketAddr) -> io::Result<()> {
        let socket = SockRef::from(socket);
        socket.set_recv_tos_v4(true)?;
        if local.is_ipv6() {
            socket.set_recv_tclass_v6(true)?;
        }
        Ok(())
    }

    impl UdpTransport {
        pub(super) async fn recv_from(
            &self,
            packet: &mut [u8],
        ) -> io::Result<(usize, SocketAddr, Ecn)> {
            let fd = self.socket.as_raw_fd();
            self.socket
                .async_io(Interest::READABLE, || {
                    let mut iov = [IoSliceMut::new(&mut *packet)];
                    let mut cmsg = CmsgBuf([0; 64]);
                    let msg = recvmsg::<SockaddrStorage>(
                        fd,
                        &mut iov,
                        Some(&mut cmsg.0),
                        MsgFlags::empty(),
                    )?;
                    let addr = msg.address.as_ref().and_then(socket_addr).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "datagram without source")
                    })?;
                    // A truncated control buffer only loses the ECN mark.
                    let ecn =
                        msg.cmsgs()
                            .ok()
                            .into_iter()
                            .flatten()
                            .fold(Ecn::NotEct, |ecn, cmsg| match cmsg {
                                ControlMessageOwned::Ipv4Tos(tos) => Ecn::from_bits(tos),
                                ControlMessageOwned::Ipv6TClass(tclass) => {
                                    u8::try_from(tclass & 0xFF).map_or(ecn, Ecn::from_bits)
                                }
                                _ => ecn,
                            });
                    Ok((msg.bytes, addr, ecn))
                })
                .await
        }

        pub(super) async fn send_to(
            &self,
            datagram: &[u8],
            to: SocketAddr,
            ecn: Ecn,
        ) -> io::Result<()> {
            let fd = self.socket.as_raw_fd();
            let dest = SockaddrStorage::from(to);
            let tos = ecn.to_bits();
            let tclass = i32::from(tos);
            // IPv4 and IPv4-mapped destinations take IP_TOS, even on an IPv6 socket.
            let cmsg = match to {
                _ if ecn == Ecn::NotEct => None,
                SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_none() => {
                    Some(ControlMessage::Ipv6TClass(&tclass))
                }
                _ => Some(ControlMessage::Ipv4Tos(&tos)),
            };
            self.socket
                .async_io(Interest::WRITABLE, || {
                    sendmsg(
                        fd,
                        &[IoSlice::new(datagram)],
                        cmsg.as_slice(),
                        MsgFlags::empty(),
                        Some(&dest),
                    )
                    .map_err(io::Error::from)
                })
                .await
                .map(drop)
        }
    }

    fn socket_addr(addr: &SockaddrStorage) -> Option<SocketAddr> {
        addr.as_sockaddr_in()
            .map(|v4| SocketAddrV4::from(*v4).into())
            .or_else(|| {
                addr.as_sockaddr_in6()
                    .map(|v6| SocketAddrV6::from(*v6).into())
            })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod other {
    //! Plain `recv_from` / `send_to`: no ECN.

    use std::io;
    use std::net::SocketAddr;

    use nsplane_packet::Ecn;

    use super::UdpTransport;

    impl UdpTransport {
        #[cfg(not(windows))]
        pub(super) async fn recv_from(
            &self,
            packet: &mut [u8],
        ) -> io::Result<(usize, SocketAddr, Ecn)> {
            let (len, addr) = self.socket.recv_from(packet).await?;
            Ok((len, addr, Ecn::NotEct))
        }

        pub(super) async fn send_to(
            &self,
            datagram: &[u8],
            to: SocketAddr,
            _ecn: Ecn,
        ) -> io::Result<()> {
            self.socket.send_to(datagram, to).await.map(drop)
        }
    }
}

#[cfg(windows)]
mod windows {
    //! `recv_from` mapped to the transport contract: truncation instead of `WSAEMSGSIZE`
    //! and no `WSAECONNRESET`.

    use std::io;
    use std::net::SocketAddr;

    use nsplane_packet::Ecn;

    use super::UdpTransport;

    /// `WSAEMSGSIZE`: the datagram did not fit; the buffer holds its first bytes and the
    /// rest is discarded.
    const WSAEMSGSIZE: i32 = 10040;

    impl UdpTransport {
        /// Receives one datagram, truncating it to `packet`.
        ///
        /// A truncated `recvfrom` fails without reporting the sender, so the sender is
        /// peeked first. With several tasks receiving on the same transport, another task
        /// may take the peeked datagram in between, and a truncated datagram is then
        /// attributed to the wrong sender; datagrams that fit are always attributed
        /// correctly. `WSAECONNRESET` (an ICMP port-unreachable for an earlier send) is
        /// transient for an unconnected socket: it is skipped and receiving continues,
        /// which needs no `SIO_UDP_CONNRESET` ioctl and so no unsafe code. A truncated
        /// datagram whose sender could not be peeked is dropped.
        pub(super) async fn recv_from(
            &self,
            packet: &mut [u8],
        ) -> io::Result<(usize, SocketAddr, Ecn)> {
            loop {
                self.socket.readable().await?;
                let sender = match self.socket.try_peek_sender() {
                    Ok(addr) => Some(addr),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => None,
                    Err(e) => return Err(e),
                };
                match self.socket.try_recv_from(packet) {
                    Ok((len, addr)) => return Ok((len, addr, Ecn::NotEct)),
                    Err(e) if e.raw_os_error() == Some(WSAEMSGSIZE) => {
                        if let Some(addr) = sender {
                            return Ok((packet.len(), addr, Ecn::NotEct));
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionReset
                        ) => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsplane_packet::{Ecn, HEADROOM};
    use std::time::Duration;
    use tokio::time::timeout;

    const DATAGRAM: &[u8] = b"wireguard datagram";

    fn bind(id: u16, addr: &str) -> UdpTransport {
        UdpTransport::bind(TransportId::new(id), addr.parse().unwrap()).unwrap()
    }

    fn path_to(addr: SocketAddr, ecn: Ecn) -> Path {
        Path {
            transport: TransportId::new(0),
            addr,
            ecn,
        }
    }

    /// The address peers see for `transport` when it sends over `ip`.
    fn seen_as(transport: &UdpTransport, ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), transport.local_addr().port())
    }

    /// Receives one datagram into a buffer whose headroom is filled with a marker.
    async fn recv(transport: &UdpTransport, capacity: usize) -> (PacketBuf, Path) {
        let mut buf = PacketBuf::with_capacity(capacity);
        buf.with_headroom_mut().fill(0xAA);
        let (len, path) = timeout(Duration::from_secs(5), transport.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(len, buf.len());
        assert!(
            buf.with_headroom_mut()[..HEADROOM]
                .iter()
                .all(|&b| b == 0xAA)
        );
        (buf, path)
    }

    async fn roundtrip(
        from: &UdpTransport,
        from_addr: SocketAddr,
        to: &UdpTransport,
        to_addr: SocketAddr,
    ) {
        from.send(DATAGRAM, &path_to(to_addr, Ecn::NotEct))
            .await
            .unwrap();
        let (buf, path) = recv(to, 1500).await;
        assert_eq!(buf.as_packet(), DATAGRAM);
        assert_eq!(path.transport, to.id());
        assert_eq!(path.addr, from_addr);
        assert_eq!(path.ecn, Ecn::NotEct);
    }

    #[tokio::test]
    async fn ipv4_roundtrip() {
        let a = bind(1, "127.0.0.1:0");
        let b = bind(2, "127.0.0.1:0");
        assert_eq!(a.id(), TransportId::new(1));
        roundtrip(&a, a.local_addr(), &b, b.local_addr()).await;
        roundtrip(&b, b.local_addr(), &a, a.local_addr()).await;
    }

    #[tokio::test]
    async fn truncates_into_small_buffer() {
        let a = bind(1, "127.0.0.1:0");
        let b = bind(2, "127.0.0.1:0");
        let mut small = PacketBuf::with_capacity(4);
        let capacity = small.capacity();
        assert!(capacity < DATAGRAM.len());
        a.send(DATAGRAM, &path_to(b.local_addr(), Ecn::NotEct))
            .await
            .unwrap();
        small.with_headroom_mut().fill(0xAA);
        let (len, path) = b.recv(&mut small).await.unwrap();
        assert_eq!(len, capacity);
        assert_eq!(small.as_packet(), &DATAGRAM[..capacity]);
        assert!(
            small.with_headroom_mut()[..HEADROOM]
                .iter()
                .all(|&b| b == 0xAA)
        );
        assert_eq!(path.addr, a.local_addr());
    }

    /// An ICMP port-unreachable for an earlier send must not fail a later receive
    /// (Windows reports it as `WSAECONNRESET`).
    #[tokio::test]
    async fn port_unreachable_does_not_fail_recv() {
        let a = bind(1, "127.0.0.1:0");
        let b = bind(2, "127.0.0.1:0");
        let closed = bind(3, "127.0.0.1:0").local_addr();
        a.send(DATAGRAM, &path_to(closed, Ecn::NotEct))
            .await
            .unwrap();
        b.send(DATAGRAM, &path_to(a.local_addr(), Ecn::NotEct))
            .await
            .unwrap();
        let (buf, path) = recv(&a, 1500).await;
        assert_eq!(buf.as_packet(), DATAGRAM);
        assert_eq!(path.addr, b.local_addr());
    }

    #[tokio::test]
    async fn ipv6_roundtrip() {
        let a = bind(1, "[::1]:0");
        let b = bind(2, "[::1]:0");
        roundtrip(&a, a.local_addr(), &b, b.local_addr()).await;
        roundtrip(&b, b.local_addr(), &a, a.local_addr()).await;
    }

    #[tokio::test]
    async fn dual_stack_unmaps_ipv4_peers() {
        let dual = bind(1, "[::]:0");
        assert!(dual.local_addr().is_ipv6());
        let v4 = bind(2, "127.0.0.1:0");
        let v6 = bind(3, "[::1]:0");
        roundtrip(&v4, v4.local_addr(), &dual, seen_as(&dual, "127.0.0.1")).await;
        roundtrip(&dual, seen_as(&dual, "127.0.0.1"), &v4, v4.local_addr()).await;
        roundtrip(&v6, v6.local_addr(), &dual, seen_as(&dual, "::1")).await;
        roundtrip(&dual, seen_as(&dual, "::1"), &v6, v6.local_addr()).await;
    }

    #[tokio::test]
    async fn ipv4_socket_rejects_ipv6_destination() {
        let a = bind(1, "127.0.0.1:0");
        let err = a
            .send(DATAGRAM, &path_to("[::1]:9".parse().unwrap(), Ecn::NotEct))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Sends one datagram per ECN codepoint from `from` to `to` and checks the mark `to`
    /// observes.
    async fn ecn_marks(from: &UdpTransport, to: &UdpTransport, to_addr: SocketAddr) {
        for ecn in [Ecn::Ect0, Ecn::Ect1, Ecn::Ce, Ecn::NotEct] {
            from.send(DATAGRAM, &path_to(to_addr, ecn)).await.unwrap();
            let (_, path) = recv(to, 1500).await;
            let expected = if cfg!(any(target_os = "linux", target_os = "android")) {
                ecn
            } else {
                Ecn::NotEct
            };
            assert_eq!(path.ecn, expected);
        }
    }

    #[tokio::test]
    async fn ecn_ipv4() {
        let a = bind(1, "127.0.0.1:0");
        let b = bind(2, "127.0.0.1:0");
        ecn_marks(&a, &b, b.local_addr()).await;
    }

    #[tokio::test]
    async fn ecn_ipv6() {
        let a = bind(1, "[::1]:0");
        let b = bind(2, "[::1]:0");
        ecn_marks(&a, &b, b.local_addr()).await;
    }

    #[tokio::test]
    async fn ecn_dual_stack() {
        let dual = bind(1, "[::]:0");
        let v4 = bind(2, "127.0.0.1:0");
        ecn_marks(&v4, &dual, seen_as(&dual, "127.0.0.1")).await;
        ecn_marks(&dual, &v4, v4.local_addr()).await;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN"]
    async fn fwmark() {
        let a = bind(1, "127.0.0.1:0");
        a.set_fwmark(0x5157).unwrap();
        assert_eq!(socket2::SockRef::from(&a.socket).mark().unwrap(), 0x5157);
    }
}
