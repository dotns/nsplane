//! The default network-side transport: one tokio UDP socket driven through `quinn-udp`,
//! with segmentation offload.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};

use nsplane_packet::{Ecn, PacketBuf, Path, TransportId};
use quinn_udp::{EcnCodepoint, Transmit, UdpSockRef, UdpSocketState};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;

use crate::transport::Transport;

/// The most bytes one send carries: the largest IPv4 UDP payload, so also the limit of a
/// segmented send.
const MAX_SEND: usize = 65_507;

/// A [`Transport`] over one UDP socket.
///
/// Bound to `[::]:port` the socket is dual-stack: IPv4 peers are reported in
/// [`Path::addr`] as plain IPv4 addresses, and IPv4 destinations are sent to as
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`). On an IPv4 socket, sending to an IPv6
/// address fails with [`io::ErrorKind::InvalidInput`].
///
/// The socket is driven through `quinn-udp`, which also sets it up: IP fragmentation is
/// off (`IP_PMTUDISC_PROBE` and `IPV6_DONTFRAG` on Linux and Android, `IP_DONTFRAG` or
/// `IP_DONTFRAGMENT` elsewhere), so a datagram larger than the interface MTU fails to send
/// instead of leaving in fragments. Where `quinn-udp` cannot set the socket up on other
/// platforms than Linux and Android (Wine lacks some IPv4 options), the transport sends with
/// plain `send_to` instead: without ECN marks and segmentation, fragmenting as the OS
/// does by default.
///
/// ECN: on send, `to.ecn` is set per datagram with an `IP_TOS` / `IPV6_TCLASS` (Windows:
/// `IP_ECN` / `IPV6_ECN`) control message, so no socket-wide state changes; Windows sets it
/// only where its Winsock provider supports ECN (Wine does not). On Linux and Android the
/// mark of each received datagram is read from its control message and reported in
/// [`Path::ecn`]; on other platforms (macOS, iOS, the BSDs, Windows) received datagrams
/// report [`Ecn::NotEct`].
///
/// Segmentation offload is on by default and turned off with
/// [`set_offload`](Self::set_offload):
/// - Receive (Linux and Android, `UDP_GRO`): the kernel may coalesce datagrams of one sender
///   into one read, a train of equally sized datagrams of which the last may be shorter.
///   [`recv_batch`](Transport::recv_batch) hands out each one as a slice of the read
///   ([`PacketBuf::from_shared`]) with [`HEADROOM`](nsplane_packet::HEADROOM) bytes in
///   front, where the engine opens it in place. The first datagram of a read is not
///   copied; the others are moved apart within the read buffer to make that room (one
///   move per train, no allocation). [`recv`](Transport::recv) copies one datagram into
///   the caller's buffer and keeps the rest of the train for the next receive.
/// - Send (Linux and Android `UDP_SEGMENT`, Windows USO):
///   [`send_batch`](Transport::send_batch) sends a run of consecutive datagrams to the same
///   address with the same ECN mark and of the same size (the last may be shorter) as one
///   segmented send, up to the kernel's segment limit and 64 KiB, copying the run into one
///   buffer. Datagrams that start no run are sent one by one. Where segmentation is not
///   available, or a segmented send fails with `EIO` or `EINVAL` (a device without
///   segmentation support), sending falls back to one datagram per send.
///
/// With offload off every datagram takes one system call in both directions, as without
/// offload support. Either way the datagrams, their order, sizes, paths and ECN marks are
/// the same.
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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    state: UdpSocketState,
    /// `None` where `quinn-udp` could not set the socket up.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    state: Option<UdpSocketState>,
    offload: AtomicBool,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rx: std::sync::Mutex<linux::Rx>,
}

impl UdpTransport {
    /// Binds a non-blocking UDP socket to `addr`, with segmentation offload on.
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
        let state = UdpSocketState::new(UdpSockRef::from(&socket));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let state = state?;
        // Receive timestamps are not used, and their control message would crowd out the
        // ECN mark of a coalesced read from `quinn-udp`'s control buffer.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        nix::sys::socket::setsockopt(
            &socket,
            nix::sys::socket::sockopt::ReceiveTimestampns,
            &false,
        )?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let state = state
            .inspect_err(|e| tracing::debug!(message = "Plain UDP sends", error = ?e))
            .ok();
        Ok(Self {
            id,
            local,
            socket,
            state,
            offload: AtomicBool::new(true),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            rx: std::sync::Mutex::default(),
        })
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

    /// Turns segmentation offload on (the default) or off; see the
    /// [type documentation](Self). Takes effect for the next receive and send; datagrams
    /// the kernel already coalesced are still split correctly.
    pub fn set_offload(&self, enabled: bool) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if self.state.gro_segments() > 1 {
            nix::sys::socket::setsockopt(
                &self.socket,
                nix::sys::socket::sockopt::UdpGroSegment,
                &enabled,
            )?;
        }
        self.offload.store(enabled, Ordering::Relaxed);
        Ok(())
    }

    /// Whether segmentation offload is on.
    pub fn offload(&self) -> bool {
        self.offload.load(Ordering::Relaxed)
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

    /// The path of a datagram received from `addr` with mark `ecn`.
    fn path(&self, addr: SocketAddr, ecn: Ecn) -> Path {
        Path {
            transport: self.id,
            addr: unmap(addr),
            ecn,
        }
    }

    /// The most datagrams one send may carry right now.
    fn max_segments(&self) -> usize {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let state = Some(&self.state);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let state = self.state.as_ref();
        match state {
            Some(state) if self.offload() => state.max_gso_segments(),
            _ => 1,
        }
    }

    /// Sends `contents` to `to`: one datagram, or with `segment_size` a train of datagrams
    /// of that size (the last may be shorter).
    async fn send_segments(
        &self,
        contents: &[u8],
        segment_size: Option<usize>,
        to: &Path,
    ) -> io::Result<()> {
        let destination = self.target(to.addr)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let state = Some(&self.state);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let state = self.state.as_ref();
        let Some(state) = state else {
            return self.socket.send_to(contents, destination).await.map(drop);
        };
        let transmit = Transmit {
            destination,
            ecn: EcnCodepoint::from_bits(to.ecn.to_bits()),
            contents,
            segment_size,
            src_ip: None,
        };
        self.socket
            .async_io(Interest::WRITABLE, || {
                state.try_send(UdpSockRef::from(&self.socket), &transmit)
            })
            .await
    }
}

impl Transport for UdpTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        self.recv_datagram(buf).await
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        self.send_segments(datagram, None, to).await
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn recv_batch(
        &self,
        buf: &mut PacketBuf,
        datagrams: &mut std::collections::VecDeque<(Path, PacketBuf)>,
    ) -> io::Result<()> {
        self.recv_datagrams(buf, datagrams).await
    }

    async fn send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
    ) -> io::Result<()> {
        // One buffer for the runs of this batch; encrypting into it directly would save
        // the copy.
        let mut train = Vec::new();
        while let Some((to, first)) = datagrams.get(*sent) {
            let run = run_len(&datagrams[*sent..], self.max_segments());
            let result = if run == 1 {
                self.send_segments(first.as_packet(), None, to).await
            } else {
                train.clear();
                for (_, datagram) in &datagrams[*sent..*sent + run] {
                    train.extend_from_slice(datagram.as_packet());
                }
                self.send_segments(&train, Some(first.len()), to).await
            };
            *sent += run;
            result?;
        }
        Ok(())
    }
}

/// How many datagrams from the start of `datagrams` go out in one send of at most
/// `max_segments`: the first one, and the ones after it with the same address and ECN mark
/// and the first one's size, up to one shorter one that ends the run, while the run fits
/// into [`MAX_SEND`] bytes. `0` for no datagrams.
fn run_len(datagrams: &[(Path, PacketBuf)], max_segments: usize) -> usize {
    let Some(((to, first), rest)) = datagrams.split_first() else {
        return 0;
    };
    let size = first.len();
    let mut run = 1;
    let mut total = size;
    for (path, datagram) in rest {
        let len = datagram.len();
        if run == max_segments
            || path.addr != to.addr
            || path.ecn != to.ecn
            || len == 0
            || len > size
            || total + len > MAX_SEND
        {
            break;
        }
        run += 1;
        total += len;
        if len < size {
            break;
        }
    }
    run
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
    //! Receiving through `quinn-udp`, with generic receive offload: one read may return a
    //! train of datagrams of one sender, all of one size (the stride) but the last.

    use std::collections::VecDeque;
    use std::io::{self, IoSliceMut};
    use std::sync::{MutexGuard, PoisonError};

    use bytes::BytesMut;
    use nsplane_packet::{Ecn, HEADROOM, MAX_BATCH, PacketBuf, Path};
    use quinn_udp::{RecvMeta, UdpSockRef};
    use tokio::io::Interest;

    use super::UdpTransport;

    /// Bytes one coalesced read may fill: the largest datagram, and the most the kernel
    /// coalesces into one read.
    const READ: usize = 1 << 16;

    /// What the receiving side keeps between receives.
    #[derive(Debug, Default)]
    pub(super) struct Rx {
        /// Storage for coalesced reads; every read takes its datagrams off the front, so
        /// they share the allocation, which is freed once all of them are dropped.
        buf: BytesMut,
        /// Datagrams read but not handed out yet, oldest first.
        pending: VecDeque<(Path, PacketBuf)>,
    }

    impl UdpTransport {
        fn rx(&self) -> MutexGuard<'_, Rx> {
            self.rx.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// [`Transport::recv`](crate::Transport::recv).
        pub(super) async fn recv_datagram(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
            loop {
                let next = self.rx().pending.pop_front();
                if let Some((path, datagram)) = next {
                    let len = datagram.len().min(buf.capacity());
                    buf.set_len(len);
                    buf.as_packet_mut()
                        .copy_from_slice(&datagram.as_packet()[..len]);
                    return Ok((len, path));
                }
                if !self.offload() {
                    return self.read_into(buf).await;
                }
                self.read_coalesced().await?;
            }
        }

        /// [`Transport::recv_batch`](crate::Transport::recv_batch).
        pub(super) async fn recv_datagrams(
            &self,
            buf: &mut PacketBuf,
            datagrams: &mut VecDeque<(Path, PacketBuf)>,
        ) -> io::Result<()> {
            let capacity = buf.capacity();
            loop {
                let room = MAX_BATCH.saturating_sub(datagrams.len());
                {
                    let mut rx = self.rx();
                    if room == 0 || !rx.pending.is_empty() {
                        let ready = room.min(rx.pending.len());
                        for (path, mut datagram) in rx.pending.drain(..ready) {
                            if datagram.len() > capacity {
                                datagram.set_len(capacity);
                            }
                            datagrams.push_back((path, datagram));
                        }
                        return Ok(());
                    }
                }
                if !self.offload() {
                    let (len, path) = self.read_into(buf).await?;
                    datagrams.push_back((path, PacketBuf::from_packet(&buf.as_packet()[..len])));
                    return Ok(());
                }
                self.read_coalesced().await?;
            }
        }

        /// Reads into `buf` under the [`recv`](crate::Transport::recv) buffer contract.
        /// Datagrams after the first of a train (coalesced before offload was turned off)
        /// are copied to the pending queue.
        async fn read_into(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
            buf.set_len(buf.capacity());
            let meta = self
                .socket
                .async_io(Interest::READABLE, || {
                    let mut meta = [RecvMeta::default()];
                    let mut bufs = [IoSliceMut::new(buf.as_packet_mut())];
                    self.state
                        .recv(UdpSockRef::from(&self.socket), &mut bufs, &mut meta)?;
                    Ok(meta[0])
                })
                .await
                .inspect_err(|_| buf.set_len(0))?;
            let path = self.path(meta.addr, ecn(&meta));
            let len = meta.stride.min(meta.len);
            if len > 0 && len < meta.len {
                let mut rx = self.rx();
                for datagram in buf.as_packet()[len..meta.len].chunks(len) {
                    rx.pending
                        .push_back((path, PacketBuf::from_packet(datagram)));
                }
            }
            buf.set_len(len);
            Ok((len, path))
        }

        /// Reads one datagram or train into the shared storage and queues its datagrams,
        /// each a zero-copy slice of the storage with [`HEADROOM`] bytes in front.
        ///
        /// The read lands [`HEADROOM`] bytes into the storage, so its first datagram stays
        /// where it was read. The core opens a datagram in place behind exactly
        /// [`HEADROOM`] bytes, so the later datagrams of a train are moved apart within the
        /// storage to make that room: one move per train and no allocation. Once the core
        /// opens at any headroom, they can be sliced where they were read.
        async fn read_coalesced(&self) -> io::Result<()> {
            // A full read spread into the most datagrams the kernel coalesces.
            let room = HEADROOM + READ + self.state.gro_segments() * HEADROOM;
            self.socket
                .async_io(Interest::READABLE, || {
                    let mut rx = self.rx();
                    let rx = &mut *rx;
                    if rx.buf.len() < room {
                        // Reuses the allocation once every slice of it is gone. Twice the
                        // room, so small datagrams take many reads per refill.
                        rx.buf.clear();
                        rx.buf.resize(2 * room, 0);
                    }
                    let mut meta = [RecvMeta::default()];
                    let mut bufs = [IoSliceMut::new(&mut rx.buf[HEADROOM..HEADROOM + READ])];
                    self.state
                        .recv(UdpSockRef::from(&self.socket), &mut bufs, &mut meta)?;
                    let meta = meta[0];
                    let path = self.path(meta.addr, ecn(&meta));
                    let stride = meta.stride.clamp(1, READ);
                    let count = meta.len.div_ceil(stride).max(1);
                    if (count + 1) * HEADROOM + meta.len > rx.buf.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "more coalesced datagrams than announced",
                        ));
                    }
                    let len = |i: usize| stride.min(meta.len - i * stride);
                    // Last first: datagram `i` moves `i * HEADROOM` bytes up.
                    for i in (1..count).rev() {
                        let from = HEADROOM + i * stride;
                        rx.buf.copy_within(from..from + len(i), from + i * HEADROOM);
                    }
                    for i in 0..count {
                        let slot = rx.buf.split_to(HEADROOM + len(i));
                        let datagram = PacketBuf::from_shared(slot, HEADROOM, len(i))
                            .map_err(io::Error::other)?;
                        rx.pending.push_back((path, datagram));
                    }
                    Ok(())
                })
                .await
        }
    }

    /// The ECN mark of a read.
    fn ecn(meta: &RecvMeta) -> Ecn {
        meta.ecn
            .map_or(Ecn::NotEct, |ecn| Ecn::from_bits(ecn as u8))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl UdpTransport {
    /// [`Transport::recv`] without receive offload: one datagram per call, no ECN.
    async fn recv_datagram(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        buf.set_len(buf.capacity());
        let (len, addr) = self
            .recv_from(buf.as_packet_mut())
            .await
            .inspect_err(|_| buf.set_len(0))?;
        buf.set_len(len);
        Ok((len, self.path(addr, Ecn::NotEct)))
    }

    /// Receives one datagram with plain `recv_from`, truncated to `packet`.
    #[cfg(not(windows))]
    async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(packet).await
    }
}

#[cfg(windows)]
mod windows {
    //! `recv_from` mapped to the transport contract: truncation instead of `WSAEMSGSIZE`
    //! and no `WSAECONNRESET`.

    use std::io;
    use std::net::SocketAddr;

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
        pub(super) async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            loop {
                self.socket.readable().await?;
                let sender = match self.socket.try_peek_sender() {
                    Ok(addr) => Some(addr),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => None,
                    Err(e) => return Err(e),
                };
                match self.socket.try_recv_from(packet) {
                    Ok(received) => return Ok(received),
                    Err(e) if e.raw_os_error() == Some(WSAEMSGSIZE) => {
                        if let Some(addr) = sender {
                            return Ok((packet.len(), addr));
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
    use nsplane_packet::{Ecn, HEADROOM, MAX_BATCH};
    use std::collections::VecDeque;
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

    /// Datagram number `seq` of `len` bytes, different from its neighbours.
    fn numbered(seq: usize, len: usize) -> Vec<u8> {
        (0..=u8::MAX).cycle().skip(seq % 256).take(len).collect()
    }

    /// `count` numbered datagrams of `size` bytes, then one shorter one if `size > 1`.
    fn train(size: usize, count: usize) -> Vec<Vec<u8>> {
        let mut datagrams: Vec<_> = (0..count).map(|seq| numbered(seq, size)).collect();
        if size > 1 {
            datagrams.push(numbered(count, size / 2));
        }
        datagrams
    }

    fn batch(to: SocketAddr, ecn: Ecn, datagrams: &[Vec<u8>]) -> Vec<(Path, PacketBuf)> {
        datagrams
            .iter()
            .map(|datagram| (path_to(to, ecn), PacketBuf::from_packet(datagram)))
            .collect()
    }

    async fn send_all(transport: &UdpTransport, batch: &[(Path, PacketBuf)]) {
        let mut sent = 0;
        transport.send_batch(batch, &mut sent).await.unwrap();
        assert_eq!(sent, batch.len());
    }

    /// Receives `count` datagrams with `recv_batch`; returns what each call appended.
    async fn recv_batches(transport: &UdpTransport, count: usize) -> Vec<Vec<(Path, PacketBuf)>> {
        let mut buf = PacketBuf::with_capacity(65_535);
        let mut calls = Vec::new();
        let mut received = 0;
        while received < count {
            let mut datagrams = VecDeque::new();
            timeout(
                Duration::from_secs(5),
                transport.recv_batch(&mut buf, &mut datagrams),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!datagrams.is_empty() && datagrams.len() <= MAX_BATCH);
            received += datagrams.len();
            calls.push(datagrams.into());
        }
        assert_eq!(received, count);
        calls
    }

    /// Checks that `received` holds exactly `expected`, in order, from `from` with `ecn`
    /// where the platform reports it.
    fn check(received: &[(Path, PacketBuf)], expected: &[Vec<u8>], from: SocketAddr, ecn: Ecn) {
        let ecn = if cfg!(any(target_os = "linux", target_os = "android")) {
            ecn
        } else {
            Ecn::NotEct
        };
        assert_eq!(received.len(), expected.len());
        for ((path, datagram), expected) in received.iter().zip(expected) {
            assert_eq!(datagram.as_packet(), expected.as_slice());
            assert_eq!(path.addr, from);
            assert_eq!(path.ecn, ecn);
        }
    }

    /// Whether both ends coalesce: `from` sends segmented, `to` receives coalesced.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn coalescing(from: &UdpTransport, to: &UdpTransport) -> bool {
        from.max_segments() > 1 && to.offload() && to.state.gro_segments() > 1
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const fn coalescing(_: &UdpTransport, _: &UdpTransport) -> bool {
        false
    }

    #[test]
    fn runs_split_at_path_ecn_and_size_changes() {
        let a: SocketAddr = "192.0.2.1:1".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:1".parse().unwrap();
        let datagram = |to, ecn, len| (path_to(to, ecn), PacketBuf::from_packet(&vec![0; len]));
        let datagrams = [
            datagram(a, Ecn::NotEct, 100),
            datagram(a, Ecn::NotEct, 100),
            datagram(a, Ecn::NotEct, 60), // shorter: ends the run
            datagram(a, Ecn::NotEct, 60),
            datagram(a, Ecn::Ect0, 60), // other ECN
            datagram(b, Ecn::Ect0, 60), // other address
            datagram(b, Ecn::Ect0, 80), // longer
            datagram(b, Ecn::Ect0, 0),  // empty
            datagram(b, Ecn::Ect0, 0),
        ];
        let runs = |max_segments| {
            let mut runs = Vec::new();
            let mut start = 0;
            while start < datagrams.len() {
                let run = run_len(&datagrams[start..], max_segments);
                runs.push(run);
                start += run;
            }
            runs
        };
        assert_eq!(runs(64), [3, 1, 1, 1, 1, 1, 1]);
        assert_eq!(runs(2), [2, 2, 1, 1, 1, 1, 1]);
        assert_eq!(runs(1), [1; 9]);
        assert_eq!(run_len(&[], 64), 0);

        // A run stops before it outgrows one send.
        let big: Vec<_> = (0..64).map(|_| datagram(a, Ecn::NotEct, 1420)).collect();
        assert_eq!(run_len(&big, 64), MAX_SEND / 1420);
    }

    /// Senders bound to `send_on` send segmented trains of every size to a plain socket
    /// bound to `recv_on`, which gets them as separate datagrams.
    async fn segmented_to_plain(send_on: &str, recv_on: &str, seen_as_ip: &str) {
        let sender = bind(1, send_on);
        let plain = tokio::net::UdpSocket::bind(recv_on).await.unwrap();
        let from = seen_as(&sender, seen_as_ip);
        for size in [1, 1279, 1280, 1420] {
            let datagrams = train(size, 10);
            let batch = batch(plain.local_addr().unwrap(), Ecn::NotEct, &datagrams);
            if sender.max_segments() > 1 {
                assert_eq!(run_len(&batch, sender.max_segments()), batch.len());
            }
            send_all(&sender, &batch).await;
            let mut buf = [0; 2048];
            for expected in &datagrams {
                let (len, addr) = timeout(Duration::from_secs(5), plain.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&buf[..len], expected.as_slice(), "size {size}");
                assert_eq!(unmap(addr), from);
            }
        }
    }

    #[tokio::test]
    async fn segmented_send_ipv4() {
        segmented_to_plain("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1").await;
    }

    #[tokio::test]
    async fn segmented_send_ipv6() {
        segmented_to_plain("[::1]:0", "[::1]:0", "::1").await;
    }

    #[tokio::test]
    async fn segmented_send_dual_stack() {
        segmented_to_plain("[::]:0", "127.0.0.1:0", "127.0.0.1").await;
        segmented_to_plain("[::]:0", "[::1]:0", "::1").await;
    }

    #[tokio::test]
    async fn burst_from_plain_socket_keeps_boundaries() {
        let receiver = bind(1, "127.0.0.1:0");
        let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let datagrams: Vec<_> = (0..100).map(|seq| numbered(seq, 1 + seq * 13)).collect();
        for datagram in &datagrams {
            plain
                .send_to(datagram, receiver.local_addr())
                .await
                .unwrap();
        }
        let received: Vec<_> = recv_batches(&receiver, datagrams.len()).await.concat();
        check(
            &received,
            &datagrams,
            plain.local_addr().unwrap(),
            Ecn::NotEct,
        );
    }

    /// `from` sends a segmented train of each size with ECT(0) to `to`, which receives it
    /// in one read where both ends coalesce: slices of one buffer, [`HEADROOM`] apart.
    async fn segmented_to_coalesced(
        from: &UdpTransport,
        from_addr: SocketAddr,
        to: &UdpTransport,
        to_addr: SocketAddr,
    ) {
        for size in [1, 1279, 1280, 1420] {
            let datagrams = train(size, 20);
            send_all(from, &batch(to_addr, Ecn::Ect0, &datagrams)).await;
            let calls = recv_batches(to, datagrams.len()).await;
            if coalescing(from, to) {
                assert_eq!(calls.len(), 1, "size {size}: one coalesced read");
                for pair in calls[0].windows(2) {
                    let (first, next) = (pair[0].1.as_packet(), pair[1].1.as_packet());
                    assert_eq!(pair[1].1.headroom(), HEADROOM);
                    assert_eq!(
                        first.as_ptr().addr() + size + HEADROOM,
                        next.as_ptr().addr()
                    );
                }
            }
            check(&calls.concat(), &datagrams, from_addr, Ecn::Ect0);
        }
    }

    #[tokio::test]
    async fn coalesced_receive_ipv4() {
        let a = bind(1, "127.0.0.1:0");
        let b = bind(2, "127.0.0.1:0");
        segmented_to_coalesced(&a, a.local_addr(), &b, b.local_addr()).await;
    }

    #[tokio::test]
    async fn coalesced_receive_ipv6() {
        let a = bind(1, "[::1]:0");
        let b = bind(2, "[::1]:0");
        segmented_to_coalesced(&a, a.local_addr(), &b, b.local_addr()).await;
    }

    #[tokio::test]
    async fn coalesced_receive_dual_stack() {
        let dual = bind(1, "[::]:0");
        let v4 = bind(2, "127.0.0.1:0");
        let v6 = bind(3, "[::1]:0");
        let dual_v4 = seen_as(&dual, "127.0.0.1");
        let dual_v6 = seen_as(&dual, "::1");
        segmented_to_coalesced(&v4, v4.local_addr(), &dual, dual_v4).await;
        segmented_to_coalesced(&dual, dual_v4, &v4, v4.local_addr()).await;
        segmented_to_coalesced(&v6, v6.local_addr(), &dual, dual_v6).await;
        segmented_to_coalesced(&dual, dual_v6, &v6, v6.local_addr()).await;
    }

    /// `recv` hands out a coalesced train one datagram at a time.
    #[tokio::test]
    async fn recv_splits_coalesced_train() {
        let a = bind(1, "127.0.0.1:0");
        let b = bind(2, "127.0.0.1:0");
        let datagrams = train(1280, 10);
        send_all(&a, &batch(b.local_addr(), Ecn::Ect1, &datagrams)).await;
        let mut received = Vec::new();
        for _ in &datagrams {
            let (buf, path) = recv(&b, 1500).await;
            received.push((path, buf));
        }
        check(&received, &datagrams, a.local_addr(), Ecn::Ect1);
    }

    #[tokio::test]
    async fn mixed_batch_reaches_each_receiver_in_order() {
        let sender = bind(1, "[::]:0");
        let v4 = bind(2, "127.0.0.1:0");
        let v6 = bind(3, "[::1]:0");
        let ecns = [Ecn::NotEct, Ecn::Ect0, Ecn::Ect1, Ecn::Ce];
        let mut batch = Vec::new();
        let mut expected: [Vec<(Ecn, Vec<u8>)>; 2] = Default::default();
        // Few enough to sit in a small (Wine) receive buffer until read.
        for seq in 0..MAX_BATCH {
            // Runs of a few datagrams, then a change of receiver, mark or size.
            let to = (seq / 7) % 2;
            let ecn = ecns[(seq / 5) % 4];
            let len = if seq % 11 == 10 { 700 } else { 1280 };
            let datagram = numbered(seq, len);
            let addr = [v4.local_addr(), v6.local_addr()][to];
            batch.push((path_to(addr, ecn), PacketBuf::from_packet(&datagram)));
            expected[to].push((ecn, datagram));
        }
        send_all(&sender, &batch).await;
        for (receiver, expected, ip) in
            [(&v4, &expected[0], "127.0.0.1"), (&v6, &expected[1], "::1")]
        {
            let received = recv_batches(receiver, expected.len()).await.concat();
            for ((path, datagram), (ecn, bytes)) in received.iter().zip(expected) {
                check(
                    &[(*path, datagram.clone())],
                    std::slice::from_ref(bytes),
                    seen_as(&sender, ip),
                    *ecn,
                );
            }
        }
    }

    #[tokio::test]
    async fn offload_off_sends_and_receives_one_datagram_per_call() {
        let a = bind(1, "127.0.0.1:0");
        let b = bind(2, "127.0.0.1:0");
        assert!(a.offload());
        a.set_offload(false).unwrap();
        b.set_offload(false).unwrap();
        assert!(!a.offload());
        assert_eq!(a.max_segments(), 1);
        let datagrams = train(1280, 20);
        let batch = batch(b.local_addr(), Ecn::Ce, &datagrams);
        assert_eq!(run_len(&batch, a.max_segments()), 1);
        send_all(&a, &batch).await;
        let calls = recv_batches(&b, datagrams.len()).await;
        assert!(calls.iter().all(|call| call.len() == 1));
        check(&calls.concat(), &datagrams, a.local_addr(), Ecn::Ce);

        // Back on, segmented again.
        a.set_offload(true).unwrap();
        b.set_offload(true).unwrap();
        segmented_to_coalesced(&a, a.local_addr(), &b, b.local_addr()).await;
    }
}
