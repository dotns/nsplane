//! The default network-side transport: one tokio UDP socket driven through `quinn-udp`,
//! with segmentation offload, and an optional side channel for datagrams that are not the
//! engine's on the same socket.

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use nsplane_packet::{Ecn, PacketBuf, Path, TransportId};
use quinn_udp::{EcnCodepoint, Transmit, UdpSockRef, UdpSocketState};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::transport::Transport;

/// The most bytes one send carries: the largest IPv4 UDP payload, so also the limit of a
/// segmented send.
const MAX_SEND: usize = 65_507;

/// The socket buffer size [`UdpTransport::bind`] requests for both directions.
const DEFAULT_SOCKET_BUFFER: usize = 4 << 20;

/// A [`Transport`] over one UDP socket.
///
/// Bound to `[::]:port` the socket is dual-stack: IPv4 peers are reported in
/// [`Path::addr`] as plain IPv4 addresses, and IPv4 destinations are sent to as
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`). On an IPv4 socket, sending to an IPv6
/// address fails with [`io::ErrorKind::InvalidInput`].
///
/// Whether the transport may use segmentation offload is chosen when binding:
/// [`bind`](Self::bind) binds with offload, [`bind_with_offload`](Self::bind_with_offload)
/// can bind without.
///
/// With offload, the socket is driven through `quinn-udp`, which also sets it up: IP
/// fragmentation is off (`IP_PMTUDISC_PROBE` and `IPV6_DONTFRAG` on Linux and Android,
/// `IP_DONTFRAG` or `IP_DONTFRAGMENT` elsewhere), as segmentation needs. A datagram larger
/// than the MTU of the outgoing interface fails to send with `EMSGSIZE` instead of leaving
/// in fragments; one that fits the interface but not a smaller MTU further along the path
/// leaves with the DF bit set and is dropped where it does not fit. So the engine's MTU plus
/// the WireGuard overhead must fit the path MTU. The engine logs a failed send at debug
/// level, drops the datagram and counts it under [`crate::DROP_TRANSPORT_SEND_ERROR`]. Where
/// `quinn-udp` cannot set the socket up on other platforms than Linux and Android (Wine
/// lacks some IPv4 options), the transport sends with plain `send_to` instead: without ECN
/// marks and segmentation, fragmenting as the OS does by default.
///
/// Without offload, `quinn-udp` never touches the socket: it keeps the OS's default path
/// MTU discovery, so a datagram larger than the path MTU leaves in fragments. On Linux and
/// Android it is driven with `sendmsg` / `recvmsg`, the ECN marks in `IP_TOS` /
/// `IPV6_TCLASS` control messages (received ones asked for with `IP_RECVTOS` /
/// `IPV6_RECVTCLASS`); elsewhere with plain `send_to` / `recv_from`, without ECN marks.
///
/// ECN: on send, `to.ecn` is set per datagram with an `IP_TOS` / `IPV6_TCLASS` (Windows:
/// `IP_ECN` / `IPV6_ECN`) control message, so no socket-wide state changes; Windows sets it
/// only with offload and where its Winsock provider supports ECN (Wine does not). On Linux
/// and Android the mark of each received datagram is read from its control message and
/// reported in [`Path::ecn`]; on other platforms (macOS, iOS, the BSDs, Windows) received
/// datagrams report [`Ecn::NotEct`].
///
/// Segmentation offload, where bound with it, is on by default and turned off with
/// [`set_offload`](Self::set_offload), which leaves the socket set up by `quinn-udp`
/// (fragmentation stays off):
/// - Receive (Linux and Android, `UDP_GRO`): the kernel may coalesce datagrams of one sender
///   into one read, a train of equally sized datagrams of which the last may be shorter.
///   [`recv_batch`](Transport::recv_batch) hands out each one as a slice of the read
///   ([`PacketBuf::from_shared`]) at the offset it was read to, without headroom, where
///   the engine opens it in place: no datagram of a train is copied.
///   [`recv`](Transport::recv) copies one datagram into the caller's buffer and keeps the
///   rest of the train for the next receive.
/// - Send (Linux and Android `UDP_SEGMENT`, Windows USO):
///   [`send_batch`](Transport::send_batch) sends a run of consecutive datagrams to the same
///   address with the same ECN mark and of the same size (the last may be shorter) as one
///   segmented send, up to the kernel's segment limit and 64 KiB, copying the run into one
///   buffer. Datagrams that start no run are sent one by one. Where segmentation is not
///   available, or a segmented send fails with `EIO` or `EINVAL` (a device without
///   segmentation support), sending falls back to one datagram per send. A failed send
///   drops and counts exactly the datagrams of its run, so the engine counts each of them
///   under [`crate::DROP_TRANSPORT_SEND_ERROR`] and none of the runs handed off before it.
///
/// With offload off every datagram takes one system call in both directions, as without
/// offload support. Either way the datagrams, their order, sizes, paths and ECN marks are
/// the same.
///
/// Socket buffers: binding requests 4 MiB for both the receive (`SO_RCVBUF`)
/// and the send buffer (`SO_SNDBUF`), so a burst does not overflow the receive queue
/// before the engine reads it, as it does with Linux's default of 208 KiB on a loaded
/// host. The kernel grants what its limits allow: Linux clamps the
/// request to `net.core.rmem_max` / `net.core.wmem_max` without an error (raise those
/// sysctls for the full size; `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE`, which bypass them with
/// `CAP_NET_ADMIN`, are not used). [`set_recv_buffer_size`](Self::set_recv_buffer_size)
/// and [`set_send_buffer_size`](Self::set_send_buffer_size) change the sizes later;
/// [`recv_buffer_size`](Self::recv_buffer_size) and
/// [`send_buffer_size`](Self::send_buffer_size) report what the kernel says, which on
/// Linux is twice the granted request (the kernel reserves the extra half for its
/// bookkeeping). Windows, macOS and the BSDs take the same options through the same calls,
/// with their own limits (macOS: `kern.ipc.maxsockbuf`) and without the doubling.
///
/// Windows: a datagram larger than the receive buffer is truncated as on other
/// platforms, although `recvfrom` reports it as `WSAEMSGSIZE`; its sender is peeked
/// before the receive. ICMP port-unreachable errors, which Windows reports on a later
/// receive as `WSAECONNRESET`, are skipped and receiving continues.
///
/// Side channel: [`with_side_channel`](Self::with_side_channel) takes the datagrams a
/// classifier picks (another protocol sharing the port) out of
/// [`recv`](Transport::recv) and [`recv_batch`](Transport::recv_batch), each datagram of a
/// coalesced read on its own, and hands them to a channel instead of the engine; a
/// [`SideSender`] sends that protocol's datagrams on the same socket. Without a side
/// channel nothing is classified.
///
/// Path MTU discovery: on Linux and Android,
/// [`set_path_mtu_discovery`](Self::set_path_mtu_discovery) turns the socket's ICMP
/// Fragmentation Needed and Packet Too Big errors into
/// [`PathMtuReport`](crate::PathMtuReport)s for the engine;
/// it is off by default.
///
/// The transport never closes: it lives as long as its socket.
#[derive(Debug)]
pub struct UdpTransport {
    id: TransportId,
    local: SocketAddr,
    /// Shared with the [`SideSender`]s.
    socket: Arc<UdpSocket>,
    /// `None` when bound without offload, or where `quinn-udp` could not set the socket up
    /// (only on other platforms than Linux and Android).
    state: Option<UdpSocketState>,
    /// Bound without offload: the socket stays as the OS set it up.
    plain: bool,
    offload: AtomicBool,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rx: std::sync::Mutex<linux::Rx>,
    side: Option<Side>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pmtu: linux::Pmtu,
    /// Path MTU reports dropped while their receiver was full or closed.
    pmtu_dropped: AtomicU64,
}

impl UdpTransport {
    /// Binds a non-blocking UDP socket to `addr`, with segmentation offload on and
    /// 4 MiB requested for both socket buffers.
    ///
    /// For the IPv6 unspecified address (`[::]:port`) the socket is dual-stack
    /// (`IPV6_V6ONLY` off). If IPv6 is unavailable on the host, it binds `0.0.0.0:port`
    /// instead and serves IPv4 only; [`local_addr`](Self::local_addr) tells which. Any
    /// other address is bound exactly.
    ///
    /// The socket buffers get what the kernel grants of the request (see the
    /// [type documentation](Self)); a failure to size them is logged and does not fail
    /// the bind.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime with I/O enabled.
    pub fn bind(id: TransportId, addr: SocketAddr) -> io::Result<Self> {
        Self::bind_with_offload(id, addr, true)
    }

    /// Binds as [`bind`](Self::bind) does, with segmentation offload or, with `offload`
    /// false, without it for the life of the transport: `quinn-udp` does not set the
    /// socket up, so it keeps the OS's default fragmentation (see the
    /// [type documentation](Self)), and [`set_offload`](Self::set_offload) cannot turn
    /// offload on.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime with I/O enabled.
    pub fn bind_with_offload(id: TransportId, addr: SocketAddr, offload: bool) -> io::Result<Self> {
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
        // Before `quinn-udp` sets the socket up: on Apple platforms it caches `SO_SNDBUF`.
        for (option, result) in [
            (
                "SO_RCVBUF",
                socket.set_recv_buffer_size(DEFAULT_SOCKET_BUFFER),
            ),
            (
                "SO_SNDBUF",
                socket.set_send_buffer_size(DEFAULT_SOCKET_BUFFER),
            ),
        ] {
            if let Err(e) = result {
                tracing::debug!(message = "Default socket buffer not set", option, error = ?e);
            }
        }
        let socket = UdpSocket::from_std(socket.into())?;
        let local = socket.local_addr()?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let state = if offload {
            Some(set_up(&socket)?)
        } else {
            linux::enable_ecn(&socket, local)?;
            None
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let state = offload.then(|| set_up(&socket)).flatten();
        Ok(Self {
            id,
            local,
            socket: Arc::new(socket),
            state,
            plain: !offload,
            offload: AtomicBool::new(offload),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            rx: std::sync::Mutex::default(),
            side: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            pmtu: linux::Pmtu::default(),
            pmtu_dropped: AtomicU64::new(0),
        })
    }

    /// Attaches a side channel: every received datagram for which `classify` returns true
    /// is taken out of [`recv`](Transport::recv) and [`recv_batch`](Transport::recv_batch)
    /// (each datagram of a coalesced read on its own) and handed to the returned receiver,
    /// which holds up to `capacity` of them; when it is full or closed the datagram is
    /// dropped. Either way it never reaches the engine, and receiving goes on with the next
    /// datagram. `classify` runs on the receiving task for every datagram, so it should be
    /// cheap (a prefix check).
    ///
    /// The [`SideSender`] sends on the transport's socket and counts what the receiver
    /// took and what it could not ([`SideStats`]).
    ///
    /// Attaching another side channel replaces this one: its receiver then closes once
    /// drained, and its senders keep sending but count nothing more. A `capacity` of 0 is
    /// raised to 1.
    pub fn with_side_channel(
        mut self,
        classify: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
        capacity: usize,
    ) -> (Self, SideSender, mpsc::Receiver<SideDatagram>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let counters = Arc::new(SideCounters::default());
        let sender = SideSender {
            socket: Arc::clone(&self.socket),
            local: self.local,
            counters: Arc::clone(&counters),
        };
        self.side = Some(Side {
            classify: Box::new(classify),
            tx,
            counters,
        });
        (self, sender, rx)
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

    /// Requests a receive buffer (`SO_RCVBUF`) of `bytes`; the kernel may grant less (see
    /// the [type documentation](Self)). [`recv_buffer_size`](Self::recv_buffer_size) tells
    /// what it granted.
    pub fn set_recv_buffer_size(&self, bytes: usize) -> io::Result<()> {
        socket2::SockRef::from(&self.socket).set_recv_buffer_size(bytes)
    }

    /// Requests a send buffer (`SO_SNDBUF`) of `bytes`; the kernel may grant less (see the
    /// [type documentation](Self)). [`send_buffer_size`](Self::send_buffer_size) tells what
    /// it granted.
    pub fn set_send_buffer_size(&self, bytes: usize) -> io::Result<()> {
        // Through `quinn-udp`, which caches the size on Apple platforms.
        let Some(state) = &self.state else {
            return socket2::SockRef::from(&self.socket).set_send_buffer_size(bytes);
        };
        state.set_send_buffer_size(UdpSockRef::from(&*self.socket), bytes)
    }

    /// The receive buffer size the kernel reports (`SO_RCVBUF`): on Linux twice the
    /// granted request.
    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        socket2::SockRef::from(&self.socket).recv_buffer_size()
    }

    /// The send buffer size the kernel reports (`SO_SNDBUF`): on Linux twice the granted
    /// request.
    pub fn send_buffer_size(&self) -> io::Result<usize> {
        socket2::SockRef::from(&self.socket).send_buffer_size()
    }

    /// Turns segmentation offload on (the default) or off; see the
    /// [type documentation](Self). Takes effect for the next receive and send; datagrams
    /// the kernel already coalesced are still split correctly. Turning it off keeps the
    /// socket set up by `quinn-udp`, so IP fragmentation stays off.
    ///
    /// On a transport bound without offload
    /// ([`bind_with_offload`](Self::bind_with_offload)), turning it off does nothing and
    /// turning it on fails with [`io::ErrorKind::Unsupported`].
    pub fn set_offload(&self, enabled: bool) -> io::Result<()> {
        if self.plain {
            if enabled {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "transport bound without offload",
                ));
            }
            return Ok(());
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if self
            .state
            .as_ref()
            .is_some_and(|state| state.gro_segments() > 1)
        {
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

    /// Turns path MTU discovery from the socket's ICMP errors on or off; it is off by
    /// default.
    ///
    /// On, on Linux and Android, the socket asks for its ICMP errors (`IP_RECVERR` unless
    /// it is IPv6-only, and `IPV6_RECVERR` on an IPv6 socket), and receiving also waits
    /// for them and reads the socket's error queue empty before reading datagrams: each
    /// ICMP Fragmentation Needed (type 3, code 4) or `ICMPv6` Packet Too Big (type 2,
    /// code 0) about one of the transport's datagrams becomes a
    /// [`PathMtuReport`](crate::PathMtuReport) for the
    /// datagram's destination (reported as [`Path::addr`] would report it) with the MTU the
    /// error carries, quoting the datagram's leading bytes. Other errors (port unreachable,
    /// for example) are read and skipped. No error fails a receive.
    ///
    /// The reports go to the receiver [`Transport::path_mtu_reports`] hands out, once,
    /// after this was first turned on; so turn it on before handing the transport to the
    /// engine, which takes the receiver when it installs the transport. The receiver holds
    /// up to 64 reports; while it is full or closed further reports are dropped and
    /// counted ([`path_mtu_reports_dropped`](Self::path_mtu_reports_dropped)).
    ///
    /// The kernel learns of a too small path only for datagrams sent with the DF bit: with
    /// offload ([`bind`](Self::bind)) all of them, without it those below the path MTU the
    /// kernel knows (it fragments larger ones itself). While on, an ICMP error can fail
    /// one send (the engine drops and counts that datagram) before receiving reads it, and
    /// once the socket has reported an error, tokio keeps its write readiness, so a send
    /// that finds the send buffer full retries without waiting until it drains.
    ///
    /// Turning it off clears the socket options, which discards the queued errors, and
    /// restores the receive path; the receiver stays with the engine.
    ///
    /// Elsewhere turning it on fails with [`io::ErrorKind::Unsupported`]: macOS and Windows
    /// do not deliver ICMP errors to an unconnected UDP socket. Report the path MTU with
    /// [`EngineHandle::report_path_mtu`](crate::EngineHandle::report_path_mtu) there.
    pub fn set_path_mtu_discovery(&self, on: bool) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            self.set_recv_err(on)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            if on {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "no ICMP errors on unconnected UDP sockets",
                ));
            }
            Ok(())
        }
    }

    /// Path MTU reports dropped because the receiver was full or closed (see
    /// [`set_path_mtu_discovery`](Self::set_path_mtu_discovery)); always 0 where path MTU
    /// discovery is not supported.
    pub fn path_mtu_reports_dropped(&self) -> u64 {
        self.pmtu_dropped.load(Ordering::Relaxed)
    }

    /// Maps `addr` to the socket's address family.
    fn target(&self, addr: SocketAddr) -> io::Result<SocketAddr> {
        target(self.local, addr)
    }

    /// Whether the side channel took the datagram `datagram` from `from` (unmapped).
    fn side_took(&self, datagram: &[u8], from: SocketAddr) -> bool {
        self.side
            .as_ref()
            .is_some_and(|side| side.take(datagram, from))
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
        match &self.state {
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
        let Some(state) = &self.state else {
            // Without `quinn-udp` state nothing is segmented.
            return self.send_to(contents, destination, to.ecn).await;
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
                state.try_send(UdpSockRef::from(&*self.socket), &transmit)
            })
            .await
    }

    /// [`UdpTransport::send_segments`] without waiting: [`io::ErrorKind::WouldBlock`] when
    /// the socket cannot take it now.
    fn try_send_segments(
        &self,
        contents: &[u8],
        segment_size: Option<usize>,
        to: &Path,
    ) -> io::Result<()> {
        let destination = self.target(to.addr)?;
        let Some(state) = &self.state else {
            return self.try_send_to(contents, destination, to.ecn);
        };
        let transmit = Transmit {
            destination,
            ecn: EcnCodepoint::from_bits(to.ecn.to_bits()),
            contents,
            segment_size,
            src_ip: None,
        };
        self.socket.try_io(Interest::WRITABLE, || {
            state.try_send(UdpSockRef::from(&*self.socket), &transmit)
        })
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
        failed: &mut usize,
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
            // A failed send loses its run only; the runs before it were handed off.
            result.inspect_err(|_| *failed += run)?;
        }
        Ok(())
    }

    /// [`send_batch`](Transport::send_batch) without waiting: the same runs, each tried
    /// once; a run the socket cannot take now ends the call with
    /// [`io::ErrorKind::WouldBlock`] and stays unsent.
    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        let mut train = Vec::new();
        while let Some((to, first)) = datagrams.get(*sent) {
            let run = run_len(&datagrams[*sent..], self.max_segments());
            let result = if run == 1 {
                self.try_send_segments(first.as_packet(), None, to)
            } else {
                train.clear();
                for (_, datagram) in &datagrams[*sent..*sent + run] {
                    train.extend_from_slice(datagram.as_packet());
                }
                self.try_send_segments(&train, Some(first.len()), to)
            };
            if let Err(e) = &result
                && e.kind() == io::ErrorKind::WouldBlock
            {
                return result;
            }
            *sent += run;
            result.inspect_err(|_| *failed += run)?;
        }
        Ok(())
    }

    /// The reports of [`UdpTransport::set_path_mtu_discovery`]: `Some` once, after it was
    /// first turned on.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn path_mtu_reports(&self) -> Option<mpsc::Receiver<crate::PathMtuReport>> {
        self.pmtu.take()
    }
}

/// A datagram the side channel took (see [`UdpTransport::with_side_channel`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideDatagram {
    /// The sender, reported as [`Path::addr`] would report it (IPv4 peers of a dual-stack
    /// socket as plain IPv4 addresses).
    pub from: SocketAddr,
    /// The datagram as received; one longer than the receive buffer may be truncated, as
    /// through [`recv`](Transport::recv).
    pub datagram: Bytes,
}

/// Counters of a side channel, from [`SideSender::stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SideStats {
    /// Datagrams handed to the side channel's receiver.
    pub received: u64,
    /// Datagrams the side channel took but its receiver could not take (full or closed),
    /// so they were dropped.
    pub dropped: u64,
}

/// Sends datagrams on the socket of a [`UdpTransport`] with a side channel (see
/// [`UdpTransport::with_side_channel`]); cheap to clone.
///
/// [`send_to`](Self::send_to) is synchronous and best effort, so a caller never waits on
/// the engine's traffic: it hands the datagram to the socket at once, or fails with
/// [`io::ErrorKind::WouldBlock`] when the socket's send buffer is full.
/// [`send_to_async`](Self::send_to_async) instead waits until the socket is writable and
/// retries, for datagrams that should not be lost to a full buffer.
#[derive(Debug, Clone)]
pub struct SideSender {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    counters: Arc<SideCounters>,
}

impl SideSender {
    /// Sends `datagram` to `to` from the transport's socket, without an ECN mark and without
    /// segmentation. IPv4 destinations of a dual-stack socket are mapped as the transport
    /// maps them; an IPv6 destination on an IPv4 socket fails with
    /// [`io::ErrorKind::InvalidInput`]. Does not wait: when the socket cannot take the
    /// datagram now this fails with [`io::ErrorKind::WouldBlock`] and the datagram is not
    /// sent.
    pub fn send_to(&self, datagram: &[u8], to: SocketAddr) -> io::Result<()> {
        // Straight to the non-blocking socket: tokio's `try_send_to` also fails while it
        // has not seen the socket writable yet.
        socket2::SockRef::from(&*self.socket)
            .send_to(datagram, &target(self.local, to)?.into())
            .map(drop)
    }

    /// Sends `datagram` to `to` as [`send_to`](Self::send_to) does, addressed the same way,
    /// but when the socket's send buffer is full waits until the socket is writable and
    /// tries again, until it is sent or fails with another error.
    ///
    /// Cancel safe: each try hands the whole datagram to the socket or nothing, so dropping
    /// the future sends either nothing or the whole datagram, once.
    ///
    /// The socket is the engine's: this waits on the same writability as the engine's own
    /// sends and takes no lock, so it neither blocks nor delays them. Once the socket is
    /// writable each waiter tries its datagram; the engine's sends and this one go out in
    /// whatever order they reach the socket, and the ones that do not fit wait again.
    pub async fn send_to_async(&self, datagram: &[u8], to: SocketAddr) -> io::Result<()> {
        let to = target(self.local, to)?.into();
        self.socket
            .async_io(Interest::WRITABLE, || {
                socket2::SockRef::from(&*self.socket).send_to(datagram, &to)
            })
            .await
            .map(drop)
    }

    /// The transport's bound address.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// What the side channel received and dropped so far.
    pub fn stats(&self) -> SideStats {
        SideStats {
            received: self.counters.received.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
        }
    }
}

/// The counters behind [`SideStats`].
#[derive(Debug, Default)]
struct SideCounters {
    received: AtomicU64,
    dropped: AtomicU64,
}

/// The classifier of a side channel.
type Classify = dyn Fn(&[u8]) -> bool + Send + Sync;

/// An attached side channel.
struct Side {
    classify: Box<Classify>,
    tx: mpsc::Sender<SideDatagram>,
    counters: Arc<SideCounters>,
}

impl Side {
    /// Hands `datagram` from `from` to the receiver if it is classified as a side datagram,
    /// counting it as received or dropped; whether it was.
    fn take(&self, datagram: &[u8], from: SocketAddr) -> bool {
        if !(self.classify)(datagram) {
            return false;
        }
        let side = SideDatagram {
            from,
            datagram: Bytes::copy_from_slice(datagram),
        };
        let counter = match self.tx.try_send(side) {
            Ok(()) => &self.counters.received,
            Err(_) => &self.counters.dropped,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        true
    }
}

impl fmt::Debug for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Side")
            .field("tx", &self.tx)
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

/// Maps `addr` to the address family of a socket bound to `local`.
fn target(local: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
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

/// Sets `socket` up for `quinn-udp`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_up(socket: &UdpSocket) -> io::Result<UdpSocketState> {
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
fn set_up(socket: &UdpSocket) -> Option<UdpSocketState> {
    UdpSocketState::new(UdpSockRef::from(socket))
        .inspect_err(|e| tracing::debug!(message = "Plain UDP sends", error = ?e))
        .ok()
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
    //! train of datagrams of one sender, all of one size (the stride) but the last. Without
    //! `quinn-udp` state, `recvmsg` / `sendmsg` with TOS and traffic class control messages.
    //! With path MTU discovery on, every read first reads the error queue empty.

    use std::collections::VecDeque;
    use std::io::{self, IoSlice, IoSliceMut};
    use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    use bytes::BytesMut;
    use nix::errno::Errno;
    use nix::libc::{SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6, sock_extended_err};
    use nix::sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, getsockopt, recvmsg,
        sendmsg, setsockopt, sockopt,
    };
    use nsplane_packet::{Ecn, MAX_BATCH, PacketBuf, Path};
    use quinn_udp::{RecvMeta, UdpSockRef, UdpSocketState};
    use socket2::SockRef;
    use tokio::io::Interest;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    use super::UdpTransport;
    use crate::transport::PathMtuReport;

    /// The most path MTU reports waiting for the engine.
    const REPORTS: usize = 64;
    /// The leading bytes of a datagram read with its error: as many as a report keeps.
    const QUOTE: usize = 8;

    /// Bytes one coalesced read may fill: the largest datagram, and the most the kernel
    /// coalesces into one read.
    const READ: usize = 1 << 16;

    /// Control-message buffer, aligned for `cmsghdr`; holds one TOS or traffic class
    /// message (24 bytes on 64-bit targets) with room to spare.
    #[repr(C, align(8))]
    struct CmsgBuf([u8; 64]);

    /// Control-message buffer for an error-queue entry, aligned for `cmsghdr`: the error
    /// with the sender of the ICMP message (64 bytes on 64-bit targets for IPv6) comes
    /// last, after the packet info and TOS the socket may also ask for.
    #[repr(C, align(8))]
    struct ErrCmsgBuf([u8; 256]);

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

    /// What the receiving side keeps between receives.
    #[derive(Debug, Default)]
    pub(super) struct Rx {
        /// Storage for coalesced reads; every read takes its datagrams off the front, so
        /// they share the allocation, which is freed once all of them are dropped.
        buf: BytesMut,
        /// Datagrams read but not handed out yet, oldest first.
        pending: VecDeque<(Path, PacketBuf)>,
    }

    /// Path MTU discovery ([`UdpTransport::set_path_mtu_discovery`]).
    #[derive(Debug, Default)]
    pub(super) struct Pmtu {
        on: AtomicBool,
        /// The reports for the engine, from the first time it is turned on.
        tx: OnceLock<mpsc::Sender<PathMtuReport>>,
        /// The receiving end, until the engine takes it.
        rx: Mutex<Option<mpsc::Receiver<PathMtuReport>>>,
    }

    impl Pmtu {
        pub(super) fn on(&self) -> bool {
            self.on.load(Ordering::Relaxed)
        }

        /// Creates the report queue if it does not exist yet.
        fn open(&self) {
            self.tx.get_or_init(|| {
                let (tx, rx) = mpsc::channel(REPORTS);
                *self.rx.lock().unwrap_or_else(PoisonError::into_inner) = Some(rx);
                tx
            });
        }

        /// Queues `report`; false when the queue is full or closed.
        fn push(&self, report: PathMtuReport) -> bool {
            self.tx.get().is_none_or(|tx| tx.try_send(report).is_ok())
        }

        /// The receiver of the reports, once.
        pub(super) fn take(&self) -> Option<mpsc::Receiver<PathMtuReport>> {
            self.rx
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
        }
    }

    /// The report an error-queue entry makes: `err` is the error about a datagram sent on
    /// `path`, `quote` the datagram's leading bytes. `None` unless the error is an ICMP
    /// Fragmentation Needed or an `ICMPv6` Packet Too Big; the MTU is the one it carries.
    pub(super) fn path_mtu_report(
        path: Path,
        err: &sock_extended_err,
        quote: &[u8],
    ) -> Option<PathMtuReport> {
        let too_big = match err.ee_origin {
            SO_EE_ORIGIN_ICMP => (err.ee_type, err.ee_code) == (3, 4),
            SO_EE_ORIGIN_ICMP6 => (err.ee_type, err.ee_code) == (2, 0),
            _ => false,
        };
        let mtu = u16::try_from(err.ee_info).unwrap_or(u16::MAX);
        too_big.then(|| PathMtuReport::with_quote(path, mtu, quote))
    }

    impl UdpTransport {
        /// [`UdpTransport::set_path_mtu_discovery`].
        pub(super) fn set_recv_err(&self, on: bool) -> io::Result<()> {
            if self.local.is_ipv4() || !getsockopt(&self.socket, sockopt::Ipv6V6Only)? {
                setsockopt(&self.socket, sockopt::Ipv4RecvErr, &on)?;
            }
            if self.local.is_ipv6() {
                setsockopt(&self.socket, sockopt::Ipv6RecvErr, &on)?;
            }
            if on {
                self.pmtu.open();
            }
            self.pmtu.on.store(on, Ordering::Relaxed);
            Ok(())
        }

        /// What a read waits for: the socket to be readable, and with path MTU discovery
        /// on also an error.
        fn readiness(&self) -> Interest {
            if self.pmtu.on() {
                Interest::READABLE | Interest::ERROR
            } else {
                Interest::READABLE
            }
        }

        /// Runs the non-blocking read `read`. With path MTU discovery on, it reads the
        /// error queue empty first, and retries a failed read: a queued ICMP error also
        /// fails the next read once with its error code, which is not the engine's.
        fn read<T>(&self, mut read: impl FnMut() -> io::Result<T>) -> io::Result<T> {
            if !self.pmtu.on() {
                return read();
            }
            loop {
                self.drain_errors();
                match read() {
                    Err(e) if e.kind() != io::ErrorKind::WouldBlock => {
                        tracing::trace!(message = "Read failed on an ICMP error", error = %e);
                    }
                    result => return result,
                }
            }
        }

        /// Reads the error queue empty, queuing a report for each Packet Too Big.
        fn drain_errors(&self) {
            let fd = self.socket.as_raw_fd();
            loop {
                let mut quote = [0; QUOTE];
                let mut cmsg = ErrCmsgBuf([0; 256]);
                let mut iov = [IoSliceMut::new(&mut quote)];
                let (len, to, err) = match recvmsg::<SockaddrStorage>(
                    fd,
                    &mut iov,
                    Some(&mut cmsg.0),
                    MsgFlags::MSG_ERRQUEUE,
                ) {
                    Ok(msg) => (
                        msg.bytes,
                        // The datagram's destination.
                        msg.address.as_ref().and_then(socket_addr),
                        msg.cmsgs()
                            .ok()
                            .into_iter()
                            .flatten()
                            .find_map(|cmsg| match cmsg {
                                ControlMessageOwned::Ipv4RecvErr(err, _)
                                | ControlMessageOwned::Ipv6RecvErr(err, _) => Some(err),
                                _ => None,
                            }),
                    ),
                    Err(Errno::EAGAIN) => return,
                    Err(e) => {
                        tracing::debug!(message = "Error queue not read", error = %e);
                        return;
                    }
                };
                if let (Some(to), Some(err)) = (to, err)
                    && let Some(report) =
                        path_mtu_report(self.path(to, Ecn::NotEct), &err, &quote[..len])
                {
                    self.push_report(report);
                }
            }
        }

        /// Queues `report` for the engine; drops and counts it when the queue is full or
        /// closed.
        pub(super) fn push_report(&self, report: PathMtuReport) {
            if !self.pmtu.push(report) {
                self.pmtu_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }

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
                match &self.state {
                    Some(state) if self.offload() => self.read_coalesced(state).await?,
                    _ => {
                        if let Some(received) = self.read_into(buf).await? {
                            return Ok(received);
                        }
                    }
                }
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
                match &self.state {
                    Some(state) if self.offload() => self.read_coalesced(state).await?,
                    _ => {
                        if let Some((len, path)) = self.read_into(buf).await? {
                            datagrams
                                .push_back((path, PacketBuf::from_packet(&buf.as_packet()[..len])));
                            return Ok(());
                        }
                    }
                }
            }
        }

        /// Reads into `buf` under the [`recv`](crate::Transport::recv) buffer contract;
        /// `None` when the side channel took the datagram. Datagrams after the first of a
        /// train (coalesced before offload was turned off) are copied to the pending queue,
        /// but for those the side channel takes.
        async fn read_into(&self, buf: &mut PacketBuf) -> io::Result<Option<(usize, Path)>> {
            buf.set_len(buf.capacity());
            let Some(state) = &self.state else {
                let (len, addr, ecn) = self
                    .recv_from(buf.as_packet_mut())
                    .await
                    .inspect_err(|_| buf.set_len(0))?;
                buf.set_len(len);
                let path = self.path(addr, ecn);
                return Ok((!self.side_took(buf.as_packet(), path.addr)).then_some((len, path)));
            };
            let meta = self
                .socket
                .async_io(self.readiness(), || {
                    self.read(|| {
                        let mut meta = [RecvMeta::default()];
                        let mut bufs = [IoSliceMut::new(buf.as_packet_mut())];
                        state.recv(UdpSockRef::from(&*self.socket), &mut bufs, &mut meta)?;
                        Ok(meta[0])
                    })
                })
                .await
                .inspect_err(|_| buf.set_len(0))?;
            let path = self.path(meta.addr, ecn(&meta));
            let len = meta.stride.min(meta.len);
            if len > 0 && len < meta.len {
                let mut rx = self.rx();
                for datagram in buf.as_packet()[len..meta.len].chunks(len) {
                    if !self.side_took(datagram, path.addr) {
                        rx.pending
                            .push_back((path, PacketBuf::from_packet(datagram)));
                    }
                }
            }
            buf.set_len(len);
            Ok((!self.side_took(buf.as_packet(), path.addr)).then_some((len, path)))
        }

        /// Reads one datagram or train into the shared storage and queues its datagrams,
        /// each a zero-copy slice of the storage at the offset it was read to (no headroom),
        /// but for those the side channel takes.
        async fn read_coalesced(&self, state: &UdpSocketState) -> io::Result<()> {
            self.socket
                .async_io(self.readiness(), || {
                    self.read(|| {
                    let mut rx = self.rx();
                    let rx = &mut *rx;
                    if rx.buf.len() < READ {
                        // Reuses the allocation once every slice of it is gone. Twice the
                        // read, so small datagrams take many reads per refill.
                        rx.buf.clear();
                        rx.buf.resize(2 * READ, 0);
                    }
                    let mut meta = [RecvMeta::default()];
                    let mut bufs = [IoSliceMut::new(&mut rx.buf[..READ])];
                    state.recv(UdpSockRef::from(&*self.socket), &mut bufs, &mut meta)?;
                    let meta = meta[0];
                    let path = self.path(meta.addr, ecn(&meta));
                    let stride = meta.stride.clamp(1, READ);
                    let count = meta.len.div_ceil(stride).max(1);
                    let len = |i: usize| stride.min(meta.len - i * stride);
                    let side = self.side.as_ref();
                    for i in 0..count {
                        let slot = rx.buf.split_to(len(i));
                        if side.is_some_and(|side| side.take(&slot, path.addr)) {
                            continue;
                        }
                        match PacketBuf::from_shared(slot, 0, len(i)) {
                            Ok(datagram) => rx.pending.push_back((path, datagram)),
                            Err(e) => {
                                debug_assert!(false, "datagram slice out of bounds: {e}");
                                tracing::debug!(message = "Dropped coalesced datagram", error = %e);
                            }
                        }
                    }
                    Ok(())
                })
                })
                .await
        }
    }

    /// The ECN mark of a read.
    fn ecn(meta: &RecvMeta) -> Ecn {
        meta.ecn
            .map_or(Ecn::NotEct, |ecn| Ecn::from_bits(ecn as u8))
    }

    impl UdpTransport {
        /// Receives one datagram with `recvmsg`, truncated to `packet`, and its ECN mark.
        async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr, Ecn)> {
            let fd = self.socket.as_raw_fd();
            self.socket
                .async_io(self.readiness(), || {
                    self.read(|| {
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
                        let ecn = msg.cmsgs().ok().into_iter().flatten().fold(
                            Ecn::NotEct,
                            |ecn, cmsg| match cmsg {
                                ControlMessageOwned::Ipv4Tos(tos) => Ecn::from_bits(tos),
                                ControlMessageOwned::Ipv6TClass(tclass) => {
                                    u8::try_from(tclass & 0xFF).map_or(ecn, Ecn::from_bits)
                                }
                                _ => ecn,
                            },
                        );
                        Ok((msg.bytes, addr, ecn))
                    })
                })
                .await
        }

        /// Sends one datagram with `sendmsg`, marked with `ecn`.
        pub(super) async fn send_to(
            &self,
            datagram: &[u8],
            to: SocketAddr,
            ecn: Ecn,
        ) -> io::Result<()> {
            self.socket
                .async_io(Interest::WRITABLE, || self.send_msg(datagram, to, ecn))
                .await
        }

        /// [`UdpTransport::send_to`] without waiting.
        pub(super) fn try_send_to(
            &self,
            datagram: &[u8],
            to: SocketAddr,
            ecn: Ecn,
        ) -> io::Result<()> {
            self.socket
                .try_io(Interest::WRITABLE, || self.send_msg(datagram, to, ecn))
        }

        /// One non-blocking `sendmsg` of `datagram` to `to`, marked with `ecn`.
        fn send_msg(&self, datagram: &[u8], to: SocketAddr, ecn: Ecn) -> io::Result<()> {
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
            sendmsg(
                fd,
                &[IoSlice::new(datagram)],
                cmsg.as_slice(),
                MsgFlags::empty(),
                Some(&dest),
            )
            .map_err(io::Error::from)
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
impl UdpTransport {
    /// [`Transport::recv`] without receive offload: one datagram per call, no ECN; the
    /// datagrams the side channel takes are skipped.
    async fn recv_datagram(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        loop {
            buf.set_len(buf.capacity());
            let (len, addr) = self
                .recv_from(buf.as_packet_mut())
                .await
                .inspect_err(|_| buf.set_len(0))?;
            buf.set_len(len);
            let path = self.path(addr, Ecn::NotEct);
            if !self.side_took(buf.as_packet(), path.addr) {
                return Ok((len, path));
            }
        }
    }

    /// Receives one datagram with plain `recv_from`, truncated to `packet`.
    #[cfg(not(windows))]
    async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(packet).await
    }

    /// Sends one datagram with plain `send_to`, without an ECN mark.
    async fn send_to(&self, datagram: &[u8], to: SocketAddr, _ecn: Ecn) -> io::Result<()> {
        self.socket.send_to(datagram, to).await.map(drop)
    }

    /// [`UdpTransport::send_to`] without waiting.
    fn try_send_to(&self, datagram: &[u8], to: SocketAddr, _ecn: Ecn) -> io::Result<()> {
        self.socket.try_send_to(datagram, to).map(drop)
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

    /// Bound with offload, then without.
    const OFFLOAD: [bool; 2] = [true, false];

    fn bind(id: u16, addr: &str) -> UdpTransport {
        UdpTransport::bind(TransportId::new(id), addr.parse().unwrap()).unwrap()
    }

    fn bind_with(id: u16, addr: &str, offload: bool) -> UdpTransport {
        UdpTransport::bind_with_offload(TransportId::new(id), addr.parse().unwrap(), offload)
            .unwrap()
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
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let b = bind_with(2, "127.0.0.1:0", offload);
            assert_eq!(a.id(), TransportId::new(1));
            roundtrip(&a, a.local_addr(), &b, b.local_addr()).await;
            roundtrip(&b, b.local_addr(), &a, a.local_addr()).await;
        }
    }

    #[tokio::test]
    async fn truncates_into_small_buffer() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let b = bind_with(2, "127.0.0.1:0", offload);
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
    }

    /// An ICMP port-unreachable for an earlier send must not fail a later receive
    /// (Windows reports it as `WSAECONNRESET`).
    #[tokio::test]
    async fn port_unreachable_does_not_fail_recv() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let b = bind_with(2, "127.0.0.1:0", offload);
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
    }

    #[tokio::test]
    async fn ipv6_roundtrip() {
        for offload in OFFLOAD {
            let a = bind_with(1, "[::1]:0", offload);
            let b = bind_with(2, "[::1]:0", offload);
            roundtrip(&a, a.local_addr(), &b, b.local_addr()).await;
            roundtrip(&b, b.local_addr(), &a, a.local_addr()).await;
        }
    }

    #[tokio::test]
    async fn dual_stack_unmaps_ipv4_peers() {
        for offload in OFFLOAD {
            let dual = bind_with(1, "[::]:0", offload);
            assert!(dual.local_addr().is_ipv6());
            let v4 = bind_with(2, "127.0.0.1:0", offload);
            let v6 = bind_with(3, "[::1]:0", offload);
            roundtrip(&v4, v4.local_addr(), &dual, seen_as(&dual, "127.0.0.1")).await;
            roundtrip(&dual, seen_as(&dual, "127.0.0.1"), &v4, v4.local_addr()).await;
            roundtrip(&v6, v6.local_addr(), &dual, seen_as(&dual, "::1")).await;
            roundtrip(&dual, seen_as(&dual, "::1"), &v6, v6.local_addr()).await;
        }
    }

    #[tokio::test]
    async fn ipv4_socket_rejects_ipv6_destination() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let err = a
                .send(DATAGRAM, &path_to("[::1]:9".parse().unwrap(), Ecn::NotEct))
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
    }

    /// Sends one datagram per ECN codepoint from `from` to `to` and checks the mark `to`
    /// observes.
    async fn ecn_marks(from: &UdpTransport, to: &UdpTransport, to_addr: SocketAddr) {
        for ecn in [Ecn::Ect0, Ecn::Ect1, Ecn::Ce, Ecn::NotEct] {
            from.send(DATAGRAM, &path_to(to_addr, ecn)).await.unwrap();
            let (_, path) = recv(to, 1500).await;
            // Marks are sent and received on Linux and Android in both modes.
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
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let b = bind_with(2, "127.0.0.1:0", offload);
            ecn_marks(&a, &b, b.local_addr()).await;
        }
    }

    #[tokio::test]
    async fn ecn_ipv6() {
        for offload in OFFLOAD {
            let a = bind_with(1, "[::1]:0", offload);
            let b = bind_with(2, "[::1]:0", offload);
            ecn_marks(&a, &b, b.local_addr()).await;
        }
    }

    #[tokio::test]
    async fn ecn_dual_stack() {
        for offload in OFFLOAD {
            let dual = bind_with(1, "[::]:0", offload);
            let v4 = bind_with(2, "127.0.0.1:0", offload);
            ecn_marks(&v4, &dual, seen_as(&dual, "127.0.0.1")).await;
            ecn_marks(&dual, &v4, v4.local_addr()).await;
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN"]
    async fn fwmark() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            a.set_fwmark(0x5157).unwrap();
            assert_eq!(socket2::SockRef::from(&a.socket).mark().unwrap(), 0x5157);
        }
    }

    /// The socket options of a transport bound to `addr` and of a plain socket bound the
    /// same way, as `(name, transport, plain)`. The path MTU discovery mode
    /// (`IP_MTU_DISCOVER`, `IPV6_MTU_DISCOVER`) has no safe getter in `nix` or `socket2`;
    /// the fragmentation e2e test in `nsplane-e2e` (`offload_udp`) checks its effect.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn socket_options(addr: &str, offload: bool) -> Vec<(&'static str, bool, bool)> {
        use nix::sys::socket::{getsockopt, sockopt};

        let transport = bind_with(1, addr, offload);
        let addr: SocketAddr = addr.parse().unwrap();
        let plain = if addr.ip().is_unspecified() {
            bind_dual_stack(addr).unwrap()
        } else {
            bind_socket(addr).unwrap()
        };
        let socket = socket2::SockRef::from(&transport.socket);
        let mut options = vec![
            (
                "UDP_GRO",
                getsockopt(&transport.socket, sockopt::UdpGroSegment).unwrap(),
                getsockopt(&plain, sockopt::UdpGroSegment).unwrap(),
            ),
            (
                "SO_TIMESTAMPNS",
                getsockopt(&transport.socket, sockopt::ReceiveTimestampns).unwrap(),
                getsockopt(&plain, sockopt::ReceiveTimestampns).unwrap(),
            ),
            (
                "IP_RECVTOS",
                socket.recv_tos_v4().unwrap(),
                plain.recv_tos_v4().unwrap(),
            ),
            (
                "IP_RECVERR",
                getsockopt(&transport.socket, sockopt::Ipv4RecvErr).unwrap(),
                getsockopt(&plain, sockopt::Ipv4RecvErr).unwrap(),
            ),
        ];
        if addr.is_ipv4() {
            options.push((
                "IP_PKTINFO",
                getsockopt(&transport.socket, sockopt::Ipv4PacketInfo).unwrap(),
                getsockopt(&plain, sockopt::Ipv4PacketInfo).unwrap(),
            ));
        } else {
            options.extend([
                (
                    "IPV6_DONTFRAG",
                    getsockopt(&transport.socket, sockopt::Ipv6DontFrag).unwrap(),
                    getsockopt(&plain, sockopt::Ipv6DontFrag).unwrap(),
                ),
                (
                    "IPV6_RECVPKTINFO",
                    getsockopt(&transport.socket, sockopt::Ipv6RecvPacketInfo).unwrap(),
                    getsockopt(&plain, sockopt::Ipv6RecvPacketInfo).unwrap(),
                ),
                (
                    "IPV6_RECVTCLASS",
                    socket.recv_tclass_v6().unwrap(),
                    plain.recv_tclass_v6().unwrap(),
                ),
                (
                    "IPV6_RECVERR",
                    getsockopt(&transport.socket, sockopt::Ipv6RecvErr).unwrap(),
                    getsockopt(&plain, sockopt::Ipv6RecvErr).unwrap(),
                ),
            ]);
        }
        options
    }

    /// Bound without offload, the socket has the kernel defaults but for the ECN options
    /// it asks for: `quinn-udp` never set it up.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn offload_off_bind_keeps_kernel_defaults() {
        for addr in ["127.0.0.1:0", "[::1]:0", "[::]:0"] {
            for (name, transport, plain) in socket_options(addr, false) {
                match name {
                    "IP_RECVTOS" | "IPV6_RECVTCLASS" => assert!(transport, "{addr} {name}"),
                    _ => assert_eq!(transport, plain, "{addr} {name}"),
                }
                if matches!(name, "IPV6_DONTFRAG" | "IP_RECVERR" | "IPV6_RECVERR") {
                    assert!(!transport, "{addr} {name}");
                }
            }
        }
    }

    /// Bound with offload, the socket is set up by `quinn-udp`: fragmentation off
    /// (`IPV6_DONTFRAG`), packet info and GRO on; turning offload off keeps that setup.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn offload_bind_sets_socket_up() {
        for addr in ["127.0.0.1:0", "[::1]:0", "[::]:0"] {
            for (name, transport, _) in socket_options(addr, true) {
                match name {
                    // Off until path MTU discovery is turned on.
                    "SO_TIMESTAMPNS" | "IP_RECVERR" | "IPV6_RECVERR" => {
                        assert!(!transport, "{addr} {name}");
                    }
                    // Set where `quinn-udp` finds it supported; IPv6 marks come with
                    // IPV6_RECVTCLASS.
                    "IP_RECVTOS" => {}
                    _ => assert!(transport, "{addr} {name}"),
                }
            }
        }
        let a = bind(1, "[::]:0");
        a.set_offload(false).unwrap();
        assert!(
            nix::sys::socket::getsockopt(&a.socket, nix::sys::socket::sockopt::Ipv6DontFrag)
                .unwrap()
        );
    }

    /// Path MTU discovery asks for ICMP errors only while on; the reports' receiver is
    /// handed out once, after it was first turned on.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn path_mtu_discovery_sets_recverr() {
        // `IP_RECVERR` and `IPV6_RECVERR` when on; a socket bound to a specific IPv6
        // address is IPv6-only and leaves `IP_RECVERR` alone.
        for (addr, on) in [
            ("127.0.0.1:0", &[true][..]),
            ("[::1]:0", &[false, true]),
            ("[::]:0", &[true, true]),
        ] {
            let off = vec![false; on.len()];
            for offload in OFFLOAD {
                let a = bind_with(1, addr, offload);
                assert_eq!(recv_err(&a), off, "{addr}");
                assert!(Transport::path_mtu_reports(&a).is_none());
                a.set_path_mtu_discovery(false).unwrap();
                assert!(Transport::path_mtu_reports(&a).is_none());

                a.set_path_mtu_discovery(true).unwrap();
                assert_eq!(recv_err(&a), on, "{addr}");
                assert!(a.pmtu.on());
                assert!(Transport::path_mtu_reports(&a).is_some());
                assert!(Transport::path_mtu_reports(&a).is_none());

                a.set_path_mtu_discovery(false).unwrap();
                assert_eq!(recv_err(&a), off, "{addr}");
                assert!(!a.pmtu.on());
                a.set_path_mtu_discovery(true).unwrap();
                assert_eq!(recv_err(&a), on, "{addr}");
                assert!(Transport::path_mtu_reports(&a).is_none());
            }
        }
    }

    /// `IP_RECVERR` and, on an IPv6 socket, `IPV6_RECVERR` of `transport`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn recv_err(transport: &UdpTransport) -> Vec<bool> {
        use nix::sys::socket::{getsockopt, sockopt};

        let mut options = vec![getsockopt(&transport.socket, sockopt::Ipv4RecvErr).unwrap()];
        if transport.local.is_ipv6() {
            options.push(getsockopt(&transport.socket, sockopt::Ipv6RecvErr).unwrap());
        }
        options
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[tokio::test]
    async fn path_mtu_discovery_is_unsupported() {
        let a = bind(1, "127.0.0.1:0");
        let err = a.set_path_mtu_discovery(true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        a.set_path_mtu_discovery(false).unwrap();
        assert!(Transport::path_mtu_reports(&a).is_none());
        assert_eq!(a.path_mtu_reports_dropped(), 0);
    }

    /// An error-queue entry with `origin`, ICMP `kind` and `code`, and `info`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn queued_error(origin: u8, (kind, code): (u8, u8), info: u32) -> nix::libc::sock_extended_err {
        nix::libc::sock_extended_err {
            ee_errno: nix::libc::EMSGSIZE.cast_unsigned(),
            ee_origin: origin,
            ee_type: kind,
            ee_code: code,
            ee_pad: 0,
            ee_info: info,
            ee_data: 0,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn error_queue_entries_report_packet_too_big_only() {
        use nix::libc::{SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6, SO_EE_ORIGIN_LOCAL};

        let path = path_to("192.0.2.1:51820".parse().unwrap(), Ecn::NotEct);
        let quote = [4, 0, 0, 0, 1, 2, 3, 4];
        let report = |origin, icmp, info| {
            linux::path_mtu_report(path, &queued_error(origin, icmp, info), &quote)
        };

        let v4 = report(SO_EE_ORIGIN_ICMP, (3, 4), 1400).unwrap();
        assert_eq!((v4.path, v4.mtu, v4.quote()), (path, 1400, &quote[..]));
        let v6 = report(SO_EE_ORIGIN_ICMP6, (2, 0), 1280).unwrap();
        assert_eq!((v6.path, v6.mtu, v6.quote()), (path, 1280, &quote[..]));
        // No MTU in the message; one beyond 16 bits saturates.
        assert_eq!(report(SO_EE_ORIGIN_ICMP, (3, 4), 0).unwrap().mtu, 0);
        assert_eq!(
            report(SO_EE_ORIGIN_ICMP6, (2, 0), 70_000).unwrap().mtu,
            u16::MAX
        );
        let short = linux::path_mtu_report(
            path,
            &queued_error(SO_EE_ORIGIN_ICMP, (3, 4), 1400),
            &quote[..2],
        )
        .unwrap();
        assert_eq!(short.quote(), &quote[..2]);

        for (origin, icmp) in [
            // Port and host unreachable.
            (SO_EE_ORIGIN_ICMP, (3, 3)),
            (SO_EE_ORIGIN_ICMP, (3, 1)),
            // ICMPv6 codes under the other family's origin.
            (SO_EE_ORIGIN_ICMP, (2, 0)),
            (SO_EE_ORIGIN_ICMP6, (3, 4)),
            // Destination unreachable, time exceeded.
            (SO_EE_ORIGIN_ICMP6, (1, 4)),
            (SO_EE_ORIGIN_ICMP6, (3, 0)),
            // A local error (EMSGSIZE on send).
            (SO_EE_ORIGIN_LOCAL, (3, 4)),
            (SO_EE_ORIGIN_LOCAL, (0, 0)),
        ] {
            assert!(report(origin, icmp, 1400).is_none(), "{origin} {icmp:?}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn path_mtu_reports_queue_is_bounded() {
        let a = bind(1, "127.0.0.1:0");
        let report = crate::PathMtuReport::new(path_to(a.local_addr(), Ecn::NotEct), 1400);
        // Not turned on yet: there is no queue.
        a.push_report(report.clone());
        assert_eq!(a.path_mtu_reports_dropped(), 0);

        a.set_path_mtu_discovery(true).unwrap();
        for _ in 0..70 {
            a.push_report(report.clone());
        }
        assert_eq!(a.path_mtu_reports_dropped(), 6);
        let mut reports = Transport::path_mtu_reports(&a).unwrap();
        let mut queued = 0;
        while let Ok(got) = reports.try_recv() {
            assert_eq!(got, report);
            queued += 1;
        }
        assert_eq!(queued, 64);
        a.push_report(report.clone());
        assert_eq!(reports.try_recv().unwrap(), report);

        // A closed receiver drops and counts too.
        drop(reports);
        a.push_report(report);
        assert_eq!(a.path_mtu_reports_dropped(), 7);
    }

    /// With path MTU discovery on, an ICMP port unreachable for an earlier send is read off
    /// the error queue: receiving goes on with the next datagram, and nothing is reported.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn path_mtu_discovery_skips_other_icmp_errors() {
        for (addr, ip) in [
            ("127.0.0.1:0", "127.0.0.1"),
            ("[::1]:0", "::1"),
            ("[::]:0", "127.0.0.1"),
            ("[::]:0", "::1"),
        ] {
            for offload in OFFLOAD {
                let a = bind_with(1, addr, offload);
                let b = bind(2, &SocketAddr::new(ip.parse().unwrap(), 0).to_string());
                a.set_path_mtu_discovery(true).unwrap();
                let mut reports = Transport::path_mtu_reports(&a).unwrap();
                for _ in 0..2 {
                    // A port nobody listens on: bound, then closed.
                    let closed =
                        bind(3, &SocketAddr::new(ip.parse().unwrap(), 0).to_string()).local_addr();
                    a.send(DATAGRAM, &path_to(closed, Ecn::NotEct))
                        .await
                        .unwrap();
                    roundtrip(&b, b.local_addr(), &a, seen_as(&a, ip)).await;
                }
                assert!(reports.try_recv().is_err(), "{addr} {ip} {offload}");
                assert_eq!(a.path_mtu_reports_dropped(), 0);
            }
        }
    }

    #[tokio::test]
    async fn offload_cannot_be_turned_on_when_bound_without() {
        let a = bind_with(1, "127.0.0.1:0", false);
        assert!(!a.offload());
        assert_eq!(a.max_segments(), 1);
        a.set_offload(false).unwrap();
        let err = a.set_offload(true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(!a.offload());
        assert!(a.state.is_none());
    }

    /// Linux's default socket buffer size (`net.core.rmem_default`), as reported.
    const OLD_DEFAULT: usize = 212_992;

    /// What the kernel reports for a request of `requested` bytes: on Linux the request
    /// clamped to the sysctl `max` and doubled; `None` elsewhere or when unreadable.
    fn granted(requested: usize, max: &str) -> Option<usize> {
        if !cfg!(any(target_os = "linux", target_os = "android")) {
            return None;
        }
        let max: usize = std::fs::read_to_string(format!("/proc/sys/net/core/{max}"))
            .ok()?
            .trim()
            .parse()
            .ok()?;
        Some(2 * requested.min(max))
    }

    #[tokio::test]
    async fn default_socket_buffers() {
        for offload in OFFLOAD {
            let plain = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            let a = bind_with(1, "127.0.0.1:0", offload);
            for (effective, before, max) in [
                (a.recv_buffer_size(), plain.recv_buffer_size(), "rmem_max"),
                (a.send_buffer_size(), plain.send_buffer_size(), "wmem_max"),
            ] {
                let (effective, before) = (effective.unwrap(), before.unwrap());
                match granted(DEFAULT_SOCKET_BUFFER, max) {
                    Some(granted) => {
                        assert_eq!(effective, granted, "{max}");
                        if granted > OLD_DEFAULT {
                            assert!(effective > OLD_DEFAULT, "{max}");
                        }
                    }
                    None => assert!(effective > 0 && effective >= before, "{max}"),
                }
            }
        }
    }

    #[tokio::test]
    async fn socket_buffer_setters() {
        for offload in OFFLOAD {
            let a = bind_with(1, "[::]:0", offload);
            let mut previous = [0; 2];
            for bytes in [64 << 10, 1 << 20] {
                a.set_recv_buffer_size(bytes).unwrap();
                a.set_send_buffer_size(bytes).unwrap();
                let effective = [a.recv_buffer_size().unwrap(), a.send_buffer_size().unwrap()];
                for ((effective, previous), max) in
                    effective.iter().zip(previous).zip(["rmem_max", "wmem_max"])
                {
                    match granted(bytes, max) {
                        Some(granted) => assert_eq!(*effective, granted, "{max}"),
                        None => assert!(*effective > previous, "{max}"),
                    }
                }
                previous = effective;
            }
        }
    }

    /// A burst of 512 datagrams of 1420 bytes sent before the receiver reads fits into the
    /// default receive buffer, with offload on, turned off, and bound without.
    #[tokio::test]
    async fn burst_fits_default_buffer() {
        for (bound, offload) in [(true, true), (true, false), (false, false)] {
            let a = bind_with(1, "127.0.0.1:0", bound);
            let b = bind_with(2, "127.0.0.1:0", bound);
            a.set_offload(offload).unwrap();
            b.set_offload(offload).unwrap();
            let datagrams: Vec<_> = (0..512).map(|seq| numbered(seq, 1420)).collect();
            send_all(&a, &batch(b.local_addr(), Ecn::NotEct, &datagrams)).await;
            let received = recv_batches(&b, datagrams.len()).await.concat();
            check(&received, &datagrams, a.local_addr(), Ecn::NotEct);
        }
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
        let (mut sent, mut failed) = (0, 0);
        transport
            .send_batch(batch, &mut sent, &mut failed)
            .await
            .unwrap();
        assert_eq!((sent, failed), (batch.len(), 0));
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
        from.max_segments() > 1
            && to.offload()
            && to
                .state
                .as_ref()
                .is_some_and(|state| state.gro_segments() > 1)
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
        for offload in OFFLOAD {
            segmented_to_plain_with(send_on, recv_on, seen_as_ip, offload).await;
        }
    }

    async fn segmented_to_plain_with(
        send_on: &str,
        recv_on: &str,
        seen_as_ip: &str,
        offload: bool,
    ) {
        let sender = bind_with(1, send_on, offload);
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
        for offload in OFFLOAD {
            let receiver = bind_with(1, "127.0.0.1:0", offload);
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
    }

    /// `from` sends a segmented train of each size with ECT(0) to `to`, which receives it
    /// in one read where both ends coalesce: slices of one buffer where they were read,
    /// without a copy.
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
                let first = calls[0][0].1.as_packet().as_ptr().addr();
                for (i, (_, datagram)) in calls[0].iter().enumerate() {
                    assert_eq!(datagram.headroom(), 0, "size {size}: datagram {i}");
                    assert_eq!(
                        datagram.as_packet().as_ptr().addr(),
                        first + i * size,
                        "size {size}: datagram {i} is not where it was read"
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
        for offload in OFFLOAD {
            mixed_batch(offload).await;
        }
    }

    async fn mixed_batch(offload: bool) {
        let sender = bind_with(1, "[::]:0", offload);
        let v4 = bind_with(2, "127.0.0.1:0", offload);
        let v6 = bind_with(3, "[::1]:0", offload);
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

    /// A batch whose middle run goes to the limited broadcast address, which the kernel
    /// refuses without `SO_BROADCAST`: a call fails only the datagrams of that run, and
    /// called past its errors as the engine does, the batch loses exactly that run while
    /// the runs around it arrive in order.
    #[tokio::test]
    async fn failed_run_counts_only_its_datagrams() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let b = bind_with(2, "127.0.0.1:0", offload);
            let refused: SocketAddr = "255.255.255.255:9".parse().unwrap();
            let (head, lost, tail) = (train(1280, 6), train(1280, 4), train(1280, 3));
            let mut datagrams = batch(b.local_addr(), Ecn::NotEct, &head);
            datagrams.extend(batch(refused, Ecn::NotEct, &lost));
            datagrams.extend(batch(b.local_addr(), Ecn::NotEct, &tail));
            let run = run_len(&datagrams[head.len()..], a.max_segments());
            if offload && cfg!(any(target_os = "linux", target_os = "android")) {
                assert_eq!(run, lost.len(), "one segmented run");
            }

            let (mut sent, mut failed) = (0, 0);
            a.send_batch(&datagrams, &mut sent, &mut failed)
                .await
                .unwrap_err();
            assert_eq!((sent, failed), (head.len() + run, run));
            while sent < datagrams.len() {
                let before = (sent, failed);
                if a.send_batch(&datagrams, &mut sent, &mut failed)
                    .await
                    .is_ok()
                {
                    assert_eq!(failed, before.1);
                } else {
                    assert!(failed > before.1 && failed - before.1 <= sent - before.0);
                }
            }
            assert_eq!((sent, failed), (datagrams.len(), lost.len()));

            let received = recv_batches(&b, head.len() + tail.len()).await.concat();
            check(
                &received,
                &[head, tail].concat(),
                a.local_addr(),
                Ecn::NotEct,
            );
        }
    }

    /// Sends `batch` with `try_send_batch`, waiting for the socket after each
    /// [`io::ErrorKind::WouldBlock`], which must leave the counts as they were.
    async fn try_send_all(transport: &UdpTransport, batch: &[(Path, PacketBuf)]) {
        let (mut sent, mut failed) = (0, 0);
        loop {
            let before = sent;
            match transport.try_send_batch(batch, &mut sent, &mut failed) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(sent >= before && sent < batch.len());
                    transport.socket.writable().await.unwrap();
                }
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!((sent, failed), (batch.len(), 0));
    }

    #[tokio::test]
    async fn try_send_batch_sends_runs_in_order() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let b = bind_with(2, "127.0.0.1:0", offload);
            let datagrams = [train(1280, 20), train(900, 3), vec![numbered(7, 1400)]].concat();
            let batch = batch(b.local_addr(), Ecn::Ect0, &datagrams);
            if offload && cfg!(any(target_os = "linux", target_os = "android")) {
                assert!(run_len(&batch, a.max_segments()) > 1, "segmented runs");
            }
            // The reactor has not reported the new socket writable yet: nothing goes out
            // and nothing counts.
            let (mut sent, mut failed) = (0, 0);
            let error = a
                .try_send_batch(&batch, &mut sent, &mut failed)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert_eq!((sent, failed), (0, 0));
            try_send_all(&a, &batch).await;
            let received = recv_batches(&b, datagrams.len()).await.concat();
            check(&received, &datagrams, a.local_addr(), Ecn::Ect0);
        }
    }

    #[tokio::test]
    async fn try_send_batch_failed_run_counts_only_its_datagrams() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let b = bind_with(2, "127.0.0.1:0", offload);
            a.socket.writable().await.unwrap();
            let refused: SocketAddr = "255.255.255.255:9".parse().unwrap();
            let (head, lost, tail) = (train(1280, 6), train(1280, 4), train(1280, 3));
            let mut datagrams = batch(b.local_addr(), Ecn::NotEct, &head);
            datagrams.extend(batch(refused, Ecn::NotEct, &lost));
            datagrams.extend(batch(b.local_addr(), Ecn::NotEct, &tail));
            let run = run_len(&datagrams[head.len()..], a.max_segments());

            let (mut sent, mut failed) = (0, 0);
            let error = a
                .try_send_batch(&datagrams, &mut sent, &mut failed)
                .unwrap_err();
            assert_ne!(error.kind(), io::ErrorKind::WouldBlock);
            assert_eq!((sent, failed), (head.len() + run, run));
            while sent < datagrams.len() {
                let before = (sent, failed);
                match a.try_send_batch(&datagrams, &mut sent, &mut failed) {
                    Ok(()) => assert_eq!(failed, before.1),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert_eq!(failed, before.1);
                        a.socket.writable().await.unwrap();
                    }
                    Err(_) => {
                        assert!(failed > before.1 && failed - before.1 <= sent - before.0);
                    }
                }
            }
            assert_eq!((sent, failed), (datagrams.len(), lost.len()));

            let received = recv_batches(&b, head.len() + tail.len()).await.concat();
            check(
                &received,
                &[head, tail].concat(),
                a.local_addr(),
                Ecn::NotEct,
            );
        }
    }

    /// The prefix of the side datagrams in the side channel tests.
    const SIDE: &[u8] = b"NSGWP2P1";

    fn is_side(datagram: &[u8]) -> bool {
        datagram.starts_with(SIDE)
    }

    /// A side datagram carrying `body`.
    fn side(body: &[u8]) -> Vec<u8> {
        [SIDE, body].concat()
    }

    /// The side datagrams waiting in `rx`, as `(from, datagram)`.
    fn drain(rx: &mut mpsc::Receiver<SideDatagram>) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut taken = Vec::new();
        while let Ok(side) = rx.try_recv() {
            taken.push((side.from, side.datagram.to_vec()));
        }
        taken
    }

    /// Side datagrams sent before a WireGuard-like one are taken out of `recv`, which
    /// returns the WireGuard-like one.
    #[tokio::test]
    async fn side_channel_takes_classified_datagrams_from_recv() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let (b, _, mut side_rx) =
                bind_with(2, "127.0.0.1:0", offload).with_side_channel(is_side, 8);
            let control = side(b"control");
            for datagram in [&control[..], &control, DATAGRAM] {
                a.send(datagram, &path_to(b.local_addr(), Ecn::NotEct))
                    .await
                    .unwrap();
            }
            let (buf, path) = recv(&b, 1500).await;
            assert_eq!(buf.as_packet(), DATAGRAM);
            assert_eq!(path.addr, a.local_addr());
            assert_eq!(drain(&mut side_rx), vec![(a.local_addr(), control); 2]);
        }
    }

    /// A train of equally sized datagrams, every third one a side datagram: `recv_batch`
    /// and `recv` hand out the others in order and the side channel gets the side ones,
    /// with offload on (one coalesced read where the kernel coalesces) and off.
    #[tokio::test]
    async fn side_channel_splits_mixed_trains() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let (b, sender, mut side_rx) =
                bind_with(2, "127.0.0.1:0", offload).with_side_channel(is_side, 64);
            // Ends with a WireGuard-like datagram, so every side one was read before it.
            let datagrams: Vec<_> = (0..21)
                .map(|seq| {
                    let datagram = numbered(seq, 1280);
                    if seq % 3 == 1 {
                        side(&datagram[SIDE.len()..])
                    } else {
                        datagram
                    }
                })
                .collect();
            let (sides, wireguard): (Vec<_>, Vec<_>) =
                datagrams.iter().cloned().partition(|d| is_side(d));
            let sides: Vec<_> = sides.into_iter().map(|d| (a.local_addr(), d)).collect();
            let batch = batch(b.local_addr(), Ecn::Ect0, &datagrams);

            send_all(&a, &batch).await;
            let calls = recv_batches(&b, wireguard.len()).await;
            if coalescing(&a, &b) {
                assert_eq!(calls.len(), 1, "one coalesced read");
            }
            check(&calls.concat(), &wireguard, a.local_addr(), Ecn::Ect0);
            assert_eq!(drain(&mut side_rx), sides);

            send_all(&a, &batch).await;
            let mut received = Vec::new();
            for _ in &wireguard {
                let (buf, path) = recv(&b, 1500).await;
                received.push((path, buf));
            }
            check(&received, &wireguard, a.local_addr(), Ecn::Ect0);
            assert_eq!(drain(&mut side_rx), sides);
            assert_eq!(
                sender.stats(),
                SideStats {
                    received: 2 * sides.len() as u64,
                    dropped: 0
                }
            );
        }
    }

    /// A full receiver drops side datagrams and counts them; a read of side datagrams only
    /// does not end `recv_batch` without a datagram.
    #[tokio::test]
    async fn side_channel_counts_drops_when_full() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let (b, sender, mut side_rx) =
                bind_with(2, "127.0.0.1:0", offload).with_side_channel(is_side, 1);
            let sides = vec![side(b"control"); 3];
            send_all(&a, &batch(b.local_addr(), Ecn::NotEct, &sides)).await;
            a.send(DATAGRAM, &path_to(b.local_addr(), Ecn::NotEct))
                .await
                .unwrap();
            let calls = recv_batches(&b, 1).await;
            check(
                &calls.concat(),
                &[DATAGRAM.to_vec()],
                a.local_addr(),
                Ecn::NotEct,
            );
            assert_eq!(
                sender.stats(),
                SideStats {
                    received: 1,
                    dropped: 2
                }
            );
            assert_eq!(drain(&mut side_rx).len(), 1);
        }
    }

    /// A closed receiver drops side datagrams and counts them.
    #[tokio::test]
    async fn side_channel_counts_drops_when_closed() {
        for offload in OFFLOAD {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let (b, sender, side_rx) =
                bind_with(2, "127.0.0.1:0", offload).with_side_channel(is_side, 4);
            drop(side_rx);
            let control = side(b"control");
            for datagram in [&control[..], &control, DATAGRAM] {
                a.send(datagram, &path_to(b.local_addr(), Ecn::NotEct))
                    .await
                    .unwrap();
            }
            let (buf, _) = recv(&b, 1500).await;
            assert_eq!(buf.as_packet(), DATAGRAM);
            assert_eq!(
                sender.stats(),
                SideStats {
                    received: 0,
                    dropped: 2
                }
            );
        }
    }

    /// A side sender sends from the transport's address, unmarked, mapping destinations as
    /// the transport does; side datagrams back are reported from the unmapped address. A
    /// second side channel replaces the first.
    #[tokio::test]
    async fn side_sender_sends_from_the_transport() {
        for offload in OFFLOAD {
            let (dual, sender, mut side_rx) =
                bind_with(1, "[::]:0", offload).with_side_channel(is_side, 4);
            assert_eq!(sender.local_addr(), dual.local_addr());
            let v4 = bind_with(2, "127.0.0.1:0", offload);
            let dual_v4 = seen_as(&dual, "127.0.0.1");
            let control = side(b"punch");
            sender.send_to(&control, v4.local_addr()).unwrap();
            let (buf, path) = recv(&v4, 1500).await;
            assert_eq!(buf.as_packet(), control);
            assert_eq!(path.addr, dual_v4);
            assert_eq!(path.ecn, Ecn::NotEct);

            for datagram in [&control[..], DATAGRAM] {
                v4.send(datagram, &path_to(dual_v4, Ecn::NotEct))
                    .await
                    .unwrap();
            }
            let (buf, _) = recv(&dual, 1500).await;
            assert_eq!(buf.as_packet(), DATAGRAM);
            assert_eq!(drain(&mut side_rx), [(v4.local_addr(), control.clone())]);

            let (_, v4_sender, _) =
                bind_with(3, "127.0.0.1:0", offload).with_side_channel(is_side, 1);
            let err = v4_sender
                .send_to(&control, "[::1]:9".parse().unwrap())
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

            let (dual, second, mut second_rx) = dual.with_side_channel(is_side, 4);
            assert!(matches!(
                side_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Disconnected)
            ));
            for datagram in [&control[..], DATAGRAM] {
                v4.send(datagram, &path_to(dual_v4, Ecn::NotEct))
                    .await
                    .unwrap();
            }
            recv(&dual, 1500).await;
            assert_eq!(drain(&mut second_rx), [(v4.local_addr(), control)]);
            assert_eq!(sender.stats().received, 1);
            assert_eq!(second.stats().received, 1);
        }
    }

    /// `send_to_async` addresses as `send_to` does: from the transport's address, unmarked,
    /// IPv4 destinations of a dual-stack socket mapped, IPv6 ones on an IPv4 socket rejected.
    #[tokio::test]
    async fn side_sender_send_to_async_addresses_as_send_to() {
        for offload in OFFLOAD {
            let (dual, sender, _) = bind_with(1, "[::]:0", offload).with_side_channel(is_side, 1);
            let v4 = bind_with(2, "127.0.0.1:0", offload);
            let control = side(b"probe");
            sender
                .send_to_async(&control, v4.local_addr())
                .await
                .unwrap();
            let (buf, path) = recv(&v4, 1500).await;
            assert_eq!(buf.as_packet(), control);
            assert_eq!(path.addr, seen_as(&dual, "127.0.0.1"));
            assert_eq!(path.ecn, Ecn::NotEct);

            let (_, v4_sender, _) =
                bind_with(3, "127.0.0.1:0", offload).with_side_channel(is_side, 1);
            let err = v4_sender
                .send_to_async(&control, "[::1]:9".parse().unwrap())
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
    }

    /// With the send buffer full, `send_to` fails with `WouldBlock` while `send_to_async`
    /// waits and sends once the buffer drains; a `send_to_async` dropped while waiting sends
    /// nothing. Loopback frees a datagram's buffer space at once, so the buffer is filled
    /// with datagrams to a neighbour on a dummy interface that never answers ARP: they wait
    /// in its queue until resolution gives up (about 3 s) and frees them.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN"]
    async fn side_sender_send_to_async_waits_for_a_full_send_buffer() {
        const DEV: &str = "nsside0";
        let ip = |args: &[&str]| {
            let status = std::process::Command::new("ip")
                .args(args)
                .status()
                .unwrap();
            assert!(status.success(), "ip {args:?}: {status}");
        };
        ip(&["link", "add", DEV, "type", "dummy"]);
        ip(&["link", "set", DEV, "arp", "on", "up"]);
        ip(&["addr", "add", "10.200.0.1/24", "dev", DEV]);

        let (a, sender, _) = bind(1, "0.0.0.0:0").with_side_channel(is_side, 1);
        a.set_send_buffer_size(1).unwrap();
        let b = bind(2, "127.0.0.1:0");
        let unresolved: SocketAddr = "10.200.0.2:9".parse().unwrap();
        for seq in 0.. {
            assert!(seq < 1000, "the send buffer never filled");
            match sender.send_to(&numbered(seq, 1400), unresolved) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        let control = side(b"register");
        let err = sender.send_to(&control, b.local_addr()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        let cancelled = sender.send_to_async(b"cancelled", b.local_addr());
        assert!(
            timeout(Duration::from_millis(100), cancelled)
                .await
                .is_err()
        );
        timeout(
            Duration::from_secs(10),
            sender.send_to_async(&control, b.local_addr()),
        )
        .await
        .unwrap()
        .unwrap();
        let (buf, path) = recv(&b, 1500).await;
        assert_eq!(buf.as_packet(), control);
        assert_eq!(path.addr, seen_as(&a, "127.0.0.1"));
        let mut buf = PacketBuf::with_capacity(1500);
        assert!(
            timeout(Duration::from_millis(100), b.recv(&mut buf))
                .await
                .is_err()
        );
        ip(&["link", "del", DEV]);
    }
}
