//! The default network-side transport: one tokio UDP socket driven through `quinn-udp`,
//! with segmentation offload, and an optional side channel for datagrams that are not the
//! engine's on the same socket.

mod send;
mod side;
mod socket;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use nsplane_packet::{Ecn, PacketBuf, Path, TransportId};
use quinn_udp::{UdpSockRef, UdpSocketState};
#[cfg(any(target_os = "linux", target_os = "android"))]
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use self::send::run_len;
#[cfg(any(target_os = "linux", target_os = "android"))]
use self::send::write_io;
use self::side::{Side, SideCounters};
pub use self::side::{SideDatagram, SideSender, SideStats};
use self::socket::{bind_dual_stack, bind_socket, set_up, target, unmap};
use crate::transport::Transport;

/// The most bytes one send carries: the largest IPv4 UDP payload, so also the limit of a
/// segmented send.
const MAX_SEND: usize = 65_507;

/// The socket buffer size [`UdpTransport::bind`] requests for both directions.
const DEFAULT_SOCKET_BUFFER: usize = 4 << 20;

/// The error queue belongs to the socket, including its side-channel sends.
#[derive(Debug)]
struct SocketErrors {
    id: TransportId,
    discovery: AtomicBool,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pmtu: linux::Pmtu,
    dropped: AtomicU64,
}

impl SocketErrors {
    const fn new(id: TransportId) -> Self {
        Self {
            id,
            discovery: AtomicBool::new(false),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            pmtu: linux::Pmtu::new(),
            dropped: AtomicU64::new(0),
        }
    }

    /// Retries only an unsuccessful syscall, never an accepted batch prefix. A concurrent
    /// receiver may already have drained its ICMP error, so one retry needs no queued
    /// evidence; further retries require an asynchronous error from the queue.
    fn write<R>(
        &self,
        socket: &UdpSocket,
        mut write: impl FnMut() -> io::Result<R>,
    ) -> io::Result<R> {
        let mut retries = 0;
        loop {
            match write() {
                Err(error)
                    if self.discovery.load(Ordering::Relaxed)
                        && error.kind() != io::ErrorKind::WouldBlock =>
                {
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    let asynchronous = self.drain_errors(socket);
                    #[cfg(not(any(target_os = "linux", target_os = "android")))]
                    let asynchronous = {
                        let _ = socket;
                        false
                    };
                    if retries == 7 || (retries > 0 && !asynchronous) {
                        return Err(error);
                    }
                    retries += 1;
                }
                result => return result,
            }
        }
    }
}

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
/// Android it is driven with `sendmsg` / `recvmsg` (`sendmmsg` / `recvmmsg` for batches),
/// the ECN marks in `IP_TOS` / `IPV6_TCLASS` control messages (received ones asked for with
/// `IP_RECVTOS` / `IPV6_RECVTCLASS`); elsewhere with plain `send_to` / `recv_from`, without
/// ECN marks.
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
///   the engine opens it in place: no datagram of a train is copied. While trains do not
///   arrive (four reads in a row of one datagram each, as from senders without
///   segmentation), [`recv_batch`](Transport::recv_batch) reads up to 16 datagrams with one
///   `recvmmsg` instead, each into a slot of 64 KiB, and copies them out; the first train
///   read that way switches back to one 64 KiB read without copies.
///   [`recv`](Transport::recv) copies one datagram into the caller's buffer and keeps the
///   rest of the train for the next receive.
/// - Send (Linux and Android `UDP_SEGMENT`, Windows USO):
///   [`send_batch`](Transport::send_batch) sends a run of consecutive datagrams to the same
///   address with the same ECN mark and of the same size (the last may be shorter) as one
///   segmented send, up to the kernel's segment limit and 64 KiB: on Linux and Android
///   straight from the datagrams' buffers, one `iovec` each, elsewhere copied into one
///   buffer the transport keeps. Datagrams that start no run are sent one by one. Where
///   segmentation is not available, or a segmented send fails with `EIO` or `EINVAL` (a
///   device without segmentation support), sending falls back to one datagram per send
///   (the failing run goes through `quinn-udp`, which turns segmentation off). A failed send
///   drops and counts exactly the datagrams of its run, so the engine counts each of them
///   under [`crate::DROP_TRANSPORT_SEND_ERROR`] and none of the runs handed off before it.
///
/// With offload off (turned off or bound without), on Linux and Android
/// [`send_batch`](Transport::send_batch) hands consecutive datagrams to the same address
/// with the same ECN mark to one `sendmmsg`, up to 64, and
/// [`recv_batch`](Transport::recv_batch) reads up to 16 datagrams with one `recvmmsg`, each
/// into a slot as large as the caller's buffer and copied out: batching, not offload, as
/// every datagram stays its own message (and a failed one fails alone). Elsewhere, or where
/// those calls do not exist, every datagram takes one system call in both directions.
/// Either way the datagrams, their order, sizes, paths and ECN marks are the same.
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
    /// Error queue and PMTU reports shared with the side senders.
    errors: Arc<SocketErrors>,
    /// The buffer a run is copied into where it is not sent from the datagrams' own
    /// buffers (see [`UdpTransport::send_run_now`]).
    train: std::sync::Mutex<Vec<u8>>,
    /// `sendmmsg` / `recvmmsg` failed with `ENOSYS`: one datagram per system call.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    no_mmsg: AtomicBool,
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
            local,
            socket: Arc::new(socket),
            state,
            plain: !offload,
            offload: AtomicBool::new(offload),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            rx: std::sync::Mutex::default(),
            side: None,
            errors: Arc::new(SocketErrors::new(id)),
            train: std::sync::Mutex::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            no_mmsg: AtomicBool::new(false),
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
            errors: Arc::clone(&self.errors),
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
    /// for them and reads at most 64 queued errors before each datagram read attempt: each
    /// ICMP Fragmentation Needed (type 3, code 4) or `ICMPv6` Packet Too Big (type 2,
    /// code 0) about one of the transport's datagrams becomes a
    /// [`PathMtuReport`](crate::PathMtuReport) for the
    /// datagram's destination (reported as [`Path::addr`] would report it) with the MTU the
    /// error carries, quoting the datagram's leading bytes. Failed sends also read this
    /// queue. Other errors (port unreachable, for example) are read and skipped. No ICMP
    /// error fails a receive.
    ///
    /// The reports go to the receiver [`Transport::path_mtu_reports`] hands out, once,
    /// after this was first turned on; so turn it on before handing the transport to the
    /// engine, which takes the receiver when it installs the transport. The receiver holds
    /// up to 64 reports; while it is full or closed further reports are dropped and
    /// counted ([`path_mtu_reports_dropped`](Self::path_mtu_reports_dropped)).
    ///
    /// The kernel learns of a too small path only for datagrams sent with the DF bit: with
    /// offload ([`bind`](Self::bind)) all of them, without it those below the path MTU the
    /// kernel knows (it fragments larger ones itself). An ICMP error reported by a send
    /// belongs to an earlier datagram, possibly to another destination. A failed send
    /// reads up to 64 queued errors and retries the unaccepted operation once, even if a
    /// concurrent receiver has already read the error. Further retries require a queued
    /// ICMP error; at most seven retries are made. Successful batch prefixes are never
    /// retried. Persistent errors still fail: the engine drops and counts the failed
    /// datagram, and [`SideSender`] returns the error. Packet Too Big reports read by a
    /// sender use the same report queue and accounting as those read by a receiver.
    ///
    /// Once the socket has reported an error, tokio
    /// reports it writable for good, so sends that find the
    /// send buffer full ([`send`](Transport::send), [`send_batch`](Transport::send_batch),
    /// [`SideSender::send_to_async`]) no longer wait for room: they try again after a
    /// pause of 1 ms, doubling up to 8 ms, until it fits. Such a send may go out up to 8 ms
    /// later than the buffer had room; sends that find room are not delayed.
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
        self.errors.dropped.load(Ordering::Relaxed)
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
            transport: self.errors.id,
            addr: unmap(addr),
            ecn,
        }
    }
}

impl Transport for UdpTransport {
    fn id(&self) -> TransportId {
        self.errors.id
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
        while let Some((to, first)) = datagrams.get(*sent) {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if self.batching() {
                let run = &datagrams[*sent..*sent + linux::mmsg_len(&datagrams[*sent..])];
                let result = match self.target(to.addr) {
                    Ok(destination) => {
                        write_io(&self.socket, &self.errors, || {
                            self.send_mmsg_or_one(run, destination, to.ecn)
                        })
                        .await
                    }
                    Err(e) => Err(e),
                };
                // Each datagram is its own message: a failure loses that one only.
                *sent += *result.as_ref().unwrap_or(&1);
                result.inspect_err(|_| *failed += 1)?;
                continue;
            }
            let run = run_len(&datagrams[*sent..], self.max_segments());
            let result = match &self.state {
                Some(state) if run > 1 => {
                    self.send_run(state, &datagrams[*sent..*sent + run], to)
                        .await
                }
                _ => self.send_segments(first.as_packet(), None, to).await,
            };
            *sent += run;
            // A failed send loses its run only; the runs before it were handed off.
            result.inspect_err(|_| *failed += run)?;
        }
        Ok(())
    }

    /// [`send_batch`](Transport::send_batch) without waiting: the same runs and bounded
    /// ICMP recovery; a run the socket cannot take now ends the call with
    /// [`io::ErrorKind::WouldBlock`] and stays unsent.
    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        while let Some((to, first)) = datagrams.get(*sent) {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if self.batching() {
                let run = &datagrams[*sent..*sent + linux::mmsg_len(&datagrams[*sent..])];
                let result = self.target(to.addr).and_then(|destination| {
                    self.socket.try_io(Interest::WRITABLE, || {
                        self.errors.write(&self.socket, || {
                            self.send_mmsg_or_one(run, destination, to.ecn)
                        })
                    })
                });
                if let Err(e) = &result
                    && e.kind() == io::ErrorKind::WouldBlock
                {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                *sent += *result.as_ref().unwrap_or(&1);
                result.inspect_err(|_| *failed += 1)?;
                continue;
            }
            let run = run_len(&datagrams[*sent..], self.max_segments());
            let result = match &self.state {
                Some(state) if run > 1 => {
                    self.try_send_run(state, &datagrams[*sent..*sent + run], to)
                }
                _ => self.try_send_segments(first.as_packet(), None, to),
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
        self.errors.pmtu.take()
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
