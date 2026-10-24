//! The stack, its source and sink halves, its handle and the driver task.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use nsplane::{PacketSink, PacketSource};
use nsplane_packet::reassembly::{Outcome, Reassembler, ReassemblyStats};
use nsplane_packet::{IpPacket, PacketBuf, PeerId, checksum, protocol};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{AnySocket, tcp};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, TcpSeqNumber};
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::config::{Admission, NetStackConfig, Settings, TcpRto};
use crate::device::{TAILROOM, VirtualDevice};
use crate::events::{EventSink, FlowEvent, FlowEventReason};
use crate::flow::{Fence, Fences, FlowState, RetirementOutcome, Revocations, Target};
use crate::ownership::{Owners, Ownership, Registration};
use crate::pending::{self, Hold, Pending, PendingFlow, PendingProtocol};
use crate::pmtu::{self, Message, TooBig};
use crate::stats::{self, Counters, NetStackStats};
use crate::tcp::{Progress, Shared, TcpConnection, WriteHalf, lock};
use crate::udp::{self, Datagram, UdpFlow, UdpOut, UdpReply, UdpSocket};

/// Most ingress packets taken per driver iteration before smoltcp runs, so one burst
/// cannot starve the bridge phase.
const MAX_INJECT_PER_ITER: usize = 256;
/// Egress packets the device holds while the source's queue is full. smoltcp stops
/// transmitting at this bound; only immediate replies to ingested packets are dropped
/// (and counted) beyond it.
const EGRESS_BACKLOG: usize = 256;
/// Commands (`connect_tcp`, `bind_udp`, `connect_udp`) queued for the driver.
const COMMAND_CAPACITY: usize = 64;
/// Longest the driver sleeps without a timer from smoltcp.
const MAX_POLL_DELAY: Duration = Duration::from_millis(50);
/// Maximum interval without application payload in either direction of a connection.
const TCP_IDLE_TIMEOUT: SmolDuration = SmolDuration::from_secs(5 * 60);
/// How long `connect_tcp` waits for the handshake.
const CONNECT_TIMEOUT: SmolDuration = SmolDuration::from_secs(20);
/// First ephemeral port for `connect_tcp`, `bind_udp` and `connect_udp` on port 0
/// (RFC 6335).
const EPHEMERAL_START: u16 = 49_152;

fn stack_gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "network stack stopped")
}

/// A user-space TCP/IP stack on smoltcp, seen from the data plane.
///
/// [`NetStack::new`] starts the stack; [`split`](Self::split) yields the
/// [`PacketSource`] and [`PacketSink`] an `nsplane::EngineBuilder` takes, and the
/// returned [`NetStackHandle`] accepts and opens TCP connections and UDP flows.
///
/// The stack is the endpoint for TCP and UDP addressed to its own addresses (any port), for IPv4
/// and IPv6, and with [`NetStackConfig::transparent`] to any in-prefix destination.
/// Everything else it receives is dropped and counted in [`NetStackHandle::stats`].
#[derive(Debug)]
pub struct NetStack {
    source: NetStackSource,
    sink: NetStackSink,
}

impl NetStack {
    /// Starts a stack with `config`, normalised as documented on [`NetStackConfig`].
    ///
    /// Spawns the stack's single driver task on the current tokio runtime. The driver
    /// stops once the [`NetStackSink`] or the [`NetStackSource`] is dropped; every
    /// connection, flow and socket of the stack then reports the stack as gone.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    pub fn new(config: NetStackConfig) -> (Self, NetStackHandle) {
        let settings = Settings::new(config);
        let stats = Arc::new(Counters::default());
        let notify = Arc::new(Notify::new());
        let (ingress_tx, ingress) = mpsc::channel(settings.ingress_capacity);
        let (egress, egress_rx) = mpsc::channel(settings.egress_capacity);
        let (commands_tx, commands) = mpsc::channel(COMMAND_CAPACITY);
        let (udp_tx, udp_rx) = mpsc::channel(settings.datagram_capacity);
        let (accept_tcp, incoming_tcp) = mpsc::channel(settings.accept_capacity);
        let (accept_udp, incoming_udp) = mpsc::channel(settings.accept_capacity);
        let (pending, incoming_pending) = pending_table(&settings, &notify).unzip();
        let pending = pending.map(Box::new);
        let (events, flow_events) = event_sink(&settings).unzip();
        let events = events.map(Box::new);
        let (_, mtu) = watch::channel(settings.mtu);
        let owners = Arc::new(Owners::new(
            settings.v4.map(|(addr, _)| addr),
            settings.v6.map(|(addr, _)| addr),
            settings
                .transparent
                .as_ref()
                .map(|transparent| transparent.prefixes.clone()),
            settings.reassembly.as_ref(),
        ));
        let reassembler = settings.reassembly.clone().map(Reassembler::new);
        let revocations = Arc::new(Revocations::new(Arc::clone(&notify)));
        let fences = Arc::new(Fences::default());

        let mut device = VirtualDevice::new(settings.mtu, EGRESS_BACKLOG, Arc::clone(&stats));
        let iface = interface(&settings, &mut device);
        let out = UdpOut {
            tx: udp_tx,
            mtu: usize::from(settings.mtu),
            allow_fragmentation: settings.udp_allow_fragmentation,
        };
        let driver = Driver {
            settings,
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            listeners: HashMap::new(),
            inbound: HashMap::new(),
            allocation_cursor: 0,
            conns: HashMap::new(),
            aborting: Vec::new(),
            deferred: Vec::new(),
            connecting: Vec::new(),
            flows: HashMap::new(),
            bound: HashMap::new(),
            connected: HashMap::new(),
            ingress,
            batch: Vec::with_capacity(MAX_INJECT_PER_ITER),
            egress,
            commands: Some(commands),
            udp_rx,
            out,
            accept_tcp,
            accept_udp,
            notify,
            stats: Arc::clone(&stats),
            carried: None,
            next_tcp_port: random_ephemeral(),
            next_udp_port: random_ephemeral(),
            waiting: VecDeque::new(),
            epoch: Instant::now(),
            owners: Arc::clone(&owners),
            reassembler,
            reassembly_counted: ReassemblyStats::default(),
            revocations: Arc::clone(&revocations),
            retiring: Vec::new(),
            sent: 0,
            marks: VecDeque::new(),
            fences: Arc::clone(&fences),
            barriers: Vec::new(),
            pending,
            events,
            #[cfg(test)]
            turns: 0,
        };
        tokio::spawn(driver.run());

        let stack = Self {
            source: NetStackSource {
                rx: egress_rx,
                mtu,
                received: 0,
                revocations,
                fences,
                stats: Arc::clone(&stats),
            },
            sink: NetStackSink { tx: ingress_tx },
        };
        let handle = NetStackHandle {
            commands: commands_tx,
            incoming_tcp: Arc::new(Mutex::new(Some(incoming_tcp))),
            incoming_udp: Arc::new(Mutex::new(Some(incoming_udp))),
            incoming_pending: Arc::new(Mutex::new(incoming_pending)),
            flow_events: Arc::new(Mutex::new(flow_events)),
            stats,
            owners,
        };
        (stack, handle)
    }

    /// Splits the stack into its egress source and its ingress sink.
    pub fn split(self) -> (NetStackSource, NetStackSink) {
        (self.source, self.sink)
    }
}

/// The stack's egress: IP packets it sends to peers.
///
/// Each packet is a [`PacketBuf`] with its headroom free and is never larger than the
/// configured MTU, except IPv4 UDP datagrams with DF clear under
/// [`NetStackConfig::udp_allow_fragmentation`]. [`recv`](PacketSource::recv) returns [`io::ErrorKind::BrokenPipe`] once
/// the driver stopped and the queue is drained, on every later call. [`mtu`](PacketSource::mtu)
/// holds the (normalised) configured MTU, which never changes. Output of a revoked flow
/// (see [`FlowControl::revoke`](crate::FlowControl::revoke)) still queued here is dropped,
/// never returned.
#[derive(Debug)]
pub struct NetStackSource {
    rx: mpsc::Receiver<PacketBuf>,
    mtu: watch::Receiver<u16>,
    /// Packets taken from `rx`: the egress position of the next one.
    received: u64,
    revocations: Arc<Revocations>,
    fences: Arc<Fences>,
    stats: Arc<Counters>,
}

impl NetStackSource {
    /// Whether every queued output position through a released TCP connection's last
    /// packet has been taken by this source. This remains false before socket release,
    /// including while a final ACK is still in the driver's backlog or egress queue.
    ///
    /// Keep receiving and forwarding packets until this returns true before revoking a
    /// gracefully closed flow. Packets already returned by `recv` remain the caller's
    /// responsibility: finish forwarding them before retirement. This does not prove
    /// delivery or application completion at the peer.
    ///
    /// Returns an error for another stack's control, a non-TCP flow, or a revoked flow.
    pub fn tcp_egress_drained(&self, control: &crate::FlowControl) -> io::Result<bool> {
        Ok(control
            .tcp_egress_end(&self.revocations)?
            .is_some_and(|end| self.received >= end))
    }

    /// Whether `packet`, the next one out of the egress queue, may leave the stack: not a
    /// placeholder of output dropped in the backlog, nor held back by a fence.
    fn admit(&mut self, packet: &PacketBuf) -> bool {
        let position = self.received;
        self.received += 1;
        if packet.is_empty() {
            return false;
        }
        if self
            .fences
            .holds(position, || tcp_tuple(packet.as_packet()))
        {
            stats::add(&self.stats.retired, 1);
            return false;
        }
        true
    }

    /// The next packet [`recv`](PacketSource::recv) would return, if one is queued now.
    #[cfg(test)]
    pub(crate) fn try_admit(&mut self) -> Option<PacketBuf> {
        loop {
            let packet = self.rx.try_recv().ok()?;
            if self.admit(&packet) {
                return Some(packet);
            }
        }
    }
}

impl PacketSource for NetStackSource {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        loop {
            let packet = self.rx.recv().await.ok_or_else(stack_gone)?;
            if self.admit(&packet) {
                return Ok(packet);
            }
        }
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu.clone()
    }
}

/// The stack's ingress: decrypted IP packets delivered into the stack.
///
/// [`send`](PacketSink::send) waits while the stack's ingress queue is full and returns
/// [`io::ErrorKind::BrokenPipe`] once the driver stopped. The peer a packet came from is
/// not used: the stack routes by addresses only.
#[derive(Debug)]
pub struct NetStackSink {
    tx: mpsc::Sender<PacketBuf>,
}

impl PacketSink for NetStackSink {
    async fn send(&self, packet: PacketBuf, _from: PeerId) -> io::Result<()> {
        self.tx.send(packet).await.map_err(|_| stack_gone())
    }
}

/// Requests from a [`NetStackHandle`] to the driver.
#[derive(Debug)]
enum Command {
    Connect {
        remote: SocketAddr,
        /// The local port, or `None` for an ephemeral one.
        local_port: Option<u16>,
        /// The tuple of a connect from an explicit port, registered by the handle.
        registration: Option<Registration>,
        reply: oneshot::Sender<io::Result<TcpConnection>>,
    },
    Bind {
        local: SocketAddr,
        reply: oneshot::Sender<io::Result<UdpSocket>>,
    },
    ConnectUdp {
        local: SocketAddr,
        remote: SocketAddr,
        reply: oneshot::Sender<io::Result<UdpSocket>>,
    },
}

/// The application's side of a [`NetStack`]: accepts and opens connections and flows.
///
/// Cloning yields another handle to the same stack. Dropping every handle does not stop
/// the stack.
#[derive(Debug, Clone)]
pub struct NetStackHandle {
    commands: mpsc::Sender<Command>,
    incoming_tcp: Arc<Mutex<Option<mpsc::Receiver<TcpConnection>>>>,
    incoming_udp: Arc<Mutex<Option<mpsc::Receiver<UdpFlow>>>>,
    incoming_pending: Arc<Mutex<Option<mpsc::Receiver<PendingFlow>>>>,
    flow_events: Arc<Mutex<Option<mpsc::Receiver<FlowEvent>>>>,
    stats: Arc<Counters>,
    owners: Arc<Owners>,
}

/// Takes the value out of a shared slot, ignoring poisoning.
fn take<T>(slot: &Mutex<Option<T>>) -> Option<T> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

impl NetStackHandle {
    /// Inbound TCP connections to any port of the stack's addresses, once established.
    ///
    /// Only the first call (on any clone of the handle) gets the connections; every later
    /// call returns a stream that ends immediately. The stream ends when the stack stops.
    /// Connections that arrive while the stream is not consumed are queued up to
    /// [`NetStackConfig::accept_capacity`], then closed and counted.
    pub fn incoming_tcp(&self) -> impl Stream<Item = TcpConnection> + Send + Unpin + use<> {
        Incoming(take(&self.incoming_tcp))
    }

    /// Inbound UDP flows, one per `(remote, local)` tuple, each with its first datagram.
    ///
    /// Datagrams to an address bound with [`bind_udp`](Self::bind_udp) or of a tuple
    /// connected with [`connect_udp`](Self::connect_udp) are not reported here. Only the first call (on any clone of the handle) gets the flows; every later
    /// call returns a stream that ends immediately. The stream ends when the stack stops.
    /// Flows that arrive while the stream is not consumed are queued up to
    /// [`NetStackConfig::accept_capacity`], then dropped and counted.
    pub fn incoming_udp(&self) -> impl Stream<Item = UdpFlow> + Send + Unpin + use<> {
        Incoming(take(&self.incoming_udp))
    }

    /// New TCP connections and UDP flows held for the application's decision, with
    /// [`Admission::Decide`] configured in [`NetStackConfig::transparent`].
    ///
    /// Each [`PendingFlow`] is accepted, rejected or dropped (which rejects); an accepted
    /// connection or flow then arrives on [`incoming_tcp`](Self::incoming_tcp) or
    /// [`incoming_udp`](Self::incoming_udp). Items not taken are queued up to the
    /// `max_pending` of [`Admission::Decide`]; beyond that a new connection or flow is
    /// rejected at once. Only the first call (on any clone of the handle) gets the items;
    /// every later call, and every call without [`Admission::Decide`], returns a stream
    /// that ends immediately. The stream ends when the stack stops.
    pub fn incoming_pending(&self) -> impl Stream<Item = PendingFlow> + Send + Unpin + use<> {
        Incoming(take(&self.incoming_pending))
    }

    /// Admission events of a transparent stack, with
    /// [`TransparentConfig::events`](crate::TransparentConfig::events) configured.
    ///
    /// Only the first call (on any clone of the handle) gets the events; every later
    /// call, and every call without events configured, returns a stream that ends
    /// immediately. The stream ends when the stack stops. Events not taken are buffered up
    /// to the configured capacity, then dropped and counted in
    /// [`events_dropped`](NetStackStats::events_dropped), as are all events once the
    /// stream is dropped.
    pub fn flow_events(&self) -> impl Stream<Item = FlowEvent> + Send + Unpin + use<> {
        Incoming(take(&self.flow_events))
    }

    /// Opens a TCP connection from the stack to `remote`.
    ///
    /// The local end is the stack's address of `remote`'s family and an ephemeral port.
    /// Fails with [`io::ErrorKind::AddrNotAvailable`] if the stack has no address of that
    /// family, [`io::ErrorKind::ConnectionRefused`] if the peer resets the handshake,
    /// [`io::ErrorKind::TimedOut`] if it does not answer within 20 seconds and
    /// [`io::ErrorKind::BrokenPipe`] once the stack stopped.
    pub async fn connect_tcp(&self, remote: SocketAddr) -> io::Result<TcpConnection> {
        self.connect(remote, None).await
    }

    /// Opens a TCP connection from the stack's `local_port` to `remote`, like
    /// [`connect_tcp`](Self::connect_tcp) (port `0` picks an ephemeral port). Fails with
    /// [`io::ErrorKind::AddrInUse`] if a connection or listener of the stack uses the port.
    pub async fn connect_tcp_from(
        &self,
        local_port: u16,
        remote: SocketAddr,
    ) -> io::Result<TcpConnection> {
        self.connect(remote, (local_port != 0).then_some(local_port))
            .await
    }

    async fn connect(
        &self,
        remote: SocketAddr,
        local_port: Option<u16>,
    ) -> io::Result<TcpConnection> {
        // An explicit port gives the whole tuple now, so the connect is visible to `owns`
        // before the command reaches the driver.
        let registration = local_port
            .zip(self.owners.local_for(remote.ip()))
            .map(|(port, local)| self.owners.tcp(SocketAddr::new(local, port), remote));
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Connect {
                remote,
                local_port,
                registration,
                reply,
            })
            .await
            .map_err(|_| stack_gone())?;
        response.await.map_err(|_| stack_gone())?
    }

    /// Binds a UDP socket to `local`.
    ///
    /// `local` must be one of the stack's addresses or the unspecified address of a family
    /// the stack has an address of; port `0` picks an ephemeral port. Fails with
    /// [`io::ErrorKind::AddrNotAvailable`] for any other address,
    /// [`io::ErrorKind::AddrInUse`] if a live socket is bound to exactly `local` and
    /// [`io::ErrorKind::BrokenPipe`] once the stack stopped.
    pub async fn bind_udp(&self, local: SocketAddr) -> io::Result<UdpSocket> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Bind { local, reply })
            .await
            .map_err(|_| stack_gone())?;
        response.await.map_err(|_| stack_gone())?
    }

    /// Opens a UDP socket connected to `remote`.
    ///
    /// The local end is the stack's address of `remote`'s family and an ephemeral port;
    /// see [`connect_udp_from`](Self::connect_udp_from).
    pub async fn connect_udp(&self, remote: SocketAddr) -> io::Result<UdpSocket> {
        self.connect_udp_from(SocketAddr::new(unspecified(remote.ip()), 0), remote)
            .await
    }

    /// Opens a UDP socket from `local` connected to `remote`.
    ///
    /// `local` must be the stack's address of `remote`'s family or the unspecified address
    /// of that family (which stands for the stack's address); port `0` picks an ephemeral
    /// port no other socket of the stack uses on that address. The socket receives only
    /// the datagrams from `remote` to `local`, ahead of a socket bound to `local` with
    /// [`bind_udp`](Self::bind_udp), which keeps every other remote's; the tuple is
    /// [`Ownership::Flow`] for [`owns`](Self::owns) until the socket is dropped.
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] if `remote` is unspecified or `local` is
    /// of the other family, [`io::ErrorKind::AddrNotAvailable`] if the stack has no address
    /// of the family or `local` is another address, [`io::ErrorKind::AddrInUse`] if a live
    /// connected socket or [`UdpFlow`] holds exactly this tuple, and
    /// [`io::ErrorKind::BrokenPipe`] once the stack stopped.
    pub async fn connect_udp_from(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> io::Result<UdpSocket> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::ConnectUdp {
                local,
                remote,
                reply,
            })
            .await
            .map_err(|_| stack_gone())?;
        response.await.map_err(|_| stack_gone())?
    }

    /// The stack's drop counters.
    pub fn stats(&self) -> NetStackStats {
        self.stats.snapshot()
    }

    /// Packets and datagrams the stack discarded because their flow was revoked with
    /// [`FlowControl::revoke`](crate::FlowControl::revoke): queued output removed from the
    /// egress backlog, held back at the [`NetStackSource`], or still waiting in the UDP
    /// send queue. Counted here and not in [`stats`](Self::stats); bytes and datagrams a
    /// revoked flow had buffered for the application are not counted. Only grows.
    pub fn retired_drops(&self) -> u64 {
        self.stats
            .retired
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Discards the fragmented datagram `(src, dst, protocol, id)` sent towards the stack,
    /// so that none of its fragments joins a later flow on the same tuple.
    ///
    /// Call it when a flow's admission is revoked while one of its datagrams may be half
    /// reassembled. From the call on, the driver drops every fragment of that datagram
    /// that reaches it, including fragments already queued in the [`NetStackSink`], and
    /// counts each in [`NetStackStats::reassembly_overflow`]; the fragments the stack
    /// already holds never complete and are discarded at the reassembly timeout (counted
    /// in [`NetStackStats::reassembly_timeout`]). The datagram is forgotten one
    /// [`ReassemblyConfig::timeout`](crate::ReassemblyConfig::timeout)
    /// after the call, when the held fragments have expired, so a later datagram with
    /// the same identification starts afresh. At most
    /// [`ReassemblyConfig::max_datagrams`](crate::ReassemblyConfig::max_datagrams)
    /// discarded datagrams are remembered at once; beyond that the oldest is forgotten
    /// early. The call also ends the [`owns`](Self::owns) memory of the datagram.
    ///
    /// `src` and `dst` are the packet's addresses (the peer's and the stack's) and
    /// `protocol` the fragmented protocol; `id` is the IPv6 Fragment header's 32-bit
    /// identification, or the IPv4 16-bit identification widened. As for reassembly, an
    /// IPv6 datagram is identified by its addresses and `id`: `protocol` only narrows an
    /// IPv4 discard.
    ///
    /// Without [`NetStackConfig::reassembly`] the stack drops every fragment anyway and
    /// the call does nothing. It takes one short lock and never waits; while nothing is
    /// discarded, fragments cost the driver one atomic load.
    pub fn discard_fragments(&self, src: IpAddr, dst: IpAddr, protocol: u8, id: u32) {
        self.owners.discard_fragments(src, dst, protocol, id);
    }

    /// Whether the stack owns `packet`, an IP packet a peer sent towards the stack.
    ///
    /// Lets a local side share one decrypted stream between the stack and other
    /// consumers, e.g. in an `nsplane::Splitter` closure:
    ///
    /// - [`Ownership::Flow`]: a TCP or UDP packet whose `(local, remote)` tuple (the
    ///   packet's destination and source) is a TCP connection of the stack (accepted,
    ///   mid handshake, opened with [`connect_tcp`](Self::connect_tcp) or
    ///   [`connect_tcp_from`](Self::connect_tcp_from) and still in SYN-SENT, or half
    ///   closed and still held), a UDP flow, or a UDP socket bound to the destination (any
    ///   remote); or an IPv4 or IPv6 ICMP error (destination unreachable, packet too big,
    ///   time exceeded, parameter problem) quoting a packet the stack sent on such a tuple.
    /// - [`Ownership::Listener`]: a bare TCP SYN or a UDP datagram to one of the stack's
    ///   addresses (with [`NetStackConfig::transparent`], to an in-prefix address) that
    ///   would open a new connection or flow.
    /// - [`Ownership::None`]: anything else, including malformed packets, IPv4 fragments
    ///   and IPv6 packets with a Fragment header without
    ///   [`NetStackConfig::reassembly`] (the stack drops them), and every packet once the
    ///   stack stopped.
    ///
    /// With [`NetStackConfig::reassembly`], every TCP or UDP fragment to one of the stack's
    /// addresses (or in-prefix addresses) is the stack's: a first fragment is [`Ownership::Flow`] when its tuple is
    /// one of the above and [`Ownership::Listener`] otherwise. A later fragment carries no
    /// ports: it is [`Ownership::Flow`] when this call classified the first fragment of
    /// its datagram (same addresses, protocol and identification) as
    /// [`Ownership::Flow`] within the last
    /// [`ReassemblyConfig::timeout`](crate::ReassemblyConfig::timeout)
    /// and the datagram was not discarded with
    /// [`discard_fragments`](Self::discard_fragments) since, and
    /// [`Ownership::Listener`] otherwise, including when it arrives before its first
    /// fragment (the stack takes it either way, and its datagram goes wherever the first
    /// fragment's tuple leads once it is complete). This memory holds at most
    /// [`ReassemblyConfig::max_datagrams`](crate::ReassemblyConfig::max_datagrams)
    /// datagrams, dropping the oldest. Fragments of other protocols stay
    /// [`Ownership::None`].
    ///
    /// The answer reflects the stack's state at the call; a connection or flow that opens
    /// or closes concurrently may be seen either way. A connect is visible from the moment
    /// its SYN is queued: at the call for [`connect_tcp_from`](Self::connect_tcp_from) with
    /// a port, before the first SYN leaves for an ephemeral port. An inbound connection is
    /// visible before its SYN-ACK leaves. A UDP flow or socket stops being visible when it
    /// is dropped.
    ///
    /// The call takes one short lock and never waits (a fragment two). The stack keeps the
    /// table it reads as connections, flows and sockets open and close, not per packet.
    pub fn owns(&self, packet: &[u8]) -> Ownership {
        if self.commands.is_closed() {
            return Ownership::None;
        }
        self.owners.owns(packet)
    }
}

/// A stream over an accept queue, or an empty stream for later callers.
struct Incoming<T>(Option<mpsc::Receiver<T>>);

impl<T> Stream for Incoming<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.0
            .as_mut()
            .map_or(Poll::Ready(None), |rx| rx.poll_recv(cx))
    }
}

/// The pending table and the receiving end of its items, with `Admission::Decide` only.
fn pending_table(
    settings: &Settings,
    notify: &Arc<Notify>,
) -> Option<(Pending, mpsc::Receiver<PendingFlow>)> {
    match settings.transparent.as_ref()?.admission {
        Admission::Decide {
            timeout,
            max_pending,
        } => {
            let (offer, incoming) = mpsc::channel(max_pending);
            let table = Pending::new(timeout, max_pending, offer, Arc::clone(notify));
            Some((table, incoming))
        }
        Admission::Immediate => None,
    }
}

/// The admission event sink and the receiving end of its events, with
/// `TransparentConfig::events` only.
fn event_sink(settings: &Settings) -> Option<(EventSink, mpsc::Receiver<FlowEvent>)> {
    let config = settings.transparent.as_ref()?.events?;
    Some(EventSink::new(config, Instant::now()))
}

/// Creates the smoltcp interface with the stack's addresses; in transparent mode it takes
/// packets to any address (`classify` has checked the prefixes before).
fn interface(settings: &Settings, device: &mut VirtualDevice) -> Interface {
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = RandomState::new().build_hasher().finish();
    let mut iface = Interface::new(config, device, SmolInstant::ZERO);
    if settings.transparent.is_some() {
        iface.set_any_ip(true);
    }
    iface.update_ip_addrs(|addrs| {
        // At most one address per family; the default capacity of two always fits.
        if let Some((addr, prefix)) = settings.v4 {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(addr), prefix));
        }
        if let Some((addr, prefix)) = settings.v6 {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(addr), prefix));
        }
    });
    iface
}

/// How an ingress packet is handled.
#[derive(Debug, PartialEq, Eq)]
enum Class {
    /// Into smoltcp; `syn` marks a bare SYN that needs a listener.
    Tcp { dst_port: u16, syn: bool },
    /// Into the UDP dispatch path.
    Udp,
    /// An ICMP or `ICMPv6` message: a Fragmentation Needed or Packet Too Big may lower a
    /// connection's MSS.
    Icmp,
}

/// Why an ingress packet is dropped.
#[derive(Debug, PartialEq, Eq)]
enum Reject {
    Malformed,
    NoAddress,
    /// In transparent mode: neither one of the stack's addresses nor in a prefix.
    Prefix,
    Unsupported,
}

/// Decides what to do with an ingress packet.
fn classify(bytes: &[u8], settings: &Settings) -> Result<Class, Reject> {
    let ip = IpPacket::parse(bytes).map_err(|_| Reject::Malformed)?;
    if !settings.is_local(ip.dst()) {
        match &settings.transparent {
            None => return Err(Reject::NoAddress),
            Some(transparent) if !transparent.prefixes.contains(ip.dst()) => {
                return Err(Reject::Prefix);
            }
            Some(_) => {}
        }
    }
    if ip.fragment().is_some() {
        return Err(Reject::Unsupported);
    }
    if let Some(dst_port) = tcp_dst_port(bytes) {
        return Ok(Class::Tcp {
            dst_port,
            syn: tcp_is_syn(bytes),
        });
    }
    match ip.protocol() {
        protocol::UDP => Ok(Class::Udp),
        protocol::TCP => Err(Reject::Malformed),
        protocol::ICMP if ip.src().is_ipv4() => Ok(Class::Icmp),
        protocol::ICMPV6 if ip.src().is_ipv6() => Ok(Class::Icmp),
        _ => Err(Reject::Unsupported),
    }
}

/// Driver-side state of one connection handed to the application.
struct Conn {
    /// Keeps the connection's tuple visible to `owns` until the socket is released.
    _registration: Registration,
    shared: Arc<Mutex<Shared>>,
    terminal: watch::Sender<bool>,
    progress: Arc<Progress>,
    /// The socket's send queue at the end of the previous bridge pass.
    queued: usize,
    /// `close()` was called on the socket.
    local_closed: bool,
    last_activity_at: SmolInstant,
    flow: Arc<FlowState>,
}

/// What one bridge pass did.
struct Bridged {
    /// Bytes moved into the socket's send buffer.
    sent: bool,
    /// The socket can be released.
    terminal: bool,
    /// The socket was aborted and releases once its RST left.
    aborting: bool,
}

impl Conn {
    /// Whether bytes wait in the socket's send buffer or in the application's.
    fn sending(&self, socket: &tcp::Socket<'_>) -> bool {
        socket.send_queue() > 0 || !lock(&self.shared).tx.is_empty()
    }

    /// Moves bytes between the socket and the application and applies half closes,
    /// filling the socket's send buffer up to `limit` bytes.
    fn bridge(&mut self, socket: &mut tcp::Socket<'_>, now: SmolInstant, limit: usize) -> Bridged {
        // Only an acknowledgement shrinks the send queue, except a reset, which empties it
        // and leaves the socket closed.
        if socket.send_queue() < self.queued && socket.state() != tcp::State::Closed {
            self.progress
                .set_last_ack(u64::try_from(now.total_micros()).unwrap_or(0));
        }
        let mut shared = lock(&self.shared);
        if shared.write_half == WriteHalf::Aborted {
            return abort(socket, &mut shared);
        }
        preserve_terminal_receive(socket, &mut shared, &mut self.last_activity_at, now);

        // smoltcp -> application.
        if shared.app_dropped {
            // Nobody reads any more: discard what arrives; the write half closes below.
            shared.rx.clear();
            while socket.can_recv() {
                if socket.recv(|data| (data.len(), ())).is_err() {
                    break;
                }
            }
        } else if receive_into(socket, &mut shared) > 0 {
            self.last_activity_at = now;
            shared.wake_reader();
        }
        // Reverse half close: the peer sent FIN and every byte before it was moved, so
        // the application reads EOF instead of blocking forever.
        if !shared.rx_eof && !socket.may_recv() && !socket.can_recv() {
            shared.rx_eof = true;
            shared.wake_reader();
        }

        // Application -> smoltcp.
        let mut sent = false;
        while !shared.tx.is_empty() && socket.can_send() {
            let room = limit.saturating_sub(socket.send_queue());
            let data = shared.tx.as_slices().0;
            let n = socket
                .send_slice(&data[..data.len().min(room)])
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            shared.tx.drain(..n);
            sent = true;
        }
        if sent {
            self.last_activity_at = now;
            shared.wake_writer();
        }
        let queued = socket.send_queue();
        if queued != self.queued {
            self.queued = queued;
            self.progress.set_unacked(queued);
        }
        // Forward half close: the application shut its write half down (or dropped the
        // connection). Once every byte is in the socket, FIN follows them, so the peer
        // observes the end of the stream.
        let closing = shared.write_half == WriteHalf::Shutdown
            || (shared.app_dropped && shared.write_half == WriteHalf::Open);
        if closing && shared.tx.is_empty() {
            if !self.local_closed && socket.may_send() {
                socket.close();
                self.local_closed = true;
            }
            shared.write_half = WriteHalf::FinSent;
            shared.wake_writer();
        }

        if tcp_idle_timeout_expired(socket.state(), self.last_activity_at, now) {
            tracing::debug!(target: "netstack", "TCP connection exceeded idle timeout; aborting");
            // Released like an application abort: once the RST left.
            shared.write_half = WriteHalf::Aborted;
            return abort(socket, &mut shared);
        }
        let terminal = tcp_terminal_ready(
            socket.state(),
            !shared.rx.is_empty() || socket.can_recv(),
            self.last_activity_at,
            now,
        );
        Bridged {
            sent,
            terminal,
            aborting: false,
        }
    }

    /// Tells the application the socket is gone.
    fn release(&self) {
        let mut shared = lock(&self.shared);
        shared.released = true;
        shared.rx_eof = true;
        shared.wake_reader();
        shared.wake_writer();
        drop(shared);
        self.terminal.send_replace(true);
    }
}

/// Resets the socket of an aborted connection and discards its bytes.
///
/// smoltcp sends the RST on its next dispatch and then forgets the remote endpoint; until
/// then the socket must stay. A socket already closed (reset by the peer, or after the
/// close handshake) has nobody to reset and is released as is.
fn abort(socket: &mut tcp::Socket<'_>, shared: &mut Shared) -> Bridged {
    shared.rx.clear();
    shared.tx.clear();
    if !matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
        socket.abort();
    }
    let terminal = socket.state() == tcp::State::TimeWait || socket.remote_endpoint().is_none();
    Bridged {
        sent: false,
        terminal,
        aborting: !terminal,
    }
}

/// Moves received bytes into the application buffer while it has room.
fn receive_into(socket: &mut tcp::Socket<'_>, shared: &mut Shared) -> usize {
    let mut total = 0;
    while socket.can_recv() && shared.rx.len() < shared.capacity {
        let room = shared.capacity - shared.rx.len();
        let received = socket.recv(|data| {
            let n = data.len().min(room);
            shared.rx.extend(&data[..n]);
            (n, n)
        });
        match received {
            Ok(n) if n > 0 => total += n,
            _ => break,
        }
    }
    total
}

/// A `connect_tcp` waiting for its handshake.
struct Connecting {
    handle: SocketHandle,
    /// Keeps the connect's tuple visible to `owns` while it is in SYN-SENT.
    _registration: Registration,
    reply: oneshot::Sender<io::Result<TcpConnection>>,
    started: SmolInstant,
    /// The egress position when the socket was created.
    start: u64,
}

/// Socket pool limits: sockets per port and in total, and each socket's buffer sizes and
/// RTO bounds.
#[derive(Debug, Clone, Copy)]
struct Pool {
    limit: usize,
    rx_buffer: usize,
    tx_buffer: usize,
    rto: TcpRto,
}

/// The queue of a UDP flow or socket, with the flow it belongs to.
type Inbox<T> = (mpsc::Sender<T>, Arc<FlowState>);

/// A revoked flow whose fragments the reassembler may still hold. Later fragments carry
/// no ports, so a held datagram cannot be told apart from one of a new flow on the same
/// tuple: every datagram completed for the flow's tuple before `until` is dropped.
#[derive(Debug)]
struct Barrier {
    protocol: u8,
    local: SocketAddr,
    /// `None` for a bound socket: every remote.
    remote: Option<SocketAddr>,
    until: std::time::Instant,
}

impl Barrier {
    /// Whether a datagram from `src` to `dst` completed at `now` is held back; `ports`
    /// gives its protocol and `(src, dst)` ports if it is TCP or UDP. One whose ports
    /// cannot be read is held back by its addresses alone.
    fn holds(
        &self,
        src: IpAddr,
        dst: IpAddr,
        ports: Option<(u8, u16, u16)>,
        now: std::time::Instant,
    ) -> bool {
        let local_ip = self.local.ip();
        let addresses = (local_ip == dst
            || (local_ip.is_unspecified() && local_ip.is_ipv4() == dst.is_ipv4()))
            && self.remote.is_none_or(|remote| remote.ip() == src);
        let ports = ports.is_none_or(|(protocol, src_port, dst_port)| {
            protocol == self.protocol
                && dst_port == self.local.port()
                && self.remote.is_none_or(|remote| remote.port() == src_port)
        });
        now < self.until && addresses && ports
    }
}

/// The single task that owns smoltcp and every queue behind the stack.
struct Driver {
    settings: Settings,
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    /// Listener sockets mid handshake, with the tuple they registered for `owns` and the
    /// egress position when they took the SYN.
    inbound: HashMap<SocketHandle, (Registration, u64)>,
    /// port -> the sockets this port has open for inbound connections: those in `Listen`
    /// (free to accept a SYN) plus those in `SynReceived` (claimed by a SYN, mid
    /// handshake). A socket leaves the pool when it is established (promoted to a
    /// connection) or dies.
    listeners: HashMap<u16, Vec<SocketHandle>>,
    /// The next destination port that receives the first listener slot when a batch has
    /// more aggregate demand than the pool.
    allocation_cursor: u16,
    conns: HashMap<SocketHandle, Conn>,
    /// Aborted connections whose RST the next poll sends; empty between turns.
    aborting: Vec<SocketHandle>,
    /// Connects from a port an aborted connection still holds, retried once it is
    /// released.
    deferred: Vec<Command>,
    connecting: Vec<Connecting>,
    flows: HashMap<(SocketAddr, SocketAddr), Inbox<Bytes>>,
    bound: HashMap<SocketAddr, Inbox<(SocketAddr, Bytes)>>,
    /// Connected UDP sockets by `(remote, local)`; checked before `bound` only while not
    /// empty.
    connected: HashMap<(SocketAddr, SocketAddr), Inbox<(SocketAddr, Bytes)>>,
    ingress: mpsc::Receiver<PacketBuf>,
    /// Ingress packets taken in one batch; empty between batches.
    batch: Vec<PacketBuf>,
    egress: mpsc::Sender<PacketBuf>,
    /// `None` once every handle is gone.
    commands: Option<mpsc::Receiver<Command>>,
    udp_rx: mpsc::Receiver<(PacketBuf, Arc<FlowState>)>,
    out: UdpOut,
    accept_tcp: mpsc::Sender<TcpConnection>,
    accept_udp: mpsc::Sender<UdpFlow>,
    /// Accepted connections waiting for room in `accept_tcp`, oldest first; only with
    /// `accept_backpressure`.
    waiting: VecDeque<TcpConnection>,
    notify: Arc<Notify>,
    stats: Arc<Counters>,
    /// A packet taken while waiting, replayed into the next batch so listener demand is
    /// counted in one place only.
    carried: Option<PacketBuf>,
    next_tcp_port: u16,
    next_udp_port: u16,
    epoch: Instant,
    owners: Arc<Owners>,
    /// Only with `NetStackConfig::reassembly`.
    reassembler: Option<Reassembler>,
    /// The reassembler's counts already added to `stats`.
    reassembly_counted: ReassemblyStats,
    revocations: Arc<Revocations>,
    /// Revoked flows taken in this turn and not retired yet; empty between turns.
    retiring: Vec<Arc<FlowState>>,
    /// Packets moved from the backlog into the egress queue. The packet at `tx_queue[i]`
    /// has egress position `sent + i`; positions never change, as packets dropped from the
    /// backlog leave an empty placeholder the source discards.
    sent: u64,
    /// The egress position and flow of every UDP datagram in the backlog or possibly still
    /// in the egress queue, ascending. Bounded by those two queues: a mark is added only
    /// with its datagram's backlog slot and pruned at the start of each turn once the
    /// source took its position: it holds at most `EGRESS_BACKLOG + egress_capacity`
    /// entries, plus what one turn moves before the next prune. It has no full state, so
    /// no revoke fails on it.
    marks: VecDeque<(u64, Arc<FlowState>)>,
    fences: Arc<Fences>,
    /// Revoked flows whose fragments the reassembler may still hold; at most
    /// `ReassemblyConfig::max_datagrams`, each for one reassembly timeout. A revoke that
    /// needs one more fails (`RetirementOutcome::Failed`).
    barriers: Vec<Barrier>,
    /// Connections and flows held for the application's decision; only with
    /// `Admission::Decide`.
    pending: Option<Box<Pending>>,
    /// Only with `TransparentConfig::events`.
    events: Option<Box<EventSink>>,
    #[cfg(test)]
    turns: u64,
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.revocations.close(&mut self.retiring);
        for conn in self.conns.values() {
            conn.release();
        }
    }
}

async fn next_command(commands: Option<&mut mpsc::Receiver<Command>>) -> Option<Command> {
    match commands {
        Some(commands) => commands.recv().await,
        None => None,
    }
}

impl Driver {
    async fn run(mut self) {
        while self.turn().await {}
        tracing::debug!(target: "netstack", "driver stopped");
    }

    /// One driver iteration; `false` once the stack must stop.
    async fn turn(&mut self) -> bool {
        #[cfg(test)]
        {
            self.turns += 1;
        }
        // 0. Retire revoked flows before anything of theirs can move.
        self.retire_revoked();
        // 1. Take a bounded batch of ingress packets and pending requests.
        self.expire_fragments();
        if self.pending.is_some() {
            self.expire_pending();
        }
        let Some(demand) = self.ingest_batch() else {
            tracing::debug!(target: "netstack", "sink dropped; stopping");
            return false;
        };
        self.take_commands();
        self.take_udp_sends();

        // A whole batch is injected before smoltcp runs, so the listener pool must cover
        // every SYN in the batch up front: sizing it against the current state would leave
        // the 2nd..Nth simultaneous SYN without a socket to land on.
        let now = self.now();
        // Before the pool reclaims sockets that left the handshake.
        self.release_inbound();
        let mark = self.position();
        let pool = Pool {
            limit: self.settings.listener_pool,
            rx_buffer: self.settings.tcp_rx_buffer(),
            tx_buffer: self.settings.tcp_tx_buffer(),
            rto: self.settings.tcp_rto,
        };
        let refused = prepare_tcp_listeners(
            &demand,
            &mut self.allocation_cursor,
            &mut self.listeners,
            &mut self.sockets,
            pool,
        );
        stats::add(&self.stats.syn_refused, refused as u64);

        // 2. Drive smoltcp.
        self.preserve_all(now);
        self.device
            .poll_interface(&mut self.iface, now, &mut self.sockets);
        self.track_inbound(&demand, mark);

        // 3. Hand established connections to the application.
        self.promote(now);
        self.finish_connects(now);

        // 4. Bridge connections. Application bytes arrive independently of packets;
        // polling once more after taking them keeps the idle tick from pacing every chunk.
        if self.bridge_all(now) {
            let now = self.now();
            self.device
                .poll_interface(&mut self.iface, now, &mut self.sockets);
            self.preserve_all(now);
        }
        self.release_aborted();

        // 5. Egress, then wait for more work.
        self.flush_egress() && self.wait(now).await
    }

    fn now(&self) -> SmolInstant {
        let micros = i64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(i64::MAX);
        SmolInstant::from_micros(micros)
    }

    /// Takes up to [`MAX_INJECT_PER_ITER`] ingress packets; `None` once the sink is gone.
    fn ingest_batch(&mut self) -> Option<HashMap<u16, usize>> {
        self.flush_waiting();
        let mut demand = HashMap::new();
        if let Some(packet) = self.carried.take() {
            self.ingest(packet, &mut demand);
        }
        // Taking the queued packets at once releases their queue slots in one step rather
        // than one per packet. Without a packet the poll registers no waker that matters:
        // `wait` polls the queue again with the driver's own.
        let mut batch = std::mem::take(&mut self.batch);
        let taken = self.ingress.poll_recv_many(
            &mut Context::from_waker(Waker::noop()),
            &mut batch,
            MAX_INJECT_PER_ITER,
        );
        self.ingest_all(&mut batch, &mut demand);
        self.batch = batch;
        // After the batch, so that a SYN retransmitted in it is absorbed by its entry
        // rather than held anew once the entry is accepted.
        if self.pending.is_some() {
            self.take_decisions(&mut demand);
        }
        // Zero packets taken means the queue is closed and drained.
        (taken != Poll::Ready(0)).then_some(demand)
    }

    /// Routes the packets of `batch` in order (see [`ingest`](Self::ingest)), leaving it
    /// empty with its allocation kept.
    fn ingest_all(&mut self, batch: &mut Vec<PacketBuf>, demand: &mut HashMap<u16, usize>) {
        for packet in batch.drain(..) {
            self.ingest(packet, demand);
        }
    }

    /// Routes one ingress packet, counting the SYNs per destination port in `demand`.
    fn ingest(&mut self, packet: PacketBuf, demand: &mut HashMap<u16, usize>) {
        let Some(packet) = self.reassemble(packet) else {
            return;
        };
        match classify(packet.as_packet(), &self.settings) {
            Ok(Class::Tcp { dst_port, syn }) => {
                if syn {
                    if self.accept_full() {
                        // Unanswered, the peer retransmits it once the queue may have room.
                        return stats::add(&self.stats.syn_deferred, 1);
                    }
                    let packet = if self.settings.transparent.is_some() {
                        match self.admit_syn(packet, demand) {
                            Some(packet) => packet,
                            None => return,
                        }
                    } else {
                        packet
                    };
                    *demand.entry(dst_port).or_insert(0) += 1;
                    return self.device.inject(packet);
                }
                self.device.inject(packet);
            }
            Ok(Class::Udp) if self.pending.is_some() => self.ingest_held_udp(packet),
            Ok(Class::Udp) => match udp::parse_udp(packet) {
                Some(datagram) => self.dispatch_udp(datagram, None),
                None => stats::add(&self.stats.malformed, 1),
            },
            Ok(Class::Icmp) => self.icmp(packet.as_packet()),
            Err(Reject::Malformed) => stats::add(&self.stats.malformed, 1),
            Err(Reject::NoAddress) => stats::add(&self.stats.no_address, 1),
            Err(Reject::Prefix) => {
                stats::add(&self.stats.no_address, 1);
                stats::add(&self.stats.rejected_prefix, 1);
                self.emit_prefix(packet.as_packet());
            }
            Err(Reject::Unsupported) => stats::add(&self.stats.unsupported, 1),
        }
    }

    /// Routes an ingress UDP packet with `Admission::Decide`, keeping the whole packet for
    /// a flow that may be held.
    #[cold]
    #[inline(never)]
    fn ingest_held_udp(&mut self, packet: PacketBuf) {
        match udp::parse_udp_whole(packet) {
            Some((datagram, whole)) => self.dispatch_held_udp(datagram, Some(whole)),
            None => stats::add(&self.stats.malformed, 1),
        }
    }

    /// [`dispatch_udp`](Self::dispatch_udp) out of line, for the `Admission::Decide` paths.
    #[cold]
    #[inline(never)]
    fn dispatch_held_udp(&mut self, datagram: Datagram, whole: Option<Bytes>) {
        self.dispatch_udp(datagram, whole);
    }

    /// Admits a bare SYN in transparent mode; the SYN if it goes on into smoltcp now. A
    /// retransmitted SYN of a handshake in progress passes uncounted, and one of a held
    /// connection is absorbed; a new connection beyond `max_connections` is answered with
    /// RST. Under `Admission::Decide` a new connection is held (or, with the table full,
    /// answered with RST).
    fn admit_syn(&mut self, packet: PacketBuf, demand: &HashMap<u16, usize>) -> Option<PacketBuf> {
        let Some((remote, local)) = tcp_tuple(packet.as_packet()) else {
            return Some(packet);
        };
        if self.owners.has_tcp(local, remote) {
            return Some(packet);
        }
        let key = pending::Key {
            protocol: PendingProtocol::Tcp,
            remote,
            local,
        };
        if self
            .pending
            .as_ref()
            .is_some_and(|table| table.contains(&key))
        {
            return None;
        }
        if self.at_connection_limit(demand) {
            self.reject_connection_limit(&key, packet.as_packet());
            return None;
        }
        if self.pending.is_some() {
            self.hold(key, pending::Held::Tcp(packet));
            return None;
        }
        stats::add(&self.stats.accepted, 1);
        self.emit(&key, FlowEventReason::Admitted);
        Some(packet)
    }

    /// Whether the stack holds `max_connections` TCP connections, counting the connections
    /// held, the handshakes in progress and the SYNs of this batch in `demand`.
    fn at_connection_limit(&self, demand: &HashMap<u16, usize>) -> bool {
        let Some(limit) = self
            .settings
            .transparent
            .as_ref()
            .and_then(|transparent| transparent.max_connections)
        else {
            return false;
        };
        let held = self.conns.len()
            + self.connecting.len()
            + self.inbound.len()
            + demand.values().sum::<usize>();
        held >= limit
    }

    /// Answers the bare SYN `packet` of `key` with RST for `max_connections`.
    fn reject_connection_limit(&mut self, key: &pending::Key, packet: &[u8]) {
        stats::add(&self.stats.rejected_connection_limit, 1);
        self.emit(key, FlowEventReason::ConnectionLimit);
        if let Some(reset) = tcp_reset(packet) {
            self.push_reply(reset);
        }
    }

    /// Holds a new connection or flow for the application's decision, rejecting it at
    /// once when the table is full or the application's stream is gone.
    fn hold(&mut self, key: pending::Key, held: pending::Held) {
        let Some(table) = self.pending.as_mut() else {
            return;
        };
        match table.hold(key, held, Instant::now()) {
            Hold::Held => self.count_pending(),
            Hold::Full(held) => self.reject(&key, &held, FlowEventReason::TableFull),
            Hold::Gone(held) => self.reject(&key, &held, FlowEventReason::Hook),
        }
    }

    /// Answers a held SYN or datagram of `key` with RST or port unreachable, counting it
    /// in the `rejected_` counter of `reason` (`Hook`, `Timeout` or `TableFull`).
    fn reject(&mut self, key: &pending::Key, held: &pending::Held, reason: FlowEventReason) {
        let counter = match reason {
            FlowEventReason::Timeout => &self.stats.rejected_timeout,
            FlowEventReason::TableFull => &self.stats.rejected_table_full,
            _ => &self.stats.rejected_hook,
        };
        stats::add(counter, 1);
        self.emit(key, reason);
        if let Some(reply) = held.rejection(self.settings.mtu) {
            self.push_reply(reply);
        }
    }

    /// Applies the application's decisions on held connections and flows: an accepted SYN
    /// goes into smoltcp with this batch (counted in `demand`), an accepted datagram
    /// opens its flow. Only with `Admission::Decide`.
    #[cold]
    #[inline(never)]
    fn take_decisions(&mut self, demand: &mut HashMap<u16, usize>) {
        let mut changed = false;
        while let Some((decision, key, held)) =
            self.pending.as_deref_mut().and_then(Pending::next_decision)
        {
            changed = true;
            if !decision.accept {
                self.reject(&key, &held, FlowEventReason::Hook);
                continue;
            }
            match held {
                pending::Held::Tcp(syn) => {
                    if self.at_connection_limit(demand) {
                        self.reject_connection_limit(&key, syn.as_packet());
                        continue;
                    }
                    stats::add(&self.stats.accepted, 1);
                    self.emit(&key, FlowEventReason::Admitted);
                    *demand.entry(key.local.port()).or_insert(0) += 1;
                    self.device.inject(syn);
                }
                pending::Held::Udp { payload, .. } => {
                    let datagram = Datagram {
                        src: key.remote,
                        dst: key.local,
                        payload,
                    };
                    self.dispatch_held_udp(datagram, None);
                }
            }
        }
        if changed {
            self.count_pending();
        }
    }

    /// Holds the new flow from `remote` to `local` with its first datagram, or drops the
    /// datagram of a flow already held.
    #[cold]
    #[inline(never)]
    fn hold_udp(&mut self, remote: SocketAddr, local: SocketAddr, payload: Bytes, packet: Bytes) {
        let key = pending::Key {
            protocol: PendingProtocol::Udp,
            remote,
            local,
        };
        if self
            .pending
            .as_ref()
            .is_some_and(|table| table.contains(&key))
        {
            // A held flow queues its first datagram only.
            stats::add(&self.stats.udp_queue_full, 1);
            return;
        }
        self.hold(key, pending::Held::Udp { payload, packet });
    }

    /// Counts and reports the new flow from `remote` to `local` admitted in transparent
    /// mode.
    #[cold]
    #[inline(never)]
    fn admit_udp(&mut self, remote: SocketAddr, local: SocketAddr) {
        stats::add(&self.stats.accepted, 1);
        let key = pending::Key {
            protocol: PendingProtocol::Udp,
            remote,
            local,
        };
        self.emit(&key, FlowEventReason::Admitted);
    }

    /// Rejects the held connections and flows past their deadline. Only with
    /// [`Admission::Decide`], so that without it the driver does not read the clock.
    #[cold]
    #[inline(never)]
    fn expire_pending(&mut self) {
        let now = Instant::now();
        let mut changed = false;
        while let Some((key, held)) = self
            .pending
            .as_mut()
            .and_then(|table| table.next_expired(now))
        {
            changed = true;
            self.reject(&key, &held, FlowEventReason::Timeout);
        }
        if changed {
            self.count_pending();
        }
    }

    /// Emits the admission event of `key` for `reason`, with `TransparentConfig::events`.
    fn emit(&mut self, key: &pending::Key, reason: FlowEventReason) {
        let Some(events) = self.events.as_mut() else {
            return;
        };
        let protocol = match key.protocol {
            PendingProtocol::Tcp => protocol::TCP,
            PendingProtocol::Udp => protocol::UDP,
        };
        events.emit(&self.stats, protocol, key.remote, key.local, reason);
    }

    /// Emits the admission event of `packet`, rejected for its destination prefix.
    fn emit_prefix(&mut self, packet: &[u8]) {
        let Some(events) = self.events.as_mut() else {
            return;
        };
        // `classify` parsed the packet before rejecting it.
        let Ok(ip) = IpPacket::parse(packet) else {
            return;
        };
        let (src_port, dst_port) = ip
            .five_tuple()
            .map_or((0, 0), |tuple| (tuple.src_port, tuple.dst_port));
        events.emit(
            &self.stats,
            ip.protocol(),
            SocketAddr::new(ip.src(), src_port),
            SocketAddr::new(ip.dst(), dst_port),
            FlowEventReason::Prefix,
        );
    }

    /// Publishes the number of held connections and flows.
    fn count_pending(&self) {
        if let Some(table) = &self.pending {
            self.stats
                .pending
                .store(table.len() as u64, Ordering::Relaxed);
        }
    }

    /// Appends a packet the driver answers an ingress packet with to the egress backlog,
    /// or drops and counts it while the backlog is full, as smoltcp's replies.
    fn push_reply(&mut self, packet: PacketBuf) {
        if self.device.tx_full() {
            return stats::add(&self.stats.egress_full, 1);
        }
        self.device.tx_queue.push_back(packet);
    }

    /// Applies an ICMP Fragmentation Needed or `ICMPv6` Packet Too Big to the connection
    /// whose segment it quotes, or counts it in `icmp_ignored`; any other ICMP message
    /// counts as `unsupported`.
    fn icmp(&mut self, packet: &[u8]) {
        match pmtu::parse(packet) {
            Message::Other => stats::add(&self.stats.unsupported, 1),
            Message::Ignored => stats::add(&self.stats.icmp_ignored, 1),
            Message::TooBig(too_big) => {
                if !self.reduce_mss(&too_big) {
                    stats::add(&self.stats.icmp_ignored, 1);
                }
            }
        }
    }

    /// Lowers the MSS of the live connection `too_big` quotes; whether it did. smoltcp
    /// checks that the quoted sequence number lies within SND.UNA..SND.NXT and that the
    /// MSS goes down, and resends the data in flight at once in segments of the new size.
    /// In transparent mode the quoted tuple alone finds the connection.
    fn reduce_mss(&mut self, too_big: &TooBig) -> bool {
        if too_big.mtu >= u32::from(self.settings.mtu)
            || (self.settings.transparent.is_none() && !self.settings.is_local(too_big.local.ip()))
        {
            return false;
        }
        let (local, remote) = (
            IpEndpoint::from(too_big.local),
            IpEndpoint::from(too_big.remote),
        );
        let (now, mss) = (self.now(), too_big.mss());
        // Linear in the sockets, but only per message: no state is kept for the lookup.
        self.sockets
            .iter_mut()
            .filter_map(|(_, socket)| tcp::Socket::downcast_mut(socket))
            .find(|socket| {
                socket.local_endpoint() == Some(local) && socket.remote_endpoint() == Some(remote)
            })
            .is_some_and(|socket| {
                socket.reduce_mss(now, mss, TcpSeqNumber(too_big.seq.cast_signed()))
            })
    }

    /// Feeds a packet to an address the stack accepts through the reassembler, if there is one:
    /// the packet to route (the packet itself or a completed datagram), or `None` while
    /// its datagram is incomplete or once the fragment is dropped.
    fn reassemble(&mut self, packet: PacketBuf) -> Option<PacketBuf> {
        let Some(reassembler) = self.reassembler.as_mut() else {
            return Some(packet);
        };
        let now = Instant::now().into_std();
        let Ok(ip) = IpPacket::parse(packet.as_packet()) else {
            // `classify` counts it.
            return Some(packet);
        };
        if !self.settings.accepts(ip.dst()) {
            return Some(packet);
        }
        if self.owners.is_discarded(&ip, now) {
            stats::add(&self.stats.reassembly_overflow, 1);
            return None;
        }
        let routed = match reassembler.push(packet.as_packet(), now) {
            Outcome::Pass => return Some(packet),
            Outcome::Complete(datagram) if self.barred(&datagram, now) => {
                stats::add(&self.stats.retired, 1);
                None
            }
            Outcome::Complete(datagram) => Some(PacketBuf::from_packet(&datagram)),
            Outcome::Held | Outcome::Dropped => None,
        };
        self.count_reassembly();
        routed
    }

    /// Discards incomplete datagrams past the reassembly timeout, and forgets discarded
    /// ones; free while none is held.
    fn expire_fragments(&mut self) {
        let Some(reassembler) = self.reassembler.as_mut() else {
            return;
        };
        let now = Instant::now().into_std();
        if reassembler.expire(now) > 0 {
            self.count_reassembly();
        }
        self.owners.expire_discarded(now);
        self.barriers.retain(|barrier| now < barrier.until);
    }

    /// Whether a reassembled `datagram` may hold fragments of a revoked flow; free while
    /// there is no barrier.
    fn barred(&self, datagram: &[u8], now: std::time::Instant) -> bool {
        if self.barriers.is_empty() {
            return false;
        }
        let Ok(ip) = IpPacket::parse(datagram) else {
            return false;
        };
        let protocol = ip.protocol();
        let ports = ip
            .payload()
            .first_chunk::<4>()
            .filter(|_| protocol == protocol::TCP || protocol == protocol::UDP)
            .map(|&[a, b, c, d]| {
                (
                    protocol,
                    u16::from_be_bytes([a, b]),
                    u16::from_be_bytes([c, d]),
                )
            });
        self.barriers
            .iter()
            .any(|barrier| barrier.holds(ip.src(), ip.dst(), ports, now))
    }

    /// Bars the datagrams of a revoked flow the reassembler may still complete, see
    /// [`Barrier`]; `false` if the table is full. Nothing while no datagram is held.
    fn bar(&mut self, target: &Target) -> bool {
        let Some(reassembler) = self.reassembler.as_ref() else {
            return true;
        };
        if reassembler.pending() == 0 {
            return true;
        }
        if self.barriers.len() >= reassembler.config().max_datagrams {
            return false;
        }
        let (protocol, local, remote) = match *target {
            Target::Tcp { local, peer, .. } => (protocol::TCP, local, Some(peer)),
            Target::UdpFlow((remote, local)) | Target::UdpConnected((remote, local)) => {
                (protocol::UDP, local, Some(remote))
            }
            Target::UdpBound(local) => (protocol::UDP, local, None),
        };
        let until = Instant::now().into_std() + reassembler.config().timeout;
        self.barriers.push(Barrier {
            protocol,
            local,
            remote,
            until,
        });
        true
    }

    /// Adds what the reassembler counted since the last call to the stack's counters.
    fn count_reassembly(&mut self) {
        let Some(reassembler) = self.reassembler.as_ref() else {
            return;
        };
        let now = reassembler.stats();
        let before = std::mem::replace(&mut self.reassembly_counted, now);
        stats::add(
            &self.stats.reassembled,
            now.reassembled - before.reassembled,
        );
        stats::add(&self.stats.reassembly_timeout, now.timeout - before.timeout);
        stats::add(
            &self.stats.reassembly_overflow,
            now.overflow - before.overflow,
        );
        let rejected = (now.overlap + now.malformed) - (before.overlap + before.malformed);
        stats::add(&self.stats.malformed, rejected);
    }

    /// Delivers a datagram to its connected socket, its bound socket, or to its flow;
    /// `whole` is the packet of an ingress datagram whose new flow may be held, `None`
    /// without `Admission::Decide` or for an accepted held datagram.
    #[allow(
        clippy::inline_always,
        reason = "the ingress path keeps its own copy, with `whole` a constant `None`"
    )]
    #[inline(always)]
    fn dispatch_udp(&mut self, datagram: Datagram, whole: Option<Bytes>) {
        let Datagram {
            src,
            dst,
            mut payload,
        } = datagram;
        if !self.connected.is_empty()
            && let Some((socket, _)) = self.connected.get(&(src, dst))
        {
            match socket.try_send((src, payload)) {
                Ok(()) => return,
                Err(TrySendError::Full(_)) => {
                    stats::add(&self.stats.udp_queue_full, 1);
                    return;
                }
                Err(TrySendError::Closed((_, returned))) => {
                    self.connected.remove(&(src, dst));
                    payload = returned;
                }
            }
        }
        let unspecified = match dst.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        for key in [dst, SocketAddr::new(unspecified, dst.port())] {
            let Some((socket, _)) = self.bound.get(&key) else {
                continue;
            };
            match socket.try_send((src, payload)) {
                Ok(()) => return,
                Err(TrySendError::Full(_)) => {
                    stats::add(&self.stats.udp_queue_full, 1);
                    return;
                }
                Err(TrySendError::Closed((_, returned))) => {
                    self.bound.remove(&key);
                    payload = returned;
                }
            }
        }
        self.dispatch_flow(src, dst, payload, whole);
    }

    /// Routes a datagram into the flow table, opening a flow for a new tuple, or holding it
    /// for the application's decision (see [`dispatch_udp`](Self::dispatch_udp)).
    fn dispatch_flow(
        &mut self,
        remote: SocketAddr,
        local: SocketAddr,
        payload: Bytes,
        whole: Option<Bytes>,
    ) {
        let key = (remote, local);
        // Existing flow: a full queue drops the datagram (normal UDP backpressure); a
        // closed one means the application dropped the flow, so it is replaced by a new
        // flow carrying this datagram.
        let payload = match self.flows.get(&key) {
            Some((flow, _)) => match flow.try_send(payload) {
                Ok(()) => return,
                Err(TrySendError::Full(_)) => {
                    tracing::trace!(%remote, %local, "UDP flow queue full; dropping");
                    stats::add(&self.stats.udp_queue_full, 1);
                    return;
                }
                Err(TrySendError::Closed(payload)) => {
                    self.flows.remove(&key);
                    payload
                }
            },
            None => payload,
        };
        if let Some(packet) = whole {
            return self.hold_udp(remote, local, payload, packet);
        }
        if self.settings.transparent.is_some() {
            self.admit_udp(remote, local);
        }
        // Bound the table: refuse a new flow when it is full of live flows rather than
        // grow without limit under a spray of distinct tuples.
        if self.flows.len() >= self.settings.max_udp_flows {
            self.flows.retain(|_, (flow, _)| !flow.is_closed());
            if self.flows.len() >= self.settings.max_udp_flows {
                tracing::warn!(%remote, %local, "UDP flow table at capacity; dropping new flow");
                stats::add(&self.stats.udp_flow_limit, 1);
                return;
            }
        }
        let (tx, rx) = mpsc::channel(self.settings.datagram_capacity);
        // The queue is empty, so the first datagram always fits.
        let _ = tx.try_send(payload);
        // Registered before the application can see (and drop) the flow.
        let registration = self.owners.udp_flow(local, remote);
        let state = FlowState::new(Target::UdpFlow(key), &self.revocations);
        let flow = UdpFlow::new(
            registration,
            rx,
            UdpReply::new(local, remote, self.out.clone(), Arc::clone(&state)),
        );
        if self.accept_udp.try_send(flow).is_ok() {
            self.flows.insert(key, (tx, state));
        } else {
            tracing::debug!(%remote, %local, "incoming_udp full or gone; dropping UDP flow");
            stats::add(&self.stats.udp_not_accepted, 1);
        }
    }

    /// Handles queued requests from handles.
    fn take_commands(&mut self) {
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

    fn command(&mut self, command: Command) {
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

    /// Moves queued UDP sends into the egress backlog while it has room, and forgets the
    /// marks of datagrams the source took.
    fn take_udp_sends(&mut self) {
        let oldest = self.oldest_queued();
        while self
            .marks
            .front()
            .is_some_and(|(position, _)| *position < oldest)
        {
            self.marks.pop_front();
        }
        while !self.device.tx_full() {
            match self.udp_rx.try_recv() {
                Ok((packet, flow)) => self.push_udp(packet, flow),
                Err(_) => break,
            }
        }
    }

    /// Appends a UDP datagram of `flow` to the egress backlog, or drops it if the flow was
    /// revoked.
    fn push_udp(&mut self, packet: PacketBuf, flow: Arc<FlowState>) {
        if flow.is_revoked() {
            return stats::add(&self.stats.retired, 1);
        }
        self.marks.push_back((self.position(), flow));
        self.device.tx_queue.push_back(packet);
    }

    /// The egress position of the next packet appended to the backlog.
    fn position(&self) -> u64 {
        self.sent + self.device.tx_queue.len() as u64
    }

    /// The egress position of the oldest packet possibly still in the egress queue.
    fn oldest_queued(&self) -> u64 {
        let queued = self.egress.max_capacity() - self.egress.capacity();
        self.sent.saturating_sub(queued as u64)
    }

    /// Retires the flows revoked since the last turn, see [`retire`](Self::retire).
    fn retire_revoked(&mut self) {
        self.revocations.take(&mut self.retiring);
        // Each flow stays in `retiring` until its outcome is written, so a panic leaves the
        // rest to `Drop`, which reports them unknown.
        while let Some(flow) = self.retiring.last().cloned() {
            #[cfg(test)]
            flow.observed_in(self.turns);
            let outcome = self.retire(&flow);
            #[cfg(test)]
            flow.completed_in(self.turns);
            flow.finish(outcome);
            self.retiring.pop();
        }
    }

    /// Removes a revoked flow's state and its output from the stack: the socket (without
    /// an RST) or the queue entry, its packets in the backlog, a fence for those already
    /// in the egress queue, and a barrier for its fragments the reassembler may hold.
    /// `Failed` if the fence or the barrier table is full.
    fn retire(&mut self, flow: &Arc<FlowState>) -> RetirementOutcome {
        let fenced = match flow.target() {
            &Target::Tcp {
                handle,
                local,
                peer,
                start,
                ..
            } => {
                if self
                    .conns
                    .get(&handle)
                    .is_some_and(|conn| Arc::ptr_eq(&conn.flow, flow))
                {
                    self.aborting.retain(|&aborting| aborting != handle);
                    self.release_conn(handle);
                }
                self.purge_tcp(local, peer, start, flow.end())
            }
            Target::UdpFlow(key) => {
                if self
                    .flows
                    .get(key)
                    .is_some_and(|(_, owner)| Arc::ptr_eq(owner, flow))
                {
                    self.flows.remove(key);
                }
                self.purge_udp(flow)
            }
            Target::UdpBound(local) => {
                if self
                    .bound
                    .get(local)
                    .is_some_and(|(_, owner)| Arc::ptr_eq(owner, flow))
                {
                    self.bound.remove(local);
                }
                self.purge_udp(flow)
            }
            Target::UdpConnected(key) => {
                if self
                    .connected
                    .get(key)
                    .is_some_and(|(_, owner)| Arc::ptr_eq(owner, flow))
                {
                    self.connected.remove(key);
                }
                self.purge_udp(flow)
            }
        };
        let barred = self.bar(flow.target());
        if fenced && barred {
            RetirementOutcome::Retired
        } else {
            RetirementOutcome::Failed
        }
    }

    /// Drops the TCP packets from `local` to `peer` at egress positions in `[start, end)`
    /// from the backlog and fences those possibly in the egress queue; `false` if the
    /// fence table is full.
    fn purge_tcp(&mut self, local: SocketAddr, peer: SocketAddr, start: u64, end: u64) -> bool {
        let sent = self.sent;
        let mut dropped = 0;
        for (position, packet) in (sent..).zip(self.device.tx_queue.iter_mut()) {
            if (start..end).contains(&position)
                && tcp_tuple(packet.as_packet()) == Some((local, peer))
            {
                *packet = placeholder();
                dropped += 1;
            }
        }
        stats::add(&self.stats.retired, dropped);
        let (start, end) = (start.max(self.oldest_queued()), end.min(sent));
        start >= end
            || self.fences.insert(Fence::Tcp {
                local,
                peer,
                start,
                end,
            })
    }

    /// Drops the UDP datagrams of `flow` from the backlog and fences those possibly in the
    /// egress queue; `false` if the fence table is full.
    fn purge_udp(&mut self, flow: &Arc<FlowState>) -> bool {
        let (sent, oldest) = (self.sent, self.oldest_queued());
        let tx_queue = &mut self.device.tx_queue;
        let mut dropped = 0;
        let mut queued = VecDeque::new();
        self.marks.retain(|(position, owner)| {
            if !Arc::ptr_eq(owner, flow) {
                return true;
            }
            if *position >= sent {
                let index = usize::try_from(position - sent).unwrap_or(usize::MAX);
                if let Some(packet) = tx_queue.get_mut(index) {
                    *packet = placeholder();
                    dropped += 1;
                }
            } else if *position >= oldest {
                queued.push_back(*position);
            }
            false
        });
        stats::add(&self.stats.retired, dropped);
        queued.is_empty() || self.fences.insert(Fence::Udp(queued))
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
        let flow = FlowState::new(Target::UdpBound(addr), &self.revocations);
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
        let flow = FlowState::new(Target::UdpConnected(key), &self.revocations);
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

    /// Promotes established listener sockets to connections for `incoming_tcp`.
    fn promote(&mut self, now: SmolInstant) {
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
    fn accept_full(&self) -> bool {
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
    fn flush_waiting(&mut self) {
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
    fn finish_connects(&mut self, now: SmolInstant) {
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

    /// Keeps the bytes of terminal sockets before smoltcp's timers discard the socket.
    fn preserve_all(&mut self, now: SmolInstant) {
        for (&handle, conn) in &mut self.conns {
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
            let mut shared = lock(&conn.shared);
            preserve_terminal_receive(socket, &mut shared, &mut conn.last_activity_at, now);
        }
    }

    /// Bridges every connection and releases terminal ones; `true` if bytes were sent or
    /// an aborted connection waits for its RST to be sent.
    fn bridge_all(&mut self, now: SmolInstant) -> bool {
        let mut sent = false;
        let mut released = Vec::new();
        // Each sending connection's share of the send budget.
        let limit = self.settings.tcp_send_budget.map_or(usize::MAX, |budget| {
            let senders = self
                .conns
                .iter()
                .filter(|&(&handle, conn)| {
                    conn.sending(self.sockets.get::<tcp::Socket<'_>>(handle))
                })
                .count();
            (budget / senders.max(1)).max(usize::from(self.settings.mtu) - 40)
        });
        for (&handle, conn) in &mut self.conns {
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
            let bridged = conn.bridge(socket, now, limit);
            sent |= bridged.sent;
            if bridged.terminal {
                released.push(handle);
            } else if bridged.aborting {
                self.aborting.push(handle);
            }
        }
        for handle in released {
            self.release_conn(handle);
        }
        sent || !self.aborting.is_empty()
    }

    /// Releases the aborted connections whose RST the poll after the bridge pass sent (one
    /// the device could not send yet stays until a later bridge pass finds it sent), then
    /// retries the connects that waited for their ports.
    fn release_aborted(&mut self) {
        for handle in std::mem::take(&mut self.aborting) {
            if self
                .sockets
                .get::<tcp::Socket<'_>>(handle)
                .remote_endpoint()
                .is_none()
            {
                self.release_conn(handle);
            }
        }
        for command in std::mem::take(&mut self.deferred) {
            self.command(command);
        }
    }

    /// Whether an aborted connection not released yet holds `port`.
    fn aborting_port(&self, port: u16) -> bool {
        self.conns.iter().any(|(&handle, conn)| {
            self.sockets
                .get::<tcp::Socket<'_>>(handle)
                .local_endpoint()
                .is_some_and(|endpoint| endpoint.port == port)
                && lock(&conn.shared).write_half == WriteHalf::Aborted
        })
    }

    /// Releases a connection's tuple and socket and tells the application.
    fn release_conn(&mut self, handle: SocketHandle) {
        let end = self.position();
        if let Some(conn) = self.conns.remove(&handle) {
            conn.flow.set_end(end);
            conn.release();
        }
        self.sockets.remove(handle);
    }

    /// Unregisters listener sockets that left the handshake without being established
    /// (reset back to `Listen`, or closed).
    fn release_inbound(&mut self) {
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
    fn track_inbound(&mut self, demand: &HashMap<u16, usize>, mark: u64) {
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

    /// Moves the egress backlog into the source's queue; `false` once the source is gone.
    fn flush_egress(&mut self) -> bool {
        while let Some(packet) = self.device.tx_queue.pop_front() {
            match self.egress.try_send(packet) {
                Ok(()) => self.sent += 1,
                Err(TrySendError::Full(packet)) => {
                    self.device.tx_queue.push_front(packet);
                    break;
                }
                Err(TrySendError::Closed(_)) => {
                    tracing::debug!(target: "netstack", "source dropped; stopping");
                    return false;
                }
            }
        }
        true
    }

    /// Waits for ingress, a request, application I/O, egress room or a smoltcp timer;
    /// `false` once the stack must stop.
    async fn wait(&mut self, now: SmolInstant) -> bool {
        let tx_full = self.device.tx_full();
        let mut delay = if tx_full {
            MAX_POLL_DELAY
        } else {
            self.iface
                .poll_delay(now, &self.sockets)
                .map_or(MAX_POLL_DELAY, |delay| {
                    Duration::from_micros(delay.total_micros()).min(MAX_POLL_DELAY)
                })
        };
        if let Some(deadline) = self.pending.as_deref_mut().and_then(Pending::next_deadline) {
            delay = delay.min(deadline.saturating_duration_since(Instant::now()));
        }
        if delay.is_zero() {
            tokio::task::yield_now().await;
            return true;
        }
        let backlog = !self.device.tx_queue.is_empty();
        let waiting = !self.waiting.is_empty();
        let has_commands = self.commands.is_some();
        let command = tokio::select! {
            packet = self.ingress.recv() => match packet {
                Some(packet) => {
                    self.carried = Some(packet);
                    return true;
                }
                None => return false,
            },
            command = next_command(self.commands.as_mut()), if has_commands => command,
            Some((packet, flow)) = self.udp_rx.recv(), if !tx_full => {
                // `push_udp`, on the fields the other branches do not borrow.
                if flow.is_revoked() {
                    stats::add(&self.stats.retired, 1);
                } else {
                    let position = self.sent + self.device.tx_queue.len() as u64;
                    self.marks.push_back((position, flow));
                    self.device.tx_queue.push_back(packet);
                }
                return true;
            }
            () = self.notify.notified() => return true,
            () = self.egress.closed() => {
                tracing::debug!(target: "netstack", "source dropped; stopping");
                return false;
            }
            permit = self.accept_tcp.reserve(), if waiting => {
                if let (Ok(permit), Some(connection)) = (permit, self.waiting.pop_front()) {
                    permit.send(connection);
                }
                return true;
            }
            permit = self.egress.reserve(), if backlog => match permit {
                Ok(permit) => {
                    if let Some(packet) = self.device.tx_queue.pop_front() {
                        permit.send(packet);
                        self.sent += 1;
                    }
                    return true;
                }
                Err(_) => return false,
            },
            () = tokio::time::sleep(delay) => return true,
        };
        match command {
            Some(command) => self.command(command),
            None => self.commands = None,
        }
        true
    }
}

/// The unspecified address of `ip`'s family.
const fn unspecified(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// A random port of the ephemeral range, where a stack starts handing out ports, so that
/// stacks (and restarts) do not reuse the same ports in the same order.
fn random_ephemeral() -> u16 {
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

/// Locates a TCP segment before reserving listener capacity.
pub(crate) fn tcp_segment(pkt: &[u8]) -> Option<&[u8]> {
    if pkt.first().is_some_and(|byte| byte >> 4 == 6) {
        let packet = smoltcp::wire::Ipv6Packet::new_checked(pkt).ok()?;
        let mut next = packet.next_header();
        let mut offset = 40;
        // Match smoltcp's receiver: one Hop-by-Hop header may precede TCP.
        if next == smoltcp::wire::IpProtocol::HopByHop {
            let extension = smoltcp::wire::Ipv6ExtHeader::new_checked(packet.payload()).ok()?;
            next = extension.next_header();
            offset += (usize::from(extension.header_len()) + 1) * 8;
        }
        if next != smoltcp::wire::IpProtocol::Tcp {
            return None;
        }
        return pkt.get(offset..40 + usize::from(packet.payload_len()));
    }
    let (&first, rest) = pkt.split_first()?;
    if pkt.len() < 20 || first >> 4 != 4 || rest.get(8) != Some(&protocol::TCP) {
        return None;
    }
    let ihl = usize::from(first & 0xf) * 4;
    if pkt.len() < ihl + 4 {
        return None;
    }
    pkt.get(ihl..)
}

/// The `(src, dst)` of a TCP packet.
pub(crate) fn tcp_tuple(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let segment = tcp_segment(pkt)?;
    let (src_port, dst_port) = (
        u16::from_be_bytes([*segment.first()?, *segment.get(1)?]),
        u16::from_be_bytes([*segment.get(2)?, *segment.get(3)?]),
    );
    let ip = IpPacket::parse(pkt).ok()?;
    Some((
        SocketAddr::new(ip.src(), src_port),
        SocketAddr::new(ip.dst(), dst_port),
    ))
}

/// What a packet dropped from the backlog leaves behind: an empty packet, which keeps the
/// later packets' egress positions and which the source discards.
fn placeholder() -> PacketBuf {
    PacketBuf::with_capacity(0)
}

/// The RST answering the bare SYN `syn`, from its destination (RFC 9293 section 3.10.7.1:
/// sequence number 0, acknowledging the SYN and its data).
pub(crate) fn tcp_reset(syn: &[u8]) -> Option<PacketBuf> {
    const RST_ACK: u8 = 0x14;
    const FIN: u8 = 0x01;
    let segment = tcp_segment(syn)?;
    let (&[src_hi, src_lo, dst_hi, dst_lo, s0, s1, s2, s3], rest) =
        segment.split_first_chunk::<8>()?;
    let offset = usize::from(rest.get(4)? >> 4) * 4;
    let flags = *rest.get(5)?;
    let data = segment.len().checked_sub(offset)?;
    let length = u32::try_from(data).ok()? + 1 + u32::from(flags & FIN);
    let ack = u32::from_be_bytes([s0, s1, s2, s3]).wrapping_add(length);
    let mut reply = [0u8; 20];
    reply[0..2].copy_from_slice(&[dst_hi, dst_lo]);
    reply[2..4].copy_from_slice(&[src_hi, src_lo]);
    reply[8..12].copy_from_slice(&ack.to_be_bytes());
    reply[12] = 5 << 4;
    reply[13] = RST_ACK;
    let ip = IpPacket::parse(syn).ok()?;
    let (src, dst) = (ip.dst(), ip.src());
    let (header, total) = match src {
        IpAddr::V4(_) => (20, 40),
        IpAddr::V6(_) => (40, 60),
    };
    let mut packet = PacketBuf::with_capacity(total + TAILROOM);
    packet.set_len(total);
    let bytes = packet.as_packet_mut();
    let (head, tcp) = bytes.split_at_mut(header);
    tcp.copy_from_slice(&reply);
    let sum = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            head[0] = 0x45;
            head[2..4].copy_from_slice(&40u16.to_be_bytes());
            head[6] = 0x40;
            head[8] = 64;
            head[9] = protocol::TCP;
            head[12..16].copy_from_slice(&src.octets());
            head[16..20].copy_from_slice(&dst.octets());
            let header_checksum = checksum::ipv4_header_checksum(head);
            head[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            pending::pseudo_header_checksum(src.into(), dst.into(), protocol::TCP, tcp)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            head[0] = 0x60;
            head[4..6].copy_from_slice(&20u16.to_be_bytes());
            head[6] = protocol::TCP;
            head[7] = 64;
            head[8..24].copy_from_slice(&src.octets());
            head[24..40].copy_from_slice(&dst.octets());
            pending::pseudo_header_checksum(src.into(), dst.into(), protocol::TCP, tcp)
        }
        _ => return None,
    };
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    Some(packet)
}

fn tcp_dst_port(pkt: &[u8]) -> Option<u16> {
    let segment = tcp_segment(pkt)?;
    Some(u16::from_be_bytes([*segment.get(2)?, *segment.get(3)?]))
}

/// Whether a raw IP packet is a bare TCP SYN (a connection attempt, not the SYN-ACK of
/// one the stack opened).
fn tcp_is_syn(pkt: &[u8]) -> bool {
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    let Some(&flags) = tcp_segment(pkt).and_then(|segment| segment.get(13)) else {
        return false;
    };
    flags & SYN != 0 && flags & ACK == 0
}

const fn tcp_listener_ready_for_promotion(state: tcp::State) -> bool {
    matches!(state, tcp::State::Established | tcp::State::CloseWait)
}

fn tcp_idle_timeout_expired(
    state: tcp::State,
    last_activity_at: SmolInstant,
    now: SmolInstant,
) -> bool {
    !matches!(state, tcp::State::Closed | tcp::State::TimeWait)
        && now >= last_activity_at + idle_timeout()
}

#[cfg(not(test))]
const fn idle_timeout() -> SmolDuration {
    TCP_IDLE_TIMEOUT
}

#[cfg(test)]
thread_local! {
    /// Replaces [`TCP_IDLE_TIMEOUT`] for the stacks a test drives on its thread.
    static IDLE_TIMEOUT: std::cell::Cell<Option<SmolDuration>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn idle_timeout() -> SmolDuration {
    IDLE_TIMEOUT
        .with(std::cell::Cell::get)
        .unwrap_or(TCP_IDLE_TIMEOUT)
}

fn tcp_terminal_ready(
    state: tcp::State,
    receive_pending: bool,
    last_activity_at: SmolInstant,
    now: SmolInstant,
) -> bool {
    matches!(state, tcp::State::Closed | tcp::State::TimeWait)
        && (!receive_pending || now >= last_activity_at + TCP_IDLE_TIMEOUT)
}

const fn record_receive_activity(
    received: usize,
    last_activity_at: &mut SmolInstant,
    now: SmolInstant,
) {
    if received > 0 {
        *last_activity_at = now;
    }
}

/// Moves every byte of a terminal socket into the application buffer, past its bound.
fn preserve_terminal_receive(
    socket: &mut tcp::Socket<'_>,
    shared: &mut Shared,
    last_activity_at: &mut SmolInstant,
    now: SmolInstant,
) {
    if !matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) || !socket.can_recv() {
        return;
    }
    // FIN bounds this transfer to one receive buffer.
    let previous = shared.rx.len();
    while socket.can_recv() {
        let received = socket.recv(|bytes| {
            shared.rx.extend(bytes.iter());
            (bytes.len(), ())
        });
        if received.is_err() {
            break;
        }
    }
    record_receive_activity(shared.rx.len() - previous, last_activity_at, now);
    shared.wake_reader();
}

/// A TCP socket tuned for relaying, with buffers of `rx_buffer` and `tx_buffer` bytes and
/// the RTO bounds `rto`.
///
/// smoltcp derives the window-scale shift from the receive buffer's capacity here.
fn new_tcp_socket(rx_buffer: usize, tx_buffer: usize, rto: TcpRto) -> tcp::Socket<'static> {
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; rx_buffer]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; tx_buffer]);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);
    // smoltcp's default 10 ms delayed ACK withholds window updates until expiry, stalling
    // a far sender that filled the receive window (one ack delay per window over a
    // high-RTT overlay); Nagle adds an RTT of coalescing latency. A relay wants neither.
    socket.set_ack_delay(None);
    socket.set_nagle_enabled(false);
    socket.set_keep_alive(None);
    // Without congestion control smoltcp sends the whole peer window at once and, after a
    // timeout, all of it again; a path that drops part of such a burst (a full socket
    // buffer) loses the retransmission too and the timeouts double past 30 s. CUBIC
    // restarts from one segment after a timeout and backs off on loss.
    socket.set_congestion_control(tcp::CongestionControl::Cubic);
    socket.set_min_rto(rto.min);
    socket.set_initial_rto(rto.initial);
    socket
}

/// Computes fair free-listener targets for the complete current SYN batch, trims idle
/// sockets above those targets, then fills each target. Every port receives one socket
/// before any port receives a second one. `SynReceived` sockets are never reclaimed
/// because they own in-flight handshakes. Returns how many SYNs find no socket.
fn prepare_tcp_listeners(
    demand: &HashMap<u16, usize>,
    allocation_cursor: &mut u16,
    listeners: &mut HashMap<u16, Vec<SocketHandle>>,
    sockets: &mut SocketSet<'_>,
    pool: Pool,
) -> usize {
    let mut held_per_port: HashMap<u16, usize> = HashMap::new();
    let mut held_total = 0usize;
    for (&port, handles) in listeners.iter() {
        for &handle in handles {
            let state = sockets.get::<tcp::Socket<'_>>(handle).state();
            if !matches!(
                state,
                tcp::State::Listen | tcp::State::Closed | tcp::State::TimeWait
            ) {
                *held_per_port.entry(port).or_insert(0) += 1;
                held_total += 1;
            }
        }
    }

    let mut requests: Vec<(u16, usize)> = demand
        .iter()
        .map(|(&port, &want)| {
            let held = held_per_port.get(&port).copied().unwrap_or(0);
            (port, want.min(pool.limit.saturating_sub(held)))
        })
        .collect();
    requests.sort_unstable_by_key(|&(port, _)| port);
    if !requests.is_empty() {
        let start = requests.partition_point(|&(port, _)| port < *allocation_cursor);
        let request_count = requests.len();
        requests.rotate_left(start % request_count);
    }

    let mut targets: HashMap<u16, usize> = HashMap::new();
    let mut available = pool.limit.saturating_sub(held_total);
    let mut last_allocated_port = None;
    for target_free in 1..=pool.limit {
        let mut needed_this_round = false;
        for &(port, want) in &requests {
            if target_free > want {
                continue;
            }
            needed_this_round = true;
            if available == 0 {
                break;
            }
            targets.insert(port, target_free);
            available -= 1;
            last_allocated_port = Some(port);
        }
        if !needed_this_round || available == 0 {
            break;
        }
    }
    if let Some(port) = last_allocated_port {
        *allocation_cursor = port.wrapping_add(1);
    }
    let planned_total = held_total + targets.values().sum::<usize>();
    let mut refused = 0;
    for (&port, &want) in demand {
        let free = targets.get(&port).copied().unwrap_or(0);
        if free < want {
            refused += want - free;
            tracing::warn!(
                target: "netstack",
                port,
                demand = want,
                free,
                held = held_per_port.get(&port).copied().unwrap_or(0),
                total = planned_total,
                "TCP listener pool at its cap; excess SYNs will be refused"
            );
        }
    }

    let mut reclaimed = Vec::new();
    for (&port, handles) in listeners.iter_mut() {
        let keep_free = targets.get(&port).copied().unwrap_or(0);
        let mut free_kept = 0usize;
        handles.retain(|&handle| {
            match sockets.get::<tcp::Socket<'_>>(handle).state() {
                tcp::State::Listen if free_kept < keep_free => {
                    free_kept += 1;
                    true
                }
                tcp::State::Listen | tcp::State::Closed | tcp::State::TimeWait => {
                    reclaimed.push(handle);
                    false
                }
                // In-flight handshakes and sockets awaiting the two-phase promotion pass
                // own their handles and are never reclaimed.
                _ => true,
            }
        });
    }
    listeners.retain(|_, handles| !handles.is_empty());
    for handle in reclaimed {
        sockets.remove(handle);
    }

    for (port, target_free) in targets {
        ensure_tcp_listeners(port, target_free, listeners, sockets, pool);
    }
    refused
}

/// Holds at least `demand` sockets in `Listen` on `port`, so that many SYNs can be
/// accepted by the next poll.
///
/// Sockets already in `SynReceived` stay tracked (they are mid-handshake and will be
/// promoted) but do not count as free capacity: a SYN cannot land on them.
fn ensure_tcp_listeners(
    port: u16,
    demand: usize,
    listeners: &mut HashMap<u16, Vec<SocketHandle>>,
    sockets: &mut SocketSet<'_>,
    pool: Pool,
) {
    let handles = listeners.entry(port).or_default();
    let mut terminal_handles = Vec::new();
    handles.retain(|&handle| {
        let terminal = matches!(
            sockets.get::<tcp::Socket<'_>>(handle).state(),
            tcp::State::Closed | tcp::State::TimeWait
        );
        if terminal {
            terminal_handles.push(handle);
        }
        !terminal
    });
    for handle in terminal_handles {
        sockets.remove(handle);
    }
    let free = handles
        .iter()
        .filter(|&&handle| sockets.get::<tcp::Socket<'_>>(handle).state() == tcp::State::Listen)
        .count();
    let held = handles.len();

    let total: usize = listeners.values().map(Vec::len).sum();
    let headroom = pool
        .limit
        .saturating_sub(held)
        .min(pool.limit.saturating_sub(total));
    let add = demand.saturating_sub(free).min(headroom);
    if add < demand.saturating_sub(free) {
        tracing::warn!(
            target: "netstack",
            port,
            demand,
            free,
            held,
            total,
            "TCP listener pool at its cap; excess SYNs will be refused"
        );
    }

    let handles = listeners.entry(port).or_default();
    for _ in 0..add {
        let mut socket = new_tcp_socket(pool.rx_buffer, pool.tx_buffer, pool.rto);
        let _ = socket.listen(port);
        handles.push(sockets.add(socket));
    }
}

/// Converts a smoltcp endpoint to a std socket address.
fn endpoint_to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.addr.into(), endpoint.port)
}

#[cfg(test)]
mod tests;
