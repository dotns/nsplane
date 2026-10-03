//! The stack, its source and sink halves, its handle and the driver task.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use nsplane::{PacketSink, PacketSource};
use nsplane_packet::{IpPacket, PacketBuf, PeerId, protocol};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::config::{NetStackConfig, Settings};
use crate::device::{VirtualDevice, note_peer_ack};
use crate::stats::{self, Counters, NetStackStats};
use crate::tcp::{Shared, TcpConnection, WriteHalf, lock};
use crate::udp::{self, Datagram, UdpFlow, UdpOut, UdpReply, UdpSocket};

/// Most ingress packets taken per driver iteration before smoltcp runs, so one burst
/// cannot starve the bridge phase.
const MAX_INJECT_PER_ITER: usize = 256;
/// Egress packets the device holds while the source's queue is full. smoltcp stops
/// transmitting at this bound; only immediate replies to ingested packets are dropped
/// (and counted) beyond it.
const EGRESS_BACKLOG: usize = 256;
/// Commands (`connect_tcp`, `bind_udp`) queued for the driver.
const COMMAND_CAPACITY: usize = 64;
/// Longest the driver sleeps without a timer from smoltcp.
const MAX_POLL_DELAY: Duration = Duration::from_millis(50);
/// Maximum interval without application payload in either direction of a connection.
const TCP_IDLE_TIMEOUT: SmolDuration = SmolDuration::from_secs(5 * 60);
/// How long a connection may go without moving application bytes before the driver
/// assumes smoltcp lost track of it and nudges it (see [`nudge_stalled`]).
const STALL_KICK: SmolDuration = SmolDuration::from_secs(1);
/// Bytes a stalled connection may take into its application buffer beyond the bound, to
/// reopen its receive window.
const STALL_RECEIVE: usize = 1024;
/// Keep-alive interval of a stalled connection with bytes to send: it probes the peer's
/// window instead of smoltcp's persist timer.
const STALL_PROBE: SmolDuration = SmolDuration::from_secs(1);
/// How long `connect_tcp` waits for the handshake.
const CONNECT_TIMEOUT: SmolDuration = SmolDuration::from_secs(20);
/// First ephemeral port for `connect_tcp` and `bind_udp` on port 0 (RFC 6335).
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
/// The stack terminates TCP and UDP addressed to its own addresses (any port), for IPv4
/// and IPv6. Everything else it receives is dropped and counted in
/// [`NetStackHandle::stats`].
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
        let (_, mtu) = watch::channel(settings.mtu);

        let mut device = VirtualDevice::new(settings.mtu, EGRESS_BACKLOG, Arc::clone(&stats));
        let iface = interface(&settings, &mut device);
        let out = UdpOut {
            tx: udp_tx,
            mtu: usize::from(settings.mtu),
        };
        let driver = Driver {
            settings,
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            listeners: HashMap::new(),
            allocation_cursor: 0,
            conns: HashMap::new(),
            connecting: Vec::new(),
            flows: HashMap::new(),
            bound: HashMap::new(),
            ingress,
            egress,
            commands: Some(commands),
            udp_rx,
            out,
            accept_tcp,
            accept_udp,
            notify,
            stats: Arc::clone(&stats),
            carried: None,
            next_tcp_port: EPHEMERAL_START,
            next_udp_port: EPHEMERAL_START,
            epoch: Instant::now(),
        };
        tokio::spawn(driver.run());

        let stack = Self {
            source: NetStackSource { rx: egress_rx, mtu },
            sink: NetStackSink { tx: ingress_tx },
        };
        let handle = NetStackHandle {
            commands: commands_tx,
            incoming_tcp: Arc::new(Mutex::new(Some(incoming_tcp))),
            incoming_udp: Arc::new(Mutex::new(Some(incoming_udp))),
            stats,
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
/// configured MTU. [`recv`](PacketSource::recv) returns [`io::ErrorKind::BrokenPipe`] once
/// the driver stopped and the queue is drained, on every later call. [`mtu`](PacketSource::mtu)
/// holds the (normalised) configured MTU, which never changes.
#[derive(Debug)]
pub struct NetStackSource {
    rx: mpsc::Receiver<PacketBuf>,
    mtu: watch::Receiver<u16>,
}

impl PacketSource for NetStackSource {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        self.rx.recv().await.ok_or_else(stack_gone)
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
        reply: oneshot::Sender<io::Result<TcpConnection>>,
    },
    Bind {
        local: SocketAddr,
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
    stats: Arc<Counters>,
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
    /// Datagrams to an address bound with [`bind_udp`](Self::bind_udp) are not reported
    /// here. Only the first call (on any clone of the handle) gets the flows; every later
    /// call returns a stream that ends immediately. The stream ends when the stack stops.
    /// Flows that arrive while the stream is not consumed are queued up to
    /// [`NetStackConfig::accept_capacity`], then dropped and counted.
    pub fn incoming_udp(&self) -> impl Stream<Item = UdpFlow> + Send + Unpin + use<> {
        Incoming(take(&self.incoming_udp))
    }

    /// Opens a TCP connection from the stack to `remote`.
    ///
    /// The local end is the stack's address of `remote`'s family and an ephemeral port.
    /// Fails with [`io::ErrorKind::AddrNotAvailable`] if the stack has no address of that
    /// family, [`io::ErrorKind::ConnectionRefused`] if the peer resets the handshake,
    /// [`io::ErrorKind::TimedOut`] if it does not answer within 20 seconds and
    /// [`io::ErrorKind::BrokenPipe`] once the stack stopped.
    pub async fn connect_tcp(&self, remote: SocketAddr) -> io::Result<TcpConnection> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Connect { remote, reply })
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

    /// The stack's drop counters.
    pub fn stats(&self) -> NetStackStats {
        self.stats.snapshot()
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

/// Creates the smoltcp interface with the stack's addresses.
fn interface(settings: &Settings, device: &mut VirtualDevice) -> Interface {
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = RandomState::new().build_hasher().finish();
    let mut iface = Interface::new(config, device, SmolInstant::ZERO);
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
}

/// Why an ingress packet is dropped.
#[derive(Debug, PartialEq, Eq)]
enum Reject {
    Malformed,
    NoAddress,
    Unsupported,
}

/// Decides what to do with an ingress packet.
fn classify(bytes: &[u8], settings: &Settings) -> Result<Class, Reject> {
    let ip = IpPacket::parse(bytes).map_err(|_| Reject::Malformed)?;
    if !settings.is_local(ip.dst()) {
        return Err(Reject::NoAddress);
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
        _ => Err(Reject::Unsupported),
    }
}

/// Driver-side state of one connection handed to the application.
struct Conn {
    shared: Arc<Mutex<Shared>>,
    terminal: watch::Sender<bool>,
    /// `close()` was called on the socket.
    local_closed: bool,
    last_activity_at: SmolInstant,
    /// `(local, remote)`, the connection's key in the device's peer acknowledgements.
    endpoints: (SocketAddr, SocketAddr),
}

/// What one bridge pass did.
struct Bridged {
    /// Bytes moved into the socket's send buffer.
    sent: bool,
    /// The socket can be released.
    terminal: bool,
}

impl Conn {
    /// Moves bytes between the socket and the application and applies half closes.
    fn bridge(&mut self, socket: &mut tcp::Socket<'_>, now: SmolInstant) -> Bridged {
        let mut shared = lock(&self.shared);
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
            let n = socket.send_slice(shared.tx.as_slices().0).unwrap_or(0);
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

        nudge_stalled(socket, &mut shared, &mut self.last_activity_at, now);

        if tcp_idle_timeout_expired(socket.state(), self.last_activity_at, now) {
            tracing::debug!(target: "netstack", "TCP connection exceeded idle timeout; aborting");
            socket.abort();
        }
        let terminal = tcp_terminal_ready(
            socket.state(),
            !shared.rx.is_empty() || socket.can_recv(),
            self.last_activity_at,
            now,
        );
        Bridged { sent, terminal }
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
    reply: oneshot::Sender<io::Result<TcpConnection>>,
    started: SmolInstant,
}

/// Socket pool limits: sockets per port and in total, and each socket's buffer size.
#[derive(Debug, Clone, Copy)]
struct Pool {
    limit: usize,
    buffer: usize,
}

/// The single task that owns smoltcp and every queue behind the stack.
struct Driver {
    settings: Settings,
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    /// port -> the sockets this port has open for inbound connections: those in `Listen`
    /// (free to accept a SYN) plus those in `SynReceived` (claimed by a SYN, mid
    /// handshake). A socket leaves the pool when it is established (promoted to a
    /// connection) or dies.
    listeners: HashMap<u16, Vec<SocketHandle>>,
    /// The next destination port that receives the first listener slot when a batch has
    /// more aggregate demand than the pool.
    allocation_cursor: u16,
    conns: HashMap<SocketHandle, Conn>,
    connecting: Vec<Connecting>,
    flows: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Bytes>>,
    bound: HashMap<SocketAddr, mpsc::Sender<(SocketAddr, Bytes)>>,
    ingress: mpsc::Receiver<PacketBuf>,
    egress: mpsc::Sender<PacketBuf>,
    /// `None` once every handle is gone.
    commands: Option<mpsc::Receiver<Command>>,
    udp_rx: mpsc::Receiver<PacketBuf>,
    out: UdpOut,
    accept_tcp: mpsc::Sender<TcpConnection>,
    accept_udp: mpsc::Sender<UdpFlow>,
    notify: Arc<Notify>,
    stats: Arc<Counters>,
    /// A packet taken while waiting, replayed into the next batch so listener demand is
    /// counted in one place only.
    carried: Option<PacketBuf>,
    next_tcp_port: u16,
    next_udp_port: u16,
    epoch: Instant,
}

impl Drop for Driver {
    fn drop(&mut self) {
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
        // 1. Take a bounded batch of ingress packets and pending requests.
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
        let pool = Pool {
            limit: self.settings.listener_pool,
            buffer: self.settings.tcp_buffer(),
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

        // 5. Egress, then wait for more work.
        self.flush_egress() && self.wait(now).await
    }

    fn now(&self) -> SmolInstant {
        let micros = i64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(i64::MAX);
        SmolInstant::from_micros(micros)
    }

    /// Takes up to [`MAX_INJECT_PER_ITER`] ingress packets; `None` once the sink is gone.
    fn ingest_batch(&mut self) -> Option<HashMap<u16, usize>> {
        let mut demand = HashMap::new();
        if let Some(packet) = self.carried.take() {
            self.ingest(packet, &mut demand);
        }
        for _ in 0..MAX_INJECT_PER_ITER {
            match self.ingress.try_recv() {
                Ok(packet) => self.ingest(packet, &mut demand),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return None,
            }
        }
        Some(demand)
    }

    /// Routes one ingress packet, counting the SYNs per destination port in `demand`.
    fn ingest(&mut self, packet: PacketBuf, demand: &mut HashMap<u16, usize>) {
        match classify(packet.as_packet(), &self.settings) {
            Ok(Class::Tcp { dst_port, syn }) => {
                if syn {
                    *demand.entry(dst_port).or_insert(0) += 1;
                }
                note_peer_ack(packet.as_packet(), &mut self.device.peer_acks);
                self.device.inject(packet);
            }
            Ok(Class::Udp) => match udp::parse_udp(packet) {
                Some(datagram) => self.dispatch_udp(datagram),
                None => stats::add(&self.stats.malformed, 1),
            },
            Err(Reject::Malformed) => stats::add(&self.stats.malformed, 1),
            Err(Reject::NoAddress) => stats::add(&self.stats.no_address, 1),
            Err(Reject::Unsupported) => stats::add(&self.stats.unsupported, 1),
        }
    }

    /// Delivers a datagram to its bound socket, or to its flow.
    fn dispatch_udp(&mut self, datagram: Datagram) {
        let Datagram {
            src,
            dst,
            mut payload,
        } = datagram;
        let unspecified = match dst.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        for key in [dst, SocketAddr::new(unspecified, dst.port())] {
            let Some(socket) = self.bound.get(&key) else {
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
        self.dispatch_flow(src, dst, payload);
    }

    /// Routes a datagram into the flow table, opening a flow for a new tuple.
    fn dispatch_flow(&mut self, remote: SocketAddr, local: SocketAddr, payload: Bytes) {
        let key = (remote, local);
        // Existing flow: a full queue drops the datagram (normal UDP backpressure); a
        // closed one means the application dropped the flow, so it is replaced by a new
        // flow carrying this datagram.
        let payload = match self.flows.get(&key) {
            Some(flow) => match flow.try_send(payload) {
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
        // Bound the table: refuse a new flow when it is full of live flows rather than
        // grow without limit under a spray of distinct tuples.
        if self.flows.len() >= self.settings.max_udp_flows {
            self.flows.retain(|_, flow| !flow.is_closed());
            if self.flows.len() >= self.settings.max_udp_flows {
                tracing::warn!(%remote, %local, "UDP flow table at capacity; dropping new flow");
                stats::add(&self.stats.udp_flow_limit, 1);
                return;
            }
        }
        let (tx, rx) = mpsc::channel(self.settings.datagram_capacity);
        // The queue is empty, so the first datagram always fits.
        let _ = tx.try_send(payload);
        let flow = UdpFlow::new(rx, UdpReply::new(local, remote, self.out.clone()));
        if self.accept_udp.try_send(flow).is_ok() {
            self.flows.insert(key, tx);
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
        match command {
            Command::Connect { remote, reply } => match self.open_connect(remote) {
                Ok(handle) => self.connecting.push(Connecting {
                    handle,
                    reply,
                    started: self.now(),
                }),
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Command::Bind { local, reply } => {
                let _ = reply.send(self.bind(local));
            }
        }
    }

    /// Moves queued UDP sends into the egress backlog while it has room.
    fn take_udp_sends(&mut self) {
        while !self.device.tx_full() {
            match self.udp_rx.try_recv() {
                Ok(packet) => self.device.tx_queue.push_back(packet),
                Err(_) => break,
            }
        }
    }

    /// Starts a handshake to `remote`.
    fn open_connect(&mut self, remote: SocketAddr) -> io::Result<SocketHandle> {
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
        let port = self
            .ephemeral_tcp_port()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "no free ephemeral port"))?;
        let mut socket = new_tcp_socket(self.settings.tcp_buffer());
        socket.set_timeout(Some(CONNECT_TIMEOUT));
        socket
            .connect(
                self.iface.context(),
                IpEndpoint::new(remote.ip().into(), remote.port()),
                IpEndpoint::new(local.into(), port),
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        Ok(self.sockets.add(socket))
    }

    /// The next ephemeral port no connection or listener uses.
    fn ephemeral_tcp_port(&mut self) -> Option<u16> {
        let used: HashSet<u16> = self
            .conns
            .keys()
            .chain(self.connecting.iter().map(|connecting| &connecting.handle))
            .filter_map(|&handle| self.sockets.get::<tcp::Socket<'_>>(handle).local_endpoint())
            .map(|endpoint| endpoint.port)
            .collect();
        let listeners = &self.listeners;
        next_ephemeral(&mut self.next_tcp_port, |port| {
            !used.contains(&port) && !listeners.contains_key(&port)
        })
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
        if self.bound.get(&addr).is_some_and(|tx| !tx.is_closed()) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "address already bound",
            ));
        }
        let (tx, rx) = mpsc::channel(self.settings.datagram_capacity);
        self.bound.insert(addr, tx);
        Ok(UdpSocket::new(addr, source, rx, self.out.clone()))
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
            let connection = self.adopt(handle, now);
            tracing::debug!(
                target: "netstack",
                port,
                remote = %connection.peer_addr(),
                "TCP connection accepted"
            );
            if self.accept_tcp.try_send(connection).is_err() {
                tracing::debug!(target: "netstack", "incoming_tcp full or gone; closing");
                stats::add(&self.stats.tcp_not_accepted, 1);
            }
        }
    }

    /// Completes, fails or abandons pending `connect_tcp` calls.
    fn finish_connects(&mut self, now: SmolInstant) {
        for connecting in std::mem::take(&mut self.connecting) {
            let Connecting {
                handle,
                reply,
                started,
            } = connecting;
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
            match socket.state() {
                tcp::State::Established | tcp::State::CloseWait => {
                    socket.set_timeout(None);
                    // A caller that gave up drops the connection, which closes it.
                    let _ = reply.send(Ok(self.adopt(handle, now)));
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
                        reply,
                        started,
                    });
                }
            }
        }
    }

    /// Registers an established socket as a connection and returns the application side.
    fn adopt(&mut self, handle: SocketHandle, now: SmolInstant) -> TcpConnection {
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
        self.device.peer_acks.insert((local, peer), None);
        self.conns.insert(
            handle,
            Conn {
                shared: Arc::clone(&shared),
                terminal,
                local_closed: false,
                last_activity_at: now,
                endpoints: (local, peer),
            },
        );
        TcpConnection::new(shared, Arc::clone(&self.notify), local, peer, terminal_rx)
    }

    /// Keeps the bytes of terminal sockets before smoltcp's timers discard the socket.
    fn preserve_all(&mut self, now: SmolInstant) {
        for (&handle, conn) in &mut self.conns {
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
            let mut shared = lock(&conn.shared);
            preserve_terminal_receive(socket, &mut shared, &mut conn.last_activity_at, now);
        }
    }

    /// Bridges every connection and releases terminal ones; `true` if bytes were sent.
    fn bridge_all(&mut self, now: SmolInstant) -> bool {
        let mut sent = false;
        let mut released = Vec::new();
        for (&handle, conn) in &mut self.conns {
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(handle);
            let bridged = conn.bridge(socket, now);
            sent |= bridged.sent;
            if bridged.terminal {
                released.push(handle);
            }
        }
        for handle in released {
            if let Some(conn) = self.conns.remove(&handle) {
                self.device.peer_acks.remove(&conn.endpoints);
                conn.release();
            }
            self.sockets.remove(handle);
        }
        sent
    }

    /// Moves the egress backlog into the source's queue; `false` once the source is gone.
    fn flush_egress(&mut self) -> bool {
        while let Some(packet) = self.device.tx_queue.pop_front() {
            match self.egress.try_send(packet) {
                Ok(()) => {}
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
        let delay = if tx_full {
            MAX_POLL_DELAY
        } else {
            self.iface
                .poll_delay(now, &self.sockets)
                .map_or(MAX_POLL_DELAY, |delay| {
                    Duration::from_micros(delay.total_micros()).min(MAX_POLL_DELAY)
                })
        };
        if delay.is_zero() {
            tokio::task::yield_now().await;
            return true;
        }
        let backlog = !self.device.tx_queue.is_empty();
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
            Some(packet) = self.udp_rx.recv(), if !tx_full => {
                self.device.tx_queue.push_back(packet);
                return true;
            }
            () = self.notify.notified() => return true,
            () = self.egress.closed() => {
                tracing::debug!(target: "netstack", "source dropped; stopping");
                return false;
            }
            permit = self.egress.reserve(), if backlog => match permit {
                Ok(permit) => {
                    if let Some(packet) = self.device.tx_queue.pop_front() {
                        permit.send(packet);
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
fn tcp_segment(pkt: &[u8]) -> Option<&[u8]> {
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
        && now >= last_activity_at + TCP_IDLE_TIMEOUT
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

/// Nudges a connection that moved no application bytes for [`STALL_KICK`].
///
/// smoltcp 0.14 can strand a connection after a lost segment when the peer's window
/// closes. Window scaling rounds a receive window of a few bytes down to zero, which
/// pulls the right edge back behind data the sender already sent and lost. The sender
/// then runs its zero-window probe timer instead of the retransmission timer, so the
/// lost bytes are never resent. The receiver drops the sender's pure ACKs, whose
/// sequence number now lies beyond its window, so its own data is never acknowledged;
/// and a sender whose retransmission timer fires while the window is zero is left with
/// no timer at all. When both ends wait on each other (an echo, a request and its
/// response) neither moves again until a retransmission backed off to tens of seconds.
///
/// Two nudges break it, each bounded:
/// - A receive side held back by a full application buffer takes up to
///   [`STALL_RECEIVE`] bytes more. The window reopens, smoltcp announces it, and the
///   peer's next data segment, which the receiver accepts, carries the ACK it dropped.
/// - A side with bytes to send keeps a keep-alive of [`STALL_PROBE`] while stalled: the
///   peer answers each probe with its current window, which stands in for the missing
///   persist timer.
fn nudge_stalled(
    socket: &mut tcp::Socket<'_>,
    shared: &mut Shared,
    last_activity_at: &mut SmolInstant,
    now: SmolInstant,
) {
    // Data may still flow in at least one direction.
    let open = socket.may_send() || socket.may_recv();
    let stalled = open && now - *last_activity_at >= STALL_KICK;
    let limit = shared.capacity + STALL_RECEIVE;
    if stalled && !shared.app_dropped && socket.can_recv() && shared.rx.len() < limit {
        let room = limit - shared.rx.len();
        let moved = socket
            .recv(|data| {
                let n = data.len().min(room);
                shared.rx.extend(&data[..n]);
                (n, n)
            })
            .unwrap_or(0);
        if moved > 0 {
            *last_activity_at = now;
            shared.wake_reader();
        }
    }
    let probe = stalled && socket.send_queue() > 0;
    if probe != socket.keep_alive().is_some() {
        socket.set_keep_alive(probe.then_some(STALL_PROBE));
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

/// A TCP socket tuned for relaying.
fn new_tcp_socket(buffer: usize) -> tcp::Socket<'static> {
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; buffer]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; buffer]);
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
        let mut socket = new_tcp_socket(pool.buffer);
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
