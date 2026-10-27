//! The stack and its source and sink halves.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::sync::{Arc, Mutex};

use nsplane::{PacketSink, PacketSource};
use nsplane_packet::reassembly::{Reassembler, ReassemblyStats};
use nsplane_packet::{PacketBuf, PeerId};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::{Notify, mpsc, watch};
use tokio::time::Instant;

use crate::config::{Admission, NetStackConfig, Settings};
use crate::device::VirtualDevice;
use crate::events::{EventSink, FlowEvent};
use crate::flow::{Fences, Revocations};
use crate::ownership::Owners;
use crate::pending::{Pending, PendingFlow};
use crate::stats::{self, Counters};
use crate::udp::UdpOut;

use super::commands::random_ephemeral;
use super::handle::NetStackHandle;
use super::wire::tcp_tuple;
use super::{COMMAND_CAPACITY, Driver, EGRESS_BACKLOG, MAX_INJECT_PER_ITER, stack_gone};

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
        let revocations = Arc::new(Revocations::new(Arc::clone(&notify)));
        let (pending, incoming_pending) = pending_table(&settings, &notify, &revocations).unzip();
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
    pub(super) rx: mpsc::Receiver<PacketBuf>,
    mtu: watch::Receiver<u16>,
    /// Packets taken from `rx`: the egress position of the next one.
    pub(super) received: u64,
    revocations: Arc<Revocations>,
    pub(super) fences: Arc<Fences>,
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
    /// Returns an error for another stack's control, a non-TCP flow, a revoked flow, or a
    /// lifetime held under [`Admission::Decide`] that has no connection yet (held,
    /// mid handshake, or ended before it was established).
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

/// The pending table and the receiving end of its items, with `Admission::Decide` only.
fn pending_table(
    settings: &Settings,
    notify: &Arc<Notify>,
    revocations: &Arc<Revocations>,
) -> Option<(Pending, mpsc::Receiver<PendingFlow>)> {
    match settings.admission {
        Admission::Decide {
            timeout,
            max_pending,
        } => {
            let (offer, incoming) = mpsc::channel(max_pending);
            let table = Pending::new(
                timeout,
                max_pending,
                offer,
                Arc::clone(notify),
                Arc::clone(revocations),
            );
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
