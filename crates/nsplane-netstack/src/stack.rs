//! The stack, its source and sink halves, its handle and the driver task.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use nsplane_packet::PacketBuf;
use nsplane_packet::reassembly::{Reassembler, ReassemblyStats};
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

use crate::config::Settings;
use crate::device::VirtualDevice;
use crate::events::EventSink;
use crate::flow::{Fences, FlowState, Revocations};
use crate::ownership::{Owners, Registration};
use crate::pending::Pending;
use crate::stats::{self, Counters};
use crate::tcp::TcpConnection;
use crate::udp::{UdpFlow, UdpOut};

use self::accept::Connecting;
use self::connections::Conn;
use self::fragments::Barrier;
use self::handle::Command;
use self::listeners::{Pool, prepare_tcp_listeners};

mod accept;
mod admission;
mod commands;
mod connections;
mod fragments;
mod handle;
mod ingress;
mod listeners;
mod netstack;
mod retire;
mod wire;

pub use self::handle::NetStackHandle;
pub use self::netstack::{NetStack, NetStackSink, NetStackSource};
pub(crate) use self::wire::{tcp_reset, tcp_segment};

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

/// The queue of a UDP flow or socket, with the flow it belongs to.
type Inbox<T> = (mpsc::Sender<T>, Arc<FlowState>);

/// A listener socket mid handshake.
struct Inbound {
    /// Keeps the tuple visible to `owns` while the handshake runs.
    registration: Registration,
    /// The egress position when the socket took the SYN.
    start: u64,
    /// The lifetime of a SYN accepted under `Admission::Decide`, its target bound to the
    /// socket.
    flow: Option<Arc<FlowState>>,
}

/// The single task that owns smoltcp and every queue behind the stack.
struct Driver {
    settings: Settings,
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    /// Listener sockets mid handshake.
    inbound: HashMap<SocketHandle, Inbound>,
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
        if let Some(table) = self.pending.as_mut() {
            table.stop();
        }
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

#[cfg(test)]
mod tests;
