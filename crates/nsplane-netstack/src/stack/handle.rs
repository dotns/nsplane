//! The stack's handle and the commands it sends the driver.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use futures_core::Stream;
use tokio::sync::{mpsc, oneshot};

use crate::events::FlowEvent;
use crate::flow::{FlowState, RetirementReceipt, Revocations, Undelivered};
use crate::ownership::{Owners, Ownership, Registration};
use crate::pending::PendingFlow;
use crate::stats::{Counters, NetStackStats};
use crate::tcp::TcpConnection;
use crate::udp::{UdpFlow, UdpSocket};

use super::commands::unspecified;
use super::stack_gone;
#[cfg(doc)]
use super::{NetStack, NetStackSink, NetStackSource};
#[cfg(doc)]
use crate::config::{Admission, NetStackConfig};

/// Requests from a [`NetStackHandle`] to the driver.
#[derive(Debug)]
pub(super) enum Command {
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
    pub(super) commands: mpsc::Sender<Command>,
    pub(super) incoming_tcp: Arc<Mutex<Option<mpsc::Receiver<TcpConnection>>>>,
    pub(super) incoming_udp: Arc<Mutex<Option<mpsc::Receiver<UdpFlow>>>>,
    pub(super) incoming_pending: Arc<Mutex<Option<mpsc::Receiver<PendingFlow>>>>,
    pub(super) flow_events: Arc<Mutex<Option<mpsc::Receiver<FlowEvent>>>>,
    pub(super) stats: Arc<Counters>,
    pub(super) owners: Arc<Owners>,
    pub(super) revocations: Arc<Revocations>,
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
    /// [`NetStackConfig::accept_capacity`], then closed and counted. Taking a connection
    /// held under [`Admission::Decide`] fixes its delivery; one whose lifetime ended while
    /// it was queued (revoked, or the stack stopped) is skipped, never returned.
    pub fn incoming_tcp(&self) -> impl Stream<Item = TcpConnection> + Send + Unpin + use<> {
        Incoming(take(&self.incoming_tcp))
    }

    /// Inbound UDP flows, one per `(remote, local)` tuple, each with its first datagram.
    ///
    /// Datagrams to an address bound with [`bind_udp`](Self::bind_udp) or of a tuple
    /// connected with [`connect_udp`](Self::connect_udp) are not reported here. Only the first call (on any clone of the handle) gets the flows; every later
    /// call returns a stream that ends immediately. The stream ends when the stack stops.
    /// Flows that arrive while the stream is not consumed are queued up to
    /// [`NetStackConfig::accept_capacity`], then dropped and counted. Flows held under
    /// [`Admission::Decide`] are handed out like connections on
    /// [`incoming_tcp`](Self::incoming_tcp).
    pub fn incoming_udp(&self) -> impl Stream<Item = UdpFlow> + Send + Unpin + use<> {
        Incoming(take(&self.incoming_udp))
    }

    /// New TCP connections and UDP flows held for the application's decision, with
    /// [`Admission::Decide`] configured in [`NetStackConfig::admission`].
    ///
    /// Each [`PendingFlow`] is accepted, rejected or dropped (which rejects); an accepted
    /// connection or flow then arrives on [`incoming_tcp`](Self::incoming_tcp) or
    /// [`incoming_udp`](Self::incoming_udp), unless its lifetime ended before (see
    /// [`PendingFlow::control`] and [`FlowControl::delivery`](crate::FlowControl::delivery)). Items not taken are queued up to the
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

    /// Revokes every lifetime with the ingress label `label` and returns the receipt.
    ///
    /// The tag of a packet sent into [`NetStackSink`] is its ingress label, and a
    /// connection or flow takes the label of its first input (see
    /// [`TcpConnection::ingress_label`] and [`UdpFlow::ingress_label`]). The call never
    /// waits; the driver turn that takes it:
    ///
    /// - retires every lifetime with the label at its stage, as [`FlowControl::revoke`]
    ///   does, and revokes its control: held under [`Admission::Decide`], a listener socket
    ///   mid handshake, a connection waiting for or queued in `incoming_tcp`, a flow queued
    ///   in `incoming_udp` (neither is handed out), and handles already handed out (reads
    ///   fail with [`io::ErrorKind::ConnectionAborted`], [`UdpFlow::recv`] returns `None`);
    ///   each lifetime's own receipts report its retirement;
    /// - drops the label's input still in the ingress queue, sent before the call, as the
    ///   driver takes it (counted in [`retired_drops`](Self::retired_drops));
    /// - discards the incomplete datagrams the reassembler holds a fragment of the label of;
    /// - records the label's tombstone: input with the label that reaches the stack later is
    ///   dropped and counted in [`label_revoked`](NetStackStats::label_revoked) and opens no
    ///   new lifetime, for at least the next
    ///   [`max_revoked_labels`](NetStackConfig::max_revoked_labels) revocations.
    ///
    /// The receipt reports [`Retired`](crate::RetirementOutcome::Retired) when nothing of
    /// the label is delivered from then on and no output of its lifetimes leaves the stack;
    /// [`Failed`](crate::RetirementOutcome::Failed) when a bounded table was full (at most
    /// 1024 labels with queued input at once, and the egress fences of
    /// [`RetirementReceipt`]): every lifetime found is still retired, but input or output
    /// queued before the call may still pass. The call is idempotent: call it again, and a
    /// later call scans again, records what did not fit and reports `Retired` once it does;
    /// keep the lifetime's owner withdrawn until then.
    /// [`Unknown`](crate::RetirementOutcome::Unknown) means the stack stopped.
    ///
    /// Labels of revoked lifetimes must not be reused, and input of the label queued on the
    /// caller's side should be cancelled before the call: the tombstone is a safety net.
    /// After `Retired`, the same tuple opens a fresh lifetime with its new label. Connections
    /// and sockets the application opened have no label and are never revoked here. The
    /// proof boundary of [`FlowControl::revoke`] applies.
    ///
    /// [`FlowControl::revoke`]: crate::FlowControl::revoke
    pub fn revoke_label(&self, label: NonZeroU64) -> RetirementReceipt {
        let state = FlowState::receipt(&self.revocations);
        self.revocations.revoke_label(label, Arc::clone(&state));
        RetirementReceipt::new(state)
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

/// An item an [`Incoming`] stream hands out.
trait HandOut {
    /// Fixes the delivery of the item's lifetime; whether the stream may return it.
    fn hand_out(&self) -> bool {
        true
    }
}

/// Fixes the delivery of `flow` unless it ended or was revoked; whether its handle may be
/// returned. A revoked lifetime is skipped also when it was delivered from the start
/// (`Admission::Immediate`); its delivery ends revoked before the skipped handle's drop
/// could end it otherwise.
fn hand_out(flow: &FlowState) -> bool {
    if flow.is_revoked() {
        flow.undeliver(Undelivered::Revoked);
        return false;
    }
    flow.deliver()
}

impl HandOut for TcpConnection {
    fn hand_out(&self) -> bool {
        hand_out(self.flow())
    }
}

impl HandOut for UdpFlow {
    fn hand_out(&self) -> bool {
        hand_out(self.flow())
    }
}

impl HandOut for PendingFlow {}

impl HandOut for FlowEvent {}

impl<T: HandOut> Stream for Incoming<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let Some(rx) = self.0.as_mut() else {
            return Poll::Ready(None);
        };
        loop {
            match rx.poll_recv(cx) {
                // Dropped: its lifetime ended while it was queued.
                Poll::Ready(Some(item)) if !item.hand_out() => {}
                ready => return ready,
            }
        }
    }
}
