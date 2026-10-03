//! The cloneable control handle of a running engine.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use nsplane_core::x25519::{PublicKey, StaticSecret};
use nsplane_core::{AllowedIp, ConfigChange, Event, PeerConfig, PeerStats};
use nsplane_packet::{PacketBuf, Path, PeerId, TransportId};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::engine::NewTransport;
use crate::fragment::FragmentStats;
use crate::transport::Transport;

/// The description of a peer for [`EngineHandle::add_or_update_peer`].
///
/// This is the core's [`PeerConfig`]: a public key, allowed IPs (added to the existing ones
/// unless `replace_allowed_ips`), an optional preshared key, keepalive and initial path. On
/// update, `None` fields leave the peer's settings unchanged.
pub type Peer = PeerConfig;

/// The error every [`EngineHandle`] call returns once the engine has stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineError;

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the engine has stopped")
    }
}

impl Error for EngineError {}

/// The error of the transport calls of [`EngineHandle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The engine has stopped.
    Stopped,
    /// A transport with this id is already installed.
    Duplicate(TransportId),
    /// No transport with this id is installed.
    Unknown(TransportId),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => EngineError.fmt(f),
            Self::Duplicate(id) => write!(f, "transport {} is already installed", id.get()),
            Self::Unknown(id) => write!(f, "transport {} is not installed", id.get()),
        }
    }
}

impl Error for TransportError {}

impl From<EngineError> for TransportError {
    fn from(_: EngineError) -> Self {
        Self::Stopped
    }
}

/// The capacity of one of the engine's bounded queues and the most it held.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueDepth {
    /// How many items the queue holds at most.
    pub capacity: usize,
    /// The most items the queue held at once since the engine started or the last
    /// [`EngineHandle::take_queue_stats`].
    pub high_water: usize,
}

impl QueueDepth {
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            high_water: 0,
        }
    }

    /// Raises the high-water mark to `occupancy`.
    pub(crate) fn record(&mut self, occupancy: usize) {
        self.high_water = self.high_water.max(occupancy);
    }

    /// Raises the high-water mark to the occupancy before an item was received, given the
    /// `left` items after it: the queue only grows between two receives, so that is its
    /// peak since the previous one. A sender may already have refilled the freed slot, so
    /// the sum is capped at the capacity.
    pub(crate) fn record_received(&mut self, left: usize) {
        self.record((left + 1).min(self.capacity));
    }
}

/// The depths of the engine's bounded queues; see [`EngineHandle::queue_stats`].
///
/// The packet queues hold `queue_capacity` items each (see
/// [`crate::EngineBuilder::queue_capacity`]). Without crypto workers (fewer than 2, see
/// [`crate::EngineBuilder::crypto_workers`]), `crypto` and `crypto_done` are
/// `QueueDepth { capacity: 0, high_water: 0 }`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueueStats {
    /// Handle calls waiting for the owner task.
    pub command: QueueDepth,
    /// Local packets read from the source, waiting for the owner task.
    pub local: QueueDepth,
    /// Datagrams received by every transport, waiting for the owner task.
    pub datagrams: QueueDepth,
    /// Decrypted packets waiting for the sink.
    pub deliver: QueueDepth,
    /// Transmitted buffers returned to the owner task for reuse.
    pub recycle: QueueDepth,
    /// Datagrams in a transport's transmit queue; the maximum over all transports.
    pub transmit: QueueDepth,
    /// Datagrams in a transport's backlog in the owner task, waiting for room in its
    /// transmit queue; the maximum over all transports. The capacity is the bound for
    /// datagrams caused by packets and timers; datagrams caused by handle calls may take a
    /// backlog past it.
    pub backlog: QueueDepth,
    /// Events not yet received by the slowest subscriber, at most the event capacity.
    /// Sampled when an event other than `Event::Dropped` is published and at every
    /// [`EngineHandle::queue_stats`], so a burst of drop events alone is not seen.
    pub events: QueueDepth,
    /// Jobs with the crypto workers: batched for a worker or handed over, and not
    /// completed by the owner task yet. The capacity is the bound of jobs in flight; at
    /// the bound, the owner task stops taking packets until the workers hand jobs back.
    pub crypto: QueueDepth,
    /// Batches of jobs the crypto workers ran, waiting for the owner task to complete
    /// them.
    pub crypto_done: QueueDepth,
}

/// The traffic counters of one installed transport since it was added; see
/// [`EngineHandle::transport_stats`].
///
/// Counted by the transport's own receive and transmit tasks: whole datagrams as the
/// transport reports and takes them (handshakes, cookie replies, keepalives, data), before
/// the core authenticates them on the receive side, so they include datagrams the core
/// drops afterwards. A [`EngineHandle::replace_transport`] keeps the counters of the id; a
/// [`EngineHandle::remove_transport`] drops them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransportStats {
    /// The transport.
    pub id: TransportId,
    /// Datagrams received.
    pub rx_datagrams: u64,
    /// Bytes of the datagrams received.
    pub rx_bytes: u64,
    /// Datagrams the transport was done with on the send side: handed off or failed.
    pub tx_datagrams: u64,
    /// Bytes of the datagrams in `tx_datagrams`.
    pub tx_bytes: u64,
    /// Datagrams of `tx_datagrams` whose send failed (also counted as
    /// [`crate::DROP_TRANSPORT_SEND_ERROR`] drops).
    pub tx_failed: u64,
}

/// A snapshot of the engine taken in one call; see [`EngineHandle::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EngineStatus {
    /// The engine's public key, once a private key is set.
    pub public_key: Option<PublicKey>,
    /// The current MTU.
    pub mtu: u16,
    /// Whether the engine is suspended.
    pub suspended: bool,
    /// Every peer, as [`EngineHandle::peers`].
    pub peers: Vec<PeerStats>,
    /// Every installed transport by id, as [`EngineHandle::transport_stats`].
    pub transports: Vec<TransportStats>,
    /// As [`EngineHandle::drop_counters`].
    pub drops: BTreeMap<&'static str, u64>,
    /// As [`EngineHandle::queue_stats`] (the marks keep running).
    pub queues: QueueStats,
    /// As [`EngineHandle::fragment_stats`].
    pub fragments: FragmentStats,
}

/// A request to the owner task; each carries the channel for its reply.
pub(crate) enum Command {
    Config(ConfigChange, oneshot::Sender<()>),
    PeerId(PublicKey, oneshot::Sender<Option<PeerId>>),
    PeerStats(PeerId, oneshot::Sender<Option<PeerStats>>),
    Peers(oneshot::Sender<Vec<PeerStats>>),
    PublicKey(oneshot::Sender<Option<PublicKey>>),
    PrivateKey(oneshot::Sender<Option<StaticSecret>>),
    InjectInbound(PeerId, PacketBuf, oneshot::Sender<()>),
    InjectOutbound(PacketBuf, oneshot::Sender<()>),
    ForceHandshake(PeerId, Option<Path>, oneshot::Sender<()>),
    AddTransport(NewTransport, oneshot::Sender<Result<(), TransportError>>),
    RemoveTransport(TransportId, oneshot::Sender<Result<(), TransportError>>),
    ReplaceTransport(NewTransport, oneshot::Sender<Result<(), TransportError>>),
    Suspend(oneshot::Sender<()>),
    Resume(oneshot::Sender<()>),
    Mtu(oneshot::Sender<u16>),
    Subscribe(oneshot::Sender<broadcast::Receiver<Event>>),
    DropCounters(oneshot::Sender<BTreeMap<&'static str, u64>>),
    /// With `true`, the high-water marks restart after the reply.
    QueueStats(bool, oneshot::Sender<QueueStats>),
    FragmentStats(oneshot::Sender<FragmentStats>),
    TransportStats(oneshot::Sender<Vec<TransportStats>>),
    Status(oneshot::Sender<EngineStatus>),
    Shutdown(oneshot::Sender<()>),
}

/// A cheap, cloneable handle to a running engine.
///
/// Every call is a message to the engine's owner task over a bounded channel and returns
/// once the owner task has processed it, so a configuration change is visible to every
/// later call. Calls fail with [`EngineError`] once the engine has stopped.
#[derive(Clone)]
pub struct EngineHandle {
    commands: mpsc::Sender<Command>,
}

impl fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineHandle")
            .field("closed", &self.commands.is_closed())
            .finish()
    }
}

impl EngineHandle {
    pub(crate) const fn new(commands: mpsc::Sender<Command>) -> Self {
        Self { commands }
    }

    /// Sends the command built by `command` and waits for its reply.
    async fn call<R>(
        &self,
        command: impl FnOnce(oneshot::Sender<R>) -> Command,
    ) -> Result<R, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(command(tx))
            .await
            .map_err(|_| EngineError)?;
        rx.await.map_err(|_| EngineError)
    }

    async fn config(&self, change: ConfigChange) -> Result<(), EngineError> {
        self.call(|tx| Command::Config(change, tx)).await
    }

    /// Replaces the private key; every peer is re-keyed and its sessions are cleared.
    pub async fn set_private_key(&self, key: StaticSecret) -> Result<(), EngineError> {
        self.config(ConfigChange::SetPrivateKey(key)).await
    }

    /// Adds a peer, or updates it in place if its public key is known.
    ///
    /// Peers cannot be added before a private key is set; the core then reports
    /// `Event::Dropped { reason: "no private key", .. }`.
    pub async fn add_or_update_peer(&self, peer: Peer) -> Result<(), EngineError> {
        self.config(ConfigChange::AddOrUpdatePeer(peer)).await
    }

    /// Removes a peer.
    pub async fn remove_peer(&self, key: PublicKey) -> Result<(), EngineError> {
        self.config(ConfigChange::RemovePeer(key)).await
    }

    /// Removes all peers.
    pub async fn remove_all_peers(&self) -> Result<(), EngineError> {
        self.config(ConfigChange::RemoveAllPeers).await
    }

    /// Replaces the allowed IPs of a peer.
    pub async fn set_allowed_ips(
        &self,
        peer: PublicKey,
        allowed_ips: Vec<AllowedIp>,
    ) -> Result<(), EngineError> {
        self.config(ConfigChange::SetAllowedIps { peer, allowed_ips })
            .await
    }

    /// Sets the preshared key of a peer; `None` removes it.
    pub async fn set_preshared_key(
        &self,
        peer: PublicKey,
        key: Option<[u8; 32]>,
    ) -> Result<(), EngineError> {
        self.config(ConfigChange::SetPresharedKey { peer, key })
            .await
    }

    /// Sets the persistent keepalive interval of a peer in seconds; `None` disables it.
    pub async fn set_keepalive(
        &self,
        peer: PublicKey,
        interval: Option<u16>,
    ) -> Result<(), EngineError> {
        self.config(ConfigChange::SetKeepalive { peer, interval })
            .await
    }

    /// Sets the path of a peer.
    pub async fn set_path(&self, peer: PublicKey, path: Path) -> Result<(), EngineError> {
        self.config(ConfigChange::SetPath { peer, path }).await
    }

    /// The id of the peer with this public key.
    pub async fn peer_id(&self, key: PublicKey) -> Result<Option<PeerId>, EngineError> {
        self.call(|tx| Command::PeerId(key, tx)).await
    }

    /// Configuration and counters of a peer.
    pub async fn peer_stats(&self, peer: PeerId) -> Result<Option<PeerStats>, EngineError> {
        self.call(|tx| Command::PeerStats(peer, tx)).await
    }

    /// Configuration and counters of every peer, in id order.
    pub async fn peers(&self) -> Result<Vec<PeerStats>, EngineError> {
        self.call(Command::Peers).await
    }

    /// The own public key, once a private key is set.
    pub async fn public_key(&self) -> Result<Option<PublicKey>, EngineError> {
        self.call(Command::PublicKey).await
    }

    /// The last private key given to the engine (by the builder or
    /// [`EngineHandle::set_private_key`]).
    pub async fn private_key(&self) -> Result<Option<StaticSecret>, EngineError> {
        self.call(Command::PrivateKey).await
    }

    /// Delivers `packet` to the local sink as if it came from `peer`, bypassing the inbound
    /// filters and the allowed-IP source check.
    pub async fn inject_inbound(&self, peer: PeerId, packet: PacketBuf) -> Result<(), EngineError> {
        self.call(|tx| Command::InjectInbound(peer, packet, tx))
            .await
    }

    /// Encrypts `packet` and sends it to the peer it is routed to, bypassing the outbound
    /// filters.
    pub async fn inject_outbound(&self, packet: PacketBuf) -> Result<(), EngineError> {
        self.call(|tx| Command::InjectOutbound(packet, tx)).await
    }

    /// Starts a handshake with `peer` now; a `path` becomes the peer's path first.
    pub async fn force_handshake(
        &self,
        peer: PeerId,
        path: Option<Path>,
    ) -> Result<(), EngineError> {
        self.call(|tx| Command::ForceHandshake(peer, path, tx))
            .await
    }

    /// Adds a transport under its [`Transport::id`] and spawns its tasks.
    ///
    /// Fails with [`TransportError::Duplicate`] when a transport with that id is installed;
    /// `transport` is then dropped.
    pub async fn add_transport<T: Transport>(&self, transport: T) -> Result<(), TransportError> {
        let transport = NewTransport::new(transport);
        self.call(|tx| Command::AddTransport(transport, tx)).await?
    }

    /// Removes the transport with id `id`.
    ///
    /// Its tasks are stopped and the transport is dropped before this returns, so its socket
    /// is closed. Every datagram still queued for it (being sent, in its transmit queue or
    /// waiting for room in it) is dropped and counted under [`crate::DROP_TRANSPORT_REMOVED`];
    /// every later datagram to a path on `id` is dropped and counted under
    /// [`crate::DROP_NO_TRANSPORT`]. Fails with [`TransportError::Unknown`] when no transport
    /// with that id is installed.
    pub async fn remove_transport(&self, id: TransportId) -> Result<(), TransportError> {
        self.call(|tx| Command::RemoveTransport(id, tx)).await?
    }

    /// Replaces the transport with the same [`Transport::id`] as `transport`.
    ///
    /// The old transport's tasks are stopped and the transport is dropped before this
    /// returns, so its socket is closed; then the new transport's tasks are spawned.
    /// Every datagram still queued for the old transport (being sent, in its transmit queue,
    /// then waiting for room in it) goes out on the new transport, in order, ahead of later
    /// ones; none is dropped. Fails with
    /// [`TransportError::Unknown`] when no transport with that id is installed; `transport`
    /// is then dropped.
    pub async fn replace_transport<T: Transport>(
        &self,
        transport: T,
    ) -> Result<(), TransportError> {
        let transport = NewTransport::new(transport);
        self.call(|tx| Command::ReplaceTransport(transport, tx))
            .await?
    }

    /// Suspends the engine, for example while the host sleeps or the network is down.
    ///
    /// Until [`EngineHandle::resume`], no source, sink or transport I/O runs (an operation
    /// already in progress may complete; datagrams that arrive stay in the socket's buffer)
    /// and no timer fires. Peers and sessions are kept, and handle calls still work: the
    /// datagrams they cause wait, within the engine's queue bounds, and go out after
    /// resuming. Transports added or replaced meanwhile start suspended. Publishes
    /// `Event::Suspended`; suspending a suspended engine does nothing.
    pub async fn suspend(&self) -> Result<(), EngineError> {
        self.call(Command::Suspend).await
    }

    /// Resumes a suspended engine.
    ///
    /// Publishes `Event::Resumed`, then runs the core's timers once with the current time,
    /// so sessions that expired while suspended expire and due handshakes and keepalives
    /// start; then normal operation continues. Resuming an engine that is not suspended
    /// does nothing.
    pub async fn resume(&self) -> Result<(), EngineError> {
        self.call(Command::Resume).await
    }

    /// The MTU of the packet source, as last observed by the engine.
    ///
    /// The engine watches [`crate::PacketSource::mtu`] and publishes `Event::MtuChanged`
    /// once for every change, after which this returns the new value. While suspended,
    /// changes are not observed: this keeps returning the value from before the suspension,
    /// and the latest value is published once after [`EngineHandle::resume`] if it
    /// differs. Once the source drops its watch's sender, the last value stays.
    pub async fn mtu(&self) -> Result<u16, EngineError> {
        self.call(Command::Mtu).await
    }

    /// Subscribes to the engine's events; see [`crate::events`] for the delivery semantics.
    ///
    /// The receiver reports `Closed` once the engine has stopped.
    pub async fn subscribe(&self) -> Result<broadcast::Receiver<Event>, EngineError> {
        self.call(Command::Subscribe).await
    }

    /// Counted drops since the engine started, by reason.
    ///
    /// Includes every `Event::Dropped` reason of the core and the engine's own reasons
    /// ([`crate::DROP_SINK_FULL`], [`crate::DROP_SINK_CLOSED`],
    /// [`crate::DROP_NO_TRANSPORT`], [`crate::DROP_TRANSPORT_CLOSED`],
    /// [`crate::DROP_TRANSPORT_REMOVED`], [`crate::DROP_TRANSMIT_FULL`],
    /// [`crate::DROP_TRANSPORT_SEND_ERROR`], [`crate::DROP_FRAGMENT_OVERSIZE`],
    /// [`crate::DROP_FRAGMENT_NO_ROUTE`], [`crate::DROP_FRAGMENT_RATE_LIMITED`]).
    pub async fn drop_counters(&self) -> Result<BTreeMap<&'static str, u64>, EngineError> {
        self.call(Command::DropCounters).await
    }

    /// The capacity and high-water mark of every bounded queue of the engine since it
    /// started or the last [`EngineHandle::take_queue_stats`].
    ///
    /// Like [`EngineHandle::drop_counters`], this is for sizing the queues: a high-water mark
    /// far below its capacity means the capacity can shrink (saving memory and latency),
    /// one at its capacity means the queue filled up, and the drop counters say whether
    /// that cost packets. The marks are kept by the owner task without locks or atomics:
    /// it samples a queue's occupancy whenever it sends to or receives from it, and every
    /// queue once more when serving this call. The calls to read the statistics do not
    /// count towards the command queue's mark.
    pub async fn queue_stats(&self) -> Result<QueueStats, EngineError> {
        self.call(|tx| Command::QueueStats(false, tx)).await
    }

    /// Like [`EngineHandle::queue_stats`], then restarts every high-water mark at 0, so
    /// measurements can be taken over windows.
    pub async fn take_queue_stats(&self) -> Result<QueueStats, EngineError> {
        self.call(|tx| Command::QueueStats(true, tx)).await
    }

    /// The counters of the fragmentation stage since the engine started; all zeros when no
    /// stage is installed (see [`crate::EngineBuilder::fragmenter`]).
    ///
    /// The packets the stage drops are counted in [`EngineHandle::drop_counters`] too.
    pub async fn fragment_stats(&self) -> Result<FragmentStats, EngineError> {
        self.call(Command::FragmentStats).await
    }

    /// The traffic counters of every installed transport, ordered by id.
    ///
    /// The transport tasks count as datagrams move, so a datagram another engine already
    /// received may show on its sender's transport a moment later.
    pub async fn transport_stats(&self) -> Result<Vec<TransportStats>, EngineError> {
        self.call(Command::TransportStats).await
    }

    /// The public key, MTU, suspension, peers, transport counters, drop counters, queue
    /// statistics and fragmentation counters, taken together in one call to the owner task,
    /// so they describe the same moment (up to the transport counters, see
    /// [`EngineHandle::transport_stats`]).
    ///
    /// Rates are left to the caller: sample this periodically and take differences.
    pub async fn status(&self) -> Result<EngineStatus, EngineError> {
        self.call(Command::Status).await
    }

    /// Stops the engine: every task is stopped and joined before this returns, and
    /// [`crate::Engine::wait`] resolves. Later calls return [`EngineError`].
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        self.call(Command::Shutdown).await
    }
}
