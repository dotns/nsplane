//! The cloneable control handle of a running engine.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use nsplane_core::x25519::{PublicKey, StaticSecret};
use nsplane_core::{
    AllowedIp, ConfigChange, Event, InboundDestinations, LocalIdentityId, LocalIdentityInfo,
    PeerConfig, PeerStats,
};
use nsplane_packet::{PacketBuf, Path, PeerId, TransportId};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::engine::{NewTransport, SourceTaken};
use crate::fragment::FragmentStats;
use crate::transport::{PathMtuReport, Transport};

/// The description of a peer for [`EngineHandle::add_or_update_peer`].
///
/// This is the core's [`PeerConfig`]: a public key, allowed IPs (added to the existing ones
/// unless `replace_allowed_ips`), an optional preshared key, keepalive and initial path. On
/// update, `None` fields leave the peer's settings unchanged.
///
/// With [`PeerConfig::local_identity`] set, the peer belongs to that local identity (see
/// [`EngineHandle::add_local_identity`]); the identity is fixed at creation, and the pair
/// (identity, public key) names the peer.
pub type Peer = PeerConfig;

/// A local identity of the engine; see [`EngineHandle::local_identities`].
///
/// This is the core's [`LocalIdentityInfo`]: its id, its public key (`None` for the default
/// identity before a private key is set), its number of peers, and the transports it answers
/// handshakes on (`None` for any transport, see [`EngineHandle::add_local_identity_on`]).
pub type LocalIdentity = LocalIdentityInfo;

/// The error every [`EngineHandle`] call returns once the engine has stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineError;

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the engine has stopped")
    }
}

impl Error for EngineError {}

/// A plaintext packet for [`nsplane_core::Core::receive_plaintext`]: the peer it is
/// attributed to, the path it arrived on and the packet.
pub(crate) type Plaintext = (PeerId, Path, PacketBuf);

/// A bounded entry for plaintext packets attributed to a peer, checked like decrypted data;
/// from [`crate::EngineBuilder::plaintext_ingress`]. Cheap to clone; every clone feeds the
/// same queue.
///
/// The engine's owner task takes the packets in order, at most a batch at a time, while the
/// deliver queue has room (like received datagrams), and runs each through
/// [`Core::receive_plaintext`](nsplane_core::Core::receive_plaintext): the sending peer's
/// allowed-IP source check, its inbound destinations, the inbound filters in install order
/// ([`crate::PacketFilter::inbound_from`] with the given path) and delivery to the sink.
/// Drops count under the same reasons as for decrypted data, a peer that does not exist or
/// was removed under [`crate::reasons::UNKNOWN_PLAINTEXT_PEER`]. Nothing is authenticated:
/// no handshake accounting, no path policy, no roaming and no `Event::Authenticated`, and a
/// filter that answers on the arrival path answers on the given one. Delivered bytes count in
/// the peer's `data_rx`, not in `rx`.
///
/// Unlike [`EngineHandle::inject_inbound`], which bypasses the checks and the filters, this
/// entry runs them all. While the engine is suspended the queue is not read.
#[derive(Debug, Clone)]
pub struct PlaintextIngress {
    queue: mpsc::Sender<Plaintext>,
}

impl PlaintextIngress {
    pub(crate) const fn new(queue: mpsc::Sender<Plaintext>) -> Self {
        Self { queue }
    }

    /// Queues `packet` as received from `peer` on `from`; waits while the queue is full.
    ///
    /// # Errors
    ///
    /// [`EngineError`] once the engine has stopped; the packet is dropped.
    pub async fn send(
        &self,
        peer: PeerId,
        from: Path,
        packet: PacketBuf,
    ) -> Result<(), EngineError> {
        self.queue
            .send((peer, from, packet))
            .await
            .map_err(|_| EngineError)
    }

    /// Like [`PlaintextIngress::send`], but refuses at once with the packet when the queue
    /// is full.
    ///
    /// # Errors
    ///
    /// [`PlaintextRefused::Full`] when the queue is full, [`PlaintextRefused::Stopped`] once
    /// the engine has stopped; both carry the packet back.
    pub fn try_send(
        &self,
        peer: PeerId,
        from: Path,
        packet: PacketBuf,
    ) -> Result<(), PlaintextRefused> {
        self.queue
            .try_send((peer, from, packet))
            .map_err(|e| match e {
                TrySendError::Full((_, _, packet)) => PlaintextRefused::Full(packet),
                TrySendError::Closed((_, _, packet)) => PlaintextRefused::Stopped(packet),
            })
    }
}

/// Why [`PlaintextIngress::try_send`] refused a packet, with the packet.
#[derive(Debug)]
pub enum PlaintextRefused {
    /// The queue is full.
    Full(PacketBuf),
    /// The engine has stopped.
    Stopped(PacketBuf),
}

impl PlaintextRefused {
    /// The refused packet.
    pub fn into_packet(self) -> PacketBuf {
        match self {
            Self::Full(packet) | Self::Stopped(packet) => packet,
        }
    }
}

impl fmt::Display for PlaintextRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(_) => f.write_str("the plaintext ingress queue is full"),
            Self::Stopped(_) => EngineError.fmt(f),
        }
    }
}

impl Error for PlaintextRefused {}

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
/// `QueueDepth { capacity: 0, high_water: 0 }`, and the datagrams and packets the owner
/// task hands to an idle transport or sink itself never enter the `transmit`, `deliver`
/// or `recycle` queue, so on a path that keeps up those marks stay low or at 0.
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
    /// Transmitted buffers returned to the owner task for reuse, which happens only when the
    /// source takes none ([`crate::PacketSource::recycle`]); the queue returning them to
    /// the source is not counted.
    pub recycle: QueueDepth,
    /// Datagrams in a transport's transmit queue, counting the batch its transmit task is
    /// sending; the maximum over all transports.
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
/// Counted once per batch by whoever moved it: the transport's receive and transmit tasks,
/// or the owner task when it sends on the transport itself. Whole datagrams as the
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

/// The inner MTU of the peers whose path limits it below the source MTU; see
/// [`EngineHandle::peer_mtus`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerMtus {
    /// The lowest inner MTU over the source MTU and every peer in `peers`: what a local side
    /// with a single MTU for all peers would use.
    pub min: u16,
    /// Every peer whose inner MTU is below the source MTU, with that MTU; empty when no
    /// ceiling applies to any peer.
    pub peers: BTreeMap<PeerId, u16>,
}

impl PeerMtus {
    /// No peer below the source MTU `mtu`.
    pub(crate) const fn unconstrained(mtu: u16) -> Self {
        Self {
            min: mtu,
            peers: BTreeMap::new(),
        }
    }
}

/// Counters of the path MTU reports since the engine started; see
/// [`EngineHandle::path_mtu_stats`]. All zeros while no ceiling or report was ever given.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathMtuStats {
    /// Reports received, from the transports and [`EngineHandle::report_path_mtu`].
    pub reports: u64,
    /// Reports accepted: they lowered a path's MTU or confirmed it (which postpones its
    /// expiry).
    pub applied: u64,
    /// Reports ignored: for an unknown path, quoting another message or session, or not
    /// lowering anything.
    pub ignored: u64,
    /// Learned path MTUs that expired.
    pub expired: u64,
    /// Paths with a learned MTU now.
    pub paths: usize,
}

/// A snapshot of the engine taken in one call; see [`EngineHandle::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EngineStatus {
    /// The public key of the default local identity, once a private key is set.
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
    /// As the current value of [`EngineHandle::peer_mtus`].
    pub peer_mtus: PeerMtus,
    /// As [`EngineHandle::path_mtu_stats`].
    pub path_mtu: PathMtuStats,
    /// Every local identity, as [`EngineHandle::local_identities`].
    pub local_identities: Vec<LocalIdentity>,
}

/// A request to the owner task; each carries the channel for its reply.
/// A packet or handshake the engine is told to send or deliver, see [`Command::Inject`].
#[derive(Debug)]
pub(crate) enum Injection {
    Inbound(PeerId, PacketBuf),
    Outbound(PacketBuf),
    OutboundOn(PeerId, Path, PacketBuf),
    Handshake(PeerId, Option<Path>),
    HandshakeOn(PeerId, Path),
}

pub(crate) enum Command {
    Config(ConfigChange, oneshot::Sender<()>),
    PeerId(PublicKey, oneshot::Sender<Option<PeerId>>),
    PeerStats(PeerId, oneshot::Sender<Option<PeerStats>>),
    PeerHasSession(PeerId, oneshot::Sender<Option<bool>>),
    Peers(oneshot::Sender<Vec<PeerStats>>),
    PublicKey(oneshot::Sender<Option<PublicKey>>),
    PrivateKey(oneshot::Sender<Option<StaticSecret>>),
    Inject(Injection, oneshot::Sender<()>),
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
    SetTransportMaxDatagram(TransportId, Option<u16>, oneshot::Sender<()>),
    ReportPathMtu(PathMtuReport, oneshot::Sender<bool>),
    PeerMtu(PeerId, oneshot::Sender<Option<u16>>),
    PeerMtus(oneshot::Sender<watch::Receiver<PeerMtus>>),
    PathMtuStats(oneshot::Sender<PathMtuStats>),
    Shutdown(oneshot::Sender<()>),
    UnansweredHandshakes(PeerId, oneshot::Sender<Option<u64>>),
    TotalUnansweredHandshakes(oneshot::Sender<u64>),
    AddLocalIdentity(
        StaticSecret,
        Option<Vec<TransportId>>,
        oneshot::Sender<Option<LocalIdentityId>>,
    ),
    RemoveLocalIdentity(LocalIdentityId, oneshot::Sender<bool>),
    SetLocalSources(LocalIdentityId, Vec<AllowedIp>, oneshot::Sender<bool>),
    LocalIdentities(oneshot::Sender<Vec<LocalIdentity>>),
    PeerIdIn(LocalIdentityId, PublicKey, oneshot::Sender<Option<PeerId>>),
    /// Replies once the owner has taken this many local packets through routing and the
    /// outbound filters.
    LocalBarrier(u64, oneshot::Sender<()>),
}

/// A cheap, cloneable handle to a running engine.
///
/// Every call is a message to the engine's owner task over a bounded channel and returns
/// once the owner task has processed it, so a configuration change is visible to every
/// later call. Calls fail with [`EngineError`] once the engine has stopped.
#[derive(Clone)]
pub struct EngineHandle {
    commands: mpsc::Sender<Command>,
    /// Local packets the source task took from the source so far.
    source_taken: Arc<SourceTaken>,
}

impl fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineHandle")
            .field("closed", &self.commands.is_closed())
            .finish_non_exhaustive()
    }
}

impl EngineHandle {
    pub(crate) const fn new(
        commands: mpsc::Sender<Command>,
        source_taken: Arc<SourceTaken>,
    ) -> Self {
        Self {
            commands,
            source_taken,
        }
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

    /// Replaces the private key of the default local identity; every peer of that identity
    /// is re-keyed and its sessions are cleared. A key another local identity holds is
    /// ignored.
    pub async fn set_private_key(&self, key: StaticSecret) -> Result<(), EngineError> {
        self.config(ConfigChange::SetPrivateKey(key)).await
    }

    /// Adds a peer, or updates it in place if its public key is known in its local identity.
    ///
    /// A peer needs a private key on its selected local identity; otherwise the core reports
    /// `Event::Dropped { reason: "no private key", .. }`. A keyed non-default identity
    /// accepts peers even when the default identity has no key.
    ///
    /// The methods below that name a peer by public key address the peer of the default
    /// local identity. A peer of another identity (`local_identity` set) is removed and given
    /// inbound destinations with the `_in` methods ([`EngineHandle::remove_peer_in`],
    /// [`EngineHandle::set_inbound_destinations_in`],
    /// [`EngineHandle::set_inbound_destination_source_in`]); every other setting of it goes
    /// through this method with `local_identity` set: allowed IPs (with
    /// `replace_allowed_ips` to replace them), the preshared key (all zeros removes it), the
    /// keepalive (0 disables it) and the path.
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

    /// Sets the inbound destinations of a peer: its decrypted packets to any other destination
    /// are dropped. `None` removes them, so the peer is unchecked again. Ignored for an
    /// unknown peer.
    pub async fn set_inbound_destinations(
        &self,
        peer: PublicKey,
        destinations: Option<Vec<AllowedIp>>,
    ) -> Result<(), EngineError> {
        self.config(ConfigChange::SetInboundDestinations { peer, destinations })
            .await
    }

    /// Sets the caller-updated source of a peer's inbound destinations, consulted once per
    /// decrypted packet of the peer, so a change to it applies to the next packet without a
    /// call here. It replaces the destinations of [`EngineHandle::set_inbound_destinations`]
    /// (and later ones replace it); `None` removes it, so the peer is unchecked again. Ignored
    /// for an unknown peer.
    pub async fn set_inbound_destination_source(
        &self,
        peer: PublicKey,
        source: Option<Arc<dyn InboundDestinations>>,
    ) -> Result<(), EngineError> {
        self.config(ConfigChange::SetInboundDestinationSource { peer, source })
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

    /// Removes the peer of `identity` with this public key, as [`EngineHandle::remove_peer`]
    /// does for the default identity. Ignored for an unknown identity or peer.
    pub async fn remove_peer_in(
        &self,
        identity: LocalIdentityId,
        key: PublicKey,
    ) -> Result<(), EngineError> {
        self.config_in(identity, ConfigChange::RemovePeer(key))
            .await
    }

    /// Sets the inbound destinations of the peer of `identity` with public key `peer`, as
    /// [`EngineHandle::set_inbound_destinations`] does for the default identity.
    pub async fn set_inbound_destinations_in(
        &self,
        identity: LocalIdentityId,
        peer: PublicKey,
        destinations: Option<Vec<AllowedIp>>,
    ) -> Result<(), EngineError> {
        self.config_in(
            identity,
            ConfigChange::SetInboundDestinations { peer, destinations },
        )
        .await
    }

    /// Sets the inbound destination source of the peer of `identity` with public key `peer`,
    /// as [`EngineHandle::set_inbound_destination_source`] does for the default identity.
    pub async fn set_inbound_destination_source_in(
        &self,
        identity: LocalIdentityId,
        peer: PublicKey,
        source: Option<Arc<dyn InboundDestinations>>,
    ) -> Result<(), EngineError> {
        self.config_in(
            identity,
            ConfigChange::SetInboundDestinationSource { peer, source },
        )
        .await
    }

    async fn config_in(
        &self,
        identity: LocalIdentityId,
        change: ConfigChange,
    ) -> Result<(), EngineError> {
        self.config(ConfigChange::InLocalIdentity {
            identity,
            change: Box::new(change),
        })
        .await
    }

    /// Adds a local identity with its own static key, which answers handshakes on every
    /// transport; returns its id, or `None` if an identity of the engine (the default one
    /// included) already holds the key or identity ids are exhausted.
    ///
    /// Peers are bound to an identity with [`PeerConfig::local_identity`]; the same remote
    /// key may be a peer of several identities. Ids are never reused.
    pub async fn add_local_identity(
        &self,
        key: StaticSecret,
    ) -> Result<Option<LocalIdentityId>, EngineError> {
        self.call(|tx| Command::AddLocalIdentity(key, None, tx))
            .await
    }

    /// Like [`EngineHandle::add_local_identity`], but the identity answers handshakes only on
    /// `transports` (on none for an empty set).
    ///
    /// On any other transport the identity behaves as if its key did not exist: an
    /// initiation for it gets no response and no cookie reply. This keeps a remote party
    /// from probing, through one transport, whether the engine also holds an identity used
    /// on another. Its peers' handshake responses and cookie replies arriving on another
    /// transport are dropped as for an unknown peer, and their data as for an unknown
    /// session. Outbound traffic is not restricted: a peer's path may name any transport.
    pub async fn add_local_identity_on(
        &self,
        key: StaticSecret,
        transports: impl IntoIterator<Item = TransportId>,
    ) -> Result<Option<LocalIdentityId>, EngineError> {
        let transports = transports.into_iter().collect();
        self.call(|tx| Command::AddLocalIdentity(key, Some(transports), tx))
            .await
    }

    /// Removes a local identity and each of its peers as [`EngineHandle::remove_peer`] does;
    /// `false` for [`LocalIdentityId::DEFAULT`] or an unknown identity.
    pub async fn remove_local_identity(&self, id: LocalIdentityId) -> Result<bool, EngineError> {
        self.call(|tx| Command::RemoveLocalIdentity(id, tx)).await
    }

    /// Replaces the source set of the local identity `identity` with `sources` (an empty set
    /// clears it); `false`, changing nothing, for an unknown identity or when another
    /// identity's set holds one of the networks (compared after truncation to the prefix
    /// length).
    ///
    /// A local packet whose source address lies in a set is routed among the allowed IPs of
    /// the peers of that set's identity only, the most specific network of all sets
    /// winning; without a route there it is dropped. A packet whose source lies in no set is
    /// routed as without sets: by the longest allowed-IP match among the peers of every
    /// identity, a range going to the peer that claimed it last. Path-MTU state and ICMP
    /// errors about a too-big packet follow the same choice. The default identity may have a
    /// set too.
    ///
    /// Removing the identity drops its set; [`EngineHandle::remove_all_peers`] keeps the
    /// sets. The sets are reported in [`LocalIdentityInfo::sources`].
    pub async fn set_local_sources(
        &self,
        identity: LocalIdentityId,
        sources: impl IntoIterator<Item = AllowedIp>,
    ) -> Result<bool, EngineError> {
        let sources = sources.into_iter().collect();
        self.call(|tx| Command::SetLocalSources(identity, sources, tx))
            .await
    }

    /// Every local identity, ascending by id; the default identity is first.
    pub async fn local_identities(&self) -> Result<Vec<LocalIdentity>, EngineError> {
        self.call(Command::LocalIdentities).await
    }

    /// The id of the peer of `identity` with this public key.
    pub async fn peer_id_in(
        &self,
        identity: LocalIdentityId,
        key: PublicKey,
    ) -> Result<Option<PeerId>, EngineError> {
        self.call(|tx| Command::PeerIdIn(identity, key, tx)).await
    }

    /// The id of the peer of the default local identity with this public key.
    pub async fn peer_id(&self, key: PublicKey) -> Result<Option<PeerId>, EngineError> {
        self.call(|tx| Command::PeerId(key, tx)).await
    }

    /// Whether the peer currently has a sending session with an unexhausted key.
    /// Returns `None` for an unknown peer. This query settles preceding crypto
    /// work and reads the actual tunnel state; it does not start a handshake.
    /// It does not establish transport reachability.
    pub async fn peer_has_session(&self, peer: PeerId) -> Result<Option<bool>, EngineError> {
        self.call(|tx| Command::PeerHasSession(peer, tx)).await
    }

    /// Configuration and counters of a peer.
    pub async fn peer_stats(&self, peer: PeerId) -> Result<Option<PeerStats>, EngineError> {
        self.call(|tx| Command::PeerStats(peer, tx)).await
    }

    /// Configuration and counters of every peer, in id order.
    pub async fn peers(&self) -> Result<Vec<PeerStats>, EngineError> {
        self.call(Command::Peers).await
    }

    /// The public key of the default local identity, once a private key is set.
    pub async fn public_key(&self) -> Result<Option<PublicKey>, EngineError> {
        self.call(Command::PublicKey).await
    }

    /// The last private key of the default local identity given to the engine (by the
    /// builder or [`EngineHandle::set_private_key`]).
    pub async fn private_key(&self) -> Result<Option<StaticSecret>, EngineError> {
        self.call(Command::PrivateKey).await
    }

    /// Delivers `packet` to the local sink as if it came from `peer`, bypassing the inbound
    /// filters and the allowed-IP source check.
    ///
    /// Part of the contract: no inbound filter sees the packet, so a stateful filter records
    /// nothing about it and a translating filter does not translate it.
    pub async fn inject_inbound(&self, peer: PeerId, packet: PacketBuf) -> Result<(), EngineError> {
        self.call(|tx| Command::Inject(Injection::Inbound(peer, packet), tx))
            .await
    }

    /// Encrypts `packet` and sends it to the peer it is routed to, bypassing the outbound
    /// filters.
    ///
    /// Part of the contract, which will not change silently: no outbound filter sees the
    /// packet. A stateful filter (e.g. `nsplane-acl`'s `AclFilter`) records no reply state for
    /// it, so the peer's replies are judged by the inbound rules alone, and a translating
    /// filter does not translate it.
    pub async fn inject_outbound(&self, packet: PacketBuf) -> Result<(), EngineError> {
        self.call(|tx| Command::Inject(Injection::Outbound(packet), tx))
            .await
    }

    /// Encrypts `packet` for `peer` in its current session and sends it on `path`, bypassing
    /// routing, the outbound filters and the path policy; the peer's path stays as it is.
    /// For probes on a candidate path while the peer's traffic stays on its path. Without a
    /// current session the packet is dropped as `reasons::NO_SESSION` (no handshake is
    /// started); unknown peers are ignored. See `Core::inject_outbound_on`.
    ///
    /// Like [`EngineHandle::inject_outbound`], part of the contract: no outbound filter sees
    /// the packet, so a stateful filter records no reply state for it (its replies are judged
    /// by the inbound rules alone) and a translating filter does not translate it.
    pub async fn inject_outbound_on(
        &self,
        peer: PeerId,
        path: Path,
        packet: PacketBuf,
    ) -> Result<(), EngineError> {
        self.call(|tx| Command::Inject(Injection::OutboundOn(peer, path, packet), tx))
            .await
    }

    /// Starts a handshake with `peer` now; a `path` becomes the peer's path first.
    pub async fn force_handshake(
        &self,
        peer: PeerId,
        path: Option<Path>,
    ) -> Result<(), EngineError> {
        self.call(|tx| Command::Inject(Injection::Handshake(peer, path), tx))
            .await
    }

    /// Sends a handshake initiation to `peer` on `path` now, without changing the peer's
    /// path (see `Core::force_handshake_on`); unknown peers are ignored.
    pub async fn force_handshake_on(&self, peer: PeerId, path: Path) -> Result<(), EngineError> {
        self.call(|tx| Command::Inject(Injection::HandshakeOn(peer, path), tx))
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

    /// Sets the largest WireGuard datagram (the bytes handed to [`Transport::send`]) the
    /// transport `id` carries, or clears it with `None`; the inner MTU of every peer whose
    /// data leaves on that transport drops to at most `max - 32` (never below 1280, never
    /// above the source MTU). Takes effect at once; the transport need not be installed.
    ///
    /// The per-peer MTU reaches the local side only through the fragmentation stage
    /// ([`crate::EngineBuilder::fragmenter`]) or through ICMP the caller generates from
    /// [`EngineHandle::peer_mtus`]. See also [`crate::EngineBuilder::transport_max_datagram`].
    pub async fn set_transport_max_datagram(
        &self,
        id: TransportId,
        max: Option<u16>,
    ) -> Result<(), EngineError> {
        self.call(|tx| Command::SetTransportMaxDatagram(id, max, tx))
            .await
    }

    /// Reports that `path` carries IP packets of at most `mtu` bytes (IP and UDP headers
    /// included), e.g. from a Packet Too Big the caller received about the engine's
    /// datagrams; returns whether the report was accepted. On Linux a transport can feed
    /// such reports itself ([`Transport::path_mtu_reports`]); on macOS and Windows no Packet
    /// Too Big reaches the transport, and this is the way to report one.
    ///
    /// Every report, from here or a transport, is checked the same way:
    ///
    /// - `path` (transport and address; its ECN mark is ignored) must be the path some
    ///   peer's data leaves on or its stored path; reports for other paths are ignored.
    /// - A report that quotes the datagram ([`PathMtuReport::with_quote`]) must quote a
    ///   transport data message (type 4) and, with 8 bytes, carry the receiver index of that
    ///   peer's current session.
    /// - `mtu` 0 stands for the next RFC 1191 plateau (1492, 1280, 1006, 576) below the
    ///   path's current outer MTU. IPv6 paths take at least 1280, IPv4 (and IPv4-mapped)
    ///   paths at least 576.
    /// - The learned MTU only goes down: a report at or above what the path allows already
    ///   (its learned MTU, or the transport's ceiling plus the IP and UDP headers) is
    ///   ignored, except that one equal to the learned MTU confirms it.
    ///
    /// A learned MTU expires a while after the report that set or last confirmed it (10
    /// minutes by default, [`crate::EngineBuilder::path_mtu_expiry`]), which restores the
    /// transport's ceiling. Every peer whose data leaves on the path gets the inner MTU
    /// `min(source MTU, min(transport ceiling, mtu - IP header - 8) - 32)`, at least 1280:
    /// with an IPv6 path MTU of 1500, 1420. The engine does not probe for a larger MTU.
    ///
    /// Installing a ceiling or lowering a learned path MTU recomputes peers' padding
    /// limits at their inner MTUs. An ignored first report creates the table but does not
    /// install padding limits by itself. A packet at its inner MTU fits the path only
    /// when the outer ceiling can carry the 1280-byte inner floor plus encapsulation headers.
    pub async fn report_path_mtu(&self, path: Path, mtu: u16) -> Result<bool, EngineError> {
        let report = PathMtuReport::new(path, mtu);
        self.call(|tx| Command::ReportPathMtu(report, tx)).await
    }

    /// The inner MTU of `peer`: the source MTU, lowered by the ceilings of the path its data
    /// leaves on (see [`EngineHandle::report_path_mtu`]); `None` for an unknown peer.
    pub async fn peer_mtu(&self, peer: PeerId) -> Result<Option<u16>, EngineError> {
        self.call(|tx| Command::PeerMtu(peer, tx)).await
    }

    /// A watch of the peers whose inner MTU is below the source MTU.
    ///
    /// Updated (only when the value changes) as path MTUs are learned or expire, transport
    /// ceilings change, the source MTU changes, peers change or move to another path. A
    /// path policy may move a peer's data to another path without telling the engine; the
    /// fragmentation stage notices that on the peer's next large packet. Without any
    /// ceiling, `peers` is empty and `min` is the source MTU.
    ///
    /// [`EngineHandle::mtu`] and `Event::MtuChanged` keep reporting the source MTU. The
    /// per-peer MTU reaches the local kernel or stack only through the fragmentation stage
    /// ([`crate::EngineBuilder::fragmenter`]), which answers packets above it with Packet
    /// Too Big or Fragmentation Needed and fragments IPv4 packets to fit it, or through ICMP
    /// the caller generates; without a fragmenter it is visible only here.
    pub async fn peer_mtus(&self) -> Result<watch::Receiver<PeerMtus>, EngineError> {
        self.call(Command::PeerMtus).await
    }

    /// The counters of the path MTU reports since the engine started.
    pub async fn path_mtu_stats(&self) -> Result<PathMtuStats, EngineError> {
        self.call(Command::PathMtuStats).await
    }

    /// The public key, MTU, suspension, peers, transport counters, drop counters, queue
    /// statistics, fragmentation counters, peer MTUs, path MTU counters and local
    /// identities, taken together in one call to the owner task,
    /// so they describe the same moment (up to the transport counters, see
    /// [`EngineHandle::transport_stats`]).
    ///
    /// Rates are left to the caller: sample this periodically and take differences.
    pub async fn status(&self) -> Result<EngineStatus, EngineError> {
        self.call(Command::Status).await
    }

    /// Handshake initiations sent to a peer that got no response; `None` for an unknown peer.
    ///
    /// An initiation counts once when another one is sent to the peer while it is still
    /// unanswered (a retry after `REKEY_TIMEOUT`, an [`EngineHandle::force_handshake`], ...)
    /// or when the peer's handshake attempt gives up (`Event::SessionExpired`). A completed
    /// handshake answers it. The count is monotonic; a peer that only ever responds to
    /// handshakes stays at 0.
    pub async fn unanswered_handshakes(&self, peer: PeerId) -> Result<Option<u64>, EngineError> {
        self.call(|tx| Command::UnansweredHandshakes(peer, tx))
            .await
    }

    /// The sum of [`EngineHandle::unanswered_handshakes`] over every peer, including the peers
    /// removed since the engine started: monotonic.
    ///
    /// Cheap to poll: a consumer that keeps a registry of its peers (e.g. a control plane) can watch this
    /// total and act on an increase, such as a registry resync when a peer stops answering,
    /// then find the peer with [`EngineHandle::unanswered_handshakes`].
    pub async fn total_unanswered_handshakes(&self) -> Result<u64, EngineError> {
        self.call(Command::TotalUnansweredHandshakes).await
    }

    /// Waits until every packet the engine took from its [`crate::PacketSource`] before this
    /// call has been routed and passed or been dropped by the outbound filters (or dropped
    /// for no route, by the fragmentation stage or by the tunnel's queue).
    ///
    /// A packet counts as taken once [`crate::PacketSource::recv_batch`] took it from the
    /// source, also while that read is still in progress: the engine counts what a read
    /// takes in the poll that ends it, and the call waits for a read in progress to end
    /// before it reads the count. This includes packets in the engine's local queue and those
    /// the source task holds while that queue is full. With the fragmentation stage the barrier waits for every fragment
    /// of a taken packet, and with crypto workers only for routing and the filters, which run
    /// on the owner task before a packet is handed to a worker. Packets the source has not
    /// handed out (a kernel TUN queue, the caller's own queue) are not covered: a caller that
    /// changes the ownership of an address stops its source from handing out packets admitted
    /// before the change, then takes the barrier. The call returns at once when nothing taken
    /// is waiting, and while the engine is suspended it completes only after
    /// [`EngineHandle::resume`].
    ///
    /// # Errors
    ///
    /// [`EngineError`] once the engine has stopped before the barrier passed; a stopped
    /// engine never reports a barrier it did not pass.
    pub async fn local_barrier(&self) -> Result<(), EngineError> {
        let position = self.source_taken.position().await;
        self.call(|tx| Command::LocalBarrier(position, tx)).await
    }

    /// Stops the engine: every task is stopped and joined before this returns, and
    /// [`crate::Engine::wait`] resolves. Later calls return [`EngineError`].
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        self.call(Command::Shutdown).await
    }
}
