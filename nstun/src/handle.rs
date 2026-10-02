//! The cloneable control handle of a running engine.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use nstun_core::x25519::{PublicKey, StaticSecret};
use nstun_core::{AllowedIp, ConfigChange, Event, PeerConfig, PeerStats};
use nstun_packet::{PacketBuf, Path, PeerId};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::transport::Transport;
use crate::udp::UdpTransport;

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

/// A request to the owner task; each carries the channel for its reply.
pub(crate) enum Command<T> {
    Config(ConfigChange, oneshot::Sender<()>),
    PeerId(PublicKey, oneshot::Sender<Option<PeerId>>),
    PeerStats(PeerId, oneshot::Sender<Option<PeerStats>>),
    Peers(oneshot::Sender<Vec<PeerStats>>),
    PublicKey(oneshot::Sender<Option<PublicKey>>),
    PrivateKey(oneshot::Sender<Option<StaticSecret>>),
    InjectInbound(PeerId, PacketBuf, oneshot::Sender<()>),
    InjectOutbound(PacketBuf, oneshot::Sender<()>),
    ForceHandshake(PeerId, Option<Path>, oneshot::Sender<()>),
    SetTransport(T, oneshot::Sender<()>),
    Subscribe(oneshot::Sender<broadcast::Receiver<Event>>),
    DropCounters(oneshot::Sender<BTreeMap<&'static str, u64>>),
    Shutdown(oneshot::Sender<()>),
}

/// A cheap, cloneable handle to a running engine.
///
/// Every call is a message to the engine's owner task over a bounded channel and returns
/// once the owner task has processed it, so a configuration change is visible to every
/// later call. Calls fail with [`EngineError`] once the engine has stopped.
pub struct EngineHandle<T: Transport = UdpTransport> {
    commands: mpsc::Sender<Command<T>>,
}

impl<T: Transport> Clone for EngineHandle<T> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
        }
    }
}

impl<T: Transport> fmt::Debug for EngineHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineHandle")
            .field("closed", &self.commands.is_closed())
            .finish()
    }
}

impl<T: Transport> EngineHandle<T> {
    pub(crate) const fn new(commands: mpsc::Sender<Command<T>>) -> Self {
        Self { commands }
    }

    /// Sends the command built by `command` and waits for its reply.
    async fn call<R>(
        &self,
        command: impl FnOnce(oneshot::Sender<R>) -> Command<T>,
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

    /// Installs or replaces the transport.
    ///
    /// The old transport's tasks are stopped and the transport is dropped before this
    /// returns, so its socket is closed; then the new transport's tasks are spawned.
    /// Datagrams waiting for transmission go out on the new transport.
    pub async fn set_transport(&self, transport: T) -> Result<(), EngineError> {
        self.call(|tx| Command::SetTransport(transport, tx)).await
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
    /// [`crate::DROP_TRANSMIT_FULL`]).
    pub async fn drop_counters(&self) -> Result<BTreeMap<&'static str, u64>, EngineError> {
        self.call(Command::DropCounters).await
    }

    /// Stops the engine: every task is stopped and joined before this returns, and
    /// [`crate::Engine::wait`] resolves. Later calls return [`EngineError`].
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        self.call(Command::Shutdown).await
    }
}
