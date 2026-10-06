//! Inputs, outputs, events and configuration of the core.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use nsplane_noise::x25519;
use nsplane_packet::{PacketBuf, Path, PeerId};

use crate::filter::PacketFilter;
use crate::policy::{PathPolicy, StandardRoaming};

/// A network in CIDR notation.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct AllowedIp {
    /// Network address.
    pub addr: IpAddr,
    /// Prefix length.
    pub cidr: u8,
}

impl FromStr for AllowedIp {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(Self { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(Self { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

/// A peer to add, or the changes to apply to an existing peer.
///
/// On update, `None` leaves the preshared key, keepalive, path and inbound destinations
/// unchanged, and an all-zero preshared key removes it.
#[derive(Clone)]
pub struct PeerConfig {
    /// Public key identifying the peer.
    pub public_key: x25519::PublicKey,
    /// Networks routed to the peer; added to the existing ones unless `replace_allowed_ips`.
    pub allowed_ips: Vec<AllowedIp>,
    /// Drop the existing allowed IPs of the peer before adding `allowed_ips`.
    pub replace_allowed_ips: bool,
    /// Preshared key; `Some([0; 32])` removes it.
    pub preshared_key: Option<[u8; 32]>,
    /// Persistent keepalive interval in seconds; `Some(0)` disables it.
    pub persistent_keepalive: Option<u16>,
    /// Path to reach the peer on.
    pub path: Option<Path>,
    /// Networks the peer's decrypted packets may be addressed to; a packet to any other
    /// destination is dropped as [`reasons::DESTINATION_NOT_ALLOWED`]. A new peer without
    /// them is unchecked; `Some(vec![])` allows no destination. Independent of
    /// `allowed_ips`: they add no routes.
    ///
    /// [`reasons::DESTINATION_NOT_ALLOWED`]: crate::reasons::DESTINATION_NOT_ALLOWED
    pub inbound_destinations: Option<Vec<AllowedIp>>,
}

impl PeerConfig {
    /// A config that adds `public_key` without settings, or changes nothing about it.
    pub const fn new(public_key: x25519::PublicKey) -> Self {
        Self {
            public_key,
            allowed_ips: Vec::new(),
            replace_allowed_ips: false,
            preshared_key: None,
            persistent_keepalive: None,
            path: None,
            inbound_destinations: None,
        }
    }
}

impl fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerConfig")
            .field("public_key", &self.public_key)
            .field("allowed_ips", &self.allowed_ips)
            .field("replace_allowed_ips", &self.replace_allowed_ips)
            .field("preshared_key", &self.preshared_key.map(|_| "<redacted>"))
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("path", &self.path)
            .field("inbound_destinations", &self.inbound_destinations)
            .finish()
    }
}

/// A configuration change applied by the core.
pub enum ConfigChange {
    /// Replaces the private key; every peer is re-keyed and its sessions are cleared.
    SetPrivateKey(x25519::StaticSecret),
    /// Adds a peer, or updates it in place if its public key is known.
    AddOrUpdatePeer(PeerConfig),
    /// Removes a peer.
    RemovePeer(x25519::PublicKey),
    /// Removes all peers.
    RemoveAllPeers,
    /// Replaces the allowed IPs of a peer.
    SetAllowedIps {
        /// Public key of the peer.
        peer: x25519::PublicKey,
        /// The new allowed IPs.
        allowed_ips: Vec<AllowedIp>,
    },
    /// Sets or removes the preshared key of a peer.
    SetPresharedKey {
        /// Public key of the peer.
        peer: x25519::PublicKey,
        /// The new preshared key; `None` removes it.
        key: Option<[u8; 32]>,
    },
    /// Sets or disables the persistent keepalive of a peer.
    SetKeepalive {
        /// Public key of the peer.
        peer: x25519::PublicKey,
        /// Interval in seconds; `None` disables it.
        interval: Option<u16>,
    },
    /// Sets the path of a peer.
    SetPath {
        /// Public key of the peer.
        peer: x25519::PublicKey,
        /// The new path.
        path: Path,
    },
    /// Sets or removes the inbound destinations of a peer (see
    /// [`PeerConfig::inbound_destinations`]).
    SetInboundDestinations {
        /// Public key of the peer.
        peer: x25519::PublicKey,
        /// The new destinations; `None` removes them, leaving the peer unchecked.
        destinations: Option<Vec<AllowedIp>>,
    },
}

impl fmt::Debug for ConfigChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetPrivateKey(_) => f.debug_tuple("SetPrivateKey").field(&"<redacted>").finish(),
            Self::AddOrUpdatePeer(config) => {
                f.debug_tuple("AddOrUpdatePeer").field(config).finish()
            }
            Self::RemovePeer(key) => f.debug_tuple("RemovePeer").field(key).finish(),
            Self::RemoveAllPeers => f.write_str("RemoveAllPeers"),
            Self::SetAllowedIps { peer, allowed_ips } => f
                .debug_struct("SetAllowedIps")
                .field("peer", peer)
                .field("allowed_ips", allowed_ips)
                .finish(),
            Self::SetPresharedKey { peer, key } => f
                .debug_struct("SetPresharedKey")
                .field("peer", peer)
                .field("key", &key.map(|_| "<redacted>"))
                .finish(),
            Self::SetKeepalive { peer, interval } => f
                .debug_struct("SetKeepalive")
                .field("peer", peer)
                .field("interval", interval)
                .finish(),
            Self::SetPath { peer, path } => f
                .debug_struct("SetPath")
                .field("peer", peer)
                .field("path", path)
                .finish(),
            Self::SetInboundDestinations { peer, destinations } => f
                .debug_struct("SetInboundDestinations")
                .field("peer", peer)
                .field("destinations", destinations)
                .finish(),
        }
    }
}

/// Input to the core.
#[derive(Debug)]
pub enum Input {
    /// A datagram from a transport, with the path it arrived on.
    Datagram {
        /// Path the datagram arrived on.
        path: Path,
        /// The datagram, consumed by the core: a packet it carries is decrypted in place and
        /// delivered in the same buffer; otherwise the buffer goes to the core's pool.
        data: PacketBuf,
    },
    /// A local packet (TUN read, netstack egress, injection) to encrypt.
    Local {
        /// The IP packet.
        packet: PacketBuf,
    },
    /// A configuration change.
    Config(ConfigChange),
}

/// Output of the core.
#[derive(Debug)]
pub enum Output {
    /// Send this datagram on this path (ECN included).
    Transmit {
        /// Path to send the datagram on.
        path: Path,
        /// The datagram.
        data: PacketBuf,
    },
    /// Deliver this decrypted packet to the local side.
    Deliver {
        /// Peer the packet came from.
        from: PeerId,
        /// The IP packet.
        packet: PacketBuf,
    },
    /// Something the driver may want to report.
    Event(Event),
}

/// An event reported by the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A handshake with `peer` completed: a new session was established.
    ///
    /// Emitted exactly once per completed handshake, on both sides, also when several
    /// handshakes complete between two timer ticks: on the initiator when it accepts the
    /// handshake response, on the responder when the initiator confirms the new session with
    /// its first data message (usually the keepalive answering the response).
    HandshakeCompleted {
        /// The peer.
        peer: PeerId,
        /// Path the message that completed the handshake arrived on, as received (ECN mark
        /// included); `None` if the completion was noticed outside a received message.
        path: Option<Path>,
        /// Round-trip time from sending the handshake initiation to receiving its response;
        /// only the initiator measures it (always `None` on the responder). Measured on the
        /// real clock, not on the `now` passed to the core.
        rtt: Option<Duration>,
    },
    /// An authenticated message from `peer` arrived on a path that is not the peer's current
    /// path (or the peer has none); paths are compared on transport and address only.
    ///
    /// Emitted once per off-path source change, not per message: a source is reported again
    /// only after another one was, or after the peer's path was set (by configuration,
    /// [`Core::force_handshake`] or adoption) or a handshake completed. A message whose path
    /// the [`PathPolicy`] adopts is always reported. The policy is still told about every
    /// message.
    ///
    /// Authenticated messages are handshake initiations and responses the peer's tunnel
    /// accepted and transport data (keepalives included) that decrypted, even if its source
    /// address is then not allowed. Cookie replies never count. Messages on the current path
    /// emit nothing.
    ///
    /// [`Core::force_handshake`]: crate::Core::force_handshake
    Authenticated {
        /// The peer.
        peer: PeerId,
        /// Path the message arrived on, as received (ECN mark included).
        from: Path,
    },
    /// `path` became the current path of `peer` by roaming.
    ///
    /// Emitted right after an [`Event::Authenticated`] when the [`PathPolicy`] adopts its
    /// path; the peer then sends on it. Path changes by configuration or
    /// [`Core::force_handshake`] emit nothing.
    ///
    /// [`PathPolicy`]: crate::PathPolicy
    /// [`Core::force_handshake`]: crate::Core::force_handshake
    PathAdopted {
        /// The peer.
        peer: PeerId,
        /// The new path: the arrival path with its ECN mark replaced by [`Ecn::NotEct`], as
        /// stored for the peer.
        ///
        /// [`Ecn::NotEct`]: crate::Ecn::NotEct
        path: Path,
    },
    /// The sessions with `peer` expired.
    SessionExpired {
        /// The peer.
        peer: PeerId,
    },
    /// Periodic counters of `peer`.
    PeerStats {
        /// The peer.
        peer: PeerId,
        /// Bytes received on the wire (handshakes, keepalives, data); see [`PeerStats::rx`].
        rx: u64,
        /// Bytes sent on the wire (handshakes, keepalives, data); see [`PeerStats::tx`].
        tx: u64,
        /// Decrypted payload bytes delivered.
        data_rx: u64,
        /// Plaintext payload bytes sealed for the peer.
        data_tx: u64,
        /// Time since the last completed handshake.
        last_handshake: Option<Duration>,
    },
    /// A packet was dropped.
    Dropped {
        /// The peer the packet came from or was routed to, if known.
        peer: Option<PeerId>,
        /// Static description of why the packet was dropped: one of [`crate::reasons`], or
        /// a reason of a [`PacketFilter`](crate::PacketFilter).
        reason: &'static str,
    },
    /// The driver suspended the engine: no I/O runs and no timers fire until
    /// [`Event::Resumed`]. Emitted by the driver (`nsplane`), never by the core.
    Suspended,
    /// The driver resumed the engine after [`Event::Suspended`]. Emitted by the driver
    /// (`nsplane`), never by the core.
    Resumed,
    /// The MTU of the local packet source changed. Emitted by the driver (`nsplane`), never
    /// by the core.
    MtuChanged {
        /// The new MTU of the packet source, in bytes.
        mtu: u16,
    },
}

/// A snapshot of one peer: its configuration and counters.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerStats {
    /// The peer.
    pub peer: PeerId,
    /// Public key of the peer.
    pub public_key: x25519::PublicKey,
    /// Current path of the peer.
    pub path: Option<Path>,
    /// Networks routed to the peer.
    pub allowed_ips: Vec<AllowedIp>,
    /// Preshared key, if set.
    pub preshared_key: Option<[u8; 32]>,
    /// Persistent keepalive interval in seconds, if enabled.
    pub persistent_keepalive: Option<u16>,
    /// Bytes received on the wire (handshakes, keepalives, data): the full datagram of every
    /// handshake initiation, handshake response and transport data message accepted from the
    /// peer. Cookie replies and datagrams dropped before authentication are not counted.
    pub rx: u64,
    /// Bytes sent on the wire (handshakes, keepalives, data): the full datagram of every
    /// handshake initiation, handshake response and transport data message transmitted to the
    /// peer. Cookie replies are not counted.
    pub tx: u64,
    /// Decrypted payload bytes delivered: IP packets that passed the inbound filters.
    pub data_rx: u64,
    /// Plaintext payload bytes sealed for the peer: IP packets before encapsulation, after the
    /// outbound filters.
    pub data_tx: u64,
    /// Time since the last completed handshake.
    pub last_handshake: Option<Duration>,
}

impl fmt::Debug for PeerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerStats")
            .field("peer", &self.peer)
            .field("public_key", &self.public_key)
            .field("path", &self.path)
            .field("allowed_ips", &self.allowed_ips)
            .field("preshared_key", &self.preshared_key.map(|_| "<redacted>"))
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("rx", &self.rx)
            .field("tx", &self.tx)
            .field("data_rx", &self.data_rx)
            .field("data_tx", &self.data_tx)
            .field("last_handshake", &self.last_handshake)
            .finish()
    }
}

/// Configuration of the core.
pub struct CoreConfig {
    /// Own private key; peers can only be added once it is set.
    pub private_key: Option<x25519::StaticSecret>,
    /// Path selection and roaming decisions.
    pub policy: Box<dyn PathPolicy>,
    /// Filters run on every plaintext packet, installed from the wire side to the local side:
    /// in this order on decrypted packets, in reverse on local packets.
    pub filters: Vec<Box<dyn PacketFilter>>,
    /// Handshakes per second tolerated before replying with cookies.
    pub handshake_rate_limit: u64,
    /// Interval of `Event::PeerStats`; `None` disables them.
    pub stats_interval: Option<Duration>,
    /// Maximum number of free packet buffers kept for reuse.
    pub pool_size: usize,
    /// Whether [`Core::handle_input_deferred`] hands out [`CryptoJob`]s: then every peer keeps
    /// its tunnel behind a lock, which the jobs never take (they carry the session keys they
    /// need), so it is uncontended. Otherwise (the default) every peer owns
    /// its tunnel, the data path takes no lock, and [`Core::handle_input_deferred`] processes
    /// every input at once like [`Core::handle_input`].
    ///
    /// [`Core::handle_input`]: crate::Core::handle_input
    /// [`Core::handle_input_deferred`]: crate::Core::handle_input_deferred
    /// [`CryptoJob`]: crate::CryptoJob
    pub crypto_jobs: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            private_key: None,
            policy: Box::new(StandardRoaming),
            filters: Vec::new(),
            handshake_rate_limit: 100,
            stats_interval: None,
            pool_size: 64,
            crypto_jobs: false,
        }
    }
}

impl fmt::Debug for CoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreConfig")
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("filters", &self.filters.len())
            .field("handshake_rate_limit", &self.handshake_rate_limit)
            .field("stats_interval", &self.stats_interval)
            .field("pool_size", &self.pool_size)
            .field("crypto_jobs", &self.crypto_jobs)
            .finish_non_exhaustive()
    }
}
