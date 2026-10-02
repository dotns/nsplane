//! Configuration of an engine before it starts.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::time::Duration;

use nsplane_core::x25519::StaticSecret;
use nsplane_core::{CoreConfig, PacketFilter, PathPolicy, StandardRoaming};
use nsplane_packet::TransportId;

use crate::engine::{self, Engine, NewTransport};
use crate::io::{PacketSink, PacketSource};
use crate::transport::Transport;

/// Default capacity of the internal packet queues, in packets.
const DEFAULT_QUEUE_CAPACITY: usize = 1024;
/// Default capacity of the event channel, in events.
const DEFAULT_EVENT_CAPACITY: usize = 1024;

/// Why [`EngineBuilder::build`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// No transport was added with [`EngineBuilder::transport`].
    NoTransport,
    /// Two transports share this id.
    DuplicateTransport(TransportId),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTransport => f.write_str("the engine has no transport"),
            Self::DuplicateTransport(id) => {
                write!(f, "transport {} was added more than once", id.get())
            }
        }
    }
}

impl Error for BuildError {}

/// Builds an [`Engine`] on a packet source, a packet sink and one or more transports.
///
/// Defaults: no private key, [`StandardRoaming`], no filters, no periodic stats, queues of
/// 1024 packets and an event channel of 1024 events. At least one transport must be added
/// with [`EngineBuilder::transport`].
pub struct EngineBuilder<Src, Snk> {
    source: Src,
    sink: Snk,
    transports: Vec<NewTransport>,
    private_key: Option<StaticSecret>,
    policy: Box<dyn PathPolicy>,
    filters: Vec<Box<dyn PacketFilter>>,
    stats_interval: Option<Duration>,
    queue_capacity: usize,
    event_capacity: usize,
}

impl<Src, Snk> fmt::Debug for EngineBuilder<Src, Snk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transports: Vec<_> = self.transports.iter().map(|t| t.id).collect();
        f.debug_struct("EngineBuilder")
            .field("transports", &transports)
            .field("private_key", &self.private_key.is_some())
            .field("filters", &self.filters.len())
            .field("stats_interval", &self.stats_interval)
            .field("queue_capacity", &self.queue_capacity)
            .field("event_capacity", &self.event_capacity)
            .finish_non_exhaustive()
    }
}

impl<Src: PacketSource, Snk: PacketSink> EngineBuilder<Src, Snk> {
    /// Starts building an engine that reads local packets from `source` and delivers
    /// decrypted packets to `sink`.
    pub fn new(source: Src, sink: Snk) -> Self {
        Self {
            source,
            sink,
            transports: Vec::new(),
            private_key: None,
            policy: Box::new(StandardRoaming),
            filters: Vec::new(),
            stats_interval: None,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            event_capacity: DEFAULT_EVENT_CAPACITY,
        }
    }

    /// Adds a transport; call it once per transport. Every transport needs its own
    /// [`Transport::id`].
    ///
    /// Transports of different types can be mixed, and more can be added, removed or
    /// replaced at runtime with [`crate::EngineHandle::add_transport`] and its siblings.
    #[must_use]
    pub fn transport<T: Transport>(mut self, transport: T) -> Self {
        self.transports.push(NewTransport::new(transport));
        self
    }

    /// Sets the own private key.
    #[must_use]
    pub fn private_key(mut self, key: StaticSecret) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Sets the path policy; [`StandardRoaming`] by default.
    #[must_use]
    pub fn policy(mut self, policy: Box<dyn PathPolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// Appends a packet filter; filters run in the order they were added.
    #[must_use]
    pub fn filter(mut self, filter: Box<dyn PacketFilter>) -> Self {
        self.filters.push(filter);
        self
    }

    /// Publishes `Event::PeerStats` for every peer at this interval.
    #[must_use]
    pub const fn stats_interval(mut self, interval: Duration) -> Self {
        self.stats_interval = Some(interval);
        self
    }

    /// Sets the capacity of each internal packet queue (local packets, received datagrams,
    /// each transport's datagrams to transmit, packets to deliver) and the bound of each
    /// transport's backlog of datagrams waiting for room in its transmit queue; at least 1.
    ///
    /// A datagram caused by a local packet, a received datagram or a timer that finds its
    /// transport's backlog at the bound is dropped under [`crate::DROP_TRANSMIT_FULL`];
    /// datagrams caused by handle calls wait regardless. Local reads pause only while every
    /// installed transport's backlog is at the bound, so a single transport holds back the
    /// source instead of dropping local packets, and a stalled transport never holds back
    /// local packets for the others. See [`Engine`] for the whole rule.
    #[must_use]
    pub fn queue_capacity(mut self, capacity: usize) -> Self {
        self.queue_capacity = capacity.max(1);
        self
    }

    /// Sets the capacity of the event channel; at least 1.
    #[must_use]
    pub fn event_capacity(mut self, capacity: usize) -> Self {
        self.event_capacity = capacity.max(1);
        self
    }

    /// Spawns the engine's tasks and returns the running engine.
    ///
    /// Fails, without spawning anything, with [`BuildError::NoTransport`] when no transport
    /// was added and with [`BuildError::DuplicateTransport`] when two share an id.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime.
    pub fn build(self) -> Result<Engine, BuildError> {
        if self.transports.is_empty() {
            return Err(BuildError::NoTransport);
        }
        let mut ids = BTreeSet::new();
        if let Some(id) = self
            .transports
            .iter()
            .map(|t| t.id)
            .find(|id| !ids.insert(*id))
        {
            return Err(BuildError::DuplicateTransport(id));
        }
        let core = CoreConfig {
            private_key: self.private_key.clone(),
            policy: self.policy,
            filters: self.filters,
            stats_interval: self.stats_interval,
            ..CoreConfig::default()
        };
        Ok(engine::spawn(engine::Parts {
            core,
            private_key: self.private_key,
            source: self.source,
            sink: self.sink,
            transports: self.transports,
            queue_capacity: self.queue_capacity,
            event_capacity: self.event_capacity,
        }))
    }
}
