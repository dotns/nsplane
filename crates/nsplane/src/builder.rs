//! Configuration of an engine before it starts.

use std::fmt;
use std::time::Duration;

use nsplane_core::x25519::StaticSecret;
use nsplane_core::{CoreConfig, PacketFilter, PathPolicy, StandardRoaming};

use crate::engine::{self, Engine};
use crate::io::{PacketSink, PacketSource};
use crate::transport::Transport;
use crate::udp::UdpTransport;

/// Default capacity of the internal packet queues, in packets.
const DEFAULT_QUEUE_CAPACITY: usize = 1024;
/// Default capacity of the event channel, in events.
const DEFAULT_EVENT_CAPACITY: usize = 1024;

/// Builds an [`Engine`] on a packet source, a packet sink and an optional transport.
///
/// Defaults: no transport (call [`EngineBuilder::transport`]; the type parameter defaults
/// to [`UdpTransport`]), no private key, [`StandardRoaming`], no filters, no periodic stats,
/// queues of 1024 packets and an event channel of 1024 events.
pub struct EngineBuilder<Src, Snk, T = UdpTransport> {
    source: Src,
    sink: Snk,
    transport: Option<T>,
    private_key: Option<StaticSecret>,
    policy: Box<dyn PathPolicy>,
    filters: Vec<Box<dyn PacketFilter>>,
    stats_interval: Option<Duration>,
    queue_capacity: usize,
    event_capacity: usize,
}

impl<Src, Snk, T> fmt::Debug for EngineBuilder<Src, Snk, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineBuilder")
            .field("transport", &self.transport.is_some())
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
            transport: None,
            private_key: None,
            policy: Box::new(StandardRoaming),
            filters: Vec::new(),
            stats_interval: None,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            event_capacity: DEFAULT_EVENT_CAPACITY,
        }
    }
}

impl<Src: PacketSource, Snk: PacketSink, T: Transport> EngineBuilder<Src, Snk, T> {
    /// Sets the transport, which fixes the engine's transport type.
    ///
    /// Without one, the engine drops every datagram it would transmit and counts it under
    /// [`crate::DROP_NO_TRANSPORT`] until [`crate::EngineHandle::set_transport`] installs one.
    pub fn transport<U: Transport>(self, transport: U) -> EngineBuilder<Src, Snk, U> {
        EngineBuilder {
            source: self.source,
            sink: self.sink,
            transport: Some(transport),
            private_key: self.private_key,
            policy: self.policy,
            filters: self.filters,
            stats_interval: self.stats_interval,
            queue_capacity: self.queue_capacity,
            event_capacity: self.event_capacity,
        }
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
    /// datagrams to transmit, packets to deliver) and of the datagrams waiting for room in
    /// the transmit queue; at least 1.
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
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime.
    pub fn build(self) -> Engine<T> {
        let core = CoreConfig {
            private_key: self.private_key.clone(),
            policy: self.policy,
            filters: self.filters,
            stats_interval: self.stats_interval,
            ..CoreConfig::default()
        };
        engine::spawn(engine::Parts {
            core,
            private_key: self.private_key,
            source: self.source,
            sink: self.sink,
            transport: self.transport,
            queue_capacity: self.queue_capacity,
            event_capacity: self.event_capacity,
        })
    }
}
