//! Tokio driver for the nsplane data plane.
//!
//! Defines the I/O traits the engine runs on: [`PacketSource`] and [`PacketSink`] for
//! the local side (TUN, netstack, host bridge) and [`Transport`] for the network side,
//! plus in-memory channel implementations for tests and embedders.
//!
//! An [`Engine`] runs one source, one sink and any number of transports of any types (a
//! direct [`UdpTransport`] next to a relay, say), each under its own [`TransportId`]; a
//! peer's [`Path`] names the transport its datagrams use. [`EngineBuilder::transport`] adds
//! the initial ones and [`EngineHandle`] adds, removes and replaces them at runtime.
//! [`DynTransport`] is the object-safe form of [`Transport`] for code that has to hold
//! transports of different types in one place. A [`UdpTransport`] can share its socket
//! with another protocol through a side channel ([`UdpTransport::with_side_channel`]).
//! [`LinkTransport`] carries datagrams as messages over a link the embedder dials (a
//! WebSocket to a relay, say) and redials it when it is lost.
//!
//! For a hybrid local side (a TUN device next to a userspace netstack), [`Splitter`]
//! routes delivered packets to one of several sinks and [`MergeSource`] merges several
//! sources fairly into one.
//! [`MapSink`] and [`MapSource`] rewrite or drop packets in place, [`pipe`] feeds one
//! engine's output into another's input and [`pump`] moves packets from a source into a
//! sink: the local-side graph primitives. [`SwapSink`] replaces a sink while the engine runs
//! and [`AbortSink`] cancels a delivery stuck on it, for a local side rebuilt per generation.

#![forbid(unsafe_code)]

mod abort;
mod builder;
mod channel;
mod engine;
pub mod events;
mod fragment;
mod handle;
mod io;
mod link;
mod map;
mod merge;
mod path_mtu;
mod pipe;
mod pump;
mod splitter;
mod swap;
mod transport;
mod udp;

pub use abort::{AbortSink, SinkAbort};
pub use builder::{BuildError, EngineBuilder};
pub use channel::{ChannelSink, ChannelSource, ChannelTransport};
pub use engine::Engine;
pub use events::{
    DROP_FRAGMENT_NO_ROUTE, DROP_FRAGMENT_OVERSIZE, DROP_FRAGMENT_RATE_LIMITED, DROP_NO_TRANSPORT,
    DROP_SINK_CLOSED, DROP_SINK_FULL, DROP_TRANSMIT_FULL, DROP_TRANSPORT_CLOSED,
    DROP_TRANSPORT_REMOVED, DROP_TRANSPORT_SEND_ERROR, Event,
};
pub use fragment::{FragmentConfig, FragmentStats};
pub use handle::{
    EngineError, EngineHandle, EngineStatus, PathMtuStats, Peer, PeerMtus, QueueDepth, QueueStats,
    TransportError, TransportStats,
};
pub use io::{PacketSink, PacketSource};
pub use link::{LinkConfig, LinkDialer, LinkReceiver, LinkSender, LinkState, LinkTransport};
pub use map::{MapSink, MapSource, MapVerdict};
pub use merge::MergeSource;
pub use nsplane_core::reasons;
pub use nsplane_core::{AllowedIp, PacketFilter, PathPolicy, PeerStats, StandardRoaming, x25519};
pub use nsplane_packet::{
    Ecn, HEADROOM, MAX_BATCH, PacketBatch, PacketBuf, PacketPool, Path, PeerId, TAILROOM,
    TransportId,
};
pub use pipe::{PipeSink, PipeSource, pipe};
pub use pump::{PumpStats, pump};
pub use splitter::{Splitter, SplitterStats};
pub use swap::SwapSink;
pub use transport::{BoxFuture, DynTransport, PathMtuReport, Transport};
pub use udp::{SideDatagram, SideSender, SideStats, UdpTransport};
