//! Stack configuration and its normalised form.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use nsplane_packet::reassembly::ReassemblyConfig;
use smoltcp::time::Duration as SmolDuration;

use crate::events::FlowEventsConfig;

/// Default MTU: the WireGuard default for an IPv4 or IPv6 outer path.
pub const DEFAULT_MTU: u16 = 1420;

/// Smallest MTU the stack runs with; a smaller configured value is raised to this.
pub const MIN_MTU: u16 = 576;

/// Largest TCP socket buffer: the largest window TCP can advertise, 65 535 shifted by the
/// maximum window scale of 14 (RFC 7323), just under smoltcp's own 1 GiB receive limit.
const MAX_TCP_BUFFER: usize = 65_535 << 14;

/// Configuration of a [`NetStack`](crate::NetStack).
///
/// Every capacity is a bound: no queue inside the stack grows past the value given here.
/// A capacity of zero is raised to one.
///
/// Fields may be added in any release. Start from [`NetStackConfig::new`] or
/// [`Default::default`] and assign the fields to change:
///
/// ```
/// use nsplane_netstack::{Admission, NetStackConfig};
///
/// let mut config = NetStackConfig::new(vec![("10.0.0.1".parse()?, 32)], 1360);
/// config.accept_capacity = 256;
/// config.admission = Admission::Immediate;
/// assert_eq!(config.mtu, 1360);
/// # Ok::<(), std::net::AddrParseError>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetStackConfig {
    /// The stack's own addresses, each with its prefix length.
    ///
    /// The stack accepts packets addressed to exactly these addresses and sources its own
    /// packets from them. It uses at most one IPv4 and one IPv6 address: the first address
    /// of each family wins and later ones are ignored. A prefix length longer than the
    /// family allows is clamped to 32 (IPv4) or 128 (IPv6).
    pub addresses: Vec<(IpAddr, u8)>,
    /// Largest IP packet the stack emits, in bytes; also the value the source reports as
    /// its MTU.
    ///
    /// The advertised TCP MSS is `mtu - 40` over IPv4 and `mtu - 60` over IPv6, so a peer
    /// never sends a segment that does not fit (the tunnel MTU rule). Values below
    /// [`MIN_MTU`] are raised to it. Default [`DEFAULT_MTU`].
    pub mtu: u16,
    /// Packets queued from the sink into the stack before `send` waits. Default 1024.
    pub ingress_capacity: usize,
    /// Packets queued from the stack to the source before the stack holds back. Default 1024.
    pub egress_capacity: usize,
    /// Connections or flows waiting in `incoming_tcp` / `incoming_udp` before new ones are
    /// dropped (or, for TCP with `accept_backpressure`, held back). Default 128.
    pub accept_capacity: usize,
    /// Whether a full `incoming_tcp` holds new TCP connections back instead of closing
    /// them. With it, bare SYNs are left unanswered (counted in
    /// [`NetStackStats::syn_deferred`](crate::NetStackStats::syn_deferred), the peer
    /// retransmits them) while the queue is full, and connections that completed their
    /// handshake meanwhile wait in the stack until the application accepts them. UDP flows
    /// are dropped when their queue is full, as without the option. Default `false`.
    pub accept_backpressure: bool,
    /// Datagrams queued per UDP flow or bound socket before new ones are dropped, and UDP
    /// payloads queued for sending before `send` waits. Default 256.
    ///
    /// The driver routes up to 256 ingress packets in one step before the application
    /// can take any, so a burst to one flow or socket beyond this capacity loses the
    /// excess even when the application keeps up on average; the default takes one whole
    /// step (the loss measured at both sizes is in `docs/performance.md`).
    ///
    /// The queue grows on demand in blocks of 32 entries, so an idle flow or socket costs
    /// the same at any capacity (one block, about 1 KiB per flow and 2 KiB per bound
    /// socket). A full queue also holds each datagram's ingress buffer (about 2 KiB on the
    /// engine path), so a flow or socket whose application stops reading pins up to about
    /// 512 KiB at the default (256 KiB at 128).
    pub datagram_capacity: usize,
    /// Bytes buffered per TCP connection and direction between the stack and the
    /// application. Default 64 KiB.
    pub stream_buffer: usize,
    /// Most TCP sockets held open for inbound handshakes, per destination port and in
    /// total; SYNs beyond it are refused with RST. Default 32.
    pub listener_pool: usize,
    /// Receive buffer of each TCP socket in bytes: the window a peer may fill.
    ///
    /// The window the stack advertises follows it, and so does the window-scale option of
    /// its SYN and SYN-ACK: smoltcp derives the shift from the buffer's capacity when the
    /// socket is created (its bit length minus 16, at least 0). The
    /// value is clamped to at least one IPv4 MSS (`mtu - 40`) and at most `65535 << 14`,
    /// the largest window TCP can advertise. Listener pool sockets get the same size.
    ///
    /// A window of more segments than the queues on the way hold costs throughput: the
    /// peer may send the whole window at once, the queue that fills first (the engine's
    /// `queue_capacity`, this stack's `ingress_capacity`, both 1024 packets by default)
    /// drops the rest. smoltcp recovers such losses by fast retransmit and New Reno's
    /// retransmission on partial ACKs, but without SACK one hole per round trip, and a lost
    /// retransmission still waits for a retransmission timeout of at least 1 s. Measured
    /// in-process at the default MTU before the fork had New Reno, 4 MiB (about 3000
    /// segments) dropped packets at the receiving engine's full sink in most runs and moved
    /// 64 MiB at about 50 MB/s instead of 250-450 MB/s; with 8192-packet queues it ran
    /// without drops. Keep the window in segments (`buffer / (mtu - 40)`)
    /// below those capacities, or raise them with it.
    /// Default `None`: 512 IPv4-sized segments, `(mtu - 40) * 512` (about 690 KiB at
    /// [`DEFAULT_MTU`]).
    pub tcp_rx_buffer: Option<usize>,
    /// Send buffer of each TCP socket in bytes: the data in flight and queued unsent.
    ///
    /// Clamped like [`tcp_rx_buffer`](Self::tcp_rx_buffer). Default `None`: the same
    /// `(mtu - 40) * 512`.
    pub tcp_tx_buffer: Option<usize>,
    /// Bytes all TCP connections of the stack together hold in their send buffers (sent
    /// and not acknowledged yet, or waiting for the window), split evenly between the
    /// connections that have data to send. Each connection gets at least one IPv4 MSS
    /// (`mtu - 40`) and at most its [`tcp_tx_buffer`](Self::tcp_tx_buffer).
    ///
    /// Without it every connection may have its whole send buffer in flight, so `n` bulk
    /// connections put `n` windows on the path at once. Where the queues on the path hold
    /// fewer packets (the receiving engine's `queue_capacity`, 1024 by default, holds two
    /// default windows), the excess is dropped and has to be recovered (one hole per round
    /// trip without SACK; a lost retransmission costs a retransmission timeout of at least
    /// 1 s). A budget of one default send buffer keeps such a path free of these drops.
    /// Measured in-process with four streams, it was what kept them as fast as one before
    /// the smoltcp fork's New Reno, sender silly window avoidance and Limited Transmit;
    /// with those, four streams without a budget match one as well. A budget also caps
    /// all connections together at `budget / RTT`, so on a path whose round trip needs more
    /// than the budget, parallel connections no longer add throughput.
    /// Default `None`: no budget, each connection up to its own send buffer.
    pub tcp_send_budget: Option<usize>,
    /// Lower bound of each TCP socket's retransmission timeout (RTO).
    ///
    /// smoltcp computes the RTO from the measured round-trip time (RFC 6298) and raises it
    /// to this bound; RTTs are sampled in whole milliseconds. On a path whose round trip is
    /// far below the bound, the bound alone sets the RTO, so a loss that fast retransmit
    /// and the tail loss probe do not recover costs at least this long. A bound below the
    /// peer's delayed-ACK time turns delayed ACKs into spurious retransmissions. A lowered
    /// bound applies from a connection's first RTT measurement.
    ///
    /// Taken in whole milliseconds and clamped to 1 ms..=60 s, smoltcp's range; the
    /// largest RTO, after exponential back-off, stays smoltcp's 60 s. Default 1 s
    /// (RFC 6298 2.4, smoltcp's default).
    pub tcp_min_rto: Duration,
    /// Retransmission timeout of each TCP socket before its first RTT measurement: the
    /// timeout of the SYN or SYN-ACK and of data sent before a round trip was measured.
    ///
    /// Taken in whole milliseconds and clamped to 1 ms..=60 s like
    /// [`tcp_min_rto`](Self::tcp_min_rto). Default 1 s (RFC 6298 2.1, smoltcp's default).
    pub tcp_initial_rto: Duration,
    /// Most UDP flows tracked at once; datagrams opening a flow beyond it are dropped.
    /// Default 65536.
    pub max_udp_flows: usize,
    /// Whether an IPv4 UDP datagram the application sends above the MTU leaves as one
    /// oversize packet with DF clear, for the engine's fragmenter
    /// (`nsplane::EngineBuilder::fragmenter`) to split, instead of failing with
    /// [`InvalidInput`](std::io::ErrorKind::InvalidInput).
    ///
    /// Datagrams that fit the MTU are unchanged (DF set), IPv6 datagrams above the MTU
    /// still fail, and so do IPv4 packets above the 65 535-byte total length limit. The
    /// source keeps reporting the configured MTU. Without a fragmenter on the engine (or
    /// with a TUN device that does not fragment) such packets are dropped further down.
    /// Default `false`.
    pub udp_allow_fragmentation: bool,
    /// Reassembly of ingress IPv4 fragments and IPv6 Fragment-header packets addressed to
    /// the stack, within the given bounds.
    ///
    /// With it, the driver holds fragments in one reassembler and hands each completed
    /// datagram on as if it had arrived whole (to a bound UDP socket or flow, or into TCP);
    /// incomplete datagrams expire on the driver's own timer. The outcome is counted in
    /// [`NetStackStats::reassembled`](crate::NetStackStats::reassembled),
    /// [`reassembly_timeout`](crate::NetStackStats::reassembly_timeout) and
    /// [`reassembly_overflow`](crate::NetStackStats::reassembly_overflow).
    /// Default `None`: fragments are dropped (counted as
    /// [`unsupported`](crate::NetStackStats::unsupported)) and no reassembly state exists.
    pub reassembly: Option<ReassemblyConfig>,
    /// Transparent mode: the stack is the endpoint for TCP and UDP addressed to any
    /// destination inside [`TransparentConfig::prefixes`], not only to its own addresses.
    ///
    /// The stack answers for every in-prefix address the engine delivers to it: a bare SYN
    /// or a UDP datagram to such an address opens a connection or flow, and replies and
    /// RSTs are sourced from the original destination. Which destinations reach the stack
    /// is decided in front of it: the peers' allowed IPs,
    /// `PeerConfig::inbound_destinations`, the ACL or a `Splitter`. On an accepted
    /// [`TcpConnection`](crate::TcpConnection) or [`UdpFlow`](crate::UdpFlow),
    /// `local_addr()` is the original destination and `peer_addr()` the source.
    ///
    /// Every bound of the stack (the listener pool, the UDP flow limit, every queue)
    /// applies to all addresses together. Fragments to in-prefix destinations are
    /// reassembled within the same [`reassembly`](Self::reassembly) bounds, and
    /// [`NetStackHandle::owns`](crate::NetStackHandle::owns) treats in-prefix destinations
    /// as the stack's. [`connect_tcp`](crate::NetStackHandle::connect_tcp),
    /// [`connect_udp`](crate::NetStackHandle::connect_udp) and
    /// [`bind_udp`](crate::NetStackHandle::bind_udp) still require one of the
    /// [`addresses`](Self::addresses).
    ///
    /// ```
    /// use nsplane_netstack::{NetStackConfig, TransparentConfig};
    ///
    /// let mut config = NetStackConfig::default();
    /// config.transparent = Some(TransparentConfig::default());
    /// assert!(config.transparent.is_some());
    /// ```
    ///
    /// Default `None`: the stack is the endpoint for its own addresses only, and the transparent
    /// checks cost nothing per packet.
    pub transparent: Option<TransparentConfig>,
    /// How a new TCP connection (a bare SYN) or UDP flow (its first datagram) is admitted,
    /// on every stack: to the stack's own addresses, and with
    /// [`transparent`](Self::transparent) to every in-prefix destination too.
    ///
    /// Under [`Admission::Decide`] each new connection or flow is offered as a
    /// [`PendingFlow`](crate::PendingFlow) whose [`control`](crate::PendingFlow::control)
    /// covers the lifetime from its first input on. On a stack without `transparent`,
    /// rejections are sourced from the stack's own addresses and there is no connection
    /// limit beyond the listener pool and the accept queue.
    ///
    /// A transparent stack also honours the deprecated
    /// [`TransparentConfig::admission`] while this field is [`Admission::Immediate`]; a
    /// `Decide` here takes precedence. Default [`Admission::Immediate`].
    pub admission: Admission,
    /// Most revoked ingress labels the stack remembers at once, see
    /// [`NetStackHandle::revoke_label`](crate::NetStackHandle::revoke_label).
    ///
    /// While the stack holds a label's tombstone, input with that label is dropped and
    /// counted in [`label_revoked`](crate::NetStackStats::label_revoked), and it never opens
    /// a new connection or flow. Beyond this many revoked labels the oldest tombstone is
    /// forgotten, so a label is remembered for at least the next `max_revoked_labels`
    /// revocations; a tombstone costs about 16 bytes. 0 keeps none: input sent after the
    /// revoke then opens new lifetimes again. Default 65536.
    pub max_revoked_labels: usize,
}

/// Configuration of transparent mode, see [`NetStackConfig::transparent`].
///
/// Fields may be added in any release. Start from [`Default::default`] and assign the
/// fields to change:
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
///
/// use nsplane_netstack::TransparentConfig;
///
/// let mut config = TransparentConfig::default();
/// config.prefixes = vec![(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)];
/// config.max_connections = Some(1024);
/// assert_eq!(config.max_connections, Some(1024));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransparentConfig {
    /// Destination prefixes the stack accepts, each an address with its prefix length;
    /// empty means every address of both families.
    ///
    /// A prefix length longer than the family allows is clamped to 32 (IPv4) or 128
    /// (IPv6), and host bits are ignored. A packet to a destination outside every prefix
    /// that is not one of the stack's addresses is dropped and counted in
    /// [`NetStackStats::no_address`](crate::NetStackStats::no_address), as without
    /// transparent mode, and also in
    /// [`rejected_prefix`](crate::NetStackStats::rejected_prefix).
    pub prefixes: Vec<(IpAddr, u8)>,
    /// Deprecated: replaced by [`NetStackConfig::admission`], and honoured while that field
    /// is [`Admission::Immediate`]. Default [`Admission::Immediate`].
    #[deprecated(note = "use `NetStackConfig::admission`, which applies to every stack")]
    pub admission: Admission,
    /// Most TCP connections the stack holds at once: accepted, mid handshake or opened
    /// with [`connect_tcp`](crate::NetStackHandle::connect_tcp), until they are released.
    ///
    /// At the limit, a bare SYN of a new connection is answered with a RST sourced from
    /// its original destination and counted in
    /// [`rejected_connection_limit`](crate::NetStackStats::rejected_connection_limit). A
    /// retransmitted SYN of a handshake in progress is not a new connection. Default
    /// `None`: no limit beyond the [`listener_pool`](NetStackConfig::listener_pool) and
    /// the accept queue.
    pub max_connections: Option<usize>,
    /// Admission events: a [`FlowEvent`](crate::FlowEvent) for each connection or flow
    /// admitted or rejected and each packet rejected for its prefix, on
    /// [`flow_events`](crate::NetStackHandle::flow_events), within the bounds of the
    /// [`FlowEventsConfig`].
    ///
    /// Events beyond the token bucket, or finding the channel full or its receiver gone,
    /// are dropped and counted in
    /// [`events_dropped`](crate::NetStackStats::events_dropped); delivered ones in
    /// [`events_emitted`](crate::NetStackStats::events_emitted). Default `None`: no
    /// events and no channel.
    pub events: Option<FlowEventsConfig>,
}

/// How a stack admits a new TCP connection or UDP flow, see
/// [`NetStackConfig::admission`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Admission {
    /// Accept on arrival: a bare SYN is answered with SYN-ACK and a UDP flow's first
    /// datagram opens the flow, as for the stack's own addresses.
    #[default]
    Immediate,
    /// Hold a bare SYN, or a UDP flow's first datagram, until the application decides,
    /// for at most `timeout`, with at most `max_pending` connections and flows held.
    ///
    /// Each held connection or flow is offered as a [`PendingFlow`](crate::PendingFlow) on
    /// [`incoming_pending`](crate::NetStackHandle::incoming_pending); the stack answers
    /// the SYN with SYN-ACK, or opens the flow, only once it is accepted. A rejected
    /// connection is answered with a RST and a rejected flow with an ICMP or `ICMPv6`
    /// port unreachable, both sourced from the original destination. This applies to
    /// every new connection and flow of the stack: to its own addresses, and on a
    /// transparent stack to in-prefix destinations too.
    ///
    /// The item's [`control`](crate::PendingFlow::control) covers the lifetime from its
    /// first input to its handle, and its [`delivery`](crate::FlowControl::delivery)
    /// receipt ends with exactly one outcome.
    ///
    /// - A connection or flow with no decision within `timeout` is rejected the same way
    ///   and counted in [`rejected_timeout`](crate::NetStackStats::rejected_timeout); a
    ///   later decision does nothing.
    /// - With `max_pending` held, or with `max_pending` items not taken from
    ///   `incoming_pending`, a new one is rejected at once and counted in
    ///   [`rejected_table_full`](crate::NetStackStats::rejected_table_full).
    /// - While a connection is held, its retransmitted SYNs are absorbed; while a flow is
    ///   held, its further datagrams are dropped and counted in
    ///   [`udp_queue_full`](crate::NetStackStats::udp_queue_full): a held flow queues its
    ///   first datagram only.
    /// - On a transparent stack, [`TransparentConfig::max_connections`] is checked when the
    ///   SYN arrives and again when the connection is accepted.
    ///
    /// An entry costs the held packet and a few words; expiry rides on the driver's
    /// timer, with no task per entry. A `max_pending` of 0 is taken as 1, and a `timeout`
    /// above one day as one day.
    Decide {
        /// Longest a connection or flow waits for the decision.
        timeout: Duration,
        /// Most connections and flows held at once.
        max_pending: usize,
    },
}

impl NetStackConfig {
    /// Creates a configuration with the given addresses and MTU and default capacities.
    pub fn new(addresses: Vec<(IpAddr, u8)>, mtu: u16) -> Self {
        Self {
            addresses,
            mtu,
            ..Self::default()
        }
    }
}

impl Default for NetStackConfig {
    /// No addresses, [`DEFAULT_MTU`] and the documented default capacities.
    fn default() -> Self {
        Self {
            addresses: Vec::new(),
            mtu: DEFAULT_MTU,
            ingress_capacity: 1024,
            egress_capacity: 1024,
            accept_capacity: 128,
            accept_backpressure: false,
            datagram_capacity: 256,
            stream_buffer: 64 * 1024,
            listener_pool: 32,
            tcp_rx_buffer: None,
            tcp_tx_buffer: None,
            tcp_send_budget: None,
            tcp_min_rto: DEFAULT_RTO,
            tcp_initial_rto: DEFAULT_RTO,
            max_udp_flows: 65_536,
            udp_allow_fragmentation: false,
            reassembly: None,
            transparent: None,
            admission: Admission::Immediate,
            max_revoked_labels: 65_536,
        }
    }
}

/// A [`NetStackConfig`] with every input normalised.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) v4: Option<(Ipv4Addr, u8)>,
    pub(crate) v6: Option<(Ipv6Addr, u8)>,
    pub(crate) mtu: u16,
    pub(crate) ingress_capacity: usize,
    pub(crate) egress_capacity: usize,
    pub(crate) accept_capacity: usize,
    pub(crate) accept_backpressure: bool,
    pub(crate) datagram_capacity: usize,
    pub(crate) stream_buffer: usize,
    pub(crate) listener_pool: usize,
    tcp_rx_buffer: usize,
    tcp_tx_buffer: usize,
    pub(crate) tcp_send_budget: Option<usize>,
    pub(crate) tcp_rto: TcpRto,
    pub(crate) max_udp_flows: usize,
    pub(crate) udp_allow_fragmentation: bool,
    pub(crate) reassembly: Option<ReassemblyConfig>,
    /// Boxed, so that it does not grow the driver.
    pub(crate) transparent: Option<Box<Transparent>>,
    /// The top-level admission, or the deprecated transparent one.
    pub(crate) admission: Admission,
    pub(crate) max_revoked_labels: usize,
}

/// The RTO bounds every TCP socket gets, see [`NetStackConfig::tcp_min_rto`] and
/// [`NetStackConfig::tcp_initial_rto`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpRto {
    pub(crate) min: SmolDuration,
    pub(crate) initial: SmolDuration,
}

impl TcpRto {
    /// Normalises `min` and `initial` as documented on [`NetStackConfig::tcp_min_rto`].
    fn new(min: Duration, initial: Duration) -> Self {
        let millis = |rto: Duration| {
            SmolDuration::from_millis(
                u64::try_from(rto.as_millis()).map_or(MAX_RTO_MS, |ms| ms.clamp(1, MAX_RTO_MS)),
            )
        };
        Self {
            min: millis(min),
            initial: millis(initial),
        }
    }
}

/// A [`TransparentConfig`] with its prefixes normalised.
#[derive(Debug, Clone)]
pub(crate) struct Transparent {
    pub(crate) prefixes: Prefixes,
    pub(crate) max_connections: Option<usize>,
    pub(crate) events: Option<FlowEventsConfig>,
}

/// One destination prefix: the network and its mask.
#[derive(Debug, Clone, Copy)]
enum Prefix {
    V4(u32, u32),
    V6(u128, u128),
}

/// The destination prefixes of a transparent stack; empty means every address.
#[derive(Debug, Clone, Default)]
pub(crate) struct Prefixes(Vec<Prefix>);

impl Prefixes {
    /// Normalises `prefixes` as documented on [`TransparentConfig::prefixes`].
    fn new(prefixes: Vec<(IpAddr, u8)>) -> Self {
        Self(
            prefixes
                .into_iter()
                .map(|(addr, len)| match addr {
                    IpAddr::V4(addr) => {
                        let mask = u32::MAX
                            .checked_shl(32 - u32::from(len.min(32)))
                            .unwrap_or(0);
                        Prefix::V4(u32::from(addr) & mask, mask)
                    }
                    IpAddr::V6(addr) => {
                        let mask = u128::MAX
                            .checked_shl(128 - u32::from(len.min(128)))
                            .unwrap_or(0);
                        Prefix::V6(u128::from(addr) & mask, mask)
                    }
                })
                .collect(),
        )
    }

    /// Whether `addr` lies inside one of the prefixes, or there are none.
    pub(crate) fn contains(&self, addr: IpAddr) -> bool {
        self.0.is_empty()
            || self.0.iter().any(|prefix| match (*prefix, addr) {
                (Prefix::V4(net, mask), IpAddr::V4(addr)) => u32::from(addr) & mask == net,
                (Prefix::V6(net, mask), IpAddr::V6(addr)) => u128::from(addr) & mask == net,
                _ => false,
            })
    }
}

/// Sockets get send and receive buffers of this many IPv4-sized segments unless
/// [`NetStackConfig::tcp_rx_buffer`] / [`NetStackConfig::tcp_tx_buffer`] say otherwise.
///
/// The receive buffer is the window a peer may fill, so the window scales with the MSS
/// (and so with the MTU): 512 segments is about 690 KiB at the default MTU.
///
/// A connection moves at most one window per round trip, so the window caps its throughput
/// at `window / RTT`: about 14 MB/s at 50 ms, against 1.8 MB/s for 64 segments. A window
/// that fits the buffer of a congested hop avoids losses there (measured in-process through
/// a 64-packet buffer: 64 segments lose nothing, 512 segments with congestion control lose
/// about 300 packets and take an order of magnitude longer), but the stack cannot know that
/// buffer, and without loss a smaller window gains nothing. Congestion control keeps the
/// large window from collapsing on a congested hop; the window stays large for long paths.
const WINDOW_SEGMENTS: usize = 512;
/// smoltcp's default minimum and initial RTO.
const DEFAULT_RTO: Duration = Duration::from_secs(1);
/// smoltcp's largest RTO in milliseconds, also the upper clamp of the configurable bounds.
const MAX_RTO_MS: u64 = 60_000;
/// Longest [`Admission::Decide`] timeout.
const MAX_PENDING_TIMEOUT: Duration = Duration::from_hours(24);

impl Settings {
    /// Normalises `config` as documented on [`NetStackConfig`].
    pub(crate) fn new(config: NetStackConfig) -> Self {
        let mut v4 = None;
        let mut v6 = None;
        for (addr, prefix) in config.addresses {
            match addr {
                IpAddr::V4(addr) => {
                    v4.get_or_insert_with(|| (addr, prefix.min(32)));
                }
                IpAddr::V6(addr) => {
                    v6.get_or_insert_with(|| (addr, prefix.min(128)));
                }
            }
        }
        #[allow(deprecated, reason = "honoured until it is removed")]
        let admission = match config.admission {
            Admission::Immediate => config
                .transparent
                .as_ref()
                .map_or(Admission::Immediate, |transparent| transparent.admission),
            admission => admission,
        };
        let mtu = config.mtu.max(MIN_MTU);
        let mss = usize::from(mtu) - 40;
        let tcp_buffer = |size: Option<usize>| {
            size.map_or(mss * WINDOW_SEGMENTS, |size| {
                size.clamp(mss, MAX_TCP_BUFFER)
            })
        };
        Self {
            v4,
            v6,
            mtu,
            ingress_capacity: config.ingress_capacity.max(1),
            egress_capacity: config.egress_capacity.max(1),
            accept_capacity: config.accept_capacity.max(1),
            accept_backpressure: config.accept_backpressure,
            datagram_capacity: config.datagram_capacity.max(1),
            stream_buffer: config.stream_buffer.max(1),
            listener_pool: config.listener_pool.max(1),
            tcp_rx_buffer: tcp_buffer(config.tcp_rx_buffer),
            tcp_tx_buffer: tcp_buffer(config.tcp_tx_buffer),
            tcp_send_budget: config.tcp_send_budget,
            tcp_rto: TcpRto::new(config.tcp_min_rto, config.tcp_initial_rto),
            max_udp_flows: config.max_udp_flows.max(1),
            udp_allow_fragmentation: config.udp_allow_fragmentation,
            reassembly: config.reassembly,
            transparent: config.transparent.map(|transparent| {
                Box::new(Transparent {
                    prefixes: Prefixes::new(transparent.prefixes),
                    max_connections: transparent.max_connections,
                    events: transparent.events,
                })
            }),
            admission: match admission {
                Admission::Decide {
                    timeout,
                    max_pending,
                } => Admission::Decide {
                    timeout: timeout.min(MAX_PENDING_TIMEOUT),
                    // Within the bound of the channel that offers the items.
                    max_pending: max_pending.clamp(1, usize::MAX >> 3),
                },
                admission => admission,
            },
            max_revoked_labels: config.max_revoked_labels,
        }
    }

    /// The stack's address of the same family as `peer`, if it has one.
    pub(crate) fn local_for(&self, peer: IpAddr) -> Option<IpAddr> {
        match peer {
            IpAddr::V4(_) => self.v4.map(|(addr, _)| IpAddr::V4(addr)),
            IpAddr::V6(_) => self.v6.map(|(addr, _)| IpAddr::V6(addr)),
        }
    }

    /// Whether `addr` is one of the stack's addresses.
    pub(crate) fn is_local(&self, addr: IpAddr) -> bool {
        self.local_for(addr) == Some(addr)
    }

    /// Whether the stack accepts packets to `addr`: one of its addresses, or in
    /// transparent mode an in-prefix address.
    pub(crate) fn accepts(&self, addr: IpAddr) -> bool {
        self.is_local(addr)
            || self
                .transparent
                .as_ref()
                .is_some_and(|transparent| transparent.prefixes.contains(addr))
    }

    /// Receive buffer size of every TCP socket, see [`NetStackConfig::tcp_rx_buffer`].
    pub(crate) const fn tcp_rx_buffer(&self) -> usize {
        self.tcp_rx_buffer
    }

    /// Send buffer size of every TCP socket, see [`NetStackConfig::tcp_tx_buffer`].
    pub(crate) const fn tcp_tx_buffer(&self) -> usize {
        self.tcp_tx_buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_first_address_per_family_and_clamps() {
        let config = NetStackConfig::new(
            vec![
                (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 40),
                (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24),
                (IpAddr::V6(Ipv6Addr::LOCALHOST), 200),
            ],
            100,
        );
        let settings = Settings::new(config);
        assert_eq!(settings.v4, Some((Ipv4Addr::new(10, 0, 0, 1), 32)));
        assert_eq!(settings.v6, Some((Ipv6Addr::LOCALHOST, 128)));
        assert_eq!(settings.mtu, MIN_MTU);
        assert!(settings.is_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!settings.is_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn zero_capacities_become_one() {
        let settings = Settings::new(NetStackConfig {
            ingress_capacity: 0,
            egress_capacity: 0,
            accept_capacity: 0,
            datagram_capacity: 0,
            stream_buffer: 0,
            listener_pool: 0,
            max_udp_flows: 0,
            ..NetStackConfig::default()
        });
        assert_eq!(settings.ingress_capacity, 1);
        assert_eq!(settings.egress_capacity, 1);
        assert_eq!(settings.accept_capacity, 1);
        assert_eq!(settings.datagram_capacity, 1);
        assert_eq!(settings.stream_buffer, 1);
        assert_eq!(settings.listener_pool, 1);
        assert_eq!(settings.max_udp_flows, 1);
        assert_eq!(settings.v4, None);
        assert_eq!(settings.mtu, DEFAULT_MTU);
    }

    #[test]
    fn tcp_buffers_default_to_512_segments() {
        let settings = Settings::new(NetStackConfig::default());
        assert_eq!(settings.tcp_rx_buffer(), 1380 * 512);
        assert_eq!(settings.tcp_tx_buffer(), 1380 * 512);
        let settings = Settings::new(NetStackConfig::new(Vec::new(), 1360));
        assert_eq!(settings.tcp_rx_buffer(), 1320 * 512);
        assert_eq!(settings.tcp_tx_buffer(), 1320 * 512);
        // The MTU is normalised first.
        let settings = Settings::new(NetStackConfig::new(Vec::new(), 100));
        assert_eq!(settings.tcp_rx_buffer(), (576 - 40) * 512);
    }

    #[test]
    fn tcp_buffers_pass_through_and_clamp() {
        let buffers = |rx, tx| {
            let settings = Settings::new(NetStackConfig {
                tcp_rx_buffer: Some(rx),
                tcp_tx_buffer: Some(tx),
                ..NetStackConfig::new(Vec::new(), 1360)
            });
            (settings.tcp_rx_buffer(), settings.tcp_tx_buffer())
        };
        assert_eq!(buffers(16 << 10, 4 << 20), (16 << 10, 4 << 20));
        assert_eq!(buffers(1320, 65_535 << 14), (1320, 65_535 << 14));
        assert_eq!(buffers(0, 1319), (1320, 1320));
        assert_eq!(
            buffers(usize::MAX, (65_535 << 14) + 1),
            (65_535 << 14, 65_535 << 14)
        );
    }

    #[test]
    #[allow(deprecated, reason = "the deprecated field is still honoured")]
    fn admission_is_top_level_first_then_transparent() {
        let decide = |timeout| Admission::Decide {
            timeout,
            max_pending: 0,
        };
        let admission = |top, transparent: Option<Admission>| {
            Settings::new(NetStackConfig {
                admission: top,
                transparent: transparent.map(|admission| TransparentConfig {
                    admission,
                    ..TransparentConfig::default()
                }),
                ..NetStackConfig::default()
            })
            .admission
        };
        let normalised = |timeout| Admission::Decide {
            timeout,
            max_pending: 1,
        };
        let second = Duration::from_secs(1);
        assert_eq!(admission(Admission::Immediate, None), Admission::Immediate);
        assert_eq!(admission(decide(second), None), normalised(second));
        assert_eq!(
            admission(Admission::Immediate, Some(decide(second))),
            normalised(second)
        );
        assert_eq!(
            admission(decide(second), Some(decide(Duration::from_secs(2)))),
            normalised(second)
        );
        assert_eq!(
            admission(decide(Duration::MAX), Some(Admission::Immediate)),
            normalised(MAX_PENDING_TIMEOUT)
        );
    }

    #[test]
    fn tcp_rto_defaults_to_smoltcp_and_clamps() {
        let rto = |min, initial| {
            Settings::new(NetStackConfig {
                tcp_min_rto: min,
                tcp_initial_rto: initial,
                ..NetStackConfig::default()
            })
            .tcp_rto
        };
        let defaults = Settings::new(NetStackConfig::default()).tcp_rto;
        assert_eq!(defaults.min, SmolDuration::from_secs(1));
        assert_eq!(defaults.initial, SmolDuration::from_secs(1));
        let set = rto(Duration::from_millis(20), Duration::from_micros(50_900));
        assert_eq!(set.min, SmolDuration::from_millis(20));
        assert_eq!(set.initial, SmolDuration::from_millis(50));
        let low = rto(Duration::ZERO, Duration::from_micros(999));
        assert_eq!(low.min, SmolDuration::from_millis(1));
        assert_eq!(low.initial, SmolDuration::from_millis(1));
        let high = rto(Duration::from_secs(61), Duration::MAX);
        assert_eq!(high.min, SmolDuration::from_secs(60));
        assert_eq!(high.initial, SmolDuration::from_secs(60));
    }
}
