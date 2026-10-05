//! Stack configuration and its normalised form.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nsplane_packet::reassembly::ReassemblyConfig;

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
    /// are dropped as before. Default `false`.
    pub accept_backpressure: bool,
    /// Datagrams queued per UDP flow or bound socket before new ones are dropped, and UDP
    /// payloads queued for sending before `send` waits. Default 128.
    ///
    /// The driver routes up to 256 ingress packets in one step before the application
    /// can take any, so a burst to one flow or socket beyond this capacity loses the
    /// excess even when the application keeps up on average. Between two `netstack_bench`
    /// nodes at 1 Gbit/s of 1380-byte datagrams, that was all of the receiver's UDP loss
    /// with the default queue and none with one of `ingress_capacity`; a bulk UDP receiver
    /// wants at least the 256.
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
    /// drops the rest, and smoltcp recovers all but one lost segment per window by a
    /// retransmission timeout of at least 1 s. Measured in-process at the default MTU,
    /// 4 MiB (about 3000 segments) dropped packets at the receiving engine's full sink in
    /// most runs and moved 64 MiB at about 50 MB/s instead of 250-450 MB/s; with 8192-packet
    /// queues it ran without drops. Keep the window in segments (`buffer / (mtu - 40)`)
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
    /// default windows), the excess is dropped, and smoltcp recovers all but one lost
    /// segment per window by a retransmission timeout of at least 1 s. A budget of one
    /// default send buffer keeps parallel streams as fast as one over such a path. It
    /// also caps all connections together at `budget / RTT`, so on a path whose round trip
    /// needs more than the budget, parallel connections no longer add throughput.
    /// Default `None`: no budget, each connection up to its own send buffer.
    pub tcp_send_budget: Option<usize>,
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
            datagram_capacity: 128,
            stream_buffer: 64 * 1024,
            listener_pool: 32,
            tcp_rx_buffer: None,
            tcp_tx_buffer: None,
            tcp_send_budget: None,
            max_udp_flows: 65_536,
            udp_allow_fragmentation: false,
            reassembly: None,
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
    pub(crate) max_udp_flows: usize,
    pub(crate) udp_allow_fragmentation: bool,
    pub(crate) reassembly: Option<ReassemblyConfig>,
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
            max_udp_flows: config.max_udp_flows.max(1),
            udp_allow_fragmentation: config.udp_allow_fragmentation,
            reassembly: config.reassembly,
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
}
