//! Stack configuration and its normalised form.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Default MTU: the WireGuard default for an IPv4 or IPv6 outer path.
pub const DEFAULT_MTU: u16 = 1420;

/// Smallest MTU the stack runs with; a smaller configured value is raised to this.
pub const MIN_MTU: u16 = 576;

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
    pub datagram_capacity: usize,
    /// Bytes buffered per TCP connection and direction between the stack and the
    /// application. Default 64 KiB.
    pub stream_buffer: usize,
    /// Most TCP sockets held open for inbound handshakes, per destination port and in
    /// total; SYNs beyond it are refused with RST. Default 32.
    pub listener_pool: usize,
    /// Most UDP flows tracked at once; datagrams opening a flow beyond it are dropped.
    /// Default 65536.
    pub max_udp_flows: usize,
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
            max_udp_flows: 65_536,
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
    pub(crate) max_udp_flows: usize,
}

/// Sockets get send and receive buffers of this many IPv4-sized segments.
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
        Self {
            v4,
            v6,
            mtu: config.mtu.max(MIN_MTU),
            ingress_capacity: config.ingress_capacity.max(1),
            egress_capacity: config.egress_capacity.max(1),
            accept_capacity: config.accept_capacity.max(1),
            accept_backpressure: config.accept_backpressure,
            datagram_capacity: config.datagram_capacity.max(1),
            stream_buffer: config.stream_buffer.max(1),
            listener_pool: config.listener_pool.max(1),
            max_udp_flows: config.max_udp_flows.max(1),
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

    /// Send and receive buffer size of every TCP socket, see [`WINDOW_SEGMENTS`].
    pub(crate) fn tcp_buffer(&self) -> usize {
        (usize::from(self.mtu) - 40) * WINDOW_SEGMENTS
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
}
