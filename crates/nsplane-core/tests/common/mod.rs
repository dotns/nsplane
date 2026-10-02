//! Core-vs-core test harness: several [`Core`]s wired to each other over a simulated network,
//! driven by a fake clock.
//!
//! Every core `i` lives at `net.paths[i]` (transport `i`, address `192.0.2.(i+1):51820`) and
//! owns the tunnel addresses [`ip4(i)`](ip4) and [`ip6(i)`](ip6). [`Net::new`] configures every
//! core with every other core as a peer: allowed IPs `ip4(j)/32` and `ip6(j)/128`, path
//! `paths[j]`.
//!
//! [`Net::pump`] moves datagrams until the network is quiet. A `Transmit` from core `i` on a
//! path whose address is `paths[j].addr` reaches core `j` as a datagram that arrived on
//! `paths[i]`, the sender's path. Tests can watch, rewrite, re-path or drop datagrams in flight
//! with [`Net::set_interceptor`], and inspect everything the cores produced through the
//! per-core logs [`Net::delivered`], [`Net::events`] and [`Net::transmits`].
//!
//! Time only moves with [`Net::advance`], which moves the `mock_instant` clock that nsplane-noise
//! runs on and the harness clock `net.now` by the same amount, then runs every core's timers.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "shared by several test crates, each of which uses a different part of it"
)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use mock_instant::MockClock;
use nsplane_core::x25519::{PublicKey, StaticSecret};
use nsplane_core::{
    AllowedIp, ConfigChange, Core, CoreConfig, Ecn, Event, Input, Output, PacketBuf, Path,
    PeerConfig, PeerId, TransportId,
};
use nsplane_packet::checksum;
use rand_core::OsRng;

/// Capacity of the packet buffers built by the harness: room for any test packet and its
/// WireGuard overhead, so sealing in place never reallocates.
pub const BUF_CAPACITY: usize = 2048;

/// A datagram in flight from one core to another.
#[derive(Debug)]
pub struct InFlight {
    /// Index of the sending core.
    pub from: usize,
    /// Path the sender transmitted on.
    pub path: Path,
    /// Path the receiver sees the datagram arrive on; defaults to the sender's path.
    pub arrival: Path,
    /// The datagram.
    pub data: PacketBuf,
}

/// What an interceptor decided about a datagram in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Route it by `path.addr` (which the interceptor may have changed).
    Pass,
    /// Lose it.
    Drop,
}

/// A datagram a core transmitted, as logged by [`Net::pump`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// Path the core transmitted on.
    pub path: Path,
    /// The datagram bytes.
    pub data: Vec<u8>,
}

/// Inspects every datagram in flight; may rewrite it, re-path it or drop it.
pub type Interceptor = Box<dyn FnMut(&mut InFlight) -> Fate>;

/// Several cores on a simulated network.
pub struct Net {
    /// The cores.
    pub cores: Vec<Core>,
    /// Where each core lives; also the path its peers have configured for it.
    pub paths: Vec<Path>,
    /// Private keys of the cores.
    pub keys: Vec<StaticSecret>,
    /// The harness clock, passed as `now` to the cores.
    pub now: Instant,
    /// Packets delivered by each core, with the peer they came from.
    pub delivered: Vec<Vec<(PeerId, PacketBuf)>>,
    /// Events reported by each core.
    pub events: Vec<Vec<Event>>,
    /// Datagrams transmitted by each core.
    pub transmits: Vec<Vec<Sent>>,
    /// Datagrams addressed to no core, with their sender.
    pub lost: Vec<InFlight>,
    /// Return delivered packets to the delivering core's pool right away, like a driver that
    /// is done with them. Off by default, so tests can inspect `delivered`.
    pub recycle_delivered: bool,
    interceptor: Option<Interceptor>,
}

impl std::fmt::Debug for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Net")
            .field("cores", &self.cores)
            .field("paths", &self.paths)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Tunnel IPv4 address of core `i`: `10.0.0.(i+1)`.
pub fn ip4(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, octet(i))
}

/// Tunnel IPv6 address of core `i`: `fd00::(i+1)`.
pub fn ip6(i: usize) -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(octet(i)))
}

/// Path of core `i`: transport `i`, address `192.0.2.(i+1):51820`.
pub fn path(i: usize) -> Path {
    Path {
        transport: TransportId::new(u16::from(octet(i)) - 1),
        addr: SocketAddr::from((Ipv4Addr::new(192, 0, 2, octet(i)), 51820)),
        ecn: Ecn::NotEct,
    }
}

fn octet(i: usize) -> u8 {
    u8::try_from(i + 1).unwrap()
}

/// An IPv4 UDP packet from `src` to `dst` carrying `payload`, with valid checksums.
pub fn udp4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let header_checksum = checksum::ipv4_header_checksum(&p[..20]);
    p[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    fill_udp(&mut p[20..], payload);
    let udp_checksum = checksum::transport_checksum_v4(src, dst, 17, &p[20..]);
    p[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    p
}

/// An IPv6 UDP packet from `src` to `dst` carrying `payload`, with a valid checksum.
pub fn udp6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut p = vec![0u8; 40 + udp_len];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&u16::try_from(udp_len).unwrap().to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    fill_udp(&mut p[40..], payload);
    let udp_checksum = checksum::transport_checksum_v6(src, dst, 17, &p[40..]);
    p[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
    p
}

/// Writes a UDP header (ports 1234 -> 5678, checksum zero) and `payload` into `segment`.
fn fill_udp(segment: &mut [u8], payload: &[u8]) {
    segment[0..2].copy_from_slice(&1234u16.to_be_bytes());
    segment[2..4].copy_from_slice(&5678u16.to_be_bytes());
    let len = u16::try_from(segment.len()).unwrap();
    segment[4..6].copy_from_slice(&len.to_be_bytes());
    segment[8..].copy_from_slice(payload);
}

/// A packet buffer holding `packet`, with room to seal it in place.
pub fn packet_buf(packet: &[u8]) -> PacketBuf {
    let mut buf = PacketBuf::with_capacity(BUF_CAPACITY);
    buf.set_len(packet.len());
    buf.as_packet_mut().copy_from_slice(packet);
    buf
}

/// The default configuration of core `i` in [`Net::new`].
pub fn default_config(_i: usize) -> CoreConfig {
    CoreConfig::default()
}

impl Net {
    /// `n` cores with default configurations, all peered with each other.
    pub fn new(n: usize) -> Self {
        Self::with_configs(n, default_config)
    }

    /// `n` cores built from `config(i)`, all peered with each other. The private key and the
    /// peers are set by the harness; a key in the returned config is replaced.
    pub fn with_configs(n: usize, config: impl FnMut(usize) -> CoreConfig) -> Self {
        let mut net = Self::unpeered(n, config);
        for i in 0..n {
            for j in (0..n).filter(|&j| j != i) {
                net.add_peer(i, j);
            }
        }
        net.pump();
        net
    }

    /// `n` cores built from `config(i)`, with private keys but without peers.
    pub fn unpeered(n: usize, mut config: impl FnMut(usize) -> CoreConfig) -> Self {
        let keys: Vec<StaticSecret> = (0..n)
            .map(|_| StaticSecret::random_from_rng(OsRng))
            .collect();
        let cores = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                Core::new(CoreConfig {
                    private_key: Some(key.clone()),
                    ..config(i)
                })
            })
            .collect();
        Self {
            cores,
            paths: (0..n).map(path).collect(),
            keys,
            now: Instant::now(),
            delivered: (0..n).map(|_| Vec::new()).collect(),
            events: (0..n).map(|_| Vec::new()).collect(),
            transmits: (0..n).map(|_| Vec::new()).collect(),
            lost: Vec::new(),
            recycle_delivered: false,
            interceptor: None,
        }
    }

    /// Public key of core `i`.
    pub fn public_key(&self, i: usize) -> PublicKey {
        PublicKey::from(&self.keys[i])
    }

    /// The peer config core `i` gets for core `j` in [`Net::new`].
    pub fn peer_config(&self, j: usize) -> PeerConfig {
        let mut config = PeerConfig::new(self.public_key(j));
        config.allowed_ips = vec![
            AllowedIp {
                addr: ip4(j).into(),
                cidr: 32,
            },
            AllowedIp {
                addr: ip6(j).into(),
                cidr: 128,
            },
        ];
        config.path = Some(self.paths[j]);
        config
    }

    /// Adds core `j` as a peer of core `i` with [`Net::peer_config`].
    pub fn add_peer(&mut self, i: usize, j: usize) {
        let config = self.peer_config(j);
        self.configure(i, ConfigChange::AddOrUpdatePeer(config));
    }

    /// Applies a configuration change to core `i`.
    pub fn configure(&mut self, i: usize, change: ConfigChange) {
        self.cores[i].handle_input(Input::Config(change), self.now);
    }

    /// The id core `i` gave to core `j`.
    pub fn peer_id(&self, i: usize, j: usize) -> PeerId {
        self.cores[i].peer_id(&self.public_key(j)).unwrap()
    }

    /// Feeds a local packet to core `i`; call [`Net::pump`] to move the results.
    pub fn send_local(&mut self, i: usize, packet: &[u8]) {
        let packet = packet_buf(packet);
        self.cores[i].handle_input(Input::Local { packet }, self.now);
    }

    /// Sends `payload` over UDP/IPv4 from core `i` to core `j` and pumps.
    pub fn ping4(&mut self, i: usize, j: usize, payload: &[u8]) -> Vec<u8> {
        let packet = udp4(ip4(i), ip4(j), payload);
        self.send_local(i, &packet);
        self.pump();
        packet
    }

    /// Sends `payload` over UDP/IPv6 from core `i` to core `j` and pumps.
    pub fn ping6(&mut self, i: usize, j: usize, payload: &[u8]) -> Vec<u8> {
        let packet = udp6(ip6(i), ip6(j), payload);
        self.send_local(i, &packet);
        self.pump();
        packet
    }

    /// Feeds a datagram to core `i` as if it arrived on `arrival`; the buffer the core leaves
    /// in its place goes back to its pool.
    pub fn receive(&mut self, i: usize, arrival: Path, mut data: PacketBuf) {
        self.cores[i].handle_input(
            Input::Datagram {
                path: arrival,
                data: &mut data,
            },
            self.now,
        );
        self.cores[i].recycle(data);
    }

    /// Installs a function that sees every datagram in flight from now on.
    pub fn set_interceptor(&mut self, interceptor: impl FnMut(&mut InFlight) -> Fate + 'static) {
        self.interceptor = Some(Box::new(interceptor));
    }

    /// Removes the interceptor.
    pub fn clear_interceptor(&mut self) {
        self.interceptor = None;
    }

    /// Drains the outputs of every core into the logs and returns the datagrams in flight.
    pub fn drain(&mut self) -> Vec<InFlight> {
        let mut in_flight = Vec::new();
        for i in 0..self.cores.len() {
            while let Some(output) = self.cores[i].poll_output() {
                match output {
                    Output::Transmit { path, data } => {
                        self.transmits[i].push(Sent {
                            path,
                            data: data.as_packet().to_vec(),
                        });
                        in_flight.push(InFlight {
                            from: i,
                            path,
                            arrival: self.paths[i],
                            data,
                        });
                    }
                    Output::Deliver { from, packet } => {
                        if self.recycle_delivered {
                            self.cores[i].recycle(packet);
                        } else {
                            self.delivered[i].push((from, packet));
                        }
                    }
                    Output::Event(event) => self.events[i].push(event),
                }
            }
        }
        in_flight
    }

    /// Moves datagrams between the cores until none is left in flight. Datagrams addressed to
    /// no core end up in [`Net::lost`].
    pub fn pump(&mut self) {
        for _ in 0..10_000 {
            let in_flight = self.drain();
            if in_flight.is_empty() {
                return;
            }
            for mut datagram in in_flight {
                if let Some(interceptor) = self.interceptor.as_mut()
                    && interceptor(&mut datagram) == Fate::Drop
                {
                    continue;
                }
                match self.paths.iter().position(|p| p.addr == datagram.path.addr) {
                    Some(to) => self.receive(to, datagram.arrival, datagram.data),
                    None => self.lost.push(datagram),
                }
            }
        }
        panic!("the network did not settle");
    }

    /// Moves both clocks forward by `d`, runs the timers of every core and pumps.
    pub fn advance(&mut self, d: Duration) {
        MockClock::advance(d);
        self.now += d;
        for core in &mut self.cores {
            core.handle_timeout(self.now);
        }
        self.pump();
    }

    /// Advances in timer ticks of 250 ms for a total of `d`.
    pub fn run_for(&mut self, d: Duration) {
        let tick = Duration::from_millis(250);
        let mut elapsed = Duration::ZERO;
        while elapsed < d {
            self.advance(tick);
            elapsed += tick;
        }
    }

    /// Starts a handshake from core `i` to core `j` and pumps until it is done.
    pub fn handshake(&mut self, i: usize, j: usize) {
        let peer = self.peer_id(i, j);
        self.cores[i].force_handshake(peer, None, self.now);
        self.pump();
    }

    /// Takes the packets core `i` delivered so far, as `(from, bytes)`.
    pub fn take_delivered(&mut self, i: usize) -> Vec<(PeerId, Vec<u8>)> {
        std::mem::take(&mut self.delivered[i])
            .into_iter()
            .map(|(from, packet)| (from, packet.as_packet().to_vec()))
            .collect()
    }

    /// Takes the events core `i` reported so far.
    pub fn take_events(&mut self, i: usize) -> Vec<Event> {
        std::mem::take(&mut self.events[i])
    }

    /// Takes the datagrams core `i` transmitted so far.
    pub fn take_transmits(&mut self, i: usize) -> Vec<Sent> {
        std::mem::take(&mut self.transmits[i])
    }

    /// Clears every log.
    pub fn clear_logs(&mut self) {
        for i in 0..self.cores.len() {
            self.delivered[i].clear();
            self.events[i].clear();
            self.transmits[i].clear();
        }
        self.lost.clear();
    }
}
