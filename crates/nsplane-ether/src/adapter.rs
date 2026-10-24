//! The adapter core: one guest's ethernet frames in, IP packets and local replies out.
//!
//! [`EtherAdapter`] is sans-I/O. [`from_guest`](EtherAdapter::from_guest) takes a frame from
//! the guest, answers ARP, neighbor and router solicitations and `DHCPv4` itself, and hands
//! back the IP packets meant for the IP side; [`to_guest`](EtherAdapter::to_guest) gives the
//! ethernet header that carries an IP packet to the guest. The guest MAC is learned from
//! the source address of the guest's frames.

use std::net::{Ipv4Addr, Ipv6Addr};

use nsplane_packet::{Ipv4Header, Ipv6Header, UdpHeader, protocol};

use crate::frame::{self, EtherType, Frame, HEADER_LEN};
use crate::ndp::{self, Ndp, NdpMessage, RaConfig};
use crate::{ArpPacket, DhcpConfig, DhcpServer, MacAddr, arp, dhcp};

/// Default link MTU.
pub const DEFAULT_MTU: u16 = 1500;

/// Length of the IPv6 fixed header.
const IPV6_HEADER_LEN: usize = 40;

/// Configuration of the gateway the adapter stands in for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtherConfig {
    /// MAC of the gateway, the source of every frame to the guest.
    pub gateway_mac: MacAddr,
    /// IPv4 address of the gateway, answered by ARP; `None` answers no ARP request.
    pub gateway_ipv4: Option<Ipv4Addr>,
    /// Global IPv6 address of the gateway, answered by neighbor discovery in addition to the
    /// link-local address derived from [`gateway_mac`](Self::gateway_mac).
    pub gateway_ipv6: Option<Ipv6Addr>,
    /// The /64 advertised in router advertisements; `None` advertises no prefix.
    pub ipv6_prefix: Option<Ipv6Addr>,
    /// DNS servers advertised in router advertisements (RDNSS); empty advertises none.
    pub ipv6_dns: Vec<Ipv6Addr>,
    /// The single `DHCPv4` lease; `None` runs no DHCP server and passes DHCP traffic to the
    /// IP side.
    pub dhcp: Option<DhcpConfig>,
    /// Link MTU, advertised in router advertisements.
    pub mtu: u16,
}

impl EtherConfig {
    /// A gateway at `gateway_mac` with no addresses, no prefix, no DHCP and [`DEFAULT_MTU`].
    pub const fn new(gateway_mac: MacAddr) -> Self {
        Self {
            gateway_mac,
            gateway_ipv4: None,
            gateway_ipv6: None,
            ipv6_prefix: None,
            ipv6_dns: Vec::new(),
            dhcp: None,
            mtu: DEFAULT_MTU,
        }
    }
}

/// Adapter counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EtherStats {
    /// Frames received from the guest.
    pub frames_in: u64,
    /// Frames produced for the guest: local replies and IP packets.
    pub frames_out: u64,
    /// IP packets from the guest handed to the IP side.
    pub ip_in: u64,
    /// IP packets from the IP side framed for the guest.
    pub ip_out: u64,
    /// ARP replies sent.
    pub arp_replies: u64,
    /// Neighbor and router advertisements sent, solicited or not.
    pub nd_replies: u64,
    /// `DHCPv4` replies sent.
    pub dhcp_replies: u64,
    /// Guest frames dropped as malformed: a bad ethernet header, a multicast source, or a
    /// bad ARP, IP or neighbor discovery packet.
    pub drop_malformed: u64,
    /// Guest frames dropped because they were sent to another unicast MAC.
    pub drop_not_for_gateway: u64,
    /// Guest frames dropped for carrying neither ARP, IPv4 nor IPv6.
    pub drop_unsupported: u64,
    /// Guest ARP, neighbor discovery and DHCP messages consumed without a reply.
    pub drop_unanswered: u64,
    /// IP packets for the guest dropped because no guest MAC was learned yet.
    pub drop_no_guest_mac: u64,
    /// IP packets for the guest dropped for not being IPv4 or IPv6.
    pub drop_bad_ip: u64,
    /// IP packets from the guest dropped because the IP side fell behind.
    pub drop_backlog: u64,
}

/// The adapter for one guest. See the [module docs](self).
#[derive(Debug, Clone)]
pub struct EtherAdapter {
    gateway_mac: MacAddr,
    gateway_ipv4: Option<Ipv4Addr>,
    /// Addresses answered by neighbor discovery: the link-local one, then the global one.
    gateway_ipv6: Vec<Ipv6Addr>,
    ra: RaConfig,
    dhcp: Option<DhcpServer>,
    guest_mac: Option<MacAddr>,
    stats: EtherStats,
}

impl EtherAdapter {
    /// An adapter that has not seen the guest yet.
    pub fn new(config: EtherConfig) -> Self {
        let mut gateway_ipv6 = vec![config.gateway_mac.link_local()];
        gateway_ipv6.extend(config.gateway_ipv6);
        Self {
            gateway_mac: config.gateway_mac,
            gateway_ipv4: config.gateway_ipv4,
            gateway_ipv6,
            ra: RaConfig {
                mtu: u32::from(config.mtu),
                prefix: config.ipv6_prefix,
                dns: config.ipv6_dns,
                ..RaConfig::default()
            },
            dhcp: config.dhcp.map(DhcpServer::new),
            guest_mac: None,
            stats: EtherStats::default(),
        }
    }

    /// The learned guest MAC.
    pub const fn guest_mac(&self) -> Option<MacAddr> {
        self.guest_mac
    }

    /// The counters.
    pub const fn stats(&self) -> EtherStats {
        self.stats
    }

    /// Handles the frame `bytes` from the guest.
    ///
    /// Frames to send back to the guest (ARP, neighbor and router advertisements, DHCP
    /// replies) are appended to `replies`. Returns the IP packet the frame carries if it is
    /// for the IP side: an IPv4 or IPv6 packet sent to the gateway MAC or to a broadcast or
    /// multicast MAC and not handled here, without any frame padding. Everything else is
    /// dropped and counted.
    ///
    /// Every frame with a unicast source teaches the guest MAC; when it is learned for the
    /// first time and a prefix is configured, an unsolicited router advertisement to
    /// all-nodes is appended to `replies`.
    pub fn from_guest<'a>(
        &mut self,
        bytes: &'a [u8],
        replies: &mut Vec<Vec<u8>>,
    ) -> Option<&'a [u8]> {
        self.stats.frames_in += 1;
        let Ok(frame) = Frame::parse(bytes) else {
            self.stats.drop_malformed += 1;
            return None;
        };
        if !frame.src.is_unicast() {
            self.stats.drop_malformed += 1;
            return None;
        }
        self.learn(frame.src, replies);
        if frame.dst != self.gateway_mac && !frame.dst.is_multicast() {
            self.stats.drop_not_for_gateway += 1;
            return None;
        }
        match frame.ethertype {
            EtherType::ARP => {
                self.arp(&frame, replies);
                None
            }
            EtherType::IPV4 => self.ipv4(&frame, replies),
            EtherType::IPV6 => self.ipv6(&frame, replies),
            _ => {
                self.stats.drop_unsupported += 1;
                None
            }
        }
    }

    /// The ethernet header that carries the IP packet `packet` from the gateway to the
    /// guest, with the `EtherType` of its version.
    ///
    /// Returns `None`, counting the drop, if no guest MAC is learned yet or `packet` is
    /// neither IPv4 nor IPv6.
    pub fn to_guest(&mut self, packet: &[u8]) -> Option<[u8; HEADER_LEN]> {
        let ethertype = match packet.first().map(|b| b >> 4) {
            Some(4) => EtherType::IPV4,
            Some(6) => EtherType::IPV6,
            _ => {
                self.stats.drop_bad_ip += 1;
                return None;
            }
        };
        let Some(guest) = self.guest_mac else {
            self.stats.drop_no_guest_mac += 1;
            return None;
        };
        let mut header = [0; HEADER_LEN];
        frame::write_header(&mut header, guest, self.gateway_mac, ethertype).ok()?;
        self.stats.ip_out += 1;
        self.stats.frames_out += 1;
        Some(header)
    }

    /// Counts an IP packet from the guest that the IP side had no room for.
    pub const fn count_backlog_drop(&mut self) {
        self.stats.drop_backlog += 1;
    }

    /// Records `mac` as the guest MAC.
    fn learn(&mut self, mac: MacAddr, replies: &mut Vec<Vec<u8>>) {
        match self.guest_mac {
            Some(known) if known == mac => {}
            Some(known) => {
                tracing::debug!(old = %known, new = %mac, "guest MAC changed");
                self.guest_mac = Some(mac);
            }
            None => {
                tracing::debug!(%mac, "guest MAC learned");
                self.guest_mac = Some(mac);
                if self.ra.prefix.is_some() {
                    let all_nodes = MacAddr::ipv6_multicast(ndp::ALL_NODES);
                    let ra = ndp::router_advertisement(
                        &self.ra,
                        self.gateway_mac,
                        ndp::ALL_NODES,
                        all_nodes,
                    );
                    self.reply(ra, replies);
                    self.stats.nd_replies += 1;
                }
            }
        }
    }

    fn arp(&mut self, frame: &Frame<'_>, replies: &mut Vec<Vec<u8>>) {
        let Ok(packet) = ArpPacket::parse(frame.payload) else {
            self.stats.drop_malformed += 1;
            return;
        };
        match self
            .gateway_ipv4
            .and_then(|ip| arp::reply(&packet, self.gateway_mac, ip))
        {
            Some(reply) => {
                self.reply(reply, replies);
                self.stats.arp_replies += 1;
            }
            None => self.stats.drop_unanswered += 1,
        }
    }

    fn ipv4<'a>(&mut self, frame: &Frame<'a>, replies: &mut Vec<Vec<u8>>) -> Option<&'a [u8]> {
        let Ok((header, payload)) = Ipv4Header::parse(frame.payload) else {
            self.stats.drop_malformed += 1;
            return None;
        };
        let total = usize::from(header.total_len());
        if let Some(server) = &mut self.dhcp
            && header.protocol() == protocol::UDP
            && !header.more_fragments()
            && header.fragment_offset() == 0
            && (header.dst() == Ipv4Addr::BROADCAST || header.dst() == server.config().server_ip)
            && let Ok((udp, message)) = UdpHeader::parse(payload)
            && udp.dst_port() == dhcp::SERVER_PORT
        {
            match server
                .handle(message, frame.src)
                .and_then(|reply| server.reply_frame(&reply, self.gateway_mac))
            {
                Some(reply) => {
                    self.reply(reply, replies);
                    self.stats.dhcp_replies += 1;
                }
                None => self.stats.drop_unanswered += 1,
            }
            return None;
        }
        self.pass(frame.payload.get(..total))
    }

    fn ipv6<'a>(&mut self, frame: &Frame<'a>, replies: &mut Vec<Vec<u8>>) -> Option<&'a [u8]> {
        let Ok((header, _)) = Ipv6Header::parse(frame.payload) else {
            self.stats.drop_malformed += 1;
            return None;
        };
        let total = IPV6_HEADER_LEN + usize::from(header.payload_len());
        let packet = frame.payload.get(..total);
        let ndp = match packet.map(Ndp::parse) {
            Some(Ok(Some(ndp))) => ndp,
            Some(Ok(None)) => return self.pass(packet),
            Some(Err(_)) | None => {
                self.stats.drop_malformed += 1;
                return None;
            }
        };
        let reply = match ndp.message {
            NdpMessage::NeighborSolicitation { .. } => ndp::answer_neighbor_solicitation(
                &ndp,
                frame.src,
                self.gateway_mac,
                &self.gateway_ipv6,
            ),
            NdpMessage::RouterSolicitation { .. } => {
                ndp::answer_router_solicitation(&ndp, frame.src, self.gateway_mac, &self.ra)
            }
            NdpMessage::NeighborAdvertisement { .. } => None,
        };
        match reply {
            Some(reply) => {
                self.reply(reply, replies);
                self.stats.nd_replies += 1;
            }
            None => self.stats.drop_unanswered += 1,
        }
        None
    }

    /// Hands `packet` to the IP side; `None` (shorter than its header claims) is malformed.
    const fn pass<'a>(&mut self, packet: Option<&'a [u8]>) -> Option<&'a [u8]> {
        if packet.is_some() {
            self.stats.ip_in += 1;
        } else {
            self.stats.drop_malformed += 1;
        }
        packet
    }

    fn reply(&mut self, frame: Vec<u8>, replies: &mut Vec<Vec<u8>>) {
        self.stats.frames_out += 1;
        replies.push(frame);
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use nsplane_packet::udp_packet;

    use super::*;
    use crate::ArpOp;

    const GW_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const GUEST_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    const OTHER_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]);
    const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

    fn prefix() -> Ipv6Addr {
        "fd00:1::".parse().unwrap()
    }

    fn adapter(prefix: Option<Ipv6Addr>) -> EtherAdapter {
        EtherAdapter::new(EtherConfig {
            gateway_ipv4: Some(GW_IP),
            ipv6_prefix: prefix,
            dhcp: Some(DhcpConfig::new(GW_IP, GUEST_IP, 24)),
            ..EtherConfig::new(GW_MAC)
        })
    }

    fn eth(dst: MacAddr, src: MacAddr, ethertype: EtherType, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0; HEADER_LEN];
        frame::write_header(&mut out, dst, src, ethertype).unwrap();
        out.extend_from_slice(payload);
        out
    }

    fn udp4(dst: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        udp_packet(
            SocketAddr::from((GUEST_IP, 40000)),
            SocketAddr::from((dst, dst_port)),
            payload,
        )
        .unwrap()
        .as_packet()
        .to_vec()
    }

    #[test]
    fn learns_and_follows_the_guest_mac() {
        let mut a = adapter(None);
        let mut replies = Vec::new();
        assert_eq!(a.guest_mac(), None);
        let packet = udp4(Ipv4Addr::new(1, 1, 1, 1), 53, b"q");
        a.from_guest(
            &eth(GW_MAC, GUEST_MAC, EtherType::IPV4, &packet),
            &mut replies,
        );
        assert_eq!(a.guest_mac(), Some(GUEST_MAC));
        a.from_guest(
            &eth(GW_MAC, OTHER_MAC, EtherType::IPV4, &packet),
            &mut replies,
        );
        assert_eq!(a.guest_mac(), Some(OTHER_MAC));
        // A multicast source teaches nothing and is dropped.
        let multicast = MacAddr([0x01, 0, 0x5e, 0, 0, 1]);
        assert_eq!(
            a.from_guest(
                &eth(GW_MAC, multicast, EtherType::IPV4, &packet),
                &mut replies
            ),
            None
        );
        assert_eq!(a.guest_mac(), Some(OTHER_MAC));
        assert_eq!(a.stats().drop_malformed, 1);
        assert_eq!(replies.len(), 0);
    }

    #[test]
    fn ip_passes_through_both_ways() {
        let mut a = adapter(None);
        let mut replies = Vec::new();
        let packet = udp4(Ipv4Addr::new(1, 1, 1, 1), 53, b"query");
        // Padded to the ethernet minimum: the padding is cut off.
        let mut frame = eth(GW_MAC, GUEST_MAC, EtherType::IPV4, &packet);
        frame.resize(60.max(frame.len()) + 4, 0);
        assert_eq!(a.from_guest(&frame, &mut replies), Some(&packet[..]));
        // Broadcast is for the IP side too; another unicast MAC is not.
        let frame = eth(MacAddr::BROADCAST, GUEST_MAC, EtherType::IPV4, &packet);
        assert_eq!(a.from_guest(&frame, &mut replies), Some(&packet[..]));
        let frame = eth(OTHER_MAC, GUEST_MAC, EtherType::IPV4, &packet);
        assert_eq!(a.from_guest(&frame, &mut replies), None);

        let header = a.to_guest(&packet).unwrap();
        let mut out = header.to_vec();
        out.extend_from_slice(&packet);
        let parsed = Frame::parse(&out).unwrap();
        assert_eq!((parsed.dst, parsed.src), (GUEST_MAC, GW_MAC));
        assert_eq!(parsed.ethertype, EtherType::IPV4);

        let mut v6 = vec![0x60, 0, 0, 0, 0, 0, protocol::UDP, 64];
        v6.extend_from_slice(&[0; 32]);
        let header = a.to_guest(&v6).unwrap();
        assert_eq!(header[12..14], [0x86, 0xdd]);
        assert_eq!(a.to_guest(&[0x50; 20]), None);

        let stats = a.stats();
        assert_eq!(stats.frames_in, 3);
        assert_eq!(stats.ip_in, 2);
        assert_eq!(stats.drop_not_for_gateway, 1);
        assert_eq!(stats.ip_out, 2);
        assert_eq!(stats.frames_out, 2);
        assert_eq!(stats.drop_bad_ip, 1);
        assert_eq!(replies.len(), 0);
    }

    #[test]
    fn no_guest_mac_drops() {
        let mut a = adapter(None);
        let packet = udp4(GUEST_IP, 53, b"x");
        assert_eq!(a.to_guest(&packet), None);
        assert_eq!(a.stats().drop_no_guest_mac, 1);
        assert_eq!(a.stats().frames_out, 0);
    }

    #[test]
    fn unsolicited_ra_on_first_learn_only() {
        let mut a = adapter(Some(prefix()));
        let mut replies = Vec::new();
        let packet = udp4(Ipv4Addr::new(1, 1, 1, 1), 53, b"q");
        let frame = eth(GW_MAC, GUEST_MAC, EtherType::IPV4, &packet);
        a.from_guest(&frame, &mut replies);
        assert_eq!(replies.len(), 1);
        let ra = Frame::parse(&replies[0]).unwrap();
        assert_eq!(ra.dst, MacAddr::ipv6_multicast(ndp::ALL_NODES));
        assert_eq!(ra.src, GW_MAC);
        let (ip, icmp) = Ipv6Header::parse(ra.payload).unwrap();
        assert_eq!(ip.dst(), ndp::ALL_NODES);
        assert_eq!(ip.src(), GW_MAC.link_local());
        assert_eq!(icmp[0], 134);

        a.from_guest(&frame, &mut replies);
        a.from_guest(
            &eth(GW_MAC, OTHER_MAC, EtherType::IPV4, &packet),
            &mut replies,
        );
        assert_eq!(replies.len(), 1);
        assert_eq!(a.stats().nd_replies, 1);

        // Without a prefix there is nothing to advertise unsolicited.
        let mut a = adapter(None);
        let mut replies = Vec::new();
        a.from_guest(&frame, &mut replies);
        assert_eq!(replies.len(), 0);
    }

    #[test]
    fn arp_answered_locally() {
        let mut a = adapter(None);
        let mut replies = Vec::new();
        let mut request = Vec::new();
        ArpPacket {
            op: ArpOp::Request,
            sender_mac: GUEST_MAC,
            sender_ip: GUEST_IP,
            target_mac: MacAddr([0; 6]),
            target_ip: GW_IP,
        }
        .write(&mut request);
        let frame = eth(MacAddr::BROADCAST, GUEST_MAC, EtherType::ARP, &request);
        assert_eq!(a.from_guest(&frame, &mut replies), None);
        assert_eq!(replies.len(), 1);
        let reply = Frame::parse(&replies[0]).unwrap();
        let arp = ArpPacket::parse(reply.payload).unwrap();
        assert_eq!(
            (arp.op, arp.sender_mac, arp.sender_ip),
            (ArpOp::Reply, GW_MAC, GW_IP)
        );
        assert_eq!(a.stats().arp_replies, 1);

        // A request for another address is consumed without a reply.
        request[24..28].copy_from_slice(&[10, 0, 2, 99]);
        let frame = eth(MacAddr::BROADCAST, GUEST_MAC, EtherType::ARP, &request);
        assert_eq!(a.from_guest(&frame, &mut replies), None);
        assert_eq!(replies.len(), 1);
        assert_eq!(a.stats().drop_unanswered, 1);
    }

    #[test]
    fn dhcp_answered_locally_and_other_udp_passed() {
        let mut a = adapter(None);
        let mut replies = Vec::new();
        let mut discover = vec![1, 1, 6, 0, 0, 0, 0, 1, 0, 0, 0x80, 0];
        discover.extend_from_slice(&[0; 16]);
        discover.extend_from_slice(&GUEST_MAC.0);
        discover.extend_from_slice(&[0; 10 + 192]);
        discover.extend_from_slice(&[99, 130, 83, 99, 53, 1, 1, 255]);
        let packet = udp_packet(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, dhcp::CLIENT_PORT)),
            SocketAddr::from((Ipv4Addr::BROADCAST, dhcp::SERVER_PORT)),
            &discover,
        )
        .unwrap();
        let frame = eth(
            MacAddr::BROADCAST,
            GUEST_MAC,
            EtherType::IPV4,
            packet.as_packet(),
        );
        assert_eq!(a.from_guest(&frame, &mut replies), None);
        assert_eq!(replies.len(), 1);
        assert_eq!(a.stats().dhcp_replies, 1);

        // Port 67 to another host is ordinary traffic.
        let other = udp4(Ipv4Addr::new(192, 0, 2, 1), dhcp::SERVER_PORT, &discover);
        let frame = eth(GW_MAC, GUEST_MAC, EtherType::IPV4, &other);
        assert_eq!(a.from_guest(&frame, &mut replies), Some(&other[..]));
    }

    #[test]
    fn unsupported_and_malformed_dropped() {
        let mut a = adapter(None);
        let mut replies = Vec::new();
        assert_eq!(a.from_guest(&[0; 10], &mut replies), None);
        let frame = eth(GW_MAC, GUEST_MAC, EtherType(0x88cc), &[0; 32]);
        assert_eq!(a.from_guest(&frame, &mut replies), None);
        // An IPv4 header claiming more bytes than the frame holds.
        let mut packet = udp4(Ipv4Addr::new(1, 1, 1, 1), 53, b"q");
        packet[2..4].copy_from_slice(&200u16.to_be_bytes());
        let frame = eth(GW_MAC, GUEST_MAC, EtherType::IPV4, &packet);
        assert_eq!(a.from_guest(&frame, &mut replies), None);
        let stats = a.stats();
        assert_eq!(stats.drop_malformed, 2);
        assert_eq!(stats.drop_unsupported, 1);
        assert_eq!(stats.ip_in, 0);
    }
}
