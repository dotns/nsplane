//! `DHCPv4` (RFC 2131, options RFC 2132) with a server for exactly one lease.
//!
//! [`DhcpMessage::parse`] reads the BOOTP fixed header, the magic cookie and the options
//! (pad and end handled, option overload not interpreted). [`DhcpServer`] answers one guest:
//!
//! - DISCOVER: OFFER of the guest address.
//! - REQUEST naming this server, or with no server id and the guest address as requested
//!   address or `ciaddr` (init-reboot, renewing, rebinding): ACK. A request for another
//!   address: NAK. A request naming another server: no reply.
//! - RELEASE and DECLINE free the lease; no reply.
//! - INFORM: ACK with the configuration, without lease times.
//!
//! The lease binds to the first client MAC that receives an ACK. While it is bound, another
//! MAC gets no offer and a NAK to its requests, until the holder releases or declines.
//!
//! Offers and ACKs carry message type (53), server id (54), lease time (51), renewal (58,
//! half the lease) and rebinding (59, seven eighths) times, subnet mask (1), router (3, if
//! set), DNS servers (6, if any) and interface MTU (26, if set).

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};

use nsplane_packet::udp_packet;

use crate::MacAddr;
use crate::frame::{self, EtherType};
use crate::read::Reader;

/// UDP port of a `DHCPv4` server.
pub const SERVER_PORT: u16 = 67;
/// UDP port of a `DHCPv4` client.
pub const CLIENT_PORT: u16 = 68;

/// Option codes (RFC 2132).
pub mod option {
    /// Padding.
    pub const PAD: u8 = 0;
    /// Subnet mask.
    pub const SUBNET_MASK: u8 = 1;
    /// Routers.
    pub const ROUTER: u8 = 3;
    /// DNS servers.
    pub const DNS: u8 = 6;
    /// Interface MTU.
    pub const MTU: u8 = 26;
    /// Requested IP address.
    pub const REQUESTED_IP: u8 = 50;
    /// IP address lease time.
    pub const LEASE_TIME: u8 = 51;
    /// DHCP message type.
    pub const MESSAGE_TYPE: u8 = 53;
    /// Server identifier.
    pub const SERVER_ID: u8 = 54;
    /// Renewal (T1) time.
    pub const RENEWAL_TIME: u8 = 58;
    /// Rebinding (T2) time.
    pub const REBINDING_TIME: u8 = 59;
    /// End of options.
    pub const END: u8 = 255;
}

/// BOOTP operation codes.
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
/// Hardware type and address length of ethernet.
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;
/// Marks the start of the options.
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// The broadcast bit of the flags field.
const FLAG_BROADCAST: u16 = 0x8000;
/// Smallest message sent; some clients drop shorter BOOTP messages.
const MIN_MESSAGE_LEN: usize = 300;
/// Length of `sname` and `file` together.
const SNAME_FILE_LEN: usize = 192;
/// Most DNS servers one option can carry.
const MAX_DNS: usize = 63;

/// Why a DHCP message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DhcpError {
    /// The buffer is shorter than the fixed header and the magic cookie.
    Truncated,
    /// The hardware type or address length is not ethernet.
    Unsupported,
    /// The magic cookie is missing.
    BadCookie,
    /// An option runs past the end of the message, or the message type option is malformed.
    BadOption,
    /// There is no message type option, or its value is unknown.
    BadMessageType,
}

impl fmt::Display for DhcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "DHCP message truncated",
            Self::Unsupported => "DHCP hardware type not ethernet",
            Self::BadCookie => "DHCP magic cookie missing",
            Self::BadOption => "malformed DHCP option",
            Self::BadMessageType => "missing or unknown DHCP message type",
        })
    }
}

impl std::error::Error for DhcpError {}

/// DHCP message type (option 53).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// DHCPDISCOVER (1).
    Discover,
    /// DHCPOFFER (2).
    Offer,
    /// DHCPREQUEST (3).
    Request,
    /// DHCPDECLINE (4).
    Decline,
    /// DHCPACK (5).
    Ack,
    /// DHCPNAK (6).
    Nak,
    /// DHCPRELEASE (7).
    Release,
    /// DHCPINFORM (8).
    Inform,
}

impl MessageType {
    /// The type for option value `value`.
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }

    /// The option value.
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }
}

/// A parsed DHCP message over ethernet, borrowing its options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpMessage<'a> {
    /// BOOTP operation: 1 request, 2 reply.
    pub op: u8,
    /// Transaction id.
    pub xid: u32,
    /// Seconds since the client began acquisition.
    pub secs: u16,
    /// Flags; the top bit asks for broadcast replies.
    pub flags: u16,
    /// Client address, when the client already has one.
    pub ciaddr: Ipv4Addr,
    /// Address offered or assigned to the client.
    pub yiaddr: Ipv4Addr,
    /// Next server address.
    pub siaddr: Ipv4Addr,
    /// Relay agent address.
    pub giaddr: Ipv4Addr,
    /// Client hardware address.
    pub chaddr: MacAddr,
    /// Message type (option 53).
    pub message_type: MessageType,
    options: &'a [u8],
}

impl<'a> DhcpMessage<'a> {
    /// Parses a DHCP message (a UDP payload).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DhcpError> {
        let mut r = Reader::new(bytes);
        let [op, htype, hlen, _hops] = r.array().ok_or(DhcpError::Truncated)?;
        let (Some(xid), Some(secs), Some(flags)) = (r.u32(), r.u16(), r.u16()) else {
            return Err(DhcpError::Truncated);
        };
        let (Some(ciaddr), Some(yiaddr), Some(siaddr), Some(giaddr)) =
            (r.ipv4(), r.ipv4(), r.ipv4(), r.ipv4())
        else {
            return Err(DhcpError::Truncated);
        };
        let chaddr = r.mac().ok_or(DhcpError::Truncated)?;
        r.slice(10 + SNAME_FILE_LEN).ok_or(DhcpError::Truncated)?;
        let cookie = r.array::<4>().ok_or(DhcpError::Truncated)?;
        if htype != HTYPE_ETHERNET || hlen != HLEN_ETHERNET {
            return Err(DhcpError::Unsupported);
        }
        if cookie != MAGIC_COOKIE {
            return Err(DhcpError::BadCookie);
        }
        let options = r.rest();
        let message_type = match find_option(options, option::MESSAGE_TYPE)? {
            Some(&[value]) => MessageType::from_u8(value).ok_or(DhcpError::BadMessageType)?,
            Some(_) => return Err(DhcpError::BadOption),
            None => return Err(DhcpError::BadMessageType),
        };
        Ok(Self {
            op,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            message_type,
            options,
        })
    }

    /// The data of the first option `code`, if present.
    pub fn option(&self, code: u8) -> Option<&'a [u8]> {
        find_option(self.options, code).ok().flatten()
    }

    /// Whether the client asks for broadcast replies.
    pub const fn broadcast(&self) -> bool {
        self.flags & FLAG_BROADCAST != 0
    }

    /// Requested IP address (option 50).
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.ipv4_option(option::REQUESTED_IP)
    }

    /// Server identifier (option 54).
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.ipv4_option(option::SERVER_ID)
    }

    fn ipv4_option(&self, code: u8) -> Option<Ipv4Addr> {
        let octets: [u8; 4] = self.option(code)?.try_into().ok()?;
        Some(Ipv4Addr::from(octets))
    }
}

/// Walks the whole option area and returns the data of the first option `code`.
fn find_option(options: &[u8], code: u8) -> Result<Option<&[u8]>, DhcpError> {
    let mut r = Reader::new(options);
    let mut found = None;
    while let Some(kind) = r.u8() {
        match kind {
            option::PAD => {}
            option::END => break,
            _ => {
                let len = r.u8().ok_or(DhcpError::BadOption)?;
                let data = r.slice(usize::from(len)).ok_or(DhcpError::BadOption)?;
                if kind == code && found.is_none() {
                    found = Some(data);
                }
            }
        }
    }
    Ok(found)
}

/// Configuration of the single lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpConfig {
    /// Address of the server: source of replies and server id.
    pub server_ip: Ipv4Addr,
    /// The one address handed out.
    pub guest_ip: Ipv4Addr,
    /// Prefix length of the subnet mask (values above 32 count as 32).
    pub prefix_len: u8,
    /// Default router, if any.
    pub router: Option<Ipv4Addr>,
    /// DNS servers; at most the first 63 are sent.
    pub dns: Vec<Ipv4Addr>,
    /// Lease time in seconds.
    pub lease_secs: u32,
    /// Interface MTU, if any.
    pub mtu: Option<u16>,
}

impl DhcpConfig {
    /// A configuration with no router, no DNS servers, no MTU and a lease of 86400 s.
    pub const fn new(server_ip: Ipv4Addr, guest_ip: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            server_ip,
            guest_ip,
            prefix_len,
            router: None,
            dns: Vec::new(),
            lease_secs: 86_400,
            mtu: None,
        }
    }

    /// The subnet mask of `prefix_len`.
    pub fn netmask(&self) -> Ipv4Addr {
        let host_bits = 32 - u32::from(self.prefix_len.min(32));
        Ipv4Addr::from_bits(u32::MAX.checked_shl(host_bits).unwrap_or(0))
    }
}

/// `DHCPv4` server for exactly one lease. See the [module docs](self).
#[derive(Debug, Clone)]
pub struct DhcpServer {
    config: DhcpConfig,
    bound: Option<MacAddr>,
}

impl DhcpServer {
    /// A server with the lease free.
    pub const fn new(config: DhcpConfig) -> Self {
        Self {
            config,
            bound: None,
        }
    }

    /// The configuration.
    pub const fn config(&self) -> &DhcpConfig {
        &self.config
    }

    /// The MAC the lease is bound to, if any.
    pub const fn bound(&self) -> Option<MacAddr> {
        self.bound
    }

    /// Handles the DHCP message `request` (a UDP payload to port 67) from the client at
    /// `client_mac` and returns the reply UDP payload, if any; wrap it with
    /// [`reply_frame`](Self::reply_frame). Malformed messages and BOOTP replies are ignored.
    pub fn handle(&mut self, request: &[u8], client_mac: MacAddr) -> Option<Vec<u8>> {
        let req = DhcpMessage::parse(request).ok()?;
        if req.op != BOOTREQUEST {
            return None;
        }
        let free = self.bound.is_none_or(|mac| mac == client_mac);
        let ours = req.server_id().is_none_or(|id| id == self.config.server_ip);
        let guest = self.config.guest_ip;
        match req.message_type {
            MessageType::Discover => free
                .then(|| self.reply(&req, MessageType::Offer, Ipv4Addr::UNSPECIFIED, guest, true)),
            MessageType::Request => {
                if !ours {
                    return None;
                }
                let wanted = req
                    .requested_ip()
                    .or_else(|| (!req.ciaddr.is_unspecified()).then_some(req.ciaddr));
                if free && wanted == Some(guest) {
                    self.bound = Some(client_mac);
                    Some(self.reply(&req, MessageType::Ack, req.ciaddr, guest, true))
                } else {
                    Some(self.reply(
                        &req,
                        MessageType::Nak,
                        Ipv4Addr::UNSPECIFIED,
                        Ipv4Addr::UNSPECIFIED,
                        false,
                    ))
                }
            }
            MessageType::Release | MessageType::Decline => {
                if ours && self.bound == Some(client_mac) {
                    self.bound = None;
                }
                None
            }
            MessageType::Inform => Some(self.reply(
                &req,
                MessageType::Ack,
                req.ciaddr,
                Ipv4Addr::UNSPECIFIED,
                false,
            )),
            MessageType::Offer | MessageType::Ack | MessageType::Nak => None,
        }
    }

    /// The reply message of type `kind` to `req`; `lease` adds the lease times.
    fn reply(
        &self,
        req: &DhcpMessage<'_>,
        kind: MessageType,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        lease: bool,
    ) -> Vec<u8> {
        let config = &self.config;
        let mut out = Vec::with_capacity(MIN_MESSAGE_LEN);
        out.extend_from_slice(&[BOOTREPLY, HTYPE_ETHERNET, HLEN_ETHERNET, 0]);
        out.extend_from_slice(&req.xid.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&req.flags.to_be_bytes());
        out.extend_from_slice(&ciaddr.octets());
        out.extend_from_slice(&yiaddr.octets());
        out.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
        out.extend_from_slice(&req.giaddr.octets());
        out.extend_from_slice(&req.chaddr.0);
        out.extend_from_slice(&[0; 10 + SNAME_FILE_LEN]);
        out.extend_from_slice(&MAGIC_COOKIE);

        push_option(&mut out, option::MESSAGE_TYPE, &[kind.to_u8()]);
        push_option(&mut out, option::SERVER_ID, &config.server_ip.octets());
        if kind != MessageType::Nak {
            if lease {
                let secs = u64::from(config.lease_secs);
                let renewal = u32::try_from(secs / 2).unwrap_or(u32::MAX);
                let rebinding = u32::try_from(secs * 7 / 8).unwrap_or(u32::MAX);
                push_option(
                    &mut out,
                    option::LEASE_TIME,
                    &config.lease_secs.to_be_bytes(),
                );
                push_option(&mut out, option::RENEWAL_TIME, &renewal.to_be_bytes());
                push_option(&mut out, option::REBINDING_TIME, &rebinding.to_be_bytes());
            }
            push_option(&mut out, option::SUBNET_MASK, &config.netmask().octets());
            if let Some(router) = config.router {
                push_option(&mut out, option::ROUTER, &router.octets());
            }
            if !config.dns.is_empty() {
                let dns: Vec<u8> = config
                    .dns
                    .iter()
                    .take(MAX_DNS)
                    .flat_map(Ipv4Addr::octets)
                    .collect();
                push_option(&mut out, option::DNS, &dns);
            }
            if let Some(mtu) = config.mtu {
                push_option(&mut out, option::MTU, &mtu.to_be_bytes());
            }
        }
        out.push(option::END);
        if out.len() < MIN_MESSAGE_LEN {
            out.resize(MIN_MESSAGE_LEN, 0);
        }
        out
    }

    /// Wraps the reply `reply` (from [`handle`](Self::handle)) in UDP, IPv4 and ethernet,
    /// from `server_mac` and `server_ip:67` to port 68.
    ///
    /// A NAK, a reply with the broadcast flag and a reply with `ciaddr` unspecified go to
    /// `255.255.255.255` at the broadcast MAC; any other reply goes to `ciaddr` at `chaddr`.
    /// Returns `None` if `reply` is not a BOOTP reply.
    pub fn reply_frame(&self, reply: &[u8], server_mac: MacAddr) -> Option<Vec<u8>> {
        let msg = DhcpMessage::parse(reply).ok()?;
        if msg.op != BOOTREPLY {
            return None;
        }
        let (dst_ip, dst_mac) = if msg.message_type == MessageType::Nak
            || msg.broadcast()
            || msg.ciaddr.is_unspecified()
        {
            (Ipv4Addr::BROADCAST, MacAddr::BROADCAST)
        } else {
            (msg.ciaddr, msg.chaddr)
        };
        let packet = udp_packet(
            SocketAddr::from((self.config.server_ip, SERVER_PORT)),
            SocketAddr::from((dst_ip, CLIENT_PORT)),
            reply,
        )
        .ok()?;
        let packet = packet.as_packet();
        let mut out = frame::start(dst_mac, server_mac, EtherType::IPV4, packet.len());
        out.extend_from_slice(packet);
        Some(out)
    }
}

/// Appends option `code` with `data` (at most 255 bytes are kept).
fn push_option(out: &mut Vec<u8>, code: u8, data: &[u8]) {
    let data = data.get(..usize::from(u8::MAX)).unwrap_or(data);
    out.push(code);
    out.push(u8::try_from(data.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Frame;
    use nsplane_packet::{Ipv4Header, UdpHeader, protocol};

    const SERVER_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const GUEST_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    const OTHER_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]);
    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

    fn server() -> DhcpServer {
        DhcpServer::new(DhcpConfig {
            router: Some(SERVER_IP),
            dns: vec![Ipv4Addr::new(10, 0, 2, 3), Ipv4Addr::new(1, 1, 1, 1)],
            mtu: Some(1400),
            ..DhcpConfig::new(SERVER_IP, GUEST_IP, 24)
        })
    }

    /// A client message of type `kind` from `mac`.
    fn client(
        kind: MessageType,
        mac: MacAddr,
        ciaddr: Ipv4Addr,
        flags: u16,
        options: &[(u8, &[u8])],
    ) -> Vec<u8> {
        let mut out = vec![BOOTREQUEST, 1, 6, 0];
        out.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        out.extend_from_slice(&[0, 3]);
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&ciaddr.octets());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&mac.0);
        out.extend_from_slice(&[0; 10 + SNAME_FILE_LEN]);
        out.extend_from_slice(&MAGIC_COOKIE);
        out.extend_from_slice(&[option::MESSAGE_TYPE, 1, kind.to_u8(), option::PAD]);
        for (code, data) in options {
            push_option(&mut out, *code, data);
        }
        out.push(option::END);
        out
    }

    fn discover(mac: MacAddr) -> Vec<u8> {
        client(
            MessageType::Discover,
            mac,
            Ipv4Addr::UNSPECIFIED,
            FLAG_BROADCAST,
            &[],
        )
    }

    fn select(mac: MacAddr, server: Ipv4Addr, requested: Ipv4Addr) -> Vec<u8> {
        client(
            MessageType::Request,
            mac,
            Ipv4Addr::UNSPECIFIED,
            0,
            &[
                (option::SERVER_ID, &server.octets()),
                (option::REQUESTED_IP, &requested.octets()),
            ],
        )
    }

    fn u32_option(msg: &DhcpMessage<'_>, code: u8) -> u32 {
        u32::from_be_bytes(msg.option(code).unwrap().try_into().unwrap())
    }

    fn check_config_options(msg: &DhcpMessage<'_>) {
        assert_eq!(msg.server_id(), Some(SERVER_IP));
        assert_eq!(
            msg.option(option::SUBNET_MASK),
            Some(&[255, 255, 255, 0][..])
        );
        assert_eq!(msg.option(option::ROUTER), Some(&SERVER_IP.octets()[..]));
        assert_eq!(
            msg.option(option::DNS),
            Some(&[10, 0, 2, 3, 1, 1, 1, 1][..])
        );
        assert_eq!(msg.option(option::MTU), Some(&1400u16.to_be_bytes()[..]));
    }

    fn check_lease_options(msg: &DhcpMessage<'_>) {
        assert_eq!(u32_option(msg, option::LEASE_TIME), 86_400);
        assert_eq!(u32_option(msg, option::RENEWAL_TIME), 43_200);
        assert_eq!(u32_option(msg, option::REBINDING_TIME), 75_600);
    }

    #[test]
    fn full_exchange() {
        let mut server = server();

        let offer = server.handle(&discover(GUEST_MAC), GUEST_MAC).unwrap();
        assert!(offer.len() >= MIN_MESSAGE_LEN);
        let msg = DhcpMessage::parse(&offer).unwrap();
        assert_eq!(msg.op, BOOTREPLY);
        assert_eq!(msg.message_type, MessageType::Offer);
        assert_eq!(msg.xid, 0x1234_5678);
        assert!(msg.broadcast());
        assert_eq!(msg.yiaddr, GUEST_IP);
        assert_eq!(msg.ciaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(msg.chaddr, GUEST_MAC);
        check_config_options(&msg);
        check_lease_options(&msg);
        assert_eq!(server.bound(), None);

        let ack = server
            .handle(&select(GUEST_MAC, SERVER_IP, GUEST_IP), GUEST_MAC)
            .unwrap();
        let msg = DhcpMessage::parse(&ack).unwrap();
        assert_eq!(msg.message_type, MessageType::Ack);
        assert_eq!(msg.yiaddr, GUEST_IP);
        assert!(!msg.broadcast());
        check_config_options(&msg);
        check_lease_options(&msg);
        assert_eq!(server.bound(), Some(GUEST_MAC));

        // Renewal: ciaddr set, no server id, no requested address.
        let renew = client(MessageType::Request, GUEST_MAC, GUEST_IP, 0, &[]);
        let ack = server.handle(&renew, GUEST_MAC).unwrap();
        let msg = DhcpMessage::parse(&ack).unwrap();
        assert_eq!(msg.message_type, MessageType::Ack);
        assert_eq!(msg.ciaddr, GUEST_IP);
        assert_eq!(msg.yiaddr, GUEST_IP);
    }

    #[test]
    fn init_reboot_acked() {
        let mut server = server();
        let reboot = client(
            MessageType::Request,
            GUEST_MAC,
            Ipv4Addr::UNSPECIFIED,
            0,
            &[(option::REQUESTED_IP, &GUEST_IP.octets())],
        );
        let ack = server.handle(&reboot, GUEST_MAC).unwrap();
        assert_eq!(
            DhcpMessage::parse(&ack).unwrap().message_type,
            MessageType::Ack
        );
        assert_eq!(server.bound(), Some(GUEST_MAC));
    }

    #[test]
    fn nak_on_wrong_requested_ip() {
        let mut server = server();
        let nak = server
            .handle(
                &select(GUEST_MAC, SERVER_IP, Ipv4Addr::new(10, 0, 2, 99)),
                GUEST_MAC,
            )
            .unwrap();
        let msg = DhcpMessage::parse(&nak).unwrap();
        assert_eq!(msg.message_type, MessageType::Nak);
        assert_eq!(msg.yiaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(msg.server_id(), Some(SERVER_IP));
        assert_eq!(msg.option(option::LEASE_TIME), None);
        assert_eq!(msg.option(option::SUBNET_MASK), None);
        assert_eq!(server.bound(), None);
    }

    #[test]
    fn other_server_id_ignored() {
        let mut server = server();
        let other = Ipv4Addr::new(10, 0, 2, 1);
        assert_eq!(
            server.handle(&select(GUEST_MAC, other, GUEST_IP), GUEST_MAC),
            None
        );
        assert_eq!(server.bound(), None);
    }

    #[test]
    fn second_mac_refused() {
        let mut server = server();
        server
            .handle(&select(GUEST_MAC, SERVER_IP, GUEST_IP), GUEST_MAC)
            .unwrap();
        assert_eq!(server.handle(&discover(OTHER_MAC), OTHER_MAC), None);
        let nak = server
            .handle(&select(OTHER_MAC, SERVER_IP, GUEST_IP), OTHER_MAC)
            .unwrap();
        assert_eq!(
            DhcpMessage::parse(&nak).unwrap().message_type,
            MessageType::Nak
        );
        assert_eq!(server.bound(), Some(GUEST_MAC));
        // A release from the other MAC does not free the lease.
        let release = client(
            MessageType::Release,
            OTHER_MAC,
            GUEST_IP,
            0,
            &[(option::SERVER_ID, &SERVER_IP.octets())],
        );
        assert_eq!(server.handle(&release, OTHER_MAC), None);
        assert_eq!(server.bound(), Some(GUEST_MAC));
    }

    #[test]
    fn release_then_new_discover() {
        let mut server = server();
        server
            .handle(&select(GUEST_MAC, SERVER_IP, GUEST_IP), GUEST_MAC)
            .unwrap();
        let release = client(
            MessageType::Release,
            GUEST_MAC,
            GUEST_IP,
            0,
            &[(option::SERVER_ID, &SERVER_IP.octets())],
        );
        assert_eq!(server.handle(&release, GUEST_MAC), None);
        assert_eq!(server.bound(), None);
        let offer = server.handle(&discover(OTHER_MAC), OTHER_MAC).unwrap();
        assert_eq!(
            DhcpMessage::parse(&offer).unwrap().message_type,
            MessageType::Offer
        );
        server
            .handle(&select(OTHER_MAC, SERVER_IP, GUEST_IP), OTHER_MAC)
            .unwrap();
        assert_eq!(server.bound(), Some(OTHER_MAC));
    }

    #[test]
    fn decline_frees_lease() {
        let mut server = server();
        server
            .handle(&select(GUEST_MAC, SERVER_IP, GUEST_IP), GUEST_MAC)
            .unwrap();
        let decline = client(
            MessageType::Decline,
            GUEST_MAC,
            Ipv4Addr::UNSPECIFIED,
            0,
            &[
                (option::SERVER_ID, &SERVER_IP.octets()),
                (option::REQUESTED_IP, &GUEST_IP.octets()),
            ],
        );
        assert_eq!(server.handle(&decline, GUEST_MAC), None);
        assert_eq!(server.bound(), None);
    }

    #[test]
    fn inform_acked_without_lease() {
        let mut server = server();
        let inform = client(MessageType::Inform, GUEST_MAC, GUEST_IP, 0, &[]);
        let ack = server.handle(&inform, GUEST_MAC).unwrap();
        let msg = DhcpMessage::parse(&ack).unwrap();
        assert_eq!(msg.message_type, MessageType::Ack);
        assert_eq!(msg.ciaddr, GUEST_IP);
        assert_eq!(msg.yiaddr, Ipv4Addr::UNSPECIFIED);
        check_config_options(&msg);
        assert_eq!(msg.option(option::LEASE_TIME), None);
        assert_eq!(msg.option(option::RENEWAL_TIME), None);
        assert_eq!(msg.option(option::REBINDING_TIME), None);
        assert_eq!(server.bound(), None);

        // Unicast to ciaddr at chaddr.
        let frame = server.reply_frame(&ack, SERVER_MAC).unwrap();
        let eth = Frame::parse(&frame).unwrap();
        assert_eq!(eth.dst, GUEST_MAC);
        let (ip, _) = Ipv4Header::parse(eth.payload).unwrap();
        assert_eq!(ip.dst(), GUEST_IP);
    }

    #[test]
    fn reply_frame_broadcast() {
        let mut server = server();
        let offer = server.handle(&discover(GUEST_MAC), GUEST_MAC).unwrap();
        let frame = server.reply_frame(&offer, SERVER_MAC).unwrap();
        let eth = Frame::parse(&frame).unwrap();
        assert_eq!(eth.dst, MacAddr::BROADCAST);
        assert_eq!(eth.src, SERVER_MAC);
        assert_eq!(eth.ethertype, EtherType::IPV4);
        let (ip, segment) = Ipv4Header::parse(eth.payload).unwrap();
        assert_eq!(ip.protocol(), protocol::UDP);
        assert_eq!(ip.src(), SERVER_IP);
        assert_eq!(ip.dst(), Ipv4Addr::BROADCAST);
        let (udp, payload) = UdpHeader::parse(segment).unwrap();
        assert_eq!(udp.src_port(), SERVER_PORT);
        assert_eq!(udp.dst_port(), CLIENT_PORT);
        assert_eq!(payload, offer.as_slice());

        // Requests are not replies.
        assert_eq!(server.reply_frame(&discover(GUEST_MAC), SERVER_MAC), None);
    }

    #[test]
    fn malformed_ignored() {
        let mut server = server();
        let bytes = discover(GUEST_MAC);
        for len in 0..240 {
            assert_eq!(DhcpMessage::parse(&bytes[..len]), Err(DhcpError::Truncated));
            assert_eq!(server.handle(&bytes[..len], GUEST_MAC), None);
        }
        // Options cut off mid option.
        let mut cut = bytes[..240].to_vec();
        cut.extend_from_slice(&[option::MESSAGE_TYPE, 1, 1, option::DNS, 8, 1, 2]);
        assert_eq!(DhcpMessage::parse(&cut), Err(DhcpError::BadOption));

        let mut bad = bytes.clone();
        bad[236] = 0;
        assert_eq!(DhcpMessage::parse(&bad), Err(DhcpError::BadCookie));
        let mut bad = bytes.clone();
        bad[1] = 6;
        assert_eq!(DhcpMessage::parse(&bad), Err(DhcpError::Unsupported));
        let mut bad = bytes;
        bad[242] = 42;
        assert_eq!(DhcpMessage::parse(&bad), Err(DhcpError::BadMessageType));
        let no_type = client(
            MessageType::Discover,
            GUEST_MAC,
            Ipv4Addr::UNSPECIFIED,
            0,
            &[],
        );
        let mut no_type = no_type[..240].to_vec();
        no_type.push(option::END);
        assert_eq!(DhcpMessage::parse(&no_type), Err(DhcpError::BadMessageType));
    }

    #[test]
    fn netmask() {
        let mut config = DhcpConfig::new(SERVER_IP, GUEST_IP, 0);
        assert_eq!(config.netmask(), Ipv4Addr::UNSPECIFIED);
        config.prefix_len = 30;
        assert_eq!(config.netmask(), Ipv4Addr::new(255, 255, 255, 252));
        config.prefix_len = 40;
        assert_eq!(config.netmask(), Ipv4Addr::BROADCAST);
    }
}
