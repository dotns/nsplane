//! IPv6 neighbor discovery (RFC 4861) for the gateway side of the link.
//!
//! [`Ndp::parse`] takes an IPv6 packet (an ethernet payload) and picks out router
//! solicitations, neighbor solicitations and neighbor advertisements with their link-layer
//! address options. A message is accepted only if it validates as RFC 4861 section 6.1 / 7.1
//! requires: hop limit 255, a correct `ICMPv6` checksum, code 0, well-formed options.
//!
//! The builders return whole ethernet frames, sent with hop limit 255:
//!
//! - [`answer_neighbor_solicitation`]: a neighbor advertisement (router and override flags
//!   set) for a target address the adapter owns. A solicitation from the unspecified address
//!   (duplicate address detection) is answered to all-nodes without the solicited flag.
//! - [`answer_router_solicitation`] and [`router_advertisement`]: a router advertisement from
//!   the link-local address of the adapter MAC, built from a [`RaConfig`].

use std::fmt;
use std::net::Ipv6Addr;

use nsplane_packet::checksum::transport_checksum_v6;
use nsplane_packet::{Ipv6Header, Malformed, protocol};

use crate::MacAddr;
use crate::frame::{self, EtherType};
use crate::read::Reader;

/// The all-nodes multicast address `ff02::1`.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// `ICMPv6` message types.
const ROUTER_SOLICITATION: u8 = 133;
const ROUTER_ADVERTISEMENT: u8 = 134;
const NEIGHBOR_SOLICITATION: u8 = 135;
const NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// Option types.
const OPT_SOURCE_LL: u8 = 1;
const OPT_TARGET_LL: u8 = 2;
const OPT_PREFIX: u8 = 3;
const OPT_MTU: u8 = 5;
const OPT_RDNSS: u8 = 25;

/// Neighbor advertisement flags.
const FLAG_ROUTER: u8 = 0x80;
const FLAG_SOLICITED: u8 = 0x40;
const FLAG_OVERRIDE: u8 = 0x20;

/// Prefix information flags: on-link and autonomous address configuration.
const FLAG_ON_LINK: u8 = 0x80;
const FLAG_AUTONOMOUS: u8 = 0x40;

/// Hop limit of every neighbor discovery message.
const HOP_LIMIT: u8 = 255;
/// Current hop limit advertised to the guest.
const CUR_HOP_LIMIT: u8 = 64;
/// Length of the IPv6 fixed header.
const IPV6_HEADER_LEN: usize = 40;
/// Most DNS servers one RDNSS option can carry (its length is 8-byte units in one byte).
const MAX_DNS: usize = 127;

/// Why a neighbor discovery message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NdpError {
    /// The packet or the message is shorter than its headers declare.
    Truncated,
    /// The IPv6 hop limit is not 255, so the message did not originate on the link.
    HopLimit,
    /// The `ICMPv6` checksum does not verify.
    Checksum,
    /// The packet is not IPv6 or the message breaks a validity rule of RFC 4861: nonzero
    /// code, zero-length option, multicast target, a link-layer address option or a
    /// non-solicited-node destination with the unspecified source, a solicited
    /// advertisement to multicast.
    Invalid,
}

impl fmt::Display for NdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "neighbor discovery message truncated",
            Self::HopLimit => "neighbor discovery hop limit is not 255",
            Self::Checksum => "bad ICMPv6 checksum",
            Self::Invalid => "invalid neighbor discovery message",
        })
    }
}

impl std::error::Error for NdpError {}

/// A neighbor discovery message the gateway acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NdpMessage {
    /// Router solicitation (type 133).
    RouterSolicitation {
        /// Source link-layer address option.
        source_mac: Option<MacAddr>,
    },
    /// Neighbor solicitation (type 135).
    NeighborSolicitation {
        /// Address whose link-layer address is asked for.
        target: Ipv6Addr,
        /// Source link-layer address option.
        source_mac: Option<MacAddr>,
    },
    /// Neighbor advertisement (type 136).
    NeighborAdvertisement {
        /// Address being advertised.
        target: Ipv6Addr,
        /// Target link-layer address option.
        target_mac: Option<MacAddr>,
        /// The sender is a router.
        router: bool,
        /// Sent in response to a solicitation.
        solicited: bool,
        /// Overrides an existing cache entry.
        override_entry: bool,
    },
}

/// A neighbor discovery message with the IPv6 addresses it travelled between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ndp {
    /// IPv6 source address.
    pub src: Ipv6Addr,
    /// IPv6 destination address.
    pub dst: Ipv6Addr,
    /// The message.
    pub message: NdpMessage,
}

impl Ndp {
    /// Parses the IPv6 packet `packet`.
    ///
    /// Returns `Ok(None)` for a packet that is not a router solicitation, neighbor
    /// solicitation or neighbor advertisement (another next header or `ICMPv6` type);
    /// extension headers are not walked.
    ///
    /// # Errors
    ///
    /// [`NdpError`] for a malformed IPv6 packet or a neighbor discovery message that fails
    /// validation.
    pub fn parse(packet: &[u8]) -> Result<Option<Self>, NdpError> {
        let (ip, icmp) = Ipv6Header::parse(packet).map_err(|err| match err {
            Malformed::Truncated => NdpError::Truncated,
            _ => NdpError::Invalid,
        })?;
        if ip.next_header() != protocol::ICMPV6 {
            return Ok(None);
        }
        let Some(&kind) = icmp.first() else {
            return Ok(None);
        };
        if !matches!(
            kind,
            ROUTER_SOLICITATION | NEIGHBOR_SOLICITATION | NEIGHBOR_ADVERTISEMENT
        ) {
            return Ok(None);
        }
        let (src, dst) = (ip.src(), ip.dst());
        if ip.hop_limit() != HOP_LIMIT {
            return Err(NdpError::HopLimit);
        }
        if transport_checksum_v6(src, dst, protocol::ICMPV6, icmp) != 0 {
            return Err(NdpError::Checksum);
        }
        let mut r = Reader::new(icmp);
        let header = r.array::<4>().ok_or(NdpError::Truncated)?;
        if header[1] != 0 {
            return Err(NdpError::Invalid);
        }
        let message = match kind {
            ROUTER_SOLICITATION => {
                r.array::<4>().ok_or(NdpError::Truncated)?;
                let source_mac = link_layer_option(r.rest(), OPT_SOURCE_LL)?;
                if src.is_unspecified() && source_mac.is_some() {
                    return Err(NdpError::Invalid);
                }
                NdpMessage::RouterSolicitation { source_mac }
            }
            NEIGHBOR_SOLICITATION => {
                r.array::<4>().ok_or(NdpError::Truncated)?;
                let target = r.ipv6().ok_or(NdpError::Truncated)?;
                let source_mac = link_layer_option(r.rest(), OPT_SOURCE_LL)?;
                if target.is_multicast()
                    || (src.is_unspecified() && (source_mac.is_some() || !is_solicited_node(dst)))
                {
                    return Err(NdpError::Invalid);
                }
                NdpMessage::NeighborSolicitation { target, source_mac }
            }
            _ => {
                let flags = r.u8().ok_or(NdpError::Truncated)?;
                r.array::<3>().ok_or(NdpError::Truncated)?;
                let target = r.ipv6().ok_or(NdpError::Truncated)?;
                let target_mac = link_layer_option(r.rest(), OPT_TARGET_LL)?;
                let solicited = flags & FLAG_SOLICITED != 0;
                if target.is_multicast() || (solicited && dst.is_multicast()) {
                    return Err(NdpError::Invalid);
                }
                NdpMessage::NeighborAdvertisement {
                    target,
                    target_mac,
                    router: flags & FLAG_ROUTER != 0,
                    solicited,
                    override_entry: flags & FLAG_OVERRIDE != 0,
                }
            }
        };
        Ok(Some(Self { src, dst, message }))
    }
}

/// Whether `addr` is a solicited-node multicast address `ff02::1:ffXX:XXXX`.
const fn is_solicited_node(addr: Ipv6Addr) -> bool {
    matches!(
        addr.octets(),
        [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, ..]
    )
}

/// Walks the options in `bytes` and returns the first link-layer address option of type
/// `wanted` that carries an ethernet address.
fn link_layer_option(bytes: &[u8], wanted: u8) -> Result<Option<MacAddr>, NdpError> {
    let mut r = Reader::new(bytes);
    let mut found = None;
    while !r.is_empty() {
        let [kind, units] = r.array().ok_or(NdpError::Truncated)?;
        if units == 0 {
            return Err(NdpError::Invalid);
        }
        let body = r
            .slice(usize::from(units) * 8 - 2)
            .ok_or(NdpError::Truncated)?;
        if kind == wanted
            && found.is_none()
            && let Some(mac) = body.first_chunk::<6>()
        {
            found = Some(MacAddr(*mac));
        }
    }
    Ok(found)
}

/// Router advertisement contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaConfig {
    /// Router lifetime in seconds; also the lifetime of the advertised DNS servers.
    pub router_lifetime: u16,
    /// Link MTU in the MTU option.
    pub mtu: u32,
    /// The /64 announced in a prefix information option (on-link and autonomous); bits
    /// past the first 64 are ignored. `None` sends no prefix option.
    pub prefix: Option<Ipv6Addr>,
    /// Valid lifetime of the prefix in seconds.
    pub valid_lifetime: u32,
    /// Preferred lifetime of the prefix in seconds.
    pub preferred_lifetime: u32,
    /// DNS servers in a recursive DNS server option (RFC 8106); empty sends none, at most
    /// the first 127 are sent.
    pub dns: Vec<Ipv6Addr>,
}

impl Default for RaConfig {
    /// Router lifetime 1800 s, MTU 1500, no prefix, prefix lifetimes of RFC 4861
    /// (valid 30 days, preferred 7 days), no DNS servers.
    fn default() -> Self {
        Self {
            router_lifetime: 1800,
            mtu: 1500,
            prefix: None,
            valid_lifetime: 2_592_000,
            preferred_lifetime: 604_800,
            dns: Vec::new(),
        }
    }
}

/// The neighbor advertisement answering `request` if it is a neighbor solicitation for one
/// of `ours`, as an ethernet frame from `our_mac`.
///
/// The advertisement comes from the target address with the router and override flags and
/// a target link-layer address option. It goes to the solicitor, at the MAC of its source
/// link-layer address option or else `peer_mac` (the source MAC of the frame that carried
/// the request), with the solicited flag; a solicitation from the unspecified address goes
/// to all-nodes without it (RFC 4861 section 7.2.4).
pub fn answer_neighbor_solicitation(
    request: &Ndp,
    peer_mac: MacAddr,
    our_mac: MacAddr,
    ours: &[Ipv6Addr],
) -> Option<Vec<u8>> {
    let NdpMessage::NeighborSolicitation { target, source_mac } = request.message else {
        return None;
    };
    if !ours.contains(&target) {
        return None;
    }
    let (dst, dst_mac, flags) = if request.src.is_unspecified() {
        (
            ALL_NODES,
            MacAddr::ipv6_multicast(ALL_NODES),
            FLAG_ROUTER | FLAG_OVERRIDE,
        )
    } else {
        (
            request.src,
            source_mac.unwrap_or(peer_mac),
            FLAG_ROUTER | FLAG_SOLICITED | FLAG_OVERRIDE,
        )
    };
    let mut icmp = Vec::with_capacity(32);
    icmp.extend_from_slice(&[NEIGHBOR_ADVERTISEMENT, 0, 0, 0, flags, 0, 0, 0]);
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[OPT_TARGET_LL, 1]);
    icmp.extend_from_slice(&our_mac.0);
    Some(icmpv6_frame(our_mac, dst_mac, target, dst, icmp))
}

/// The router advertisement answering `request` if it is a router solicitation.
///
/// It goes unicast to the solicitor (at the MAC of its source link-layer address option or
/// else `peer_mac`), or to all-nodes if the solicitation came from the unspecified address.
/// See [`router_advertisement`].
pub fn answer_router_solicitation(
    request: &Ndp,
    peer_mac: MacAddr,
    our_mac: MacAddr,
    config: &RaConfig,
) -> Option<Vec<u8>> {
    let NdpMessage::RouterSolicitation { source_mac } = request.message else {
        return None;
    };
    let (dst, dst_mac) = if request.src.is_unspecified() {
        (ALL_NODES, MacAddr::ipv6_multicast(ALL_NODES))
    } else {
        (request.src, source_mac.unwrap_or(peer_mac))
    };
    Some(router_advertisement(config, our_mac, dst, dst_mac))
}

/// A router advertisement from the link-local address of `our_mac` to `dst` at `dst_mac`,
/// as an ethernet frame; pass [`ALL_NODES`] and its multicast MAC for an unsolicited one.
///
/// Header: current hop limit 64, managed and other-configuration flags clear, router
/// lifetime from `config`, reachable time and retransmission timer unspecified. Options in
/// order: source link-layer address, MTU, prefix information (if set), recursive DNS server
/// (if any).
pub fn router_advertisement(
    config: &RaConfig,
    our_mac: MacAddr,
    dst: Ipv6Addr,
    dst_mac: MacAddr,
) -> Vec<u8> {
    let dns = config.dns.get(..MAX_DNS).unwrap_or(&config.dns);
    let mut icmp = Vec::with_capacity(16 + 8 + 8 + 32 + 8 + 16 * dns.len());
    icmp.extend_from_slice(&[ROUTER_ADVERTISEMENT, 0, 0, 0, CUR_HOP_LIMIT, 0]);
    icmp.extend_from_slice(&config.router_lifetime.to_be_bytes());
    icmp.extend_from_slice(&[0; 8]);

    icmp.extend_from_slice(&[OPT_SOURCE_LL, 1]);
    icmp.extend_from_slice(&our_mac.0);

    icmp.extend_from_slice(&[OPT_MTU, 1, 0, 0]);
    icmp.extend_from_slice(&config.mtu.to_be_bytes());

    if let Some(prefix) = config.prefix {
        let [network @ .., _, _, _, _, _, _, _, _] = prefix.octets();
        icmp.extend_from_slice(&[OPT_PREFIX, 4, 64, FLAG_ON_LINK | FLAG_AUTONOMOUS]);
        icmp.extend_from_slice(&config.valid_lifetime.to_be_bytes());
        icmp.extend_from_slice(&config.preferred_lifetime.to_be_bytes());
        icmp.extend_from_slice(&[0; 4]);
        icmp.extend_from_slice(&network);
        icmp.extend_from_slice(&[0; 8]);
    }

    if !dns.is_empty() {
        let units = u8::try_from(1 + 2 * dns.len()).unwrap_or(u8::MAX);
        icmp.extend_from_slice(&[OPT_RDNSS, units, 0, 0]);
        icmp.extend_from_slice(&u32::from(config.router_lifetime).to_be_bytes());
        for server in dns {
            icmp.extend_from_slice(&server.octets());
        }
    }
    icmpv6_frame(our_mac, dst_mac, our_mac.link_local(), dst, icmp)
}

/// Fills in the checksum of the `ICMPv6` message `icmp` and wraps it in IPv6 (hop limit 255)
/// and ethernet.
fn icmpv6_frame(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    mut icmp: Vec<u8>,
) -> Vec<u8> {
    let sum = transport_checksum_v6(src, dst, protocol::ICMPV6, &icmp);
    if let Some(field) = icmp.get_mut(2..4) {
        field.copy_from_slice(&sum.to_be_bytes());
    }
    // The builders stay far below 64 KiB: at most 127 DNS servers.
    let len = u16::try_from(icmp.len()).unwrap_or(u16::MAX);
    let mut out = frame::start(
        dst_mac,
        src_mac,
        EtherType::IPV6,
        IPV6_HEADER_LEN + icmp.len(),
    );
    out.extend_from_slice(&[0x60, 0, 0, 0]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[protocol::ICMPV6, HOP_LIMIT]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&icmp);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Frame;
    use crate::frame::HEADER_LEN;

    const GW_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const GUEST_MAC: MacAddr = MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn gw_global() -> Ipv6Addr {
        addr("fd00:1::1")
    }

    fn guest_ll() -> Ipv6Addr {
        GUEST_MAC.link_local()
    }

    fn solicited_node(target: Ipv6Addr) -> Ipv6Addr {
        let [.., a, b, c] = target.octets();
        Ipv6Addr::from([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, a, b, c])
    }

    /// An IPv6 packet carrying `icmp` with a correct checksum.
    fn packet(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8, mut icmp: Vec<u8>) -> Vec<u8> {
        icmp[2..4].fill(0);
        let sum = transport_checksum_v6(src, dst, protocol::ICMPV6, &icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        let mut out = vec![0x60, 0, 0, 0];
        out.extend_from_slice(&u16::try_from(icmp.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&[protocol::ICMPV6, hop_limit]);
        out.extend_from_slice(&src.octets());
        out.extend_from_slice(&dst.octets());
        out.extend_from_slice(&icmp);
        out
    }

    fn ns(target: Ipv6Addr, slla: Option<MacAddr>) -> Vec<u8> {
        let mut icmp = vec![NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&target.octets());
        if let Some(mac) = slla {
            icmp.extend_from_slice(&[OPT_SOURCE_LL, 1]);
            icmp.extend_from_slice(&mac.0);
        }
        icmp
    }

    fn rs(slla: Option<MacAddr>) -> Vec<u8> {
        let mut icmp = vec![ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0];
        if let Some(mac) = slla {
            icmp.extend_from_slice(&[OPT_SOURCE_LL, 1]);
            icmp.extend_from_slice(&mac.0);
        }
        icmp
    }

    /// Splits a built frame into ethernet, IPv6 header and `ICMPv6` message, checking the
    /// framing and recomputing the checksum.
    fn open(frame: &[u8]) -> (Frame<'_>, Ipv6Addr, Ipv6Addr, &[u8]) {
        let eth = Frame::parse(frame).unwrap();
        assert_eq!(eth.ethertype, EtherType::IPV6);
        let (ip, icmp) = Ipv6Header::parse(eth.payload).unwrap();
        assert_eq!(ip.next_header(), protocol::ICMPV6);
        assert_eq!(ip.hop_limit(), 255);
        assert_eq!(usize::from(ip.payload_len()), icmp.len());
        assert_eq!(frame.len(), HEADER_LEN + IPV6_HEADER_LEN + icmp.len());
        // Recompute: zero the field, compare with the carried value.
        let mut zeroed = icmp.to_vec();
        zeroed[2..4].fill(0);
        let sum = transport_checksum_v6(ip.src(), ip.dst(), protocol::ICMPV6, &zeroed);
        assert_eq!(icmp[2..4], sum.to_be_bytes());
        assert_eq!(
            transport_checksum_v6(ip.src(), ip.dst(), protocol::ICMPV6, icmp),
            0
        );
        (eth, ip.src(), ip.dst(), icmp)
    }

    #[test]
    fn parses_ns_with_slla() {
        let bytes = packet(
            guest_ll(),
            solicited_node(gw_global()),
            255,
            ns(gw_global(), Some(GUEST_MAC)),
        );
        let msg = Ndp::parse(&bytes).unwrap().unwrap();
        assert_eq!(msg.src, guest_ll());
        assert_eq!(
            msg.message,
            NdpMessage::NeighborSolicitation {
                target: gw_global(),
                source_mac: Some(GUEST_MAC),
            }
        );
    }

    #[test]
    fn ns_for_our_address_answered() {
        let bytes = packet(
            guest_ll(),
            solicited_node(gw_global()),
            255,
            ns(gw_global(), Some(GUEST_MAC)),
        );
        let msg = Ndp::parse(&bytes).unwrap().unwrap();
        let other_mac = MacAddr([0x02, 0, 0, 0, 0, 9]);
        let out = answer_neighbor_solicitation(
            &msg,
            other_mac,
            GW_MAC,
            &[GW_MAC.link_local(), gw_global()],
        )
        .unwrap();
        let (eth, src, dst, icmp) = open(&out);
        // The source link-layer option wins over the frame source MAC.
        assert_eq!(eth.dst, GUEST_MAC);
        assert_eq!(eth.src, GW_MAC);
        assert_eq!(src, gw_global());
        assert_eq!(dst, guest_ll());
        assert_eq!(icmp.len(), 32);
        assert_eq!(icmp[0], NEIGHBOR_ADVERTISEMENT);
        assert_eq!(icmp[1], 0);
        assert_eq!(icmp[4], FLAG_ROUTER | FLAG_SOLICITED | FLAG_OVERRIDE);
        assert_eq!(icmp[8..24], gw_global().octets());
        assert_eq!(icmp[24..26], [OPT_TARGET_LL, 1]);
        assert_eq!(icmp[26..32], GW_MAC.0);

        // Our own parser accepts it as an advertisement.
        let parsed = Ndp::parse(eth.payload).unwrap().unwrap();
        assert_eq!(
            parsed.message,
            NdpMessage::NeighborAdvertisement {
                target: gw_global(),
                target_mac: Some(GW_MAC),
                router: true,
                solicited: true,
                override_entry: true,
            }
        );
    }

    #[test]
    fn ns_without_slla_uses_peer_mac() {
        let target = GW_MAC.link_local();
        let bytes = packet(guest_ll(), solicited_node(target), 255, ns(target, None));
        let msg = Ndp::parse(&bytes).unwrap().unwrap();
        let out = answer_neighbor_solicitation(&msg, GUEST_MAC, GW_MAC, &[target]).unwrap();
        let (eth, src, _, _) = open(&out);
        assert_eq!(eth.dst, GUEST_MAC);
        assert_eq!(src, target);
    }

    #[test]
    fn ns_for_foreign_address_ignored() {
        let foreign = addr("fd00:1::99");
        let bytes = packet(
            guest_ll(),
            solicited_node(foreign),
            255,
            ns(foreign, Some(GUEST_MAC)),
        );
        let msg = Ndp::parse(&bytes).unwrap().unwrap();
        assert_eq!(
            answer_neighbor_solicitation(&msg, GUEST_MAC, GW_MAC, &[gw_global()]),
            None
        );
    }

    #[test]
    fn dad_ns_handling() {
        // DAD for our own address: answered to all-nodes, not solicited.
        let ours = gw_global();
        let bytes = packet(
            Ipv6Addr::UNSPECIFIED,
            solicited_node(ours),
            255,
            ns(ours, None),
        );
        let msg = Ndp::parse(&bytes).unwrap().unwrap();
        let out = answer_neighbor_solicitation(&msg, GUEST_MAC, GW_MAC, &[ours]).unwrap();
        let (eth, src, dst, icmp) = open(&out);
        assert_eq!(eth.dst, MacAddr([0x33, 0x33, 0, 0, 0, 1]));
        assert_eq!(src, ours);
        assert_eq!(dst, ALL_NODES);
        assert_eq!(icmp[4], FLAG_ROUTER | FLAG_OVERRIDE);

        // DAD by the guest for its own address: not answered.
        let theirs = addr("fd00:1::15");
        let bytes = packet(
            Ipv6Addr::UNSPECIFIED,
            solicited_node(theirs),
            255,
            ns(theirs, None),
        );
        let msg = Ndp::parse(&bytes).unwrap().unwrap();
        assert_eq!(
            answer_neighbor_solicitation(&msg, GUEST_MAC, GW_MAC, &[ours]),
            None
        );

        // DAD with a source link-layer option or to a unicast destination is invalid.
        let bytes = packet(
            Ipv6Addr::UNSPECIFIED,
            solicited_node(ours),
            255,
            ns(ours, Some(GUEST_MAC)),
        );
        assert_eq!(Ndp::parse(&bytes), Err(NdpError::Invalid));
        let bytes = packet(Ipv6Addr::UNSPECIFIED, ours, 255, ns(ours, None));
        assert_eq!(Ndp::parse(&bytes), Err(NdpError::Invalid));
    }

    #[test]
    fn rs_to_ra_with_all_options() {
        let bytes = packet(guest_ll(), addr("ff02::2"), 255, rs(Some(GUEST_MAC)));
        let msg = Ndp::parse(&bytes).unwrap().unwrap();
        assert_eq!(
            msg.message,
            NdpMessage::RouterSolicitation {
                source_mac: Some(GUEST_MAC)
            }
        );
        let dns = vec![addr("fd00:1::53"), addr("2001:db8::53")];
        let config = RaConfig {
            mtu: 1400,
            prefix: Some(addr("fd00:1::1234")),
            dns: dns.clone(),
            ..RaConfig::default()
        };
        let out = answer_router_solicitation(&msg, GUEST_MAC, GW_MAC, &config).unwrap();
        let (eth, src, dst, icmp) = open(&out);
        assert_eq!((eth.dst, eth.src), (GUEST_MAC, GW_MAC));
        assert_eq!(src, GW_MAC.link_local());
        assert_eq!(dst, guest_ll());

        assert_eq!(icmp[..2], [ROUTER_ADVERTISEMENT, 0]);
        assert_eq!(icmp[4], 64);
        assert_eq!(icmp[5], 0);
        assert_eq!(icmp[6..8], 1800u16.to_be_bytes());
        assert_eq!(icmp[8..16], [0; 8]);
        let opts = &icmp[16..];
        // Source link-layer address.
        assert_eq!(opts[..2], [OPT_SOURCE_LL, 1]);
        assert_eq!(opts[2..8], GW_MAC.0);
        // MTU.
        assert_eq!(opts[8..12], [OPT_MTU, 1, 0, 0]);
        assert_eq!(opts[12..16], 1400u32.to_be_bytes());
        // Prefix information, masked to /64.
        let pi = &opts[16..48];
        assert_eq!(pi[..4], [OPT_PREFIX, 4, 64, 0xc0]);
        assert_eq!(pi[4..8], 2_592_000u32.to_be_bytes());
        assert_eq!(pi[8..12], 604_800u32.to_be_bytes());
        assert_eq!(pi[12..16], [0; 4]);
        assert_eq!(pi[16..32], addr("fd00:1::").octets());
        // RDNSS.
        let rdnss = &opts[48..];
        assert_eq!(rdnss.len(), 8 + 32);
        assert_eq!(rdnss[..4], [OPT_RDNSS, 5, 0, 0]);
        assert_eq!(rdnss[4..8], 1800u32.to_be_bytes());
        assert_eq!(rdnss[8..24], dns[0].octets());
        assert_eq!(rdnss[24..40], dns[1].octets());
    }

    #[test]
    fn minimal_ra_to_all_nodes() {
        let bytes = packet(Ipv6Addr::UNSPECIFIED, addr("ff02::2"), 255, rs(None));
        let msg = Ndp::parse(&bytes).unwrap().unwrap();
        let out =
            answer_router_solicitation(&msg, GUEST_MAC, GW_MAC, &RaConfig::default()).unwrap();
        let (eth, _, dst, icmp) = open(&out);
        assert_eq!(eth.dst, MacAddr::ipv6_multicast(ALL_NODES));
        assert_eq!(dst, ALL_NODES);
        // Header, source link-layer address, MTU; no prefix, no DNS.
        assert_eq!(icmp.len(), 16 + 8 + 8);

        let unsolicited = router_advertisement(
            &RaConfig::default(),
            GW_MAC,
            ALL_NODES,
            MacAddr::ipv6_multicast(ALL_NODES),
        );
        assert_eq!(unsolicited, out);
    }

    #[test]
    fn hop_limit_not_255_rejected() {
        let bytes = packet(guest_ll(), addr("ff02::2"), 64, rs(None));
        assert_eq!(Ndp::parse(&bytes), Err(NdpError::HopLimit));
        let bytes = packet(
            guest_ll(),
            solicited_node(gw_global()),
            1,
            ns(gw_global(), None),
        );
        assert_eq!(Ndp::parse(&bytes), Err(NdpError::HopLimit));
    }

    #[test]
    fn bad_checksum_code_and_options_rejected() {
        let mut bytes = packet(guest_ll(), addr("ff02::2"), 255, rs(Some(GUEST_MAC)));
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(Ndp::parse(&bytes), Err(NdpError::Checksum));

        let mut icmp = rs(None);
        icmp[1] = 1;
        assert_eq!(
            Ndp::parse(&packet(guest_ll(), addr("ff02::2"), 255, icmp)),
            Err(NdpError::Invalid)
        );

        let mut icmp = rs(None);
        icmp.extend_from_slice(&[OPT_SOURCE_LL, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            Ndp::parse(&packet(guest_ll(), addr("ff02::2"), 255, icmp)),
            Err(NdpError::Invalid)
        );

        let mut icmp = rs(None);
        icmp.extend_from_slice(&[OPT_SOURCE_LL, 2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            Ndp::parse(&packet(guest_ll(), addr("ff02::2"), 255, icmp)),
            Err(NdpError::Truncated)
        );

        let mut icmp = ns(gw_global(), None);
        icmp.truncate(20);
        assert_eq!(
            Ndp::parse(&packet(guest_ll(), solicited_node(gw_global()), 255, icmp)),
            Err(NdpError::Truncated)
        );
    }

    #[test]
    fn truncated_packets_never_panic() {
        let bytes = packet(
            guest_ll(),
            solicited_node(gw_global()),
            255,
            ns(gw_global(), Some(GUEST_MAC)),
        );
        for len in 0..bytes.len() {
            assert!(Ndp::parse(&bytes[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn non_ndp_packets_pass_through() {
        // Echo request.
        let echo = vec![128, 0, 0, 0, 0, 1, 0, 1];
        assert_eq!(
            Ndp::parse(&packet(guest_ll(), gw_global(), 64, echo)),
            Ok(None)
        );
        // UDP.
        let mut udp = packet(guest_ll(), gw_global(), 64, vec![0; 8]);
        udp[6] = protocol::UDP;
        assert_eq!(Ndp::parse(&udp), Ok(None));
        // Not IPv6.
        assert_eq!(Ndp::parse(&[0x45; 40]), Err(NdpError::Invalid));
    }
}
