//! Tests of the port map filter, adapted from ns `packet_nat` tests (forward
//! and reverse NAT, conntrack reuse, checksums) to the `PacketFilter` form.
//! Every rewritten packet has all its checksums verified by full recompute.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{IpPacket, PacketBuf, PeerId, protocol};

use super::*;
use crate::checksum::{
    internet_checksum, ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6, udp_wire,
};
use crate::conntrack::{ConntrackConfig, TcpState};

const A: PeerId = PeerId::new(1);
const B: PeerId = PeerId::new(2);
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;
const FIN_ACK: u8 = 0x11;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn listen4() -> SocketAddr {
    sa("100.64.0.1:80")
}
fn target4() -> SocketAddr {
    sa("127.0.0.1:8080")
}
fn client4() -> SocketAddr {
    sa("100.64.0.2:40000")
}
fn listen6() -> SocketAddr {
    sa("[fd00::1]:80")
}
fn target6() -> SocketAddr {
    sa("[fd00::10]:8080")
}
fn client6() -> SocketAddr {
    sa("[fd00::2]:40000")
}

fn rule(protocol: PortMapProtocol, listen: SocketAddr, target: SocketAddr) -> PortMapRule {
    PortMapRule {
        protocol,
        listen,
        target,
        peers: None,
    }
}

fn config() -> ConntrackConfig {
    ConntrackConfig {
        max_entries: 16,
        tcp_established_timeout: Duration::from_secs(300),
        tcp_transitory_timeout: Duration::from_secs(30),
        udp_timeout: Duration::from_secs(30),
        icmp_timeout: Duration::from_secs(30),
    }
}

/// A port map whose conntrack clock is moved by hand, with the clock handle.
fn clocked(rules: Vec<PortMapRule>, config: ConntrackConfig) -> (PortMap, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let handle = Arc::clone(&clock);
    let conntrack = Conntrack::with_clock(config, move || *handle.lock().unwrap());
    (PortMap::with_conntrack(rules, conntrack).unwrap(), clock)
}

fn advance(clock: &Mutex<Instant>, secs: u64) {
    *clock.lock().unwrap() += Duration::from_secs(secs);
}

// ── Packet building and checking ──────────────────────────────────────────────

/// An IP packet carrying `transport`, with every checksum filled in.
fn ip(src: IpAddr, dst: IpAddr, proto: u8, mut transport: Vec<u8>) -> Vec<u8> {
    let checksum_at = match proto {
        protocol::TCP => Some(16),
        protocol::UDP => Some(6),
        protocol::ICMP | protocol::ICMPV6 => Some(2),
        _ => None,
    };
    if let Some(at) = checksum_at {
        transport[at..at + 2].fill(0);
        let checksum = match (src, dst, proto) {
            (_, _, protocol::ICMP) => internet_checksum(&transport),
            (IpAddr::V4(s), IpAddr::V4(d), _) => transport_checksum_v4(s, d, proto, &transport),
            (IpAddr::V6(s), IpAddr::V6(d), _) => transport_checksum_v6(s, d, proto, &transport),
            _ => panic!("mixed address families"),
        };
        let checksum = if proto == protocol::UDP {
            udp_wire(checksum)
        } else {
            checksum
        };
        transport[at..at + 2].copy_from_slice(&checksum.to_be_bytes());
    }
    let mut bytes = Vec::new();
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = u16::try_from(20 + transport.len()).unwrap();
            bytes.extend_from_slice(&[0x45, 0]);
            bytes.extend_from_slice(&total.to_be_bytes());
            bytes.extend_from_slice(&[0x12, 0x34, 0x40, 0, 64, proto, 0, 0]);
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
            let checksum = ipv4_header_checksum(&bytes);
            bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let len = u16::try_from(transport.len()).unwrap();
            bytes.extend_from_slice(&[0x60, 0, 0, 0]);
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(&[proto, 64]);
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
        }
        _ => panic!("mixed address families"),
    }
    bytes.extend_from_slice(&transport);
    bytes
}

fn tcp_bytes(src: SocketAddr, dst: SocketAddr, flags: u8) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&src.port().to_be_bytes());
    t.extend_from_slice(&dst.port().to_be_bytes());
    t.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(b"payload");
    ip(src.ip(), dst.ip(), protocol::TCP, t)
}

fn udp_bytes(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let payload = b"hello";
    let len = u16::try_from(8 + payload.len()).unwrap();
    let mut u = Vec::new();
    u.extend_from_slice(&src.port().to_be_bytes());
    u.extend_from_slice(&dst.port().to_be_bytes());
    u.extend_from_slice(&len.to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    ip(src.ip(), dst.ip(), protocol::UDP, u)
}

fn tcp(src: SocketAddr, dst: SocketAddr, flags: u8) -> PacketBuf {
    PacketBuf::from_packet(&tcp_bytes(src, dst, flags))
}

fn udp(src: SocketAddr, dst: SocketAddr) -> PacketBuf {
    PacketBuf::from_packet(&udp_bytes(src, dst))
}

fn packet(proto: PortMapProtocol, src: SocketAddr, dst: SocketAddr) -> PacketBuf {
    match proto {
        PortMapProtocol::Tcp => tcp(src, dst, ACK),
        PortMapProtocol::Udp => udp(src, dst),
    }
}

/// An ICMP (IPv4) or `ICMPv6` error of `icmp_type` quoting `quote`.
fn icmp_error(src: IpAddr, dst: IpAddr, icmp_type: u8, code: u8, quote: &[u8]) -> PacketBuf {
    let mut message = vec![icmp_type, code, 0, 0, 0, 0, 0x05, 0x00];
    message.extend_from_slice(quote);
    let proto = if src.is_ipv4() {
        protocol::ICMP
    } else {
        protocol::ICMPV6
    };
    PacketBuf::from_packet(&ip(src, dst, proto, message))
}

/// The source and destination of a TCP/UDP packet.
fn ends(packet: &PacketBuf) -> (SocketAddr, SocketAddr) {
    let tuple = IpPacket::parse(packet.as_packet())
        .unwrap()
        .five_tuple()
        .unwrap();
    (
        SocketAddr::new(tuple.src, tuple.src_port),
        SocketAddr::new(tuple.dst, tuple.dst_port),
    )
}

/// Asserts that the stored checksum of the transport `segment` (TCP, UDP or
/// ICMP) equals a full recompute.
fn assert_transport_checksum(src: IpAddr, dst: IpAddr, proto: u8, segment: &[u8]) {
    let at = match proto {
        protocol::TCP => 16,
        protocol::UDP => 6,
        _ => 2,
    };
    let stored = u16::from_be_bytes([segment[at], segment[at + 1]]);
    if proto == protocol::UDP && stored == 0 && src.is_ipv4() {
        return;
    }
    let mut zeroed = segment.to_vec();
    zeroed[at..at + 2].fill(0);
    let computed = match (src, dst, proto) {
        (_, _, protocol::ICMP) => internet_checksum(&zeroed),
        (IpAddr::V4(s), IpAddr::V4(d), _) => transport_checksum_v4(s, d, proto, &zeroed),
        (IpAddr::V6(s), IpAddr::V6(d), _) => transport_checksum_v6(s, d, proto, &zeroed),
        _ => panic!("mixed address families"),
    };
    let computed = if proto == protocol::UDP {
        udp_wire(computed)
    } else {
        computed
    };
    assert_eq!(stored, computed, "protocol {proto} checksum");
}

/// Asserts that every checksum of `bytes` (IPv4 header, transport, and for an
/// ICMP error the quoted IPv4 header) equals a full recompute.
fn assert_checksums(bytes: &[u8]) {
    let ip = IpPacket::parse(bytes).unwrap();
    if let IpPacket::V4 { header, .. } = &ip {
        let header_bytes = &bytes[..header.header_len()];
        assert_eq!(
            header.checksum(),
            ipv4_header_checksum(header_bytes),
            "IPv4 header"
        );
    }
    assert_transport_checksum(ip.src(), ip.dst(), ip.protocol(), ip.payload());
    if matches!(ip.protocol(), protocol::ICMP | protocol::ICMPV6) {
        let quoted = &ip.payload()[8..];
        if quoted[0] >> 4 == 4 {
            let stored = u16::from_be_bytes([quoted[10], quoted[11]]);
            assert_eq!(
                stored,
                ipv4_header_checksum(&quoted[..20]),
                "quoted IPv4 header"
            );
        }
    }
}

fn assert_accepted(verdict: Verdict, packet: &PacketBuf) {
    assert_eq!(verdict, Verdict::Accept);
    assert_checksums(packet.as_packet());
}

// ── DNAT / SNAT ───────────────────────────────────────────────────────────────

/// One flow through a port map: inbound DNAT, outbound SNAT, both twice.
fn roundtrip(proto: PortMapProtocol, client: SocketAddr, listen: SocketAddr, target: SocketAddr) {
    let map = PortMap::new([rule(proto, listen, target)]).unwrap();
    for _ in 0..2 {
        let mut request = packet(proto, client, listen);
        assert_accepted(map.inbound(A, &mut request), &request);
        assert_eq!(ends(&request), (client, target), "DNAT");

        let mut reply = packet(proto, target, client);
        assert_accepted(map.outbound(A, &mut reply), &reply);
        assert_eq!(ends(&reply), (listen, client), "SNAT");
    }
    let stats = map.conntrack().stats();
    assert_eq!((stats.entries, stats.inserted, stats.hits), (1, 1, 3));
}

#[test]
fn tcp_dnat_snat_ipv4() {
    roundtrip(PortMapProtocol::Tcp, client4(), listen4(), target4());
}

#[test]
fn tcp_dnat_snat_ipv6() {
    roundtrip(PortMapProtocol::Tcp, client6(), listen6(), target6());
}

#[test]
fn udp_dnat_snat_ipv4() {
    roundtrip(PortMapProtocol::Udp, client4(), listen4(), target4());
}

#[test]
fn udp_dnat_snat_ipv6() {
    roundtrip(PortMapProtocol::Udp, client6(), listen6(), target6());
}

#[test]
fn ipv4_udp_without_checksum_keeps_none() {
    let map = PortMap::new([rule(PortMapProtocol::Udp, listen4(), target4())]).unwrap();
    let mut bytes = udp_bytes(client4(), listen4());
    bytes[26..28].fill(0);
    let mut request = PacketBuf::from_packet(&bytes);
    assert_accepted(map.inbound(A, &mut request), &request);
    assert_eq!(ends(&request), (client4(), target4()));
    assert_eq!(&request.as_packet()[26..28], &[0, 0]);
}

#[test]
fn two_clients_with_the_same_port_get_distinct_flows() {
    let map = PortMap::new([rule(PortMapProtocol::Tcp, listen4(), target4())]).unwrap();
    let other = sa("100.64.0.3:40000");
    for client in [client4(), other] {
        let mut request = tcp(client, listen4(), SYN);
        assert_accepted(map.inbound(A, &mut request), &request);
    }
    for client in [client4(), other] {
        let mut reply = tcp(target4(), client, SYN_ACK);
        assert_accepted(map.outbound(A, &mut reply), &reply);
        assert_eq!(ends(&reply), (listen4(), client));
    }
    assert_eq!(map.conntrack().stats().entries, 2);
}

#[test]
fn unmatched_packets_pass_unchanged() {
    let map = PortMap::new([rule(PortMapProtocol::Tcp, listen4(), target4())]).unwrap();
    let originals = [
        // Another port, another protocol on the listen port, the target directly.
        tcp_bytes(client4(), sa("100.64.0.1:81"), SYN),
        udp_bytes(client4(), listen4()),
        tcp_bytes(client4(), target4(), SYN),
        // ICMP echo.
        ip(
            client4().ip(),
            listen4().ip(),
            protocol::ICMP,
            vec![8, 0, 0, 0, 0, 7, 0, 1],
        ),
        // Not an IP packet.
        vec![0x00, 0x01, 0x02],
    ];
    for original in &originals {
        let mut inbound = PacketBuf::from_packet(original);
        assert_eq!(map.inbound(A, &mut inbound), Verdict::Accept);
        assert_eq!(inbound.as_packet(), original.as_slice());
    }
    // A reply from the target with no recorded flow.
    let reply = tcp_bytes(target4(), client4(), SYN_ACK);
    let mut outbound = PacketBuf::from_packet(&reply);
    assert_eq!(map.outbound(A, &mut outbound), Verdict::Accept);
    assert_eq!(outbound.as_packet(), reply.as_slice());
    assert_eq!(map.conntrack().stats().entries, 0);
}

#[test]
fn packets_of_a_flow_going_the_wrong_way_pass_unchanged() {
    let map = PortMap::new([rule(PortMapProtocol::Udp, listen4(), target4())]).unwrap();
    let mut request = udp(client4(), listen4());
    assert_accepted(map.inbound(A, &mut request), &request);
    // The original tuple sent outbound is not a reply.
    let original = udp_bytes(client4(), listen4());
    let mut outbound = PacketBuf::from_packet(&original);
    assert_eq!(map.outbound(A, &mut outbound), Verdict::Accept);
    assert_eq!(outbound.as_packet(), original.as_slice());
}

#[test]
fn ipv4_fragments_pass_unchanged() {
    let map = PortMap::new([rule(PortMapProtocol::Udp, listen4(), target4())]).unwrap();
    let mut bytes = udp_bytes(client4(), listen4());
    bytes[6] = 0x20; // more fragments
    let mut first = PacketBuf::from_packet(&bytes);
    assert_eq!(map.inbound(A, &mut first), Verdict::Accept);
    assert_eq!(first.as_packet(), bytes.as_slice());
}

// ── Peers ─────────────────────────────────────────────────────────────────────

#[test]
fn rule_peers_restrict_who_may_connect() {
    let mut restricted = rule(PortMapProtocol::Tcp, listen4(), target4());
    restricted.peers = Some(vec![A]);
    let map = PortMap::new([restricted]).unwrap();

    let mut from_b = tcp(client4(), listen4(), SYN);
    assert_eq!(
        map.inbound(B, &mut from_b),
        Verdict::Drop {
            reason: reasons::PEER_NOT_ALLOWED
        }
    );
    assert_eq!(map.conntrack().stats().entries, 0);

    let mut from_a = tcp(client4(), listen4(), SYN);
    assert_accepted(map.inbound(A, &mut from_a), &from_a);
    assert_eq!(ends(&from_a).1, target4());
}

#[test]
fn a_flow_belongs_to_its_peer() {
    let map = PortMap::new([rule(PortMapProtocol::Udp, listen6(), target6())]).unwrap();
    let mut request = udp(client6(), listen6());
    assert_accepted(map.inbound(A, &mut request), &request);

    let wrong = Verdict::Drop {
        reason: reasons::WRONG_PEER,
    };
    // The same tuple from another peer.
    let mut spoofed = udp(client6(), listen6());
    assert_eq!(map.inbound(B, &mut spoofed), wrong);
    // A reply routed to another peer.
    let mut reply = udp(target6(), client6());
    assert_eq!(map.outbound(B, &mut reply), wrong);
    // The flow's own peer still works.
    let mut reply = udp(target6(), client6());
    assert_accepted(map.outbound(A, &mut reply), &reply);
}

// ── Conntrack ─────────────────────────────────────────────────────────────────

#[test]
fn expired_flow_is_gone_and_the_next_packet_creates_a_new_one() {
    let (map, clock) = clocked(
        vec![rule(PortMapProtocol::Udp, listen4(), target4())],
        config(),
    );
    let mut request = udp(client4(), listen4());
    assert_accepted(map.inbound(A, &mut request), &request);
    advance(&clock, 29);
    let mut reply = udp(target4(), client4());
    assert_accepted(map.outbound(A, &mut reply), &reply);
    assert_eq!(ends(&reply).0, listen4());

    advance(&clock, 30);
    let late = udp_bytes(target4(), client4());
    let mut reply = PacketBuf::from_packet(&late);
    assert_eq!(map.outbound(A, &mut reply), Verdict::Accept);
    assert_eq!(reply.as_packet(), late.as_slice(), "no flow, no SNAT");
    assert_eq!(map.conntrack().stats().entries, 0);

    let mut request = udp(client4(), listen4());
    assert_accepted(map.inbound(A, &mut request), &request);
    let stats = map.conntrack().stats();
    assert_eq!((stats.entries, stats.inserted, stats.expired), (1, 2, 1));
}

#[test]
fn bounded_table_counts_evictions() {
    let (map, clock) = clocked(
        vec![rule(PortMapProtocol::Udp, listen4(), target4())],
        ConntrackConfig {
            max_entries: 2,
            ..config()
        },
    );
    let clients = [client4(), sa("100.64.0.3:1"), sa("100.64.0.4:2")];
    for client in clients {
        let mut request = udp(client, listen4());
        assert_accepted(map.inbound(A, &mut request), &request);
        advance(&clock, 1);
    }
    let stats = map.conntrack().stats();
    assert_eq!((stats.entries, stats.evicted, stats.expired), (2, 1, 0));
    // The oldest client's flow was evicted: its reply is not mapped.
    let mut reply = udp(target4(), clients[0]);
    assert_eq!(map.outbound(A, &mut reply), Verdict::Accept);
    assert_eq!(ends(&reply).0, target4());
    let mut reply = udp(target4(), clients[2]);
    assert_accepted(map.outbound(A, &mut reply), &reply);
    assert_eq!(ends(&reply).0, listen4());
}

#[test]
fn table_without_room_drops_new_flows() {
    let (map, _clock) = clocked(
        vec![rule(PortMapProtocol::Udp, listen4(), target4())],
        ConntrackConfig {
            max_entries: 0,
            ..config()
        },
    );
    let mut request = udp(client4(), listen4());
    assert_eq!(
        map.inbound(A, &mut request),
        Verdict::Drop {
            reason: reasons::CONNTRACK_FULL
        }
    );
}

#[test]
fn tcp_state_sets_the_flow_timeout() {
    let (map, clock) = clocked(
        vec![rule(PortMapProtocol::Tcp, listen6(), target6())],
        config(),
    );
    let tcp_state = |map: &PortMap| {
        let tuple = IpPacket::parse(tcp(client6(), listen6(), ACK).as_packet())
            .unwrap()
            .five_tuple()
            .unwrap();
        map.conntrack()
            .lookup(&tuple, None)
            .map(|found| found.flow.tcp_state)
    };

    // An unanswered SYN lives for the transitory timeout.
    let mut syn = tcp(client6(), listen6(), SYN);
    assert_accepted(map.inbound(A, &mut syn), &syn);
    advance(&clock, 30);
    assert_eq!(tcp_state(&map), None);

    // An answered one is established and lives for the established timeout.
    let mut syn = tcp(client6(), listen6(), SYN);
    assert_accepted(map.inbound(A, &mut syn), &syn);
    let mut syn_ack = tcp(target6(), client6(), SYN_ACK);
    assert_accepted(map.outbound(A, &mut syn_ack), &syn_ack);
    assert_eq!(tcp_state(&map), Some(Some(TcpState::Established)));
    advance(&clock, 299);
    let mut ack = tcp(client6(), listen6(), ACK);
    assert_accepted(map.inbound(A, &mut ack), &ack);
    assert_eq!(ends(&ack).1, target6());

    // After a FIN the flow is closing and back on the transitory timeout.
    let mut fin = tcp(target6(), client6(), FIN_ACK);
    assert_accepted(map.outbound(A, &mut fin), &fin);
    assert_eq!(tcp_state(&map), Some(Some(TcpState::Closing)));
    advance(&clock, 30);
    assert_eq!(tcp_state(&map), None);
    assert_eq!(map.conntrack().stats().expired, 2);
}

#[test]
fn shared_target_conflict_is_dropped() {
    let map = PortMap::new([
        rule(PortMapProtocol::Udp, listen4(), target4()),
        rule(PortMapProtocol::Udp, sa("100.64.0.9:80"), target4()),
    ])
    .unwrap();
    let mut first = udp(client4(), listen4());
    assert_accepted(map.inbound(A, &mut first), &first);
    let mut second = udp(client4(), sa("100.64.0.9:80"));
    assert_eq!(
        map.inbound(A, &mut second),
        Verdict::Drop {
            reason: reasons::FLOW_CONFLICT
        }
    );
}

// ── Rules ─────────────────────────────────────────────────────────────────────

#[test]
fn set_rules_replaces_rules_and_drops_flows_of_changed_rules() {
    let kept = rule(PortMapProtocol::Tcp, listen4(), target4());
    let moved_listen = sa("100.64.0.1:81");
    let moved = rule(PortMapProtocol::Tcp, moved_listen, sa("127.0.0.1:8081"));
    let restricted_listen = sa("100.64.0.1:82");
    let restricted = rule(
        PortMapProtocol::Tcp,
        restricted_listen,
        sa("127.0.0.1:8082"),
    );
    let removed_listen = sa("100.64.0.1:83");
    let removed = rule(PortMapProtocol::Tcp, removed_listen, sa("127.0.0.1:8083"));
    let map = PortMap::new([kept.clone(), moved.clone(), restricted.clone(), removed]).unwrap();
    for listen in [listen4(), moved_listen, restricted_listen, removed_listen] {
        let mut syn = tcp(client4(), listen, SYN);
        assert_accepted(map.inbound(A, &mut syn), &syn);
    }
    assert_eq!(map.conntrack().stats().entries, 4);

    let moved = PortMapRule {
        target: sa("127.0.0.1:9091"),
        ..moved
    };
    let restricted = PortMapRule {
        peers: Some(vec![B]),
        ..restricted
    };
    map.set_rules([kept, moved, restricted]).unwrap();
    assert_eq!(map.rules().len(), 3);
    let stats = map.conntrack().stats();
    assert_eq!((stats.entries, stats.removed), (1, 3));

    // The unchanged rule's flow survives.
    let mut reply = tcp(target4(), client4(), SYN_ACK);
    assert_accepted(map.outbound(A, &mut reply), &reply);
    assert_eq!(ends(&reply).0, listen4());
    // The moved rule's next packet goes to the new target.
    let mut ack = tcp(client4(), moved_listen, ACK);
    assert_accepted(map.inbound(A, &mut ack), &ack);
    assert_eq!(ends(&ack).1, sa("127.0.0.1:9091"));
    // The old target's reply is no longer mapped.
    let mut stale = tcp(sa("127.0.0.1:8081"), client4(), ACK);
    assert_eq!(map.outbound(A, &mut stale), Verdict::Accept);
    assert_eq!(ends(&stale).0, sa("127.0.0.1:8081"));
    // The restricted rule now refuses peer A.
    let mut ack = tcp(client4(), restricted_listen, ACK);
    assert_eq!(
        map.inbound(A, &mut ack),
        Verdict::Drop {
            reason: reasons::PEER_NOT_ALLOWED
        }
    );
    // The removed rule's port is no longer published.
    let original = tcp_bytes(client4(), removed_listen, ACK);
    let mut ack = PacketBuf::from_packet(&original);
    assert_eq!(map.inbound(A, &mut ack), Verdict::Accept);
    assert_eq!(ack.as_packet(), original.as_slice());
}

#[test]
fn invalid_rules_are_refused_and_change_nothing() {
    let map = PortMap::new([rule(PortMapProtocol::Udp, listen4(), target4())]).unwrap();
    assert_eq!(
        map.set_rules([rule(PortMapProtocol::Udp, listen4(), target6())]),
        Err(PortMapError::FamilyMismatch {
            listen: listen4(),
            target: target6()
        })
    );
    assert_eq!(
        map.set_rules([rule(PortMapProtocol::Udp, listen4(), sa("127.0.0.1:0"))]),
        Err(PortMapError::ZeroPort(sa("127.0.0.1:0")))
    );
    assert_eq!(
        map.set_rules([
            rule(PortMapProtocol::Udp, listen4(), target4()),
            rule(PortMapProtocol::Udp, listen4(), sa("127.0.0.1:9"))
        ]),
        Err(PortMapError::DuplicateListen(listen4()))
    );
    // The same listen port for TCP and UDP is fine.
    PortMap::new([
        rule(PortMapProtocol::Udp, listen4(), target4()),
        rule(PortMapProtocol::Tcp, listen4(), target4()),
    ])
    .unwrap();
    assert_eq!(
        map.rules(),
        vec![rule(PortMapProtocol::Udp, listen4(), target4())]
    );
}

// ── ICMP errors ───────────────────────────────────────────────────────────────

#[test]
fn outbound_icmp_error_about_a_mapped_packet_is_rewritten() {
    let map = PortMap::new([rule(PortMapProtocol::Udp, listen4(), target4())]).unwrap();
    let mut request = udp(client4(), listen4());
    assert_accepted(map.inbound(A, &mut request), &request);

    // The local stack answers the mapped packet with port unreachable.
    let mut error = icmp_error(target4().ip(), client4().ip(), 3, 3, request.as_packet());
    assert_accepted(map.outbound(A, &mut error), &error);

    let bytes = error.as_packet();
    let outer = IpPacket::parse(bytes).unwrap();
    assert_eq!(outer.src(), listen4().ip());
    assert_eq!(outer.dst(), client4().ip());
    let quoted = PacketBuf::from_packet(&outer.payload()[8..]);
    assert_eq!(ends(&quoted), (client4(), listen4()));
    // The whole quoted packet is the one the client sent.
    assert_eq!(
        quoted.as_packet(),
        udp_bytes(client4(), listen4()).as_slice()
    );

    let mut wrong_peer = icmp_error(target4().ip(), client4().ip(), 3, 3, request.as_packet());
    assert_eq!(
        map.outbound(B, &mut wrong_peer),
        Verdict::Drop {
            reason: reasons::WRONG_PEER
        }
    );
}

#[test]
fn outbound_icmp_error_with_a_truncated_quote_is_rewritten() {
    let map = PortMap::new([rule(PortMapProtocol::Tcp, listen4(), target4())]).unwrap();
    let mut request = tcp(client4(), listen4(), SYN);
    assert_accepted(map.inbound(A, &mut request), &request);

    // IP header and 8 bytes of TCP: the TCP checksum is cut off. Sent from
    // another local address, which stays as it is.
    let router: IpAddr = "100.64.0.254".parse().unwrap();
    let mut error = icmp_error(router, client4().ip(), 11, 0, &request.as_packet()[..28]);
    assert_accepted(map.outbound(A, &mut error), &error);
    let outer = IpPacket::parse(error.as_packet()).unwrap();
    assert_eq!(outer.src(), router);
    let quoted = &outer.payload()[8..];
    assert_eq!(&quoted[16..20], &[100, 64, 0, 1]);
    assert_eq!(&quoted[22..24], &80u16.to_be_bytes());
}

#[test]
fn inbound_icmpv6_error_about_a_reply_is_rewritten() {
    let map = PortMap::new([rule(PortMapProtocol::Tcp, listen6(), target6())]).unwrap();
    let mut request = tcp(client6(), listen6(), SYN);
    assert_accepted(map.inbound(A, &mut request), &request);
    let mut reply = tcp(target6(), client6(), SYN_ACK);
    assert_accepted(map.outbound(A, &mut reply), &reply);

    // The peer's path reports packet too big for the reply.
    let mut error = icmp_error(client6().ip(), listen6().ip(), 2, 0, reply.as_packet());
    assert_accepted(map.inbound(A, &mut error), &error);

    let bytes = error.as_packet();
    let outer = IpPacket::parse(bytes).unwrap();
    assert_eq!(outer.src(), client6().ip());
    assert_eq!(outer.dst(), target6().ip());
    let quoted = PacketBuf::from_packet(&outer.payload()[8..]);
    assert_eq!(ends(&quoted), (target6(), client6()));
    assert_eq!(
        quoted.as_packet(),
        tcp_bytes(target6(), client6(), SYN_ACK).as_slice()
    );
    // The error does not count as a reply for the TCP state.
    let stats = map.conntrack().stats();
    assert_eq!(stats.entries, 1);
}

#[test]
fn icmp_errors_about_unknown_flows_pass_unchanged() {
    let map = PortMap::new([rule(PortMapProtocol::Udp, listen4(), target4())]).unwrap();
    let quote = udp_bytes(client4(), target4());
    let original = icmp_error(target4().ip(), client4().ip(), 3, 3, &quote);
    for inbound in [true, false] {
        let mut error = PacketBuf::from_packet(original.as_packet());
        let verdict = if inbound {
            map.inbound(A, &mut error)
        } else {
            map.outbound(A, &mut error)
        };
        assert_eq!(verdict, Verdict::Accept);
        assert_eq!(error.as_packet(), original.as_packet());
    }
}

#[test]
fn port_map_is_a_shareable_filter() {
    fn assert_filter<T: PacketFilter>() {}
    assert_filter::<PortMap>();
}
