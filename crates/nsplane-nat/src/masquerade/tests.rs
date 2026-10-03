//! Tests of the local-side masquerade: round trips with checksums, the pass
//! cases, expiry, re-entrancy, and the ns parity cases (`parity_*`) ported
//! from ns `subnet/tests/lan_translation.rs` (route change kills the
//! reverse, the SYN-only rule, token wrap, capacity) to in-place rewriting
//! on `PacketBuf`.

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Barrier, OnceLock, Weak};
use std::thread;

use super::*;

/// The LAN host opening flows (ns `fd00:aa::10`).
const HOST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xaa, 0, 0, 0, 0, 0, 0x10);
/// The remote the flows go to (ns `fd00:1:2:1:0:b:c0a8:b01`).
const REMOTE: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 0xb, 0xc0a8, 0xb01);
const OTHER_REMOTE: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 0xb, 0xc0a8, 0xb02);
/// The gateway return identity the flows take as their source (ns
/// `fd00:1:2:2::6440:1`).
const SOURCE: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 2, 2, 0, 0, 0x6440, 1);
const ROUTE: u64 = 7;
const HOST_PORT: u16 = 10_000;
const FIRST_TOKEN: u16 = 49_152;
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;

fn decision(route: u64) -> MasqueradeDecision {
    MasqueradeDecision {
        source: IpAddr::V6(SOURCE),
        route,
    }
}

/// A masquerade whose closure answers what `answer` holds, with its
/// decision count and test clock.
struct Fixture {
    masquerade: Masquerade,
    answer: Arc<Mutex<Option<MasqueradeDecision>>>,
    calls: Arc<AtomicUsize>,
    now: Arc<Mutex<Instant>>,
}

impl Fixture {
    fn new(config: MasqueradeConfig) -> Self {
        let answer = Arc::new(Mutex::new(Some(decision(ROUTE))));
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(Mutex::new(Instant::now()));
        let (a, c, n) = (Arc::clone(&answer), Arc::clone(&calls), Arc::clone(&now));
        let masquerade = Masquerade::with_clock(
            move |_| {
                c.fetch_add(1, Ordering::Relaxed);
                *a.lock().unwrap()
            },
            config,
            move || *n.lock().unwrap(),
        );
        Self {
            masquerade,
            answer,
            calls,
            now,
        }
    }

    fn answer(&self, answer: Option<MasqueradeDecision>) {
        *self.answer.lock().unwrap() = answer;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    fn advance(&self, by: Duration) {
        *self.now.lock().unwrap() += by;
    }

    /// Forwards `packet`, asserts that it was rewritten with a valid
    /// checksum from [`SOURCE`], and returns it.
    fn forward(&self, mut packet: PacketBuf) -> PacketBuf {
        assert_eq!(
            self.masquerade.forward(&mut packet),
            MasqueradeVerdict::Rewritten
        );
        assert_valid(&packet);
        assert_eq!(src(&packet), SOURCE);
        packet
    }

    /// Reverses `packet`, asserts that it was rewritten with a valid checksum
    /// to [`HOST`], and returns it.
    fn reverse(&self, mut packet: PacketBuf) -> PacketBuf {
        assert_eq!(
            self.masquerade.reverse(&mut packet),
            MasqueradeVerdict::Rewritten
        );
        assert_valid(&packet);
        assert_eq!(dst(&packet), HOST);
        packet
    }
}

fn fixture() -> Fixture {
    Fixture::new(MasqueradeConfig::default())
}

// -- Packet builders: every packet carries a valid transport checksum. --

const fn checksum_at(protocol: u8) -> usize {
    match protocol {
        protocol::TCP => 16,
        protocol::UDP => 6,
        _ => 2,
    }
}

/// An IPv6 packet carrying `segment`, with its transport checksum computed.
fn ipv6(protocol: u8, src: Ipv6Addr, dst: Ipv6Addr, mut segment: Vec<u8>) -> PacketBuf {
    let at = checksum_at(protocol);
    segment[at..at + 2].fill(0);
    let checksum = transport_checksum_v6(src, dst, protocol, &segment);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    segment[at..at + 2].copy_from_slice(&checksum.to_be_bytes());
    let mut bytes = vec![0x60, 0, 0, 0];
    bytes.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&[protocol, 64]);
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&dst.octets());
    bytes.extend_from_slice(&segment);
    PacketBuf::from_packet(&bytes)
}

fn ports(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut segment = src_port.to_be_bytes().to_vec();
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment
}

fn tcp(src: (Ipv6Addr, u16), dst: (Ipv6Addr, u16), flags: u8) -> PacketBuf {
    let mut segment = ports(src.1, dst.1);
    segment.extend_from_slice(&[0; 8]);
    segment.extend_from_slice(&[5 << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    segment.extend_from_slice(b"payload");
    ipv6(protocol::TCP, src.0, dst.0, segment)
}

fn udp(src: (Ipv6Addr, u16), dst: (Ipv6Addr, u16)) -> PacketBuf {
    let mut segment = ports(src.1, dst.1);
    segment.extend_from_slice(&15_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(b"payload");
    ipv6(protocol::UDP, src.0, dst.0, segment)
}

fn echo(src: Ipv6Addr, dst: Ipv6Addr, icmp_type: u8, id: u16) -> PacketBuf {
    let mut segment = vec![icmp_type, 0, 0, 0];
    segment.extend_from_slice(&id.to_be_bytes());
    segment.extend_from_slice(&1_u16.to_be_bytes());
    segment.extend_from_slice(b"ping");
    ipv6(protocol::ICMPV6, src, dst, segment)
}

/// The UDP request of the LAN host to `remote` from `port`.
fn request(remote: Ipv6Addr, port: u16) -> PacketBuf {
    udp((HOST, port), (remote, 53))
}

fn be16_at(packet: &PacketBuf, at: usize) -> u16 {
    be16(packet.as_packet(), at)
}

fn src(packet: &PacketBuf) -> Ipv6Addr {
    addr(packet.as_packet(), SRC_ADDR)
}

fn dst(packet: &PacketBuf) -> Ipv6Addr {
    addr(packet.as_packet(), DST_ADDR)
}

/// The source port, or the Echo identifier.
fn token(packet: &PacketBuf) -> u16 {
    if packet.as_packet()[6] == protocol::ICMPV6 {
        be16_at(packet, 44)
    } else {
        be16_at(packet, 40)
    }
}

/// The reply of the remote to a forwarded packet: a SYN-ACK for TCP, an Echo
/// reply for `ICMPv6`.
fn reply(forwarded: &PacketBuf) -> PacketBuf {
    let (from, to) = (dst(forwarded), src(forwarded));
    let bytes = forwarded.as_packet();
    match bytes[6] {
        protocol::TCP => tcp((from, be16(bytes, 42)), (to, be16(bytes, 40)), SYN_ACK),
        protocol::UDP => udp((from, be16(bytes, 42)), (to, be16(bytes, 40))),
        _ => echo(from, to, ECHO_REPLY, be16(bytes, 44)),
    }
}

/// Asserts that the transport checksum of an IPv6 packet is valid.
fn assert_valid(packet: &PacketBuf) {
    let bytes = packet.as_packet();
    assert_ne!(be16(bytes, 40 + checksum_at(bytes[6])), 0);
    assert_eq!(
        transport_checksum_v6(src(packet), dst(packet), bytes[6], &bytes[40..]),
        0,
        "transport checksum"
    );
}

/// Asserts that `call` passes `packet` unchanged.
fn assert_pass(mut packet: PacketBuf, call: impl Fn(&mut PacketBuf) -> MasqueradeVerdict) {
    let before = packet.as_packet().to_vec();
    assert_eq!(call(&mut packet), MasqueradeVerdict::Pass);
    assert_eq!(packet.as_packet(), before.as_slice());
}

/// Asserts that `call` drops `packet` for `reason` without changing it.
fn assert_drop(
    mut packet: PacketBuf,
    reason: &'static str,
    call: impl Fn(&mut PacketBuf) -> MasqueradeVerdict,
) {
    let before = packet.as_packet().to_vec();
    assert_eq!(call(&mut packet), MasqueradeVerdict::Drop(reason));
    assert_eq!(packet.as_packet(), before.as_slice());
}

// -- Round trips. --

#[test]
fn defaults_match_the_contract() {
    let config = MasqueradeConfig::default();
    assert_eq!(config.ports, 49_152..=65_535);
    assert_eq!((config.tries, config.max_flows), (16_384, 4096));
    assert_eq!(config.tcp_timeout, Duration::from_secs(300));
    assert_eq!(config.udp_timeout, Duration::from_secs(120));
    assert_eq!(config.icmp_timeout, Duration::from_secs(30));
    assert!(config.tcp_new_flow_requires_syn && config.verify_checksums);
}

#[test]
fn udp_round_trip_restores_the_lan_host() {
    let f = fixture();
    let forwarded = f.forward(request(REMOTE, HOST_PORT));
    assert_eq!(dst(&forwarded), REMOTE);
    assert_eq!(token(&forwarded), FIRST_TOKEN);
    assert_eq!(be16_at(&forwarded, 42), 53);
    assert_eq!(&forwarded.as_packet()[48..], b"payload");
    assert_eq!(f.masquerade.len(), 1);

    let restored = f.reverse(reply(&forwarded));
    assert_eq!(src(&restored), REMOTE);
    assert_eq!(
        (be16_at(&restored, 40), be16_at(&restored, 42)),
        (53, HOST_PORT)
    );
    assert_eq!(&restored.as_packet()[48..], b"payload");
}

#[test]
fn tcp_round_trip_restores_the_lan_host() {
    let f = fixture();
    let forwarded = f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
    assert_eq!(token(&forwarded), FIRST_TOKEN);
    let restored = f.reverse(reply(&forwarded));
    assert_eq!(be16_at(&restored, 42), HOST_PORT);
    // The established flow needs no SYN.
    f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), ACK));
    assert_eq!(f.masquerade.len(), 1);
}

#[test]
fn icmp_echo_round_trip_restores_the_identifier() {
    let f = fixture();
    let forwarded = f.forward(echo(HOST, REMOTE, ECHO_REQUEST, 321));
    assert_eq!(token(&forwarded), FIRST_TOKEN);
    assert_eq!(be16_at(&forwarded, 46), 1, "the sequence is kept");
    let restored = f.reverse(reply(&forwarded));
    assert_eq!(src(&restored), REMOTE);
    assert_eq!(token(&restored), 321);
}

#[test]
fn decide_gets_the_original_tuple() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let masquerade = Masquerade::new(
        move |tuple| {
            log.lock().unwrap().push(*tuple);
            Some(decision(ROUTE))
        },
        MasqueradeConfig::default(),
    );
    let mut packet = echo(HOST, REMOTE, ECHO_REQUEST, 321);
    masquerade.forward(&mut packet);
    let mut answer = reply(&packet);
    masquerade.reverse(&mut answer);
    let expected = FiveTuple {
        src: IpAddr::V6(HOST),
        dst: IpAddr::V6(REMOTE),
        protocol: protocol::ICMPV6,
        src_port: 321,
        dst_port: 321,
    };
    assert_eq!(*seen.lock().unwrap(), [expected, expected]);
}

#[test]
fn later_packets_reuse_the_flow_and_replies_ask_again() {
    let f = fixture();
    let first = f.forward(request(REMOTE, HOST_PORT));
    let second = f.forward(request(REMOTE, HOST_PORT));
    assert_eq!(token(&first), token(&second));
    assert_eq!(f.calls(), 1, "decide runs once per new flow");
    f.reverse(reply(&first));
    f.reverse(reply(&first));
    assert_eq!(f.calls(), 3, "every reply checks the route");
}

#[test]
fn flows_get_distinct_tokens_per_destination() {
    let f = fixture();
    let a = f.forward(request(REMOTE, HOST_PORT));
    let b = f.forward(request(REMOTE, HOST_PORT + 1));
    let c = f.forward(request(OTHER_REMOTE, HOST_PORT));
    assert_eq!(
        [token(&a), token(&b), token(&c)],
        [FIRST_TOKEN, FIRST_TOKEN + 1, FIRST_TOKEN + 2]
    );
    assert_eq!(be16_at(&f.reverse(reply(&b)), 42), HOST_PORT + 1);
    assert_eq!(be16_at(&f.reverse(reply(&a)), 42), HOST_PORT);
    assert_eq!(f.masquerade.len(), 3);
}

// -- Pass cases. --

#[test]
fn a_none_decision_passes_and_records_nothing() {
    let f = fixture();
    f.answer(None);
    assert_pass(request(REMOTE, HOST_PORT), |p| f.masquerade.forward(p));
    // A mid-stream TCP packet of traffic that is not masqueraded passes too.
    assert_pass(tcp((HOST, HOST_PORT), (REMOTE, 443), ACK), |p| {
        f.masquerade.forward(p)
    });
    assert_eq!(f.calls(), 2);
    assert_eq!(f.masquerade.len(), 0);
    assert_eq!(f.masquerade.stats().passed, 2);
}

#[test]
fn ipv4_passes() {
    let f = fixture();
    let mut bytes = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, protocol::UDP, 0, 0];
    bytes.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
    bytes.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 3).octets());
    bytes.extend_from_slice(&[0x27, 0x10, 0, 53, 0, 8, 0, 0]);
    assert_pass(PacketBuf::from_packet(&bytes), |p| f.masquerade.forward(p));
    assert_pass(PacketBuf::from_packet(&bytes), |p| f.masquerade.reverse(p));
    assert_eq!(f.calls(), 0);
}

/// `packet` with its next header replaced by `next_header`.
fn with_next_header(packet: &PacketBuf, next_header: u8) -> PacketBuf {
    let mut bytes = packet.as_packet().to_vec();
    bytes[6] = next_header;
    PacketBuf::from_packet(&bytes)
}

#[test]
fn fragments_and_extension_headers_pass() {
    let f = fixture();
    let request = request(REMOTE, HOST_PORT);
    for next_header in [44, 0, 43, 60] {
        assert_pass(with_next_header(&request, next_header), |p| {
            f.masquerade.forward(p)
        });
    }
    let forwarded = f.forward(request);
    assert_pass(with_next_header(&reply(&forwarded), 44), |p| {
        f.masquerade.reverse(p)
    });
    assert_eq!(f.calls(), 1);
}

#[test]
fn a_length_mismatch_passes() {
    let f = fixture();
    let bytes = request(REMOTE, HOST_PORT).as_packet().to_vec();
    let mut longer = bytes.clone();
    longer.push(0);
    assert_pass(PacketBuf::from_packet(&longer), |p| f.masquerade.forward(p));
    let shorter = &bytes[..bytes.len() - 1];
    assert_pass(PacketBuf::from_packet(shorter), |p| f.masquerade.forward(p));
    // A UDP length that disagrees with the IPv6 payload length.
    let mut udp_len = bytes;
    udp_len[45] -= 1;
    assert_pass(PacketBuf::from_packet(&udp_len), |p| {
        f.masquerade.forward(p)
    });
    assert_eq!(f.calls(), 0);
}

#[test]
fn unparsable_and_other_packets_pass() {
    let f = fixture();
    // Too short, a TCP header longer than the payload, an `ICMPv6` error,
    // an Echo reply forward and an Echo request reverse.
    assert_pass(PacketBuf::from_packet(&[0x60; 30]), |p| {
        f.masquerade.forward(p)
    });
    let mut bad_offset = tcp((HOST, HOST_PORT), (REMOTE, 443), SYN)
        .as_packet()
        .to_vec();
    bad_offset[52] = 15 << 4;
    assert_pass(PacketBuf::from_packet(&bad_offset), |p| {
        f.masquerade.forward(p)
    });
    assert_pass(echo(HOST, REMOTE, 1, 321), |p| f.masquerade.forward(p));
    assert_pass(echo(HOST, REMOTE, ECHO_REPLY, 321), |p| {
        f.masquerade.forward(p)
    });
    assert_pass(echo(REMOTE, SOURCE, ECHO_REQUEST, FIRST_TOKEN), |p| {
        f.masquerade.reverse(p)
    });
    assert_eq!(f.calls(), 0);
}

#[test]
fn replies_of_unknown_flows_pass() {
    let f = fixture();
    let forwarded = f.forward(request(REMOTE, HOST_PORT));
    assert_pass(udp((REMOTE, 53), (SOURCE, FIRST_TOKEN + 1)), |p| {
        f.masquerade.reverse(p)
    });
    assert_pass(udp((OTHER_REMOTE, 53), (SOURCE, FIRST_TOKEN)), |p| {
        f.masquerade.reverse(p)
    });
    assert_pass(udp((REMOTE, 54), (SOURCE, FIRST_TOKEN)), |p| {
        f.masquerade.reverse(p)
    });
    // A TCP reply of a UDP flow.
    assert_pass(tcp((REMOTE, 53), (SOURCE, FIRST_TOKEN), SYN_ACK), |p| {
        f.masquerade.reverse(p)
    });
    f.reverse(reply(&forwarded));
    assert_eq!(f.calls(), 2);
}

// -- Checksums. --

/// `packet` with its last byte flipped, so its transport checksum fails.
fn corrupt(packet: &PacketBuf) -> PacketBuf {
    let mut bytes = packet.as_packet().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    PacketBuf::from_packet(&bytes)
}

#[test]
fn a_bad_checksum_drops_without_asking() {
    let f = fixture();
    let request = request(REMOTE, HOST_PORT);
    assert_drop(corrupt(&request), reasons::BAD_CHECKSUM, |p| {
        f.masquerade.forward(p)
    });
    // A zero UDP checksum is not allowed over IPv6.
    let mut zero = request.as_packet().to_vec();
    zero[46..48].fill(0);
    assert_drop(PacketBuf::from_packet(&zero), reasons::BAD_CHECKSUM, |p| {
        f.masquerade.forward(p)
    });
    assert_eq!(f.calls(), 0);

    let forwarded = f.forward(request);
    assert_drop(corrupt(&reply(&forwarded)), reasons::BAD_CHECKSUM, |p| {
        f.masquerade.reverse(p)
    });
    // A corrupted reply of no flow is not ours.
    assert_pass(corrupt(&udp((REMOTE, 53), (SOURCE, 1))), |p| {
        f.masquerade.reverse(p)
    });
    assert_eq!(f.masquerade.stats().bad_checksum, 3);
}

#[test]
fn without_verification_a_bad_checksum_is_recomputed() {
    let f = Fixture::new(MasqueradeConfig {
        verify_checksums: false,
        ..MasqueradeConfig::default()
    });
    let forwarded = f.forward(corrupt(&request(REMOTE, HOST_PORT)));
    f.reverse(corrupt(&reply(&forwarded)));
}

// -- ns parity. --

#[test]
fn parity_route_change_kills_the_reverse() {
    let f = fixture();
    let forwarded = f.forward(request(REMOTE, HOST_PORT));
    f.reverse(reply(&forwarded));

    f.answer(Some(decision(ROUTE + 1)));
    assert_drop(reply(&forwarded), reasons::ROUTE_CHANGED, |p| {
        f.masquerade.reverse(p)
    });
    assert_eq!(f.masquerade.len(), 0, "the flow is removed");
    assert_pass(reply(&forwarded), |p| f.masquerade.reverse(p));

    // A new flow under the new route works; then `None` kills it too.
    let next = f.forward(request(REMOTE, HOST_PORT));
    f.reverse(reply(&next));
    f.answer(None);
    assert_drop(reply(&next), reasons::ROUTE_CHANGED, |p| {
        f.masquerade.reverse(p)
    });
    let stats = f.masquerade.stats();
    assert_eq!((stats.route_changed, stats.flows), (2, 0));
}

#[test]
fn parity_tcp_new_flows_require_a_syn() {
    let f = fixture();
    for flags in [ACK, SYN_ACK, 0] {
        assert_drop(
            tcp((HOST, HOST_PORT), (REMOTE, 443), flags),
            reasons::TCP_NOT_SYN,
            |p| f.masquerade.forward(p),
        );
    }
    assert_eq!(f.masquerade.len(), 0);
    f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
    assert_eq!(f.masquerade.stats().tcp_not_syn, 3);

    let lenient = Fixture::new(MasqueradeConfig {
        tcp_new_flow_requires_syn: false,
        ..MasqueradeConfig::default()
    });
    lenient.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), ACK));
}

#[test]
fn parity_tokens_wrap_within_the_range() {
    let f = Fixture::new(MasqueradeConfig {
        ports: 65_534..=65_535,
        ..MasqueradeConfig::default()
    });
    let remotes = [REMOTE, OTHER_REMOTE, SOURCE];
    let tokens: Vec<_> = remotes
        .iter()
        .map(|remote| token(&f.forward(request(*remote, HOST_PORT))))
        .collect();
    assert_eq!(tokens, [65_534, 65_535, 65_534]);
}

#[test]
fn parity_tokens_exhausted() {
    let f = Fixture::new(MasqueradeConfig {
        ports: 65_534..=65_535,
        ..MasqueradeConfig::default()
    });
    f.forward(request(REMOTE, HOST_PORT));
    f.forward(request(REMOTE, HOST_PORT + 1));
    assert_drop(
        request(REMOTE, HOST_PORT + 2),
        reasons::TOKENS_EXHAUSTED,
        |p| f.masquerade.forward(p),
    );
    // Tokens are unique per destination: another remote still gets one.
    f.forward(request(OTHER_REMOTE, HOST_PORT));
    assert_eq!(f.masquerade.stats().tokens_exhausted, 1);
}

#[test]
fn the_token_search_gives_up_after_tries() {
    let f = Fixture::new(MasqueradeConfig {
        ports: 100..=103,
        tries: 2,
        ..MasqueradeConfig::default()
    });
    for port in 0..3 {
        f.forward(request(REMOTE, HOST_PORT + port));
    }
    // 103 goes to another remote; the cursor wraps to 100, and 100 and 101
    // are in use towards `REMOTE`, though 103 is free for it.
    assert_eq!(token(&f.forward(request(OTHER_REMOTE, HOST_PORT))), 103);
    assert_drop(
        request(REMOTE, HOST_PORT + 3),
        reasons::TOKENS_EXHAUSTED,
        |p| f.masquerade.forward(p),
    );
    // The cursor moved on to 102 (in use) and 103 (free).
    assert_eq!(token(&f.forward(request(REMOTE, HOST_PORT + 3))), 103);
}

#[test]
fn parity_capacity_drops_new_flows_without_eviction() {
    let f = Fixture::new(MasqueradeConfig {
        max_flows: 1,
        ..MasqueradeConfig::default()
    });
    let first = f.forward(request(REMOTE, HOST_PORT));
    assert_drop(request(REMOTE, HOST_PORT + 1), reasons::CAPACITY, |p| {
        f.masquerade.forward(p)
    });
    f.reverse(reply(&first));

    f.advance(Duration::from_secs(121));
    let current = f.forward(request(REMOTE, HOST_PORT + 1));
    assert_pass(reply(&first), |p| f.masquerade.reverse(p));
    f.reverse(reply(&current));
    let stats = f.masquerade.stats();
    assert_eq!((stats.capacity, stats.expired, stats.flows), (1, 1, 1));
}

#[test]
fn a_zero_capacity_drops_every_new_flow() {
    let f = Fixture::new(MasqueradeConfig {
        max_flows: 0,
        ..MasqueradeConfig::default()
    });
    assert_drop(request(REMOTE, HOST_PORT), reasons::CAPACITY, |p| {
        f.masquerade.forward(p)
    });
}

#[test]
fn an_ipv4_source_drops() {
    let f = fixture();
    f.answer(Some(MasqueradeDecision {
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        route: ROUTE,
    }));
    assert_drop(request(REMOTE, HOST_PORT), reasons::SOURCE_NOT_IPV6, |p| {
        f.masquerade.forward(p)
    });
    assert_eq!(f.masquerade.stats().source_not_ipv6, 1);
}

// -- Expiry. --

#[test]
fn idle_flows_expire_per_protocol_and_hits_refresh() {
    let f = fixture();
    let udp = f.forward(request(REMOTE, HOST_PORT));
    let tcp = f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
    let icmp = f.forward(echo(HOST, REMOTE, ECHO_REQUEST, 321));

    f.advance(Duration::from_secs(29));
    f.reverse(reply(&icmp));
    f.advance(Duration::from_secs(29));
    f.reverse(reply(&icmp));
    f.advance(Duration::from_secs(30));
    assert_pass(reply(&icmp), |p| f.masquerade.reverse(p));
    assert_eq!(f.masquerade.len(), 2);

    // 88 s in: refresh UDP, then 119 s idle keeps it, 120 s does not.
    f.forward(request(REMOTE, HOST_PORT));
    f.advance(Duration::from_secs(119));
    f.reverse(reply(&udp));
    f.advance(Duration::from_secs(120));
    assert_pass(reply(&udp), |p| f.masquerade.reverse(p));

    // TCP was last seen 327 s ago: past its 300 s timeout.
    assert_pass(reply(&tcp), |p| f.masquerade.reverse(p));
    assert_eq!(f.masquerade.len(), 0);
    assert_eq!(f.masquerade.stats().expired, 3);

    let calls = f.calls();
    f.forward(request(REMOTE, HOST_PORT));
    assert_eq!(f.calls(), calls + 1, "an expired flow asks again");
}

#[test]
fn len_removes_expired_flows() {
    let f = fixture();
    f.forward(echo(HOST, REMOTE, ECHO_REQUEST, 321));
    f.forward(request(REMOTE, HOST_PORT));
    assert_eq!(f.masquerade.len(), 2);
    f.advance(Duration::from_secs(30));
    assert_eq!(f.masquerade.len(), 1);
    f.advance(Duration::from_secs(90));
    assert!(f.masquerade.is_empty());
    assert_eq!(f.masquerade.stats().expired, 2);
}

#[test]
fn an_expired_flow_frees_its_token() {
    let f = Fixture::new(MasqueradeConfig {
        ports: 200..=200,
        ..MasqueradeConfig::default()
    });
    let first = f.forward(request(REMOTE, HOST_PORT));
    assert_drop(
        request(REMOTE, HOST_PORT + 1),
        reasons::TOKENS_EXHAUSTED,
        |p| f.masquerade.forward(p),
    );
    f.advance(Duration::from_secs(120));
    let second = f.forward(request(REMOTE, HOST_PORT + 1));
    assert_eq!((token(&first), token(&second)), (200, 200));
    assert_eq!(be16_at(&f.reverse(reply(&second)), 42), HOST_PORT + 1);
}

// -- Stats, re-entrancy and races. --

#[test]
fn stats_count_every_verdict() {
    let f = fixture();
    let forwarded = f.forward(request(REMOTE, HOST_PORT));
    f.forward(request(REMOTE, HOST_PORT));
    f.reverse(reply(&forwarded));
    assert_pass(udp((REMOTE, 53), (SOURCE, 1)), |p| f.masquerade.reverse(p));
    assert_drop(
        tcp((HOST, HOST_PORT), (REMOTE, 443), ACK),
        reasons::TCP_NOT_SYN,
        |p| f.masquerade.forward(p),
    );
    assert_eq!(
        f.masquerade.stats(),
        MasqueradeStats {
            forwarded: 2,
            reversed: 1,
            passed: 1,
            tcp_not_syn: 1,
            flows: 1,
            created: 1,
            ..MasqueradeStats::default()
        }
    );
}

#[test]
fn masquerade_is_send_and_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Masquerade>();
}

/// A masquerade whose closure reaches the masquerade itself.
fn reentrant(
    decide: impl Fn(&Masquerade, &FiveTuple) -> Option<MasqueradeDecision> + Send + Sync + 'static,
) -> Arc<Masquerade> {
    let slot: Arc<OnceLock<Weak<Masquerade>>> = Arc::new(OnceLock::new());
    let inner = Arc::clone(&slot);
    let masquerade = Arc::new(Masquerade::new(
        move |tuple| {
            let masquerade = inner.get().and_then(Weak::upgrade).unwrap();
            decide(&masquerade, tuple)
        },
        MasqueradeConfig::default(),
    ));
    slot.set(Arc::downgrade(&masquerade)).unwrap();
    masquerade
}

#[test]
fn decide_may_call_back_into_the_masquerade() {
    // Would deadlock if `decide` ran under the table lock.
    let masquerade = reentrant(|masquerade, _| {
        let _ = masquerade.stats();
        Some(decision(ROUTE))
    });
    let mut packet = request(REMOTE, HOST_PORT);
    assert_eq!(
        masquerade.forward(&mut packet),
        MasqueradeVerdict::Rewritten
    );
    let mut answer = reply(&packet);
    assert_eq!(
        masquerade.reverse(&mut answer),
        MasqueradeVerdict::Rewritten
    );
}

#[test]
fn a_racing_first_packet_takes_the_recorded_flow() {
    // The first decision forwards the same packet again before answering, as
    // a racing thread that wins the insert would.
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let masquerade = reentrant(move |masquerade, _| {
        if counter.fetch_add(1, Ordering::Relaxed) == 0 {
            let mut packet = request(REMOTE, HOST_PORT);
            assert_eq!(
                masquerade.forward(&mut packet),
                MasqueradeVerdict::Rewritten
            );
            return Some(decision(1));
        }
        Some(decision(2))
    });
    let mut packet = request(REMOTE, HOST_PORT);
    assert_eq!(
        masquerade.forward(&mut packet),
        MasqueradeVerdict::Rewritten
    );
    assert_eq!(token(&packet), FIRST_TOKEN);
    let stats = masquerade.stats();
    assert_eq!((stats.flows, stats.created), (1, 1));
}

#[test]
fn concurrent_first_packets_record_one_flow() {
    const THREADS: usize = 8;
    let f = fixture();
    let barrier = Barrier::new(THREADS);
    let tokens: Vec<_> = thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    token(&f.forward(request(REMOTE, HOST_PORT)))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(tokens.iter().all(|t| *t == FIRST_TOKEN));
    let stats = f.masquerade.stats();
    assert_eq!((stats.flows, stats.created), (1, 1));
}
