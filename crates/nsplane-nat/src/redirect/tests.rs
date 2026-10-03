//! Tests of the local-side redirect, adapted from the ns `tun_service`
//! rewrite tests to in-place rewriting on `PacketBuf`, plus checksums, the
//! flow lifetime (expiry, eviction, removal) and the re-entrancy rules.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use nsplane_packet::{PacketBuf, protocol};

use super::*;
use crate::checksum::{ipv4_header_checksum, transport_checksum_v4, valid};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 51_234);
const OTHER_CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 51_234);
const SERVICE_A: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 10), 80);
const SERVICE_B: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 11), 80);
const STACK: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
const FIRST_PORT: u16 = 49_152;
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;

const fn endpoint(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(STACK, port)
}

/// A decision closure handing out `size` endpoints of `STACK` in turn,
/// starting at [`FIRST_PORT`], with a count of its calls.
fn pool(size: u16) -> (Arc<AtomicUsize>, impl Fn(&FiveTuple) -> RedirectDecision) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let decide = move |_: &FiveTuple| {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        let offset = u16::try_from(n % usize::from(size)).unwrap();
        RedirectDecision::Redirect(endpoint(FIRST_PORT + offset))
    };
    (calls, decide)
}

/// A redirect over a pool of `size` endpoints, with its decision count.
fn redirect(size: u16) -> (Redirect, Arc<AtomicUsize>) {
    let (calls, decide) = pool(size);
    (Redirect::new(decide), calls)
}

// -- Packet builders: every packet carries valid checksums. --

fn segment(protocol: u8, src: u16, dst: u16, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut segment = vec![0; if protocol == protocol::TCP { 20 } else { 8 }];
    segment[0..2].copy_from_slice(&src.to_be_bytes());
    segment[2..4].copy_from_slice(&dst.to_be_bytes());
    if protocol == protocol::TCP {
        segment[12] = 5 << 4;
        segment[13] = flags;
        segment[14..16].copy_from_slice(&65535_u16.to_be_bytes());
    } else {
        segment[4..6].copy_from_slice(&u16::try_from(8 + data.len()).unwrap().to_be_bytes());
    }
    segment.extend_from_slice(data);
    segment
}

const fn checksum_at(protocol: u8) -> usize {
    if protocol == protocol::TCP { 16 } else { 6 }
}

/// An IPv4 packet carrying `segment`, with its transport checksum computed
/// unless `zero_checksum`.
fn ipv4_bytes(
    protocol: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    mut segment: Vec<u8>,
    zero_checksum: bool,
) -> Vec<u8> {
    let at = checksum_at(protocol);
    if !zero_checksum {
        let checksum = transport_checksum_v4(src, dst, protocol, &segment);
        segment[at..at + 2].copy_from_slice(&checksum.to_be_bytes());
    }
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(20 + segment.len()).unwrap().to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&segment);
    packet
}

/// A TCP or UDP packet from `src` to `dst`.
fn packet(protocol: u8, src: SocketAddrV4, dst: SocketAddrV4, flags: u8) -> PacketBuf {
    let segment = segment(protocol, src.port(), dst.port(), flags, b"payload");
    PacketBuf::from_packet(&ipv4_bytes(protocol, *src.ip(), *dst.ip(), segment, false))
}

fn tcp(src: SocketAddrV4, dst: SocketAddrV4, flags: u8) -> PacketBuf {
    packet(protocol::TCP, src, dst, flags)
}

fn udp(src: SocketAddrV4, dst: SocketAddrV4) -> PacketBuf {
    packet(protocol::UDP, src, dst, 0)
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn addr(bytes: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3])
}

/// The source and destination of an IPv4 TCP/UDP packet.
fn ends(packet: &PacketBuf) -> (SocketAddrV4, SocketAddrV4) {
    let bytes = packet.as_packet();
    (
        SocketAddrV4::new(addr(bytes, 12), be16(bytes, 20)),
        SocketAddrV4::new(addr(bytes, 16), be16(bytes, 22)),
    )
}

/// Asserts that an IPv4 packet's header and transport checksums are valid.
fn assert_valid(packet: &PacketBuf) {
    let bytes = packet.as_packet();
    assert!(valid(&bytes[..20]), "IPv4 header checksum");
    let (src, dst) = (addr(bytes, 12), addr(bytes, 16));
    assert_eq!(transport_checksum_v4(src, dst, bytes[9], &bytes[20..]), 0);
}

/// Forwards `packet` and asserts that it was redirected; returns its new
/// destination.
fn forward(redirect: &Redirect, mut packet: PacketBuf) -> SocketAddrV4 {
    assert_eq!(redirect.forward(&mut packet), RedirectVerdict::Rewritten);
    assert_valid(&packet);
    ends(&packet).1
}

/// Reverses `packet` and asserts that it was rewritten; returns its new
/// source.
fn reverse(redirect: &Redirect, mut packet: PacketBuf) -> SocketAddrV4 {
    assert_eq!(redirect.reverse(&mut packet), RedirectVerdict::Rewritten);
    assert_valid(&packet);
    ends(&packet).0
}

/// Asserts that `call` passes `packet` unchanged.
fn assert_pass(packet: &mut PacketBuf, call: impl Fn(&mut PacketBuf) -> RedirectVerdict) {
    let before = packet.as_packet().to_vec();
    assert_eq!(call(packet), RedirectVerdict::Pass);
    assert_eq!(packet.as_packet(), before.as_slice());
}

// -- Rewriting (ns `rewrite_inbound_for_netstack` / `rewrite_outbound_from_netstack`). --

#[test]
fn rewrites_tcp_to_the_endpoint_and_restores_the_service_on_replies() {
    let (redirect, _) = redirect(8);
    let mut syn = tcp(CLIENT, SERVICE_A, SYN);
    assert_eq!(redirect.forward(&mut syn), RedirectVerdict::Rewritten);
    assert_valid(&syn);
    let (src, stack_local) = ends(&syn);
    assert_eq!(src, CLIENT, "the source is kept");
    assert_eq!(stack_local, endpoint(FIRST_PORT));
    assert_eq!(&syn.as_packet()[40..], b"payload");

    let restored = reverse(&redirect, tcp(stack_local, CLIENT, SYN_ACK));
    assert_eq!(restored, SERVICE_A);
    let stats = redirect.stats();
    assert_eq!((stats.redirected, stats.reversed), (1, 1));
    assert_eq!(stats.conntrack.entries, 1);
}

#[test]
fn rewrites_udp_to_the_endpoint_and_restores_the_service_on_replies() {
    let (redirect, _) = redirect(8);
    let stack_local = forward(&redirect, udp(CLIENT, SERVICE_A));
    assert_eq!(stack_local, endpoint(FIRST_PORT));
    let mut reply = udp(stack_local, CLIENT);
    assert_eq!(redirect.reverse(&mut reply), RedirectVerdict::Rewritten);
    assert_valid(&reply);
    assert_eq!(ends(&reply), (SERVICE_A, CLIENT));
}

#[test]
fn keeps_a_zero_udp_checksum_zero() {
    let (redirect, _) = redirect(8);
    let request = segment(protocol::UDP, CLIENT.port(), SERVICE_A.port(), 0, b"x");
    let bytes = ipv4_bytes(protocol::UDP, *CLIENT.ip(), *SERVICE_A.ip(), request, true);
    let mut packet = PacketBuf::from_packet(&bytes);
    assert_eq!(redirect.forward(&mut packet), RedirectVerdict::Rewritten);
    assert!(valid(&packet.as_packet()[..20]));
    assert_eq!(be16(packet.as_packet(), 26), 0);

    let answer = segment(protocol::UDP, FIRST_PORT, CLIENT.port(), 0, b"y");
    let bytes = ipv4_bytes(protocol::UDP, STACK, *CLIENT.ip(), answer, true);
    let mut reply = PacketBuf::from_packet(&bytes);
    assert_eq!(redirect.reverse(&mut reply), RedirectVerdict::Rewritten);
    assert_eq!(ends(&reply).0, SERVICE_A);
    assert_eq!(be16(reply.as_packet(), 26), 0);
}

#[test]
fn resolves_the_original_destination_of_tcp_and_udp_flows() {
    let (redirect, _) = redirect(8);
    let tcp_local = forward(&redirect, tcp(CLIENT, SERVICE_A, SYN));
    let udp_local = forward(&redirect, udp(CLIENT, SERVICE_B));
    assert_eq!(
        redirect.original_destination(protocol::TCP, tcp_local, CLIENT),
        Some(SERVICE_A)
    );
    assert_eq!(
        redirect.original_destination(protocol::UDP, udp_local, CLIENT),
        Some(SERVICE_B)
    );
    // Fails closed: wrong protocol, unknown remote, unsupported protocol.
    assert_eq!(
        redirect.original_destination(protocol::UDP, tcp_local, CLIENT),
        None
    );
    assert_eq!(
        redirect.original_destination(protocol::TCP, tcp_local, OTHER_CLIENT),
        None
    );
    assert_eq!(
        redirect.original_destination(protocol::ICMP, tcp_local, CLIENT),
        None
    );
}

#[test]
fn reuses_the_endpoint_of_a_flow_without_asking_again() {
    let (redirect, calls) = redirect(8);
    let first = forward(&redirect, tcp(CLIENT, SERVICE_A, SYN));
    let second = forward(&redirect, tcp(CLIENT, SERVICE_A, ACK));
    assert_eq!(first, second);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(reverse(&redirect, tcp(first, CLIENT, ACK)), SERVICE_A);
}

#[test]
fn gives_distinct_flows_distinct_endpoints() {
    let (redirect, calls) = redirect(8);
    let a = forward(&redirect, tcp(CLIENT, SERVICE_A, SYN));
    let b = forward(&redirect, tcp(CLIENT, SERVICE_B, SYN));
    assert_ne!(a, b);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    // The same client port to two services: each reply gets its own service.
    assert_eq!(reverse(&redirect, tcp(a, CLIENT, SYN_ACK)), SERVICE_A);
    assert_eq!(reverse(&redirect, tcp(b, CLIENT, SYN_ACK)), SERVICE_B);
}

#[test]
fn asks_again_when_the_endpoint_is_in_use_by_the_same_source() {
    let endpoints = Mutex::new(vec![endpoint(2), endpoint(1), endpoint(1)]);
    let redirect = Redirect::new(move |_| {
        RedirectDecision::Redirect(endpoints.lock().unwrap().pop().unwrap())
    });
    assert_eq!(forward(&redirect, udp(CLIENT, SERVICE_A)), endpoint(1));
    assert_eq!(forward(&redirect, udp(CLIENT, SERVICE_B)), endpoint(2));
    assert_eq!(redirect.stats().conflicts, 0);
}

#[test]
fn drops_a_new_flow_when_every_offered_endpoint_is_in_use() {
    // ns `StackEndpointPoolExhausted`: a pool of one endpoint.
    let (redirect, calls) = redirect(1);
    forward(&redirect, udp(CLIENT, SERVICE_A));
    let mut packet = udp(CLIENT, SERVICE_B);
    assert_eq!(
        redirect.forward(&mut packet),
        RedirectVerdict::Drop(reasons::ENDPOINT_EXHAUSTED)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1 + ENDPOINT_TRIES);
    let stats = redirect.stats();
    assert_eq!((stats.conflicts, stats.dropped), (1, 0));
    assert_eq!(stats.conntrack.entries, 1);

    // Another source may share the endpoint: its replies differ.
    assert_eq!(
        forward(&redirect, udp(OTHER_CLIENT, SERVICE_B)),
        endpoint(FIRST_PORT)
    );
}

// -- Flow removal (ns `remove_netstack_flow`, `revoke_removed_routes`, `clear_udp_flows`). --

#[test]
fn removed_flows_stop_rewriting_and_ask_again() {
    let (redirect, calls) = redirect(8);
    let local = forward(&redirect, tcp(CLIENT, SERVICE_A, SYN));
    assert!(!redirect.remove_flow(protocol::UDP, local, CLIENT));
    assert!(!redirect.remove_flow(protocol::ICMP, local, CLIENT));
    assert!(redirect.remove_flow(protocol::TCP, local, CLIENT));
    assert!(!redirect.remove_flow(protocol::TCP, local, CLIENT));

    assert_pass(&mut tcp(local, CLIENT, ACK), |p| redirect.reverse(p));
    assert_eq!(
        redirect.original_destination(protocol::TCP, local, CLIENT),
        None
    );
    forward(&redirect, tcp(CLIENT, SERVICE_A, ACK));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(redirect.stats().conntrack.removed, 1);
}

#[test]
fn retain_revokes_the_flows_of_a_service() {
    let (redirect, _) = redirect(8);
    let a = forward(&redirect, tcp(CLIENT, SERVICE_A, SYN));
    let b = forward(&redirect, tcp(CLIENT, SERVICE_B, SYN));
    let revoked = IpAddr::V4(*SERVICE_A.ip());
    assert_eq!(redirect.retain(|flow| flow.original.dst != revoked), 1);
    assert_pass(&mut tcp(a, CLIENT, SYN_ACK), |p| redirect.reverse(p));
    assert_eq!(reverse(&redirect, tcp(b, CLIENT, SYN_ACK)), SERVICE_B);
}

#[test]
fn clearing_udp_flows_keeps_tcp_flows() {
    let (redirect, _) = redirect(8);
    let tcp_local = forward(&redirect, tcp(CLIENT, SERVICE_A, SYN));
    let udp_local = forward(&redirect, udp(CLIENT, SERVICE_A));
    assert_eq!(
        redirect.retain(|flow| flow.original.protocol != protocol::UDP),
        1
    );
    assert_pass(&mut udp(udp_local, CLIENT), |p| redirect.reverse(p));
    assert_eq!(
        reverse(&redirect, tcp(tcp_local, CLIENT, SYN_ACK)),
        SERVICE_A
    );
}

// -- Flow lifetime. --

#[test]
fn idle_flows_expire() {
    let now = Arc::new(Mutex::new(Instant::now()));
    let clock = Arc::clone(&now);
    let conntrack =
        Conntrack::with_clock(ConntrackConfig::default(), move || *clock.lock().unwrap());
    let (calls, decide) = pool(8);
    let redirect = Redirect::with_conntrack(conntrack, decide);
    let local = forward(&redirect, udp(CLIENT, SERVICE_A));

    *now.lock().unwrap() += Duration::from_secs(29);
    assert_eq!(reverse(&redirect, udp(local, CLIENT)), SERVICE_A);
    *now.lock().unwrap() += Duration::from_secs(30);
    assert_pass(&mut udp(local, CLIENT), |p| redirect.reverse(p));
    assert_eq!(redirect.stats().conntrack.expired, 1);
    forward(&redirect, udp(CLIENT, SERVICE_A));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn a_full_table_evicts_the_least_recently_seen_flow() {
    let config = ConntrackConfig {
        max_entries: 2,
        ..ConntrackConfig::default()
    };
    let (_, decide) = pool(8);
    let redirect = Redirect::with_conntrack(Conntrack::new(config), decide);
    let a = forward(&redirect, udp(CLIENT, SERVICE_A));
    let b = forward(&redirect, udp(CLIENT, SERVICE_B));
    forward(&redirect, udp(OTHER_CLIENT, SERVICE_A));
    assert_pass(&mut udp(a, CLIENT), |p| redirect.reverse(p));
    assert_eq!(reverse(&redirect, udp(b, CLIENT)), SERVICE_B);
    let stats = redirect.stats().conntrack;
    assert_eq!((stats.entries, stats.evicted), (2, 1));
}

#[test]
fn an_empty_table_drops_new_flows() {
    let config = ConntrackConfig {
        max_entries: 0,
        ..ConntrackConfig::default()
    };
    let (_, decide) = pool(8);
    let redirect = Redirect::with_conntrack(Conntrack::new(config), decide);
    assert_eq!(
        redirect.forward(&mut udp(CLIENT, SERVICE_A)),
        RedirectVerdict::Drop(reasons::CONNTRACK_FULL)
    );
    assert_eq!(redirect.stats().dropped, 1);
}

// -- Decisions and packets left alone. --

#[test]
fn denied_flows_are_dropped_and_not_recorded() {
    let redirect = Redirect::new(|_| RedirectDecision::Drop);
    assert_eq!(
        redirect.forward(&mut tcp(CLIENT, SERVICE_A, SYN)),
        RedirectVerdict::Drop(reasons::DENIED)
    );
    let stats = redirect.stats();
    assert_eq!((stats.dropped, stats.conntrack.entries), (1, 0));
}

#[test]
fn passed_flows_are_unchanged_and_asked_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let redirect = Redirect::new(move |_| {
        counter.fetch_add(1, Ordering::Relaxed);
        RedirectDecision::Pass
    });
    for _ in 0..2 {
        assert_pass(&mut tcp(CLIENT, SERVICE_A, SYN), |p| redirect.forward(p));
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(redirect.stats().conntrack.entries, 0);
}

#[test]
fn other_packets_pass_byte_identical_without_a_decision() {
    let (redirect, calls) = redirect(8);
    let ipv6 = {
        let mut bytes = vec![0; 48];
        bytes[0] = 0x60;
        bytes[5] = 8;
        bytes[6] = protocol::UDP;
        bytes[7] = 64;
        bytes[40..42].copy_from_slice(&CLIENT.port().to_be_bytes());
        bytes[42..44].copy_from_slice(&SERVICE_A.port().to_be_bytes());
        bytes[44..46].copy_from_slice(&8_u16.to_be_bytes());
        bytes
    };
    let icmp = ipv4_bytes(
        protocol::ICMP,
        *CLIENT.ip(),
        *SERVICE_A.ip(),
        vec![8, 0, 0, 0, 0, 1, 0, 1],
        true,
    );
    let mut fragment = udp(CLIENT, SERVICE_A).as_packet().to_vec();
    fragment[6] = 0x20; // more fragments
    let packets = [ipv6, icmp, fragment, vec![0x45, 0, 0], Vec::new()];
    for bytes in &packets {
        assert_pass(&mut PacketBuf::from_packet(bytes), |p| redirect.forward(p));
        assert_pass(&mut PacketBuf::from_packet(bytes), |p| redirect.reverse(p));
    }
    // A reply of an untracked flow.
    assert_pass(&mut udp(endpoint(FIRST_PORT), CLIENT), |p| {
        redirect.reverse(p)
    });
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(redirect.stats().passed, 2 * packets.len() as u64 + 1);
}

// -- Re-entrancy and races. --

/// A slot through which a decision closure reaches its own `Redirect`.
type Slot = Arc<OnceLock<Weak<Redirect>>>;

fn reentrant(
    decide: impl Fn(&Redirect, &FiveTuple) -> RedirectDecision + Send + Sync + 'static,
) -> Arc<Redirect> {
    let slot: Slot = Arc::new(OnceLock::new());
    let inner = Arc::clone(&slot);
    let redirect = Arc::new(Redirect::new(move |tuple| {
        let redirect = inner.get().and_then(Weak::upgrade).unwrap();
        decide(&redirect, tuple)
    }));
    slot.set(Arc::downgrade(&redirect)).unwrap();
    redirect
}

#[test]
fn decide_may_call_back_into_the_redirect() {
    // A pool of one endpoint that recycles it: each new flow ends the flow
    // that holds it. Would deadlock if `decide` ran under a lock.
    let holder = Arc::new(Mutex::new(None::<SocketAddrV4>));
    let held = Arc::clone(&holder);
    let redirect = reentrant(move |redirect, tuple| {
        let IpAddr::V4(src) = tuple.src else {
            return RedirectDecision::Drop;
        };
        let mut holder = held.lock().unwrap();
        if let Some(previous) = holder.replace(SocketAddrV4::new(src, tuple.src_port)) {
            assert!(
                redirect
                    .original_destination(protocol::UDP, endpoint(1), previous)
                    .is_some()
            );
            assert!(redirect.remove_flow(protocol::UDP, endpoint(1), previous));
            assert_eq!(redirect.retain(|_| true), 0);
        }
        RedirectDecision::Redirect(endpoint(1))
    });
    assert_eq!(forward(&redirect, udp(CLIENT, SERVICE_A)), endpoint(1));
    assert_eq!(forward(&redirect, udp(CLIENT, SERVICE_B)), endpoint(1));
    assert_eq!(reverse(&redirect, udp(endpoint(1), CLIENT)), SERVICE_B);
    let stats = redirect.stats().conntrack;
    assert_eq!((stats.entries, stats.removed), (1, 1));
}

#[test]
fn a_racing_first_packet_takes_the_recorded_flow() {
    // The first decision forwards the same packet again before answering, as
    // a racing thread that wins the insert would.
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let redirect = reentrant(move |redirect, _| {
        if counter.fetch_add(1, Ordering::Relaxed) == 0 {
            assert_eq!(forward(redirect, udp(CLIENT, SERVICE_A)), endpoint(2));
            return RedirectDecision::Redirect(endpoint(1));
        }
        RedirectDecision::Redirect(endpoint(2))
    });
    assert_eq!(forward(&redirect, udp(CLIENT, SERVICE_A)), endpoint(2));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    let stats = redirect.stats().conntrack;
    assert_eq!((stats.entries, stats.inserted), (1, 1));
}

#[test]
fn concurrent_first_packets_record_one_flow() {
    const THREADS: usize = 8;
    let (redirect, _) = redirect(64);
    let barrier = Barrier::new(THREADS);
    let endpoints: Vec<_> = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            handles.push(scope.spawn(|| {
                barrier.wait();
                forward(&redirect, udp(CLIENT, SERVICE_A))
            }));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(endpoints.iter().all(|e| *e == endpoints[0]));
    let stats = redirect.stats().conntrack;
    assert_eq!((stats.entries, stats.inserted), (1, 1));
}
