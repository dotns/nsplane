//! Tests of the conntrack table, adapted from ns `conntrack/table/tests.rs`
//! with a hand-moved clock instead of a background sweeper.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nsplane_packet::{FiveTuple, PeerId, protocol};

use super::*;

const PEER: PeerId = PeerId::new(1);
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;
const FIN_ACK: u8 = 0x11;
const RST: u8 = 0x04;

const LISTEN: [u8; 4] = [10, 0, 0, 1];
const TARGET: [u8; 4] = [127, 0, 0, 1];

fn config() -> ConntrackConfig {
    ConntrackConfig {
        max_entries: 16,
        tcp_established_timeout: Duration::from_secs(300),
        tcp_transitory_timeout: Duration::from_secs(30),
        udp_timeout: Duration::from_secs(60),
        icmp_timeout: Duration::from_secs(10),
    }
}

/// A table whose clock is moved by hand, with the clock handle.
fn clocked(config: ConntrackConfig) -> (Conntrack, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let handle = Arc::clone(&clock);
    (
        Conntrack::with_clock(config, move || *handle.lock().unwrap()),
        clock,
    )
}

fn advance(clock: &Mutex<Instant>, secs: u64) {
    *clock.lock().unwrap() += Duration::from_secs(secs);
}

fn tuple(proto: u8, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> FiveTuple {
    FiveTuple {
        src: IpAddr::V4(Ipv4Addr::from(src)),
        dst: IpAddr::V4(Ipv4Addr::from(dst)),
        protocol: proto,
        src_port: sport,
        dst_port: dport,
    }
}

/// The original and translated tuples of client `10.0.0.<host>:<port>` to
/// `LISTEN:80`, mapped to `TARGET:8080`.
fn flow(proto: u8, host: u8, port: u16) -> (FiveTuple, FiveTuple) {
    let original = tuple(proto, [10, 0, 0, host], port, LISTEN, 80);
    let translated = tuple(proto, [10, 0, 0, host], port, TARGET, 8080);
    (original, translated)
}

fn insert(table: &Conntrack, (original, translated): (FiveTuple, FiveTuple), flags: u8) -> Flow {
    table.insert(PEER, original, translated, flags).unwrap()
}

/// Every inserted flow is in the table or counted as gone exactly once.
fn assert_balanced(table: &Conntrack) {
    let s = table.stats();
    assert_eq!(
        s.inserted,
        s.entries as u64 + s.expired + s.evicted + s.removed,
        "{s:?}"
    );
}

#[test]
fn insert_and_lookup_both_directions_refresh_the_flow() {
    let (table, clock) = clocked(config());
    let tuples = flow(protocol::UDP, 2, 40000);
    let inserted = insert(&table, tuples, 0);
    assert_eq!(inserted.peer, PEER);
    assert_eq!(inserted.tcp_state, None);

    advance(&clock, 40);
    let found = table.lookup(&tuples.0, None).unwrap();
    assert_eq!(found.direction, FlowDirection::Original);
    assert_eq!(found.flow, inserted);

    // 80 s after insert but 40 s after the last hit: still alive.
    advance(&clock, 40);
    let found = table.lookup(&reverse(&tuples.1), None).unwrap();
    assert_eq!(found.direction, FlowDirection::Reply);

    // The translated tuple itself and the reverse of the original are not keys.
    assert_eq!(table.lookup(&tuples.1, None), None);
    assert_eq!(table.lookup(&reverse(&tuples.0), None), None);

    let s = table.stats();
    assert_eq!((s.entries, s.inserted, s.hits, s.misses), (1, 1, 2, 2));
    assert_balanced(&table);
}

#[test]
fn timeouts_follow_the_protocol() {
    let (table, clock) = clocked(config());
    let udp = flow(protocol::UDP, 2, 40000);
    let tcp = flow(protocol::TCP, 3, 40000);
    let icmp = (
        tuple(protocol::ICMP, [10, 0, 0, 4], 7, LISTEN, 7),
        tuple(protocol::ICMP, [10, 0, 0, 4], 7, TARGET, 7),
    );
    insert(&table, udp, 0);
    insert(&table, tcp, SYN);
    insert(&table, icmp, 0);
    let state = table.lookup(&reverse(&tcp.1), Some(SYN_ACK)).unwrap();
    assert_eq!(state.flow.tcp_state, Some(TcpState::Established));

    advance(&clock, 10);
    assert_eq!(table.lookup(&icmp.0, None), None, "ICMP after 10 s");
    advance(&clock, 50);
    assert_eq!(table.lookup(&udp.0, None), None, "UDP after 60 s");
    assert!(
        table.lookup(&tcp.0, None).is_some(),
        "established TCP after 60 s"
    );
    advance(&clock, 300);
    assert_eq!(table.lookup(&tcp.0, None), None, "TCP after 300 s idle");

    let s = table.stats();
    assert_eq!((s.entries, s.expired), (0, 3));
    assert_balanced(&table);
}

#[test]
fn expired_flow_is_gone_and_the_next_packet_creates_a_new_one() {
    let (table, clock) = clocked(config());
    let tuples = flow(protocol::UDP, 2, 40000);
    insert(&table, tuples, 0);
    advance(&clock, 59);
    assert!(table.lookup(&tuples.0, None).is_some());
    advance(&clock, 60);
    assert_eq!(table.lookup(&reverse(&tuples.1), None), None);
    assert_eq!(table.stats().entries, 0);

    insert(&table, tuples, 0);
    assert!(table.lookup(&tuples.0, None).is_some());
    let s = table.stats();
    assert_eq!((s.entries, s.inserted, s.expired), (1, 2, 1));
    assert_balanced(&table);
}

#[test]
fn insert_of_an_expired_original_replaces_it() {
    let (table, clock) = clocked(config());
    let tuples = flow(protocol::UDP, 2, 40000);
    insert(&table, tuples, 0);
    advance(&clock, 60);
    // No lookup in between: the insert itself finds the stale flow.
    insert(&table, tuples, 0);
    let s = table.stats();
    assert_eq!((s.entries, s.inserted, s.expired), (1, 2, 1));
    assert_balanced(&table);
}

#[test]
fn full_table_evicts_the_least_recently_seen_flow() {
    let (table, clock) = clocked(ConntrackConfig {
        max_entries: 3,
        ..config()
    });
    let flows: Vec<_> = (2..6)
        .map(|host| flow(protocol::UDP, host, 40000))
        .collect();
    for tuples in &flows[..3] {
        insert(&table, *tuples, 0);
        advance(&clock, 1);
    }
    // Refresh the oldest, so the second becomes the least recently seen.
    assert!(table.lookup(&flows[0].0, None).is_some());
    insert(&table, flows[3], 0);

    assert!(table.lookup(&flows[0].0, None).is_some());
    assert_eq!(table.lookup(&flows[1].0, None), None, "evicted");
    assert!(table.lookup(&flows[2].0, None).is_some());
    assert!(table.lookup(&flows[3].0, None).is_some());
    let s = table.stats();
    assert_eq!((s.entries, s.evicted, s.expired), (3, 1, 0));
    assert_balanced(&table);
}

#[test]
fn full_table_drops_an_expired_flow_before_evicting_a_live_one() {
    let (table, clock) = clocked(ConntrackConfig {
        max_entries: 2,
        ..config()
    });
    let icmp = (
        tuple(protocol::ICMP, [10, 0, 0, 4], 7, LISTEN, 7),
        tuple(protocol::ICMP, [10, 0, 0, 4], 7, TARGET, 7),
    );
    insert(&table, icmp, 0);
    insert(&table, flow(protocol::UDP, 2, 40000), 0);
    advance(&clock, 10);
    insert(&table, flow(protocol::UDP, 3, 40000), 0);

    let s = table.stats();
    assert_eq!((s.entries, s.expired, s.evicted), (2, 1, 0));
    assert_balanced(&table);
}

#[test]
fn zero_max_entries_refuses_every_flow() {
    let (table, _clock) = clocked(ConntrackConfig {
        max_entries: 0,
        ..config()
    });
    let (original, translated) = flow(protocol::UDP, 2, 40000);
    assert_eq!(
        table.insert(PEER, original, translated, 0),
        Err(ConntrackError::Full)
    );
    assert_eq!(table.stats(), ConntrackStats::default());
}

#[test]
fn inserts_sweep_expired_flows() {
    let (table, clock) = clocked(config());
    for host in 2..6 {
        insert(&table, flow(protocol::UDP, host, 40000), 0);
    }
    advance(&clock, 60);
    // No lookups: the sweep of the next insert finds the four expired flows.
    insert(&table, flow(protocol::UDP, 9, 40000), 0);
    let s = table.stats();
    assert_eq!((s.entries, s.expired), (1, 4));
    assert_balanced(&table);
}

#[test]
fn tcp_state_sets_the_timeout() {
    let (table, clock) = clocked(config());
    let tuples = flow(protocol::TCP, 2, 40000);
    let reply = reverse(&tuples.1);

    // Handshake without an answer: transitory timeout.
    assert_eq!(
        insert(&table, tuples, SYN).tcp_state,
        Some(TcpState::SynSent)
    );
    advance(&clock, 30);
    assert_eq!(table.lookup(&tuples.0, Some(SYN)), None);

    // Answered handshake: established timeout.
    insert(&table, tuples, SYN);
    advance(&clock, 29);
    let m = table.lookup(&reply, Some(SYN_ACK)).unwrap();
    assert_eq!(m.flow.tcp_state, Some(TcpState::Established));
    advance(&clock, 299);
    let m = table.lookup(&tuples.0, Some(ACK)).unwrap();
    assert_eq!(m.flow.tcp_state, Some(TcpState::Established));

    // FIN: back to the transitory timeout.
    let m = table.lookup(&tuples.0, Some(FIN_ACK)).unwrap();
    assert_eq!(m.flow.tcp_state, Some(TcpState::Closing));
    let m = table.lookup(&reply, Some(ACK)).unwrap();
    assert_eq!(m.flow.tcp_state, Some(TcpState::Closing));
    advance(&clock, 30);
    assert_eq!(table.lookup(&tuples.0, Some(ACK)), None);

    // RST closes; a new SYN on the same tuple starts over.
    insert(&table, tuples, SYN);
    table.lookup(&reply, Some(SYN_ACK)).unwrap();
    let m = table.lookup(&reply, Some(RST)).unwrap();
    assert_eq!(m.flow.tcp_state, Some(TcpState::Closed));
    let m = table.lookup(&tuples.0, Some(SYN)).unwrap();
    assert_eq!(m.flow.tcp_state, Some(TcpState::SynSent));

    // An ICMP error lookup (no flags) does not move the state.
    let m = table.lookup(&reply, None).unwrap();
    assert_eq!(m.flow.tcp_state, Some(TcpState::SynSent));

    assert_eq!(table.stats().expired, 2);
    assert_balanced(&table);
}

#[test]
fn mid_stream_pickup_waits_for_a_reply() {
    let (table, _clock) = clocked(config());
    let tuples = flow(protocol::TCP, 2, 40000);
    assert_eq!(
        insert(&table, tuples, ACK).tcp_state,
        Some(TcpState::SynSent)
    );
    let m = table.lookup(&reverse(&tuples.1), Some(ACK)).unwrap();
    assert_eq!(m.flow.tcp_state, Some(TcpState::Established));
    // A RST as the first packet records a closed flow.
    let other = flow(protocol::TCP, 3, 40000);
    assert_eq!(insert(&table, other, RST).tcp_state, Some(TcpState::Closed));
}

#[test]
fn shared_reply_tuple_is_a_conflict_until_the_owner_expires() {
    let (table, clock) = clocked(config());
    let (original, translated) = flow(protocol::UDP, 2, 40000);
    insert(&table, (original, translated), 0);
    // The same client port to another listen address, mapped to the same target.
    let other = tuple(protocol::UDP, [10, 0, 0, 2], 40000, [10, 0, 0, 9], 80);
    assert_eq!(
        table.insert(PEER, other, translated, 0),
        Err(ConntrackError::Conflict)
    );
    advance(&clock, 60);
    insert(&table, (other, translated), 0);
    let m = table.lookup(&reverse(&translated), None).unwrap();
    assert_eq!(m.flow.original, other);
    assert_balanced(&table);
}

#[test]
fn insert_of_a_live_original_returns_the_existing_flow() {
    let (table, _clock) = clocked(config());
    let tuples = flow(protocol::UDP, 2, 40000);
    let first = insert(&table, tuples, 0);
    let other_target = tuple(protocol::UDP, [10, 0, 0, 2], 40000, TARGET, 9090);
    let second = table
        .insert(PeerId::new(2), tuples.0, other_target, 0)
        .unwrap();
    assert_eq!(second, first);
    assert_eq!(table.stats().inserted, 1);
}

#[test]
fn retain_removes_and_counts() {
    let (table, _clock) = clocked(config());
    for host in 2..6 {
        insert(&table, flow(protocol::UDP, host, 40000), 0);
    }
    let removed = table.retain(|flow| flow.original.src_port == 0);
    assert_eq!(removed, 4);
    // Freed slots are reused.
    insert(&table, flow(protocol::UDP, 7, 40000), 0);
    let s = table.stats();
    assert_eq!((s.entries, s.removed), (1, 4));
    assert!(
        table
            .lookup(&flow(protocol::UDP, 7, 40000).0, None)
            .is_some()
    );
    assert_balanced(&table);
}

#[test]
fn unsupported_protocols_are_refused() {
    let (table, _clock) = clocked(config());
    let (original, translated) = flow(47, 2, 0);
    assert_eq!(
        table.insert(PEER, original, translated, 0),
        Err(ConntrackError::Unsupported)
    );
    let (tcp, _) = flow(protocol::TCP, 2, 40000);
    let (_, udp) = flow(protocol::UDP, 2, 40000);
    assert_eq!(
        table.insert(PEER, tcp, udp, 0),
        Err(ConntrackError::Unsupported)
    );
}

#[test]
fn lru_order_survives_heavy_churn() {
    let (table, clock) = clocked(ConntrackConfig {
        max_entries: 8,
        ..config()
    });
    for port in 0..200u16 {
        insert(&table, flow(protocol::UDP, 2, 1000 + port), 0);
        // Keep port 1000 hot: it must never be evicted.
        assert!(
            table
                .lookup(&flow(protocol::UDP, 2, 1000).0, None)
                .is_some()
        );
        advance(&clock, 1);
    }
    let s = table.stats();
    assert_eq!((s.entries, s.evicted), (8, 192));
    for port in std::iter::once(1000).chain(1193..1200) {
        let present = table
            .lookup(&flow(protocol::UDP, 2, port).0, None)
            .is_some();
        assert!(present, "port {port}");
    }
    assert_balanced(&table);
}

#[test]
fn conntrack_is_shareable() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Conntrack>();
    assert_eq!(Conntrack::default().config(), ConntrackConfig::default());
}
