//! The per-source quota, the gate in front of the expiry scan and the short
//! timeout of closing TCP flows.

use super::*;

/// A second LAN host.
const NEIGHBOR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xaa, 0, 0, 0, 0, 0, 0x11);
const FIN_ACK: u8 = 0x11;
const RST: u8 = 0x04;

fn quota_fixture(max_flows: usize, per_source: Option<usize>) -> Fixture {
    let mut fixture = Fixture::new(MasqueradeConfig {
        max_flows,
        ..MasqueradeConfig::default()
    });
    if let Some(flows) = per_source {
        fixture.masquerade = fixture.masquerade.with_max_flows_per_source(flows);
    }
    fixture
}

fn from(host: Ipv6Addr, port: u16) -> PacketBuf {
    udp((host, port), (REMOTE, 53))
}

fn may_expire(fixture: &Fixture) -> bool {
    let now = *fixture.now.lock().unwrap();
    fixture.masquerade.lock().may_expire(now)
}

#[test]
fn the_default_quota_is_half_the_table() {
    assert_eq!(fixture().masquerade.max_flows_per_source(), 2048);
    for (max_flows, quota) in [(0, 0), (1, 1), (3, 2), (4, 2)] {
        let fixture = quota_fixture(max_flows, None);
        assert_eq!(fixture.masquerade.max_flows_per_source(), quota);
    }
    let fixture = quota_fixture(4, Some(4));
    assert_eq!(fixture.masquerade.max_flows_per_source(), 4);
}

#[test]
fn one_source_cannot_fill_the_table() {
    let f = quota_fixture(4, None);
    f.forward(from(HOST, 1));
    f.forward(from(HOST, 2));
    assert_drop(from(HOST, 3), reasons::SOURCE_QUOTA, |p| {
        f.masquerade.forward(p)
    });
    assert_eq!(f.masquerade.source_quota_drops(), 1);
    assert_eq!(f.masquerade.len(), 2);
    // The recorded flows go on, and the other host has its share.
    f.forward(from(HOST, 1));
    f.forward(from(NEIGHBOR, 1));
    f.forward(from(NEIGHBOR, 2));
    // The table's own bound comes first.
    assert_drop(from(NEIGHBOR, 3), reasons::CAPACITY, |p| {
        f.masquerade.forward(p)
    });
    let stats = f.masquerade.stats();
    assert_eq!((stats.flows, stats.capacity, stats.created), (4, 1, 4));
    assert_eq!(f.masquerade.source_quota_drops(), 1);
}

#[test]
fn the_quota_counts_live_flows_only() {
    let f = quota_fixture(8, Some(2));
    f.forward(from(HOST, 1));
    f.advance(Duration::from_mins(1));
    let second = f.forward(from(HOST, 2));
    assert_drop(from(HOST, 3), reasons::SOURCE_QUOTA, |p| {
        f.masquerade.forward(p)
    });
    // The first flow expires: its place is free again.
    f.advance(Duration::from_mins(1));
    f.forward(from(HOST, 3));
    assert_drop(from(HOST, 4), reasons::SOURCE_QUOTA, |p| {
        f.masquerade.forward(p)
    });
    // A flow removed for its route frees its place too.
    f.answer(Some(decision(ROUTE + 1)));
    assert_drop(reply(&second), reasons::ROUTE_CHANGED, |p| {
        f.masquerade.reverse(p)
    });
    f.forward(from(HOST, 4));
    assert_eq!(f.masquerade.len(), 2);
    assert_eq!(f.masquerade.source_quota_drops(), 2);
}

#[test]
fn a_raised_quota_gives_one_source_the_whole_table() {
    let f = quota_fixture(4, Some(4));
    for port in 1..=4 {
        f.forward(from(HOST, port));
    }
    assert_drop(from(HOST, 5), reasons::CAPACITY, |p| {
        f.masquerade.forward(p)
    });
    assert_eq!(f.masquerade.source_quota_drops(), 0);
}

#[test]
fn a_full_table_is_scanned_only_when_a_flow_may_have_expired() {
    let f = quota_fixture(2, Some(2));
    assert!(!may_expire(&f), "an empty table has nothing to expire");
    f.forward(from(HOST, 1));
    f.advance(Duration::from_secs(90));
    f.forward(from(HOST, 2));
    assert_drop(from(HOST, 3), reasons::CAPACITY, |p| {
        f.masquerade.forward(p)
    });
    assert!(!may_expire(&f));
    // The first flow is refreshed just before its 2 min; the bound is the
    // old one until a scan finds that nothing expired.
    f.advance(Duration::from_secs(29));
    f.forward(from(HOST, 1));
    f.advance(Duration::from_secs(1));
    assert!(may_expire(&f));
    assert_drop(from(HOST, 3), reasons::CAPACITY, |p| {
        f.masquerade.forward(p)
    });
    assert!(!may_expire(&f));
    assert_eq!(f.masquerade.len(), 2);
    // The second flow expires 2 min after its only packet.
    f.advance(Duration::from_secs(89));
    assert!(!may_expire(&f));
    f.advance(Duration::from_secs(1));
    assert!(may_expire(&f));
    f.forward(from(HOST, 3));
    let stats = f.masquerade.stats();
    assert_eq!((stats.flows, stats.expired, stats.capacity), (2, 1, 2));
}

#[test]
fn a_shorter_timeout_of_a_later_flow_lowers_the_bound() {
    let f = quota_fixture(2, Some(2));
    f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
    f.forward(echo(HOST, REMOTE, ECHO_REQUEST, 9));
    f.advance(Duration::from_secs(29));
    assert!(!may_expire(&f));
    f.advance(Duration::from_secs(1));
    assert!(may_expire(&f));
    f.forward(from(HOST, 1));
    assert_eq!(f.masquerade.stats().expired, 1);
}

#[test]
fn a_closing_tcp_flow_expires_after_30_s() {
    for (flags, from_remote) in [(FIN_ACK, false), (FIN_ACK, true), (RST, false), (RST, true)] {
        let f = fixture();
        let syn = f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
        f.reverse(reply(&syn));
        // An open flow outlives 30 s of silence.
        f.advance(Duration::from_secs(31));
        assert_eq!(f.masquerade.len(), 1);
        if from_remote {
            f.reverse(tcp((REMOTE, 443), (SOURCE, token(&syn)), flags));
        } else {
            f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), flags));
        }
        // The last packets of the close still find the flow.
        f.advance(Duration::from_secs(29));
        f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), ACK));
        f.advance(Duration::from_secs(29));
        assert_eq!(f.masquerade.len(), 1);
        f.advance(Duration::from_secs(1));
        assert_eq!(f.masquerade.len(), 0, "flags {flags:#x}");
        assert_eq!(f.masquerade.stats().expired, 1);
    }
}

#[test]
fn a_closing_flow_makes_room_in_a_full_table() {
    let f = quota_fixture(1, None);
    f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
    f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), FIN_ACK));
    f.advance(Duration::from_secs(29));
    assert_drop(
        tcp((HOST, HOST_PORT + 1), (REMOTE, 443), SYN),
        reasons::CAPACITY,
        |p| f.masquerade.forward(p),
    );
    f.advance(Duration::from_secs(1));
    f.forward(tcp((HOST, HOST_PORT + 1), (REMOTE, 443), SYN));
}

#[test]
fn a_syn_reuses_a_closing_flow() {
    let f = fixture();
    let syn = f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
    f.reverse(tcp((REMOTE, 443), (SOURCE, token(&syn)), RST));
    let again = f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
    assert_eq!(token(&again), token(&syn));
    f.advance(Duration::from_secs(31));
    assert_eq!(f.masquerade.len(), 1);
    f.advance(Duration::from_mins(5));
    assert_eq!(f.masquerade.len(), 0);
}

#[test]
fn a_fin_with_a_bad_checksum_does_not_close_the_flow() {
    let f = fixture();
    let syn = f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
    let forged = corrupt(&tcp((REMOTE, 443), (SOURCE, token(&syn)), RST));
    assert_drop(forged, reasons::BAD_CHECKSUM, |p| f.masquerade.reverse(p));
    let forged = corrupt(&tcp((HOST, HOST_PORT), (REMOTE, 443), FIN_ACK));
    assert_drop(forged, reasons::BAD_CHECKSUM, |p| f.masquerade.forward(p));
    f.advance(Duration::from_secs(31));
    assert_eq!(f.masquerade.len(), 1);
}

#[test]
fn a_short_tcp_timeout_stays_the_timeout_of_a_closing_flow() {
    let f = Fixture::new(MasqueradeConfig {
        tcp_timeout: Duration::from_secs(10),
        ..MasqueradeConfig::default()
    });
    f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), SYN));
    f.forward(tcp((HOST, HOST_PORT), (REMOTE, 443), FIN_ACK));
    f.advance(Duration::from_secs(9));
    assert_eq!(f.masquerade.len(), 1);
    f.advance(Duration::from_secs(1));
    assert_eq!(f.masquerade.len(), 0);
}
