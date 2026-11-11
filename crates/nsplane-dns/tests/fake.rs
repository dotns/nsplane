//! `FakePool` behavior.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nsplane_dns::{
    Answer, FakePool, FakePoolConfig, FakePoolConfigError, FakePoolStats, Query, Record, Resolver,
    ResponseCode, StaticRecords,
};
use simple_dns::{CLASS, Name, Packet, Question, TYPE};

fn query(name: &str, qtype: TYPE) -> Query {
    let mut packet = Packet::new_query(1);
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        qtype.into(),
        CLASS::IN.into(),
        false,
    ));
    Query::decode(&packet.build_bytes_vec().unwrap()).unwrap()
}

fn client() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40000))
}

const NET4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
const NET6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);

fn config(ipv4_len: Option<u8>, ipv6_len: Option<u8>) -> FakePoolConfig {
    FakePoolConfig {
        ipv4: ipv4_len.map(|len| (NET4, len)),
        ipv6: ipv6_len.map(|len| (NET6, len)),
        ..FakePoolConfig::default()
    }
}

async fn a(pool: &impl Resolver, name: &str) -> Answer {
    pool.resolve(&query(name, TYPE::A), client()).await
}

async fn a_addr(pool: &impl Resolver, name: &str) -> Ipv4Addr {
    match a(pool, name).await {
        Answer::Records(records) if records.len() == 1 => match records[0].data {
            nsplane_dns::RecordData::A(addr) => addr,
            ref other => panic!("not an A record: {other:?}"),
        },
        other => panic!("unexpected answer: {other:?}"),
    }
}

async fn aaaa(pool: &impl Resolver, name: &str) -> Answer {
    pool.resolve(&query(name, TYPE::AAAA), client()).await
}

#[tokio::test(start_paused = true)]
async fn allocates_sequentially_from_both_families() {
    let pool = FakePool::new(config(Some(24), Some(64))).unwrap();
    assert_eq!(pool.capacity(), 254);
    assert!(pool.is_empty());

    assert_eq!(
        a(&pool, "one.example").await,
        Answer::Records(vec![Record::a(
            "one.example",
            60,
            Ipv4Addr::new(198, 18, 0, 1)
        )])
    );
    assert_eq!(
        aaaa(&pool, "two.example").await,
        Answer::Records(vec![Record::aaaa(
            "two.example",
            60,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)
        )])
    );
    // AAAA of `one` comes from the same binding as its A.
    assert_eq!(
        aaaa(&pool, "One.Example.").await,
        Answer::Records(vec![Record::aaaa(
            "one.example",
            60,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)
        )])
    );
    assert_eq!(
        a_addr(&pool, "two.example").await,
        Ipv4Addr::new(198, 18, 0, 2)
    );
    assert_eq!(pool.len(), 2);
    assert_eq!(
        pool.lookup_name("ONE.example"),
        Some((
            Some(Ipv4Addr::new(198, 18, 0, 1)),
            Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
        ))
    );
    assert_eq!(pool.lookup_name("three.example"), None);
    assert_eq!(pool.len(), 2);
    assert_eq!(
        pool.stats(),
        FakePoolStats {
            allocated: 2,
            reused: 0,
            exhausted: 0
        }
    );
}

#[tokio::test(start_paused = true)]
async fn skips_network_and_broadcast() {
    let pool = FakePool::new(config(Some(30), None))
        .unwrap()
        .with_client_limit(2);
    assert_eq!(pool.capacity(), 2);
    assert_eq!(a_addr(&pool, "a").await, Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(a_addr(&pool, "b").await, Ipv4Addr::new(198, 18, 0, 2));

    // /31 has no broadcast address, only the network address is skipped.
    let pool = FakePool::new(config(Some(31), None)).unwrap();
    assert_eq!(pool.capacity(), 1);
    assert_eq!(a_addr(&pool, "a").await, Ipv4Addr::new(198, 18, 0, 1));

    // Capacity bounds the pool below the prefix size.
    let pool = FakePool::new(FakePoolConfig {
        capacity: 3,
        ..config(Some(24), Some(120))
    })
    .unwrap();
    assert_eq!(pool.capacity(), 3);
    let pool = FakePool::new(config(Some(24), Some(126))).unwrap();
    assert_eq!(pool.capacity(), 3);
}

#[tokio::test(start_paused = true)]
async fn missing_family_answers_nodata() {
    let pool = FakePool::new(config(Some(24), None)).unwrap();
    assert_eq!(aaaa(&pool, "host").await, Answer::Records(Vec::new()));
    assert!(pool.is_empty());
    assert_eq!(a_addr(&pool, "host").await, Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(aaaa(&pool, "host").await, Answer::Records(Vec::new()));
    assert_eq!(
        pool.lookup_name("host"),
        Some((Some(Ipv4Addr::new(198, 18, 0, 1)), None))
    );

    let pool = FakePool::new(config(None, Some(64))).unwrap();
    assert_eq!(a(&pool, "host").await, Answer::Records(Vec::new()));
    assert!(pool.is_empty());
}

#[tokio::test(start_paused = true)]
async fn reverse_lookup() {
    let pool = FakePool::new(config(Some(24), Some(64))).unwrap();
    a(&pool, "v4.example").await;
    aaaa(&pool, "v6.example").await;

    assert_eq!(
        pool.lookup(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
        Some("v4.example".to_owned())
    );
    assert_eq!(
        pool.lookup(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
        Some("v4.example".to_owned())
    );
    assert_eq!(
        pool.lookup(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))),
        Some("v6.example".to_owned())
    );
    for unknown in [
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 3)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        assert_eq!(pool.lookup(unknown), None, "{unknown}");
    }

    let v4_only = FakePool::new(config(Some(24), None)).unwrap();
    a(&v4_only, "x").await;
    assert_eq!(
        v4_only.lookup(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
        None
    );
}

#[tokio::test(start_paused = true)]
async fn reuses_least_recently_used_expired_binding() {
    let pool = FakePool::new(config(Some(30), Some(64)))
        .unwrap()
        .with_client_limit(2);
    assert_eq!(a_addr(&pool, "old").await, Ipv4Addr::new(198, 18, 0, 1));
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(a_addr(&pool, "newer").await, Ipv4Addr::new(198, 18, 0, 2));
    // Repeats keep the address.
    assert_eq!(a_addr(&pool, "old").await, Ipv4Addr::new(198, 18, 0, 1));
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(a_addr(&pool, "newer").await, Ipv4Addr::new(198, 18, 0, 2));

    // `old` was used at 10 s, `newer` at 15 s; at 71 s only `old` has expired.
    tokio::time::advance(Duration::from_secs(56)).await;
    assert_eq!(a_addr(&pool, "fresh").await, Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(
        pool.lookup(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
        Some("fresh".to_owned())
    );
    assert_eq!(
        pool.lookup(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
        Some("fresh".to_owned())
    );
    assert_eq!(pool.lookup_name("old"), None);
    assert_eq!(pool.len(), 2);

    // `old` asks again: `newer` has expired by now and its address goes to `old`.
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(a_addr(&pool, "old").await, Ipv4Addr::new(198, 18, 0, 2));
    assert_eq!(
        pool.lookup(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2))),
        Some("old".to_owned())
    );
    assert_eq!(
        pool.stats(),
        FakePoolStats {
            allocated: 2,
            reused: 2,
            exhausted: 0
        }
    );
}

#[tokio::test(start_paused = true)]
async fn exhausted_until_ttl_expires() {
    let pool = FakePool::new(config(Some(30), None))
        .unwrap()
        .with_client_limit(2);
    a(&pool, "a").await;
    a(&pool, "b").await;
    assert_eq!(a(&pool, "c").await, Answer::Code(ResponseCode::ServFail));
    assert_eq!(pool.stats().exhausted, 1);
    assert_eq!(pool.lookup_name("c"), None);

    tokio::time::advance(Duration::from_secs(61)).await;
    assert_eq!(a_addr(&pool, "c").await, Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(
        pool.stats(),
        FakePoolStats {
            allocated: 2,
            reused: 1,
            exhausted: 1
        }
    );
}

#[tokio::test(start_paused = true)]
async fn ttl_from_config_and_refresh_on_use() {
    let pool = FakePool::new(FakePoolConfig {
        ttl: Duration::from_secs(30),
        ..config(Some(30), None)
    })
    .unwrap()
    .with_client_limit(2);
    assert_eq!(
        a(&pool, "a").await,
        Answer::Records(vec![Record::a("a", 30, Ipv4Addr::new(198, 18, 0, 1))])
    );
    a(&pool, "b").await;

    // `a` keeps being used; `b` expires and goes to `c`.
    for _ in 0..4 {
        tokio::time::advance(Duration::from_secs(20)).await;
        a(&pool, "a").await;
    }
    assert_eq!(a_addr(&pool, "c").await, Ipv4Addr::new(198, 18, 0, 2));
    assert_eq!(pool.lookup_name("b"), None);
    // `a` and `c` are both in use now.
    assert_eq!(a(&pool, "d").await, Answer::Code(ResponseCode::ServFail));

    // Forward inspection does not refresh `a`; `c` is used again.
    tokio::time::advance(Duration::from_secs(20)).await;
    a(&pool, "c").await;
    pool.lookup_name("a");
    tokio::time::advance(Duration::from_secs(15)).await;
    assert_eq!(a_addr(&pool, "d").await, Ipv4Addr::new(198, 18, 0, 1));
}

#[tokio::test(start_paused = true)]
async fn other_types_answer_nodata_by_default() {
    let pool = FakePool::new(config(Some(24), Some(64))).unwrap();
    for qtype in [TYPE::TXT, TYPE::MX, TYPE::PTR] {
        assert_eq!(
            pool.resolve(&query("host.example", qtype), client()).await,
            Answer::Records(Vec::new())
        );
    }
    assert!(pool.is_empty());
}

#[tokio::test(start_paused = true)]
async fn other_types_go_to_fallback() {
    let mut records = StaticRecords::new();
    records.insert(Record::txt("host.example", 300, vec!["v=1".into()]));
    let pool = Arc::new(
        FakePool::new(config(Some(24), None))
            .unwrap()
            .with_fallback(records),
    );
    assert_eq!(
        pool.resolve(&query("host.example", TYPE::TXT), client())
            .await,
        Answer::Records(vec![Record::txt("host.example", 300, vec!["v=1".into()])])
    );
    assert_eq!(
        pool.resolve(&query("host.example", TYPE::MX), client())
            .await,
        Answer::Records(Vec::new())
    );
    assert_eq!(
        pool.resolve(&query("other.example", TYPE::MX), client())
            .await,
        Answer::Code(ResponseCode::NxDomain)
    );
    // A still comes from the pool, not the fallback.
    assert_eq!(
        a_addr(&pool, "host.example").await,
        Ipv4Addr::new(198, 18, 0, 1)
    );
    assert_eq!(pool.capacity(), 254);
}

#[test]
fn config_validation() {
    let err = |config| FakePool::new(config).unwrap_err();
    assert_eq!(err(config(None, None)), FakePoolConfigError::NoPrefix);
    assert_eq!(
        err(config(Some(33), None)),
        FakePoolConfigError::InvalidPrefixLength(33)
    );
    assert_eq!(
        err(config(None, Some(129))),
        FakePoolConfigError::InvalidPrefixLength(129)
    );
    assert_eq!(
        err(FakePoolConfig {
            ipv4: Some((Ipv4Addr::new(198, 18, 0, 1), 24)),
            ..FakePoolConfig::default()
        }),
        FakePoolConfigError::HostBitsSet
    );
    assert_eq!(
        err(FakePoolConfig {
            ipv6: Some((Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0), 48)),
            ..FakePoolConfig::default()
        }),
        FakePoolConfigError::HostBitsSet
    );
    assert_eq!(err(config(Some(32), None)), FakePoolConfigError::Empty);
    assert_eq!(err(config(None, Some(128))), FakePoolConfigError::Empty);
    assert_eq!(
        err(FakePoolConfig {
            capacity: 0,
            ..config(Some(24), None)
        }),
        FakePoolConfigError::Empty
    );

    let pool = FakePool::new(FakePoolConfig {
        ipv4: Some((Ipv4Addr::UNSPECIFIED, 0)),
        ipv6: Some((Ipv6Addr::UNSPECIFIED, 0)),
        ..FakePoolConfig::default()
    })
    .unwrap();
    assert_eq!(pool.capacity(), 65536);
}

#[test]
fn pool_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FakePool>();
    assert_send_sync::<FakePool<StaticRecords>>();
}

fn client_at(host: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, host], 40000))
}

async fn a_from(pool: &impl Resolver, name: &str, host: u8) -> Answer {
    pool.resolve(&query(name, TYPE::A), client_at(host)).await
}

fn record(name: &str, host: u8) -> Answer {
    Answer::Records(vec![Record::a(name, 60, Ipv4Addr::new(198, 18, 0, host))])
}

fn sized(capacity: usize) -> FakePool {
    FakePool::new(FakePoolConfig {
        capacity,
        ..config(Some(24), None)
    })
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn one_client_takes_at_most_half_of_the_pool() {
    let pool = sized(4);
    assert_eq!(a_from(&pool, "x1", 1).await, record("x1", 1));
    assert_eq!(a_from(&pool, "x2", 1).await, record("x2", 2));
    // The third name of one client is refused while its two bindings are in use; a
    // different source port is the same client.
    assert_eq!(
        a_from(&pool, "x3", 1).await,
        Answer::Code(ResponseCode::ServFail)
    );
    let other_port = SocketAddr::from(([10, 0, 0, 1], 40001));
    assert_eq!(
        pool.resolve(&query("x4", TYPE::A), other_port).await,
        Answer::Code(ResponseCode::ServFail)
    );
    assert_eq!(pool.lookup_name("x3"), None);
    // Its bound names still answer, and the rest of the pool serves another client.
    assert_eq!(a_from(&pool, "x1", 1).await, record("x1", 1));
    assert_eq!(a_from(&pool, "y1", 2).await, record("y1", 3));
    // A name another client bound is shared: it does not count for the one asking.
    assert_eq!(a_from(&pool, "x2", 2).await, record("x2", 2));
    assert_eq!(a_from(&pool, "y1", 1).await, record("y1", 3));
    assert_eq!(a_from(&pool, "y2", 2).await, record("y2", 4));
    assert_eq!(pool.stats().exhausted, 0);
    assert_eq!(pool.len(), 4);
}

#[tokio::test(start_paused = true)]
async fn a_binding_in_use_by_lookup_is_not_the_one_reused() {
    let pool = sized(2);
    assert_eq!(a_from(&pool, "busy", 1).await, record("busy", 1));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(a_from(&pool, "idle", 2).await, record("idle", 2));
    let busy = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));

    // Connections to `busy` keep being opened after its DNS TTL; `idle` is not used.
    for _ in 0..4 {
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(pool.lookup(busy), Some("busy".to_owned()));
    }
    assert_eq!(a_from(&pool, "new", 3).await, record("new", 2));
    assert!(pool.lookup_name("busy").is_some());
    assert_eq!(pool.lookup_name("idle"), None);

    // Once `busy` is no longer looked up, its address is reused after the TTL.
    tokio::time::advance(Duration::from_secs(59)).await;
    assert_eq!(
        a_from(&pool, "late", 2).await,
        Answer::Code(ResponseCode::ServFail)
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(a_from(&pool, "late", 2).await, record("late", 1));
}

#[tokio::test(start_paused = true)]
async fn client_limit_is_configurable_and_counted() {
    assert_eq!(sized(4).client_limit(), 2);
    assert_eq!(sized(5).client_limit(), 3);
    assert_eq!(sized(1).client_limit(), 1);
    assert_eq!(sized(4).with_client_limit(0).client_limit(), 1);
    assert_eq!(
        FakePool::new(config(Some(15), None))
            .unwrap()
            .client_limit(),
        32768
    );

    // The limit survives `with_fallback`; at 1 a client replaces its own binding.
    let pool = sized(4)
        .with_client_limit(1)
        .with_fallback(StaticRecords::new());
    assert_eq!(pool.client_limit(), 1);
    assert_eq!(a_from(&pool, "x1", 1).await, record("x1", 1));
    assert_eq!(
        a_from(&pool, "x2", 1).await,
        Answer::Code(ResponseCode::ServFail)
    );
    assert_eq!(a_from(&pool, "y1", 2).await, record("y1", 2));
    assert_eq!(pool.client_limited(), 1);

    // After the TTL the client's own address goes to its new name, though the pool has
    // never used addresses left; the other client's binding stays.
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(a_from(&pool, "x2", 1).await, record("x2", 1));
    assert_eq!(pool.lookup_name("x1"), None);
    assert_eq!(
        pool.lookup_name("y1").unwrap().0,
        Some(Ipv4Addr::new(198, 18, 0, 2))
    );
    assert_eq!(
        pool.stats(),
        FakePoolStats {
            allocated: 2,
            reused: 1,
            exhausted: 0
        }
    );
    assert_eq!(pool.client_limited(), 1);

    // The whole pool for one client.
    let pool = sized(3).with_client_limit(3);
    for (name, host) in [("a", 1), ("b", 2), ("c", 3)] {
        assert_eq!(a_from(&pool, name, 1).await, record(name, host));
    }
    assert_eq!(
        a_from(&pool, "d", 1).await,
        Answer::Code(ResponseCode::ServFail)
    );
    assert_eq!((pool.client_limited(), pool.stats().exhausted), (0, 1));
}

#[tokio::test(start_paused = true)]
async fn an_ipv4_mapped_client_is_its_ipv4_address() {
    let pool = sized(2);
    assert_eq!(a_from(&pool, "x1", 1).await, record("x1", 1));
    let mapped = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped().into(), 40000);
    assert_eq!(
        pool.resolve(&query("x2", TYPE::A), mapped).await,
        Answer::Code(ResponseCode::ServFail)
    );
}
