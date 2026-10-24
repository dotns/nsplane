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
    let pool = FakePool::new(config(Some(30), None)).unwrap();
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
    let pool = FakePool::new(config(Some(30), Some(64))).unwrap();
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
    let pool = FakePool::new(config(Some(30), None)).unwrap();
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
    .unwrap();
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

    // Reverse and forward inspection do not refresh `a`; `c` is used again.
    tokio::time::advance(Duration::from_secs(20)).await;
    a(&pool, "c").await;
    pool.lookup(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)));
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
