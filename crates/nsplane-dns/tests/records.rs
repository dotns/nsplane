//! `StaticRecords` and `Fallback` behavior.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nsplane_dns::{Answer, Query, Record, Resolver, ResponseCode, StaticRecords};
use simple_dns::{CLASS, Name, Packet, QCLASS, Question, TYPE};

fn query(name: &str, qtype: TYPE) -> Query {
    query_class(name, qtype, CLASS::IN.into())
}

fn query_class(name: &str, qtype: TYPE, class: QCLASS) -> Query {
    let mut packet = Packet::new_query(1);
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        qtype.into(),
        class,
        false,
    ));
    Query::decode(&packet.build_bytes_vec().unwrap()).unwrap()
}

fn client() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40000))
}

fn table() -> StaticRecords {
    let mut table = StaticRecords::new();
    table
        .insert(Record::a("Host.Lan.", 60, Ipv4Addr::new(10, 0, 0, 1)))
        .insert(Record::aaaa("host.lan", 60, Ipv6Addr::LOCALHOST))
        .insert(Record::txt("host.lan", 60, vec!["v=1".into()]))
        .insert(Record::cname("alias.lan", 60, "host.lan"))
        .insert(Record::ptr("1.0.0.10.in-addr.arpa", 60, "host.lan"));
    table
}

#[tokio::test]
async fn answers_by_type() {
    let table = table();
    assert_eq!(table.len(), 3);
    assert_eq!(
        table.resolve(&query("host.lan", TYPE::A), client()).await,
        Answer::Records(vec![Record::a("host.lan", 60, Ipv4Addr::new(10, 0, 0, 1))])
    );
    assert_eq!(
        table
            .resolve(&query("host.lan", TYPE::AAAA), client())
            .await,
        Answer::Records(vec![Record::aaaa("host.lan", 60, Ipv6Addr::LOCALHOST)])
    );
    assert_eq!(
        table
            .resolve(&query("1.0.0.10.in-addr.arpa", TYPE::PTR), client())
            .await,
        Answer::Records(vec![Record::ptr("1.0.0.10.in-addr.arpa", 60, "host.lan")])
    );
}

#[tokio::test]
async fn names_are_case_insensitive() {
    let answer = table()
        .resolve(&query("HOST.lan", TYPE::TXT), client())
        .await;
    assert_eq!(
        answer,
        Answer::Records(vec![Record::txt("host.lan", 60, vec!["v=1".into()])])
    );
}

#[tokio::test]
async fn known_name_without_the_type_is_nodata() {
    let answer = table()
        .resolve(&query("host.lan", TYPE::MX), client())
        .await;
    assert_eq!(answer, Answer::Records(Vec::new()));
}

#[tokio::test]
async fn any_returns_every_record() {
    let Answer::Records(records) = table().resolve(&query_any("host.lan"), client()).await else {
        panic!("expected records");
    };
    assert_eq!(records.len(), 3);
}

fn query_any(name: &str) -> Query {
    let mut packet = Packet::new_query(1);
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        simple_dns::QTYPE::ANY,
        CLASS::IN.into(),
        false,
    ));
    Query::decode(&packet.build_bytes_vec().unwrap()).unwrap()
}

#[tokio::test]
async fn unknown_name_and_other_class_are_nxdomain() {
    let table = table();
    assert_eq!(
        table.resolve(&query("nope.lan", TYPE::A), client()).await,
        Answer::Code(ResponseCode::NxDomain)
    );
    assert_eq!(
        table
            .resolve(
                &query_class("host.lan", TYPE::A, CLASS::CH.into()),
                client()
            )
            .await,
        Answer::Code(ResponseCode::NxDomain)
    );
}

#[tokio::test]
async fn cname_answers_any_type() {
    let expected = Answer::Records(vec![Record::cname("alias.lan", 60, "host.lan")]);
    let table = table();
    assert_eq!(
        table.resolve(&query("alias.lan", TYPE::A), client()).await,
        expected
    );
    assert_eq!(
        table
            .resolve(&query("alias.lan", TYPE::CNAME), client())
            .await,
        expected
    );
    assert_eq!(
        table
            .resolve(&query("Alias.LAN", TYPE::TXT), client())
            .await,
        expected
    );
}

/// Answers `REFUSED` and counts its calls.
#[derive(Default)]
struct Counting(AtomicUsize);

impl Resolver for Counting {
    fn resolve(
        &self,
        _query: &Query,
        _client: SocketAddr,
    ) -> impl std::future::Future<Output = Answer> + Send {
        self.0.fetch_add(1, Ordering::Relaxed);
        std::future::ready(Answer::Code(ResponseCode::Refused))
    }
}

#[tokio::test]
async fn fallback_only_for_nxdomain() {
    let second = Arc::new(Counting::default());
    let chain = table().with_fallback(Arc::clone(&second));

    assert_eq!(
        chain.resolve(&query("nope.lan", TYPE::A), client()).await,
        Answer::Code(ResponseCode::Refused)
    );
    assert_eq!(second.0.load(Ordering::Relaxed), 1);

    // A hit and NODATA are final.
    assert!(matches!(
        chain.resolve(&query("host.lan", TYPE::A), client()).await,
        Answer::Records(r) if r.len() == 1
    ));
    assert_eq!(
        chain.resolve(&query("host.lan", TYPE::MX), client()).await,
        Answer::Records(vec![])
    );
    assert_eq!(second.0.load(Ordering::Relaxed), 1);

    // Chains nest, here through `&R`.
    let inner = StaticRecords::from_iter([Record::a("other.lan", 5, Ipv4Addr::new(10, 0, 0, 9))]);
    let deeper = inner.with_fallback(&chain);
    assert_eq!(
        deeper.resolve(&query("host.lan", TYPE::A), client()).await,
        Answer::Records(vec![Record::a("host.lan", 60, Ipv4Addr::new(10, 0, 0, 1))])
    );
    assert_eq!(
        deeper.resolve(&query("nope.lan", TYPE::A), client()).await,
        Answer::Code(ResponseCode::Refused)
    );
    assert_eq!(second.0.load(Ordering::Relaxed), 2);
}
