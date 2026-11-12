//! Query names outside host name syntax: any octets in a label (RFC 2181 section 11), a dot
//! or a backslash inside one.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nsplane_dns::{
    Action, Answer, EncodeOptions, FakePool, FakePoolConfig, NameMatch, PolicyResolver,
    PolicyTable, Query, Record, RecordType, Resolver, ResolverSet, ResponseCode, Rule,
    StaticRecords, encode_response, normalize_name,
};
use simple_dns::Packet;

/// A class IN query of type `qtype` for the name made of `labels`.
fn query(labels: &[&[u8]], qtype: u16) -> Query {
    let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in labels {
        message.push(u8::try_from(label.len()).unwrap());
        message.extend_from_slice(label);
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&[0, 1]);
    Query::decode(&message).unwrap()
}

fn client() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 2], 5353))
}

fn pool() -> FakePool {
    FakePool::new(FakePoolConfig {
        ipv4: Some((Ipv4Addr::new(198, 18, 0, 0), 24)),
        ..FakePoolConfig::default()
    })
    .unwrap()
}

/// The labels of the owner of the single answer in the response to `query`, which must be
/// `NOERROR`.
fn answered_owner(query: &Query, answer: &Answer) -> Vec<Vec<u8>> {
    let response = encode_response(query, answer, 65535, EncodeOptions::default());
    assert_eq!(
        response[3] & 0x0f,
        0,
        "rcode of the answer to {}",
        query.name()
    );
    let packet = Packet::parse(&response).unwrap();
    let [record] = packet.answers.as_slice() else {
        panic!("{} answers to {}", packet.answers.len(), query.name());
    };
    record.name.as_bytes().map(<[u8]>::to_vec).collect()
}

/// Names a client may ask for that are not host names, with their text form.
const ODD: [(&[&[u8]], &str); 9] = [
    (&[b"foo-", b"test"], "foo-.test"),
    (&[b"-foo", b"test"], "-foo.test"),
    (&[b"*", b"test"], "*.test"),
    (&[b"a b", b"test"], "a\\032b.test"),
    (&[b"A.B", b"Test"], "a\\046b.test"),
    (&[b"a\\b", b"test"], "a\\092b.test"),
    (&[b"\x00\xff", b"test"], "\\000\\255.test"),
    (&[b"b\xc3\xbccher", b"test"], "b\\195\\188cher.test"),
    (&[b"allowed.example"], "allowed\\046example"),
];

#[test]
fn a_query_name_is_text_that_tells_every_name_apart() {
    for (labels, text) in ODD {
        assert_eq!(query(labels, 1).name(), text);
        // The text form is stable under normalization.
        assert_eq!(normalize_name(text), text);
    }
    assert_eq!(query(&[b"a.b", b"test"], 1).name(), "a\\046b.test");
    assert_eq!(query(&[b"a", b"b", b"test"], 1).name(), "a.b.test");
    assert_ne!(query(&[b"\xff"], 1).name(), query(&[b"\xfe"], 1).name());
}

#[test]
fn normalize_name_takes_escapes_and_plain_octets() {
    for (given, normalized) in [
        ("WWW.Example.COM.", "www.example.com"),
        ("", ""),
        (".", ""),
        ("_sip._tcp.Example", "_sip._tcp.example"),
        ("a b.test", "a\\032b.test"),
        ("a\\ b.test", "a\\032b.test"),
        ("a\\.b.test.", "a\\046b.test"),
        ("a\\046B.test", "a\\046b.test"),
        ("\\065\\066.test", "ab.test"),
        ("a\\\\b.test", "a\\092b.test"),
        ("b\u{fc}cher.test", "b\\195\\188cher.test"),
        // A backslash in front of anything else, or of nothing, stands for what follows.
        ("a\\x.test", "ax.test"),
        ("a\\999.test", "a999.test"),
        ("a.test\\", "a.test\\092"),
        ("a.test\\.", "a.test\\046"),
    ] {
        assert_eq!(normalize_name(given), normalized, "{given}");
        assert_eq!(normalize_name(normalized), normalized, "{given}, again");
    }
}

#[tokio::test]
async fn a_name_outside_host_name_syntax_is_answered_under_its_own_name() {
    let pool = pool();
    let mut records = StaticRecords::new();
    let table = PolicyTable::new([Rule::new(NameMatch::Default, Action::Sinkhole)]).unwrap();
    let policy = PolicyResolver::new(ResolverSet::new(), table).unwrap();
    for (index, (labels, text)) in ODD.into_iter().enumerate() {
        let query = query(labels, 1);
        let lower: Vec<Vec<u8>> = labels.iter().map(|l| l.to_ascii_lowercase()).collect();

        // The fake pool binds the name and its answer reaches the client.
        let answer = pool.resolve(&query, client()).await;
        assert_eq!(answered_owner(&query, &answer), lower, "{text}");
        assert_eq!(pool.len(), index + 1);
        let Some((Some(addr), None)) = pool.lookup_name(text) else {
            panic!("{text} is not bound");
        };
        assert_eq!(pool.lookup(IpAddr::V4(addr)).as_deref(), Some(text));

        // A static record under the name, given as the query names it.
        records.insert(Record::a(text, 30, Ipv4Addr::new(192, 0, 2, 1)));
        let answer = records.resolve(&query, client()).await;
        assert_eq!(answered_owner(&query, &answer), lower, "{text}");

        // A policy answer.
        let answer = policy.resolve(&query, client()).await;
        assert_eq!(answered_owner(&query, &answer), lower, "{text}");
    }
    assert_eq!(pool.stats().allocated, 9);
}

#[tokio::test]
async fn a_dot_inside_a_label_is_not_a_label_boundary() {
    let dotted = query(&[b"a.b", b"test"], 1);
    let plain = query(&[b"a", b"b", b"test"], 1);

    // Two names, two bindings.
    let pool = pool();
    let Answer::Records(first) = pool.resolve(&dotted, client()).await else {
        panic!("no answer");
    };
    let Answer::Records(second) = pool.resolve(&plain, client()).await else {
        panic!("no answer");
    };
    assert_ne!(first[0].data, second[0].data);
    assert_eq!(pool.len(), 2);

    // A record of one is not a record of the other.
    let mut records = StaticRecords::new();
    records.insert(Record::a("a.b.test", 30, Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(
        records.lookup(&dotted),
        Answer::Code(ResponseCode::NxDomain)
    );
    assert!(matches!(records.lookup(&plain), Answer::Records(r) if r.len() == 1));
    let mut records = StaticRecords::new();
    records.insert(Record::a("a\\.b.test", 30, Ipv4Addr::new(192, 0, 2, 2)));
    assert!(matches!(records.lookup(&dotted), Answer::Records(r) if r.len() == 1));
    assert_eq!(records.lookup(&plain), Answer::Code(ResponseCode::NxDomain));
}

#[test]
fn a_rule_matches_on_label_boundaries_only() {
    let table = PolicyTable::new([
        Rule::new(NameMatch::Exact("allowed.example".into()), Action::NoData),
        Rule::new(NameMatch::Suffix("corp.example".into()), Action::NoData),
        Rule::new(NameMatch::Wildcard("*.dev.example".into()), Action::NoData),
        Rule::new(NameMatch::Suffix("example".into()), Action::Sinkhole),
    ])
    .unwrap();
    let ip = client().ip();
    let rule = |labels: &[&[u8]]| table.matching(query(labels, 1).name(), RecordType::A, ip);

    assert_eq!(rule(&[b"allowed", b"example"]), Some(0));
    assert_eq!(rule(&[b"x", b"corp", b"example"]), Some(1));
    assert_eq!(rule(&[b"x", b"dev", b"example"]), Some(2));
    // One label that spells a rule's name with dots is another name: a top-level one.
    assert_eq!(rule(&[b"allowed.example"]), None);
    assert_eq!(rule(&[b"x.corp.example"]), None);
    assert_eq!(rule(&[b"x.dev.example"]), None);
    // Below `example`, but not below `corp.example` or `dev.example`.
    assert_eq!(rule(&[b"x.corp", b"example"]), Some(3));
    assert_eq!(rule(&[b"x", b"corp.example"]), None);
    assert_eq!(rule(&[b"x.dev", b"example"]), Some(3));
}
