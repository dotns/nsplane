//! Hosts-format text parsing.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use nsplane_dns::{
    Action, Answer, Hosts, HostsError, HostsErrorKind, NameMatch, PolicyResolver, PolicyTable,
    Query, Record, RecordData, Resolver, ResolverSet, Rule,
};
use simple_dns::{CLASS, Name, Packet, Question, TYPE};

const TEXT: &str = "\
# local names
127.0.0.1   localhost
::1         localhost ip6-localhost   # trailing comment

10.0.0.7    Printer.LAN. nas.lan
fd00::7     printer.lan
10.0.0.7    printer.lan
10.0.0.8\tnas.lan
198.51.100.1  *.dev.example
2001:db8::1   *.dev.example
";

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

#[tokio::test]
async fn static_records_from_plain_names() {
    let hosts = Hosts::parse(TEXT);
    assert!(hosts.errors().is_empty(), "{:?}", hosts.errors());
    let records = hosts.static_records(300);
    // localhost, ip6-localhost, printer.lan, nas.lan; the wildcard is not a record.
    assert_eq!(records.len(), 4);

    let lookup = |name: &str, qtype| records.lookup(&query(name, qtype));
    assert_eq!(
        lookup("localhost", TYPE::A),
        Answer::Records(vec![Record::a("localhost", 300, Ipv4Addr::LOCALHOST)])
    );
    assert_eq!(
        lookup("ip6-localhost", TYPE::AAAA),
        Answer::Records(vec![Record::aaaa(
            "ip6-localhost",
            300,
            Ipv6Addr::LOCALHOST
        )])
    );
    // Several lines for one name; a repeated address once.
    assert_eq!(
        lookup("printer.lan", TYPE::A),
        Answer::Records(vec![Record::a(
            "printer.lan",
            300,
            Ipv4Addr::new(10, 0, 0, 7)
        )])
    );
    assert_eq!(
        lookup("printer.lan", TYPE::AAAA),
        Answer::Records(vec![Record::aaaa(
            "printer.lan",
            300,
            "fd00::7".parse().unwrap()
        )])
    );
    assert_eq!(
        lookup("nas.lan", TYPE::A),
        Answer::Records(vec![
            Record::a("nas.lan", 300, Ipv4Addr::new(10, 0, 0, 7)),
            Record::a("nas.lan", 300, Ipv4Addr::new(10, 0, 0, 8)),
        ])
    );
    assert_eq!(
        lookup("x.dev.example", TYPE::A),
        Answer::Code(nsplane_dns::ResponseCode::NxDomain)
    );
}

#[test]
fn wildcard_names_become_records_rules() {
    let hosts = Hosts::parse(TEXT);
    assert_eq!(
        hosts.wildcard_rules(),
        vec![Rule::new(
            NameMatch::Wildcard("*.dev.example".into()),
            Action::Records(vec![
                RecordData::A(Ipv4Addr::new(198, 51, 100, 1)),
                RecordData::Aaaa("2001:db8::1".parse().unwrap()),
            ]),
        )]
    );
    let rules = hosts.rules();
    assert_eq!(rules.len(), 5);
    assert_eq!(
        rules[0],
        Rule::new(
            NameMatch::Exact("localhost".into()),
            Action::Records(vec![
                RecordData::A(Ipv4Addr::LOCALHOST),
                RecordData::Aaaa(Ipv6Addr::LOCALHOST),
            ]),
        )
    );
    assert_eq!(rules[4], hosts.wildcard_rules()[0]);
}

#[tokio::test]
async fn wildcard_rule_answers_every_name_below_but_not_the_apex() {
    let hosts = Hosts::parse(TEXT);
    let table = PolicyTable::new(hosts.rules()).unwrap();
    let policy = &PolicyResolver::new(ResolverSet::new(), table).unwrap();
    let answer = |name: &'static str, qtype| async move {
        policy.resolve(&query(name, qtype), client()).await
    };
    assert_eq!(
        answer("api.dev.example", TYPE::A).await,
        Answer::Records(vec![Record::a(
            "api.dev.example",
            60,
            Ipv4Addr::new(198, 51, 100, 1)
        )])
    );
    assert_eq!(
        answer("a.b.dev.example", TYPE::AAAA).await,
        Answer::Records(vec![Record::aaaa(
            "a.b.dev.example",
            60,
            "2001:db8::1".parse().unwrap()
        )])
    );
    assert_eq!(
        answer("api.dev.example", TYPE::MX).await,
        Answer::Records(vec![])
    );
    assert_eq!(
        answer("dev.example", TYPE::A).await,
        Answer::Code(nsplane_dns::ResponseCode::Refused)
    );
    assert_eq!(
        answer("printer.lan", TYPE::A).await,
        Answer::Records(vec![Record::a(
            "printer.lan",
            60,
            Ipv4Addr::new(10, 0, 0, 7)
        )])
    );
}

#[test]
fn bad_lines_are_reported_and_the_rest_is_kept() {
    let hosts = Hosts::parse(
        "10.0.0.1 good.lan\n\
         10.0.0.300 bad-address.lan\n\
         fe80::1%eth0 zoned.lan\n\
         10.0.0.2\n\
         10.0.0.3 ok.lan bad..name *.ok.lan * a.*.lan\n\
         # 10.0.0.4 commented.lan\n\
         \x20\x20\t\n",
    );
    let error = |line, kind| HostsError { line, kind };
    assert_eq!(
        hosts.errors(),
        [
            error(2, HostsErrorKind::InvalidAddress("10.0.0.300".into())),
            error(3, HostsErrorKind::InvalidAddress("fe80::1%eth0".into())),
            error(4, HostsErrorKind::NoName),
            error(5, HostsErrorKind::InvalidName("bad..name".into())),
            error(5, HostsErrorKind::InvalidName("*".into())),
            error(5, HostsErrorKind::InvalidName("a.*.lan".into())),
        ]
    );
    assert_eq!(
        hosts.errors()[0].to_string(),
        "line 2: invalid address `10.0.0.300`"
    );
    let rules = hosts.rules();
    let names: Vec<&NameMatch> = rules.iter().map(|r| &r.name).collect();
    assert_eq!(
        names,
        [
            &NameMatch::Exact("good.lan".into()),
            &NameMatch::Exact("ok.lan".into()),
            &NameMatch::Wildcard("*.ok.lan".into()),
        ]
    );
    assert_eq!(hosts.static_records(60).len(), 2);
    assert!(!hosts.is_empty());
}

#[test]
fn empty_text() {
    let hosts = Hosts::parse("# nothing\n\n");
    assert!(hosts.is_empty());
    assert_eq!(hosts.errors(), Vec::<HostsError>::new());
    assert_eq!(hosts.rules(), Vec::<Rule>::new());
    assert!(hosts.static_records(60).is_empty());
}
