//! `PolicyResolver` and `PolicyTable` behavior.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use nsplane_dns::{
    Action, Answer, MAX_CNAME_CHAIN, NameMatch, NxDomainFallback, PolicyError, PolicyResolver,
    PolicyTable, Query, Record, RecordData, RecordType, Resolver, ResolverSet, ResponseCode, Rule,
    StaticRecords,
};
use simple_dns::rdata::RData;
use simple_dns::{CLASS, Name, Packet, PacketFlag, QTYPE, Question, RCODE, TYPE};
use tokio::sync::Notify;

fn query(name: &str, qtype: impl Into<QTYPE>) -> Query {
    let mut packet = Packet::new_query(7);
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        qtype.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.set_flags(PacketFlag::RECURSION_DESIRED);
    Query::decode(&packet.build_bytes_vec().unwrap()).unwrap()
}

fn client() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 2], 40000))
}

const fn v4(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, last)
}

fn exact(name: &str) -> NameMatch {
    NameMatch::Exact(name.into())
}

fn suffix(name: &str) -> NameMatch {
    NameMatch::Suffix(name.into())
}

fn wildcard(name: &str) -> NameMatch {
    NameMatch::Wildcard(name.into())
}

fn addr(last: u8) -> Action {
    Action::Records(vec![RecordData::A(v4(last))])
}

fn policy(rules: Vec<Rule>) -> PolicyResolver {
    PolicyResolver::new(resolvers(), PolicyTable::new(rules).unwrap()).unwrap()
}

/// `local` answers `host.lan` and NXDOMAIN otherwise; `other` always answers 192.0.2.99.
fn resolvers() -> ResolverSet {
    let local: StaticRecords = std::iter::once(Record::a("host.lan", 60, v4(10))).collect();
    ResolverSet::new().with("local", local).with(
        "other",
        Fixed(Answer::Records(vec![Record::a("x", 60, v4(99))])),
    )
}

/// Always answers the same.
struct Fixed(Answer);

impl Resolver for Fixed {
    fn resolve(&self, _query: &Query, _client: SocketAddr) -> impl Future<Output = Answer> + Send {
        std::future::ready(self.0.clone())
    }
}

/// A raw upstream-style response to `query` with response code `rcode` and no answers.
fn raw_code(rcode: RCODE) -> Answer {
    let mut packet = Packet::new_reply(1);
    *packet.rcode_mut() = rcode;
    Answer::Raw(Bytes::from(packet.build_bytes_vec().unwrap()))
}

async fn answer(resolver: &impl Resolver, name: &str, qtype: impl Into<QTYPE>) -> Answer {
    resolver.resolve(&query(name, qtype), client()).await
}

fn a_records(answer: &Answer) -> Vec<Ipv4Addr> {
    let Answer::Records(records) = answer else {
        panic!("expected records, got {answer:?}");
    };
    records
        .iter()
        .filter_map(|r| match r.data {
            RecordData::A(a) => Some(a),
            _ => None,
        })
        .collect()
}

fn matching(policy: &PolicyResolver, name: &str) -> Option<usize> {
    policy.matching(name, RecordType::A, client().ip())
}

#[tokio::test]
async fn precedence_exact_suffix_wildcard_default() {
    let policy = policy(vec![
        Rule::new(NameMatch::Default, addr(0)),
        Rule::new(suffix("example"), addr(1)),
        Rule::new(wildcard("*.dev.example"), addr(2)),
        Rule::new(suffix("dev.example"), addr(3)),
        Rule::new(exact("api.dev.example"), addr(4)),
        Rule::new(wildcard("*.corp.example"), addr(5)),
        Rule::new(suffix("a.corp.example"), addr(6)),
    ]);
    // Exact before every suffix and wildcard, whatever the declaration order.
    assert_eq!(matching(&policy, "API.dev.example."), Some(4));
    // Equal anchor length: suffix before wildcard.
    assert_eq!(matching(&policy, "www.dev.example"), Some(3));
    assert_eq!(matching(&policy, "dev.example"), Some(3));
    // The longer anchor first: a.corp.example (suffix) over *.corp.example.
    assert_eq!(matching(&policy, "x.a.corp.example"), Some(6));
    // The wildcard over the shorter suffix `example`.
    assert_eq!(matching(&policy, "b.corp.example"), Some(5));
    assert_eq!(matching(&policy, "x.y.corp.example"), Some(5));
    // The wildcard does not match its apex; the shorter suffix does.
    assert_eq!(matching(&policy, "corp.example"), Some(1));
    assert_eq!(matching(&policy, "other.test"), Some(0));
    assert_eq!(
        a_records(&answer(&policy, "www.dev.example", TYPE::A).await),
        [v4(3)]
    );
}

#[tokio::test]
async fn wildcard_does_not_match_its_apex() {
    let policy = policy(vec![Rule::new(wildcard("*.dev.example"), addr(2))]);
    assert_eq!(matching(&policy, "a.dev.example"), Some(0));
    assert_eq!(matching(&policy, "a.b.dev.example"), Some(0));
    assert_eq!(matching(&policy, "dev.example"), None);
    assert_eq!(matching(&policy, "xdev.example"), None);
    assert_eq!(
        answer(&policy, "dev.example", TYPE::A).await,
        Answer::Code(ResponseCode::Refused)
    );
    assert_eq!(policy.stats().unmatched, 1);
}

#[tokio::test]
async fn suffix_matches_on_label_boundaries() {
    let policy = policy(vec![Rule::new(suffix("lan"), addr(1))]);
    assert_eq!(matching(&policy, "lan"), Some(0));
    assert_eq!(matching(&policy, "a.b.lan"), Some(0));
    assert_eq!(matching(&policy, "plan"), None);
}

#[tokio::test]
async fn first_rule_of_a_name_whose_conditions_hold() {
    let lan = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24);
    let policy = policy(vec![
        Rule::new(suffix("example"), addr(1)).with_types([RecordType::AAAA]),
        Rule::new(suffix("example"), addr(2)).with_clients([lan]),
        Rule::new(suffix("example"), addr(3)),
        Rule::new(exact("only.example"), addr(4)).with_types([RecordType::TXT]),
        Rule::new(NameMatch::Default, addr(5))
            .with_clients([(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)]),
    ]);
    let t = |name: &str, ty: RecordType, ip: IpAddr| policy.matching(name, ty, ip);
    let inside = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let outside = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 9));
    assert_eq!(t("a.example", RecordType::AAAA, outside), Some(0));
    assert_eq!(t("a.example", RecordType::A, inside), Some(1));
    // IPv4-mapped clients match IPv4 prefixes.
    let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 9).to_ipv6_mapped());
    assert_eq!(t("a.example", RecordType::A, mapped), Some(1));
    assert_eq!(t("a.example", RecordType::A, outside), Some(2));
    // An exact rule whose conditions fail falls through to the suffix rules.
    assert_eq!(t("only.example", RecordType::TXT, outside), Some(3));
    assert_eq!(t("only.example", RecordType::A, outside), Some(2));
    // Default restricted to IPv6 clients.
    assert_eq!(t("other.test", RecordType::A, outside), None);
    assert_eq!(
        t("other.test", RecordType::A, IpAddr::V6(Ipv6Addr::LOCALHOST)),
        Some(4)
    );
}

#[tokio::test]
async fn each_local_action() {
    let policy = policy(vec![
        Rule::new(
            wildcard("*.hosts.test"),
            Action::Records(vec![
                RecordData::A(v4(1)),
                RecordData::Aaaa(Ipv6Addr::LOCALHOST),
                RecordData::Txt(vec!["t".into()]),
            ]),
        ),
        Rule::new(exact("nx.test"), Action::Block(ResponseCode::NxDomain)),
        Rule::new(exact("refused.test"), Action::Block(ResponseCode::Refused)),
        Rule::new(suffix("sink.test"), Action::Sinkhole),
        Rule::new(exact("empty.test"), Action::NoData),
    ]);

    let records = |answer: Answer| match answer {
        Answer::Records(records) => records,
        other => panic!("expected records, got {other:?}"),
    };
    assert_eq!(
        records(answer(&policy, "Www.Hosts.Test", TYPE::A).await),
        [Record::a("www.hosts.test", 60, v4(1))]
    );
    assert_eq!(
        records(answer(&policy, "a.b.hosts.test", TYPE::AAAA).await),
        [Record::aaaa("a.b.hosts.test", 60, Ipv6Addr::LOCALHOST)]
    );
    assert_eq!(
        records(answer(&policy, "w.hosts.test", TYPE::TXT).await),
        [Record::txt("w.hosts.test", 60, vec!["t".into()])]
    );
    assert_eq!(
        answer(&policy, "w.hosts.test", TYPE::MX).await,
        Answer::Records(vec![])
    );
    assert_eq!(
        records(answer(&policy, "w.hosts.test", QTYPE::ANY).await).len(),
        3
    );

    assert_eq!(
        answer(&policy, "nx.test", TYPE::A).await,
        Answer::Code(ResponseCode::NxDomain)
    );
    assert_eq!(
        answer(&policy, "refused.test", TYPE::A).await,
        Answer::Code(ResponseCode::Refused)
    );

    assert_eq!(
        records(answer(&policy, "ads.sink.test", TYPE::A).await),
        [Record::a("ads.sink.test", 60, Ipv4Addr::UNSPECIFIED)]
    );
    assert_eq!(
        records(answer(&policy, "sink.test", TYPE::AAAA).await),
        [Record::aaaa("sink.test", 60, Ipv6Addr::UNSPECIFIED)]
    );
    assert_eq!(
        answer(&policy, "sink.test", TYPE::MX).await,
        Answer::Records(vec![])
    );
    assert_eq!(
        records(answer(&policy, "sink.test", QTYPE::ANY).await).len(),
        2
    );

    assert_eq!(
        answer(&policy, "empty.test", TYPE::A).await,
        Answer::Records(vec![])
    );

    let stats = policy.stats();
    assert_eq!(stats.records, 5);
    assert_eq!(stats.blocked, 2);
    assert_eq!(stats.sinkholed, 4);
    assert_eq!(stats.nodata, 1);
    assert_eq!(stats.rule_hits, [5, 1, 1, 4, 1]);
}

#[tokio::test]
async fn local_ttl_is_configurable() {
    let table = PolicyTable::new([Rule::new(exact("a.test"), addr(1))])
        .unwrap()
        .with_ttl(5);
    let policy = PolicyResolver::new(ResolverSet::new(), table).unwrap();
    assert_eq!(
        answer(&policy, "a.test", TYPE::A).await,
        Answer::Records(vec![Record::a("a.test", 5, v4(1))])
    );
}

#[tokio::test]
async fn resolve_asks_the_registered_resolver() {
    let policy = policy(vec![
        Rule::new(suffix("lan"), Action::Resolve("local".into())),
        Rule::new(NameMatch::Default, Action::Resolve("other".into())),
    ]);
    assert_eq!(
        a_records(&answer(&policy, "host.lan", TYPE::A).await),
        [v4(10)]
    );
    assert_eq!(
        a_records(&answer(&policy, "x.test", TYPE::A).await),
        [v4(99)]
    );
    // Without a fallback, NXDOMAIN of the resolver is the answer.
    assert_eq!(
        answer(&policy, "missing.lan", TYPE::A).await,
        Answer::Code(ResponseCode::NxDomain)
    );
    let stats = policy.stats();
    assert_eq!((stats.resolved, stats.fallbacks), (3, 0));
}

#[tokio::test]
async fn nxdomain_fallback_to_default_or_resolver() {
    let policy = policy(vec![
        Rule::new(suffix("lan"), Action::Resolve("local".into()))
            .with_on_nxdomain(NxDomainFallback::Default),
        Rule::new(suffix("corp"), Action::Resolve("local".into()))
            .with_on_nxdomain(NxDomainFallback::Resolve("other".into())),
        Rule::new(exact("nodata.test"), Action::NoData),
        Rule::new(NameMatch::Default, Action::Sinkhole),
    ]);
    // Found locally: no fallback.
    assert_eq!(
        a_records(&answer(&policy, "host.lan", TYPE::A).await),
        [v4(10)]
    );
    // NXDOMAIN -> the default rule.
    assert_eq!(
        a_records(&answer(&policy, "missing.lan", TYPE::A).await),
        [Ipv4Addr::UNSPECIFIED]
    );
    // NXDOMAIN -> another resolver.
    assert_eq!(
        a_records(&answer(&policy, "missing.corp", TYPE::A).await),
        [v4(99)]
    );
    let stats = policy.stats();
    assert_eq!(stats.fallbacks, 2);
    assert_eq!(stats.rule_hits, [2, 1, 0, 1]);
}

/// `resolvers()` plus `raw-nx`, answering a raw NXDOMAIN.
fn policy_with_raw(rules: Vec<Rule>) -> PolicyResolver {
    let set = resolvers().with("raw-nx", Fixed(raw_code(RCODE::NameError)));
    PolicyResolver::new(set, PolicyTable::new(rules).unwrap()).unwrap()
}

#[tokio::test]
async fn nxdomain_fallback_on_raw_responses() {
    let policy = policy_with_raw(vec![
        Rule::new(exact("raw.test"), Action::Resolve("raw-nx".into()))
            .with_on_nxdomain(NxDomainFallback::Default),
        Rule::new(NameMatch::Default, addr(7)),
    ]);
    assert_eq!(
        a_records(&answer(&policy, "raw.test", TYPE::A).await),
        [v4(7)]
    );
    // The default rule itself is not retried when it answers NXDOMAIN.
    let policy = policy_with_raw(vec![
        Rule::new(NameMatch::Default, Action::Resolve("raw-nx".into()))
            .with_on_nxdomain(NxDomainFallback::Default),
    ]);
    assert!(matches!(
        answer(&policy, "x.test", TYPE::A).await,
        Answer::Raw(_)
    ));
    assert_eq!(policy.stats().fallbacks, 0);
}

#[tokio::test]
async fn cname_chain_follows_the_rules() {
    let policy = policy(vec![
        Rule::new(exact("www.example"), Action::Cname("Edge.Example.".into())),
        Rule::new(exact("edge.example"), Action::Cname("host.lan".into())),
        Rule::new(suffix("lan"), Action::Resolve("local".into())),
        Rule::new(exact("alias.example"), Action::Cname("gone.example".into())),
        Rule::new(exact("gone.example"), Action::Block(ResponseCode::NxDomain)),
    ]);
    assert_eq!(
        answer(&policy, "www.example", TYPE::A).await,
        Answer::Records(vec![
            Record::cname("www.example", 60, "edge.example"),
            Record::cname("edge.example", 60, "host.lan"),
            Record::a("host.lan", 60, v4(10)),
        ])
    );
    // A CNAME query gets the first CNAME only.
    assert_eq!(
        answer(&policy, "www.example", TYPE::CNAME).await,
        Answer::Records(vec![Record::cname("www.example", 60, "edge.example")])
    );
    // The target's code comes back with the chain.
    let Answer::Raw(raw) = answer(&policy, "alias.example", TYPE::A).await else {
        panic!("expected a raw answer");
    };
    let packet = Packet::parse(&raw).unwrap();
    assert_eq!(packet.rcode(), RCODE::NameError);
    assert_eq!(packet.id(), 7);
    assert_eq!(packet.questions[0].qname.to_string(), "alias.example");
    let [cname] = packet.answers.as_slice() else {
        panic!("answers {:?}", packet.answers);
    };
    assert!(matches!(&cname.rdata, RData::CNAME(t) if t.0.to_string() == "gone.example"));
    assert_eq!(policy.stats().cnames, 4);
}

#[tokio::test]
async fn cname_loop_and_depth_limit_end_the_chain() {
    let policy = policy(vec![
        Rule::new(exact("a.loop"), Action::Cname("b.loop".into())),
        Rule::new(exact("b.loop"), Action::Cname("a.loop".into())),
        Rule::new(exact("self.loop"), Action::Cname("self.loop".into())),
        Rule::new(exact("dangling.test"), Action::Cname("nowhere.test".into())),
    ]);
    assert_eq!(
        answer(&policy, "a.loop", TYPE::A).await,
        Answer::Records(vec![
            Record::cname("a.loop", 60, "b.loop"),
            Record::cname("b.loop", 60, "a.loop"),
        ])
    );
    assert_eq!(
        answer(&policy, "self.loop", TYPE::A).await,
        Answer::Records(vec![Record::cname("self.loop", 60, "self.loop")])
    );
    // No rule for the target: the chain ends with what it has.
    assert_eq!(
        answer(&policy, "dangling.test", TYPE::A).await,
        Answer::Records(vec![Record::cname("dangling.test", 60, "nowhere.test")])
    );

    // n0 -> n1 -> ... -> n19: cut after MAX_CNAME_CHAIN records.
    let rules = (0..20)
        .map(|i| {
            Rule::new(
                exact(&format!("n{i}.test")),
                Action::Cname(format!("n{}.test", i + 1)),
            )
        })
        .collect();
    let long = self::policy(rules);
    let Answer::Records(records) = answer(&long, "n0.test", TYPE::A).await else {
        panic!("expected records");
    };
    assert_eq!(records.len(), MAX_CNAME_CHAIN);
    assert_eq!(
        records.last().unwrap(),
        &Record::cname("n7.test", 60, "n8.test")
    );
}

/// Answers once released, with 192.0.2.50.
struct Gate(Arc<Notify>);

impl Resolver for Gate {
    async fn resolve(&self, _query: &Query, _client: SocketAddr) -> Answer {
        self.0.notified().await;
        Answer::Records(vec![Record::a("slow.test", 60, v4(50))])
    }
}

#[tokio::test]
async fn replace_takes_effect_for_new_queries_only() {
    let gate = Arc::new(Notify::new());
    let set = ResolverSet::new().with("slow", Gate(Arc::clone(&gate)));
    let table = PolicyTable::new([
        Rule::new(exact("a.test"), Action::Cname("slow.test".into())),
        Rule::new(exact("slow.test"), Action::Resolve("slow".into())),
    ])
    .unwrap();
    let policy = Arc::new(PolicyResolver::new(set, table).unwrap());

    let in_flight = tokio::spawn({
        let policy = Arc::clone(&policy);
        async move { answer(&*policy, "a.test", TYPE::A).await }
    });
    tokio::task::yield_now().await;

    // The new installation drops the `slow` resolver and answers both names locally.
    policy
        .replace(
            ResolverSet::new(),
            PolicyTable::new([
                Rule::new(exact("a.test"), Action::Cname("slow.test".into())),
                Rule::new(exact("slow.test"), addr(60)),
            ])
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        a_records(&answer(&*policy, "a.test", TYPE::A).await),
        [v4(60)]
    );

    // The query in flight finishes its chain with the installation it started with.
    gate.notify_one();
    assert_eq!(a_records(&in_flight.await.unwrap()), [v4(50)]);
    assert_eq!(policy.stats().rule_hits, [1, 1]);
}

#[tokio::test]
async fn replace_table_keeps_the_resolvers() {
    let policy = policy(vec![Rule::new(NameMatch::Default, addr(1))]);
    policy
        .replace_table(
            PolicyTable::new([Rule::new(
                NameMatch::Default,
                Action::Resolve("other".into()),
            )])
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        a_records(&answer(&policy, "x.test", TYPE::A).await),
        [v4(99)]
    );
    assert_eq!(policy.table().rules().len(), 1);
}

#[test]
fn invalid_tables_are_rejected() {
    let invalid_name = |name: NameMatch, bad: &str| {
        assert_eq!(
            PolicyTable::new([
                Rule::new(NameMatch::Default, Action::NoData),
                Rule::new(name, Action::NoData)
            ])
            .unwrap_err(),
            PolicyError::InvalidName {
                rule: 1,
                name: bad.into()
            }
        );
    };
    invalid_name(exact(""), "");
    invalid_name(exact("."), ".");
    invalid_name(exact("a..b"), "a..b");
    invalid_name(exact("sp ace.test"), "sp ace.test");
    invalid_name(exact(&"x".repeat(64)), &"x".repeat(64));
    invalid_name(exact("*.test"), "*.test");
    invalid_name(suffix(""), "");
    invalid_name(wildcard("dev.example"), "dev.example");
    invalid_name(wildcard("*"), "*");
    invalid_name(wildcard("*."), "*.");
    invalid_name(wildcard("*x.example"), "*x.example");
    invalid_name(wildcard("a.*.example"), "a.*.example");
    invalid_name(wildcard("*.*.example"), "*.*.example");

    assert_eq!(
        PolicyTable::new([Rule::new(exact("a.test"), Action::Cname("bad name".into()))])
            .unwrap_err(),
        PolicyError::InvalidTarget {
            rule: 0,
            target: "bad name".into()
        }
    );
    assert_eq!(
        PolicyTable::new([Rule::new(
            exact("a.test"),
            Action::Records(vec![RecordData::Cname(String::new())])
        )])
        .unwrap_err(),
        PolicyError::InvalidTarget {
            rule: 0,
            target: String::new()
        }
    );
    assert_eq!(
        PolicyTable::new([Rule::new(exact("a.test"), Action::NoData)
            .with_clients([(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 33)])])
        .unwrap_err(),
        PolicyError::InvalidPrefix { rule: 0, len: 33 }
    );
}

#[tokio::test]
async fn unknown_resolver_ids_are_rejected_and_the_table_stays() {
    let table = |id: &str| {
        PolicyTable::new([
            Rule::new(exact("a.test"), addr(1)),
            Rule::new(NameMatch::Default, Action::Resolve("local".into()))
                .with_on_nxdomain(NxDomainFallback::Resolve(id.into())),
        ])
        .unwrap()
    };
    let unknown = PolicyError::UnknownResolver {
        rule: 1,
        id: "nope".into(),
    };
    assert_eq!(
        PolicyResolver::new(resolvers(), table("nope")).unwrap_err(),
        unknown
    );

    let policy = policy(vec![Rule::new(NameMatch::Default, addr(2))]);
    assert_eq!(
        policy.replace(resolvers(), table("nope")).unwrap_err(),
        unknown
    );
    assert_eq!(policy.replace_table(table("nope")).unwrap_err(), unknown);
    assert_eq!(
        policy
            .replace(
                ResolverSet::new(),
                PolicyTable::new([Rule::new(
                    NameMatch::Default,
                    Action::Resolve("local".into())
                )])
                .unwrap()
            )
            .unwrap_err(),
        PolicyError::UnknownResolver {
            rule: 0,
            id: "local".into()
        }
    );
    assert_eq!(
        a_records(&answer(&policy, "a.test", TYPE::A).await),
        [v4(2)]
    );

    policy.replace_table(table("other")).unwrap();
    assert_eq!(
        a_records(&answer(&policy, "a.test", TYPE::A).await),
        [v4(1)]
    );
}

#[test]
fn names_are_normalized_on_install() {
    let table = PolicyTable::new([
        Rule::new(exact("Printer.LAN."), Action::Cname("Host.LAN.".into())),
        Rule::new(wildcard("*.Dev.Example"), Action::NoData),
    ])
    .unwrap();
    assert_eq!(table.rules()[0].name, exact("printer.lan"));
    assert_eq!(table.rules()[0].action, Action::Cname("host.lan".into()));
    assert_eq!(table.rules()[1].name, wildcard("*.dev.example"));
    assert_eq!(
        table.matching("PRINTER.lan", RecordType::A, client().ip()),
        Some(0)
    );
}

#[test]
fn resolver_is_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<PolicyResolver>();
    check::<ResolverSet>();
}
