//! DNS policy routing: per-name rules pick a resolver or answer locally.
//!
//! A [`PolicyResolver`] is built from hosts-format text ([`Hosts`]: plain names as
//! [`StaticRecords`], a `*.` name as a wildcard rule), a [`FakePool`] and, with
//! `--upstream`, a [`Forwarder`]. Its rules send `*.lan` to the local records, names below
//! `fake.example` to the fake pool, sinkhole `ads.example`, block `blocked.example`, alias
//! `www.example` to `printer.lan` with a CNAME and send the rest to the upstream (or answer
//! `REFUSED` without one). The program resolves a set of names through the policy, prints
//! one `CHECK` line each, replaces the rule table at runtime, checks the new routing, and
//! prints the policy counters and `CHECKS PASS` or `CHECKS FAIL`. Queries go to the
//! resolver directly; a [`nsplane_dns::Server`] serves the same resolver over UDP and TCP.
//!
//! APIs shown: [`Hosts::parse`], [`ResolverSet`], [`PolicyTable`], [`Rule`] with
//! [`NameMatch`] and [`Action`], [`PolicyResolver::replace_table`],
//! [`PolicyResolver::matching`], [`PolicyResolver::stats`].
//!
//! Usage: `cargo run -p nsplane-examples --bin dns_policy -- [--upstream <IP:PORT>]`

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context as _, bail};
use clap::Parser;
use nsplane_dns::{
    Action, Answer, FakePool, FakePoolConfig, Forwarder, ForwarderConfig, Hosts, NameMatch,
    PolicyResolver, PolicyTable, Query, RecordData, RecordType, Resolver, ResolverSet,
    ResponseCode, Rule, StaticRecords,
};
use nsplane_examples::node::init_logging;
use nsplane_examples::out;

/// Routes DNS queries by name through a rule table.
#[derive(Debug, Parser)]
#[command(name = "dns_policy", version)]
struct Args {
    /// Upstream DNS server for names no other rule covers; without it they get REFUSED
    #[arg(long, value_name = "IP:PORT")]
    upstream: Option<SocketAddr>,

    /// Log filter for stderr
    #[arg(long, value_name = "FILTER", default_value = "warn")]
    log: String,
}

/// The local names, as an embedder would read them from a hosts file.
const HOSTS: &str = "\
# local names
10.0.0.7      printer.lan
10.0.0.8      nas.lan
198.51.100.1  *.dev.example
";

/// The client the queries come from.
const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5353);

/// A query for `name` of type `record_type`, class IN, recursion desired.
fn query(name: &str, record_type: RecordType) -> anyhow::Result<Query> {
    let mut message = vec![0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        message.push(u8::try_from(label.len())?);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&record_type.0.to_be_bytes());
    message.extend_from_slice(&nsplane_dns::CLASS_IN.to_be_bytes());
    Ok(Query::decode(&message)?)
}

/// The answer as text: the records' data, or the response code.
fn describe(answer: &Answer) -> String {
    match answer {
        Answer::Records(records) if records.is_empty() => "NODATA".to_owned(),
        Answer::Records(records) => records
            .iter()
            .map(|r| match &r.data {
                RecordData::A(a) => a.to_string(),
                RecordData::Aaaa(a) => a.to_string(),
                RecordData::Cname(target) => format!("CNAME:{target}"),
                other => format!("{other:?}"),
            })
            .collect::<Vec<_>>()
            .join(","),
        Answer::Code(code) => format!("{code:?}"),
        Answer::Raw(raw) => format!("raw:{}bytes", raw.len()),
    }
}

/// Resolves `name`, prints the check line and returns whether the answer is `want` (any
/// answer when `want` is `None`).
async fn check(policy: &PolicyResolver, name: &str, want: Option<&str>) -> bool {
    let result = async {
        let answer = policy.resolve(&query(name, RecordType::A)?, CLIENT).await;
        let got = describe(&answer);
        match want {
            Some(want) if got != want => bail!("{got}, want {want}"),
            _ => Ok(got),
        }
    }
    .await;
    match result {
        Ok(detail) => {
            out::line(format_args!("CHECK A {name} {detail} PASS"));
            true
        }
        Err(err) => {
            out::line(format_args!("CHECK A {name} FAIL {err:#}"));
            false
        }
    }
}

/// The rules: hosts wildcards, then the named routes, then the default.
fn rules(hosts: &Hosts, upstream: bool, blocked: Action) -> Vec<Rule> {
    let mut rules = vec![
        Rule::new(
            NameMatch::Suffix("lan".into()),
            Action::Resolve("local".into()),
        ),
        Rule::new(
            NameMatch::Wildcard("*.fake.example".into()),
            Action::Resolve("fake".into()),
        ),
        Rule::new(NameMatch::Suffix("ads.example".into()), Action::Sinkhole),
        Rule::new(NameMatch::Exact("blocked.example".into()), blocked),
        Rule::new(
            NameMatch::Exact("www.example".into()),
            Action::Cname("printer.lan".into()),
        ),
    ];
    rules.extend(hosts.wildcard_rules());
    rules.push(Rule::new(
        NameMatch::Default,
        if upstream {
            Action::Resolve("upstream".into())
        } else {
            Action::Block(ResponseCode::Refused)
        },
    ));
    rules
}

async fn run(args: &Args) -> anyhow::Result<bool> {
    let hosts = Hosts::parse(HOSTS);
    if let Some(error) = hosts.errors().first() {
        bail!("hosts text: {error}");
    }
    let records: StaticRecords = hosts.static_records(300);
    let pool = Arc::new(FakePool::new(FakePoolConfig {
        ipv4: Some((Ipv4Addr::new(198, 18, 0, 0), 15)),
        ..FakePoolConfig::default()
    })?);
    let mut resolvers = ResolverSet::new()
        .with("local", records)
        .with("fake", Arc::clone(&pool));
    if let Some(upstream) = args.upstream {
        resolvers.insert(
            "upstream",
            Forwarder::new(ForwarderConfig::new(vec![upstream]))?,
        );
    }
    let upstream = args.upstream.is_some();
    let table = PolicyTable::new(rules(
        &hosts,
        upstream,
        Action::Block(ResponseCode::NxDomain),
    ))?;
    let policy = PolicyResolver::new(resolvers, table)?;

    let mut passed = true;
    passed &= check(&policy, "printer.lan", Some("10.0.0.7")).await;
    passed &= check(&policy, "api.dev.example", Some("198.51.100.1")).await;
    passed &= check(&policy, "app.fake.example", Some("198.18.0.1")).await;
    passed &= check(&policy, "tracker.ads.example", Some("0.0.0.0")).await;
    passed &= check(&policy, "blocked.example", Some("NxDomain")).await;
    passed &= check(&policy, "www.example", Some("CNAME:printer.lan,10.0.0.7")).await;
    // The wildcard does not cover `dev.example` itself: the default rule answers.
    let default = if upstream { None } else { Some("Refused") };
    passed &= check(&policy, "dev.example", default).await;
    let rule = policy
        .matching("dev.example", RecordType::A, CLIENT.ip())
        .context("no rule")?;
    out::line(format_args!("RULE dev.example -> {rule}"));

    // Unblock `blocked.example` at runtime; the resolvers stay.
    let unblocked = Action::Records(vec![RecordData::A(Ipv4Addr::new(192, 0, 2, 9))]);
    policy.replace_table(PolicyTable::new(rules(&hosts, upstream, unblocked))?)?;
    passed &= check(&policy, "blocked.example", Some("192.0.2.9")).await;

    let stats = policy.stats();
    out::line(format_args!(
        "STATS resolved={} sinkholed={} blocked={} cnames={} records={} fake_bindings={}",
        stats.resolved,
        stats.sinkholed,
        stats.blocked,
        stats.cnames,
        stats.records,
        pool.len()
    ));
    Ok(passed)
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    init_logging(&args.log)?;
    let passed = run(&args).await?;
    out::line(format_args!(
        "CHECKS {}",
        if passed { "PASS" } else { "FAIL" }
    ));
    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
