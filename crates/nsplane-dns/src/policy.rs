//! [`PolicyResolver`]: per-name rules that pick a resolver or answer locally.
//!
//! The embedder registers resolvers under ids in a [`ResolverSet`] and builds a
//! [`PolicyTable`] of [`Rule`]s; each rule matches names ([`NameMatch`]), optionally query
//! types and client prefixes, and has an [`Action`]: ask a registered resolver, or answer
//! with records, a block code, a sinkhole address, `NODATA` or a CNAME. Both can be replaced
//! while a server runs.
//!
//! ```
//! use std::net::{Ipv4Addr, SocketAddr};
//!
//! use nsplane_dns::{
//!     Action, Answer, Hosts, NameMatch, PolicyResolver, PolicyTable, Query, Record, Resolver,
//!     ResolverSet, ResponseCode, Rule,
//! };
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! let hosts = Hosts::parse("10.0.0.7 printer.lan\n198.51.100.1 *.dev.example\n");
//! let resolvers = ResolverSet::new().with("local", hosts.static_records(300));
//! let mut rules = vec![
//!     Rule::new(NameMatch::Suffix("lan".into()), Action::Resolve("local".into())),
//!     Rule::new(NameMatch::Suffix("ads.example".into()), Action::Sinkhole),
//!     Rule::new(NameMatch::Exact("www.example".into()), Action::Cname("printer.lan".into())),
//! ];
//! rules.extend(hosts.wildcard_rules());
//! rules.push(Rule::new(NameMatch::Default, Action::Block(ResponseCode::Refused)));
//! let policy = PolicyResolver::new(resolvers, PolicyTable::new(rules).unwrap()).unwrap();
//!
//! // A query for `www.example. A`.
//! let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
//! message.extend_from_slice(b"\x03www\x07example\x00\x00\x01\x00\x01");
//! let query = Query::decode(&message).unwrap();
//!
//! let client = SocketAddr::from(([10, 0, 0, 2], 5353));
//! assert_eq!(
//!     policy.resolve(&query, client).await,
//!     Answer::Records(vec![
//!         Record::cname("www.example", 60, "printer.lan"),
//!         Record::a("printer.lan", 300, Ipv4Addr::new(10, 0, 0, 7)),
//!     ])
//! );
//! # }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use bytes::Bytes;
use simple_dns::rdata::{CNAME, RData};
use simple_dns::{CLASS, Name, Packet, ResourceRecord};

use crate::message::{
    Answer, EncodeOptions, Query, Record, RecordData, RecordType, ResponseCode, encode_response,
    normalize_name,
};
use crate::resolver::Resolver;

/// Default [`PolicyTable::with_ttl`]: TTL of the records a rule answers itself.
pub const DEFAULT_POLICY_TTL: u32 = 60;

/// Most CNAME records a chain of [`Action::Cname`] rules adds to one answer.
pub const MAX_CNAME_CHAIN: usize = 8;

/// The names a [`Rule`] applies to. Names are normalized ([`normalize_name`]) on install.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NameMatch {
    /// Exactly this name.
    Exact(String),
    /// This name and every name below it: `corp.example` matches `corp.example` and
    /// `a.b.corp.example`.
    Suffix(String),
    /// Every name below the part after `*.`, hosts-style: `*.dev.example` matches
    /// `a.dev.example` and `a.b.dev.example` but not `dev.example`. The `*` is the whole
    /// leftmost label.
    Wildcard(String),
    /// Every name; tried after all named rules.
    Default,
}

/// What a [`Rule`] does with the queries it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Asks the resolver registered under this id in the [`ResolverSet`].
    Resolve(String),
    /// Answers with this data under the query name: the entries of the query type (all of
    /// them for `ANY`), `NODATA` when there are none. Under a suffix or wildcard rule this is
    /// a wildcard hosts entry.
    Records(Vec<RecordData>),
    /// Answers with this code and no records, typically `NXDOMAIN` or `REFUSED`.
    Block(ResponseCode),
    /// Answers A with `0.0.0.0` and AAAA with `::` (both for `ANY`); `NODATA` for other types.
    Sinkhole,
    /// Answers `NODATA` (`NOERROR` without records).
    NoData,
    /// Answers a CNAME from the query name to this name, followed by the answer for the
    /// target under the same query type through the same rules. A query of type CNAME gets
    /// the CNAME alone.
    Cname(String),
}

/// Where a query goes when the resolver of an [`Action::Resolve`] rule answers `NXDOMAIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NxDomainFallback {
    /// The default rule (the first [`NameMatch::Default`] rule whose conditions hold).
    Default,
    /// The resolver registered under this id.
    Resolve(String),
}

/// A name match, optional conditions and an action.
///
/// A rule applies to a query when its name matches, the query type is one of `types` (any
/// type when empty) and the client address is inside one of `clients` (any client when
/// empty).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rule {
    /// The names the rule applies to.
    pub name: NameMatch,
    /// What the rule answers.
    pub action: Action,
    /// Query types the rule applies to; empty for all.
    pub types: Vec<RecordType>,
    /// Client prefixes (network address, prefix length) the rule applies to; empty for all.
    /// IPv4-mapped IPv6 clients match as IPv4.
    pub clients: Vec<(IpAddr, u8)>,
    /// What to do when an [`Action::Resolve`] resolver answers `NXDOMAIN`; `None` keeps the
    /// answer.
    pub on_nxdomain: Option<NxDomainFallback>,
}

impl Rule {
    /// A rule without conditions or fallback.
    pub const fn new(name: NameMatch, action: Action) -> Self {
        Self {
            name,
            action,
            types: Vec::new(),
            clients: Vec::new(),
            on_nxdomain: None,
        }
    }

    /// Restricts the rule to these query types.
    #[must_use]
    pub fn with_types(mut self, types: impl IntoIterator<Item = RecordType>) -> Self {
        self.types = types.into_iter().collect();
        self
    }

    /// Restricts the rule to clients in these prefixes.
    #[must_use]
    pub fn with_clients(mut self, prefixes: impl IntoIterator<Item = (IpAddr, u8)>) -> Self {
        self.clients = prefixes.into_iter().collect();
        self
    }

    /// Sets the `NXDOMAIN` fallback of an [`Action::Resolve`] rule.
    #[must_use]
    pub fn with_on_nxdomain(mut self, fallback: NxDomainFallback) -> Self {
        self.on_nxdomain = Some(fallback);
        self
    }

    fn applies(&self, record_type: RecordType, client: IpAddr) -> bool {
        (self.types.is_empty() || self.types.contains(&record_type))
            && (self.clients.is_empty()
                || self
                    .clients
                    .iter()
                    .any(|&(net, len)| in_prefix(client, net, len)))
    }
}

/// Why a [`PolicyTable`] or a [`PolicyResolver`] installation is rejected. `rule` is the
/// index of the offending rule in declaration order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// A rule name is empty or not a host name (labels of letters, digits, `-` and `_`), or
    /// a wildcard does not start with `*.`.
    #[error("rule {rule}: invalid name `{name}`")]
    InvalidName {
        /// Rule index.
        rule: usize,
        /// The name as given.
        name: String,
    },
    /// A CNAME target, or a CNAME / PTR target in [`Action::Records`], is not a host name.
    #[error("rule {rule}: invalid target `{target}`")]
    InvalidTarget {
        /// Rule index.
        rule: usize,
        /// The target as given.
        target: String,
    },
    /// A client prefix length exceeds the address width.
    #[error("rule {rule}: invalid client prefix length {len}")]
    InvalidPrefix {
        /// Rule index.
        rule: usize,
        /// The prefix length.
        len: u8,
    },
    /// An [`Action::Resolve`] or [`NxDomainFallback::Resolve`] id is not in the
    /// [`ResolverSet`].
    #[error("rule {rule}: unknown resolver `{id}`")]
    UnknownResolver {
        /// Rule index.
        rule: usize,
        /// The resolver id.
        id: String,
    },
}

/// A validated rule table, indexed for lookup.
///
/// The rule for a query is found by precedence, then declaration order:
///
/// 1. exact rules of the query name;
/// 2. suffix and wildcard rules, by the length of the name they are anchored at, longer
///    first; at equal length suffix rules before wildcard rules;
/// 3. default rules.
///
/// Among the rules of one name (an exact name, a suffix or wildcard anchor, or the default
/// rules) the first in declaration order whose conditions hold wins; when none holds, the
/// search goes on. A lookup costs a few hash lookups per label of the query name,
/// plus a scan of the candidate rules in each matching bucket and, if reached, the defaults.
#[derive(Debug, Clone)]
pub struct PolicyTable {
    rules: Vec<Rule>,
    exact: HashMap<String, Vec<usize>>,
    suffix: HashMap<String, Vec<usize>>,
    /// Keyed by the name after `*.`.
    wildcard: HashMap<String, Vec<usize>>,
    default: Vec<usize>,
    ttl: u32,
}

impl PolicyTable {
    /// Validates and indexes `rules`, with TTL [`DEFAULT_POLICY_TTL`].
    ///
    /// # Errors
    ///
    /// The first invalid name, target or client prefix as a [`PolicyError`]. Resolver ids
    /// are checked when the table is installed into a [`PolicyResolver`].
    pub fn new(rules: impl IntoIterator<Item = Rule>) -> Result<Self, PolicyError> {
        let mut table = Self {
            rules: Vec::new(),
            exact: HashMap::new(),
            suffix: HashMap::new(),
            wildcard: HashMap::new(),
            default: Vec::new(),
            ttl: DEFAULT_POLICY_TTL,
        };
        for (index, mut rule) in rules.into_iter().enumerate() {
            let invalid_name = |name: &str| PolicyError::InvalidName {
                rule: index,
                name: name.to_owned(),
            };
            let bucket = match &mut rule.name {
                NameMatch::Exact(name) => {
                    let key =
                        normalize_in_place(name, is_host_name).ok_or_else(|| invalid_name(name))?;
                    Some((&mut table.exact, key))
                }
                NameMatch::Suffix(name) => {
                    let key =
                        normalize_in_place(name, is_host_name).ok_or_else(|| invalid_name(name))?;
                    Some((&mut table.suffix, key))
                }
                NameMatch::Wildcard(name) => {
                    let is_wildcard = |n: &str| n.strip_prefix("*.").is_some_and(is_host_name);
                    let key =
                        normalize_in_place(name, is_wildcard).ok_or_else(|| invalid_name(name))?;
                    Some((&mut table.wildcard, key[2..].to_owned()))
                }
                NameMatch::Default => None,
            };
            match bucket {
                Some((map, key)) => map.entry(key).or_default().push(index),
                None => table.default.push(index),
            }
            check_action(index, &mut rule.action)?;
            for &(net, len) in &rule.clients {
                let width = if net.is_ipv4() { 32 } else { 128 };
                if len > width {
                    return Err(PolicyError::InvalidPrefix { rule: index, len });
                }
            }
            table.rules.push(rule);
        }
        Ok(table)
    }

    /// Sets the TTL of the records answered by [`Action::Records`], [`Action::Sinkhole`] and
    /// [`Action::Cname`].
    #[must_use]
    pub const fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// The rules in declaration order, names normalized.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The local answer TTL.
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// The index of the rule a query for `name` of type `record_type` from `client` uses,
    /// `None` when no rule applies. `name` is normalized first.
    pub fn matching(&self, name: &str, record_type: RecordType, client: IpAddr) -> Option<usize> {
        self.find(&normalize_name(name), record_type, client)
    }

    /// [`matching`](Self::matching) for an already normalized name.
    fn find(&self, name: &str, record_type: RecordType, client: IpAddr) -> Option<usize> {
        let client = client.to_canonical();
        let pick = |ids: Option<&Vec<usize>>| {
            ids.into_iter()
                .flatten()
                .copied()
                .find(|&i| self.rules[i].applies(record_type, client))
        };
        if let Some(index) = pick(self.exact.get(name)) {
            return Some(index);
        }
        let mut base = name;
        let mut below = false;
        while !base.is_empty() {
            if let Some(index) = pick(self.suffix.get(base)) {
                return Some(index);
            }
            if below && let Some(index) = pick(self.wildcard.get(base)) {
                return Some(index);
            }
            base = base.split_once('.').map_or("", |(_, rest)| rest);
            below = true;
        }
        pick(Some(&self.default))
    }

    fn default_rule(&self, record_type: RecordType, client: IpAddr) -> Option<usize> {
        let client = client.to_canonical();
        self.default
            .iter()
            .copied()
            .find(|&i| self.rules[i].applies(record_type, client))
    }
}

/// Normalizes `name` in place when `valid` accepts the normalized form, and returns it.
fn normalize_in_place(name: &mut String, valid: impl Fn(&str) -> bool) -> Option<String> {
    let normalized = normalize_name(name);
    valid(&normalized).then(|| {
        name.clone_from(&normalized);
        normalized
    })
}

/// Normalizes and validates the names inside an action.
fn check_action(rule: usize, action: &mut Action) -> Result<(), PolicyError> {
    let invalid = |target: &str| PolicyError::InvalidTarget {
        rule,
        target: target.to_owned(),
    };
    match action {
        Action::Cname(target) => {
            let normalized = normalize_name(target);
            if !is_host_name(&normalized) {
                return Err(invalid(target));
            }
            *target = normalized;
        }
        Action::Records(data) => {
            for entry in data {
                if let RecordData::Cname(target) | RecordData::Ptr(target) = entry
                    && !is_host_name(&normalize_name(target))
                {
                    return Err(invalid(target));
                }
            }
        }
        Action::Resolve(_) | Action::Block(_) | Action::Sinkhole | Action::NoData => {}
    }
    Ok(())
}

/// Whether `name` (normalized) is a non-empty host name: labels of 1 to 63 letters, digits,
/// `-` and `_`, at most 253 bytes.
pub(crate) fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn in_prefix(addr: IpAddr, net: IpAddr, len: u8) -> bool {
    let len = u32::from(len);
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32u32.saturating_sub(len)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX
                .checked_shl(128u32.saturating_sub(len))
                .unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// Object-safe form of [`Resolver`], for resolvers of different types under one map.
trait DynResolver: Send + Sync {
    fn resolve_dyn<'a>(
        &'a self,
        query: &'a Query,
        client: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Answer> + Send + 'a>>;
}

impl<R: Resolver> DynResolver for R {
    fn resolve_dyn<'a>(
        &'a self,
        query: &'a Query,
        client: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Answer> + Send + 'a>> {
        Box::pin(self.resolve(query, client))
    }
}

/// Resolvers of any types, registered under ids for [`Action::Resolve`] rules.
///
/// Register a shared resolver as `Arc<R>` to keep a handle on it (for its stats). Cloning
/// the set shares the resolvers.
#[derive(Clone, Default)]
pub struct ResolverSet {
    resolvers: HashMap<String, Arc<dyn DynResolver>>,
}

impl ResolverSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `resolver` under `id`, replacing a resolver with the same id.
    #[must_use]
    pub fn with(mut self, id: impl Into<String>, resolver: impl Resolver + 'static) -> Self {
        self.insert(id, resolver);
        self
    }

    /// Registers `resolver` under `id`, replacing a resolver with the same id.
    pub fn insert(
        &mut self,
        id: impl Into<String>,
        resolver: impl Resolver + 'static,
    ) -> &mut Self {
        self.resolvers.insert(id.into(), Arc::new(resolver));
        self
    }

    /// Whether a resolver is registered under `id`.
    pub fn contains(&self, id: &str) -> bool {
        self.resolvers.contains_key(id)
    }

    /// Number of registered resolvers.
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// Whether no resolver is registered.
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

impl fmt::Debug for ResolverSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ids: Vec<&str> = self.resolvers.keys().map(String::as_str).collect();
        ids.sort_unstable();
        f.debug_struct("ResolverSet").field("ids", &ids).finish()
    }
}

/// Counters of a [`PolicyResolver`].
///
/// Each rule applied counts once in `rule_hits` and in the counter of its action; a CNAME
/// chain applies one rule per step. `rule_hits` belongs to the installed table and restarts
/// at zero when a table is installed; the other counters run since the resolver was created.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyStats {
    /// Applications per rule of the installed table, by rule index.
    pub rule_hits: Vec<u64>,
    /// [`Action::Resolve`] rules applied.
    pub resolved: u64,
    /// [`Action::Records`] rules applied.
    pub records: u64,
    /// [`Action::Block`] rules applied.
    pub blocked: u64,
    /// [`Action::Sinkhole`] rules applied.
    pub sinkholed: u64,
    /// [`Action::NoData`] rules applied.
    pub nodata: u64,
    /// [`Action::Cname`] rules applied.
    pub cnames: u64,
    /// `NXDOMAIN` answers handed to a rule's [`NxDomainFallback`].
    pub fallbacks: u64,
    /// Lookups no rule applied to.
    pub unmatched: u64,
}

#[derive(Debug, Default)]
struct Counters {
    resolved: AtomicU64,
    records: AtomicU64,
    blocked: AtomicU64,
    sinkholed: AtomicU64,
    nodata: AtomicU64,
    cnames: AtomicU64,
    fallbacks: AtomicU64,
    unmatched: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// A resolver set and a table, installed together.
#[derive(Debug)]
struct Installed {
    resolvers: ResolverSet,
    table: PolicyTable,
    hits: Vec<AtomicU64>,
}

impl Installed {
    fn new(resolvers: ResolverSet, table: PolicyTable) -> Result<Self, PolicyError> {
        for (rule, r) in table.rules.iter().enumerate() {
            let fallback = match &r.on_nxdomain {
                Some(NxDomainFallback::Resolve(id)) => Some(id),
                _ => None,
            };
            let action = match &r.action {
                Action::Resolve(id) => Some(id),
                _ => None,
            };
            if let Some(id) = action
                .into_iter()
                .chain(fallback)
                .find(|id| !resolvers.contains(id))
            {
                return Err(PolicyError::UnknownResolver {
                    rule,
                    id: id.clone(),
                });
            }
        }
        let hits = table.rules.iter().map(|_| AtomicU64::new(0)).collect();
        Ok(Self {
            resolvers,
            table,
            hits,
        })
    }

    async fn ask(&self, id: &str, query: &Query, client: SocketAddr) -> Answer {
        match self.resolvers.resolvers.get(id) {
            Some(resolver) => resolver.resolve_dyn(query, client).await,
            // Ids are checked on install.
            None => Answer::Code(ResponseCode::ServFail),
        }
    }

    async fn resolve(&self, query: &Query, client: SocketAddr, counters: &Counters) -> Answer {
        let ip = client.ip();
        let ttl = self.table.ttl;
        let mut chain: Vec<Record> = Vec::new();
        let mut target: Option<Query> = None;
        let mut forced: Option<usize> = None;
        let mut fell_back = false;
        let answer = loop {
            let q = target.as_ref().unwrap_or(query);
            let found = forced
                .take()
                .or_else(|| self.table.find(q.name(), q.record_type(), ip));
            let Some(index) = found else {
                bump(&counters.unmatched);
                // A CNAME target no rule applies to ends the chain with what it has.
                break if chain.is_empty() {
                    Answer::Code(ResponseCode::Refused)
                } else {
                    Answer::Records(Vec::new())
                };
            };
            bump(&self.hits[index]);
            let rule = &self.table.rules[index];
            let wanted =
                |ty: RecordType| q.record_type() == RecordType::ANY || q.record_type() == ty;
            match &rule.action {
                Action::Resolve(id) => {
                    bump(&counters.resolved);
                    let answer = self.ask(id, q, client).await;
                    if !fell_back && is_nxdomain(&answer) {
                        match &rule.on_nxdomain {
                            Some(NxDomainFallback::Default) => {
                                let default = self
                                    .table
                                    .default_rule(q.record_type(), ip)
                                    .filter(|&d| d != index);
                                if default.is_some() {
                                    bump(&counters.fallbacks);
                                    fell_back = true;
                                    forced = default;
                                    continue;
                                }
                            }
                            Some(NxDomainFallback::Resolve(id)) => {
                                bump(&counters.fallbacks);
                                break self.ask(id, q, client).await;
                            }
                            None => {}
                        }
                    }
                    break answer;
                }
                Action::Records(data) => {
                    bump(&counters.records);
                    break Answer::Records(
                        data.iter()
                            .filter(|d| wanted(d.record_type()))
                            .map(|d| Record::new(q.name(), ttl, d.clone()))
                            .collect(),
                    );
                }
                Action::Block(code) => {
                    bump(&counters.blocked);
                    break Answer::Code(*code);
                }
                Action::Sinkhole => {
                    bump(&counters.sinkholed);
                    let mut records = Vec::new();
                    if wanted(RecordType::A) {
                        records.push(Record::a(q.name(), ttl, Ipv4Addr::UNSPECIFIED));
                    }
                    if wanted(RecordType::AAAA) {
                        records.push(Record::aaaa(q.name(), ttl, Ipv6Addr::UNSPECIFIED));
                    }
                    break Answer::Records(records);
                }
                Action::NoData => {
                    bump(&counters.nodata);
                    break Answer::Records(Vec::new());
                }
                Action::Cname(next) => {
                    bump(&counters.cnames);
                    chain.push(Record::cname(q.name(), ttl, next.clone()));
                    let looped = chain.iter().any(|r| r.name == *next);
                    if q.record_type() == RecordType::CNAME
                        || looped
                        || chain.len() >= MAX_CNAME_CHAIN
                    {
                        break Answer::Records(Vec::new());
                    }
                    let Some(next) = target_query(query, next) else {
                        break Answer::Records(Vec::new());
                    };
                    target = Some(next);
                    fell_back = false;
                }
            }
        };
        with_chain(query, chain, answer)
    }
}

/// Whether `answer` is `NXDOMAIN`, local or raw.
fn is_nxdomain(answer: &Answer) -> bool {
    match answer {
        Answer::Code(code) => *code == ResponseCode::NxDomain,
        Answer::Raw(raw) => raw
            .get(3)
            .is_some_and(|flags| flags & 0x0f == ResponseCode::NxDomain.value()),
        Answer::Records(_) => false,
    }
}

/// A query for `target` with the type, class, ID, `RD` and EDNS payload size of `original`.
fn target_query(original: &Query, target: &str) -> Option<Query> {
    let edns = original.udp_payload_size();
    let mut message = Vec::with_capacity(target.len() + 29);
    message.extend_from_slice(&original.id().to_be_bytes());
    message.push(u8::from(original.recursion_desired()));
    message.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0, u8::from(edns.is_some())]);
    for label in target.split('.') {
        message.push(u8::try_from(label.len()).ok()?);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&original.record_type().0.to_be_bytes());
    message.extend_from_slice(&original.class().to_be_bytes());
    if let Some(size) = edns {
        // OPT: root owner, type 41, class = payload size, TTL 0, no data.
        message.extend_from_slice(&[0, 0, 41]);
        message.extend_from_slice(&size.to_be_bytes());
        message.extend_from_slice(&[0; 6]);
    }
    Query::decode(&message).ok()
}

/// Puts the CNAME `chain` in front of `answer`, the answer for the chain's last target.
fn with_chain(query: &Query, mut chain: Vec<Record>, answer: Answer) -> Answer {
    if chain.is_empty() {
        return answer;
    }
    match answer {
        Answer::Records(records) => {
            chain.extend(records);
            Answer::Records(chain)
        }
        Answer::Code(ResponseCode::NoError) => Answer::Records(chain),
        Answer::Code(code) => {
            coded(query, &chain, code).map_or(Answer::Records(chain), Answer::Raw)
        }
        Answer::Raw(raw) => {
            spliced(query, &chain, &raw).map_or(Answer::Records(chain), Answer::Raw)
        }
    }
}

/// A response to `query` with the `chain` records and response code `code`.
fn coded(query: &Query, chain: &[Record], code: ResponseCode) -> Option<Bytes> {
    let records = Answer::Records(chain.to_vec());
    let mut response =
        encode_response(query, &records, usize::MAX, EncodeOptions::default()).to_vec();
    let flags = response.get_mut(3)?;
    *flags = (*flags & 0xf0) | code.value();
    Some(Bytes::from(response))
}

/// The upstream response `raw` for the chain's last target, with the client's question and
/// the `chain` records in front of its answers.
fn spliced(query: &Query, chain: &[Record], raw: &[u8]) -> Option<Bytes> {
    let request = Packet::parse(query.raw()).ok()?;
    let mut response = Packet::parse(raw).ok()?;
    response.questions = request.questions;
    let mut answers = Vec::with_capacity(chain.len() + response.answers.len());
    for record in chain {
        let RecordData::Cname(target) = &record.data else {
            return None;
        };
        answers.push(ResourceRecord::new(
            Name::new(&record.name).ok()?,
            CLASS::IN,
            record.ttl,
            RData::CNAME(CNAME(Name::new(target).ok()?)),
        ));
    }
    answers.append(&mut response.answers);
    response.answers = answers;
    response.build_bytes_vec_compressed().ok().map(Bytes::from)
}

/// A [`Resolver`] that routes each query by a rule table: to one of several registered
/// resolvers, or to a local answer.
///
/// The rule for a query is chosen as described on [`PolicyTable`] from the query name, type
/// and client address. A query no rule applies to is answered `REFUSED`. Messages that do
/// not decode as a query never reach it.
///
/// An [`Action::Resolve`] rule asks its resolver; when that answers `NXDOMAIN` (an
/// [`Answer::Code`] or an [`Answer::Raw`] with that code) and the rule has an
/// [`NxDomainFallback`], the query goes to the default rule or to the other resolver once.
///
/// An [`Action::Cname`] rule answers a CNAME and resolves its target through the table again,
/// with the same type, class and client. The answer carries the chain of CNAME records
/// followed by the target's answer: its records, or the upstream response with the client's
/// question and the chain in front of its answers, or the target's response code with the
/// chain. A chain stops with the records collected so far when a target repeats a name of
/// the chain, when it holds [`MAX_CNAME_CHAIN`] records, or when no rule applies to a target.
///
/// The resolver set and the table are installed together and replaced atomically with
/// [`replace`](Self::replace) or [`replace_table`](Self::replace_table): every query runs,
/// CNAME chain included, against the installation current when it started. Replacing takes
/// effect for the next query without restarting a server; queries in flight finish with the
/// previous installation.
#[derive(Debug)]
pub struct PolicyResolver {
    installed: RwLock<Arc<Installed>>,
    counters: Counters,
}

impl PolicyResolver {
    /// A resolver routing by `table` to the resolvers of `resolvers`.
    ///
    /// # Errors
    ///
    /// [`PolicyError::UnknownResolver`] when a rule names an id not in `resolvers`.
    pub fn new(resolvers: ResolverSet, table: PolicyTable) -> Result<Self, PolicyError> {
        Ok(Self {
            installed: RwLock::new(Arc::new(Installed::new(resolvers, table)?)),
            counters: Counters::default(),
        })
    }

    /// Installs a new resolver set and table together.
    ///
    /// # Errors
    ///
    /// [`PolicyError::UnknownResolver`] when a rule names an id not in `resolvers`; the
    /// current installation stays.
    pub fn replace(&self, resolvers: ResolverSet, table: PolicyTable) -> Result<(), PolicyError> {
        let installed = Arc::new(Installed::new(resolvers, table)?);
        *self
            .installed
            .write()
            .unwrap_or_else(PoisonError::into_inner) = installed;
        Ok(())
    }

    /// Installs a new table with the current resolver set.
    ///
    /// # Errors
    ///
    /// [`PolicyError::UnknownResolver`] when a rule names an id not in the current set; the
    /// current installation stays.
    pub fn replace_table(&self, table: PolicyTable) -> Result<(), PolicyError> {
        let mut current = self
            .installed
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *current = Arc::new(Installed::new(current.resolvers.clone(), table)?);
        Ok(())
    }

    /// The installed table.
    pub fn table(&self) -> PolicyTable {
        self.current().table.clone()
    }

    /// The index of the rule of the installed table a query for `name` of type
    /// `record_type` from `client` uses, `None` when no rule applies
    /// ([`PolicyTable::matching`]).
    pub fn matching(&self, name: &str, record_type: RecordType, client: IpAddr) -> Option<usize> {
        self.current().table.matching(name, record_type, client)
    }

    /// The counters.
    pub fn stats(&self) -> PolicyStats {
        let installed = self.current();
        let c = &self.counters;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        PolicyStats {
            rule_hits: installed.hits.iter().map(load).collect(),
            resolved: load(&c.resolved),
            records: load(&c.records),
            blocked: load(&c.blocked),
            sinkholed: load(&c.sinkholed),
            nodata: load(&c.nodata),
            cnames: load(&c.cnames),
            fallbacks: load(&c.fallbacks),
            unmatched: load(&c.unmatched),
        }
    }

    fn current(&self) -> Arc<Installed> {
        Arc::clone(
            &self
                .installed
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }
}

impl Resolver for PolicyResolver {
    async fn resolve(&self, query: &Query, client: SocketAddr) -> Answer {
        let installed = self.current();
        installed.resolve(query, client, &self.counters).await
    }
}
